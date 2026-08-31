// Package cabundle publishes the relay CA into the namespaces that need it.
//
// A workload can only speak to an inspected destination if it trusts the relay
// CA, and nothing in Kubernetes puts a CA into a container for you. This
// controller writes a ConfigMap into every namespace selected by an
// inspect-mode policy; tenants mount it and point their runtime at it. Tenants
// that use no inspected destination never see the ConfigMap, which keeps the
// blast radius of interception visible in the cluster itself.
package cabundle

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cropalato/proxy-relay-control/internal/policy"
	"github.com/cropalato/proxy-relay-control/internal/tlsbump"
)

// Defaults for the published ConfigMap.
const (
	DefaultConfigMapName = "relay-ca-bundle"
	BundleKey            = "ca.crt"

	managedByLabel = "app.kubernetes.io/managed-by"
	managedByValue = "proxy-relay-control"
)

// Controller keeps the CA bundle ConfigMaps in sync.
type Controller struct {
	client   client.Client
	store    *policy.Store
	issuer   *tlsbump.Issuer
	name     string
	interval time.Duration
	log      *slog.Logger
}

// Options configures a Controller.
type Options struct {
	Client client.Client
	Store  *policy.Store
	Issuer *tlsbump.Issuer
	// ConfigMapName defaults to DefaultConfigMapName.
	ConfigMapName string
	// Interval is the full resync period. Events are not watched directly; a
	// short periodic sync is simpler to reason about than an event graph over two
	// CRDs plus namespaces, and the object count here is small.
	Interval time.Duration
	Log      *slog.Logger
}

// New builds a Controller.
func New(opts Options) (*Controller, error) {
	if opts.Client == nil || opts.Store == nil || opts.Issuer == nil {
		return nil, fmt.Errorf("cabundle: client, store and issuer are required")
	}
	if opts.ConfigMapName == "" {
		opts.ConfigMapName = DefaultConfigMapName
	}
	if opts.Interval <= 0 {
		opts.Interval = 30 * time.Second
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	return &Controller{
		client:   opts.Client,
		store:    opts.Store,
		issuer:   opts.Issuer,
		name:     opts.ConfigMapName,
		interval: opts.Interval,
		log:      opts.Log,
	}, nil
}

// Start runs until the context is cancelled.
func (c *Controller) Start(ctx context.Context) error {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		if err := c.Sync(ctx); err != nil {
			c.log.Error("CA bundle sync failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// Sync reconciles every namespace once.
func (c *Controller) Sync(ctx context.Context) error {
	bundle := c.issuer.Bundle().PEM()
	if len(bundle) == 0 {
		return fmt.Errorf("cabundle: issuer produced an empty bundle")
	}

	var namespaces corev1.NamespaceList
	if err := c.client.List(ctx, &namespaces); err != nil {
		return fmt.Errorf("cabundle: list namespaces: %w", err)
	}

	selectors, err := c.inspectedSelectors()
	if err != nil {
		return err
	}

	var errs []error
	for i := range namespaces.Items {
		ns := &namespaces.Items[i]
		if ns.DeletionTimestamp != nil {
			continue
		}
		if matchesAny(selectors, ns.Labels) {
			if err := c.publish(ctx, ns.Name, bundle); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if err := c.remove(ctx, ns.Name); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("cabundle: %d namespace(s) failed to sync, first: %w", len(errs), errs[0])
	}
	return nil
}

func (c *Controller) inspectedSelectors() ([]labels.Selector, error) {
	var out []labels.Selector
	for _, pol := range c.store.InspectedPolicies() {
		sel := pol.Spec.Selector.NamespaceSelector
		if sel == nil {
			continue
		}
		parsed, err := metav1.LabelSelectorAsSelector(sel)
		if err != nil {
			return nil, fmt.Errorf("cabundle: policy %s namespace selector: %w", pol.Name, err)
		}
		out = append(out, parsed)
	}
	return out, nil
}

func matchesAny(selectors []labels.Selector, nsLabels map[string]string) bool {
	set := labels.Set(nsLabels)
	for _, sel := range selectors {
		if sel.Matches(set) {
			return true
		}
	}
	return false
}

func (c *Controller) publish(ctx context.Context, namespace string, bundle []byte) error {
	key := client.ObjectKey{Namespace: namespace, Name: c.name}

	var existing corev1.ConfigMap
	err := c.client.Get(ctx, key, &existing)
	switch {
	case apierrors.IsNotFound(err):
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      c.name,
				Namespace: namespace,
				Labels:    map[string]string{managedByLabel: managedByValue},
			},
			Data: map[string]string{BundleKey: string(bundle)},
		}
		if err := c.client.Create(ctx, cm); err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("cabundle: create %s: %w", key, err)
		}
		c.log.Info("published CA bundle", "namespace", namespace)
		return nil

	case err != nil:
		return fmt.Errorf("cabundle: read %s: %w", key, err)
	}

	// Never take over a ConfigMap this controller did not create. A name
	// collision with something a tenant owns should surface as a stuck sync, not
	// as silently overwritten tenant data.
	if existing.Labels[managedByLabel] != managedByValue {
		return fmt.Errorf("cabundle: %s exists and is not managed by %s", key, managedByValue)
	}
	if existing.Data[BundleKey] == string(bundle) {
		return nil
	}
	existing.Data = map[string]string{BundleKey: string(bundle)}
	if err := c.client.Update(ctx, &existing); err != nil {
		return fmt.Errorf("cabundle: update %s: %w", key, err)
	}
	c.log.Info("updated CA bundle", "namespace", namespace)
	return nil
}

func (c *Controller) remove(ctx context.Context, namespace string) error {
	key := client.ObjectKey{Namespace: namespace, Name: c.name}
	var existing corev1.ConfigMap
	if err := c.client.Get(ctx, key, &existing); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("cabundle: read %s: %w", key, err)
	}
	if existing.Labels[managedByLabel] != managedByValue {
		return nil
	}
	if err := c.client.Delete(ctx, &existing); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("cabundle: delete %s: %w", key, err)
	}
	c.log.Info("removed CA bundle", "namespace", namespace)
	return nil
}

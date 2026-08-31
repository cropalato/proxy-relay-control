package policy

import (
	"context"
	"fmt"
	"sync/atomic"

	toolscache "k8s.io/client-go/tools/cache"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/cropalato/proxy-relay-control/api/v1alpha1"
)

// Store is a Lister backed by a watch cache.
//
// Every connection consults policy, so the hot path reads an immutable snapshot
// rebuilt on watch events rather than listing and deep-copying per request.
type Store struct {
	cache ctrlcache.Cache

	snapshot atomic.Pointer[snapshot]
}

type snapshot struct {
	policies  []*v1alpha1.EgressPolicy
	upstreams map[string]*v1alpha1.UpstreamProxy
}

// NewStore registers informers for both kinds and keeps a snapshot current.
// The caller starts and syncs the cache.
func NewStore(ctx context.Context, c ctrlcache.Cache) (*Store, error) {
	s := &Store{cache: c}
	s.snapshot.Store(&snapshot{upstreams: map[string]*v1alpha1.UpstreamProxy{}})

	handler := toolscache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { s.refresh(ctx) },
		UpdateFunc: func(any, any) { s.refresh(ctx) },
		DeleteFunc: func(any) { s.refresh(ctx) },
	}

	for _, obj := range []client.Object{&v1alpha1.EgressPolicy{}, &v1alpha1.UpstreamProxy{}} {
		inf, err := c.GetInformer(ctx, obj)
		if err != nil {
			return nil, fmt.Errorf("policy: get informer for %T: %w", obj, err)
		}
		if _, err := inf.AddEventHandler(handler); err != nil {
			return nil, fmt.Errorf("policy: add event handler for %T: %w", obj, err)
		}
	}
	return s, nil
}

// Refresh rebuilds the snapshot. It runs once at startup after cache sync and
// then on every watch event.
func (s *Store) Refresh(ctx context.Context) error { return s.refreshErr(ctx) }

func (s *Store) refresh(ctx context.Context) {
	// Event handlers have nowhere to return an error to. A failed rebuild leaves
	// the previous snapshot in place, which is the safe outcome: policy goes
	// stale rather than empty, and an empty snapshot would deny all egress.
	_ = s.refreshErr(ctx)
}

func (s *Store) refreshErr(ctx context.Context) error {
	var policies v1alpha1.EgressPolicyList
	if err := s.cache.List(ctx, &policies); err != nil {
		return fmt.Errorf("policy: list EgressPolicy: %w", err)
	}
	var upstreams v1alpha1.UpstreamProxyList
	if err := s.cache.List(ctx, &upstreams); err != nil {
		return fmt.Errorf("policy: list UpstreamProxy: %w", err)
	}

	next := &snapshot{
		policies:  make([]*v1alpha1.EgressPolicy, 0, len(policies.Items)),
		upstreams: make(map[string]*v1alpha1.UpstreamProxy, len(upstreams.Items)),
	}
	for i := range policies.Items {
		next.policies = append(next.policies, &policies.Items[i])
	}
	for i := range upstreams.Items {
		next.upstreams[upstreams.Items[i].Name] = &upstreams.Items[i]
	}
	s.snapshot.Store(next)
	return nil
}

// ListEgressPolicies implements Lister.
func (s *Store) ListEgressPolicies() ([]*v1alpha1.EgressPolicy, error) {
	return s.snapshot.Load().policies, nil
}

// GetUpstreamProxy implements Lister.
func (s *Store) GetUpstreamProxy(name string) (*v1alpha1.UpstreamProxy, error) {
	up, ok := s.snapshot.Load().upstreams[name]
	if !ok {
		return nil, fmt.Errorf("UpstreamProxy %q not found", name)
	}
	return up, nil
}

// InspectedPolicies returns every policy that uses TLS inspection. The CA
// bundle controller uses this to decide which namespaces need the relay CA.
func (s *Store) InspectedPolicies() []*v1alpha1.EgressPolicy {
	var out []*v1alpha1.EgressPolicy
	for _, pol := range s.snapshot.Load().policies {
		for _, dst := range pol.Spec.Destinations {
			if dst.TLSMode == v1alpha1.TLSModeInspect {
				out = append(out, pol)
				break
			}
		}
	}
	return out
}

var _ Lister = (*Store)(nil)

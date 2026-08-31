package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/cropalato/proxy-relay-control/api/v1alpha1"
	"github.com/cropalato/proxy-relay-control/internal/audit"
	"github.com/cropalato/proxy-relay-control/internal/cabundle"
	"github.com/cropalato/proxy-relay-control/internal/config"
	"github.com/cropalato/proxy-relay-control/internal/guard"
	"github.com/cropalato/proxy-relay-control/internal/identity"
	"github.com/cropalato/proxy-relay-control/internal/policy"
	"github.com/cropalato/proxy-relay-control/internal/proxy"
	"github.com/cropalato/proxy-relay-control/internal/tlsbump"
	"github.com/cropalato/proxy-relay-control/internal/upstream"
)

// Secret keys holding the relay CA. The "next" pair exists so that a rotation
// can publish the upcoming CA for trust before anything is signed with it.
const (
	caCertKey     = "ca.crt"
	caKeyKey      = "ca.key"
	nextCACertKey = "next-ca.crt"
)

func serve(ctx context.Context, args []string) error {
	cfg := config.Default()
	parseFlags("serve", args, cfg.BindFlags)
	if err := cfg.Validate(); err != nil {
		return err
	}

	log := newLogger(cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(log)
	// controller-runtime dumps a goroutine trace on first use if no logger was
	// set. Route its output into the same handler as everything else.
	ctrl.SetLogger(logr.FromSlogHandler(log.Handler()))

	restCfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("load kubernetes config: %w", err)
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return err
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		return err
	}

	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("build kubernetes client: %w", err)
	}

	// Secrets are cached for one namespace only. Watching them cluster-wide would
	// mean holding every tenant Secret in memory, which is the opposite of what a
	// relay handling other people's credentials should do.
	cache, err := ctrlcache.New(restCfg, ctrlcache.Options{
		Scheme: scheme,
		ByObject: map[ctrlclient.Object]ctrlcache.ByObject{
			&corev1.Secret{}: {Namespaces: map[string]ctrlcache.Config{cfg.Namespace: {}}},
		},
	})
	if err != nil {
		return fmt.Errorf("build watch cache: %w", err)
	}

	// The CA bundle controller writes ConfigMaps into every tenant namespace.
	// Those go through a direct client so the relay never watches cluster-wide
	// ConfigMaps just to write a handful of them.
	direct, err := ctrlclient.New(restCfg, ctrlclient.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("build api client: %w", err)
	}

	store, err := policy.NewStore(ctx, cache)
	if err != nil {
		return err
	}

	factory := informers.NewSharedInformerFactory(clientset, 10*time.Minute)
	idProvider, err := identity.NewPodIPProvider(factory, clientset, cfg.IdentityNegTTL)
	if err != nil {
		return err
	}

	bundle, err := loadCABundle(ctx, direct, cfg)
	if err != nil {
		return err
	}
	issuer, err := tlsbump.NewIssuer(bundle, cfg.LeafValidity, tlsbump.DefaultCacheSize)
	if err != nil {
		return err
	}

	g, err := guard.New(cfg.ExtraDeniedCIDRs, cfg.DisableDefaultDeniedCIDRs, nil)
	if err != nil {
		return err
	}

	originTLS, err := originTLSConfig(cfg.OriginCAFile)
	if err != nil {
		return err
	}

	dialer := upstream.NewDialer(upstream.Options{
		Credentials: upstream.NewSecretCredentials(cache, cfg.Namespace),
		Guard:       g,
		Timeout:     cfg.UpstreamTimeout,
	})

	// Readiness is latched rather than recomputed. It is consulted on every
	// accepted connection, and WaitForCacheSync walks every informer each call.
	var synced atomic.Bool
	ready := synced.Load

	server, err := proxy.New(proxy.Options{
		Identity:         idProvider,
		Engine:           policy.NewEngine(store),
		Guard:            g,
		Dialer:           dialer,
		Issuer:           issuer,
		Audit:            audit.New(log),
		Log:              log,
		OriginTLSConfig:  originTLS,
		HandshakeTimeout: cfg.HandshakeTimeout,
		IdleTimeout:      cfg.IdleTimeout,
		ShutdownGrace:    cfg.ShutdownGrace,
		Ready:            ready,
	})
	if err != nil {
		return err
	}

	caCtl, err := cabundle.New(cabundle.Options{
		Client:        direct,
		Store:         store,
		Issuer:        issuer,
		ConfigMapName: cfg.CAConfigMapName,
		Interval:      cfg.CASyncInterval,
		Log:           log,
	})
	if err != nil {
		return err
	}

	// Start caches before serving. A relay that answers before policy is loaded
	// denies everything, which tenants experience as an outage.
	go func() {
		if err := cache.Start(ctx); err != nil {
			log.Error("watch cache stopped", "error", err)
		}
	}()
	factory.Start(ctx.Done())

	if !cache.WaitForCacheSync(ctx) {
		return fmt.Errorf("watch cache did not sync")
	}
	if !idProvider.WaitForCacheSync(ctx) {
		return fmt.Errorf("pod cache did not sync")
	}
	if err := store.Refresh(ctx); err != nil {
		return err
	}
	synced.Store(true)

	go caCtl.Start(ctx)
	go watchCARotation(ctx, direct, issuer, cfg, log)

	adminErr := make(chan error, 1)
	go func() { adminErr <- serveAdmin(ctx, cfg.AdminAddr, ready, log) }()

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.ListenAddr, err)
	}
	log.Info("relay listening",
		"proxy", cfg.ListenAddr, "admin", cfg.AdminAddr, "namespace", cfg.Namespace)

	if err := server.Serve(ctx, ln); err != nil {
		return err
	}
	select {
	case err := <-adminErr:
		return err
	default:
		return nil
	}
}

// originTLSConfig extends the system roots rather than replacing them. An
// internal CA is normally an addition to the public ones, and a config that
// silently dropped the public set would break every external destination the
// moment one internal host needed inspecting.
func originTLSConfig(caFile string) (*tls.Config, error) {
	if caFile == "" {
		return nil, nil
	}
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read --origin-ca-file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("--origin-ca-file %s contains no usable certificate", caFile)
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

// serveAdmin exposes health, metrics and the preflight echo on a port separate
// from the proxy itself.
func serveAdmin(ctx context.Context, addr string, ready func() bool, log *slog.Logger) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintln(w, "caches not synced")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	// observed-ip is what makes the NAT problem diagnosable: a canary pod asks
	// the relay which address it appeared to come from, and compares.
	mux.HandleFunc("/observed-ip", func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		fmt.Fprintln(w, host)
	})

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Info("admin listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("admin server: %w", err)
	}
	return nil
}

// loadCABundle reads the relay CA, optionally creating it on a first install.
func loadCABundle(ctx context.Context, c ctrlclient.Client, cfg *config.Config) (*tlsbump.Bundle, error) {
	key := ctrlclient.ObjectKey{Namespace: cfg.Namespace, Name: cfg.CASecretName}

	var secret corev1.Secret
	err := c.Get(ctx, key, &secret)
	if apierrors.IsNotFound(err) && cfg.AutoInitCA {
		return initCASecret(ctx, c, key)
	}
	if err != nil {
		return nil, fmt.Errorf("read CA Secret %s: %w (run 'relay init-ca' or set --auto-init-ca)", key, err)
	}
	return bundleFromSecret(&secret)
}

func bundleFromSecret(secret *corev1.Secret) (*tlsbump.Bundle, error) {
	current, err := tlsbump.LoadCA(secret.Data[caCertKey], secret.Data[caKeyKey])
	if err != nil {
		return nil, fmt.Errorf("Secret %s/%s: %w", secret.Namespace, secret.Name, err)
	}
	bundle := &tlsbump.Bundle{Current: current}
	if next, ok := secret.Data[nextCACertKey]; ok && len(next) > 0 {
		nextCA, err := tlsbump.LoadCACert(next)
		if err != nil {
			return nil, fmt.Errorf("Secret %s/%s %s: %w", secret.Namespace, secret.Name, nextCACertKey, err)
		}
		bundle.Next = nextCA
	}
	return bundle, nil
}

func initCASecret(ctx context.Context, c ctrlclient.Client, key ctrlclient.ObjectKey) (*tlsbump.Bundle, error) {
	ca, err := tlsbump.GenerateCA("proxy-relay-control", tlsbump.DefaultCAValidity)
	if err != nil {
		return nil, err
	}
	keyPEM, err := ca.MarshalKey()
	if err != nil {
		return nil, err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{caCertKey: ca.CertPEM, caKeyKey: keyPEM},
	}
	if err := c.Create(ctx, secret); err != nil {
		return nil, fmt.Errorf("create CA Secret %s: %w", key, err)
	}
	return &tlsbump.Bundle{Current: ca}, nil
}

// watchCARotation re-reads the CA Secret so a rotation takes effect without a
// restart. Publishing the new CA is the CA bundle controller's job; this only
// changes what the relay signs with.
func watchCARotation(ctx context.Context, c ctrlclient.Client, issuer *tlsbump.Issuer, cfg *config.Config, log *slog.Logger) {
	ticker := time.NewTicker(cfg.CASyncInterval)
	defer ticker.Stop()

	key := ctrlclient.ObjectKey{Namespace: cfg.Namespace, Name: cfg.CASecretName}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		var secret corev1.Secret
		if err := c.Get(ctx, key, &secret); err != nil {
			log.Error("re-read CA Secret", "error", err)
			continue
		}
		bundle, err := bundleFromSecret(&secret)
		if err != nil {
			log.Error("parse CA Secret", "error", err)
			continue
		}
		if current := issuer.Bundle(); current.Current != nil && bundle.Current != nil &&
			current.Current.Certificate.Equal(bundle.Current.Certificate) &&
			sameNext(current.Next, bundle.Next) {
			continue
		}
		issuer.SetBundle(bundle)
		log.Info("relay CA reloaded", "subject", bundle.Current.Certificate.Subject.CommonName)
	}
}

func sameNext(a, b *tlsbump.CA) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return a.Certificate.Equal(b.Certificate)
	}
}

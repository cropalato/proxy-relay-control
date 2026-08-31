// Package config holds the relay's runtime configuration.
package config

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config is the fully resolved relay configuration.
type Config struct {
	// ListenAddr is the explicit-proxy port tenants point http_proxy at.
	ListenAddr string
	// AdminAddr serves health, metrics and the preflight echo endpoint. It is
	// separate from the proxy port so that it can stay off the tenant-facing
	// NetworkPolicy.
	AdminAddr string

	// Namespace is where the relay runs; credential Secrets and the CA Secret are
	// read only from here.
	Namespace string

	CASecretName    string
	CAConfigMapName string
	// AutoInitCA generates and stores a CA when the Secret is missing. Convenient
	// for a first install, and deliberately opt-in so that a misconfigured
	// deployment cannot quietly start issuing under a brand-new CA that no tenant
	// trusts.
	AutoInitCA bool

	// OriginCAFile adds trust roots for the origin leg of inspected connections.
	// Destinations signed by an internal CA are otherwise unreachable in inspect
	// mode, since the relay verifies origins against system roots.
	OriginCAFile string

	// ExtraDeniedCIDRs are added to the guard's defaults. Cluster pod and service
	// CIDRs belong here: they are the addresses a tenant would most like to reach
	// through an egress proxy, and they are not knowable without being told.
	ExtraDeniedCIDRs []string
	// DisableDefaultDeniedCIDRs turns off the built-in private-range denials.
	DisableDefaultDeniedCIDRs bool

	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
	ShutdownGrace    time.Duration
	UpstreamTimeout  time.Duration
	LeafValidity     time.Duration
	IdentityNegTTL   time.Duration
	CASyncInterval   time.Duration

	LogLevel  string
	LogFormat string

	Kubeconfig string
}

// Default returns the configuration before flags are applied.
func Default() *Config {
	return &Config{
		ListenAddr:       ":3128",
		AdminAddr:        ":9090",
		Namespace:        envOr("POD_NAMESPACE", "relay-system"),
		CASecretName:     "relay-ca",
		CAConfigMapName:  "relay-ca-bundle",
		HandshakeTimeout: 30 * time.Second,
		IdleTimeout:      5 * time.Minute,
		ShutdownGrace:    20 * time.Second,
		UpstreamTimeout:  10 * time.Second,
		LeafValidity:     24 * time.Hour,
		IdentityNegTTL:   2 * time.Second,
		CASyncInterval:   30 * time.Second,
		LogLevel:         "info",
		LogFormat:        "json",
	}
}

// BindFlags registers every option on a FlagSet.
func (c *Config) BindFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.ListenAddr, "listen", c.ListenAddr, "address for the explicit proxy listener")
	fs.StringVar(&c.AdminAddr, "admin-listen", c.AdminAddr, "address for health, metrics and preflight")
	fs.StringVar(&c.Namespace, "namespace", c.Namespace, "namespace holding the relay's Secrets")
	fs.StringVar(&c.CASecretName, "ca-secret", c.CASecretName, "Secret holding the relay CA")
	fs.StringVar(&c.CAConfigMapName, "ca-configmap", c.CAConfigMapName, "name of the CA bundle ConfigMap published to tenant namespaces")
	fs.StringVar(&c.OriginCAFile, "origin-ca-file", c.OriginCAFile, "PEM file of extra trust roots for verifying inspected origins")
	fs.BoolVar(&c.AutoInitCA, "auto-init-ca", c.AutoInitCA, "generate and store a CA when the Secret is missing")
	fs.Var((*stringList)(&c.ExtraDeniedCIDRs), "deny-cidr", "additional CIDR to refuse as a destination; repeatable (set your pod and service CIDRs)")
	fs.BoolVar(&c.DisableDefaultDeniedCIDRs, "no-default-deny-cidrs", c.DisableDefaultDeniedCIDRs, "do not deny the built-in private ranges")
	fs.DurationVar(&c.HandshakeTimeout, "handshake-timeout", c.HandshakeTimeout, "bound on reading a request line and completing TLS")
	fs.DurationVar(&c.IdleTimeout, "idle-timeout", c.IdleTimeout, "close tunnels idle for this long")
	fs.DurationVar(&c.ShutdownGrace, "shutdown-grace", c.ShutdownGrace, "how long to wait for established tunnels on shutdown")
	fs.DurationVar(&c.UpstreamTimeout, "upstream-timeout", c.UpstreamTimeout, "bound on contacting the corporate proxy")
	fs.DurationVar(&c.LeafValidity, "leaf-validity", c.LeafValidity, "validity of certificates minted for inspected destinations")
	fs.DurationVar(&c.CASyncInterval, "ca-sync-interval", c.CASyncInterval, "how often to re-read the CA Secret and republish bundles")
	fs.StringVar(&c.LogLevel, "log-level", c.LogLevel, "debug, info, warn or error")
	fs.StringVar(&c.LogFormat, "log-format", c.LogFormat, "json or text")
	fs.StringVar(&c.Kubeconfig, "kubeconfig", c.Kubeconfig, "path to a kubeconfig; in-cluster config is used when empty")
}

// Validate checks the configuration for combinations that cannot work.
func (c *Config) Validate() error {
	if c.Namespace == "" {
		return fmt.Errorf("config: namespace is required (set POD_NAMESPACE or --namespace)")
	}
	if c.ListenAddr == "" {
		return fmt.Errorf("config: --listen is required")
	}
	if c.LeafValidity < time.Hour {
		return fmt.Errorf("config: --leaf-validity must be at least 1h, got %s", c.LeafValidity)
	}
	switch c.LogFormat {
	case "json", "text":
	default:
		return fmt.Errorf("config: --log-format must be json or text, got %q", c.LogFormat)
	}
	return nil
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

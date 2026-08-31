// Package metrics exposes relay counters for Prometheus.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Collectors registered on the default registry.
var (
	// Requests counts authorization outcomes. Namespace is a label because the
	// question operators actually ask is "which tenant is being denied".
	Requests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "relay_requests_total",
		Help: "Authorization outcomes, by tenant namespace and decision.",
	}, []string{"namespace", "decision", "tls_mode"})

	// UpstreamErrors separates a broken relay credential from tenant behaviour.
	UpstreamErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "relay_upstream_errors_total",
		Help: "Failures contacting the corporate proxy, by upstream profile and kind.",
	}, []string{"upstream", "kind"})

	// ActiveConnections tracks tunnels currently open.
	ActiveConnections = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "relay_active_connections",
		Help: "Currently open client connections, by TLS mode.",
	}, []string{"tls_mode"})

	// IdentityFailures highlights the deployment problems that make pod-IP
	// identity stop working, such as NAT in front of the relay.
	IdentityFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "relay_identity_failures_total",
		Help: "Client connections that could not be attributed to a workload.",
	}, []string{"kind"})

	// BytesRelayed measures traffic per tenant.
	BytesRelayed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "relay_bytes_total",
		Help: "Bytes relayed, by tenant namespace and direction.",
	}, []string{"namespace", "direction"})

	// LeafCerts tracks the inspect-mode certificate cache.
	LeafCerts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "relay_leaf_certs_total",
		Help: "Leaf certificates minted or served from cache for inspected connections.",
	}, []string{"result"})
)

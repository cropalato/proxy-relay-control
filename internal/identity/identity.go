// Package identity resolves a proxy client connection to the Kubernetes workload
// behind it.
//
// The provider used in v1 maps the connection's source IP to a pod. That trust
// boundary is the CNI: it holds only while the CNI prevents pods from spoofing
// source addresses (Calico and Cilium enforce this by default) and while no NAT
// sits between the pod and the relay. Both conditions are checked by the
// preflight command. Stronger providers (ServiceAccount token, mTLS/SPIFFE) are
// meant to satisfy this same interface without touching the data path.
package identity

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// Errors returned by a Provider. Callers distinguish them to produce a useful
// denial message; an operator debugging a 403 needs to know whether the client
// was unknown, ambiguous, or structurally unidentifiable.
var (
	// ErrUnknownClient means no workload could be matched to the source address.
	ErrUnknownClient = errors.New("identity: no pod matches the client address")

	// ErrAmbiguousClient means several workloads share the source address, which
	// happens with host-network pods and with NAT in front of the relay.
	ErrAmbiguousClient = errors.New("identity: client address matches multiple pods")

	// ErrHostNetwork means the client shares its node's network namespace, so its
	// address identifies a node rather than a workload.
	ErrHostNetwork = errors.New("identity: host-network clients cannot be identified")
)

// Identity is the workload behind a proxy connection.
type Identity struct {
	Namespace       string
	Pod             string
	ServiceAccount  string
	PodLabels       map[string]string
	NamespaceLabels map[string]string
	SourceIP        netip.Addr
}

// String renders the identity for logs and denial messages.
func (i *Identity) String() string {
	if i == nil {
		return "<unidentified>"
	}
	return fmt.Sprintf("%s/%s (sa=%s, ip=%s)", i.Namespace, i.Pod, i.ServiceAccount, i.SourceIP)
}

// Provider resolves a client address to a workload identity.
type Provider interface {
	Identify(ctx context.Context, remote net.Addr) (*Identity, error)
}

// AddrToIP extracts the IP from a net.Addr, tolerating both host:port and bare
// address forms.
func AddrToIP(remote net.Addr) (netip.Addr, error) {
	if remote == nil {
		return netip.Addr{}, errors.New("identity: nil remote address")
	}
	s := remote.String()
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("identity: cannot parse client address %q: %w", s, err)
	}
	return addr.Unmap(), nil
}

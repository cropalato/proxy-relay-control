// Package guard rejects destinations that resolve into the cluster or onto
// other internal networks.
//
// The relay normally hands the hostname to the corporate proxy, which does its
// own resolution, so this check is advisory for tunnelled traffic: it stops a
// tenant from naming an internal address, but it cannot bind the corporate
// proxy's later lookup. For destinations dialled directly (an UpstreamProxy
// noProxy match) the check is authoritative, and callers dial the returned
// addresses rather than the name.
package guard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// ErrDeniedAddress means the destination resolved onto a denied network.
var ErrDeniedAddress = errors.New("guard: destination resolves to a denied address")

// ErrUnresolvable means the destination has no usable address.
var ErrUnresolvable = errors.New("guard: destination has no resolvable address")

// DefaultDeniedCIDRs covers loopback, link-local (including the cloud metadata
// address), private ranges and the shared/benchmark ranges. Cluster pod and
// service CIDRs are added from configuration, since they are not knowable here.
var DefaultDeniedCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
}

// Guard validates destination addresses.
type Guard struct {
	resolver *net.Resolver
	denied   []netip.Prefix
}

// New builds a guard denying the given CIDRs in addition to the defaults.
// Passing skipDefaults disables the built-in list, which is only appropriate in
// tests or in a deployment where the corporate proxy is itself on a private
// range and the operator has accepted the consequences.
func New(extraCIDRs []string, skipDefaults bool, resolver *net.Resolver) (*Guard, error) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	var raw []string
	if !skipDefaults {
		raw = append(raw, DefaultDeniedCIDRs...)
	}
	raw = append(raw, extraCIDRs...)

	denied := make([]netip.Prefix, 0, len(raw))
	for _, cidr := range raw {
		p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("guard: parse denied CIDR %q: %w", cidr, err)
		}
		denied = append(denied, p.Masked())
	}
	return &Guard{resolver: resolver, denied: denied}, nil
}

// Denied reports whether an address falls inside a denied range.
func (g *Guard) Denied(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range g.denied {
		if p.Addr().Is4() != addr.Is4() {
			continue
		}
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Resolve checks a destination host and returns its permitted addresses.
//
// Every resolved address must pass. A name that resolves to a mix of public and
// internal addresses is rejected outright rather than filtered down, because the
// client would otherwise reach whichever address the corporate proxy happens to
// pick.
func (g *Guard) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		return nil, fmt.Errorf("%w: empty host", ErrUnresolvable)
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		if g.Denied(addr) {
			return nil, fmt.Errorf("%w: %s", ErrDeniedAddress, addr)
		}
		return []netip.Addr{addr}, nil
	}

	ips, err := g.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrUnresolvable, host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrUnresolvable, host)
	}

	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		ip = ip.Unmap()
		if g.Denied(ip) {
			return nil, fmt.Errorf("%w: %s resolves to %s", ErrDeniedAddress, host, ip)
		}
		out = append(out, ip)
	}
	return out, nil
}

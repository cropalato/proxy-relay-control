// Package upstream opens the second leg of the relay: the connection from this
// service to the corporate proxy, authenticated with the credentials belonging
// to the tenant whose policy allowed the request.
//
// Chaining is what lets the corporate proxy keep its existing authentication
// model. It sees one client — the relay — presenting a different account per
// tenant, so its logs and quotas stay attributable without any tenant ever
// holding a proxy credential.
package upstream

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	v1alpha1 "github.com/cropalato/proxy-relay-control/api/v1alpha1"
	"github.com/cropalato/proxy-relay-control/internal/guard"
	"github.com/cropalato/proxy-relay-control/internal/policy"
)

// Errors distinguishing the ways the second leg can fail. The relay maps each to
// a different client-facing status so that an operator reading a tenant's logs
// can tell a policy denial from a broken credential from an unreachable proxy.
var (
	// ErrUpstreamAuth means the corporate proxy rejected the relay's credentials.
	// This is a relay misconfiguration, never a tenant error.
	ErrUpstreamAuth = errors.New("upstream: corporate proxy rejected relay credentials")

	// ErrUpstreamRefused means the corporate proxy refused the tunnel, typically
	// because its own policy disallows the destination.
	ErrUpstreamRefused = errors.New("upstream: corporate proxy refused the tunnel")

	// ErrUpstreamUnreachable means the corporate proxy could not be contacted.
	ErrUpstreamUnreachable = errors.New("upstream: corporate proxy unreachable")
)

// CredentialSource supplies proxy credentials for an UpstreamProxy profile.
type CredentialSource interface {
	Credentials(ctx context.Context, ref *v1alpha1.SecretRef) (username, password string, err error)
}

// Dialer opens tunnels through corporate proxies.
type Dialer struct {
	creds   CredentialSource
	guard   *guard.Guard
	timeout time.Duration
	netDial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Options configures a Dialer.
type Options struct {
	Credentials CredentialSource
	Guard       *guard.Guard
	// Timeout bounds dialling the corporate proxy and completing its CONNECT
	// handshake. It does not bound the tunnel itself.
	Timeout time.Duration
	// DialContext overrides the network dialler, for tests.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewDialer builds a Dialer.
func NewDialer(opts Options) *Dialer {
	d := &Dialer{
		creds:   opts.Credentials,
		guard:   opts.Guard,
		timeout: opts.Timeout,
		netDial: opts.DialContext,
	}
	if d.timeout <= 0 {
		d.timeout = 10 * time.Second
	}
	if d.netDial == nil {
		dialer := &net.Dialer{Timeout: d.timeout}
		d.netDial = dialer.DialContext
	}
	return d
}

// Target is a destination to reach.
type Target struct {
	Host string
	Port int32
	// Addrs are the guard-validated addresses for Host. They are used only when
	// the destination bypasses the corporate proxy, where this relay performs the
	// connection itself and must not repeat the lookup.
	Addrs []netip.Addr
}

func (t Target) hostPort() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(int(t.Port)))
}

// Dial opens a byte stream to the target, through the given profile's corporate
// proxy unless the profile's noProxy list covers the destination.
func (d *Dialer) Dial(ctx context.Context, profile *v1alpha1.UpstreamProxy, target Target) (net.Conn, error) {
	if profile == nil {
		return nil, errors.New("upstream: nil profile")
	}

	if matchesNoProxy(profile.Spec.NoProxy, target.Host) {
		return d.dialDirect(ctx, target)
	}

	proxyURL, err := url.Parse(profile.Spec.URL)
	if err != nil {
		return nil, fmt.Errorf("upstream: parse %s URL %q: %w", profile.Name, profile.Spec.URL, err)
	}

	conn, err := d.dialProxy(ctx, proxyURL)
	if err != nil {
		return nil, err
	}

	authorized, err := d.connect(ctx, conn, proxyURL, profile, target)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return authorized, nil
}

// DialForward opens a connection to the corporate proxy for absolute-form
// forwarding, which is how plain HTTP requests are relayed. It returns the
// connection and the Proxy-Authorization value the caller must put on each
// forwarded request; unlike CONNECT, that header travels with every request
// rather than being established once for the connection.
func (d *Dialer) DialForward(ctx context.Context, profile *v1alpha1.UpstreamProxy) (net.Conn, string, error) {
	if profile == nil {
		return nil, "", errors.New("upstream: nil profile")
	}
	proxyURL, err := url.Parse(profile.Spec.URL)
	if err != nil {
		return nil, "", fmt.Errorf("upstream: parse %s URL %q: %w", profile.Name, profile.Spec.URL, err)
	}

	auth := ""
	if ref := profile.Spec.CredentialsSecretRef; ref != nil {
		if d.creds == nil {
			return nil, "", fmt.Errorf("upstream: profile %s needs credentials but none are configured", profile.Name)
		}
		user, pass, err := d.creds.Credentials(ctx, ref)
		if err != nil {
			return nil, "", fmt.Errorf("upstream: credentials for profile %s: %w", profile.Name, err)
		}
		auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	}

	conn, err := d.dialProxy(ctx, proxyURL)
	if err != nil {
		return nil, "", err
	}
	return conn, auth, nil
}

func (d *Dialer) dialDirect(ctx context.Context, target Target) (net.Conn, error) {
	if len(target.Addrs) == 0 {
		return nil, fmt.Errorf("upstream: direct dial to %s has no validated address", target.Host)
	}
	var lastErr error
	for _, addr := range target.Addrs {
		hostPort := net.JoinHostPort(addr.String(), strconv.Itoa(int(target.Port)))
		conn, err := d.netDial(ctx, "tcp", hostPort)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("upstream: direct dial %s: %w", target.hostPort(), lastErr)
}

func (d *Dialer) dialProxy(ctx context.Context, proxyURL *url.URL) (net.Conn, error) {
	host := proxyURL.Host
	if proxyURL.Port() == "" {
		if proxyURL.Scheme == "https" {
			host = net.JoinHostPort(host, "443")
		} else {
			host = net.JoinHostPort(host, "3128")
		}
	}

	dialCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	conn, err := d.netDial(dialCtx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrUpstreamUnreachable, host, err)
	}
	if proxyURL.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: proxyURL.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tlsConn.HandshakeContext(dialCtx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("%w: TLS handshake with %s: %v", ErrUpstreamUnreachable, host, err)
		}
		return tlsConn, nil
	}
	return conn, nil
}

// connect performs the CONNECT handshake with the corporate proxy.
func (d *Dialer) connect(ctx context.Context, conn net.Conn, proxyURL *url.URL, profile *v1alpha1.UpstreamProxy, target Target) (net.Conn, error) {
	header := make(http.Header)
	header.Set("Host", target.hostPort())
	// Some corporate proxies key policy off the client's product token; sending a
	// stable, identifiable one beats an empty header when someone reads their logs.
	header.Set("User-Agent", "proxy-relay-control")

	if ref := profile.Spec.CredentialsSecretRef; ref != nil {
		if d.creds == nil {
			return nil, fmt.Errorf("upstream: profile %s needs credentials but none are configured", profile.Name)
		}
		user, pass, err := d.creds.Credentials(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("upstream: credentials for profile %s: %w", profile.Name, err)
		}
		header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
	}

	deadline := time.Now().Add(d.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target.hostPort()},
		Host:   target.hostPort(),
		Header: header,
	}
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("%w: write CONNECT to %s: %v", ErrUpstreamUnreachable, proxyURL.Host, err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, fmt.Errorf("%w: read CONNECT response from %s: %v", ErrUpstreamUnreachable, proxyURL.Host, err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusProxyAuthRequired:
		return nil, fmt.Errorf("%w: profile %s got 407 from %s", ErrUpstreamAuth, profile.Name, proxyURL.Host)
	default:
		return nil, fmt.Errorf("%w: profile %s got %s for %s", ErrUpstreamRefused, profile.Name, resp.Status, target.hostPort())
	}

	_ = conn.SetDeadline(time.Time{})
	// http.ReadResponse may have buffered bytes belonging to the tunnel. Hand them
	// back before any further reads, or the first payload bytes go missing.
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

// bufferedConn replays bytes already pulled into a bufio.Reader.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// matchesNoProxy reports whether a host is covered by a noProxy pattern.
// Patterns use the same host globs as policy destinations, plus the bare-suffix
// form (".corp.example") that NO_PROXY conventions have trained everyone to write.
func matchesNoProxy(patterns []string, host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	for _, p := range patterns {
		p = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(p)), ".")
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, ".") {
			if strings.HasSuffix(host, p) && len(host) > len(p) {
				return true
			}
			continue
		}
		if policy.MatchHost(p, host) {
			return true
		}
	}
	return false
}

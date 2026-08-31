package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/cropalato/proxy-relay-control/api/v1alpha1"
	"github.com/cropalato/proxy-relay-control/internal/audit"
	"github.com/cropalato/proxy-relay-control/internal/guard"
	"github.com/cropalato/proxy-relay-control/internal/identity"
	"github.com/cropalato/proxy-relay-control/internal/policy"
	"github.com/cropalato/proxy-relay-control/internal/tlsbump"
	"github.com/cropalato/proxy-relay-control/internal/upstream"
)

// fixedIdentity stands in for the pod-IP provider.
type fixedIdentity struct {
	id  *identity.Identity
	err error
}

func (f fixedIdentity) Identify(context.Context, net.Addr) (*identity.Identity, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.id, nil
}

type fakeLister struct {
	policies  []*v1alpha1.EgressPolicy
	upstreams map[string]*v1alpha1.UpstreamProxy
}

func (f *fakeLister) ListEgressPolicies() ([]*v1alpha1.EgressPolicy, error) { return f.policies, nil }

func (f *fakeLister) GetUpstreamProxy(name string) (*v1alpha1.UpstreamProxy, error) {
	up, ok := f.upstreams[name]
	if !ok {
		return nil, fmt.Errorf("UpstreamProxy %q not found", name)
	}
	return up, nil
}

type staticCreds struct{ user, pass string }

func (s staticCreds) Credentials(context.Context, *v1alpha1.SecretRef) (string, string, error) {
	return s.user, s.pass, nil
}

// corporateProxy is a stand-in for the on-prem proxy: it demands basic auth and
// records the account each tunnel was opened under, which is the attribution the
// whole design exists to produce.
type corporateProxy struct {
	t        *testing.T
	listener net.Listener
	want     string

	mu       sync.Mutex
	accounts []string
	targets  []string
	wg       sync.WaitGroup
}

func newCorporateProxy(t *testing.T, expectedUser, expectedPass string) *corporateProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &corporateProxy{
		t:        t,
		listener: ln,
		want:     "Basic " + base64.StdEncoding.EncodeToString([]byte(expectedUser+":"+expectedPass)),
	}
	p.wg.Add(1)
	go p.serve()
	t.Cleanup(func() {
		ln.Close()
		p.wg.Wait()
	})
	return p
}

func (p *corporateProxy) serve() {
	defer p.wg.Done()
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *corporateProxy) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	auth := req.Header.Get("Proxy-Authorization")
	p.mu.Lock()
	p.accounts = append(p.accounts, decodeAccount(auth))
	p.targets = append(p.targets, req.Host)
	p.mu.Unlock()

	if auth != p.want {
		io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
		return
	}

	if req.Method != http.MethodConnect {
		p.forward(conn, br, req)
		return
	}

	origin, err := net.Dial("tcp", req.Host)
	if err != nil {
		io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer origin.Close()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		io.Copy(origin, br)
	}()
	io.Copy(conn, origin)
	<-done
}

// forward handles absolute-form requests, the plain-HTTP half of a forward proxy.
func (p *corporateProxy) forward(client net.Conn, br *bufio.Reader, req *http.Request) {
	host := req.URL.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}
	origin, err := net.Dial("tcp", host)
	if err != nil {
		io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer origin.Close()

	req.RequestURI = ""
	req.Header.Del("Proxy-Authorization")
	if err := req.Write(origin); err != nil {
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(origin), req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	resp.Write(client)
}

func decodeAccount(auth string) string {
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, prefix))
	if err != nil {
		return ""
	}
	user, _, _ := strings.Cut(string(raw), ":")
	return user
}

func (p *corporateProxy) addr() string { return p.listener.Addr().String() }

func (p *corporateProxy) seenAccounts() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.accounts...)
}

func (p *corporateProxy) seenTargets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...)
}

// relay bundles a running Server with the pieces a test needs to talk to it.
type relay struct {
	addr      string
	caPool    *x509.CertPool
	corporate *corporateProxy
}

type relayConfig struct {
	policies   []v1alpha1.Destination
	identity   identity.Provider
	originCAs  *x509.CertPool
	upstream   string
	credUser   string
	credPass   string
	proxyUser  string
	proxyPass  string
	extraDenyC []string
}

func startRelay(t *testing.T, cfg relayConfig) *relay {
	t.Helper()

	corporate := newCorporateProxy(t, cfg.proxyUser, cfg.proxyPass)

	upstreamName := cfg.upstream
	if upstreamName == "" {
		upstreamName = "corp-team-a"
	}
	lister := &fakeLister{
		policies: []*v1alpha1.EgressPolicy{{
			ObjectMeta: metav1.ObjectMeta{Name: "team-a"},
			Spec: v1alpha1.EgressPolicySpec{
				Selector:     v1alpha1.WorkloadSelector{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "team-a"}}},
				UpstreamRef:  v1alpha1.UpstreamRef{Name: upstreamName},
				Destinations: cfg.policies,
			},
		}},
		upstreams: map[string]*v1alpha1.UpstreamProxy{
			upstreamName: {
				ObjectMeta: metav1.ObjectMeta{Name: upstreamName},
				Spec: v1alpha1.UpstreamProxySpec{
					URL:                  "http://" + corporate.addr(),
					CredentialsSecretRef: &v1alpha1.SecretRef{Name: "corp", Namespace: "relay-system"},
				},
			},
		},
	}

	// The corporate proxy and the origin both live on loopback in tests, so the
	// guard's default private-range denials are turned off here. Every other test
	// of the guard covers that behaviour directly.
	g, err := guard.New(cfg.extraDenyC, true, nil)
	if err != nil {
		t.Fatal(err)
	}

	ca, err := tlsbump.GenerateCA("relay-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := tlsbump.NewIssuer(&tlsbump.Bundle{Current: ca}, time.Hour, 16)
	if err != nil {
		t.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(ca.Certificate)

	id := cfg.identity
	if id == nil {
		id = fixedIdentity{id: &identity.Identity{
			Namespace: "team-a", Pod: "builder-0", ServiceAccount: "builder",
			NamespaceLabels: map[string]string{"tenant": "team-a"},
			SourceIP:        netip.MustParseAddr("10.244.1.7"),
		}}
	}

	srv, err := New(Options{
		Identity: id,
		Engine:   policy.NewEngine(lister),
		Guard:    g,
		Dialer: upstream.NewDialer(upstream.Options{
			Credentials: staticCreds{cfg.credUser, cfg.credPass},
		}),
		Issuer:          issuer,
		Audit:           audit.New(slog.New(slog.DiscardHandler)),
		Log:             slog.New(slog.DiscardHandler),
		OriginTLSConfig: &tls.Config{RootCAs: cfg.originCAs},
		IdleTimeout:     5 * time.Second,
		ShutdownGrace:   0,
	})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	return &relay{addr: ln.Addr().String(), caPool: caPool, corporate: corporate}
}

// clientThrough builds an HTTP client that treats the relay as its proxy.
func (r *relay) clientThrough(trust *x509.CertPool) *http.Client {
	proxyURL := &url.URL{Scheme: "http", Host: r.addr}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			TLSClientConfig:   &tls.Config{RootCAs: trust},
			DisableKeepAlives: false,
		},
	}
}

// newOrigin starts an HTTPS server that echoes the path it was asked for.
func newOrigin(t *testing.T) (*httptest.Server, *x509.CertPool, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin-Path", r.URL.Path)
		fmt.Fprintf(w, "%s %s", r.Method, r.URL.Path)
	}))
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	host := strings.TrimPrefix(srv.URL, "https://")
	return srv, pool, host
}

func newPlainOrigin(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s %s", r.Method, r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	return srv, strings.TrimPrefix(srv.URL, "http://")
}

func hostOnly(t *testing.T, hostPort string) string {
	t.Helper()
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatal(err)
	}
	return host
}

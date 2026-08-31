package upstream

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/cropalato/proxy-relay-control/api/v1alpha1"
)

type staticCreds struct{ user, pass string }

func (s staticCreds) Credentials(context.Context, *v1alpha1.SecretRef) (string, string, error) {
	return s.user, s.pass, nil
}

// fakeProxy is a minimal CONNECT server that records what it was asked for.
type fakeProxy struct {
	listener net.Listener
	status   string
	greeting string

	mu      sync.Mutex
	lastReq *http.Request
	wg      sync.WaitGroup
}

func newFakeProxy(t *testing.T, status, greeting string) *fakeProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProxy{listener: ln, status: status, greeting: greeting}
	p.wg.Add(1)
	go p.serve()
	t.Cleanup(func() {
		ln.Close()
		p.wg.Wait()
	})
	return p
}

func (p *fakeProxy) serve() {
	defer p.wg.Done()
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			br := bufio.NewReader(conn)
			req, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			p.mu.Lock()
			p.lastReq = req
			p.mu.Unlock()

			if _, err := io.WriteString(conn, "HTTP/1.1 "+p.status+"\r\n\r\n"+p.greeting); err != nil {
				return
			}
			if !strings.HasPrefix(p.status, "200") {
				return
			}
			io.Copy(io.Discard, conn)
		}()
	}
}

func (p *fakeProxy) addr() string { return p.listener.Addr().String() }

func (p *fakeProxy) request() *http.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastReq
}

func profileFor(addr string, withCreds bool) *v1alpha1.UpstreamProxy {
	up := &v1alpha1.UpstreamProxy{
		ObjectMeta: metav1.ObjectMeta{Name: "corp"},
		Spec:       v1alpha1.UpstreamProxySpec{URL: "http://" + addr},
	}
	if withCreds {
		up.Spec.CredentialsSecretRef = &v1alpha1.SecretRef{Name: "corp", Namespace: "relay-system"}
	}
	return up
}

func TestDialSendsTenantCredentials(t *testing.T) {
	proxy := newFakeProxy(t, "200 Connection established", "")
	d := NewDialer(Options{Credentials: staticCreds{"team-a", "s3cret"}})

	conn, err := d.Dial(t.Context(), profileFor(proxy.addr(), true), Target{Host: "example.com", Port: 443})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	req := proxy.request()
	if req == nil {
		t.Fatal("proxy recorded no request")
	}
	if req.Method != http.MethodConnect {
		t.Fatalf("method = %q, want CONNECT", req.Method)
	}
	if req.Host != "example.com:443" && req.RequestURI != "example.com:443" {
		t.Fatalf("target = %q/%q, want example.com:443", req.Host, req.RequestURI)
	}
	// "team-a:s3cret" base64-encoded.
	if got, want := req.Header.Get("Proxy-Authorization"), "Basic dGVhbS1hOnMzY3JldA=="; got != want {
		t.Fatalf("Proxy-Authorization = %q, want %q", got, want)
	}
}

func TestDialPreservesBufferedTunnelBytes(t *testing.T) {
	// A server that speaks first (SMTP-style, or simply a fast TLS ServerHello)
	// can have its opening bytes pulled into the response reader. Losing them
	// would corrupt the tunnel in a way that is very hard to diagnose later.
	proxy := newFakeProxy(t, "200 Connection established", "HELLO")
	d := NewDialer(Options{Credentials: staticCreds{"u", "p"}})

	conn, err := d.Dial(t.Context(), profileFor(proxy.addr(), true), Target{Host: "example.com", Port: 443})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if string(buf) != "HELLO" {
		t.Fatalf("greeting = %q, want HELLO", buf)
	}
}

func TestDialUpstreamErrors(t *testing.T) {
	cases := []struct {
		name   string
		status string
		want   error
	}{
		{name: "auth rejected", status: "407 Proxy Authentication Required", want: ErrUpstreamAuth},
		{name: "refused", status: "403 Forbidden", want: ErrUpstreamRefused},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxy := newFakeProxy(t, tc.status, "")
			d := NewDialer(Options{Credentials: staticCreds{"u", "p"}})
			_, err := d.Dial(t.Context(), profileFor(proxy.addr(), true), Target{Host: "example.com", Port: 443})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDialUnreachable(t *testing.T) {
	d := NewDialer(Options{Credentials: staticCreds{"u", "p"}})
	// 127.0.0.1:1 is reliably closed.
	_, err := d.Dial(t.Context(), profileFor("127.0.0.1:1", true), Target{Host: "example.com", Port: 443})
	if !errors.Is(err, ErrUpstreamUnreachable) {
		t.Fatalf("err = %v, want ErrUpstreamUnreachable", err)
	}
}

func TestMatchesNoProxy(t *testing.T) {
	patterns := []string{".corp.example", "*.internal", "exact.example"}
	allow := []string{"git.corp.example", "svc.internal", "exact.example"}
	for _, h := range allow {
		if !matchesNoProxy(patterns, h) {
			t.Errorf("matchesNoProxy(%q) = false, want true", h)
		}
	}
	deny := []string{"corp.example", "a.b.internal", "notexact.example"}
	for _, h := range deny {
		if matchesNoProxy(patterns, h) {
			t.Errorf("matchesNoProxy(%q) = true, want false", h)
		}
	}
}

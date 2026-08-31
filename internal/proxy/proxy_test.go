package proxy

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	v1alpha1 "github.com/cropalato/proxy-relay-control/api/v1alpha1"
	"github.com/cropalato/proxy-relay-control/internal/identity"
)

func originPort(t *testing.T, hostPort string) int32 {
	t.Helper()
	_, portStr, err := splitHostPortStrings(hostPort)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return int32(port)
}

func splitHostPortStrings(hostPort string) (string, string, error) {
	i := strings.LastIndex(hostPort, ":")
	if i < 0 {
		return "", "", errors.New("no port")
	}
	return hostPort[:i], hostPort[i+1:], nil
}

func TestTunnelAllowedAndAttributed(t *testing.T) {
	origin, originCAs, originHostPort := newOrigin(t)
	_ = origin
	port := originPort(t, originHostPort)

	r := startRelay(t, relayConfig{
		policies:  []v1alpha1.Destination{{Host: hostOnly(t, originHostPort), Ports: []int32{port}}},
		originCAs: originCAs,
		credUser:  "team-a", credPass: "s3cret",
		proxyUser: "team-a", proxyPass: "s3cret",
	})

	resp, err := r.clientThrough(originCAs).Get("https://" + originHostPort + "/anything")
	if err != nil {
		t.Fatalf("request through relay failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// The point of the relay: the corporate proxy sees the tenant's account.
	accounts := r.corporate.seenAccounts()
	if len(accounts) == 0 || accounts[0] != "team-a" {
		t.Fatalf("corporate proxy saw accounts %v, want team-a", accounts)
	}
	if targets := r.corporate.seenTargets(); len(targets) == 0 || targets[0] != originHostPort {
		t.Fatalf("corporate proxy saw targets %v, want %s", targets, originHostPort)
	}
}

func TestTunnelDeniedHostNeverReachesCorporateProxy(t *testing.T) {
	origin, originCAs, originHostPort := newOrigin(t)
	_ = origin

	r := startRelay(t, relayConfig{
		policies:  []v1alpha1.Destination{{Host: "allowed.example", Ports: []int32{443}}},
		originCAs: originCAs,
		credUser:  "team-a", credPass: "s3cret",
		proxyUser: "team-a", proxyPass: "s3cret",
	})

	_, err := r.clientThrough(originCAs).Get("https://" + originHostPort + "/anything")
	if err == nil {
		t.Fatal("expected the request to be denied")
	}
	if !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("error = %v, want a 403 from the relay", err)
	}
	// A denied destination must not appear in the corporate proxy's logs.
	if accounts := r.corporate.seenAccounts(); len(accounts) != 0 {
		t.Fatalf("corporate proxy was contacted for a denied destination: %v", accounts)
	}
}

func TestDeniedPortIsRefused(t *testing.T) {
	origin, originCAs, originHostPort := newOrigin(t)
	_ = origin

	r := startRelay(t, relayConfig{
		policies:  []v1alpha1.Destination{{Host: hostOnly(t, originHostPort), Ports: []int32{9999}}},
		originCAs: originCAs,
		credUser:  "team-a", credPass: "s3cret",
		proxyUser: "team-a", proxyPass: "s3cret",
	})

	if _, err := r.clientThrough(originCAs).Get("https://" + originHostPort + "/anything"); err == nil {
		t.Fatal("expected a denial for a port outside the policy")
	}
}

func inspectRelay(t *testing.T) (*relay, string) {
	t.Helper()
	origin, originCAs, originHostPort := newOrigin(t)
	_ = origin
	port := originPort(t, originHostPort)

	r := startRelay(t, relayConfig{
		policies: []v1alpha1.Destination{{
			Host:    hostOnly(t, originHostPort),
			Ports:   []int32{port},
			TLSMode: v1alpha1.TLSModeInspect,
			Paths: []v1alpha1.PathRule{
				{Path: "/repos/team-a", Methods: []string{"GET", "HEAD"}},
				{Path: "/v2/*/blobs/**", Methods: []string{"GET"}},
			},
		}},
		originCAs: originCAs,
		credUser:  "team-a", credPass: "s3cret",
		proxyUser: "team-a", proxyPass: "s3cret",
	})
	return r, originHostPort
}

func TestInspectEnforcesPathRules(t *testing.T) {
	r, originHostPort := inspectRelay(t)
	client := r.clientThrough(r.caPool)

	cases := []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{name: "allowed path", method: "GET", path: "/repos/team-a/index.json", want: http.StatusOK},
		{name: "allowed wildcard", method: "GET", path: "/v2/team-a/blobs/sha256/abc", want: http.StatusOK},
		{name: "other tenant path", method: "GET", path: "/repos/team-b/index.json", want: http.StatusForbidden},
		{name: "prefix boundary", method: "GET", path: "/repos/team-ab/index.json", want: http.StatusForbidden},
		{name: "disallowed method", method: "PUT", path: "/repos/team-a/index.json", want: http.StatusForbidden},
		{name: "traversal", method: "GET", path: "/repos/team-a/../team-b/secret", want: http.StatusForbidden},
		{name: "encoded traversal", method: "GET", path: "/repos/team-a/%2e%2e/team-b", want: http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, "https://"+originHostPort+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d (body %q)", resp.StatusCode, tc.want, body)
			}
			if tc.want == http.StatusForbidden && resp.Header.Get("X-Relay-Reason") == "" {
				t.Error("denial should explain itself in X-Relay-Reason")
			}
		})
	}
}

func TestInspectDenialKeepsConnectionUsable(t *testing.T) {
	// Clients reuse one connection for many URLs. Dropping the connection on a
	// denial would fail the requests that policy actually allows.
	r, originHostPort := inspectRelay(t)
	client := r.clientThrough(r.caPool)

	denied, err := client.Get("https://" + originHostPort + "/repos/team-b/x")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, denied.Body)
	denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("first status = %d, want 403", denied.StatusCode)
	}

	allowed, err := client.Get("https://" + originHostPort + "/repos/team-a/x")
	if err != nil {
		t.Fatalf("follow-up request failed after a denial: %v", err)
	}
	defer allowed.Body.Close()
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("second status = %d, want 200", allowed.StatusCode)
	}
}

func TestInspectDeniedRequestNeverReachesCorporateProxy(t *testing.T) {
	r, originHostPort := inspectRelay(t)
	resp, err := r.clientThrough(r.caPool).Get("https://" + originHostPort + "/repos/team-b/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if accounts := r.corporate.seenAccounts(); len(accounts) != 0 {
		t.Fatalf("corporate proxy was contacted for a denied request: %v", accounts)
	}
}

func TestInspectVerifiesOriginCertificate(t *testing.T) {
	// Interception must not become a downgrade: if the relay cannot verify the
	// origin, the request fails rather than silently succeeding behind a
	// certificate the client does trust.
	origin, _, originHostPort := newOrigin(t)
	_ = origin
	port := originPort(t, originHostPort)

	r := startRelay(t, relayConfig{
		policies: []v1alpha1.Destination{{
			Host: hostOnly(t, originHostPort), Ports: []int32{port},
			TLSMode: v1alpha1.TLSModeInspect,
			Paths:   []v1alpha1.PathRule{{Path: "/"}},
		}},
		originCAs: nil, // the relay does not trust the origin's CA
		credUser:  "team-a", credPass: "s3cret",
		proxyUser: "team-a", proxyPass: "s3cret",
	})

	resp, err := r.clientThrough(r.caPool).Get("https://" + originHostPort + "/repos/team-a/x")
	if err != nil {
		return // a transport-level failure is an acceptable outcome too
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 when the origin cannot be verified", resp.StatusCode)
	}
}

func TestPlainHTTPPathRules(t *testing.T) {
	origin, originHostPort := newPlainOrigin(t)
	_ = origin
	port := originPort(t, originHostPort)

	r := startRelay(t, relayConfig{
		policies: []v1alpha1.Destination{{
			Host:  hostOnly(t, originHostPort),
			Ports: []int32{port},
			Paths: []v1alpha1.PathRule{{Path: "/repos/team-a", Methods: []string{"GET"}}},
		}},
		credUser: "team-a", credPass: "s3cret",
		proxyUser: "team-a", proxyPass: "s3cret",
	})
	client := r.clientThrough(nil)

	// Plain HTTP shows the relay the path without any interception at all.
	allowed, err := client.Get("http://" + originHostPort + "/repos/team-a/x")
	if err != nil {
		t.Fatal(err)
	}
	defer allowed.Body.Close()
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("allowed status = %d, want 200", allowed.StatusCode)
	}

	denied, err := client.Get("http://" + originHostPort + "/repos/team-b/x")
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("denied status = %d, want 403", denied.StatusCode)
	}
}

func TestUnidentifiedClientIsRefusedWithAUsefulMessage(t *testing.T) {
	origin, originCAs, originHostPort := newOrigin(t)
	_ = origin

	r := startRelay(t, relayConfig{
		policies:  []v1alpha1.Destination{{Host: hostOnly(t, originHostPort), Ports: []int32{443}}},
		identity:  fixedIdentity{err: identity.ErrUnknownClient},
		originCAs: originCAs,
		credUser:  "team-a", credPass: "s3cret",
		proxyUser: "team-a", proxyPass: "s3cret",
	})

	_, err := r.clientThrough(originCAs).Get("https://" + originHostPort + "/x")
	if err == nil {
		t.Fatal("expected an unidentified client to be refused")
	}
	if !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("error = %v, want 403", err)
	}
}

func TestBadRelayCredentialsReportedAsGatewayError(t *testing.T) {
	origin, originCAs, originHostPort := newOrigin(t)
	_ = origin
	port := originPort(t, originHostPort)

	r := startRelay(t, relayConfig{
		policies:  []v1alpha1.Destination{{Host: hostOnly(t, originHostPort), Ports: []int32{port}}},
		originCAs: originCAs,
		credUser:  "team-a", credPass: "wrong",
		proxyUser: "team-a", proxyPass: "s3cret",
	})

	_, err := r.clientThrough(originCAs).Get("https://" + originHostPort + "/x")
	if err == nil {
		t.Fatal("expected a gateway error")
	}
	// 502, not 403: a rejected relay credential is the operator's problem and
	// must not read as a tenant policy denial.
	if !strings.Contains(err.Error(), "Bad Gateway") {
		t.Fatalf("error = %v, want 502", err)
	}
}

func TestInspectDeniedRequestWithBodyKeepsConnectionUsable(t *testing.T) {
	// A denied request's body has to be consumed before the connection can carry
	// another request; anything left behind would be parsed as the next request
	// line.
	r, originHostPort := inspectRelay(t)
	client := r.clientThrough(r.caPool)

	denied, err := client.Post("https://"+originHostPort+"/repos/team-b/upload",
		"text/plain", strings.NewReader(strings.Repeat("x", 4096)))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, denied.Body)
	denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", denied.StatusCode)
	}

	allowed, err := client.Get("https://" + originHostPort + "/repos/team-a/index.json")
	if err != nil {
		t.Fatalf("follow-up request failed after a denied POST: %v", err)
	}
	defer allowed.Body.Close()
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", allowed.StatusCode)
	}
}

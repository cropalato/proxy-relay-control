package policy

import (
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/cropalato/proxy-relay-control/api/v1alpha1"
	"github.com/cropalato/proxy-relay-control/internal/identity"
)

type fakeLister struct {
	policies  []*v1alpha1.EgressPolicy
	upstreams map[string]*v1alpha1.UpstreamProxy
}

func (f *fakeLister) ListEgressPolicies() ([]*v1alpha1.EgressPolicy, error) {
	return f.policies, nil
}

func (f *fakeLister) GetUpstreamProxy(name string) (*v1alpha1.UpstreamProxy, error) {
	up, ok := f.upstreams[name]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return up, nil
}

func nsSelector(labels map[string]string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: labels}
}

func teamAIdentity() *identity.Identity {
	return &identity.Identity{
		Namespace:       "team-a",
		Pod:             "builder-0",
		ServiceAccount:  "builder",
		NamespaceLabels: map[string]string{"tenant": "team-a"},
	}
}

func policyFixture() *fakeLister {
	return &fakeLister{
		policies: []*v1alpha1.EgressPolicy{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "team-a"},
				Spec: v1alpha1.EgressPolicySpec{
					Selector:    v1alpha1.WorkloadSelector{NamespaceSelector: nsSelector(map[string]string{"tenant": "team-a"})},
					UpstreamRef: v1alpha1.UpstreamRef{Name: "corp-team-a"},
					Destinations: []v1alpha1.Destination{
						{Host: "*.github.com", Ports: []int32{443}},
						{
							Host:    "artifacts.corp.example",
							Ports:   []int32{443},
							TLSMode: v1alpha1.TLSModeInspect,
							Paths: []v1alpha1.PathRule{
								{Path: "/repos/team-a", Methods: []string{"GET", "HEAD"}},
								{Path: "/v2/*/blobs/**", Methods: []string{"GET"}},
							},
						},
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "team-b"},
				Spec: v1alpha1.EgressPolicySpec{
					Selector:     v1alpha1.WorkloadSelector{NamespaceSelector: nsSelector(map[string]string{"tenant": "team-b"})},
					UpstreamRef:  v1alpha1.UpstreamRef{Name: "corp-team-b"},
					Destinations: []v1alpha1.Destination{{Host: "*.github.com", Ports: []int32{443}}},
				},
			},
		},
		upstreams: map[string]*v1alpha1.UpstreamProxy{
			"corp-team-a": {ObjectMeta: metav1.ObjectMeta{Name: "corp-team-a"}},
			"corp-team-b": {ObjectMeta: metav1.ObjectMeta{Name: "corp-team-b"}},
		},
	}
}

func TestAuthorizeConnect(t *testing.T) {
	e := NewEngine(policyFixture())

	t.Run("allowed tunnel destination", func(t *testing.T) {
		dec, err := e.AuthorizeConnect(teamAIdentity(), "api.github.com", 443)
		if err != nil {
			t.Fatal(err)
		}
		if !dec.Allowed {
			t.Fatalf("expected allow, got deny: %s", dec.Reason)
		}
		if dec.TLSMode != v1alpha1.TLSModeTunnel {
			t.Fatalf("TLSMode = %q, want tunnel", dec.TLSMode)
		}
		if dec.Upstream != "corp-team-a" {
			t.Fatalf("Upstream = %q, want corp-team-a", dec.Upstream)
		}
	})

	t.Run("inspect destination selects inspection", func(t *testing.T) {
		dec, err := e.AuthorizeConnect(teamAIdentity(), "artifacts.corp.example", 443)
		if err != nil {
			t.Fatal(err)
		}
		if !dec.Allowed || dec.TLSMode != v1alpha1.TLSModeInspect {
			t.Fatalf("expected inspected allow, got allowed=%v mode=%q", dec.Allowed, dec.TLSMode)
		}
	})

	t.Run("unselected namespace is denied", func(t *testing.T) {
		other := teamAIdentity()
		other.Namespace = "team-c"
		other.NamespaceLabels = map[string]string{"tenant": "team-c"}
		dec, err := e.AuthorizeConnect(other, "api.github.com", 443)
		if err != nil {
			t.Fatal(err)
		}
		if dec.Allowed {
			t.Fatal("expected deny for unselected namespace")
		}
	})

	t.Run("unlisted host is denied", func(t *testing.T) {
		dec, err := e.AuthorizeConnect(teamAIdentity(), "evil.example.com", 443)
		if err != nil {
			t.Fatal(err)
		}
		if dec.Allowed {
			t.Fatal("expected deny for unlisted host")
		}
	})

	t.Run("unlisted port is denied", func(t *testing.T) {
		dec, err := e.AuthorizeConnect(teamAIdentity(), "api.github.com", 22)
		if err != nil {
			t.Fatal(err)
		}
		if dec.Allowed {
			t.Fatal("expected deny for unlisted port")
		}
	})

	t.Run("nil namespace selector grants nothing", func(t *testing.T) {
		lister := policyFixture()
		lister.policies[0].Spec.Selector = v1alpha1.WorkloadSelector{}
		dec, err := NewEngine(lister).AuthorizeConnect(teamAIdentity(), "api.github.com", 443)
		if err != nil {
			t.Fatal(err)
		}
		if dec.Allowed {
			t.Fatal("an empty selector must not grant egress")
		}
	})
}

func TestAuthorizeRequest(t *testing.T) {
	e := NewEngine(policyFixture())
	conn, err := e.AuthorizeConnect(teamAIdentity(), "artifacts.corp.example", 443)
	if err != nil || !conn.Allowed {
		t.Fatalf("connect stage failed: %v %+v", err, conn)
	}

	cases := []struct {
		name    string
		method  string
		target  string
		upgrade bool
		allow   bool
	}{
		{name: "allowed path", method: "GET", target: "/repos/team-a/index.json", allow: true},
		{name: "allowed path with query", method: "GET", target: "/repos/team-a/x?ref=main", allow: true},
		{name: "wildcard rule", method: "GET", target: "/v2/team-a/blobs/sha256/abc", allow: true},
		{name: "other tenant path", method: "GET", target: "/repos/team-b/index.json"},
		{name: "prefix boundary", method: "GET", target: "/repos/team-ab/index.json"},
		{name: "disallowed method", method: "PUT", target: "/repos/team-a/index.json"},
		{name: "traversal to other tenant", method: "GET", target: "/repos/team-a/../team-b/secret"},
		{name: "encoded traversal", method: "GET", target: "/repos/team-a/%2e%2e/team-b"},
		{name: "double encoded", method: "GET", target: "/repos/%252e%252e/team-b"},
		{name: "upgrade without opt-in", method: "GET", target: "/repos/team-a/ws", upgrade: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec, err := e.AuthorizeRequest(conn, tc.method, tc.target, tc.upgrade)
			if err != nil {
				t.Fatal(err)
			}
			if dec.Allowed != tc.allow {
				t.Fatalf("%s %s: allowed=%v want %v (%s)", tc.method, tc.target, dec.Allowed, tc.allow, dec.Reason)
			}
			if dec.Allowed && dec.Upstream != "corp-team-a" {
				t.Fatalf("upstream = %q, want corp-team-a", dec.Upstream)
			}
		})
	}
}

func TestAuthorizeRequestHostGrant(t *testing.T) {
	// A destination with no path rules grants the whole host. Reaching it on an
	// inspected connection must not accidentally deny every request.
	e := NewEngine(policyFixture())
	conn, err := e.AuthorizeConnect(teamAIdentity(), "api.github.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := e.AuthorizeRequest(conn, "POST", "/graphql", false)
	if err != nil {
		t.Fatal(err)
	}
	if !dec.Allowed {
		t.Fatalf("host grant should allow any path: %s", dec.Reason)
	}
}

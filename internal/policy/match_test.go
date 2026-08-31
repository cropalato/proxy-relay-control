package policy

import "testing"

func TestMatchHost(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"api.example.com", "api.example.com", true},
		{"api.example.com", "API.Example.Com", true},
		{"api.example.com", "api.example.com.", true},
		{"api.example.com", "evil.example.com", false},

		{"*.example.com", "api.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "notexample.com", false},

		{"**.example.com", "a.b.example.com", true},
		{"**.example.com", "api.example.com", true},
		{"**.example.com", "example.com", false},

		{"*", "anything.internal", true},
	}
	for _, tc := range cases {
		if got := MatchHost(tc.pattern, tc.host); got != tc.want {
			t.Errorf("MatchHost(%q, %q) = %v, want %v", tc.pattern, tc.host, got, tc.want)
		}
	}
}

func TestMatchPort(t *testing.T) {
	if !MatchPort(nil, 443) || !MatchPort(nil, 80) {
		t.Error("empty port list should default to 80 and 443")
	}
	if MatchPort(nil, 8080) {
		t.Error("empty port list should not allow 8080")
	}
	if !MatchPort([]int32{8443}, 8443) || MatchPort([]int32{8443}, 443) {
		t.Error("explicit port list not honoured")
	}
}

func TestMatchPath(t *testing.T) {
	cases := []struct {
		name          string
		pattern, path string
		exact         bool
		want          bool
	}{
		{name: "prefix self", pattern: "/repos/team-a", path: "/repos/team-a", want: true},
		{name: "prefix child", pattern: "/repos/team-a", path: "/repos/team-a/x", want: true},
		{name: "prefix boundary", pattern: "/repos/team-a", path: "/repos/team-ab", want: false},
		{name: "prefix sibling", pattern: "/repos/team-a", path: "/repos/team-b", want: false},
		{name: "trailing slash pattern", pattern: "/repos/team-a/", path: "/repos/team-a/x", want: true},
		{name: "trailing slash pattern bare", pattern: "/repos/team-a/", path: "/repos/team-a", want: true},

		{name: "exact match", pattern: "/health", path: "/health", exact: true, want: true},
		{name: "exact rejects child", pattern: "/health", path: "/health/deep", exact: true, want: false},

		{name: "segment wildcard", pattern: "/v2/*/blobs", path: "/v2/team-a/blobs", want: true},
		{name: "segment wildcard depth", pattern: "/v2/*/blobs", path: "/v2/a/b/blobs", want: false},
		{name: "partial segment wildcard", pattern: "/v2/team-*", path: "/v2/team-a", want: true},
		{name: "partial segment wildcard miss", pattern: "/v2/team-*", path: "/v2/other", want: false},
		{name: "deep wildcard", pattern: "/v2/**/blobs", path: "/v2/a/b/c/blobs", want: true},
		{name: "trailing deep wildcard", pattern: "/v2/**", path: "/v2/a/b", want: true},
		{name: "trailing deep wildcard empty", pattern: "/v2/**", path: "/v2", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchPath(tc.pattern, tc.exact, tc.path); got != tc.want {
				t.Fatalf("MatchPath(%q, exact=%v, %q) = %v, want %v", tc.pattern, tc.exact, tc.path, got, tc.want)
			}
		})
	}
}

func TestMatchMethod(t *testing.T) {
	if !MatchMethod(nil, "DELETE") {
		t.Error("empty method list should allow any method")
	}
	if !MatchMethod([]string{"get", "HEAD"}, "GET") {
		t.Error("method matching should be case-insensitive")
	}
	if MatchMethod([]string{"GET"}, "PUT") {
		t.Error("PUT should not match a GET-only rule")
	}
}

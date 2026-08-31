package policy

import (
	"errors"
	"testing"
)

func TestNormalizePath(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		want   string
		reject bool
	}{
		{name: "empty", in: "", want: "/"},
		{name: "root", in: "/", want: "/"},
		{name: "plain", in: "/repos/team-a/file", want: "/repos/team-a/file"},
		{name: "query stripped", in: "/a/b?x=1&y=2", want: "/a/b"},
		{name: "fragment stripped", in: "/a/b#frag", want: "/a/b"},
		{name: "duplicate slashes", in: "/a//b///c", want: "/a/b/c"},
		{name: "dot segments", in: "/a/./b", want: "/a/b"},
		{name: "trailing slash kept", in: "/a/b/", want: "/a/b/"},
		{name: "missing leading slash", in: "a/b", want: "/a/b"},
		{name: "path params dropped", in: "/a;v=1/b;q=2", want: "/a/b"},
		{name: "safe escape decoded", in: "/a/hello%20world", want: "/a/hello world"},

		{name: "traversal resolved", in: "/repos/team-a/../team-b", want: "/repos/team-b"},
		{name: "traversal escaping root", in: "/../etc", reject: true},
		{name: "encoded traversal", in: "/repos/team-a/%2e%2e/team-b", want: "/repos/team-b"},
		{name: "double encoded", in: "/repos/%252e%252e/team-b", reject: true},
		{name: "encoded slash", in: "/repos%2fteam-b", reject: true},
		{name: "encoded backslash", in: "/repos%5cteam-b", reject: true},
		{name: "literal backslash", in: "/repos\\team-b", reject: true},
		{name: "truncated escape", in: "/a/%2", reject: true},
		{name: "invalid escape", in: "/a/%zz", reject: true},
		{name: "encoded nul", in: "/a/%00b", reject: true},
		{name: "control byte", in: "/a/\x01b", reject: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizePath(tc.in)
			if tc.reject {
				if err == nil {
					t.Fatalf("NormalizePath(%q) = %q, want rejection", tc.in, got)
				}
				if !errors.Is(err, ErrMalformedPath) {
					t.Fatalf("NormalizePath(%q) error = %v, want ErrMalformedPath", tc.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizePath(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizePath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

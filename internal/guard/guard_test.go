package guard

import (
	"net/netip"
	"testing"
)

func TestDenied(t *testing.T) {
	g, err := New([]string{"10.244.0.0/16"}, false, nil)
	if err != nil {
		t.Fatal(err)
	}

	denied := []string{
		"127.0.0.1",
		"10.0.0.5",
		"10.244.1.7",
		"169.254.169.254",
		"192.168.1.1",
		"172.20.0.1",
		"::1",
		"fd00::1",
	}
	for _, s := range denied {
		if !g.Denied(netip.MustParseAddr(s)) {
			t.Errorf("Denied(%s) = false, want true", s)
		}
	}

	allowed := []string{"93.184.216.34", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946"}
	for _, s := range allowed {
		if g.Denied(netip.MustParseAddr(s)) {
			t.Errorf("Denied(%s) = true, want false", s)
		}
	}
}

func TestDeniedIgnoresFamilyMismatch(t *testing.T) {
	// A v4-mapped v6 literal must be judged as the v4 address it is, not slip
	// past the v4 prefixes because it presents as v6.
	g, err := New(nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !g.Denied(netip.MustParseAddr("::ffff:127.0.0.1")) {
		t.Error("v4-mapped loopback should be denied")
	}
}

func TestResolveIPLiteral(t *testing.T) {
	g, err := New(nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Resolve(t.Context(), "10.0.0.1"); err == nil {
		t.Error("private literal should be denied")
	}
	addrs, err := g.Resolve(t.Context(), "93.184.216.34")
	if err != nil {
		t.Fatalf("public literal rejected: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("got %d addresses, want 1", len(addrs))
	}
}

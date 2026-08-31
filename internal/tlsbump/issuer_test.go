package tlsbump

import (
	"crypto/x509"
	"testing"
	"time"
)

func testIssuer(t *testing.T) (*Issuer, *CA) {
	t.Helper()
	ca, err := GenerateCA("relay-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := NewIssuer(&Bundle{Current: ca}, time.Hour, 4)
	if err != nil {
		t.Fatal(err)
	}
	return iss, ca
}

func TestLeafVerifiesAgainstCA(t *testing.T) {
	iss, ca := testIssuer(t)
	cert, err := iss.Certificate("artifacts.corp.example")
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate)
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{
		DNSName:   "artifacts.corp.example",
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf does not verify: %v", err)
	}

	if _, err := cert.Leaf.Verify(x509.VerifyOptions{
		DNSName:   "other.example",
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err == nil {
		t.Fatal("leaf verified for the wrong hostname")
	}
}

func TestCertificateCaching(t *testing.T) {
	iss, _ := testIssuer(t)
	first, err := iss.Certificate("a.example")
	if err != nil {
		t.Fatal(err)
	}
	second, err := iss.Certificate("A.Example.")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("host lookup should be canonicalized and cached")
	}
}

func TestCacheEviction(t *testing.T) {
	iss, _ := testIssuer(t) // capacity 4
	for _, h := range []string{"a.example", "b.example", "c.example", "d.example", "e.example"} {
		if _, err := iss.Certificate(h); err != nil {
			t.Fatal(err)
		}
	}
	if got := iss.order.Len(); got != 4 {
		t.Fatalf("cache holds %d entries, want 4", got)
	}
}

func TestRotationInvalidatesCachedLeaves(t *testing.T) {
	iss, old := testIssuer(t)
	before, err := iss.Certificate("a.example")
	if err != nil {
		t.Fatal(err)
	}

	next, err := GenerateCA("relay-test-next", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	iss.SetBundle(&Bundle{Current: next, Next: nil})

	after, err := iss.Certificate("a.example")
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("leaf signed by the previous CA was reused after rotation")
	}

	pool := x509.NewCertPool()
	pool.AddCert(next.Certificate)
	if _, err := after.Leaf.Verify(x509.VerifyOptions{DNSName: "a.example", Roots: pool}); err != nil {
		t.Fatalf("leaf not signed by the new CA: %v", err)
	}
	oldPool := x509.NewCertPool()
	oldPool.AddCert(old.Certificate)
	if _, err := after.Leaf.Verify(x509.VerifyOptions{DNSName: "a.example", Roots: oldPool}); err == nil {
		t.Fatal("new leaf still chains to the old CA")
	}
}

func TestBundlePEMCarriesBothCAs(t *testing.T) {
	current, err := GenerateCA("current", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	next, err := GenerateCA("next", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pem := (&Bundle{Current: current, Next: next}).PEM()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("bundle is not parseable PEM")
	}
	// Both must be present, or a rotation would break clients mid-flight.
	if got := len(pool.Subjects()); got != 2 {
		t.Fatalf("bundle holds %d CAs, want 2", got)
	}
}

func TestLoadCARoundTrip(t *testing.T) {
	ca, err := GenerateCA("relay-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := ca.MarshalKey()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCA(ca.CertPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Certificate.Equal(ca.Certificate) {
		t.Fatal("round-tripped CA certificate differs")
	}
}

package tlsbump

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/cropalato/proxy-relay-control/internal/metrics"
)

// DefaultLeafValidity is short on purpose: a leaf minted by this relay is only
// ever used by connections it is already terminating, so there is no reason for
// one to outlive an incident.
const DefaultLeafValidity = 24 * time.Hour

// DefaultCacheSize bounds the number of cached leaves.
const DefaultCacheSize = 1024

// Issuer mints and caches leaf certificates for inspected destinations.
type Issuer struct {
	mu       sync.Mutex
	bundle   *Bundle
	validity time.Duration
	maxSize  int

	entries map[string]*list.Element
	order   *list.List
}

type cacheEntry struct {
	key     string
	cert    *tls.Certificate
	expires time.Time
	signer  *x509.Certificate
}

// NewIssuer returns an issuer signing with bundle.Current.
func NewIssuer(bundle *Bundle, validity time.Duration, maxSize int) (*Issuer, error) {
	if bundle == nil || bundle.Current == nil {
		return nil, errors.New("tlsbump: issuer needs a current CA")
	}
	if validity <= 0 {
		validity = DefaultLeafValidity
	}
	if maxSize <= 0 {
		maxSize = DefaultCacheSize
	}
	return &Issuer{
		bundle:   bundle,
		validity: validity,
		maxSize:  maxSize,
		entries:  make(map[string]*list.Element, maxSize),
		order:    list.New(),
	}, nil
}

// SetBundle swaps the signing material, for example at the end of a rotation.
// Cached leaves signed by a CA that is no longer current are discarded on next
// use rather than eagerly, since they remain valid for existing connections.
func (i *Issuer) SetBundle(b *Bundle) {
	if b == nil || b.Current == nil {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.bundle = b
}

// Bundle returns the current trust bundle.
func (i *Issuer) Bundle() *Bundle {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.bundle
}

// ServerConfig returns a TLS configuration for the client leg of an inspected
// connection.
//
// ALPN is pinned to HTTP/1.1 because the relay parses requests itself to apply
// path rules, and offering h2 would mean either implementing a second parser or
// silently failing to enforce policy on multiplexed streams.
func (i *Issuer) ServerConfig(fallbackHost string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				// A client that sends no SNI still has to be given a certificate for
				// the host it asked for in CONNECT.
				name = fallbackHost
			}
			return i.Certificate(name)
		},
	}
}

// Certificate returns a leaf for the given host, minting one if needed.
func (i *Issuer) Certificate(host string) (*tls.Certificate, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return nil, errors.New("tlsbump: cannot mint a certificate without a host")
	}

	i.mu.Lock()
	ca := i.bundle.Current
	if elem, ok := i.entries[host]; ok {
		entry := elem.Value.(*cacheEntry)
		if time.Now().Before(entry.expires) && entry.signer == ca.Certificate {
			i.order.MoveToFront(elem)
			i.mu.Unlock()
			metrics.LeafCerts.WithLabelValues("hit").Inc()
			return entry.cert, nil
		}
		i.removeLocked(elem)
	}
	i.mu.Unlock()

	cert, notAfter, err := i.mint(ca, host)
	if err != nil {
		metrics.LeafCerts.WithLabelValues("error").Inc()
		return nil, err
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	// Re-check: a concurrent mint for the same host is harmless, but caching the
	// loser would evict the winner for no reason.
	if elem, ok := i.entries[host]; ok {
		entry := elem.Value.(*cacheEntry)
		if time.Now().Before(entry.expires) && entry.signer == ca.Certificate {
			i.order.MoveToFront(elem)
			return entry.cert, nil
		}
		i.removeLocked(elem)
	}
	elem := i.order.PushFront(&cacheEntry{
		key: host, cert: cert,
		// Expire the cache entry well before the leaf itself, so a long-lived relay
		// never hands out a certificate that is about to stop being accepted.
		expires: notAfter.Add(-i.validity / 2),
		signer:  ca.Certificate,
	})
	i.entries[host] = elem
	for i.order.Len() > i.maxSize {
		i.removeLocked(i.order.Back())
	}
	metrics.LeafCerts.WithLabelValues("mint").Inc()
	return cert, nil
}

func (i *Issuer) removeLocked(elem *list.Element) {
	if elem == nil {
		return
	}
	entry := elem.Value.(*cacheEntry)
	delete(i.entries, entry.key)
	i.order.Remove(elem)
}

func (i *Issuer) mint(ca *CA, host string) (*tls.Certificate, time.Time, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("tlsbump: generate leaf key for %s: %w", host, err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, time.Time{}, err
	}

	now := time.Now()
	notAfter := now.Add(i.validity)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		tmpl.IPAddresses = []net.IP{net.IP(addr.AsSlice())}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Certificate, key.Public(), ca.Key)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("tlsbump: sign leaf for %s: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("tlsbump: parse leaf for %s: %w", host, err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, ca.Certificate.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, notAfter, nil
}

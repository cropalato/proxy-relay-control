// Package tlsbump implements the certificate side of TLS inspection.
//
// Inspection is what makes path and method rules possible: a CONNECT tunnel
// shows the relay a host and a port and nothing else. The cost is that the relay
// becomes a certificate authority for the destinations it inspects, so this
// package is deliberately narrow — mint short-lived leaves, publish the trust
// bundle, and nothing more. The connection to the origin is always verified
// normally; interception must never become a downgrade.
package tlsbump

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// DefaultCAValidity is the lifetime of a generated relay CA.
const DefaultCAValidity = 10 * 365 * 24 * time.Hour

// CA is a signing identity for inspected connections.
type CA struct {
	Certificate *x509.Certificate
	Key         crypto.Signer
	CertPEM     []byte
}

// Bundle is the set of CAs tenants must trust.
//
// It holds two entries during a rotation. Publishing the next CA before signing
// with it is the whole point: swapping a single CA in place breaks every running
// tenant pod at the same instant, because nothing reloads a trust store on its
// own.
type Bundle struct {
	Current *CA
	Next    *CA
}

// PEM returns the trust bundle tenants mount.
func (b *Bundle) PEM() []byte {
	var out []byte
	if b.Current != nil {
		out = append(out, b.Current.CertPEM...)
	}
	if b.Next != nil {
		out = append(out, b.Next.CertPEM...)
	}
	return out
}

// GenerateCA creates a new relay CA. It is used to bootstrap an installation and
// to prepare a rotation.
func GenerateCA(commonName string, validity time.Duration) (*CA, error) {
	if validity <= 0 {
		validity = DefaultCAValidity
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tlsbump: generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"proxy-relay-control"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("tlsbump: self-sign CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("tlsbump: parse generated CA: %w", err)
	}
	return &CA{
		Certificate: cert,
		Key:         key,
		CertPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}, nil
}

// MarshalKey returns the CA private key in PKCS#8 PEM form for storage.
func (c *CA) MarshalKey() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(c.Key)
	if err != nil {
		return nil, fmt.Errorf("tlsbump: marshal CA key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// LoadCA parses a CA from PEM material.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("tlsbump: CA certificate is not a PEM CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tlsbump: parse CA certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("tlsbump: configured CA certificate is not a CA")
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("tlsbump: CA key is not PEM encoded")
	}
	key, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{
		Certificate: cert,
		Key:         key,
		CertPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
	}, nil
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.New("tlsbump: CA key does not implement crypto.Signer")
		}
		return signer, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("tlsbump: unrecognised CA private key format")
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("tlsbump: generate serial: %w", err)
	}
	return serial, nil
}

// LoadCACert parses a CA certificate without its private key.
//
// The upcoming CA in a rotation is published for trust long before it signs
// anything, and the relay should not need its key in memory to do that.
func LoadCACert(certPEM []byte) (*CA, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("tlsbump: CA certificate is not a PEM CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tlsbump: parse CA certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("tlsbump: certificate is not a CA")
	}
	return &CA{
		Certificate: cert,
		CertPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
	}, nil
}

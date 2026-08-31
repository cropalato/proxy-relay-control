package upstream

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/cropalato/proxy-relay-control/api/v1alpha1"
)

// Default keys used when a SecretRef does not name them.
const (
	DefaultUsernameKey = "username"
	DefaultPasswordKey = "password"
)

// SecretCredentials reads proxy credentials from Secrets in a single namespace.
//
// The namespace is pinned rather than taken from the reference. An UpstreamProxy
// is cluster-scoped, so an unpinned reference would let anyone who can edit one
// point the relay at an arbitrary Secret and have its contents sent to a proxy
// they control. Pinning keeps that reachable set to the relay's own namespace,
// which is also the only namespace its RBAC grants.
type SecretCredentials struct {
	reader    client.Reader
	namespace string
}

// NewSecretCredentials returns a credential source restricted to namespace.
func NewSecretCredentials(reader client.Reader, namespace string) *SecretCredentials {
	return &SecretCredentials{reader: reader, namespace: namespace}
}

// Credentials implements CredentialSource.
func (s *SecretCredentials) Credentials(ctx context.Context, ref *v1alpha1.SecretRef) (string, string, error) {
	if ref == nil || ref.Name == "" {
		return "", "", fmt.Errorf("upstream: credentialsSecretRef has no name")
	}
	if ref.Namespace != "" && ref.Namespace != s.namespace {
		return "", "", fmt.Errorf("upstream: credentials Secret must live in %q, got %q", s.namespace, ref.Namespace)
	}

	var secret corev1.Secret
	key := client.ObjectKey{Namespace: s.namespace, Name: ref.Name}
	if err := s.reader.Get(ctx, key, &secret); err != nil {
		return "", "", fmt.Errorf("upstream: read Secret %s: %w", key, err)
	}

	userKey := orDefault(ref.UsernameKey, DefaultUsernameKey)
	passKey := orDefault(ref.PasswordKey, DefaultPasswordKey)

	user, ok := secret.Data[userKey]
	if !ok {
		return "", "", fmt.Errorf("upstream: Secret %s has no key %q", key, userKey)
	}
	pass, ok := secret.Data[passKey]
	if !ok {
		return "", "", fmt.Errorf("upstream: Secret %s has no key %q", key, passKey)
	}

	// Trailing newlines are the classic result of `echo -n` being forgotten, and
	// they produce a 407 that looks like a wrong password.
	return strings.TrimRight(string(user), "\r\n"), strings.TrimRight(string(pass), "\r\n"), nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

var _ CredentialSource = (*SecretCredentials)(nil)

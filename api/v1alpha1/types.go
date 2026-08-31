// Package v1alpha1 contains the API types served by proxy-relay-control.
//
// Both kinds are cluster-scoped and owned by the platform team. Tenants must not
// be granted write access to them: an EgressPolicy is the grant itself, so a tenant
// able to create one could self-authorize egress.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupName is the API group for all relay types.
const GroupName = "relay.cropalato.io"

// GroupVersion is the group/version for this package.
var GroupVersion = schema.GroupVersion{Group: GroupName, Version: "v1alpha1"}

// TLSMode selects how the relay treats a CONNECT tunnel to a destination.
type TLSMode string

const (
	// TLSModeTunnel splices bytes opaquely. The relay never sees the URL path,
	// so only host and port can be authorized. This is the default.
	TLSModeTunnel TLSMode = "tunnel"

	// TLSModeInspect terminates TLS at the relay so that path and method rules
	// can be enforced per request. Requires tenants to trust the relay CA.
	TLSModeInspect TLSMode = "inspect"
)

// PathRule authorizes a set of request paths and methods within a destination.
// Rules are only meaningful when the destination is in TLSModeInspect (or is
// reached over plain HTTP, where the path is visible without interception).
type PathRule struct {
	// Path is matched against the normalized request path. It is a prefix match
	// by default, or an exact match when Exact is set. A "*" matches within a
	// single path segment; "**" matches across segments.
	Path string `json:"path"`

	// Exact requires the normalized path to equal Path rather than be prefixed
	// by it. Ignored when Path contains wildcards.
	Exact bool `json:"exact,omitempty"`

	// Methods limits the rule to these HTTP methods. Empty means any method.
	Methods []string `json:"methods,omitempty"`

	// AllowUpgrade permits protocol upgrades (for example WebSocket) on requests
	// matching this rule. Upgrades are denied by default because the relay cannot
	// enforce path rules on the traffic that follows one.
	AllowUpgrade bool `json:"allowUpgrade,omitempty"`
}

// Destination is one allowed egress target.
type Destination struct {
	// Host is a hostname or a glob such as "*.github.com". Exact hostnames are
	// preferred; a leading "*." matches exactly one additional label unless the
	// pattern is "**.", which matches any depth.
	Host string `json:"host"`

	// Ports limits the destination to these ports. Empty means 80 and 443.
	Ports []int32 `json:"ports,omitempty"`

	// TLSMode defaults to TLSModeTunnel.
	TLSMode TLSMode `json:"tlsMode,omitempty"`

	// Paths restricts which request paths and methods are allowed. Empty means
	// every path is allowed. Setting Paths on a tunnel destination is rejected
	// at validation time: silently ignored path rules read as enforced.
	Paths []PathRule `json:"paths,omitempty"`
}

// WorkloadSelector chooses which pods a policy applies to.
type WorkloadSelector struct {
	// NamespaceSelector matches namespaces by label. A nil selector matches no
	// namespace; use an explicit empty selector ({}) to match all of them.
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// PodSelector further narrows the match within selected namespaces.
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`
}

// UpstreamRef names an UpstreamProxy.
type UpstreamRef struct {
	Name string `json:"name"`
}

// EgressPolicySpec is the desired egress grant.
type EgressPolicySpec struct {
	Selector     WorkloadSelector `json:"selector"`
	Destinations []Destination    `json:"destinations"`
	UpstreamRef  UpstreamRef      `json:"upstreamRef"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster

// EgressPolicy grants a set of workloads access to a set of destinations through
// a named upstream proxy profile.
type EgressPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec EgressPolicySpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// EgressPolicyList is a list of EgressPolicy.
type EgressPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EgressPolicy `json:"items"`
}

// SecretRef points at the credentials presented to the corporate proxy.
type SecretRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`

	// UsernameKey defaults to "username".
	UsernameKey string `json:"usernameKey,omitempty"`
	// PasswordKey defaults to "password".
	PasswordKey string `json:"passwordKey,omitempty"`
}

// UpstreamProxySpec describes one corporate proxy plus the credentials to use
// with it. Distinct profiles pointing at the same proxy with different
// credentials are how per-tenant attribution is achieved.
type UpstreamProxySpec struct {
	// URL of the corporate proxy, for example http://corp-proxy.internal:3128.
	URL string `json:"url"`

	// CredentialsSecretRef supplies the Proxy-Authorization credentials. Omit for
	// an unauthenticated parent proxy.
	CredentialsSecretRef *SecretRef `json:"credentialsSecretRef,omitempty"`

	// NoProxy lists host globs dialed directly instead of through the parent.
	NoProxy []string `json:"noProxy,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster

// UpstreamProxy is a named corporate-proxy profile.
type UpstreamProxy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec UpstreamProxySpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// UpstreamProxyList is a list of UpstreamProxy.
type UpstreamProxyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []UpstreamProxy `json:"items"`
}

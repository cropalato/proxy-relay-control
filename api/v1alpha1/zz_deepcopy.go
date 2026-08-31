package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto copies the receiver into out.
func (in *PathRule) DeepCopyInto(out *PathRule) {
	*out = *in
	if in.Methods != nil {
		out.Methods = make([]string, len(in.Methods))
		copy(out.Methods, in.Methods)
	}
}

// DeepCopyInto copies the receiver into out.
func (in *Destination) DeepCopyInto(out *Destination) {
	*out = *in
	if in.Ports != nil {
		out.Ports = make([]int32, len(in.Ports))
		copy(out.Ports, in.Ports)
	}
	if in.Paths != nil {
		out.Paths = make([]PathRule, len(in.Paths))
		for i := range in.Paths {
			in.Paths[i].DeepCopyInto(&out.Paths[i])
		}
	}
}

// DeepCopyInto copies the receiver into out.
func (in *WorkloadSelector) DeepCopyInto(out *WorkloadSelector) {
	*out = *in
	if in.NamespaceSelector != nil {
		out.NamespaceSelector = in.NamespaceSelector.DeepCopy()
	}
	if in.PodSelector != nil {
		out.PodSelector = in.PodSelector.DeepCopy()
	}
}

// DeepCopyInto copies the receiver into out.
func (in *EgressPolicySpec) DeepCopyInto(out *EgressPolicySpec) {
	*out = *in
	in.Selector.DeepCopyInto(&out.Selector)
	if in.Destinations != nil {
		out.Destinations = make([]Destination, len(in.Destinations))
		for i := range in.Destinations {
			in.Destinations[i].DeepCopyInto(&out.Destinations[i])
		}
	}
}

// DeepCopyInto copies the receiver into out.
func (in *EgressPolicy) DeepCopyInto(out *EgressPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
}

// DeepCopy returns a deep copy of the receiver.
func (in *EgressPolicy) DeepCopy() *EgressPolicy {
	if in == nil {
		return nil
	}
	out := new(EgressPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject returns a deep copy of the receiver as a runtime.Object.
func (in *EgressPolicy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto copies the receiver into out.
func (in *EgressPolicyList) DeepCopyInto(out *EgressPolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]EgressPolicy, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// DeepCopy returns a deep copy of the receiver.
func (in *EgressPolicyList) DeepCopy() *EgressPolicyList {
	if in == nil {
		return nil
	}
	out := new(EgressPolicyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject returns a deep copy of the receiver as a runtime.Object.
func (in *EgressPolicyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto copies the receiver into out.
func (in *SecretRef) DeepCopyInto(out *SecretRef) { *out = *in }

// DeepCopyInto copies the receiver into out.
func (in *UpstreamProxySpec) DeepCopyInto(out *UpstreamProxySpec) {
	*out = *in
	if in.CredentialsSecretRef != nil {
		out.CredentialsSecretRef = new(SecretRef)
		in.CredentialsSecretRef.DeepCopyInto(out.CredentialsSecretRef)
	}
	if in.NoProxy != nil {
		out.NoProxy = make([]string, len(in.NoProxy))
		copy(out.NoProxy, in.NoProxy)
	}
}

// DeepCopyInto copies the receiver into out.
func (in *UpstreamProxy) DeepCopyInto(out *UpstreamProxy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
}

// DeepCopy returns a deep copy of the receiver.
func (in *UpstreamProxy) DeepCopy() *UpstreamProxy {
	if in == nil {
		return nil
	}
	out := new(UpstreamProxy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject returns a deep copy of the receiver as a runtime.Object.
func (in *UpstreamProxy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto copies the receiver into out.
func (in *UpstreamProxyList) DeepCopyInto(out *UpstreamProxyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]UpstreamProxy, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// DeepCopy returns a deep copy of the receiver.
func (in *UpstreamProxyList) DeepCopy() *UpstreamProxyList {
	if in == nil {
		return nil
	}
	out := new(UpstreamProxyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject returns a deep copy of the receiver as a runtime.Object.
func (in *UpstreamProxyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

var _ = metav1.LabelSelector{}

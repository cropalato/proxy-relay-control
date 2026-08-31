package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// SchemeBuilder registers the relay types with a runtime scheme.
var SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

// AddToScheme adds the relay types to the given scheme.
var AddToScheme = SchemeBuilder.AddToScheme

// Resource qualifies an unqualified resource name with the relay group.
func Resource(resource string) schema.GroupResource {
	return GroupVersion.WithResource(resource).GroupResource()
}

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&EgressPolicy{}, &EgressPolicyList{},
		&UpstreamProxy{}, &UpstreamProxyList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}

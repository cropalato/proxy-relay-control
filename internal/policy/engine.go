// Package policy decides whether a workload may reach a destination.
//
// Authorization happens in two stages because a CONNECT tunnel reveals only the
// host and port up front. The connect stage answers "may this workload open a
// tunnel here, and must the tunnel be inspected"; the request stage runs once
// per HTTP request on an inspected connection and answers "may this workload
// make this request". Everything is default deny.
package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	v1alpha1 "github.com/cropalato/proxy-relay-control/api/v1alpha1"
	"github.com/cropalato/proxy-relay-control/internal/identity"
)

// ErrNoUpstream means a matched policy references an UpstreamProxy that does not
// exist. It is reported separately from a denial so the operator sees a
// misconfiguration rather than a policy gap.
var ErrNoUpstream = errors.New("policy: referenced UpstreamProxy not found")

// Lister supplies the policy objects. It is an interface so the engine can be
// tested without an API server.
type Lister interface {
	ListEgressPolicies() ([]*v1alpha1.EgressPolicy, error)
	GetUpstreamProxy(name string) (*v1alpha1.UpstreamProxy, error)
}

// Engine evaluates policy. It holds no state of its own; freshness comes from
// the Lister.
type Engine struct {
	lister Lister
}

// NewEngine returns an engine reading from the given lister.
func NewEngine(lister Lister) *Engine { return &Engine{lister: lister} }

// MatchedDestination is one destination grant that applied to a connection,
// along with the policy that granted it. The policy is carried through so that
// per-request decisions can be attributed, and so the request egresses under the
// credentials of the policy that actually allowed it.
type MatchedDestination struct {
	Policy      string
	Upstream    string
	Destination v1alpha1.Destination
	specificity int
}

// ConnectDecision is the outcome of the connect stage.
type ConnectDecision struct {
	Allowed bool
	Reason  string

	Host string
	Port int32

	// TLSMode is inspect when any matched destination requires it.
	TLSMode v1alpha1.TLSMode

	// Matched holds every destination grant that applied, most specific first.
	Matched []MatchedDestination

	// Upstream is the profile used for a tunnel-mode connection. Inspect-mode
	// connections choose per request instead, since the winning rule is not known
	// until the request line is read.
	Upstream string
}

// RequestDecision is the outcome of the request stage.
type RequestDecision struct {
	Allowed  bool
	Reason   string
	Policy   string
	Upstream string
	Rule     string
}

// AuthorizeConnect evaluates a CONNECT (or the origin of a plain HTTP request)
// against every policy selecting the workload.
func (e *Engine) AuthorizeConnect(id *identity.Identity, host string, port int32) (*ConnectDecision, error) {
	dec := &ConnectDecision{Host: host, Port: port, TLSMode: v1alpha1.TLSModeTunnel}
	if id == nil {
		dec.Reason = "no workload identity"
		return dec, nil
	}

	policies, err := e.lister.ListEgressPolicies()
	if err != nil {
		return nil, fmt.Errorf("policy: list EgressPolicy: %w", err)
	}

	var selected int
	for _, pol := range policies {
		ok, err := selects(&pol.Spec.Selector, id)
		if err != nil {
			return nil, fmt.Errorf("policy: %s selector: %w", pol.Name, err)
		}
		if !ok {
			continue
		}
		selected++

		for _, dst := range pol.Spec.Destinations {
			if !MatchHost(dst.Host, host) || !MatchPort(dst.Ports, port) {
				continue
			}
			dec.Matched = append(dec.Matched, MatchedDestination{
				Policy:      pol.Name,
				Upstream:    pol.Spec.UpstreamRef.Name,
				Destination: dst,
				specificity: hostSpecificity(dst.Host),
			})
		}
	}

	if len(dec.Matched) == 0 {
		dec.Reason = denyReason(id, host, port, selected)
		return dec, nil
	}

	// Most specific host pattern first, ties broken by policy name so that the
	// chosen upstream is stable across relay replicas and restarts.
	sort.SliceStable(dec.Matched, func(i, j int) bool {
		if dec.Matched[i].specificity != dec.Matched[j].specificity {
			return dec.Matched[i].specificity > dec.Matched[j].specificity
		}
		return dec.Matched[i].Policy < dec.Matched[j].Policy
	})

	dec.Allowed = true
	dec.Upstream = dec.Matched[0].Upstream
	for _, m := range dec.Matched {
		if m.Destination.TLSMode == v1alpha1.TLSModeInspect {
			// Inspection wins over tunnelling. If any policy author asked for path
			// rules here, honouring them matters more than avoiding interception.
			dec.TLSMode = v1alpha1.TLSModeInspect
			break
		}
	}
	dec.Reason = fmt.Sprintf("allowed by %s", strings.Join(dec.policyNames(), ", "))
	return dec, nil
}

func (d *ConnectDecision) policyNames() []string {
	seen := make(map[string]struct{}, len(d.Matched))
	var names []string
	for _, m := range d.Matched {
		if _, dup := seen[m.Policy]; dup {
			continue
		}
		seen[m.Policy] = struct{}{}
		names = append(names, m.Policy)
	}
	return names
}

// AuthorizeRequest evaluates one request on an already-authorized connection.
// The raw target is normalized here rather than by the caller so that every
// entry point gets the same treatment.
func (e *Engine) AuthorizeRequest(conn *ConnectDecision, method, target string, upgrade bool) (*RequestDecision, error) {
	if conn == nil || !conn.Allowed {
		return &RequestDecision{Reason: "connection was not authorized"}, nil
	}

	path, err := NormalizePath(target)
	if err != nil {
		return &RequestDecision{Reason: err.Error()}, nil
	}

	for _, m := range conn.Matched {
		// A destination with no path rules grants the whole host, which is what a
		// plain tunnel grant means when it is reached on an inspected connection.
		if len(m.Destination.Paths) == 0 {
			if upgrade && m.Destination.TLSMode == v1alpha1.TLSModeInspect {
				continue
			}
			return &RequestDecision{
				Allowed:  true,
				Policy:   m.Policy,
				Upstream: m.Upstream,
				Rule:     "host grant",
				Reason:   fmt.Sprintf("allowed by %s (whole host)", m.Policy),
			}, nil
		}

		for _, rule := range m.Destination.Paths {
			if !MatchPath(rule.Path, rule.Exact, path) || !MatchMethod(rule.Methods, method) {
				continue
			}
			if upgrade && !rule.AllowUpgrade {
				// Past an upgrade the relay can no longer see requests, so path rules
				// would stop being enforced. Require the policy to say so explicitly.
				continue
			}
			return &RequestDecision{
				Allowed:  true,
				Policy:   m.Policy,
				Upstream: m.Upstream,
				Rule:     rule.Path,
				Reason:   fmt.Sprintf("allowed by %s rule %q", m.Policy, rule.Path),
			}, nil
		}
	}

	reason := fmt.Sprintf("no rule allows %s %s on %s", method, path, conn.Host)
	if upgrade {
		reason += " (protocol upgrade requires allowUpgrade)"
	}
	return &RequestDecision{Reason: reason}, nil
}

// Upstream resolves an upstream profile by name.
func (e *Engine) Upstream(name string) (*v1alpha1.UpstreamProxy, error) {
	up, err := e.lister.GetUpstreamProxy(name)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrNoUpstream, name, err)
	}
	if up == nil {
		return nil, fmt.Errorf("%w: %s", ErrNoUpstream, name)
	}
	return up, nil
}

// selects reports whether a policy's selector matches the workload.
func selects(sel *v1alpha1.WorkloadSelector, id *identity.Identity) (bool, error) {
	if sel == nil || sel.NamespaceSelector == nil {
		// A nil namespace selector is treated as matching nothing. An accidental
		// empty spec should grant no egress, not all of it; authors who mean "every
		// namespace" write an explicit empty selector.
		return false, nil
	}
	nsSel, err := metav1.LabelSelectorAsSelector(sel.NamespaceSelector)
	if err != nil {
		return false, err
	}
	if !nsSel.Matches(labels.Set(id.NamespaceLabels)) {
		return false, nil
	}
	if sel.PodSelector == nil {
		return true, nil
	}
	podSel, err := metav1.LabelSelectorAsSelector(sel.PodSelector)
	if err != nil {
		return false, err
	}
	return podSel.Matches(labels.Set(id.PodLabels)), nil
}

// hostSpecificity ranks host patterns so the most precise grant wins ties.
func hostSpecificity(pattern string) int {
	switch {
	case pattern == "*" || pattern == "**":
		return 0
	case strings.HasPrefix(pattern, "**."):
		return 1
	case strings.HasPrefix(pattern, "*."):
		return 2
	default:
		return 3
	}
}

func denyReason(id *identity.Identity, host string, port int32, selected int) string {
	if selected == 0 {
		return fmt.Sprintf("no EgressPolicy selects namespace %q", id.Namespace)
	}
	return fmt.Sprintf("no destination in the %d policy/policies selecting %s allows %s:%d",
		selected, id.Namespace, host, port)
}

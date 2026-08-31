// Package audit emits one structured record per relayed request.
//
// The record is the only durable evidence of what a tenant reached, so it is
// written for denials as well as allows, and it names the policy that decided.
// Tunnelled connections carry no path: that absence is meaningful when reading
// an audit trail, and is why inspect mode exists.
package audit

import (
	"log/slog"
	"time"
)

// Decision is the outcome recorded for a request.
type Decision string

// Decisions recorded by the relay.
const (
	DecisionAllow         Decision = "allow"
	DecisionDenyPolicy    Decision = "deny_policy"
	DecisionDenyIdentity  Decision = "deny_identity"
	DecisionDenyGuard     Decision = "deny_guard"
	DecisionDenyMalformed Decision = "deny_malformed"
	DecisionErrorUpstream Decision = "error_upstream"
	DecisionErrorInternal Decision = "error_internal"
)

// Record is one audited request.
type Record struct {
	SourceIP       string
	Namespace      string
	Pod            string
	ServiceAccount string

	Method string
	Scheme string
	Host   string
	Port   int32
	// Path is empty for tunnelled connections, where it is not observable.
	Path string

	TLSMode  string
	Policy   string
	Rule     string
	Upstream string

	Decision Decision
	Reason   string

	BytesUp   int64
	BytesDown int64
	Duration  time.Duration
	// UpstreamStatus is the corporate proxy's CONNECT status, when one was received.
	UpstreamStatus string
}

// Logger writes audit records.
type Logger struct {
	log *slog.Logger
}

// New returns a Logger writing to the given slog handler.
func New(log *slog.Logger) *Logger {
	if log == nil {
		log = slog.Default()
	}
	return &Logger{log: log.With(slog.String("stream", "audit"))}
}

// Log writes one record. Denials are logged at warn so that an operator tailing
// warnings sees a tenant's failures without having to enable debug logging.
func (l *Logger) Log(r Record) {
	attrs := []any{
		slog.String("decision", string(r.Decision)),
		slog.String("src_ip", r.SourceIP),
		slog.String("namespace", r.Namespace),
		slog.String("pod", r.Pod),
		slog.String("service_account", r.ServiceAccount),
		slog.String("method", r.Method),
		slog.String("host", r.Host),
		slog.Int("port", int(r.Port)),
		slog.String("tls_mode", r.TLSMode),
		slog.Int64("bytes_up", r.BytesUp),
		slog.Int64("bytes_down", r.BytesDown),
		slog.Int64("duration_ms", r.Duration.Milliseconds()),
	}
	if r.Scheme != "" {
		attrs = append(attrs, slog.String("scheme", r.Scheme))
	}
	if r.Path != "" {
		attrs = append(attrs, slog.String("path", r.Path))
	}
	if r.Policy != "" {
		attrs = append(attrs, slog.String("policy", r.Policy))
	}
	if r.Rule != "" {
		attrs = append(attrs, slog.String("rule", r.Rule))
	}
	if r.Upstream != "" {
		attrs = append(attrs, slog.String("upstream", r.Upstream))
	}
	if r.UpstreamStatus != "" {
		attrs = append(attrs, slog.String("upstream_status", r.UpstreamStatus))
	}
	if r.Reason != "" {
		attrs = append(attrs, slog.String("reason", r.Reason))
	}

	if r.Decision == DecisionAllow {
		l.log.Info("egress", attrs...)
		return
	}
	l.log.Warn("egress", attrs...)
}

package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	v1alpha1 "github.com/cropalato/proxy-relay-control/api/v1alpha1"
	"github.com/cropalato/proxy-relay-control/internal/audit"
	"github.com/cropalato/proxy-relay-control/internal/guard"
	"github.com/cropalato/proxy-relay-control/internal/identity"
	"github.com/cropalato/proxy-relay-control/internal/metrics"
	"github.com/cropalato/proxy-relay-control/internal/policy"
	"github.com/cropalato/proxy-relay-control/internal/upstream"
)

func (s *Server) handleConnect(ctx context.Context, conn net.Conn, br *bufio.Reader, req *http.Request, id *identity.Identity, started time.Time) {
	host, port := splitTarget(req)
	if host == "" || port == 0 {
		s.audit(id, conn, audit.Record{
			Method: req.Method, Host: host, Port: port,
			Decision: audit.DecisionDenyMalformed,
			Reason:   fmt.Sprintf("CONNECT target %q is not host:port", req.Host),
			Duration: time.Since(started),
		})
		writeStatus(conn, http.StatusBadRequest, "CONNECT target must be host:port")
		return
	}

	dec, err := s.opts.Engine.AuthorizeConnect(id, host, port)
	if err != nil {
		s.internalError(conn, id, req.Method, host, port, err, started)
		return
	}
	if !dec.Allowed {
		s.audit(id, conn, audit.Record{
			Method: req.Method, Host: host, Port: port,
			Decision: audit.DecisionDenyPolicy, Reason: dec.Reason,
			Duration: time.Since(started),
		})
		metrics.Requests.WithLabelValues(id.Namespace, string(audit.DecisionDenyPolicy), string(dec.TLSMode)).Inc()
		writeStatus(conn, http.StatusForbidden, fmt.Sprintf(
			"proxy-relay-control denied %s:%d for %s/%s: %s", host, port, id.Namespace, id.Pod, dec.Reason))
		return
	}

	client := net.Conn(conn)
	if br.Buffered() > 0 {
		client = &readerConn{Conn: conn, r: io.MultiReader(io.LimitReader(br, int64(br.Buffered())), conn)}
	}

	if dec.TLSMode == v1alpha1.TLSModeInspect {
		s.handleInspect(ctx, client, dec, id, started)
		return
	}

	s.tunnel(ctx, client, dec, id, started)
}

// tunnel relays an opaque CONNECT. Only the host and port were ever visible, so
// this is the one path where no path rule can apply and the audit record
// deliberately carries no path.
func (s *Server) tunnel(ctx context.Context, client net.Conn, dec *policy.ConnectDecision, id *identity.Identity, started time.Time) {
	profile, target, err := s.resolveTarget(ctx, dec.Host, dec.Port, dec.Upstream)
	if err != nil {
		s.dialFailure(client, id, http.MethodConnect, dec, err, started)
		return
	}

	server, err := s.opts.Dialer.Dial(ctx, profile, target)
	if err != nil {
		s.dialFailure(client, id, http.MethodConnect, dec, err, started)
		return
	}
	defer server.Close()

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}

	metrics.ActiveConnections.WithLabelValues(string(v1alpha1.TLSModeTunnel)).Inc()
	defer metrics.ActiveConnections.WithLabelValues(string(v1alpha1.TLSModeTunnel)).Dec()
	metrics.Requests.WithLabelValues(id.Namespace, string(audit.DecisionAllow), string(v1alpha1.TLSModeTunnel)).Inc()

	up, down := splice(client, server, s.opts.IdleTimeout)
	metrics.BytesRelayed.WithLabelValues(id.Namespace, "up").Add(float64(up))
	metrics.BytesRelayed.WithLabelValues(id.Namespace, "down").Add(float64(down))

	s.audit(id, client, audit.Record{
		Method: http.MethodConnect, Host: dec.Host, Port: dec.Port,
		TLSMode:  string(v1alpha1.TLSModeTunnel),
		Policy:   firstPolicy(dec),
		Upstream: dec.Upstream,
		Decision: audit.DecisionAllow, Reason: dec.Reason,
		BytesUp: up, BytesDown: down, Duration: time.Since(started),
	})
}

// dialFailure reports the difference between "your destination is not allowed
// out there either" and "this relay is misconfigured", which are diagnosed by
// completely different people.
func (s *Server) dialFailure(client net.Conn, id *identity.Identity, method string, dec *policy.ConnectDecision, err error, started time.Time) {
	rec := audit.Record{
		Method: method, Host: dec.Host, Port: dec.Port,
		TLSMode: string(dec.TLSMode), Policy: firstPolicy(dec), Upstream: dec.Upstream,
		Reason: err.Error(), Duration: time.Since(started),
	}

	switch {
	case errors.Is(err, guard.ErrDeniedAddress), errors.Is(err, guard.ErrUnresolvable):
		rec.Decision = audit.DecisionDenyGuard
		s.audit(id, client, rec)
		metrics.Requests.WithLabelValues(id.Namespace, string(audit.DecisionDenyGuard), string(dec.TLSMode)).Inc()
		writeStatus(client, http.StatusForbidden, "proxy-relay-control refused the destination: "+err.Error())

	case errors.Is(err, upstream.ErrUpstreamAuth):
		rec.Decision = audit.DecisionErrorUpstream
		rec.UpstreamStatus = "407"
		s.audit(id, client, rec)
		metrics.UpstreamErrors.WithLabelValues(dec.Upstream, "auth").Inc()
		// The tenant can do nothing about this, so say plainly whose problem it is.
		writeStatus(client, http.StatusBadGateway,
			"the corporate proxy rejected this relay's credentials; the relay operator must fix the "+dec.Upstream+" profile")

	case errors.Is(err, upstream.ErrUpstreamRefused):
		rec.Decision = audit.DecisionErrorUpstream
		s.audit(id, client, rec)
		metrics.UpstreamErrors.WithLabelValues(dec.Upstream, "refused").Inc()
		writeStatus(client, http.StatusBadGateway, "the corporate proxy refused this destination: "+err.Error())

	case errors.Is(err, upstream.ErrUpstreamUnreachable):
		rec.Decision = audit.DecisionErrorUpstream
		s.audit(id, client, rec)
		metrics.UpstreamErrors.WithLabelValues(dec.Upstream, "unreachable").Inc()
		writeStatus(client, http.StatusBadGateway, "the corporate proxy is unreachable: "+err.Error())

	case errors.Is(err, policy.ErrNoUpstream):
		rec.Decision = audit.DecisionErrorInternal
		s.audit(id, client, rec)
		metrics.UpstreamErrors.WithLabelValues(dec.Upstream, "missing_profile").Inc()
		writeStatus(client, http.StatusBadGateway, err.Error())

	default:
		rec.Decision = audit.DecisionErrorInternal
		s.audit(id, client, rec)
		writeStatus(client, http.StatusBadGateway, err.Error())
	}
}

func (s *Server) internalError(conn net.Conn, id *identity.Identity, method, host string, port int32, err error, started time.Time) {
	s.log.Error("relay failure", "error", err, "namespace", id.Namespace, "pod", id.Pod, "host", host)
	s.audit(id, conn, audit.Record{
		Method: method, Host: host, Port: port,
		Decision: audit.DecisionErrorInternal, Reason: err.Error(),
		Duration: time.Since(started),
	})
	writeStatus(conn, http.StatusInternalServerError, "proxy-relay-control failed to evaluate policy")
}

func (s *Server) audit(id *identity.Identity, conn net.Conn, rec audit.Record) {
	if id != nil {
		rec.Namespace = id.Namespace
		rec.Pod = id.Pod
		rec.ServiceAccount = id.ServiceAccount
		rec.SourceIP = id.SourceIP.String()
	}
	if rec.SourceIP == "" {
		rec.SourceIP = remoteIP(conn)
	}
	s.opts.Audit.Log(rec)
}

func firstPolicy(dec *policy.ConnectDecision) string {
	if dec == nil || len(dec.Matched) == 0 {
		return ""
	}
	return dec.Matched[0].Policy
}

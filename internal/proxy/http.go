package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	v1alpha1 "github.com/cropalato/proxy-relay-control/api/v1alpha1"
	"github.com/cropalato/proxy-relay-control/internal/audit"
	"github.com/cropalato/proxy-relay-control/internal/identity"
	"github.com/cropalato/proxy-relay-control/internal/metrics"
	"github.com/cropalato/proxy-relay-control/internal/policy"
)

// handlePlainHTTP relays absolute-form requests, which is how a client reaches
// an http:// URL through an explicit proxy.
//
// Path rules apply here without any interception: the request target is in the
// clear because the client put it there. This is the one case where inspect-mode
// machinery is unnecessary, and the audit record still carries a path.
func (s *Server) handlePlainHTTP(ctx context.Context, conn net.Conn, br *bufio.Reader, req *http.Request, id *identity.Identity, started time.Time) {
	for {
		if req.URL == nil || !req.URL.IsAbs() {
			writeStatus(conn, http.StatusBadRequest,
				"this is a forward proxy: send an absolute-form request or CONNECT")
			return
		}

		keepAlive := s.relayPlainRequest(ctx, conn, req, id, started)
		if !keepAlive {
			return
		}

		_ = conn.SetReadDeadline(time.Now().Add(s.opts.IdleTimeout))
		next, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Time{})
		req = next
		started = time.Now()
	}
}

func (s *Server) relayPlainRequest(ctx context.Context, conn net.Conn, req *http.Request, id *identity.Identity, started time.Time) bool {
	host, port := splitTarget(req)
	if host == "" || port == 0 {
		writeStatus(conn, http.StatusBadRequest, "request URI has no usable host")
		return false
	}

	dec, err := s.opts.Engine.AuthorizeConnect(id, host, port)
	if err != nil {
		s.internalError(conn, id, req.Method, host, port, err, started)
		return false
	}
	if !dec.Allowed {
		metrics.Requests.WithLabelValues(id.Namespace, string(audit.DecisionDenyPolicy), string(v1alpha1.TLSModeTunnel)).Inc()
		s.audit(id, conn, audit.Record{
			Method: req.Method, Scheme: "http", Host: host, Port: port,
			Decision: audit.DecisionDenyPolicy, Reason: dec.Reason, Duration: time.Since(started),
		})
		writeStatus(conn, http.StatusForbidden, fmt.Sprintf(
			"proxy-relay-control denied %s:%d for %s/%s: %s", host, port, id.Namespace, id.Pod, dec.Reason))
		return false
	}

	target := req.URL.RequestURI()
	upgrade := isUpgrade(req)
	rdec, err := s.opts.Engine.AuthorizeRequest(dec, req.Method, target, upgrade)
	if err != nil {
		s.internalError(conn, id, req.Method, host, port, err, started)
		return false
	}
	path, _ := policy.NormalizePath(target)
	if !rdec.Allowed {
		metrics.Requests.WithLabelValues(id.Namespace, string(audit.DecisionDenyPolicy), string(v1alpha1.TLSModeTunnel)).Inc()
		s.audit(id, conn, audit.Record{
			Method: req.Method, Scheme: "http", Host: host, Port: port, Path: path,
			Policy:   firstPolicy(dec),
			Decision: audit.DecisionDenyPolicy, Reason: rdec.Reason, Duration: time.Since(started),
		})
		drained := drain(req)
		_ = writeDeniedRequest(conn, http.StatusForbidden, fmt.Sprintf(
			"proxy-relay-control denied %s %s for %s/%s: %s", req.Method, req.URL, id.Namespace, id.Pod, rdec.Reason))
		return !req.Close && drained
	}

	profile, err := s.opts.Engine.Upstream(rdec.Upstream)
	if err != nil {
		s.dialFailure(conn, id, req.Method, dec, err, started)
		return false
	}
	if s.opts.Guard != nil {
		if _, err := s.opts.Guard.Resolve(ctx, host); err != nil {
			s.dialFailure(conn, id, req.Method, dec, err, started)
			return false
		}
	}

	// Plain HTTP is forwarded in absolute form to the corporate proxy, which is
	// what an explicit proxy expects and what keeps its own logging intact. The
	// upstream connection is not pooled: a fresh one per request costs little on
	// this path and keeps one tenant's request from ever riding another's socket.
	upConn, proxyAuth, err := s.opts.Dialer.DialForward(ctx, profile)
	if err != nil {
		s.dialFailure(conn, id, req.Method, dec, err, started)
		return false
	}
	defer upConn.Close()

	outReq := req.Clone(ctx)
	outReq.RequestURI = ""
	stripHopByHop(outReq.Header)
	if proxyAuth != "" {
		outReq.Header.Set("Proxy-Authorization", proxyAuth)
	}
	if upgrade {
		outReq.Header.Set("Connection", "Upgrade")
		outReq.Header.Set("Upgrade", req.Header.Get("Upgrade"))
	}

	if err := outReq.WriteProxy(upConn); err != nil {
		s.dialFailure(conn, id, req.Method, dec, err, started)
		return false
	}

	upReader := bufio.NewReader(upConn)
	resp, err := http.ReadResponse(upReader, outReq)
	if err != nil {
		metrics.UpstreamErrors.WithLabelValues(rdec.Upstream, "roundtrip").Inc()
		s.audit(id, conn, audit.Record{
			Method: req.Method, Scheme: "http", Host: host, Port: port, Path: path,
			Policy: rdec.Policy, Rule: rdec.Rule, Upstream: rdec.Upstream,
			Decision: audit.DecisionErrorUpstream, Reason: err.Error(), Duration: time.Since(started),
		})
		writeStatus(conn, http.StatusBadGateway, "upstream request failed: "+err.Error())
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusSwitchingProtocols {
		if err := resp.Write(conn); err == nil {
			splice(conn, &readerConn{Conn: upConn, r: upReader}, s.opts.IdleTimeout)
		}
		return false
	}

	headers := resp.Header.Clone()
	stripHopByHop(headers)
	resp.Header = headers
	written, err := writeCounted(conn, resp)

	metrics.Requests.WithLabelValues(id.Namespace, string(audit.DecisionAllow), string(v1alpha1.TLSModeTunnel)).Inc()
	metrics.BytesRelayed.WithLabelValues(id.Namespace, "down").Add(float64(written))
	s.audit(id, conn, audit.Record{
		Method: req.Method, Scheme: "http", Host: host, Port: port, Path: path,
		Policy: rdec.Policy, Rule: rdec.Rule, Upstream: rdec.Upstream,
		UpstreamStatus: resp.Status,
		Decision:       audit.DecisionAllow, Reason: rdec.Reason,
		BytesDown: written, Duration: time.Since(started),
	})
	if err != nil {
		return false
	}
	return !resp.Close && !req.Close
}

// writeCounted writes a response and reports how many bytes reached the client.
func writeCounted(w io.Writer, resp *http.Response) (int64, error) {
	counter := &writeCounter{w: w}
	err := resp.Write(counter)
	return counter.n, err
}

type writeCounter struct {
	w io.Writer
	n int64
}

func (c *writeCounter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

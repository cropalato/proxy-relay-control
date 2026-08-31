package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	v1alpha1 "github.com/cropalato/proxy-relay-control/api/v1alpha1"
	"github.com/cropalato/proxy-relay-control/internal/audit"
	"github.com/cropalato/proxy-relay-control/internal/identity"
	"github.com/cropalato/proxy-relay-control/internal/metrics"
	"github.com/cropalato/proxy-relay-control/internal/policy"
	"github.com/cropalato/proxy-relay-control/internal/upstream"
)

// hopByHopHeaders are removed in both directions. Forwarding them would let a
// client's connection-management headers leak into the relay's own upstream
// connection, which is pooled and shared.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// handleInspect terminates TLS so that path and method rules can be applied.
//
// The corporate proxy is not contacted until a request has been authorized: a
// denied request should never appear in the corporate proxy's logs, and opening
// a tunnel for one would put it there.
func (s *Server) handleInspect(ctx context.Context, client net.Conn, dec *policy.ConnectDecision, id *identity.Identity, started time.Time) {
	if s.opts.Issuer == nil {
		s.internalError(client, id, http.MethodConnect, dec.Host, dec.Port,
			errors.New("TLS inspection requested but no CA is configured"), started)
		return
	}

	counted := &countingConn{Conn: client}
	if _, err := io.WriteString(counted, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}

	metrics.ActiveConnections.WithLabelValues(string(v1alpha1.TLSModeInspect)).Inc()
	defer metrics.ActiveConnections.WithLabelValues(string(v1alpha1.TLSModeInspect)).Dec()

	tlsConn := tls.Server(counted, s.opts.Issuer.ServerConfig(dec.Host))
	hsCtx, cancel := context.WithTimeout(ctx, s.opts.HandshakeTimeout)
	err := tlsConn.HandshakeContext(hsCtx)
	cancel()
	if err != nil {
		// The overwhelmingly common cause is a client that does not trust the relay
		// CA, so name that first; it saves a round of guessing.
		s.audit(id, client, audit.Record{
			Method: http.MethodConnect, Host: dec.Host, Port: dec.Port,
			TLSMode: string(v1alpha1.TLSModeInspect), Policy: firstPolicy(dec),
			Decision: audit.DecisionErrorInternal,
			Reason:   fmt.Sprintf("client TLS handshake failed (does the workload trust the relay CA?): %v", err),
			Duration: time.Since(started),
		})
		return
	}
	defer tlsConn.Close()

	s.serveBumped(ctx, tlsConn, counted, dec, id)

	metrics.BytesRelayed.WithLabelValues(id.Namespace, "up").Add(float64(counted.read.Load()))
	metrics.BytesRelayed.WithLabelValues(id.Namespace, "down").Add(float64(counted.written.Load()))
}

func (s *Server) serveBumped(ctx context.Context, tlsConn *tls.Conn, counted *countingConn, dec *policy.ConnectDecision, id *identity.Identity) {
	authority := net.JoinHostPort(dec.Host, strconv.Itoa(int(dec.Port)))
	// One reader for the life of the connection: a fresh one per request would
	// discard whatever the client pipelined behind the request just parsed.
	br := bufio.NewReader(tlsConn)

	for {
		_ = tlsConn.SetReadDeadline(time.Now().Add(s.opts.IdleTimeout))
		req, err := readBumpedRequest(br)
		if err != nil {
			return
		}
		_ = tlsConn.SetReadDeadline(time.Time{})

		reqStart := time.Now()
		target := req.RequestURI
		upgrade := isUpgrade(req)

		rdec, err := s.opts.Engine.AuthorizeRequest(dec, req.Method, target, upgrade)
		if err != nil {
			s.auditBumped(id, dec, req, target, audit.DecisionErrorInternal, err.Error(), rdec, counted, reqStart)
			_ = writeDeniedRequest(tlsConn, http.StatusInternalServerError, "policy evaluation failed")
			return
		}
		if !rdec.Allowed {
			metrics.Requests.WithLabelValues(id.Namespace, string(audit.DecisionDenyPolicy), string(v1alpha1.TLSModeInspect)).Inc()
			s.auditBumped(id, dec, req, target, audit.DecisionDenyPolicy, rdec.Reason, rdec, counted, reqStart)
			// Draining the body keeps the connection usable: clients pipeline many
			// URLs over one connection, and tearing it down on the first denial
			// would fail the requests that policy actually allows.
			drained := drain(req)
			if err := writeDeniedRequest(tlsConn, http.StatusForbidden, fmt.Sprintf(
				"proxy-relay-control denied %s https://%s%s for %s/%s: %s",
				req.Method, dec.Host, target, id.Namespace, id.Pod, rdec.Reason)); err != nil {
				return
			}
			if req.Close || !drained {
				return
			}
			continue
		}

		keepAlive, err := s.forwardBumped(ctx, tlsConn, req, rdec, dec, authority, upgrade)
		metrics.Requests.WithLabelValues(id.Namespace, string(audit.DecisionAllow), string(v1alpha1.TLSModeInspect)).Inc()
		if err != nil {
			s.auditBumped(id, dec, req, target, audit.DecisionErrorUpstream, err.Error(), rdec, counted, reqStart)
			return
		}
		s.auditBumped(id, dec, req, target, audit.DecisionAllow, rdec.Reason, rdec, counted, reqStart)
		if !keepAlive {
			return
		}
	}
}

// readBumpedRequest reads one request from an inspected connection. Requests in
// absolute form are refused: inside a tunnel the authority is already fixed by
// CONNECT, and honouring a second one would let a client be authorized for one
// host and served by another.
func readBumpedRequest(br *bufio.Reader) (*http.Request, error) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, err
	}
	if req.URL != nil && req.URL.IsAbs() {
		return nil, errors.New("proxy: absolute-form request inside a tunnel")
	}
	return req, nil
}

func (s *Server) forwardBumped(ctx context.Context, client net.Conn, req *http.Request, rdec *policy.RequestDecision, dec *policy.ConnectDecision, authority string, upgrade bool) (bool, error) {
	transport, err := s.transportFor(rdec.Upstream)
	if err != nil {
		_ = writeDeniedRequest(client, http.StatusBadGateway, err.Error())
		return false, err
	}

	outURL := &url.URL{Scheme: "https", Host: authority, Opaque: ""}
	parsed, err := url.ParseRequestURI(req.RequestURI)
	if err != nil {
		_ = writeDeniedRequest(client, http.StatusBadRequest, "malformed request target")
		return false, err
	}
	outURL.Path = parsed.Path
	outURL.RawPath = parsed.RawPath
	outURL.RawQuery = parsed.RawQuery

	outReq := req.Clone(ctx)
	outReq.URL = outURL
	outReq.RequestURI = ""
	outReq.Host = req.Host
	if outReq.Host == "" {
		outReq.Host = dec.Host
	}
	stripHopByHop(outReq.Header)
	if upgrade {
		// A permitted upgrade must keep its negotiation headers, which are
		// hop-by-hop by definition.
		outReq.Header.Set("Connection", "Upgrade")
		outReq.Header.Set("Upgrade", req.Header.Get("Upgrade"))
	}

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		metrics.UpstreamErrors.WithLabelValues(rdec.Upstream, "roundtrip").Inc()
		_ = writeDeniedRequest(client, http.StatusBadGateway, "upstream request failed: "+err.Error())
		return false, err
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		return false, s.spliceUpgrade(client, resp)
	}
	defer resp.Body.Close()

	respHeaders := resp.Header.Clone()
	stripHopByHop(respHeaders)
	resp.Header = respHeaders

	if err := resp.Write(client); err != nil {
		return false, err
	}
	return !resp.Close && !req.Close, nil
}

// spliceUpgrade hands the connection over after a permitted protocol upgrade.
// Path rules stop applying at this point, which is why allowUpgrade has to be
// set explicitly in policy.
func (s *Server) spliceUpgrade(client net.Conn, resp *http.Response) error {
	body, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		resp.Body.Close()
		_ = writeDeniedRequest(client, http.StatusBadGateway, "upstream upgrade is not splittable")
		return errors.New("proxy: upgraded response body is not writable")
	}
	defer body.Close()

	if err := resp.Write(client); err != nil {
		return err
	}
	// resp.Write does not copy the upgraded stream; splice it by hand.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(body, client)
	}()
	_, _ = io.Copy(client, body)
	<-done
	return nil
}

// transportFor returns the pooled transport for an upstream profile.
//
// Pooling is per profile so that a connection opened under one tenant's
// credentials is never reused for another. The profile is looked up at dial time
// rather than captured, so credential and URL changes take effect on the next
// new connection without a restart.
func (s *Server) transportFor(profileName string) (*http.Transport, error) {
	if v, ok := s.transports.Load(profileName); ok {
		return v.(*http.Transport), nil
	}
	if _, err := s.opts.Engine.Upstream(profileName); err != nil {
		return nil, err
	}

	transport := &http.Transport{
		// The relay parses HTTP/1.1 itself in order to enforce path rules; letting
		// the upstream leg negotiate h2 would not change what the client sees but
		// would add a protocol the audit path has never been tested against.
		ForceAttemptHTTP2:     false,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return s.dialOriginTLS(ctx, profileName, addr)
		},
	}
	actual, _ := s.transports.LoadOrStore(profileName, transport)
	return actual.(*http.Transport), nil
}

// dialOriginTLS opens the origin leg: through the corporate proxy, then a fully
// verified TLS handshake with the origin itself. Verification is not optional
// here — an intercepting proxy that skips it turns every inspected destination
// into an unauthenticated one.
func (s *Server) dialOriginTLS(ctx context.Context, profileName, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("proxy: bad origin address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("proxy: bad origin port in %q: %w", addr, err)
	}

	profile, err := s.opts.Engine.Upstream(profileName)
	if err != nil {
		return nil, err
	}

	target := upstream.Target{Host: host, Port: int32(port)}
	if s.opts.Guard != nil {
		addrs, err := s.opts.Guard.Resolve(ctx, host)
		if err != nil {
			return nil, err
		}
		target.Addrs = addrs
	}

	raw, err := s.opts.Dialer.Dial(ctx, profile, target)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{}
	if s.opts.OriginTLSConfig != nil {
		cfg = s.opts.OriginTLSConfig.Clone()
	}
	cfg.ServerName = host
	cfg.NextProtos = []string{"http/1.1"}
	if cfg.MinVersion == 0 {
		cfg.MinVersion = tls.VersionTLS12
	}
	// Whatever else was configured, the origin is verified. An intercepting proxy
	// that skips this turns every inspected destination into an unauthenticated
	// one, with the client none the wiser because it trusts the relay CA.
	cfg.InsecureSkipVerify = false

	tlsConn := tls.Client(raw, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("proxy: TLS handshake with origin %s failed: %w "+
			"(if this destination pins certificates or requires a client certificate, set tlsMode: tunnel)", host, err)
	}
	return tlsConn, nil
}

func (s *Server) auditBumped(id *identity.Identity, dec *policy.ConnectDecision, req *http.Request, target string, decision audit.Decision, reason string, rdec *policy.RequestDecision, counted *countingConn, started time.Time) {
	path := target
	if normalized, err := policy.NormalizePath(target); err == nil {
		path = normalized
	}
	rec := audit.Record{
		Method: req.Method, Scheme: "https", Host: dec.Host, Port: dec.Port, Path: path,
		TLSMode:  string(v1alpha1.TLSModeInspect),
		Decision: decision, Reason: reason,
		BytesUp:   counted.read.Load(),
		BytesDown: counted.written.Load(),
		Duration:  time.Since(started),
	}
	if rdec != nil {
		rec.Policy = rdec.Policy
		rec.Rule = rdec.Rule
		rec.Upstream = rdec.Upstream
	}
	if rec.Policy == "" {
		rec.Policy = firstPolicy(dec)
	}
	s.audit(id, nil, rec)
}

func stripHopByHop(h http.Header) {
	// Anything named in Connection is hop-by-hop for this message.
	for _, name := range strings.Split(h.Get("Connection"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			h.Del(name)
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

func isUpgrade(req *http.Request) bool {
	if req.Header.Get("Upgrade") == "" {
		return false
	}
	for _, token := range strings.Split(req.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
			return true
		}
	}
	return false
}

// drainLimit bounds how much of a denied request's body the relay will read to
// keep a connection usable. An unauthorized client must not be able to make the
// relay consume an unbounded body just by being denied.
const drainLimit = 1 << 20

// drain discards the body of a denied request and reports whether the whole of
// it was consumed. A body left half-read desynchronises the connection: the
// remainder would be parsed as the next request line. Callers that get false
// must close rather than continue.
func drain(req *http.Request) bool {
	if req.Body == nil {
		return true
	}
	defer req.Body.Close()
	n, err := io.Copy(io.Discard, io.LimitReader(req.Body, drainLimit+1))
	if err != nil {
		return false
	}
	return n <= drainLimit
}

// Package proxy is the relay's data plane: it accepts explicit-proxy
// connections from tenant workloads, authorizes them, and relays them through
// the corporate proxy under the credentials of the policy that allowed them.
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	v1alpha1 "github.com/cropalato/proxy-relay-control/api/v1alpha1"
	"github.com/cropalato/proxy-relay-control/internal/audit"
	"github.com/cropalato/proxy-relay-control/internal/guard"
	"github.com/cropalato/proxy-relay-control/internal/identity"
	"github.com/cropalato/proxy-relay-control/internal/metrics"
	"github.com/cropalato/proxy-relay-control/internal/policy"
	"github.com/cropalato/proxy-relay-control/internal/tlsbump"
	"github.com/cropalato/proxy-relay-control/internal/upstream"
)

// Options configures a Server.
type Options struct {
	Identity identity.Provider
	Engine   *policy.Engine
	Guard    *guard.Guard
	Dialer   *upstream.Dialer
	Issuer   *tlsbump.Issuer
	Audit    *audit.Logger
	Log      *slog.Logger

	// HandshakeTimeout bounds reading a request line and completing TLS on an
	// inspected connection. It does not bound an established tunnel.
	HandshakeTimeout time.Duration
	// IdleTimeout closes tunnels with no traffic in either direction.
	IdleTimeout time.Duration

	// OriginTLSConfig is the base configuration for the origin leg of an
	// inspected connection. It exists so an operator can add an internal root for
	// destinations signed by a private CA; verification itself is never optional,
	// and InsecureSkipVerify is cleared when the config is used.
	OriginTLSConfig *tls.Config

	// ShutdownGrace bounds how long Serve waits for established tunnels after the
	// listener stops accepting. Long-lived tunnels are normal, so a relay that
	// waited for them unconditionally would never finish terminating.
	ShutdownGrace time.Duration

	// Ready gates serving on cache sync. Answering before policy is loaded would
	// deny every request, which reads to tenants as an outage rather than a
	// startup delay.
	Ready func() bool
}

// Server relays proxy connections.
type Server struct {
	opts Options
	log  *slog.Logger

	connMu sync.Mutex
	conns  map[net.Conn]struct{}

	// transports are keyed by upstream profile name. Sharing one per profile is
	// what keeps connection reuse working while ensuring a pooled connection is
	// never reused under another tenant's credentials.
	transports sync.Map
}

// New builds a Server.
func New(opts Options) (*Server, error) {
	if opts.Identity == nil || opts.Engine == nil || opts.Dialer == nil {
		return nil, errors.New("proxy: identity, engine and dialer are required")
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Audit == nil {
		opts.Audit = audit.New(opts.Log)
	}
	if opts.HandshakeTimeout <= 0 {
		opts.HandshakeTimeout = 30 * time.Second
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 5 * time.Minute
	}
	if opts.Ready == nil {
		opts.Ready = func() bool { return true }
	}
	return &Server{opts: opts, log: opts.Log, conns: make(map[net.Conn]struct{})}, nil
}

// Serve accepts connections until the listener fails or the context is done.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	var wg sync.WaitGroup

	go func() {
		<-ctx.Done()
		ln.Close()
		s.drain(&wg)
	}()

	defer wg.Wait()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return fmt.Errorf("proxy: accept: %w", err)
		}
		s.track(conn)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer s.untrack(conn)
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) track(conn net.Conn) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	s.conns[conn] = struct{}{}
}

func (s *Server) untrack(conn net.Conn) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	delete(s.conns, conn)
}

// drain gives established connections a bounded chance to finish, then closes
// them. Without the bound, a single idle tunnel would hold the process open past
// any termination grace period and the pod would be killed mid-shutdown anyway.
func (s *Server) drain(wg *sync.WaitGroup) {
	if s.opts.ShutdownGrace > 0 {
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
			return
		case <-time.After(s.opts.ShutdownGrace):
			s.log.Info("shutdown grace expired, closing established tunnels")
		}
	}

	s.connMu.Lock()
	defer s.connMu.Unlock()
	for conn := range s.conns {
		conn.Close()
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	started := time.Now()

	if !s.opts.Ready() {
		// 503 rather than a denial: the request may well be allowed, the relay just
		// cannot say yet.
		writeStatus(conn, http.StatusServiceUnavailable, "relay is still loading policy")
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(s.opts.HandshakeTimeout))
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		// A client that opened a connection and said nothing is routine; do not
		// audit it as a decision.
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	id, err := s.opts.Identity.Identify(ctx, conn.RemoteAddr())
	if err != nil {
		s.denyIdentity(conn, req, err, started)
		return
	}

	if req.Method == http.MethodConnect {
		s.handleConnect(ctx, conn, br, req, id, started)
		return
	}
	s.handlePlainHTTP(ctx, conn, br, req, id, started)
}

func (s *Server) denyIdentity(conn net.Conn, req *http.Request, err error, started time.Time) {
	kind := "unknown"
	switch {
	case errors.Is(err, identity.ErrHostNetwork):
		kind = "host_network"
	case errors.Is(err, identity.ErrAmbiguousClient):
		kind = "ambiguous"
	case errors.Is(err, identity.ErrUnknownClient):
		kind = "unknown_client"
	}
	metrics.IdentityFailures.WithLabelValues(kind).Inc()
	metrics.Requests.WithLabelValues("", string(audit.DecisionDenyIdentity), "").Inc()

	host, port := splitTarget(req)
	s.opts.Audit.Log(audit.Record{
		SourceIP: remoteIP(conn),
		Method:   req.Method,
		Host:     host,
		Port:     port,
		Decision: audit.DecisionDenyIdentity,
		Reason:   err.Error(),
		Duration: time.Since(started),
	})

	// The message names the source address deliberately: the usual cause is NAT
	// between the pod and the relay, and the observed address is the fact an
	// operator needs to see that.
	writeStatus(conn, http.StatusForbidden, fmt.Sprintf(
		"proxy-relay-control cannot identify the workload at %s: %v", remoteIP(conn), err))
}

// connectTarget resolves the destination and profile for an authorized request.
func (s *Server) resolveTarget(ctx context.Context, host string, port int32, upstreamName string) (*v1alpha1.UpstreamProxy, upstream.Target, error) {
	profile, err := s.opts.Engine.Upstream(upstreamName)
	if err != nil {
		return nil, upstream.Target{}, err
	}
	target := upstream.Target{Host: host, Port: port}
	if s.opts.Guard != nil {
		addrs, err := s.opts.Guard.Resolve(ctx, host)
		if err != nil {
			return nil, upstream.Target{}, err
		}
		target.Addrs = addrs
	}
	return profile, target, nil
}

// splitTarget extracts host and port from either a CONNECT target or an
// absolute-form request URI.
func splitTarget(req *http.Request) (string, int32) {
	raw := req.Host
	if req.Method != http.MethodConnect && req.URL != nil && req.URL.Host != "" {
		raw = req.URL.Host
	}
	if raw == "" {
		return "", 0
	}

	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		host = raw
		if req.Method == http.MethodConnect {
			// CONNECT without a port is malformed; report it as such rather than
			// guessing a port the client never asked for.
			return strings.TrimSuffix(host, ":"), 0
		}
		if req.URL != nil && req.URL.Scheme == "https" {
			return host, 443
		}
		return host, 80
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return host, 0
	}
	return host, int32(port)
}

func remoteIP(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}

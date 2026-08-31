# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- MIT license.

## [0.1.0] - 2026-08-31

Initial release.

### Added

#### Relay

- Explicit forward proxy (`CONNECT` and absolute-form HTTP) that authorizes
  Kubernetes workloads and relays their traffic through a corporate proxy using
  the credentials of the policy that allowed the request. The corporate proxy
  keeps its existing authentication model and gains per-tenant attribution,
  while no tenant ever holds a proxy credential.
- Workload identity from the connection's source address, resolved against pod
  IPs from the Kubernetes API. Host-network clients are refused explicitly
  rather than attributed to their node, and pod-IP reuse resolves in favour of
  the live pod.
- `EgressPolicy` and `UpstreamProxy` cluster-scoped CRDs. Policy is default
  deny; an absent namespace selector grants nothing.
- Per-tenant upstream credentials read from Secrets in the relay's own
  namespace. The namespace is pinned rather than taken from the reference, so a
  cluster-scoped object cannot point the relay at an arbitrary Secret.
- Destination guard that resolves each destination and refuses loopback,
  link-local (including the cloud metadata address), private ranges, and any
  operator-supplied CIDRs such as the cluster pod and service networks.
- Structured audit record per request, covering denials as well as allows, and
  Prometheus metrics broken down by tenant namespace.
- Graceful shutdown that stops accepting, then drains established tunnels within
  a bounded grace period.

#### Path and method rules

- `tlsMode: inspect` terminates TLS at the relay so that URL path and HTTP
  method rules can be enforced per request; `tlsMode: tunnel` (the default)
  splices bytes opaquely and authorizes host and port only. Plain `http://`
  requests get path rules with no interception at all.
- The origin leg of an inspected connection is always verified against system
  roots with hostname checking, and cannot be configured otherwise.
- Path normalization that resolves traversal and rejects anything the relay and
  the origin could read differently — double-encoded escapes, encoded path
  separators, control bytes — rather than rewriting it.
- Segment-aware prefix matching, so `/repos/team-a` does not match
  `/repos/team-ab`, plus `*` (within a segment) and `**` (across segments).
- Protocol upgrades are denied unless a rule opts in, because path rules stop
  being enforceable once a connection upgrades.
- Denied requests are refused before the corporate proxy is contacted, and a
  denial leaves a keep-alive connection usable for the requests that follow.

#### Certificate handling

- Relay CA held in a Secret, with short-lived leaf certificates minted per
  destination and cached.
- CA bundle published as a ConfigMap into exactly the namespaces selected by an
  inspect-mode policy, and removed when none selects them.
- Dual-CA rotation: the upcoming CA is published for trust before it signs
  anything, so a rotation does not break running workloads.

#### Operations

- `relay preflight`, run from inside a pod, reports whether the relay observes
  the pod's real address — the assumption pod-IP identity rests on, and the one
  that NAT silently breaks.
- `relay init-ca` generates a CA and prints the Secret rather than applying it,
  leaving the operator to decide where the key lands.
- Helm chart with namespaced Secret RBAC, NetworkPolicy, PodDisruptionBudget,
  ServiceMonitor, and readiness gated on cache sync.
- Distroless container image running as a non-root user with a read-only root
  filesystem.
- GitHub Actions running gofmt, `go vet`, the race-enabled test suite, a
  compile, `helm lint`, shellcheck and a container build on every push and pull
  request, plus a tag-triggered release that republishes the image to Docker Hub
  as `cropalato/proxy-relay-control`.
- End-to-end suite against a kind cluster, covering what unit tests cannot:
  identity through a real Service, RBAC, CA bundle scoping, and per-tenant
  attribution at the corporate proxy. It also runs in CI, where kind builds the
  cluster on the runner itself, and dumps relay logs and cluster state on
  failure.

### Known limitations

- Identity is pod-IP based. It depends on the CNI preventing source-address
  spoofing and on no NAT between the pod and the relay; `relay preflight` checks
  the latter. ServiceAccount-token and mTLS/SPIFFE providers fit the same
  interface and are the intended hardening path.
- The relay is only meaningful if tenants cannot reach the corporate proxy
  directly. That requires a cluster-level NetworkPolicy or firewall rule
  alongside the one shipped in the chart.
- Destinations that pin certificates or present client certificates to the
  origin cannot be inspected and must stay `tlsMode: tunnel`, which means host
  granularity only.
- HTTP/2 and HTTP/3 are not offered on the inspected client leg; ALPN is pinned
  to HTTP/1.1.

[Unreleased]: https://github.com/cropalato/proxy-relay-control/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/cropalato/proxy-relay-control/releases/tag/v0.1.0

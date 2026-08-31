# proxy-relay-control

[![CI](https://github.com/cropalato/proxy-relay-control/actions/workflows/ci.yml/badge.svg)](https://github.com/cropalato/proxy-relay-control/actions/workflows/ci.yml)
[![E2E](https://github.com/cropalato/proxy-relay-control/actions/workflows/e2e.yml/badge.svg)](https://github.com/cropalato/proxy-relay-control/actions/workflows/e2e.yml)
[![Docker Hub](https://img.shields.io/docker/v/cropalato/proxy-relay-control?label=docker&sort=semver)](https://hub.docker.com/r/cropalato/proxy-relay-control)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/cropalato/proxy-relay-control/blob/main/LICENSE)

An identity-aware egress relay for multi-tenant Kubernetes clusters that reach the
internet through a corporate forward proxy.

## The problem

On-prem clusters usually have exactly one way out: a corporate proxy that
authenticates its clients. That leaves two unappealing options.

- **Allow the node IPs on the proxy.** Every pod on every node gets internet
  access, and the proxy's logs attribute all of it to a node rather than a team.
- **Give each tenant a proxy username and password.** Unmanageable at
  namespace scale, and the credential ends up in manifests the tenant controls.

Host-level allowlists do not rescue the first option either. Once
`raw.githubusercontent.com` or a shared artifact host is allowed, it is
effectively the whole internet.

## What this does

Tenants point `http_proxy` at the relay. For each connection the relay:

1. **identifies** the calling workload from its pod IP via the Kubernetes API,
2. **authorizes** it against a cluster-scoped `EgressPolicy` — host, port, and
   optionally URL path and HTTP method,
3. **relays** the traffic to the corporate proxy using the credentials of the
   policy that allowed it.

The corporate proxy keeps its existing authentication model. It sees one client
presenting a different account per tenant, so its logs and quotas stay
attributable, and no tenant ever holds a proxy credential.

```
tenant pod ──http_proxy──▶ relay ──CONNECT + Proxy-Authorization──▶ corporate proxy ──▶ internet
                             │
                             ├─ identity: pod IP → namespace, pod, service account
                             ├─ policy:   EgressPolicy (host, port, path, method)
                             └─ credential: UpstreamProxy → Secret, per tenant
```

## Path rules and TLS

A `CONNECT` tunnel shows the relay a host and a port and nothing else, so path
rules require terminating TLS. That is opt-in per destination:

- `tlsMode: tunnel` (default) — bytes are spliced opaquely. Authorization is
  host and port only. Cert-pinned clients and client-certificate workloads keep
  working.
- `tlsMode: inspect` — TLS is terminated at the relay so path and method rules
  apply. Workloads must trust the relay CA, which the relay publishes as a
  ConfigMap into every namespace an inspect-mode policy selects.

The origin leg of an inspected connection is always verified normally, against
system roots with hostname checking. Interception never becomes a downgrade.

Plain `http://` requests carry their path in the clear, so path rules apply
there with no interception at all.

## Quick start

```sh
# 1. CRDs and the relay
helm install relay deploy/helm -n relay-system --create-namespace \
  --set denyCIDRs='{10.244.0.0/16,10.96.0.0/12}'   # your pod and service CIDRs

# 2. The corporate proxy account for one tenant
kubectl -n relay-system create secret generic corp-team-a \
  --from-literal=username=svc-team-a --from-literal=password='...'

# 3. The profile and the grant
kubectl apply -f deploy/examples/
```

Then, in a tenant pod:

```sh
export http_proxy=http://relay.relay-system:3128
export https_proxy=$http_proxy
curl https://api.github.com/zen
```

## Before you trust pod-IP identity

Identity rests on the relay seeing the client's real pod IP. Check it:

```sh
kubectl run preflight --rm -it --image=cropalato/proxy-relay-control:0.1.0 \
  --env POD_IP=... -- preflight --url http://relay.relay-system:9090
```

A mismatch means something is rewriting the source address — `kube-proxy
--masquerade-all`, a CNI masquerade rule, or a `hostNetwork` client. See
[docs/operations.md](https://github.com/cropalato/proxy-relay-control/blob/main/docs/operations.md).

## Documentation

- [docs/policy.md](https://github.com/cropalato/proxy-relay-control/blob/main/docs/policy.md) — writing `EgressPolicy` and `UpstreamProxy`
- [docs/onboarding.md](https://github.com/cropalato/proxy-relay-control/blob/main/docs/onboarding.md) — what a tenant has to do
- [docs/operations.md](https://github.com/cropalato/proxy-relay-control/blob/main/docs/operations.md) — CA rotation, preflight, troubleshooting
- [docs/testing.md](https://github.com/cropalato/proxy-relay-control/blob/main/docs/testing.md) — the end-to-end suite

## Status

v0.1.0. Identity is pod-IP based; ServiceAccount-token and mTLS/SPIFFE providers
fit the same interface and are the intended hardening path.

Images are published to [Docker Hub](https://hub.docker.com/r/cropalato/proxy-relay-control)
as `cropalato/proxy-relay-control`.

## License

[MIT](https://github.com/cropalato/proxy-relay-control/blob/main/LICENSE).

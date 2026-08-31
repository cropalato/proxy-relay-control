# Operations

## Preflight: does the relay see real pod IPs?

v1 identity is the connection's source address, matched against pod IPs from the
API server. That holds only while two things are true:

1. Nothing NATs traffic between the pod and the relay.
2. The CNI stops pods from spoofing source addresses (Calico and Cilium do).

The first is worth checking on every cluster before trusting the relay:

```sh
kubectl run preflight --rm -it --restart=Never \
  --image=cropalato/proxy-relay-control:0.1.0 \
  --overrides='{"spec":{"containers":[{"name":"preflight","image":"cropalato/proxy-relay-control:0.1.0","args":["preflight","--url","http://relay.relay-system:9090"],"env":[{"name":"POD_IP","valueFrom":{"fieldRef":{"fieldPath":"status.podIP"}}}]}]}}'
```

A mismatch means the relay will attribute traffic to a node rather than a
workload, and refuse it. Usual causes:

- `kube-proxy` running with `--masquerade-all`
- a CNI masquerade rule covering traffic to the relay's Service
- the client pod using `hostNetwork`, which has no address of its own — these are
  refused explicitly rather than guessed at

## Making the relay unavoidable

The relay is only meaningful if tenants cannot route around it. Two controls:

- A cluster-level `NetworkPolicy` (or firewall rule) that stops tenant pods from
  reaching the corporate proxy directly.
- The chart's `NetworkPolicy`, which limits who may reach the relay's proxy port.

Without the first, a tenant that discovers the corporate proxy's address and any
credential bypasses every policy in this system.

## CA rotation

Only relevant if any policy uses `tlsMode: inspect`.

The bundle published to tenants can hold two CAs. Publishing the next one before
signing with it is the whole point: swapping a single CA in place breaks every
running tenant pod at the same instant, because nothing reloads a trust store on
its own.

**Step 1 — publish the upcoming CA.**

```sh
relay init-ca --next            # prints next-ca.crt and holds back its key
kubectl -n relay-system patch secret relay-ca --type merge \
  -p '{"data":{"next-ca.crt":"<base64>"}}'
```

Within `--ca-sync-interval` (30s by default) the relay picks up the change and
the CA bundle ConfigMap in every inspected namespace grows to two certificates.

**Step 2 — wait for propagation.** Tenant pods read the bundle at start, so wait
for a full restart cycle, or long enough that you are willing to restart the
stragglers. Nothing is signed by the new CA yet, so there is no deadline.

**Step 3 — switch signing.** Move the new material into `ca.crt`/`ca.key` and
drop `next-ca.crt`. The relay reloads within the sync interval and existing
tunnels are unaffected; cached leaves signed by the old CA are discarded on next
use.

## Reading the audit log

One structured record per relayed request, on the `audit` stream. Denials are
logged at `warn`, so tailing warnings shows tenant failures without turning on
debug logging.

```json
{"level":"INFO","stream":"audit","msg":"egress","decision":"allow",
 "namespace":"team-a","pod":"builder-0","service_account":"builder",
 "method":"GET","host":"artifacts.corp.example","port":443,
 "path":"/repos/team-a/index.json","tls_mode":"inspect",
 "policy":"team-a","rule":"/repos/team-a","upstream":"corp-team-a"}
```

Tunnelled records carry **no** `path` field. That absence is meaningful: it says
the destination was authorized at host granularity only, and it is the signal to
look at when deciding what to move to `tlsMode: inspect`.

Decisions: `allow`, `deny_policy`, `deny_identity`, `deny_guard`,
`deny_malformed`, `error_upstream`, `error_internal`.

## Metrics

| Metric | Use |
| --- | --- |
| `relay_requests_total{namespace,decision,tls_mode}` | which tenant is being denied |
| `relay_upstream_errors_total{upstream,kind}` | `kind="auth"` means a relay credential is wrong |
| `relay_identity_failures_total{kind}` | a rising `unknown_client` usually means NAT appeared |
| `relay_active_connections{tls_mode}` | tunnel load |
| `relay_bytes_total{namespace,direction}` | per-tenant traffic |
| `relay_leaf_certs_total{result}` | inspect-mode certificate cache behaviour |

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| Every request 403s with "no EgressPolicy selects namespace" | the namespace lacks the label the policy selects on |
| 403 "cannot identify the workload at `<ip>`" where `<ip>` is a node | NAT between pod and relay; run preflight |
| 403 on one URL, allowed on another for the same host | working as intended — an inspect-mode path rule |
| 502 "the corporate proxy rejected this relay's credentials" | the profile's Secret is wrong; a trailing newline in the password is the usual cause |
| TLS handshake failures only on inspected hosts | tenants do not trust the relay CA, or the destination pins certificates |
| Readiness never passes | the watch caches are not syncing; check RBAC on pods, namespaces and the CRDs |

## Shutdown

On `SIGTERM` the relay stops accepting, then waits `--shutdown-grace` for
established tunnels before closing them. Set `terminationGracePeriodSeconds`
above that value; the chart does. Long-lived tunnels are normal, so the wait is
bounded — a relay that waited for them unconditionally would never terminate.

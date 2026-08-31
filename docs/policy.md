# Writing policy

Both kinds are cluster-scoped and belong to the platform team. **Do not grant
tenants write access to `EgressPolicy`** — the policy *is* the grant, so a tenant
who can create one can authorize their own egress.

## UpstreamProxy

A profile is a corporate proxy plus the credentials the relay presents to it.
Several profiles may point at the same proxy with different accounts; that is how
per-tenant attribution is produced in the corporate proxy's logs.

```yaml
apiVersion: relay.cropalato.io/v1alpha1
kind: UpstreamProxy
metadata:
  name: corp-team-a
spec:
  url: http://corp-proxy.internal:3128
  credentialsSecretRef:
    name: corp-team-a
    namespace: relay-system      # must be the relay's own namespace
```

The Secret namespace is pinned to the relay's namespace regardless of what the
reference says. An unpinned reference would let anyone able to edit a cluster-
scoped object point the relay at an arbitrary Secret and have its contents sent
to a proxy of their choosing.

Omit `credentialsSecretRef` for an unauthenticated parent proxy. Use `noProxy`
for destinations the relay should dial itself:

```yaml
  noProxy: [".internal.corp", "*.svc.cluster.local"]
```

## EgressPolicy

```yaml
apiVersion: relay.cropalato.io/v1alpha1
kind: EgressPolicy
metadata:
  name: team-a
spec:
  selector:
    namespaceSelector:
      matchLabels:
        tenant: team-a
  upstreamRef:
    name: corp-team-a
  destinations:
    - host: "*.github.com"
      ports: [443]

    - host: artifacts.corp.example
      ports: [443]
      tlsMode: inspect
      paths:
        - path: /repos/team-a
          methods: [GET, HEAD]
        - path: /v2/*/blobs/**
          methods: [GET]
```

### Selectors

`namespaceSelector` is required in practice: **omitting it grants nothing**. An
accidentally empty spec should authorize no egress rather than all of it, so
"every namespace" has to be written explicitly as `namespaceSelector: {}`.

`podSelector` narrows further within the selected namespaces.

### Host patterns

| Pattern | Matches | Does not match |
| --- | --- | --- |
| `api.example.com` | `api.example.com` | anything else |
| `*.example.com` | `api.example.com` | `a.b.example.com`, `example.com` |
| `**.example.com` | `api.example.com`, `a.b.example.com` | `example.com` |
| `*` | any host | — |

Single-label `*.` is the default because `*.example.com` silently granting
`evil.cdn.example.com` surprises most authors.

`ports` defaults to `[80, 443]`.

### Path rules

Path rules require `tlsMode: inspect` on an `https://` destination; the CRD
rejects them on a tunnelled one, because rules that are never evaluated read as
enforced. They apply to plain `http://` destinations without any interception.

- A pattern without wildcards is a **segment-aware prefix**: `/repos/team-a`
  matches `/repos/team-a/x` but never `/repos/team-ab`.
- `exact: true` requires equality.
- `*` matches within one path segment; `**` matches across segments.
- `methods` is empty for "any method".
- `allowUpgrade` is off by default. Once a connection upgrades (WebSocket), the
  relay can no longer see requests, so path rules stop being enforceable —
  permitting that has to be deliberate.
- A destination with **no** `paths` grants the whole host.

Paths are normalized before matching, and anything the relay and the origin
could read differently is refused outright rather than rewritten:

| Input | Result |
| --- | --- |
| `/repos/team-a/../team-b` | normalized to `/repos/team-b`, then matched |
| `/repos/team-a/%2e%2e/team-b` | same |
| `/repos/%252e%252e/team-b` | rejected — double-encoded |
| `/repos%2fteam-b` | rejected — encoded path separator |
| `/a;v=1/b` | parameters stripped, matched as `/a/b` |
| `/a//b` | collapsed to `/a/b` |

### Overlapping policies

Grants are additive. Every policy selecting a workload contributes its matching
destinations, and a request is allowed if any rule allows it. The upstream
profile used is the one belonging to the policy whose rule matched, so the
corporate proxy attributes the request to the tenant that was actually granted
it. If any matching destination asks for `inspect`, the connection is inspected.

## Denials

Every denial names the namespace, the destination and the reason, in the response
body and in an `X-Relay-Reason` header. A `403` is a policy decision; a `502` is
the relay's own problem (a rejected relay credential, an unreachable corporate
proxy, a missing `UpstreamProxy`) and is never the tenant's to fix.

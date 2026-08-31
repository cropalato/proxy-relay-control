# Testing

## Unit and integration

```sh
make test
```

Go tests cover the parts where a mistake is a security bug rather than a bug:

- **Path normalization** (`internal/policy`) — traversal, encoded traversal,
  double encoding, encoded separators, path parameters, prefix boundaries.
- **Matching** — host globs, port defaults, segment-aware prefixes, wildcards,
  case-insensitive methods.
- **Policy evaluation** — default deny, an empty selector granting nothing,
  per-rule attribution, upgrades requiring an explicit opt-in.
- **The relay itself** (`internal/proxy`) — a full in-process stack with a fake
  corporate proxy and a real TLS origin, asserting that allowed requests carry
  the tenant's credentials, that denied ones never reach the corporate proxy at
  all, that a denial leaves a keep-alive connection usable, that the origin is
  verified even under interception, and that a rejected relay credential
  surfaces as 502 rather than 403.
- **Certificate handling** (`internal/tlsbump`) — leaves verify against the CA
  and only for their own hostname, the cache is bounded, and a rotation
  invalidates leaves signed by the previous CA while the bundle carries both.

## End-to-end

```sh
make e2e            # or: KEEP=1 ./hack/e2e.sh
```

Requires `kind`, `kubectl`, `helm`, `docker` and `openssl`. It builds the image,
creates a cluster, and stands up a stand-in corporate proxy
(`hack/testproxy.py`) plus an nginx origin with a certificate from a throwaway
CA. `KEEP=1` leaves the cluster running for inspection.

### In CI

The suite runs on every push and pull request via the `E2E` workflow. No
external or publicly reachable cluster is involved: kind builds the cluster out
of containers on the GitHub runner's own Docker daemon, and the runner is
discarded afterwards. The runner image already provides docker, kubectl, helm
and openssl, so the workflow only installs kind.

The workflow keeps the cluster alive on failure and dumps pods, relay logs,
corporate proxy logs, policy objects and events. The relay explains every
denial in its audit log, which is the quickest way to tell a real regression
from a broken fixture when you cannot reach the cluster yourself.

It asserts what only a real cluster can show:

| Assertion | What it proves |
| --- | --- |
| team-a reaches an allowed path | the whole chain works end to end |
| team-a is denied another tenant's path | path rules survive a real TLS handshake |
| prefix boundaries are respected | `/repos/team-ab` is not `/repos/team-a` |
| a disallowed method is refused | method rules apply per request |
| traversal cannot escape the grant | normalization runs on real client input |
| a host outside the policy is refused | host matching, not just path matching |
| a namespace with no policy is refused | default deny across namespaces |
| a denial leaves the connection usable | keep-alive isolation |
| the CA bundle is published to team-a, not team-b | the controller scopes interception correctly |
| the corporate proxy sees `svc-team-a` | per-tenant attribution, the point of the project |
| denied requests never reach the corporate proxy | authorization happens before the second leg |
| preflight confirms the relay sees pod IPs | no NAT between pods and the relay |

The e2e run turns off the guard's private-range denials, because in a test
cluster both the origin and the corporate proxy are on private addresses. A real
deployment leaves them on and adds its pod and service CIDRs.

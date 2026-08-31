#!/usr/bin/env bash
# End-to-end suite for proxy-relay-control against a kind cluster.
#
# What it proves that the Go tests cannot: that identity works from real pod IPs
# through a real Service, that RBAC is sufficient, that the CA bundle reaches the
# namespaces that need it and no others, and that the corporate proxy sees a
# different account per tenant.
set -euo pipefail

CLUSTER="${CLUSTER:-proxy-relay-e2e}"
IMAGE="${IMAGE:-cropalato/proxy-relay-control}"
TAG="${TAG:-e2e}"
KEEP="${KEEP:-0}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"

# kind switches the current kubeconfig context on create and unsets it on
# delete. Every command here is pinned to the kind context anyway, so restore
# whatever the operator had selected rather than leaving them pointed at
# nothing — or, worse, at a cluster they did not expect.
PREV_CONTEXT="$(kubectl config current-context 2>/dev/null || true)"
restore_context() {
  [[ -n "$PREV_CONTEXT" ]] || return 0
  command kubectl config use-context "$PREV_CONTEXT" >/dev/null 2>&1 || true
}
trap 'rm -rf "$WORK"; [[ "$KEEP" == 1 ]] || kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true; restore_context' EXIT

PASS=0
FAIL=0

info() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }

need() { command -v "$1" >/dev/null || { echo "missing required tool: $1" >&2; exit 1; }; }
need kind; need kubectl; need helm; need docker; need openssl

# Every cluster operation is pinned to the kind context. Relying on whatever
# kubeconfig context happens to be current would let a stray run create CRDs,
# ClusterRoles and namespaces on a real cluster.
KCTX="kind-${CLUSTER}"
kubectl() { command kubectl --context "$KCTX" "$@"; }

kexec() { # kexec <namespace> <pod> <command...>
  local ns=$1 pod=$2; shift 2
  kubectl -n "$ns" exec "$pod" -- "$@" 2>/dev/null
}

# status <namespace> <pod> <url> [curl args...] -> prints the HTTP status code
status() {
  local ns=$1 pod=$2 url=$3; shift 3
  local got
  # curl already prints 000 when it cannot connect; the fallback is only for the
  # case where exec itself failed and printed nothing.
  got="$(kexec "$ns" "$pod" curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$@" "$url")" || true
  echo "${got:-000}"
}

connect_status() {
  local ns=$1 pod=$2 url=$3; shift 3
  local got
  got="$(kexec "$ns" "$pod" curl -s -o /dev/null -w '%{http_connect}' --max-time 15 "$@" "$url")" || true
  echo "${got:-000}"
}

expect_connect() { # expect_connect <want> <description> <namespace> <pod> <url> [curl args...]
  local want=$1 desc=$2; shift 2
  local got; got="$(connect_status "$@")"
  if [[ "$got" == "$want" ]]; then ok "$desc (CONNECT $got)"; else bad "$desc: got CONNECT $got, want $want"; fi
}

expect_status() { # expect_status <want> <description> <namespace> <pod> <url> [curl args...]
  local want=$1 desc=$2; shift 2
  local got; got="$(status "$@")"
  if [[ "$got" == "$want" ]]; then ok "$desc (HTTP $got)"; else bad "$desc: got HTTP $got, want $want"; fi
}

info "Creating kind cluster $CLUSTER"
kind get clusters 2>/dev/null | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER" --wait 120s
kubectl cluster-info >/dev/null

info "Building and loading the relay image"
docker build -q -t "$IMAGE:$TAG" "$ROOT" >/dev/null
kind load docker-image "$IMAGE:$TAG" --name "$CLUSTER" >/dev/null

info "Preparing namespaces"
kubectl create namespace relay-system --dry-run=client -o yaml | kubectl apply -f - >/dev/null
for tenant in team-a team-b; do
  kubectl create namespace "$tenant" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl label namespace "$tenant" "tenant=$tenant" --overwrite >/dev/null
done

info "Issuing a certificate for the test origin"
ORIGIN_HOST="origin.relay-system.svc.cluster.local"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj "/CN=e2e-origin-ca" -keyout "$WORK/ca.key" -out "$WORK/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=$ORIGIN_HOST" \
  -keyout "$WORK/origin.key" -out "$WORK/origin.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:%s,DNS:origin.relay-system\n' "$ORIGIN_HOST" > "$WORK/san.cnf"
openssl x509 -req -in "$WORK/origin.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" \
  -CAcreateserial -days 2 -extfile "$WORK/san.cnf" -out "$WORK/origin.crt" >/dev/null 2>&1

kubectl -n relay-system create secret tls origin-tls \
  --cert="$WORK/origin.crt" --key="$WORK/origin.key" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n relay-system create configmap origin-ca --from-file=ca.crt="$WORK/ca.crt" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

info "Deploying the stand-in corporate proxy and origin"
kubectl -n relay-system create configmap corp-proxy-src \
  --from-file=testproxy.py="$ROOT/hack/testproxy.py" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

cat > "$WORK/origin-nginx.conf" <<'CONF'
events {}
http {
  access_log /dev/stdout;
  server {
    listen 80;
    listen 443 ssl;
    ssl_certificate     /etc/origin-tls/tls.crt;
    ssl_certificate_key /etc/origin-tls/tls.key;
    location / { default_type text/plain; return 200 "origin $request_method $uri\n"; }
  }
}
CONF
kubectl -n relay-system create configmap origin-conf --from-file=nginx.conf="$WORK/origin-nginx.conf" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

kubectl apply -f - >/dev/null <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata: {name: corp-proxy, namespace: relay-system}
spec:
  replicas: 1
  selector: {matchLabels: {app: corp-proxy}}
  template:
    metadata: {labels: {app: corp-proxy}}
    spec:
      containers:
        - name: proxy
          image: python:3.12-alpine
          command: ["python3", "/src/testproxy.py"]
          ports: [{containerPort: 3128}, {containerPort: 3129}]
          volumeMounts: [{name: src, mountPath: /src}]
      volumes: [{name: src, configMap: {name: corp-proxy-src}}]
---
apiVersion: v1
kind: Service
metadata: {name: corp-proxy, namespace: relay-system}
spec:
  selector: {app: corp-proxy}
  ports:
    - {name: proxy, port: 3128, targetPort: 3128}
    - {name: audit, port: 3129, targetPort: 3129}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: origin, namespace: relay-system}
spec:
  replicas: 1
  selector: {matchLabels: {app: origin}}
  template:
    metadata: {labels: {app: origin}}
    spec:
      containers:
        - name: nginx
          image: nginx:alpine
          ports: [{containerPort: 80}, {containerPort: 443}]
          volumeMounts:
            - {name: conf, mountPath: /etc/nginx/nginx.conf, subPath: nginx.conf}
            - {name: tls, mountPath: /etc/origin-tls}
      volumes:
        - {name: conf, configMap: {name: origin-conf}}
        - {name: tls, secret: {secretName: origin-tls}}
---
apiVersion: v1
kind: Service
metadata: {name: origin, namespace: relay-system}
spec:
  selector: {app: origin}
  ports:
    - {name: http, port: 80, targetPort: 80}
    - {name: https, port: 443, targetPort: 443}
YAML

info "Restarting the origin so it picks up this run's certificate"
kubectl -n relay-system rollout restart deployment/origin >/dev/null
kubectl -n relay-system rollout status deployment/origin --timeout=120s >/dev/null

info "Creating per-tenant corporate proxy credentials"
kubectl -n relay-system create secret generic corp-team-a \
  --from-literal=username=svc-team-a --from-literal=password=pw-a \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n relay-system create secret generic corp-team-b \
  --from-literal=username=svc-team-b --from-literal=password=pw-b \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

info "Installing the relay"
# The origin and the corporate proxy are both inside the cluster, so the guard's
# private-range denials are turned off for this run. A real deployment leaves
# them on and adds its pod and service CIDRs.
helm upgrade --install relay "$ROOT/deploy/helm" -n relay-system \
  --kube-context "$KCTX" \
  --set "image.repository=$IMAGE" --set "image.tag=$TAG" \
  --set image.pullPolicy=IfNotPresent \
  --set replicaCount=1 \
  --set ca.autoInit=true \
  --set disableDefaultDenyCIDRs=true \
  --set originCA.configMapName=origin-ca \
  --set networkPolicy.enabled=false \
  --wait --timeout 180s >/dev/null

# The relay reads --origin-ca-file at startup, so a rerun with a new throwaway
# CA needs a restart even though the pod spec is unchanged.
kubectl -n relay-system rollout restart deployment/relay >/dev/null
kubectl -n relay-system rollout status deployment/relay --timeout=180s >/dev/null

info "Applying policy"
kubectl apply -f - >/dev/null <<YAML
apiVersion: relay.cropalato.io/v1alpha1
kind: UpstreamProxy
metadata: {name: corp-team-a}
spec:
  url: http://corp-proxy.relay-system:3128
  credentialsSecretRef: {name: corp-team-a, namespace: relay-system}
---
apiVersion: relay.cropalato.io/v1alpha1
kind: EgressPolicy
metadata: {name: team-a}
spec:
  selector:
    namespaceSelector:
      matchLabels: {tenant: team-a}
  upstreamRef: {name: corp-team-a}
  destinations:
    - host: $ORIGIN_HOST
      ports: [80, 443]
      tlsMode: inspect
      paths:
        - {path: /repos/team-a, methods: [GET, HEAD]}
YAML

info "Waiting for the CA bundle to reach team-a"
for _ in $(seq 1 30); do
  kubectl -n team-a get configmap relay-ca-bundle >/dev/null 2>&1 && break
  sleep 2
done

info "Starting tenant clients"
# Pod environment is immutable, so a rerun has to recreate the clients rather
# than apply over them.
kubectl -n team-a delete pod client --ignore-not-found --wait=true >/dev/null
kubectl -n team-b delete pod client --ignore-not-found --wait=true >/dev/null
kubectl apply -f - >/dev/null <<'YAML'
apiVersion: v1
kind: Pod
metadata: {name: client, namespace: team-a}
spec:
  containers:
    - name: curl
      image: curlimages/curl:latest
      command: ["sleep", "infinity"]
      env:
        # curl ignores SSL_CERT_FILE; it loads its own compiled-in CA bundle.
        - {name: CURL_CA_BUNDLE, value: /etc/relay-ca/ca.crt}
        - {name: SSL_CERT_FILE, value: /etc/relay-ca/ca.crt}
      volumeMounts: [{name: ca, mountPath: /etc/relay-ca, readOnly: true}]
  volumes: [{name: ca, configMap: {name: relay-ca-bundle}}]
---
apiVersion: v1
kind: Pod
metadata: {name: client, namespace: team-b}
spec:
  containers:
    - name: curl
      image: curlimages/curl:latest
      command: ["sleep", "infinity"]
YAML
kubectl -n team-a wait --for=condition=Ready pod/client --timeout=120s >/dev/null
kubectl -n team-b wait --for=condition=Ready pod/client --timeout=120s >/dev/null

PROXY="http://relay.relay-system:3128"
BASE="https://$ORIGIN_HOST"

info "Assertions"

expect_status 200 "team-a reaches an allowed path" \
  team-a client "$BASE/repos/team-a/index.json" -x "$PROXY"

expect_status 403 "team-a is denied another tenant's path" \
  team-a client "$BASE/repos/team-b/secret" -x "$PROXY"

expect_status 403 "prefix boundaries are respected" \
  team-a client "$BASE/repos/team-ab/index.json" -x "$PROXY"

expect_status 403 "a disallowed method is refused" \
  team-a client "$BASE/repos/team-a/index.json" -x "$PROXY" -X PUT

expect_status 403 "path traversal cannot escape the grant" \
  team-a client "$BASE/repos/team-a/../repos/team-b/secret" -x "$PROXY" --path-as-is

expect_connect 403 "a host outside the policy is refused" \
  team-a client "https://example.invalid/" -x "$PROXY"

expect_connect 403 "a namespace with no policy is refused" \
  team-b client "$BASE/repos/team-a/index.json" -x "$PROXY"

# Keep-alive isolation: a denial must not poison the connection behind it.
if out="$(kexec team-a client curl -s -o /dev/null -o /dev/null -w '%{http_code} ' --max-time 15 \
    -x "$PROXY" "$BASE/repos/team-b/x" "$BASE/repos/team-a/x")"; then
  if [[ "$out" == "403 200 " ]]; then
    ok "a denial leaves the connection usable for the next request"
  else
    bad "keep-alive isolation: got '$out', want '403 200 '"
  fi
else
  bad "keep-alive isolation: curl failed"
fi

# The CA bundle must reach exactly the namespaces that need it.
if kubectl -n team-a get configmap relay-ca-bundle >/dev/null 2>&1; then
  ok "the CA bundle is published to the inspected namespace"
else
  bad "the CA bundle is missing from team-a"
fi
if kubectl -n team-b get configmap relay-ca-bundle >/dev/null 2>&1; then
  bad "the CA bundle leaked into a namespace with no inspected destination"
else
  ok "the CA bundle stays out of namespaces that do not need it"
fi

# Attribution: the corporate proxy must see the tenant's own account, and must
# never have been contacted for a denied request.
AUDIT="$(kexec team-a client curl -s --max-time 10 --noproxy '*' http://corp-proxy.relay-system:3129/ || echo '[]')"
if grep -q 'svc-team-a' <<<"$AUDIT"; then
  ok "the corporate proxy attributes traffic to svc-team-a"
else
  bad "the corporate proxy never saw svc-team-a (audit: $AUDIT)"
fi
if grep -q 'team-b/secret' <<<"$AUDIT"; then
  bad "a denied request reached the corporate proxy"
else
  ok "denied requests never reach the corporate proxy"
fi

# Identity depends on the relay seeing real pod IPs. The preflight pod asks the
# relay which address it appeared to come from and compares it with its own,
# which is the only way to catch NAT sitting between pods and the relay.
PREFLIGHT_OVERRIDES=$(cat <<'JSON'
{"spec":{"restartPolicy":"Never","containers":[{
  "name":"preflight",
  "image":"IMAGE_PLACEHOLDER",
  "imagePullPolicy":"IfNotPresent",
  "args":["preflight","--url","http://relay.relay-system:9090"],
  "env":[{"name":"POD_IP","valueFrom":{"fieldRef":{"fieldPath":"status.podIP"}}}]
}]}}
JSON
)
PREFLIGHT_OVERRIDES="${PREFLIGHT_OVERRIDES//IMAGE_PLACEHOLDER/$IMAGE:$TAG}"

if kubectl -n team-a run preflight --rm -i --restart=Never \
    --image="$IMAGE:$TAG" --overrides="$PREFLIGHT_OVERRIDES" \
    >"$WORK/preflight.txt" 2>&1; then
  ok "preflight confirms the relay sees pod IPs"
else
  bad "preflight failed: $(tail -4 "$WORK/preflight.txt")"
fi

info "Result: $PASS passed, $FAIL failed"
[[ "$FAIL" == 0 ]]

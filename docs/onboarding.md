# Tenant onboarding

## Every tenant: point clients at the relay

```yaml
env:
  - name: http_proxy
    value: http://relay.relay-system:3128
  - name: https_proxy
    value: http://relay.relay-system:3128
  - name: no_proxy
    value: .svc,.cluster.local,localhost,127.0.0.1
```

Set the uppercase variants too; different runtimes read different ones.

Nothing else is required for `tlsMode: tunnel` destinations, which is the
default. There is no CA to install and no credential to hold.

## Tenants with inspected destinations: trust the relay CA

If any destination in your policy uses `tlsMode: inspect`, the relay terminates
TLS for that host and presents a certificate it signed itself. Your workload has
to trust the relay CA or the connection fails at handshake.

The relay publishes the CA into your namespace as a ConfigMap named
`relay-ca-bundle`, key `ca.crt`. It appears automatically once an inspect-mode
policy selects your namespace, and disappears when none does.

Mount it:

```yaml
volumes:
  - name: relay-ca
    configMap:
      name: relay-ca-bundle
containers:
  - name: app
    volumeMounts:
      - name: relay-ca
        mountPath: /etc/relay-ca
        readOnly: true
```

Then point your runtime at it. Runtimes do not agree on how:

| Runtime | How |
| --- | --- |
| curl | `CURL_CA_BUNDLE=/etc/relay-ca/ca.crt` (or `--cacert`) |
| git | `GIT_SSL_CAINFO=/etc/relay-ca/ca.crt` |
| Python (requests, pip) | `REQUESTS_CA_BUNDLE=/etc/relay-ca/ca.crt`, `PIP_CERT=/etc/relay-ca/ca.crt` |
| Node.js | `NODE_EXTRA_CA_CERTS=/etc/relay-ca/ca.crt` |
| Go | `SSL_CERT_FILE=/etc/relay-ca/ca.crt` |
| Java | import into a truststore at build time, or `-Djavax.net.ssl.trustStore=...` |
| OpenSSL / system | append to the image trust store and run `update-ca-certificates` |

**`SSL_CERT_FILE` does not work for curl.** curl loads its own compiled-in CA
bundle rather than OpenSSL's default paths, so the OpenSSL variable is ignored
and you get `self-signed certificate in certificate chain` with the file mounted
and apparently correct. Use `CURL_CA_BUNDLE`. Setting both is the safe move when
a container runs a mix of tools.

The bundle may contain **two** certificates during a CA rotation. Append it to
your trust store; do not parse out a single certificate, or the rotation will
break you when the second one starts signing.

## What breaks under inspection

Two kinds of workload cannot be inspected:

- **Certificate pinning.** The client checks for a specific certificate or
  public key and will not accept one the relay signed.
- **Client certificates to the origin.** The relay terminates the connection, so
  the origin never sees the client's certificate.

Both need the destination moved to `tlsMode: tunnel`, which means it can only be
authorized at host granularity. Ask the platform team; the relay's error message
names the destination and says the same thing.

## Diagnosing a failure

The relay explains itself. A denial's body and its `X-Relay-Reason` header carry
the reason:

```
$ curl -x http://relay.relay-system:3128 https://example.com
proxy-relay-control denied example.com:443 for team-a/builder-0:
no destination in the 1 policy/policies selecting team-a allows example.com:443
```

A denial of the *tunnel itself* — the host or port is not granted at all — is
answered to the `CONNECT`, so curl reports it differently:

```
$ curl -x http://relay.relay-system:3128 https://not-granted.example/
curl: (56) Received HTTP code 403 from proxy after CONNECT
```

`%{http_code}` stays `000` there because no end-to-end response ever happens;
`%{http_connect}` carries the 403. A denial of a *request* on an inspected
destination is an ordinary 403 response instead.

- **403** — policy. Either no policy selects your namespace, or none of its
  destinations covers the host, port, path or method you asked for.
- **502** — the relay or the corporate proxy. Not something you can fix; send
  the message to the platform team.
- **TLS handshake failure on an inspected host** — your workload does not trust
  the relay CA. Check the mount and the environment variable for your runtime.

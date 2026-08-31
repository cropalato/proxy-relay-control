package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"time"

	"github.com/cropalato/proxy-relay-control/internal/tlsbump"
)

// initCA generates a relay CA and prints the Secret holding it.
//
// It prints rather than applies by default: the CA key is the most sensitive
// object in this system, and an operator should decide where it lands (a sealed
// secret, an external secret store, a vault) instead of having it written to the
// API server as a side effect of running a command.
func initCA(_ context.Context, args []string) error {
	var (
		name       string
		namespace  string
		commonName string
		validity   time.Duration
		rotate     bool
	)
	parseFlags("init-ca", args, func(fs *flag.FlagSet) {
		fs.StringVar(&name, "name", "relay-ca", "Secret name")
		fs.StringVar(&namespace, "namespace", "relay-system", "Secret namespace")
		fs.StringVar(&commonName, "common-name", "proxy-relay-control", "CA subject common name")
		fs.DurationVar(&validity, "validity", tlsbump.DefaultCAValidity, "CA validity")
		fs.BoolVar(&rotate, "next", false, "emit the certificate as next-ca.crt for a rotation instead of a new install")
	})

	ca, err := tlsbump.GenerateCA(commonName, validity)
	if err != nil {
		return err
	}
	keyPEM, err := ca.MarshalKey()
	if err != nil {
		return err
	}

	if rotate {
		// During a rotation only the certificate is published first, so that every
		// tenant trusts the new CA before it signs anything. The key is held back
		// and merged into ca.key at the end of the propagation window.
		fmt.Printf(`# Rotation step 1: publish the upcoming CA for trust.
# Merge into the existing Secret, wait for every tenant pod to pick up the new
# bundle, then move these values into ca.crt/ca.key.
#
# kubectl -n %s patch secret %s --type merge -p "$(cat <<'EOF'
# {"data":{"next-ca.crt":"%s"}}
# EOF
# )"

next-ca.crt: %s
next-ca.key (hold until step 2): %s
`, namespace, name, base64.StdEncoding.EncodeToString(ca.CertPEM),
			base64.StdEncoding.EncodeToString(ca.CertPEM),
			base64.StdEncoding.EncodeToString(keyPEM))
		return nil
	}

	fmt.Printf(`apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: %s
type: Opaque
data:
  ca.crt: %s
  ca.key: %s
`, name, namespace,
		base64.StdEncoding.EncodeToString(ca.CertPEM),
		base64.StdEncoding.EncodeToString(keyPEM))
	return nil
}

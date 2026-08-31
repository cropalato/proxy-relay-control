package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// preflight verifies the assumption the whole pod-IP identity model rests on:
// that the relay sees a client's real pod IP.
//
// It is run from inside a pod in the cluster. If the address the relay observed
// differs from the pod's own, something between them is rewriting the source —
// kube-proxy masquerading, a CNI masquerade rule, or a host-network client — and
// every request from that path will be attributed to a node instead of a
// workload, or refused.
func preflight(ctx context.Context, args []string) error {
	var (
		adminURL string
		podIP    string
		timeout  time.Duration
	)
	parseFlags("preflight", args, func(fs *flag.FlagSet) {
		fs.StringVar(&adminURL, "url", "http://relay.relay-system:9090", "relay admin endpoint")
		fs.StringVar(&podIP, "pod-ip", os.Getenv("POD_IP"), "this pod's IP; defaults to $POD_IP")
		fs.DurationVar(&timeout, "timeout", 10*time.Second, "request timeout")
	})

	if podIP == "" {
		return fmt.Errorf("no pod IP: set --pod-ip or expose POD_IP via the downward API")
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoint := strings.TrimSuffix(adminURL, "/") + "/observed-ip"
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("contact relay at %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return err
	}
	observed := strings.TrimSpace(string(body))

	fmt.Printf("pod IP:      %s\n", podIP)
	fmt.Printf("relay saw:   %s\n", observed)

	if observed == podIP {
		fmt.Println("result:      ok — the relay sees this pod's own address")
		return nil
	}

	fmt.Println("result:      MISMATCH")
	fmt.Println()
	fmt.Println("The relay cannot identify workloads on this path. Something is rewriting")
	fmt.Println("the source address between the pod and the relay. Usual causes:")
	fmt.Println("  - kube-proxy running with --masquerade-all")
	fmt.Println("  - a CNI masquerade rule covering traffic to the relay's Service")
	fmt.Println("  - the client pod using hostNetwork, which has no address of its own")
	if ip := net.ParseIP(observed); ip != nil {
		fmt.Printf("  - the observed address %s is most likely this pod's node\n", ip)
	}
	return fmt.Errorf("preflight failed: relay observed %s, expected %s", observed, podIP)
}

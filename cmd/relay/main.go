// Command relay is proxy-relay-control: an identity-aware egress relay that
// authorizes Kubernetes workloads and forwards their traffic through a
// corporate proxy under per-tenant credentials.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "relay:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	command := "serve"
	args := os.Args[1:]
	if len(args) > 0 && !isFlag(args[0]) {
		command, args = args[0], args[1:]
	}

	switch command {
	case "serve":
		return serve(ctx, args)
	case "preflight":
		return preflight(ctx, args)
	case "init-ca":
		return initCA(ctx, args)
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", command)
	}
}

func isFlag(s string) bool { return len(s) > 0 && s[0] == '-' }

func usage() {
	fmt.Fprint(os.Stderr, `proxy-relay-control

Commands:
  serve       run the relay (default)
  preflight   check, from inside a pod, that the relay sees the pod's own IP
  init-ca     generate a relay CA and print the Secret that holds it

Run "relay <command> -h" for the flags of a command.
`)
}

func newLogger(level, format string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if format == "text" {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, opts))
}

// parseFlags uses ExitOnError so that -h prints usage and exits cleanly rather
// than falling through into the command it was asking about.
func parseFlags(name string, args []string, bind func(*flag.FlagSet)) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	bind(fs)
	_ = fs.Parse(args)
}

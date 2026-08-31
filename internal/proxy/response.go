package proxy

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// writeStatus sends a minimal proxy response.
//
// The body carries the reason in plain text. Tenants see these messages in curl
// output and container logs, and a denial that only says "403" turns into a
// support ticket; one that names the namespace, destination and missing policy
// usually does not.
func writeStatus(w io.Writer, status int, reason string) {
	body := reason
	if body == "" {
		body = http.StatusText(status)
	}
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	fmt.Fprintf(w, "Content-Type: text/plain; charset=utf-8\r\n")
	fmt.Fprintf(w, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(w, "X-Relay-Reason: %s\r\n", sanitizeHeader(reason))
	fmt.Fprintf(w, "Connection: close\r\n\r\n")
	io.WriteString(w, body)
}

// writeResponseOnBumped sends a response inside an inspected connection, where
// the client is speaking real HTTP and the connection stays open.
func writeDeniedRequest(w io.Writer, status int, reason string) error {
	body := reason
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	if _, err := fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nX-Relay-Reason: %s\r\n\r\n%s",
		status, http.StatusText(status), len(body), sanitizeHeader(reason), body); err != nil {
		return err
	}
	return nil
}

// sanitizeHeader keeps a reason safe to place in a header value.
func sanitizeHeader(s string) string {
	s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	if len(s) > 400 {
		s = s[:400]
	}
	return s
}

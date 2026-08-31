package policy

import (
	"errors"
	"fmt"
	"strings"
)

// Errors returned when a request target cannot be safely authorized.
var (
	// ErrMalformedPath means the target could not be normalized. Such requests are
	// refused rather than guessed at: a path this proxy cannot agree on with the
	// origin server is a path whose authorization decision cannot be trusted.
	ErrMalformedPath = errors.New("policy: malformed request path")
)

// NormalizePath canonicalizes a request target for authorization.
//
// Authorization runs against the normalized form while the original target is
// what gets forwarded, so any input where the two could be read differently by
// the origin server is rejected outright instead of rewritten. That closes the
// usual proxy/backend parser differentials (encoded separators, double encoding,
// path parameters) without this code having to model every origin's parser.
//
// The returned path always starts with "/" and contains no "." or ".." segments,
// no empty segments, and no query or fragment.
func NormalizePath(target string) (string, error) {
	if target == "" {
		return "/", nil
	}

	// Drop query and fragment; neither participates in path rules.
	if i := strings.IndexAny(target, "?#"); i >= 0 {
		target = target[:i]
	}
	if target == "" {
		return "/", nil
	}

	for i := 0; i < len(target); i++ {
		if c := target[i]; c < 0x20 || c == 0x7f {
			return "", fmt.Errorf("%w: control byte at offset %d", ErrMalformedPath, i)
		}
	}

	decoded, err := decodeOnce(target)
	if err != nil {
		return "", err
	}

	// A "%" surviving one decoding pass means the client encoded its encoding.
	// Which layer wins differs between servers, so refuse to have the argument.
	if strings.Contains(decoded, "%") {
		return "", fmt.Errorf("%w: double-encoded escape in %q", ErrMalformedPath, target)
	}
	if strings.Contains(decoded, "\\") {
		return "", fmt.Errorf("%w: backslash in %q", ErrMalformedPath, target)
	}

	if !strings.HasPrefix(decoded, "/") {
		decoded = "/" + decoded
	}

	var out []string
	for _, seg := range strings.Split(decoded, "/") {
		// Strip RFC 3986 path parameters; origins disagree on whether they are
		// part of the segment name.
		if i := strings.IndexByte(seg, ';'); i >= 0 {
			seg = seg[:i]
		}
		switch seg {
		case "", ".":
			// Empty segments come from duplicate slashes and are collapsed.
			continue
		case "..":
			if len(out) == 0 {
				return "", fmt.Errorf("%w: %q escapes the path root", ErrMalformedPath, target)
			}
			out = out[:len(out)-1]
		default:
			out = append(out, seg)
		}
	}

	normalized := "/" + strings.Join(out, "/")
	// Preserve a trailing slash: "/a/" and "/a" are different resources to many
	// origins, and prefix rules are written with that distinction in mind.
	if len(out) > 0 && strings.HasSuffix(decoded, "/") {
		normalized += "/"
	}
	return normalized, nil
}

// decodeOnce performs exactly one percent-decoding pass and rejects escapes that
// would introduce a path separator, since those are indistinguishable from a
// literal separator after decoding.
func decodeOnce(s string) (string, error) {
	if !strings.Contains(s, "%") {
		return s, nil
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", fmt.Errorf("%w: truncated escape in %q", ErrMalformedPath, s)
		}
		hi, ok1 := unhex(s[i+1])
		lo, ok2 := unhex(s[i+2])
		if !ok1 || !ok2 {
			return "", fmt.Errorf("%w: invalid escape %q", ErrMalformedPath, s[i:i+3])
		}
		c := hi<<4 | lo
		switch c {
		case '/', '\\':
			return "", fmt.Errorf("%w: encoded path separator in %q", ErrMalformedPath, s)
		case 0:
			return "", fmt.Errorf("%w: encoded NUL in %q", ErrMalformedPath, s)
		}
		b.WriteByte(c)
		i += 2
	}
	return b.String(), nil
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

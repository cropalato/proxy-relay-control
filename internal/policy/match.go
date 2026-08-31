package policy

import "strings"

// MatchHost reports whether host satisfies pattern.
//
// Supported patterns: an exact hostname, "*" for any host, "*.example.com" for
// exactly one additional label, and "**.example.com" for one or more. The
// single-label form is the default because "*.example.com" granting
// "evil.cdn.example.com" surprises most policy authors.
func MatchHost(pattern, host string) bool {
	pattern = canonicalHost(pattern)
	host = canonicalHost(host)
	if pattern == "" || host == "" {
		return false
	}
	if pattern == "*" || pattern == "**" {
		return true
	}

	switch {
	case strings.HasPrefix(pattern, "**."):
		suffix := pattern[2:] // keeps the leading dot
		return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	case strings.HasPrefix(pattern, "*."):
		suffix := pattern[1:] // keeps the leading dot
		if !strings.HasSuffix(host, suffix) || len(host) <= len(suffix) {
			return false
		}
		label := host[:len(host)-len(suffix)]
		return label != "" && !strings.Contains(label, ".")
	default:
		return pattern == host
	}
}

func canonicalHost(h string) string {
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	return h
}

// DefaultPorts applies when a destination lists none.
var DefaultPorts = []int32{80, 443}

// MatchPort reports whether port is allowed by the destination's port list.
func MatchPort(ports []int32, port int32) bool {
	if len(ports) == 0 {
		ports = DefaultPorts
	}
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

// MatchPath reports whether a normalized path satisfies a rule pattern.
//
// A pattern without wildcards is a prefix match that respects segment
// boundaries, so "/repos/team-a" matches "/repos/team-a/x" but never
// "/repos/team-ab". Setting exact requires equality instead. Patterns may use
// "*" to match within one segment and "**" to match across segments; exact is
// ignored for wildcard patterns, which already state their own extent.
func MatchPath(pattern string, exact bool, path string) bool {
	if pattern == "" {
		pattern = "/"
	}
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}

	if strings.Contains(pattern, "*") {
		return matchGlob(splitSegments(pattern), splitSegments(path))
	}

	if exact {
		return path == pattern || strings.TrimSuffix(path, "/") == strings.TrimSuffix(pattern, "/")
	}
	if strings.HasSuffix(pattern, "/") {
		return strings.HasPrefix(path, pattern) || strings.TrimSuffix(path, "/") == strings.TrimSuffix(pattern, "/")
	}
	return path == pattern || strings.HasPrefix(path, pattern+"/")
}

func splitSegments(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// matchGlob matches segment lists, where "**" consumes any number of segments.
func matchGlob(pattern, path []string) bool {
	if len(pattern) == 0 {
		return len(path) == 0
	}
	if pattern[0] == "**" {
		// Trailing "**" matches the rest, including nothing.
		if len(pattern) == 1 {
			return true
		}
		for i := 0; i <= len(path); i++ {
			if matchGlob(pattern[1:], path[i:]) {
				return true
			}
		}
		return false
	}
	if len(path) == 0 {
		return false
	}
	if !matchSegment(pattern[0], path[0]) {
		return false
	}
	return matchGlob(pattern[1:], path[1:])
}

// matchSegment matches one segment, where "*" stands for any run of characters
// that does not cross a segment boundary.
func matchSegment(pattern, seg string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == seg
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(seg, parts[0]) {
		return false
	}
	seg = seg[len(parts[0]):]
	last := len(parts) - 1
	for _, part := range parts[1:last] {
		if part == "" {
			continue
		}
		i := strings.Index(seg, part)
		if i < 0 {
			return false
		}
		seg = seg[i+len(part):]
	}
	return strings.HasSuffix(seg, parts[last])
}

// MatchMethod reports whether method is allowed by a rule's method list. An
// empty list means any method.
func MatchMethod(methods []string, method string) bool {
	if len(methods) == 0 {
		return true
	}
	for _, m := range methods {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

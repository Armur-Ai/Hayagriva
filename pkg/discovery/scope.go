package discovery

import (
	"net"
	"net/url"
	"strings"

	contracts "github.com/Armur-Ai/armur-contracts"
)

// enforceScope drops network-target observations whose host falls outside the
// authorized scope. It returns the kept observations and the number dropped.
// Non-network observations (e.g. a "technology" label) are always kept — scope
// governs targets, not descriptive facts. An empty scope performs no filtering
// (used by import-only runs where the operator vouches for the input).
func enforceScope(obs []contracts.ComponentObservation, scope []string) ([]contracts.ComponentObservation, int) {
	if len(scope) == 0 {
		return obs, 0
	}
	kept := obs[:0]
	dropped := 0
	for _, o := range obs {
		if !isNetworkTarget(o.Kind) {
			kept = append(kept, o)
			continue
		}
		if inScope(hostOf(o.Value), scope) {
			kept = append(kept, o)
		} else {
			dropped++
		}
	}
	return kept, dropped
}

func isNetworkTarget(kind string) bool {
	switch kind {
	case "host", "service", "endpoint":
		return true
	default:
		return false
	}
}

// hostOf extracts a bare host from an observation value, tolerating a leading
// "METHOD " (OpenAPI), a URL scheme, a port, and a path.
func hostOf(value string) string {
	v := strings.TrimSpace(value)
	if i := strings.IndexByte(v, ' '); i >= 0 {
		v = v[i+1:] // drop a leading METHOD token
	}
	if strings.Contains(v, "://") {
		if u, err := url.Parse(v); err == nil && u.Host != "" {
			v = u.Host
		}
	}
	// strip path
	if i := strings.IndexByte(v, '/'); i >= 0 {
		v = v[:i]
	}
	// strip port
	if i := strings.LastIndexByte(v, ':'); i >= 0 {
		v = v[:i]
	}
	return strings.ToLower(v)
}

// inScope reports whether host is in scope. A scope entry may be a domain
// (exact host or subdomain match), an exact IP, or a CIDR (host IP contained in
// the network).
func inScope(host string, scope []string) bool {
	if host == "" {
		return false
	}
	hostIP := net.ParseIP(host)
	for _, s := range scope {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		// CIDR entry: match by IP containment.
		if strings.Contains(s, "/") {
			if hostIP != nil {
				if _, nw, err := net.ParseCIDR(s); err == nil && nw.Contains(hostIP) {
					return true
				}
			}
			continue
		}
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

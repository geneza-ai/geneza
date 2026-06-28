// Package enrollcode encodes the single opaque "gzk_" enrollment credential that
// the curl|bash install.sh consumes. It bundles the one-time join token, the
// pinned root-key fingerprint, and (optionally) the controller endpoints, so the
// install one-liner needs exactly one argument instead of a fistful of flags.
// install.sh decodes it in POSIX sh; Decode here mirrors that for tests.
//
// The code carries no secret beyond the join token itself and is delivered over
// the same trusted channel as before (the authenticated console one-liner, or
// the TLS+Nova vendordata) — the root-fp pin inside it is what makes curl|bash
// safe, exactly as the standalone --root-fp flag did.
package enrollcode

import (
	"encoding/base64"
	"strings"
)

// Prefix marks an enrollment code. The base64url body (no padding) follows.
const Prefix = "gzk_"

// Fields are the values bundled in an enrollment code. Token and RootFP are
// always set; the endpoints are empty when the installer should derive them
// (HTTP from the origin install.sh was fetched over, Runtime from HTTP, GRPC
// from host(Runtime):7401).
type Fields struct {
	Token   string
	RootFP  string // "sha256:<hex>"
	HTTP    string // installer-fetch base URL
	Runtime string // controller runtime HTTP endpoint
	GRPC    string // controller gRPC host:port
}

// Encode bundles the fields into "gzk_<base64url>". The payload is a ';'-joined
// record; the fields never contain ';' (token is gz-<hex>, rootFP is
// sha256:<hex>, endpoints are URLs / host:port).
func Encode(f Fields) string {
	payload := strings.Join([]string{f.Token, f.RootFP, f.HTTP, f.Runtime, f.GRPC}, ";")
	return Prefix + base64.RawURLEncoding.EncodeToString([]byte(payload))
}

// Decode parses a "gzk_" code. ok is false if the prefix or base64 is invalid.
func Decode(code string) (f Fields, ok bool) {
	body, found := strings.CutPrefix(code, Prefix)
	if !found {
		return Fields{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Fields{}, false
	}
	p := strings.Split(string(raw), ";")
	for len(p) < 5 {
		p = append(p, "")
	}
	return Fields{Token: p[0], RootFP: p[1], HTTP: p[2], Runtime: p[3], GRPC: p[4]}, true
}

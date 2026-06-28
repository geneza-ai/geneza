package agentd

import (
	"crypto/sha256"
	"testing"
)

// hexSHA returns a valid 64-hex-char sha256 string for the manifest digest input,
// shared by the file-backed and token-backed node-key tests.
func hexSHA(t *testing.T) string {
	t.Helper()
	sum := sha256.Sum256([]byte("cast"))
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, 64)
	for _, b := range sum {
		out = append(out, hexdigits[b>>4], hexdigits[b&0x0f])
	}
	return string(out)
}

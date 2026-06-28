// Package nodeseal seals a small secret to a node's X25519 key so only that node
// can open it. The controller distributes managed-domain certificate material to
// agents (and, later, funnel certs to relays) over channels that are already
// mTLS, but sealing makes the payload opaque at rest and to any blind relay it
// passes through — the key never appears in cleartext anywhere but the holder.
//
// It reuses filippo.io/age for the actual encryption, sealing to the node's
// existing Noise static key (a Curve25519/X25519 keypair the controller already
// stores the public half of). age only exposes its X25519 keys as bech32 strings,
// so the one primitive here is encoding a raw 32-byte X25519 key into age's
// "age1..."/"AGE-SECRET-KEY-1..." forms; the round-trip is proven against age's
// own parser in the tests.
package nodeseal

import (
	"bytes"
	"errors"
	"io"
	"strings"

	"filippo.io/age"
)

// Seal encrypts plaintext to the holder of the X25519 private key matching
// x25519Pub (a raw 32-byte public key, e.g. NodeRecord.NoisePub).
func Seal(plaintext, x25519Pub []byte) ([]byte, error) {
	rs, err := recipientString(x25519Pub)
	if err != nil {
		return nil, err
	}
	r, err := age.ParseX25519Recipient(rs)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Open decrypts ciphertext with the raw 32-byte X25519 private key (e.g. the
// node's Noise static private key).
func Open(ciphertext, x25519Priv []byte) ([]byte, error) {
	is, err := identityString(x25519Priv)
	if err != nil {
		return nil, err
	}
	id, err := age.ParseX25519Identity(is)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(ciphertext), id)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func recipientString(pub []byte) (string, error) {
	if len(pub) != 32 {
		return "", errors.New("nodeseal: x25519 public key must be 32 bytes")
	}
	return bech32Encode("age", pub)
}

func identityString(priv []byte) (string, error) {
	if len(priv) != 32 {
		return "", errors.New("nodeseal: x25519 private key must be 32 bytes")
	}
	// bech32's checksum is over the canonical (lower-case) HRP; an age secret key
	// is that canonical form displayed upper-cased.
	s, err := bech32Encode("age-secret-key-", priv)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(s), nil
}

// --- bech32 (BIP-173) encoding, the form age uses for X25519 keys ---

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Polymod(values []int) int {
	gen := []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []int {
	out := make([]int, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, int(hrp[i])>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, int(hrp[i])&31)
	}
	return out
}

func bech32Checksum(hrp string, data []int) []int {
	values := append(bech32HRPExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	polymod := bech32Polymod(values) ^ 1
	out := make([]int, 6)
	for i := 0; i < 6; i++ {
		out[i] = (polymod >> uint(5*(5-i))) & 31
	}
	return out
}

// convertBits regroups 8-bit bytes into 5-bit groups (with padding) for bech32.
func convertBits8to5(data []byte) []int {
	const maxv = (1 << 5) - 1
	acc, bits := 0, uint(0)
	var out []int
	for _, b := range data {
		acc = (acc << 8) | int(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, (acc>>bits)&maxv)
		}
	}
	if bits > 0 {
		out = append(out, (acc<<(5-bits))&maxv)
	}
	return out
}

func bech32Encode(hrp string, data []byte) (string, error) {
	conv := convertBits8to5(data)
	combined := append(conv, bech32Checksum(hrp, conv)...)
	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, p := range combined {
		if p < 0 || p >= len(bech32Charset) {
			return "", errors.New("nodeseal: invalid bech32 value")
		}
		sb.WriteByte(bech32Charset[p])
	}
	return sb.String(), nil
}

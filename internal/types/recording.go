package types

import (
	"crypto/sha256"
	"strconv"
)

// RecordingManifestDigest is the canonical 32-byte digest a node signs to attest
// an uploaded recording, and that the controller verifies against the node cert.
// Binding the ciphertext sha256, its size and the finish time makes a signature
// minted for one cast non-transferable to another (a different blob, a resized
// truncation, or a replay all change the digest). sha256Hex is the lower-case hex
// SHA-256 of the ciphertext; the fields are length-prefixed so no concatenation
// of distinct inputs can collide.
func RecordingManifestDigest(sessionID, sha256Hex string, size, finishedUnix int64) []byte {
	h := sha256.New()
	writeField := func(s string) {
		h.Write([]byte(strconv.Itoa(len(s))))
		h.Write([]byte{':'})
		h.Write([]byte(s))
	}
	writeField("geneza-recording-manifest")
	writeField(sessionID)
	writeField(sha256Hex)
	writeField(strconv.FormatInt(size, 10))
	writeField(strconv.FormatInt(finishedUnix, 10))
	return h.Sum(nil)
}

import { Decrypter } from "age-encryption"

import type { RecordingBlob } from "@/types"

// hexSha256 returns the lowercase-hex SHA-256 of the given bytes, using the
// browser's SubtleCrypto so nothing is hand-rolled.
async function hexSha256(bytes: Uint8Array): Promise<string> {
  // Hand SubtleCrypto a fresh ArrayBuffer-backed view so the digest input is a
  // BufferSource regardless of how the caller's Uint8Array was constructed.
  const digest = await crypto.subtle.digest("SHA-256", bytes.slice())
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
}

// verifyIntegrity recomputes the SHA-256 of the fetched ciphertext and compares it
// to the manifest digest the controller served. This is the auditor re-verifying the
// node-attested bytes for themselves, not trusting the controller's own check. It runs
// before any decryption attempt so a tampered or corrupt cast is rejected up front.
export async function verifyIntegrity(blob: RecordingBlob): Promise<boolean> {
  if (!blob.sha256) return false
  const got = await hexSha256(blob.ciphertext)
  // Constant-time-ish compare is unnecessary here (the digest is public), so a
  // plain case-insensitive string compare is fine.
  return got.toLowerCase() === blob.sha256.toLowerCase()
}

/**
 * Result of checking the node's attestation over a recording.
 *
 * `unavailable` is NOT `false`: recordings stored before the controller retained
 * the signing key carry a signature nothing can check, and telling an auditor
 * "unsigned" there would be a lie in the other direction.
 */
export type NodeSigResult = "valid" | "invalid" | "unavailable"

// manifestPreimage is the byte string internal/types.RecordingManifestDigest
// hashes: length-prefixed fields under a domain tag, so no concatenation of
// different inputs can collide. It must stay byte-identical to the Go function or
// every signature fails.
//
// The PRE-IMAGE, not the digest: the node signs SHA-256 of this, and WebCrypto's
// ECDSA verify hashes the message itself — it has no pre-hashed mode. Passing the
// digest here would verify a signature over SHA-256(SHA-256(...)) and never match.
function manifestPreimage(
  sessionId: string,
  sha256Hex: string,
  size: number,
  finishedUnix: number
): Uint8Array {
  const enc = new TextEncoder()
  const parts: Uint8Array[] = []
  for (const s of [
    "geneza-recording-manifest",
    sessionId,
    sha256Hex,
    String(size),
    String(finishedUnix),
  ]) {
    const b = enc.encode(s)
    parts.push(enc.encode(`${b.length}:`), b)
  }
  const buf = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let off = 0
  for (const p of parts) {
    buf.set(p, off)
    off += p.length
  }
  return buf
}

// Go signs with ecdsa.SignASN1, which emits SEQUENCE { INTEGER r, INTEGER s };
// WebCrypto verifies only the fixed-width r‖s form. This unpacks the former into
// the latter. Returns null on anything malformed rather than guessing.
function derToRawEcdsaSig(der: Uint8Array, byteLen = 32): Uint8Array | null {
  let i = 0
  const readLen = (): number => {
    const first = der[i++]
    if (first === undefined) return -1
    if (first < 0x80) return first
    const n = first & 0x7f
    if (n === 0 || n > 4 || i + n > der.length) return -1
    let len = 0
    for (let k = 0; k < n; k++) len = (len << 8) | der[i++]
    return len
  }
  const readInt = (): Uint8Array | null => {
    if (der[i++] !== 0x02) return null
    const len = readLen()
    if (len < 0 || i + len > der.length) return null
    let v = der.subarray(i, i + len)
    i += len
    // Strip the leading zero DER adds to keep the integer positive, then
    // left-pad to the curve's fixed width.
    while (v.length > byteLen && v[0] === 0x00) v = v.subarray(1)
    if (v.length > byteLen) return null
    const out = new Uint8Array(byteLen)
    out.set(v, byteLen - v.length)
    return out
  }
  if (der[i++] !== 0x30) return null
  const seqLen = readLen()
  if (seqLen < 0 || i + seqLen !== der.length) return null
  const r = readInt()
  const s = readInt()
  if (!r || !s || i !== der.length) return null
  const raw = new Uint8Array(byteLen * 2)
  raw.set(r, 0)
  raw.set(s, byteLen)
  return raw
}

/**
 * verifyNodeSignature checks the node's ECDSA-P256 attestation over the manifest.
 *
 * This is a strictly stronger claim than the sha256 check: the digest the node
 * signed binds the session id, the ciphertext hash, its size and the finish time,
 * and the controller holds no key that could re-sign a substituted blob. What it
 * does NOT prove on its own is that the key belongs to the node — that binding
 * comes from the cluster CA that issued the node's certificate.
 */
export async function verifyNodeSignature(
  sessionId: string,
  blob: RecordingBlob
): Promise<NodeSigResult> {
  if (!blob.nodeKey.length || !blob.nodeSig.length || !blob.sha256) return "unavailable"
  const raw = derToRawEcdsaSig(blob.nodeSig)
  if (!raw) return "invalid"
  try {
    const key = await crypto.subtle.importKey(
      "spki",
      blob.nodeKey.slice(),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    )
    const msg = manifestPreimage(
      sessionId,
      blob.sha256,
      blob.sizeBytes,
      blob.endedUnix
    )
    // .slice() for the same reason hexSha256 does it: hand SubtleCrypto a fresh
    // ArrayBuffer-backed view so both arguments are BufferSources.
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      raw.slice(),
      msg.slice()
    )
    return ok ? "valid" : "invalid"
  } catch {
    // An unimportable key is a key we cannot check with, not a bad signature.
    return "unavailable"
  }
}

// plaintextCast decodes an unencrypted cast (recorded with no audit recipient)
// straight to asciicast text — no key needed. Integrity is still verified first,
// so a tampered plaintext cast is rejected the same as an encrypted one.
export function plaintextCast(blob: RecordingBlob): string {
  return new TextDecoder().decode(blob.ciphertext)
}

export class DecryptError extends Error {
  constructor(message: string) {
    super(message)
    this.name = "DecryptError"
  }
}

// decryptCast decrypts the age ciphertext with the auditor-supplied identity and
// returns the asciicast (v2) text to feed asciinema-player. The identity (an
// `AGE-SECRET-KEY-1...` string) is used only here, in the browser — it is never
// sent to the controller. A wrong/incompatible key surfaces as a DecryptError so the
// UI can tell the auditor their key didn't fit, distinct from an integrity failure.
export async function decryptCast(
  blob: RecordingBlob,
  identity: string
): Promise<string> {
  const key = identity.trim()
  if (!key) throw new DecryptError("No decryption key supplied.")
  const d = new Decrypter()
  try {
    d.addIdentity(key)
  } catch {
    throw new DecryptError(
      "That doesn't look like an age identity (expected an AGE-SECRET-KEY-1… key)."
    )
  }
  try {
    return await d.decrypt(blob.ciphertext, "text")
  } catch {
    throw new DecryptError(
      "Decryption failed — this key does not match the recording's audit key."
    )
  }
}

// formatBytes renders a size for the recordings table (the casts are tiny, so the
// common case is bytes/KiB).
export function formatBytes(n: number): string {
  if (!n || n <= 0) return "0 B"
  const units = ["B", "KiB", "MiB", "GiB"]
  let v = n
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

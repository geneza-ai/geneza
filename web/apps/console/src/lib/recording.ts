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

import { useEffect, useRef, useState } from "react"
import { create as createPlayer, type Player } from "asciinema-player"
import "asciinema-player/dist/bundle/asciinema-player.css"
import { Download, KeyRound, ShieldCheck, ShieldX, Upload } from "lucide-react"

import { api, ApiError } from "@/api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@geneza/ui"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@geneza/ui"
import {
  DecryptError,
  decryptCast,
  formatBytes,
  plaintextCast,
  verifyIntegrity,
} from "@/lib/recording"
import { absoluteTime, formatDuration, truncateMiddle } from "@/lib/format"
import type { RecordingBlob, RecordingInfo } from "@/types"

type Phase = "loading" | "needsKey" | "playing" | "error"

// RecordingPlayer fetches a recording's ciphertext, verifies its integrity, then
// asks the auditor for their age identity and decrypts CLIENT-SIDE before handing
// the asciicast to asciinema-player. The private key never leaves the browser, and
// the controller never sees plaintext — the offline-key model the recording design
// settled on.
export function RecordingPlayer({
  recording,
  onClose,
}: {
  recording: RecordingInfo
  onClose: () => void
}) {
  const [phase, setPhase] = useState<Phase>("loading")
  const [error, setError] = useState<string | null>(null)
  const [integrityOk, setIntegrityOk] = useState(false)
  const [blob, setBlob] = useState<RecordingBlob | null>(null)
  const [keyText, setKeyText] = useState("")
  const [decrypting, setDecrypting] = useState(false)
  const [castText, setCastText] = useState<string | null>(null)

  // Fetch + verify on open. The ciphertext is buffered; the manifest sha256 the
  // controller echoed is re-checked here so a tampered cast never reaches decryption.
  // A fresh player mounts per recording, so the initial state already reflects the
  // loading phase — the effect only needs to drive the async fetch.
  useEffect(() => {
    const ctl = new AbortController()
    api
      .getRecordingBlob(recording.sessionId, ctl.signal)
      .then(async (b) => {
        const ok = await verifyIntegrity(b)
        if (ctl.signal.aborted) return
        setBlob(b)
        setIntegrityOk(ok)
        if (!ok) {
          setError(
            "Integrity check failed: the fetched bytes do not match the recording's signed digest. The cast may be corrupt or tampered."
          )
          setPhase("error")
          return
        }
        // No audit key id => the cast was recorded in plaintext (no recipient
        // configured); play it directly. An audit-key id means it is sealed and
        // needs the auditor's identity to decrypt.
        if (!recording.auditKeyId) {
          setCastText(plaintextCast(b))
          setPhase("playing")
          return
        }
        setPhase("needsKey")
      })
      .catch((err) => {
        if (ctl.signal.aborted) return
        setError(err instanceof ApiError ? err.message : String(err))
        setPhase("error")
      })
    return () => ctl.abort()
  }, [recording.sessionId, recording.auditKeyId])

  async function onFile(file: File) {
    setKeyText((await file.text()).trim())
  }

  async function play() {
    if (!blob) return
    setDecrypting(true)
    setError(null)
    try {
      const cast = await decryptCast(blob, keyText)
      setCastText(cast)
      setPhase("playing")
    } catch (err) {
      setError(
        err instanceof DecryptError || err instanceof Error
          ? err.message
          : String(err)
      )
    } finally {
      setDecrypting(false)
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-5xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 font-serif text-lg font-medium tracking-tight">
            Recording {recording.sessionId}
            {integrityOk && (
              <Badge variant="success" className="gap-1">
                <ShieldCheck className="size-3" />
                integrity verified
              </Badge>
            )}
            {phase === "error" && !integrityOk && blob && (
              <Badge variant="destructive" className="gap-1">
                <ShieldX className="size-3" />
                integrity failed
              </Badge>
            )}
          </DialogTitle>
          <DialogDescription className="font-mono text-xs text-faint">
            {recording.principal || "—"} → {recording.nodeId} ·{" "}
            {recording.action || "shell"}
          </DialogDescription>
        </DialogHeader>

        {phase === "loading" && (
          <div className="space-y-2 py-4">
            <Skeleton className="h-4 w-48" />
            <Skeleton className="h-40 w-full" />
          </div>
        )}

        {phase === "error" && (
          <div className="flex flex-col items-center gap-3 px-6 py-12 text-center">
            <ShieldX className="size-8 text-destructive" />
            <p className="max-w-md text-sm text-muted-foreground">
              {error ?? "Failed to load the recording."}
            </p>
            <Button variant="outline" size="sm" onClick={onClose}>
              Close
            </Button>
          </div>
        )}

        {phase === "needsKey" && (
          <div className="space-y-3 py-2">
            <p className="text-sm text-muted-foreground">
              This recording is encrypted to the workspace audit key. Supply the
              audit private key (an <code>AGE-SECRET-KEY-1…</code> identity) to
              decrypt and play it. The key is used only in your browser — it is
              never sent to the controller.
            </p>
            <div className="flex items-start gap-2">
              <div className="relative flex-1">
                <KeyRound className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
                <Input
                  value={keyText}
                  onChange={(e) => setKeyText(e.target.value)}
                  placeholder="AGE-SECRET-KEY-1…"
                  className="pl-8 font-mono text-xs"
                  type="password"
                  autoComplete="off"
                />
              </div>
              <label className="inline-flex">
                <input
                  type="file"
                  accept=".key,.txt,text/plain"
                  className="hidden"
                  onChange={(e) => {
                    const f = e.target.files?.[0]
                    if (f) void onFile(f)
                  }}
                />
                <Button asChild variant="outline" type="button">
                  <span className="cursor-pointer">
                    <Upload className="size-4" />
                    Key file
                  </span>
                </Button>
              </label>
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
            <div className="flex justify-end">
              <Button
                onClick={() => void play()}
                disabled={decrypting || keyText.trim() === ""}
              >
                {decrypting ? "Decrypting…" : "Decrypt & play"}
              </Button>
            </div>
          </div>
        )}

        {phase === "playing" && castText && (
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1.6fr_1fr]">
            {/* Terminal chrome — the cast plays inside the design's warm-black
                window regardless of the console theme. */}
            <div className="overflow-hidden rounded-[14px] border bg-[#14130E]">
              <div className="flex items-center gap-2 border-b border-[#2A271F] px-4 py-3">
                <span className="size-2.5 rounded-full bg-[#322E25]" />
                <span className="size-2.5 rounded-full bg-[#322E25]" />
                <span className="size-2.5 rounded-full bg-[#322E25]" />
                <span className="ml-2.5 truncate font-mono text-[11px] text-[#7E7868]">
                  {recording.principal || "auditor"}@{recording.nodeId} — geneza
                  replay
                </span>
              </div>
              <CastView cast={castText} />
            </div>

            {/* Recording facts, in machine text. */}
            <div className="flex flex-col gap-4">
              <div className="rounded-[14px] border bg-card p-5">
                <div className="mb-4 font-mono text-2xs uppercase tracking-[0.1em] text-faint">
                  Recording {truncateMiddle(recording.sessionId, 10, 4)}
                </div>
                <div className="flex flex-col gap-2.5 font-mono text-xs">
                  <MetaRow label="user" value={recording.principal || "—"} />
                  <MetaRow label="node" value={recording.nodeId} />
                  <MetaRow label="type" value={recording.action || "shell"} />
                  <MetaRow
                    label="started"
                    value={absoluteTime(recording.startedUnix)}
                  />
                  <MetaRow
                    label="duration"
                    value={formatDuration(recording.startedUnix, recording.endedUnix)}
                  />
                  <MetaRow label="size" value={formatBytes(recording.sizeBytes)} />
                  <MetaRow
                    label="sha256"
                    value={truncateMiddle(blob?.sha256 ?? "", 10, 6) || "—"}
                  />
                </div>
                <div className="my-4 h-px bg-border" />
                <div className="flex items-center gap-2 font-mono text-[11.5px] text-success">
                  ✓ node-attested · tamper-evident
                </div>
              </div>
              <Button variant="outline" className="w-full" onClick={exportCast}>
                <Download className="size-4" />
                Export transcript
              </Button>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )

  // Saves the decrypted asciicast to disk — the auditor's local transcript copy.
  function exportCast() {
    if (!castText) return
    const url = URL.createObjectURL(
      new Blob([castText], { type: "application/x-asciicast" })
    )
    const a = document.createElement("a")
    a.href = url
    a.download = `${recording.sessionId}.cast`
    a.click()
    URL.revokeObjectURL(url)
  }
}

function MetaRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-3">
      <span className="shrink-0 text-faint">{label}</span>
      <span className="truncate text-muted-foreground">{value}</span>
    </div>
  )
}

// CastView mounts the asciinema-player web component over the decrypted asciicast
// text. The player is created imperatively (it owns its DOM) and disposed on
// unmount so a closed dialog leaves no dangling terminal.
function CastView({ cast }: { cast: string }) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!ref.current) return
    let player: Player | null = null
    try {
      player = createPlayer(
        { data: cast, parser: "asciicast" },
        ref.current,
        { fit: "width", autoPlay: false, controls: true }
      )
    } catch {
      // A malformed cast that slipped past integrity (shouldn't happen) is shown
      // as an empty terminal rather than crashing the dialog.
    }
    return () => player?.dispose()
  }, [cast])
  return <div ref={ref} className="overflow-hidden [&_.ap-player]:rounded-none" />
}

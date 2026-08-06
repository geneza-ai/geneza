import { useState } from "react"
import { Check, ChevronDown, Copy, KeyRound, Plus, Terminal, Trash2 } from "lucide-react"
import { toast } from "sonner"

import { api, ApiError } from "@/api"
import { Card, CardContent, CardHeader, CardTitle } from "@geneza/ui"
import { Button } from "@geneza/ui"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { copyToClipboard } from "@/lib/format"
import { absoluteTime } from "@/lib/format"
import type { TokenResponse } from "@/types"

const TTL_OPTIONS = [
  { label: "15 minutes", seconds: 900 },
  { label: "1 hour", seconds: 3600 },
  { label: "24 hours", seconds: 86400 },
  { label: "7 days", seconds: 604800 },
  { label: "30 days", seconds: 2592000 },
]

interface LabelPair {
  key: string
  value: string
}

// The artifact the operator should actually copy, in descending order of
// usefulness. The raw token is last on purpose: install.sh rejects it outright
// ("unknown argument"), so leading with it sends people down a dead end.
function primaryArtifact(r: TokenResponse): {
  value: string
  title: string
  hint: string
} {
  if (r.installCommand) {
    return {
      value: r.installCommand,
      title: "Run this on the new node",
      hint: "Installs the agent and enrolls it. The code pins this controller's root key, so the download verifies itself.",
    }
  }
  if (r.enrollCode) {
    return {
      value: r.enrollCode,
      title: "Enrollment code",
      hint: "This controller does not serve an installer (set install_dir to enable the curl one-liner). Pass this code to install-agent.sh on the node.",
    }
  }
  return {
    value: r.token,
    title: "Join token",
    hint: "This controller serves no root pubkey, so there is no verifiable install code. Enroll with: geneza-agent enroll --token <token> --controller <host:7401>",
  }
}

export function TokensPage() {
  const [ttl, setTtl] = useState(3600)
  const [maxUses, setMaxUses] = useState(1)
  const [autoApprove, setAutoApprove] = useState(false)
  const [labels, setLabels] = useState<LabelPair[]>([{ key: "", value: "" }])
  const [submitting, setSubmitting] = useState(false)
  const [result, setResult] = useState<TokenResponse | null>(null)
  const [copied, setCopied] = useState(false)
  const [showRaw, setShowRaw] = useState(false)

  const setLabel = (i: number, field: keyof LabelPair, val: string) => {
    setLabels((prev) =>
      prev.map((p, idx) => (idx === i ? { ...p, [field]: val } : p))
    )
  }
  const addLabel = () =>
    setLabels((prev) => [...prev, { key: "", value: "" }])
  const removeLabel = (i: number) =>
    setLabels((prev) => prev.filter((_, idx) => idx !== i))

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSubmitting(true)
    setResult(null)
    setShowRaw(false)

    const labelMap: Record<string, string> = {}
    for (const { key, value } of labels) {
      const k = key.trim()
      if (k) labelMap[k] = value.trim()
    }

    try {
      const res = await api.createToken({
        ttlSeconds: ttl,
        labels: labelMap,
        maxUses: Math.max(1, maxUses),
        autoApprove,
      })
      setResult(res)
      toast.success("Enrollment code created")
    } catch (err) {
      const msg =
        err instanceof ApiError ? err.message : "Failed to create token"
      toast.error(msg)
    } finally {
      setSubmitting(false)
    }
  }

  const artifact = result ? primaryArtifact(result) : null

  const copyArtifact = async () => {
    if (!artifact) return
    await copyToClipboard(artifact.value, "Copied")
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div className="mx-auto max-w-2xl space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <KeyRound className="size-4 text-muted-foreground" />
            Enroll a node
          </CardTitle>
          <p className="text-sm text-muted-foreground">
            Generate a single-use or limited-use enrollment code, then run the
            install one-liner on the new machine.
          </p>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="space-y-5">
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="ttl">Time to live</Label>
                <Select
                  value={String(ttl)}
                  onValueChange={(v) => setTtl(Number(v))}
                >
                  <SelectTrigger id="ttl">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {TTL_OPTIONS.map((o) => (
                      <SelectItem key={o.seconds} value={String(o.seconds)}>
                        {o.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="maxUses">Max uses</Label>
                <Input
                  id="maxUses"
                  type="number"
                  min={1}
                  value={maxUses}
                  onChange={(e) =>
                    setMaxUses(Math.max(1, Number(e.target.value) || 1))
                  }
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label className="flex items-start gap-2.5 font-normal">
                <input
                  type="checkbox"
                  className="mt-0.5 size-4 shrink-0 accent-primary"
                  checked={autoApprove}
                  onChange={(e) => setAutoApprove(e.target.checked)}
                />
                <span className="space-y-1">
                  <span className="block text-sm font-medium">
                    Approve enrolled nodes automatically
                  </span>
                  <span className="block text-xs text-muted-foreground">
                    Skips the admin approval gate — a node that enrols is
                    immediately usable. Anyone who obtains this code gets a
                    working node with no human check.
                  </span>
                </span>
              </Label>
            </div>

            <div className="space-y-2">
              <Label>Labels</Label>
              <p className="text-xs text-muted-foreground">
                Applied to every node enrolled with this code.
              </p>
              <div className="space-y-2">
                {labels.map((pair, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <Input
                      placeholder="key"
                      value={pair.key}
                      onChange={(e) => setLabel(i, "key", e.target.value)}
                      className="font-mono text-xs"
                    />
                    <span className="text-muted-foreground">=</span>
                    <Input
                      placeholder="value"
                      value={pair.value}
                      onChange={(e) => setLabel(i, "value", e.target.value)}
                      className="font-mono text-xs"
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon-sm"
                      onClick={() => removeLabel(i)}
                      disabled={labels.length === 1}
                      title="Remove"
                    >
                      <Trash2 className="size-3.5" />
                    </Button>
                  </div>
                ))}
              </div>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={addLabel}
              >
                <Plus className="size-3.5" />
                Add label
              </Button>
            </div>

            <Separator />

            <Button type="submit" disabled={submitting}>
              <KeyRound className="size-4" />
              {submitting ? "Creating…" : "Create enrollment code"}
            </Button>
          </form>
        </CardContent>
      </Card>

      {result && artifact && (
        <Card className="border-success/30">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm">
              <Terminal className="size-4 text-muted-foreground" />
              {artifact.title}
            </CardTitle>
            <p className="text-sm text-muted-foreground">{artifact.hint}</p>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-stretch gap-2">
              <code className="flex-1 overflow-x-auto rounded-md border bg-muted/40 px-3 py-2.5 font-mono text-xs">
                {artifact.value}
              </code>
              <Button
                variant="outline"
                size="icon"
                onClick={copyArtifact}
                className="shrink-0"
                title="Copy"
              >
                {copied ? (
                  <Check className="size-4 text-success" />
                ) : (
                  <Copy className="size-4" />
                )}
              </Button>
            </div>

            <dl className="grid gap-1 text-xs text-muted-foreground">
              <div className="flex gap-2">
                <dt className="w-20 shrink-0">Expires</dt>
                <dd>{absoluteTime(result.expiresUnix)}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="w-20 shrink-0">Approval</dt>
                <dd>
                  {result.autoApprove ? (
                    <span className="text-warning">
                      AUTO — enrolled nodes are usable immediately
                    </span>
                  ) : (
                    <>
                      PENDING — approve the node under Nodes after it arrives
                    </>
                  )}
                </dd>
              </div>
            </dl>

            <p className="text-xs text-muted-foreground">
              Copy it now — it won’t be shown again.
            </p>

            {artifact.value !== result.token && (
              <>
                <Separator />
                <button
                  type="button"
                  onClick={() => setShowRaw((v) => !v)}
                  className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
                >
                  <ChevronDown
                    className={`size-3.5 transition-transform ${showRaw ? "rotate-180" : ""}`}
                  />
                  Advanced — raw join token
                </button>
                {showRaw && (
                  <div className="space-y-2">
                    <p className="text-xs text-muted-foreground">
                      For <code className="font-mono">geneza-agent enroll
                      --token</code> on a host that already has the binary and
                      the CA roots. <strong>install.sh does not accept this</strong> —
                      it takes the code above.
                    </p>
                    <div className="flex items-stretch gap-2">
                      <code className="flex-1 overflow-x-auto rounded-md border bg-muted/40 px-3 py-2 font-mono text-xs">
                        {result.token}
                      </code>
                      <Button
                        variant="outline"
                        size="icon"
                        onClick={() =>
                          copyToClipboard(result.token, "Token copied")
                        }
                        className="shrink-0"
                        title="Copy token"
                      >
                        <Copy className="size-4" />
                      </Button>
                    </div>
                  </div>
                )}
              </>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}

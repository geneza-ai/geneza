import { useState } from "react"
import { Check, Copy, KeyRound, Plus, Trash2 } from "lucide-react"
import { toast } from "sonner"

import { api, ApiError } from "@/api"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
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

export function TokensPage() {
  const [ttl, setTtl] = useState(3600)
  const [maxUses, setMaxUses] = useState(1)
  const [labels, setLabels] = useState<LabelPair[]>([{ key: "", value: "" }])
  const [submitting, setSubmitting] = useState(false)
  const [result, setResult] = useState<TokenResponse | null>(null)
  const [copied, setCopied] = useState(false)

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
      })
      setResult(res)
      toast.success("Join token created")
    } catch (err) {
      const msg =
        err instanceof ApiError ? err.message : "Failed to create token"
      toast.error(msg)
    } finally {
      setSubmitting(false)
    }
  }

  const copyToken = async () => {
    if (!result) return
    await copyToClipboard(result.token, "Token copied")
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div className="mx-auto max-w-2xl space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <KeyRound className="size-4 text-muted-foreground" />
            Mint a join token
          </CardTitle>
          <p className="text-sm text-muted-foreground">
            Generate a single-use or limited-use enrollment token for a new
            agent node.
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
              <Label>Labels</Label>
              <p className="text-xs text-muted-foreground">
                Applied to every node enrolled with this token.
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
              {submitting ? "Creating…" : "Create token"}
            </Button>
          </form>
        </CardContent>
      </Card>

      {result && (
        <Card className="border-[var(--success)]/30">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm">Token created</CardTitle>
            <p className="text-sm text-muted-foreground">
              Copy it now — it won’t be shown again. Expires{" "}
              {absoluteTime(result.expiresUnix)}.
            </p>
          </CardHeader>
          <CardContent>
            <div className="flex items-stretch gap-2">
              <code className="flex-1 overflow-x-auto rounded-md border bg-muted/40 px-3 py-2.5 font-mono text-xs">
                {result.token}
              </code>
              <Button
                variant="outline"
                size="icon"
                onClick={copyToken}
                className="shrink-0"
                title="Copy token"
              >
                {copied ? (
                  <Check className="size-4 text-[var(--success)]" />
                ) : (
                  <Copy className="size-4" />
                )}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

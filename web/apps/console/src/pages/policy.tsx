import { useEffect, useMemo, useRef, useState } from "react"
import { Shield, Users, Check, AlertTriangle, Loader2, Save } from "lucide-react"
import { toast } from "sonner"

import { api, ApiError } from "@/api"
import { usePolling } from "@/hooks/use-polling"
import { Card, CardContent, CardHeader, CardTitle } from "@geneza/ui"
import { Badge } from "@/components/ui/badge"
import { Button } from "@geneza/ui"
import { Separator } from "@/components/ui/separator"
import { EmptyState, ErrorState } from "@/components/states"
import { PageToolbar } from "@/components/page-toolbar"
import { CopyId } from "@/components/copy-id"
import { relativeTime } from "@/lib/format"
import type { Policy, PolicyRule, PolicyValidation } from "@/types"
import { PolicyVisualEditor } from "@/components/policy-visual"

// PolicyPage is the per-workspace authorization editor. A workspace admin edits
// their own policy document; it validates live against the controller's real
// parser (so the preview and the save share one authority) and is saved to the
// HA store. Non-admins see it read-only.
export function PolicyPage() {
  const { data, error, initialLoading, refresh } = usePolling(
    (s) => api.getPolicy(s),
    0
  )

  const [draft, setDraft] = useState("")
  const loadedYaml = data?.yaml ?? ""
  // Seed the editor once the document loads (and after a save reloads it).
  useEffect(() => {
    setDraft(loadedYaml)
  }, [loadedYaml])

  // Visual | YAML, Tailscale-style. The YAML text stays canonical — it is what is
  // validated and what is saved — and the visual editor is a view onto it that
  // renders back through the controller's own parser. One source of truth avoids
  // the failure mode where the two halves disagree about the document that
  // decides who may reach what.
  const [mode, setMode] = useState<"visual" | "yaml">("visual")
  const [visualDoc, setVisualDoc] = useState<Policy | null>(null)
  const [visualError, setVisualError] = useState<string | null>(null)
  const [rendering, setRendering] = useState(false)

  const editable = data?.editable ?? false
  const dirty = data !== undefined && draft !== loadedYaml

  // Live validation: debounce edits, then ask the controller to parse the draft.
  // The result carries the parsed structure for the preview (no client YAML lib).
  const [validation, setValidation] = useState<PolicyValidation | null>(null)
  const [validating, setValidating] = useState(false)
  const seq = useRef(0)
  useEffect(() => {
    if (!data) return
    // Pristine (no edits since load): nothing to validate, and never leave the
    // spinner on. NOTE: do NOT depend on `validation` here — this effect SETS it, so
    // listing it would self-trigger forever (Validating… never ends, Save stays
    // disabled). Re-validate only when the draft (or the loaded doc) changes.
    if (draft === loadedYaml) {
      setValidating(false)
      return
    }
    const mine = ++seq.current
    setValidating(true)
    const t = setTimeout(async () => {
      try {
        const v = await api.validatePolicy(draft)
        if (mine === seq.current) setValidation(v)
      } catch {
        if (mine === seq.current)
          setValidation({ valid: false, error: "could not reach the controller" })
      } finally {
        if (mine === seq.current) setValidating(false)
      }
    }, 450)
    return () => clearTimeout(t)
  }, [draft, data, loadedYaml])

  // Entering the visual editor needs the CURRENT draft as a structure. Parse it
  // through the controller rather than guessing, and refuse to switch on a
  // document that does not parse — a structured editor over an unparseable file
  // would silently discard whatever it could not understand.
  async function enterVisual() {
    setVisualError(null)
    try {
      const v = await api.validatePolicy(draft)
      if (!v.valid || !v.policy) {
        setVisualError(v.error ?? "the document does not parse")
        return
      }
      setVisualDoc(v.policy)
      setMode("visual")
    } catch {
      setVisualError("could not reach the controller")
    }
  }

  // A visual edit re-renders the canonical document. The controller emits it, so
  // the editor never needs a YAML writer of its own.
  async function applyVisual(next: Policy) {
    setVisualDoc(next)
    setRendering(true)
    try {
      const r = await api.renderPolicy(next)
      setDraft(r.yaml)
      setVisualError(r.valid ? null : (r.error ?? null))
    } catch {
      setVisualError("could not reach the controller")
    } finally {
      setRendering(false)
    }
  }

  // Seed the visual document whenever the loaded policy changes under us.
  useEffect(() => {
    if (data?.policy) setVisualDoc(data.policy)
  }, [data?.policy])

  // Preview source: the freshly-validated structure when valid, else the last
  // good loaded policy so the preview never blanks while typing an invalid edit.
  const previewPolicy: Policy | null =
    validation?.valid && validation.policy
      ? validation.policy
      : (data?.policy ?? null)

  const valid = validation ? validation.valid : true
  const [saving, setSaving] = useState(false)

  async function save() {
    setSaving(true)
    try {
      await api.setPolicy(draft)
      toast.success("Policy saved", {
        description: "The new policy is live for this workspace.",
      })
      refresh()
      setValidation(null)
    } catch (e) {
      toast.error("Save failed", {
        description: e instanceof ApiError ? e.message : String(e),
      })
    } finally {
      setSaving(false)
    }
  }

  const status = useMemo(() => {
    if (validating)
      return { icon: Loader2, cls: "text-muted-foreground", spin: true, text: "Validating…" }
    if (validation && !validation.valid)
      return { icon: AlertTriangle, cls: "text-destructive", spin: false, text: "Invalid" }
    return { icon: Check, cls: "text-success", spin: false, text: "Valid" }
  }, [validating, validation])

  if (error && !data) {
    return (
      <Card>
        <ErrorState message={error} onRetry={refresh} />
      </Card>
    )
  }

  const StatusIcon = status.icon

  return (
    <div className="space-y-4">
      <PageToolbar
        description={
          editable
            ? `Edit this workspace's authorization policy${data ? ` (${data.workspace})` : ""}.`
            : "Authorization policy (read-only — workspace admin required to edit)."
        }
      >
        {data && (
          <span className="hidden text-xs text-muted-foreground sm:inline">
            {data.updatedUnix
              ? `Edited by ${data.updatedBy} · ${relativeTime(data.updatedUnix)}`
              : `Seeded by ${data.updatedBy}`}
          </span>
        )}
        {editable && (
          <Button
            size="sm"
            onClick={save}
            disabled={!dirty || !valid || saving || validating}
          >
            {saving ? (
              <Loader2 className="size-4 animate-spin" />
            ) : (
              <Save className="size-4" />
            )}
            Save
          </Button>
        )}
      </PageToolbar>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Editor */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold">Policy document</h2>
            <span className={`inline-flex items-center gap-1.5 text-xs ${status.cls}`}>
              <StatusIcon className={`size-3.5 ${status.spin ? "animate-spin" : ""}`} />
              {status.text}
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <ModeTab
              active={mode === "visual"}
              onClick={enterVisual}
              disabled={initialLoading}
            >
              Visual
            </ModeTab>
            <ModeTab
              active={mode === "yaml"}
              onClick={() => setMode("yaml")}
              disabled={initialLoading}
            >
              YAML
            </ModeTab>
            {rendering && (
              <span className="ml-1 text-2xs text-muted-foreground">rendering…</span>
            )}
          </div>

          {initialLoading ? (
            <div className="h-[60vh] animate-pulse rounded-lg bg-muted/40" />
          ) : mode === "yaml" ? (
            <textarea
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              readOnly={!editable}
              spellCheck={false}
              className="h-[60vh] w-full resize-none rounded-lg border bg-muted/20 p-3 font-mono text-xs leading-relaxed text-foreground outline-none focus:ring-2 focus:ring-ring read-only:opacity-80"
            />
          ) : visualDoc ? (
            <PolicyVisualEditor
              policy={visualDoc}
              editable={editable}
              onChange={applyVisual}
            />
          ) : (
            <Card className="p-4 text-sm text-muted-foreground">
              This document does not parse, so it cannot be edited structurally.
              Fix it in the YAML view.
            </Card>
          )}

          {visualError && (
            <div className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/10 p-2 text-xs text-warning">
              <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
              <span className="font-mono">{visualError}</span>
            </div>
          )}
          {validation && !validation.valid && validation.error && (
            <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-destructive">
              <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
              <span className="font-mono">{validation.error}</span>
            </div>
          )}
          {editable && (
            <p className="text-2xs text-muted-foreground">
              Roles grant actions on label-matched nodes; bindings map users and
              IdP groups to roles. <span className="font-mono">admin</span> is the
              reserved cluster role and cannot be granted here.
              {mode === "visual" && (
                <>
                  {" "}
                  A structural edit rewrites the document from the parsed policy,
                  so comments and key order are not preserved — use the YAML view
                  to keep them.
                </>
              )}
            </p>
          )}
        </div>

        {/* Live structured preview */}
        <div className="space-y-2">
          <h2 className="text-sm font-semibold text-muted-foreground">Preview</h2>
          <PolicyPreview policy={previewPolicy} />
        </div>
      </div>
    </div>
  )
}

function PolicyPreview({ policy }: { policy: Policy | null }) {
  const roles = policy ? Object.entries(policy.roles ?? {}) : []
  const bindings = policy?.bindings ?? []
  if (!policy) {
    return (
      <Card>
        <EmptyState title="No valid policy to preview" />
      </Card>
    )
  }
  return (
    <div className="max-h-[66vh] space-y-4 overflow-auto pr-1">
      <h3 className="flex items-center gap-2 text-xs font-semibold text-muted-foreground">
        <Shield className="size-3.5" /> Roles
      </h3>
      {roles.length === 0 ? (
        <Card>
          <EmptyState title="No roles defined" />
        </Card>
      ) : (
        roles.map(([name, role]) => (
          <Card key={name}>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-sm">
                <span className="font-mono">{name}</span>
                <Badge variant="muted">
                  {role.allow?.length ?? 0} rule
                  {(role.allow?.length ?? 0) === 1 ? "" : "s"}
                </Badge>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {(role.allow ?? []).map((rule, i) => (
                <RuleRow key={i} rule={rule} />
              ))}
              {(role.allow?.length ?? 0) === 0 && (
                <p className="text-sm text-muted-foreground">No allow rules.</p>
              )}
            </CardContent>
          </Card>
        ))
      )}

      <h3 className="flex items-center gap-2 text-xs font-semibold text-muted-foreground">
        <Users className="size-3.5" /> Bindings
      </h3>
      {bindings.length === 0 ? (
        <Card>
          <EmptyState title="No bindings" />
        </Card>
      ) : (
        <Card>
          <CardContent className="divide-y p-0">
            {bindings.map((b, i) => (
              <div key={i} className="px-4 py-3">
                <div className="mb-1.5 flex items-center gap-2">
                  <Badge className="font-mono">{b.role}</Badge>
                  <span className="text-xs text-muted-foreground">←</span>
                </div>
                <div className="space-y-1 pl-1 text-sm">
                  {b.users?.map((u) => (
                    <div key={`u-${u}`} className="flex items-center gap-2">
                      <Badge variant="outline" className="text-2xs">
                        user
                      </Badge>
                      <span className="text-muted-foreground">{u}</span>
                    </div>
                  ))}
                  {b.groups?.map((g) => (
                    <div key={`g-${g}`} className="flex items-center gap-2">
                      <Badge variant="outline" className="text-2xs">
                        group
                      </Badge>
                      <span className="text-muted-foreground">{g}</span>
                    </div>
                  ))}
                  {!b.users?.length && !b.groups?.length && (
                    <span className="text-xs text-muted-foreground">
                      no subjects
                    </span>
                  )}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  )
}

function RuleRow({ rule }: { rule: PolicyRule }) {
  const actions = Array.isArray(rule.actions) ? rule.actions : []
  const labelEntries =
    rule.node_labels && !Array.isArray(rule.node_labels)
      ? Object.entries(rule.node_labels)
      : []
  const labelArr = Array.isArray(rule.node_labels) ? rule.node_labels : []

  return (
    <div className="rounded-md border bg-muted/30 p-3">
      <div className="flex flex-wrap items-center gap-1.5">
        {actions.length > 0 ? (
          actions.map((a) => (
            <Badge key={a} variant="secondary" className="font-mono text-[11px]">
              {a}
            </Badge>
          ))
        ) : (
          <Badge variant="secondary" className="font-mono text-[11px]">
            any action
          </Badge>
        )}
      </div>

      {(labelEntries.length > 0 || labelArr.length > 0) && (
        <div className="mt-2">
          <span className="mr-2 text-xs text-muted-foreground">on nodes</span>
          <span className="inline-flex flex-wrap gap-1">
            {labelEntries.map(([k, v]) => (
              <Badge key={k} variant="muted" className="font-mono text-2xs">
                {k}
                <span className="opacity-50">=</span>
                {v}
              </Badge>
            ))}
            {labelArr.map((l) => (
              <Badge key={l} variant="muted" className="font-mono text-2xs">
                {l}
              </Badge>
            ))}
          </span>
        </div>
      )}

      <ExtraKeys rule={rule} />
    </div>
  )
}

const KNOWN = new Set(["actions", "node_labels"])

function ExtraKeys({ rule }: { rule: PolicyRule }) {
  const extras = Object.entries(rule).filter(([k]) => !KNOWN.has(k))
  if (extras.length === 0) return null
  return (
    <>
      <Separator className="my-2" />
      <div className="space-y-0.5 text-xs text-muted-foreground">
        {extras.map(([k, v]) => (
          <div key={k} className="flex gap-2">
            <span>{k}:</span>
            <CopyId
              value={typeof v === "string" ? v : JSON.stringify(v)}
              full
              label="Copied"
              className="text-foreground"
            />
          </div>
        ))}
      </div>
    </>
  )
}

// ModeTab is the Visual | YAML switch. Switching to Visual has to parse the
// current draft first, so it is a callback rather than plain state.
function ModeTab({
  active,
  disabled,
  onClick,
  children,
}: {
  active: boolean
  disabled?: boolean
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={
        active
          ? "rounded-[7px] border border-brand-line bg-brand-tint px-3 py-[5px] font-mono text-[11.5px] text-foreground"
          : "rounded-[7px] border border-border px-3 py-[5px] font-mono text-[11.5px] text-muted-foreground hover:text-foreground"
      }
    >
      {children}
    </button>
  )
}

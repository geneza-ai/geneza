import { ChevronDown, ChevronRight, Plus, Trash2 } from "lucide-react"

import { Button, Card, cn } from "@geneza/ui"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useState } from "react"
import type {
  Policy,
  PolicyBinding,
  PolicyRole,
  PolicyRule,
  PolicyTimeWindow,
} from "@/types"

// The actions the policy engine understands. "*" is offered explicitly because a
// blanket grant should be a deliberate click, not a typo that happens to parse.
const ACTIONS = ["*", "shell", "exec", "sftp", "forward", "attach", "vpn"]

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

/**
 * The structured half of the policy editor.
 *
 * It edits the parsed document and hands the whole structure back on every
 * change; the page renders that to canonical YAML through the controller, which
 * is also what validates and stores it. Nothing here re-implements the schema —
 * the one document that decides who may reach what must not have a second,
 * subtly-different notion of what it means living in the browser.
 */
export function PolicyVisualEditor({
  policy,
  editable,
  onChange,
}: {
  policy: Policy
  editable: boolean
  onChange: (next: Policy) => void
}) {
  const roles = Object.entries(policy.roles ?? {})
  const bindings = policy.bindings ?? []

  const setRole = (name: string, role: PolicyRole) =>
    onChange({ ...policy, roles: { ...(policy.roles ?? {}), [name]: role } })

  const renameRole = (from: string, to: string) => {
    if (!to.trim() || from === to) return
    const next: Record<string, PolicyRole> = {}
    for (const [k, v] of Object.entries(policy.roles ?? {})) {
      next[k === from ? to : k] = v
    }
    // Bindings reference roles by name, so a rename has to follow through or the
    // binding silently stops granting anything.
    onChange({
      ...policy,
      roles: next,
      bindings: bindings.map((b) => (b.role === from ? { ...b, role: to } : b)),
    })
  }

  const dropRole = (name: string) => {
    const next = { ...(policy.roles ?? {}) }
    delete next[name]
    onChange({ ...policy, roles: next })
  }

  const addRole = () => {
    let name = "new-role"
    let i = 2
    while (policy.roles?.[name]) name = `new-role-${i++}`
    setRole(name, { allow: [{ actions: ["shell"], node_labels: { "*": "*" } }] })
  }

  const setBindings = (next: PolicyBinding[]) =>
    onChange({ ...policy, bindings: next })

  return (
    <div className="max-h-[60vh] space-y-4 overflow-auto pr-1">
      <section className="space-y-2">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-semibold text-muted-foreground">
            ROLES — what may be done, and to which nodes
          </h3>
          {editable && (
            <Button variant="outline" size="sm" onClick={addRole}>
              <Plus className="size-3.5" />
              Add role
            </Button>
          )}
        </div>
        {roles.length === 0 ? (
          <Card className="p-4 text-sm text-muted-foreground">
            No roles. A policy with no roles grants nothing.
          </Card>
        ) : (
          roles.map(([name, role]) => (
            <RoleCard
              key={name}
              name={name}
              role={role}
              editable={editable}
              onRename={(to) => renameRole(name, to)}
              onChange={(r) => setRole(name, r)}
              onDelete={() => dropRole(name)}
            />
          ))
        )}
      </section>

      <section className="space-y-2">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-semibold text-muted-foreground">
            BINDINGS — who holds which role
          </h3>
          {editable && (
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                setBindings([
                  ...bindings,
                  { role: roles[0]?.[0] ?? "", users: [] },
                ])
              }
            >
              <Plus className="size-3.5" />
              Add binding
            </Button>
          )}
        </div>
        {bindings.length === 0 ? (
          <Card className="p-4 text-sm text-muted-foreground">
            No bindings. Roles may still be granted by workspace membership.
          </Card>
        ) : (
          bindings.map((b, i) => (
            <Card key={i} className="space-y-3 p-3">
              <div className="flex items-center gap-2">
                <select
                  value={b.role}
                  disabled={!editable}
                  onChange={(e) =>
                    setBindings(
                      bindings.map((x, j) =>
                        j === i ? { ...x, role: e.target.value } : x
                      )
                    )
                  }
                  className="rounded-[7px] border bg-background px-2 py-1.5 font-mono text-xs"
                >
                  {roles.map(([r]) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
                <div className="flex-1" />
                {editable && (
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    onClick={() => setBindings(bindings.filter((_, j) => j !== i))}
                  >
                    <Trash2 className="size-3.5" />
                  </Button>
                )}
              </div>
              <ListField
                label="Users"
                value={b.users ?? []}
                editable={editable}
                placeholder="alice, bob"
                onChange={(v) =>
                  setBindings(
                    bindings.map((x, j) => (j === i ? { ...x, users: v } : x))
                  )
                }
              />
              <ListField
                label="Groups"
                value={b.groups ?? []}
                editable={editable}
                placeholder="IdP groups"
                onChange={(v) =>
                  setBindings(
                    bindings.map((x, j) => (j === i ? { ...x, groups: v } : x))
                  )
                }
              />
            </Card>
          ))
        )}
      </section>
    </div>
  )
}

function RoleCard({
  name,
  role,
  editable,
  onRename,
  onChange,
  onDelete,
}: {
  name: string
  role: PolicyRole
  editable: boolean
  onRename: (to: string) => void
  onChange: (r: PolicyRole) => void
  onDelete: () => void
}) {
  const [open, setOpen] = useState(true)
  const [draftName, setDraftName] = useState(name)
  const rules = role.allow ?? []

  const setRule = (i: number, rule: PolicyRule) =>
    onChange({ ...role, allow: rules.map((r, j) => (j === i ? rule : r)) })

  return (
    <Card className="p-3">
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className="text-faint hover:text-foreground"
        >
          {open ? (
            <ChevronDown className="size-4" />
          ) : (
            <ChevronRight className="size-4" />
          )}
        </button>
        <Input
          value={draftName}
          disabled={!editable}
          onChange={(e) => setDraftName(e.target.value)}
          onBlur={() => onRename(draftName.trim())}
          className="h-8 w-52 font-mono text-xs"
        />
        <Badge variant="outline">
          {rules.length} rule{rules.length === 1 ? "" : "s"}
        </Badge>
        <div className="flex-1" />
        {editable && (
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                onChange({
                  ...role,
                  allow: [...rules, { actions: ["shell"], node_labels: { "*": "*" } }],
                })
              }
            >
              <Plus className="size-3.5" />
              Rule
            </Button>
            <Button variant="ghost" size="icon-sm" onClick={onDelete}>
              <Trash2 className="size-3.5" />
            </Button>
          </>
        )}
      </div>

      {open && (
        <div className="mt-3 space-y-3">
          {rules.map((rule, i) => (
            <RuleEditor
              key={i}
              rule={rule}
              editable={editable}
              onChange={(r) => setRule(i, r)}
              onDelete={() =>
                onChange({ ...role, allow: rules.filter((_, j) => j !== i) })
              }
            />
          ))}
        </div>
      )}
    </Card>
  )
}

function RuleEditor({
  rule,
  editable,
  onChange,
  onDelete,
}: {
  rule: PolicyRule
  editable: boolean
  onChange: (r: PolicyRule) => void
  onDelete: () => void
}) {
  const actions = rule.actions ?? []
  const toggleAction = (a: string) =>
    onChange({
      ...rule,
      actions: actions.includes(a)
        ? actions.filter((x) => x !== a)
        : [...actions.filter((x) => x !== "*" || a === "*"), a],
    })

  // node_labels may be a map or a list in the wild; the editor only offers the map
  // form and leaves a list untouched rather than lossily converting it.
  const labelsAreMap =
    rule.node_labels === undefined ||
    (typeof rule.node_labels === "object" && !Array.isArray(rule.node_labels))
  const labels = labelsAreMap
    ? ((rule.node_labels as Record<string, string>) ?? {})
    : {}

  return (
    <div className="space-y-3 rounded-lg border bg-muted/20 p-3">
      <div className="flex items-start justify-between gap-2">
        <div className="space-y-1.5">
          <Label className="text-2xs">Actions</Label>
          <div className="flex flex-wrap gap-1.5">
            {ACTIONS.map((a) => (
              <button
                key={a}
                type="button"
                disabled={!editable}
                onClick={() => toggleAction(a)}
                className={cn(
                  "rounded-[6px] border px-2 py-1 font-mono text-[11px] transition-colors",
                  actions.includes(a)
                    ? "border-brand-line bg-brand-tint text-foreground"
                    : "border-border text-muted-foreground hover:text-foreground"
                )}
              >
                {a}
              </button>
            ))}
          </div>
        </div>
        {editable && (
          <Button variant="ghost" size="icon-sm" onClick={onDelete}>
            <Trash2 className="size-3.5" />
          </Button>
        )}
      </div>

      {labelsAreMap ? (
        <MapField
          label="Node labels"
          hint='All must match. Use * = * for any node.'
          value={labels}
          editable={editable}
          onChange={(v) => onChange({ ...rule, node_labels: v })}
        />
      ) : (
        <p className="text-2xs text-muted-foreground">
          This rule's node_labels use a list form the visual editor does not edit;
          switch to YAML to change it. It is preserved as-is.
        </p>
      )}

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label className="text-2xs">Max session TTL</Label>
          <Input
            value={rule.max_session_ttl ?? ""}
            disabled={!editable}
            placeholder="e.g. 8h (blank = engine default)"
            onChange={(e) =>
              onChange({
                ...rule,
                max_session_ttl: e.target.value || undefined,
              })
            }
            className="h-8 font-mono text-xs"
          />
        </div>
        <ListField
          label="Services"
          value={rule.services ?? []}
          editable={editable}
          placeholder="blank = plain node access"
          onChange={(v) =>
            onChange({ ...rule, services: v.length ? v : undefined })
          }
        />
      </div>

      <div className="flex flex-wrap gap-x-5 gap-y-2">
        <Toggle
          label="Record sessions"
          hint="Unset defaults to on."
          checked={rule.record !== false}
          editable={editable}
          onChange={(v) => onChange({ ...rule, record: v ? undefined : false })}
        />
        <Toggle
          label="Allow detach"
          hint="Unset defaults to on."
          checked={rule.allow_detach !== false}
          editable={editable}
          onChange={(v) =>
            onChange({ ...rule, allow_detach: v ? undefined : false })
          }
        />
        <Toggle
          label="Read-only"
          hint="Input denied while the session is live."
          checked={!!rule.read_only}
          editable={editable}
          onChange={(v) => onChange({ ...rule, read_only: v || undefined })}
        />
        <Toggle
          label="Require presence"
          hint="Continuous human-presence factor."
          checked={!!rule.require_presence}
          editable={editable}
          onChange={(v) => onChange({ ...rule, require_presence: v || undefined })}
        />
        <Toggle
          label="Native client only"
          hint="Excludes the web shell, which proxies plaintext."
          checked={!!rule.require_native}
          editable={editable}
          onChange={(v) => onChange({ ...rule, require_native: v || undefined })}
        />
      </div>

      <TimeWindowField
        label="Time window"
        value={rule.time_window}
        editable={editable}
        onChange={(v) => onChange({ ...rule, time_window: v })}
      />
    </div>
  )
}

function Toggle({
  label,
  hint,
  checked,
  editable,
  onChange,
}: {
  label: string
  hint?: string
  checked: boolean
  editable: boolean
  onChange: (v: boolean) => void
}) {
  return (
    <label className="flex items-start gap-2 text-xs">
      <input
        type="checkbox"
        className="mt-0.5 size-3.5 shrink-0 accent-primary"
        checked={checked}
        disabled={!editable}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>
        {label}
        {hint && <span className="block text-2xs text-muted-foreground">{hint}</span>}
      </span>
    </label>
  )
}

function ListField({
  label,
  value,
  editable,
  placeholder,
  onChange,
}: {
  label: string
  value: string[]
  editable: boolean
  placeholder?: string
  onChange: (v: string[]) => void
}) {
  return (
    <div className="space-y-1.5">
      <Label className="text-2xs">{label}</Label>
      <Input
        value={value.join(", ")}
        disabled={!editable}
        placeholder={placeholder}
        onChange={(e) =>
          onChange(
            e.target.value
              .split(",")
              .map((s) => s.trim())
              .filter(Boolean)
          )
        }
        className="h-8 font-mono text-xs"
      />
    </div>
  )
}

function MapField({
  label,
  hint,
  value,
  editable,
  onChange,
}: {
  label: string
  hint?: string
  value: Record<string, string>
  editable: boolean
  onChange: (v: Record<string, string>) => void
}) {
  const entries = Object.entries(value)
  const set = (i: number, k: string, v: string) => {
    const next: Record<string, string> = {}
    entries.forEach(([ek, ev], j) => {
      if (j === i) next[k] = v
      else next[ek] = ev
    })
    onChange(next)
  }
  return (
    <div className="space-y-1.5">
      <Label className="text-2xs">{label}</Label>
      {hint && <p className="text-2xs text-muted-foreground">{hint}</p>}
      <div className="space-y-1.5">
        {entries.map(([k, v], i) => (
          <div key={i} className="flex items-center gap-1.5">
            <Input
              value={k}
              disabled={!editable}
              onChange={(e) => set(i, e.target.value, v)}
              className="h-8 font-mono text-xs"
              placeholder="key"
            />
            <span className="text-muted-foreground">=</span>
            <Input
              value={v}
              disabled={!editable}
              onChange={(e) => set(i, k, e.target.value)}
              className="h-8 font-mono text-xs"
              placeholder="value"
            />
            {editable && (
              <Button
                variant="ghost"
                size="icon-sm"
                onClick={() => {
                  const next = { ...value }
                  delete next[k]
                  onChange(next)
                }}
              >
                <Trash2 className="size-3.5" />
              </Button>
            )}
          </div>
        ))}
      </div>
      {editable && (
        <Button
          variant="outline"
          size="sm"
          onClick={() => onChange({ ...value, "": "" })}
        >
          <Plus className="size-3.5" />
          Add label
        </Button>
      )}
    </div>
  )
}

function TimeWindowField({
  label,
  value,
  editable,
  onChange,
}: {
  label: string
  value?: PolicyTimeWindow
  editable: boolean
  onChange: (v: PolicyTimeWindow | undefined) => void
}) {
  const on = !!value
  return (
    <div className="space-y-1.5">
      <Toggle
        label={label}
        hint="Restrict this rule to a clock window (controller-local time)."
        checked={on}
        editable={editable}
        onChange={(v) => onChange(v ? { start: "09:00", end: "17:00" } : undefined)}
      />
      {on && (
        <div className="ml-5 space-y-2">
          <div className="flex items-center gap-2">
            <Input
              value={value?.start ?? ""}
              disabled={!editable}
              placeholder="09:00"
              onChange={(e) => onChange({ ...value, start: e.target.value })}
              className="h-8 w-24 font-mono text-xs"
            />
            <span className="text-xs text-muted-foreground">to</span>
            <Input
              value={value?.end ?? ""}
              disabled={!editable}
              placeholder="17:00"
              onChange={(e) => onChange({ ...value, end: e.target.value })}
              className="h-8 w-24 font-mono text-xs"
            />
          </div>
          <div className="flex flex-wrap gap-1.5">
            {DAYS.map((d) => {
              const days = value?.days ?? []
              const active = days.length === 0 || days.includes(d)
              return (
                <button
                  key={d}
                  type="button"
                  disabled={!editable}
                  onClick={() =>
                    onChange({
                      ...value,
                      days: days.includes(d)
                        ? days.filter((x) => x !== d)
                        : [...days, d],
                    })
                  }
                  className={cn(
                    "rounded-[6px] border px-2 py-1 font-mono text-[11px]",
                    active
                      ? "border-brand-line bg-brand-tint text-foreground"
                      : "border-border text-muted-foreground"
                  )}
                >
                  {d}
                </button>
              )
            })}
          </div>
          <p className="text-2xs text-muted-foreground">
            No days selected means every day.
          </p>
        </div>
      )}
    </div>
  )
}

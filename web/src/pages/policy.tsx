import { useState } from "react"
import { Shield, Users } from "lucide-react"

import { api } from "@/api"
import { usePolling } from "@/hooks/use-polling"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { Separator } from "@/components/ui/separator"
import { EmptyState, ErrorState } from "@/components/states"
import { PageToolbar } from "@/components/page-toolbar"
import { CopyId } from "@/components/copy-id"
import type { Policy, PolicyRule } from "@/types"

export function PolicyPage() {
  const { data, error, initialLoading, refresh } = usePolling<Policy>(
    (s) => api.getPolicy(s),
    0
  )
  const [raw, setRaw] = useState(false)

  const roles = data ? Object.entries(data.roles) : []
  const bindings = data?.bindings ?? []

  return (
    <div className="space-y-4">
      <PageToolbar description="Roles and bindings (read-only).">
        <Button
          variant={raw ? "secondary" : "outline"}
          size="sm"
          onClick={() => setRaw((v) => !v)}
        >
          {raw ? "Formatted view" : "View raw"}
        </Button>
      </PageToolbar>

      {error && !data ? (
        <Card>
          <ErrorState message={error} onRetry={refresh} />
        </Card>
      ) : initialLoading ? (
        <PolicySkeleton />
      ) : raw ? (
        <Card>
          <CardContent className="p-0">
            <pre className="max-h-[70vh] overflow-auto rounded-lg bg-muted/40 p-4 font-mono text-xs leading-relaxed">
              {JSON.stringify(data, null, 2)}
            </pre>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <div className="space-y-4 lg:col-span-2">
            <h2 className="flex items-center gap-2 text-sm font-semibold">
              <Shield className="size-4 text-muted-foreground" /> Roles
            </h2>
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
                      <p className="text-sm text-muted-foreground">
                        No allow rules.
                      </p>
                    )}
                  </CardContent>
                </Card>
              ))
            )}
          </div>

          <div className="space-y-4">
            <h2 className="flex items-center gap-2 text-sm font-semibold">
              <Users className="size-4 text-muted-foreground" /> Bindings
            </h2>
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
                        <span className="text-xs text-muted-foreground">
                          ←
                        </span>
                      </div>
                      <div className="space-y-1 pl-1 text-sm">
                        {b.users?.map((u) => (
                          <div
                            key={`u-${u}`}
                            className="flex items-center gap-2"
                          >
                            <Badge variant="outline" className="text-[10px]">
                              user
                            </Badge>
                            <span className="text-muted-foreground">{u}</span>
                          </div>
                        ))}
                        {b.groups?.map((g) => (
                          <div
                            key={`g-${g}`}
                            className="flex items-center gap-2"
                          >
                            <Badge variant="outline" className="text-[10px]">
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
        </div>
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
              <Badge key={k} variant="muted" className="font-mono text-[10px]">
                {k}
                <span className="opacity-50">=</span>
                {v}
              </Badge>
            ))}
            {labelArr.map((l) => (
              <Badge key={l} variant="muted" className="font-mono text-[10px]">
                {l}
              </Badge>
            ))}
          </span>
        </div>
      )}

      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
        {rule.time_window && (
          <span>
            window:{" "}
            <span className="font-mono text-foreground">{rule.time_window}</span>
          </span>
        )}
        {rule.require_native !== undefined && (
          <span>
            require_native:{" "}
            <span className="font-mono text-foreground">
              {String(rule.require_native)}
            </span>
          </span>
        )}
      </div>

      <ExtraKeys rule={rule} />
    </div>
  )
}

const KNOWN = new Set([
  "actions",
  "node_labels",
  "time_window",
  "require_native",
])

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

function PolicySkeleton() {
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      <div className="space-y-4 lg:col-span-2">
        {Array.from({ length: 2 }).map((_, i) => (
          <Card key={i}>
            <CardHeader>
              <Skeleton className="h-5 w-32" />
            </CardHeader>
            <CardContent className="space-y-2">
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-16 w-full" />
            </CardContent>
          </Card>
        ))}
      </div>
      <Card>
        <CardHeader>
          <Skeleton className="h-5 w-24" />
        </CardHeader>
        <CardContent className="space-y-3">
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-12 w-full" />
        </CardContent>
      </Card>
    </div>
  )
}

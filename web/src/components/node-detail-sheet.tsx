import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
import { StatusDot } from "@/components/status-dot"
import { CopyId } from "@/components/copy-id"
import { LabelTags } from "@/components/label-tags"
import { Separator } from "@/components/ui/separator"
import { absoluteTime, relativeTime } from "@/lib/format"
import type { NodeInfo } from "@/types"

function Field({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}) {
  return (
    <div className="grid grid-cols-3 gap-3 py-2 text-sm">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="col-span-2 min-w-0 break-words">{children}</dd>
    </div>
  )
}

export function NodeDetailSheet({
  node,
  open,
  onOpenChange,
}: {
  node: NodeInfo | null
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent>
        {node && (
          <>
            <SheetHeader>
              <SheetTitle className="flex items-center gap-2">
                <StatusDot online={node.online} />
                {node.name}
              </SheetTitle>
              <SheetDescription>
                {node.online
                  ? "Online"
                  : `Offline · last seen ${relativeTime(node.lastSeenUnix)}`}
              </SheetDescription>
            </SheetHeader>

            <div className="flex-1 overflow-y-auto px-6 pb-6">
              <dl className="divide-y">
                <Field label="Node ID">
                  <CopyId value={node.nodeId} full label="Node ID copied" />
                </Field>
                <Field label="Status">
                  {node.online ? "Online" : "Offline"}
                </Field>
                <Field label="Version">
                  <span className="font-mono text-xs">
                    {node.version || "—"}
                  </span>
                </Field>
                <Field label="Platform">
                  <span className="font-mono text-xs">
                    {node.os}/{node.arch}
                  </span>
                </Field>
                <Field label="Active sessions">
                  {node.activeSessions}
                </Field>
                <Field label="Detached sessions">
                  {node.detachedSessions}
                </Field>
                <Field label="Last seen">
                  <span title={absoluteTime(node.lastSeenUnix)}>
                    {relativeTime(node.lastSeenUnix)}
                  </span>
                </Field>
                <Field label="Enrolled">
                  <span title={absoluteTime(node.createdUnix)}>
                    {absoluteTime(node.createdUnix)}
                  </span>
                </Field>
              </dl>

              <Separator className="my-4" />

              <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Labels
              </p>
              {Object.keys(node.labels ?? {}).length === 0 ? (
                <p className="text-sm text-muted-foreground">No labels.</p>
              ) : (
                <LabelTags labels={node.labels} />
              )}
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  )
}

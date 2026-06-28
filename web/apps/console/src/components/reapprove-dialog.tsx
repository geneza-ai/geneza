import { useEffect, useRef, useState } from "react"
import { toast } from "sonner"

import { Button } from "@geneza/ui"

import { api } from "@/api"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import type { NodeInfo } from "@/types"

// ReapproveDialog collects the reason the server requires before a quarantined
// node can be re-approved (the cause is recorded in the audit log). A freshly
// pending node is approved without this dialog — only quarantined nodes
// open it. Pass node=null to keep it closed.
export function ReapproveDialog({
  node,
  onClose,
  onApproved,
}: {
  node: NodeInfo | null
  onClose: () => void
  onApproved: () => void
}) {
  const [reason, setReason] = useState("")
  const [busy, setBusy] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (node) {
      setReason("")
      // Focus after the dialog's open animation so the caret lands in the field.
      const t = setTimeout(() => inputRef.current?.focus(), 50)
      return () => clearTimeout(t)
    }
  }, [node])

  async function confirm() {
    if (!node || !reason.trim()) return
    setBusy(true)
    try {
      await api.approveNode(node.nodeId, true, reason.trim())
      toast.success("Node approved", { description: node.name })
      onApproved()
    } catch (e) {
      toast.error("Approve failed", {
        description: e instanceof Error ? e.message : String(e),
      })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={node !== null} onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Re-approve quarantined node?</DialogTitle>
          <DialogDescription>
            {node?.name ?? "This node"} is quarantined
            {node?.quarantineReason ? ` — ${node.quarantineReason}` : ""}. Enter a
            reason to re-approve it; it is recorded in the audit log.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-2">
          <Label htmlFor="reapprove-reason">Reason</Label>
          <Input
            id="reapprove-reason"
            ref={inputRef}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="e.g. drift investigated, package re-pinned"
            disabled={busy}
            onKeyDown={(e) => {
              if (e.key === "Enter" && reason.trim()) confirm()
            }}
          />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={confirm} disabled={busy || !reason.trim()}>
            Re-approve
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

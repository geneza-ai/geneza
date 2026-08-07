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

// isBinaryDrift reports whether a quarantine was caused by the node's binary
// changing. It matters because re-approval CANNOT clear that: the controller
// deliberately preserves the blessed baseline across an approval, so the node
// re-quarantines on its next 15s sweep. Only a re-baseline resolves it.
function isBinaryDrift(reason?: string): boolean {
  return reason === "binary_tamper" || reason === "binary_downgrade"
}

// ReapproveDialog collects the reason the server requires before a quarantined
// node can be re-approved (the cause is recorded in the audit log). A freshly
// pending node is approved without this dialog — only quarantined nodes
// open it. Pass node=null to keep it closed.
//
// For a BINARY-DRIFT quarantine it offers re-baseline instead, because plain
// re-approval there is the failure this dialog used to walk operators into: it
// reports success, the node goes green, and it flips back seconds later with
// nothing connecting the two events.
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
  const drift = isBinaryDrift(node?.quarantineReason)
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
      if (drift) {
        // Blesses the binary the node is CURRENTLY running, then returns it to
        // service. Approving instead would be undone by the next sweep.
        const r = await api.rebaselineNode(node.nodeId, reason.trim())
        toast.success("Binary re-baselined", {
          description: `${node.name} — now pinned to ${r.binaryHash.slice(0, 12)}…`,
        })
      } else {
        await api.approveNode(node.nodeId, true, reason.trim())
        toast.success("Node approved", { description: node.name })
      }
      onApproved()
    } catch (e) {
      toast.error(drift ? "Re-baseline failed" : "Approve failed", {
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
          <DialogTitle>
            {drift ? "Accept this node's current binary?" : "Re-approve quarantined node?"}
          </DialogTitle>
          <DialogDescription>
            {node?.name ?? "This node"} is quarantined
            {node?.quarantineReason ? ` — ${node.quarantineReason}` : ""}.{" "}
            {drift ? (
              <>
                Its agent binary no longer matches the one that was approved, and
                the controller has no published release matching what it now runs.
                Re-approving alone would not hold — the next check would quarantine
                it again. This blesses the binary it is running now as the new
                baseline, so only do it if you updated that agent yourself and have
                verified it. Recorded in the audit log as a re-baseline.
              </>
            ) : (
              <>Enter a reason to re-approve it; it is recorded in the audit log.</>
            )}
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-2">
          <Label htmlFor="reapprove-reason">Reason</Label>
          <Input
            id="reapprove-reason"
            ref={inputRef}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder={
              drift
                ? "e.g. agent updated by hand from release 0.0.12, checksum verified"
                : "e.g. drift investigated, package re-pinned"
            }
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
            {drift ? "Accept binary" : "Re-approve"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

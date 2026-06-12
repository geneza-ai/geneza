import { useEffect, useMemo, useState } from "react"
import { Activity, Power } from "lucide-react"
import { toast } from "sonner"

import { api, ApiError } from "@/api"
import { usePolling } from "@/hooks/use-polling"
import { useSession } from "@/components/session-context"
import { Button } from "@/components/ui/button"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { EmptyState } from "@/components/states"
import { PageToolbar } from "@/components/page-toolbar"
import { NodeMetricsGrid, RANGES } from "@/components/node-metrics"
import type { NodesResponse } from "@/types"

export function MetricsPage() {
  const { me } = useSession()
  const { data: nodesData } = usePolling<NodesResponse>(
    (s) => api.getNodes(s),
    15000
  )
  const nodes = useMemo(() => nodesData?.nodes ?? [], [nodesData])

  const [node, setNode] = useState<string>("")
  const [rangeSec, setRangeSec] = useState(RANGES[1].sec)

  // Default to the first online node once nodes load.
  useEffect(() => {
    if (!node && nodes.length) {
      setNode(nodes.find((n) => n.online)?.name || nodes[0].name)
    }
  }, [nodes, node])

  const selected = nodes.find((n) => n.name === node)
  const enabled = Boolean(node)

  // Module state for the toggle.
  const [monOn, setMonOn] = useState<boolean | null>(null)
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    if (!selected) return
    let active = true
    api
      .getNodeModules(selected.nodeId)
      .then((r) => {
        if (active)
          setMonOn(r.modules.some((m) => m.name === "node-exporter" && m.enabled))
      })
      .catch(() => active && setMonOn(null))
    return () => {
      active = false
    }
  }, [selected])

  async function toggleMonitoring() {
    if (!selected) return
    setBusy(true)
    const next = !monOn
    try {
      await api.setNodeModules(selected.nodeId, [
        { name: "node-exporter", enabled: next },
      ])
      setMonOn(next)
      toast.success(next ? "Monitoring enabled" : "Monitoring disabled", {
        description: selected.name,
      })
    } catch (err) {
      toast.error("Failed to update monitoring", {
        description: err instanceof ApiError ? err.message : String(err),
      })
    } finally {
      setBusy(false)
    }
  }

  if (nodes.length === 0) {
    return (
      <EmptyState
        icon={<Activity className="size-8" />}
        title="No machines"
        message="Enroll a machine to collect metrics."
      />
    )
  }

  return (
    <div className="space-y-4">
      <PageToolbar description="Built-in metrics — collected over the agent control channel, stored in the gateway's embedded TSDB.">
        <Select value={node} onValueChange={setNode}>
          <SelectTrigger className="w-48">
            <SelectValue placeholder="Select machine" />
          </SelectTrigger>
          <SelectContent>
            {nodes.map((n) => (
              <SelectItem key={n.nodeId} value={n.name}>
                {n.name}
                {!n.online && " (offline)"}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={String(rangeSec)}
          onValueChange={(v) => setRangeSec(Number(v))}
        >
          <SelectTrigger className="w-36">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {RANGES.map((r) => (
              <SelectItem key={r.sec} value={String(r.sec)}>
                {r.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {me.admin && selected && (
          <Button
            variant={monOn ? "outline" : "default"}
            size="sm"
            onClick={toggleMonitoring}
            disabled={busy || monOn === null}
          >
            <Power className="size-4" />
            {monOn ? "Disable monitoring" : "Enable monitoring"}
          </Button>
        )}
      </PageToolbar>

      {me.admin && monOn === false && (
        <div className="rounded-md border border-dashed bg-muted/30 px-4 py-3 text-sm text-muted-foreground">
          Monitoring is <span className="font-medium text-foreground">off</span>{" "}
          for {node}. Enable it to start collecting metrics — the agent will begin
          rendering node-exporter metrics on demand over its control channel.
        </div>
      )}

      <NodeMetricsGrid node={node} rangeSec={rangeSec} enabled={enabled} />
    </div>
  )
}

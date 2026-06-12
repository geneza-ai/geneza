import { MetricChart } from "@/components/metric-chart"
import { useMetricRange, promInstance } from "@/lib/promql"

export const RANGES = [
  { label: "Last 15m", sec: 15 * 60 },
  { label: "Last 1h", sec: 60 * 60 },
  { label: "Last 6h", sec: 6 * 60 * 60 },
  { label: "Last 24h", sec: 24 * 60 * 60 },
]

const pct = (v: number) => `${Math.round(v * 10) / 10}%`
const bytesPerSec = (v: number) => {
  const u = ["B/s", "KB/s", "MB/s", "GB/s"]
  let i = 0
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024
    i++
  }
  return `${Math.round(v * 10) / 10} ${u[i]}`
}

// NodeMetricsGrid renders the standard node-exporter panels for one machine,
// shared by the Metrics page and the machine-detail Metrics tab.
export function NodeMetricsGrid({
  node,
  rangeSec,
  enabled = true,
}: {
  node: string
  rangeSec: number
  enabled?: boolean
}) {
  const inst = node ? promInstance(node) : ""
  const on = enabled && Boolean(node)

  const cpu = useMetricRange(
    `clamp_min((1 - avg by(instance)(rate(node_cpu_seconds_total{instance="${inst}",mode="idle"}[2m]))) * 100, 0)`,
    rangeSec,
    () => "cpu",
    { enabled: on }
  )
  const mem = useMetricRange(
    `(1 - node_memory_MemAvailable_bytes{instance="${inst}"} / node_memory_MemTotal_bytes{instance="${inst}"}) * 100`,
    rangeSec,
    () => "memory",
    { enabled: on }
  )
  const load = useMetricRange(
    `node_load1{instance="${inst}"}`,
    rangeSec,
    () => "load1",
    { enabled: on }
  )
  const disk = useMetricRange(
    `(1 - node_filesystem_avail_bytes{instance="${inst}",mountpoint="/"} / node_filesystem_size_bytes{instance="${inst}",mountpoint="/"}) * 100`,
    rangeSec,
    () => "disk /",
    { enabled: on }
  )
  const netRx = useMetricRange(
    `rate(node_network_receive_bytes_total{instance="${inst}",device!="lo"}[2m])`,
    rangeSec,
    (l) => `rx ${l.device}`,
    { enabled: on }
  )
  const netTx = useMetricRange(
    `rate(node_network_transmit_bytes_total{instance="${inst}",device!="lo"}[2m])`,
    rangeSec,
    (l) => `tx ${l.device}`,
    { enabled: on }
  )

  return (
    <div className="grid gap-4 md:grid-cols-2">
      <MetricChart title="CPU utilization" rows={cpu.rows} keys={cpu.keys} loading={cpu.loading} error={cpu.error} format={pct} domain={[0, 100]} />
      <MetricChart title="Memory used" rows={mem.rows} keys={mem.keys} loading={mem.loading} error={mem.error} format={pct} domain={[0, 100]} />
      <MetricChart title="Load (1m)" rows={load.rows} keys={load.keys} loading={load.loading} error={load.error} variant="line" />
      <MetricChart title="Disk used (/)" rows={disk.rows} keys={disk.keys} loading={disk.loading} error={disk.error} format={pct} domain={[0, 100]} />
      <MetricChart title="Network in" rows={netRx.rows} keys={netRx.keys} loading={netRx.loading} error={netRx.error} format={bytesPerSec} />
      <MetricChart title="Network out" rows={netTx.rows} keys={netTx.keys} loading={netTx.loading} error={netTx.error} format={bytesPerSec} />
    </div>
  )
}

import { useMemo } from "react"
import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
  XAxis,
  YAxis,
} from "recharts"

import { Card, CardContent, CardHeader, CardTitle } from "@geneza/ui"
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart"
import { Skeleton } from "@geneza/ui"
import type { ChartRow } from "@/lib/promql"

// Neutral, theme-aware palette (chart series only).
const PALETTE = [
  "var(--chart-1, #2563eb)",
  "var(--chart-2, #16a34a)",
  "var(--chart-3, #d97706)",
  "var(--chart-4, #9333ea)",
  "var(--chart-5, #dc2626)",
  "var(--chart-6, #0891b2)",
]

function fmtTime(t: number): string {
  return new Date(t * 1000).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  })
}

export interface MetricChartProps {
  title: string
  rows: ChartRow[]
  keys: string[]
  loading?: boolean
  error?: string | null
  unit?: string
  format?: (v: number) => string
  domain?: [number, number]
  variant?: "area" | "line"
  height?: number
}

export function MetricChart({
  title,
  rows,
  keys,
  loading,
  error,
  unit,
  format,
  domain,
  variant = "area",
  height = 200,
}: MetricChartProps) {
  const fmt =
    format ?? ((v: number) => `${Math.round(v * 100) / 100}${unit ?? ""}`)
  const hasData = rows.length > 0 && keys.length > 0

  // Build a shadcn ChartConfig (label + color per series). The container injects
  // --color-<key> CSS vars so series colors are theme-driven, not hardcoded.
  const config = useMemo<ChartConfig>(() => {
    const c: ChartConfig = {}
    keys.forEach((k, i) => {
      c[k] = { label: k, color: PALETTE[i % PALETTE.length] }
    })
    return c
  }, [keys])

  return (
    <Card className="overflow-hidden">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent className="pl-0">
        {loading && !hasData ? (
          <Skeleton className="mx-4" style={{ height }} />
        ) : error ? (
          <div
            className="flex items-center justify-center px-4 text-center text-sm text-destructive"
            style={{ height }}
          >
            {error}
          </div>
        ) : !hasData ? (
          <div
            className="flex items-center justify-center px-4 text-sm text-muted-foreground"
            style={{ height }}
          >
            No data yet — enable monitoring on this node.
          </div>
        ) : (
          <ChartContainer
            config={config}
            className="aspect-auto w-full"
            style={{ height }}
          >
            {variant === "area" ? (
              <AreaChart
                data={rows}
                margin={{ top: 4, right: 16, left: 4, bottom: 0 }}
              >
                <defs>
                  {keys.map((k) => (
                    <linearGradient
                      id={`fill-${title}-${k}`}
                      key={k}
                      x1="0"
                      y1="0"
                      x2="0"
                      y2="1"
                    >
                      <stop
                        offset="0%"
                        stopColor={`var(--color-${k})`}
                        stopOpacity={0.35}
                      />
                      <stop
                        offset="100%"
                        stopColor={`var(--color-${k})`}
                        stopOpacity={0.02}
                      />
                    </linearGradient>
                  ))}
                </defs>
                <CartesianGrid vertical={false} />
                <XAxis
                  dataKey="t"
                  tickFormatter={fmtTime}
                  tickLine={false}
                  axisLine={false}
                  minTickGap={48}
                />
                <YAxis
                  tickFormatter={fmt}
                  tickLine={false}
                  axisLine={false}
                  width={56}
                  domain={domain}
                />
                <ChartTooltip
                  content={<ChartTooltipContent />}
                  labelFormatter={(_, p) =>
                    p?.[0] ? fmtTime(Number(p[0].payload.t)) : ""
                  }
                />
                {keys.map((k) => (
                  <Area
                    key={k}
                    type="monotone"
                    dataKey={k}
                    stroke={`var(--color-${k})`}
                    strokeWidth={1.5}
                    fill={`url(#fill-${title}-${k})`}
                    isAnimationActive={false}
                    connectNulls
                    dot={false}
                  />
                ))}
              </AreaChart>
            ) : (
              <LineChart
                data={rows}
                margin={{ top: 4, right: 16, left: 4, bottom: 0 }}
              >
                <CartesianGrid vertical={false} />
                <XAxis
                  dataKey="t"
                  tickFormatter={fmtTime}
                  tickLine={false}
                  axisLine={false}
                  minTickGap={48}
                />
                <YAxis
                  tickFormatter={fmt}
                  tickLine={false}
                  axisLine={false}
                  width={56}
                  domain={domain}
                />
                <ChartTooltip
                  content={<ChartTooltipContent />}
                  labelFormatter={(_, p) =>
                    p?.[0] ? fmtTime(Number(p[0].payload.t)) : ""
                  }
                />
                {keys.map((k) => (
                  <Line
                    key={k}
                    type="monotone"
                    dataKey={k}
                    stroke={`var(--color-${k})`}
                    strokeWidth={1.5}
                    isAnimationActive={false}
                    connectNulls
                    dot={false}
                  />
                ))}
              </LineChart>
            )}
          </ChartContainer>
        )}
      </CardContent>
    </Card>
  )
}

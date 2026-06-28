import type {
  AgentsResponse,
  ControllersResponse,
  RelaysResponse,
  RiskResponse,
  WorkspacesResponse,
} from "@/types"
import { getToken } from "@/auth"

const BASE = "/clusterconsole/v1"

// A 401 (a cluster session expired/revoked and no break-glass cert backs the
// request) bubbles to a single handler so the shell can fall back to the login
// screen, mirroring the tenant console.
let onUnauthorized: (() => void) | null = null
export function setUnauthorizedHandler(fn: (() => void) | null) {
  onUnauthorized = fn
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
    this.name = "ApiError"
  }
}

type Query = Record<string, string | number | boolean | undefined>

function buildUrl(path: string, query?: Query): string {
  const url = `${BASE}${path}`
  if (!query) return url
  const params = new URLSearchParams()
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== "" && v !== false) params.set(k, String(v))
  }
  const qs = params.toString()
  return qs ? `${url}?${qs}` : url
}

// The console shares the origin with the API. Two auth paths are carried at once:
// a break-glass mTLS client cert (credentials:"include" presents it at the TLS
// layer) and/or an OIDC-minted cluster session (the Authorization bearer). A
// cert-authed operator simply has no bearer to send.
async function get<T>(path: string, signal: AbortSignal, query?: Query): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" }
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`
  const res = await fetch(buildUrl(path, query), {
    method: "GET",
    credentials: "include",
    headers,
    signal,
  })
  if (!res.ok) {
    if (res.status === 401 || res.status === 403) onUnauthorized?.()
    let message = `Request failed (${res.status})`
    try {
      const body = await res.json()
      if (body?.error) message = body.error
    } catch {
      // Non-JSON error body; keep the status-derived message.
    }
    throw new ApiError(res.status, message)
  }
  return (await res.json()) as T
}

export const api = {
  controllers: (signal: AbortSignal) =>
    get<ControllersResponse>("/topology/controllers", signal),
  relays: (signal: AbortSignal) => get<RelaysResponse>("/topology/relays", signal),
  agents: (signal: AbortSignal, outdated?: boolean) =>
    get<AgentsResponse>("/agents", signal, { outdated }),
  risk: (signal: AbortSignal, outdatedOnly?: boolean) =>
    get<RiskResponse>("/agents/risk", signal, { outdated_only: outdatedOnly }),
  workspaces: (signal: AbortSignal) =>
    get<WorkspacesResponse>("/workspaces", signal),
}

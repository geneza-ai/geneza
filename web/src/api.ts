import { clearSession, getToken } from "@/auth"
import type {
  AppConfig,
  AuditResponse,
  Fleet,
  Me,
  NodeModule,
  NodeModulesResponse,
  NodesResponse,
  Overview,
  Policy,
  PromResponse,
  SessionsResponse,
  TokenRequest,
  TokenResponse,
} from "@/types"

const BASE = "/api/v1"

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
    this.name = "ApiError"
  }
}

/** Fired whenever a request comes back 401; the app navigates to Login. */
type UnauthorizedHandler = () => void
let onUnauthorized: UnauthorizedHandler | null = null
export function setUnauthorizedHandler(fn: UnauthorizedHandler | null) {
  onUnauthorized = fn
}

interface RequestOptions {
  /** Skip attaching the Bearer token (used for /config). */
  anonymous?: boolean
  signal?: AbortSignal
  query?: Record<string, string | number | undefined>
}

function buildUrl(path: string, query?: RequestOptions["query"]): string {
  const url = `${BASE}${path}`
  if (!query) return url
  const params = new URLSearchParams()
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null && v !== "") params.set(k, String(v))
  }
  const qs = params.toString()
  return qs ? `${url}?${qs}` : url
}

async function request<T>(
  method: "GET" | "POST" | "PUT" | "DELETE",
  path: string,
  opts: RequestOptions = {},
  body?: unknown
): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" }
  if (!opts.anonymous) {
    const token = getToken()
    if (token) headers.Authorization = `Bearer ${token}`
  }
  if (body !== undefined) headers["Content-Type"] = "application/json"

  let res: Response
  try {
    res = await fetch(buildUrl(path, opts.query), {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: opts.signal,
    })
  } catch (err) {
    if ((err as Error).name === "AbortError") throw err
    throw new ApiError(0, "Network error — gateway unreachable")
  }

  if (res.status === 401) {
    clearSession()
    onUnauthorized?.()
    throw new ApiError(401, "Session expired. Please sign in again.")
  }

  if (!res.ok) {
    let message = `Request failed (${res.status})`
    try {
      const data = await res.json()
      if (typeof data?.error === "string") message = data.error
      else if (typeof data?.message === "string") message = data.message
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, message)
  }

  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

export const api = {
  get<T>(path: string, opts?: RequestOptions) {
    return request<T>("GET", path, opts)
  },
  post<T>(path: string, body: unknown, opts?: RequestOptions) {
    return request<T>("POST", path, opts, body)
  },
  del<T>(path: string, opts?: RequestOptions) {
    return request<T>("DELETE", path, opts)
  },

  // Typed endpoint helpers --------------------------------------------------
  getConfig: (signal?: AbortSignal) =>
    request<AppConfig>("GET", "/config", { anonymous: true, signal }),
  getMe: (signal?: AbortSignal) => request<Me>("GET", "/me", { signal }),
  getOverview: (signal?: AbortSignal) =>
    request<Overview>("GET", "/overview", { signal }),
  getNodes: (signal?: AbortSignal) =>
    request<NodesResponse>("GET", "/nodes", { signal }),
  getSessions: (signal?: AbortSignal) =>
    request<SessionsResponse>("GET", "/sessions", { signal }),
  getFleet: (signal?: AbortSignal) =>
    request<Fleet>("GET", "/fleet", { signal }),
  getPolicy: (signal?: AbortSignal) =>
    request<Policy>("GET", "/policy", { signal }),
  getAudit: (
    query: { since?: number; type?: string; limit?: number },
    signal?: AbortSignal
  ) => request<AuditResponse>("GET", "/audit", { query, signal }),
  createToken: (body: TokenRequest) =>
    request<TokenResponse>("POST", "/tokens", {}, body),
  revokeSession: (id: string) =>
    request<{ ok: boolean }>("DELETE", `/sessions/${encodeURIComponent(id)}`),
  approveNode: (id: string, approve: boolean) =>
    request<{ ok: boolean; approved: boolean }>(
      "POST",
      `/nodes/${encodeURIComponent(id)}/approve`,
      {},
      { approve }
    ),
  removeNode: (id: string) =>
    request<{ ok: boolean }>("DELETE", `/nodes/${encodeURIComponent(id)}`),

  // --- monitoring ---
  getNodeModules: (id: string, signal?: AbortSignal) =>
    request<NodeModulesResponse>(
      "GET",
      `/nodes/${encodeURIComponent(id)}/modules`,
      { signal }
    ),
  setNodeModules: (id: string, modules: NodeModule[]) =>
    request<{ ok: boolean; version: number; modules: NodeModule[] }>(
      "PUT",
      `/nodes/${encodeURIComponent(id)}/modules`,
      {},
      { modules }
    ),
  queryRange: (
    query: string,
    startSec: number,
    endSec: number,
    stepSec: number,
    signal?: AbortSignal
  ) =>
    request<PromResponse>("GET", "/metrics/query_range", {
      query: {
        query,
        start: startSec,
        end: endSec,
        step: stepSec,
      },
      signal,
    }),
  queryInstant: (query: string, signal?: AbortSignal) =>
    request<PromResponse>("GET", "/metrics/query", {
      query: { query },
      signal,
    }),
}

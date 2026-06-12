// Shared API types mirroring the gateway JSON contract (base /api/v1).

export interface OidcConfig {
  issuer: string
  clientId: string
  redirectUri: string
}

export interface AppConfig {
  oidc: OidcConfig
  clusterName: string
  externalUrl: string
}

export interface Me {
  user: string
  roles: string[]
  groups: string[]
  admin: boolean
  expiresUnix: number
}

export interface Overview {
  nodes: { total: number; online: number }
  sessions: { active: number; detached: number; total: number }
  versions: { stable: string; canary: string }
  audit: { count: number; chainOk: boolean }
  relays: string[]
}

export interface NodeInfo {
  nodeId: string
  name: string
  online: boolean
  version: string
  os: string
  arch: string
  labels: Record<string, string>
  lastSeenUnix: number
  activeSessions: number
  detachedSessions: number
  createdUnix: number
  approved: boolean
  overlayIp?: string
}

export interface NodesResponse {
  nodes: NodeInfo[]
}

export type SessionAction =
  | "shell"
  | "exec"
  | "sftp"
  | "forward"
  | "attach"
  | string

export type SessionState =
  | "active"
  | "detached"
  | "pending"
  | "ended"
  | "revoked"
  | string

export interface SessionInfo {
  sessionId: string
  nodeId: string
  nodeName: string
  user: string
  action: SessionAction
  state: SessionState
  startedUnix: number
  detachable: boolean
  hostSessionId: string
}

export interface SessionsResponse {
  sessions: SessionInfo[]
}

// --- monitoring ---
export interface NodeModule {
  name: string
  enabled: boolean
  settings?: Record<string, string>
}

export interface NodeModulesResponse {
  nodeId: string
  version: number
  modules: NodeModule[]
}

// Prometheus HTTP API response shape (matrix/vector), served by the gateway.
export interface PromSeries {
  metric: Record<string, string>
  values?: [number, string][] // matrix
  value?: [number, string] // vector
}

export interface PromResponse {
  status: "success" | "error"
  error?: string
  data?: {
    resultType: "matrix" | "vector" | "scalar"
    result: PromSeries[]
  }
}

export interface Fleet {
  stable: string
  canary: string
  canaryNodes: string[]
}

export interface PolicyRule {
  actions?: string[]
  node_labels?: Record<string, string> | string[]
  time_window?: string
  require_native?: boolean
  [key: string]: unknown
}

export interface PolicyRole {
  allow: PolicyRule[]
}

export interface PolicyBinding {
  role: string
  users?: string[]
  groups?: string[]
}

export interface Policy {
  roles: Record<string, PolicyRole>
  bindings: PolicyBinding[]
}

export interface AuditRecord {
  seq: number
  ts: number
  type: string
  actor?: string
  node?: string
  session?: string
  detail?: Record<string, string>
  prev: string
  hash: string
}

export interface AuditResponse {
  records: AuditRecord[]
  chainOk: boolean
}

export interface TokenRequest {
  ttlSeconds: number
  labels: Record<string, string>
  maxUses: number
}

export interface TokenResponse {
  token: string
  expiresUnix: number
}

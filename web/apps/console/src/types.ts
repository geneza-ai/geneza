// Shared API types mirroring the controller JSON contract (base /api/v1).

export interface OidcConfig {
  issuer: string
  clientId: string
  redirectUri: string
}

export interface KeystoneCloud {
  cloud: string
  label: string
}

export interface AuthConfig {
  local: boolean
  oidc: OidcConfig | null
  keystone: KeystoneCloud[]
}

export interface AppConfig {
  clusterName: string
  externalUrl: string
  auth: AuthConfig
}

export interface Me {
  user: string
  provider?: string
  workspace: string
  roles: string[]
  groups: string[]
  admin: boolean
  expiresUnix: number
  // Whether this workspace records sessions at all (a policy choice). The
  // Recordings UI is hidden when recording is turned off everywhere.
  recordingEnabled?: boolean
}

export interface Overview {
  nodes: { total: number; online: number }
  sessions: { active: number; detached: number; total: number }
  versions: { stable: string; canary: string }
  audit: { count: number; chainOk: boolean }
}

export interface NodeInfo {
  nodeId: string
  name: string
  online: boolean
  version: string
  os: string
  arch: string
  // Cross-platform OS identity probed by the agent at enroll. distro is a
  // normalized id ("ubuntu", "macos", "windows") driving the OS icon; osPretty
  // is the human label ("Ubuntu 22.04.4 LTS"). May be empty for older agents.
  distro?: string
  distroVersion?: string
  osPretty?: string
  labels: Record<string, string>
  lastSeenUnix: number
  activeSessions: number
  detachedSessions: number
  createdUnix: number
  approved: boolean
  // Non-empty when the node is quarantined (drift or a manual deny) rather
  // than freshly pending; re-approving it requires a recorded reason.
  quarantineReason?: string
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
  total: number
  limit: number
  offset: number
}

/** Server-driven list controls (filter + sort + page) for the list views. */
export interface ListParams {
  limit?: number
  offset?: number
  q?: string
  sort?: string
  order?: "asc" | "desc"
  state?: string
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

// --- vulnerabilities ---
export type CVEStatus =
  | "affected"
  | "fixed"
  | "not_affected"
  | "under_investigation"
  | string

// One computed (node, package, CVE) verdict row. The prioritization fields ride
// the row so a list view never needs a second lookup.
export interface NodeCVE {
  nodeId: string
  cve: string
  purl: string
  status: CVEStatus
  severity: string
  kev: boolean
  epss: number
  fixedVersion: string
  vexJustification: string
  matchedUnix: number
}

export interface NodeCVEsResponse {
  cves: NodeCVE[]
  total: number
  limit: number
  offset: number
}

export interface NodesAffectedResponse {
  nodes: NodeCVE[]
  total: number
  limit: number
  offset: number
}

// One fleet-wide rollup row: a CVE affecting the workspace, the representative
// severity/status, the version that fixes it, and the distinct nodes it touches
// (host and container-image verdicts unioned, each node counted once).
export interface WorkspaceCVE {
  cve: string
  severity: string
  status: CVEStatus
  fixedVersion: string
  nodeCount: number
  nodes: string[]
}

export interface WorkspaceCVEsResponse {
  cves: WorkspaceCVE[]
  total: number
  limit: number
  offset: number
}

// One resolved inventory entry — the flattened component the matcher joins against.
export interface NodeComponent {
  purl: string
  source: string
  ecosystem: string
  name: string
  version: string
  distro: string
}

export interface NodeComponentsResponse {
  components: NodeComponent[]
  total: number
  limit: number
  offset: number
}

// --- session recordings ---
// One recording index row. Metadata only: the cast itself is age ciphertext the
// controller cannot read and the auditor decrypts client-side. sha256 is over the
// ciphertext; principal is the durable subject the recording is attributed to.
export interface RecordingInfo {
  sessionId: string
  nodeId: string
  principal: string
  action: string
  startedUnix: number
  endedUnix: number
  sizeBytes: number
  sha256: string
  auditKeyId: string
  truncated: boolean
}

export interface RecordingsResponse {
  recordings: RecordingInfo[]
  total: number
  limit: number
  offset: number
}

// The recording's opaque ciphertext plus the node-signed manifest the controller
// echoes in response headers, so the browser can re-verify integrity before it
// decrypts. The private key never leaves the browser.
export interface RecordingBlob {
  ciphertext: Uint8Array
  sha256: string // hex, over the ciphertext, from the manifest header
  sizeBytes: number
}

// Prometheus HTTP API response shape (matrix/vector), served by the controller.
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

// The workspace policy as served by GET /api/v1/policy: the editable raw document
// plus the parsed structure (for the preview), edit provenance, and whether the
// caller (a ws-admin) may edit it.
export interface PolicyDocument {
  workspace: string
  yaml: string
  policy: Policy | null
  updatedBy: string
  updatedUnix: number
  editable: boolean
}

// POST /api/v1/policy/validate result: authoritative parse outcome + the parsed
// structure when valid (so the editor renders a live preview with no client YAML
// parser).
export interface PolicyValidation {
  valid: boolean
  error?: string
  policy?: Policy | null
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

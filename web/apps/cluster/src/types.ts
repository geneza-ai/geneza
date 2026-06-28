// Wire shapes returned by the cluster-operator read plane under /clusterconsole/v1.
// Every endpoint is GET, read-only, and same-origin behind the cluster-admin gate
// (a break-glass client cert, or an OIDC session in the required group).

export interface Controller {
  controllerId: string
  region: string
  addrs: string[]
  controlAddrs: string[]
  version: string
  lastSeenUnix: number
  online: boolean
}

export interface Relay {
  regionId: string
  relayId: string
  addrs: string[]
  version: string
  lastSeenUnix: number
  online: boolean
  // A configured-but-not-heartbeating relay (relay_addrs). Its version is "".
  static: boolean
}

export interface Agent {
  workspace: string
  nodeId: string
  name: string
  agentVersion: string
  desiredVersion: string
  outdated: boolean
  online: boolean
}

export interface RiskAgent extends Agent {
  worstSeverity: string
  kevCount: number
  cveCount: number
}

export interface Workspace {
  id: string
  name: string
  overlayCidr: string
  createdUnix: number
}

export interface ControllersResponse {
  controllers: Controller[]
}
export interface RelaysResponse {
  relays: Relay[]
}
export interface AgentsResponse {
  agents: Agent[]
}
export interface RiskResponse {
  agents: RiskAgent[]
}
export interface WorkspacesResponse {
  workspaces: Workspace[]
}

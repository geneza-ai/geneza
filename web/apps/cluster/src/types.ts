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
  // Shedding for a binary swap: still online and visible, but excluded from
  // new-session selection. Without this a draining relay renders as plain
  // "Online", which is exactly the state a swap needs to distinguish.
  draining: boolean
  healthy: boolean
  // Live splice + control-mux count. Reaches 0 once the relay's sessions have
  // migrated off and the binary is safe to swap — the drain's progress bar.
  activeCount: number
  // The serial `genezactl cert revoke` takes.
  certSerial?: string
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

# WireGuard per-Network data plane — implementation plan

Status: design approved (2026-06-13), implementing. Decisional-workflow output.

I have all the anchors confirmed. The briefs are accurate against the actual code. Let me write the final plan.

# Geneza kernel-WireGuard per-Network data plane — concrete build plan

Verified against the tree: every cited symbol exists (`module.go:67 reconcile`, `registry.go:222 SendModuleConfig`, `monitoring.go:26/40`, `nodecontrol.go:90 pushNodeModules`, `worker.go:139/246/459`, `store.go` NetworkRecord:83/SubnetRecord:94/BindingRecord:113/NodeRecord:129/NoisePub:134, `overlay.go:29`, `server.go:265 overlayFor`, `continuousauthz.go:22/40`, `control.proto` ControllerMsg oneof tags 1-5, EnrollRequest tags 1-8). `wgctrl` is **not** yet a dependency (must be added). The find for `scripts/e2e.sh` returned nothing — confirm its real path before Phase G (CLAUDE.md says it exists; locate it).

---

## Guiding invariants (must hold after every phase)

- **Blind relay**: relay never parses past the rendezvous frame. WG payload is E2E-encrypted to peer WG static keys; the new UDP forwarder shuttles opaque datagrams by token only.
- **Dial-out only**: agents/clients never listen for inbound controller/relay connections. WG `ListenPort` binds a local UDP socket for *data*, but the controller learns endpoints from observed source addr / STUN, never by dialing in.
- **Agent re-verifies**: the WG static pubkey distribution is gated by the controller's policy (`policy.LabelsMatch`), and each wg interface is keyed so a peer not in the Network simply has no key entry → kernel WG drops its packets.
- **Per-Network isolation**: one wg interface per VNI, distinct allowedIPs, distinct overlay CIDR per (ws,network). A node not tagged for Network B has no `wg<vniB>` link at all.
- **Monotonic versioning**: every push carries a per-principal monotonic version; the agent drops stale (`cfg.GetVersion() < m.version`) exactly like `module.go:71`.

---

## Phase A — controller computes + persists desired Network set + WG key handling (no wire changes yet)

Goal: controller can derive "which Networks does node N belong to" and store each node's WG static pubkey. Compiles, fully unit-testable, lab stays green (nothing pushed yet).

**A1. WG key on the agent.** New file `internal/agentd/wgkey.go` (or extend `state.go`). At enroll (`enroll.go`, next to the `tunnel.GenerateKeypair()` at the Noise-key site), generate a **dedicated per-node** X25519 WG keypair, persist `wg.json` (`{Priv,Pub}` hex, 0600, validated 32 bytes — mirror `state.go` `noiseFile`). Decision (see §"WG key design"): **dedicated key**, not Noise reuse, for clean protocol separation; per-node, never per-Network.

**A2. Store field.** `internal/controller/store.go`: add `WGPub []byte `json:"wg_pub"`` to `NodeRecord` (line 129 block). Bbolt records are JSON, so this is additive/backward-compatible (old records decode `WGPub=nil`; handle nil downstream by skipping the peer).

**A3. Enroll persists WGPub.** `internal/controller/enroll.go`: read `req.GetWgStaticPub()` (proto field added in B1, but stub now: accept absent), validate 32 bytes, store on `NodeRecord` next to `NoisePub`.

**A4. Desired-Network computation.** New file `internal/controller/networkpush.go`:
- `func (s *Server) desiredNetworks(ws string, node *NodeRecord) []*NetworkRecord` — `s.store.ListNetworks(ws)` (store.go:349) filtered by `policy.LabelsMatch(n.Selector, node.Labels)` (empty Selector = all).
- `func (s *Server) networkPeers(ws string, net *NetworkRecord, self *NodeRecord) []peerSpec` — `s.store.ListNodes(ws)` (store.go:564) filtered to approved nodes with `LabelsMatch(net.Selector, peer.Labels)`, excluding self, with `WGPub != nil`. Each peer carries {WGPub, endpoint(empty for now), allowedIPs:[peer's per-network overlay IP /32]}.

**A5. Per-(ws,network) IPAM.** `internal/controller/overlay.go` + `server.go:265 overlayFor`:
- Re-key `s.overlays` from `map[ws]` to `map[overlayKey]` where `overlayKey = struct{WS string; NetVNI uint32}`.
- `overlayFor(ws string, vni uint32, baseCIDR string)` seeds the allocator from the Network's `SubnetRecord.CIDR` instead of `defaultOverlayCIDR`. Keep `alloc/release/allocMachineIP/used` logic verbatim — only keying + base change.
- Add `func (s *Server) networkOverlayIP(ws string, net *NetworkRecord, nodeID string) (string, error)` that returns a **stable** per-node IP for that Network, persisted as a `BindingRecord` (store.go:113 — finally written): key `(VNI,nodeID)→overlayIP`. Add `Store.PutBinding`/`GetBinding`/`ListBindings(ws,vni)`. On first call, `allocMachineIP` from the Network subnet, persist; subsequent calls return the stored binding (idempotent, survives restart).

**A6. Tests.** `networkpush_test.go`: table-driven — given Networks with selectors + nodes with labels, assert `desiredNetworks` membership and peer lists; assert BindingRecord stability across two calls; assert two Networks with overlapping CIDRs get independent allocators. `overlay_test.go` already exists — extend for the new keying.

Invariant check: A node with no matching tags → `desiredNetworks` returns empty → (later) no wg interface. This is the isolation property's root.

---

## Phase B — NetworkConfig push over the control stream

Goal: controller pushes the derived set to connected nodes over the existing `NodeControl.Stream`; agent receives it and logs (no reconcile yet). Compiles, lab green (agent only logs).

**B1. Proto** (`api/proto/geneza/v1/control.proto`):
```proto
// ControllerMsg oneof (next free tag = 6, after module_config=5)
ControllerMsg { ... NetworkConfig network_config = 6; }

message NetworkConfig {
  int64 version = 1;                 // monotonic per principal; agent drops stale
  repeated NetworkSpec networks = 2; // desired set; a VNI absent => tear it down
}
message NetworkSpec {
  uint32 vni = 1;                    // 24-bit; ONE wg interface at the agent
  string name = 2;
  string overlay_cidr = 3;          // THIS principal's overlay IP/CIDR on this Network
  repeated WGPeer peers = 4;
}
message WGPeer {
  bytes  wg_pubkey   = 1;            // peer WireGuard static (Curve25519)
  string endpoint    = 2;            // direct host:port if known; else DERP relay addr (Phase D)
  repeated string allowed_ips = 3;   // peer overlay /32 (+ subnet-route CIDRs later)
  bytes  rendezvous_token = 4;       // DERP fallback token; empty when direct (Phase D)
}
// EnrollRequest: next free tag = 9
message EnrollRequest { ... bytes wg_static_pub = 9; }
```
Regenerate: `protoc`/`buf` (use the repo's existing gen command — check `Makefile`/`buf.gen.yaml`).

**B2. Proto builder.** `networkpush.go`: `func (s *Server) networkConfigProto(ws string, node *NodeRecord, version int64) *genezav1.NetworkConfig` — for each `desiredNetworks` entry, build `NetworkSpec{vni, name, overlay_cidr: networkOverlayIP/<prefix>, peers: networkPeers(...)}`. Endpoints empty for now (Phase D fills DERP/direct).

**B3. Per-principal monotonic version.** Add to `registry.go agentHandle` (line 31) a `netVersion int64` field; bump under `sendMu` on each push. (Computed, not stored — unlike `NodeModulesRecord.Version`, because membership is derived.) Expose `func (h *agentHandle) nextNetVersion() int64`.

**B4. Registry send.** `internal/controller/registry.go`: clone `SendModuleConfig` (line 222):
```go
func (r *Registry) SendNetworkConfig(nodeID string, cfg *genezav1.NetworkConfig) error {
    h := r.get(nodeID); if h == nil { return fmt.Errorf("node %s is not connected", nodeID) }
    return h.send(&genezav1.ControllerMsg{Msg: &genezav1.ControllerMsg_NetworkConfig{NetworkConfig: cfg}})
}
```

**B5. Push one node + fleet.** `networkpush.go`:
- `func (s *Server) pushNodeNetworks(ws, nodeID string)` — clone `pushNodeModules` (monitoring.go:40); resolves node, builds proto with `h.nextNetVersion()`, `registry.SendNetworkConfig` best-effort (debug-log if offline).
- `func (s *Server) repushAllNetworks(ws string)` — iterate `s.store.ListNodes(ws)`, `pushNodeNetworks` each (no-op when offline). This is the N×N fan-out primitive (a new peer must appear in every co-member's config).

**B6. Push on connect.** `internal/controller/nodecontrol.go`: one line right after line 90 (`s.pushNodeModules(...)`): `s.pushNodeNetworks(ident.Workspace, ident.Name)`. Reconnect re-derivation comes free.

**B7. Agent receive (log only).** `internal/agentd/worker.go streamOnce` (line 459 block): add
```go
case *genezav1.ControllerMsg_NetworkConfig:
    w.log.Info("network config", "version", m.NetworkConfig.GetVersion(), "nets", len(m.NetworkConfig.GetNetworks()))
```
Lab green: agent just logs. **This is the minimal first slice's wire half.**

**B8. Tests.** `server_test.go`/`registry`: connect a fake node stream, assert it receives a `ControllerMsg_NetworkConfig` on connect with the expected VNIs/peers; assert version monotonic across two pushes.

---

## Phase C — agent `networkManager` reconcile → real kernel-WG interface

Goal: agent brings up/tears down one kernel-WG interface per Network from the pushed set, with overlay IP + peers + allowedIPs. **This is the load-bearing data-plane phase.**

**C1. Dependency.** `go get golang.zx2c4.com/wireguard/wgctrl@latest` (pure-Go, CGO-free, netlink/genetlink — matches the repo constraint and `tun_linux.go`'s `x/sys/unix` style). Verify `go build ./...` stays CGO-free (`CGO_ENABLED=0 go build ./...`).

**C2. Link create/up — linux, behind build tag.** New file `internal/vpn/wg_linux.go` (`//go:build linux`, mirroring `tun_linux.go`):
- `func WGCreate(name string) error` — `ip link add <name> type wireguard` via the existing `ipCmd` (tun_linux.go:68) to stay shell-consistent; or `netlink.LinkAdd` if `vishvananda/netlink` is pulled. Idempotent: ignore "exists".
- Reuse **verbatim**: `LinkUpAddr(name, overlayIP/prefix)` (tun_linux.go:89), `AddRoute(allowedCIDR, name)` (tun_linux.go:98), `DelRoute` (tun_linux.go:106).
- `func WGConfigure(name string, priv wgtypes.Key, listenPort int, peers []wgtypes.PeerConfig) error` — `wgctrl.New()` → `client.ConfigureDevice(name, wgtypes.Config{PrivateKey:&priv, ListenPort:&port, ReplacePeers:true, Peers:peers})`.
- `func WGDelete(name string) error` — `ip link del <name>`.
- New file `internal/vpn/wg_other.go` (`//go:build !linux`): stubs returning `errors.New("wireguard data plane: linux only")`, mirroring `tun_other.go`. macOS-utun WG is the documented follow-up.

**C3. networkManager.** New file `internal/agentd/network.go`, near-copy of `module.go:moduleManager`:
```go
type networkManager struct {
    log     *slog.Logger
    wgPriv  wgtypes.Key
    mu      sync.Mutex
    running map[uint32]*wgIface   // keyed by VNI
    version int64
}
func (m *networkManager) reconcile(cfg *genezav1.NetworkConfig) {
    m.mu.Lock(); defer m.mu.Unlock()
    if cfg.GetVersion() < m.version { return }   // module.go:71 idiom
    m.version = cfg.GetVersion()
    desired := map[uint32]*genezav1.NetworkSpec{}
    for _, n := range cfg.GetNetworks() { desired[n.GetVni()] = n }
    for vni := range m.running {
        if _, ok := desired[vni]; !ok { m.downLocked(vni) }   // tag removed → tear down
    }
    for vni, spec := range desired { m.upOrSyncLocked(vni, spec) }
}
```
- `upOrSyncLocked`: if not running → `WGCreate("gnzw"+vni)`, `LinkUpAddr`, `WGConfigure` with peers, `AddRoute` per allowedIP; record `wgIface`. If running → diff peer set (mirror `module.go:177 settingsChanged`) and re-`ConfigureDevice` only on change (idempotent, cheap).
- `downLocked`: remove routes, `WGDelete`, drop from map.
- `downAll()` for teardown.
- **No upward push** — unlike `moduleManager` it takes no `push func(*AgentMsg)` (module.go:55 arg dropped). WG data rides its own UDP socket E2E, never the control stream.

**C4. Wire into worker.** `internal/agentd/worker.go`:
- construct next to line 139: load `wg.json` key, `w.networks = newNetworkManager(log, wgPriv)`.
- dispatch (replace the B7 log-only case at 459): `w.networks.reconcile(m.NetworkConfig)`.
- teardown next to line 246: `w.networks.downAll()`.

**C5. Naming.** Interface `gnzw<vni>` (≤15 chars; VNI is 24-bit → fits `gnzw16777215`). Document the convention next to `OpenTUN`'s `gnz%d`.

**C6. Tests + lab proof.** Unit: `network_test.go` with a fake WG backend (interface the WGCreate/Configure/Delete calls so tests run without root) — assert reconcile brings up exactly the desired VNIs, tears down removed ones, ignores stale versions. Lab: on VM 106/107, push a 1-Network config from the controller, assert `ip link show gnzw<vni>` exists with the overlay IP and `wg show` lists the peer. **This is the minimal first slice's agent half — proves "agent brings up a Network wg interface from a controller push."**

At this point two same-Network nodes have wg interfaces with each other as peers, but `endpoint` is empty → no data path yet (Phase D).

---

## Phase D — endpoint distribution + blind relay WG UDP forward

Goal: actual packet flow between Network members — direct when punchable, blind DERP fallback otherwise.

**D1. Endpoint discovery (dial-out-safe).** The controller must learn each node's WG `host:port` without dialing in. Two layers:
- **Observed source addr**: when an agent connects the NodeControl stream, the controller already sees its TCP source IP (`peer.FromContext`). Add to `AgentHello` (proto, `AgentHello` block ~line 127) a `uint32 wg_listen_port = 7`; the controller pairs observed-IP + advertised-port as a *candidate* direct endpoint. Store transiently on `agentHandle`.
- **STUN-lite via relay** (preferred for correctness behind NAT): the agent sends one WG-bind probe to the relay's UDP port; the relay echoes the observed `srcaddr` back (a tiny non-blind control frame on a *separate* control path, not the data forward). The agent advertises that reflexive address. This is additive and optional for Phase D-min (start with observed-source-addr only; lab VMs are on one bridge, direct works).

**D2. Direct-first in the proto build.** `networkpush.go networkConfigProto`: for each peer, set `WGPeer.endpoint` = peer's known candidate endpoint (observed addr:port). WG's own keepalive punches/maintains. Add `PersistentKeepalive` via wgctrl (25s) so dial-out NAT mappings stay open — this is what makes "no inbound ports" work.

**D3. Blind UDP relay (DERP fallback).** `internal/relay/relay.go`: add a **parallel UDP listener** alongside the TCP `tls.Listen` (relay.go:76). The existing TCP `Serve`/`splice`/`copyHalf` (relay.go:328/381) is **untouched** (still carries Noise/SSH). New surface:
- A UDP socket; a `map[token]→{addrA, addrB net.UDPAddr, lastSeen}` forwarding table guarded by a mutex.
- Registration: first datagram from each side is prefixed with the rendezvous token (reuse the `gz-…` token model from `types.NewToken`); relay records `addrA`, then `addrB`, mirroring the TCP `pending[token]` rendezvous (relay.go:219).
- Forward loop: read datagram, strip token-prefix only on registration packets; thereafter forward opaque payload A↔B by table lookup. **Not one byte of WG payload parsed** — identical blindness invariant to relay.go:326. Forged/wrong datagrams are dropped by the peers' kernel WG (E2E auth), so the relay holds zero trust.
- Idle-expire table entries; cap table size (DoS guard).

**D4. Controller hands out DERP endpoint.** When the controller can't confirm a direct candidate (no observed addr, or a future reachability probe fails), `networkConfigProto` sets `WGPeer.endpoint = <relay UDP host:port>` and `WGPeer.rendezvous_token = <minted per (a,b,vni)>`. Both peers send WG UDP to the relay; the relay shuttles by token. Mint these tokens like relay tokens in the broker (`types.NewToken`), single-Network scoped.

**D5. Agent uses endpoint.** Already handled in C3 — `upOrSyncLocked` sets `peer.Endpoint` from `WGPeer.endpoint`. If `rendezvous_token` present, the agent first emits the token-registration datagram to the relay UDP addr, then WG flows through it.

**D6. Tests.** Relay unit test: two UDP peers register by token, assert datagrams forwarded both ways and that a wrong-token datagram is dropped/not cross-delivered. Lab: force DERP path (block direct with a host firewall rule between 106↔107), assert ping over overlay still works through the relay UDP forwarder, and `tcpdump` on the relay shows only opaque UDP (no WG decrypt possible).

---

## Phase E — VPN client watch-stream + reconcile (unify client with agent)

Goal: a `geneza vpn` client (user cert, no NodeControl stream today) receives the same realtime desired-set and runs the **same** `networkManager`.

**E1. Proto.** `control.proto UserAPI`: `rpc WatchNetworks(WatchNetworksRequest) returns (stream NetworkConfig);` and `message WatchNetworksRequest { int64 known_version = 1; }`. The `NetworkConfig` message is **shared verbatim** with the node channel.

**E2. Client registry.** `internal/controller/registry.go` (or new `clientregistry.go`): a trimmed clone of `Registry` keyed by `(ws,user,sessionPubkey)`, holding the server-stream `Send` behind a `sendMu` (reuse `agentHandle.sendMu` pattern), plus a per-client `netVersion`.

**E3. Handler.** `internal/controller/userapi.go`: `WatchNetworks`:
1. `identityFrom(ctx)` → user identity (reuses the existing user-mTLS interceptor — no new auth).
2. Register stream in clientRegistry.
3. Compute client's desired Networks: `desiredNetworks(ws, principalLabels)` matching `net.Selector` against the **client's labels/roles** (a client's membership = Networks it could `vpn`/`connect` into — the same projection `dns.go dnsCanReach` already does, lines ~57-75). Reuse that projection so DNS-reachability and WG-membership stay consistent.
4. Push initial `NetworkConfig` if `known_version` stale; block until disconnect.

**E4. Client side.** `internal/vpn` + `cmd/geneza/vpn.go`: a `watchLoop` mirroring `worker.go:331 streamLoop` (reconnect+backoff) that calls `UserAPI.WatchNetworks` and feeds each `NetworkConfig` into the **identical** `networkManager.reconcile` from Phase C. Node and client now run the same reconciler; only the desired-set *source* differs (NodeControl stream vs WatchNetworks). The legacy per-session `vpn.Pump`/`serveVPN` path stays for now (interactive SSH); WG coexists.

**E5. Tests.** Fake user-cert stream: assert initial push + monotonic re-push; assert a client with role X gets exactly the role-X Networks.

---

## Phase F — realtime membership-change push + symmetric teardown

Goal: admin adds a tag → the principal provisions the new Network's wg within seconds; removes tag → teardown within one reconcile.

**F1. Label-mutation RPC.** `control.proto AdminAPI`: `rpc SetNodeLabels(SetNodeLabelsRequest) returns (Empty);` (and optionally `SetNetwork` for Selector edits) next to `SetNodeModules` (line 348). Today labels are written only at enroll (`enroll.go`) and DNS overlay assignment (`dns.go`, which preserves labels) — there is **no label-update RPC**, so this is the missing trigger surface. Add `Store.SetNodeLabels` preserving all other fields.

**F2. Recompute on every mutation point.** Call `repushAllNetworks(ws)` (B5) from:
- `SetNodeLabels` / `SetNetwork` handlers (label/selector change).
- `SetNodeApproval` (store.go:500) and `DeleteNode` (store.go:482) callers — approval gates membership; a removed node must be dropped from every co-member's peer list (symmetric teardown).
- Extend to also iterate the **clientRegistry** (E2) since a client's set changes when a reachable node appears/disappears.

**F3. Continuous-authz network sweep (defense-in-depth).** `internal/controller/continuousauthz.go runContinuousAuthz` (line 22) / `reauthSweep` (line 40): add a parallel `networkSweep()` on the same ticker (server.go:487 already launches the loop). For each online node + client: recompute `desiredNetworks`, compare to a cached per-principal hash, push only on change. Catches label/policy edits that bypassed an explicit RPC. The monotonic version (B3) protects the explicit-push-vs-sweep-push race.

**F4. Tests.** Integration: connect a fake node; admin `SetNodeLabels` to match Network B → assert a new `NetworkConfig` arrives within one push containing VNI-B; remove the label → assert next config omits VNI-B (and a peer-removed config reaches the co-member). Assert `networkManager` tears down `gnzw<vniB>` on the omit.

---

## Phase G — e2e on the VMs

Locate the real e2e harness first (`find /root/geneza /root/labs/geneza1 -name 'e2e*.sh'`; the find above came up empty — it may live under `labs/geneza1/scripts`). Add a new check block:

1. Enroll/approve nodes 106 + 107 with WG keys (verify `wg.json` written, `NodeRecord.WGPub` populated in store).
2. Create Network B with `Selector{role:db}`; tag node 106 only → assert `gnzw<vniB>` exists on 106, **absent** on 107 (isolation property).
3. Tag node 107 `role:db` via `SetNodeLabels` → assert within ~ReauthInterval both have `gnzw<vniB>` with each other as peers, overlay ping works (direct path).
4. Block direct 106↔107 → assert overlay ping still works via blind DERP UDP forward; `tcpdump` on relay = opaque UDP only.
5. Remove `role:db` from 107 → assert `gnzw<vniB>` torn down on 107 within one reconcile, and 106's peer list no longer lists 107.
6. VPN client (user cert) with matching role → `WatchNetworks` brings up its `gnzw<vniB>`; revoke role → teardown.
7. Restart controller → BindingRecords give stable overlay IPs; agents reconnect and re-derive identical interfaces (idempotent).
8. Confirm the existing 35-check battery still passes (Noise/SSH sessions unaffected — WG coexists).

---

## WG key + peer-distribution design (decision)

- **Key: dedicated per-node X25519 WG keypair** (`wg.json`), generated at enroll alongside the Noise static. Both curves are Curve25519/32-byte so reuse is *mechanically* valid, but a dedicated key gives clean protocol separation (Noise IK control/SSH vs WG data plane) at near-zero cost. **One key per node, never per Network** — `allowedIPs` + separate interfaces already segment per Network; per-Network keys buy nothing and multiply distribution.
- **Pubkey distribution**: `NodeRecord.WGPub` in the bbolt store → controller computes membership → ships peer `{WGPub, endpoint, allowedIPs}` in `NetworkConfig` over the existing control stream. No new channel; no out-of-band key exchange.
- **Endpoint learning under dial-out/NAT**: controller never dials in. It infers each node's endpoint from (a) the observed TCP source addr of the NodeControl stream + an advertised `wg_listen_port` in `AgentHello`, and optionally (b) a STUN-lite reflexive-address echo from the relay. WG `PersistentKeepalive` keeps the NAT mapping open so peers reach each other on the punched mapping.
- **Blind relay fit**: direct is preferred (relay not in path). When no direct candidate, controller sets `endpoint=relayUDP` + a rendezvous token; both peers send WG UDP to the relay, which forwards opaque datagrams by token — payload-blind, identical invariant to the TCP splice. The relay holds zero trust because WG is E2E-authenticated; a malicious relay can only drop/misforward, which the kernel WG rejects.

---

## Cross-Network isolation as testable properties

1. **No membership ⇒ no interface**: node N with labels not matching Network B's Selector has no `gnzw<vniB>` link and no route into B's CIDR. (Test: `ip link show` absence + `ip route` absence.)
2. **No key ⇒ no path**: even if a stray B datagram reaches N's host, N has no `gnzw<vniB>` device and no peer entry → kernel drops it. (Test: inject; assert no delivery.)
3. **Tag removal ⇒ teardown within one reconcile**: removing N's matching tag triggers `repushAllNetworks` → next `NetworkConfig` omits VNI-B → `networkManager.downLocked` deletes the link before the next ticker. (Test: timestamp the link's disappearance < one reconcile interval.)
4. **Symmetric peer removal**: when N leaves B, every co-member's next config drops N from its peer list. (Test: `wg show` on co-member no longer lists N's pubkey.)
5. **Overlapping CIDRs stay isolated**: two Networks with the same CIDR realize as two interfaces with independent IPAM; traffic never crosses (no shared route, no shared key). (Test: identical overlay IPs on two VNIs, assert ping reaches only the same-VNI peer.)
6. **Monotonic safety**: a stale sweep-push racing an explicit push cannot regress state. (Test: deliver version N then N-1; assert N-1 ignored.)

---

## Riskiest changes, mitigations, stub-first, minimal first slice

**Riskiest:**
- **Blind UDP relay (Phase D3)** — new network surface; risk of accidentally parsing payload (breaking blindness) or a forwarding-table DoS. *Mitigate*: token only on registration datagrams; opaque copy thereafter; size-cap + idle-expire the table; a test asserting forged-token isolation and a `tcpdump`-blindness check. Keep TCP splice 100% untouched.
- **wgctrl/kernel-WG on the agent (Phase C)** — needs root + the `wireguard` kernel module; failures are environment-specific. *Mitigate*: interface the WG backend so unit tests use a fake; gate real ops behind `//go:build linux`; preflight-check module presence and surface a clear error; stubs on non-linux.
- **Proto oneof tag / enroll field migration (B1)** — wrong tag numbers corrupt the wire. *Mitigate*: strictly use next-free tags (ControllerMsg=6, EnrollRequest=9); bbolt JSON records make `WGPub`/labels additive; old records decode with nil and are skipped.
- **N×N fan-out cost (F2/F3)** — `repushAllNetworks` is O(nodes²) on each mutation. *Mitigate*: per-principal change-hash so the sweep pushes only on real change; debounce explicit mutations; fine for the lab's handful of nodes, revisit at scale.
- **Endpoint discovery correctness (D1)** — wrong endpoint = silent no-connectivity. *Mitigate*: start with observed-source-addr (works on the single bridge), add STUN-lite + DERP fallback so a wrong direct guess degrades to the relay rather than failing.

**Stub first:** the relay's STUN-lite reflexive echo (use observed-addr only at first); macOS/Windows WG (stub like `tun_other.go`); subnet-route/exit-node behavior on `wg<vni>` (reuse `NodeRouteFor` later, bound to wg instead of per-session TUN); cross-Network "router node". **Build fully:** A (computation + IPAM + keys), B (push), C (reconcile + real wg up/down), because those are the load-bearing data plane.

**Minimal first slice that proves the system (do this before anything else):**
A2+A4 (store WGPub field + `desiredNetworks`) → B1+B4+B6+B7 (proto `network_config=6`, `SendNetworkConfig`, push-on-connect, agent log-only) → C1+C2+C3+C4 (wgctrl dep, `wg_linux.go`, `networkManager`, worker wiring). Then on VM 106: controller pushes a 1-Network config and the agent runs `ip link add gnzw<vni> type wireguard` + sets its key/overlay IP. Verified by `ip link show gnzw<vni>` + `wg show` listing the configured peer. That single push→reconcile→interface-up loop proves the entire pattern; everything after (peers' real endpoints, DERP, client watch, realtime tag changes) is incremental on that spine.

---

Key file:symbol anchors for the build (all verified present): reconcile template `internal/agentd/module.go:67`; agent dispatch/construct/teardown `internal/agentd/worker.go:459/139/246`; registry send `internal/controller/registry.go:222` + `agentHandle:31`; push-on-connect `internal/controller/nodecontrol.go:90`; proto-build/push template `internal/controller/monitoring.go:26/40`; records `internal/controller/store.go` Network:83/Subnet:94/Binding:113/Node:129/NoisePub:134; IPAM `internal/controller/overlay.go:29` + `server.go:265`; authz sweep `internal/controller/continuousauthz.go:22/40` launched at `server.go:487`; DNS reachability projection `internal/controller/dns.go`; relay splice/rendezvous `internal/relay/relay.go:76/219/326/328/381`; tun helpers to reuse `internal/vpn/tun_linux.go:89/98/106/151`; proto `api/proto/geneza/v1/control.proto` ControllerMsg oneof (tags 1-5, add 6), EnrollRequest (tags 1-8, add 9), UserAPI (add WatchNetworks), AdminAPI:328 (add SetNodeLabels).

**Open items to confirm before starting:** (1) locate the real e2e harness (`find` for `e2e*.sh` returned nothing under `/root/geneza`); (2) the proto codegen command (`Makefile`/`buf.gen.yaml`); (3) whether `vishvananda/netlink` is wanted for link-create or stick with `ipCmd` shell-out (recommend `ipCmd` for in-repo consistency).
# Geneza Scale & Degradation Test Plan — Finding the Knees and Cliffs

**Organizing principle:** every test is a *ramp to saturation*. We never ask "is it fast enough"; we ask **"at what value of the scaling variable does a degradation signal first bend (the KNEE), where does it collapse (the CLIFF), what is the curve SHAPE between them (flat / linear / superlinear / cliff), and which resource saturates FIRST."** Every load-bearing code claim below was re-verified against the tree at `/root/geneza` (module `geneza.io`, go1.26.4, 48-core / ~32 GiB-available shared Hetzner host).

---

## 0. Headline degradation questions

Three questions drive the suite, in priority order.

1. **"Does traffic through the derp degrade at scale?"** (user's explicit ask) — The relay is a payload-blind TCP rendezvous splice **plus** a pion/turn UDP floor. Two distinct ceilings: (a) TCP splice aggregate goodput + per-iteration `SetReadDeadline`/`SetWriteDeadline` syscall tax (`relay.go:403–409`, on **every** copyHalf loop, 32 KiB buf) + single `r.mu` under connect churn; (b) the UDP floor forwards **one datagram per syscall, no GSO** (`turnserver.go:33` single `ListenPacket`) → a hard **pps ceiling**, not a Gbit ceiling. *Yes, it degrades — and the two paths degrade for different reasons at different load shapes.*

2. **"Does the control channel stay stable with many agents?"** (user's explicit ask) — N agents each hold one `NodeControl.Stream`. The headline instability is **not** steady-state memory; it is the **no-jitter reconnect herd**: `streamLoop` reconnects on `time.After(backoff)` (`worker.go:710`) with backoff starting at `reconnectBackoffLo=1s` and **no rand jitter** (verified: only `crypto/rand` for keygen in `worker.go`). All N wake in phase → all call `ClaimAgentAffinity` = a SERIALIZABLE upsert (`maxSerialRetries=10`) against a pgxpool whose MaxConns defaults to `max(4, NumCPU)` (no `pool_max_conns` in DSN). *The risk is a positive-feedback herd that oscillates instead of converging.*

3. **"Does anything degrade at scale?"** (general) — Yes, with one **deterministic cliff** and several slopes:
   - **The deny-path sweep falls behind.** `reauthSweep` runs every 15 s; its `reauthorize()` does up to **two PG point reads per live session** (`IsSuspended` `continuousauthz.go:134` + `GetNode` `:148`, both **bypassing `denyCache`** — the cache is wired only into the per-RPC path at `auth.go:211`) — an **O(M) round-trip term** that dominates the single O(M log M) `ListAllSessions` scan. Find where one sweep crosses 15 s → a written deny is enforced a *multiple* of 15 s late.
   - **Adding controllers subtracts, not adds.** Every controller runs its own `runContinuousAuthz` against the *one shared Postgres*; `ListAllSessions` is global (`SELECT doc FROM sessions ORDER BY started_unix`, no workspace filter) → total sweep load = N × (global scan + O(M) point reads)/15 s, **unsharded across every workspace**.
   - **Confirmed overlay-pool leak → hard cliff at 127.** Broker VPN-reject path (`broker.go:460–475`) marks `SessionEnded` via a raw `UpdateSession` and returns **without `overlayFor().release()`** (verified) → leaks one IP per rejected VPN session; the pool is IPs 128..254 = 127 addresses *per workspace* → `codes.ResourceExhausted` after exactly 127 rejects, permanent until restart.
   - **Data-plane floor-stuck tunnels never recover.** `OnPunchAt` is a literal empty no-op (`icebind.go:723` — verified `func (b *ICEBind) OnPunchAt(...) {}`) → a tunnel that selected the relay floor at setup never upgrades to direct.

---

## 1. Shared ramp harness (build once, reuse everywhere)

**Prerequisite instrumentation (BLOCKING — confirmed absent):** `grep -rn 'net/http/pprof|expvar|runtime.NumGoroutine|SetMutexProfileFraction|SetBlockProfileRate' internal/ cmd/` returns **zero hits**. Without it, sweep-CPU vs metrics-forward-CPU vs broker-CPU is unattributable and goroutine-leak detection is impossible. **First deliverable:** add a build-tagged (`//go:build perfdebug`) loopback-only `net/http/pprof` listener + a `/debug/vars` expvar exposing `runtime.NumGoroutine`, process RSS, open-fd count, and component-specific gauges (`overlayAllocator.used` size, `len(w.live)`/`len(w.sessionICE)`, relay `r.active`/`len(r.pending)`/`len(r.conns)`, `turnRelay.allocations()`) on controller, relay, agentd, and session-host.

**Profiling is NOT free — separate the capacity number from the attribution number.** `SetMutexProfileFraction(5)` and `SetBlockProfileRate` add contention accounting to *every* `r.mu`/`a.mu`/`b.mu` acquire — the exact locks R2/R4/R7/R9 measure. Gate the profile rates behind a runtime knob (default OFF). **Quote every knee/capacity number from a profiling-OFF build; use the profiling-ON build only to *attribute* the wall to a named lock.** Never report a knee location from a profiled binary.

**Load generators** (the data paths are Geneza protocols, not HTTP/gRPC — generic tools mostly don't fit):

| Harness | Drives | Built from |
|---|---|---|
| **`ctlbench`** (new) | CA-gated user certs (via `internal/ca` — a generic gRPC client cannot speak the mTLS+PeerIdentity listener) + fast-ack fake-agent fleet (`NodeControl.Stream` that instantly acks `SendOffer`); closed-loop **and** open-loop drivers | new, ~300 LoC |
| **`agentstorm`** (new) | N real `NodeControl.Stream` clients with per-node mTLS, Hello+15 s Heartbeat+optional 15 s MetricsPush, plus a **phase-barrier release** to inject synchronized arrival deterministically (not via a real disconnect — see R4) | new, ~200 LoC |
| **`splicegen`** (new) | S TCP splice pairs against the real relay; mints tokens passing `validateHello` (`gz-<16..64 hex>`); configurable frame size/rate; per-splice received-bytes/s + setup latency; **fine-grained A/B interleave driver** (alternate stock/patched relay every 30 s, ≥10 cycles) | modeled on `relay_test.go:54 dialHello` |
| **session pre-seeder** | bulk-loads M live session jsonb docs via `sqlStore.PutSession`/COPY across W workspaces and K principals to set up the M×K×W grid **without** paying the broker path | pattern from `bulkLoadSessions` (`brokercost_bench_test.go:238`) |
| **existing benches** | per-op + per-M curves: `BenchmarkScaleListAllSessions` (M=1k..1M wired), `BenchmarkScalePutSessionAtSize`, `BenchmarkCostAuditAppend/StorePutSession/PolicyEvaluate/GrantSign` | `internal/controller/brokercost_bench_test.go` |
| **existing rigs** | `/root/labs/geneza1/scripts/{e2e.sh,overlay-bench.sh}`, `ha-p3/scripts/chaos-2gw-hard.sh` (cgroup-freeze black-hole), `ha-p3/tools/turnprobe` (extend to sustained pps) | reuse as-is |

**Isolation (mandatory):** load-gen and component-under-test run in **non-overlapping cgroups** via `systemd-run --scope -p AllowedCPUs=… -p MemoryMax=…`. For any scale-out test, **each component + Postgres + loadgen gets its own cpuset** — otherwise "doesn't scale" is just two processes fighting over cores. **`AllowedCPUs` pins userland, not the kernel RX/softirq path** — this is fatal for the UDP and any pps-bound measurement (see R3/R6 below).

**First-saturating-resource attribution, every step:** at each ramp point sample, in the same 5 s window — per-cgroup CPU (`pidstat`/`mpstat` per core, split %sys/**%softirq separately, because softirq is not cgroup-attributable**), `/proc/<pid>/status` VmRSS, `ls /proc/<pid>/fd|wc -l` vs `/proc/<pid>/limits`, `runtime.NumGoroutine` (expvar), pgx pool stats (in-use/wait/empty-acquire), `pg_stat_statements` **reset per run** (bucket: sessions-scan / GetNode / IsSuspension / affinity-upsert / broker-INSERT), `ss -u`/`nstat` UDP RcvbufErrors, and a concurrent **`fio --fsync=1`** measurement of the shared NVMe — every sess/s number is normalized to measured fsync/s because audit + bbolt + PG-WAL all fsync to the disk four other labs share.

**Rigor:** **open-loop ramp-to-saturation** (fixed arrival rate, not fixed concurrency) so post-knee collapse isn't hidden by closed-loop back-pressure; **HDR histogram, coordinated-omission-corrected** latency. One closed-loop run to find the knee, ≥1 open-loop run past it to expose collapse. `store=postgres` for **every** scale number (bbolt is single-writer/single-node and hides the dominant DB bottleneck). Gate every run on `e2e.sh` before *and after* — a number from a functionally-broken build is worthless.

**Three scaling axes, not one.** Most ramps below sweep **M** (sessions), but two more axes change the answers by an order of magnitude and must be first-class where marked:
- **K = distinct principals/nodes.** The sweep's per-record reads are pure functions of `(ws,provider,subject)` and `(ws,nodeID)`; M sessions across K principals/D nodes issue M reads but touch only K+D distinct rows. A realistic fleet has K,D ≪ M. The sweep knee is a **surface over (M, K)**, not a scalar in M.
- **W = workspaces.** `overlayFor(ws)`, `policyFor(ws)`, the 127-IP pool, suspensions, and `repushAllNetworks(ws)` are **all per-workspace**, but `ListAllSessions` is **global**. So sweep cost is the *sum over all workspaces*, the overlay leak surface is *per-workspace*, and allocator/policy structure count scales with W. Ramp W in R1/R5/R6/R8.

---

## 2. The suite — ramps in priority order

Each ramp: **scaling variable(s) → swept values → degradation signal → expected knee/cliff & shape → key metrics.**

### R1 — Deny-path sweep crossing 15 s (control plane) ★ headline cliff
- **Variables (2-D + W):** M = live (Active+Detached) session rows **× sessions-per-principal** (i.e. M and K independently) **× W workspaces**. **Sweep:** M ∈ {1k, 5k, 20k, 50k, 100k, 250k, 500k, 1M}; sessions/principal ∈ {1, 10, 100, 1000}; W ∈ {1, 100, 1000} with M held; `reauth_interval` ∈ {5s, 15s, 60s}. Pre-seed via pre-seeder; drive one controller's real `runContinuousAuthz`.
- **Signal:** `sweep_duration_seconds ≥ reauth_interval`. **Note the mechanism correctly:** `time.NewTicker` (`continuousauthz.go:30`) has a buffer-1 channel and the Go runtime **silently drops** coalesced ticks — sweeps do **not** queue or overlap. So the real signal is `sweep_duration / interval > 1` and the **tail of enforcement latency**: inject a suspension mid-sweep and time write-to-teardown (`deny_enforcement_latency_p99`). `sweep_overlap_ratio` is a measurement artifact (reads ~1.0 forever) — **do not use it.** Split cost three ways: scan+`json.Unmarshal`, O(M log M) sort, and the **per-record `reauthorize()` read loop** (1–2 PG point reads each, deduping to K+D rows).
- **Expected:** scan ~linear with an O(M log M) sort knee bending up past ~100k; the **dominant superlinear term is the per-record read loop, but its magnitude collapses as K,D shrink** — so the 15 s crossing is a *surface*: at high K it lands in the 20k–100k M band; at low K (few principals) it moves up by an order of magnitude. SHAPE: superlinear in M, near-flat in M at fixed low K. **Actionable A/B:** hoist the `IsSuspended`/`GetNode` reads into a per-sweep batched/deduped prefetch and re-measure the knee — that delta *is* the fix's value.
- **Revoke-storm arm (the real 5× bite):** only **1** of the 5 `ListAllSessions` call sites is on the 15 s timer (`:77`); the other 4 (`:221,:363,:446,:470`) are **event-driven** (revokeBySubject / revokeUser / redeliverPendingRevokes / suspension-invalidation). Trigger K concurrent revocations and measure the resulting **full-scan pileup** — K simultaneous global scans landing on the one Postgres. This is where the prompt's "5×/15s" actually bites and it is otherwise untested.
- **Metrics:** `sweep_duration`, `deny_enforcement_latency_p99`, `pg_qps_by_statement`, `distinct_rows_read_vs_M` (K+D dedup ratio), `revoke_storm_concurrent_scans`, `cpu_per_sweep_per_live_session`, unmarshal alloc/GC.

### R2 — Relay TCP splice: aggregate goodput + deadline tax + r.mu + clean-shed ★ user ask #1 (TCP)
- **Variable:** S = concurrent splices {64, 256, 1k, 4k, 8k, 16k(=cap)} × frame size {bulk 32 KiB; interactive 64–512 B} × connect-churn C {100, 500, 2k, 10k matches/s}. Push 10–20 % **past** `MaxPending*16=16384` (`relay.go:152`).
- **Signals:** (a) aggregate goodput flattens then per-splice goodput falls ~1/S (fairness decay); (b) at small frames, CPU scales with **chunks/s not bytes/s** — A/B the stock relay against a one-line patch that refreshes the deadline ≤1×/s to isolate the `time.Now`+timer-heap cost; (c) `'connection cap reached, shedding'` Warn fires (`:156–159`) with **flat RSS** (clean shed) vs climbing RSS (cap bypassed → would OOM); (d) `r.mu` serializes accept/match/untrack → matches/s flattens while cores idle.
- **A/B contamination control (shared host):** the deadline-tax A/B cancels *steady* contention but not co-tenant *variance*. **Interleave A/B at fine grain** — alternate stock/patched every 30 s within one wall-clock window, ≥10 cycles — and report the **paired-difference distribution**, not two separate-run means. Cheap; makes the within-process truth robust to four neighboring labs.
- **Expected:** bulk = CPU plateau (TLS+memcpy), no hard cliff. Small-frame = **superlinear CPU in chunks/s** → interactive ceiling far below bulk. Churn = `r.mu` knee (matches/s caps regardless of spare cores). Cap = designed clean-shed plateau (verify, don't assume).
- **Metrics:** `aggregate_spliced_goodput`, `per_splice_goodput_p50/p10/min`, `paired_deadline_tax_delta`, `mutex_block_time`, `conn_cap_shed_rate`, `relay_rss`.

### R3 — Relay UDP floor pps ceiling (no-GSO) ★ user ask #1 (UDP) — MULTI-HOST ONLY
- **Variable:** A = concurrent TURN allocations {1,4,16,64,256,1024} × datagram size {1280 B, 64 B}; ramp aggregate pps until forwarded-pps flattens/drops. Extend `turnprobe`; confirm `:7404` in-path via `overlay-bench.sh` tcpdump count.
- **Signal:** `turn_forwarded_pps` flattens then **drops**; `UDP RcvbufErrors` (`ss -u`/`nstat`/`netstat -su`) climb = single pion read loop overrun.
- **Expected:** **hard pps CEILING** set by per-datagram syscall cost on the single read path (`turnserver.go:33` single `ListenPacket`); 1280 B caps Gbit/s far below the TCP bulk number; 64 B hits the **same pps wall at a fraction of the bytes** — proving pps-bound, not byte-bound. The floor's multi-gig limiter and the motivation for GSO on the direct path.
- **Metrics:** `turn_forwarded_pps`, `turn_forwarded_throughput` (1280 vs 64 B), `udp_rx_buffer_errors`, single-core %sys/%softirq.
- **CAVEAT (HARD):** `AllowedCPUs` pins userland but **not** the kernel RX/softirq path, which the relay shares with four co-tenant labs + the load-gen's own TX softirqs. Co-tenant pps can saturate the RX path first, so you measure the *host's* pps ceiling, not the *relay's* — and this can **invert** the relative 64B-vs-1280B claim. **R3 has NO single-host Class-A claim.** Run load-gen and relay on **separate physical hosts** (or dedicated-queue NIC / SR-IOV with RPS pinned away from co-tenants) and confirm drops are on the *relay's* socket via its own `nstat`, not the sender's. Otherwise quote nothing.

### R4 — No-jitter reconnect herd vs SERIALIZABLE affinity ★ user ask #2 (the instability)
- **Variable:** N agents {100, 500, 1000, 2000} on `store=postgres`; arrival synchronized **via an injected phase barrier in `agentstorm`** (release all N reconnects at one instant) — **not** via a real controller black-hole. Rationale: on a shared host a CPU-starved controller drops its own gRPC keepalive and *manufactures* reconnects, so a real disconnect would "reproduce" the herd from scheduler starvation, not from the no-jitter bug. The barrier injects the synchronization deterministically.
- **Signal:** `agent_affinity` 40001 retry rate; claims approaching/exceeding `maxSerialRetries=10` → `codes.Unavailable` → agent re-loops at 1 s (no jitter, `worker.go:710`) → **re-forms the herd** (positive feedback); pgxpool `EmptyAcquireCount` rising (only ~NumCPU pooled conns vs N concurrent claims); the phase-aligned 15 s metrics+heartbeat sawtooth (parsed + forwarded to the external VictoriaMetrics).
- **Expected (Class-A narrowed):** claim latency + 40001 rate rise **superlinearly** in synchronized N, and **jitter in `streamLoop` flattens both curves** — the directly actionable finding, valid on one host *because the arrival sync is injected, not scheduler-induced*. **CLIFF / non-convergence** (herd-arrival-rate > sustained-claim-rate) and **absolute N-at-collapse** stay Class-B (need PG + agents on distinct VMs).
- **Metrics:** `affinity_serialization_retry_rate`, `affinity_claim_p99` (CO-corrected), `unavailable_reconnect_fraction`, `reconnect_herd_reconvergence_time`, `pgxpool_acquire_wait`, `metrics_forward_cpu_burst`.

### R5 — Overlay-pool exhaustion (the confirmed leak) ★ deterministic cliff, cheapest signal
- **Variables:** cumulative VPN-rejects **× W workspaces** (each workspace is an independent 127-IP leak surface; W workspaces hold W allocator maps). Trigger rejection (e.g. agent-policy `forbid_detach` / workspace-scope mismatch); fire `ActionVPN` at 5–20 req/s.
- **Two arms:**
  - **Arm A (all-reject, Tier-0 unit test, host-independent):** cliff in ~10–25 s. 100 % `codes.ResourceExhausted "overlay address"` while exec/ssh keep working, that **does not recover** when load stops and persists across sweep ticks (the sweep's release path only fires for sessions that reached Active then got revoked — never for offer-rejected ones, `broker.go:460–475`).
  - **Arm B (1:10 reject:success) — must include drain-and-recheck.** `overlay_pool_used` rises under *both* a leak and legitimate concurrent VPN load, so a raw climb is indistinguishable from healthy saturation until the cliff. The clean signal is: stop all traffic, wait > maxTTL + one sweep, then **assert `used == count(actually-active VPN sessions)`**. The non-zero leaked delta is the finding — not the climb.
- **Expected:** **hard CLIFF at exactly 127 rejects per workspace** (IPs 128..254). Not a slope. Healthy below, dead above, permanent until restart. With W ramped, W independent cliffs.
- **Metrics:** `overlay_pool_used` (per ws), `cumulative_vpn_rejects_to_cliff` (expect ==127), `drained_leaked_delta` (arm B). Arm A reproducible in a unit test — fully host-independent.

### R6 — N-controller scale-out: capacity or just N× sweep load? — POSTGRES MUST BE OFF-BOX
- **Variable:** N controllers {1, 2, 4}, **each in its own cpuset**; M held at {5k, 20k}; W ∈ {1, 100}. Measure aggregate broker sess/s at fixed p99 SLO and `pg_qps_by_statement` attributed to sweeps.
- **Signal:** aggregate broker capacity FLAT or DECLINING in N; total sweep-attributed PG QPS grows ~linearly in N at constant M; per-controller sweep duration *rises* with N (PG contention).
- **Expected:** confirms the **O(N·M/I) load model** — controllers add deny-path COST, not capacity.
- **CAVEAT (HARD — this ramp is self-defeating on one host):** its premise is "the *Postgres* is the shared bottleneck," but on one box PG also fights the controllers + load-gen for 48 cores, so cpuset-starving PG produces a "flat capacity" curve that is an **artifact of the partition, not the architecture**. The negative result is valid **only if PG is provably NOT the first-saturating resource** — i.e. **Postgres on a separate physical host (or a dedicated NUMA node with guaranteed memory bandwidth), with `postgres_cpu < 70%` at the measured plateau**. If PG cannot be given headroom, **demote R6 to model-only / multi-host-pending and report NO capacity-vs-N curve from this host.**
- **Metrics:** aggregate `broker_throughput` at fixed p99, `pg_qps_by_statement`, per-controller `sweep_duration` vs N, `postgres_cpu` (must be < 70 % for the curve to count).

### R7 — Broker p99 vs concurrency C at large M (serialization wall) — needs a separate-audit-disk arm
- **Variable:** C {1,4,16,64,128,256,512} via `ctlbench` (fast-ack fake agents — without fast-ack you measure one agent's serialization); store {bbolt, postgres}; M ∈ {1k, 100k} so latency is measured **with a heavy sweep in flight**; **audit-sink ∈ {shared NVMe, dedicated tmpfs/NVMe}**.
- **Signal:** throughput flattens early, latency rises linearly with C while throughput is flat = serialization wall; mutex/block profile names it (`audit.a.mu` serializing all appends + the two synchronous fsyncs per session).
- **Disk-vs-mutex disambiguation (mandatory on this host):** flat-in-cores + rising p99 is produced by **both** `audit.a.mu` contention and the shared-NVMe fsync queue (bbolt-WAL + PG-WAL + audit JSONL + 4 co-tenant labs all fsync to one disk). They are indistinguishable without an arm that **points audit at a separate tmpfs/dedicated NVMe** and re-measures the C-knee. The **delta attributes the wall to disk-vs-mutex**; without it R7's "serialization wall" is unfalsifiable here.
- **Expected:** **flat-in-cores** plateau; knee in C is low (single-digit to low-tens) at the fsync/mutex wall. bbolt cap ≈ 1/(fsync_audit + fsync_bbolt); PG shifts it to synchronous INSERT commit + pool size; the separate-disk arm isolates which.
- **Metrics:** `broker_throughput` (fsync-normalized), `broker_latency_p50/p99/p999`, `mutex_block_time` (profiling-ON build only), `pg_pool_wait`, `c_knee_shared_vs_dedicated_audit_disk`.

### R8 — Many-agents steady-state footprint + fan-out (control-channel linearity)
- **Variable:** N {100→10000} idle agents (`agentstorm`) **× W workspaces**; plus fan-out triggers at fixed N.
- **Signals:** goroutines/fd/RSS slope per agent (baseline LINEAR — `Stream` spawns no per-agent helper goroutine server-side, verified); **fd approaching RLIMIT_NOFILE** (a deceptive partial cliff at ~1024 if unraised); `repushAllNetworks` is **at least O(N²)** — verified `pushNodeNetworks → networkDNS` does its *own* `ListNodes(ws)` (`networkpush.go:187`) inside a per-peer loop that also calls `networkOverlayIP` per peer, so it's N×(ListNodes + N×networkOverlayIP); a single membership change at N=10k is ≥10⁸ reads (a **floor**, worse if `networkOverlayIP` rescans); `Broadcast` is a serial loop where one back-pressured agent head-of-line-blocks the rest.
- **Expected:** goroutine/RSS LINEAR (a superlinear bend is *itself* the finding); fd-RLIMIT cliff first if ulimit untuned (note it explicitly — host-config, not capacity); network-push **≥quadratic** wall-clock is the dominant fan-out cliff. **`repushAllNetworks` and serial-`Broadcast` are host-independent algorithmic truths — promote firmly into Tier 0 with R5.** The micro-harness should also profile `networkOverlayIP` to confirm it is not O(N³).
- **Metrics:** `controller_goroutines_per_agent` (slope), `controller_fd_headroom_to_rlimit`, `controller_rss_per_agent`, `repush_all_networks_wall_clock`, `networkoverlayip_complexity`, `broadcast_fanout_last_delivery`.

### R9 — Data-plane overlay: direct vs floor + the un-upgradeable tunnel
- **Variable:** G = offered Gbit/s (`iperf3 -u -P {1,4,8,16}`) on one VNI; P = concurrent in-process `ICEBind` peers sharing the one GSO socket + one `readLoop` {2..64}; the OnPunchAt cliff arm.
- **Signals:** direct vs floored Gbit/s gap (floor = no GSO); single per-VNI `readLoop` goroutine pinned at one core (numDrainers=4 sit *after* recvCh); `b.mu` taken on **every** inbound and outbound packet → per-tunnel throughput falls ~1/P; **relay-stuck fraction does NOT decay** after impairment lifts (`OnPunchAt` no-op verified at `icebind.go:723`).
- **Expected:** direct scales multi-gig to the readLoop/`b.mu` knee; floor plateaus far lower; floor-stuck fraction stays constant — permanent per-tunnel tax = (direct−floor gap) × stuck fraction. SHAPE: direct≫floor (ratio host-defensible), floored flat, no-recovery cliff. The controller cred-mint fan-out is the same O(N²) algorithmic shape as R8.
- **Metrics:** `overlay_throughput_direct_vs_floored`, `relay_pkts_in_data_path`, `readloop_goroutine_cpu`, `bind_mutex_wait`, `relay_stuck_fraction` vs time.

### R10 — Soak / leaks (the slope-only failures) — runs alongside R1–R9 over 1 h / 12 h / 72 h
- **Variable:** churn C (create+reap/s) × held concurrency × duration T.
- **Signal:** **monotone positive slope** in goroutines/fd/RSS sampled at the *same churn-cycle phase*, that survives drain + `runtime.GC`×2 + `debug.FreeOSMemory` (a cache returns to baseline; a leak does not). Watch agent `len(w.live)`/`len(w.sessionICE)` + leaked lease `*time.Timer`s on fault paths (client-killed mid-handshake); session-host tombstone plateau (expected ≈ C×60 s — distinguish from a leak); relay `used`/`pending`/`conns` draining to 0; audit JSONL unbounded growth (no rotation) + **O(total-records) open-time `verifyAuditFile` rescan** → slow restart.
- **Expected:** mostly bounded/flat on clean churn; the deliverable is *which fault path* leaves a nonzero floor. Audit = flat append latency but a latent **restart-time/disk cliff**, not a request cliff.
- **Metrics:** `*_slope` (per hour), `return_to_baseline_delta`, `tombstone_population`, `lease_timer_count`, `audit_chain_size`, `audit_open_verify_time`.

---

## 3. What is defensible on the one shared host vs needs separated VMs / multiple hosts

| Fact | Class A — defensible on ONE shared host (shape / existence / ordering / first-resource) | Class B — needs separated VMs / multiple hosts (absolute capacity / timing / scale-OUT) |
|---|---|---|
| **R1 sweep** | SHAPE (linear scan + O(M log M) knee + per-record read term) **as a surface over (M, K, W)**; existence of a 15 s crossing; `deny_enforcement_latency` tail; revoke-storm scan-pileup count (in-process + PG variant) | **Absolute M-at-crossing** (function of shared NVMe fsync queue + cores) — report fsync-normalized + cpuset-isolated only |
| **R2 TCP relay** | Goodput-rollover + 1/S fairness shape; deadline-tax via **fine-grained interleaved A/B** (paired-difference cancels co-tenant variance); clean-shed-vs-OOM (within-process); `r.mu` serialization shape | **Absolute max Gbit/s** and exact splice-count knee |
| **R3 UDP floor** | **NONE.** `AllowedCPUs` doesn't pin softirq/RX; co-tenant pps can invert even the relative 64B-vs-1280B claim | **Everything** — absolute pps ceiling AND the relative pps-bound claim; **multi-host-only**, drops must be confirmed on the relay's own socket |
| **R4 herd** | No-jitter superlinearity + that jitter flattens it — **only with arrival sync injected by phase barrier** (a real disconnect manufactures the herd from scheduler-starved keepalive loss) | **Absolute N-at-collapse** + non-convergence (needs PG + agents on distinct VMs) |
| **R5 overlay leak** | **Fully deterministic, host-independent** (arm A = unit test); per-ws leak surface scales with W | (none — nothing) |
| **R6 N-controller** | DIRECTION (flat/declining in N) **only if Postgres is OFF-BOX with `postgres_cpu < 70 %`**; otherwise **no claim** (cpuset-starved PG fakes the flat curve) | **Absolute scale-OUT capacity across N hosts is explicitly NOT established** — only the negative per-Postgres ceiling, and only with PG given headroom |
| **R7 broker** | Serialization-wall shape (flat in cores) **only if the separate-audit-disk arm disambiguates disk-vs-mutex**; which lock names it (profiling-ON build) | Absolute sess/s |
| **R8 agents** | goroutine/fd/RSS slope + per-agent constant; **≥O(N²) repush** and serial-`Broadcast` head-of-line (algorithmic, host-independent); fd-RLIMIT cliff (note ulimit); per-ws structure cost | Absolute "how many agents fit"; false-disconnect/keepalive rates (need PG+controller+loadgen on distinct VMs) |
| **R9 data plane** | readLoop single-core + `b.mu` plateau; direct≫floor ordering; `OnPunchAt` no-recovery cliff; controller O(N²) cred-mint shape | **Absolute Gbit/Mpps**; real NAT/srflx/double-NAT selection (flat-L2 bridge under-exercises hole-punching); mesh fan-out at M>~8 |
| **R10 soak** | Every leak slope + return-to-baseline + audit open-verify linearity (code-path properties) | Absolute max N/S/C before saturation; VictoriaMetrics ingest latency under a true off-box agent herd |

**Mandatory for any Class-A number:** `store=postgres`; load-gen in a separate cgroup/VM; profiling OFF for capacity numbers; every sess/s normalized to a concurrent `fio --fsync=1`.

---

## 4. Prioritization — most signal, cheapest first

**Tier 0 — do today (deterministic, no rig, highest signal/cost):**
1. **R5 overlay-pool cliff (arm A)** — provable in a unit test in minutes; a confirmed bug with a hard cliff at 127 and a one-line-ish fix (call `release()` on the reject path). **Fix-validating, ship first.**
2. **R8 algorithmic shapes** — `repushAllNetworks` ≥O(N²) (verified N×(ListNodes + N×networkOverlayIP) at `networkpush.go:187`) and serial-`Broadcast` head-of-line are provable by code reading + a micro-timing harness; profile `networkOverlayIP` for a hidden O(N³). Host-independent — co-equal Tier 0 with R5.
3. **R1 sweep, in-process** — extend the wired `BenchmarkScaleListAllSessions` (M=1k..1M already there) with M=3k/30k/300k + a **PG variant running the real `reauthorize()` read loop** + the **(M, K) 2-D grid** + the **revoke-storm** arm. Places the 15 s-crossing *surface* before any VM rig is stood up.

**Tier 1 — needs the cgroup rig + new harnesses, but single-host-valid:**
4. **R4 reconnect herd** (`agentstorm` phase-barrier + jitter A/B) — the user's stability ask; the jitter-fixes-it finding is directly actionable.
5. **R2 TCP relay** (`splicegen`, fine-grained interleaved A/B) — the user's derp ask (TCP half); deadline-tax and clean-shed are within-process truths.
6. **R7 broker-vs-C** (`ctlbench` + separate-audit-disk arm) — names the serialization wall and disambiguates disk-vs-mutex.

**Tier 2 — needs cpuset discipline / off-box dependencies:**
7. **R6 N-controller negative-scaling** — **only** with Postgres off-box and proven `< 70 %` CPU; else model-only.
8. **R9 data plane** (`overlay-bench.sh` + in-process ICEBind harness) — direct-vs-floor ratio + OnPunchAt cliff single-host; absolutes deferred.

**Tier 3 — multi-host / long-running, schedule explicitly:**
9. **R3 UDP-floor pps** — quote any number, including the *relative* one, **only** from two physical hosts.
10. **R10 soak** — 12 h/72 h endurance, run continuously *under* Tier-1/2 load.

Every Tier requires the **pprof/expvar instrumentation** (§1) landed first — the single highest-leverage prerequisite — with **profiling OFF for capacity, ON only for attribution**.

---

## 5. Regression-gate form — a knee that moves

Each ramp emits not a pass/fail latency but a **knee LOCATION**, checked into a baseline and gated build-to-build. **A build fails when it moves a knee earlier (toward less load) by more than the run-to-run noise band.**

```
gate: <ramp-id>
  knee_metric:   <e.g. M_at_sweep_crosses_15s@(K,W) | N_at_herd_40001_superlinear
                      | C_at_broker_throughput_plateau | S_at_per_splice_goodput_halves
                      | pps_at_turn_floor_rollover | cumulative_rejects_to_overlay_cliff>
  baseline:      <value>          # measured on the reference build, this host, isolated cgroups, profiling OFF
  noise_band:    <±X% over K runs> # established from K≥5 reference runs
  fail_if:       knee < baseline*(1 - noise_band)     # moved EARLIER = regression
  warn_if:       curve_shape changed (linear→superlinear, plateau→cliff, slope sign flip)
  context_pins:  store=postgres; cgroup-isolated; profiling=OFF; fsync_norm=<concurrent fio fsync/s>;
                 host=shared-hetzner; e2e.sh=GREEN(before&after)
```

**Hard, build-to-build invariants (any breach = fail, independent of the moving knee):**
- `cumulative_rejects_to_overlay_cliff == 127` per workspace, and **rises to ∞** once `release()` is added on the reject path (R5 — proves the fix and prevents its regression).
- Relay RSS at the 16384 conn cap stays **flat** (clean shed), never climbs (R2).
- 64 B-datagram pps ceiling ≈ 1280 B pps ceiling **on the multi-host rig** (proves pps-bound; divergence means GSO crept onto the floor or the harness is byte-limited) (R3).
- Controller goroutines stay **linear** in N (any superlinear bend is a leak) (R8); `return_to_baseline_delta ≈ 0` after drain+forced-GC (R10).
- `repushAllNetworks` wall-clock stays **≤ O(N²)** — a slip to O(N³) (e.g. `networkOverlayIP` regressing) is a fail (R8).
- `OnPunchAt` upgrade count stays 0 until it's implemented — then `relay_stuck_fraction` must **decay** after impairment lifts (R9).

Because all gated values are **shapes, knee locations, and orderings** (Class A), they are valid build-to-build from the single shared host even though their absolute magnitudes are contended — the gate compares each build against the *same-host reference baseline*, so host contention cancels. (R3 and R6 capacity gates run on their multi-host/off-box rigs only.)

---

**Key files for the implementer.** Instrumentation seam to add (build-tag `perfdebug`, profiling default-OFF): `/root/geneza/internal/controller/server.go`, `/root/geneza/internal/relay/relay.go`, `/root/geneza/internal/agentd/worker.go`, `/root/geneza/internal/sessionhost/sessionhost.go`. Confirmed leak to fix: `/root/geneza/internal/controller/broker.go:460–475` (add `overlayFor(ident.Workspace).release(overlayIP)` on the reject path). Sweep read loop to hoist/batch: `/root/geneza/internal/controller/continuousauthz.go:134,148` (bypasses `denycache.go:54`). ≥O(N²) fan-out to profile: `/root/geneza/internal/controller/networkpush.go:187,280`. Existing benches to extend (add (M,K,W) grid + revoke-storm + PG read-loop variant): `/root/geneza/internal/controller/brokercost_bench_test.go:238,264`. Reuse rigs: `/root/labs/geneza1/scripts/{e2e.sh,overlay-bench.sh}`, `/root/labs/geneza1/ha-p3/scripts/chaos-2gw-hard.sh`, `/root/labs/geneza1/ha-p3/tools/turnprobe`.
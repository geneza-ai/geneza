The critique's corrections are all confirmed against source:

- **audit.go:180** — exactly **one** `f.Sync()` in `Append`; `writeCheckpoint` (`:382-391`) is `os.WriteFile`+`os.Rename`, **no fsync**. The critique's mechanism fix is correct.
- **store.go:294** — `bbolt.Open` with no `NoSync`; `PutSession` (`:952`) uses `s.db.Update` (default sync). So "two fsyncs" = 1 audit + 1 bbolt, right total but the plan's decomposition was wrong.
- **broker.go:476/542** — the two `Append("session_request"...)` are allow-path and deny-path. A successful broker does ~1 audit append.
- **continuousauthz.go** — 5× `ListAllSessions` (`:77,221,363,446,470`) confirmed.
- **icebind.go** — GSO strings (`:190/:197`), `batch=128` (`:320`), `OnPunchAt` no-op (`:723`), `readLoop` single RX (`:806`), `OnSelectedCandidatePairChange` (`:517`) all confirmed; **vpn.go:21** MTU=1280 confirmed.
- **relay.go:403-409** — 32 KiB buffer, per-iteration `SetReadDeadline`/`SetWriteDeadline` confirmed.
- Reuse artifacts live under `/root/labs/geneza1/`, **not** `/root/geneza/`. `iperf3`/`tcpdump` **absent**. **No pprof** anywhere in `cmd/` or `internal/`.

All folded in below.

---

# Geneza Load & Performance Benchmark Plan

*Final plan. Synthesizes six per-dimension benchmark designs (control-plane brokering, session data plane, mesh-VPN data plane, scale/concurrency/soak, resource footprint, HA failover) and folds in the adversarial methodology review.*

> **Read this first — the one framing that governs everything below.** We have **one shared Hetzner bare-metal host** running kolla1, sunbeam1, scs1, keycloak1, and geneza1 simultaneously. On this hardware Geneza benchmarks split into two epistemically different classes, and **conflating them is the single biggest way this report goes from useful to misleading**:
>
> - **Class A — defensible on one host: relative orderings, ratios, presence/absence of a bottleneck, per-CPU efficiency.** "Direct is N× the relay floor," "removing the audit fsync buys K×," "the sweep ceiling rises/falls/flattens with controller count," "conduits tear down at the lease TTL," "GSO is on / off." These compare components against each other on the same contended substrate, so the contention largely cancels.
> - **Class B — NOT defensible on one host: absolute capacity & timing.** Absolute **Gbit/s** ("multi-gig"), absolute **sessions/sec scale-out across controllers**, and **failover wall-clock timing** are all functions of cores/NVMe-fsync-queue/clock that the components under test *share with each other and with four other labs*. These are valid **only** on isolated lab VMs with cores pinned and other labs quiesced (or on multiple hosts), and must be labelled lab-bound every time they appear.
>
> Every headline in §3 is tagged **[Class A]** or **[Class B]**. A Class-B number reported without core-isolation + lab-quiesce is **noise wearing a lab coat** and must not ship.

---

## 1. Goals, Non-Goals & Key Questions

### Goals
Produce a **defensible, reproducible quantitative model** of one Geneza deployment along five axes — control-plane throughput/latency, session-data-plane goodput, mesh-VPN goodput, scale ceilings, HA failover timing — plus a **per-component resource model** (RSS/fd/goroutines/CPU per agent, per session, per relayed byte) usable to size a host and to name the **first saturating resource** for each axis.

Every number carries: the **path/backend it belongs to** (direct vs relay-TCP vs TURN-UDP; bbolt vs postgres; local-broker vs redirect), **percentiles not means**, a **measured-fsync-rate footnote** wherever durability writes are on the hot path, and a **Class-A/Class-B tag** so a reader never mistakes a ratio for an absolute.

### Non-Goals
- Not a correctness suite — `e2e.sh`, `dataplane-libs-proof.sh`, the `*-proof.sh` scripts already cover that; we **reuse their bring-up**, not their assertions.
- Not multi-host WAN at scale — cross-host realism is bounded to the geneza1 lab VMs and emulated NAT/latency (`tc netem`). **Controller scale-out (N hosts) is explicitly out of scope; only the negative sweep-ceiling result is in scope, and only with CPU isolated** (see §3 P3.2 and the P0-4 caveat).
- Not the DERP/global-edge HA spec (`docs/ha-architecture-spec.md` is historical here) — only the **implemented Postgres-flat leaderless** HA.
- Not productizing the diagnostic knobs (bbolt `NoSync`, pg `synchronous_commit=off`) — those are **headroom-only**, clearly labelled, never reported as product throughput.

### Key questions the benchmark MUST answer
1. **Multi-gig / GSO claim (mesh-VPN) [mixed]:** *Relative (Class A):* does the **direct GSO path** (`sendmmsg`, batch=128, `icebind.go:197/320`) beat the **relay floor** — which has **no GSO** (relayed peers stay on pion/TURN sockets, `icebind.go:130-133`) — and by what ratio in **CPU-s/GiB**? Does MTU-matching the TUN (1280, `vpn.go:21`) toward the wg device ceiling measurably help? *Absolute (Class B, lab-bound):* the absolute Gbit/s figure is reportable **only** with VM106/107 on isolated cores and other labs quiesced; otherwise we report **only** the ratio and per-core efficiency.
2. **Sessions/sec claim (control plane) [Class A for the wall, Class B for the absolute rate]:** Is the ceiling — as the code implies — the **two independent serialized fsyncs per brokered session**: one audit `f.Sync()` (`audit.go:180`, under `a.mu`) **plus** one bbolt tx-commit sync in `PutSession` (`store.go:952`, `bbolt.Open` has no `NoSync`, `:294`) — **not** crypto or policy? The *attribution* (fsync dominates) is Class A; the *absolute* sessions/sec is Class B and must be normalized to measured fsync latency.
3. **Agent-RTT honesty [Class A ratio + 1 Class-B anchor]:** `CreateSession` blocks on a live agent acking the offer (`broker.go:460`, `offerTimeout=5s` `:79`). What is the **fast-ack controller ceiling** vs the **honest agent-RTT-bound** number? The synthetic ack-delay sweep is a **model**; anchor it with **one real-RTT datapoint from VM106** or the "honest number" is just a second synthetic number.
4. **HA tax & timing [redirect=Class A; failover wall-clock=Class B, lab-bound]:** What does a cross-controller **redirect** add (the `dialRedirect` fresh mTLS handshake, `controller.go`)? What is **deny-path doorbell propagation** — suspend (in-txn `NOTIFY`) vs cert-revoke (no fanout, `denyCacheTTL=3s` floor)? **Time-to-re-home** and **fail-closed conduit window** are **config-derived predictions** (keepalive 15s+20s; `SessionLeaseTTL=120s`) — measuring them on host-net loopback adds little and can mislead; the trustworthy timing run is **VM-only**.
5. **The unsharded sweep [Class A direction only]:** Does adding controllers add broker capacity, or just add **N × `ListAllSessions()` per 15s** on one Postgres? (`continuousauthz.go` calls `ListAllSessions()` **5×** per sweep — confirmed `:77,221,363,446,470`.) We can establish the **direction** (flat/declining) **only if controllers are in non-overlapping CPU cgroups**, else "doesn't scale" is just two controllers fighting over one box's cores.
6. **Leaks [Class A]:** Over a churn soak sized to actually exercise the suspect maps, are goroutines/fd/RSS **flat** on controller, agent worker, and session host — and do they **return to baseline on drain after a forced GC**?

---

## 2. Shared Test Harness Design

### Where to run — three tiers, used deliberately, never conflated

| Tier | Target | Use for | Class it can support |
|---|---|---|---|
| **Tier-1: in-process Go (`go test -bench`, loopback, `relay.New(TLS=false)`)** | per-component attribution: policy eval, ed25519 sign, **audit fsync**, **bbolt commit sync**, ECDSA issue; layer-overhead ladder (raw→Noise→SSH→SCTP); relay-splice memcpy ceiling + **raw-`io.Copy`-no-deadline control** | **A** (orderings, per-op cost). Isolates the two independent fsyncs and the per-frame crypto cost; nothing off-the-shelf composes Geneza's `tunnel.Client/Server`+`sessionconn` stack |
| **Tier-2: docker stacks on the hypervisor (`deploy/compose/all-in-one`, `deploy/compose/ha`)** | control-plane throughput vs **postgres store**; HA redirect/doorbell **correctness + relative tax**; relay fan-out soak against the real TLS binary | **A only.** bbolt hides the dominant DB bottleneck → HA/scale numbers MUST use `store=postgres`. **Each controller in a non-overlapping `cpuset` cgroup; PG+loadgen in their own.** This tier **cannot** establish failover wall-clock or scale-out capacity (see P0-4). |
| **Tier-3: geneza1 lab VMs (gw+relay VM105 `10.70.70.10`, agents VM106/107 `.21`/`.22`, vmbr5)** | the **honest** data-plane/mesh numbers, real NAT/double-NAT (`iptables MASQUERADE`), real PTYs, fail-closed conduit teardown, real-RTT anchor, real failover physics | **A always; B only with cores pinned + other labs quiesced.** Only tier with distinct per-node CPU and real NAT. |

> **Single-host caveat, stated once and referenced everywhere:** docker host-networking **cannot** do double-NAT or per-process CPU attribution, and loopback `iptables -j DROP` does **not** reproduce a real link going dark (no link-down, different RST/keepalive physics, and it can sever PG/relay loopback too). **Run the load generator in a separate VM/cgroup from the controller** — co-locating loadgen+controller+PG+relay on one box measures harness CPU starvation, not a Geneza ceiling.

### Load generators
- **`tools/ctlbench` (NEW, build-tagged):** primary control-plane driver. Reuses `internal/ca` (mint role-bearing user certs + node CSRs — a generic gRPC tool **cannot** speak the CA-gated mTLS listener with per-principal certs, `auth.go` `VerifyClientCertIfGiven` + `ca.go` `PeerIdentity`), `internal/types`, the generated `genezav1` client. Implements: cert/CSR pools, a **fast-ack fake-agent fleet** (NodeControl stream + instant/delayed `SessionOffer` ack — required, else you measure one agent's serialization), closed-loop + open-loop drivers, **HDR histogram** (coordinated-omission-corrected).
- **`tools/hostload` (NEW):** drives the **sessionhost unix socket** directly (`SessionHostClient`) to isolate PTY density / ring / vt10x memory and the `Create` check-and-reserve TOCTOU from controller+relay.
- **`tools/ha-loadgen` (NEW):** brokers across controllers round-robin/targeted; splits redirect latency (first-RPC vs `dialRedirect` fresh mTLS); supports an explicit **prewarmed-owner-pool counterfactual arm** (see P2.7); stands up **stub agents** (hello+heartbeat+ack only) to scale homed-agent count and seed live-session rows. **Note:** stubs do NOT arm the lease timer — fail-closed teardown (P3.8) and soak leaks (P4) need **real VM agents**.
- **`go test -bench -benchmem -cpuprofile`** (NEW `_test.go`, no production change): `BenchmarkPolicyEvaluate` (1/5/25/100 rules), `BenchmarkGrantSign` (ed25519), **`BenchmarkAuditAppend`** (real vs no-`Sync`), **`BenchmarkBboltCommitSync`** (default vs `NoSync` — a *second, independent* fsync to attribute), `BenchmarkCSRIssue` (ECDSA P256), `BenchmarkRelaySplice` (with vs without per-iteration deadline set).
- **`iperf3`** over the gnzw TUN and through the relay TCP splice. **NOT installed anywhere** — explicit provisioning is a Phase-0 step (see P0-2), not an assumption.
- **`geneza` CLI** (`exec`/`cp`/`forward`/`shell`+`ptydrive.py`) — the only honest end-to-end action measurement.
- **Reuse — with corrected absolute paths (these live under `/root/labs/geneza1/`, NOT `/root/geneza/`):**
  - `/root/labs/geneza1/scripts/e2e.sh` (35-check correctness gate)
  - `/root/labs/geneza1/scripts/overlay-bench.sh` (ICE pair class, RTT/loss, single+N-parallel iperf3, tcpdump relay-in-path; **apt-installs iperf3 on the VM**)
  - `/root/labs/geneza1/scripts/dataplane-libs-proof.sh` (relay-restart/controller-restart/blindness fault choreography)
  - `/root/labs/geneza1/ha-p3/scripts/chaos-2gw-hard.sh` (cgroup `systemctl freeze` black-hole, `chk()`/`PG()`/`owner()` helpers, §C concurrent cross-gw exec)
  - `/root/labs/geneza1/ha-p3/tools/turnprobe` (mint region cred → force/verify the `:7404` TURN floor)

### Results collection
- **Server-side ground truth:** the agent node_exporter module (`module_nodeexporter.go`) streams `process_resident_memory_bytes`/`process_open_fds` over the control channel; the controller forwards those to an external VictoriaMetrics (`metrics.go` is a thin proxy — no series state in-process) — query via console `/api/v1/metrics/query[_range]`. Use for **agent RSS/fd soak trends**. Note: the metrics store is now a separate container, so its RAM/CPU is **not** attributed to the controller process; sample VM's own pid separately.
- **CRITICAL GAP — confirmed by grep: there is NO `net/http/pprof` anywhere in `cmd/` or `internal/`.** The controller, relay, and session host expose **no broker-latency metric, no Go-runtime self-metrics, no pprof.** Therefore:
  1. **Broker latency/throughput is measured client-side** in `ctlbench` (HDR), corroborated by go-bench + CPU/mutex/block profiles.
  2. **A build-tagged, loopback-only `net/http/pprof` listener must be added to `geneza-controller`, `geneza-relay`, and `geneza-agent`/session-host** (off in shipped binaries). This is a **real code change touching three binaries and requiring review — not harness glue** — and **must land, be merged, and pass an `e2e.sh` smoke BEFORE Phase 0**, because Phase 0.2 asserts pprof is reachable. Without it, goroutine-leak detection is impossible and `/proc/<pid>/task` thread count is only a **floor**, not a goroutine count.
- **OS-level sampler (`sampler.sh`, NEW):** every 60s append `VmRSS`, fd count, thread count, CPU (`utime+stime`) to per-pid **CSV**. `iostat -x`/`pidstat`/`mpstat` for fsync io-await and per-core CPU. For PG: `pg_stat_statements` (reset per run) + `pg_stat_activity` sampling, bucketed into broker-txn / sweep / affinity-upsert / deny-read.
- **Disk-contention control (mandatory on every CP run):** alongside each control-plane run, run a `fio --fsync=1` probe and record **baseline idle `fsync/s` of the `data_dir` mount AND `fsync/s` under the other labs' nominal load.** Report **sessions/sec normalized to measured fsync latency** (and prefer **CPU-s/op** over wall-clock). The audit file, the bbolt file, and Postgres' WAL all fsync to the **same shared NVMe** that kolla1/scs1/keycloak1 are hitting — without this normalization the headline is non-reproducible even on the same box next week.

### Rigor (applies to every scenario)
- **Warmup/drain:** discard first+last 10% of every window; discard the **first iteration per config** (TLS ticket, GC, page-cache, ICE convergence).
- **Closed-loop sweep** to find the knee + **≥1 open-loop fixed-arrival-rate** run to expose throughput collapse past the knee (closed-loop self-throttles and hides coordinated omission).
- **Repeat ≥3× (≥5× for stochastic failover/recovery/hole-punch); report distributions, never single samples.**
- **Predictions vs observations are separate columns.** A value derived from a config constant (e.g. re-home ≈ 35s from 15s+20s keepalive) is a **prediction** labelled with its constant; a measured value is an **observation**. **Never put a guessed multiplier or point estimate (`~10×`, `~300µs`) in a pass/fail cell** — predictions inform, observations decide.
- **Record per run:** `GOMAXPROCS`, core pinning (`taskset`/`cpuset`), CPU governor state, store backend, MTU, **selected ICE pair class**, host idle headroom, **and which other labs were running**.
- **Emit CSV/JSON** (`host,tier,class,path,backend,dir,C,mtu,proto,metric,p50,p99,p999,cpu_s_per_op,fsync_per_s,...`).

---

## 3. Benchmark Suite — by Phase

Tags: **[CP]** control-plane · **[SD]** session-data · **[VPN]** mesh-vpn · **[SC]** scale/soak · **[RF]** resource-footprint · **[HA]** ha-failover. Each row also carries **[Class A]** (orderings/ratios — defensible on one host) or **[Class B]** (absolute capacity/timing — VM-only, cores pinned, labs quiesced).

### PHASE 0 — Smoke + provisioning (≈1 day, gated by the pprof seam landing first)
Prove the rig + instrumentation before any number is trusted. **All provisioning below is a prerequisite, not an assumption.**

| # | Tag | Workload | Pass/observe |
|---|---|---|---|
| 0.1 | RF | Bring up `all-in-one` + `ha`, idle 5 min, `/proc` sample | **The `ha` docker stack has never been built/run (compose ps empty); building+wiring it is part of this step, not a given.** Fix the DSN mismatch: the only PG container up is `geneza-pgtest` on **`:55432`**, but `deploy/compose/ha/config/controller.yaml` points at `:5432` — reconcile before claiming a fixture. Capture **idle RSS/fd/goroutine y-intercept** (hypothesis: controller > relay,agent; the metrics store is now its own VictoriaMetrics container — sample its pid separately, don't fold it into the controller). |
| 0.2 | all | pprof seam already merged → assert reachable on loopback for all three binaries; `go test ./...`; `/root/labs/geneza1/scripts/e2e.sh` (35 checks) green | **Use the corrected absolute path** — the script is NOT in `/root/geneza`. pprof reachable; e2e passes → fixture sane. |
| 0.3 | prov | Install `iperf3` + `tcpdump` on the hypervisor AND on VM105/106/107; raise `rmem_max`/`wmem_max` and verify `UDP_SEGMENT`/`recvmmsg` kernel support on the 2 GB VMs | **Both tools are absent today.** The path-attribution `tcpdump :7404` gate that EVERY data-plane scenario relies on does not exist until this runs. GSO RX silently underperforms on tiny VMs without socket-buffer sysctls — assert them. |
| 0.4 | VPN | `overlay-bench.sh` one run; assert `shared GSO data socket up … batch=128` (`icebind.go:197`), **ICE selected-pair-class log** (primary path signal, `OnSelectedCandidatePairChange` `:517`), **tcpdump :7404 == 0** (corroboration only) | GSO **confirmed on**; path-class assertion wired. *Without these, every direct number is invalid.* |
| 0.5 | CP | `ctlbench` fast-ack at C=1, 1k sessions | end-to-end harness path works; sane single-shot latency. |

### PHASE 1 — Baseline resource model + per-component attribution (≈1.5 days) — **[Class A]**
Establishes the coefficients everything else references (§4).

| # | Tag/Class | Workload | Swept | Metrics | Observe (predictions labelled) |
|---|---|---|---|---|---|
| 1.1 | RF/CP · A | `go test -bench` micro suite | policy rules {1,5,25,100}; **audit `Sync` vs none**; **bbolt commit `NoSync` vs default** (two independent fsyncs); `GOMAXPROCS{1,2,4,8,16}` | per-op ns: PolicyEvaluate, GrantSign, AuditAppend, BboltCommit, CSRIssue | **Confirm ordering** audit-fsync & bbolt-fsync (the two walls) ≫ ECDSA issue ≫ ed25519 sign ≫ policy ≫ denyCache. *Prediction (constants): ECDSA ~hundreds-µs, ed25519 ~tens-µs — verify, don't assert.* Crypto parallelizes; fsync does not. |
| 1.2 | SD · A | Tier-1 layer ladder: raw→+Noise→+SSH→+SCTP, 5 GiB each way | payload write {1K,8K,32K,128K,1M}; SCTP MTU {1200,1400,9000} | per-layer overhead (% goodput lost), noise rechunk factor | Quantify the tax: 1 MiB Write → ~32 frames (32 KiB `MaxPlaintext`); SCTP@1200 → many DATA chunks/frame. |
| 1.3 | RF/SD · A | Tier-1 relay-splice microbench (`relay.New` TLS-off) **+ raw `io.Copy` no-deadline control** | pairs 1..8192; buffer {16,32,64,256}K; uni/duplex; `GOMAXPROCS{1,2,4,8}` | relay MiB/CPU-s, heap KiB/splice (vs 64 KiB code floor), **Δ from per-iteration `SetRead/WriteDeadline` (`relay.go:406,409`)** | The deadline-set runs **every iteration** (~tens of thousands of setsockopt-class calls/s/dir at multi-Gbit); the no-deadline control attributes its real cost. Justify/challenge the 32 KiB buffer. |
| 1.4 | RF/SC · A | `agent-fanout-idle`: N idle agents, monitoring on/off | N {0,50,100,250,500,1000}; push {15s,2s} | RSS/connected-agent, controller forward CPU/push, VM-pid RSS/series | Regress slope; **expect the synchronized 15s push burst** (parse + import POST to VM) to move controller CPU before gRPC stream memory; series RAM now accrues in the **VM container**, not the controller. *No isolation of forward-CPU from broker-CPU is possible without the pprof seam — that is why the seam gates this phase.* |
| 1.5 | RF/SC · A | `session-scaling`: M long-lived sessions | M {0,10,50,100,250,500}; ring {256K,1M,16M}; cols×rows | RSS/fd/goroutines per session | per-session RSS ≈ `ring_bytes` + vt10x grid; ~8–10 goroutines/session agent-side (`session.go`). |

### PHASE 2 — Load: the headline ceilings (≈3 days)

| # | Tag/Class | Workload | Swept | Metrics | Observe (predictions labelled) |
|---|---|---|---|---|---|
| 2.1 | CP · **A** (wall) **/ B** (abs rate) | **`broker-fastack-concurrency-sweep`** | C{1..512}; store{bbolt,postgres}; action{exec,shell,vpn}; session_p2p{off,on} | broker throughput (sess/s, **normalized to fsync/s**), latency p50/p90/p99/p999, saturating_resource | **Headline.** Hypothesis (Class A): bbolt flattens at low C, capped near `1/(fsync_audit + fsync_bbolt)` **regardless of cores**; mutex/block profile shows `audit.a.mu`. postgres shifts cap to synchronous INSERT commit + pgx pool. *Absolute sess/s is Class B — ship it only with the fsync-normalization footnote.* |
| 2.2 | CP · A | **`broker-component-attribution`** live A/B at C=64 | shim out **independently**: (a) audit `Sync`, (b) bbolt commit-sync, (c) store→in-mem, (d) policy→1-rule, (e) session_p2p | sessions/s delta per shim | **Two independent fsyncs to attribute** (audit `:180` and bbolt commit `:952`) — shim each separately; the `os.Rename` checkpoint (`:391`) is a third, cheaper write, **not a removable fsync — do not conflate.** Report the measured multiplier; do **not** pre-commit to "~10×". |
| 2.3 | CP · A (sweep) + **B-anchor** | **`broker-realistic-agent-latency`** | ack delay{0,2,20,200}ms; dist{fanout-2000,hotspot-1}; C{16,64,256} | throughput, agent-wait vs controller-work share, error/deny rate, goroutine growth | **HOTSPOT** surfaces per-agent waiter serialization → 5s `offerTimeout` (`:79`) tail + goroutine/RSS growth. FANOUT@200ms→throughput≈C/0.2s is **a model, state it as such.** **Anchor with ONE real-RTT datapoint from a real VM106 agent** or the "honest number" is just a second synthetic number. |
| 2.4 | CP · A | `enrollment-and-token-mint` | enroll C{1,8,32,128}; auto_approve{F,T}; co-members{0,100,1000}; store | enroll/s, ms p50/p99, token/s | Enroll path = 2 audit appends + ECDSA issue + PutNode → lower than brokering. **Verify the per-success audit-append count by instrumentation** (broker success path is **1** audit append, not 2 — `:476` allow vs `:542` deny). `repushAllNetworks` fanout at 1000 co-members starves the broker. |
| 2.5 | SD · A (ratios) **/ B** (abs Mbit/s, VM-only) | `S3` end-to-end actions, **per transport** | action{exec,sftp↑↓,forward(1,8),shell}; transport{relay-tcp,ice-direct,turn-udp}; size{64M,1G} | goodput (Mbit/s), interactive RTT p50/p99, establish latency | **Assert path per run** via ICE pair-class log (primary) + tcpdump:7404 (corrob.); `offer.go:253` path label `relay-tcp`. Hypotheses (Class A ordering): sftp latency-bound; **TURN-UDP < relay-TCP** due to SCTP@1200. Absolute Mbit/s is **VM-only, cores pinned**. |
| 2.6 | VPN · A (ratio + CPU-s/GiB) **/ B** (multi-gig abs, VM-only) | `S1` direct baseline + `S2` relay-floor ceiling **on isolated VMs** | dir TX/RX; P{1,4,8,16}; TCP/UDP; MTU{1280, 1420-matched, jumbo} | overlay Gbit/s, udp pps, **per-tunnel CPU-s/GiB**, selected pair class | **The "multi-gig" test, and the document's #1 misleading risk.** A single-stream ChaCha20 test is CPU-bound by definition; on a contended host you measure *the scheduler's mood*, not Geneza. **Report only the direct-vs-floor RATIO and CPU-s/GiB unless VM106/107 are on dedicated isolated cores with the other labs shut down** — only then is an absolute Gbit/s defensible, and it ships labelled "lab-bound, isolated-cores." Direct: single-core ChaCha + single per-VNI `readLoop` (`:806`); MTU-match should help. Floor (`dataplane_relay_only:true`): **no GSO (`:130-133`), expect order-of-magnitude lower**; relay CPU saturates as pairs grow. |
| 2.7 | HA · A (relative tax) | `baseline-local-vs-redirect` (no faults), `store=postgres`, controllers in **separate cpusets** | target{owner,non-owner}; C{1,4,16,64}; arms{cold-dial-real, prewarmed-owner-pool-counterfactual} | redirect Δ p50/p95/p99, split first-RPC vs `dialRedirect` | **The arms are structurally un-matchable**: `dialRedirect` (`controller.go`) *always* fresh-dials mTLS; the client pools to the *first* controller, not the owner. So measure the **real cold-dial redirect cost** and report it as the product behavior, and add the **prewarmed-owner-pool arm only as an explicit counterfactual**, not as "matched." Fresh mTLS dominates the tax, not the extra `AgentAffinity` SELECT. |
| 2.8 | HA · A | `doorbell-propagation-under-load`, `store=postgres` | N gw{2,3,4}; churn{0,50,200}/s; fault{delivered,dropped}; event{suspend,cert-revoke,config} | propagation ms, notify-drop recovery (≤3000ms) | **suspend** = in-txn `NOTIFY` fanout, sub-10s-of-ms; **cert-revoke has NO bus fanout** → floored by `denyCacheTTL=3s` (label which mechanism — a "propagation" number that always lands near 3s is the TTL backstop, not the doorbell). Dropped-notify must converge by the 3s backstop. *Clock-skew is moot on the single-kernel docker tier — don't over-engineer chrony here; it matters only on VMs.* |

### PHASE 3 — Stress / saturation (≈3 days)

| # | Tag/Class | Workload | Swept | Metrics | Observe (predictions labelled) |
|---|---|---|---|---|---|
| 3.1 | CP/RF · A | **`broker-throughput-audit`** at saturation | C{1..200}; audit_sink{none,file-local,file-separate,http}; store{bbolt,pg} | brokers/sec, p99, cpu-s/broker, audit-append latency | **http sink (`Append` blocks ≤5s under `a.mu`) collapses throughput** to a handful/sec — the sharpest demonstration of audit serialization. |
| 3.2 | SC/CP · **A (direction ONLY, and only with cores isolated)** | **`create-session-throughput-ceiling`** + the unsharded sweep, `store=postgres`, **each controller in a non-overlapping `cpuset`, PG+loadgen separate** | M live sessions{1k,5k,20k}; N gw{1,2,4}; reauth{5,15,60}s; pool MaxConns | throughput knee (sess/s @ p99 SLO), pg QPS attribution, sweep duration, **per-cgroup CPU** | **Most architecturally important finding — and structurally fragile.** Goal: does throughput go **flat/declining in N** at large M, confirming the unsharded `ListAllSessions()`×5/sweep ceiling (O(N·M/interval))? **On one host, controller #2 competes for the exact cores it would add — so a "doesn't scale" result is only meaningful if per-cgroup CPU shows controllers are NOT CPU-starved.** State plainly: **N-host scale-OUT is NOT established here; only the negative sweep-ceiling result is, and only if CPU isn't the confound.** Track when sweep duration crosses **15s** (sweeps overlap). |
| 3.3 | SC · A | `agent-fanin-ceiling` + `session-host-pty-density`, `store=postgres` | agents{100..10k}; max_sessions{64,256,1024}; ring{256K,1M,16M}; burst-200 TOCTOU | max concurrent agents, connect throughput, max sessions/host, TOCTOU never over-admits | connect path = synchronous `ClaimAgentAffinity`+audit PG write → DB-write-bound; PTY density → RSS=(ring+vt grid)·sessions then **pty fd vs RLIMIT_NOFILE**; caps hold under concurrent burst. |
| 3.4 | VPN · A | `S2` relay-floor fan-out + `S4` NAT/double-NAT (VMs) | pairs{1,2,4,8}; NAT{none,single,double via MASQUERADE}; 10 cold connects/class | relay aggregate throughput, time-to-connected, selected pair type, success rate | **double-NAT srflx likely fails → relay floor / no-mesh** (matches recorded OpenStack double-NAT failure). MASQUERADE is full-cone-ish — **optimistic vs real symmetric NAT; label NAT type.** |
| 3.5 | VPN · A | `S3` relay→direct **late-upgrade cliff** (VMs) | direct blocked-at-start vs open; observe re-upgrade | re-upgrade happens? (expected **no**) | **`OnPunchAt` is a confirmed no-op (`icebind.go:723`)** → a tunnel nominated on the floor **stays on the floor permanently.** A perf cliff, not a tuning knob. |
| 3.6 | SD/SC · A | `S4` relay fan-out soak + `concurrent-broker-fanout` | sessions{10..1000}@{1,10,50}Mbit/s; churn{10,50,100}/s; MaxPending tightened | max concurrent splices, offer-ack drop rate, fairness, conn-cap shedding | single relay mutex `r.mu` under churn contends before data-forwarding cores saturate; conn cap = `MaxPending*16` (16384) must **shed cleanly, not OOM**. |
| 3.7 | HA · **B (timing is config-derived; VM-only for real physics)** | `blackhole-rehome-timing` + `rapid-flap`, **on VMs** | fault{iptables-DROP, SIGSTOP, SIGKILL}; agents-on-dead{10,50,200}; flap{2/2,5/5,20/10}s | time-to-rehome, redirect-to-dead-owner rate, 40001 retry rate, reconvergence | **Re-home ≈35s is a PREDICTION from keepalive constants (15s+20s), not a host-net measurement** — loopback DROP doesn't reproduce a dark link, so measure it **on the VMs** where link physics are real. Redirect-at-dead-owner ≤60s (`controllerStaleTTL`); reconnect herd → synchronized `ClaimAgentAffinity` SERIALIZABLE burst + 40001 retries (**no jitter in `streamLoop` — confirmed**). Include one flap > 60s+35s as the "must converge" control. **Scope any `iptables` DROP to the specific gRPC port; verify PG/relay still reachable; reverse in a `trap`.** |
| 3.8 | HA · **B (window is config-derived; needs REAL agents)** | `pg-outage-failclosed-window`, **VMs, real agents** | outage{10,60,180}s; load present vs quiesced; deny-written-during | failclosed teardown window, recovery convergence | broker errors immediately (fail-closed); **live conduits die within ~`SessionLeaseTTL=120s`** of leases stopping → <120s outages coast, >120s tear all; **no stale-allow leak**; recovery herd on `connectAndResync` (flush denyCache + re-read config per LISTEN reconnect). **Stub agents do NOT arm the lease timer — this scenario REQUIRES real VM agents.** |

### PHASE 4 — Endurance soak (6h, then 24h) (≈1.5 days wall, mostly unattended) — **[Class A]**

| # | Tag | Workload | Sample (60s) | Observe |
|---|---|---|---|---|
| 4.1 | SC/RF | `endurance-soak`: churn sized to actually trip the leaks (see below) + forced reaper via small `idle_reap_sec`/`detached_ttl_sec` | RSS, fd, threads, **goroutines (pprof)** for controller/agent/sessionhost | **Flat slopes after warmup.** **Size churn from the suspected leak:** to detect a 4 KiB/session leak as 100 MiB over 6h you need ~25k full **create+reap** cycles ≈ **≥1.2 leaking-ops/s** — exec-only churn will NOT exercise `w.live`/`w.sessionICE`/lease `*time.Timer`. **End with a quiescent drain → `GODEBUG=gctrace=1` + forced GC, THEN measure** so "RSS didn't drop" is distinguishable from "GC hadn't run." Leak suspects: agent `w.live`/`w.sessionICE` maps + lease timers; sessionhost ring/vt10x on reap; controller overlay-IP release on `ended`/`rejected`/`revoked`; registry waiters on offer timeout; PTY/splice fds. |
| 4.2 | VPN | `S6` recovery under churn (×5): relay-restart, controller-restart, cred-expiry (VMs) | ping-loss as liveness signal | **relay-restart recovery is a PREDICTION ~50–70s** (livenessWatchdog 10s + 45s stale + jittered backoff) — observe, don't pass/fail on the number; **controller-restart must be ZERO data-plane interruption** (data rides its own UDP socket); cred-expiry mid-transfer must not strand the allocation. **Cap test duration below TURN cred TTL (~2m)** or extend the grant, else expiry masquerades as throughput collapse. |

---

## 4. Baseline Resource Model (establish FIRST — Phase 0/1) — **[Class A]**

Produce this table before any saturation test; it is the y-intercept + slopes everything references. **These are coefficients/orderings (Class A) — defensible on one host.**

| Coefficient | Source scenario | Hypothesis to confirm |
|---|---|---|
| idle RSS/fd/goroutines per controller/relay/agent/sessionhost/metrics | 0.1, 1.x | controller > relay,agent; the VictoriaMetrics container is its own line item (not folded into the controller) |
| RSS MiB / connected idle agent | 1.4 | small stream state + recurring 15s push (parse + forward); series RAM accrues in the VM container, not the controller |
| RSS/fd/goroutines per active session | 1.5 | ≈ `ring_bytes`(256K) + vt10x grid; ~8–10 goroutines/session agent-side |
| relay heap / active splice & / pending slot | 1.3, 3.6 | ~64 KiB/active (2×32K) + stacks; sheds at conn cap |
| relay MiB copied / CPU-second (TLS on/off) **and Δ from per-iter deadlines** | 1.3 | the per-relayed-byte efficiency → "how many relays for X Gbit/s"; deadline-set cost is non-trivial |
| CPU-s / brokered session (policy/sign/**audit-fsync**/**bbolt-fsync**/store split) | 2.1, 2.2, 3.1 | **two independent fsyncs** dominate wall; ed25519 ~tens-of-µs CPU |
| CPU-s / sweep-tick / live session | 3.2 | linear; sets the practical live-session ceiling per controller |
| VM-container KiB/series + controller forward CPU-s/push | 1.4 | series RAM is the VM container's ceiling; the controller's per-push cost is parse + import POST |
| **measured fsync/s of the actual `data_dir` mount, idle AND under other-lab load** | every CP run | **report alongside brokers/sec, normalized — or the number is non-portable** |

---

## 5. Prioritization & Effort

**Measure first for the most signal** (each validates/refutes a headline and is cheap):

1. **P1.1 + P2.2 micro/A-B fsync attribution** (½–1 day) — proves the **two independent fsync walls** (audit `:180` + bbolt commit `:952`) in isolation; cheapest, most decisive evidence for the sessions/sec story. **Class A.**
2. **P2.1 broker fast-ack sweep, bbolt vs postgres, fsync-normalized** (1 day) — the **sessions/sec headline** (wall=Class A; absolute rate=Class B with footnote). mutex/block profile names the wall.
3. **P2.6 mesh direct vs relay-floor RATIO + CPU-s/GiB, MTU sweep, VM-isolated** (1 day) — the **multi-gig/GSO headline**; ships as a **ratio** unless cores are isolated and labs quiesced.
4. **P2.3 realistic-agent-latency + 1 real-RTT VM anchor** (½ day) — converts the headline into the **honest** number.
5. **P3.2 unsharded-sweep direction, controllers in separate cpusets** (1 day) — "does HA scale or just multiply sweep load," meaningful **only** if per-cgroup CPU rules out starvation.
6. **P3.7 black-hole re-home timing, on VMs** (1 day) — the failover number users feel; ~35s keepalive **prediction**, measured where link physics are real.

**Rough effort:** Phase 0 ≈ 1d · Phase 1 ≈ 1.5d · Phase 2 ≈ 3d · Phase 3 ≈ 3d · Phase 4 ≈ 1.5d wall (unattended). **Up-front harness build ≈ 1.5–2d**, of which the **pprof seam is a reviewed code change across three binaries (controller/relay/agent) — not glue — and must merge BEFORE Phase 0**, plus `ctlbench`/`hostload`/`ha-loadgen` + CSV sampler + the unbuilt `deploy/compose/ha` stack wiring (DSN reconcile). **Total ≈ 11–12 engineer-days.**

---

## 6. Expected Bottlenecks (hypotheses to test) & Pitfalls to Avoid

### Top bottleneck hypotheses (all code-grounded)
1. **[CP] TWO independent serialized fsyncs per brokered session** — (a) audit `f.Sync()` under `a.mu` (`audit.go:180`) and (b) bbolt tx-commit sync in `PutSession` (`store.go:952`, `bbolt.Open` has no `NoSync` `:294`). The audit **checkpoint** (`writeCheckpoint`, `os.WriteFile`+`os.Rename`, `:382-391`) is **NOT a fsync** — don't attribute a third fsync to it. A *successful* broker does **1 audit append** (`:476`); `:542` is the **deny** path. Ceiling ≈ `1/(fsync_audit + fsync_bbolt)` independent of cores. The **http audit sink (≤5s under `a.mu`) collapses it.**
2. **[CP/SC] Unsharded `ListAllSessions()` ×5 per 15s on every controller** (`continuousauthz.go:77,221,363,446,470`) → O(N·M/interval) PG load; adding controllers adds sweep load, not capacity. Sweep must finish < 15s or sweeps overlap.
3. **[SD/VPN] Relay floor has no GSO** (relayed peers stay on pion/TURN sockets, `icebind.go:130-133`) + pion/turn forwards one datagram/syscall → floor ≈ order-of-magnitude below direct; **SCTP@1200** makes TURN-UDP slower than relay-TCP for bulk. Relay `copyHalf` sets **deadlines every iteration** (`relay.go:406,409`) — a real per-byte tax measured against a no-deadline `io.Copy` control.
4. **[VPN] Late-upgrade cliff:** `OnPunchAt` no-op (`icebind.go:723`) → floor-nominated tunnels never upgrade. Re-home ≈35s (keepalive 15s+20s); relay-restart recovery ≈50–70s — both **predictions from constants**, measured on VMs.
5. **[CP/SC] Blocking agent `SendOffer` (5s, `:79`)** makes throughput a function of agent RTT + in-flight concurrency; hotspot serializes per-agent and pins goroutines.
6. **[HA] No jitter in `streamLoop`** → synchronized reconnect herds hammer SERIALIZABLE `ClaimAgentAffinity` (40001 retries). **cert-revoke ≈3s** (no fanout, `denyCacheTTL`) vs **suspend** (in-txn `NOTIFY`). Conduits fail-closed at **120s** lease TTL (needs real agents to arm).
7. **Not the bottleneck:** ed25519 sign, ECDSA issue, policy eval (linear in rules) — all parallelize far below the fsync wall. *(Magnitudes are predictions to verify, not pass-criteria.)*

### Pitfalls (each invalidates a result if ignored)
- **The Class-A/Class-B confusion** — reporting an absolute Gbit/s, scale-out sess/s, or failover wall-clock measured on the shared host as if defensible. **Reframe every headline as the ratio/ordering it can support, or mark it VM-bound with cores isolated.**
- **Broken reuse paths** — the reuse scripts are under **`/root/labs/geneza1/`, not `/root/geneza/`**; a `./e2e.sh` from the repo fails at the first invocation.
- **Missing primitives** — `iperf3` and `tcpdump` are **not installed** anywhere; the `:7404` path gate doesn't exist until P0.3 provisions it.
- **Unbuilt HA stack** — `deploy/compose/ha` has never run; `geneza-nats` is irrelevant to the pg-flat path; the live PG is on `:55432` not the config's `:5432`. Build + reconcile in Phase 0.
- **No pprof = no leak detection** — the seam is a reviewed three-binary code change that must land **before** Phase 0; `/proc/task` is a floor, not goroutines.
- **fsync io-await polluted by other labs** — quiesce, run a `fio --fsync=1` control alongside every CP run, **normalize sessions/sec to measured fsync latency**, prefer CPU-s/op.
- **Co-located loadgen** — run it in a separate VM/cgroup from the controller; in P3.2 put each controller in a non-overlapping cpuset and report per-cgroup CPU, else "doesn't scale" = cores fighting.
- **Path misattribution** — gate on the **ICE selected-pair-class log as primary**, tcpdump:7404 as corroboration only (tcpdump==0 is necessary, not sufficient — a TCP-fallback or off-:7404 srflx can fool it).
- **GSO silently off** — assert `shared GSO data socket up … batch=128` per run; on 2 GB VMs raise `rmem_max`/`wmem_max` and verify `UDP_SEGMENT`/`recvmmsg`.
- **Single-agent / 0ms-ack** — report fast-ack AND realistic-ack, labelled; anchor the synthetic delay sweep with one real VM-RTT datapoint.
- **bbolt masks the DB bottleneck** — any HA/scale number uses postgres.
- **Redirect arms are un-matchable** — measure the real cold-dial redirect cost; the prewarmed-owner-pool arm is a labelled counterfactual, not product behavior.
- **Closed-loop only** hides post-knee collapse — add open-loop + HDR/coordinated-omission; **percentiles, never means; predictions and observations in separate columns; no guessed multiplier in a pass cell.**
- **Soak under-churn** — size churn from the suspected per-event leak size; force full create+reap cycles; end with `GODEBUG=gctrace` + forced GC then measure; drain to baseline.
- **denyCache 3s TTL floors propagation** — a "propagation" number landing near 3s is the cert-revoke TTL backstop, not the doorbell.
- **TURN cred TTL (~2m) expiry mid-transfer** masquerades as throughput collapse — cap test duration below TTL.
- **Diagnostic knobs (`NoSync`, `synchronous_commit=off`)** are headroom-only — never product throughput.
- **iptables blackhole on host-net** can cut PG/relay loopback — scope DROP to the gRPC port, verify reachability, reverse in `trap`; **clock-skew handling (PG `now()`/chrony) matters only on the VM tier — the single-kernel docker tier shares one clock; don't over-engineer it there.**
- **Stale environmental snapshots** (container uptimes, "37–38h up") are load-bearing for nothing — keep them out of a plan meant to be re-run.

---

## Phase 0 — Do This First

Nothing in Phases 1–4 is trustworthy until all of the following are true. Do them in order.

1. **Land the pprof seam.** Build-tagged, loopback-only `net/http/pprof` in `geneza-controller`, `geneza-relay`, `geneza-agent`/session-host (off in shipped binaries). It is a reviewed code change across three binaries — merge it and pass an `e2e.sh` smoke **before anything else**. Without it, leak detection is impossible and metrics-forward-vs-broker CPU is unattributable.
2. **Provision the missing primitives.** `apt-get install iperf3 tcpdump` on the hypervisor and on VM105/106/107. Raise `net.core.rmem_max`/`wmem_max` on the 2 GB VMs and verify `UDP_SEGMENT`/`recvmmsg` kernel support (else GSO RX silently underperforms).
3. **Build and wire the `deploy/compose/ha` stack.** It has never run. Reconcile the DSN: the live PG container is on `:55432`; `deploy/compose/ha/config/controller.yaml` points at `:5432`. Confirm `router=pg`, `store=postgres` in the rendered config. Ignore `geneza-nats` (not on the pg-flat path). Put each controller in a non-overlapping `cpuset`; PG + loadgen in their own.
4. **Fix every reuse path.** They live under `/root/labs/geneza1/`, not `/root/geneza/`: `/root/labs/geneza1/scripts/e2e.sh`, `/root/labs/geneza1/scripts/overlay-bench.sh`, `/root/labs/geneza1/scripts/dataplane-libs-proof.sh`, `/root/labs/geneza1/ha-p3/scripts/chaos-2gw-hard.sh`, `/root/labs/geneza1/ha-p3/tools/turnprobe`.
5. **Decide the multi-gig scope now, on the record.** Either (a) declare absolute Gbit/s **out of scope**, reporting only the direct-vs-floor **ratio** + **CPU-s/GiB**; or (b) commit to shutting down kolla1/sunbeam1/scs1/keycloak1 and pinning VM106/107 to dedicated isolated cores for the duration. Do not publish an absolute "multi-gig" number produced any other way.
6. **Stand up the harness scaffolding.** `ctlbench` (CA-minted cert pools + fast-ack fake-agent fleet + HDR), `hostload`, `ha-loadgen` (stub agents + prewarmed-owner counterfactual arm), `sampler.sh` (60s `/proc` CSV), and the per-run `fio --fsync=1` disk-contention control. Pre-mint cert pools and pre-enroll/approve agents **outside** every timed window.
7. **Smoke-gate the rig.** Idle-RSS baseline (0.1), `go test ./...` + `e2e.sh` green (0.2), tools/sysctls verified (0.3), GSO-on + ICE-pair-class + tcpdump:7404 assertion wired (0.4), `ctlbench` C=1/1k sane (0.5). Only then start Phase 1.
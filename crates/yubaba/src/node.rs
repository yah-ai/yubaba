//! Node specs + resource usage — the data behind `GET /node` and
//! `GET /node/usage`.
//!
//! # Why this exists
//!
//! Every capacity decision in the fleet currently rests on a hand-typed
//! number. `.yah/infra/machines/<name>.toml` declares `[allocatable]
//! memory_mb / cpu_millis`, the scheduler's capacity floor
//! (`cloud::config::RequiredSpec::matches`) compares a workload request
//! against it, and *nothing* has ever asked the box whether the number is
//! true. `us-west-015`'s `12288` was read off a Colima config by a human.
//!
//! These two endpoints make the node itself the source of truth: `/node`
//! reports what the hardware *is*, `/node/usage` reports what it is
//! *doing*. A declared `allocatable` that disagrees with the measured
//! ceiling becomes surfaceable drift instead of an unverifiable assertion.
//!
//! # Why plain JSON with OpenTelemetry field names (and not the OTel SDK)
//!
//! The decision was made deliberately, and the shape of this module is the
//! consequence, so it is recorded here rather than only in a working doc.
//!
//! **We adopt OpenTelemetry's semantic-convention *attribute names*. We do
//! not adopt the OpenTelemetry SDK.**
//!
//! Every field below that has a standard name uses it verbatim —
//! `host.arch`, `host.name`, `host.cpu.model.name`, `os.type`,
//! `system.cpu.utilization`, `system.memory.usage`, `system.memory.limit`,
//! `system.filesystem.usage`. Anything with no standard equivalent is
//! namespaced under `yah.` (`yah.allocatable.memory_mb`,
//! `yah.committed.cpu_millis`, `yah.collector`), which is exactly what the
//! conventions prescribe for non-standard attributes. The keys are emitted
//! *flat and dotted* rather than nested for one specific reason: each key is
//! then already a valid OTLP attribute key, so an exporter is a rename-free
//! `for (k, v) in payload` loop rather than a translation layer.
//!
//! What we skip is the crate stack — `opentelemetry`, `opentelemetry_sdk`,
//! `opentelemetry-otlp`, and their tonic/prost/protobuf transitive tree.
//! Three reasons, in order of weight:
//!
//! 1. **Binary size.** yubaba ships as a statically-linked
//!    `*-unknown-linux-musl` artifact that is curl-fetched onto every node
//!    at provision time, and its size is actively tracked (W156 binary-size
//!    audit). The OTLP exporter tree is megabytes of gRPC machinery to
//!    publish ~15 scalars.
//! 2. **The consumer is in-house.** Both callers — the desktop Infra tab and
//!    a peer yubaba — speak the same `cloud-client` types. Neither needs a
//!    collector between them.
//! 3. **The push/pull requirement is already satisfied.** "Report usage at
//!    whatever interval another yubaba or client wants" is a *pull*: the
//!    client polls `/node/usage` on its own clock. See
//!    [`NodeProbe`] for how the sampling window follows the caller's
//!    interval rather than a server-side subscription.
//!
//! The cost of being wrong is bounded and known: if the fleet later wants
//! real OTLP, the work is an exporter that reads these same keys, not a
//! re-modelling of the payload. That asymmetry — cheap to adopt later,
//! expensive to carry now — is the whole argument.
//!
//! # Platform support
//!
//! Collection is *feature-detected, not target-gated*. Linux reads procfs;
//! macOS shells out to `sysctl` / `vm_stat`; anything else reports
//! `yah.collector = "unsupported"` with null measurements rather than
//! failing the request. A node that cannot measure itself must still answer
//! `/node` — an unmeasurable node and an unreachable node are different
//! states and the Infra tab has to be able to tell them apart.
//!
//! macOS matters concretely: `us-west-015` (MacBook Air M2) is the fleet's
//! first darwin node and has no `/proc` at all.
//!
//! # Domain metrics: pushed by the producer, not hardcoded here
//!
//! CPU/memory/disk are the metrics *every* node has. They are not the only
//! metrics a node's operator cares about, and the second consumer of this
//! endpoint proves it: a noisetable gallery installation is a small yubaba
//! cluster whose per-plinth health question is "audio xruns, callback deadline
//! misses, BLE advert rate", none of which yubaba can or should know how to
//! measure.
//!
//! So the metric *set* is open. [`DomainMetrics`] is a registry of
//! `source -> {key: scalar}` that anything can publish into, and
//! [`NodeUsage`] merges it flat into the same payload. A domain metric is
//! indistinguishable from a built-in one at the wire — `noisetable.audio.xruns`
//! sits beside `system.cpu.utilization` and an OTLP exporter forwards both with
//! the same rename-free loop.
//!
//! **Push, not pull.** There is no register-a-callback API, and that is
//! deliberate on two counts. Both real producers are *out of process* — the
//! noisetable design has an egress peer translating impulse-carried telemetry
//! into this RPC (that repo's `W138` §Telemetry), and a workload publishing its
//! own health is a separate container by construction — so an in-process
//! closure would serve neither. And a pull callback would run on the request
//! path, where one slow producer stalls the health endpoint for everything
//! else. An in-process producer calls [`DomainMetrics::report`] directly; the
//! HTTP endpoint is that same call with a transport in front of it.
//!
//! **Every scope carries a TTL**, because the failure that matters is a
//! producer dying. A plinth whose audio process crashes must not keep
//! reporting its last `xruns` value forever — that reads as healthy. Past its
//! TTL a scope's *values* are dropped from the payload while
//! `yah.metrics.<source>.stale` stays `true`, so "the producer went quiet" is
//! distinguishable from "the producer never existed" (no keys at all) and from
//! "the producer reported zero" (a value of `0`). It is the same three-state
//! discipline the collector fields apply to an unmeasurable node.
//!
//! @yah:relay(R646, "yubaba per-node telemetry RPC — CPU/mem/disk plus consumer-registered domain metrics (unblocks R573-F7; second consumer is noisetable's gallery rig)")
//! @yah:status(review)
//! @yah:at(2026-08-02T02:15:00Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:next("R573-F7 is blocked on exactly this, with the recorded assumption 'yubaba does not yet expose per-node usage telemetry — this is blocked until that RPC lands'. This relay is that RPC.")
//! @yah:next("TWO consumers, so build the primitive generic rather than hardcoding a metric set: yah-cloud wants CPU/mem/disk for the InfraView machine cards; noisetable's gallery installations want per-plinth health PLUS domain metrics (audio xruns, callback deadline misses, BLE advert rate).")
//! @yah:next("Let the consumer REGISTER domain metrics instead of hardcoding a struct — otherwise every downstream grows a private telemetry path that duplicates the fleet one.")
//! @yah:next("Cross-camp context: filed from the noisetable camp, where an art installation is literally a small yubaba cluster. See that repo's .yah/docs/working/W138-installation-as-a-cluster.md §Telemetry.")
//! @arch:see(.yah/docs/working/W243-byo-static-node-infra.md)
//! @yah:handoff("The relay's own @yah:assumes was FALSE and is now removed: a telemetry surface DID already exist. GET /node (measured specs) and GET /node/usage (CPU/mem/disk/load + committed workload requests) were already built, wired into ServerState.node_probe, and consumed end-to-end by cloud_client::CloudClient::{node,node_usage} and yah_fleet_metrics::YubabaProbe. What was genuinely missing was the OTHER half the ticket named — consumer-registered domain metrics — and that is what this pass built.")
//! @yah:handoff("node.rs: DomainMetrics, a source -> {flat dotted key: scalar} registry that anything can publish into, merged FLAT into NodeUsage via #[serde(flatten)]. noisetable.audio.xruns is a sibling of system.cpu.utilization on the wire, so an OTLP exporter stays the same rename-free loop the module docs promise. Producer type is MetricValue (scalar-only untagged enum); the NodeUsage capture is serde_json::Value so an older client still parses a newer node.")
//! @yah:handoff("Push, not register-a-callback — recorded in the module docs with the reasoning. Both real producers are out of process (noisetable's W138 has an egress peer translating impulse-carried telemetry into this RPC; a workload publishing its own health is a separate container), so an in-process closure would serve neither, and a pull callback would run on the request path where one slow producer stalls the health endpoint. An in-process producer calls DomainMetrics::report directly — same primitive, no transport.")
//! @yah:handoff("Every scope carries a TTL because the failure that matters is a producer DYING: a crashed plinth must not keep reporting its last xruns forever. Past TTL the values are withheld while yah.metrics.<source>.stale stays true, so 'went quiet' is distinguishable from 'never existed' (no keys) and from 'reported zero' (a 0 value). Long-dead scopes are evicted after 20x TTL so a churning producer cannot leak.")
//! @yah:handoff("HTTP: POST /node/metrics (publish; 204, or 400 naming the offending source/key), GET /node/metrics (the same keys without paying for a CPU sampling window — the confirm-my-push path), DELETE /node/metrics/{source} (clean shutdown; 204/404). Reserved prefixes system./host./os./yah. are refused WHOLE rather than per-key, since dropping one key of a batch leaves the producer believing it published.")
//! @yah:handoff("cloud-client: NodeUsage gained the flattened domain map plus domain_metric/metric_sources/metric_source_is_stale/metric_source_age_ms, and CloudClient gained report_node_metrics/node_metrics/withdraw_node_metrics with mirrored MetricReport/MetricValue types. yah-fleet-metrics re-exports cloud_client::NodeUsage, so the fleet snapshot carries domain metrics with no change there.")
//! @yah:handoff("NODE_SCHEMA_VERSION deliberately NOT bumped — every change is additive, which is exactly the case the version comment says does not bump.")
//! @yah:verify("cd oss/yubaba && cargo test -p yubaba --lib  # 294 passed, 0 failed")
//! @yah:verify("cargo test -p cloud-client --lib  # 28 passed, 1 failed — the failure is deploy_headscale_round_trips_via_yubaba, PRE-EXISTING and filed as R646-B1")
//! @yah:verify("cargo test -p yah-fleet-metrics -p yah-cloud-admin  # 61 passed, 0 failed")
//! @yah:verify("The end-to-end assertion is cloud-client's domain_metrics_round_trip_from_yubaba: it spawns a REAL yubaba, publishes through the typed client, and reads the values back off /node/usage — so a rename drift between the two hand-written mirrors fails the build instead of silently publishing into nothing.")
//! @yah:gotcha("oss/yubaba/crates/yubaba/src/lib.rs was co-edited: @Ashguard:hydra is live on R609 and has uncommitted R609-F1 control-plane work in the same file (new pub mod control_plane, a ServerState.control_plane field, and an untracked src/control_plane.rs). No semantic overlap with R646 — my edits are the routing import, three /node/metrics routes, three handlers and two tests — and R646 needed no ServerState field at all because DomainMetrics hangs off NodeProbe. Nothing was reverted or reshaped on their side.")
//! @yah:gotcha("Unrelated pre-existing breakage seen while checking dependents: cargo check -p yah fails at app/yah/cli/src/camp.rs:8535 with 'cannot find PARTY_POST in module rpc::method' — a peer's half-landed party-post RPC (both camp.rs and crates/yah/rpc/src/lib.rs are dirty). Left alone per shared-tree discipline; it does not block R646, and every crate this relay touches (yubaba, cloud-client, yah-fleet-metrics, yah-cloud-admin, yah-hub, yah-agent-tools) builds and tests green.")
//! @yah:next("R573-F7 is unblocked and its now-false assumes was removed; two @yah:next entries were added there naming the exact client call and the two traps (system.cpu.utilization is a 0..1 fraction not a percentage; check yah.cpu.source, which is the loadavg APPROXIMATION on the fleet's darwin node).")
//! @yah:next("Second consumer (cross-camp, noisetable): the egress peer publishes with POST /node/metrics on its own cadence, ttl_ms set to a small multiple of that cadence, one source per plinth. Keys are producer-owned in full — use a noisetable. prefix; system./host./os./yah. are refused. A report REPLACES that source's previous set, so a metric it stops sending disappears rather than pinning its last value, and an empty metrics map is a legal heartbeat.")
//!
//! @yah:ticket(R885-B7, "/node/usage reports workloads.count 0 after every restart: workload_resources is in-memory and nothing rehydrates it at boot")
//! @yah:at(2026-09-10T22:33:21Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R885)
//! @yah:severity(high)
//! @yah:gotcha("THIS IS NOT STALENESS, IT IS STRUCTURAL ZERO — and that distinction is the whole ticket. Measured 2026-09-10 on us-west-003 by @Ashguard:eclipse. yubaba serves GET /node/usage at oss/yubaba/crates/yubaba/src/lib.rs:2581, which calls node::committed_totals(&s.workload_resources) (node.rs:512). `workload_resources` is an in-memory Mutex<BTreeMap> (node.rs:509), constructed Default::default() at lib.rs:1390, inserted on deploy success (lib.rs:4512) and removed on destroy (lib.rs:4680). NOTHING REHYDRATES IT AT STARTUP. So after any yubaba/kamaji restart it reports `yah.workloads.count` = 0 permanently, no matter what the node is actually holding — it does not drift toward wrong, it starts wrong and stays wrong. A scheduler trusting /node/usage will therefore overcommit a rebooted node indefinitely. CONTRAST THE SIBLING ENDPOINT, which is correct: GET /workloads (lib.rs:3073) goes through the kamaji UDS `client.list()` to containerd, which SURVIVES a restart. The two endpoints disagreeing is the visible symptom; the durability asymmetry is the cause. OBSERVED CONCRETELY: on us-west-003 after its restart, /workloads listed 16 Pending forge-* entries while /node/usage read workloads.count 0 — and when those 16 containerd records were removed, /workloads went to [] while /node/usage read 0 both before AND after, i.e. it was never tracking them at all.")
//! @yah:next("THE FIX IS CHEAP AND THE CALL ALREADY EXISTS — rehydrate `workload_resources` at boot from kamaji's `client.list()`, which is the SAME call GET /workloads already makes at lib.rs:3073. That makes containerd the single source of truth for what a node holds and removes the durability asymmetry rather than papering over it. Do NOT solve this by making /workloads read the in-memory map too: that would make both endpoints wrong after a restart instead of one.")
//! @yah:gotcha("RELATED BUT DELIBERATELY SEPARATE — do not fold these together. (1) kamaji HAS NO STARTUP RECONCILIATION AT ALL: its boot is build_ctx + resume_bundle_workloads() only (crates/kamaji-bin/src/main.rs:510-516), which replays persisted BUNDLE deploy records and never looks at containerd's namespace. The labels that would support reconciliation already exist and document the intent — crates/kamaji-bin/src/containerd.rs:1115-1118 literally says 'how reconciliation recovers the workload id after a Kamaji restart' — but nothing consumes them at boot. Confirmed by tree-wide grep for reconcile/sweep/orphan/gc/prune. This ticket's rehydration is the yubaba-side half; a kamaji-side reconcile is a larger, separable piece. (2) R823-B4 owns the LEAK that made this visible: teardown_workload sends the MeshIdent `forge.<uuid>` where the container is named `forge-<uuid>`, so every reap silently no-ops while reporting success. That is a different bug with a different fix and it is already diagnosed and code-complete but unrolled. Fixing B7 does not fix the leak, and rolling the leak fix does not fix B7. (3) The rest of R885 is per-workload cgroup limits at ADMISSION — complementary; nothing there reclaims a record or corrects an accounting surface.")
//! @yah:verify("Restart yubaba on a node holding at least one live workload and assert GET /node/usage `yah.workloads.count` matches GET /workloads immediately after boot, without a deploy having happened in between. That last clause is the real test: the count is currently repopulated ONLY by a subsequent deploy (lib.rs:4512), so any verification that deploys first will pass against the unfixed code. us-west-003 is a usable target — it is reachable on LAN (yah@192.168.10.32) and mesh (100.64.0.9), running yubaba/kamaji 0.8.28, single-node, epoch 4.")
//! @yah:gotcha("Tier: Cleric — a single well-understood seam with the required call already in the codebase; it needs care about restart ordering and source-of-truth choice, not novel design.")
//!
//! @yah:ticket(R885-B8, "/node/usage system.filesystem.* measures the wrong filesystem: it reports / while containerd fills /var")
//! @yah:at(2026-09-10T22:34:26Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R885)
//! @yah:severity(high)
//! @yah:gotcha("CAUGHT BY A CONTROLLED EXPERIMENT, not by reading the code — measured 2026-09-10 on us-west-003 by @Ashguard:eclipse. 16 inert containerd records were removed and 10G of disk was genuinely reclaimed (/var went from 23G avail to 33G avail, stable across two minutes of 20-second polls). Across that reclaim, GET /node/usage's `system.filesystem.*` reported 54505013248 / 422566010880 BYTE-IDENTICAL BEFORE AND AFTER. The reason: 422566010880 = 393.6 GiB = `/`, which on that box is 394G with 343G free. containerd writes to `/var`, which is a SEPARATE LV of only 60G. So the endpoint reports the roomy filesystem and is structurally blind to the one that actually fills. THE CONSEQUENCE IS THE OPPOSITE OF A COSMETIC BUG: this is the surface a scheduler or an operator would consult to decide whether a node has room for a build, and on this node it would have answered '343G free, plenty' at the exact moment /var had 23G left and a pending ~1h49m rusty-v8-musl build needed headroom there. A disk-pressure incident on this hardware is therefore invisible to the metric designed to catch it.")
//! @yah:next("Report the filesystem containerd ACTUALLY writes to, resolved at runtime rather than assumed — stat the containerd root (/var/lib/containerd on us-west-003) and report the filesystem backing it, so a node that puts containerd on / and a node that gives it its own LV both report truthfully. Do NOT hardcode /var: that is the same class of mistake as hardcoding /, just with a different constant, and it breaks the moment a node is laid out differently. Consider reporting BOTH filesystems when they differ, since the root FS is still worth knowing — but the one the scheduler keys on must be the one workloads consume.")
//! @yah:gotcha("WHY THIS NODE IS LAID OUT THIS WAY, so the fix is not built against a wrong mental model: a 2026-08-29 layout change on us-west-003 removed the docker LV and gave `/` 394 GB with no containment — that machine file's own 'WHAT THIS COSTS' note flags the absence of containment as a known cost. `/var` remained a separate 60G LV, and that is where containerd's snapshotter lives (measured: /var/lib/containerd 30G total, snapshotter 29G, before the cleanup). So the two filesystems genuinely differ in SIZE BY A FACTOR OF SIX on this hardware, which is what makes the misreport so consequential here — on a node where containerd sits on / the bug would be invisible. Do not assume other nodes share this layout; that is exactly why the fix must resolve the path at runtime. RELATED, SAME INCIDENT, SEPARATE TICKETS: R885-B7 covers /node/usage's workloads.count reading a never-rehydrated in-memory map, and R823-B4 owns the reap-key mismatch that leaked the records in the first place. All three surfaced together on 2026-09-10; none of them fixes another.")
//! @yah:verify("Reproduce the original catch rather than only asserting the new number looks right: consume a measurable amount of space under the containerd root, then confirm GET /node/usage's system.filesystem.* MOVES by roughly that amount. The unfixed code passes any check that merely reads the endpoint once and sees a plausible figure — it was reporting a perfectly plausible 54505013248 / 422566010880 throughout. A delta test is what distinguishes the fix; a snapshot test does not.")
//! @yah:gotcha("Tier: Cleric — small, contained change to one metric path, but it needs runtime path resolution and a delta-based test rather than a snapshot assertion, which is where a careless fix would go wrong.")

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Payload schema version, bumped on any breaking field change.
///
/// Additive fields do NOT bump this — every field is `Option` or
/// `#[serde(default)]` on the client side precisely so a newer node can be
/// read by an older client.
pub const NODE_SCHEMA_VERSION: u32 = 1;

/// Default sampling window when the caller has no previous poll to diff
/// against and did not ask for a specific one.
const DEFAULT_WINDOW_MS: u64 = 200;

/// Bounds on a caller-requested `?window_ms=`. The floor keeps a CPU delta
/// statistically meaningful (a sub-50ms window over jiffy-granularity
/// counters is noise); the ceiling keeps a poll from pinning an HTTP worker.
const MIN_WINDOW_MS: u64 = 50;
const MAX_WINDOW_MS: u64 = 5_000;

/// How long a domain-metric scope's values stay trustworthy when the producer
/// didn't say. 30s is a compromise: long enough that a producer publishing on a
/// 10s cadence survives one missed beat, short enough that a dead producer
/// stops looking healthy inside a dashboard refresh.
const DEFAULT_METRIC_TTL_MS: u64 = 30_000;

/// Bounds on a producer-declared TTL. The floor stops a producer from making
/// its own metrics permanently stale by asking for a window shorter than its
/// publish jitter; the ceiling stops "never expire" being requested by
/// spelling it `u64::MAX`.
const MIN_METRIC_TTL_MS: u64 = 1_000;
const MAX_METRIC_TTL_MS: u64 = 3_600_000;

/// A scope is *forgotten* — not merely stale — once it has been silent for this
/// many times its TTL. Staleness is a reportable state and must persist long
/// enough for an operator to see it; unbounded retention of dead scopes is a
/// leak. At the default TTL this is 10 minutes of visible "gone quiet" before
/// the source disappears entirely.
const METRIC_EVICT_TTL_MULTIPLE: u64 = 20;

/// Caps on what one node will hold, so a looping producer costs bounded memory
/// rather than the process.
const MAX_METRIC_SOURCES: usize = 64;
const MAX_METRICS_PER_SOURCE: usize = 128;
const MAX_METRIC_SOURCE_LEN: usize = 64;
const MAX_METRIC_KEY_LEN: usize = 128;

/// Key prefixes owned by the built-in payload.
///
/// Domain metrics merge *flat* into [`NodeUsage`], so a producer publishing
/// `system.cpu.utilization` would shadow the real reading with a duplicate JSON
/// key. Rejecting the report — loudly, naming the key — is the only honest
/// outcome; silently dropping one key of a batch leaves the producer believing
/// it published.
const RESERVED_METRIC_PREFIXES: [&str; 4] = ["system.", "host.", "os.", "yah."];

/// Which measurement backend answered.
///
/// Reported to the client as `yah.collector` so a null reading can be
/// attributed — "this platform has no collector" reads very differently from
/// "the collector ran and found nothing".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Collector {
    /// Linux `/proc` — no subprocesses, exact counters.
    Procfs,
    /// macOS `sysctl` + `vm_stat` + `df`, via subprocess.
    Sysctl,
    /// Neither is available on this target.
    Unsupported,
}

impl Collector {
    pub fn as_str(self) -> &'static str {
        match self {
            Collector::Procfs => "procfs",
            Collector::Sysctl => "sysctl",
            Collector::Unsupported => "unsupported",
        }
    }

    /// The collector for the compiled target.
    pub fn detect() -> Self {
        if cfg!(target_os = "linux") {
            Collector::Procfs
        } else if cfg!(target_os = "macos") {
            Collector::Sysctl
        } else {
            Collector::Unsupported
        }
    }
}

/// `GET /node` — what the hardware *is*.
///
/// Static for the process lifetime and cached after first collection
/// ([`NodeProbe::specs`]); nothing here changes without a reboot or a VM
/// resize, and both imply a yubaba restart.
///
/// Field names follow OTel semantic conventions where one exists — see the
/// module docs for why the keys are flat and dotted.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct NodeSpecs {
    pub schema_version: u32,

    #[serde(rename = "host.name", skip_serializing_if = "Option::is_none", default)]
    pub host_name: Option<String>,

    /// OTel-vocabulary architecture: `amd64` / `arm64` / `x86` / `arm32`.
    ///
    /// Deliberately NOT the same string as [`Self::arch`]. The semantic
    /// conventions enumerate their own values, and `.yah/infra/machines/*.toml`
    /// uses the Rust/uname vocabulary (`x86_64`, `aarch64`). Emitting both
    /// costs one short string and removes the need for every consumer to
    /// re-derive the mapping — the drift check in `fleet-metrics` compares
    /// against `yah.arch`, an OTLP exporter would forward `host.arch`.
    #[serde(rename = "host.arch")]
    pub host_arch: String,

    /// Repo-vocabulary architecture (`x86_64` / `aarch64`), directly
    /// comparable to `MachineRecord::arch`.
    #[serde(rename = "yah.arch")]
    pub arch: String,

    #[serde(
        rename = "host.cpu.model.name",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub cpu_model: Option<String>,

    /// `linux` | `darwin` | `windows` | … (OTel `os.type` vocabulary).
    #[serde(rename = "os.type")]
    pub os_type: String,

    #[serde(
        rename = "os.version",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub os_version: Option<String>,

    #[serde(
        rename = "system.cpu.logical.count",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub cpu_logical_count: Option<u32>,

    /// Total physical RAM in **bytes** (semconv units are bytes, not MiB).
    #[serde(
        rename = "system.memory.limit",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub memory_limit_bytes: Option<u64>,

    /// Total size of the root filesystem in bytes.
    #[serde(
        rename = "system.filesystem.limit",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub filesystem_limit_bytes: Option<u64>,

    /// What this node's `[allocatable] memory_mb` *would* be if derived from
    /// measurement — total RAM in MiB.
    ///
    /// This is the measured counterpart to the hand-written TOML value, and
    /// the reason the endpoint exists. It is NOT automatically authoritative:
    /// a node whose workloads run inside a VM (Colima on `us-west-015`) has a
    /// schedulable ceiling *below* physical RAM, so a declaration that is
    /// lower than this is legitimate. Higher than this is not — that is
    /// over-promising, and it is the drift a consumer should flag.
    #[serde(
        rename = "yah.allocatable.memory_mb",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub allocatable_memory_mb: Option<u32>,

    /// Measured counterpart to `[allocatable] cpu_millis` —
    /// `logical_cpus * 1000`, in k8s millicores. Same
    /// "lower-is-legitimate, higher-is-drift" reading as
    /// [`Self::allocatable_memory_mb`].
    #[serde(
        rename = "yah.allocatable.cpu_millis",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub allocatable_cpu_millis: Option<u32>,

    #[serde(rename = "yah.collector")]
    pub collector: String,

    #[serde(rename = "yah.collected_at_unix_ms")]
    pub collected_at_unix_ms: u64,
}

/// `GET /node/usage` — what the node is *doing*.
///
/// Every measurement is `Option`: a node that can report memory but not CPU
/// returns the memory and a null CPU, rather than a 500. Partial data beats
/// no data for a health dashboard.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct NodeUsage {
    pub schema_version: u32,

    /// Fraction in `0.0..=1.0` across all logical CPUs — semconv units, NOT
    /// a percentage. See [`Self::cpu_source`] for how it was derived; the two
    /// derivations are not equally trustworthy.
    #[serde(
        rename = "system.cpu.utilization",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub cpu_utilization: Option<f64>,

    /// How [`Self::cpu_utilization`] was computed:
    ///
    /// - `procstat` — a true delta of `/proc/stat` jiffy counters between two
    ///   samples. Accurate.
    /// - `loadavg` — `load1 / logical_cpus`, clamped to 1.0. An
    ///   **approximation**: load average counts runnable *and* uninterruptible
    ///   tasks, so a box blocked on I/O reads as busy, and the 1-minute
    ///   smoothing lags a real spike. Used on macOS, where true CPU tick
    ///   counters need `host_processor_info` from the mach API.
    /// - `unavailable` — no CPU reading.
    ///
    /// If the darwin number ever needs to be exact, the upgrade is a `libc`
    /// dep plus an `unsafe` `host_processor_info` call against
    /// `PROCESSOR_CPU_LOAD_INFO`, diffed the same way procstat is. That was
    /// deliberately not taken here: it trades a documented approximation for
    /// unsafe FFI, and the consumer of this number is a dashboard gauge and a
    /// bin-packer floor, neither of which is sensitive at that resolution.
    #[serde(rename = "yah.cpu.source")]
    pub cpu_source: String,

    #[serde(
        rename = "system.memory.usage",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub memory_usage_bytes: Option<u64>,

    #[serde(
        rename = "system.memory.limit",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub memory_limit_bytes: Option<u64>,

    #[serde(
        rename = "system.memory.utilization",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub memory_utilization: Option<f64>,

    #[serde(
        rename = "system.filesystem.usage",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub filesystem_usage_bytes: Option<u64>,

    #[serde(
        rename = "system.filesystem.limit",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub filesystem_limit_bytes: Option<u64>,

    #[serde(
        rename = "system.filesystem.utilization",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub filesystem_utilization: Option<f64>,

    #[serde(
        rename = "yah.load.1m",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub load_1m: Option<f64>,
    #[serde(
        rename = "yah.load.5m",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub load_5m: Option<f64>,
    #[serde(
        rename = "yah.load.15m",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub load_15m: Option<f64>,

    /// Number of workloads this node currently has resource requests recorded
    /// for — i.e. the size of the committed set, not the runtime's list.
    #[serde(rename = "yah.workloads.count", default)]
    pub workloads_count: u32,

    /// Sum of `resources.memory_mb` across workloads deployed through this
    /// yubaba.
    ///
    /// This is the missing half of `available = allocatable − committed`. The
    /// scheduler's capacity floor has always compared a request against the
    /// static `allocatable` without subtracting what is already running,
    /// because nothing reported this number. Now something does.
    ///
    /// Caveat a consumer must respect: this counts what *this yubaba*
    /// admitted. Workloads started out-of-band (a container launched directly
    /// against the node's docker/containerd socket) are invisible here, and it
    /// resets to zero across a yubaba restart until each workload is
    /// re-admitted. Treat it as a lower bound on commitment, and cross-check
    /// against `system.memory.usage` — which *is* whole-machine truth — when
    /// the two disagree.
    #[serde(rename = "yah.committed.memory_mb", default)]
    pub committed_memory_mb: u32,

    /// Sum of `resources.cpu_millis` across admitted workloads. Same
    /// lower-bound caveat as [`Self::committed_memory_mb`].
    #[serde(rename = "yah.committed.cpu_millis", default)]
    pub committed_cpu_millis: u32,

    /// Milliseconds spanned by the CPU delta. Absent when CPU is unavailable
    /// or derived from load average (which has no window of our choosing).
    #[serde(
        rename = "yah.sample.window_ms",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub sample_window_ms: Option<u64>,

    #[serde(rename = "yah.collector")]
    pub collector: String,

    #[serde(rename = "yah.collected_at_unix_ms")]
    pub collected_at_unix_ms: u64,

    /// Consumer-registered domain metrics, merged **flat** into this payload —
    /// `noisetable.audio.xruns` is a sibling of `system.cpu.utilization`, not a
    /// nested object, so an exporter needs no special case for it. See
    /// [`DomainMetrics::snapshot`] for the `yah.metrics.*` staleness keys that
    /// come with them.
    ///
    /// Typed as `serde_json::Value` rather than [`MetricValue`] on purpose:
    /// this is also the *capture* for any key a newer node emits that this
    /// build doesn't know about, and rejecting an unknown field would break the
    /// newer-node/older-client compatibility every other field here preserves
    /// by being `Option`. Producers push the scalar-only [`MetricValue`]; the
    /// wire is deliberately more permissive than the ingest.
    #[serde(flatten)]
    pub domain: BTreeMap<String, serde_json::Value>,
}

/// Per-workload resource request, as admitted by this node.
///
/// Mirrors `workload_spec::ResourceLimits`, kept as its own type because it
/// crosses the HTTP boundary and must stay additive independently of the
/// spec type.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkloadResources {
    pub memory_mb: u32,
    pub cpu_millis: u32,
}

/// Registry of `ident -> requested resources` for workloads this yubaba
/// admitted.
///
/// Deliberately the same shape and lifecycle as `ServerState`'s
/// `archetype_registry`: written by the deploy handler on success, removed by
/// destroy. In-memory only — see [`NodeUsage::committed_memory_mb`] for what
/// that costs a consumer.
pub type ResourceRegistry = Mutex<BTreeMap<String, WorkloadResources>>;

/// Sum of all recorded requests, and how many workloads contributed.
pub fn committed_totals(registry: &ResourceRegistry) -> (u32, u32, u32) {
    let guard = match registry.lock() {
        Ok(g) => g,
        // A poisoned registry means a panic mid-deploy. Report zero committed
        // rather than propagating the panic into a health endpoint — usage is
        // exactly what an operator reaches for while diagnosing that panic.
        Err(poisoned) => poisoned.into_inner(),
    };
    let mem = guard.values().map(|r| r.memory_mb).sum();
    let cpu = guard.values().map(|r| r.cpu_millis).sum();
    (guard.len() as u32, mem, cpu)
}

/// Merge recorded resource requests into an already-serialized `workloads`
/// array, in place.
///
/// # Why this operates on JSON instead of a typed row
///
/// `GET /workloads` produces one of *two* different row shapes depending on
/// which backend answered — kamaji's `WorkloadEntry {id, state, pid}` or the
/// legacy runtime's richer `WorkloadState {ident, container_id, status,
/// mesh_ip}` — and the `x-workload-source` response header is a documented
/// back-compat contract that lets callers branch on which they got. Unifying
/// the two types to attach two integers would break that contract for a
/// cosmetic gain. Enriching the serialized value keeps the change purely
/// additive to both shapes.
///
/// Rows are matched on `ident`, falling back to `id` (kamaji's key; the
/// container id is the workload id, which is the mesh ident). A row with no
/// recorded entry is left untouched, so `memory_mb` / `cpu_millis` are absent
/// rather than zero — a workload deployed before this yubaba restarted has an
/// *unknown* request, not a zero one, and a bin-packer must not read those
/// the same way.
pub fn enrich_workloads(registry: &ResourceRegistry, workloads: &mut serde_json::Value) {
    let guard = match registry.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if guard.is_empty() {
        return;
    }
    let Some(rows) = workloads.as_array_mut() else {
        return;
    };
    for row in rows {
        let Some(obj) = row.as_object_mut() else {
            continue;
        };
        let key = obj
            .get("ident")
            .or_else(|| obj.get("id"))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let Some(res) = key.and_then(|k| guard.get(&k).copied()) else {
            continue;
        };
        obj.insert("memory_mb".into(), res.memory_mb.into());
        obj.insert("cpu_millis".into(), res.cpu_millis.into());
    }
}

// ---------------------------------------------------------------------------
// Domain metrics
// ---------------------------------------------------------------------------

/// One domain-metric value.
///
/// Scalars only, and untagged so the JSON is a bare `3`, `0.41`, `true` or
/// `"degraded"` — i.e. exactly a valid OTLP attribute value, matching what the
/// built-in fields emit. Objects and arrays are rejected at ingest: a nested
/// value has no flat-dotted spelling, and letting one through would make the
/// "every key is already an OTLP attribute key" property false for the whole
/// payload rather than just that key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum MetricValue {
    Bool(bool),
    U64(u64),
    I64(i64),
    F64(f64),
    Text(String),
}

impl From<bool> for MetricValue {
    fn from(v: bool) -> Self {
        MetricValue::Bool(v)
    }
}
impl From<u64> for MetricValue {
    fn from(v: u64) -> Self {
        MetricValue::U64(v)
    }
}
impl From<u32> for MetricValue {
    fn from(v: u32) -> Self {
        MetricValue::U64(v.into())
    }
}
impl From<i64> for MetricValue {
    fn from(v: i64) -> Self {
        MetricValue::I64(v)
    }
}
impl From<f64> for MetricValue {
    fn from(v: f64) -> Self {
        MetricValue::F64(v)
    }
}
impl From<String> for MetricValue {
    fn from(v: String) -> Self {
        MetricValue::Text(v)
    }
}
impl From<&str> for MetricValue {
    fn from(v: &str) -> Self {
        MetricValue::Text(v.to_string())
    }
}

impl From<MetricValue> for serde_json::Value {
    fn from(v: MetricValue) -> Self {
        match v {
            MetricValue::Bool(b) => b.into(),
            MetricValue::U64(n) => n.into(),
            MetricValue::I64(n) => n.into(),
            // A non-finite float has no JSON spelling; serde_json renders it
            // null. Do that explicitly rather than at the serializer's
            // discretion — a NaN xrun rate is a producer bug and null is how
            // the rest of this payload spells "no reading".
            MetricValue::F64(f) => serde_json::Number::from_f64(f)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
            MetricValue::Text(s) => s.into(),
        }
    }
}

/// A producer's publish: everything it wants this node to report on its behalf,
/// as a full replacement of that source's previous set.
///
/// Replace rather than merge, because merge cannot express deletion — a
/// producer that stops emitting a metric would leave the last value pinned
/// until the whole scope expired.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MetricReport {
    /// Who is publishing, e.g. `plinth-3-audio`. Namespaces the staleness keys
    /// and scopes the replacement; does NOT prefix the metric keys, which the
    /// producer owns in full.
    pub source: String,

    /// `key -> value`. Keys are the flat dotted names as they will appear in
    /// the payload (`noisetable.audio.xruns`); see [`RESERVED_METRIC_PREFIXES`]
    /// for the ones a producer may not use.
    ///
    /// An empty map is legal and means "alive, nothing to report" — a
    /// heartbeat that keeps the source non-stale.
    #[serde(default)]
    pub metrics: BTreeMap<String, MetricValue>,

    /// How long these values stay trustworthy, clamped to
    /// `[MIN_METRIC_TTL_MS, MAX_METRIC_TTL_MS]`. Defaults to
    /// [`DEFAULT_METRIC_TTL_MS`]; set it to a small multiple of your publish
    /// interval.
    #[serde(default)]
    pub ttl_ms: Option<u64>,
}

/// Why a [`MetricReport`] was refused.
///
/// Every variant names the offending value, because the producer is remote and
/// a 400 body is the only debugging channel it has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricRejection {
    /// `source` was empty, over-long, or contained something outside
    /// `[A-Za-z0-9._-]`.
    BadSource { source: String, why: &'static str },
    /// A metric key was empty, over-long, or contained whitespace/control
    /// characters.
    BadKey { key: String, why: &'static str },
    /// A metric key collided with a built-in namespace.
    ReservedKey { key: String, prefix: &'static str },
    /// This one report carried more than [`MAX_METRICS_PER_SOURCE`] keys.
    TooManyMetrics { count: usize, limit: usize },
    /// A *new* source arrived with [`MAX_METRIC_SOURCES`] already live.
    /// Existing sources can still update; only registration is refused.
    TooManySources { limit: usize },
}

impl std::fmt::Display for MetricRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetricRejection::BadSource { source, why } => {
                write!(f, "invalid metric source {source:?}: {why}")
            }
            MetricRejection::BadKey { key, why } => {
                write!(f, "invalid metric key {key:?}: {why}")
            }
            MetricRejection::ReservedKey { key, prefix } => write!(
                f,
                "metric key {key:?} uses the reserved prefix {prefix:?} — that namespace \
                 belongs to the built-in node payload and a duplicate key would shadow it"
            ),
            MetricRejection::TooManyMetrics { count, limit } => {
                write!(f, "report carries {count} metrics, limit is {limit}")
            }
            MetricRejection::TooManySources { limit } => write!(
                f,
                "node already holds {limit} metric sources; existing sources may still \
                 update, but no new source can register until one is withdrawn or evicted"
            ),
        }
    }
}

impl std::error::Error for MetricRejection {}

/// One source's most recent publish, plus when it landed.
#[derive(Debug, Clone, PartialEq)]
struct MetricScope {
    metrics: BTreeMap<String, MetricValue>,
    reported_at_unix_ms: u64,
    ttl_ms: u64,
}

impl MetricScope {
    fn age_ms(&self, now: u64) -> u64 {
        now.saturating_sub(self.reported_at_unix_ms)
    }
    fn is_stale(&self, now: u64) -> bool {
        self.age_ms(now) > self.ttl_ms
    }
    fn is_evictable(&self, now: u64) -> bool {
        self.age_ms(now) > self.ttl_ms.saturating_mul(METRIC_EVICT_TTL_MULTIPLE)
    }
}

/// The consumer-registered half of the telemetry surface — see the module docs
/// for why the metric set is open and why publishing is a push.
///
/// In-memory and per-process, exactly like [`ResourceRegistry`]: a yubaba
/// restart empties it and every producer re-publishes on its next tick. That is
/// the right lifetime for a liveness signal — persisting the last-known xrun
/// count across a restart would republish a measurement nobody is standing
/// behind any more.
#[derive(Debug, Default)]
pub struct DomainMetrics {
    sources: Mutex<BTreeMap<String, MetricScope>>,
}

impl DomainMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept a producer's publish, replacing that source's previous set.
    pub fn report(&self, report: MetricReport) -> Result<(), MetricRejection> {
        validate_source(&report.source)?;
        if report.metrics.len() > MAX_METRICS_PER_SOURCE {
            return Err(MetricRejection::TooManyMetrics {
                count: report.metrics.len(),
                limit: MAX_METRICS_PER_SOURCE,
            });
        }
        for key in report.metrics.keys() {
            validate_key(key)?;
        }

        let ttl_ms = report
            .ttl_ms
            .unwrap_or(DEFAULT_METRIC_TTL_MS)
            .clamp(MIN_METRIC_TTL_MS, MAX_METRIC_TTL_MS);
        let now = now_ms();

        let mut guard = self.lock();
        // Evict first, so a source that churned out frees the slot for the one
        // arriving now rather than the cap being held by the dead.
        guard.retain(|_, scope| !scope.is_evictable(now));
        if !guard.contains_key(&report.source) && guard.len() >= MAX_METRIC_SOURCES {
            return Err(MetricRejection::TooManySources {
                limit: MAX_METRIC_SOURCES,
            });
        }
        guard.insert(
            report.source,
            MetricScope {
                metrics: report.metrics,
                reported_at_unix_ms: now,
                ttl_ms,
            },
        );
        Ok(())
    }

    /// Drop a source immediately. Returns whether it was there.
    ///
    /// The clean-shutdown counterpart to TTL expiry: a producer that knows it
    /// is going away says so, instead of leaving a scope to look merely slow
    /// for a TTL and then stale for twenty more.
    pub fn withdraw(&self, source: &str) -> bool {
        self.lock().remove(source).is_some()
    }

    /// The flat payload contribution — metric keys plus per-source staleness.
    ///
    /// Emitted for every live source, stale or not:
    ///
    /// - `yah.metrics.<source>.age_ms` — ms since that source last published.
    /// - `yah.metrics.<source>.stale` — always present, so a consumer never has
    ///   to read absence as `false` (absence means the source is gone, which is
    ///   a different fact).
    ///
    /// Plus `yah.metrics.sources` (the live source names) and, when two sources
    /// publish the same key, `yah.metrics.collisions`. A collision is a
    /// producer-side namespacing bug; the payload keeps one value
    /// (alphabetically-last source wins, since sources are iterated in order)
    /// and names the key rather than letting the loss be silent.
    pub fn snapshot(&self) -> BTreeMap<String, serde_json::Value> {
        let now = now_ms();
        let mut guard = self.lock();
        guard.retain(|_, scope| !scope.is_evictable(now));

        let mut out: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        if guard.is_empty() {
            return out;
        }
        let mut collisions: Vec<String> = Vec::new();
        let mut names: Vec<serde_json::Value> = Vec::new();

        for (source, scope) in guard.iter() {
            names.push(source.as_str().into());
            let stale = scope.is_stale(now);
            out.insert(
                format!("yah.metrics.{source}.age_ms"),
                scope.age_ms(now).into(),
            );
            out.insert(format!("yah.metrics.{source}.stale"), stale.into());
            if stale {
                continue;
            }
            for (key, value) in &scope.metrics {
                if out.insert(key.clone(), value.clone().into()).is_some() {
                    collisions.push(key.clone());
                }
            }
        }

        out.insert("yah.metrics.sources".into(), names.into());
        if !collisions.is_empty() {
            // Three sources colliding on two keys pushes them interleaved, so
            // sort before dedup — `dedup` alone only collapses neighbours.
            collisions.sort_unstable();
            collisions.dedup();
            let collisions: Vec<serde_json::Value> =
                collisions.into_iter().map(Into::into).collect();
            out.insert("yah.metrics.collisions".into(), collisions.into());
        }
        out
    }

    /// A poisoned registry means a panic mid-report. Metrics are what an
    /// operator reaches for while diagnosing that panic, so recover the map
    /// rather than propagating into a health endpoint — same call as
    /// [`committed_totals`].
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, MetricScope>> {
        match self.sources.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

fn validate_source(source: &str) -> Result<(), MetricRejection> {
    let bad = |why: &'static str| {
        Err(MetricRejection::BadSource {
            source: source.to_string(),
            why,
        })
    };
    if source.is_empty() {
        return bad("must not be empty");
    }
    if source.len() > MAX_METRIC_SOURCE_LEN {
        return bad("longer than 64 bytes");
    }
    // The name is interpolated into `yah.metrics.<source>.age_ms`, so anything
    // outside this set could produce a key a consumer cannot split back apart.
    if !source
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return bad("must be ASCII alphanumeric, '.', '_' or '-'");
    }
    Ok(())
}

fn validate_key(key: &str) -> Result<(), MetricRejection> {
    let bad = |why: &'static str| {
        Err(MetricRejection::BadKey {
            key: key.to_string(),
            why,
        })
    };
    if key.is_empty() {
        return bad("must not be empty");
    }
    if key.len() > MAX_METRIC_KEY_LEN {
        return bad("longer than 128 bytes");
    }
    if key.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return bad("must not contain whitespace or control characters");
    }
    for prefix in RESERVED_METRIC_PREFIXES {
        if key.starts_with(prefix) {
            return Err(MetricRejection::ReservedKey {
                key: key.to_string(),
                prefix,
            });
        }
    }
    Ok(())
}

/// A point-in-time read of the CPU tick counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CpuSample {
    /// Sum of all jiffy counters.
    total: u64,
    /// Idle + iowait jiffies.
    idle: u64,
    at_unix_ms: u64,
}

/// Owns the cached specs and the previous CPU sample.
///
/// # How "report at whatever interval the client wants" is implemented
///
/// The client sets the interval by *polling* at that interval; there is no
/// server-side subscription, no registered callback, and no push channel to
/// keep alive across a yubaba restart. Two modes fall out of that:
///
/// - **No `window_ms`** (the normal case): CPU utilization is the delta
///   between this poll and the caller's *previous* poll. A client polling
///   every 5s gets true mean utilization over its own 5s window; a client
///   polling every 500ms gets a 500ms window. The measurement interval
///   automatically equals the reporting interval, which is what a graph
///   wants. First poll after startup has nothing to diff, so it falls back to
///   an in-request [`DEFAULT_WINDOW_MS`] sample.
/// - **`?window_ms=N`**: take two samples `N` ms apart inside the request and
///   diff those. For a caller that wants an instantaneous reading independent
///   of its own cadence — or for the *second* of two clients, whose polls
///   would otherwise interleave and shrink each other's windows.
///
/// That interleaving is the one sharp edge and it is inherent to a shared
/// last-sample: `last_cpu` is per-node, not per-client. Two clients polling
/// without `window_ms` will each see a window shortened by the other's poll.
/// The reading stays *correct* (it is still a true delta over a real
/// interval, and `yah.sample.window_ms` reports which interval) — it is only
/// noisier. A client that cares should pass `window_ms`.
#[derive(Debug, Default)]
pub struct NodeProbe {
    specs: std::sync::OnceLock<NodeSpecs>,
    last_cpu: Mutex<Option<CpuSample>>,
    domain: DomainMetrics,
}

impl NodeProbe {
    pub fn new() -> Self {
        Self::default()
    }

    /// The consumer-registered metric registry this probe merges into every
    /// usage sample.
    ///
    /// Lives here rather than beside it on `ServerState` because it is the same
    /// kind of thing as the cached specs and the last CPU sample: per-node
    /// measurement state whose only consumer is [`Self::usage`]. Hanging it off
    /// the probe means a producer's push cannot be wired up without the read
    /// path picking it up.
    pub fn domain(&self) -> &DomainMetrics {
        &self.domain
    }

    /// Node specs, collected once and cached.
    pub fn specs(&self) -> &NodeSpecs {
        self.specs.get_or_init(collect_specs)
    }

    /// Collect a usage sample.
    ///
    /// `window_ms` is the caller's optional explicit sampling window, clamped
    /// to `[MIN_WINDOW_MS, MAX_WINDOW_MS]`. `committed` is
    /// `(count, memory_mb, cpu_millis)` from [`committed_totals`], passed in
    /// rather than read here so this module stays free of `ServerState`.
    pub async fn usage(&self, window_ms: Option<u64>, committed: (u32, u32, u32)) -> NodeUsage {
        let collector = Collector::detect();
        let (workloads_count, committed_memory_mb, committed_cpu_millis) = committed;

        let (cpu_utilization, cpu_source, sample_window_ms) = self.sample_cpu(window_ms).await;
        let mem = read_memory();
        let fs = read_filesystem();
        let load = read_loadavg();

        NodeUsage {
            schema_version: NODE_SCHEMA_VERSION,
            cpu_utilization,
            cpu_source: cpu_source.into(),
            memory_usage_bytes: mem.map(|(used, _)| used),
            memory_limit_bytes: mem.map(|(_, total)| total),
            memory_utilization: mem.and_then(|(used, total)| ratio(used, total)),
            filesystem_usage_bytes: fs.map(|(used, _)| used),
            filesystem_limit_bytes: fs.map(|(_, total)| total),
            filesystem_utilization: fs.and_then(|(used, total)| ratio(used, total)),
            load_1m: load.map(|l| l.0),
            load_5m: load.map(|l| l.1),
            load_15m: load.map(|l| l.2),
            workloads_count,
            committed_memory_mb,
            committed_cpu_millis,
            sample_window_ms,
            collector: collector.as_str().into(),
            collected_at_unix_ms: now_ms(),
            domain: self.domain.snapshot(),
        }
    }

    /// Returns `(utilization, source, window_ms)`.
    async fn sample_cpu(&self, window_ms: Option<u64>) -> (Option<f64>, &'static str, Option<u64>) {
        // Only procfs exposes true tick counters; everything else falls
        // through to the load-average approximation.
        if !matches!(Collector::detect(), Collector::Procfs) {
            return match (read_loadavg(), self.specs().cpu_logical_count) {
                (Some((one, _, _)), Some(cpus)) if cpus > 0 => (
                    Some((one / f64::from(cpus)).clamp(0.0, 1.0)),
                    "loadavg",
                    None,
                ),
                _ => (None, "unavailable", None),
            };
        }

        let Some(current) = read_cpu_sample() else {
            return (None, "unavailable", None);
        };

        // Explicit window: take a second sample inside the request. The
        // stored sample is refreshed too, so a caller mixing both modes
        // doesn't leave a stale anchor behind.
        if let Some(requested) = window_ms {
            let window = requested.clamp(MIN_WINDOW_MS, MAX_WINDOW_MS);
            tokio::time::sleep(std::time::Duration::from_millis(window)).await;
            let Some(second) = read_cpu_sample() else {
                return (None, "unavailable", None);
            };
            self.store_cpu(second);
            return (
                cpu_delta(&current, &second),
                "procstat",
                Some(second.at_unix_ms.saturating_sub(current.at_unix_ms)),
            );
        }

        // Implicit window: diff against the caller's previous poll.
        let previous = self.swap_cpu(current);
        match previous {
            Some(prev) if current.at_unix_ms > prev.at_unix_ms => (
                cpu_delta(&prev, &current),
                "procstat",
                Some(current.at_unix_ms - prev.at_unix_ms),
            ),
            // First poll since startup — nothing to diff against, so pay for
            // one short in-request window rather than returning null.
            _ => {
                tokio::time::sleep(std::time::Duration::from_millis(DEFAULT_WINDOW_MS)).await;
                let Some(second) = read_cpu_sample() else {
                    return (None, "unavailable", None);
                };
                self.store_cpu(second);
                (
                    cpu_delta(&current, &second),
                    "procstat",
                    Some(second.at_unix_ms.saturating_sub(current.at_unix_ms)),
                )
            }
        }
    }

    fn store_cpu(&self, sample: CpuSample) {
        let mut guard = match self.last_cpu.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *guard = Some(sample);
    }

    fn swap_cpu(&self, sample: CpuSample) -> Option<CpuSample> {
        let mut guard = match self.last_cpu.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard.replace(sample)
    }
}

/// `1 - Δidle/Δtotal`, or `None` when the counters didn't advance.
fn cpu_delta(prev: &CpuSample, next: &CpuSample) -> Option<f64> {
    let total = next.total.checked_sub(prev.total)?;
    let idle = next.idle.saturating_sub(prev.idle);
    if total == 0 {
        return None;
    }
    Some((1.0 - (idle as f64 / total as f64)).clamp(0.0, 1.0))
}

fn ratio(used: u64, total: u64) -> Option<f64> {
    if total == 0 {
        None
    } else {
        Some((used as f64 / total as f64).clamp(0.0, 1.0))
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Map `std::env::consts::ARCH` onto the OTel `host.arch` vocabulary.
///
/// Unknown architectures pass through unchanged — a wrong-but-truthful value
/// beats silently reporting `amd64` for something that isn't.
pub fn otel_arch(rust_arch: &str) -> &str {
    match rust_arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "x86",
        "arm" => "arm32",
        "powerpc64" => "ppc64",
        "s390x" => "s390x",
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

fn collect_specs() -> NodeSpecs {
    let collector = Collector::detect();
    let rust_arch = std::env::consts::ARCH;
    let cpu_logical_count = read_cpu_count();
    let memory_limit_bytes = read_memory().map(|(_, total)| total);
    let filesystem_limit_bytes = read_filesystem().map(|(_, total)| total);

    NodeSpecs {
        schema_version: NODE_SCHEMA_VERSION,
        host_name: read_hostname(),
        host_arch: otel_arch(rust_arch).into(),
        arch: rust_arch.into(),
        cpu_model: read_cpu_model(),
        // `std::env::consts::OS` already uses `linux` / `macos` / `windows`;
        // OTel's `os.type` says `darwin` for macOS, so that one is remapped.
        os_type: match std::env::consts::OS {
            "macos" => "darwin".into(),
            other => other.into(),
        },
        os_version: read_os_version(),
        cpu_logical_count,
        memory_limit_bytes,
        filesystem_limit_bytes,
        // MiB, matching the `[allocatable]` TOML unit.
        allocatable_memory_mb: memory_limit_bytes.map(|b| (b / (1024 * 1024)) as u32),
        allocatable_cpu_millis: cpu_logical_count.map(|c| c.saturating_mul(1000)),
        collector: collector.as_str().into(),
        collected_at_unix_ms: now_ms(),
    }
}

/// Run a command and return trimmed stdout, or `None` if it failed.
///
/// Used only on the darwin path. Errors are swallowed on purpose: a missing
/// `vm_stat` should degrade one field to null, not fail the endpoint.
fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn read_hostname() -> Option<String> {
    if cfg!(target_os = "linux") {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    } else if cfg!(target_os = "macos") {
        run("sysctl", &["-n", "kern.hostname"])
    } else {
        None
    }
}

fn read_os_version() -> Option<String> {
    if cfg!(target_os = "linux") {
        // `PRETTY_NAME` from os-release is the human-facing distro string;
        // fall back to the kernel release when os-release is absent (musl
        // containers frequently have neither).
        if let Ok(rel) = std::fs::read_to_string("/etc/os-release") {
            for line in rel.lines() {
                if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
                    return Some(v.trim_matches('"').to_string());
                }
            }
        }
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    } else if cfg!(target_os = "macos") {
        run("sysctl", &["-n", "kern.osrelease"])
    } else {
        None
    }
}

fn read_cpu_model() -> Option<String> {
    if cfg!(target_os = "linux") {
        let text = std::fs::read_to_string("/proc/cpuinfo").ok()?;
        for line in text.lines() {
            // x86 uses `model name`; aarch64 (Raspberry Pi) has no such key
            // and exposes the board under `Model` instead.
            for key in ["model name", "Model"] {
                if let Some(rest) = line.strip_prefix(key) {
                    if let Some(v) = rest.split_once(':') {
                        let v = v.1.trim();
                        if !v.is_empty() {
                            return Some(v.to_string());
                        }
                    }
                }
            }
        }
        None
    } else if cfg!(target_os = "macos") {
        run("sysctl", &["-n", "machdep.cpu.brand_string"])
            .or_else(|| run("sysctl", &["-n", "hw.model"]))
    } else {
        None
    }
}

fn read_cpu_count() -> Option<u32> {
    if cfg!(target_os = "linux") {
        let text = std::fs::read_to_string("/proc/cpuinfo").ok()?;
        let n = text
            .lines()
            .filter(|l| l.starts_with("processor") && l.contains(':'))
            .count();
        (n > 0).then_some(n as u32)
    } else if cfg!(target_os = "macos") {
        run("sysctl", &["-n", "hw.logicalcpu"])
            .or_else(|| run("sysctl", &["-n", "hw.ncpu"]))
            .and_then(|s| s.parse().ok())
    } else {
        None
    }
}

/// Returns `(used_bytes, total_bytes)`.
fn read_memory() -> Option<(u64, u64)> {
    if cfg!(target_os = "linux") {
        let text = std::fs::read_to_string("/proc/meminfo").ok()?;
        let total = parse_meminfo_kb(&text, "MemTotal")?;
        // `MemAvailable` is the kernel's own estimate of what a new
        // allocation could get, and is the right basis for "used" — plain
        // `MemFree` counts page cache as used and makes every healthy box
        // look 95% full. Pre-3.14 kernels lack it; fall back to MemFree.
        let available = parse_meminfo_kb(&text, "MemAvailable")
            .or_else(|| parse_meminfo_kb(&text, "MemFree"))?;
        Some((
            total.saturating_sub(available).saturating_mul(1024),
            total.saturating_mul(1024),
        ))
    } else if cfg!(target_os = "macos") {
        let total: u64 = run("sysctl", &["-n", "hw.memsize"])?.parse().ok()?;
        let stat = run("vm_stat", &[])?;
        Some((parse_vm_stat_used(&stat)?, total))
    } else {
        None
    }
}

fn parse_meminfo_kb(text: &str, key: &str) -> Option<u64> {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            if let Some(rest) = rest.strip_prefix(':') {
                return rest.split_whitespace().next()?.parse().ok();
            }
        }
    }
    None
}

/// Used bytes from `vm_stat` output.
///
/// macOS has no single "used memory" number. The convention Activity Monitor
/// itself uses is `active + wired + compressed`: free and speculative pages
/// are available, and *inactive* pages are reclaimable file-backed cache, so
/// counting them as used would repeat the `MemFree` mistake described in
/// [`read_memory`].
fn parse_vm_stat_used(text: &str) -> Option<u64> {
    // Header: "Mach Virtual Memory Statistics: (page size of 16384 bytes)"
    let page_size: u64 = text
        .lines()
        .next()
        .and_then(|l| l.split("page size of ").nth(1))
        .and_then(|r| r.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or(4096);

    let field = |key: &str| -> u64 {
        text.lines()
            .find_map(|l| l.strip_prefix(key))
            .and_then(|r| r.strip_prefix(':'))
            .map(|r| r.trim().trim_end_matches('.'))
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(0)
    };

    let pages = field("Pages active")
        .saturating_add(field("Pages wired down"))
        .saturating_add(field("Pages occupied by compressor"));
    (pages > 0).then(|| pages.saturating_mul(page_size))
}

/// `(used_bytes, total_bytes)` for the filesystem that actually holds
/// workload data, via POSIX `df -Pk`.
///
/// `df` rather than `statvfs` keeps this dep-free and identical on both
/// platforms. `-P` forces single-line records — without it a long device name
/// wraps onto its own line and every field offset shifts.
///
/// # Two things that look like nitpicks and are not
///
/// **The mount point.** On macOS, `/` is the *sealed system volume*, not where
/// anything writes. Measured on a live camp Mac: `df /` reported 4% used while
/// `df /System/Volumes/Data` reported 64% on the same APFS container. Reading
/// `/` would have made a nearly-full build worker report as almost empty —
/// exactly backwards for the signal this endpoint exists to give. So darwin
/// probes the Data volume and falls back to `/` only if it is absent.
///
/// **Used = total − available, not the `Used` column.** They differ, and the
/// subtraction is the one a scheduler wants: on APFS the `Used` column excludes
/// other volumes sharing the container, and on Linux it excludes the
/// root-reserved blocks. Both are space a workload cannot have. `total −
/// available` is the honest "how much can still be written" figure on both.
fn read_filesystem() -> Option<(u64, u64)> {
    if matches!(Collector::detect(), Collector::Unsupported) {
        return None;
    }
    let mount =
        if cfg!(target_os = "macos") && std::path::Path::new("/System/Volumes/Data").exists() {
            "/System/Volumes/Data"
        } else {
            "/"
        };
    parse_df(&run("df", &["-Pk", mount])?)
}

/// Parse `df -Pk` output into `(used_bytes, total_bytes)`.
fn parse_df(out: &str) -> Option<(u64, u64)> {
    // Filesystem  1024-blocks  Used  Available  Capacity  Mounted-on
    let fields: Vec<&str> = out.lines().nth(1)?.split_whitespace().collect();
    if fields.len() < 4 {
        return None;
    }
    let total_kb: u64 = fields[1].parse().ok()?;
    let available_kb: u64 = fields[3].parse().ok()?;
    Some((
        total_kb.saturating_sub(available_kb).saturating_mul(1024),
        total_kb.saturating_mul(1024),
    ))
}

fn read_loadavg() -> Option<(f64, f64, f64)> {
    if cfg!(target_os = "linux") {
        let text = std::fs::read_to_string("/proc/loadavg").ok()?;
        let mut it = text.split_whitespace();
        Some((
            it.next()?.parse().ok()?,
            it.next()?.parse().ok()?,
            it.next()?.parse().ok()?,
        ))
    } else if cfg!(target_os = "macos") {
        // `sysctl -n vm.loadavg` prints "{ 1.23 1.45 1.67 }".
        let text = run("sysctl", &["-n", "vm.loadavg"])?;
        let mut it = text
            .trim_matches(|c| c == '{' || c == '}')
            .split_whitespace();
        Some((
            it.next()?.parse().ok()?,
            it.next()?.parse().ok()?,
            it.next()?.parse().ok()?,
        ))
    } else {
        None
    }
}

fn read_cpu_sample() -> Option<CpuSample> {
    // procfs-only; callers gate on `Collector::Procfs` before reaching here.
    let text = std::fs::read_to_string("/proc/stat").ok()?;
    parse_proc_stat(&text)
}

/// Parse the aggregate `cpu` line of `/proc/stat`.
///
/// `cpu  user nice system idle iowait irq softirq steal guest guest_nice`
///
/// `guest`/`guest_nice` are already counted inside `user`/`nice`, so summing
/// all ten double-counts them. Only the first eight are totalled.
fn parse_proc_stat(text: &str) -> Option<CpuSample> {
    let line = text.lines().find(|l| l.starts_with("cpu "))?;
    let vals: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .take(8)
        .map(|v| v.parse().unwrap_or(0))
        .collect();
    if vals.len() < 4 {
        return None;
    }
    let total: u64 = vals.iter().sum();
    // idle (index 3) + iowait (index 4) — a CPU waiting on I/O is not busy.
    let idle = vals[3] + vals.get(4).copied().unwrap_or(0);
    Some(CpuSample {
        total,
        idle,
        at_unix_ms: now_ms(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Domain metrics ─────────────────────────────────────────────────────

    fn report(source: &str, metrics: &[(&str, MetricValue)]) -> MetricReport {
        MetricReport {
            source: source.into(),
            metrics: metrics
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
            ttl_ms: None,
        }
    }

    #[test]
    fn domain_metrics_merge_flat_into_the_usage_payload() {
        let reg = DomainMetrics::new();
        reg.report(report(
            "plinth-3",
            &[
                ("noisetable.audio.xruns", 4u64.into()),
                ("noisetable.audio.deadline_misses", 0u64.into()),
                ("noisetable.ble.advert_hz", 9.5f64.into()),
            ],
        ))
        .unwrap();

        let snap = reg.snapshot();
        // Flat, unprefixed, exactly as the producer named them — a sibling of
        // `system.cpu.utilization`, not a nested object.
        assert_eq!(snap["noisetable.audio.xruns"], serde_json::json!(4));
        assert_eq!(snap["noisetable.ble.advert_hz"], serde_json::json!(9.5));
        // Zero survives as zero. It is a measurement, not an absence.
        assert_eq!(
            snap["noisetable.audio.deadline_misses"],
            serde_json::json!(0)
        );
        assert_eq!(snap["yah.metrics.sources"], serde_json::json!(["plinth-3"]));
        assert_eq!(snap["yah.metrics.plinth-3.stale"], serde_json::json!(false));
        assert!(snap.contains_key("yah.metrics.plinth-3.age_ms"));
    }

    /// The failure that matters: the producer died. Its last values must stop
    /// being reported, while the fact that it exists and has gone quiet must
    /// not — "crashed" and "never here" are different states.
    #[test]
    fn a_stale_source_drops_its_values_but_not_its_staleness() {
        let reg = DomainMetrics::new();
        reg.report(report(
            "plinth-3",
            &[("noisetable.audio.xruns", 4u64.into())],
        ))
        .unwrap();
        // Backdate the publish past its TTL without sleeping through one.
        {
            let mut guard = reg.lock();
            let scope = guard.get_mut("plinth-3").unwrap();
            scope.reported_at_unix_ms = scope.reported_at_unix_ms.saturating_sub(60_000);
        }

        let snap = reg.snapshot();
        assert!(
            !snap.contains_key("noisetable.audio.xruns"),
            "a dead producer's last value must not keep reading healthy"
        );
        assert_eq!(snap["yah.metrics.plinth-3.stale"], serde_json::json!(true));
        assert!(snap["yah.metrics.plinth-3.age_ms"].as_u64().unwrap() >= 60_000);
        assert_eq!(snap["yah.metrics.sources"], serde_json::json!(["plinth-3"]));
    }

    /// Staleness is visible for a bounded time, then the scope is forgotten —
    /// otherwise a churning producer leaks a scope per identity forever.
    #[test]
    fn a_long_dead_source_is_evicted_entirely() {
        let reg = DomainMetrics::new();
        reg.report(report("gone", &[("x.y", 1u64.into())])).unwrap();
        {
            let mut guard = reg.lock();
            let scope = guard.get_mut("gone").unwrap();
            // Past DEFAULT_METRIC_TTL_MS * METRIC_EVICT_TTL_MULTIPLE.
            scope.reported_at_unix_ms = scope
                .reported_at_unix_ms
                .saturating_sub(DEFAULT_METRIC_TTL_MS * METRIC_EVICT_TTL_MULTIPLE + 1);
        }
        assert!(
            reg.snapshot().is_empty(),
            "an evicted source leaves no keys at all — absence is how a consumer reads 'gone'"
        );
    }

    #[test]
    fn a_report_replaces_the_previous_set_rather_than_merging() {
        let reg = DomainMetrics::new();
        reg.report(report(
            "p",
            &[("a.one", 1u64.into()), ("a.two", 2u64.into())],
        ))
        .unwrap();
        reg.report(report("p", &[("a.one", 9u64.into())])).unwrap();

        let snap = reg.snapshot();
        assert_eq!(snap["a.one"], serde_json::json!(9));
        assert!(
            !snap.contains_key("a.two"),
            "merge semantics cannot express deletion; a metric the producer \
             stopped sending must disappear"
        );
    }

    #[test]
    fn withdraw_removes_a_source_immediately() {
        let reg = DomainMetrics::new();
        reg.report(report("p", &[("a.one", 1u64.into())])).unwrap();
        assert!(reg.withdraw("p"));
        assert!(reg.snapshot().is_empty());
        // Idempotent — a second shutdown signal is not an error worth raising.
        assert!(!reg.withdraw("p"));
    }

    /// An empty report is a heartbeat: the producer is alive and has nothing
    /// to say. It must keep the source non-stale.
    #[test]
    fn an_empty_report_is_a_heartbeat() {
        let reg = DomainMetrics::new();
        reg.report(report("p", &[])).unwrap();
        let snap = reg.snapshot();
        assert_eq!(snap["yah.metrics.p.stale"], serde_json::json!(false));
        assert_eq!(snap["yah.metrics.sources"], serde_json::json!(["p"]));
    }

    /// Domain metrics merge flat, so a producer claiming a built-in key would
    /// emit a duplicate JSON key and shadow a real measurement. Refuse the
    /// whole report — dropping one key of a batch would leave the producer
    /// believing it published.
    #[test]
    fn reserved_prefixes_are_refused_by_name() {
        let reg = DomainMetrics::new();
        for key in [
            "system.cpu.utilization",
            "host.arch",
            "os.type",
            "yah.collector",
        ] {
            let err = reg
                .report(report("p", &[(key, 1u64.into())]))
                .expect_err("{key} must be refused");
            assert!(
                matches!(err, MetricRejection::ReservedKey { .. }),
                "got {err:?}"
            );
            assert!(err.to_string().contains(key), "the 400 must name the key");
        }
        assert!(reg.snapshot().is_empty(), "a refused report writes nothing");
    }

    #[test]
    fn a_source_name_must_survive_being_interpolated_into_a_key() {
        let reg = DomainMetrics::new();
        assert!(matches!(
            reg.report(report("", &[])),
            Err(MetricRejection::BadSource { .. })
        ));
        assert!(matches!(
            reg.report(report("has space", &[])),
            Err(MetricRejection::BadSource { .. })
        ));
        assert!(matches!(
            reg.report(report(&"x".repeat(MAX_METRIC_SOURCE_LEN + 1), &[])),
            Err(MetricRejection::BadSource { .. })
        ));
        // The shapes a real producer uses.
        reg.report(report("plinth-3.audio", &[])).unwrap();
        reg.report(report("egress_peer", &[])).unwrap();
    }

    #[test]
    fn a_metric_key_must_not_be_empty_oversized_or_whitespaced() {
        let reg = DomainMetrics::new();
        for key in ["", "has space", "tab\there"] {
            assert!(
                matches!(
                    reg.report(report("p", &[(key, 1u64.into())])),
                    Err(MetricRejection::BadKey { .. })
                ),
                "{key:?} must be refused"
            );
        }
        let long = "x".repeat(MAX_METRIC_KEY_LEN + 1);
        assert!(matches!(
            reg.report(report("p", &[(long.as_str(), 1u64.into())])),
            Err(MetricRejection::BadKey { .. })
        ));
    }

    #[test]
    fn a_looping_producer_costs_bounded_memory() {
        let reg = DomainMetrics::new();
        let many: Vec<(String, MetricValue)> = (0..=MAX_METRICS_PER_SOURCE)
            .map(|i| (format!("d.k{i}"), MetricValue::U64(i as u64)))
            .collect();
        let over = MetricReport {
            source: "p".into(),
            metrics: many.into_iter().collect(),
            ttl_ms: None,
        };
        assert!(matches!(
            reg.report(over),
            Err(MetricRejection::TooManyMetrics { .. })
        ));

        for i in 0..MAX_METRIC_SOURCES {
            reg.report(report(&format!("s{i}"), &[])).unwrap();
        }
        assert!(matches!(
            reg.report(report("one-too-many", &[])),
            Err(MetricRejection::TooManySources { .. })
        ));
        // A source already registered can still update at the cap — refusing
        // that would silently freeze every live producer's readings.
        reg.report(report("s0", &[("d.k", 1u64.into())])).unwrap();
        assert_eq!(reg.snapshot()["d.k"], serde_json::json!(1));
    }

    /// Two producers publishing the same key is a namespacing bug on their
    /// side. The payload can only carry one value, so name the loss instead of
    /// letting it be silent.
    #[test]
    fn a_key_collision_between_sources_is_reported() {
        let reg = DomainMetrics::new();
        reg.report(report("aaa", &[("shared.key", 1u64.into())]))
            .unwrap();
        reg.report(report("zzz", &[("shared.key", 2u64.into())]))
            .unwrap();
        let snap = reg.snapshot();
        assert_eq!(
            snap["yah.metrics.collisions"],
            serde_json::json!(["shared.key"])
        );
        // Alphabetically-last source wins, deterministically.
        assert_eq!(snap["shared.key"], serde_json::json!(2));

        // Three sources over two keys push their collisions interleaved; each
        // key must still be named once.
        let reg = DomainMetrics::new();
        for source in ["aaa", "bbb", "ccc"] {
            reg.report(report(
                source,
                &[("k.one", 1u64.into()), ("k.two", 2u64.into())],
            ))
            .unwrap();
        }
        assert_eq!(
            reg.snapshot()["yah.metrics.collisions"],
            serde_json::json!(["k.one", "k.two"])
        );
    }

    #[test]
    fn ttl_is_clamped_to_a_usable_range() {
        let reg = DomainMetrics::new();
        for (requested, expected) in [
            (Some(0), MIN_METRIC_TTL_MS),
            (Some(u64::MAX), MAX_METRIC_TTL_MS),
            (Some(5_000), 5_000),
            (None, DEFAULT_METRIC_TTL_MS),
        ] {
            reg.report(MetricReport {
                source: "p".into(),
                metrics: BTreeMap::new(),
                ttl_ms: requested,
            })
            .unwrap();
            assert_eq!(reg.lock()["p"].ttl_ms, expected, "requested {requested:?}");
        }
    }

    /// The values serialize as bare JSON scalars, so every key in the merged
    /// payload is a valid OTLP attribute pair with no translation layer.
    #[test]
    fn metric_values_serialize_as_bare_scalars() {
        assert_eq!(
            serde_json::to_value(MetricValue::U64(7)).unwrap(),
            serde_json::json!(7)
        );
        assert_eq!(
            serde_json::to_value(MetricValue::F64(0.5)).unwrap(),
            serde_json::json!(0.5)
        );
        assert_eq!(
            serde_json::to_value(MetricValue::Bool(true)).unwrap(),
            serde_json::json!(true)
        );
        assert_eq!(
            serde_json::to_value(MetricValue::Text("degraded".into())).unwrap(),
            serde_json::json!("degraded")
        );
        // A NaN has no JSON spelling; null is how the rest of this payload
        // says "no reading" rather than whatever the serializer would choose.
        assert_eq!(
            serde_json::Value::from(MetricValue::F64(f64::NAN)),
            serde_json::Value::Null
        );
    }

    /// A producer's JSON scalars must land on the right variant, since that is
    /// what the untagged enum's ordering decides.
    #[test]
    fn metric_values_deserialize_from_bare_scalars() {
        let parsed: MetricReport = serde_json::from_str(
            r#"{"source":"p","metrics":{"a":3,"b":-3,"c":1.5,"d":true,"e":"x"}}"#,
        )
        .unwrap();
        assert_eq!(parsed.metrics["a"], MetricValue::U64(3));
        assert_eq!(parsed.metrics["b"], MetricValue::I64(-3));
        assert_eq!(parsed.metrics["c"], MetricValue::F64(1.5));
        assert_eq!(parsed.metrics["d"], MetricValue::Bool(true));
        assert_eq!(parsed.metrics["e"], MetricValue::Text("x".into()));
        // Objects and arrays have no flat-dotted spelling and must not parse.
        assert!(
            serde_json::from_str::<MetricReport>(r#"{"source":"p","metrics":{"a":{"b":1}}}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<MetricReport>(r#"{"source":"p","metrics":{"a":[1,2]}}"#)
                .is_err()
        );
    }

    /// The flattened `domain` map is also the capture for keys this build does
    /// not know about, so an older client can still read a newer node.
    #[test]
    fn node_usage_round_trips_domain_keys_flat() {
        let usage = NodeUsage {
            schema_version: NODE_SCHEMA_VERSION,
            cpu_source: "procstat".into(),
            collector: "procfs".into(),
            domain: [("noisetable.audio.xruns".to_string(), serde_json::json!(4))]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let json = serde_json::to_value(&usage).unwrap();
        // Flat sibling of the built-in keys, not nested under `domain`.
        assert_eq!(json["noisetable.audio.xruns"], serde_json::json!(4));
        assert!(json.get("domain").is_none());
        assert_eq!(json["yah.cpu.source"], serde_json::json!("procstat"));

        let back: NodeUsage = serde_json::from_value(json).unwrap();
        assert_eq!(back, usage);

        // An unknown key from a newer node lands in `domain` rather than
        // failing the parse.
        let newer: NodeUsage = serde_json::from_str(
            r#"{"schema_version":1,"yah.cpu.source":"procstat","yah.collector":"procfs",
                "yah.collected_at_unix_ms":0,"yah.workloads.count":0,
                "yah.committed.memory_mb":0,"yah.committed.cpu_millis":0,
                "some.future.field":{"nested":true}}"#,
        )
        .unwrap();
        assert_eq!(
            newer.domain["some.future.field"],
            serde_json::json!({"nested":true})
        );
    }

    #[test]
    fn otel_arch_maps_the_semconv_vocabulary() {
        assert_eq!(otel_arch("x86_64"), "amd64");
        assert_eq!(otel_arch("aarch64"), "arm64");
        // Unknown arch passes through rather than guessing.
        assert_eq!(otel_arch("riscv64"), "riscv64");
    }

    #[test]
    fn proc_stat_totals_exclude_guest_double_count() {
        // user nice system idle iowait irq softirq steal guest guest_nice
        let text = "cpu  100 10 50 800 20 5 5 10 99 99\ncpu0 1 2 3 4\n";
        let s = parse_proc_stat(text).expect("aggregate cpu line parses");
        // 100+10+50+800+20+5+5+10 = 1000; guest columns are NOT added.
        assert_eq!(s.total, 1000);
        // idle + iowait
        assert_eq!(s.idle, 820);
    }

    #[test]
    fn proc_stat_missing_aggregate_line_is_none() {
        assert!(parse_proc_stat("cpu0 1 2 3 4\n").is_none());
    }

    #[test]
    fn cpu_delta_is_one_minus_idle_fraction() {
        let a = CpuSample {
            total: 1000,
            idle: 800,
            at_unix_ms: 0,
        };
        let b = CpuSample {
            total: 2000,
            idle: 1600,
            at_unix_ms: 1000,
        };
        // Δtotal 1000, Δidle 800 -> 20% busy.
        let u = cpu_delta(&a, &b).unwrap();
        assert!((u - 0.2).abs() < 1e-9, "got {u}");
    }

    #[test]
    fn cpu_delta_none_when_counters_did_not_advance() {
        let a = CpuSample {
            total: 1000,
            idle: 800,
            at_unix_ms: 0,
        };
        assert!(cpu_delta(&a, &a).is_none());
    }

    #[test]
    fn cpu_delta_clamps_a_counter_rollback() {
        // Idle can appear to jump past total across a CPU hotplug; the
        // result must stay a valid fraction rather than going negative.
        let a = CpuSample {
            total: 1000,
            idle: 500,
            at_unix_ms: 0,
        };
        let b = CpuSample {
            total: 1100,
            idle: 900,
            at_unix_ms: 1000,
        };
        let u = cpu_delta(&a, &b).unwrap();
        assert!((0.0..=1.0).contains(&u), "got {u}");
    }

    #[test]
    fn meminfo_prefers_available_over_free() {
        let text = "MemTotal:       16384000 kB\n\
                    MemFree:          512000 kB\n\
                    MemAvailable:    8192000 kB\n";
        assert_eq!(parse_meminfo_kb(text, "MemTotal"), Some(16_384_000));
        assert_eq!(parse_meminfo_kb(text, "MemAvailable"), Some(8_192_000));
        assert_eq!(parse_meminfo_kb(text, "NoSuchKey"), None);
    }

    #[test]
    fn vm_stat_used_is_active_plus_wired_plus_compressed() {
        let text = "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n\
                    Pages free:                        1000.\n\
                    Pages active:                      2000.\n\
                    Pages inactive:                    3000.\n\
                    Pages speculative:                  500.\n\
                    Pages wired down:                  1500.\n\
                    Pages occupied by compressor:       500.\n";
        // (2000 + 1500 + 500) * 16384
        assert_eq!(parse_vm_stat_used(text), Some(4000 * 16384));
    }

    #[test]
    fn vm_stat_falls_back_to_4k_pages_without_a_header() {
        let text = "Pages active: 10.\nPages wired down: 10.\n";
        assert_eq!(parse_vm_stat_used(text), Some(20 * 4096));
    }

    /// Used is `total − available`, NOT the `Used` column. This is the real
    /// APFS output from a camp Mac: the two disagree by 590 GB because the
    /// `Used` column only counts the one volume, while `available` accounts
    /// for the whole shared container.
    #[test]
    fn df_used_is_total_minus_available() {
        let out = "Filesystem     1024-blocks      Used Available Capacity  Mounted on\n\
                   /dev/disk3s1s1   971298980  12271396 344029740     4%    /\n";
        let (used, total) = parse_df(out).unwrap();
        assert_eq!(total, 971_298_980 * 1024);
        // 971298980 - 344029740 = 627269240, i.e. ~65% — not the 4% the
        // `Used` column would have implied.
        assert_eq!(used, 627_269_240 * 1024);
        assert!(used * 100 / total > 60);
    }

    #[test]
    fn df_ignores_a_header_only_or_short_record() {
        assert!(parse_df("Filesystem 1024-blocks Used Available Capacity Mounted on\n").is_none());
        assert!(parse_df("Filesystem Blocks\n/dev/disk1 100\n").is_none());
    }

    #[test]
    fn committed_totals_sums_the_registry() {
        let reg: ResourceRegistry = Mutex::new(BTreeMap::new());
        reg.lock().unwrap().insert(
            "a.pdx".into(),
            WorkloadResources {
                memory_mb: 512,
                cpu_millis: 250,
            },
        );
        reg.lock().unwrap().insert(
            "b.pdx".into(),
            WorkloadResources {
                memory_mb: 1024,
                cpu_millis: 500,
            },
        );
        assert_eq!(committed_totals(&reg), (2, 1536, 750));
    }

    fn registry_with(entries: &[(&str, u32, u32)]) -> ResourceRegistry {
        let reg: ResourceRegistry = Mutex::new(BTreeMap::new());
        for (k, memory_mb, cpu_millis) in entries {
            reg.lock().unwrap().insert(
                (*k).into(),
                WorkloadResources {
                    memory_mb: *memory_mb,
                    cpu_millis: *cpu_millis,
                },
            );
        }
        reg
    }

    /// The legacy runtime shape keys on `ident`.
    #[test]
    fn enrich_matches_runtime_rows_on_ident() {
        let reg = registry_with(&[("api.pdx", 512, 250)]);
        let mut rows = serde_json::json!([
            { "ident": "api.pdx", "container_id": "c1", "status": "running" },
        ]);
        enrich_workloads(&reg, &mut rows);
        assert_eq!(rows[0]["memory_mb"], 512);
        assert_eq!(rows[0]["cpu_millis"], 250);
        // Pre-existing fields survive — enrichment is additive.
        assert_eq!(rows[0]["container_id"], "c1");
    }

    /// Kamaji's shape keys on `id`; the container id IS the workload ident.
    #[test]
    fn enrich_matches_kamaji_rows_on_id() {
        let reg = registry_with(&[("api.pdx", 512, 250)]);
        let mut rows = serde_json::json!([{ "id": "api.pdx", "state": "running", "pid": 42 }]);
        enrich_workloads(&reg, &mut rows);
        assert_eq!(rows[0]["memory_mb"], 512);
        assert_eq!(rows[0]["pid"], 42);
    }

    /// A workload with no recorded request — deployed before this yubaba
    /// restarted, or started out-of-band — must come back with the fields
    /// ABSENT, not zero. A bin-packer reading 0 would treat an unknown
    /// footprint as a free one.
    #[test]
    fn enrich_leaves_unknown_workloads_without_resource_fields() {
        let reg = registry_with(&[("api.pdx", 512, 250)]);
        let mut rows = serde_json::json!([
            { "ident": "api.pdx" },
            { "ident": "ghost.pdx" },
        ]);
        enrich_workloads(&reg, &mut rows);
        assert_eq!(rows[0]["memory_mb"], 512);
        assert!(rows[1].get("memory_mb").is_none());
        assert!(rows[1].get("cpu_millis").is_none());
    }

    #[test]
    fn enrich_is_a_noop_on_an_empty_registry_or_non_array() {
        let empty: ResourceRegistry = Mutex::new(BTreeMap::new());
        let mut rows = serde_json::json!([{ "ident": "api.pdx" }]);
        enrich_workloads(&empty, &mut rows);
        assert!(rows[0].get("memory_mb").is_none());

        let reg = registry_with(&[("api.pdx", 512, 250)]);
        let mut not_an_array = serde_json::json!({ "workloads": [] });
        enrich_workloads(&reg, &mut not_an_array);
        assert_eq!(not_an_array, serde_json::json!({ "workloads": [] }));
    }

    #[test]
    fn committed_totals_of_empty_registry_is_zero() {
        let reg: ResourceRegistry = Mutex::new(BTreeMap::new());
        assert_eq!(committed_totals(&reg), (0, 0, 0));
    }

    /// The wire contract: OTel semantic-convention keys, flat and dotted, so
    /// an exporter can forward each key as an OTLP attribute name without a
    /// rename table. Guarding this in a test is the point — a serde field
    /// rename dropped by accident would silently break that property.
    #[test]
    fn specs_serialize_with_otel_semconv_keys() {
        let specs = NodeSpecs {
            schema_version: NODE_SCHEMA_VERSION,
            host_name: Some("us-west-015".into()),
            host_arch: "arm64".into(),
            arch: "aarch64".into(),
            cpu_model: Some("Apple M2".into()),
            os_type: "darwin".into(),
            os_version: Some("25.5.0".into()),
            cpu_logical_count: Some(8),
            memory_limit_bytes: Some(17_179_869_184),
            filesystem_limit_bytes: Some(494_384_795_648),
            allocatable_memory_mb: Some(16384),
            allocatable_cpu_millis: Some(8000),
            collector: "sysctl".into(),
            collected_at_unix_ms: 1,
        };
        let v = serde_json::to_value(&specs).unwrap();
        assert_eq!(v["host.name"], "us-west-015");
        assert_eq!(v["host.arch"], "arm64");
        assert_eq!(v["yah.arch"], "aarch64");
        assert_eq!(v["host.cpu.model.name"], "Apple M2");
        assert_eq!(v["os.type"], "darwin");
        assert_eq!(v["system.cpu.logical.count"], 8);
        assert_eq!(v["system.memory.limit"], 17_179_869_184u64);
        assert_eq!(v["yah.allocatable.memory_mb"], 16384);
        assert_eq!(v["yah.collector"], "sysctl");

        // Round-trips: the same dotted keys deserialize back.
        let back: NodeSpecs = serde_json::from_value(v).unwrap();
        assert_eq!(back, specs);
    }

    #[test]
    fn usage_serializes_with_otel_semconv_keys() {
        let usage = NodeUsage {
            schema_version: NODE_SCHEMA_VERSION,
            cpu_utilization: Some(0.25),
            cpu_source: "procstat".into(),
            memory_usage_bytes: Some(1024),
            memory_limit_bytes: Some(4096),
            memory_utilization: Some(0.25),
            committed_memory_mb: 512,
            committed_cpu_millis: 250,
            workloads_count: 1,
            sample_window_ms: Some(200),
            collector: "procfs".into(),
            collected_at_unix_ms: 1,
            ..Default::default()
        };
        let v = serde_json::to_value(&usage).unwrap();
        assert_eq!(v["system.cpu.utilization"], 0.25);
        assert_eq!(v["system.memory.usage"], 1024);
        assert_eq!(v["system.memory.utilization"], 0.25);
        assert_eq!(v["yah.committed.memory_mb"], 512);
        assert_eq!(v["yah.cpu.source"], "procstat");
        assert_eq!(v["yah.sample.window_ms"], 200);
        // Unmeasured fields are omitted entirely rather than sent as 0 —
        // "unknown" and "zero" are different states for a capacity floor.
        assert!(v.get("system.filesystem.usage").is_none());

        let back: NodeUsage = serde_json::from_value(v).unwrap();
        assert_eq!(back, usage);
    }

    /// Whatever the host platform is, `/node` must answer with a coherent
    /// payload — never a partially-filled struct with a bogus schema version.
    #[test]
    fn specs_collect_on_this_platform() {
        let probe = NodeProbe::new();
        let specs = probe.specs();
        assert_eq!(specs.schema_version, NODE_SCHEMA_VERSION);
        assert_eq!(specs.arch, std::env::consts::ARCH);
        assert!(!specs.host_arch.is_empty());
        assert!(!specs.os_type.is_empty());

        // On a platform we claim to support, the core numbers must be real.
        if !matches!(Collector::detect(), Collector::Unsupported) {
            assert!(specs.cpu_logical_count.unwrap_or(0) > 0, "{specs:?}");
            assert!(specs.memory_limit_bytes.unwrap_or(0) > 0, "{specs:?}");
            assert_eq!(
                specs.allocatable_cpu_millis,
                specs.cpu_logical_count.map(|c| c * 1000)
            );
        }

        // Cached: the second call is the same collection, not a re-read.
        assert_eq!(
            probe.specs().collected_at_unix_ms,
            specs.collected_at_unix_ms
        );
    }

    #[tokio::test]
    async fn usage_collects_on_this_platform() {
        let probe = NodeProbe::new();
        let usage = probe.usage(Some(MIN_WINDOW_MS), (2, 1536, 750)).await;
        assert_eq!(usage.schema_version, NODE_SCHEMA_VERSION);
        assert_eq!(usage.workloads_count, 2);
        assert_eq!(usage.committed_memory_mb, 1536);
        assert_eq!(usage.committed_cpu_millis, 750);

        if !matches!(Collector::detect(), Collector::Unsupported) {
            let mem = usage.memory_utilization.expect("memory is measurable");
            assert!((0.0..=1.0).contains(&mem), "{mem}");
            assert!(usage.memory_usage_bytes.unwrap() <= usage.memory_limit_bytes.unwrap());
            let cpu = usage.cpu_utilization.expect("cpu is measurable");
            assert!((0.0..=1.0).contains(&cpu), "{cpu}");
            assert_ne!(usage.cpu_source, "unavailable");
        }
    }

    /// An oversized `window_ms` must not pin an HTTP worker for the caller's
    /// requested duration.
    #[tokio::test]
    async fn window_ms_is_clamped_to_the_ceiling() {
        let probe = NodeProbe::new();
        let start = std::time::Instant::now();
        let usage = probe.usage(Some(60_000), (0, 0, 0)).await;
        assert!(
            start.elapsed() < std::time::Duration::from_millis(MAX_WINDOW_MS + 2_000),
            "a 60s request window was not clamped"
        );
        if let Some(w) = usage.sample_window_ms {
            assert!(w <= MAX_WINDOW_MS + 1_000, "reported window {w}ms");
        }
    }

    /// Second poll with no explicit window diffs against the first poll — the
    /// "measurement interval follows the client's reporting interval"
    /// property that makes the pull model work.
    #[tokio::test]
    async fn implicit_window_follows_the_poll_interval() {
        if !matches!(Collector::detect(), Collector::Procfs) {
            return; // loadavg path has no window to report
        }
        let probe = NodeProbe::new();
        let _first = probe.usage(None, (0, 0, 0)).await;
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        let second = probe.usage(None, (0, 0, 0)).await;
        let window = second.sample_window_ms.expect("procstat reports a window");
        // Diffed against the previous poll (~120ms), not a fresh in-request
        // DEFAULT_WINDOW_MS sample.
        assert!(window >= 100, "window {window}ms looks like a fresh sample");
        assert_eq!(second.cpu_source, "procstat");
    }
}

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
}

impl NodeProbe {
    pub fn new() -> Self {
        Self::default()
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

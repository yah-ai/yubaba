//! Device compute — a component running on an attached iOS device or
//! simulator, or on an Android device or emulator (R941).
//!
//! The sibling of [`super::local_process`] for a process that runs somewhere
//! other than the host. Like it, this is a **mirror compute slot, not a
//! component kind** (R715): the component's `workload.toml` says *what* the app
//! is — a bundle id, a package — and the mirror says *where* it runs:
//!
//! ```toml
//! [providers.compute]
//! kind = "device"
//! target = "ios-simulator"   # ios-device | android-emulator | android-device
//! device = "iPhone 17 Pro"   # optional: an id (udid / serial) or a name
//! ```
//!
//! ```toml
//! # workload.toml
//! [device]
//! pre_build = ["cargo", "mobile", "build"]   # optional, runs on the host
//! env = { RUST_LOG = "info" }                # iOS: process env; Android: intent extras
//! control = true                             # opt in to the W315 status channel
//!
//! [device.ios]
//! bundle_id = "dev.yah.noisetable"
//! app = "target/ios-sim/NoiseTable.app"      # optional; installed before launch
//!
//! [device.android]
//! package = "dev.yah.noisetable"
//! activity = "android.app.NativeActivity"
//! apk = "target/android/noisetable.apk"      # optional; installed before launch
//! ```
//!
//! Everything goes through the host tools that are already installed — `xcrun
//! simctl`, `xcrun devicectl`, `adb`. No daemon is added, on either side.
//!
//! ## Inventory
//!
//! [`enumerate`] is the other half, and has its own consumer: noisetable's
//! W203 étude controller (Gap 4) reads one [`DeviceHost`] record per host —
//! platform, the discovery lanes it can claim, its bind addresses, and which
//! control rail reaches it — instead of building its own inventory. The
//! reconciler picks its target out of the same records, so "what can run here"
//! has one answer.
//!
//! ## Status rail, per host
//!
//! The app side is W315's process-control channel (`kamaji-procctl`, default
//! features). How the supervisor reaches it differs by host:
//!
//! - **Simulator** shares the host filesystem, so `$YAH_CONTROL_SOCK` is a
//!   host path exactly as for `local-process` (delivered via `SIMCTL_CHILD_`).
//! - **Android** apps cannot bind anywhere the host can see, so the app is
//!   handed `@yah.<ident>` — an abstract-namespace name, as the intent string
//!   extra `YAH_CONTROL_SOCK`, since an activity has no process env — and the
//!   host reaches it through `adb forward tcp:0 localabstract:yah.<ident>` as
//!   [`ControlEndpoint::Tcp`].
//! - **Physical iOS** has no Unix-socket path to the host at all. That needs a
//!   network rail, which W203 leaves open (can a pinned endpoint ride the
//!   CoreDevice USB tunnel?). Until then readiness there is liveness only, and
//!   the running workload says so in its notes rather than claiming health.
//!
//! @arch:see(oss/yubaba/crates/cloud/src/reconciler/local_process.rs)
//!
//! @yah:relay(R941, "Device compute provider: launch/enumerate/health for iOS devices+simulators and Android devices+emulators via devicectl/simctl/adb")
//! @yah:status(review)
//! @yah:at(2026-09-26T05:19:22Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:next("Sibling of R715's local-process provider, for a process that runs on an attached device or simulator instead of on the host. Uses only the existing host tools: `xcrun devicectl`, `xcrun simctl`, `adb`. No new daemons.")
//! @yah:next("Host enumeration + one capability record per host (platform, lanes it can claim, bind addresses, which control rail reaches it). noisetable W203 Gap 4 consumes this instead of building its own inventory.")
//! @yah:next("W315 status rail per host: simulator shares the host FS, so $YAH_CONTROL_SOCK works as is; Android via `adb forward tcp:N localabstract:<name>`; physical iOS has no Unix-socket path (network rail, open question in W203). The app side uses kamaji-procctl (default features: serde + serde_json only).")
//! @yah:next("Per R715's gotcha: the runtime is a property of the MIRROR, not the component. A device target is a mirror compute slot, not a new component kind.")
//! @yah:next("Consumer doc: noisetable .yah/docs/working/W203-multi-instance-etudes.md (Gap 4, Phase 4).")
//! @yah:handoff("LANDED: device compute provider oss/yubaba/crates/cloud/src/reconciler/device.rs (unix-gated like local_process). Mirror slot `[providers.compute] kind=\"device\" target=ios-simulator|ios-device|android-emulator|android-device device=<id|name>`; component `workload.toml [device]` + `[device.ios] bundle_id/app` / `[device.android] package/activity/apk`, optional pre_build/env/args/control. Launch via simctl launch --console / devicectl process launch --console / adb am start + logcat --pid; supervisor = launcher child (Android: pidof poll); teardown = simctl terminate / SIGTERM forwarded by devicectl / am force-stop + adb forward --remove.")
//! @yah:handoff("INVENTORY: `cloud::reconciler::device::enumerate()` -> Inventory{hosts: Vec<DeviceHost>, probes} — one capability record per host (kind, platform, os_version, state+detail, W203 lanes, shares_host_network, bind_addrs, control_rail). Emulator claims no `lan` (W203). Consumer surface for noisetable W203 Gap 4: `yah cloud devices [--json]` (app/yah/cli/src/cloud.rs handle_devices).")
//! @yah:handoff("STATUS RAIL: simulator = host-path $YAH_CONTROL_SOCK via SIMCTL_CHILD_; Android = app gets `@yah.<ident>` as intent string extra YAH_CONTROL_SOCK, host reaches it via `adb forward tcp:0 localabstract:` -> new `ControlEndpoint::Tcp` (proc_control.rs; newline-JSON shared with the UDS arm). Physical iOS = no rail, readiness liveness-only and the notes say so.")
//! @yah:handoff("WIDER THAN THE TITLE: (1) oss/kamaji/crates/procctl serve.rs/lib.rs — producer now binds `@name` as a Linux/Android abstract-namespace socket (needed for the adb rail; no file created/unlinked). (2) Provider::Device in config.rs + sync_status.rs label; .yah/schema/{mirror,provider}.toml.schema.json regenerated. (3) dispatch arms in app/yah/cli/src/cloud.rs reconcile_component and app/yah/desktop/src/mirror_run.rs. (4) local_process::run_pre_build -> pub(super) for reuse. (5) wedged-emulator handling: `adb devices` lists a hung guest as `device`; a 5s getprop liveness probe now marks it offline (found live on emulator-5554).")
//! @yah:verify("cargo test --manifest-path oss/yubaba/Cargo.toml -p yah-cloud --lib -- reconciler::device proc_control: 24 passed (13 device unit + TCP transport test).")
//! @yah:verify("LIVE (2026-09-26): YAH_DEVICE_LIVE_ANDROID=emulator-5580 YAH_DEVICE_LIVE_SIM=\"iPhone 17 Pro\" ... reconciler::device --include-ignored: both pass — Android Settings launched with a quoted extra, supervised, force-stopped (pidof empty after); simulator booted from Shutdown, Safari launched, stopped.")
//! @yah:verify("`yah cloud devices` live: 27 hosts, simctl/devicectl/adb probes all ok; iPad correctly offline (tunnel unavailable).")
//! @yah:verify("cargo test -p kamaji-procctl green; cargo check -p kamaji-procctl --target aarch64-linux-android EXIT=0. cargo build -p yah and cargo check -p desktop EXIT=0.")
//! @yah:gotcha("NOT LIVE-VERIFIED: the control rail end to end on a device (sim socket / adb-forward TCP to an abstract socket) — no producer app exists yet; that is noisetable W203 Phase 4's first step (kamaji-procctl in winit, then mobile). Pieces are verified separately: TCP arm unit test, procctl abstract bind compiles for android, its linux-only test cannot run on this mac.")
//! @yah:gotcha("Live sim test leaves the simulator booted (by design: booting is expensive; teardown only terminates the app).")
//! @yah:cleanup("select_host name match: two simulators can share a name across runtimes (this machine has two `iPhone 17 Pro`, iOS 26.4 + 26.5); the first by udid wins silently. Prefer Ready, then newest os_version, and note the rest.")
//! @yah:cleanup("Physical-iOS network rail (W203 open question: pinned endpoint over the CoreDevice USB tunnel) — ControlRail::None until answered.")

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::oneshot;
use tracing::{info, warn};

use super::local_process::run_pre_build;
use super::native_support::sanitize_ident;
use super::{into_running, LogBuffer, ReconcileCtx, Reconciler, RunningWorkload};
use crate::proc_control::{self, ControlEndpoint, ReadyOutcome};
use crate::{MirrorProviderSlot, MirrorShape, Provider};

const SLOT: &str = "compute";

/// A device app has further to go than a host process: a simulator may be
/// cold-booting, and a physical device is reached over a tunnel.
const READY_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a channel-less app must stay up to count as launched.
const ALIVE_GRACE: Duration = Duration::from_millis(1500);

/// Ceiling on any one host-tool call during enumeration. `devicectl` in
/// particular can sit for a long time on a device it half-sees.
const PROBE_TIMEOUT: Duration = Duration::from_secs(20);

/// A responsive `adb shell getprop` answers well inside a second.
const SHELL_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the Android supervisor checks the app's pid is still there —
/// `logcat --pid` does not exit when the process does.
const ANDROID_PID_POLL: Duration = Duration::from_secs(2);

// ─── Inventory ──────────────────────────────────────────────────────────────

/// What kind of host a [`DeviceHost`] is. Also the mirror slot's `target`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostKind {
    /// The machine this runs on. Always present; it can always spawn a
    /// process (that is `local-process`'s job, not this module's).
    Local,
    IosSimulator,
    IosDevice,
    AndroidEmulator,
    AndroidDevice,
}

impl HostKind {
    pub fn as_str(self) -> &'static str {
        match self {
            HostKind::Local => "local",
            HostKind::IosSimulator => "ios-simulator",
            HostKind::IosDevice => "ios-device",
            HostKind::AndroidEmulator => "android-emulator",
            HostKind::AndroidDevice => "android-device",
        }
    }

    pub fn platform(self) -> Platform {
        match self {
            HostKind::Local if cfg!(target_os = "macos") => Platform::Macos,
            HostKind::Local => Platform::Linux,
            HostKind::IosSimulator | HostKind::IosDevice => Platform::Ios,
            HostKind::AndroidEmulator | HostKind::AndroidDevice => Platform::Android,
        }
    }

    /// Discovery lanes a process on this host can claim — W203's `lookup=`
    /// vocabulary (society's `PeerLookup` lane names).
    ///
    /// The emulator is the one host W203 names as LAN-less: it sits behind the
    /// emulator's own NAT, and whether multicast reaches the host from it under
    /// any network mode is an open question there. Until that is answered it
    /// does not claim `lan`, so a placement asking for it gets a legible skip
    /// rather than a run that silently never discovers its peer. The simulator
    /// *does* claim `lan` — it uses the host's stack — but see
    /// [`DeviceHost::shares_host_network`].
    pub fn lanes(self) -> Vec<Lane> {
        match self {
            HostKind::AndroidEmulator => vec![Lane::Direct, Lane::Roster, Lane::Wan],
            _ => vec![Lane::Direct, Lane::Lan, Lane::Roster, Lane::Wan],
        }
    }

    /// Which W315 control rail reaches a process on this host.
    pub fn control_rail(self) -> ControlRail {
        match self {
            HostKind::Local | HostKind::IosSimulator => ControlRail::UnixSocket,
            HostKind::AndroidEmulator | HostKind::AndroidDevice => ControlRail::AdbForward,
            HostKind::IosDevice => ControlRail::None,
        }
    }

    fn parse(s: &str) -> Option<Self> {
        [
            HostKind::IosSimulator,
            HostKind::IosDevice,
            HostKind::AndroidEmulator,
            HostKind::AndroidDevice,
            HostKind::Local,
        ]
        .into_iter()
        .find(|k| k.as_str() == s)
    }
}

impl std::fmt::Display for HostKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    Macos,
    Linux,
    Ios,
    Android,
}

/// A W203 `lookup=` lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Lane {
    Direct,
    Lan,
    Roster,
    Wan,
}

/// How the supervisor reaches a process's W315 status channel on a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlRail {
    /// `$YAH_CONTROL_SOCK` as a host filesystem path.
    UnixSocket,
    /// An abstract-namespace socket on the device, forwarded to a host TCP
    /// port by `adb forward`.
    AdbForward,
    /// No rail yet — physical iOS. Readiness is liveness only.
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostState {
    /// Can launch now.
    Ready,
    /// A simulator that exists but is not booted. Launchable — the reconciler
    /// boots it — when a mirror names it explicitly.
    Shutdown,
    /// Known but not usable: unpaired, unreachable, `unauthorized`, …
    /// `state_detail` says which.
    Offline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindAddr {
    pub interface: String,
    pub addr: IpAddr,
}

/// One capability record per host (W203 Gap 4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceHost {
    /// The identifier the host tool takes: a simulator/device UDID, an adb
    /// serial, or `local`.
    pub id: String,
    pub name: String,
    pub kind: HostKind,
    pub platform: Platform,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    pub state: HostState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_detail: Option<String>,
    pub lanes: Vec<Lane>,
    /// True when the host has no network identity of its own — a simulator
    /// runs on the Mac's stack. Two roles on such a pair are separated by bind
    /// address at best, never by interface; W203's `host!=` needs this.
    pub shares_host_network: bool,
    /// Addresses a process there can bind. `None` means not knowable from the
    /// host tools (a physical iOS device), which is different from empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_addrs: Option<Vec<BindAddr>>,
    pub control_rail: ControlRail,
}

impl DeviceHost {
    fn new(id: impl Into<String>, name: impl Into<String>, kind: HostKind) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            kind,
            platform: kind.platform(),
            os_version: None,
            state: HostState::Ready,
            state_detail: None,
            lanes: kind.lanes(),
            shares_host_network: kind == HostKind::IosSimulator,
            bind_addrs: None,
            control_rail: kind.control_rail(),
        }
    }

    fn offline(mut self, detail: impl Into<String>) -> Self {
        self.state = HostState::Offline;
        self.state_detail = Some(detail.into());
        self
    }
}

/// Result of one enumeration pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Inventory {
    pub hosts: Vec<DeviceHost>,
    /// One entry per host tool consulted, so "no Android hosts" can be told
    /// apart from "`adb` is not installed".
    pub probes: Vec<Probe>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Probe {
    pub tool: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Enumerate every host this machine can launch onto: itself, iOS simulators
/// and devices (macOS only), and whatever `adb` sees.
///
/// Never fails. A missing or broken tool becomes a failed [`Probe`] and simply
/// contributes no hosts — an inventory is useful precisely when some of it is
/// absent.
pub async fn enumerate() -> Inventory {
    let mut inv = Inventory::default();
    let host_addrs = local_bind_addrs();

    let mut local = DeviceHost::new("local", local_hostname(), HostKind::Local);
    local.bind_addrs = Some(host_addrs.clone());
    inv.hosts.push(local);

    if cfg!(target_os = "macos") {
        match tool_output("xcrun", &["simctl", "list", "devices", "--json"]).await {
            Ok(json) => match parse_simctl(&json) {
                Ok(mut sims) => {
                    for sim in &mut sims {
                        sim.bind_addrs = Some(host_addrs.clone());
                    }
                    inv.probes.push(probe_ok("simctl", sims.len()));
                    inv.hosts.extend(sims);
                }
                Err(e) => inv.probes.push(probe_err("simctl", e)),
            },
            Err(e) => inv.probes.push(probe_err("simctl", e)),
        }

        match devicectl_devices().await {
            Ok(devices) => {
                inv.probes.push(probe_ok("devicectl", devices.len()));
                inv.hosts.extend(devices);
            }
            Err(e) => inv.probes.push(probe_err("devicectl", e)),
        }
    }

    match tool_output("adb", &["devices", "-l"]).await {
        Ok(text) => {
            // Concurrently: a wedged device costs one probe timeout in
            // total, not one per device.
            let probes: Vec<_> = parse_adb_devices(&text)
                .into_iter()
                .map(|host| {
                    tokio::spawn(async move {
                        if host.state == HostState::Ready {
                            probe_android(host).await
                        } else {
                            host
                        }
                    })
                })
                .collect();
            let mut androids = Vec::with_capacity(probes.len());
            for p in probes {
                if let Ok(host) = p.await {
                    androids.push(host);
                }
            }
            inv.probes.push(probe_ok("adb", androids.len()));
            inv.hosts.extend(androids);
        }
        Err(e) => inv.probes.push(probe_err("adb", e)),
    }

    inv
}

fn probe_ok(tool: &str, n: usize) -> Probe {
    Probe {
        tool: tool.to_string(),
        ok: true,
        detail: Some(format!("{n} host(s)")),
    }
}

fn probe_err(tool: &str, e: anyhow::Error) -> Probe {
    Probe {
        tool: tool.to_string(),
        ok: false,
        detail: Some(format!("{e:#}")),
    }
}

async fn devicectl_devices() -> Result<Vec<DeviceHost>> {
    // devicectl's JSON goes to a file, not stdout.
    let out = tempfile::NamedTempFile::new().context("creating devicectl --json-output file")?;
    let path = out.path().display().to_string();
    tool_output(
        "xcrun",
        &["devicectl", "list", "devices", "--quiet", "--json-output", &path],
    )
    .await?;
    let json = tokio::fs::read_to_string(out.path())
        .await
        .context("reading devicectl --json-output")?;
    parse_devicectl(&json)
}

/// Fill the Android fields `adb devices -l` does not carry. Best-effort: a
/// failed probe leaves the field unset rather than the host dropped.
///
/// The `getprop` doubles as a shell liveness check. `adb devices` reports an
/// emulator whose guest has wedged as `device` all the same, and every
/// `adb shell` against it then hangs — seen on this machine, not hypothesised.
/// Such a host cannot launch anything, so it is reported offline rather than
/// ready-but-useless.
async fn probe_android(mut host: DeviceHost) -> DeviceHost {
    let serial = host.id.clone();
    match tool_output_within(
        SHELL_PROBE_TIMEOUT,
        "adb",
        &["-s", &serial, "shell", "getprop", "ro.build.version.release"],
    )
    .await
    {
        Ok(v) => {
            let v = v.trim();
            if !v.is_empty() {
                host.os_version = Some(v.to_string());
            }
        }
        Err(e) if format!("{e}").contains("timed out") => {
            return host.offline(format!(
                "`adb shell` did not answer within {SHELL_PROBE_TIMEOUT:?}"
            ));
        }
        Err(_) => {}
    }
    if let Ok(text) = tool_output("adb", &["-s", &serial, "shell", "ip", "-o", "-4", "addr", "show"]).await {
        host.bind_addrs = Some(parse_ip_addr(&text));
    }
    host
}

#[derive(Deserialize)]
struct SimctlList {
    devices: BTreeMap<String, Vec<SimctlDevice>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SimctlDevice {
    udid: String,
    name: String,
    state: String,
    #[serde(default)]
    is_available: bool,
}

/// `xcrun simctl list devices --json` → iOS simulator hosts.
///
/// Only iOS runtimes (iPadOS simulators report as iOS too); watchOS, tvOS and
/// visionOS simulators are not app targets here. Unavailable ones — a runtime
/// that has been deleted — are dropped rather than reported offline: they
/// cannot come back without reinstalling Xcode components.
pub fn parse_simctl(json: &str) -> Result<Vec<DeviceHost>> {
    let list: SimctlList = serde_json::from_str(json).context("parsing simctl --json")?;
    let mut out = Vec::new();
    for (runtime, devices) in list.devices {
        let Some(version) = runtime
            .rsplit_once(".iOS-")
            .map(|(_, v)| v.replace('-', "."))
        else {
            continue;
        };
        for d in devices.into_iter().filter(|d| d.is_available) {
            let mut host = DeviceHost::new(d.udid, d.name, HostKind::IosSimulator);
            host.os_version = Some(version.clone());
            match d.state.as_str() {
                "Booted" => {}
                "Shutdown" => host.state = HostState::Shutdown,
                other => host = host.offline(other.to_lowercase()),
            }
            out.push(host);
        }
    }
    Ok(out)
}

#[derive(Deserialize)]
struct DevicectlList {
    result: DevicectlResult,
}

#[derive(Deserialize)]
struct DevicectlResult {
    #[serde(default)]
    devices: Vec<DevicectlDevice>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DevicectlDevice {
    identifier: String,
    #[serde(default)]
    connection_properties: DevicectlConnection,
    #[serde(default)]
    device_properties: DevicectlProps,
    #[serde(default)]
    hardware_properties: DevicectlHardware,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct DevicectlConnection {
    pairing_state: Option<String>,
    tunnel_state: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct DevicectlProps {
    name: Option<String>,
    os_version_number: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct DevicectlHardware {
    platform: Option<String>,
    reality: Option<String>,
    udid: Option<String>,
    marketing_name: Option<String>,
}

/// `xcrun devicectl list devices --json-output` → physical iOS hosts.
///
/// `tunnelState == "unavailable"` is read as unreachable (the device is not on
/// USB or the local network right now); any other state — `disconnected`
/// included — as launchable, because devicectl brings the tunnel up on demand
/// for a reachable device. That reading of `disconnected` is an inference from
/// devicectl's behaviour, not a documented contract.
pub fn parse_devicectl(json: &str) -> Result<Vec<DeviceHost>> {
    let list: DevicectlList = serde_json::from_str(json).context("parsing devicectl JSON")?;
    let mut out = Vec::new();
    for d in list.result.devices {
        let hw = &d.hardware_properties;
        if hw.reality.as_deref() != Some("physical") || hw.platform.as_deref() != Some("iOS") {
            continue;
        }
        let id = hw.udid.clone().unwrap_or_else(|| d.identifier.clone());
        let name = d
            .device_properties
            .name
            .clone()
            .or_else(|| hw.marketing_name.clone())
            .unwrap_or_else(|| id.clone());
        let mut host = DeviceHost::new(id, name, HostKind::IosDevice);
        host.os_version = d.device_properties.os_version_number.clone();
        let conn = &d.connection_properties;
        if conn.pairing_state.as_deref().is_some_and(|p| p != "paired") {
            host = host.offline(format!(
                "not paired ({})",
                conn.pairing_state.as_deref().unwrap_or_default()
            ));
        } else if conn.tunnel_state.as_deref() == Some("unavailable") {
            host = host.offline("not reachable (CoreDevice tunnel unavailable)");
        }
        out.push(host);
    }
    Ok(out)
}

/// `adb devices -l` → Android hosts. An `emulator-` serial is an emulator;
/// anything else a device. Any state but `device` (`offline`,
/// `unauthorized`, `recovery`, …) is reported offline under that name.
pub fn parse_adb_devices(text: &str) -> Vec<DeviceHost> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("List of devices") || line.starts_with('*') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(serial), Some(state)) = (parts.next(), parts.next()) else {
            continue;
        };
        let props: BTreeMap<&str, &str> = parts.filter_map(|kv| kv.split_once(':')).collect();
        let kind = if serial.starts_with("emulator-") {
            HostKind::AndroidEmulator
        } else {
            HostKind::AndroidDevice
        };
        let name = props
            .get("model")
            .map(|m| m.replace('_', " "))
            .unwrap_or_else(|| serial.to_string());
        let mut host = DeviceHost::new(serial, name, kind);
        if state != "device" {
            host = host.offline(state.to_string());
        }
        out.push(host);
    }
    out
}

/// `ip -o -4 addr show` → bind addresses. One line per address:
/// `15: eth0    inet 10.0.2.15/8 brd … scope global eth0\ …`.
pub fn parse_ip_addr(text: &str) -> Vec<BindAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some(inet) = tokens.iter().position(|t| *t == "inet" || *t == "inet6") else {
            continue;
        };
        let (Some(iface), Some(cidr)) = (tokens.get(1), tokens.get(inet + 1)) else {
            continue;
        };
        let addr = cidr.split('/').next().unwrap_or(cidr);
        if let Ok(addr) = addr.parse() {
            out.push(BindAddr {
                interface: iface.to_string(),
                addr,
            });
        }
    }
    out
}

/// This machine's interface addresses, via `getifaddrs`. IPv6 link-local is
/// left out: it is not bindable without a scope id, which a placement record
/// has no way to carry.
fn local_bind_addrs() -> Vec<BindAddr> {
    let mut out = Vec::new();
    // SAFETY: getifaddrs hands back a linked list we only read, and free with
    // freeifaddrs exactly once. Each ifa_addr is checked for null and its
    // family before being cast to the matching sockaddr type.
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return out;
        }
        let mut cur = head;
        while !cur.is_null() {
            let ifa = &*cur;
            cur = ifa.ifa_next;
            if ifa.ifa_addr.is_null() || (ifa.ifa_flags & libc::IFF_UP as libc::c_uint) == 0 {
                continue;
            }
            let addr = match (*ifa.ifa_addr).sa_family as libc::c_int {
                libc::AF_INET => {
                    let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)))
                }
                libc::AF_INET6 => {
                    let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    let v6 = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                        continue;
                    }
                    IpAddr::V6(v6)
                }
                _ => continue,
            };
            let interface = std::ffi::CStr::from_ptr(ifa.ifa_name)
                .to_string_lossy()
                .into_owned();
            out.push(BindAddr { interface, addr });
        }
        libc::freeifaddrs(head);
    }
    out.sort_by(|a, b| (&a.interface, a.addr).cmp(&(&b.interface, b.addr)));
    out.dedup();
    out
}

fn local_hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: gethostname writes at most buf.len() bytes into buf.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc != 0 {
        return "localhost".to_string();
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Run a host tool to completion and return its stdout. A missing binary is
/// reported as such — "adb not installed" is a different answer from "adb
/// failed".
async fn tool_output(program: &str, args: &[&str]) -> Result<String> {
    tool_output_within(PROBE_TIMEOUT, program, args).await
}

async fn tool_output_within(timeout: Duration, program: &str, args: &[&str]) -> Result<String> {
    let mut cmd = Command::new(program);
    cmd.args(args).stdin(Stdio::null()).kill_on_drop(true);
    let out = match tokio::time::timeout(timeout, cmd.output()).await {
        Err(_) => bail!("`{program} {}` timed out after {timeout:?}", args.join(" ")),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("`{program}` is not installed (not on PATH)")
        }
        Ok(r) => r.with_context(|| format!("running `{program} {}`", args.join(" ")))?,
    };
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let why = if stderr.trim().is_empty() { stdout } else { stderr };
        bail!(
            "`{program} {}` failed ({}): {}",
            args.join(" "),
            out.status,
            why.trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

// ─── Mirror slot + component spec ───────────────────────────────────────────

/// Whether this mirror binds its compute slot to the device provider.
pub fn slot_declared(mirror: &crate::MirrorConfig) -> bool {
    matches!(
        mirror.providers.get(SLOT),
        Some(MirrorProviderSlot::Inline {
            kind: Provider::Device,
            ..
        })
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeviceSlot {
    target: HostKind,
    device: Option<String>,
}

fn device_slot(mirror: &crate::MirrorConfig) -> Result<DeviceSlot> {
    let fields = match mirror.providers.get(SLOT) {
        Some(slot @ MirrorProviderSlot::Inline { .. }) => slot.fields(),
        _ => bail!("mirror has no inline `[providers.compute]` slot of kind `device`"),
    };
    let target = fields
        .get("target")
        .and_then(|v| v.as_str())
        .context(
            "`[providers.compute] kind = \"device\"` needs `target` — one of ios-simulator, \
             ios-device, android-emulator, android-device",
        )?;
    let target = match HostKind::parse(target) {
        Some(HostKind::Local) | None => bail!(
            "`[providers.compute] target = \"{target}\"` is not a device target — use one of \
             ios-simulator, ios-device, android-emulator, android-device (a host process is \
             `kind = \"local-process\"`)"
        ),
        Some(k) => k,
    };
    let device = fields
        .get("device")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    Ok(DeviceSlot { target, device })
}

#[derive(Debug, Default, Deserialize)]
struct DeviceComponent {
    #[serde(default)]
    device: Option<DeviceSpec>,
}

#[derive(Debug, Default, Deserialize)]
struct DeviceSpec {
    #[serde(default)]
    pre_build: Option<Vec<String>>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    control: bool,
    #[serde(default)]
    ios: Option<IosApp>,
    #[serde(default)]
    android: Option<AndroidApp>,
}

#[derive(Debug, Deserialize)]
struct IosApp {
    bundle_id: String,
    #[serde(default)]
    app: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AndroidApp {
    package: String,
    activity: String,
    #[serde(default)]
    apk: Option<String>,
}

fn load_device_spec(ctx: &ReconcileCtx<'_>) -> Result<DeviceSpec> {
    let path = ctx.workload_dir().join("workload.toml");
    let src =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    parse_device_spec(&src).with_context(|| {
        format!(
            "component {} is bound to a `device` compute slot: {}",
            ctx.component.id,
            path.display()
        )
    })
}

fn parse_device_spec(src: &str) -> Result<DeviceSpec> {
    let parsed: DeviceComponent = toml::from_str(src).context("parsing workload.toml")?;
    parsed
        .device
        .context("declares no [device] section — add one with [device.ios] and/or [device.android]")
}

/// Pick the host a slot names out of an inventory.
///
/// With `device` set, it must match a host of the target kind by id or by name
/// (names case-insensitively). Without it, the first `Ready` host of the kind
/// wins, ordered by id so the choice is stable across runs; the caller notes
/// which one and what else was eligible, so a two-emulator machine is legible.
fn select_host<'a>(inv: &'a Inventory, slot: &DeviceSlot) -> Result<(&'a DeviceHost, Vec<&'a DeviceHost>)> {
    let mut of_kind: Vec<&DeviceHost> = inv.hosts.iter().filter(|h| h.kind == slot.target).collect();
    of_kind.sort_by(|a, b| a.id.cmp(&b.id));
    let describe = |hs: &[&DeviceHost]| {
        if hs.is_empty() {
            "none".to_string()
        } else {
            hs.iter()
                .map(|h| format!("{} [{}] ({:?})", h.name, h.id, h.state).to_lowercase())
                .collect::<Vec<_>>()
                .join(", ")
        }
    };
    let probe_notes = || {
        let failed: Vec<String> = inv
            .probes
            .iter()
            .filter(|p| !p.ok)
            .map(|p| format!("{}: {}", p.tool, p.detail.as_deref().unwrap_or("failed")))
            .collect();
        if failed.is_empty() {
            String::new()
        } else {
            format!(" — probe failures: {}", failed.join("; "))
        }
    };

    if let Some(want) = &slot.device {
        let host = of_kind
            .iter()
            .find(|h| h.id == *want || h.name.eq_ignore_ascii_case(want))
            .copied()
            .with_context(|| {
                format!(
                    "no {} matches `device = \"{want}\"`; known: {}{}",
                    slot.target,
                    describe(&of_kind),
                    probe_notes()
                )
            })?;
        let launchable = host.state == HostState::Ready
            || (host.state == HostState::Shutdown && host.kind == HostKind::IosSimulator);
        if !launchable {
            bail!(
                "{} `{}` [{}] is {:?}{}",
                slot.target,
                host.name,
                host.id,
                host.state,
                host.state_detail
                    .as_deref()
                    .map(|d| format!(": {d}"))
                    .unwrap_or_default()
            );
        }
        return Ok((host, Vec::new()));
    }

    let ready: Vec<&DeviceHost> = of_kind
        .iter()
        .filter(|h| h.state == HostState::Ready)
        .copied()
        .collect();
    let Some(first) = ready.first().copied() else {
        let hint = if slot.target == HostKind::IosSimulator {
            " — name one with `device = \"<name or udid>\"` and it will be booted"
        } else {
            ""
        };
        bail!(
            "no ready {} attached; known: {}{hint}{}",
            slot.target,
            describe(&of_kind),
            probe_notes()
        );
    };
    Ok((first, ready[1..].to_vec()))
}

// ─── Reconciler ─────────────────────────────────────────────────────────────

/// Launches a component's app on a device or simulator and supervises it.
#[derive(Debug, Default)]
pub struct DeviceReconciler {
    log_buf: Option<LogBuffer>,
}

impl DeviceReconciler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Stream into a caller-owned buffer, so it can be registered for polling
    /// before `up` returns — same contract as `LocalProcessReconciler`.
    pub fn with_log_buf(mut self, log_buf: LogBuffer) -> Self {
        self.log_buf = Some(log_buf);
        self
    }
}

/// What the supervisor watches to decide the app is still up.
#[derive(Debug, Clone)]
enum Watch {
    /// The launcher child itself: `simctl launch --console` and `devicectl
    /// device process launch --console` both block until the app exits.
    Launcher,
    /// `logcat --pid` outlives the app, so poll `pidof` instead.
    AndroidPid { serial: String, package: String, pid: String },
}

/// What undoing a launch takes, beyond stopping the launcher child.
#[derive(Debug, Clone)]
enum Cleanup {
    Simulator { udid: String, bundle_id: String },
    /// SIGTERM to `devicectl --console` is forwarded to the app; nothing more.
    Device,
    Android { serial: String, package: String, forward: Option<u16> },
}

impl Cleanup {
    async fn run(self) -> Result<()> {
        match self {
            Cleanup::Simulator { udid, bundle_id } => {
                // Already gone is fine: the app may have exited on its own.
                tool_output("xcrun", &["simctl", "terminate", &udid, &bundle_id])
                    .await
                    .ok();
            }
            Cleanup::Device => {}
            Cleanup::Android {
                serial,
                package,
                forward,
            } => {
                tool_output("adb", &["-s", &serial, "shell", "am", "force-stop", &package])
                    .await
                    .ok();
                if let Some(port) = forward {
                    tool_output(
                        "adb",
                        &["-s", &serial, "forward", "--remove", &format!("tcp:{port}")],
                    )
                    .await
                    .ok();
                }
            }
        }
        Ok(())
    }
}

struct Launched {
    child: Child,
    watch: Watch,
    cleanup: Cleanup,
    control: Option<ControlEndpoint>,
    notes: Vec<String>,
}

#[async_trait]
impl Reconciler for DeviceReconciler {
    fn kind(&self) -> &'static str {
        "device"
    }

    async fn up(&self, ctx: ReconcileCtx<'_>) -> Result<RunningWorkload> {
        ctx.materialize().await?;

        // Attached devices are attached to *this* machine. Same rule, same
        // reason, as `local-process`.
        if !matches!(ctx.mirror.shape, MirrorShape::Local) {
            bail!(
                "component {}: `device` is a dev-tier compute slot — mirror shape is {:?}, not \
                 `local`",
                ctx.component.id,
                ctx.mirror.shape,
            );
        }

        let slot = device_slot(ctx.mirror)?;
        let spec = load_device_spec(&ctx)?;
        let log_buf = self.log_buf.clone().unwrap_or_default();

        if let Some(argv) = &spec.pre_build {
            run_pre_build(ctx.workspace_root, argv, &log_buf).await?;
        }

        let inventory = enumerate().await;
        let (host, others) = select_host(&inventory, &slot)?;
        let host = host.clone();
        let mut notes = vec![format!(
            "host: {} [{}] ({}{})",
            host.name,
            host.id,
            host.kind,
            host.os_version
                .as_deref()
                .map(|v| format!(" {v}"))
                .unwrap_or_default()
        )];
        if !others.is_empty() {
            notes.push(format!(
                "also ready: {} — pin one with `device = \"…\"` in [providers.compute]",
                others
                    .iter()
                    .map(|h| format!("{} [{}]", h.name, h.id))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        let ident = sanitize_ident(&format!(
            "device-{}-{}-{}",
            ctx.service.name, ctx.env, ctx.component.id
        ));
        info!(host = %host.id, kind = %host.kind, ident = %ident, "launching device component");

        let launched = match host.kind {
            HostKind::IosSimulator => {
                launch_simulator(&ctx, &spec, &host, &ident, &log_buf).await?
            }
            HostKind::IosDevice => launch_ios_device(&ctx, &spec, &host, &log_buf).await?,
            HostKind::AndroidEmulator | HostKind::AndroidDevice => {
                launch_android(&ctx, &spec, &host, &ident, &log_buf).await?
            }
            HostKind::Local => unreachable!("device_slot rejects a local target"),
        };
        notes.extend(launched.notes);
        let Launched {
            mut child,
            watch,
            cleanup,
            control,
            ..
        } = launched;

        // Stream the launcher's output from the start, so a readiness failure
        // below has the app's own last words to show.
        let pumps = pump_output(&mut child, &log_buf);

        let fail = |what: String| {
            let log_buf = log_buf.clone();
            let cleanup = cleanup.clone();
            async move {
                cleanup.run().await.ok();
                let (lines, _) = log_buf.since(0).await;
                let tail: Vec<&String> = lines.iter().rev().take(20).collect();
                let tail: Vec<&str> = tail.into_iter().rev().map(String::as_str).collect();
                if tail.is_empty() {
                    anyhow::anyhow!("{what}")
                } else {
                    anyhow::anyhow!("{what}\n--- last output ---\n{}", tail.join("\n"))
                }
            }
        };

        if let Some(endpoint) = &control {
            match proc_control::wait_ready(endpoint, READY_TIMEOUT).await {
                ReadyOutcome::Ready(status) => {
                    notes.push(format!("control: {}", status.summary()));
                }
                ReadyOutcome::Terminal(status) => {
                    kill_gracefully(&mut child).await;
                    return Err(fail(format!(
                        "component {} reported `{}` on its control channel ({endpoint})",
                        ctx.component.id,
                        status.summary()
                    ))
                    .await);
                }
                ReadyOutcome::TimedOut { last } => {
                    kill_gracefully(&mut child).await;
                    let seen = match last {
                        Some(s) => format!("last reported `{}`", s.summary()),
                        None => format!(
                            "never answered — is the app serving {} ?",
                            proc_control::CONTROL_SOCK_ENV
                        ),
                    };
                    return Err(fail(format!(
                        "component {} was not ready within {READY_TIMEOUT:?} on {endpoint} ({seen})",
                        ctx.component.id
                    ))
                    .await);
                }
            }
        } else {
            tokio::time::sleep(ALIVE_GRACE).await;
            if !still_alive(&mut child, &watch).await {
                kill_gracefully(&mut child).await;
                return Err(fail(format!(
                    "component {} exited within {ALIVE_GRACE:?} of launching on {} [{}]",
                    ctx.component.id, host.name, host.id
                ))
                .await);
            }
            notes.push(if spec.control && host.control_rail == ControlRail::None {
                "control requested, but a physical iOS device has no status rail yet (W203 \
                 open question) — readiness is liveness only"
                    .to_string()
            } else {
                "no [device] control — readiness is liveness only".to_string()
            });
        }
        info!(host = %host.id, "device component ready");

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let supervisor = tokio::spawn(supervise(child, watch, pumps, shutdown_rx));

        Ok(into_running(
            "device",
            SLOT,
            None,
            None,
            Some(log_buf),
            shutdown_tx,
            supervisor,
        )
        .with_notes(notes)
        .with_control(control)
        .with_teardown(move || cleanup.run()))
    }
}

fn resolve_artifact(ctx: &ReconcileCtx<'_>, rel: &str) -> Result<PathBuf> {
    let p = Path::new(rel);
    let path = if p.is_absolute() {
        p.to_path_buf()
    } else {
        ctx.workspace_root.join(p)
    };
    if !path.exists() {
        bail!(
            "[device] artifact {} does not exist — build it first (a `pre_build` step runs \
             before install)",
            path.display()
        );
    }
    Ok(path)
}

async fn launch_simulator(
    ctx: &ReconcileCtx<'_>,
    spec: &DeviceSpec,
    host: &DeviceHost,
    ident: &str,
    log_buf: &LogBuffer,
) -> Result<Launched> {
    let ios = spec
        .ios
        .as_ref()
        .context("target is ios-simulator but workload.toml declares no [device.ios]")?;
    let udid = host.id.as_str();
    let mut notes = Vec::new();

    if host.state == HostState::Shutdown {
        log_buf.push(format!("booting simulator {} [{udid}]", host.name)).await;
        tool_output("xcrun", &["simctl", "bootstatus", udid, "-b"])
            .await
            .with_context(|| format!("booting simulator {udid}"))?;
        notes.push(format!("booted {}", host.name));
    }
    if let Some(app) = &ios.app {
        let app = resolve_artifact(ctx, app)?;
        log_buf.push(format!("installing {}", app.display())).await;
        tool_output("xcrun", &["simctl", "install", udid, &app.display().to_string()]).await?;
    }

    let mut env = spec.env.clone();
    let mut control = None;
    if spec.control {
        // The simulator shares the host filesystem: a host path works as is.
        let sock = ctx
            .workspace_root
            .join(".yah/jit/device")
            .join(ident)
            .join("control.sock");
        if let Some(dir) = sock.parent() {
            tokio::fs::create_dir_all(dir).await.ok();
        }
        tokio::fs::remove_file(&sock).await.ok();
        env.entry(proc_control::CONTROL_SOCK_ENV.to_string())
            .or_insert_with(|| sock.display().to_string());
        control = Some(ControlEndpoint::Socket(sock));
    }

    let mut cmd = Command::new("xcrun");
    cmd.args(["simctl", "launch", "--console", "--terminate-running-process", udid]);
    cmd.arg(&ios.bundle_id).args(&spec.args);
    // simctl passes SIMCTL_CHILD_<K> through to the app as <K>.
    for (k, v) in &env {
        cmd.env(format!("SIMCTL_CHILD_{k}"), v);
    }
    let child = spawn_piped(cmd, "xcrun simctl launch")?;
    Ok(Launched {
        child,
        watch: Watch::Launcher,
        cleanup: Cleanup::Simulator {
            udid: udid.to_string(),
            bundle_id: ios.bundle_id.clone(),
        },
        control,
        notes,
    })
}

async fn launch_ios_device(
    ctx: &ReconcileCtx<'_>,
    spec: &DeviceSpec,
    host: &DeviceHost,
    log_buf: &LogBuffer,
) -> Result<Launched> {
    let ios = spec
        .ios
        .as_ref()
        .context("target is ios-device but workload.toml declares no [device.ios]")?;
    let id = host.id.as_str();
    if let Some(app) = &ios.app {
        let app = resolve_artifact(ctx, app)?;
        log_buf.push(format!("installing {} on {}", app.display(), host.name)).await;
        tool_output(
            "xcrun",
            &["devicectl", "device", "install", "app", "--device", id, &app.display().to_string()],
        )
        .await?;
    }

    let mut cmd = Command::new("xcrun");
    cmd.args([
        "devicectl",
        "device",
        "process",
        "launch",
        "--console",
        "--terminate-existing",
        "--device",
        id,
    ]);
    if !spec.env.is_empty() {
        cmd.arg("--environment-variables")
            .arg(serde_json::to_string(&spec.env)?);
    }
    cmd.arg(&ios.bundle_id).args(&spec.args);
    let child = spawn_piped(cmd, "xcrun devicectl device process launch")?;
    Ok(Launched {
        child,
        watch: Watch::Launcher,
        cleanup: Cleanup::Device,
        control: None,
        notes: Vec::new(),
    })
}

async fn launch_android(
    ctx: &ReconcileCtx<'_>,
    spec: &DeviceSpec,
    host: &DeviceHost,
    ident: &str,
    log_buf: &LogBuffer,
) -> Result<Launched> {
    let android = spec.android.as_ref().with_context(|| {
        format!("target is {} but workload.toml declares no [device.android]", host.kind)
    })?;
    if !spec.args.is_empty() {
        bail!(
            "[device] args are not deliverable to an Android activity (it has no argv) — pass \
             values through [device.env], which arrive as intent string extras"
        );
    }
    let serial = host.id.as_str();
    if let Some(apk) = &android.apk {
        let apk = resolve_artifact(ctx, apk)?;
        log_buf.push(format!("installing {} on {}", apk.display(), host.name)).await;
        tool_output("adb", &["-s", serial, "install", "-r", &apk.display().to_string()]).await?;
    }

    let mut extras = spec.env.clone();
    let mut control = None;
    let mut forward = None;
    if spec.control {
        let name = format!("yah.{ident}");
        let port = tool_output(
            "adb",
            &["-s", serial, "forward", "tcp:0", &format!("localabstract:{name}")],
        )
        .await?;
        let port: u16 = port
            .trim()
            .parse()
            .with_context(|| format!("`adb forward tcp:0` printed `{}`, not a port", port.trim()))?;
        forward = Some(port);
        extras
            .entry(proc_control::CONTROL_SOCK_ENV.to_string())
            .or_insert_with(|| format!("@{name}"));
        control = Some(ControlEndpoint::Tcp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        )));
    }
    let cleanup = Cleanup::Android {
        serial: serial.to_string(),
        package: android.package.clone(),
        forward,
    };

    let component = format!("{}/{}", android.package, android.activity);
    let script = am_start_script(&component, &extras);
    let out = match tool_output("adb", &["-s", serial, "shell", &script]).await {
        Ok(out) => out,
        Err(e) => {
            cleanup.clone().run().await.ok();
            return Err(e.context(format!("launching {component}")));
        }
    };
    // `am start` exits 0 on most failures and says so on stdout.
    if let Some(err) = out.lines().find(|l| l.starts_with("Error")) {
        cleanup.clone().run().await.ok();
        bail!("`am start {component}` failed: {err}\n{}", out.trim());
    }

    let mut pid = None;
    for _ in 0..20 {
        if let Some(p) = android_pid(serial, &android.package).await {
            pid = Some(p);
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let Some(pid) = pid else {
        cleanup.clone().run().await.ok();
        bail!("{} started but no process is running for {}", component, android.package);
    };

    let mut cmd = Command::new("adb");
    cmd.args(["-s", serial, "logcat", "-v", "brief", &format!("--pid={pid}")]);
    let child = spawn_piped(cmd, "adb logcat")?;
    let notes = vec![format!("pid {pid}")];
    Ok(Launched {
        child,
        watch: Watch::AndroidPid {
            serial: serial.to_string(),
            package: android.package.clone(),
            pid,
        },
        cleanup,
        control,
        notes,
    })
}

/// The device-side `am start` command line. `adb shell` hands its arguments to
/// the device's shell as one string, so every value is quoted there.
fn am_start_script(component: &str, extras: &BTreeMap<String, String>) -> String {
    let mut s = format!("am start -S -W -n {}", sh_quote(component));
    for (k, v) in extras {
        s.push_str(&format!(" --es {} {}", sh_quote(k), sh_quote(v)));
    }
    s
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

async fn android_pid(serial: &str, package: &str) -> Option<String> {
    let out = tool_output("adb", &["-s", serial, "shell", "pidof", package])
        .await
        .ok()?;
    out.split_whitespace().next().map(str::to_string)
}

fn spawn_piped(mut cmd: Command, what: &str) -> Result<Child> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    cmd.spawn().with_context(|| format!("spawning `{what}`"))
}

/// Copy the child's stdout and stderr into the log buffer, line by line.
fn pump_output(child: &mut Child, log_buf: &LogBuffer) -> Vec<tokio::task::JoinHandle<()>> {
    fn pump<R: AsyncRead + Unpin + Send + 'static>(
        r: R,
        log_buf: LogBuffer,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut lines = BufReader::new(r).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                log_buf.push(line).await;
            }
        })
    }
    let mut out = Vec::new();
    if let Some(s) = child.stdout.take() {
        out.push(pump(s, log_buf.clone()));
    }
    if let Some(s) = child.stderr.take() {
        out.push(pump(s, log_buf.clone()));
    }
    out
}

async fn still_alive(child: &mut Child, watch: &Watch) -> bool {
    if !matches!(child.try_wait(), Ok(None)) {
        return false;
    }
    match watch {
        Watch::Launcher => true,
        Watch::AndroidPid {
            serial,
            package,
            pid,
        } => android_pid(serial, package).await.as_deref() == Some(pid.as_str()),
    }
}

/// SIGTERM first — `simctl`/`devicectl --console` forward catchable signals
/// to the app — then SIGKILL if it has not gone within a few seconds.
async fn kill_gracefully(child: &mut Child) {
    if let Some(pid) = child.id() {
        // SAFETY: plain kill(2) on a pid we spawned and have not yet reaped.
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
        if tokio::time::timeout(Duration::from_secs(3), child.wait())
            .await
            .is_ok()
        {
            return;
        }
    }
    child.kill().await.ok();
}

/// Health for the life of the workload: the supervisor task ends when the app
/// does, which is what `RunningWorkload::is_alive` reports.
async fn supervise(
    mut child: Child,
    watch: Watch,
    pumps: Vec<tokio::task::JoinHandle<()>>,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let mut tick = tokio::time::interval(ANDROID_PID_POLL);
    tick.tick().await;
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                kill_gracefully(&mut child).await;
                break;
            }
            status = child.wait() => {
                if let Ok(status) = status {
                    info!(%status, "device launcher exited");
                }
                break;
            }
            _ = tick.tick(), if matches!(watch, Watch::AndroidPid { .. }) => {
                if !still_alive(&mut child, &watch).await {
                    warn!("device app process is gone; stopping its log stream");
                    kill_gracefully(&mut child).await;
                    break;
                }
            }
        }
    }
    for p in pumps {
        p.await.ok();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Trimmed from real output on the machine this was written on
    // (2026-09-25): Xcode 26 simctl, devicectl with a paired iPad that was not
    // in range, and two running emulators.
    const SIMCTL: &str = r#"{
      "devices" : {
        "com.apple.CoreSimulator.SimRuntime.iOS-26-5" : [
          { "udid" : "6D1DA2F9-EA11-40C0-85CC-8849D85077BF", "isAvailable" : true,
            "state" : "Shutdown", "name" : "iPhone 17 Pro" },
          { "udid" : "AAAA0000-0000-0000-0000-000000000001", "isAvailable" : true,
            "state" : "Booted", "name" : "iPad Air" },
          { "udid" : "AAAA0000-0000-0000-0000-000000000002", "isAvailable" : false,
            "state" : "Shutdown", "name" : "Gone" }
        ],
        "com.apple.CoreSimulator.SimRuntime.watchOS-26-0" : [
          { "udid" : "AAAA0000-0000-0000-0000-000000000003", "isAvailable" : true,
            "state" : "Booted", "name" : "Apple Watch" }
        ]
      }
    }"#;

    const DEVICECTL: &str = r#"{ "result": { "devices": [ {
      "identifier": "CD97292E-F1E5-589B-898F-3039FCDA735E",
      "connectionProperties": { "pairingState": "paired", "tunnelState": "unavailable" },
      "deviceProperties": { "name": "Leif’s iPad", "osVersionNumber": "18.7.7" },
      "hardwareProperties": { "platform": "iOS", "reality": "physical",
        "udid": "00008112-001149E91423C01E", "marketingName": "iPad Pro" }
    }, {
      "identifier": "11111111-2222-3333-4444-555555555555",
      "connectionProperties": { "pairingState": "paired", "tunnelState": "connected" },
      "deviceProperties": { "name": "Test iPhone", "osVersionNumber": "26.0" },
      "hardwareProperties": { "platform": "iOS", "reality": "physical", "udid": "0000-PHONE" }
    }, {
      "identifier": "watch",
      "connectionProperties": { "pairingState": "paired", "tunnelState": "connected" },
      "deviceProperties": { "name": "Watch" },
      "hardwareProperties": { "platform": "watchOS", "reality": "physical", "udid": "0000-WATCH" }
    } ] } }"#;

    const ADB: &str = "List of devices attached\n\
        emulator-5554          device product:sdk_gphone64_arm64 model:sdk_gphone64_arm64 device:emu64a transport_id:3\n\
        R58M123ABC             unauthorized usb:1-1 transport_id:4\n\
        \n";

    const IP_ADDR: &str = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n\
        15: eth0    inet 10.0.2.15/8 brd 10.255.255.255 scope global eth0\\       valid_lft forever preferred_lft forever\n\
        16: wlan0    inet 10.0.2.16/24 brd 10.0.2.255 scope global wlan0\\       valid_lft forever preferred_lft forever\n";

    #[test]
    fn simctl_keeps_available_ios_simulators_and_maps_state() {
        let hosts = parse_simctl(SIMCTL).unwrap();
        assert_eq!(hosts.len(), 2, "unavailable + watchOS dropped: {hosts:?}");
        let phone = hosts.iter().find(|h| h.name == "iPhone 17 Pro").unwrap();
        assert_eq!(phone.state, HostState::Shutdown);
        assert_eq!(phone.os_version.as_deref(), Some("26.5"));
        assert_eq!(phone.kind, HostKind::IosSimulator);
        assert!(phone.shares_host_network);
        assert_eq!(phone.control_rail, ControlRail::UnixSocket);
        let pad = hosts.iter().find(|h| h.name == "iPad Air").unwrap();
        assert_eq!(pad.state, HostState::Ready);
    }

    #[test]
    fn devicectl_keeps_physical_ios_and_reads_the_tunnel() {
        let hosts = parse_devicectl(DEVICECTL).unwrap();
        assert_eq!(hosts.len(), 2, "watch dropped: {hosts:?}");
        let ipad = &hosts[0];
        assert_eq!(ipad.id, "00008112-001149E91423C01E");
        assert_eq!(ipad.name, "Leif\u{2019}s iPad");
        assert_eq!(ipad.state, HostState::Offline);
        assert!(ipad.state_detail.as_deref().unwrap().contains("tunnel unavailable"));
        assert_eq!(ipad.control_rail, ControlRail::None);
        assert_eq!(ipad.bind_addrs, None, "unknowable, not empty");
        assert_eq!(hosts[1].state, HostState::Ready);
    }

    #[test]
    fn adb_splits_emulators_from_devices_and_keeps_offline_ones() {
        let hosts = parse_adb_devices(ADB);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].kind, HostKind::AndroidEmulator);
        assert_eq!(hosts[0].name, "sdk gphone64 arm64");
        assert_eq!(hosts[0].state, HostState::Ready);
        assert!(!hosts[0].lanes.contains(&Lane::Lan), "W203: the emulator claims no LAN");
        assert_eq!(hosts[0].control_rail, ControlRail::AdbForward);
        assert_eq!(hosts[1].kind, HostKind::AndroidDevice);
        assert_eq!(hosts[1].state, HostState::Offline);
        assert_eq!(hosts[1].state_detail.as_deref(), Some("unauthorized"));
        assert!(hosts[1].lanes.contains(&Lane::Lan));
    }

    #[test]
    fn ip_addr_lines_become_bind_addrs() {
        let addrs = parse_ip_addr(IP_ADDR);
        let pairs: Vec<(String, String)> = addrs
            .iter()
            .map(|a| (a.interface.clone(), a.addr.to_string()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("lo".into(), "127.0.0.1".into()),
                ("eth0".into(), "10.0.2.15".into()),
                ("wlan0".into(), "10.0.2.16".into()),
            ]
        );
    }

    #[test]
    fn the_capability_record_serializes_in_kebab_case() {
        let host = &parse_adb_devices(ADB)[0];
        let v = serde_json::to_value(host).unwrap();
        assert_eq!(v["kind"], "android-emulator");
        assert_eq!(v["platform"], "android");
        assert_eq!(v["control_rail"], "adb-forward");
        assert_eq!(v["lanes"], serde_json::json!(["direct", "roster", "wan"]));
    }

    fn inventory() -> Inventory {
        let mut hosts = parse_simctl(SIMCTL).unwrap();
        hosts.extend(parse_adb_devices(ADB));
        let mut second = parse_adb_devices(ADB)[0].clone();
        second.id = "emulator-5580".into();
        hosts.push(second);
        Inventory {
            hosts,
            probes: vec![Probe {
                tool: "devicectl".into(),
                ok: false,
                detail: Some("timed out".into()),
            }],
        }
    }

    fn slot(target: HostKind, device: Option<&str>) -> DeviceSlot {
        DeviceSlot {
            target,
            device: device.map(str::to_string),
        }
    }

    #[test]
    fn select_picks_the_first_ready_host_by_id_and_names_the_rest() {
        let inv = inventory();
        let (host, others) = select_host(&inv, &slot(HostKind::AndroidEmulator, None)).unwrap();
        assert_eq!(host.id, "emulator-5554");
        assert_eq!(others.len(), 1);
        assert_eq!(others[0].id, "emulator-5580");
    }

    #[test]
    fn select_by_name_can_target_a_shutdown_simulator() {
        let inv = inventory();
        let (host, _) =
            select_host(&inv, &slot(HostKind::IosSimulator, Some("iphone 17 pro"))).unwrap();
        assert_eq!(host.state, HostState::Shutdown);
    }

    #[test]
    fn select_refuses_an_offline_device_and_says_why() {
        let inv = inventory();
        let err = select_host(&inv, &slot(HostKind::AndroidDevice, Some("R58M123ABC")))
            .unwrap_err()
            .to_string();
        assert!(err.contains("unauthorized"), "{err}");
    }

    #[test]
    fn select_with_nothing_ready_names_failed_probes() {
        let inv = inventory();
        let err = select_host(&inv, &slot(HostKind::IosDevice, None))
            .unwrap_err()
            .to_string();
        assert!(err.contains("no ready ios-device"), "{err}");
        assert!(err.contains("devicectl: timed out"), "{err}");
    }

    fn mirror(fields: &[(&str, &str)]) -> crate::MirrorConfig {
        let mut providers = BTreeMap::new();
        providers.insert(
            SLOT.to_string(),
            MirrorProviderSlot::Inline {
                kind: Provider::Device,
                fields: fields
                    .iter()
                    .map(|(k, v)| (k.to_string(), toml::Value::String(v.to_string())))
                    .collect(),
            },
        );
        crate::MirrorConfig {
            schema_version: 1,
            shape: MirrorShape::Local,
            providers,
            ingress: Default::default(),
            ingress_machines: Vec::new(),
            drivers: Default::default(),
            asset_aliases: Default::default(),
            build: Default::default(),
            workload: Default::default(),
        }
    }

    #[test]
    fn the_slot_is_read_from_the_mirror() {
        let m = mirror(&[("target", "ios-simulator"), ("device", "iPhone 17 Pro")]);
        assert!(slot_declared(&m));
        assert_eq!(
            device_slot(&m).unwrap(),
            slot(HostKind::IosSimulator, Some("iPhone 17 Pro"))
        );
        assert!(device_slot(&mirror(&[])).is_err());
        let err = device_slot(&mirror(&[("target", "local")])).unwrap_err().to_string();
        assert!(err.contains("local-process"), "{err}");
    }

    #[test]
    fn the_component_spec_parses_both_platforms() {
        let spec = parse_device_spec(
            r#"
            kind = "container"
            [device]
            control = true
            env = { RUST_LOG = "info" }
            [device.ios]
            bundle_id = "dev.yah.noisetable"
            [device.android]
            package = "dev.yah.noisetable"
            activity = "android.app.NativeActivity"
            apk = "target/x.apk"
            "#,
        )
        .unwrap();
        assert!(spec.control);
        assert_eq!(spec.ios.unwrap().bundle_id, "dev.yah.noisetable");
        assert_eq!(spec.android.unwrap().apk.as_deref(), Some("target/x.apk"));
        assert!(parse_device_spec("kind = \"container\"").is_err());
    }

    #[test]
    fn am_start_quotes_every_value_for_the_device_shell() {
        let mut extras = BTreeMap::new();
        extras.insert("YAH_CONTROL_SOCK".to_string(), "@yah.device-x".to_string());
        extras.insert("MSG".to_string(), "it's a test".to_string());
        assert_eq!(
            am_start_script("dev.yah.nt/android.app.NativeActivity", &extras),
            "am start -S -W -n 'dev.yah.nt/android.app.NativeActivity' \
             --es 'MSG' 'it'\\''s a test' --es 'YAH_CONTROL_SOCK' '@yah.device-x'"
        );
    }

    // ── Live: the real reconciler against real hardware ──────────────────
    //
    // Ignored by default — they need an attached emulator / a simulator and
    // they launch real apps. Stock system apps stand in for a component so no
    // build is involved:
    //
    //   YAH_DEVICE_LIVE_ANDROID=emulator-5580 cargo test -p yah-cloud --lib \
    //     reconciler::device::tests::live -- --ignored --nocapture
    //   YAH_DEVICE_LIVE_SIM="iPhone 17 Pro" cargo test … (same filter)

    fn live_service() -> crate::ServiceConfig {
        crate::ServiceConfig {
            schema_version: 1,
            name: "devlive".into(),
            address: crate::config::ServiceAddress::front_door("devlive.example"),
            description: None,
            components: vec![crate::ServiceComponent {
                mount: None,
                id: "app".into(),
                kind: "container".into(),
                path: "app".into(),
                role: "compute".into(),
                publishes: None,
                wave: 0,
                git: None,
                deploy: Default::default(),
                workload: None,
            }],
        }
    }

    async fn live_up_and_down(target: &str, device: &str, workload: &str) {
        let ws = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(ws.path().join("app")).unwrap();
        std::fs::write(ws.path().join("app/workload.toml"), workload).unwrap();
        let svc = live_service();
        let m = mirror(&[("target", target), ("device", device)]);
        let ctx = ReconcileCtx {
            workspace_root: ws.path(),
            service: &svc,
            component: &svc.components[0],
            mirror: &m,
            env: "dev",
            scope: crate::ProviderScope::singleton(),
        };
        let running = DeviceReconciler::new().up(ctx).await.expect("up");
        eprintln!("notes: {:#?}", running.notes);
        assert_eq!(running.kind, "device");
        assert!(running.dev_url.is_none());
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(running.is_alive(), "supervisor ended while the app should be up");
        running.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    #[ignore = "needs an attached Android emulator/device: YAH_DEVICE_LIVE_ANDROID=<serial>"]
    async fn live_android_launch_supervise_and_stop() {
        let Ok(serial) = std::env::var("YAH_DEVICE_LIVE_ANDROID") else {
            return;
        };
        let target = if serial.starts_with("emulator-") {
            "android-emulator"
        } else {
            "android-device"
        };
        live_up_and_down(
            target,
            &serial,
            "kind = \"container\"\n[device]\nenv = { R941 = \"it's live\" }\n\
             [device.android]\npackage = \"com.android.settings\"\nactivity = \".Settings\"\n",
        )
        .await;
        let pid = android_pid(&serial, "com.android.settings").await;
        assert_eq!(pid, None, "force-stop on teardown should leave no process");
    }

    #[tokio::test]
    #[ignore = "needs Xcode simulators: YAH_DEVICE_LIVE_SIM=<name or udid>"]
    async fn live_simulator_launch_supervise_and_stop() {
        let Ok(sim) = std::env::var("YAH_DEVICE_LIVE_SIM") else {
            return;
        };
        live_up_and_down(
            "ios-simulator",
            &sim,
            "kind = \"container\"\n[device]\n[device.ios]\nbundle_id = \"com.apple.mobilesafari\"\n",
        )
        .await;
    }

    #[test]
    fn local_bind_addrs_include_loopback() {
        let addrs = local_bind_addrs();
        assert!(
            addrs.iter().any(|a| a.addr == IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "{addrs:?}"
        );
    }
}

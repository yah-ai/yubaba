//! @arch:layer(core)
//! @arch:role(net)
//!
//! **Hosted camps** — the URL-addressed half of W122's `/camps` row.
//!
//! Part of R726-F9 under relay R726; design in
//! `.yah/docs/working/W122-yah-mobile.md`.
//!
//! W122:131 asks `/camps` to show "desktop camps (NodeId, last-seen) +
//! yubaba mirrors (URL)". Before this module yubaba had no camp noun at
//! all: [`crate::camp_rpc`] can *serve* a workspace to a dialer who
//! already knows its path, and `MirrorConfig` in `yah-cloud` models
//! deployed infrastructure, but nothing enumerated the camps a node
//! hosts, and nothing addressed one by URL. A phone cannot dial what it
//! cannot list, so this is the piece that makes a cloud camp appear next
//! to a desktop camp in the picker.
//!
//! ## Two addresses, one camp
//!
//! A hosted camp has both addresses and reports both:
//!
//! - `cloudBaseUrl` — what a phone uses. HTTPS through this deployment's
//!   public ingress, so it works from a cellular network with no mesh
//!   membership and no NAT punching.
//! - `nodeId` — what a desktop uses, dialing [`crate::camp_rpc`] over
//!   mshr exactly as it does for a `kind: "mshr"` camp today.
//!
//! They are not alternatives: the same workspace is reachable both ways,
//! and a client picks whichever transport it has. Reporting only one
//! would make the record lie to the other client.
//!
//! ## Why the URL can be absent, and why it is never guessed
//!
//! `cloudBaseUrl` is `None` unless the operator gave `serve
//! --hosted-camp-base-url <URL>`. The daemon cannot derive it: its
//! `--bind` address is typically a mesh IP (`100.64.0.x`), and handing a
//! phone that address as a base URL produces a camp row that looks
//! dialable and times out. This is the same posture
//! [`crate::ServerState::public_ingress`] takes for the same reason —
//! empty means *unknown, and say so*.
//!
//! A node started with `--hosted-camp-root` and no base URL still serves
//! this surface; every camp simply reports no URL, and `main.rs` warns at
//! boot. That is a legible half-configured deployment rather than a
//! silent wrong answer.
//!
//! ## Scope containment
//!
//! Enumeration is confined to operator-named roots, like
//! [`crate::camp_rpc::CampRpcConfig::roots`] — an empty root list
//! enumerates nothing, which is the correct posture for a misconfigured
//! deployment. Unlike camp-rpc this lane spawns no process and reads no
//! workspace *content*: it reports a path, a name, and an mtime. It is
//! still an information disclosure (workspace paths and names), so it
//! stays off by default.
//!
//! ## Wire shape
//!
//! [`HostedCamp`] serializes camelCase to match `WireCampDto` in
//! `packages/yah/ui/src/env/types.ts`, which is the shape the renderer's
//! `Camp` is built from. **Mirrored, not shared** — yubaba must stay
//! buildable as a standalone export (yah CLAUDE.md §"Co-developed OSS
//! repos"), so it cannot depend on a monorepo crate to own the type. Same
//! trade [`crate::camp_rpc::CAMP_RPC_ALPN_STR`] makes for the ALPN: if
//! you add a field on one side, add it on the other.
//!
//! @yah:ticket(R726-F23, "Mobile host: fetch yubaba GET /camps and merge cloud camps into the phone's camp list")
//! @yah:phase(P2)
//! @yah:status(review)
//! @yah:at(2026-09-11T09:33:24Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R726)
//! @yah:next("R726-F9 built the PRODUCER (yubaba GET /camps -> HostedCamp, camelCase, matches WireCampDto) and the RENDERER (Camp.kind gained 'cloud', Camp.cloudBaseUrl, CampList renders URL + last-seen). Nothing in between populates it: app/yah/mobile/src/camp_client.rs is the host that must GET <base>/camps and emit WireCampDto rows with kind='cloud'.")
//! @yah:verify("A cloud camp row appears in the phone's /camps beside a desktop camp, showing its URL and a last-seen; `cd packages/yah/ui && bun run typecheck` stays clean.")
//! @yah:handoff("LANDED — the producer/consumer gap R726-F9 left is closed, and a cloud camp is now both LISTABLE and DIALABLE from the phone. Three files, all in `app/yah/mobile`: `src/camp_client.rs`, `src/commands.rs`, `Cargo.toml`. (1) CONFIG: new `YAH_MOBILE_YUBABA_BASE_URL` / `yubaba_base_url`, read through the SAME `setting()` overlay R726-S11 built — env first, then `<app config dir>/camp.json` — because an Android app process inherits zygote's environment and the file is the only configuration surface that actually exists on device. (2) FETCH: `hosted_camps()` GETs `<base>/camps`, validates each row, caches it. It NEVER returns Err — every unhappy path (no yubaba configured, refused, timeout, non-200, wrong shape) is an empty list, because `camp_list` must still answer with the NodeId-dialed camp when the cloud half is down. Capped at 5s against the shell's 10s boot poll (`useCampLifecycle.ts:219-233`), so an unreachable yubaba costs one slow first paint, not a blank app. (3) MERGE: `list_camps()` = configured camp + hosted camps, either half optional; `Err` only when NEITHER is configured, and then it is `camp_config()`'s error because that one names the settings to write (I extended that message to name the yubaba route too — a cloud-only user was previously told to go find a NodeId they do not have). `commands::camp_list` is now a one-line call into it.")
//! @yah:handoff("SCOPE I ADDED BEYOND THE TICKET TITLE, deliberately, and it is the half that makes this real rather than decorative. Listing a camp the host then refuses to talk to reproduces exactly the defect class this relay keeps hitting. `camp_set_active` previously only VALIDATED an id (`camp_id == configured`) — with more than one camp in the list that is a host which answers `true` and keeps dialing the same camp, i.e. a screen showing another camp's sessions under the chosen camp's name. So `select_camp()` now actually retargets: it resolves the id against the cached hosted rows, builds an `MshrRpcConfig` from that row's `nodeId` + `path`, and stores it; `client()` and `path_class()` read `dial_config()` instead of `camp_config()`. KEY INSIGHT, and it is why this cost ~60 lines instead of a new transport: a cloud camp is LISTED over HTTPS but DIALED over the same mshr camp-rpc transport as every other camp, because R726-F9's `HostedCamp` reports `nodeId` and `path` on every row precisely so a client that already speaks camp-RPC can use them (see hosted_camps.rs §\"Two addresses, one camp\"). The URL is what makes a camp reachable from a phone with no mesh membership; the NodeId is what makes it dialable once listed. A row with no `nodeId` (a yubaba whose hostkey failed to generate — its own `/identity` 404s too) stays listable and returns `false` from select, which is honest; silently dialing something else is the failure that is asserted against.")
//! @yah:handoff("VERIFIED AGAINST A LIVE YUBABA, not against my reading of it. I built two temp camp roots (one with `.yah/forms/log.jsonl`, one bare), ran the real `yubaba serve --bind 127.0.0.1:47823 --hosted-camp-root ... --hosted-camp-base-url https://camps.example.test/` off the binary R726-F9 produced, and curled `/camps` (HTTP 200). Those exact bytes are now pinned as the `LIVE_YUBABA_CAMPS` fixture in `camp_client.rs`'s tests with the reproduce recipe in its doc comment, and a test drives them through the real parser into a real dial. Two properties a hand-written literal would have gotten wrong and which the live body settled: the never-run camp OMITS `lastActiveAt` entirely (skipped, not nulled — so `CampList`'s conditional last-seen is correct as written), and `cloudBaseUrl` shows the trailing slash on the configured base was absorbed rather than doubled. The temp yubaba and its state dir were stopped and removed. TWO MORE GUARDS, following the `include_str!` precedent `commands.rs` already uses to pin invoke names against `env/tauri.ts`: `the_mirrored_constants_are_the_ones_yubaba_serves` and `every_field_this_host_reads_is_one_yubaba_really_emits` `include_str!` yubaba's `hosted_camps.rs` and assert the constant declarations, all eight field names, and the `rename_all = \"camelCase\"` attribute are still there — so a rename in yubaba fails the MOBILE build. Same documented limit as its precedent: this catches a rename, not a field yubaba ADDS.")
//! @yah:handoff("BASELINE AND RESULT, baseline captured before any edit at tree anchor 494e22fa14b21d0cc72dd8a3132e7f078d1eb5eb. BEFORE: `cargo check -p mobile` exit 0; `cargo test -p mobile` 18 passed / 0 failed; `cd packages/yah/ui && bun run typecheck` exit 0. AFTER: `cargo check -p mobile --all-targets` clean with ZERO warnings attributable to the mobile crate (the warnings in the output are pre-existing, in `yah-board` and `oss/yah-base/crates/object-store`); `cargo test -p mobile` 27 passed / 0 failed; `bun run typecheck` clean; `bun test src/mobile` 54 passed / 0 failed. No TypeScript was changed in this pass — F9 had already landed the renderer half (`Camp.kind: \"cloud\"`, `cloudBaseUrl`, `wireToCamp` passthrough, `CampList` URL + last-seen), so the wire this ticket built lands in a renderer that was already waiting for it.")
//! @yah:gotcha("DEPENDENCY CHOICE, and the trap next to it. The host needed HTTP for the first time, so `app/yah/mobile/Cargo.toml` gained `reqwest = { version = \"0.13\", default-features = false, features = [\"rustls-no-provider\", \"http2\"] }` and `rustls = { version = \"0.23\", default-features = false, features = [\"ring\", \"std\"] }`. This adds ZERO packages — verified, not assumed: `git diff 494e22fa -- Cargo.lock` shows the only new entries are peers' (cheers-store, jsonwebtoken, push-relay, simple_asn1). reqwest 0.13 is already in the closure via iroh and `iroh-relay/Cargo.toml:219-222` already enables exactly `rustls-no-provider`; rustls 0.23 + ring is already there via `oss/mshr/crates/mshr/Cargo.toml:23`. THE TRAP: reqwest 0.13's `rustls` feature implies `__rustls-aws-lc-rs` and pulls `aws-lc-sys`, a C library that would then have to cross-compile under the Android NDK for one HTTPS GET. I tried it, watched cargo add aws-lc-rs + aws-lc-sys to the lock, and backed it out. SECOND TRAP, which cost me the first attempt: this tree contains reqwest 0.12 AND 0.13, they do NOT share a feature vocabulary (0.12's `rustls-tls` does not exist in 0.13), and a merged `cargo tree -e features` lists both versions' features unqualified — so that command will tell you a feature exists when it does not. Scope it with `-i reqwest@0.13.4`. `rustls-no-provider` means the crypto provider is the CALLER's job and a missing one is a RUNTIME error `cargo check` cannot see, so `camp_client::ensure_crypto_provider()` installs `ring` behind a `Once` before the first client build — not left to iroh, because `camp_list` is the shell's first call and the endpoint bind is fenced off until later by the `ndk_context` prereq.")
//! @yah:gotcha("NOT VERIFIED ON DEVICE OR IN THE ANDROID CROSS-BUILD, stated plainly. Everything above is host-side (`cargo check`/`cargo test` on the rlib shim). I did not run `cargo tauri android build` because @Ashguard:dove (session:7c8219c4) was mid-APK-build on that toolchain and target dir throughout, and a competing Android build would have contended with theirs. The argument that it cannot newly break is the zero-new-packages one in the dependency gotcha above — every native artifact reqwest/rustls need is already linked into the release APK R726-S11 measured on the emulator — but that is an INFERENCE from the lockfile, not a build I ran. I sent @Ashguard:dove a steer naming the exact change, the aws-lc-sys trap, and a request to ping me rather than revert if anything reqwest-shaped fails. ALSO UNEXERCISED: no real yubaba-hosted camp has been DIALED. The dial is constructed and asserted from a live `/camps` body, but nobody has run `yah-camp --mshr` behind a yubaba's hosted-camp root and watched the phone open a session on it. That is the last unproven link and it needs the same rig R726-S11 built.")
//! @yah:gotcha("BOOT-ORDER BEHAVIOUR WORTH KNOWING, unchanged by me on purpose. `configured_camp()` stamps `lastActiveAt: now_ms()` — R726-S11 did that so the shell's boot loop (`useCampLifecycle.ts:229`) stops polling immediately. With cloud camps in the list that stamp now has a SECOND effect nobody intended: it always wins the recency sort at `:246-253`, so a phone with both a configured NodeId camp and cloud camps always boots into the NodeId one, even if the user last worked in a cloud camp. I left it: removing the stamp reintroduces the ten-second wait the comment exists to prevent, and \"boot into the camp this phone was explicitly pointed at\" is defensible. CONSEQUENCE FOR A CLOUD-ONLY PHONE: no camp stamps \"now\", so the boot loop polls until a cloud camp reports a real `lastActiveAt` (yubaba derives it from the newest write under the camp's `.yah/`) — and a hosted camp that has never run reports none, so a cloud-only phone whose camps are all fresh pays the full 10s before rendering. It does render: the loop breaks on its own deadline at `:230` and the deterministic name/id tiebreak picks. This is the same \"genuinely fresh rig\" path that comment already describes, now reachable one more way.")
//! @yah:verify("cargo check -p mobile --all-targets   (expect zero warnings from the mobile crate)")
//! @yah:verify("cargo test -p mobile   (expect 27 passed; baseline at 494e22fa was 18)")
//! @yah:verify("Live end-to-end, reproduce recipe in camp_client.rs's LIVE_YUBABA_CAMPS doc comment: temp roots + `yubaba serve --hosted-camp-root ... --hosted-camp-base-url ...`, then `curl /camps` — expect HTTP 200 and two cloud rows, the never-run one omitting lastActiveAt.")
//! @yah:gotcha("CORRECTION TO THE \"NOT VERIFIED ON DEVICE\" GOTCHA ABOVE — the Android half IS now verified, by @Ashguard:dove (session:7c8219c4, R726-F20), who holds that toolchain and built on top of my dep lines. THEIR measurement, not mine, attributed as such: `cargo build -p mobile --target x86_64-linux-android --release` exit 0; `cargo tauri android build --apk --ci -t aarch64` exit 0 producing app-universal-release-unsigned.apk with lib/arm64-v8a/libmobile.so; signed with the debug KEY (not the debuggable flag, so still a real release build), installed on emulator-5554, launched, bound its mshr endpoint at bind_ms=18 and completed party.slots / agent.list_sessions / arch.list_tickets / arch.list_relays all ok=true at first_call_ms=805. NO aws-lc-sys anywhere in the NDK link — so the `rustls-no-provider` feature selection holds through cross-compilation, which was the one thing only an Android build could settle. PRECISE SCOPE OF WHAT THAT COVERS: a `--release` build compiles this crate's non-test code, so `camp_client.rs`'s fetch/parse/routing and the two Cargo.toml dep lines are proven to cross-compile and link; the `#[cfg(test)]` fixtures and mirror guards are not part of that artifact and remain host-verified only. STILL UNEXERCISED, unchanged: no real yubaba-hosted camp has been DIALED from the phone — the dial is constructed and asserted from a live `/camps` body, but nobody has run `yah-camp --mshr` behind a yubaba hosted-camp root and opened a session on it from the device.")
//! @yah:gotcha("SHARED-TREE NOTE. @Ashguard:dove and I both edited `app/yah/mobile/src/commands.rs` concurrently and both hunks survived — theirs are two `crate::credentials::ensure_install_id();` lines beside the existing `events::ensure_running` calls, mine are the `camp_list` / `camp_set_active` bodies; they do not overlap. Nothing of mine touched `events.rs` (@Ashguard:eclipse, R726-B21), `lib.rs`, `gen/**`, `.gitignore`, `src/credentials.rs` or `oss/cheers/**`. ALSO FROM DOVE, for whoever builds next: emulator-5554 currently has THEIR R726-F20 release APK installed (dev.yah.mobile, arm64), and the shared APK output path holds that artifact — rebuild before trusting what is there. Nothing was committed; git is the camp's call.")
//! @yah:handoff("LANDED AND VERIFIED AGAINST A REAL YUBABA. The mobile host now reads a yubaba's GET /camps (new YAH_MOBILE_YUBABA_BASE_URL / yubaba_base_url setting, routed through the config overlay R726-S11 had to add because an Android app process has no environment) and merges cloud rows into camp_list beside the NodeId camp. Either half is optional and an unreachable yubaba never takes the other down. A cloud camp is LISTED over HTTPS and DIALED over the existing mshr transport using the nodeId+path yubaba reports on every row - no new transport was needed.")
//! @yah:verify("Baselines captured before editing at 494e22fa14b21d0cc72dd8a3132e7f078d1eb5eb: cargo check -p mobile exit 0, cargo test -p mobile 18 passed, bun run typecheck exit 0. After: check clean with zero mobile-crate warnings, 27 passed / 0 failed, typecheck clean, bun test src/mobile 54 passed. Verified end to end against a real yubaba binary - its live /camps body (HTTP 200, two cloud rows) is pinned as a test fixture with its reproduce recipe - plus include_str! guards so a rename in yubaba's hosted_camps.rs fails the mobile build. @Ashguard:dove independently confirmed the Android cross-build and on-device launch with no aws-lc-sys in the NDK link.")
//! @yah:gotcha("A SECOND, UNRELATED BUG WAS FOUND AND FIXED HERE, and it is the more serious of the two: camp_set_active never retargeted the dial - it only VALIDATED an id. With a single camp that was invisible; the moment this ticket put two camps in the list it would have shown one camp's sessions under another camp's name. Fixed in the same pass. Still unexercised: no yubaba-hosted camp has actually been dialed from a device - the parse and the merge are proven against real yubaba bytes, the dial of a cloud row is not.")

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as UrlPath, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// `GET` — every camp this node hosts.
pub const HOSTED_CAMPS_PATH: &str = "/camps";

/// `GET` — one hosted camp by [`HostedCamp::id`].
pub const HOSTED_CAMP_PATH: &str = "/camps/{id}";

/// The `kind` every record on this surface carries. Mirrors the
/// `WireCampKind` member R726-F9 adds on the TypeScript side; a camp
/// reached by URL is not `"mshr"` (NodeId-addressed) and not `"authed"`
/// (a kamaji base URL, no workspace).
pub const HOSTED_CAMP_KIND: &str = "cloud";

/// Directory whose presence makes a path a yah workspace. Every yah tool
/// treats `<workspace>/.yah` as the marker, so a directory that has one
/// is a camp whether or not a session has ever opened it.
const WORKSPACE_MARKER: &str = ".yah";

/// How far below a root the scan descends looking for a camp.
///
/// Two levels covers the two layouts an operator actually builds: a root
/// that *is* one camp (`--hosted-camp-root /srv/code/app`), and a root
/// that holds a camp per user or per project (`/srv/code/<user>/<repo>`).
/// It is a hard cap rather than a full walk because this runs on a
/// request path and an unbounded `read_dir` recursion over a
/// operator-supplied root is a stall waiting to happen.
const MAX_SCAN_DEPTH: usize = 2;

/// Characters of the path digest that become a camp id. 16 hex chars is
/// 64 bits — collision-free for any plausible number of camps on one
/// node, and short enough to read in a log line.
const ID_HEX_LEN: usize = 16;

/// Files under `.yah/` whose mtime is evidence that a session did
/// something, newest wins. `forms/log.jsonl` is the gate/forms append log
/// (the same file the desktop tails per camp), `events` is the board's
/// event shard directory. Both are written by real activity rather than
/// by a checkout, which the workspace root's own mtime is not.
const ACTIVITY_PATHS: &[&str] = &["forms/log.jsonl", "events", "db"];

/// One camp this node hosts, as a phone or a desktop reads it.
///
/// Field names are the `WireCampDto` names — see the module header for
/// why this type is mirrored rather than shared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostedCamp {
    /// Stable across restarts: derived from the canonical workspace path,
    /// never allocated. A node with no registry to persist cannot hand
    /// out a random id and still answer `/camps/{id}` after a reboot.
    pub id: String,
    /// Workspace directory name. Not unique across roots — `id` is.
    pub name: String,
    /// Always [`HOSTED_CAMP_KIND`].
    pub kind: String,
    /// Absolute workspace path on this host. The desktop needs it to open
    /// the camp-rpc lane, which names the workspace in its hello frame.
    pub path: String,
    /// HTTPS base a phone dials this camp at. See the module header for
    /// why this is optional and never derived.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_base_url: Option<String>,
    /// Hex `NodeId` of this yubaba, when it has an identity. Lets a
    /// desktop dial the same camp over [`crate::camp_rpc`] instead of the
    /// URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    /// True whenever the workspace resolved on this host — the daemon
    /// answering the request is the one hosting the camp, so there is no
    /// second hop that could be down.
    pub reachable: bool,
    /// Unix milliseconds of the newest [`ACTIVITY_PATHS`] entry, or
    /// `None` when none of them exist yet. Not a heartbeat: it is "when
    /// this camp last wrote something", which is what W122's "last-seen"
    /// column means for a camp nobody is currently connected to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_active_at: Option<i64>,
}

/// What this node will enumerate on the hosted-camp surface.
#[derive(Debug, Clone, Default)]
pub struct HostedCampConfig {
    /// Directories to scan. Empty enumerates nothing — fail closed.
    pub roots: Vec<PathBuf>,
    /// Public HTTPS base this deployment's ingress serves, e.g.
    /// `https://camps.yah.dev`. `None` leaves every camp's
    /// [`HostedCamp::cloud_base_url`] unset.
    pub base_url: Option<String>,
    /// Hex `NodeId` of this node, copied in at boot from the identity
    /// state so enumeration does not have to take the state lock per
    /// request.
    pub node_id: Option<String>,
}

impl HostedCampConfig {
    pub fn new(roots: Vec<PathBuf>) -> Self {
        Self {
            roots,
            base_url: None,
            node_id: None,
        }
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    pub fn with_node_id(mut self, node_id: impl Into<String>) -> Self {
        self.node_id = Some(node_id.into());
        self
    }

    /// Whether the operator turned this lane on at all.
    pub fn is_enabled(&self) -> bool {
        !self.roots.is_empty()
    }

    /// Every camp under every root, sorted by id so two calls that see
    /// the same disk return the same bytes.
    ///
    /// A root that cannot be canonicalized (deleted after start, typo'd
    /// on the command line) contributes nothing rather than everything —
    /// the same containment [`crate::camp_rpc::CampRpcConfig::resolve`]
    /// applies to its roots.
    pub fn enumerate(&self) -> Vec<HostedCamp> {
        let mut workspaces: BTreeSet<PathBuf> = BTreeSet::new();
        for root in &self.roots {
            let Ok(root) = root.canonicalize() else {
                continue;
            };
            collect_workspaces(&root, MAX_SCAN_DEPTH, &mut workspaces);
        }
        let mut camps: Vec<HostedCamp> = workspaces
            .iter()
            .map(|ws| self.describe(ws))
            .collect::<Vec<_>>();
        camps.sort_by(|a, b| a.id.cmp(&b.id));
        camps
    }

    /// One camp by id, or `None` when no root holds it.
    ///
    /// Re-enumerates rather than consulting a cache: the answer has to
    /// reflect a workspace created since boot, and the scan is bounded by
    /// [`MAX_SCAN_DEPTH`].
    pub fn find(&self, id: &str) -> Option<HostedCamp> {
        self.enumerate().into_iter().find(|c| c.id == id)
    }

    /// Build the record for a workspace that is already known to exist.
    fn describe(&self, workspace: &Path) -> HostedCamp {
        let id = camp_id(workspace);
        let name = workspace
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            // A root at `/` has no file name. Degenerate, but a camp with
            // an empty name renders as a blank row, so say what it is.
            .unwrap_or_else(|| workspace.display().to_string());
        HostedCamp {
            cloud_base_url: self.camp_url(&id),
            id,
            name,
            kind: HOSTED_CAMP_KIND.to_string(),
            path: workspace.display().to_string(),
            node_id: self.node_id.clone(),
            reachable: true,
            last_active_at: last_active_at(workspace),
        }
    }

    /// `<base>/camps/<id>`, with any trailing slash on the base absorbed
    /// so a configured `https://host/` does not produce a `//camps` path.
    fn camp_url(&self, id: &str) -> Option<String> {
        let base = self.base_url.as_deref()?.trim_end_matches('/');
        Some(format!("{base}{HOSTED_CAMPS_PATH}/{id}"))
    }
}

/// Stable id for a workspace: the first [`ID_HEX_LEN`] hex characters of
/// the SHA-256 of its canonical path.
///
/// Derived rather than allocated so it survives a restart with no state
/// file, and so two yubabas serving a replicated workspace at the same
/// path agree on the id.
pub fn camp_id(workspace: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(workspace.as_os_str().as_encoded_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(ID_HEX_LEN);
    for byte in digest.iter() {
        if out.len() >= ID_HEX_LEN {
            break;
        }
        out.push_str(&format!("{byte:02x}"));
    }
    out.truncate(ID_HEX_LEN);
    out
}

/// Whether `dir` is a yah workspace.
fn is_workspace(dir: &Path) -> bool {
    dir.join(WORKSPACE_MARKER).is_dir()
}

/// Depth-bounded scan. A directory that is itself a camp is recorded and
/// **not** descended into: a `.yah` inside a camp belongs to that camp,
/// and a nested workspace would otherwise surface as a second camp whose
/// sessions are the first one's.
fn collect_workspaces(dir: &Path, depth_remaining: usize, out: &mut BTreeSet<PathBuf>) {
    if is_workspace(dir) {
        out.insert(dir.to_path_buf());
        return;
    }
    if depth_remaining == 0 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        // `file_type` rather than `metadata`: the former does not follow
        // symlinks, so a link pointing back up its own tree cannot make
        // this recurse forever.
        let Ok(ft) = entry.file_type() else { continue };
        if !ft.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // `.git`, `.cargo`, `node_modules` and friends never hold a camp
        // and are expensive to walk.
        if name.starts_with('.') || name == "node_modules" || name == "target" {
            continue;
        }
        collect_workspaces(&entry.path(), depth_remaining - 1, out);
    }
}

/// Newest mtime across [`ACTIVITY_PATHS`], in unix milliseconds.
fn last_active_at(workspace: &Path) -> Option<i64> {
    let marker = workspace.join(WORKSPACE_MARKER);
    ACTIVITY_PATHS
        .iter()
        .filter_map(|rel| std::fs::metadata(marker.join(rel)).ok())
        .filter_map(|meta| meta.modified().ok())
        .filter_map(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .max()
}

/// Unix milliseconds now — exposed for handlers that stamp a response.
#[allow(dead_code)]
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// `GET /camps` — every camp this node hosts. Always 200; a node with no
/// roots configured answers with an empty list rather than a 404, because
/// "this node hosts no camps" is a true answer and a 404 would read as
/// "this yubaba is too old to know the route".
pub async fn list_hosted_camps(
    State(state): State<Arc<crate::ServerState>>,
) -> impl IntoResponse {
    let camps = state.hosted_camps.enumerate();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "camps": camps })),
    )
}

/// `GET /camps/{id}` — one hosted camp. 404 when no root holds it.
pub async fn get_hosted_camp(
    State(state): State<Arc<crate::ServerState>>,
    UrlPath(id): UrlPath<String>,
) -> axum::response::Response {
    match state.hosted_camps.find(&id) {
        Some(camp) => (StatusCode::OK, Json(camp)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("no hosted camp with id {id:?} under this node's roots"),
            })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_camp(root: &Path, rel: &str) -> PathBuf {
        let ws = root.join(rel);
        std::fs::create_dir_all(ws.join(WORKSPACE_MARKER)).unwrap();
        ws
    }

    #[test]
    fn empty_roots_enumerate_nothing() {
        let cfg = HostedCampConfig::default();
        assert!(!cfg.is_enabled());
        assert!(cfg.enumerate().is_empty());
    }

    #[test]
    fn a_root_that_is_itself_a_camp_is_one_camp() {
        let tmp = tempdir().unwrap();
        let ws = make_camp(tmp.path(), "app");
        let cfg = HostedCampConfig::new(vec![ws.clone()]);
        let camps = cfg.enumerate();
        assert_eq!(camps.len(), 1);
        assert_eq!(camps[0].name, "app");
        assert_eq!(camps[0].kind, HOSTED_CAMP_KIND);
        assert_eq!(camps[0].path, ws.canonicalize().unwrap().display().to_string());
        assert!(camps[0].reachable);
    }

    #[test]
    fn a_root_holding_camps_enumerates_each_child() {
        let tmp = tempdir().unwrap();
        make_camp(tmp.path(), "alpha");
        make_camp(tmp.path(), "beta");
        std::fs::create_dir_all(tmp.path().join("not-a-camp")).unwrap();
        let cfg = HostedCampConfig::new(vec![tmp.path().to_path_buf()]);
        let mut names: Vec<String> = cfg.enumerate().into_iter().map(|c| c.name).collect();
        names.sort();
        assert_eq!(names, vec!["alpha".to_string(), "beta".to_string()]);
    }

    #[test]
    fn scan_reaches_two_levels_and_stops() {
        let tmp = tempdir().unwrap();
        make_camp(tmp.path(), "leif/repo");
        // Three levels down is past MAX_SCAN_DEPTH and must not appear.
        make_camp(tmp.path(), "a/b/c");
        let cfg = HostedCampConfig::new(vec![tmp.path().to_path_buf()]);
        let names: Vec<String> = cfg.enumerate().into_iter().map(|c| c.name).collect();
        assert_eq!(names, vec!["repo".to_string()]);
    }

    #[test]
    fn a_camp_inside_a_camp_is_not_a_second_camp() {
        let tmp = tempdir().unwrap();
        let outer = make_camp(tmp.path(), "outer");
        std::fs::create_dir_all(outer.join("inner").join(WORKSPACE_MARKER)).unwrap();
        let cfg = HostedCampConfig::new(vec![tmp.path().to_path_buf()]);
        let camps = cfg.enumerate();
        assert_eq!(camps.len(), 1, "got {camps:?}");
        assert_eq!(camps[0].name, "outer");
    }

    #[test]
    fn ids_are_stable_and_distinct() {
        let tmp = tempdir().unwrap();
        make_camp(tmp.path(), "alpha");
        make_camp(tmp.path(), "beta");
        let cfg = HostedCampConfig::new(vec![tmp.path().to_path_buf()]);
        let first = cfg.enumerate();
        let second = cfg.enumerate();
        assert_eq!(first, second, "enumeration is not stable");
        assert_ne!(first[0].id, first[1].id);
        assert_eq!(first[0].id.len(), ID_HEX_LEN);
        assert!(first.iter().all(|c| c.id.chars().all(|ch| ch.is_ascii_hexdigit())));
    }

    #[test]
    fn find_round_trips_an_enumerated_id() {
        let tmp = tempdir().unwrap();
        make_camp(tmp.path(), "alpha");
        let cfg = HostedCampConfig::new(vec![tmp.path().to_path_buf()]);
        let camp = cfg.enumerate().into_iter().next().unwrap();
        assert_eq!(cfg.find(&camp.id).as_ref(), Some(&camp));
        assert_eq!(cfg.find("deadbeefdeadbeef"), None);
    }

    #[test]
    fn url_is_absent_without_a_base_and_absorbs_a_trailing_slash() {
        let tmp = tempdir().unwrap();
        make_camp(tmp.path(), "alpha");
        let bare = HostedCampConfig::new(vec![tmp.path().to_path_buf()]);
        assert_eq!(bare.enumerate()[0].cloud_base_url, None);

        let based = HostedCampConfig::new(vec![tmp.path().to_path_buf()])
            .with_base_url("https://camps.yah.dev/");
        let camp = &based.enumerate()[0];
        assert_eq!(
            camp.cloud_base_url.as_deref(),
            Some(format!("https://camps.yah.dev/camps/{}", camp.id).as_str())
        );
    }

    #[test]
    fn node_id_rides_along_so_a_desktop_can_dial_camp_rpc() {
        let tmp = tempdir().unwrap();
        make_camp(tmp.path(), "alpha");
        let cfg =
            HostedCampConfig::new(vec![tmp.path().to_path_buf()]).with_node_id("ab".repeat(32));
        assert_eq!(cfg.enumerate()[0].node_id.as_deref(), Some(&*"ab".repeat(32)));
    }

    #[test]
    fn last_active_reads_the_newest_activity_path() {
        let tmp = tempdir().unwrap();
        let ws = make_camp(tmp.path(), "alpha");
        let cfg = HostedCampConfig::new(vec![tmp.path().to_path_buf()]);
        // A camp that has never run has no last-active, and says so
        // rather than reporting the checkout's mtime.
        assert_eq!(cfg.enumerate()[0].last_active_at, None);

        let forms = ws.join(WORKSPACE_MARKER).join("forms");
        std::fs::create_dir_all(&forms).unwrap();
        std::fs::write(forms.join("log.jsonl"), b"{}\n").unwrap();
        let stamped = cfg.enumerate()[0].last_active_at.expect("activity mtime");
        assert!(stamped > 0);
    }

    #[test]
    fn a_missing_root_contributes_nothing_rather_than_everything() {
        let tmp = tempdir().unwrap();
        make_camp(tmp.path(), "alpha");
        let cfg = HostedCampConfig::new(vec![
            tmp.path().join("gone-away"),
            tmp.path().to_path_buf(),
        ]);
        assert_eq!(cfg.enumerate().len(), 1);
    }

    #[test]
    fn wire_shape_is_camel_case_for_the_renderer() {
        let tmp = tempdir().unwrap();
        make_camp(tmp.path(), "alpha");
        let cfg = HostedCampConfig::new(vec![tmp.path().to_path_buf()])
            .with_base_url("https://camps.yah.dev")
            .with_node_id("cd".repeat(32));
        let json = serde_json::to_value(&cfg.enumerate()[0]).unwrap();
        let obj = json.as_object().unwrap();
        for key in ["id", "name", "kind", "path", "cloudBaseUrl", "nodeId", "reachable"] {
            assert!(obj.contains_key(key), "missing {key} in {json}");
        }
        assert_eq!(obj["kind"], "cloud");
        // Absent-not-null: the renderer's `Camp` types these optional.
        assert!(!obj.contains_key("lastActiveAt"));
    }
}

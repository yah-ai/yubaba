//! `yah-yubaba` — per-machine infrastructure daemon.
//!
//! Modes:
//!
//! - `serve` — long-running HTTP daemon (systemd unit on the machine).
//!   Pass `--raft-node-id` + `--raft-dir` to enable Phase 2 raft coordination.
//! - `register-hostkey <path>` — one-shot: parse an SSH pubkey file,
//!   compute its fingerprint, write it to the state file.
//! - `raft status|peers|transfer-leader` — operator commands for the
//!   raft coordination layer (Phase 2, R040-F20).
//!
//! @yah:ticket(R471-B7, "yah-yubaba container launches without `serve` subcommand → prints help, exits 2, restart-loops")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-06T20:35:57Z)
//! @yah:status(review)
//! @yah:parent(R471)
//! @yah:severity(P1)
//! @yah:verify("Fresh container reaches `kamaji UDS listening` AND stays running >30s with `docker inspect` showing State.Status=running (not restarting).")
//! @yah:verify("RestartCount stops climbing.")
//! @yah:verify("Doubles as the verify fixture for R471-T5 / R471-F6 — once fixed, induce a different crash (e.g. bad config) to keep exercising the status pipeline.")
//! @yah:gotcha("Discovered as the proximate cause of the pond crash-loop that motivated R471. Container 37a1652... with image ghcr.io/yah-ai/yah-yubaba:latest: 14 restarts in 1m, exit code 2, policy=unless-stopped. Entry runs `yah-yubaba` with no subcommand. Either the Dockerfile CMD/ENTRYPOINT dropped `serve` or the clap root recently lost the implicit default. Check oss/qed/crates/qed/images/yah-yubaba/Dockerfile + pond-supervise.sh, the wrapper script that exec's yah-yubaba.")
//! @yah:handoff("Root cause: `Cli::cmd: Cmd` was a required subcommand — a bare `yah-yubaba` invocation made clap print help and exit 2. That's what's crash-looping the pond container (Dockerfile CMD = pond-supervise.sh → `yah-yubaba ${YAH_WARDEN_ARGS:-}` with no subcommand).")
//! @yah:handoff("Fix is two-pronged: (1) main.rs flips `cmd` to `Option<Cmd>` and treats `None` as `Cmd::Serve` with every field at its declared default via a new `default_serve()` helper kept in lockstep with the variant; (2) pond-supervise.sh now invokes `yah-yubaba serve` explicitly so YAH_WARDEN_ARGS attaches unambiguously to the serve subcommand. Either fix alone would unstick pond; both ship for defense in depth.")
//! @yah:handoff("Verified locally: `/Users/user/ss/yah/target/debug/yah-yubaba` (no args) logs `INFO yah-yubaba serve` then `yah-yubaba listening` on 0.0.0.0:7443 (debug build is featureless so /workloads/deploy stays in stub mode — expected); `yah-yubaba --help` still lists serve/register-hostkey/raft. cargo test -p yubaba --lib → 96 passed.")
//! @yah:handoff("Image rebuild needed before the live pond container actually picks this up: `.yah/qed/build-yah-yubaba.toml` (arm64 local) rebuilds ghcr.io/yah-ai/yah-yubaba:latest into the local docker daemon; the GHA image-yah-yubaba job needs to retag for amd64 once main lands. Until that ships, the pond container at 37a1652... will keep crash-looping on the old image — that's a deploy step, not a code fix.")
//! @yah:next("Sign-off: skim main.rs::default_serve to confirm field-for-field parity with Cmd::Serve—if either drifts in future, the default-boot path silently picks the wrong value. Consider a compile-time assertion (Cmd::Serve::default() trait + derive) in a follow-up if drift becomes a worry.")
//! @yah:next("Rebuild + push ghcr.io/yah-ai/yah-yubaba:latest so the pond container actually picks up the fix — this is the gating step for R471's outer verify (`Restarting (2) · N restarts in 1m` chip on the Services grid). Until then, B7's code is correct but the live fixture stays broken.")
//! @yah:verify("cargo build -p yubaba --bin yah-yubaba  # clean")
//! @yah:verify("cargo test -p yubaba --lib  # 96 passed")
//! @yah:verify("./target/debug/yah-yubaba  # logs 'yah-yubaba serve' + 'yah-yubaba listening', does NOT print help and exit 2")
//! @yah:verify("./target/debug/yah-yubaba --help  # still lists subcommands (root-level help unchanged)")
//! @yah:verify("Rebuild + reload the pond image (`yah qed run build-yah-yubaba` or equivalent), then `docker inspect <pond-yubaba>` shows State.Restarting=false and RestartCount stops climbing.")
//!
//! @yah:ticket(R590-B9, "yubaba GET /workloads/{id}/state returns 404 for kamaji-deployed forge workloads — CLI can't poll state, marks fleet runs Failed")
//! @yah:at(2026-07-12T15:24:47Z)
//! @yah:status(review)
//! @yah:assignee(agent:claude)
//! @yah:parent(R590)
//! @yah:severity(blocks-on-box-green)
//! @yah:next("Register kamaji-dispatched workloads in yubaba's state map at deploy time (or proxy GET /workloads/{id}/state through the kamaji UDS list/state RPC, which IS attached), so the ident is queryable for the run's lifetime and terminal state (Exited 0 / Failed) is observable. Cross-check R590-F2's MeshYubabaClient::connect_logs which polls this endpoint for terminal status.")
//! @yah:verify("After deploying a forge workload, GET http://<node>:7443/workloads/{ident}/state returns the live state (not 404) through to a terminal Exited/Failed; `yah qed run rusty-v8-musl` reflects the container's real exit instead of failing on the 404 poll.")
//! @yah:gotcha("PROVEN live (2026-07-11): a workload deploy succeeds (kamaji logs 'containerd workload deployed container_id=forge-... pid=...'), but the qed CLI's state poll gets `404 Not Found {\"error\":\"workload not found\"}` from GET /workloads/{id}/state on the SAME ident — so RemoteForgeDriver marks the run Failed regardless of the container's real outcome. Even a green long build would be reported Failed. The deploy goes yubaba->kamaji->containerd, but yubaba's queryable state registry doesn't hold the deployed ident.")
//!
//! @yah:ticket(R870-B20, "A door cannot have a cert store without an ACME issuer config — parse_issuer_config owns CertStoreConfig, so YUBABA_CERT_STORE_* is silently inert alone")
//! @yah:status(review)
//! @yah:at(2026-09-09T08:21:38Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R870)
//! @yah:severity(medium)
//! @yah:next("Hoist CertStoreConfig::parse to its own call in main.rs and pass the store INTO the issuer rather than reading it out — the issuer only wants it as a mirror (acme_issuer.rs `mirror_pair`), so IssuerConfig::cert_store can be deleted rather than made Option-of-Option. Per the workspace's below-1.0 rule: change the signature and fix the call sites, do not add a fallback beside it. The workaround R870-T17 shipped is that us-west-001 now carries a 40-acme-issuer.conf it does not otherwise need, which makes it a third standby candidate for the fleet-cert issuer lock; that drop-in can be removed once this lands.")
//! @yah:verify("A node with YUBABA_CERT_STORE_BUCKET set and YUBABA_ACME_DOMAIN unset logs 'cert store: per-domain TLS material resolves from the object store...' and spawns the demux publisher. A node with neither logs nothing new. Unit test over the pure parse functions, no env.")
//! @yah:gotcha("MEASURED 2026-09-09 on us-west-001 (R870-T17). CertStoreConfig::parse is called from acme_issuer::parse_issuer_config (acme_issuer.rs:400) and surfaces only as IssuerConfig::cert_store; main.rs:928 reads the store off `if let Ok(Some(cfg)) = parse_issuer_config(...)`. parse_issuer_config returns Ok(None) whenever YUBABA_ACME_DOMAIN is unset. So a door that sets YUBABA_CERT_STORE_BUCKET/_ACCOUNT_ID but has no issuer drop-in gets NO cert store, and therefore no route publisher, no per-domain issuer and no tenant-passway reconciler — with not one log line saying why. us-west-001 was in exactly that state (east and south got 40-acme-issuer.conf on 2026-09-05, west never did). This directly contradicts demux_routes.rs's own module doc and main.rs:941's comment, both of which say the publisher is spawned outside the raft branch precisely because 'the node holding :443 for a free tier need not be a raft member'. It equally need not be an ACME issuer.")
//! @yah:handoff("SHIPPED AS SPECIFIED. CertStoreConfig::parse is now its own call in main.rs (the `match yubaba::cert_store::CertStoreConfig::parse(...)` block at main.rs:932-1026) and `IssuerConfig::cert_store` is DELETED, not made optional — no fallback beside the old path. The store, the demux route publisher, the per-domain issuer and (further down) the tenant-passway reconciler now all hang off YUBABA_CERT_STORE_BUCKET alone; YUBABA_ACME_DOMAIN is no longer in that path. acme_issuer::spawn/run gained a fifth parameter `mirror: Option<Arc<ObjectCertStore>>` and main.rs:1437-1440 hands it `shared_state.cert_store.clone()` — the issuer no longer parses or connects a store of its own, it is handed the node's. Three main.rs hunks only (932-947, 1018-1026, 1437-1440), deliberately tight because @Ashguard is editing demux_routes.rs + lib.rs for R870-F19 in the same tree; I touched neither.")
//! @yah:handoff("WIDER THAN THE TITLE, one discovered fix: the ACME directory default (\"staging\") was duplicated in FOUR places — acme_issuer.rs, domain_issuer.rs, domain_admin.rs (which carried the DIRECTORY_ENV/DEFAULT_DIRECTORY consts plus a doc comment saying \"kept equal deliberately\"), and it would have become a fifth copy in main.rs, since main now needs the directory URL to connect the store without an issuer config. That value names the store's issuer path segment, so a drift between two copies means a reader addressing an empty prefix. Given one owner instead: cert_store.rs now holds DIRECTORY_ENV, DEFAULT_DIRECTORY and `pub fn acme_directory(get) -> AcmeDirectory` (cert_store.rs:300-324), and all four callers go through it. domain_admin's copies of the consts were deleted; nothing outside that module referenced them.")
//! @yah:verify("BASELINE MEASURED FIRST on the dispatch anchor 718dfacba1f6bfc8f0587713a5d30bc15ac21f2f: `cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib --bins` = 864 passed / 0 failed / 0 ignored (the bin target has 0 tests). AFTER: 865 passed / 0 failed / 0 ignored. Net +1 is exactly accounted for: 3 tests deleted from acme_issuer (cert_store_mirror_is_off_unless_a_bucket_is_named, cert_store_mirror_parses_from_the_issuer_env, a_bucket_without_an_account_id_is_a_config_error — all asserted a field that no longer exists), 4 added. Unit tests over the pure parse functions with no env, as the ticket required: acme_issuer::a_cert_store_parses_with_no_acme_issuer_configured (the regression itself — bucket+account with no YUBABA_ACME_DOMAIN yields Some(store) AND None issuer), acme_issuer::issuer_config_no_longer_reads_the_cert_store_env (the reverse coupling), cert_store::a_bucket_without_an_account_id_is_rejected (the half-configured error, moved to where it now lives), cert_store::the_acme_directory_defaults_to_staging_and_is_overridable. `cargo check -p yubaba --all-targets` is clean — no errors and no warnings in any of the five files touched.")
//! @yah:verify("NOT RUN: the yubaba integration binaries (`--test main`, domain_onboarding_endpoint). They compile clean under `--all-targets` and nothing in them spawns an issuer or a cert store, so the change cannot reach them; the raft suite there is also the documented pre-existing flake (see domain_admin.rs's R852-F2 gotcha). Also NOT run: any fleet node. The two behavioural claims in the ticket's verify line are structural after this change — the info line \"cert store: per-domain TLS material resolves from the object store...\" and the demux publisher spawn are now both inside the CertStoreConfig::parse branch, which no longer consults any YUBABA_ACME_* key; a node with neither variable takes the `Ok(None) => {}` arm and logs nothing new.")
//! @yah:cleanup("NOW REMOVABLE, NOT TOUCHED BY ME (live fleet action, explicitly out of scope): us-west-001's `40-acme-issuer.conf`, the R870-T17 workaround. It exists only so parse_issuer_config would return Ok(Some(..)) and let west reach a cert store; after this change west gets its store from YUBABA_CERT_STORE_BUCKET alone. Removing it changes exactly one other thing: west stops being a third standby candidate for the fleet-cert issuer raft lock, which is the reason it should go rather than a side effect to tolerate.")
//! @yah:gotcha("ONE DELIBERATE BEHAVIOUR CHANGE beyond the decoupling: the issuer used to build its own ObjectCertStore from its own config, so a bucket that failed to connect at boot got a second connect attempt when the issuer started. It now shares the node's store, so a failed connect means no mirror for that process lifetime — main logs \"cert store unavailable — per-domain TLS material will not resolve on this node\" at boot, and the issuer keeps writing to raft exactly as before (a missing mirror has never been allowed to stop issuance). Also new: a half-configured store (BUCKET set, ACCOUNT_ID missing) used to fail parse_issuer_config and take the whole issuer down with it; it is now reported on its own line (\"cert store config invalid — no per-domain TLS material on this node\") and leaves the issuer running.")
//! @yah:verify("LEADER RE-VERIFICATION (session:abde2cbb, 2026-09-09), independent of the courier. `cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib --bins` = 865 passed / 0 failed, matching the courier's count against the 864 baseline it measured first on anchor 718dfacb. Then checked the two properties that mattered more than the count, because this ticket was ABOUT a hidden coupling and a shim would have preserved it: (1) `IssuerConfig::cert_store` is GONE — a grep of acme_issuer.rs for the field returns nothing, so the store is passed IN as a mirror rather than read back out, which is what the ticket asked for rather than an Option-of-Option; (2) `acme_directory` now has exactly one definition, at cert_store.rs:321. That second one was discovered work, not the brief: the ACME directory default was already duplicated in FOUR places and the hoist would have made main.rs a fifth, on a value that names the store's issuer path segment — so a drift between copies means a reader addressing an empty prefix. Collapsing it to one owner was the right call and is exactly the \"change the abstraction rather than shortcut around it\" case. A PostToolUse tree-drift warning fired on my run naming oss/yubaba/crates/cloud/src/reconciler/ingress.rs, which is R870-F16's file and not on this ticket's path, so the result stands.")

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use yubaba::cluster_policy::ClusterPolicy;
use yubaba::failure_detector::RaftHeartbeatDetector;
use yubaba::lease_detector::{LeaseFailureDetector, RpoWatermarkRegistry};
use yubaba::{identity, serve, ServerState, SovereignRole, DEFAULT_BIND, DEFAULT_STATE_PATH};

/// Which [`ClusterPolicy`] this daemon runs under — the operator's one-time
/// deployment choice (R118-T9).
///
/// This enum exists **only** to spell the choice on the command line. It is
/// converted to a `ClusterPolicy` value once, here, and never stored: nothing
/// downstream can ask which profile it was launched with, because the answer to
/// every question that matters is a field on the policy itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ClusterProfile {
    /// Geographically distributed voters, a fixed voter set, and an external
    /// ingress identity that follows raft leadership. The default.
    Fleet,
    /// A self-contained installation on one LAN: peers grow their own voter
    /// set, no external ingress identity, sub-second failover.
    Rig,
}

impl ClusterProfile {
    fn policy(self) -> ClusterPolicy {
        match self {
            Self::Fleet => ClusterPolicy::fleet(),
            Self::Rig => ClusterPolicy::rig(),
        }
    }
}

/// Default raft state directory. Writable runtime state → under the systemd
/// StateDirectory (/var/lib/yah-cloud), not read-only /etc (R330-F28 #14).
const DEFAULT_RAFT_DIR: &str = "/var/lib/yah-cloud/raft";

/// Default containerd socket. Mirrors `runtime::containerd::DEFAULT_SOCKET`,
/// duplicated here so `--containerd-socket` has a default even when the binary
/// is built without the `containerd-integration` feature.
const DEFAULT_CONTAINERD_SOCKET: &str = "/run/containerd/containerd.sock";

/// Per-attempt timeout on a single Kamaji UDS handshake. Short enough that a
/// dead socket fails fast so the outer retry loop can back off and try again.
const CONSTABLE_CONNECT_TIMEOUT_SECS: u64 = 5;

/// Total wall-clock budget yubaba spends retrying the Kamaji UDS handshake at
/// startup before falling back to the legacy in-process `ContainerRuntime`.
///
/// R589-T2 boot race: `yubaba.service` orders `After=kamaji.service`, but
/// kamaji is `Type=simple`, so systemd considers it "active" the instant it
/// forks — *before* it has bound `/run/kamaji/kamaji.sock`. On a slow node
/// (e.g. the Raspberry Pi worker) yubaba would win the race, get
/// ECONNREFUSED on its single connect attempt, and silently fall back to the
/// in-process runtime — leaving kamaji unused until a manual
/// `systemctl restart yubaba`, and recurring on every reboot. Retrying with
/// backoff for this budget rides out the socket-bind gap without a
/// per-box shim or a kamaji-side `Type=notify` change.
const KAMAJI_CONNECT_BUDGET_SECS: u64 = 30;

#[derive(Parser)]
#[command(version, about = "yah per-machine infrastructure daemon")]
struct Cli {
    /// Subcommand; defaults to `serve` so bare `yah-yubaba` boots the daemon.
    ///
    /// Historically the root command implicitly ran `serve`; the explicit
    /// subcommand structure was added in R040-F11 (raft commands) and that
    /// silently flipped the bare-binary path to "print help, exit 2", which
    /// crash-looped the pond container under image
    /// `ghcr.io/yah-ai/yah-yubaba:latest`. We treat `None` as Serve-with-defaults
    /// so any invocation that drops the subcommand (Dockerfile CMD, k8s
    /// args:, systemd ExecStart) keeps working. See R471-B7.
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

// `Serve` dwarfs the operator subcommands and always will — it carries the
// whole daemon's configuration. Boxing its fields to even the variants out
// would buy nothing (this enum is constructed exactly once, at startup) and
// cost the clap surface its readability.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Cmd {
    /// Run the HTTP daemon.
    Serve {
        /// Address to bind (prefer the tailscale0 IP in production).
        #[arg(long, default_value = DEFAULT_BIND)]
        bind: String,
        /// State file path (hostkey identity persistence).
        #[arg(long, default_value = DEFAULT_STATE_PATH)]
        state: PathBuf,
        /// Release channel the cloud-init systemd unit was provisioned for
        /// (`stable` | `beta`). Informational at runtime — the deployed binary
        /// already reflects the channel — but accepted so the unit's
        /// `serve --channel <c>` invocation boots cleanly.
        #[arg(long, default_value = "stable")]
        channel: String,
        /// containerd socket to drive workloads through. Production:
        /// `/run/containerd/containerd.sock`; Colima on macOS:
        /// `~/.colima/default/containerd.sock`. Only used when the binary is
        /// built with the `containerd-integration` feature; otherwise
        /// `/workloads/deploy` stays in stub mode.
        #[arg(long, default_value = DEFAULT_CONTAINERD_SOCKET)]
        containerd_socket: String,
        /// R881-T4 (W343): container range this node addresses isolated-netns
        /// workloads out of, e.g. `10.128.0.0/9`. Unset, such a workload gets
        /// no address at all and its service record is published
        /// `NotReady { reason: "unroutable" }` — reachable only by `nsenter`.
        ///
        /// **Must match the `--container-net` this node's kamaji was started
        /// with.** The two never exchange it: yubaba allocates out of the range
        /// and kamaji recovers the `/24` from the address it is handed. A
        /// mismatch does not error — kamaji declines to wire an address outside
        /// its own range and every tenant workload on the node is quietly
        /// unreachable again. Set both from one drop-in.
        ///
        /// R881-T5: readable from `$YUBABA_CONTAINER_NET` so that "set both
        /// from one drop-in" is actually possible. kamaji takes its half from
        /// `$KAMAJI_CONTAINER_NET` (kamaji-bin/src/main.rs), and yubaba's own
        /// unit on a fleet node already has its `ExecStart=` re-declared by a
        /// raft drop-in — so a flag-only knob here would have meant editing
        /// that re-declaration, which is exactly the footgun kamaji.service's
        /// header warns about (a later drop-in resetting `ExecStart=` silently
        /// drops flags, and half of the 2026-09-03 mesh outage was that).
        /// `Environment=` composes; a second `ExecStart=` does not.
        #[arg(long, env = "YUBABA_CONTAINER_NET")]
        container_net: Option<String>,
        /// R406-T8: UDS path for the Kamaji sibling process. When set,
        /// yubaba dispatches workload list/state/drain through Kamaji
        /// over postcard-framed messages. If the connection fails at
        /// startup, yubaba retries with backoff (rides out kamaji settling
        /// on a fresh boot) and then falls back to the legacy in-process
        /// `ContainerRuntime` (with a warning) so existing single-node
        /// deploys keep working.
        ///
        /// Flag name tracks the constable→kamaji rename: the sibling unit
        /// (`kamaji.service`) and the cloud-init drop-ins spell it
        /// `--kamaji-socket`, so the binary must too (R589-T2 — the shipped
        /// v0.8.17 skew where the unit passed `--kamaji-socket` but the
        /// binary only accepted `--constable-socket` fails `serve` with
        /// exit 2).
        #[arg(long = "kamaji-socket")]
        kamaji_socket: Option<PathBuf>,
        /// R556-F6 gate (b) / A049 §federation: advertised endpoint of the
        /// node-local scryer (`http://<mesh-ip>:6543`). When set, `GET
        /// /services` carries the kamaji-managed scryer entry
        /// (`ServerState::with_scryer_endpoint`) so consumers — hub Mode-1
        /// federation, peers, tower — can locate it; unset, the node
        /// advertises no scryer, which is correct for an opted-out box
        /// (the mesh tolerates absence, A049 §"What scryer is not"). The
        /// value names THIS node's own mesh IP so it is per-node config:
        /// production sets it via a yubaba.service drop-in.
        ///
        /// `env =` FOR THE SAME REASON `--container-net` HAS ONE (R881-T5,
        /// above): on a raft voter, `30-raft.conf` already re-declares this
        /// unit's whole `ExecStart=` line, so a flag-only knob forces a THIRD
        /// copy of that line into a later drop-in — and a copy is exactly how
        /// a flag gets silently dropped when someone edits one of the other
        /// two. `Environment=YUBABA_SCRYER_ENDPOINT=http://<mesh-ip>:6543`
        /// composes instead. Added 2026-09-10 while wiring us-east-001
        /// (R556-F6 gate (b)); that node runs 0.8.37-h1, which predates this,
        /// so it carries the ExecStart re-declaration as a stated interim and
        /// its drop-in names the `Environment=` line that replaces it.
        #[arg(long, env = "YUBABA_SCRYER_ENDPOINT")]
        scryer_endpoint: Option<String>,
        /// Phase 2: this node's raft node ID (u64, unique per yubaba instance).
        /// When set, the raft coordination layer is started and `/raft/*`
        /// routes become active.
        #[arg(long)]
        raft_node_id: Option<u64>,
        /// Phase 2: directory for raft persistence files.
        #[arg(long, default_value = DEFAULT_RAFT_DIR)]
        raft_dir: PathBuf,
        /// W197 §"Single-node raft" / A032 cluster-mesh-1 (R482-T3): on the
        /// BYO-VPS bootstrap path, auto-initialise this node as a raft
        /// cluster-of-one at startup instead of waiting for an operator
        /// `raft init --member …` call. Requires `--raft-node-id`. Idempotent
        /// across restarts. Do NOT combine with the multi-node founding flow —
        /// a self-initialised node is its own cluster and cannot later merge
        /// with a separately-founded one; fleet growth is join-by-NodeId.
        #[arg(long)]
        bootstrap_single_node: bool,
        /// Membership address recorded for this node when self-initialising a
        /// cluster-of-one (`--bootstrap-single-node`). Defaults to `--bind`.
        /// Self-referential for a cluster-of-one and never dialed.
        #[arg(long)]
        raft_advertise_addr: Option<String>,
        /// R734-F5 (W247 §2): this node's geo region, e.g. `us-west`.
        ///
        /// Copy it from the `region` this machine declares in
        /// `.yah/infra/machines/<name>.toml` — that is the same label space, not
        /// a second taxonomy, and a node whose machine file and raft row
        /// disagree is a bug nothing would catch.
        ///
        /// Once raft is up, the node writes this into its own member row so the
        /// cluster knows where every voter is. That is what the
        /// quorum-geography rule (`--cluster-profile fleet`) is judged on beyond
        /// founding. Requires `--raft-node-id`; without it there is no cluster
        /// to tell. Unset means untagged, which is normal for a `rig` (one
        /// failure domain) and works — but leaves a fleet node's row with no
        /// region for a peer to read.
        #[arg(long)]
        region: Option<String>,
        /// R859-F2 phase A: which provider hosts this box — `hetzner`, `ovh`,
        /// `vultr`, `static`.
        ///
        /// One of four flags carrying this machine's **public-ingress
        /// declaration** into its raft member row. Copy each from the
        /// `.yah/infra/machines/<name>.toml` field of the same name, exactly as
        /// `--region` and `--sovereign-group` are copied — same label space, one
        /// source of truth, and a box whose flags and machine file disagree is a
        /// bug nothing else would catch.
        ///
        /// # Why the fleet needs these at all
        ///
        /// A yubaba node never loads `.yah/infra/machines/`. So the raft leader
        /// — the one process that sees `ingress_owner` move and sees a node die
        /// — could observe both and act on neither: it had no provider to
        /// command, no floating IP to move, and no address to pull out of DNS.
        /// These four flags are that missing half, published by each node about
        /// itself (operator decision 2, 2026-09-08). Unset means the effector
        /// treats this box as *undeclared* and refuses to act on it, which is
        /// every node's behaviour before R859-F2 and is safe.
        ///
        /// Requires `--raft-node-id`; without a cluster there is no member row.
        #[arg(long)]
        provider: Option<String>,
        /// R859-F2 phase A: this box's provider DC code (`hil`, `ewr`, `sbg5`),
        /// from its machine file's `location`.
        ///
        /// Read only by the vendor floating-IP adapters, to derive the mobility
        /// zone an IP may move within. Carried now because adding it later
        /// would cost a second raft-surface change and a second cluster-epoch
        /// re-record for one optional string. See `--provider`.
        #[arg(long)]
        location: Option<String>,
        /// R859-F2 phase A: the floating/reserved IP that follows public
        /// ingress onto this box, from its machine file's
        /// `ingress_floating_ip`.
        ///
        /// Unset is the common case and a supported shape, not a
        /// misconfiguration: a fleet whose public ingress moves by DNS alone has
        /// no floating IP anywhere, which is every machine this camp declares
        /// today. See `--provider`.
        #[arg(long)]
        ingress_floating_ip: Option<String>,
        /// R859-F2 phase A: the **public** address this box answers on — the
        /// content of its A record at the ingress apex.
        ///
        /// Deliberately not the mesh address raft membership records: that is
        /// `100.64.x.x`, which is exactly what a public apex must never carry.
        /// This is the one fact the withdrawal path cannot work without, because
        /// a Cloudflare record delete is content-matched — see
        /// [`ingress_effector`](yubaba::ingress_effector). See `--provider`.
        #[arg(long)]
        public_address: Option<String>,
        /// R742-F1 (W305 §F1): which sovereign group this node votes in, e.g.
        /// `prod` or `dev`.
        ///
        /// Copy it from the `sovereign_group` this machine declares in
        /// `.yah/infra/machines/<name>.toml` — same label space, one source of
        /// truth. Editing that file alone changes nothing on a running box: the
        /// daemon declares what this flag says, so the two land together or the
        /// node's comments describe a membership it does not hold.
        ///
        /// A sovereign group is a **blast radius** — its own quorum, its own
        /// upgrade cadence, destroyable and rebuildable without touching
        /// anything else — not a placement constraint. Nothing about it filters
        /// workloads.
        ///
        /// What setting it does is *refuse*: `POST /raft/add-learner` on this
        /// node then declines any join whose joiner is not in the same group,
        /// asking the joiner rather than trusting the request. Unset means no
        /// group is asserted and that gate does not run, which is the right
        /// answer for a pond cluster, a rig, and a standalone BYO node — and
        /// was every cluster's behaviour before R742-F1.
        ///
        /// Requires `--raft-node-id`; without a cluster there is no join to
        /// refuse.
        #[arg(long)]
        sovereign_group: Option<String>,
        /// R605-F12: whether this node may hold a seat in its sovereign group's
        /// quorum — `voter` (default) or `non-voter`.
        ///
        /// Copy it from the `sovereign_role` this machine declares in
        /// `.yah/infra/machines/<name>.toml`, alongside `--sovereign-group`.
        /// Editing the TOML alone changes nothing on a running box.
        ///
        /// `--sovereign-group` says WHICH blast radius this node is in;
        /// this says whether it votes in it. The two are separate because a box
        /// can legitimately share a group's secrets, upgrade cadence and
        /// destruction without being fit to hold a quorum seat — us-west-003 is
        /// prod's x86 build worker on a residential uplink, and a home-internet
        /// partition must never be able to stall the prod raft.
        ///
        /// Passing `non-voter` makes `POST /raft/add-learner` refuse in both
        /// directions: this node will not be joined into its group's quorum,
        /// and if it somehow holds a raft seat already it refuses to grow the
        /// quorum from it. Unset means `voter`, which is what declaring a group
        /// alone meant before this flag existed.
        ///
        /// Has no effect without `--sovereign-group`: a node in no group has no
        /// quorum to be eligible for.
        #[arg(long, default_value = "voter")]
        sovereign_role: SovereignRole,
        /// R736-T3 (W250): the legal jurisdiction this node's data is bound to,
        /// e.g. `us` or `eu`.
        ///
        /// Setting it declares that this node's `--sovereign-group` is a
        /// **cell**: one raft group, one jurisdiction, named in the global
        /// tenant pointer (`tenants/<tenant>/cell.toml`) by the group's own
        /// label. There is deliberately no separate `--cell` id — a second name
        /// for one raft group is a second thing to get wrong, and the
        /// disagreement would be a pointer naming a cell nothing answers to.
        ///
        /// What setting it does is *refuse*: `POST /raft/add-learner` declines a
        /// joiner in a different jurisdiction even when the sovereign group
        /// matches, because one voter across a legal boundary breaks the
        /// residency promise for every tenant already in the cell — not only for
        /// tenants placed after it. Moving a *tenant* between cells is the
        /// cross-cell move protocol (W250 §5), never a raft join.
        ///
        /// Requires `--sovereign-group`: a jurisdiction with no group names no
        /// cell, and the daemon refuses to start rather than carry a residency
        /// claim nothing can act on. Unset means this cluster is a blast radius
        /// that is not a cell, which is every yubaba cluster today.
        #[arg(long)]
        jurisdiction: Option<String>,
        /// R734-T4 (W247 §3): softly prefer this region for raft leadership.
        ///
        /// A label from the same space as `--region`. When the raft leader is
        /// outside it and a caught-up voter is inside it, the leader hands off,
        /// so client writes stop paying a cross-region round trip to whichever
        /// voter happened to win the last election.
        ///
        /// A *preference*, never a requirement: if no voter in this region is
        /// available — the ordinary shape of that region being dark — leadership
        /// stays wherever the cluster elected it and nothing is retried. The pin
        /// can tidy up after a failover; it can never block one.
        ///
        /// Requires `--raft-node-id`, and refused under `--cluster-profile rig`,
        /// where every voter shares one failure domain and there are no regions
        /// to prefer between. Unset means leadership is left wherever raft puts
        /// it, which is the behaviour every yubaba cluster had before R734-T4.
        #[arg(long)]
        leader_anchor: Option<String>,
        /// Phase 2: S3 URL for litestream Headscale DB replication.
        /// Format: `s3://bucket/path?endpoint=https://fsn1.your-objectstorage.com`
        /// When set, the leader watcher manages litestream replicate + restore.
        ///
        /// # Delivered by environment on the fleet, not by ExecStart
        ///
        /// `yubaba.service` ships in the release tarball and is copied verbatim
        /// onto every node of every camp, so a bucket named in its ExecStart
        /// would be a *fleet* URL baked into a binary a rig also installs. The
        /// env fallback puts it in `/etc/yah-cloud/litestream.env` instead —
        /// the same per-node file that already carries
        /// `LITESTREAM_ACCESS_KEY_ID` / `LITESTREAM_SECRET_ACCESS_KEY`, which is
        /// the right place because a URL is useless without the credentials
        /// that authenticate to it and the two must never drift apart.
        /// `yubaba.service` reads that file via `EnvironmentFile=-`, so turning
        /// replication on for a node is one file, not a unit edit and a roll.
        #[arg(long, env = "YUBABA_LITESTREAM_S3_URL")]
        litestream_s3_url: Option<String>,
        /// R609-F1 (A032 §"yah-aware control plane"): bind the yah control
        /// plane — an `mshr::Endpoint` on this machine's hostkey — so
        /// yah-aware callers (a camp daemon, the desktop, the mobile app)
        /// dial this node by `NodeId` over NAT-punched QUIC instead of by
        /// IP/SSH. The NodeId is the one `GET /identity` already reports and
        /// is stable across restarts.
        ///
        /// Opt-in: single-node dev and the containerized pond path have no
        /// caller for it, and an unused UDP socket on every dev box is a cost
        /// with no matching benefit. Binding is non-fatal — a failure warns
        /// and leaves the HTTP surface serving.
        #[arg(long)]
        control_plane: bool,
        /// R609-F2 (A043 §transport): serve `yah camp --stdio` over the
        /// control plane's camp-RPC ALPN for workspaces under this root.
        /// Repeatable. Implies nothing on its own — `--control-plane` must
        /// also be set, since this lane rides that endpoint.
        ///
        /// Admitting a dial on this lane SPAWNS A PROCESS on this machine,
        /// so it requires an admission policy: without at least one
        /// `--control-plane-allow` (or a configured cheers client) the lane
        /// is withheld and its ALPN is not advertised. Roots are a path
        /// containment on top of that, never a substitute for it.
        #[arg(long = "camp-rpc-root", value_name = "PATH")]
        camp_rpc_roots: Vec<PathBuf>,
        /// R609-F3 (W268 §"The binding"): admit control-plane dials from
        /// this `NodeId`. Repeatable. Accepts the hex spelling `GET
        /// /identity` reports (`node_id`) — copy it off the dialing machine.
        ///
        /// Passing any value flips the endpoint from admit-everyone to
        /// **default-deny**: this list, plus this node's own NodeId, plus
        /// every machine holding a live cheers `node` enrollment row this
        /// yubaba wrote. Everything else is closed right after the
        /// handshake, before a single application byte is served.
        ///
        /// This is the bootstrap path — a freshly-provisioned node has no
        /// cheers rows yet and the operator's desktop has to get in
        /// somehow (R609-F5 turns first-connect TOFU into an entry here).
        #[arg(long = "control-plane-allow", value_name = "NODE_ID")]
        control_plane_allow: Vec<String>,
        /// R609-F2: the `yah` binary the camp-RPC lane execs. Bare `yah`
        /// resolves through `$PATH`, matching what the SSH path runs on the
        /// far side today.
        #[arg(long, default_value = "yah")]
        camp_rpc_yah_bin: String,
        /// R609-F4 (W197 §"Open questions" 2): pin a peer this node should
        /// always know how to reach. Repeatable, or comma-separated.
        ///
        /// Spelled `<node-id>` or `mshr://<node-id>?addr=host:port&relay=URL`
        /// — the same string the desktop's connect field takes. Additive: a
        /// pin never displaces the discovery lanes below.
        ///
        /// Falls back to `$YAH_XLB_SEED` when unset, which is how a systemd
        /// `Environment=` line reaches it.
        #[arg(long = "xlb-seed", value_name = "SEED")]
        xlb_seeds: Vec<String>,
        /// R609-F4: NAT-traversal relay servers — how a peer reaches this
        /// node when hole-punching fails. Repeatable. `none` turns the lane
        /// off; unset ships n0's production relays. Falls back to
        /// `$YAH_XLB_RELAY`.
        ///
        /// Overrides **replace** the shipped list rather than extending it:
        /// an operator running their own relay does not want a silent
        /// fallback carrying their traffic somewhere else.
        #[arg(long = "xlb-relay", value_name = "URL")]
        xlb_relays: Vec<String>,
        /// R609-F4: pkarr relays — how a *bare* NodeId is resolved into
        /// addresses. Repeatable. `none` turns the lane off; unset ships
        /// n0's production pkarr relay. Falls back to `$YAH_XLB_PKARR`.
        ///
        /// Separate from `--xlb-relay` because an `iroh-relay` server does
        /// not serve pkarr: it proxies QUIC and answers address discovery,
        /// nothing more. Hosting your own relay does not move your lookups.
        #[arg(long = "xlb-pkarr", value_name = "URL")]
        xlb_pkarr: Vec<String>,
        /// R609-F4: turn off the LAN (mDNS) discovery lane, which is on by
        /// default. It costs nothing where multicast is blocked — every cloud
        /// VPS — and finds the camp on the next desk instantly where it is
        /// not. Turn it off on a LAN you do not trust to see this node's
        /// NodeId.
        #[arg(long = "xlb-no-lan")]
        xlb_no_lan: bool,
        /// R118-T9: which cluster policy this deployment runs under — voter
        /// admission, external-ingress ownership, and raft timings.
        ///
        /// A deployment-time decision, fixed for the life of the process and
        /// never negotiated with peers: every voter of one cluster must be
        /// launched with the same profile, and two clusters running different
        /// profiles never merge.
        #[arg(long, value_enum, default_value = "fleet")]
        cluster_profile: ClusterProfile,
    },
    /// Parse an SSH pubkey file, compute its SHA256 fingerprint, and write
    /// it to the state file. Idempotent.
    RegisterHostkey {
        /// Path to the SSH public key file (e.g. `/etc/yah-cloud/hostkey.pub`).
        pubkey_path: PathBuf,
        #[arg(long, default_value = DEFAULT_STATE_PATH)]
        state: PathBuf,
    },
    /// Raft coordination commands (Phase 2 — R040-F20).
    Raft {
        /// Yubaba daemon address to query (default: localhost).
        #[arg(long, default_value = "http://127.0.0.1:7443")]
        daemon: String,
        #[command(subcommand)]
        cmd: RaftCmd,
    },
    /// Custom tenant domains: enrol, unenrol, inspect (R779 / W267).
    ///
    /// Reads and writes the object store directly — the enrollment set is not
    /// raft state, so these verbs need no quorum, no leader, and no running
    /// daemon, only `YUBABA_CERT_STORE_*` and the `cloudflare-r2-*` credentials
    /// the daemon itself uses.
    Domain {
        #[command(subcommand)]
        cmd: DomainCmd,
    },
    /// Holding-page bodies a parked domain's 503 carries (R870-F8).
    ///
    /// Same store and same credentials as `domain`, and for the same reason:
    /// the pages sit beside the enrollment set in the bucket, not in raft.
    Holding {
        #[command(subcommand)]
        cmd: HoldingCmd,
    },
    /// The off-fleet copy of the raft state: inspect, restore, adopt
    /// (R869 / W339).
    ///
    /// Like `domain`, these read and write the object store directly — the copy
    /// is one object, so they need no quorum, no leader and no running daemon,
    /// only `YUBABA_STATE_BACKUP_CLUSTER` plus the `YUBABA_CERT_STORE_*` and
    /// `cloudflare-r2-*` credentials the daemon already uses. That is the
    /// point: the machine you rebuild from is not part of a cluster yet.
    State {
        #[command(subcommand)]
        cmd: StateCmd,
    },
}

#[derive(Subcommand)]
enum StateCmd {
    /// Show the off-fleet copy — how stale it is, and what it holds.
    Show {
        /// Read a retired lineage (see the `lineage` line in the default
        /// output) instead of the current copy.
        #[arg(long)]
        lineage: Option<u64>,
        /// Emit JSON — the whole snapshot, state included.
        #[arg(long)]
        json: bool,
    },
    /// Seed an empty raft dir from the off-fleet copy.
    ///
    /// Run against every founding voter of the new cluster *before* `raft init`
    /// and before yubaba starts, then init as usual. Refuses a dir that already
    /// holds any of the four raft files.
    ///
    /// `locks` and `rollouts` are dropped: on a rebuild every lock holder is
    /// dead by construction, and a lease with hours left on it would stall the
    /// new cluster on a lock nobody will ever release.
    Restore {
        /// The raft dir to seed — the daemon's `--raft-dir`.
        #[arg(long)]
        dir: PathBuf,
        /// Restore a retired lineage rather than the current copy.
        #[arg(long)]
        lineage: Option<u64>,
        /// Report what would be written without writing it.
        #[arg(long)]
        dry_run: bool,
    },
    /// Accept a rebuilt cluster as a new incarnation, so it can back up again.
    ///
    /// The backup refuses to overwrite a copy with a *lower* applied index —
    /// that is what a wiped raft dir looks like from the object store, and an
    /// unguarded backup would destroy the only surviving copy of the cluster
    /// within one tick of the first node coming back. This is the operator
    /// saying the low index is legitimate. The pre-rebuild copy is archived
    /// under its lineage first, and `state show --lineage <n>` still reads it.
    Adopt,
}

#[derive(Subcommand)]
enum DomainCmd {
    /// Register a domain and print the DNS records its owner must create.
    ///
    /// Enrolment is the *whole* of turning a domain on: the same object is the
    /// allowlist `passway-demux` routes from and the work list the per-domain
    /// issuer sweeps, so there is no second activation step. The tenant's DNS is
    /// the only remaining input, which is why this prints it.
    ///
    /// Idempotent for an identical record; a conflicting one is refused rather
    /// than silently re-pointed.
    Enroll {
        /// The tenant's domain, e.g. `shop.tenant.io`.
        domain: String,
        /// Where the demux splices this domain's TLS bytes — the per-tenant
        /// passway's listener, or the socket kamaji holds for a cold tenant.
        ///
        /// A `host:port`, never a hostname: the demux's route table parses its
        /// backends to a `SocketAddr`, so a name here would be discovered as a
        /// routes file the demux refuses at load rather than as an enrolment
        /// error here.
        #[arg(long)]
        tls_backend: SocketAddr,
        /// Optional port-80 backend, for when an HTTP tier exists. Carried in
        /// the record and unused today.
        #[arg(long)]
        http_backend: Option<SocketAddr>,
        /// This deployment's *public* ingress address, as the tenant's A/AAAA
        /// record should name it. Repeatable.
        ///
        /// Not derivable: `--tls-backend` is the internal address the demux
        /// splices to, which is precisely not what a tenant points DNS at.
        /// Omitted, the printed instruction says so instead of guessing.
        #[arg(long = "ingress")]
        ingress: Vec<String>,
        /// Emit JSON — the form an onboarding page renders from.
        #[arg(long)]
        json: bool,
    },
    /// Drop a domain's route, keeping its certificate material.
    ///
    /// Keeping the cert is the default because undoing a typo should not cost
    /// an ACME order against a rate limit that is counted per identifier.
    Unenroll {
        /// The domain to unenrol.
        domain: String,
        /// Also delete the sealed cert, key and any issuance claim.
        ///
        /// Deliberate rather than default: re-enrolling afterwards orders a
        /// fresh certificate, and Let's Encrypt counts new orders per account
        /// and failures per identifier.
        #[arg(long)]
        forget_cert: bool,
    },
    /// List enrolled domains and whether each holds a certificate.
    List {
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show one domain's enrolment, certificate, issuance claim and DNS contract.
    Status {
        /// The domain to inspect.
        domain: String,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Point a domain at a holding page, or back at passway's own (R870-F8).
    ///
    /// The page is the body a door serves on a fail-ready 503 — a parked
    /// domain, or the seconds after a deploy before the new backend reports
    /// ready. Which page is cosmetic and freely re-decided, so this is its own
    /// verb rather than a re-enrolment: routing is untouched.
    ///
    /// Upload the page itself with `yubaba holding put`. The two can happen in
    /// either order; a domain naming a page that is not there keeps the default.
    Holding {
        /// The enrolled domain to brand.
        domain: String,
        /// The page name, as `yubaba holding list` shows it.
        #[arg(long, conflicts_with = "clear", required_unless_present = "clear")]
        page: Option<String>,
        /// Remove the override — back to passway's own page.
        #[arg(long)]
        clear: bool,
    },
}

/// Manage the holding-page bodies domains point at (R870-F8).
///
/// A page is one object shared by every domain naming it, which is why these
/// are their own commands: at ten thousand tenants and a handful of brands, the
/// pages are the small set.
#[derive(Subcommand)]
enum HoldingCmd {
    /// Store (or replace) a page from a local HTML file.
    Put {
        /// The page name domains will reference. Lowercase letters, digits,
        /// `-` and `_`; it becomes a filename on every door.
        name: String,
        /// Path to the HTML document to upload.
        file: PathBuf,
    },
    /// List stored page names.
    List,
    /// Delete a page.
    ///
    /// Domains naming it are left alone and fall back to passway's own page on
    /// the next sweep; re-uploading the name restores them.
    Remove {
        /// The page name to delete.
        name: String,
    },
}

#[derive(Subcommand)]
enum RaftCmd {
    /// Show raft cluster status (leader, term, last log).
    Status,
    /// One-time cluster bootstrap: write the founding membership (R570-F1).
    ///
    /// Run against exactly one founding voter after every member is up with
    /// `--raft-node-id`; the rest learn membership from the elected leader.
    Init {
        /// Founding voter as `id=host:port[@region]`, repeatable
        /// (e.g. --member 1=100.64.0.1:7443@us-west
        ///       --member 2=100.64.0.2:7443@us-east
        ///       --member 3=100.64.0.3:7443@us-south).
        ///
        /// The `@region` suffix is the machine's `region` from
        /// `.yah/infra/machines/<name>.toml`. Under the default `fleet`
        /// profile it is REQUIRED for a multi-voter cluster: the daemon
        /// refuses a founding set where one region holds a majority, and it
        /// cannot check that on untagged voters (R734-F2, W247 §2). A `rig`
        /// cluster is one failure domain by construction and needs no tags.
        #[arg(long = "member", required = true)]
        members: Vec<String>,
    },
    /// List raft peers and their current state.
    Peers,
    /// Add a node to a *running* cluster as a non-voting learner (R569-F3).
    ///
    /// The join-an-existing-quorum path (vs `init`, which founds a fresh
    /// cluster). Run against the current **leader** (`--daemon <leader-mesh>`).
    /// The joining node must already be up with `--raft-node-id <node-id>` and
    /// uninitialised (no `init`, no `--bootstrap-single-node`). The learner
    /// receives full replicated state but never votes or counts toward quorum;
    /// promotion to voter is a separate, deliberate step (not this command) —
    /// a home-lab macOS node stays a learner by design (W301).
    AddLearner {
        /// The joining node's raft node id (u64, unique fleet-wide).
        #[arg(long)]
        node_id: u64,
        /// The joining node's mesh address `host:port` the leader will dial —
        /// e.g. its Tailscale mesh IP `100.64.0.7:7443`, never a LAN address.
        #[arg(long)]
        addr: String,
    },
    /// Promote an existing learner to a voter (R118-T9).
    ///
    /// The counterpart to `add-learner`, and subject to the cluster policy the
    /// daemon was launched with: under the default `fleet` profile promotion is
    /// refused outright (403) so the founding voter set stays fixed. Run
    /// against the current **leader**.
    PromoteVoter {
        /// The learner's raft node id. It must already be in membership.
        #[arg(long)]
        node_id: u64,
    },
    /// Remove nodes from the cluster (R734-T3).
    ///
    /// The third membership verb, symmetric with `add-learner` and
    /// `promote-voter`. Removed nodes leave entirely — they are not demoted to
    /// learners — so a decommissioned box stops receiving replication. Run
    /// against the current **leader**.
    ///
    /// Repeatable, and that matters: the surviving voter count must stay odd,
    /// so shrinking a five-voter cluster to three is ONE call naming both
    /// departing voters (`--node-id 4 --node-id 5`). Removing a single voter
    /// from three is refused — it would leave two, which tolerates no failures
    /// while requiring both nodes for every write.
    RemoveMember {
        /// A raft node id to remove; repeatable.
        #[arg(long = "node-id", required = true)]
        node_ids: Vec<u64>,
    },
    /// Transfer raft leadership to another node.
    TransferLeader {
        /// Target node ID to become leader.
        to: u64,
    },
}

/// Default-construct a `Cmd::Serve` matching every `default_value` declared on
/// the variant. Kept in lockstep with the `Cmd::Serve` struct above.
fn default_serve() -> Cmd {
    Cmd::Serve {
        bind: DEFAULT_BIND.to_string(),
        state: PathBuf::from(DEFAULT_STATE_PATH),
        channel: "stable".to_string(),
        containerd_socket: DEFAULT_CONTAINERD_SOCKET.to_string(),
        container_net: None,
        kamaji_socket: None,
        scryer_endpoint: None,
        raft_node_id: None,
        raft_dir: PathBuf::from(DEFAULT_RAFT_DIR),
        bootstrap_single_node: false,
        raft_advertise_addr: None,
        region: None,
        provider: None,
        location: None,
        ingress_floating_ip: None,
        public_address: None,
        sovereign_group: None,
        sovereign_role: SovereignRole::default(),
        jurisdiction: None,
        leader_anchor: None,
        litestream_s3_url: None,
        control_plane: false,
        camp_rpc_roots: Vec::new(),
        control_plane_allow: Vec::new(),
        camp_rpc_yah_bin: "yah".to_string(),
        xlb_seeds: Vec::new(),
        xlb_relays: Vec::new(),
        xlb_pkarr: Vec::new(),
        xlb_no_lan: false,
        cluster_profile: ClusterProfile::Fleet,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    // None → default to `serve` with every flag at its declared default. This
    // mirrors how the binary used to behave before raft subcommands shipped
    // and keeps bare-binary launchers (pond Dockerfile CMD) booting cleanly.
    let cmd = cli.cmd.unwrap_or_else(default_serve);
    match cmd {
        Cmd::Serve {
            bind,
            state,
            channel,
            containerd_socket,
            container_net,
            kamaji_socket,
            scryer_endpoint,
            raft_node_id,
            raft_dir,
            bootstrap_single_node,
            raft_advertise_addr,
            region,
            provider,
            location,
            ingress_floating_ip,
            public_address,
            sovereign_group,
            sovereign_role,
            jurisdiction,
            leader_anchor,
            litestream_s3_url,
            control_plane,
            camp_rpc_roots,
            control_plane_allow,
            camp_rpc_yah_bin,
            xlb_seeds,
            xlb_relays,
            xlb_pkarr,
            xlb_no_lan,
            cluster_profile,
        } => {
            tracing::info!(channel = %channel, "yah-yubaba serve");
            let policy = cluster_profile.policy();
            tracing::info!(?policy, "cluster policy");
            // R555-F5 / W235 §(c): yubaba now enforces signed-recipe admission
            // at the deploy handler, ahead of secret resolution — so it needs
            // the same posture kamaji-bin logs at startup, and for a sharper
            // reason. yubaba.service and kamaji.service are separate units with
            // separate environments, so a node can pin YAH_ADMISSION_KEYS for
            // one and not the other. That misconfiguration looks like nothing
            // until a signed dispatch is refused for an untrusted key that the
            // operator can see is pinned — on the other unit. Two log lines at
            // boot, one per unit, make the mismatch readable.
            let admission = workload_spec::admission::NodeAdmission::from_env();
            tracing::info!(
                policy = ?admission.policy,
                pinned_keys = admission.trusted_keys.len(),
                policy_env = workload_spec::admission::POLICY_ENV,
                keys_env = workload_spec::admission::KEYS_ENV,
                "signed-recipe admission posture (W235 §(c)) — must match kamaji's on this node"
            );
            // R734-T4: refuse a meaningless anchor at boot rather than starting a
            // loop that could never act on it. This is an operator flag typo, and
            // a typo that silently does nothing is the worst of the three
            // outcomes — the operator believes leadership is pinned and it is not.
            if let Some(anchor) = &leader_anchor {
                if let Err(why) = yubaba::leader_pin::validate(&policy, anchor) {
                    anyhow::bail!("--leader-anchor: {why}");
                }
            }
            // R736-T3: same reasoning one flag over. A jurisdiction that names
            // no cell, or a label the global tenant pointer could not carry,
            // must fail here — where the fix is a flag edit — rather than in the
            // middle of a cross-cell move months later, on a value fixed at
            // boot. `identify` is also what decides the cell exists at all, so
            // this is the one place the two labels are checked together.
            let cell = yubaba::cell::identify(sovereign_group.as_deref(), jurisdiction.as_deref())
                .map_err(|why| anyhow::anyhow!("--jurisdiction: {why}"))?;
            if let Some(cell) = &cell {
                tracing::info!(
                    cell_id = %cell.id,
                    jurisdiction = %cell.jurisdiction,
                    "this cluster is a residency cell (W250) — cross-jurisdiction joins refused"
                );
            }
            // R599-F12: `--bind` is also this node's own mesh address (in
            // production it is the tailscale0 IP), and a natively forked
            // workload can only bind an address the node already holds. Record
            // it so a bundle deploy can tell kamaji where to listen instead of
            // being pinned to loopback.
            let mut server_state = ServerState::load(state)?
                .with_cluster_policy(policy)
                .with_bind_addr(&bind);

            // R881-T4 (W343). A malformed range fails startup rather than
            // degrading to "no container networking": an operator who passed
            // --container-net asked for reachable workloads, and quietly
            // serving unreachable ones is the failure R881 exists to remove.
            if let Some(range) = &container_net {
                let range = kamaji::container_net::Ipv4Cidr::parse(range)
                    .map_err(|e| anyhow::anyhow!("--container-net: {e:#}"))?;
                tracing::info!(
                    %range,
                    node_mesh_ip = ?server_state.node_mesh_ip(),
                    "allocating per-workload container addresses (W343)"
                );
                server_state = server_state.with_container_net(
                    kamaji::container_net::ContainerNet::new(
                        range,
                        kamaji::container_net::DEFAULT_BRIDGE,
                    ),
                );
            }

            // R556-F6 gate (b): make the /services scryer advertisement
            // reachable from the daemon. `with_scryer_endpoint` existed since
            // R556-T10 but nothing in the serve path called it, so a node
            // running a scryer still answered `/services -> []`.
            if let Some(endpoint) = scryer_endpoint {
                server_state = server_state.with_scryer_endpoint(endpoint);
            }

            if let Some(s3_url) = litestream_s3_url {
                server_state = server_state.with_litestream_s3_url(s3_url);
            }

            // R858-T16: the coordinator's public base URL. Two readers, one
            // fact: the operator-bridge preauth path already used it, and
            // `headscale_state::hydrate_config` now renders `config.yaml`'s
            // `server_url` from it. Env rather than a flag for the same reason
            // `YUBABA_LITESTREAM_S3_URL` is — see `yubaba::HEADSCALE_URL_ENV`.
            // Unset leaves both readers exactly as they were.
            if let Ok(url) = std::env::var(yubaba::HEADSCALE_URL_ENV) {
                if !url.trim().is_empty() {
                    server_state = server_state.with_headscale_url(url.trim());
                }
            }

            // R852-F2: what `GET /domains/{d}/onboarding` reports to a tenant.
            // Resolved here, once, rather than per request — the handler must
            // be a pure function of node config so it is testable and so two
            // requests in the same second cannot disagree.
            server_state = server_state.with_domain_onboarding(
                std::env::var(yubaba::domain_issuer::DELEGATE_ZONE_ENV).ok(),
                yubaba::public_ingress_targets(std::env::var(yubaba::PUBLIC_INGRESS_ENV).ok()),
            );

            // R779 (W267): the object-store fallback for per-domain TLS material.
            // Opt-in via YUBABA_CERT_STORE_BUCKET; a node without it resolves
            // from raft alone, exactly as before. Non-fatal on failure — an
            // unreachable bucket must not stop the daemon from booting, and a
            // node that cannot reach it simply has no per-domain certs.
            //
            // The ACME directory names the store's issuer segment, so writer and
            // reader agree on one path without a second config knob — resolved
            // by `cert_store::acme_directory`, the single owner of that default.
            //
            // R870-B20: parsed HERE, not read off the ACME issuer's config. It
            // used to hang off `IssuerConfig`, which returns `Ok(None)` whenever
            // YUBABA_ACME_DOMAIN is unset — so a door with a bucket and no
            // issuer drop-in silently got no cert store, and therefore no route
            // publisher, no per-domain issuer and no tenant passways, with
            // nothing in the log to attribute it to (us-west-001, 2026-09-09).
            // A cert store is a property of the node, not of the issuer.
            match yubaba::cert_store::CertStoreConfig::parse(|k| std::env::var(k).ok()) {
                Ok(Some(store_cfg)) => {
                    let directory_url =
                        yubaba::cert_store::acme_directory(|k| std::env::var(k).ok()).url();
                    match store_cfg.connect(&directory_url) {
                        Ok(store) => {
                            tracing::info!(
                                bucket = %store_cfg.bucket,
                                issuer = %store.issuer(),
                                "cert store: per-domain TLS material resolves from the \
                                 object store when raft does not hold it"
                            );
                            server_state = server_state.with_cert_store(store);

                            // R779 (W267): and, if this node fronts a
                            // passway-demux, keep that demux's route table in
                            // step with the enrollment set. Spawned here rather
                            // than in the raft branch below on purpose — the
                            // node holding :443 for a free tier need not be a
                            // raft member, which is the whole reason the
                            // enrollment set lives in the bucket.
                            match yubaba::demux_routes::parse_publisher_config(|k| {
                                std::env::var(k).ok()
                            }) {
                                Ok(Some(pub_cfg)) => {
                                    if let Some(store) = server_state.cert_store.clone() {
                                        let _publisher =
                                            yubaba::demux_routes::spawn(store, pub_cfg);
                                    }
                                }
                                Ok(None) => {}
                                Err(e) => tracing::error!(
                                    "demux route publisher config invalid — not started \
                                     (fix YUBABA_DEMUX_ROUTES_*): {e}"
                                ),
                            }

                            // R779 (W267 §Decision 2): and the writer for that
                            // same set — per-domain issuance for custom tenant
                            // domains, validated by DNS-01 CNAME delegation.
                            // Spawned here, outside the raft branch, for the
                            // same reason as the publisher: issuance and
                            // routing both live in the bucket, and neither
                            // needs this node to be a raft member. Single-writer
                            // per domain is the store's own CAS claim, not a
                            // raft lock — see `cert_store::claim_issuance`.
                            match yubaba::domain_issuer::parse_domain_issuer_config(|k| {
                                std::env::var(k).ok()
                            }) {
                                Ok(Some(issuer_cfg)) => {
                                    if let Some(store) = server_state.cert_store.clone() {
                                        let _domain_issuer = yubaba::domain_issuer::spawn(
                                            store,
                                            // The claim holder, as an operator
                                            // reading a stuck `issuing` object
                                            // wants to see it: which node.
                                            bind.clone(),
                                            issuer_cfg,
                                        );
                                    }
                                }
                                Ok(None) => {}
                                Err(e) => tracing::error!(
                                    "per-domain issuer config invalid — not started (fix \
                                     YUBABA_DOMAIN_ISSUER_* / YUBABA_ACME_*): {e}"
                                ),
                            }
                        }
                        Err(e) => tracing::error!(
                            bucket = %store_cfg.bucket,
                            "cert store unavailable — per-domain TLS material will not \
                             resolve on this node: {e}"
                        ),
                    }
                }
                Ok(None) => {}
                // Half-configured: the bucket is named but the account id is
                // not. Loud, because the store's own parse treats that as an
                // operator who meant to turn this on, and because silence here
                // is exactly the failure R870-B20 fixed.
                Err(e) => tracing::error!(
                    "cert store config invalid — no per-domain TLS material on this node \
                     (fix YUBABA_CERT_STORE_*): {e}"
                ),
            }

            // Wire the container runtime. This is what flips `/workloads/deploy`
            // from `runtime=stub` to a daemon that actually deploys containers.
            // Attached before the raft branch so both single-node and clustered
            // wardens deploy workloads.
            server_state = attach_runtime(server_state, &containerd_socket).await;

            // R406-T8: connect to Kamaji when --kamaji-socket is set.
            // Failure here is non-fatal so an operator can boot yubaba alone
            // for triage, but the warning makes it clear the requested
            // dispatch path is unavailable.
            server_state = attach_constable_client(server_state, kamaji_socket).await;

            // R852-F1 (W267): the far end of the splice the demux publisher
            // above renders. One cold passway per enrolled custom domain, armed
            // through kamaji's JIT tier so 10k idle domains cost 10k held fds
            // rather than 10k processes.
            //
            // Spawned HERE and not beside the publisher because it is the only
            // one of the three that needs a kamaji, and `attach_constable_client`
            // runs after that block. Both halves still read the same enrollment
            // set, so a domain becomes routable and servable from one write —
            // see `tenant_passway`'s module doc for why deriving them from
            // different sources is the failure to avoid.
            match yubaba::tenant_passway::parse_config(|k| std::env::var(k).ok()) {
                Ok(Some(tp_cfg)) => match (
                    server_state.cert_store.clone(),
                    server_state.constable_client.clone(),
                ) {
                    (Some(store), Some(kamaji)) => {
                        let _tenant_passways = yubaba::tenant_passway::spawn(store, kamaji, tp_cfg);
                    }
                    // Configured but unusable. Named rather than silent: the
                    // symptom otherwise is every tenant domain resolving,
                    // handshaking and hanging, with nothing in the log to
                    // attribute it to.
                    (None, _) => tracing::error!(
                        "tenant passway reconciler requested ({}) but no cert store is \
                         configured — set YUBABA_CERT_STORE_BUCKET, or the enrollment set \
                         cannot be read",
                        yubaba::tenant_passway::STATE_DIR_ENV
                    ),
                    (_, None) => tracing::error!(
                        "tenant passway reconciler requested ({}) but no kamaji is attached \
                         — pass --kamaji-socket, or nothing can hold the tenant sockets",
                        yubaba::tenant_passway::STATE_DIR_ENV
                    ),
                },
                Ok(None) => {}
                Err(e) => tracing::error!(
                    "tenant passway reconciler config invalid — not started (fix \
                     YUBABA_TENANT_PASSWAY_*): {e}"
                ),
            }

            // Pond (R454-F1 seam): the containerized pond yubaba drives
            // MinIO/miniflare as sibling containers through the host docker
            // socket mounted at /var/run/docker.sock. Wire the LocalRuntime
            // whenever that socket exists so `POST /pond/deploy` works;
            // without it the pond routes answer 503 and every camp deploy
            // silently fails. Cloud/systemd deployments don't mount the
            // socket, so this is a no-op there.
            server_state = attach_pond_runtime(server_state).await;

            // R609-F4: resolved before the `--control-plane` branch, and
            // fatally, because a malformed seed is a typo either way. The
            // tolerant version boots clean and then cannot be dialed, which
            // is discovered over the transport that is broken.
            let seed_flags_given = !xlb_seeds.is_empty()
                || !xlb_relays.is_empty()
                || !xlb_pkarr.is_empty()
                || xlb_no_lan;
            let seeds = mshr::Seeds::resolve(xlb_seeds, xlb_relays, xlb_pkarr)
                .context(
                    "resolving --xlb-seed / --xlb-relay / --xlb-pkarr (or their \
                     YAH_XLB_SEED / YAH_XLB_RELAY / YAH_XLB_PKARR environment fallbacks)",
                )?
                .with_lan(!xlb_no_lan);

            // R609-F1: the yah control plane. Bound before raft so the
            // NodeId is logged early — it is the address an operator copies
            // into a desktop dial, and it should not be buried behind
            // election chatter.
            server_state = attach_control_plane(
                server_state,
                control_plane,
                camp_rpc_roots,
                camp_rpc_yah_bin,
                control_plane_allow,
                seeds,
                seed_flags_given,
            )
            .await?;

            if let Some(node_id) = raft_node_id {
                tracing::info!(node_id, dir = ?raft_dir, "starting raft coordination layer");
                let (raft_node, state_machine) =
                    yubaba::raft::open_with_state_machine(node_id, raft_dir, &policy).await?;
                server_state = server_state
                    .with_raft(raft_node.clone())
                    .with_node_id(node_id)
                    // R118-T9: liveness reporting for `/raft/status`. Thresholds
                    // scale off the policy's heartbeat period, so a LAN cluster
                    // is not held to a WAN cluster's patience.
                    .with_failure_detector(Arc::new(RaftHeartbeatDetector::new(
                        raft_node.clone(),
                        policy.liveness_thresholds(),
                    )))
                    // R737-F2: the node-lease channel a placement scheduler
                    // is allowed to trust — see `lease_detector` module doc
                    // for why this must stay separate from the detector
                    // above.
                    .with_lease_detector(Arc::new(LeaseFailureDetector::new(
                        policy.liveness_thresholds(),
                    )))
                    // R782 (W253 §7): the streamer-RPO evidence channel a
                    // placement scheduler is allowed to trust — see
                    // `with_rpo_registry`'s doc for why this needs no
                    // thresholds, unlike the detector above.
                    .with_rpo_registry(Arc::new(RpoWatermarkRegistry::new()))
                    // R600-F6 (W273): share the raft state-machine handle so
                    // admission can resolve `SecretRef::Cluster` File mounts.
                    // Cloned here because the ACME issuer (F3) also moves a
                    // handle in below.
                    .with_cluster_state(state_machine.clone());
                if let Some(region) = region.clone() {
                    server_state = server_state.with_region(region);
                }
                // R742-F1: declaring a group turns on the add-learner gate on
                // this node. Unset leaves it off — see the flag's doc.
                if let Some(group) = sovereign_group.clone() {
                    server_state = server_state.with_sovereign_group(group);
                }
                // R736-T3: and declaring a jurisdiction beside it makes that
                // group a cell, which arms the cross-jurisdiction half of the
                // same gate. Validated above, so this cannot be a jurisdiction
                // with no group.
                if let Some(jurisdiction) = jurisdiction.clone() {
                    server_state = server_state.with_jurisdiction(jurisdiction);
                }
                // R605-F12: set unconditionally — it defaults to `voter`, so
                // there is no "unset" to preserve, and the gate reads it only
                // when a group is declared above.
                server_state = server_state.with_sovereign_role(sovereign_role);
                if !sovereign_role.is_voter() {
                    // This branch has a --raft-node-id, so the node holds a
                    // raft seat while declaring it must not. Both halves came
                    // from the operator, so neither can be silently preferred —
                    // and the add-learner gate refuses every join here, which
                    // is a confusing symptom without this line above it.
                    tracing::warn!(
                        role = %sovereign_role,
                        node_id,
                        "--sovereign-role non-voter with a --raft-node-id: this node is holding \
                         a raft seat its own declaration says it should not have. Joins through \
                         it will be refused. Drop --raft-node-id (the us-west-003 shape: `mode: \
                         standalone`), or correct sovereign_role in \
                         .yah/infra/machines/<name>.toml and restart with --sovereign-role voter"
                    );
                }
                // W197 §"Single-node raft" (R482-T3): the BYO-VPS bootstrap
                // path self-initialises a cluster-of-one so the node comes up
                // as a live one-voter raft with no operator `raft init` call.
                // Idempotent across restarts; a no-op once the node has
                // vote/log state. Runs before the leader watcher spawns so the
                // watcher observes the self-election on its first tick.
                if bootstrap_single_node {
                    let addr = raft_advertise_addr.clone().unwrap_or_else(|| bind.clone());
                    match yubaba::raft::bootstrap_single_node(&raft_node, node_id, addr).await {
                        Ok(true) => tracing::info!(
                            node_id,
                            "raft cluster-of-one initialised (single-node bootstrap)"
                        ),
                        Ok(false) => tracing::info!(
                            node_id,
                            "raft already initialised — single-node bootstrap is a no-op"
                        ),
                        Err(e) => return Err(e.context("single-node raft bootstrap")),
                    }
                }
                let shared_state = Arc::new(server_state);
                // R859-F2 / R858-T3: ONE derivation, handed to both consumers.
                // `ingress_owner` (written by the leadership watcher) and
                // `MemberInfo::machine` (written by the registration loop) are
                // only comparable — and `node_for_machine` only answers — if
                // they are the same string. Two calls to the same function made
                // that a convention; one value makes it a fact.
                let machine = yubaba::leader::derive_machine_name();
                // Spawn leadership watcher before serving so Headscale starts
                // immediately on the first leader election.
                let _watcher = yubaba::leader::spawn(
                    node_id,
                    raft_node.clone(),
                    Arc::clone(&shared_state),
                    machine.clone(),
                );
                // R734-F5: publish this node's own member row (address + region)
                // into replicated state, and keep it correct. Convergent and
                // non-fatal — see the module docs; nothing downstream waits on
                // it, so it is spawned and forgotten like the watcher above.
                // R737-F1: publish this node's schedulable budget in the same
                // row. Measured, not declared — `specs()` is the same collection
                // `GET /node/specs` serves and is cached after this first call,
                // so reading it here costs one probe rather than a second
                // capacity source that could disagree with the endpoint.
                let capacity = {
                    let specs = shared_state.node_probe.specs();
                    match (specs.allocatable_memory_mb, specs.allocatable_cpu_millis) {
                        // Both axes or neither. A half-measured node published as
                        // `cpu_millis: 0` would read as "unconstrained on CPU"
                        // (this system's spelling of zero) and take every tenant
                        // on the fleet, which is worse than being unschedulable.
                        (Some(memory_mb), Some(cpu_millis)) => Some(yubaba::raft::NodeCapacity {
                            memory_mb,
                            cpu_millis,
                        }),
                        _ => None,
                    }
                };
                let _member_registration = yubaba::member_registration::spawn(
                    node_id,
                    raft_node.clone(),
                    state_machine.clone(),
                    yubaba::raft::NodeDeclaration {
                        region,
                        capacity,
                        // R859-F2: the SAME derivation the leader path writes
                        // into `ingress_owner` — now literally the same value,
                        // not a second call that happens to agree (R858-T3).
                        machine,
                        // R859-F2 phase A: this box's public-ingress
                        // declaration, straight off the flags. A fleet node has
                        // no `.yah/infra/machines/` tree, so this row is the
                        // only place the leader can learn them.
                        provider,
                        location,
                        ingress_floating_ip,
                        public_address,
                    },
                );
                // R734-T4: soft leader pin. Started on every node, not just the
                // leader — a follower's loop reaches `NotLeader` and does
                // nothing, so there is no start/stop edge to get wrong across an
                // election. Paced off the policy's own timings, so a WAN cluster
                // is not evaluated at LAN speed.
                if let Some(anchor) = leader_anchor {
                    let _leader_pin = yubaba::leader_pin::spawn(
                        node_id,
                        raft_node.clone(),
                        state_machine.clone(),
                        yubaba::leader_pin::PinConfig::new(anchor, policy.timing),
                    );
                }
                // R859-F2 phase B: the public-ingress effector, built before
                // the scheduler because it rides that loop's tick. Config is
                // env-sourced (`YUBABA_INGRESS_APEX` + a fob-injected
                // Cloudflare token file), matching the ACME issuer's shape
                // rather than adding a fourth credential flag.
                //
                // A misconfiguration is fatal at startup ON PURPOSE. This is
                // the opposite of member registration's never-wedge-a-boot
                // rule, and the difference is what each failure costs: an
                // unregistered node is metadata nobody waits on, whereas an
                // effector that half-parsed its config discovers it during the
                // 3am failover it exists to perform. Unset is not a
                // misconfiguration — it is the default, and it is `None`.
                let ingress_effector = match yubaba::ingress_effector::parse_effector_config(
                    |k| std::env::var(k).ok(),
                ) {
                    Ok(Some(cfg)) => {
                        tracing::info!(
                            apex = cfg.apex.as_ref().map(|a| a.apex.as_str()).unwrap_or("-"),
                            zone_id = cfg.apex.as_ref().map(|a| a.zone_id.as_str()).unwrap_or("-"),
                            floating_ip_providers = %if cfg.floating_ip_token_files.is_empty() {
                                "-".to_string()
                            } else {
                                cfg.floating_ip_token_files
                                    .keys()
                                    .cloned()
                                    .collect::<Vec<_>>()
                                    .join(",")
                            },
                            "public-ingress effector armed: this node may withdraw dead origins \
                             from the apex and/or move an ingress floating IP"
                        );
                        Some(yubaba::ingress_effector::IngressEffector::from_config(&cfg)?)
                    }
                    Ok(None) => None,
                    Err(e) => anyhow::bail!("public-ingress effector configuration: {e}"),
                };
                // R737-F3: tenant placement scheduler. Started on every node
                // for the same reason as the leader pin above — a follower's
                // tick is a no-op. Unlike the pin, this has no operator flag
                // to gate it: a raft-configured node always has tenants that
                // could need re-placement.
                let _scheduler = yubaba::scheduler::spawn(
                    node_id,
                    raft_node.clone(),
                    state_machine.clone(),
                    yubaba::scheduler::SchedulerDeps {
                        lease_detector: shared_state.lease_detector.clone(),
                        // R737-F2: the raft-heartbeat channel supplies W253
                        // §7's `raft peer healthy` gate — as a veto only, never
                        // as grounds to place. See the scheduler module doc for
                        // why that direction is what keeps the two channels
                        // separate.
                        raft_detector: shared_state.failure_detector.clone(),
                        // R782: streamer_watermark_age's live source.
                        rpo_registry: shared_state.rpo_registry.clone(),
                        // R859-F2 phase B: public ingress follows placement.
                        // `None` unless YUBABA_INGRESS_APEX is set, which is
                        // every camp today — see `ingress_effector`'s module
                        // doc for why the fleet is allowed to subtract from the
                        // apex and nothing else.
                        ingress: ingress_effector,
                    },
                    yubaba::scheduler::SchedulerConfig::new(
                        policy.timing,
                        yubaba::lease_detector::HysteresisPolicy::from_thresholds(
                            policy.liveness_thresholds(),
                        ),
                    ),
                );
                // R118-F8: the membership ratchet. Unlike the scheduler above
                // this one is NOT started unconditionally — under
                // `MembershipRatchet::Frozen` (the fleet) every tick would hold
                // for the same reason forever, so not carrying the task is the
                // honest expression of "this cluster does not shrink itself".
                // Reads the policy FIELD, not a preset name.
                let _membership_ratchet = policy.membership_ratchet.floor().map(|_| {
                    yubaba::membership_ratchet::spawn(
                        node_id,
                        raft_node.clone(),
                        state_machine.clone(),
                        policy,
                        yubaba::membership_ratchet::RatchetConfig::default(),
                    )
                });
                // R118-T5: the rollout supervisor. Started on every node for
                // the same reason as the scheduler above — a follower's tick is
                // a no-op — and it is what makes an interrupted fleet image
                // update finish: without it a rollout is driven only by the
                // process that accepted it, and dies with that process.
                let _rollout_supervisor = yubaba::rollout::supervisor::spawn(
                    node_id,
                    raft_node.clone(),
                    state_machine.clone(),
                    yubaba::rollout::supervisor::SupervisorConfig::new(
                        policy.timing,
                        shared_state.prometheus_url.clone(),
                    ),
                );
                // R737-F3: the client half of the node-lease channel — without
                // this nothing ever calls `POST /mesh/lease-renew` and the
                // scheduler above never confirms anyone Up or Down. Paced off
                // the raft heartbeat so a detector gets several chances to
                // hear from a live node within `down_after`.
                let _lease_renewal = yubaba::lease_renewal::spawn(
                    node_id,
                    raft_node.clone(),
                    shared_state.lease_detector.clone(),
                    std::time::Duration::from_millis(policy.timing.heartbeat_interval_ms.max(1)),
                );
                // R737-T4: N+1 headroom accounting. Started on every node like
                // the scheduler above; only the leader has real liveness
                // evidence to act on, so a follower's tick is a no-op.
                let _headroom = yubaba::headroom::spawn(
                    node_id,
                    raft_node.clone(),
                    state_machine.clone(),
                    shared_state.lease_detector.clone(),
                    Arc::clone(&shared_state),
                    yubaba::headroom::HeadroomConfig::new(
                        policy.timing,
                        yubaba::lease_detector::HysteresisPolicy::from_thresholds(
                            policy.liveness_thresholds(),
                        ),
                    ),
                );
                // R600-F4 (W273): every node consuming a cluster cert runs the
                // rotation watcher — not just the elected issuer. On a replicated
                // cert renewal it re-renders the local tmpfs mount and graceful-
                // upgrades the consuming workload. No-op until a workload with a
                // cluster File secret is deployed on this node.
                tokio::spawn(yubaba::secret_reload::run(Arc::clone(&shared_state)));
                // R600-F10: the same delivery for a door systemd supervises
                // rather than kamaji. The watcher above finds its consumers in
                // the deployed-workload registry, so on a node whose passway is
                // a hand-rolled unit it has nothing to re-render; this writes
                // the pair to two configured paths instead. Opt-in on
                // YUBABA_CERT_FILES_DOMAIN and inert without it.
                tokio::spawn(yubaba::cert_materialize::run(Arc::clone(&shared_state)));
                // R869 (W339): the off-fleet copy of the applied raft state —
                // the one input a cluster needs that lived nowhere but the
                // voters' own disks. Opt-in on YUBABA_STATE_BACKUP_CLUSTER, and
                // it rides the cert store's bucket and credentials rather than
                // asking for its own: a disaster-recovery mechanism that needs
                // config the fleet does not already carry is one that is not
                // there when the disaster happens. Spawned on every node like
                // the scheduler; only the leader ships a copy.
                match yubaba::state_backup::StateBackupConfig::parse(|k| std::env::var(k).ok()) {
                    Ok(Some(backup_cfg)) => match shared_state.cert_store.as_ref() {
                        Some(cert_store) => {
                            let _state_backup = yubaba::state_backup::spawn(
                                node_id,
                                raft_node.clone(),
                                state_machine.clone(),
                                cert_store.objects(),
                                backup_cfg,
                            );
                        }
                        // Reachable despite the config check, which reads env:
                        // the store is built earlier and its connect() is
                        // non-fatal, so an unreachable bucket lands here.
                        None => tracing::error!(
                            "state backup configured but the cert store did not connect — the \
                             raft state has NO off-fleet copy on this node (fix the \
                             YUBABA_CERT_STORE_* credentials)"
                        ),
                    },
                    Ok(None) => {}
                    Err(e) => tracing::error!(
                        "state backup config invalid — the raft state has NO off-fleet copy \
                         (fix YUBABA_STATE_BACKUP_*): {e}"
                    ),
                }
                // R600-F3 (W273): the fleet-shared ACME issuer. Opt-in — only
                // spawns when YUBABA_ACME_DOMAIN et al are set (the HA fleet),
                // and only one node issues at a time (raft-lock elected). Reads
                // the stored cert's age via the state-machine handle to decide
                // renewal; seals cert+key under the node KEK and PutSecrets them.
                match yubaba::acme_issuer::parse_issuer_config(|k| std::env::var(k).ok()) {
                    Ok(Some(issuer_cfg)) => {
                        let _issuer = yubaba::acme_issuer::spawn(
                            node_id,
                            raft_node,
                            state_machine,
                            issuer_cfg,
                            // R870-B20: the node's store, connected above, handed
                            // in as the issuer's mirror. The issuer no longer
                            // parses or connects one of its own.
                            shared_state.cert_store.clone(),
                        );
                    }
                    Ok(None) => {}
                    Err(e) => tracing::error!(
                        "acme issuer config invalid — issuer not started (fix YUBABA_ACME_*): {e}"
                    ),
                }
                serve(&bind, shared_state).await
            } else {
                // Single-node mode: real containerd runtime, no raft mesh.
                // This is the intentional surface tested before adding HA (R276-F4).
                // Use --raft-node-id to enable the cluster coordination layer.
                if let Some(region) = &region {
                    // Not fatal — the flag is harmless here — but silence would
                    // let an operator believe a node is tagged when there is no
                    // cluster for the tag to reach.
                    tracing::warn!(
                        %region,
                        "--region has no effect without --raft-node-id: there is no raft \
                         cluster to publish this node's member row to"
                    );
                }
                if let Some(group) = &sovereign_group {
                    // The most dangerous of the three to pass silently: an
                    // operator who set it believes cross-group joins are being
                    // refused, and there is no raft here to refuse one.
                    tracing::warn!(
                        %group,
                        "--sovereign-group has no effect without --raft-node-id: there is no \
                         raft cluster, so no join can be refused"
                    );
                }
                if let Some(jurisdiction) = &jurisdiction {
                    // R736-T3. Same shape as the group above and dangerous for
                    // the same reason, one level up: this declares the node a
                    // member of a residency CELL, and a cell with no raft has no
                    // join to refuse — so the boundary an operator believes is
                    // being enforced is not.
                    tracing::warn!(
                        %jurisdiction,
                        "--jurisdiction has no effect without --raft-node-id: a cell is one raft \
                         group, and there is no raft cluster here to bind to a jurisdiction"
                    );
                }
                if !sovereign_role.is_voter() {
                    // R605-F12. Not an error: this is the *expected* shape for
                    // us-west-003 — a non-voting member runs standalone, with
                    // no raft node id, which is exactly what the role declares.
                    // Logged at info so the box's own logs record the claim,
                    // because the only other place it appears is a TOML in a
                    // camp this process cannot see.
                    tracing::info!(
                        role = %sovereign_role,
                        "declared non-voting and running without --raft-node-id, which is the \
                         consistent pair: this node holds no raft seat and asserts it should \
                         not"
                    );
                }
                if let Some(anchor) = &leader_anchor {
                    // Same reasoning as `--region` above: harmless, but an
                    // operator who passed it believes leadership is pinned.
                    tracing::warn!(
                        %anchor,
                        "--leader-anchor has no effect without --raft-node-id: there is no \
                         raft leadership to steer"
                    );
                }
                // R859-F2 phase A. Same shape as `--region` and warned about as
                // one group, because they are one declaration: they only ever
                // travel together and a node missing any of them is equally
                // un-actable. Dangerous to pass silently for the reason
                // `--sovereign-group` is — an operator who set `--public-address`
                // believes this box can be withdrawn from the apex when it dies,
                // and with no raft there is no member row, no leader, and no
                // effector.
                if provider.is_some()
                    || location.is_some()
                    || ingress_floating_ip.is_some()
                    || public_address.is_some()
                {
                    tracing::warn!(
                        provider = ?provider,
                        location = ?location,
                        ingress_floating_ip = ?ingress_floating_ip,
                        public_address = ?public_address,
                        "the public-ingress declaration has no effect without --raft-node-id: \
                         there is no raft member row to publish it into, so nothing can withdraw \
                         this node from the apex when it dies"
                    );
                }
                // The effector is leader-driven and is built inside the raft
                // branch, so on this path it is never even parsed. Saying so
                // matters more than the flags above: a configured apex plus a
                // live Cloudflare token — or a vendor token file — reads like an
                // armed failover. Both arms warn, because either alone is enough
                // for an operator to believe this node will act (R859-F3).
                if let Ok(apex) = std::env::var(yubaba::ingress_effector::APEX_ENV) {
                    tracing::warn!(
                        %apex,
                        "{} has no effect without --raft-node-id: the ingress effector runs on \
                         the raft leader, and there is no raft cluster here",
                        yubaba::ingress_effector::APEX_ENV
                    );
                }
                for (provider, _, _) in floating_ip::FLOATING_IP_PROVIDERS {
                    let key = yubaba::ingress_effector::floating_ip_token_file_env(provider);
                    if std::env::var(&key).is_ok() {
                        tracing::warn!(
                            %provider,
                            "{key} has no effect without --raft-node-id: the ingress effector \
                             runs on the raft leader, and there is no raft cluster here"
                        );
                    }
                }
                tracing::info!(
                    "yubaba running in single-node mode — \
                     containerd runtime active, raft mesh disabled. \
                     Deploy workloads with `yah cloud workload deploy`. \
                     Pass --raft-node-id to enable cluster coordination."
                );
                serve(&bind, Arc::new(server_state)).await
            }
        }

        Cmd::RegisterHostkey { pubkey_path, state } => {
            let id = identity::parse_pubkey_file(&pubkey_path)
                .with_context(|| format!("parsing {}", pubkey_path.display()))?;
            let mut on_disk = identity::load_state(&state)?;
            on_disk.identity = Some(id.clone());
            identity::save_state(&state, &on_disk)?;
            println!("{}", id.hostkey_fingerprint);
            Ok(())
        }

        Cmd::Raft { daemon, cmd } => match cmd {
            RaftCmd::Status => {
                let body: serde_json::Value = reqwest::get(format!("{daemon}/raft/status"))
                    .await?
                    .json()
                    .await?;
                println!("{}", serde_json::to_string_pretty(&body)?);
                Ok(())
            }
            RaftCmd::Init { members } => {
                let mut parsed = std::collections::BTreeMap::new();
                for m in &members {
                    let (id, rest) = m.split_once('=').ok_or_else(|| {
                        anyhow::anyhow!("--member must be id=host:port[@region], got {m:?}")
                    })?;
                    let id: u64 = id
                        .parse()
                        .with_context(|| format!("--member node id must be a u64, got {id:?}"))?;
                    // Split on the LAST '@': a mesh address never contains one
                    // today, but rsplit keeps this correct if a user@host form
                    // ever shows up, and a bare address stays a bare address.
                    let (addr, region) = match rest.rsplit_once('@') {
                        Some((addr, region)) if !region.is_empty() => (addr, Some(region)),
                        _ => (rest, None),
                    };
                    parsed.insert(id, serde_json::json!({ "addr": addr, "region": region }));
                }
                let client = reqwest::Client::new();
                let resp = client
                    .post(format!("{daemon}/raft/initialize"))
                    .json(&serde_json::json!({ "members": parsed }))
                    .send()
                    .await?;
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                if status.is_success() {
                    println!("{body}");
                } else {
                    anyhow::bail!("raft init failed ({status}): {body}");
                }
                Ok(())
            }
            RaftCmd::AddLearner { node_id, addr } => {
                let client = reqwest::Client::new();
                let resp = client
                    .post(format!("{daemon}/raft/add-learner"))
                    .json(&serde_json::json!({ "node_id": node_id, "addr": addr }))
                    .send()
                    .await?;
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                if status.is_success() {
                    println!("{body}");
                } else {
                    anyhow::bail!("raft add-learner failed ({status}): {body}");
                }
                Ok(())
            }
            RaftCmd::PromoteVoter { node_id } => {
                let client = reqwest::Client::new();
                let resp = client
                    .post(format!("{daemon}/raft/promote-voter"))
                    .json(&serde_json::json!({ "node_id": node_id }))
                    .send()
                    .await?;
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                if status.is_success() {
                    println!("{body}");
                } else {
                    anyhow::bail!("raft promote-voter failed ({status}): {body}");
                }
                Ok(())
            }
            RaftCmd::RemoveMember { node_ids } => {
                let client = reqwest::Client::new();
                let resp = client
                    .post(format!("{daemon}/raft/remove-member"))
                    .json(&serde_json::json!({ "node_ids": node_ids }))
                    .send()
                    .await?;
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                if status.is_success() {
                    println!("{body}");
                } else {
                    anyhow::bail!("raft remove-member failed ({status}): {body}");
                }
                Ok(())
            }
            RaftCmd::Peers => {
                // Membership says who the cluster believes in; the liveness
                // section (R118-T9, present when a failure detector is wired)
                // says which of them the leader has actually heard from.
                let body: serde_json::Value = reqwest::get(format!("{daemon}/raft/status"))
                    .await?
                    .json()
                    .await?;
                let peers = serde_json::json!({
                    "membership": &body["membership_config"],
                    "liveness": &body["liveness"],
                });
                println!("{}", serde_json::to_string_pretty(&peers)?);
                Ok(())
            }
            RaftCmd::TransferLeader { to } => {
                let client = reqwest::Client::new();
                let resp = client
                    .post(format!("{daemon}/raft/transfer-leader"))
                    .json(&serde_json::json!({ "to": to }))
                    .send()
                    .await?;
                if resp.status().is_success() {
                    println!("leadership transfer to node {to} initiated");
                } else {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    anyhow::bail!("transfer-leader failed ({status}): {body}");
                }
                Ok(())
            }
        },
        Cmd::Domain { cmd } => run_domain_cmd(cmd),
        Cmd::Holding { cmd } => run_holding_cmd(cmd),
        // Off the runtime, unlike its two siblings above — see `run_state_cmd`.
        Cmd::State { cmd } => tokio::task::spawn_blocking(move || run_state_cmd(cmd)).await?,
    }
}

/// R869 (W339) — the `state` verbs, against the object store directly.
///
/// Synchronous, like [`run_domain_cmd`] and [`run_holding_cmd`]: the
/// object-store API is blocking and these are one-shot commands.
///
/// **Called through `spawn_blocking`, unlike those two, and that is not
/// stylistic.** `R2ObjectStore::new` builds a `reqwest::blocking::Client`,
/// whose constructor drops a temporary tokio runtime; `reqwest::blocking`
/// asserts against that happening inside an async context, so calling this
/// directly from the async `main` panics with "Cannot drop a runtime in a
/// context where blocking is not allowed" before it reads a single byte.
///
/// The assert is `#[cfg(debug_assertions)]`, so a **release** binary — which is
/// what `/usr/local/bin/yubaba` is — never trips it. That asymmetry is exactly
/// why this is worth fixing rather than documenting: these are the
/// disaster-recovery verbs, the one family somebody may well run from a
/// `cargo build` of a checkout on a machine that has nothing installed on it,
/// and discovering they panic is a terrible thing to discover during a
/// recovery. `yubaba domain` and `yubaba holding` still have the un-wrapped
/// shape and still panic from a debug build; that is their tickets' call, not
/// R869's.
fn run_state_cmd(cmd: StateCmd) -> Result<()> {
    use yubaba::state_backup;

    let backup = state_backup::connect_from_env(|k| std::env::var(k).ok())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Both readers name the same "there is nothing there" case, and it is worth
    // a sentence rather than an empty print: on a rebuild, "no copy" and "a copy
    // of an empty cluster" lead to completely different next actions.
    let read = |lineage: Option<u64>| -> Result<state_backup::StateSnapshot> {
        let found = match lineage {
            Some(n) => backup.read_lineage(n)?,
            None => backup.read_latest()?,
        };
        found.ok_or_else(|| match lineage {
            Some(n) => anyhow::anyhow!(
                "cluster {} has no retired lineage {n}. Retired lineages: {:?}",
                backup.cluster(),
                backup.lineages().unwrap_or_default()
            ),
            None => anyhow::anyhow!(
                "cluster {} has never shipped an off-fleet copy ({} does not exist). Nothing to \
                 restore from — this is not the same as a copy of an empty cluster.",
                backup.cluster(),
                backup.locate_latest()
            ),
        })
    };

    match cmd {
        StateCmd::Show { lineage, json } => {
            let snap = read(lineage)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&snap)?);
                return Ok(());
            }
            println!("cluster        {}", backup.cluster());
            println!("object         {}", backup.locate_latest());
            println!("lineage        {}", snap.lineage);
            println!("applied index  {}", snap.applied_index);
            println!(
                "taken at       {} ({}s ago)",
                snap.taken_at,
                now.saturating_sub(snap.taken_at)
            );
            println!(
                "written by     node {} on yubaba {}",
                snap.node_id, snap.version
            );
            println!("retired        {:?}", backup.lineages().unwrap_or_default());
            println!();
            println!("members            {}", snap.state.members.len());
            println!("service placement  {}", snap.state.service_placement.len());
            println!("cluster secrets    {}", snap.state.secrets.len());
            println!("tenants            {}", snap.state.tenants.len());
            println!("tenant placement   {}", snap.state.placement.len());
            println!("ingress owner      {:?}", snap.state.ingress_owner);
            println!(
                "dropped on restore locks={} rollouts={}",
                snap.state.locks.len(),
                snap.state.rollouts.len()
            );
            Ok(())
        }
        StateCmd::Restore {
            dir,
            lineage,
            dry_run,
        } => {
            let snap = read(lineage)?;
            let state = state_backup::restorable(snap.clone());
            println!(
                "restoring cluster {} lineage {} applied index {} (taken {}s ago) into {}",
                backup.cluster(),
                snap.lineage,
                snap.applied_index,
                now.saturating_sub(snap.taken_at),
                dir.display()
            );
            println!(
                "  members={} services={} secrets={} tenants={} placement={} (locks and rollouts \
                 dropped)",
                state.members.len(),
                state.service_placement.len(),
                state.secrets.len(),
                state.tenants.len(),
                state.placement.len()
            );
            if dry_run {
                println!("dry run — nothing written");
                return Ok(());
            }
            yubaba::raft::store::seed_state_machine(&dir, &state)
                .with_context(|| format!("seeding {}", dir.display()))?;
            println!("wrote {}/raft_state.json", dir.display());
            println!(
                "next: repeat on every founding voter, start yubaba with --raft-node-id, then \
                 `yubaba raft init --member ...` exactly once, then \
                 `yubaba-tenant-streamer rebuild` before starting any streamer. The restored \
                 fencing epochs mean the first claim on each tenant outranks any survivor \
                 holding an epoch from before this copy was taken — but the R2 sink is still the \
                 authority on what it accepts, and `rebuild` is what reads its floor and lifts \
                 over it if this copy was stale. Skipping it is silent: a fenced tenant is \
                 dropped, not paged."
            );
            Ok(())
        }
        StateCmd::Adopt => {
            let before = read(None)?;
            let lineage = backup.adopt(now)?;
            println!(
                "adopted: cluster {} is now lineage {lineage}. The previous copy (lineage {}, \
                 applied index {}) is archived — read it with `yubaba state show --lineage {}` \
                 and restore from it with `yubaba state restore --lineage {}`.",
                backup.cluster(),
                before.lineage,
                before.applied_index,
                before.lineage,
                before.lineage
            );
            Ok(())
        }
    }
}

/// R779 (W267) — the `domain` verbs, against the object store directly.
///
/// Synchronous inside an async `main` on purpose: [`yubaba::cert_store`]'s API
/// is blocking, these are one-shot commands with nothing else on the runtime,
/// and wrapping four `get`s in `spawn_blocking` would buy nothing but noise.
fn run_domain_cmd(cmd: DomainCmd) -> Result<()> {
    use yubaba::domain_admin::{self, DomainReport};

    let cfg = domain_admin::parse_admin_config(|k| std::env::var(k).ok())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let store = cfg
        .connect()
        .with_context(|| format!("opening cert store bucket {}", cfg.store.bucket))?;
    let zone = cfg.delegate_zone.as_deref();
    let now = std::time::SystemTime::now();
    let now_secs = now
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    match cmd {
        DomainCmd::Enroll {
            domain,
            tls_backend,
            http_backend,
            ingress,
            json,
        } => {
            let onboarding = domain_admin::enroll(
                &store,
                &domain,
                tls_backend,
                http_backend,
                zone,
                ingress,
                now,
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&onboarding.to_json())?);
            } else {
                println!("enrolled {domain} -> {tls_backend}\n");
                print!("{}", onboarding.render());
            }
            Ok(())
        }
        DomainCmd::Unenroll {
            domain,
            forget_cert,
        } => {
            store.unenroll(&domain)?;
            println!("unenrolled {domain} — the demux drops the route on its next sweep");
            if forget_cert {
                store.delete_domain(&domain)?;
                println!(
                    "deleted the sealed cert, key and any issuance claim; re-enrolling \
                     will place a fresh ACME order"
                );
            } else {
                println!(
                    "certificate material kept — re-enrolling costs no ACME order \
                     (pass --forget-cert to delete it)"
                );
            }
            Ok(())
        }
        DomainCmd::List { json } => {
            let rows = domain_admin::list(&store)?;
            if json {
                let out: Vec<serde_json::Value> = rows
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "domain": r.domain,
                            "has_cert": r.has_cert,
                            "tls_backend": r.enrollment.tls_backend.to_string(),
                            "http_backend": r.enrollment.http_backend.map(|a| a.to_string()),
                            "enrolled_at": r.enrollment.enrolled_at,
                            "holding": r.enrollment.holding,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                print!("{}", domain_admin::render_list(&rows));
            }
            Ok(())
        }
        DomainCmd::Status { domain, json } => {
            let report = DomainReport::collect(&store, &domain, zone)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report.to_json(now_secs))?
                );
            } else {
                print!("{}", report.render(now_secs));
            }
            Ok(())
        }
        DomainCmd::Holding {
            domain,
            page,
            clear,
        } => {
            let page = if clear { None } else { page.as_deref() };
            store.set_holding(&domain, page)?;
            match page {
                Some(name) => println!(
                    "{domain} now shows the {name:?} holding page — doors pick it up on \
                     their next sweep"
                ),
                None => println!("{domain} is back to passway's own holding page"),
            }
            if let Some(name) = page {
                if store.holding_page(name)?.is_none() {
                    println!(
                        "note: no page is stored under {name:?} yet — until one is \
                         (`yubaba holding put {name} <file>`), those doors keep the \
                         default page"
                    );
                }
            }
            Ok(())
        }
    }
}

/// `yubaba holding …` — the page bodies, beside the enrollment set (R870-F8).
fn run_holding_cmd(cmd: HoldingCmd) -> Result<()> {
    use yubaba::domain_admin;

    let cfg = domain_admin::parse_admin_config(|k| std::env::var(k).ok())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let store = cfg
        .connect()
        .with_context(|| format!("opening cert store bucket {}", cfg.store.bucket))?;

    match cmd {
        HoldingCmd::Put { name, file } => {
            let body =
                std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            let bytes = body.len();
            store.write_holding_page(&name, body)?;
            println!(
                "stored holding page {name:?} ({bytes} bytes) — doors serving a domain \
                 that names it pick it up on their next sweep"
            );
            Ok(())
        }
        HoldingCmd::List => {
            let names = store.holding_pages()?;
            if names.is_empty() {
                println!("no holding pages stored — every parked domain shows passway's own");
            }
            for name in names {
                println!("{name}");
            }
            Ok(())
        }
        HoldingCmd::Remove { name } => {
            store.delete_holding_page(&name)?;
            println!(
                "deleted holding page {name:?} — any domain still naming it falls back to \
                 passway's own page"
            );
            Ok(())
        }
    }
}

/// Attach a `ContainerRuntime` to the server state when one is available.
///
/// With the `containerd-integration` feature, connect to the containerd socket
/// and wire `ContainerdRuntime` so `/workloads/*` deploy real containers. On
/// connection failure the daemon stays up in stub mode — the other endpoints
/// (`/identity`, `/raft/*`, `/headscale/*`) don't depend on containerd, and a
/// loud warning tells the operator workloads won't deploy until it's reachable.
///
/// Without the feature, the binary has no container backend compiled in, so
/// `/workloads/deploy` reports `runtime=stub`. The single-node deploy path
/// (R276) requires a binary built with `--features containerd-integration`.
#[allow(unused_variables, unused_mut)]
async fn attach_runtime(mut state: ServerState, containerd_socket: &str) -> ServerState {
    #[cfg(feature = "containerd-integration")]
    {
        match kamaji::containerd::ContainerdRuntime::connect_at(containerd_socket).await {
            Ok(rt) => {
                tracing::info!(
                    socket = %containerd_socket,
                    "containerd runtime attached; /workloads/* are live"
                );
                state = state.with_runtime(Arc::new(rt));
            }
            Err(e) => {
                tracing::warn!(
                    socket = %containerd_socket,
                    error = %e,
                    "containerd unreachable; /workloads/deploy runs in stub mode \
                     until the socket is available"
                );
            }
        }
    }
    #[cfg(not(feature = "containerd-integration"))]
    {
        tracing::warn!(
            "yah-yubaba built without the containerd-integration feature; \
             /workloads/deploy runs in stub mode (rebuild with \
             --features containerd-integration to deploy real containers)"
        );
    }
    state
}

/// Wire the pond [`local_driver::LocalRuntime`] when a docker socket is
/// reachable, flipping `POST /pond/deploy` from 503 to live.
///
/// The containerized pond yubaba (R454-F1) gets the host docker socket
/// bind-mounted at `/var/run/docker.sock` (see
/// `local_driver::pond_warden::build_warden_run_spec`); sibling MinIO/
/// miniflare containers spawn through it as host siblings, never
/// docker-in-docker. `DOCKER_HOST` overrides the socket path for
/// non-standard runtimes. When neither is present (cloud/systemd nodes),
/// pond stays unwired and the routes answer 503 — that's the correct
/// shape for non-pond deployments.
async fn attach_pond_runtime(state: ServerState) -> ServerState {
    let docker_host = match std::env::var("DOCKER_HOST") {
        Ok(h) if !h.trim().is_empty() => h,
        _ => {
            let sock =
                std::path::Path::new(local_driver::pond_warden::DOCKER_SOCKET_CONTAINER_PATH);
            if !sock.exists() {
                tracing::info!(
                    socket = %sock.display(),
                    "no docker socket mounted; pond deploy routes stay 503 \
                     (expected outside pond)"
                );
                return state;
            }
            format!("unix://{}", sock.display())
        }
    };

    let spec = local_driver::LocalContainerSpec {
        runtime: local_driver::RuntimePref::Custom,
        discovery: Default::default(),
        custom_docker_host: Some(docker_host.clone()),
    };
    match local_driver::LocalRuntime::detect(&spec).await {
        Ok(rt) => {
            tracing::info!(
                docker_host = %docker_host,
                probe_host = %local_driver::pond_probe_host(),
                "pond LocalRuntime attached; /pond/deploy is live"
            );
            state.with_pond_local_runtime(Arc::new(rt))
        }
        Err(e) => {
            tracing::warn!(
                docker_host = %docker_host,
                error = %e,
                "pond LocalRuntime detect failed; /pond/deploy stays 503"
            );
            state
        }
    }
}

/// Bind the yah control-plane endpoint when `--control-plane` is set, spawn
/// its accept loop, and log the `NodeId` an operator dials.
///
/// The endpoint's key is loaded from the same hostkey directory
/// [`ServerState::load`] generated into, so the NodeId equals `GET
/// /identity`'s `node_id` and is stable across restarts by construction.
///
/// Bind failure is non-fatal, deliberately: the control plane is one of
/// four planes (A032), and losing it must not take `/identity`, `/raft/*`
/// or `/workloads/*` down with it. The warning names the directory, which
/// is the actionable half — a bind failure here is almost always an
/// unreadable key rather than a busy socket.
#[allow(clippy::too_many_arguments)]
async fn attach_control_plane(
    state: ServerState,
    enabled: bool,
    camp_rpc_roots: Vec<PathBuf>,
    camp_rpc_yah_bin: String,
    control_plane_allow: Vec<String>,
    seeds: mshr::Seeds,
    seed_flags_given: bool,
) -> Result<ServerState> {
    if !enabled {
        if seed_flags_given {
            tracing::warn!(
                seeds = %seeds.describe(),
                "--xlb-seed / --xlb-relay / --xlb-pkarr given without --control-plane; they \
                 configure that endpoint's discovery, so nothing uses them"
            );
        }
        if !camp_rpc_roots.is_empty() {
            // Silently ignoring the roots would leave an operator staring at
            // a node that answers /identity but refuses every dial, with
            // nothing in the log to say why.
            tracing::warn!(
                roots = ?camp_rpc_roots,
                "--camp-rpc-root given without --control-plane; the camp-rpc lane rides that \
                 endpoint, so nothing is served"
            );
        }
        if !control_plane_allow.is_empty() {
            tracing::warn!(
                allow = ?control_plane_allow,
                "--control-plane-allow given without --control-plane; no endpoint is bound, \
                 so nothing is gated"
            );
        }
        return Ok(state);
    }
    let hostkey_dir = state.hostkey_dir();
    let admission = build_admission(&state, &hostkey_dir, control_plane_allow)?;
    let planes = yubaba::control_plane::Planes {
        camp_rpc: (!camp_rpc_roots.is_empty()).then_some(yubaba::camp_rpc::CampRpcConfig {
            yah_bin: camp_rpc_yah_bin,
            roots: camp_rpc_roots,
        }),
        admission,
        // Always Some on a real daemon: a node that binds the control plane
        // in order to be dialed but resolves nothing is the failure R609-F4
        // exists to remove. `None` stays reserved for the in-process tests
        // that want two isolated endpoints.
        seeds: Some(seeds),
    };
    if planes.camp_rpc_withheld() {
        // ERROR, not WARN: the operator asked for a lane and is not getting
        // it. Left at WARN this reads as advisory noise next to the bind
        // logs, and the failure it prevents (any NodeId execing `yah camp`
        // here) is exactly the one worth being loud about.
        tracing::error!(
            "--camp-rpc-root is set but nothing gates who may dial: the camp-rpc lane is \
             WITHHELD and its ALPN unadvertised. Admitting that lane spawns a process, so it \
             needs an admission policy — pass --control-plane-allow <node-id> (the dialing \
             machine's /identity node_id) or configure a cheers client."
        );
    }
    let endpoint = match yubaba::control_plane::bind_planes(&hostkey_dir, &planes).await {
        Ok(ep) => ep,
        Err(e) => {
            tracing::warn!(
                hostkey_dir = %hostkey_dir.display(),
                error = format!("{e:#}"),
                "control-plane endpoint bind failed; this node is not dialable \
                 by NodeId (HTTP surface unaffected)"
            );
            return Ok(state);
        }
    };

    // Identity is loaded by `ServerState::load`; a node that failed to
    // generate one still binds (mshr mints its own key), but its greeting
    // can only carry what the endpoint itself knows.
    let identity = state
        .state
        .lock()
        .expect("identity state mutex poisoned")
        .identity
        .clone();
    let node_id = endpoint.node_id().to_string();
    let hello = yubaba::control_plane::Hello::new(
        node_id.clone(),
        identity.as_ref().map(|id| id.hostkey_fingerprint.clone()),
    );

    tracing::info!(
        node_id = %node_id,
        alpn = yubaba::control_plane::CONTROL_PLANE_ALPN_STR,
        addr = ?endpoint.endpoint_addr(),
        admission = ?planes.admission,
        seeds = %planes.seeds().describe(),
        "yah control plane listening — dial this node by NodeId"
    );
    if !endpoint.resolves_bare_node_ids() {
        // WARN, not INFO: the node IS listening, so nothing looks wrong from
        // here, but a caller holding only its NodeId gets "No addressing
        // information available" — a message that names nothing they can act
        // on. This log is the half that does.
        tracing::warn!(
            "no discovery lane is configured: this node is reachable only by a caller that \
             already holds its address. Pass --xlb-pkarr (or leave it unset for the shipped \
             default) so a bare NodeId resolves."
        );
    }
    if let Some(camp_rpc) = planes.camp_rpc_lane() {
        tracing::info!(
            alpn = yubaba::camp_rpc::CAMP_RPC_ALPN_STR,
            roots = ?camp_rpc.roots,
            yah_bin = %camp_rpc.yah_bin,
            "camp-rpc lane serving — admitted NodeIds may spawn `yah camp` under these roots"
        );
    }

    let accept_endpoint = endpoint.clone();
    let accept_planes = planes.clone();
    tokio::spawn(async move {
        if let Err(e) =
            yubaba::control_plane::run_planes(accept_endpoint, hello, accept_planes).await
        {
            tracing::warn!(error = format!("{e:#}"), "control-plane accept loop exited");
        }
    });

    Ok(state.with_control_plane_planes(endpoint, planes))
}

/// Assemble the control plane's [`Admission`](yubaba::control_plane::Admission)
/// policy from the operator's allowlist and whatever cheers client this
/// daemon holds (R609-F3).
///
/// No `--control-plane-allow` and no cheers client leaves the pre-F3
/// admit-everyone posture: that is what the bare greeting lane was
/// designed for, and flipping an unconfigured node to default-deny would
/// make `--control-plane` mean "bind a socket nobody may use". Give it
/// either source and the endpoint becomes default-deny.
///
/// A malformed allowlist entry is **fatal**, not skipped. The failure mode
/// of tolerating it — a node that boots clean and then refuses the one
/// desktop the operator meant to admit — is discovered at the worst
/// possible time, over a transport with no other way in.
fn build_admission(
    state: &ServerState,
    hostkey_dir: &std::path::Path,
    control_plane_allow: Vec<String>,
) -> Result<yubaba::control_plane::Admission> {
    use yubaba::control_plane::{Admission, Entitlement, DEFAULT_ENROLLMENT_TTL};

    let cheers = state.cheers_client.clone();
    if control_plane_allow.is_empty() && cheers.is_none() {
        tracing::warn!(
            "control plane admits ANY NodeId — no --control-plane-allow entries and no cheers \
             client configured. Only the reachability greeting is served in this posture."
        );
        return Ok(Admission::AllowAll);
    }

    let mut allowed = Vec::with_capacity(control_plane_allow.len() + 1);
    for raw in &control_plane_allow {
        let node: mshr::NodeId = raw.trim().parse().with_context(|| {
            format!(
                "--control-plane-allow {raw:?} is not a NodeId (expected the 64-char hex \
                     `node_id` from the dialing machine's GET /identity)"
            )
        })?;
        allowed.push(node);
    }

    // The node's own NodeId, so a dial from this machine to itself — the
    // obvious way to verify the plane from the box you just provisioned —
    // isn't refused by the policy that machine is enforcing.
    match yubaba::control_plane::node_id_at(hostkey_dir) {
        Ok(self_id) => allowed.push(self_id),
        Err(e) => tracing::warn!(
            error = format!("{e:#}"),
            "could not resolve this node's own NodeId for the admission allowlist; \
             self-dials will be refused"
        ),
    }

    let mut entitlement = Entitlement::new().allow_all_of(allowed);
    if let Some(cheers) = cheers {
        entitlement = entitlement.with_cheers(cheers, DEFAULT_ENROLLMENT_TTL);
    }
    tracing::info!(
        allowlisted = entitlement.allowlisted(),
        cheers_enrollment = entitlement.has_cheers(),
        "control-plane admission: default-deny"
    );
    Ok(Admission::entitled(entitlement))
}

/// Connect to Kamaji when `--kamaji-socket` is set, retrying with backoff to
/// ride out the sibling unit's socket-bind gap on a fresh boot (see
/// [`KAMAJI_CONNECT_BUDGET_SECS`]). If the whole budget is exhausted, log a
/// warning and leave `constable_client = None` so yubaba falls back to the
/// legacy in-process runtime.
async fn attach_constable_client(state: ServerState, socket: Option<PathBuf>) -> ServerState {
    let Some(socket) = socket else {
        return state;
    };
    let per_attempt = std::time::Duration::from_secs(CONSTABLE_CONNECT_TIMEOUT_SECS);
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(KAMAJI_CONNECT_BUDGET_SECS);
    let mut backoff = std::time::Duration::from_millis(500);
    let last_err = loop {
        match kamaji::sibling::connect_with_timeout(socket.clone(), per_attempt).await {
            Ok(client) => {
                tracing::info!(
                    socket = %socket.display(),
                    kamaji_version = %client.info().kamaji_version,
                    "kamaji client attached; workload list/state/drain dispatch \
                     through UDS"
                );
                // KamajiSibling (not a bare client) so a later `systemctl
                // restart kamaji` — e.g. a binary swap — doesn't strand this
                // yubaba on PeerClosed until it, too, is restarted (R406-T8
                // gap, live incident 2026-08-13).
                let sibling = kamaji::sibling::KamajiSibling::new(client, socket, per_attempt);
                return state.with_constable_client(sibling);
            }
            Err(e) => {
                let now = std::time::Instant::now();
                if now >= deadline {
                    break e;
                }
                // Never sleep past the budget deadline.
                let nap = backoff.min(deadline - now);
                tracing::debug!(
                    socket = %socket.display(),
                    error = %e,
                    retry_in = ?nap,
                    "kamaji UDS not ready yet (sibling unit still settling); retrying"
                );
                tokio::time::sleep(nap).await;
                backoff = (backoff * 2).min(std::time::Duration::from_secs(3));
            }
        }
    };
    tracing::warn!(
        socket = %socket.display(),
        error = %last_err,
        budget_secs = KAMAJI_CONNECT_BUDGET_SECS,
        "kamaji UDS connect failed within budget; falling back to in-process \
         ContainerRuntime for workload lifecycle"
    );
    state
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    // `yubaba` = lib target; `yah_warden` = this binary crate (where the
    // serve-time runtime-attach + channel lines are emitted). Include both so
    // the stub-mode warning is visible by default.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("yubaba=info,yah_warden=info,axum=info"));
    // JSON format: one structured line per event, carrying all tracing fields
    // (including the request_id + session_id stamped by the correlation-ID
    // middleware). Agents and scryer ingest these lines directly; the desktop
    // pretty-prints them for humans.
    fmt().with_env_filter(filter).json().init();
}

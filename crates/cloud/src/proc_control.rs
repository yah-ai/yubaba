//! The **process-control channel** — how a yah-supervised process describes
//! itself to its supervisor and to an agent, instead of being guessed at from
//! the outside.
//!
//! ## Why this is opinionated
//!
//! Everything yah runs is supervised by something in the kamaji family, and
//! until now the supervisor's only questions were "is the pid alive?" and "is
//! the port open?". Both are proxies. A process that has finished booting, a
//! process still replaying a WAL, and a process wedged on a lock all answer
//! them identically — so the only richer signal available to an operator or
//! an agent was grepping the log tail for a line somebody hopefully logged.
//!
//! So: **any process built to run under a yah camp SHOULD expose a control
//! channel**, dev tier or cloud tier, port or no port. It is the difference
//! between an agent reading `state = "starting", detail = "migrating 3/7"`
//! and an agent tailing stdout hoping for a sentence.
//!
//! ## The contract
//!
//! One required verb. A conforming process answers a `status` request with a
//! **status document**:
//!
//! ```json
//! {"state":"running","ready":true,"pid":71455,"uptime_secs":41,
//!  "detail":"3 windows open","endpoints":{"gui":"winit://main"},
//!  "metrics":{"frames_per_sec":59.9}}
//! ```
//!
//! `state` is the only required field, and its vocabulary is *exactly*
//! kamaji's [`WorkloadState`](https://docs.rs/kamaji-proto) —
//! `pending | starting | running | draining | exited | failed`. That is the
//! compatibility rule that matters: the supervisor already has this enum in
//! its wire protocol and already answers a `Probe` verb with it, so a
//! workload that reports in the same words can be believed verbatim rather
//! than translated. Everything else in the document is optional.
//!
//! ## Two transports, one document
//!
//! | Transport | Where | How |
//! |---|---|---|
//! | Unix socket | dev tier, portless or not | newline-delimited JSON: write `{"cmd":"status"}\n`, read one JSON line back |
//! | HTTP | any tier that already serves HTTP | `GET <base><path>` (conventionally `/_yah/status`) returning the same document |
//!
//! The cloud tier gets this for free: a `Healthcheck { probe: Http { path } }`
//! in `workload-spec` pointed at the status path is the *same* endpoint the
//! dev tier reads over a socket. One document, two transports, no per-tier
//! fork — which is the same rule W265 applies to everything else here.
//!
//! ## Why newline-JSON and not the kamaji postcard wire
//!
//! Because the producer side has to be implementable in twenty lines with no
//! dependency, in any language, by someone whose actual job that day is their
//! own app. kamaji's `kamaji-proto` is postcard over a framed UDS: excellent
//! between two Rust processes that both link it, a non-starter as a thing you
//! ask every workload in the fleet to adopt. A strict-subset JSON document
//! that a Bun script or a Python daemon can emit is the version that actually
//! gets adopted, and it is trivially bridged into `kamaji-proto`'s
//! `WorkloadState` because the vocabulary was chosen to match.
//!
//! ## Where the socket path comes from
//!
//! The supervisor picks it and hands it over in the environment as
//! **`YAH_CONTROL_SOCK`**. A conforming process binds `$YAH_CONTROL_SOCK` if
//! it is set and does nothing if it isn't — so the same binary runs unchanged
//! outside a camp.
//!
//! @arch:see(.yah/docs/working/W315-process-control-channel.md)
//! @arch:see(.yah/docs/working/W265-service-capabilities-and-drivers.md)
//!
//! @yah:ticket(R715-F3, "Process-control channel phase 2: producer helper crate, run.spawn injection, kamaji Probe bridge")
//! @yah:status(review)
//! @yah:at(2026-08-14T22:30:16Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R715)
//! @arch:see(.yah/docs/working/W315-process-control-channel.md)
//! @yah:next("Producer-side helper crate so conforming is two lines for a Rust workload (bind the socket, answer status from a Fn() -> ProcStatus). CRATE HOME IS AN OPERATOR CALL: oss/kamaji/crates/* (nearest owner, but an independent workspace and a publish surface) versus a standalone oss/procctl. It cannot live in yah-cloud where the client is, because external consumers (noisetable, in the entambi repo) need it from crates.io.")
//! @yah:next("run.spawn does not inject YAH_CONTROL_SOCK, so agent-spawned processes have no channel even if they speak it. Injecting the var is trivial; the value only appears once the camp daemon exposes a run.status RPC to read it back. Do both together.")
//! @yah:next("kamaji bridge: kamaji already answers a Probe verb with WorkloadState, and ProcState was chosen to match it word for word, but nothing wires the two. A workload that reports `starting` is currently believed by the reconciler and invisible to kamaji.")
//! @yah:next("Run tab polls the status once at bring-up (surfaced via RunningWorkloadSummary.notes). Live polling - a status line that moves starting -> running while you watch - needs an RPC, not new protocol.")
//! @yah:next("Nothing enforces the SHOULD. A lint over workload.toml (long-running component, no [process.control], no healthcheck) would turn W315 into a gate. One implementation was judged too little evidence to start failing builds over.")
//! @yah:gotcha("The protocol is deliberately dependency-free (one newline-delimited JSON verb), so nothing REQUIRES a crate to conform. The helper is ergonomics, not a gate - do not let its crate-home question block anyone from implementing the channel by hand.")
//! @yah:gotcha("Do not switch the wire to kamaji-proto's postcard framing to unify them. That was considered and rejected in W315: the producer side has to be implementable in twenty lines in any language, and postcard-over-framed-UDS is a Rust-links-the-crate contract.")
//! @yah:next("DECIDED 2026-08-14 by the operator, do not re-litigate: the producer helper crate lives at oss/kamaji/crates/procctl. Kamaji already owns the WorkloadState vocabulary this protocol reuses, so helper and enum move together; accepted cost is one more publish surface in kamaji's workspace. Rejected alternative: a standalone oss/procctl. Note kamaji is an INDEPENDENT cargo workspace with an export mirror - no workspace = true inheritance from yah's root, and the crate ships outward via scripts/export-oss.sh.")
//! @yah:handoff("All three titled items shipped. (1) PRODUCER CRATE: oss/kamaji/crates/procctl, package kamaji-procctl, lib name procctl (dir per the operator's call; package name follows the kamaji-* convention and is now listed in scripts/reserve-crate-names.sh + scripts/set-trusted-publishers.sh). Default build is std + serde only - a winit GUI with no runtime can adopt it, which was the motivating case. serve_env() returns Ok(None) when YAH_CONTROL_SOCK is unset; the server stamps pid and uptime when the producer omits them; a dead predecessor socket is reclaimed but a LIVE one is refused rather than stolen. Optional features: client (async consumer, tokio) and kamaji (ProcState -> WorkloadState).")
//! @yah:handoff("(2) KAMAJI BRIDGE: procctl's kamaji feature holds the From impl as an exhaustive match, so a state added to either vocabulary stops compiling - that compile error is the entire mechanism keeping W315's believed-verbatim claim true. The reverse direction is deliberately absent (WorkloadState is non_exhaustive, so matching it needs a wildcard, which is the silent drift the design refuses). ProbeTarget gained control: Option<PathBuf> and healthcheck became Option<Healthcheck> (a portless GUI has no port to probe and inventing a healthcheck for it is a lie); constructors ProbeTarget::healthcheck / ::control replace the struct literals. A control socket is the WHOLE probe when present - unreachable reads Starting, never a fallback to the port, per W315. Registered on the native-exec deploy path only, read from the spec's own YAH_CONTROL_SOCK literal, because a container's socket path names a location inside its mount namespace kamaji has no route to.")
//! @yah:handoff("(3) RUN.SPAWN INJECTION + RUN.STATUS: every spawn is now offered the channel unconditionally (a conforming process binds when set, does nothing when unset, so this costs a declining process nothing). New rpc::method::RUN_STATUS + RunStatusParams/RunStatusResult, run_status_handler in camp.rs, and a read-only run.status agent tool. The result relays the document verbatim (serde_json::Value) so a producer's own metrics/endpoints reach the caller intact. run.stop now unlinks the socket.")
//! @yah:verify("cargo test --workspace --all-features in oss/kamaji: all green. kamaji-procctl 26 passed + 1 doc-test; kamaji-bin lib 248 passed (was 216, +5 control-channel probe tests, +3 server tests).")
//! @yah:verify("cargo test -p yah --lib camp:: - 298 passed, including 5 new r715_f3_control_channel_tests that drive real child processes through run_spawn_handler / run_status_handler / run_stop_handler.")
//! @yah:verify("cargo test -p yah-agent-tools --lib run_tools - 16 passed. cargo test -p yah-rpc --lib - 45 passed. cargo test -p yah-cloud --lib proc_control (oss/yubaba) - 10 passed, untouched.")
//! @yah:verify("cargo check --workspace (root) and cargo check -p yubaba (oss/yubaba) clean; scripts/check-workspace-members.sh resolves all 58 members. kamaji-procctl also checked with default features (no client, no kamaji) so the producer half stays std-only.")
//! @yah:verify("The sandbox rule is pinned by a test that binds from INSIDE the sandbox - a_sandboxed_child_can_bind_the_socket_it_is_handed (camp.rs), a ~15-line stdlib-Python producer spawned through run_spawn_handler. Every other test in that module binds from the test process, which is outside the sandbox and proves nothing about it. It skips (does not fail) where no python3 exists.")
//! @yah:gotcha("MACOS SANDBOX BUG FOUND AND FIXED, and it would have made the whole injection useless on macOS. run.spawn puts the control socket at <workload_dir>/.yah-control.sock because that is the only writable path both sandbox facilities agree on (Seatbelt allows file-write* under WORKLOAD; bwrap binds workload_dir and nothing else - .yah/jit/ is not even present inside the bwrap namespace). But file-write* is NOT sufficient: Seatbelt gates AF_UNIX bind under network-bind, so a child got EPERM binding a path it could otherwise create any file at. MACOS_SANDBOX_PROFILE now carries (allow network-bind (local unix-socket (subpath (param WORKLOAD)))). Reproduced by hand with sandbox-exec before and after. plugin_host.rs shares the same profile constant and passes the same -D WORKLOAD, so it inherits the rule.")
//! @yah:gotcha("DISCOVERED, NOT FIXED (deliberately): kamaji never registers a ProbeTarget from a spec's own healthcheck on any path except the mesofact-bundle deploy. insert_probe has exactly three call sites (server.rs registry decl, the bundle deploy, and now the native control-channel registration), so a container workload declaring a healthcheck is probed as Ready unconditionally. Fixing it means live fleet workloads that report Ready today would start reporting real probe status - a behaviour change on running infra, not a drive-by. The control registration added here cannot regress that: it only fires when the spec declares YAH_CONTROL_SOCK, so a spec without it registers nothing and behaves exactly as before.")
//! @yah:cleanup("kamaji-procctl is not on crates.io. In-tree consumers resolve it by path so nothing is blocked, but kamaji-bin now depends on it and cargo publish --workspace publishes in topological order - the name must be reserved (scripts/reserve-crate-names.sh, entry added) before the next kamaji release, or that release fails on an unpublished dep. The external consumers this crate exists for (noisetable, entambi repo) need it published anyway.")

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Environment variable naming the control socket a supervised process should
/// bind. Absent → the process is not running under a supervisor that wants a
/// control channel, and MUST NOT fail for its absence.
pub const CONTROL_SOCK_ENV: &str = "YAH_CONTROL_SOCK";

/// Conventional HTTP path for the status document on a process that already
/// serves HTTP. Not enforced — `[process.control] http_path` overrides it —
/// but a service with no reason to differ should use this one.
pub const DEFAULT_HTTP_PATH: &str = "/_yah/status";

/// Lifecycle vocabulary of a supervised process.
///
/// Deliberately identical to `kamaji_proto::WorkloadState` so a workload's own
/// report can be handed to the supervisor without a translation table that
/// would rot the first time either side gained a state. Kept as a separate
/// type rather than a re-export only because this crate must not force a
/// `kamaji-proto` dependency on every consumer of the status document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcState {
    /// Accepted, nothing started yet.
    Pending,
    /// Started, not yet serving — booting, migrating, warming a cache.
    Starting,
    /// Serving. This is the only state that counts as ready.
    Running,
    /// Shutting down gracefully.
    Draining,
    /// Exited cleanly.
    Exited,
    /// Exited with a failure, or reported itself unrecoverable.
    Failed,
}

impl ProcState {
    /// Whether a process in this state is ready to be used.
    ///
    /// `Starting` is deliberately *not* ready: the entire point of the channel
    /// is to distinguish "the port is open" from "I am serving".
    pub fn is_ready(self) -> bool {
        matches!(self, ProcState::Running)
    }

    /// Whether this state is terminal — no amount of further polling changes
    /// it, so a readiness wait should fail fast rather than burn its timeout.
    pub fn is_terminal(self) -> bool {
        matches!(self, ProcState::Exited | ProcState::Failed)
    }
}

/// A workload's self-description. Only [`Self::state`] is required.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcStatus {
    /// Lifecycle state, in kamaji's vocabulary.
    pub state: ProcState,
    /// Redundant convenience mirror of `state == running`, accepted from
    /// producers that emit it. Never trusted over `state` — a document
    /// claiming `{"state":"starting","ready":true}` is a producer bug, and
    /// believing the optimistic half of it is how a supervisor reports a
    /// half-booted process as up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<bool>,
    /// Process id, when the process knows and cares to say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Seconds since the process considered itself started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uptime_secs: Option<u64>,
    /// Build/version string, for an operator staring at two of these.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// One human line elaborating on `state` — "replaying WAL 3/7",
    /// "waiting for GPU". This is the field that replaces log-grepping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Named addresses the process serves — `{"http":"http://127.0.0.1:4325"}`.
    /// A portless process may legitimately name a non-URL surface here.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub endpoints: std::collections::BTreeMap<String, String>,
    /// Numeric gauges the process wants surfaced. Free-form on purpose: this
    /// is a status channel, not a metrics pipeline.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub metrics: std::collections::BTreeMap<String, f64>,
}

impl ProcStatus {
    /// Ready iff the *state* says so. See [`Self::ready`] for why the
    /// producer-supplied boolean does not get a vote.
    pub fn is_ready(&self) -> bool {
        self.state.is_ready()
    }

    /// One-line rendering for an operator-facing note or log line.
    pub fn summary(&self) -> String {
        let mut s = format!("{:?}", self.state).to_lowercase();
        if let Some(detail) = &self.detail {
            s.push_str(" — ");
            s.push_str(detail);
        }
        if let Some(v) = &self.version {
            s.push_str(&format!(" (v{v})"));
        }
        s
    }
}

/// Where to ask for the status document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlEndpoint {
    /// Newline-JSON over a unix domain socket — the dev-tier default.
    Socket(PathBuf),
    /// `GET <url>` returning the status document — for a process that already
    /// serves HTTP, including every cloud-tier workload.
    Http(String),
}

impl std::fmt::Display for ControlEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlEndpoint::Socket(p) => write!(f, "unix:{}", p.display()),
            ControlEndpoint::Http(u) => write!(f, "{u}"),
        }
    }
}

/// Ask a process for its status document once.
///
/// Errors mean *unreachable or unparseable*, which is not the same as
/// unhealthy: a process that has not yet bound its socket is indistinguishable
/// here from one that never will. Callers deciding readiness should poll with
/// [`wait_ready`] rather than treating one error as a verdict.
pub async fn fetch_status(endpoint: &ControlEndpoint) -> anyhow::Result<ProcStatus> {
    match endpoint {
        ControlEndpoint::Socket(path) => fetch_status_uds(path).await,
        ControlEndpoint::Http(url) => {
            let body = reqwest::Client::new()
                .get(url)
                .timeout(Duration::from_secs(2))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            Ok(serde_json::from_str(&body)?)
        }
    }
}

/// Newline-JSON round trip: write one request line, read one response line.
///
/// The connection is not reused. A status poll happens every few seconds at
/// most, and a per-call connection means a wedged reader on the producer side
/// cannot poison later polls — worth far more here than the syscalls saved.
async fn fetch_status_uds(path: &Path) -> anyhow::Result<ProcStatus> {
    let mut stream = tokio::net::UnixStream::connect(path).await?;
    stream.write_all(b"{\"cmd\":\"status\"}\n").await?;
    stream.flush().await?;

    let mut line = String::new();
    let read = tokio::time::timeout(
        Duration::from_secs(2),
        BufReader::new(stream).read_line(&mut line),
    )
    .await
    .map_err(|_| anyhow::anyhow!("control socket {} did not answer within 2s", path.display()))??;
    if read == 0 {
        anyhow::bail!(
            "control socket {} closed without answering",
            path.display()
        );
    }
    Ok(serde_json::from_str(line.trim())?)
}

/// Outcome of waiting for a process to report itself ready.
#[derive(Debug)]
pub enum ReadyOutcome {
    /// The process reported [`ProcState::Running`].
    Ready(ProcStatus),
    /// The process reported a terminal state — it is not coming up. Failing
    /// here rather than burning the whole timeout is the practical difference
    /// between a five-second and a twenty-second edit loop.
    Terminal(ProcStatus),
    /// The deadline passed. `last` is the most recent document read, or `None`
    /// when the endpoint never answered at all — a distinction worth keeping
    /// in the error message, since "never bound its socket" and "stuck in
    /// starting" are different bugs with different fixes.
    TimedOut { last: Option<ProcStatus> },
}

/// Poll `endpoint` until the process reports ready, reports terminal, or the
/// timeout expires.
pub async fn wait_ready(endpoint: &ControlEndpoint, timeout: Duration) -> ReadyOutcome {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last: Option<ProcStatus> = None;
    loop {
        if let Ok(status) = fetch_status(endpoint).await {
            if status.is_ready() {
                return ReadyOutcome::Ready(status);
            }
            if status.state.is_terminal() {
                return ReadyOutcome::Terminal(status);
            }
            last = Some(status);
        }
        if tokio::time::Instant::now() >= deadline {
            return ReadyOutcome::TimedOut { last };
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Minimal conforming producer: accept, read a line, answer one document.
    /// This is also the reference for how little a workload has to implement.
    fn serve_once(path: PathBuf, docs: Vec<String>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let listener = tokio::net::UnixListener::bind(&path).unwrap();
            for doc in docs {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (read_half, mut write_half) = stream.into_split();
                let mut line = String::new();
                BufReader::new(read_half).read_line(&mut line).await.ok();
                write_half.write_all(doc.as_bytes()).await.ok();
                write_half.write_all(b"\n").await.ok();
                write_half.flush().await.ok();
            }
        })
    }

    #[test]
    fn the_state_vocabulary_matches_kamajis_workload_state_on_the_wire() {
        // If this ever drifts, a workload's own report can no longer be handed
        // to the supervisor verbatim — which is the entire compatibility claim
        // this module makes.
        for (state, wire) in [
            (ProcState::Pending, "\"pending\""),
            (ProcState::Starting, "\"starting\""),
            (ProcState::Running, "\"running\""),
            (ProcState::Draining, "\"draining\""),
            (ProcState::Exited, "\"exited\""),
            (ProcState::Failed, "\"failed\""),
        ] {
            assert_eq!(serde_json::to_string(&state).unwrap(), wire);
            assert_eq!(
                serde_json::from_str::<ProcState>(wire).unwrap(),
                state,
                "{wire} must round-trip"
            );
        }
    }

    #[test]
    fn state_is_the_only_required_field() {
        let s: ProcStatus = serde_json::from_str(r#"{"state":"running"}"#).unwrap();
        assert!(s.is_ready());
        assert_eq!(s.pid, None);
        assert!(s.endpoints.is_empty());
        assert!(s.metrics.is_empty());
    }

    #[test]
    fn a_full_document_parses() {
        let s: ProcStatus = serde_json::from_str(
            r#"{"state":"starting","ready":false,"pid":71455,"uptime_secs":41,
                "version":"0.8.20","detail":"replaying WAL 3/7",
                "endpoints":{"gui":"winit://main"},"metrics":{"fps":59.9}}"#,
        )
        .unwrap();
        assert_eq!(s.state, ProcState::Starting);
        assert!(!s.is_ready(), "starting is not ready");
        assert_eq!(s.pid, Some(71455));
        assert_eq!(s.detail.as_deref(), Some("replaying WAL 3/7"));
        assert_eq!(s.endpoints.get("gui").map(String::as_str), Some("winit://main"));
        assert_eq!(s.metrics.get("fps"), Some(&59.9));
        assert_eq!(s.summary(), "starting — replaying WAL 3/7 (v0.8.20)");
    }

    /// A producer that contradicts itself must not be believed on the
    /// optimistic half — that is precisely how a half-booted process gets
    /// reported as up, which is the failure this channel exists to end.
    #[test]
    fn a_ready_flag_never_overrides_a_not_running_state() {
        let s: ProcStatus =
            serde_json::from_str(r#"{"state":"starting","ready":true}"#).unwrap();
        assert_eq!(s.ready, Some(true), "the claim is preserved verbatim");
        assert!(!s.is_ready(), "but state decides");
    }

    #[tokio::test]
    async fn fetch_status_reads_a_document_over_a_unix_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("control.sock");
        let server = serve_once(
            sock.clone(),
            vec![r#"{"state":"running","detail":"3 windows"}"#.to_string()],
        );
        // Give the listener a moment to bind.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let got = fetch_status(&ControlEndpoint::Socket(sock)).await.unwrap();
        assert_eq!(got.state, ProcState::Running);
        assert_eq!(got.detail.as_deref(), Some("3 windows"));
        server.abort();
    }

    #[tokio::test]
    async fn wait_ready_polls_through_starting_to_running() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("control.sock");
        let server = serve_once(
            sock.clone(),
            vec![
                r#"{"state":"starting"}"#.to_string(),
                r#"{"state":"starting"}"#.to_string(),
                r#"{"state":"running"}"#.to_string(),
            ],
        );
        tokio::time::sleep(Duration::from_millis(50)).await;

        let outcome = wait_ready(&ControlEndpoint::Socket(sock), Duration::from_secs(5)).await;
        assert!(
            matches!(&outcome, ReadyOutcome::Ready(s) if s.state == ProcState::Running),
            "{outcome:?}"
        );
        server.abort();
    }

    /// `failed` must short-circuit. Burning the full readiness timeout on a
    /// process that has already said it is not coming up is the slow-edit-loop
    /// failure this outcome exists to prevent.
    #[tokio::test]
    async fn wait_ready_fails_fast_on_a_terminal_state() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("control.sock");
        let server = serve_once(
            sock.clone(),
            vec![r#"{"state":"failed","detail":"no GPU"}"#.to_string()],
        );
        tokio::time::sleep(Duration::from_millis(50)).await;

        let started = std::time::Instant::now();
        let outcome = wait_ready(&ControlEndpoint::Socket(sock), Duration::from_secs(30)).await;
        assert!(
            matches!(&outcome, ReadyOutcome::Terminal(s) if s.detail.as_deref() == Some("no GPU")),
            "{outcome:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "must not burn the 30s timeout on a terminal state"
        );
        server.abort();
    }

    #[tokio::test]
    async fn wait_ready_times_out_when_nothing_is_listening() {
        let tmp = tempfile::tempdir().unwrap();
        let outcome = wait_ready(
            &ControlEndpoint::Socket(tmp.path().join("never-bound.sock")),
            Duration::from_millis(300),
        )
        .await;
        assert!(
            matches!(outcome, ReadyOutcome::TimedOut { last: None }),
            "an endpoint that never answered must report no last document"
        );
    }

    #[test]
    fn endpoints_render_distinguishably() {
        assert_eq!(
            ControlEndpoint::Socket(PathBuf::from("/tmp/c.sock")).to_string(),
            "unix:/tmp/c.sock"
        );
        assert_eq!(
            ControlEndpoint::Http("http://127.0.0.1:4325/_yah/status".into()).to_string(),
            "http://127.0.0.1:4325/_yah/status"
        );
    }

    #[test]
    fn a_status_document_round_trips_through_serialization() {
        let mut endpoints = BTreeMap::new();
        endpoints.insert("http".to_string(), "http://127.0.0.1:4325".to_string());
        let original = ProcStatus {
            state: ProcState::Running,
            ready: None,
            pid: Some(9),
            uptime_secs: Some(3),
            version: None,
            detail: None,
            endpoints,
            metrics: BTreeMap::new(),
        };
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(serde_json::from_str::<ProcStatus>(&json).unwrap(), original);
        assert!(
            !json.contains("\"ready\""),
            "absent optionals must not be emitted: {json}"
        );
    }
}

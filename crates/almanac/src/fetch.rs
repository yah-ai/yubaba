//! The **feed-fetch tier** (R330-F31) — the half of almanac that refreshes a
//! feed's artifact on the node so a revalidate poke has something new to render.
//!
//! ## Why it is separate from the receiver
//!
//! W225 §4 retires the standalone almanac *receiver*: the `POST /revalidate`
//! endpoint is a route the consumer's own `mesofact serve --revalidate` process
//! mounts, not a binary of ours. What that rule does **not** retire is the
//! *fetcher* — `source.fetch()` → `sink.write()` (R535-T2). The receiver
//! re-reads the route's declared `data_inputs` from the workload root at poke
//! time; it does not know where those bytes came from and never fetches. So
//! without this tier a poke re-renders byte-identical output forever.
//!
//! This module is therefore deliberately **HTTP-server-free**. It runs
//! [`FeedRunner`] on a cadence and, when the artifact actually changed, *makes*
//! one outbound poke to the local receiver. Nothing listens.
//!
//! ## Cadence, not webhook — and why that is enough
//!
//! W059 §1 lists two trigger classes that collapse to one verb, and notes that
//! "timed cron is just push on a schedule". Giving this tier its own inbound
//! webhook would re-create the retired receiver shape (two public
//! `/revalidate`s, only one of them mesofact's), so the trigger here is the
//! timer: run at startup, then every `interval`. A release lands, the next tick
//! notices, and yah.dev is fresh within one interval — "SSR at a glacial pace"
//! is exactly the freshness contract almanac advertises.
//!
//! `FeedRunner`'s change-suppression is what makes a short interval cheap: a
//! tick with no upstream change costs one conditional fetch and stops there —
//! no write-through render, no publish, no CDN purge.
//!
//! ## Poke delivery is at-least-once
//!
//! A fetch that changed the artifact but then failed to reach the receiver
//! would otherwise be lost: the *next* tick re-fetches, compares equal to the
//! artifact already on disk, and reports no change. So a failed poke is
//! remembered ([`FeedFetcher::pending`]) and retried on every subsequent tick
//! until it lands.
//!
//! ## The poke carries its data (R330-F33)
//!
//! A poke used to be `{route, mirror_key}` alone, which made the *render
//! inputs* node-local while the *output* is global R2: whichever instance
//! serviced the poke rendered from its own sidecar's copy of the artifact and
//! published that to the shared bucket. An instance whose sidecar had not yet
//! ticked would therefore publish **staler output over fresher**, silently —
//! last write wins and nothing errors.
//!
//! So the poke carries the bytes it is asking to have rendered
//! ([`Poke::data_inputs`]). The receiver writes them into its workload before
//! rendering, which means any instance can service any poke with zero
//! node-local state and nearest-hop / least-busy routing becomes a pure
//! optimisation rather than a correctness input.
//!
//! A poke with no `data_inputs` stays valid and means exactly what it used to:
//! "re-render from whatever you have". That is what a whole-site poke and a
//! poll-only feed still send.
//!
//! ## The payload has a ceiling, and it is stated rather than inherited
//! (R330-F38)
//!
//! An inline payload rides in an HTTP body, so it has a maximum size whether or
//! not anyone chose one. Until R330-F38 nobody had: the receiver's limit was
//! axum's built-in `DefaultBodyLimit` of 2 MiB, set by the framework, named
//! nowhere in this tree and pinned by no test. That was survivable while every
//! feed carried a single release. R330-F38 makes the `releases` feed carry the
//! **whole published history**, so the payload now grows once per release
//! forever and the ceiling stops being theoretical — see
//! [`MAX_POKE_PAYLOAD_BYTES`] for the number, how many releases it is, and what
//! to do when it is reached.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;

use crate::config::{FeedConfig, OnChangeConfig};
use crate::runner::FeedRunner;

/// Render inputs a poke carries: the **project-relative** path a route declares
/// in its `data_inputs` → the JSON that path should hold.
///
/// The key is deliberately the same string the route declares and the same one
/// [`FeedFetcher`] writes to disk (post prefix-strip, see [`FeedFetcher::new`]),
/// so the receiver needs no knowledge of feed config to place the bytes.
pub type PokeInputs = BTreeMap<String, serde_json::Value>;

/// One outbound revalidate request.
///
/// ## Two receivers, one producer
///
/// There are two `/revalidate` endpoints in this system and they take **different
/// bodies**, because they answer different questions:
///
/// | receiver | body | question it answers |
/// |---|---|---|
/// | `mesofact serve --revalidate` | `{route, data_inputs, mirror_key}` | *re-render this page from these bytes* |
/// | [`crate::receiver`] (almanac's own) | `{feed, mirror_key}` | *go re-fetch this feed* |
///
/// Which one is on the other end is a property of the **feed**, not of the
/// caller: a `mesofact-rebuild` feed's consumer is a renderer, a
/// [`crate::config::OnChangeConfig::Reload`] feed's consumer reads the artifact
/// almanac fetches. [`poke_for`] derives it from the config so no caller has to
/// know, and [`HttpPoke`] is still the single place either body is constructed.
///
/// Getting this wrong is not hypothetical and does not fail loudly: mesofact's
/// `RevalidateBody` is `#[serde(default)]` with no `deny_unknown_fields`, so a
/// `{"feed": …}` sent to *it* parses fine and silently means "whole site". That
/// is the exact bug R330-T14 was opened for — which is why the discrimination
/// lives here rather than in each producer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Poke {
    /// Route pattern to re-render, e.g. `/releases`. **Empty = the whole-site
    /// poke**: [`HttpPoke`] then omits the key entirely so the receiver takes
    /// its documented "every render-eligible route" branch. Sending `""`
    /// instead would make the receiver try to render a route named `""` and
    /// fail, so the emptiness check belongs on the wire, not on each caller.
    ///
    /// Ignored when `feed` is set — see the type docs.
    pub route: String,
    /// The render inputs this poke hands over. Empty = payload-less: the
    /// receiver renders from its own disk (the pre-R330-F33 contract, still
    /// valid — see the module docs).
    pub data_inputs: PokeInputs,
    /// Feed name, set when the receiver on the other end is **almanac's** and
    /// the ask is "go re-fetch", not "go re-render". Mutually exclusive with
    /// `route`/`data_inputs` in practice; see the type docs for the two wire
    /// shapes.
    pub feed: Option<String>,
}

/// The largest inline poke payload this tier will put on the wire, in bytes.
///
/// **Deliberately half the receiver's own limit.** `mesofact serve
/// --revalidate` caps a request body at 4 MiB (`MAX_REVALIDATE_BODY_BYTES` in
/// `crates/mesofact/src/revalidate.rs`); this side stops at 2 MiB. The gap is
/// the point: sender and receiver are separately deployed binaries, so a
/// payload sized right at a shared limit would 413 on any version skew. Refusing
/// first, locally, where the reason can be logged, beats a 413 the fetcher can
/// only report as a transport error.
///
/// **How many releases that is.** The `releases` feed's payload is the whole
/// serialized [`crate::feed::ReleaseFeed`], and a `yah` release carries five
/// triples at roughly 700 B each once the tagged hashes, the legacy bare
/// mirrors, and the sig/cert URLs are counted — call it ~3.5 KB per release.
/// 2 MiB is therefore on the order of **600 releases**. At yah's cadence that
/// is many years, which is why an inline payload is the right shape today and
/// not a permanent one. `payload_over_ceiling_is_caught_before_the_wire`
/// measures a real feed rather than trusting this paragraph.
///
/// **What happens when it is reached** — the decision R330-F38 owed, written
/// down so the next agent does not have to re-derive it. The poke degrades to
/// payload-less (the documented pre-R330-F33 contract: the receiver renders
/// from its own disk) and the tick reports a loud error naming the size and
/// this constant. It does NOT truncate the payload — a half-history rendered as
/// if it were the whole one is worse than a stale one — and it does not drop
/// the revalidation. The real fix at that point is the escape hatch R330-F33
/// already named: carry an **R2 pointer** instead of the bytes, so the poke
/// stays small and the receiver fetches the payload it names. Raising this
/// number is a stopgap, not that fix.
pub const MAX_POKE_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;

/// The sender/receiver margin, enforced at COMPILE time rather than by a test,
/// because it is the kind of coupling that gets broken by someone raising one
/// number in isolation. `MAX_REVALIDATE_BODY_BYTES` in mesofact is 4 MiB;
/// raising the ceiling above it turns a graceful degrade into a 413. The two
/// live in separately-exported workspaces so the constant cannot be shared —
/// this is the next best thing.
const _: () = assert!(MAX_POKE_PAYLOAD_BYTES < 4 * 1024 * 1024);

impl Poke {
    /// A payload-less poke — "re-render `route` from whatever you have".
    pub fn route(route: impl Into<String>) -> Self {
        Self { route: route.into(), data_inputs: PokeInputs::new(), feed: None }
    }

    /// A feed-keyed poke — "go re-fetch this feed". The body
    /// [`crate::receiver`] accepts; see [`Poke`]'s docs for why it is a
    /// different shape from the route-keyed one.
    ///
    /// Carries no payload by construction: the receiving side's whole job is to
    /// perform the fetch itself, and a source that needed its bytes handed over
    /// would not satisfy `coalesce.rs`'s absoluteness invariant.
    pub fn feed(name: impl Into<String>) -> Self {
        Self { route: String::new(), data_inputs: PokeInputs::new(), feed: Some(name.into()) }
    }

    /// Attach one data input at its project-relative path.
    pub fn with_input(mut self, path: impl Into<String>, value: serde_json::Value) -> Self {
        self.data_inputs.insert(path.into(), value);
        self
    }

    /// Serialized size of the carried payload, in bytes.
    ///
    /// Measured on the JSON that actually goes on the wire rather than
    /// estimated from the release count: the whole reason this is checked is
    /// that a guess about payload size is what let the limit stay unnoticed.
    pub fn payload_bytes(&self) -> usize {
        self.data_inputs
            .values()
            .map(|v| serde_json::to_vec(v).map(|b| b.len()).unwrap_or(0))
            .sum()
    }
}

/// Delivery seam for the outbound "re-render this route" poke.
///
/// A trait rather than a bare `reqwest` call so the tier's interesting
/// behaviour — poke on change, stay silent on no-change, retry a poke that
/// failed, hand over the payload — is testable without a network or a live
/// receiver.
#[async_trait]
pub trait RevalidatePoke: Send + Sync {
    /// Ask the receiver to re-render `poke.route` from `poke.data_inputs`.
    /// Returns the transport/status error verbatim; the caller decides whether
    /// to retry.
    async fn poke(&self, poke: &Poke) -> Result<(), String>;
}

/// Fetch-only [`RevalidatePoke`]: writes the artifact, tells no one.
///
/// The shape a **producer-side one-shot** needs (R330-T32) — a CI or `yah qed
/// run` step that fetches a feed, lands its artifact in the working tree, and
/// then hands that tree to a build+publish step itself. There is no receiver
/// to notify because nothing is serving yet: the render happens downstream in
/// the same job, not on a node.
///
/// Distinct from a *failed* poke, which [`FeedFetcher`] retries on the next
/// tick. This one is a deliberate no-receiver configuration, so it reports
/// success and the change is logged rather than re-attempted forever.
pub struct NoPoke;

#[async_trait]
impl RevalidatePoke for NoPoke {
    async fn poke(&self, poke: &Poke) -> Result<(), String> {
        tracing::info!(
            route = %poke.route,
            "almanac feed changed — no receiver configured, artifact written only"
        );
        Ok(())
    }
}

/// The real poke: `POST <receiver>/revalidate {"route": …, "mirror_key": …,
/// "data_inputs": {…}}` — the body shape `mesofact serve --revalidate` accepts.
///
/// `data_inputs` is omitted entirely when the poke carries no payload, so the
/// wire form of a payload-less poke is byte-identical to what shipped before
/// R330-F33 and older receivers keep parsing it. `route` is likewise omitted
/// when empty — that is the whole-site branch (see [`Poke::route`]).
///
/// There is exactly **one** construction of this body in the tree, on purpose
/// (R330-T14): the desktop release path used to hand-roll its own JSON in
/// `scripts/publish-desktop.sh` and silently kept sending the pre-correction
/// `{"feed": …}` shape for months, because the receiver's `RevalidateBody` is
/// `#[serde(default)]` with no `deny_unknown_fields` and so *parsed it fine*.
/// Both publish paths now reach the wire through here.
///
/// The receiver is bound to loopback on the tenant's own node (kamaji forks it
/// at `127.0.0.1:<bind_port+1>`), so this never leaves the machine and the
/// bearer never crosses a network.
pub struct HttpPoke {
    client: reqwest::Client,
    /// Receiver base URL, e.g. `http://127.0.0.1:3001`.
    base_url: String,
    mirror_key: Option<String>,
}

impl HttpPoke {
    pub fn new(base_url: impl Into<String>, mirror_key: Option<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.into(),
            mirror_key,
        }
    }
}

#[async_trait]
impl RevalidatePoke for HttpPoke {
    async fn poke(&self, poke: &Poke) -> Result<(), String> {
        let url = format!("{}/revalidate", self.base_url.trim_end_matches('/'));
        let mut body = serde_json::Value::Object(serde_json::Map::new());
        match poke.feed {
            // Almanac's own receiver: it looks the feed up in the almanac dir,
            // checks the mirror binding, and re-runs it. Nothing else belongs in
            // this body — the change lives in the feed, never in the request.
            Some(ref feed) => {
                body["feed"] = serde_json::Value::String(feed.clone());
            }
            // mesofact's receiver. An empty route is the whole-site poke — omit
            // the key rather than send `""`, which the receiver would take as a
            // route pattern and fail to render (see [`Poke::route`]).
            None => {
                if !poke.route.is_empty() {
                    body["route"] = serde_json::Value::String(poke.route.clone());
                }
                if !poke.data_inputs.is_empty() {
                    body["data_inputs"] = serde_json::Value::Object(
                        poke.data_inputs
                            .iter()
                            .map(|(path, value)| (path.clone(), value.clone()))
                            .collect(),
                    );
                }
            }
        }
        if let Some(ref key) = self.mirror_key {
            body["mirror_key"] = serde_json::Value::String(key.clone());
        }
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("POST {url}: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().await.unwrap_or_default();
            return Err(format!("POST {url} → {status}: {detail}"));
        }
        Ok(())
    }
}

/// What one feed did on one tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedOutcome {
    pub feed: String,
    /// The artifact on disk differs from what the source now returns.
    pub changed: bool,
    /// Route successfully poked this tick, if any.
    pub poked: Option<String>,
    /// Fetch or poke failure — logged and carried, never fatal to the loop. A
    /// wedged feed must not stop its siblings from refreshing.
    pub error: Option<String>,
}

/// Runs a set of feeds on a cadence and pokes the local receiver on change.
pub struct FeedFetcher {
    feeds: Vec<FeedConfig>,
    project_root: PathBuf,
    /// Workspace-relative path of the project that `project_root` materializes.
    /// See [`FeedFetcher::new`].
    project_prefix: Option<PathBuf>,
    poke: Box<dyn RevalidatePoke>,
    /// Feeds whose change was written but whose poke has not yet landed, keyed
    /// by feed name → the undelivered poke. Retried every tick (see the module
    /// docs). The whole [`Poke`] is held, payload included: a retry that
    /// dropped the payload would re-introduce exactly the node-local-render bug
    /// R330-F33 removes, since the retried poke could land on a different
    /// instance than the one whose sidecar produced the bytes.
    pending: Mutex<BTreeMap<String, Poke>>,
}

impl FeedFetcher {
    /// `project_root` is the directory each feed's artifact is written relative
    /// to — on a node, the materialized bundle's `app/` dir, which is exactly
    /// where the receiver re-reads `data_inputs` from.
    ///
    /// `project_prefix` reconciles two different roots for the same file. A feed
    /// declares `emit.artifact` **workspace-relative**
    /// (`app/yah/web/marketing/src/data/releases.json`) because that is where it
    /// is authored and built; the route declares the same file
    /// **project-relative** (`src/data/releases.json`) because that is what the
    /// bundle carries. Passing the component's workspace-relative path
    /// (`app/yah/web/marketing`) strips one to get the other. `None` → the
    /// artifact path is already relative to `project_root` (the workspace-root
    /// case, where the two coincide).
    ///
    /// A feed whose artifact does not sit under `project_prefix` is a
    /// mis-attachment — that feed's data belongs to a different site — and is
    /// reported per-tick rather than silently written somewhere no one reads.
    pub fn new(
        feeds: Vec<FeedConfig>,
        project_root: impl Into<PathBuf>,
        project_prefix: Option<PathBuf>,
        poke: Box<dyn RevalidatePoke>,
    ) -> Self {
        Self {
            feeds,
            project_root: project_root.into(),
            project_prefix,
            poke,
            pending: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn feeds(&self) -> &[FeedConfig] {
        &self.feeds
    }

    pub fn project_root(&self) -> &Path {
        &self.project_root
    }

    /// One pass over every feed: fetch → write → poke-if-changed.
    ///
    /// Feed failures are collected into the per-feed [`FeedOutcome::error`]
    /// rather than short-circuiting, so one unreachable source cannot stall the
    /// others.
    pub async fn run_once(&self) -> Vec<FeedOutcome> {
        let mut outcomes = Vec::with_capacity(self.feeds.len());
        for cfg in &self.feeds {
            outcomes.push(self.run_feed(cfg).await);
        }
        outcomes
    }

    async fn run_feed(&self, cfg: &FeedConfig) -> FeedOutcome {
        let name = cfg.feed.name.clone();

        let artifact = match self.artifact_rel(cfg) {
            Ok(rel) => rel,
            Err(e) => {
                return FeedOutcome {
                    feed: name,
                    changed: false,
                    poked: None,
                    error: Some(e),
                }
            }
        };
        let runner = FeedRunner::with_sink(
            cfg.clone(),
            crate::sink::local_file(&self.project_root, &artifact),
        );

        let (changed, fetched, mut error) = match runner.run().await {
            // `on_change` is `Some` only when the artifact actually changed —
            // `FeedRunner` suppresses it otherwise, which is the whole reason a
            // short interval is affordable.
            Ok(result) => (
                result.on_change.is_some(),
                // The same value that was just serialized to disk — this is the
                // payload the poke hands over, so the receiver renders these
                // bytes rather than whatever its own sidecar last wrote.
                // Serialized here from the in-memory feed rather than re-read
                // from the file: a re-read could pick up a concurrent write and
                // ship a payload that does not match the change we detected.
                serde_json::to_value(&result.payload).ok(),
                None,
            ),
            Err(e) => (false, None, Some(format!("fetch failed: {e}"))),
        };

        // A poke owed from an earlier tick outranks nothing — it IS this tick's
        // poke when the fetch found no new change.
        let owed = if changed {
            route_of(cfg).map(|route| match fetched {
                Some(value) => Poke::route(route).with_input(artifact.as_str(), value),
                // Unserializable feed: still ask for the re-render, just
                // without the payload. Degrades to the old node-local render
                // rather than dropping the revalidation entirely.
                None => Poke::route(route),
            })
        } else {
            self.pending.lock().expect("pending mutex").get(&name).cloned()
        };

        // The payload has a stated ceiling; over it, degrade LOUDLY rather than
        // hand the receiver a body it will 413. See [`MAX_POKE_PAYLOAD_BYTES`]
        // for the number, what it is in releases, and the escape hatch.
        let owed = owed.map(|poke| {
            let bytes = poke.payload_bytes();
            if bytes <= MAX_POKE_PAYLOAD_BYTES {
                return poke;
            }
            let msg = format!(
                "poke payload is {bytes} B, over the {MAX_POKE_PAYLOAD_BYTES} B ceiling — \
                 sent payload-less, so the receiver rendered from its own disk and may be \
                 stale; carry an R2 pointer instead of the bytes (almanac::fetch::\
                 MAX_POKE_PAYLOAD_BYTES)"
            );
            tracing::error!(feed = %name, route = %poke.route, bytes, "{msg}");
            error = Some(match error {
                Some(ref prev) => format!("{prev}; {msg}"),
                None => msg,
            });
            Poke::route(poke.route)
        });

        let mut poked = None;
        if let Some(poke) = owed {
            match self.poke.poke(&poke).await {
                Ok(()) => {
                    self.pending.lock().expect("pending mutex").remove(&name);
                    poked = Some(poke.route);
                }
                Err(e) => {
                    // Remember it: the artifact is already updated, so the next
                    // fetch will report "unchanged" and would otherwise drop
                    // this revalidation on the floor.
                    self.pending
                        .lock()
                        .expect("pending mutex")
                        .insert(name.clone(), poke);
                    let msg = format!("poke failed (will retry next tick): {e}");
                    error = Some(match error {
                        Some(prev) => format!("{prev}; {msg}"),
                        None => msg,
                    });
                }
            }
        }

        FeedOutcome { feed: name, changed, poked, error }
    }

    /// Run forever: one pass immediately (a freshly-deployed node must not wait
    /// out a full interval before it is correct), then one per `interval`.
    pub async fn run_forever(&self, interval: Duration) -> ! {
        loop {
            for outcome in self.run_once().await {
                match (&outcome.error, &outcome.poked) {
                    (Some(err), _) => {
                        tracing::error!(feed = %outcome.feed, %err, "almanac feed tick failed")
                    }
                    (None, Some(route)) => tracing::info!(
                        feed = %outcome.feed,
                        %route,
                        "almanac feed changed — receiver poked"
                    ),
                    // A fetch-only feed has no route to poke, so a real change
                    // lands here too — see the same branch in `bin/feed.rs`.
                    (None, None) if outcome.changed => tracing::info!(
                        feed = %outcome.feed,
                        "almanac feed changed — artifact written; this feed pokes no one, its \
                         consumer re-reads the artifact"
                    ),
                    (None, None) => {
                        tracing::debug!(feed = %outcome.feed, "almanac feed unchanged")
                    }
                }
            }
            tokio::time::sleep(interval).await;
        }
    }

    /// This feed's artifact path relative to [`Self::project_root`].
    ///
    /// See [`FeedFetcher::new`] for why the two roots differ.
    fn artifact_rel(&self, cfg: &FeedConfig) -> Result<String, String> {
        project_relative_artifact(cfg, self.project_prefix.as_deref())
    }

    /// Feed names whose poke has not landed yet (test/observability hook).
    pub fn pending_feeds(&self) -> Vec<String> {
        self.pending
            .lock()
            .expect("pending mutex")
            .keys()
            .cloned()
            .collect()
    }
}

/// A feed's artifact path as the *route* declares it — project-relative, which
/// is also the key a [`Poke`] carries its payload under.
///
/// `project_prefix` is the component's workspace-relative path (e.g.
/// `app/yah/web/marketing`); `None` means the artifact path is already relative
/// to the project root. See [`FeedFetcher::new`] for why the two roots differ.
///
/// Free function rather than a `FeedFetcher` method because a **producer** needs
/// the identical answer (R330-T14): `yah almanac revalidate` keys its carried
/// `data_inputs` by this exact string, and a second implementation of the
/// prefix-strip would be a silent-divergence seam of the same class this
/// ticket removed between the two publish paths.
pub fn project_relative_artifact(
    cfg: &FeedConfig,
    project_prefix: Option<&Path>,
) -> Result<String, String> {
    let declared = &cfg.feed.emit.artifact;
    let Some(prefix) = project_prefix else {
        return Ok(declared.clone());
    };
    Path::new(declared)
        .strip_prefix(prefix)
        .map(|rel| rel.to_string_lossy().into_owned())
        .map_err(|_| {
            format!(
                "feed artifact {declared:?} is not under the project {:?} this fetcher serves \
                 — the feed is attached to the wrong workload",
                prefix.display()
            )
        })
}

/// The route a feed's `on_change` asks to have re-rendered. `None` for a
/// fetch-only feed (one that just materialises an artifact for someone else).
///
/// [`OnChangeConfig::Reload`] is `None` on purpose and not for want of a route
/// to name: its consumer reads the emitted artifact directly, so the write this
/// tier just performed IS the update. Poking a mesofact receiver for it would
/// ask a renderer to re-render a page that does not exist.
pub fn route_of(cfg: &FeedConfig) -> Option<String> {
    match cfg.feed.emit.on_change {
        Some(OnChangeConfig::MesofactRebuild { ref route, .. }) => Some(route.clone()),
        Some(OnChangeConfig::Reload { .. }) | None => None,
    }
}

/// The poke this feed's own config says to send — which receiver, and therefore
/// which wire shape.
///
/// The dispatch lives here, once, rather than at each producer, for the reason
/// [`Poke`]'s docs give: the two `/revalidate` bodies are structurally
/// compatible enough that sending the wrong one **parses and silently does the
/// wrong thing**. A producer that had to choose would eventually choose wrong
/// and nothing would report it.
///
/// - [`OnChangeConfig::Reload`] → feed-keyed, for [`crate::receiver`]. The
///   consumer's job is to re-fetch; there is no page to render.
/// - [`OnChangeConfig::MesofactRebuild`] → route-keyed, for `mesofact serve
///   --revalidate`. The caller may still attach a payload with
///   [`Poke::with_input`].
/// - no `on_change` → the route-keyed whole-site poke, unchanged.
pub fn poke_for(cfg: &FeedConfig) -> Poke {
    match cfg.feed.emit.on_change {
        Some(OnChangeConfig::Reload { .. }) => Poke::feed(cfg.feed.name.clone()),
        Some(OnChangeConfig::MesofactRebuild { ref route, .. }) => Poke::route(route.clone()),
        None => Poke::route(String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Records every poke — payload included — and can be told to fail, so the
    /// tier's behaviour is exercised with no receiver and no network.
    #[derive(Default)]
    struct FakePoke {
        calls: Arc<Mutex<Vec<Poke>>>,
        fail: Arc<Mutex<bool>>,
    }

    impl FakePoke {
        fn handles(&self) -> (Arc<Mutex<Vec<Poke>>>, Arc<Mutex<bool>>) {
            (Arc::clone(&self.calls), Arc::clone(&self.fail))
        }
    }

    #[async_trait]
    impl RevalidatePoke for FakePoke {
        async fn poke(&self, poke: &Poke) -> Result<(), String> {
            if *self.fail.lock().unwrap() {
                return Err("receiver down".into());
            }
            self.calls.lock().unwrap().push(poke.clone());
            Ok(())
        }
    }

    /// The routes recorded by a [`FakePoke`], in call order.
    fn routes(calls: &Arc<Mutex<Vec<Poke>>>) -> Vec<String> {
        calls.lock().unwrap().iter().map(|p| p.route.clone()).collect()
    }

    /// A feed whose source is unreachable — enough to drive the failure paths
    /// without a network. `route_of` / pending-retry logic doesn't care which
    /// adapter produced the bytes.
    fn unreachable_feed(name: &str, route: &str) -> FeedConfig {
        toml::from_str(&format!(
            r#"
[feed]
name = "{name}"
[feed.source]
kind = "r2-manifest"
url = "http://127.0.0.1:1/manifest.json"
[feed.trigger]
kind = "webhook"
[feed.emit]
artifact = "src/data/{name}.json"
on_change = {{ kind = "mesofact-rebuild", service = "yah-marketing", route = "{route}" }}
"#
        ))
        .unwrap()
    }

    fn fetch_only_feed(name: &str) -> FeedConfig {
        toml::from_str(&format!(
            r#"
[feed]
name = "{name}"
[feed.source]
kind = "r2-manifest"
url = "http://127.0.0.1:1/manifest.json"
[feed.trigger]
kind = "webhook"
[feed.emit]
artifact = "src/data/{name}.json"
"#
        ))
        .unwrap()
    }

    #[test]
    fn route_comes_from_on_change() {
        assert_eq!(
            route_of(&unreachable_feed("releases", "/releases")),
            Some("/releases".to_string())
        );
        assert_eq!(route_of(&fetch_only_feed("releases")), None);
    }

    /// A fetch that fails must not poke — re-rendering off stale bytes is worse
    /// than not re-rendering, because it burns a publish + purge to produce the
    /// output already on the CDN.
    #[tokio::test]
    async fn failed_fetch_reports_the_error_and_pokes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let poke = FakePoke::default();
        let (calls, _) = poke.handles();
        let fetcher = FeedFetcher::new(
            vec![unreachable_feed("releases", "/releases")],
            tmp.path(),
            None,
            Box::new(poke),
        );

        let outcomes = fetcher.run_once().await;
        assert_eq!(outcomes.len(), 1);
        assert!(!outcomes[0].changed);
        assert_eq!(outcomes[0].poked, None);
        assert!(
            outcomes[0].error.as_deref().unwrap().contains("fetch failed"),
            "got {:?}",
            outcomes[0].error
        );
        assert!(calls.lock().unwrap().is_empty(), "no poke on a failed fetch");
    }

    /// One wedged feed must not stop its siblings — the loop collects per-feed
    /// outcomes instead of short-circuiting.
    #[tokio::test]
    async fn one_failing_feed_does_not_stop_the_others() {
        let tmp = tempfile::tempdir().unwrap();
        let fetcher = FeedFetcher::new(
            vec![
                unreachable_feed("releases", "/releases"),
                unreachable_feed("yah-desktop", "/releases"),
            ],
            tmp.path(),
            None,
            Box::new(FakePoke::default()),
        );

        let outcomes = fetcher.run_once().await;
        assert_eq!(outcomes.len(), 2, "every feed gets a tick");
        assert!(outcomes.iter().all(|o| o.error.is_some()));
    }

    /// The at-least-once property: a change whose poke failed is retried on the
    /// next tick even though the artifact is now identical (so the fetch
    /// reports no change and would otherwise never mention it again).
    #[tokio::test]
    async fn a_failed_poke_is_retried_on_the_next_tick() {
        let tmp = tempfile::tempdir().unwrap();
        let poke = FakePoke::default();
        let (calls, fail) = poke.handles();
        let fetcher = FeedFetcher::new(
            vec![unreachable_feed("releases", "/releases")],
            tmp.path(),
            None,
            Box::new(poke),
        );

        // Simulate "the fetch changed the artifact but the receiver was down"
        // by seeding the pending entry — the same state `run_feed` records.
        *fail.lock().unwrap() = true;
        fetcher
            .pending
            .lock()
            .unwrap()
            .insert("releases".to_string(), Poke::route("/releases"));

        let outcomes = fetcher.run_once().await;
        assert_eq!(outcomes[0].poked, None);
        assert_eq!(
            fetcher.pending_feeds(),
            vec!["releases".to_string()],
            "an undelivered poke stays owed"
        );

        // Receiver comes back: the owed poke lands without any new upstream
        // change, and the debt clears.
        *fail.lock().unwrap() = false;
        let outcomes = fetcher.run_once().await;
        assert_eq!(outcomes[0].poked, Some("/releases".to_string()));
        assert_eq!(routes(&calls), vec!["/releases".to_string()]);
        assert!(fetcher.pending_feeds().is_empty(), "debt cleared once delivered");
    }

    /// A fetch-only feed (no `on_change`) never pokes, even when it changed.
    #[tokio::test]
    async fn fetch_only_feed_never_pokes() {
        let tmp = tempfile::tempdir().unwrap();
        let poke = FakePoke::default();
        let (calls, _) = poke.handles();
        let fetcher = FeedFetcher::new(
            vec![fetch_only_feed("releases")],
            tmp.path(),
            None,
            Box::new(poke),
        );

        let _ = fetcher.run_once().await;
        assert!(calls.lock().unwrap().is_empty());
    }

    // ── Full-cycle acceptance (R330-F31 verify #3) ───────────────────────────
    //
    // A real HTTP source over loopback, so the cycle under test is the one that
    // runs on a node: fetch → write the artifact → poke only when the payload
    // actually moved. The FakePoke stands in for the receiver (booting V8 is
    // the receiver's business, not this tier's).

    use std::sync::atomic::{AtomicU64, Ordering};

    /// Serve a `release-manifest.json` whose version is read from a shared cell,
    /// so a test can "publish a release" between ticks. Returns the base URL.
    async fn spawn_manifest_source(version: Arc<AtomicU64>) -> String {
        use axum::{routing::get, Router};

        let app = Router::new().route(
            "/release-manifest.json",
            get(move || {
                let version = Arc::clone(&version);
                async move {
                    let patch = version.load(Ordering::SeqCst);
                    axum::Json(serde_json::json!({
                        "version": format!("v0.8.{patch}"),
                        "pub_date": "2026-07-24T00:00:00Z",
                        "host": { "bundle": {
                            "aarch64-apple-darwin": {
                                "url": format!("https://cdn.example/yah_0.8.{patch}.dmg"),
                                "size": 1234
                            }
                        }}
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        format!("http://{addr}")
    }

    fn manifest_feed(name: &str, url: &str, route: &str) -> FeedConfig {
        toml::from_str(&format!(
            r#"
[feed]
name = "{name}"
[feed.source]
kind = "r2-manifest"
url = "{url}/release-manifest.json"
[feed.trigger]
kind = "webhook"
[feed.emit]
artifact = "src/data/{name}.json"
on_change = {{ kind = "mesofact-rebuild", service = "yah-marketing", route = "{route}" }}
"#
        ))
        .unwrap()
    }

    /// The property the whole tier exists for: the first tick materialises the
    /// artifact under the project root (where the receiver re-reads
    /// `data_inputs` from) and pokes; a second tick with no upstream change
    /// pokes nothing; a version bump pokes again.
    #[tokio::test]
    async fn fetch_writes_the_artifact_and_pokes_only_on_real_change() {
        let tmp = tempfile::tempdir().unwrap();
        let version = Arc::new(AtomicU64::new(20));
        let base = spawn_manifest_source(Arc::clone(&version)).await;

        let poke = FakePoke::default();
        let (calls, _) = poke.handles();
        let fetcher = FeedFetcher::new(
            vec![manifest_feed("releases", &base, "/releases")],
            tmp.path(),
            None,
            Box::new(poke),
        );

        // Tick 1 — nothing on disk yet, so everything is new.
        let outcomes = fetcher.run_once().await;
        assert_eq!(outcomes[0].error, None, "loopback fetch should succeed");
        assert!(outcomes[0].changed);
        assert_eq!(outcomes[0].poked, Some("/releases".to_string()));

        let artifact = tmp.path().join("src/data/releases.json");
        let written = std::fs::read_to_string(&artifact).expect("artifact written under app root");
        assert!(written.contains("0.8.20"), "got {written}");

        // Tick 2 — same upstream payload. `fetched_at` moves but the releases
        // don't, so this must publish nothing (a re-render + R2 publish + CDN
        // purge for byte-identical output is pure waste).
        let outcomes = fetcher.run_once().await;
        assert!(!outcomes[0].changed, "unchanged upstream must not count as a change");
        assert_eq!(outcomes[0].poked, None);
        assert_eq!(calls.lock().unwrap().len(), 1, "second tick must not poke");

        // Tick 3 — a release lands upstream.
        version.store(21, Ordering::SeqCst);
        let outcomes = fetcher.run_once().await;
        assert!(outcomes[0].changed);
        assert_eq!(outcomes[0].poked, Some("/releases".to_string()));
        assert_eq!(calls.lock().unwrap().len(), 2);
        assert!(std::fs::read_to_string(&artifact).unwrap().contains("0.8.21"));
    }

    /// Serve the CLI install pointer (`yah/latest.json`) — the shape
    /// `cli-release-manifest` publishes — with a settable patch version, so a
    /// test can "tag a release" between ticks.
    async fn spawn_install_pointer(version: Arc<AtomicU64>) -> String {
        use axum::{routing::get, Router};

        let app = Router::new().route(
            "/yah/latest.json",
            get(move || {
                let version = Arc::clone(&version);
                async move {
                    let patch = version.load(Ordering::SeqCst);
                    // Five triples, keyed and ordered as the merge job emits
                    // them — enough legs that a HashMap's per-process ordering
                    // would visibly churn if the mapping did not sort.
                    let triples: serde_json::Map<String, serde_json::Value> = [
                        ("aarch64-apple-darwin", "macos-arm64"),
                        ("x86_64-apple-darwin", "macos-x86_64"),
                        ("x86_64-unknown-linux-gnu", "linux-x86_64"),
                        ("x86_64-unknown-linux-musl", "linux-x86_64-musl"),
                        ("aarch64-unknown-linux-musl", "linux-aarch64-musl"),
                    ]
                    .into_iter()
                    .map(|(triple, platform)| {
                        let url = format!(
                            "https://cdn.example/yah/0.8.{patch}/{triple}/yah-{triple}.tar.gz"
                        );
                        (
                            triple.to_string(),
                            serde_json::json!({
                                "platform": platform,
                                "filename": format!("yah-{triple}.tar.gz"),
                                "url": url,
                                "sha256": "a".repeat(64),
                                "size_bytes": 1234,
                                "sig_url": format!("{url}.sig"),
                                "cert_url": format!("{url}.cert"),
                                "bins": ["yah", "yahh", "yahb", "yaha"],
                            }),
                        )
                    })
                    .collect();
                    axum::Json(serde_json::json!({
                        "name": "yah",
                        "version": format!("0.8.{patch}"),
                        "pub_date": "2026-08-04T00:00:00Z",
                        "triples": triples,
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        format!("http://{addr}")
    }

    /// The acceptance path for R330-T32, end to end and server-free: the
    /// shipped `.yah/almanac/releases.toml` wiring, against the shape the GHA
    /// publish job actually emits, through the real runner.
    ///
    /// Stands in for a live fetch on purpose — `cdn.yah.dev/yah/latest.json`
    /// 404s until the next tagged release runs `cli-release-manifest` (the job
    /// landed after v0.8.20 was cut), so there is nothing live to point at yet.
    /// What can be verified now is everything between the bytes and the page:
    /// the pointer parses, every published triple becomes a download, the
    /// artifact lands where the /releases route reads it, and an unchanged
    /// release does not fire a rebuild.
    #[tokio::test]
    async fn the_cli_install_pointer_feeds_the_releases_page() {
        let tmp = tempfile::tempdir().unwrap();
        let version = Arc::new(AtomicU64::new(21));
        let base = spawn_install_pointer(Arc::clone(&version)).await;

        let feed: FeedConfig = toml::from_str(&format!(
            r#"
[feed]
name = "releases"
[feed.source]
kind = "r2-triples"
url = "{base}/yah/latest.json"
id = "yah"
[feed.trigger]
kind = "webhook"
[feed.emit]
artifact = "src/data/releases.json"
on_change = {{ kind = "mesofact-rebuild", service = "yah-marketing", route = "/releases" }}
"#
        ))
        .unwrap();

        let poke = FakePoke::default();
        let (calls, _) = poke.handles();
        let fetcher = FeedFetcher::new(vec![feed], tmp.path(), None, Box::new(poke));

        let outcomes = fetcher.run_once().await;
        assert_eq!(outcomes[0].error, None);
        assert!(outcomes[0].changed);
        assert_eq!(outcomes[0].poked, Some("/releases".to_string()));

        // The blank page this ticket exists to fix: releases.json shipped as
        // `{"releases":[]}`. Assert on the parsed feed, since "the file is
        // non-empty" was true of the broken stub too.
        let artifact = tmp.path().join("src/data/releases.json");
        let feed: crate::feed::ReleaseFeed =
            serde_json::from_str(&std::fs::read_to_string(&artifact).unwrap()).unwrap();
        assert_eq!(feed.releases.len(), 1, "latest.json is one version");
        let rel = &feed.releases[0];
        assert_eq!(rel.version, "0.8.21");
        assert_eq!(rel.tag, "v0.8.21");
        assert_eq!(rel.assets.len(), 5, "every published triple is downloadable");
        assert!(
            rel.assets.iter().all(|a| a.url.starts_with("https://") && a.sha256.is_some()),
            "each download needs a public URL and a checksum to verify it with"
        );

        // Re-publishing the same version must not cost a rebuild + CDN purge.
        let outcomes = fetcher.run_once().await;
        assert!(!outcomes[0].changed, "an unchanged release must be a no-op");
        assert_eq!(calls.lock().unwrap().len(), 1);

        // A real release does.
        version.store(22, Ordering::SeqCst);
        let outcomes = fetcher.run_once().await;
        assert!(outcomes[0].changed);
        assert_eq!(calls.lock().unwrap().len(), 2);
        assert!(std::fs::read_to_string(&artifact).unwrap().contains("0.8.22"));
    }

    // ── The accumulating index feeds the whole history (R330-F38) ────────────

    /// One version's worth of the index, in the exact shape the
    /// `cli-release-manifest` append step writes: five triples, TAGGED hashes
    /// only, and per-version URLs. Used both to measure what a release costs on
    /// the wire and to overrun the ceiling deliberately.
    fn index_version(patch: u64) -> serde_json::Value {
        let triples: serde_json::Map<String, serde_json::Value> = [
            ("aarch64-apple-darwin", "macos-arm64"),
            ("x86_64-apple-darwin", "macos-x86_64"),
            ("x86_64-unknown-linux-gnu", "linux-x86_64"),
            ("x86_64-unknown-linux-musl", "linux-x86_64-musl"),
            ("aarch64-unknown-linux-musl", "linux-aarch64-musl"),
        ]
        .into_iter()
        .map(|(triple, platform)| {
            let url =
                format!("https://cdn.example/yah/0.8.{patch}/{triple}/yah-{triple}.tar.gz");
            (
                triple.to_string(),
                serde_json::json!({
                    "platform": platform,
                    "filename": format!("yah-{triple}.tar.gz"),
                    "url": url,
                    "hash": format!("blake3:{}", "a".repeat(64)),
                    "bootstrap_hash": format!("sha256:{}", "b".repeat(64)),
                    "size_bytes": 1234,
                    "sig_url": format!("{url}.sig"),
                    "cert_url": format!("{url}.cert"),
                    "bins": ["yah", "yahh", "yahb", "yaha"],
                }),
            )
        })
        .collect();
        serde_json::json!({
            "version": format!("0.8.{patch}"),
            // Descending dates, so "newest first" is a real assertion rather
            // than an accident of insertion order.
            "pub_date": format!("2026-08-04T00:00:{:02}Z", (patch % 60)),
            "manifest_url": format!("https://cdn.example/yah/0.8.{patch}/manifest.json"),
            "triples": triples,
        })
    }

    /// The index document for the newest `n` versions, newest first.
    fn index_doc(n: u64) -> serde_json::Value {
        serde_json::json!({
            "name": "yah",
            "schema": 1,
            "updated_at": "2026-08-04T00:00:00Z",
            "versions": (0..n).map(|i| index_version(n - i)).collect::<Vec<_>>(),
        })
    }

    /// Serve `yah/index.json` with a settable release count, so a test can
    /// "tag a release" (append one entry) between ticks.
    async fn spawn_release_index(count: Arc<AtomicU64>) -> String {
        use axum::{routing::get, Router};

        let app = Router::new().route(
            "/yah/index.json",
            get(move || {
                let count = Arc::clone(&count);
                async move { axum::Json(index_doc(count.load(Ordering::SeqCst))) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        format!("http://{addr}")
    }

    fn index_feed_config(base: &str) -> FeedConfig {
        toml::from_str(&format!(
            r#"
[feed]
name = "releases"
[feed.source]
kind = "r2-index"
url = "{base}/yah/index.json"
id = "yah"
[feed.trigger]
kind = "webhook"
[feed.emit]
artifact = "src/data/releases.json"
on_change = {{ kind = "mesofact-rebuild", service = "yah-marketing", route = "/releases" }}
"#
        ))
        .unwrap()
    }

    /// R330-F38's acceptance path, end to end and server-free: the shipped
    /// `.yah/almanac/releases.toml` wiring against the shape the release job
    /// maintains, through the real runner.
    ///
    /// The thing R330-T32 could not deliver and explicitly left here: the
    /// pointer is ONE version, so the page it fed was a one-entry list. This
    /// asserts the full history reaches the artifact the /releases route reads,
    /// newest first, with each version's links aimed at its own bytes.
    #[tokio::test]
    async fn the_release_index_feeds_the_whole_history_to_the_page() {
        let tmp = tempfile::tempdir().unwrap();
        let count = Arc::new(AtomicU64::new(9));
        let base = spawn_release_index(Arc::clone(&count)).await;

        let poke = FakePoke::default();
        let (calls, _) = poke.handles();
        let fetcher =
            FeedFetcher::new(vec![index_feed_config(&base)], tmp.path(), None, Box::new(poke));

        let outcomes = fetcher.run_once().await;
        assert_eq!(outcomes[0].error, None);
        assert!(outcomes[0].changed);
        assert_eq!(outcomes[0].poked, Some("/releases".to_string()));

        let artifact = tmp.path().join("src/data/releases.json");
        let feed: crate::feed::ReleaseFeed =
            serde_json::from_str(&std::fs::read_to_string(&artifact).unwrap()).unwrap();
        assert_eq!(feed.releases.len(), 9, "every published version, not just the latest");
        let versions: Vec<&str> = feed.releases.iter().map(|r| r.version.as_str()).collect();
        assert_eq!(
            versions,
            vec!["0.8.9", "0.8.8", "0.8.7", "0.8.6", "0.8.5", "0.8.4", "0.8.3", "0.8.2", "0.8.1"],
            "newest first"
        );
        for release in &feed.releases {
            assert_eq!(release.assets.len(), 5, "every triple stays downloadable forever");
            for asset in &release.assets {
                // A per-version link that resolves to another version's bytes
                // is the failure mode that makes a history page useless.
                assert!(
                    asset.url.contains(&format!("/yah/{}/", release.version)),
                    "{} links to {}",
                    release.version,
                    asset.url
                );
                assert_eq!(
                    asset.hash.as_ref().map(|h| h.algo()),
                    Some(crate::feed::HashAlgo::Blake3),
                    "the index is tagged-only and blake3 is the identity"
                );
            }
        }
        // The poke handed the page these exact bytes. Cloned out rather than
        // borrowed: a `let` binding borrowing through `calls.lock()` extends the
        // guard to the end of this block, and the ticks below would then
        // deadlock against `FakePoke::poke` taking the same mutex.
        let carried = calls.lock().unwrap()[0].data_inputs["src/data/releases.json"].clone();
        assert_eq!(carried["releases"].as_array().unwrap().len(), 9);

        // Re-reading an unchanged index must not cost a rebuild + CDN purge.
        let outcomes = fetcher.run_once().await;
        assert!(!outcomes[0].changed, "an unchanged history must be a no-op");
        assert_eq!(calls.lock().unwrap().len(), 1);

        // A new release APPENDS — the prior nine survive, which is the ticket's
        // "append is not clobber" acceptance criterion seen from the read side.
        count.store(10, Ordering::SeqCst);
        let outcomes = fetcher.run_once().await;
        assert!(outcomes[0].changed);
        let feed: crate::feed::ReleaseFeed =
            serde_json::from_str(&std::fs::read_to_string(&artifact).unwrap()).unwrap();
        assert_eq!(feed.releases.len(), 10);
        assert_eq!(feed.releases[0].version, "0.8.10", "the new one leads");
        assert!(
            feed.releases.iter().any(|r| r.version == "0.8.1"),
            "and the oldest is still listed"
        );
    }

    // ── The payload ceiling (R330-F38) ───────────────────────────────────────

    /// What one release costs in a poke payload, measured on real serialized
    /// bytes rather than estimated.
    fn payload_bytes_for(n: u64) -> usize {
        let feed = crate::r2::feed_from_index_manifest(&index_doc(n).to_string()).unwrap();
        serde_json::to_vec(&feed).unwrap().len()
    }

    /// The number in [`MAX_POKE_PAYLOAD_BYTES`]'s doc comment is a *release
    /// count*, and a doc comment cannot go stale quietly if a test reads it.
    ///
    /// This is the "pin the limit" half of R330-F38: the limit stopped being
    /// theoretical the moment the feed started accumulating, so the capacity it
    /// buys is asserted rather than asserted-about-in-prose. A change that makes
    /// a release two or three times fatter — another triple, another hash, notes
    /// inlined — fails here and forces the escape-hatch conversation instead of
    /// silently eating the headroom.
    #[test]
    fn the_payload_ceiling_is_a_measured_release_count_not_a_guess() {
        // Differenced so the per-release cost excludes the fixed envelope.
        let per_release = (payload_bytes_for(21) - payload_bytes_for(1)) / 20;
        let capacity = MAX_POKE_PAYLOAD_BYTES / per_release;
        assert!(
            (300..1500).contains(&capacity),
            "a release costs {per_release} B, so the {MAX_POKE_PAYLOAD_BYTES} B ceiling \
             holds {capacity} releases — the doc comment says ~600. If this is now much \
             SMALLER, the inline payload is running out and the R2-pointer escape hatch \
             (R330-F33) is due; if much LARGER, update the doc comment."
        );
    }

    /// Over the ceiling, the tick degrades to a payload-less poke and says so
    /// loudly. It must NOT truncate the payload (a half-history rendered as the
    /// whole one is worse than a stale one) and must NOT drop the revalidation.
    #[tokio::test]
    async fn an_oversize_payload_degrades_loudly_instead_of_reaching_the_wire() {
        let tmp = tempfile::tempdir().unwrap();
        let per_release = (payload_bytes_for(21) - payload_bytes_for(1)) / 20;
        let too_many = (MAX_POKE_PAYLOAD_BYTES / per_release + 20) as u64;
        let count = Arc::new(AtomicU64::new(too_many));
        let base = spawn_release_index(Arc::clone(&count)).await;

        let poke = FakePoke::default();
        let (calls, _) = poke.handles();
        let fetcher =
            FeedFetcher::new(vec![index_feed_config(&base)], tmp.path(), None, Box::new(poke));

        let outcomes = fetcher.run_once().await;
        assert!(outcomes[0].changed);
        assert_eq!(
            outcomes[0].poked,
            Some("/releases".to_string()),
            "the revalidation still has to happen — degrade, do not drop"
        );
        let err = outcomes[0].error.as_deref().expect("an oversize payload is not silent");
        assert!(
            err.contains("over the") && err.contains("ceiling"),
            "the error must name the ceiling so an operator can act on it: {err}"
        );

        let sent = calls.lock().unwrap()[0].clone();
        assert!(
            sent.data_inputs.is_empty(),
            "nothing over the ceiling may reach the wire — not even truncated"
        );

        // The artifact is still written in full: only the *poke* degraded, so
        // the receiver's own sidecar copy remains the fallback path.
        let feed: crate::feed::ReleaseFeed = serde_json::from_str(
            &std::fs::read_to_string(tmp.path().join("src/data/releases.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(feed.releases.len() as u64, too_many);
    }

    /// The seam that decides whether any of this works on a node: a feed
    /// declares its artifact **workspace-relative**, the route declares the same
    /// file **project-relative**, and the receiver only re-reads the latter.
    /// Strip the component prefix and the two agree; forget to, and every tick
    /// writes a file nothing renders.
    #[tokio::test]
    async fn the_artifact_lands_where_the_route_declares_its_data_input() {
        let tmp = tempfile::tempdir().unwrap();
        let version = Arc::new(AtomicU64::new(20));
        let base = spawn_manifest_source(Arc::clone(&version)).await;

        // The shipped shape: `.yah/almanac/releases.toml` emits
        // `app/yah/web/marketing/src/data/releases.json`, while
        // `/releases` declares `data_inputs = ["src/data/releases.json"]`.
        let mut cfg = manifest_feed("releases", &base, "/releases");
        cfg.feed.emit.artifact = "app/yah/web/marketing/src/data/releases.json".into();

        let fetcher = FeedFetcher::new(
            vec![cfg],
            tmp.path(),
            Some(PathBuf::from("app/yah/web/marketing")),
            Box::new(FakePoke::default()),
        );
        let outcomes = fetcher.run_once().await;
        assert_eq!(outcomes[0].error, None);

        assert!(
            tmp.path().join("src/data/releases.json").is_file(),
            "artifact must land at the route's data_inputs path under the workload root"
        );
        assert!(
            !tmp.path().join("app").exists(),
            "the workspace-relative prefix must not be reproduced inside the bundle"
        );
    }

    /// A feed attached to a workload that doesn't consume it would otherwise
    /// write into the bundle at a path nothing reads, and poke a route that
    /// re-renders unchanged — a fetcher that looks healthy and does nothing.
    #[tokio::test]
    async fn a_feed_outside_the_project_is_reported_not_silently_written() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = unreachable_feed("releases", "/releases");
        cfg.feed.emit.artifact = "app/yah/web/dashboard/src/data/releases.json".into();

        let poke = FakePoke::default();
        let (calls, _) = poke.handles();
        let fetcher = FeedFetcher::new(
            vec![cfg],
            tmp.path(),
            Some(PathBuf::from("app/yah/web/marketing")),
            Box::new(poke),
        );

        let outcomes = fetcher.run_once().await;
        let err = outcomes[0].error.as_deref().unwrap();
        assert!(err.contains("wrong workload"), "got {err}");
        assert!(calls.lock().unwrap().is_empty());
    }

    /// The real `HttpPoke` speaks the body shape `mesofact serve --revalidate`
    /// parses (`{route, mirror_key}` → 202). Asserting it here keeps the wire
    /// contract from drifting silently across the two repos.
    #[tokio::test]
    async fn http_poke_posts_route_and_mirror_key_to_revalidate() {
        use axum::{routing::post, Json, Router};
        use tokio::sync::mpsc;

        let (tx, mut rx) = mpsc::channel::<serde_json::Value>(4);
        let app = Router::new().route(
            "/revalidate",
            post(move |Json(body): Json<serde_json::Value>| {
                let tx = tx.clone();
                async move {
                    tx.send(body).await.ok();
                    axum::http::StatusCode::ACCEPTED
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });

        HttpPoke::new(format!("http://{addr}"), Some("bearer-abc".into()))
            .poke(&Poke::route("/releases"))
            .await
            .expect("202 is a success");

        let body = rx.recv().await.unwrap();
        assert_eq!(body["route"], "/releases");
        assert_eq!(body["mirror_key"], "bearer-abc");
        assert!(
            body.get("data_inputs").is_none(),
            "a payload-less poke must stay on the wire shape older receivers parse, got {body}"
        );
    }

    /// The whole-site poke: an empty route omits the key rather than sending
    /// `""`. `""` parses fine into the receiver's `Option<String>` route and
    /// then makes it try to render a route literally named `""` — the same
    /// class of silent-but-wrong body as the `{"feed": …}` bug, so it is
    /// pinned here rather than left to each caller to remember.
    #[tokio::test]
    async fn an_empty_route_omits_the_key_and_takes_the_whole_site_branch() {
        use axum::{routing::post, Json, Router};
        use tokio::sync::mpsc;

        let (tx, mut rx) = mpsc::channel::<serde_json::Value>(4);
        let app = Router::new().route(
            "/revalidate",
            post(move |Json(body): Json<serde_json::Value>| {
                let tx = tx.clone();
                async move {
                    tx.send(body).await.ok();
                    axum::http::StatusCode::ACCEPTED
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });

        HttpPoke::new(format!("http://{addr}"), None)
            .poke(&Poke::route(""))
            .await
            .expect("202 is a success");

        let body = rx.recv().await.unwrap();
        assert!(
            body.get("route").is_none(),
            "an empty route must be absent, not \"\" — got {body}"
        );
        assert!(body.get("feed").is_none(), "`feed` is not part of this wire shape: {body}");
    }

    /// R707-F4 — the OTHER receiver. A feed-keyed poke must be the body
    /// [`crate::receiver`] accepts and nothing more: no `route` (it would be
    /// meaningless), no `data_inputs` (the receiving side re-fetches, which is
    /// what makes the source absolute and the poke coalescable).
    ///
    /// This is the same class of bug as the one above, pointed the other way:
    /// mesofact's `RevalidateBody` would happily parse `{"feed": …}` and render
    /// the whole site. Both shapes are pinned so neither can drift into the
    /// other's endpoint unnoticed.
    #[tokio::test]
    async fn a_feed_keyed_poke_sends_the_receiver_body_and_nothing_else() {
        use axum::{routing::post, Json, Router};
        use tokio::sync::mpsc;

        let (tx, mut rx) = mpsc::channel::<serde_json::Value>(4);
        let app = Router::new().route(
            "/revalidate",
            post(move |Json(body): Json<serde_json::Value>| {
                let tx = tx.clone();
                async move {
                    tx.send(body).await.ok();
                    axum::http::StatusCode::OK
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });

        HttpPoke::new(format!("http://{addr}"), Some("bearer-abc".into()))
            .poke(&Poke::feed("fleet"))
            .await
            .unwrap();

        let body = rx.recv().await.unwrap();
        assert_eq!(body["feed"], "fleet");
        assert_eq!(body["mirror_key"], "bearer-abc");
        assert!(body.get("route").is_none(), "no route on this shape: {body}");
        assert!(
            body.get("data_inputs").is_none(),
            "the change lives in the feed, never in the request body: {body}"
        );
    }

    /// The producer never chooses a wire shape — the feed's `on_change` does.
    #[test]
    fn poke_for_derives_the_shape_from_the_feeds_own_on_change() {
        let parse = |on_change: &str| -> FeedConfig {
            toml::from_str(&format!(
                "[feed]\nname = \"f\"\n[feed.source]\nkind = \"gh-releases\"\nrepo = \"o/r\"\n\
                 [feed.trigger]\nkind = \"webhook\"\n[feed.emit]\nartifact = \"out.json\"\n{on_change}"
            ))
            .unwrap()
        };

        let reload = poke_for(&parse(
            "[feed.emit.on_change]\nkind = \"reload\"\nservice = \"yah-cloud-admin\"\n",
        ));
        assert_eq!(reload.feed.as_deref(), Some("f"));
        assert!(reload.route.is_empty());

        let rebuild = poke_for(&parse(
            "[feed.emit.on_change]\nkind = \"mesofact-rebuild\"\nservice = \"s\"\nroute = \"/releases\"\n",
        ));
        assert_eq!(rebuild.feed, None);
        assert_eq!(rebuild.route, "/releases");

        let bare = poke_for(&parse(""));
        assert_eq!(bare.feed, None);
        assert!(bare.route.is_empty(), "no on_change is still the whole-site poke");
    }

    /// End to end over TCP against the REAL receiver, not a stub that accepts
    /// anything: `poke_for` → `HttpPoke` → `receiver::router` with its binding
    /// gate on. This is the leg the publish workflow fires, and it is the one
    /// place the two halves of R707-F4 (the `reload` arm and the feed-keyed
    /// body) have to agree.
    #[tokio::test]
    async fn the_workflows_poke_is_accepted_by_the_real_receiver() {
        use tokio::sync::mpsc;

        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("fleet.toml"),
            "[feed]\nname = \"fleet\"\n\n\
             [feed.source]\nkind = \"gh-releases\"\nrepo = \"o/r\"\n\n\
             [feed.trigger]\nkind = \"webhook\"\n\n\
             [feed.emit]\nartifact = \"out.json\"\n\n\
             [feed.emit.on_change]\nkind = \"reload\"\nservice = \"yah-cloud-admin\"\n",
        )
        .unwrap();
        let cfg = crate::FeedLoader::new(tmp.path()).load("fleet").unwrap();

        let (tx, mut rx) = mpsc::channel::<String>(4);
        let app = crate::receiver::router(
            tx,
            None,
            Some(crate::receiver::MirrorBind {
                service_id: "yah-cloud-admin".into(),
                env: "cloud".into(),
                almanac_dir: tmp.path().to_path_buf(),
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });

        HttpPoke::new(format!("http://{addr}"), None)
            .poke(&poke_for(&cfg))
            .await
            .expect("the receiver must accept the poke its own feed config produces");
        assert_eq!(rx.recv().await.unwrap(), "fleet");
    }

    /// A non-2xx from the receiver is an error the caller can retry, not a
    /// silently-swallowed success.
    #[tokio::test]
    async fn http_poke_surfaces_a_rejecting_receiver() {
        use axum::{routing::post, Router};

        let app = Router::new().route(
            "/revalidate",
            post(|| async { axum::http::StatusCode::FORBIDDEN }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });

        let err = HttpPoke::new(format!("http://{addr}"), None)
            .poke(&Poke::route("/releases"))
            .await
            .unwrap_err();
        assert!(err.contains("403"), "got {err}");
    }

    // ── The poke carries its data (R330-F33) ─────────────────────────────────

    /// The payload the receiver needs: the poke names the route's own
    /// `data_inputs` path and carries the exact feed that was just written, so
    /// an instance with no sidecar of its own can still render correctly.
    #[tokio::test]
    async fn a_changed_feed_pokes_with_the_data_it_just_wrote() {
        let tmp = tempfile::tempdir().unwrap();
        let version = Arc::new(AtomicU64::new(20));
        let base = spawn_manifest_source(Arc::clone(&version)).await;

        // The shipped shape: workspace-relative artifact, project-relative
        // data_input. The payload must be keyed by the latter — the receiver
        // knows nothing about feed config or workspace layout.
        let mut cfg = manifest_feed("releases", &base, "/releases");
        cfg.feed.emit.artifact = "app/yah/web/marketing/src/data/releases.json".into();

        let poke = FakePoke::default();
        let (calls, _) = poke.handles();
        let fetcher = FeedFetcher::new(
            vec![cfg],
            tmp.path(),
            Some(PathBuf::from("app/yah/web/marketing")),
            Box::new(poke),
        );

        let outcomes = fetcher.run_once().await;
        assert_eq!(outcomes[0].error, None);

        let sent = calls.lock().unwrap().clone();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].route, "/releases");
        let carried = sent[0]
            .data_inputs
            .get("src/data/releases.json")
            .expect("payload is keyed by the route's own data_inputs path");
        assert_eq!(
            carried,
            &serde_json::from_str::<serde_json::Value>(
                &std::fs::read_to_string(tmp.path().join("src/data/releases.json")).unwrap()
            )
            .unwrap(),
            "the poke must carry exactly the artifact that was written",
        );
        assert_eq!(carried["releases"][0]["version"], "0.8.20");
    }

    /// A retried poke must still carry its payload. The artifact is unchanged
    /// by then, so a retry that shipped only the route would re-render from
    /// node-local state — the exact failure this ticket removes, resurfacing on
    /// the one path where the poke is most likely to land on another instance.
    #[tokio::test]
    async fn a_retried_poke_still_carries_its_payload() {
        let tmp = tempfile::tempdir().unwrap();
        let version = Arc::new(AtomicU64::new(20));
        let base = spawn_manifest_source(Arc::clone(&version)).await;

        let poke = FakePoke::default();
        let (calls, fail) = poke.handles();
        let fetcher = FeedFetcher::new(
            vec![manifest_feed("releases", &base, "/releases")],
            tmp.path(),
            None,
            Box::new(poke),
        );

        // Tick 1: the fetch lands the artifact, the receiver is down.
        *fail.lock().unwrap() = true;
        let outcomes = fetcher.run_once().await;
        assert!(outcomes[0].changed);
        assert_eq!(outcomes[0].poked, None);
        assert_eq!(fetcher.pending_feeds(), vec!["releases".to_string()]);

        // Tick 2: receiver is back. The fetch now reports no change (the
        // artifact already matches upstream), so the payload can only come from
        // what the owed poke remembered.
        *fail.lock().unwrap() = false;
        let outcomes = fetcher.run_once().await;
        assert!(!outcomes[0].changed, "precondition: nothing new upstream");
        assert_eq!(outcomes[0].poked, Some("/releases".to_string()));

        let sent = calls.lock().unwrap().clone();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].data_inputs.get("src/data/releases.json").map(|v| &v["releases"][0]["version"]),
            Some(&serde_json::json!("0.8.20")),
            "the owed poke must be retried with its payload intact",
        );
    }

    /// The wire form of a payload-carrying poke, asserted against a receiver
    /// that only speaks JSON — this is the contract `mesofact serve
    /// --revalidate` parses, and it lives in two repos, so it is pinned here.
    #[tokio::test]
    async fn http_poke_puts_the_payload_on_the_wire_under_data_inputs() {
        use axum::{routing::post, Json, Router};
        use tokio::sync::mpsc;

        let (tx, mut rx) = mpsc::channel::<serde_json::Value>(4);
        let app = Router::new().route(
            "/revalidate",
            post(move |Json(body): Json<serde_json::Value>| {
                let tx = tx.clone();
                async move {
                    tx.send(body).await.ok();
                    axum::http::StatusCode::ACCEPTED
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });

        HttpPoke::new(format!("http://{addr}"), None)
            .poke(
                &Poke::route("/releases")
                    .with_input("src/data/releases.json", serde_json::json!({"releases": []})),
            )
            .await
            .expect("202 is a success");

        let body = rx.recv().await.unwrap();
        assert_eq!(body["route"], "/releases");
        assert_eq!(
            body["data_inputs"]["src/data/releases.json"],
            serde_json::json!({"releases": []})
        );
    }
}

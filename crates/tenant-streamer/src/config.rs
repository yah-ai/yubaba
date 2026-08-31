//! Operator-supplied configuration, and the two naming conventions that turn a
//! [`TenantId`] into a local DB path and an object-store key prefix.
//!
//! Everything here is deliberately *config*, not placement. R737's placement
//! record does not exist yet and R732-T4 says not to block on it, so a node
//! streams exactly the tenants it has been configured for. Ownership — asked
//! of yubaba every tick — decides which of those are actually live.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use workload_spec::TenantId;

/// Default RPO bound. The tail cadence is derived from it (see
/// [`StreamerConfig::tail_interval`]) rather than configured separately,
/// because the two are not independent: the cadence *is* the mechanism, the
/// RPO is the promise, and letting an operator set them to contradictory
/// values buys nothing but a way to be wrong.
///
/// **120 s, so the derived cadence is 60 s** — deliberately equal to
/// [`turso_backup::stream::DEFAULT_TAIL_INTERVAL`], with this bound equal to
/// [`turso_backup::stream::DEFAULT_RPO_TARGET`]. Those two constants carry the
/// measurement that picked the number (R761-T1): `PUTs/write = frames/write +
/// 2 / writes_per_tail`, so every tail that uploads anything costs two fixed
/// objects — one generation manifest, one watermark CAS — on top of the
/// frames. The previous 30 s bound tailed every 15 s, which at a casual app's
/// burst rate is 1.5–15 writes per tail: 3.36–2.16 PUTs/write, the worst
/// column of the measured sweep. 60 s spans 6–60 writes per tail (2.36–2.06)
/// and captures ~97% of the total reduction available; going further buys ~3%
/// for a multiple of the exposure window. **Do not change this without
/// changing turso-backup's two constants in the same commit** — they are one
/// decision with two homes, and the arithmetic lives there.
///
/// The cost this buys the reduction with is stated plainly: the data-loss
/// window on unclean node death is now 120 s rather than 30 s. It is also the
/// floor for any per-tenant `TenantPlacement.rpo_bound` an operator declares
/// to yubaba's placement gate — a bound under the cadence would refuse every
/// candidate, since a reported watermark age saw-tooths up to one cadence
/// between tails.
pub const DEFAULT_RPO_SECS: u64 = 120;

/// Default tenant lease TTL requested from yubaba.
///
/// Long relative to the tail cadence on purpose. The lease is a *liveness*
/// hint that bounds when a takeover is permitted; the epoch is what makes a
/// takeover safe (R732-F1's `TenantOwnership` doc spells out the split). A
/// short lease therefore does not buy safety — it buys spurious failovers on a
/// jittery WAN link, and more raft traffic.
///
/// **Raised 300 → 540 s with the cadence** (R761-T1), because the two are
/// coupled and `StreamerConfig::validate` enforces the coupling: renewal is
/// only *attempted* on a tail tick, so the retry budget
/// ([`StreamerConfig::renew_when_remaining_below`], a third of the TTL) has to
/// be at least two ticks wide or one failed renewal drops a tenant this node
/// legitimately owns. At a 60 s cadence a 300 s lease leaves a 100 s budget
/// against a 120 s minimum — it would have failed at startup, which is the
/// validator doing its job.
///
/// 540 s makes that budget 180 s, three ticks. Two alternatives were
/// considered and rejected. 360 s is the smallest value that validates, but it
/// puts the shipped default exactly on the validator's boundary, where any
/// operator trimming the lease slightly gets a startup error and there is no
/// margin for jitter — the old default never sat there (100 s of budget was
/// ~6.7 ticks). 1080 s would preserve that *attempt count*, but attempts are
/// the wrong unit: what a retry budget protects against is a transient local
/// yubaba or raft outage, which is measured in wall-clock, and 180 s already
/// covers strictly more of it than the old default's 100 s. What 1080 s would
/// really buy is an 18-minute failover, since the lease TTL is exactly how
/// long a dead node's tenants stay unclaimable.
///
/// So the cost side of 540 s is: takeover after unclean death is permitted at
/// up to 9 minutes rather than 5. The raft write rate moves the other way —
/// renewal lands once per ⅔ TTL, i.e. every 360 s instead of every 200 s, so
/// W253 §4's "no heartbeats through the log" property gets *stronger*.
pub const DEFAULT_LEASE_SECS: u64 = 540;

/// The whole service's configuration, parsed from a TOML file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamerConfig {
    /// This node's yubaba raft node id. The streamer only writes for tenants
    /// yubaba says *this* id owns.
    pub node_id: u64,
    /// Base URL of the yubaba on this node, e.g. `http://127.0.0.1:7777`.
    /// Always node-local: the epoch is read from the LOCAL state machine, and
    /// staleness is safe by design (see the crate doc).
    pub yubaba_url: String,
    /// Root of the local hot tier. Tenant DBs live at
    /// `<data_root>/tenants/<id>/db`.
    pub data_root: PathBuf,
    /// The single object-store sink every tenant is keyed under.
    pub sink: SinkConfig,
    /// The tenants this node is configured to stream. Replaced by R737's
    /// placement record when that exists.
    #[serde(default)]
    pub tenants: Vec<TenantConfig>,
    /// Stated RPO bound. Drives both the tail cadence and turso-backup's own
    /// [`RpoStatus`](turso_backup::stream::RpoStatus) drift reporting.
    #[serde(default = "default_rpo_secs")]
    pub rpo_secs: u64,
    /// Lease TTL requested on each renewal.
    #[serde(default = "default_lease_secs")]
    pub lease_secs: u64,
}

fn default_rpo_secs() -> u64 {
    DEFAULT_RPO_SECS
}
fn default_lease_secs() -> u64 {
    DEFAULT_LEASE_SECS
}

/// The one bucket. Not one per tenant: per-tenant buckets would multiply
/// credentials and bucket-count limits by the tenant count for no isolation
/// the key prefix does not already give, and R2 charges per-operation, not
/// per-bucket.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SinkConfig {
    pub bucket: String,
    pub endpoint: String,
    pub region: String,
    /// Key prefix under which every tenant's own `tenants/<id>/` prefix hangs.
    /// Empty means "at the bucket root".
    #[serde(default)]
    pub prefix: String,
    /// Credentials come from the environment (`S3_ACCESS_KEY_ID` /
    /// `S3_SECRET_ACCESS_KEY`), never from this file — a config file is
    /// world-readable often enough that putting a secret in one is a decision
    /// nobody should be able to make by accident.
    #[serde(default)]
    pub access_key_env: Option<String>,
    #[serde(default)]
    pub secret_key_env: Option<String>,
}

/// Per-tenant configuration. Only the base snapshot is per-tenant data the
/// streamer cannot derive — everything else falls out of the conventions.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantConfig {
    pub tenant: TenantId,
    /// Object key of the tier-1a base snapshot the streamed frames replay
    /// onto.
    pub base_snapshot_key: String,
    /// Page size of that base snapshot. Read from the snapshot header, never
    /// assumed — turso-backup's [`StreamConfig::page_size`] is explicit about
    /// why inheriting `sync_server.rs`'s 4 KB hardcode is wrong.
    ///
    /// [`StreamConfig::page_size`]: turso_backup::stream::StreamConfig::page_size
    pub page_size: usize,
    /// Overrides the `<data_root>/tenants/<id>/db` convention. Present for the
    /// operator/manual path T4 sanctions; unset is the norm.
    #[serde(default)]
    pub db_path: Option<PathBuf>,
}

impl StreamerConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading streamer config {}", path.display()))?;
        let cfg: StreamerConfig = toml::from_str(&text)
            .with_context(|| format!("parsing streamer config {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if self.rpo_secs == 0 {
            bail!("rpo_secs must be > 0 — the tail cadence is derived from it");
        }
        // The renewal retry budget must be at least two ticks wide, or a
        // single failed renewal loses a tenant this node legitimately owns —
        // an outage produced entirely by configuration arithmetic, which is
        // the kind that gets diagnosed at 3am rather than at startup.
        let budget = self.renew_when_remaining_below();
        let tick = self.tail_interval();
        if budget < tick * 2 {
            bail!(
                "lease_secs ({}) leaves a {}s renewal retry budget, under {}s of tail cadence \
                 (rpo_secs {} / 2) — one failed renewal would drop the tenant. Raise lease_secs \
                 to at least {}.",
                self.lease_secs,
                budget.as_secs(),
                (tick * 2).as_secs(),
                self.rpo_secs,
                (tick * 6).as_secs().max(1),
            );
        }
        for t in &self.tenants {
            if t.page_size == 0 {
                bail!("tenant {}: page_size must be > 0", t.tenant.0);
            }
            // Reject early so a bad id fails at startup rather than on the
            // first tick of one unlucky tenant.
            tenant_path_segment(&t.tenant)?;
        }
        Ok(())
    }

    /// Tail at half the RPO bound, so a single missed tick still lands inside
    /// it. Tailing *at* the bound would mean every ordinary scheduling jitter
    /// reads as a breach.
    pub fn tail_interval(&self) -> Duration {
        Duration::from_secs(self.rpo_secs).div_f64(2.0)
    }

    pub fn rpo_target(&self) -> Duration {
        Duration::from_secs(self.rpo_secs)
    }

    /// Renew once a lease has less than a third of its TTL left.
    ///
    /// Renewal is deliberately NOT attempted on every tick, and this is the
    /// one place the ratified design is knowingly relaxed. W253 §4 is explicit
    /// that heartbeats must not go through the raft log; renewing every tail
    /// would put a write rate proportional to `tenants × tail rate` through a
    /// cross-region quorum, which is exactly what that section forbids.
    /// Renewing on a fraction of the lease makes the raft write rate a
    /// function of the lease TTL alone — one entry per tenant per ~⅔ TTL.
    ///
    /// The safety property is untouched either way: the epoch, not the lease,
    /// is what fences a stale writer (R732-F1's `TenantOwnership` doc).
    ///
    /// Once *below* this threshold a renewal is attempted every tick, so the
    /// remaining third of the lease is a retry budget — with the default 540s
    /// lease and 60s cadence, 180s of budget: three attempts before the lease
    /// actually lapses, covering more wall-clock outage than the 100s the
    /// previous 300s/15s default covered in about six.
    /// [`StreamerConfig::validate`] enforces that this budget is at least two
    /// ticks wide, and [`DEFAULT_LEASE_SECS`] explains why the default is not
    /// simply the smallest value that clears it.
    pub fn renew_when_remaining_below(&self) -> Duration {
        Duration::from_secs(self.lease_secs).div_f64(3.0)
    }

    /// Where this tenant's local DB lives.
    pub fn db_path(&self, t: &TenantConfig) -> Result<PathBuf> {
        if let Some(explicit) = &t.db_path {
            return Ok(explicit.clone());
        }
        Ok(self
            .data_root
            .join("tenants")
            .join(tenant_path_segment(&t.tenant)?)
            .join("db"))
    }

    /// Object-store key prefix for this tenant, under the single sink prefix.
    pub fn key_prefix(&self, tenant: &TenantId) -> Result<String> {
        let seg = tenant_path_segment(tenant)?;
        Ok(match self.sink.prefix.trim_matches('/') {
            "" => format!("tenants/{seg}"),
            root => format!("{root}/tenants/{seg}"),
        })
    }
}

/// A tenant id, validated as a single safe path/key segment.
///
/// [`TenantId`] is `pub struct TenantId(pub String)` — a raw string anyone can
/// construct, with no validation of its own. It reaches both a filesystem path
/// and an object key here, so it is checked rather than trusted: `..` would
/// escape `data_root`, a `/` would forge a nested prefix, and a NUL or a
/// leading `-` are the usual argument-injection shapes.
///
/// **This rejects rather than sanitises, deliberately.** Mangling an id into
/// something safe is worse than refusing it: two distinct tenants can mangle to
/// the same segment, and then they share a DB path and an R2 prefix — a
/// cross-tenant data leak produced by the very code meant to prevent one.
pub fn tenant_path_segment(tenant: &TenantId) -> Result<&str> {
    let id = tenant.0.as_str();
    if id.is_empty() {
        bail!("tenant id must not be empty");
    }
    if id == "." || id == ".." {
        bail!("tenant id {id:?} is a path traversal");
    }
    if id.starts_with('-') {
        bail!("tenant id {id:?} must not start with '-'");
    }
    if let Some(bad) = id
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
    {
        bail!(
            "tenant id {id:?} contains {bad:?}; ids must match [A-Za-z0-9._-]+ to be usable as \
             both a path segment and an object key"
        );
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(rpo: u64, lease: u64) -> StreamerConfig {
        StreamerConfig {
            node_id: 1,
            yubaba_url: "http://127.0.0.1:7777".into(),
            data_root: PathBuf::from("/var/lib/yah"),
            sink: SinkConfig {
                bucket: "b".into(),
                endpoint: "https://e".into(),
                region: "auto".into(),
                prefix: String::new(),
                access_key_env: None,
                secret_key_env: None,
            },
            tenants: vec![],
            rpo_secs: rpo,
            lease_secs: lease,
        }
    }

    /// The cadence is half the RPO so one missed tick is still inside the
    /// bound. Tailing at the bound would report a breach on ordinary jitter.
    #[test]
    fn the_tail_cadence_is_half_the_rpo_target() {
        let c = cfg(120, 540);
        assert_eq!(c.tail_interval(), Duration::from_secs(60));
        assert_eq!(c.rpo_target(), Duration::from_secs(120));
        // The ratio is the property, not the numbers — an arbitrary bound
        // halves the same way.
        assert_eq!(cfg(90, 540).tail_interval(), Duration::from_secs(45));
    }

    /// The shipped cadence default is one decision with two homes: this crate
    /// schedules the tail, turso-backup measured what a tail costs and carries
    /// the arithmetic. If either side moves alone the bill or the RPO promise
    /// silently stops matching the measurement that justified it (R761-T1), so
    /// the two are pinned to each other here rather than by comment.
    #[test]
    fn the_default_cadence_matches_turso_backups_measured_constants() {
        let c = cfg(DEFAULT_RPO_SECS, DEFAULT_LEASE_SECS);
        assert_eq!(c.tail_interval(), turso_backup::stream::DEFAULT_TAIL_INTERVAL);
        assert_eq!(c.rpo_target(), turso_backup::stream::DEFAULT_RPO_TARGET);
    }

    /// Renewal is paced off the lease, not the tail — the raft write rate must
    /// not scale with the tenant count times the tail rate (W253 §4).
    #[test]
    fn lease_renewal_is_paced_off_the_lease_not_the_tail_cadence() {
        let c = cfg(30, 300);
        assert_eq!(c.renew_when_remaining_below(), Duration::from_secs(100));
        assert!(
            c.renew_when_remaining_below() > c.tail_interval() * 4,
            "renewal must be far rarer than tailing, or it is a heartbeat through the log"
        );

        // Under the shipped defaults the threshold is three ticks, not the
        // ~6.7 the old 300s/15s pairing gave — so the tick-relative form above
        // is checked in the unit that actually bounds raft load: how often a
        // renewal LANDS in wall-clock. A renewal happens once the lease has
        // burned down to a third of its TTL, i.e. once per ⅔ TTL — 360s at
        // the 540s default, rarer than the 200s the 300s default gave, on a
        // cadence four times longer. W253 §4's property strengthens here; it
        // does not merely survive.
        let d = cfg(DEFAULT_RPO_SECS, DEFAULT_LEASE_SECS);
        let renewal_period = Duration::from_secs(DEFAULT_LEASE_SECS) - d.renew_when_remaining_below();
        assert_eq!(renewal_period, Duration::from_secs(360));
        assert!(
            renewal_period >= d.tail_interval() * 6,
            "a renewal per tenant per {renewal_period:?} must stay rare against a \
             {:?} tail cadence",
            d.tail_interval()
        );
    }

    /// A lease whose retry budget is under two ticks drops tenants on a single
    /// failed renewal — caught at startup, not in production.
    #[test]
    fn a_lease_with_no_room_for_a_retry_is_rejected_at_startup() {
        let err = cfg(30, 30).validate().unwrap_err();
        assert!(format!("{err}").contains("renewal retry budget"), "{err}");
        assert!(cfg(30, 300).validate().is_ok());

        // The shipped defaults must clear their OWN rule. They very nearly did
        // not: lengthening the cadence to 60s (R761-T1) put the old 300s lease
        // at a 100s budget against a 120s minimum, so raising the cadence
        // alone would have shipped a binary that refuses to start on its
        // default config. Pin the pair, not just the arithmetic.
        assert!(
            cfg(DEFAULT_RPO_SECS, DEFAULT_LEASE_SECS).validate().is_ok(),
            "the shipped defaults must be a startable config"
        );
        assert!(
            cfg(DEFAULT_RPO_SECS, 300).validate().is_err(),
            "the pre-R761 lease must NOT quietly pass under the new cadence — if this \
             starts passing, the budget rule moved and the default needs rethinking"
        );
        // 90s lease / 3 = 30s budget = exactly two 15s ticks — the boundary is
        // inclusive, so this is the shortest lease that passes.
        assert!(cfg(30, 90).validate().is_ok());
        assert!(cfg(30, 89).validate().is_err());
    }

    /// The traversal cases. `..` must never reach a `data_root.join()`.
    #[test]
    fn traversal_and_separator_ids_are_rejected_not_mangled() {
        for bad in ["..", ".", "", "a/b", "../etc/passwd", "a\0b", "-rf", "a b", "tenant/"] {
            assert!(
                tenant_path_segment(&TenantId(bad.into())).is_err(),
                "{bad:?} should have been rejected"
            );
        }
        for ok in ["t1", "acme-corp", "a.b_c", "T_9"] {
            assert_eq!(tenant_path_segment(&TenantId(ok.into())).unwrap(), ok);
        }
    }

    /// Both conventions in one place, so a change to either is visible here.
    #[test]
    fn the_path_and_key_conventions_are_what_the_design_says() {
        let mut c = cfg(30, 300);
        let t = TenantConfig {
            tenant: TenantId("acme".into()),
            base_snapshot_key: "base.db".into(),
            page_size: 4096,
            db_path: None,
        };
        assert_eq!(
            c.db_path(&t).unwrap(),
            PathBuf::from("/var/lib/yah/tenants/acme/db")
        );
        assert_eq!(c.key_prefix(&t.tenant).unwrap(), "tenants/acme");

        c.sink.prefix = "/yubaba/".into();
        assert_eq!(
            c.key_prefix(&t.tenant).unwrap(),
            "yubaba/tenants/acme",
            "the sink prefix is joined without doubling or dropping separators"
        );

        // An explicit path wins — the sanctioned manual/operator path.
        let explicit = TenantConfig { db_path: Some("/srv/one.db".into()), ..t };
        assert_eq!(c.db_path(&explicit).unwrap(), PathBuf::from("/srv/one.db"));
    }

    /// The shipped example must parse, and must parse into what it claims to
    /// document. An example config that has drifted from its struct is worse
    /// than none — it is a confident wrong answer at the moment someone is
    /// trying to bring a node up.
    #[test]
    fn the_example_config_parses_and_says_what_it_documents() {
        let text = include_str!("../tenant-streamer.example.toml");
        let cfg: StreamerConfig = toml::from_str(text).expect("the example config must parse");
        cfg.validate().expect("the example config must validate");

        assert_eq!(cfg.rpo_secs, DEFAULT_RPO_SECS);
        assert_eq!(cfg.lease_secs, DEFAULT_LEASE_SECS);
        assert_eq!(cfg.tail_interval(), Duration::from_secs(60));
        assert_eq!(cfg.tenants.len(), 2);

        // The convention tenant, and the explicit-override tenant. Both shapes
        // are documented in the file, so both are exercised here.
        let acme = &cfg.tenants[0];
        assert_eq!(acme.tenant, TenantId("acme".into()));
        assert_eq!(cfg.db_path(acme).unwrap(), PathBuf::from("/var/lib/yah/tenants/acme/db"));
        assert_eq!(cfg.key_prefix(&acme.tenant).unwrap(), "tenants/acme");

        let globex = &cfg.tenants[1];
        assert_eq!(cfg.db_path(globex).unwrap(), PathBuf::from("/mnt/nvme1/globex.db"));
    }

    /// `deny_unknown_fields` is what turns a typo in a hand-edited config into
    /// a startup error instead of a silently-ignored setting. Losing it would
    /// mean `rpo_sec = 5` parses fine and streams at the 120s default.
    #[test]
    fn an_unknown_config_key_is_an_error_not_a_silent_default() {
        let text = r#"
            node_id = 1
            yubaba_url = "http://127.0.0.1:7777"
            data_root = "/var/lib/yah"
            rpo_sec = 5
            [sink]
            bucket = "b"
            endpoint = "https://e"
            region = "auto"
        "#;
        let err = toml::from_str::<StreamerConfig>(text).unwrap_err();
        assert!(format!("{err}").contains("rpo_sec"), "{err}");
    }

    /// Two tenants must never share a prefix or a path. This is the property
    /// the reject-don't-sanitise rule exists to protect.
    #[test]
    fn distinct_tenants_never_collide_on_a_prefix() {
        let c = cfg(30, 300);
        let a = c.key_prefix(&TenantId("acme".into())).unwrap();
        let b = c.key_prefix(&TenantId("acme-2".into())).unwrap();
        assert_ne!(a, b);
    }
}

//! Per-domain TLS material in an object store instead of raft (R779 / W267).
//!
//! [`crate::acme_issuer`] seals the fleet's wildcard cert under the node KEK and
//! `PutSecret`s it into raft. That is correct for *one* cert: `raft/store.rs:5`
//! sizes the state machine as "tiny (KB-scale) so we can afford to rewrite the
//! full file on every mutation", and `persist()` does exactly that —
//! `serde_json::to_string` of the whole state, on every mutation, on every node.
//! W267's free-tier ingress wants a cert *per domain* at 10k domains, which is
//! ~40 MB of full-state rewrite per `PutSecret` and breaks that assumption
//! outright. R779's DECISION 1: **raft holds nothing per domain**; per-domain
//! cert material lives in an object store (R2), reached through
//! [`yah_object_store::ObjectStore`].
//!
//! ## What does *not* change, deliberately
//!
//! Only the backing store moves. Everything W273 established stays:
//!
//! - The stored value is the same [`SecretRecord`] — AES-256-GCM ciphertext,
//!   12-byte nonce, `updated_at`, the R706 [`SecretAccess`] rule and the R720-F1
//!   keyed digest — serialised as JSON. The object store, like a raft snapshot
//!   on disk, holds **ciphertext only**.
//! - Sealing stays [`crate::secrets::seal_cluster_secret`] under the node-local
//!   cluster KEK, and opening stays [`crate::secrets::ClusterResolver`], which
//!   still checks the record's access rule *before* touching the KEK. This
//!   module implements [`ClusterSecretStore`], the one-method read trait the
//!   resolver is already generic over, so the resolver does not know or care
//!   which store a record came from.
//! - The KEK never leaves the node, and in particular **never reaches passway**.
//!   That is load-bearing, not incidental: passway is the most exposed process
//!   in the fleet, and R777's tenant-isolation verdict (`passway/src/tls.rs`,
//!   "One listener serves one cert") turns on one compromised passway costing
//!   one tenant's key. A passway that fetched its own cert from R2 would need
//!   the cluster KEK, and one RCE would then decrypt *every* tenant's key. So
//!   the fetch stays on this side of the mount boundary: the node resolves and
//!   materialises two files, passway reads two files, exactly as today.
//!
//! ## Layout
//!
//! ```text
//! certs/<issuer>/<domain>/cert.sealed   SecretRecord JSON — the chain PEM
//! certs/<issuer>/<domain>/key.sealed    SecretRecord JSON — the private key PEM
//! certs/<issuer>/<domain>/issuing       IssuanceClaim JSON — the CAS lock, transient
//! enrolled/<domain>                     Enrollment JSON — the tenant registry
//! ```
//!
//! `<issuer>` is the ACME directory's host ([`issuer_key`]), mirroring
//! certmagic's `certificates/<issuer-key>/<domain>/` layout. It is in the path
//! so one domain can hold a Let's Encrypt cert and a second-CA cert side by side
//! — R779's DECISION 3 keeps ZeroSSL/GTS as overflow if LE refuses a rate-limit
//! adjustment, and a flat layout would make that a migration instead of a write.
//!
//! ## The two things this store does that raft did not
//!
//! - [`ObjectCertStore::enrolled`] enumerates the *routable* set with one
//!   `list_prefix`. That is the source of truth for the SNI demux's route table,
//!   which R779's DECISION 2 makes *structural*: an SNI absent from
//!   `PASSWAY_DEMUX_ROUTES` never reaches a passway, so it can never provoke an
//!   ACME order. Caddy spells this an "ask" endpoint; here it is a list.
//!   [`ObjectCertStore::domains`] is the neighbouring but *different* question —
//!   which domains hold a cert — and is what a renewal sweep works from.
//! - [`ObjectCertStore::claim_issuance`] is a TTL lock over
//!   [`yah_object_store::Precondition`] compare-and-swap — certmagic's `Locker`,
//!   and the reason the per-domain path does not need a raft `AcquireLock` per
//!   domain (which would put the pressure straight back where DECISION 1 took it
//!   from). Two nodes racing the same domain: one wins the `IfAbsent` put, the
//!   other backs off; a dead holder's claim expires and is stolen under
//!   `IfMatch`.
//!
//! @yah:ticket(R870-F1, "The :80 tier is single-tenant: build the HTTP Host-router that renders off Enrollment::http_backend")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:at(2026-09-06T07:26:06Z)
//! @yah:phase(P1)
//! @yah:parent(R870)
//! @yah:next("THE GAP, verified in source not inherited from the doc. cert_store.rs render_demux_routes renders ONLY tls_backend, and its own doc comment states the intended shape: \"When an HTTP tier lands it gets its own render off Enrollment::http_backend rather than a second column here — the demux parser takes host=addr, and widening that format would break every existing PASSWAY_DEMUX_ROUTES string.\" Enrollment::http_backend exists (cert_store.rs:357), is settable via with_http_backend, is carried through domain_admin.rs:487-494 and surfaced in yubaba main.rs:1429 JSON — and NOTHING routes on it. Grep is conclusive: every http_backend hit is a carrier, none is a consumer.")
//! @yah:next("THE CONSEQUENCE, which is why this is P1 and not cleanup: passway owns 0.0.0.0:80 DIRECTLY on each origin for the 308 redirect (PASSWAY_HTTP_REDIRECT_BIND, added on south by R853-T2), and the SNI demux only speaks TLS. So :80 has no fan-in tier at all. Tenant #2 — noisetable.com is the live case — gets no scheme-less redirect: every `curl noisetable.com/install.sh` and every scheme-less URL it documents is refused, while the identical yah.dev command works. https:// is unaffected.")
//! @yah:next("DO NOT ADD A TLS LIBRARY OR A BUCKET CLIENT TO THE :443 DEMUX WHILE DOING THIS. The R777 invariant is that the demux holds no key and sees no plaintext; W267 §\"custom domains validate by DNS-01\" also records that keeping a SECOND protocol off the edge was the reason DNS-01 CNAME delegation was chosen over HTTP-01. An :80 router is a separate process with its own route render — it parses HTTP, so it must not share the :443 binary.")
//! @arch:see(.yah/docs/working/W267-sovereign-public-ingress.md)
//! @yah:handoff("BUILT AND GREEN: passway-http-router, a new crate in the passway workspace (oss/passway/crates/http-router, lib http_router, bin passway-http-router), plus the yubaba render + publish rail that feeds it. A SEPARATE PROCESS from the :443 demux, per the ticket's own constraint — it parses HTTP, the demux must not. No TLS library, no HTTP library, no credential: tokio + log only. head.rs reads request-line + Host bounded at 8 KiB; route.rs is HostTable over Disposition::{Redirect, Proxy(addr)} with the demux's exact match precedence (exact / one-label wildcard / typed catch-all, fail-closed); redirect.rs builds the 308 with strict Host validation; router.rs is accept -> read -> route -> answer-or-splice; routes_file.rs is the same never-make-the-table-worse reload policy.")
//! @yah:handoff("THE DESIGN DECISION THAT MAKES A SECOND APEX FREE: a domain with NO http_backend renders as `<domain>=redirect`, not as an omission (cert_store::http_route_entries). Omitting it would have left every tenant but the first refused on :80 — the exact gap this ticket exists to close. So enrolling noisetable.com now makes `curl noisetable.com/install.sh` work with zero per-tenant :80 config; an http_backend is the EXCEPTION, for a tenant validating by http-01 rather than W267's DNS-01 CNAME delegation, and its requests are spliced to that address instead.")
//! @yah:handoff("YUBABA SIDE — ONE LISTING, TWO RENDERS. cert_store gains http_route_entries / render_http_routes / HTTP_REDIRECT_TOKEN beside the tls pair, and render_demux_routes' stale 'when an HTTP tier lands' doc comment now points at them. demux_routes gains YUBABA_HTTP_ROUTES_FILE (HTTP_ROUTES_FILE_ENV) and publish_sweep(store, cfg) -> Sweep{tls, http}, which lists the enrollment set ONCE and renders both files; publish_once keeps its old signature (all 12 existing call sites untouched) and publish_http_once is its :80 twin. The fail-stale rules bind both files identically: an empty enrollment set writes neither. Pins stay :443-only and are tested not to leak onto :80 — they exist for fleet TLS hostnames that nothing dials over plaintext.")
//! @yah:handoff("DISCOVERED WORK, DONE IN PASS — the router would otherwise have been undeployable. (1) Release + roll rail: added passway-http-router to scripts/publish-yubaba-release.sh (cross-build, staging copy, tarball layout gate), scripts/roll-node.sh (snapshot, expected-sha, before/after content gates) and oss/yah-base/crates/workload-spec/src/control_plane_install.sh (anchor, conditional install, content assert). Gated on ITS OWN tarball member, not on HAS_PASSWAY: it joins at 0.8.34, one release after the passway pair R870-B2 added, so rolling a 0.8.33 tarball must still succeed. (2) Deployment contract: app/yah/cli/resources/passway-http-router.{service,env}, beside passway-mesh.* and for the same reason — nothing generates them, so the file IS the contract.")
//! @yah:verify("cargo test --manifest-path oss/passway/Cargo.toml (whole workspace, so the :443 demux is proven unbroken) = 291 passed / 0 failed across all targets; of those the new crate is 25 unit + 9 integration. The integration suite (crates/http-router/tests/fanin.rs) asserts the byte-exact head replay to the right backend, a body arriving in the same segment being replayed too, a fragmented head reassembled, 308 with Location for the exact and wildcard cases, 404-never-a-redirect for an unrouted Host, silent close on a TLS ClientHello aimed at :80, cut-off at the read deadline, and close on a dead backend. cargo clippy -p passway-http-router --all-targets: zero warnings. cargo fmt --check on the crate: clean.")
//! @yah:verify("cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib = 766 passed / 0 failed (was 745 at this tree; +21 covering the :80 render and the two-tier sweep). cargo test --manifest-path oss/yah-base/crates/workload-spec/Cargo.toml --lib control_plane_install = 11 passed, including the new gate that the :80 tier rides its own conditional. cargo test -p yah --test main camp_systemd_unit_emit = 9 passed, including the new template test. rustfmt --check on the four Rust files edited outside the new crate: every hunk in code I authored hand-applied; the remainder is PRE-EXISTING drift in cert_store.rs (26 sites), demux_routes.rs (2) and control_plane_install.rs (4), left alone rather than reformatting files this ticket does not own. bash -n on both scripts.")
//! @yah:gotcha("THE CUT-OVER IS NOT FREE AND NOTHING LIVE WAS TOUCHED. Both origins hold :80 from INSIDE a passway today — /etc/passway.env (south) and /etc/passway-test.env (east) set PASSWAY_HTTP_REDIRECT_BIND=0.0.0.0:80, added by R853-T2. Two processes cannot bind one port, so this router CANNOT START until that line is gone and that passway has restarted, and a passway restart drops in-flight :443 connections (passway cannot hot-swap — tls.rs 'The reload gap'). Order per door: remove the line -> restart that passway (take the blip, OR wait for R870-T3's PASSWAY_UPGRADE handoff, which is exactly what makes that restart free) -> systemctl enable --now passway-http-router -> prove `curl -sI http://<host>/install.sh` is 308 for every enrolled name. The full sequence is written into app/yah/cli/resources/passway-http-router.env.")
//! @yah:gotcha("TWO THINGS I CHOSE THAT A REVIEWER SHOULD AGREE WITH RATHER THAN DISCOVER. (1) A CONNECTION IS ROUTED BY ITS FIRST REQUEST and never re-examined — HTTP/1.1 lets a client reuse a socket for a different Host, so a pipelined follow-up can reach the first request's backend. Every response this process writes itself carries `Connection: close`, so the redirect leg (every enrolled domain by default) never invites a second request; the proxy leg's backend is an http-01 responder that 404s everything but one challenge path, so a misdirected follow-up gets a wrong answer, not another tenant's data. Re-parsing every request means buffering and re-emitting bodies on the shared plaintext tier — a much larger surface than the one it closes. Same trade haproxy makes in mode tcp. Documented at router.rs 'One connection, one host'. (2) redirect.rs DUPLICATES passway::redirect's Host validation rather than sharing it, because passway links pingora/rustls/an ACME client and this tier links tokio; sharing would either drag pingora onto :80 or put a third crate between passway and crates.io. Both sides carry the same tests and a cross-reference note.")
//! @yah:next("READY FOR TENANT #2, and this is now the whole remaining list for a second apex. Nothing is code. (1) Point the new apex's A records at BOTH 45.32.194.254 and 51.81.85.145 — as of 2026-09-08 `dig +short noisetable.com A` is still empty and every downstream step is blocked on it. (2) One passway per origin on a free loopback port with its own cert and its own DNS-01 zone credential (the R777 one-listener-one-cert tenant boundary), plus its own PASSWAY_UPGRADE_SOCK — both nodes already run three passway processes and an unpinned sock would hand a reload's listeners to the wrong one. (3) One line in /etc/passway-demux.routes (`<apex>=127.0.0.1:<port>`) and one in /etc/passway-http-router.routes (`<apex>=redirect`), on BOTH nodes. Both files hot-reload at 10s, so neither tier takes a restart or a :443/:80 gap. Test the TLS half before DNS with `curl --resolve <apex>:443:<ip>` — today that returns tlsv1 unrecognized_name on both origins, which is the demux correctly refusing an unenrolled SNI.")
//! @yah:verify("LIVE ON BOTH PUBLIC DOORS 2026-09-08 by @Ashguard:dragon — the :80 tier is no longer single-tenant. Cut-over ran exactly as passway-http-router.env's header prescribes, per door: remove PASSWAY_HTTP_REDIRECT_BIND from the door's env file (backed up to /etc/passway-test.env.rollback-20260908-r870 on east, /etc/passway.env.rollback-20260908-r870 on south), restart that passway to release :80, then `systemctl enable --now passway-http-router`. Both routers report \"listening on 0.0.0.0:80, 3 routes\" and reload /etc/passway-http-router.routes every 10s. Route table mirrors the demux's host set (yah.dev=redirect, *.yah.dev=redirect, cloud.mesh.yah.dev=redirect — the three-label mesh name needs its own line for the same one-label-wildcard reason the demux table documents). Verified against BOTH origin IPs: http://yah.dev/install.sh -> 308 https://yah.dev/install.sh (path preserved), http://cloud.mesh.yah.dev/ -> 308, and Host: nope.example -> 404 rather than a redirect, so the table is the allowlist as designed. DynamicUser start needed no intervention; /etc/passway-http-router.routes installed 0644 as the unit requires.")
//! @yah:verify("STEP 1 OF THE SECOND-APEX LIST IS DONE — noisetable.com apex now resolves to the fleet, 2026-09-08, operator-authorised. Two GREY (proxied=false, ttl=auto) A records created in Cloudflare zone 21fadafc03c976486e0d7b5941dd89be -> 45.32.194.254 and 51.81.85.145. Grey is load-bearing, not a default: the door terminates its own TLS and validates by DNS-01, so an orange-cloud record would put Cloudflare in front of the sovereign front door and break both. CREDENTIAL GOTCHA worth knowing before the next zone: the `cloudflare-api-token` slot is ACCOUNT-scoped and sees ONLY yah.dev — `zones?name=noisetable.com` returns success with an EMPTY result, which reads like a missing zone rather than a missing grant. `cloudflare-legacy-yah` (the user-owned bootstrap root) sees all four zones and is what this used. Nothing else in the zone was touched; the live MX/SPF/DKIM mail set and the proxied cdn.noisetable.com -> public.r2.dev CNAME are intact. BOTH TIERS CORRECTLY FAIL CLOSED for the not-yet-enrolled name, which is the proof the allowlists work: https://noisetable.com -> tlsv1 unrecognized_name from the demux, http://noisetable.com -> 404 from the http-router. Steps 2 and 3 (per-origin passway + the two route lines) are unchanged and are now the only remaining work.")
//! @yah:verify("us-west-001 PROMOTED TO APEX ORIGIN 3, live and in DNS 2026-09-08, operator-authorised. It was previously a mesh-name-only door: passway-demux on :443 with a ONE-LINE route table (cloud.mesh.yah.dev), passway-mesh on 127.0.0.1:8444, nothing on :80, no apex passway and no yah.dev cert — so adding its IP to the apex before this would have black-holed a third of requests on an unenrolled SNI. What was added: /etc/passway.env + passway.service (origin 3, loopback 8443, per-instance /run/passway-apex-upgrade.sock because this box runs two passways), the R870-T3 drop-in, two demux route lines, and the http-router tier. Binaries needed no roll — west already carried passway-http-router and passway-graceful-upgrade from a fuller Sep 8 roll than east or south got. Demux picked up the new routes by HOT RELOAD (journal: \"reloaded, 3 routes\"), no restart, no :443 gap. VERIFIED PER-ORIGIN with --resolve before the A record was written, then again after: all three of 15.204.89.240 / 45.32.194.254 / 51.81.85.145 now return apex 200/43488, www 200, /releases 200/41629, mesh key 200, unenrolled Host on :80 -> 404. Both apexes (yah.dev and noisetable.com) now carry all three grey A records.")
//! @yah:gotcha("THE THIRD ORIGIN'S CERT NAME COULD NOT BE THE OBVIOUS ONE, twice over. (1) A bare {*.yah.dev, yah.dev} on west would have been byte-identical to us-east-001's identifier set, and LE keys its 5-per-week duplicate-certificate limit on the EXACT set — that is the collision R777/W273 split the SAN sets to avoid, so west needed a disambiguating name like south's. (2) The obvious name west.origin.yah.dev WAS ALREADY TAKEN BY THIS SAME BOX: passway-mesh.service's /etc/passway-mesh.env carries PASSWAY_ACME_DOMAIN=cloud.mesh.yah.dev,west.origin.yah.dev, added by R858-T1. So the apex door took apex.west.origin.yah.dev instead. Check /etc/passway-mesh.env before picking a disambiguator on any node that already runs a mesh door. Issued first try in 78s with PASSWAY_ACME_DNS01_PROPAGATION_SECS=75 (the default 10 would have NXDOMAINed on a never-before-used name — the R853-T2 gotcha, confirmed again). Three distinct SAN sets are now live with full wildcard parity: east {*.yah.dev, yah.dev} notAfter Dec 3, south {*.yah.dev, south.origin.yah.dev, yah.dev} Dec 4, west {*.yah.dev, apex.west.origin.yah.dev, yah.dev} Dec 7. ALSO CHECKED, and it is why the wildcard is safe here: issues.yah.dev and passway-test.yah.dev are A-pinned to east ALONE, so they never arrive at west and west needs none of east's static upstream pins — only www.yah.dev (a CNAME to the apex) actually rides the wildcard on three origins.")
//! @yah:verify("TENANT 2 IS ENROLLED AND LIVE ON ALL THREE ORIGINS, 2026-09-08 — steps 2 and 3 of this ticket's second-apex list are done. Per origin: passway-noisetable.service on loopback 8445 (8443 apex, 8444 mesh were taken), own cert dir /var/lib/passway-noisetable, own ACME account, own per-instance /run/passway-noisetable-upgrade.sock, and the R870-T3 drop-in. Three DISTINCT SAN sets, wildcard from day one so a new service on this domain is a DNS record and a route line rather than a cert order: {*.noisetable.com, noisetable.com, <east|south|west>.origin.noisetable.com}. Both route tiers took the two new lines by HOT RELOAD on all three nodes — \"reloaded, 5 routes\" on demux and http-router alike, no restart, no :443 or :80 gap, which is the whole design claim of R853-T2 and R870-F1 demonstrated on a real second tenant. VERIFIED per-origin and through real DNS: https://noisetable.com and https://app.noisetable.com return 503 with ssl_verify_result=0 (browser-trusted, no backend yet), http://noisetable.com/install.sh -> 308 https path-preserved, an unenrolled Host still 404s, and yah.dev is untouched at 200/43488 on all three with cloud.mesh.yah.dev 200. The bare 503 is filed as R870-F5.")
//! @yah:gotcha("THE APEX DOORS' ACME CREDENTIAL IS ACCOUNT-SCOPED, WHICH MAKES THE TENANT BOUNDARY FICTIONAL IF YOU REUSE IT. Measured 2026-09-08: /var/lib/passway/cf-token on us-east-001 lists FOUR zones (noisetable.com, scrabcake.com, scrabcake.net, yah.dev), so the token every yah.dev door holds for its DNS-01 challenge can edit DNS for every domain in the account. Tenant 2 was therefore given a purpose-minted token instead — CF token id 79bebdb4c1d2b994963357d209e4201f, DNS:Read + DNS:Write on zone 21fadafc03c976486e0d7b5941dd89be ONLY, verified to list exactly one zone, stored in keys slot `passway-acme-noisetable-dns`. Do the same for tenant 3, and treat re-scoping the apex doors' own token as outstanding: `yah cloud cf token create` does NOT mint this shape — it builds MESOFACT_STATIC_GRANTS (Workers Scripts:Write, R2:Write, Cache Purge), which is far more than a door needs and should not sit on three public boxes.")

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use acme_engine::AcmeDirectory;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use yah_object_store::{Error as ObjectError, ObjectStore, Precondition};

use crate::raft::SecretRecord;
use crate::secrets::ClusterSecretStore;

/// Top-level key prefix for every object this module writes.
pub const CERT_PREFIX: &str = "certs";

/// Object suffix holding the sealed certificate chain.
pub const CERT_OBJECT: &str = "cert.sealed";

/// Object suffix holding the sealed private key.
pub const KEY_OBJECT: &str = "key.sealed";

/// Object suffix holding a live issuance claim ([`IssuanceClaim`]).
pub const CLAIM_OBJECT: &str = "issuing";

/// How long an issuance claim stays valid before another node may steal it.
///
/// Long enough to cover a full ACME order including DNS-01 propagation (the
/// issuer's own `dns01_propagation_delay` plus validation), short enough that a
/// node that dies mid-order does not park the domain for an hour.
pub const CLAIM_TTL: Duration = Duration::from_secs(10 * 60);

/// Failures reaching the object-backed cert store.
///
/// Deliberately does **not** wrap [`crate::secrets::SecretError`]: nothing here
/// decrypts, so there is no failure mode that could name key material.
#[derive(Debug, Error)]
pub enum CertStoreError {
    /// The backing object store failed (network, auth, protocol).
    #[error("cert store backend: {0}")]
    Backend(#[from] ObjectError),

    /// An object exists at the key but is not a record this module wrote.
    /// Treated as a hard error rather than a miss — a corrupt cert object must
    /// not silently become "no cert yet, order another one".
    #[error("cert store: malformed record at {key}: {source}")]
    Malformed {
        key: String,
        #[source]
        source: serde_json::Error,
    },

    /// Another node holds a live issuance claim on this domain.
    #[error("cert store: {domain} is already being issued by {holder} ({remaining_secs}s left)")]
    Claimed {
        domain: String,
        holder: String,
        remaining_secs: u64,
    },

    /// A write was attempted under a logical name that is not per-domain TLS
    /// material. Refused rather than given an invented key — see [`object_key`].
    #[error("cert store: {name} is not per-domain TLS material (expected tls/<domain>/cert or tls/<domain>/key)")]
    NotCertMaterial { name: String },

    /// A domain name that cannot be a single key segment — empty, containing
    /// `/`, or containing `..`. Refused at the API rather than sanitised, so a
    /// caller never believes it enrolled a domain that landed under some other
    /// prefix.
    #[error("cert store: {domain:?} is not a usable domain (empty, or contains '/' or '..')")]
    InvalidDomain { domain: String },

    /// [`ObjectCertStore::enroll`] found a *different* enrollment already in
    /// place. Two tenants claiming one hostname is a configuration bug that
    /// must not resolve silently to last-writer-wins — the same rule
    /// `RouteTable::parse` applies to a duplicate host in
    /// `PASSWAY_DEMUX_ROUTES`.
    #[error("cert store: {domain} is already enrolled to {existing} (unenroll it first)")]
    AlreadyEnrolled { domain: String, existing: String },

    /// A holding-page name that could not survive the trip to a door — see
    /// [`is_safe_holding_name`]. Refused at the API, because the name is
    /// rendered into a map file every door parses and becomes a filename on
    /// every door's disk.
    #[error(
        "cert store: {name:?} is not a usable holding-page name (lowercase a-z, 0-9, '-' and '_', \
         starting with a letter or digit, at most {MAX_HOLDING_NAME} characters)"
    )]
    InvalidHoldingName { name: String },

    /// [`ObjectCertStore::set_holding`] on a domain that is not in the
    /// enrollment set. Refused rather than creating a record: an enrollment is
    /// what makes a domain routable, and inventing one from a request to change
    /// its holding page would route a hostname nobody enrolled.
    #[error("cert store: {domain} is not enrolled")]
    NotEnrolled { domain: String },

    /// A holding page past [`MAX_HOLDING_PAGE_BYTES`]. Refused at the upload
    /// rather than at the door, where it would be a silent non-appearance.
    #[error(
        "cert store: holding page {name:?} is {bytes} bytes, over the {MAX_HOLDING_PAGE_BYTES}-byte \
         ceiling every door enforces"
    )]
    HoldingPageTooLarge { name: String, bytes: usize },
}

/// Whether `domain` can be used as one object-key segment.
///
/// Rejects the shapes that would address an object outside the domain's own
/// prefix, or collapse two domains into one key.
fn is_safe_domain(domain: &str) -> bool {
    !domain.is_empty() && !domain.contains('/') && !domain.contains("..")
}

/// Derive the path segment for an ACME directory URL — its host, lowercased.
///
/// `https://acme-v02.api.letsencrypt.org/directory` → `acme-v02.api.letsencrypt.org`.
/// Any character outside `[a-z0-9.-]` is replaced with `-` so the result is
/// always a single safe path segment; a URL with no recognisable host falls back
/// to the sanitised whole string rather than an empty segment (which would
/// collapse two issuers' key spaces into one).
pub fn issuer_key(directory_url: &str) -> String {
    let after_scheme = directory_url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(directory_url);
    let host = after_scheme
        .split(['/', '?', '#'])
        .next()
        .filter(|h| !h.is_empty())
        .unwrap_or(directory_url);
    let sanitised: String = host
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if sanitised.is_empty() {
        "unknown-issuer".to_string()
    } else {
        sanitised
    }
}

/// `certs/<issuer>/` — the prefix every object for one issuer sits under.
pub fn issuer_prefix(issuer: &str) -> String {
    format!("{CERT_PREFIX}/{issuer}/")
}

/// Map a logical cluster-secret name onto its object key, or `None` if the name
/// is not per-domain TLS material.
///
/// Recognises exactly the two names [`crate::acme_issuer::cert_secret_name`] and
/// [`crate::acme_issuer::key_secret_name`] produce — `tls/<domain>/cert` and
/// `tls/<domain>/key`. **Everything else returns `None` on purpose**: this store
/// is for certs, and a general cluster secret (a registry credential, a mesh
/// pre-shared key) must never be looked for in an object store just because raft
/// happened to miss. That would turn a fail-closed `ClusterNotFound` into a
/// network round-trip whose answer an operator with bucket access controls.
///
/// A domain containing `/` is rejected for the same reason a path traversal is:
/// it would let a crafted secret name address an object outside its own domain's
/// prefix.
pub fn object_key(issuer: &str, name: &str) -> Option<String> {
    let rest = name.strip_prefix("tls/")?;
    let (domain, leaf) = rest.rsplit_once('/')?;
    let object = match leaf {
        "cert" => CERT_OBJECT,
        "key" => KEY_OBJECT,
        _ => return None,
    };
    if !is_safe_domain(domain) {
        return None;
    }
    Some(format!("{}{domain}/{object}", issuer_prefix(issuer)))
}

/// Where the object-backed cert store lives.
///
/// Parsed from the daemon environment by [`CertStoreConfig::parse`] and turned
/// into a live store by [`CertStoreConfig::connect`]. Kept separate from the
/// store itself so config parsing stays a pure function over a `key -> value`
/// lookup — the same shape [`crate::acme_issuer::parse_issuer_config`] uses, and
/// for the same reason: it is unit-testable without a network or `std::env`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertStoreConfig {
    /// Cloudflare account id — the subdomain in `<id>.r2.cloudflarestorage.com`.
    pub account_id: String,
    /// Bucket holding the `certs/` prefix.
    pub bucket: String,
    /// S3-compatible endpoint override (the pond tier's MinIO, or a test
    /// server). `None` uses the derived R2 endpoint.
    pub endpoint: Option<String>,
}

/// Env key naming the bucket. Its presence is what turns the cert store on.
pub const BUCKET_ENV: &str = "YUBABA_CERT_STORE_BUCKET";
/// Env key naming the Cloudflare account id.
pub const ACCOUNT_ID_ENV: &str = "YUBABA_CERT_STORE_ACCOUNT_ID";
/// Env key overriding the S3 endpoint.
pub const ENDPOINT_ENV: &str = "YUBABA_CERT_STORE_ENDPOINT";

/// Env key naming the ACME directory, shared by every reader and writer of this
/// store.
///
/// It lives here, with exactly one owner, because the directory URL is what
/// [`issuer_key`] turns into the store's issuer path segment: a consumer that
/// resolved a *different* default from the writer would address an empty prefix
/// and report a fleet of enrolled domains as having no certificates.
pub const DIRECTORY_ENV: &str = "YUBABA_ACME_DIRECTORY";

/// The default when [`DIRECTORY_ENV`] is unset — **staging**. Deliberately the
/// same for the daemon, both issuers and the admin commands; see
/// [`DIRECTORY_ENV`].
pub const DEFAULT_DIRECTORY: &str = "staging";

/// Resolve the ACME directory from a `key -> value` lookup — pure, so it is
/// unit-testable without `std::env`.
///
/// Every caller that needs an issuer segment goes through this rather than
/// reading [`DIRECTORY_ENV`] itself, so the default cannot drift between the
/// node that writes a cert and the node that reads it.
pub fn acme_directory(get: impl Fn(&str) -> Option<String>) -> AcmeDirectory {
    AcmeDirectory::parse(&get(DIRECTORY_ENV).unwrap_or_else(|| DEFAULT_DIRECTORY.to_string()))
}

impl CertStoreConfig {
    /// `Ok(None)` when [`BUCKET_ENV`] is unset — the cert store is opt-in, and a
    /// node without it behaves exactly as it did before R779.
    ///
    /// A bucket *with* no account id is a hard error rather than a silent
    /// skip: half-configured means an operator meant to turn this on, and a
    /// cert store that quietly does not exist is discovered as a missing cert
    /// weeks later.
    pub fn parse(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        let bucket = match get(BUCKET_ENV) {
            Some(b) if !b.trim().is_empty() => b.trim().to_string(),
            _ => return Ok(None),
        };
        let account_id = get(ACCOUNT_ID_ENV)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or(format!("{ACCOUNT_ID_ENV} is required when {BUCKET_ENV} is set"))?;
        let endpoint = get(ENDPOINT_ENV)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Ok(Some(Self {
            account_id,
            bucket,
            endpoint,
        }))
    }

    /// Build a live [`ObjectCertStore`] against `directory_url`'s issuer segment.
    ///
    /// Credentials come from [`yah_object_store::R2ObjectStore::from_vault`] —
    /// the `cloudflare-r2-*` vault slots with a `CF_R2_*` env fallback — so this
    /// adds no new credential surface beyond the one every other R2 consumer in
    /// the tree already uses.
    pub fn connect(&self, directory_url: &str) -> Result<ObjectCertStore, CertStoreError> {
        Ok(ObjectCertStore::new(self.connect_objects()?, directory_url))
    }

    /// The bare bucket, for a consumer that is not cert material.
    ///
    /// R869's off-fleet state copy shares this bucket and these credentials —
    /// see [`ObjectCertStore::objects`] for why — but has no issuer segment and
    /// no directory URL to derive one from, so it takes the store directly
    /// rather than being handed a cert store it would only unwrap.
    pub fn connect_objects(&self) -> Result<Arc<dyn ObjectStore>, CertStoreError> {
        let mut store =
            yah_object_store::R2ObjectStore::from_vault(&self.account_id, &self.bucket)?;
        if let Some(endpoint) = &self.endpoint {
            store = store.with_endpoint(endpoint.clone());
        }
        Ok(Arc::new(store))
    }
}

/// A live issuance claim — certmagic's `Locker`, expressed as one object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuanceClaim {
    /// Who holds it. A node id, for the operator reading a stuck claim.
    pub holder: String,
    /// Unix seconds the claim was taken.
    pub acquired_at: u64,
    /// Seconds from `acquired_at` after which another node may steal it.
    pub ttl_secs: u64,
}

impl IssuanceClaim {
    /// Whether `now` is past `acquired_at + ttl_secs`.
    ///
    /// A claim from the *future* (clock skew between nodes) is not expired —
    /// `saturating_sub` would otherwise read a skewed-ahead claim as instantly
    /// stealable, which is the one case where two nodes would both order.
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.acquired_at.saturating_add(self.ttl_secs)
    }

    /// Seconds still to run, `0` once expired.
    pub fn remaining_secs(&self, now: u64) -> u64 {
        self.acquired_at
            .saturating_add(self.ttl_secs)
            .saturating_sub(now)
    }
}

// ── The enrollment set ───────────────────────────────────────────────────────

/// Top-level key prefix for the enrollment set.
///
/// Deliberately **not** under [`CERT_PREFIX`]: enrolment is a fact about a
/// tenant, not about a CA, so it must not be duplicated per issuer. A domain
/// enrolled once stays routable whichever CA ends up holding its cert (DECISION
/// 3's overflow).
pub const ENROLLED_PREFIX: &str = "enrolled/";

/// One enrolled domain — the tenant registry, as one object per domain.
///
/// This is what DECISION 2 means by "the route table *is* the allowlist". A
/// hostname with no enrollment object has no route, so it never reaches a
/// passway and can never provoke an ACME order; registering a domain *is*
/// writing this object.
///
/// @yah:ticket(R870-F8, "Per-domain holding-page override on the enrollment record, so yah.dev-family doors can show the camp art")
/// @yah:status(review)
/// @yah:at(2026-09-09T04:03:33Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R870)
/// @yah:next("THE SPLIT THE OPERATOR ASKED FOR (2026-09-08): the passway default (R870-F7's inline-CSS graphic) is what an unbranded tenant like noisetable.com gets; the `solid-parked` camp illustration is OVERRIDE content for the yah.dev family of sites. So this ticket builds the override rail, and the camp art is its first consumer — not something compiled into passway.")
/// @yah:gotcha("DO NOT INLINE PAGE BYTES INTO Enrollment — it is swept whole, per domain, every 300s. yubaba::demux_routes (oss/yubaba/crates/yubaba/src/demux_routes.rs) sweeps the enrollment set on YUBABA_DEMUX_ROUTES_SWEEP_SECS (default 300) as one list_prefix plus ONE GET PER DOMAIN, purely to render `host=addr` lines. A holding page embedded in the record would be pulled on every domain on every sweep to produce a routes file that does not use it — invisible at one tenant, and exactly the cost that makes the free tier's 10k-custom-domain target unaffordable. Store a reference, or a separate object the serving process fetches only when it is about to render a 503.")
/// @yah:handoff("RAIL BUILT END TO END, and the camp art is in-tree as its first consumer. Enrollment gains `holding: Option<String>` — A NAME, NEVER BYTES (the gotcha's demand): the page is one object at `holding/<name>` shared by every domain naming it, so 10k tenants on one brand cost ONE extra object read per sweep instead of 10k. Chain: `.yah/assets/holding/yah-camp.html` -> `yubaba holding put` -> `holding/yah-camp` -> `yubaba domain holding yah.dev --page yah-camp` -> enrollment record -> yubaba's existing 300s sweep materializes `<YUBABA_HOLDING_DIR>/{hosts,pages/<name>.html}` -> passway reads `PASSWAY_HOLDING_DIR` (re-read every 30s) -> branded 503 body.")
/// @yah:handoff("DELIVERY IS A FILE, NOT A FETCH, and that was the load-bearing shape call. passway does NOT get an object-store client: it is the most exposed process in the fleet, and `sni_demux::routes_file` already refuses one for the same reason (a compromise of the shared public process would yield the whole fleet's routing plus a credential). yubaba already holds the credentials and already sweeps the enrollment set, so it materializes the bodies onto local disk exactly as it does the tenant cert pairs — one-way pipe, tmp-plus-rename, passway reads bytes it did not write. `publish_holding` runs off the SAME single listing as the :443 and :80 tables, so the added cost is one GET per DISTINCT page per sweep.")
/// @yah:handoff("FILES. yubaba: cert_store.rs (`holding` field + `with_holding`, HOLDING_PREFIX, MAX_HOLDING_PAGE_BYTES=256KiB, `is_safe_holding_name`, `holding_entries`, and store verbs `set_holding` / `holding_page` / `write_holding_page` / `delete_holding_page` / `holding_pages`), demux_routes.rs (HOLDING_DIR_ENV=YUBABA_HOLDING_DIR, HOLDING_MAP_FILE=\"hosts\", HOLDING_PAGES_DIR=\"pages\", `publish_holding` + `materialize_page` + `prune_pages`, `Sweep.holding`, `log_holding`), main.rs (`yubaba holding put|list|remove` + `yubaba domain holding <d> --page|--clear`, `holding` in `domain list --json`). passway: holding.rs (HoldingPages/load/page_for, SharedHoldingPages, HoldingWatcher BackgroundService, MAX_OVERRIDE_PAGE_BYTES, DEFAULT_RELOAD_SECS=30), proxy.rs (`with_holding_pages` + `holding_page_for`, both 503 sites), main.rs (PASSWAY_HOLDING_DIR / PASSWAY_HOLDING_RELOAD_SECS), lib.rs + README. Docs: W267 gained '### The holding tier — built'; new `.yah/assets/holding/` (README, build.sh, template, the two recovered webps, generated yah-camp.html at 93,020 bytes).")
/// @yah:handoff("TWO DELIBERATE DIVERGENCES FROM THE ROUTE-TABLE RULES, both documented at the code: (1) AN EMPTY HOLDING MAP IS WRITTEN, where an empty route table is skipped. An empty route table is every tenant going dark; an empty holding map is 'nobody here has an override', which is the steady state on a fresh install and the only way to un-brand a domain without a restart. An empty ENROLLMENT LISTING still skips everything, as it does for every tier. (2) Fail-stale is per-page: a store 404 prunes the page and drops its domains from the map (a real delete), while a fetch FAILURE keeps the copy on disk and keeps its domains mapped (a bucket blip must not un-brand a live door). The map never names a page absent from disk, so passway never has to decide what a dangling reference means — though it tolerates one anyway.")
/// @yah:handoff("DISCOVERED WORK, done in-pass: `ObjectCertStore::enroll`'s idempotence check compared only tls_backend + http_backend, so once `holding` existed an `enroll` differing ONLY in the page would have returned Ok having written nothing — a silent no-op on the exact command an operator would reach for. It now compares `holding` too (cert_store.rs, and `re_enrolling_with_a_different_page_is_refused_rather_than_silently_ignored` pins it); changing the page is the separate `set_holding` verb, which refuses an unenrolled domain rather than inventing a route. Also: `write_table` rendered an empty entry list as a bare newline; it now renders an empty file, which only the holding tier can reach.")
/// @yah:verify("GREEN, run by me on the settled tree. `cargo test -p passway` = 166 lib + 43 bin + 29 integration = 238, 0 failed (baseline 228; +9 lib, +1 integration). `cargo test -p yubaba --lib` = 845, 0 failed, with cert_store 37 and demux_routes 30 (+6 and +8). rustfmt --edition 2021 --check clean on EVERY line I wrote — note cert_store.rs, yubaba/main.rs and passway/main.rs are NOT rustfmt-clean at baseline (30+ pre-existing hunks), so I fixed only my own and left theirs alone rather than reformatting a shared-tree file. `cargo clippy -p passway --all-targets` and `-p yubaba --lib --bins`: zero warnings on any file I touched (passway's 3 and yubaba's are all pre-existing, in auth.rs/path.rs/tenant_passway.rs/cluster_*/pond).")
/// @yah:verify("WHAT THE TESTS ACTUALLY PIN, not just the count. passway integration (`a_branded_authority_gets_its_own_holding_page`) drives a real proxy over the wire: Host: branded.test + Accept: text/html gets the override body, Host: unbranded.test on the SAME door gets HOLDING_PAGE byte-for-byte, and the machine leg on the branded host still gets application/json {\"error\":\"no ready upstreams\"} — so the override cannot regress either the default or the JSON contract. Unit side: two hosts naming one page are asserted `Arc::ptr_eq` (the memory argument the whole indirection exists for), every broken map line costs only its own host (dangling name, traversal, absolute path, dotted name, empty host, nonsense line), an oversized page falls back, and the watcher swaps on a body edit, installs an EMPTIED map, and refuses a VANISHED one. yubaba side: 5 domains on one page materialize ONE file, a missing object keeps its domains out of the map, un-naming prunes, an unchanged sweep writes nothing, an empty enrollment set touches nothing.")
/// @yah:verify("THE CROSS-WORKSPACE JOIN IS PINNED BY CONSTANTS, NOT BY ONE EXECUTING TEST — stated plainly because it is the weakest link. yubaba writes the directory and passway reads it, and they share no crate, so the layout (\"hosts\", \"pages\", \"<name>.html\") and the 256 KiB ceiling are duplicated with a test at each end asserting the literal (`the_layout_matches_what_passway_reads`, `the_ceiling_and_the_layout_match_the_publishers_constants`) — the same device HTTP_REDIRECT_TOKEN already uses for the :80 tier. NOT run: one process publishing and another serving the same directory. That is the fleet enable (see the gotcha), and it is the only step that would catch a mismatch the two constant-tests do not.")
/// @yah:gotcha("NOTHING IS DEPLOYED AND NOTHING CHANGES ON THE FLEET UNTIL TWO ENV VARS ARE SET. No node sets YUBABA_HOLDING_DIR and no door sets PASSWAY_HOLDING_DIR, so today every domain — yah.dev included — still shows passway's own page, and rolling these binaries changes no served byte. Enabling it is: `yubaba holding put yah-camp .yah/assets/holding/yah-camp.html` against the live bucket, `yubaba domain holding <each yah.dev-family domain> --page yah-camp`, YUBABA_HOLDING_DIR in /etc/yubaba.env, PASSWAY_HOLDING_DIR (same path) in each door's passway env, restart both. Filed as its own ticket because it is an outward-facing live-fleet action plus an R2 write.")
/// @yah:gotcha("PRE-EXISTING RED, verified not mine: `cargo test -p yubaba --test main` = 58 passed / 10 failed, EVERY failure a raft_* test (raft_member_registration, raft_membership_loop). Identical to the flake R852-F2's own gotcha already records on this crate (load-sensitive, varies between runs on a box running concurrent agent builds). My change touches no raft code and no integration test in that binary. Also unchanged and still true: R870-F5's gotcha that HEAD (09e3f35d) carries the VETOED raster inside passway's own holding.rs plus the deleted-from-worktree `oss/passway/crates/passway/assets/` — I recovered those two webps into `.yah/assets/holding/` (the override's home) rather than restoring them under oss/passway, so a build from HEAD is still the wrong binary and the operator's commit list on F5 still applies.")
/// @yah:cleanup("The per-tenant passway tier (`yubaba::tenant_passway::declare`) renders `env: BTreeMap::new()` for each forked door and so cannot brand a cold tenant — that tier is not deployed, and the shape when it is: TenantPasswayConfig gains a holding dir and `declare` sets PASSWAY_HOLDING_DIR, since the dir form works unchanged for a one-domain map. Deliberately not built here: wiring an undeployed tier for a feature that is itself not yet enabled is two hypotheticals stacked.")
/// @yah:next("RESOLVED, retiring the filing-time shape call so nobody reads it as open: the reference form won (a NAME in the record, one shared object per page), and the delivery is yubaba materializing onto local disk rather than passway fetching — passway gets no bucket client. The art recovery is done: both webps now live at `.yah/assets/holding/`. Remaining work is the fleet enable, which is R870-T10, not this ticket.")
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Enrollment {
    /// Where the demux splices this domain's TLS bytes — the per-tenant
    /// passway's listener (a loopback or mesh address, or the socket kamaji
    /// holds in custody for a cold tenant).
    ///
    /// A [`SocketAddr`], not a string, because the demux's `RouteTable` parses
    /// its backends to one: a hostname here would be a routes file the demux
    /// refuses at load, discovered as an outage instead of as an enrollment
    /// error.
    pub tls_backend: SocketAddr,
    /// Where this domain's port-80 traffic goes, once an HTTP tier exists — the
    /// same passway's HTTP-01 responder (`PASSWAY_ACME_HTTP01_BIND`), which is a
    /// *different* port from `tls_backend` because one process cannot serve
    /// plaintext and TLS on one port.
    ///
    /// `None` today, and `#[serde(default)]` so records written now load once it
    /// is populated. Carried in the record rather than derived (`tls_backend`
    /// port + 1, say) because a derived port is a silent collision waiting for
    /// the first tenant whose neighbour took it.
    #[serde(default)]
    pub http_backend: Option<SocketAddr>,
    /// Unix seconds the enrollment was written. For an operator reading the
    /// bucket; nothing keys off it.
    pub enrolled_at: u64,
    /// R870-F8: which holding page this domain shows on a fail-ready 503 —
    /// **a name, never bytes**.
    ///
    /// The page itself is one object at `holding/<name>` ([`HOLDING_PREFIX`]),
    /// shared by every domain that names it. That indirection is the whole
    /// design: this record is read once per domain on every route sweep
    /// (`crate::demux_routes`, default 300s), so page bytes carried here would
    /// be pulled 10k times per sweep to render a routes file that does not use
    /// them, while a name costs a handful of bytes and the pages are fetched
    /// once each per sweep regardless of how many domains point at them.
    ///
    /// `None` — the overwhelming majority, and the default — means the tenant
    /// gets passway's own unbranded holding page. An override is for a domain
    /// whose *brand* the operator owns; see `passway::holding`.
    #[serde(default)]
    pub holding: Option<String>,
}

impl Enrollment {
    /// A TLS-only enrollment stamped at `now`.
    pub fn new(tls_backend: SocketAddr, now: SystemTime) -> Self {
        Self {
            tls_backend,
            http_backend: None,
            enrolled_at: unix_secs(now),
            holding: None,
        }
    }

    /// The same, also routing port 80 to `http_backend`.
    pub fn with_http_backend(mut self, http_backend: SocketAddr) -> Self {
        self.http_backend = Some(http_backend);
        self
    }

    /// The same, showing the holding page named `holding` on a 503 (R870-F8).
    pub fn with_holding(mut self, holding: impl Into<String>) -> Self {
        self.holding = Some(holding.into());
        self
    }
}

/// Render `PASSWAY_DEMUX_ROUTES` from an enrollment set.
///
/// `domain=addr` pairs, comma-joined, sorted by domain — deterministic so a
/// publisher can compare two renders byte-for-byte and skip a no-op write, and
/// so an operator diffing two routes files sees only what actually changed.
///
/// Only `tls_backend` is rendered: the demux is the `:443` tier and its table
/// has one backend per host. The `:80` tier gets its own render off
/// [`Enrollment::http_backend`] ([`render_http_routes`], R870-F1) rather than a
/// second column here — the demux's parser takes `host=addr`, and widening that
/// format would break every existing `PASSWAY_DEMUX_ROUTES` string.
pub fn render_demux_routes<'a>(
    enrolled: impl IntoIterator<Item = (&'a str, &'a Enrollment)>,
) -> String {
    route_entries(enrolled).join(",")
}

/// The `host=addr` entries [`render_demux_routes`] joins, sorted and deduped.
///
/// Exposed because the routes *file* the demux reloads is newline-separated —
/// one entry per line is what makes a 10k-domain table diffable — while the
/// `PASSWAY_DEMUX_ROUTES` env var is comma-separated. Same entries, two
/// separators, one place that decides what an entry is.
pub fn route_entries<'a>(
    enrolled: impl IntoIterator<Item = (&'a str, &'a Enrollment)>,
) -> Vec<String> {
    let mut entries: Vec<String> = enrolled
        .into_iter()
        .map(|(domain, e)| format!("{domain}={}", e.tls_backend))
        .collect();
    entries.sort();
    entries.dedup();
    entries
}

/// The token `passway-http-router` reads as "answer the `308` yourself".
///
/// Kept next to the render that emits it, because the two ends of this string
/// are in different Cargo workspaces and nothing else holds them to one
/// spelling — same reason [`render_demux_routes`]'s tests assert the demux's
/// `host=addr` shape here.
pub const HTTP_REDIRECT_TOKEN: &str = "redirect";

/// Render `PASSWAY_HTTP_ROUTER_ROUTES` from an enrollment set (R870-F1).
///
/// The `:80` twin of [`render_demux_routes`], with the same determinism and
/// the same `host=` grammar, over [`Enrollment::http_backend`].
pub fn render_http_routes<'a>(
    enrolled: impl IntoIterator<Item = (&'a str, &'a Enrollment)>,
) -> String {
    http_route_entries(enrolled).join(",")
}

/// The `host=disposition` entries [`render_http_routes`] joins, sorted and
/// deduped. Newline-joined for the routes *file*, comma-joined for the env var.
///
/// **A domain with no `http_backend` renders as
/// `<domain>=`[`HTTP_REDIRECT_TOKEN`], not as an omission.** That is the whole
/// point of the tier: enrolling a second apex makes scheme-less
/// `curl example.com/install.sh` work — the router answers `308 https://…`
/// itself — with no per-tenant `:80` process to run and nothing else to
/// configure. Omitting it instead would leave every tenant but the first with a
/// refused connection on port 80, which is the gap R870-F1 exists to close.
///
/// An `http_backend` is therefore the *exception*: a tenant that needs its own
/// plaintext listener, which today means one validating by `http-01` rather
/// than by W267's DNS-01 CNAME delegation.
pub fn http_route_entries<'a>(
    enrolled: impl IntoIterator<Item = (&'a str, &'a Enrollment)>,
) -> Vec<String> {
    let mut entries: Vec<String> = enrolled
        .into_iter()
        .map(|(domain, e)| match e.http_backend {
            Some(addr) => format!("{domain}={addr}"),
            None => format!("{domain}={HTTP_REDIRECT_TOKEN}"),
        })
        .collect();
    entries.sort();
    entries.dedup();
    entries
}

// ── Holding pages ────────────────────────────────────────────────────────────

/// Top-level key prefix for holding-page bodies (R870-F8).
///
/// One object per *page*, not per domain: `holding/<name>` is the whole HTML
/// document a door serves on a fail-ready 503 for every domain whose
/// [`Enrollment::holding`] names it. Sibling of [`ENROLLED_PREFIX`] and outside
/// [`CERT_PREFIX`] for the same reason enrolment is — a page belongs to a brand,
/// not to a CA and not to one tenant.
pub const HOLDING_PREFIX: &str = "holding/";

/// The longest a holding-page name may be.
///
/// Not a storage limit — a limit on how bad a mistake can look. The name is
/// rendered into a map file and becomes a filename on every door in the fleet,
/// so a runaway string is caught where it is written rather than by the
/// filesystem of whichever node happens to have the shortest `NAME_MAX`.
pub const MAX_HOLDING_NAME: usize = 64;

/// The largest holding page this store will accept, and the largest a door will
/// serve.
///
/// **The number is duplicated in `passway::holding::MAX_OVERRIDE_PAGE_BYTES`**,
/// which is in a different Cargo workspace with no shared crate — same
/// arrangement as [`HTTP_REDIRECT_TOKEN`], and a test at each end pins the
/// value with a comment naming the other. A page over the door's ceiling is
/// silently ignored *there*, so the useful place to refuse it is here, at the
/// upload, where a human is watching.
///
/// 256 KiB is deliberately generous next to passway's own 16 KiB default page:
/// an override is a branded document that may carry inlined artwork, and the
/// thing the ceiling exists to prevent is an accident (a whole photo library, a
/// wrong file) rather than a large-but-intended page.
pub const MAX_HOLDING_PAGE_BYTES: usize = 256 * 1024;

/// Whether `name` may be a holding-page name.
///
/// Stricter than [`is_safe_domain`], deliberately. A domain is only ever an
/// object key here; a holding-page name additionally travels to every door,
/// becomes `<holding dir>/pages/<name>.html` on their disks, and is parsed back
/// out of a `host=name` map file. So the alphabet is the intersection of what
/// all three accept: ASCII lowercase alphanumerics plus `-` and `_`, starting
/// with an alphanumeric. No dots (no `..`, and no extension games), no `/`, no
/// `=` (which would split a map line in the wrong place), no whitespace.
pub fn is_safe_holding_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_HOLDING_NAME
        && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// The `host=<page name>` entries a door's holding-page map is built from
/// (R870-F8), sorted and deduped.
///
/// Third render off the same single listing of the enrollment set, in the same
/// `host=` grammar as [`route_entries`] and [`http_route_entries`], for the same
/// reason: one sweep, N tiers, and one place that decides what an entry is.
///
/// Two differences from its siblings, both load-bearing:
///
/// - **A domain with no override is omitted, not rendered as a token.** There is
///   no `holding=default` line, because passway's built-in page *is* the answer
///   for an absent entry and a door with an empty map is the correct steady
///   state, not an outage. (The `:80` tier renders `=redirect` precisely because
///   omission there is a refused connection.)
/// - **An unusable name is dropped, loudly**, rather than propagated. A name
///   that fails [`is_safe_holding_name`] cannot have been written by
///   [`ObjectCertStore::set_holding`], so it arrived by a hand-edited object;
///   rendering it would push a bad filename onto every door in the fleet.
pub fn holding_entries<'a>(
    enrolled: impl IntoIterator<Item = (&'a str, &'a Enrollment)>,
) -> Vec<String> {
    let mut entries: Vec<String> = enrolled
        .into_iter()
        .filter_map(|(domain, e)| {
            let name = e.holding.as_deref()?;
            if !is_safe_holding_name(name) {
                tracing::warn!(
                    domain = %domain,
                    holding = %name,
                    "cert store: unusable holding-page name — this domain keeps the default page"
                );
                return None;
            }
            Some(format!("{domain}={name}"))
        })
        .collect();
    entries.sort();
    entries.dedup();
    entries
}

/// Object-store-backed store for per-domain sealed TLS material.
///
/// Cheap to clone in the sense that matters — the backing store is behind an
/// `Arc` — so a node can hand one to both the issuer loop and each per-deploy
/// resolver without re-establishing an HTTP client.
#[derive(Clone)]
pub struct ObjectCertStore {
    objects: Arc<dyn ObjectStore>,
    issuer: String,
}

impl std::fmt::Debug for ObjectCertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The store itself may hold credentials; only the issuer segment is safe
        // (and useful) to print.
        f.debug_struct("ObjectCertStore")
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl ObjectCertStore {
    /// Build a store writing under `certs/<issuer_key(directory_url)>/`.
    pub fn new(objects: Arc<dyn ObjectStore>, directory_url: &str) -> Self {
        Self {
            objects,
            issuer: issuer_key(directory_url),
        }
    }

    /// The path segment this store writes under.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The bucket underneath, for a consumer that keys off it differently.
    ///
    /// R869: the off-fleet state copy lives in this same bucket under
    /// `cluster-state/` rather than behind a second set of credentials — a
    /// disaster-recovery mechanism that needs config the fleet does not already
    /// carry is one that is not there when the disaster happens. It is not
    /// *cert* material, so it is not routed through this type's own verbs.
    pub fn objects(&self) -> Arc<dyn ObjectStore> {
        Arc::clone(&self.objects)
    }

    /// Read and deserialise the [`SecretRecord`] at `name`, or `None` if the
    /// name is not TLS material or no object exists.
    ///
    /// Separate from the [`ClusterSecretStore`] impl because that trait's
    /// `Option` return cannot distinguish "absent" from "the bucket is
    /// unreachable" — a caller that needs to tell those apart (the issuer
    /// deciding whether to order) calls this and reads the error.
    pub fn read_secret(&self, name: &str) -> Result<Option<SecretRecord>, CertStoreError> {
        let Some(key) = object_key(&self.issuer, name) else {
            return Ok(None);
        };
        let Some(bytes) = self.objects.get(&key)? else {
            return Ok(None);
        };
        let rec = serde_json::from_slice(&bytes).map_err(|source| CertStoreError::Malformed {
            key: key.clone(),
            source,
        })?;
        Ok(Some(rec))
    }

    /// Write the sealed `rec` at `name`. Overwrites.
    ///
    /// Rejects a name that is not per-domain TLS material rather than inventing
    /// a key for it — see [`object_key`].
    pub fn write_secret(&self, name: &str, rec: &SecretRecord) -> Result<(), CertStoreError> {
        let Some(key) = object_key(&self.issuer, name) else {
            return Err(CertStoreError::NotCertMaterial {
                name: name.to_string(),
            });
        };
        let body = serde_json::to_vec(rec).map_err(|source| CertStoreError::Malformed {
            key: key.clone(),
            source,
        })?;
        self.objects.put(&key, body)?;
        Ok(())
    }

    /// Write a freshly-issued sealed pair.
    ///
    /// **Key first, cert last** — the same ordering, for the same reason, as
    /// [`crate::acme_issuer`]'s raft writes: renewal-due is gated off the *cert*
    /// record's `updated_at`, so writing the gate record last means a partial
    /// failure leaves the cert stale and the next tick re-issues and heals. The
    /// reverse order can wedge the store with a fresh cert against a stale key,
    /// which is a TLS failure for every consumer until someone notices.
    pub fn write_pair(
        &self,
        cert_name: &str,
        key_name: &str,
        cert_rec: &SecretRecord,
        key_rec: &SecretRecord,
    ) -> Result<(), CertStoreError> {
        self.write_secret(key_name, key_rec)?;
        self.write_secret(cert_name, cert_rec)?;
        Ok(())
    }

    /// Remove both objects for `domain`. Idempotent.
    pub fn delete_domain(&self, domain: &str) -> Result<(), CertStoreError> {
        let prefix = format!("{}{domain}/", issuer_prefix(&self.issuer));
        for leaf in [CERT_OBJECT, KEY_OBJECT, CLAIM_OBJECT] {
            self.objects.delete(&format!("{prefix}{leaf}"))?;
        }
        Ok(())
    }

    /// Every domain with a stored certificate under this issuer.
    ///
    /// Keyed off the *cert* object specifically — a domain with only a claim or
    /// only a key is mid-issuance and holds nothing servable. This answers "what
    /// have we issued", which is a renewal sweep's work list.
    ///
    /// **Not the demux's route table.** R779's first pass recorded it as such,
    /// and that deadlocks: on-demand TLS issues a domain's first cert when the
    /// first connection reaches its passway, so a route table gated on the cert
    /// already existing means a new domain is never routed, therefore never
    /// reached, therefore never issued. The allowlist is
    /// [`ObjectCertStore::enrolled`] — the fact that a tenant registered the
    /// name, which is knowable before any cert exists.
    ///
    /// Sorted, so a caller diffing successive listings sees a stable order.
    pub fn domains(&self) -> Result<Vec<String>, CertStoreError> {
        let prefix = issuer_prefix(&self.issuer);
        let suffix = format!("/{CERT_OBJECT}");
        let mut out: Vec<String> = self
            .objects
            .list_prefix(&prefix)?
            .into_iter()
            .filter_map(|k| {
                let rest = k.strip_prefix(&prefix)?;
                let domain = rest.strip_suffix(&suffix)?;
                (!domain.is_empty() && !domain.contains('/')).then(|| domain.to_string())
            })
            .collect();
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// Try to become the node that issues for `domain`.
    ///
    /// Wins by creating the claim object under [`Precondition::IfAbsent`]. A
    /// losing caller gets [`CertStoreError::Claimed`] naming the holder, unless
    /// the existing claim has expired — in which case it is stolen under
    /// [`Precondition::IfMatch`] against the etag just read, so two nodes both
    /// noticing the same expiry still produce exactly one winner.
    pub fn claim_issuance(
        &self,
        domain: &str,
        holder: &str,
        now: SystemTime,
    ) -> Result<IssuanceClaim, CertStoreError> {
        let key = format!("{}{domain}/{CLAIM_OBJECT}", issuer_prefix(&self.issuer));
        let now = unix_secs(now);
        let claim = IssuanceClaim {
            holder: holder.to_string(),
            acquired_at: now,
            ttl_secs: CLAIM_TTL.as_secs(),
        };
        let body = serde_json::to_vec(&claim).map_err(|source| CertStoreError::Malformed {
            key: key.clone(),
            source,
        })?;

        // None throughout this file: ACME issuance claims are a private
        // inter-node lock read over the S3 API, never served to a browser, so
        // there is no cache to direct (R330-B51).
        match self
            .objects
            .put_if(&key, body.clone(), Precondition::IfAbsent, None)
        {
            Ok(_) => return Ok(claim),
            Err(ObjectError::PreconditionFailed(_)) => {}
            Err(e) => return Err(e.into()),
        }

        // Someone holds it. Read the etag and the record together: the etag is
        // what makes the steal a compare-and-swap rather than a second racer's
        // blind overwrite.
        let etag = self.objects.etag(&key)?;
        let existing = self.objects.get(&key)?;
        let (Some(etag), Some(bytes)) = (etag, existing) else {
            // It vanished between the failed IfAbsent and this read — the holder
            // finished and released. Retry the create; a second racer that got
            // here at the same moment loses that IfAbsent, and losing is
            // `Claimed`, not a backend fault.
            return match self.objects.put_if(&key, body, Precondition::IfAbsent, None) {
                Ok(_) => Ok(claim),
                Err(ObjectError::PreconditionFailed(_)) => Err(CertStoreError::Claimed {
                    domain: domain.to_string(),
                    holder: "another node".to_string(),
                    remaining_secs: CLAIM_TTL.as_secs(),
                }),
                Err(e) => Err(e.into()),
            };
        };
        let held: IssuanceClaim =
            serde_json::from_slice(&bytes).map_err(|source| CertStoreError::Malformed {
                key: key.clone(),
                source,
            })?;
        if !held.is_expired(now) {
            let remaining_secs = held.remaining_secs(now);
            return Err(CertStoreError::Claimed {
                domain: domain.to_string(),
                holder: held.holder,
                remaining_secs,
            });
        }
        match self.objects.put_if(&key, body, Precondition::IfMatch(etag), None) {
            Ok(_) => Ok(claim),
            // Lost the steal to another node that noticed the same expiry.
            Err(ObjectError::PreconditionFailed(_)) => Err(CertStoreError::Claimed {
                domain: domain.to_string(),
                holder: held.holder,
                remaining_secs: 0,
            }),
            Err(e) => Err(e.into()),
        }
    }

    /// Read `domain`'s issuance claim without competing for it.
    ///
    /// The read-only peer of [`claim_issuance`](Self::claim_issuance), and the
    /// only way to tell the two states an operator most needs distinguished
    /// apart: a domain that is *mid-order* on some node, and a domain whose last
    /// order **failed** and is serving out its cooldown. Both are one `issuing`
    /// object; [`cool_down_issuance`](Self::cool_down_issuance) writes the
    /// failure case with a longer `ttl_secs`, so the TTL is the tell.
    ///
    /// Never taken, stolen, or refreshed by this call — an admin command that
    /// peeked by attempting a claim would evict a live issuer.
    pub fn issuance_claim(&self, domain: &str) -> Result<Option<IssuanceClaim>, CertStoreError> {
        let key = format!("{}{domain}/{CLAIM_OBJECT}", issuer_prefix(&self.issuer));
        let Some(bytes) = self.objects.get(&key)? else {
            return Ok(None);
        };
        let claim = serde_json::from_slice(&bytes).map_err(|source| CertStoreError::Malformed {
            key: key.clone(),
            source,
        })?;
        Ok(Some(claim))
    }

    /// Drop this node's claim on `domain`. Idempotent.
    ///
    /// Not required for correctness — a claim expires on its own — but a
    /// released claim lets a retry start immediately instead of waiting out
    /// [`CLAIM_TTL`] after a fast failure.
    pub fn release_issuance(&self, domain: &str) -> Result<(), CertStoreError> {
        let key = format!("{}{domain}/{CLAIM_OBJECT}", issuer_prefix(&self.issuer));
        self.objects.delete(&key)?;
        Ok(())
    }

    /// R779 — the opposite of [`release_issuance`]: **hold** the claim past its
    /// normal TTL so a *failed* order is not retried by anyone until `ttl`
    /// elapses.
    ///
    /// The claim object doubles as the failure backoff marker, which is why
    /// there is no separate one. That matters: Let's Encrypt rate-limits
    /// authorization failures **per identifier**, not per client, so a
    /// node-local marker (passway's `<cert>.acme-failed` file) would let N nodes
    /// each burn the same domain's budget N times over. This one is in the
    /// shared bucket, so every node sees the same cooldown.
    ///
    /// Written unconditionally rather than under `IfMatch`: the caller reached
    /// here holding the claim, and if its own claim had already lapsed and been
    /// stolen mid-order, over-writing the thief's claim costs one delayed
    /// issuance — strictly cheaper than the alternative of leaving a
    /// just-failed domain immediately retryable.
    pub fn cool_down_issuance(
        &self,
        domain: &str,
        holder: &str,
        now: SystemTime,
        ttl: Duration,
    ) -> Result<(), CertStoreError> {
        let key = format!("{}{domain}/{CLAIM_OBJECT}", issuer_prefix(&self.issuer));
        let claim = IssuanceClaim {
            holder: holder.to_string(),
            acquired_at: unix_secs(now),
            ttl_secs: ttl.as_secs(),
        };
        let body = serde_json::to_vec(&claim).map_err(|source| CertStoreError::Malformed {
            key: key.clone(),
            source,
        })?;
        self.objects.put(&key, body)?;
        Ok(())
    }

    // ── Enrollment ───────────────────────────────────────────────────────────

    /// `enrolled/<domain>` — issuer-independent, see [`ENROLLED_PREFIX`].
    fn enrolled_key(domain: &str) -> Result<String, CertStoreError> {
        if !is_safe_domain(domain) {
            return Err(CertStoreError::InvalidDomain {
                domain: domain.to_string(),
            });
        }
        Ok(format!("{ENROLLED_PREFIX}{domain}"))
    }

    /// Add `domain` to the routable set.
    ///
    /// Idempotent for an identical record and **refused** for a conflicting one
    /// ([`CertStoreError::AlreadyEnrolled`]): re-pointing a live domain at a
    /// different backend is `unenroll` + `enroll`, spelled in two calls so it
    /// cannot happen by a stale config being replayed.
    pub fn enroll(&self, domain: &str, enrollment: &Enrollment) -> Result<(), CertStoreError> {
        let key = Self::enrolled_key(domain)?;
        if let Some(existing) = self.enrollment(domain)? {
            // Every field but the timestamp: a record differing only in
            // `holding` is a *different* enrollment, and treating it as a no-op
            // would make `enroll --holding` silently do nothing on a domain that
            // is already registered. Changing the page is
            // [`Self::set_holding`], which does not touch routing.
            if existing.tls_backend == enrollment.tls_backend
                && existing.http_backend == enrollment.http_backend
                && existing.holding == enrollment.holding
            {
                return Ok(()); // same enrollment, different timestamp — a no-op
            }
            return Err(CertStoreError::AlreadyEnrolled {
                domain: domain.to_string(),
                existing: existing.tls_backend.to_string(),
            });
        }
        let body = serde_json::to_vec(enrollment).map_err(|source| CertStoreError::Malformed {
            key: key.clone(),
            source,
        })?;
        self.objects.put(&key, body)?;
        Ok(())
    }

    /// Read one domain's enrollment, or `None` if it is not enrolled.
    ///
    /// A malformed object here IS a hard error (unlike in [`Self::enrolled`]):
    /// a single-domain lookup has one caller asking about one domain, and
    /// reporting "not enrolled" for a corrupt record would let a caller
    /// re-enroll it to a different backend without ever seeing the conflict.
    pub fn enrollment(&self, domain: &str) -> Result<Option<Enrollment>, CertStoreError> {
        let key = Self::enrolled_key(domain)?;
        let Some(bytes) = self.objects.get(&key)? else {
            return Ok(None);
        };
        let rec = serde_json::from_slice(&bytes).map_err(|source| CertStoreError::Malformed {
            key: key.clone(),
            source,
        })?;
        Ok(Some(rec))
    }

    /// Remove `domain` from the routable set. Idempotent.
    ///
    /// Leaves the cert material alone: unenrolling is a routing decision, and a
    /// re-enrolled domain should not have to re-order a cert it already holds
    /// (which would spend an ACME order to undo an operator's typo). Deleting
    /// the material is [`Self::delete_domain`], explicitly.
    pub fn unenroll(&self, domain: &str) -> Result<(), CertStoreError> {
        let key = Self::enrolled_key(domain)?;
        self.objects.delete(&key)?;
        Ok(())
    }

    /// The whole enrollment set, sorted by domain.
    ///
    /// One `list_prefix` plus one `get` per domain — the listing carries keys
    /// only, so the backend has to be read. That is the cost of keeping one
    /// object per domain (concurrent enrollments never collide, unlike writers
    /// to a single manifest); a publisher sweeping this should do so on the
    /// order of minutes, not seconds.
    ///
    /// **A malformed object is skipped with a warning, not an error** — the
    /// opposite of [`Self::read_secret`], deliberately. The consumer is the
    /// route table: erroring out on one corrupt object would withhold the whole
    /// render and freeze *every* tenant's routing on one bad key, while skipping
    /// costs exactly the one domain that is broken. A cert read makes the
    /// reverse trade because there a miss means "order another one".
    pub fn enrolled(&self) -> Result<Vec<(String, Enrollment)>, CertStoreError> {
        let mut out: Vec<(String, Enrollment)> = Vec::new();
        for key in self.objects.list_prefix(ENROLLED_PREFIX)? {
            let Some(domain) = key.strip_prefix(ENROLLED_PREFIX) else {
                continue;
            };
            if !is_safe_domain(domain) {
                continue;
            }
            let Some(bytes) = self.objects.get(&key)? else {
                continue; // unenrolled between the list and the get
            };
            match serde_json::from_slice::<Enrollment>(&bytes) {
                Ok(rec) => out.push((domain.to_string(), rec)),
                Err(e) => tracing::warn!(
                    domain = %domain,
                    error = %e,
                    "cert store: malformed enrollment object — this domain will not be routed"
                ),
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    // ── Holding pages (R870-F8) ─────────────────────────────────────────────

    /// `holding/<name>`, refused for a name no door could put on disk.
    fn holding_key(name: &str) -> Result<String, CertStoreError> {
        if !is_safe_holding_name(name) {
            return Err(CertStoreError::InvalidHoldingName {
                name: name.to_string(),
            });
        }
        Ok(format!("{HOLDING_PREFIX}{name}"))
    }

    /// Point `domain` at a holding page, or (with `None`) back at passway's own.
    ///
    /// Deliberately **not** part of [`Self::enroll`]'s conflict rule: which page
    /// a parked domain shows is cosmetic and freely re-decided, whereas
    /// re-pointing `tls_backend` is a routing change that must go through
    /// unenroll + enroll so it cannot happen by a stale config replay. So this
    /// is a read-modify-write of an *existing* record and refuses an unenrolled
    /// domain rather than creating one — there is no domain to brand until it is
    /// routable.
    ///
    /// The page object need not exist yet: a door that cannot find the page
    /// falls back to its built-in one, so the two writes can happen in either
    /// order and neither leaves a tenant with a blank door.
    pub fn set_holding(&self, domain: &str, name: Option<&str>) -> Result<(), CertStoreError> {
        if let Some(name) = name {
            // Validate before the read, so a typo costs no round trip and the
            // error names the name rather than the domain.
            Self::holding_key(name)?;
        }
        let key = Self::enrolled_key(domain)?;
        let Some(mut record) = self.enrollment(domain)? else {
            return Err(CertStoreError::NotEnrolled {
                domain: domain.to_string(),
            });
        };
        if record.holding.as_deref() == name {
            return Ok(());
        }
        record.holding = name.map(str::to_owned);
        let body = serde_json::to_vec(&record).map_err(|source| CertStoreError::Malformed {
            key: key.clone(),
            source,
        })?;
        self.objects.put(&key, body)?;
        Ok(())
    }

    /// Read one holding page's bytes, or `None` if nothing is stored under it.
    pub fn holding_page(&self, name: &str) -> Result<Option<Vec<u8>>, CertStoreError> {
        Ok(self.objects.get(&Self::holding_key(name)?)?)
    }

    /// Store a holding page under `name`, replacing any previous body.
    ///
    /// Last-writer-wins, unlike [`Self::enroll`]: a page is one operator's
    /// content being revised, not two tenants racing for one hostname.
    ///
    /// Refuses a body past [`MAX_HOLDING_PAGE_BYTES`] — the doors would decline
    /// to serve it anyway, and a refusal here is the only one a human sees.
    pub fn write_holding_page(&self, name: &str, body: Vec<u8>) -> Result<(), CertStoreError> {
        let key = Self::holding_key(name)?;
        if body.len() > MAX_HOLDING_PAGE_BYTES {
            return Err(CertStoreError::HoldingPageTooLarge {
                name: name.to_string(),
                bytes: body.len(),
            });
        }
        self.objects.put(&key, body)?;
        Ok(())
    }

    /// Remove a holding page. Idempotent.
    ///
    /// Leaves every [`Enrollment::holding`] that names it alone — those domains
    /// fall back to passway's built-in page on the next sweep, which is the
    /// behaviour an operator deleting a page is asking for. Re-uploading the
    /// name restores them with no re-enrollment.
    pub fn delete_holding_page(&self, name: &str) -> Result<(), CertStoreError> {
        self.objects.delete(&Self::holding_key(name)?)?;
        Ok(())
    }

    /// Every stored holding-page name, sorted.
    ///
    /// Keys only — the bodies are whole HTML documents and an operator listing
    /// what exists does not want them.
    pub fn holding_pages(&self) -> Result<Vec<String>, CertStoreError> {
        let mut out: Vec<String> = self
            .objects
            .list_prefix(HOLDING_PREFIX)?
            .into_iter()
            .filter_map(|key| key.strip_prefix(HOLDING_PREFIX).map(str::to_owned))
            .filter(|name| is_safe_holding_name(name))
            .collect();
        out.sort();
        out.dedup();
        Ok(out)
    }
}

/// Reading a cert record fails **closed but quiet**: the resolver's trait can
/// only say present-or-absent, so a backend error is logged here and reported as
/// absent, which the resolver turns into a fail-closed `ClusterNotFound`. The
/// log line is what tells an operator "the bucket is down" apart from "no cert
/// for that domain" — do not remove it in favour of the silent `Option`.
impl ClusterSecretStore for ObjectCertStore {
    fn get_secret(&self, name: &str) -> Option<SecretRecord> {
        match self.read_secret(name) {
            Ok(rec) => rec,
            Err(e) => {
                tracing::warn!(
                    secret = %name,
                    issuer = %self.issuer,
                    error = %e,
                    "object cert store read failed; treating as absent (fail-closed)"
                );
                None
            }
        }
    }
}

/// Read cluster secrets from `primary`, falling back to `fallback` on a miss.
///
/// Production shape is `LayeredSecretStore::new(state_machine, object_cert_store)`:
/// raft answers everything it has — including the fleet-wide wildcard cert, which
/// is one KB-scale record and exactly what raft was sized for — and per-domain
/// TLS material, which raft deliberately never holds, comes from the object
/// store. The order matters: raft is local and synchronous, so the common case
/// costs no network at all, and a domain migrated *into* raft (an operator
/// pinning one cert) shadows the object store rather than racing it.
pub struct LayeredSecretStore<P, F> {
    primary: P,
    fallback: F,
}

impl<P, F> LayeredSecretStore<P, F> {
    pub fn new(primary: P, fallback: F) -> Self {
        Self { primary, fallback }
    }
}

impl<P: ClusterSecretStore, F: ClusterSecretStore> ClusterSecretStore for LayeredSecretStore<P, F> {
    fn get_secret(&self, name: &str) -> Option<SecretRecord> {
        self.primary
            .get_secret(name)
            .or_else(|| self.fallback.get_secret(name))
    }
}

impl<S: ClusterSecretStore + ?Sized> ClusterSecretStore for Arc<S> {
    fn get_secret(&self, name: &str) -> Option<SecretRecord> {
        (**self).get_secret(name)
    }
}

/// An absent store is a store that holds nothing.
///
/// This is what lets the production call site layer unconditionally —
/// `LayeredSecretStore::new(state_machine, state.cert_store.clone())` — instead
/// of branching on `Option` and building two differently-typed resolvers. An
/// unconfigured node then takes exactly the pre-R779 path, one `Option::is_none`
/// short of it.
impl<S: ClusterSecretStore> ClusterSecretStore for Option<S> {
    fn get_secret(&self, name: &str) -> Option<SecretRecord> {
        self.as_ref().and_then(|s| s.get_secret(name))
    }
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme_issuer::{cert_secret_name, key_secret_name};
    use std::sync::Mutex;
    use workload_spec::secrets::SecretAccess;
    use yah_object_store::InMemoryObjectStore;

    const LE: &str = "https://acme-v02.api.letsencrypt.org/directory";

    fn store() -> (Arc<InMemoryObjectStore>, ObjectCertStore) {
        let mem = Arc::new(InMemoryObjectStore::new());
        let certs = ObjectCertStore::new(mem.clone(), LE);
        (mem, certs)
    }

    fn rec(body: &[u8]) -> SecretRecord {
        SecretRecord {
            ciphertext: body.to_vec(),
            nonce: vec![0u8; 12],
            updated_at: 1_700_000_000,
            access: SecretAccess::AllowAny,
            digest: None,
            sans: None,
            ari: None,
        }
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn issuer_key_is_the_directory_host() {
        assert_eq!(issuer_key(LE), "acme-v02.api.letsencrypt.org");
        assert_eq!(
            issuer_key("https://acme-staging-v02.api.letsencrypt.org/directory"),
            "acme-staging-v02.api.letsencrypt.org"
        );
        // Two CAs must not collapse into one key space — DECISION 3 keeps a
        // second CA as overflow, and both may hold a cert for one domain.
        assert_ne!(issuer_key(LE), issuer_key("https://acme.zerossl.com/v2/DV90"));
    }

    #[test]
    fn issuer_key_sanitises_to_one_path_segment() {
        let k = issuer_key("https://ca.example.com:8443/acme/dir");
        assert!(!k.contains('/'), "issuer key must be one segment: {k}");
        assert_eq!(k, "ca.example.com-8443");
        assert_eq!(issuer_key(""), "unknown-issuer");
    }

    #[test]
    fn object_key_maps_only_tls_names() {
        let i = "le";
        assert_eq!(
            object_key(i, &cert_secret_name("a.example.com")),
            Some("certs/le/a.example.com/cert.sealed".to_string())
        );
        assert_eq!(
            object_key(i, &key_secret_name("a.example.com")),
            Some("certs/le/a.example.com/key.sealed".to_string())
        );
        // A general cluster secret is never sought in the object store.
        assert_eq!(object_key(i, "registry/dockerhub"), None);
        assert_eq!(object_key(i, "tls/a.example.com/account"), None);
        assert_eq!(object_key(i, "tls//cert"), None);
    }

    #[test]
    fn object_key_refuses_a_traversing_domain() {
        // `tls/../../etc/cert` must not address an object outside the prefix.
        assert_eq!(object_key("le", "tls/../../etc/cert"), None);
        assert_eq!(object_key("le", "tls/a/../b/cert"), None);
    }

    #[test]
    fn write_then_read_round_trips_the_sealed_record() {
        let (_mem, certs) = store();
        let name = cert_secret_name("a.example.com");
        let original = rec(b"sealed-chain");
        certs.write_secret(&name, &original).unwrap();
        assert_eq!(certs.read_secret(&name).unwrap(), Some(original.clone()));
        // And through the resolver's trait, which is how it is actually read.
        assert_eq!(certs.get_secret(&name), Some(original));
    }

    #[test]
    fn the_object_body_is_ciphertext_only() {
        let (mem, certs) = store();
        certs
            .write_secret(&key_secret_name("a.example.com"), &rec(b"sealed-key-bytes"))
            .unwrap();
        let raw = mem
            .get("certs/acme-v02.api.letsencrypt.org/a.example.com/key.sealed")
            .unwrap()
            .unwrap();
        let text = String::from_utf8_lossy(&raw);
        // The record serialises its ciphertext as a byte array; what must never
        // appear is a PEM header, i.e. plaintext key material.
        assert!(!text.contains("BEGIN"), "object body must hold no PEM: {text}");
        assert!(text.contains("ciphertext"));
    }

    #[test]
    fn writing_a_non_tls_name_is_refused() {
        let (mem, certs) = store();
        let err = certs.write_secret("registry/dockerhub", &rec(b"x")).unwrap_err();
        assert!(matches!(err, CertStoreError::NotCertMaterial { .. }), "got {err:?}");
        assert!(mem.keys().is_empty(), "nothing may be written under a bad name");
    }

    #[test]
    fn a_malformed_object_is_an_error_not_a_miss() {
        // The dangerous failure: a corrupt cert object read as "no cert yet",
        // which would order a replacement on every boot.
        let (mem, certs) = store();
        mem.put(
            "certs/acme-v02.api.letsencrypt.org/a.example.com/cert.sealed",
            b"{ not json".to_vec(),
        )
        .unwrap();
        let err = certs
            .read_secret(&cert_secret_name("a.example.com"))
            .unwrap_err();
        assert!(matches!(err, CertStoreError::Malformed { .. }), "got {err:?}");
    }

    #[test]
    fn domains_lists_only_domains_with_a_cert() {
        let (mem, certs) = store();
        certs.write_secret(&cert_secret_name("b.example.com"), &rec(b"c")).unwrap();
        certs.write_secret(&key_secret_name("b.example.com"), &rec(b"k")).unwrap();
        certs.write_secret(&cert_secret_name("a.example.com"), &rec(b"c")).unwrap();
        // Mid-issuance: key + claim but no cert. Not servable, so not routable.
        certs.write_secret(&key_secret_name("z.example.com"), &rec(b"k")).unwrap();
        certs.claim_issuance("z.example.com", "node-1", at(100)).unwrap();
        // Another issuer's objects are not this issuer's route table.
        mem.put("certs/acme.zerossl.com/q.example.com/cert.sealed", b"{}".to_vec())
            .unwrap();

        assert_eq!(
            certs.domains().unwrap(),
            vec!["a.example.com".to_string(), "b.example.com".to_string()]
        );
    }

    #[test]
    fn write_pair_writes_the_key_before_the_cert() {
        // renewal-due is gated off the CERT record, so the cert must land last:
        // a partial failure has to leave the cert stale (re-issue heals) rather
        // than fresh-against-a-stale-key (TLS failure until someone notices).
        struct OrderRecording(Mutex<Vec<String>>);
        impl ObjectStore for OrderRecording {
            fn put(&self, key: &str, _data: Vec<u8>) -> Result<(), yah_object_store::Error> {
                self.0.lock().unwrap().push(key.to_string());
                Ok(())
            }
            fn get(&self, _key: &str) -> Result<Option<Vec<u8>>, yah_object_store::Error> {
                Ok(None)
            }
            fn delete(&self, _key: &str) -> Result<(), yah_object_store::Error> {
                Ok(())
            }
            fn list_prefix(&self, _p: &str) -> Result<Vec<String>, yah_object_store::Error> {
                Ok(vec![])
            }
        }

        let rec_store = Arc::new(OrderRecording(Mutex::new(Vec::new())));
        let certs = ObjectCertStore::new(rec_store.clone(), LE);
        certs
            .write_pair(
                &cert_secret_name("a.example.com"),
                &key_secret_name("a.example.com"),
                &rec(b"c"),
                &rec(b"k"),
            )
            .unwrap();

        let order = rec_store.0.lock().unwrap().clone();
        assert_eq!(
            order,
            vec![
                "certs/acme-v02.api.letsencrypt.org/a.example.com/key.sealed".to_string(),
                "certs/acme-v02.api.letsencrypt.org/a.example.com/cert.sealed".to_string(),
            ]
        );
    }

    #[test]
    fn cert_store_config_is_off_without_a_bucket() {
        let none = |_: &str| None;
        assert_eq!(CertStoreConfig::parse(none).unwrap(), None);
    }

    #[test]
    fn cert_store_config_reads_bucket_account_and_endpoint() {
        let cfg = CertStoreConfig::parse(|k| match k {
            BUCKET_ENV => Some(" yah-certs ".to_string()),
            ACCOUNT_ID_ENV => Some("acct123".to_string()),
            ENDPOINT_ENV => Some("http://127.0.0.1:9000".to_string()),
            _ => None,
        })
        .unwrap()
        .unwrap();
        assert_eq!(cfg.bucket, "yah-certs");
        assert_eq!(cfg.account_id, "acct123");
        assert_eq!(cfg.endpoint.as_deref(), Some("http://127.0.0.1:9000"));
    }

    /// Half-configured is a hard error, not a silent skip — an operator who set
    /// the bucket meant to turn the store on. Lived on `parse_issuer_config`
    /// until R870-B20 hoisted the store out of the issuer config.
    #[test]
    fn a_bucket_without_an_account_id_is_rejected() {
        let err = CertStoreConfig::parse(|k| match k {
            BUCKET_ENV => Some("yah-certs".to_string()),
            _ => None,
        })
        .unwrap_err();
        assert!(err.contains(ACCOUNT_ID_ENV), "got {err}");
    }

    /// R870-B20: one owner for the issuer segment. A door reading a different
    /// default from the issuer that wrote the cert would address an empty prefix.
    #[test]
    fn the_acme_directory_defaults_to_staging_and_is_overridable() {
        assert_eq!(acme_directory(|_: &str| None), AcmeDirectory::Staging);
        assert_eq!(
            acme_directory(|k: &str| (k == DIRECTORY_ENV).then(|| "production".to_string())),
            AcmeDirectory::Production
        );
    }

    #[test]
    fn delete_domain_removes_cert_key_and_claim() {
        let (mem, certs) = store();
        certs.write_secret(&cert_secret_name("a.example.com"), &rec(b"c")).unwrap();
        certs.write_secret(&key_secret_name("a.example.com"), &rec(b"k")).unwrap();
        certs.claim_issuance("a.example.com", "node-1", at(100)).unwrap();
        certs.delete_domain("a.example.com").unwrap();
        assert!(mem.keys().is_empty(), "left over: {:?}", mem.keys());
        // Idempotent.
        certs.delete_domain("a.example.com").unwrap();
    }

    #[test]
    fn one_claim_wins_and_the_loser_is_told_who_holds_it() {
        let (_mem, certs) = store();
        let won = certs.claim_issuance("a.example.com", "node-1", at(1_000)).unwrap();
        assert_eq!(won.holder, "node-1");

        let err = certs
            .claim_issuance("a.example.com", "node-2", at(1_060))
            .unwrap_err();
        match err {
            CertStoreError::Claimed { holder, remaining_secs, .. } => {
                assert_eq!(holder, "node-1");
                assert_eq!(remaining_secs, CLAIM_TTL.as_secs() - 60);
            }
            other => panic!("expected Claimed, got {other:?}"),
        }
    }

    #[test]
    fn an_expired_claim_is_stolen() {
        let (_mem, certs) = store();
        certs.claim_issuance("a.example.com", "dead-node", at(1_000)).unwrap();
        let after = 1_000 + CLAIM_TTL.as_secs();
        let stolen = certs
            .claim_issuance("a.example.com", "node-2", at(after))
            .unwrap();
        assert_eq!(stolen.holder, "node-2");
        assert_eq!(stolen.acquired_at, after);
    }

    #[test]
    fn a_released_claim_is_immediately_reclaimable() {
        let (_mem, certs) = store();
        certs.claim_issuance("a.example.com", "node-1", at(1_000)).unwrap();
        certs.release_issuance("a.example.com").unwrap();
        let re = certs.claim_issuance("a.example.com", "node-2", at(1_001)).unwrap();
        assert_eq!(re.holder, "node-2");
    }

    #[test]
    fn a_cooled_down_domain_is_not_retried_when_the_ordinary_ttl_lapses() {
        // R779: the failure backoff IS the claim, written with a longer TTL. The
        // point of the test is the gap — a domain whose order just failed must
        // still be untouchable at the moment an ordinary claim would have
        // expired, or every node re-orders it every CLAIM_TTL and burns Let's
        // Encrypt's 5-failures-per-hour-per-identifier budget in minutes.
        let (_mem, certs) = store();
        certs.claim_issuance("a.example.com", "node-1", at(1_000)).unwrap();
        certs
            .cool_down_issuance("a.example.com", "node-1", at(1_010), Duration::from_secs(3600))
            .unwrap();

        let just_past_the_ordinary_ttl = 1_010 + CLAIM_TTL.as_secs() + 1;
        let err = certs
            .claim_issuance("a.example.com", "node-2", at(just_past_the_ordinary_ttl))
            .unwrap_err();
        assert!(
            matches!(err, CertStoreError::Claimed { ref holder, .. } if holder == "node-1"),
            "still parked, and it says who parked it: {err}"
        );

        // And it does free itself: a permanently broken tenant domain retries on
        // a human timescale rather than never.
        let after_cooldown = 1_010 + 3600;
        let retry = certs
            .claim_issuance("a.example.com", "node-2", at(after_cooldown))
            .unwrap();
        assert_eq!(retry.holder, "node-2");
    }

    #[test]
    fn a_future_dated_claim_is_not_expired() {
        // Clock skew between nodes must not read as "stealable now" — that is
        // the one shape where two nodes would both place an order.
        let c = IssuanceClaim {
            holder: "node-1".into(),
            acquired_at: 2_000,
            ttl_secs: 600,
        };
        assert!(!c.is_expired(1_000));
        assert!(!c.is_expired(2_599));
        assert!(c.is_expired(2_600));
    }

    struct FakeRaft(Vec<(String, SecretRecord)>);
    impl ClusterSecretStore for FakeRaft {
        fn get_secret(&self, name: &str) -> Option<SecretRecord> {
            self.0.iter().find(|(n, _)| n == name).map(|(_, r)| r.clone())
        }
    }

    #[test]
    fn layered_prefers_raft_and_falls_back_to_the_object_store() {
        let (_mem, certs) = store();
        certs
            .write_secret(&cert_secret_name("tenant.example.com"), &rec(b"from-r2"))
            .unwrap();
        let raft = FakeRaft(vec![(
            cert_secret_name("yah.dev"),
            rec(b"from-raft"),
        )]);
        let layered = LayeredSecretStore::new(raft, certs);

        // The fleet wildcard still comes from raft, unchanged.
        assert_eq!(
            layered.get_secret(&cert_secret_name("yah.dev")).unwrap().ciphertext,
            b"from-raft".to_vec()
        );
        // A per-domain cert raft never held comes from the object store.
        assert_eq!(
            layered
                .get_secret(&cert_secret_name("tenant.example.com"))
                .unwrap()
                .ciphertext,
            b"from-r2".to_vec()
        );
        // A miss in both stays a miss — the resolver turns it into a
        // fail-closed ClusterNotFound.
        assert_eq!(layered.get_secret(&cert_secret_name("nope.example.com")), None);
    }

    #[test]
    fn raft_shadows_the_object_store_for_the_same_name() {
        let (_mem, certs) = store();
        let name = cert_secret_name("pinned.example.com");
        certs.write_secret(&name, &rec(b"from-r2")).unwrap();
        let layered = LayeredSecretStore::new(FakeRaft(vec![(name.clone(), rec(b"pinned"))]), certs);
        assert_eq!(layered.get_secret(&name).unwrap().ciphertext, b"pinned".to_vec());
    }

    // ── Enrollment ───────────────────────────────────────────────────────────

    fn backend(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn enrollment(port: u16) -> Enrollment {
        Enrollment::new(backend(port), at(1_700_000_000))
    }

    #[test]
    fn enroll_then_list_round_trips_and_sorts() {
        let (_mem, certs) = store();
        certs.enroll("b.example.com", &enrollment(8444)).unwrap();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();
        let enrolled = certs.enrolled().unwrap();
        assert_eq!(
            enrolled.iter().map(|(d, _)| d.as_str()).collect::<Vec<_>>(),
            vec!["a.example.com", "b.example.com"]
        );
        assert_eq!(enrolled[0].1.tls_backend, backend(8443));
        assert_eq!(certs.enrollment("b.example.com").unwrap(), Some(enrollment(8444)));
        assert_eq!(certs.enrollment("nope.example.com").unwrap(), None);
    }

    #[test]
    fn enrollment_is_not_scoped_to_an_issuer() {
        // A domain enrolled once stays routable if DECISION 3's overflow moves
        // its cert to a second CA — the key must carry no issuer segment.
        let mem = Arc::new(InMemoryObjectStore::new());
        let le = ObjectCertStore::new(mem.clone(), LE);
        let other = ObjectCertStore::new(mem.clone(), "https://acme.zerossl.com/v2/DV90");
        le.enroll("a.example.com", &enrollment(8443)).unwrap();
        assert_eq!(other.enrolled().unwrap().len(), 1);
        assert_eq!(mem.keys(), vec!["enrolled/a.example.com".to_string()]);
    }

    #[test]
    fn re_enrolling_the_same_backend_is_a_no_op_and_a_different_one_is_refused() {
        let (_mem, certs) = store();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();
        // Same backend, later stamp: a replayed config, not a change.
        certs
            .enroll(
                "a.example.com",
                &Enrollment::new(backend(8443), at(1_700_009_999)),
            )
            .unwrap();
        // A different backend is two tenants claiming one name.
        let err = certs.enroll("a.example.com", &enrollment(8444)).unwrap_err();
        assert!(matches!(err, CertStoreError::AlreadyEnrolled { .. }), "got {err:?}");
        assert_eq!(
            certs.enrollment("a.example.com").unwrap().unwrap().tls_backend,
            backend(8443),
            "a refused enroll must not have overwritten the live backend"
        );
    }

    #[test]
    fn unenroll_drops_the_route_but_keeps_the_cert() {
        let (_mem, certs) = store();
        let cert = cert_secret_name("a.example.com");
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();
        certs.write_secret(&cert, &rec(b"sealed-chain")).unwrap();

        certs.unenroll("a.example.com").unwrap();
        assert!(certs.enrolled().unwrap().is_empty());
        // Re-enrolling must not have to spend an ACME order to undo a typo.
        assert!(certs.read_secret(&cert).unwrap().is_some());
        certs.unenroll("a.example.com").unwrap(); // idempotent
    }

    #[test]
    fn enrollment_refuses_a_traversing_domain() {
        let (mem, certs) = store();
        for bad in ["", "../../etc", "a/b"] {
            assert!(
                matches!(
                    certs.enroll(bad, &enrollment(8443)),
                    Err(CertStoreError::InvalidDomain { .. })
                ),
                "{bad:?} must be refused"
            );
            assert!(matches!(
                certs.enrollment(bad),
                Err(CertStoreError::InvalidDomain { .. })
            ));
        }
        assert!(mem.keys().is_empty(), "nothing may be written under a bad domain");
    }

    #[test]
    fn a_malformed_enrollment_is_skipped_not_fatal() {
        // One corrupt object must cost exactly one domain's route, not the
        // whole render — a listing error would freeze every tenant's routing.
        let (mem, certs) = store();
        certs.enroll("good.example.com", &enrollment(8443)).unwrap();
        mem.put("enrolled/bad.example.com", b"{not json".to_vec()).unwrap();
        let enrolled = certs.enrolled().unwrap();
        assert_eq!(
            enrolled.iter().map(|(d, _)| d.as_str()).collect::<Vec<_>>(),
            vec!["good.example.com"]
        );
        // Asked about directly, though, it is an error and not "not enrolled".
        assert!(matches!(
            certs.enrollment("bad.example.com"),
            Err(CertStoreError::Malformed { .. })
        ));
    }

    #[test]
    fn an_enrolled_domain_is_routable_before_it_has_a_cert() {
        // The deadlock this set exists to break: on-demand TLS issues on the
        // first connection, so routing gated on a cert existing means the
        // connection never arrives and the cert never exists.
        let (_mem, certs) = store();
        certs.enroll("new.example.com", &enrollment(8443)).unwrap();
        assert!(certs.domains().unwrap().is_empty(), "no cert yet");
        assert_eq!(
            render_demux_routes(certs.enrolled().unwrap().iter().map(|(d, e)| (d.as_str(), e))),
            "new.example.com=127.0.0.1:8443"
        );
    }

    #[test]
    fn rendered_routes_are_sorted_and_parse_as_demux_routes() {
        let set = [
            ("b.example.com".to_string(), enrollment(8444)),
            ("a.example.com".to_string(), enrollment(8443)),
        ];
        let rendered = render_demux_routes(set.iter().map(|(d, e)| (d.as_str(), e)));
        assert_eq!(
            rendered,
            "a.example.com=127.0.0.1:8443,b.example.com=127.0.0.1:8444"
        );
        // The demux's own parser shape: `host=addr` pairs, comma-separated,
        // every addr a SocketAddr. Checked here because the two crates are in
        // different workspaces and nothing else holds them to one format.
        for entry in rendered.split(',') {
            let (host, addr) = entry.split_once('=').expect("host=addr");
            assert!(!host.is_empty());
            addr.parse::<SocketAddr>().expect("backend parses as a SocketAddr");
        }
        assert_eq!(render_demux_routes(std::iter::empty()), "");
    }

    #[test]
    fn a_domain_with_no_http_backend_still_gets_a_port_80_route() {
        // R870-F1: the gap this closes. Without the `redirect` default, a
        // second apex is enrolled, routable on :443, and refuses every
        // scheme-less `curl example.com/install.sh` — which is how the
        // documented install path is written.
        let set = [
            ("b.example.com".to_string(), enrollment(8444)),
            (
                "a.example.com".to_string(),
                enrollment(8443).with_http_backend(backend(8081)),
            ),
        ];
        let rendered = render_http_routes(set.iter().map(|(d, e)| (d.as_str(), e)));
        assert_eq!(
            rendered,
            "a.example.com=127.0.0.1:8081,b.example.com=redirect"
        );
        // The router's own parser shape: `host=disposition`, comma-separated,
        // every disposition either the redirect token or a SocketAddr. Checked
        // here because the two crates are in different workspaces and nothing
        // else holds them to one format.
        for entry in rendered.split(',') {
            let (host, value) = entry.split_once('=').expect("host=disposition");
            assert!(!host.is_empty());
            if value != HTTP_REDIRECT_TOKEN {
                value
                    .parse::<SocketAddr>()
                    .expect("a backend or `redirect`");
            }
        }
        assert_eq!(render_http_routes(std::iter::empty()), "");
    }

    // ── Holding pages (R870-F8) ──────────────────────────────────────────────

    #[test]
    fn a_holding_name_must_survive_being_a_filename_and_a_map_line() {
        for good in ["camp", "yah-camp", "camp_2", "a", "9lives"] {
            assert!(is_safe_holding_name(good), "{good:?} should be usable");
        }
        for bad in [
            "",
            "-leading",  // a leading dash reads as a flag to half the tools that see it
            "camp.html", // dots invite extension games and `..`
            "../etc/passwd", // the traversal the alphabet exists to exclude
            "camp/dark",
            "camp=dark", // would split a `host=name` line in the wrong place
            "camp dark",
            "Camp", // case-folding filesystems make two names one file
            &"x".repeat(MAX_HOLDING_NAME + 1),
        ] {
            assert!(!is_safe_holding_name(bad), "{bad:?} must be refused");
        }
    }

    #[test]
    fn only_domains_with_an_override_reach_the_map_and_a_bad_name_never_does() {
        let set = [
            ("b.example.com".to_string(), enrollment(8444)),
            (
                "a.example.com".to_string(),
                enrollment(8443).with_holding("camp"),
            ),
            (
                "evil.example.com".to_string(),
                // Only reachable by hand-editing the object — `set_holding`
                // refuses it — so the render must refuse it too rather than
                // pushing the name onto every door's disk.
                enrollment(8445).with_holding("../../etc/passwd"),
            ),
        ];
        assert_eq!(
            holding_entries(set.iter().map(|(d, e)| (d.as_str(), e))),
            vec!["a.example.com=camp".to_string()]
        );
        assert!(holding_entries(std::iter::empty()).is_empty());
    }

    #[test]
    fn an_enrollment_written_before_this_field_existed_still_loads() {
        // The `#[serde(default)]` contract, against the exact bytes already in
        // the live bucket rather than against a round-trip of today's struct.
        let (mem, certs) = store();
        mem.put(
            "enrolled/old.example.com",
            br#"{"tls_backend":"127.0.0.1:8443","enrolled_at":1700000000}"#.to_vec(),
        )
        .unwrap();
        let rec = certs.enrollment("old.example.com").unwrap().unwrap();
        assert_eq!(rec.tls_backend, backend(8443));
        assert_eq!(rec.holding, None);
    }

    #[test]
    fn setting_a_holding_page_is_a_mutation_and_re_enrolling_is_not() {
        let (_mem, certs) = store();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();

        certs.set_holding("a.example.com", Some("camp")).unwrap();
        assert_eq!(
            certs.enrollment("a.example.com").unwrap().unwrap().holding,
            Some("camp".to_string())
        );
        certs.set_holding("a.example.com", Some("camp")).unwrap(); // idempotent
        certs.set_holding("a.example.com", None).unwrap();
        assert_eq!(
            certs.enrollment("a.example.com").unwrap().unwrap().holding,
            None
        );

        // Routing is untouched by any of it.
        assert_eq!(
            certs
                .enrollment("a.example.com")
                .unwrap()
                .unwrap()
                .tls_backend,
            backend(8443)
        );

        // An unusable name never reaches the bucket, and an unenrolled domain
        // is not created by asking to brand it.
        assert!(matches!(
            certs.set_holding("a.example.com", Some("../x")),
            Err(CertStoreError::InvalidHoldingName { .. })
        ));
        assert!(matches!(
            certs.set_holding("nope.example.com", Some("camp")),
            Err(CertStoreError::NotEnrolled { .. })
        ));
    }

    #[test]
    fn re_enrolling_with_a_different_page_is_refused_rather_than_silently_ignored() {
        // The trap the idempotence check has to avoid: `enroll --holding camp`
        // on an already-enrolled domain must not report success having changed
        // nothing. Changing the page is `set_holding`.
        let (_mem, certs) = store();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();
        let err = certs
            .enroll("a.example.com", &enrollment(8443).with_holding("camp"))
            .unwrap_err();
        assert!(
            matches!(err, CertStoreError::AlreadyEnrolled { .. }),
            "got {err:?}"
        );
        assert_eq!(
            certs.enrollment("a.example.com").unwrap().unwrap().holding,
            None
        );
    }

    #[test]
    fn holding_pages_round_trip_and_refuse_an_oversized_body() {
        let (mem, certs) = store();
        certs
            .write_holding_page("camp", b"<p>camp</p>".to_vec())
            .unwrap();
        assert_eq!(
            certs.holding_page("camp").unwrap().as_deref(),
            Some(&b"<p>camp</p>"[..])
        );
        assert_eq!(certs.holding_pages().unwrap(), vec!["camp".to_string()]);
        assert_eq!(mem.keys(), vec!["holding/camp".to_string()]);

        // Refused at the upload, where a human sees it — the doors would only
        // ever decline to serve it, silently.
        let err = certs
            .write_holding_page("camp", vec![b'x'; MAX_HOLDING_PAGE_BYTES + 1])
            .unwrap_err();
        assert!(
            matches!(err, CertStoreError::HoldingPageTooLarge { .. }),
            "got {err:?}"
        );
        assert_eq!(
            certs.holding_page("camp").unwrap().as_deref(),
            Some(&b"<p>camp</p>"[..]),
            "a refused write must not have replaced the live page"
        );

        // Deleting a page leaves the domains naming it alone: they fall back to
        // passway's own page, and re-uploading restores them.
        certs.delete_holding_page("camp").unwrap();
        assert!(certs.holding_page("camp").unwrap().is_none());
        assert!(certs.holding_pages().unwrap().is_empty());
        certs.delete_holding_page("camp").unwrap(); // idempotent
        assert!(matches!(
            certs.holding_page("../../secrets"),
            Err(CertStoreError::InvalidHoldingName { .. })
        ));
    }
}

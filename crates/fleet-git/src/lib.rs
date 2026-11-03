//! The fleet git remote (W363, R971): `git push fleet` from a camp,
//! `git fetch` from a worker, over the mesh.
//!
//! An axum supervisor execs the host's own `git http-backend` per request
//! ([`gitbin`], [`cgi`]); it authenticates camp-minted cheers tokens
//! ([`auth`]), serialises pushes per repo, owns ref policy from the
//! `pre-receive` hook ([`hook`]), and serves only while it holds the
//! store-claim writer fence ([`fence`]). Every accepted push is in R2 before
//! it is acknowledged ([`stream`], keyed per [`layout`], entries per
//! [`journal`]); [`snapshot`] and [`sweep`] bound what a rehydrate replays,
//! and [`hydrate`] restores the volume from R2 on every start.
//!
//! @arch:see(.yah/docs/working/W363-fleet-git-remote.md)
//!
//! @yah:ticket(R978-T22, "fleet-git exposes its journal head over HTTP and the lander's CampRemote::journal_head() reads it, so per-landing journal entries stop being null")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-miravel)
//! @yah:at(2026-10-24T00:48:34Z)
//! @yah:phase(P1)
//! @yah:parent(R978)
//! @yah:next("Tier: Warrior. Follows R978-T21. Today fleet-git serves only /healthz (epoch), so CampRemote::journal_head() (app/yah/cli/src/lander/) returns None. Add a read-only journal-position field: extend /healthz or add an authenticated GET. Implement journal_head() against it, with tests on both sides. Redeploying fleet-git is out of scope: note the image rebuild and roll it needs.")
//! @yah:depends_on(R978-T21)
//! @yah:handoff("fleet-git /healthz now returns 'ok epoch N' plus one 'journal <repo> <seq>' line per repo (serve.rs healthz_body/journal_heads; seq = volume marker, local file read, no R2 LIST; repos with no marker omitted). Chosen over a new route: counters are non-sensitive and sit beside the already-unauthenticated epoch; first line unchanged so old probes match. Lander: GitRemote::journal_head() (lander/mod.rs) GETs <base>/healthz (5s, scoped thread to dodge reqwest-blocking-in-tokio panic), parses its repo's line; old server => None not 0; local remote => None. Tests: fleet-git +2 unit +1 integration assertion (roundtrip, raw-socket healthz == 'journal yah 4'); lander +2 (parse/url, fake HTTP server).")
//! @yah:handoff("NEEDS ROLL: fleet-git image rebuild + roll of the fleet-git service; until then journal_head_* stay null (older server lists no journal lines). Not rebuilt/pushed/deployed here. Marker trails the journal by one entry between a push's pre- and post-receive, so a record taken mid-push can undercount by 1. W366 'Adoption measurements' still says journal counts are null; update after the roll.")
//! @yah:verify("cd oss/yubaba && cargo test -p fleet-git: 26 lib + 10 roundtrip + 1 tail_cost passed, 0 failed (no pre-edit baseline taken; new tests are 2 unit + 1 assertion)")
//! @yah:verify("cargo test -p yah --lib -- lander relay_land camp_lander_cli: 79 passed, 0 failed (T21 baseline 77, +2)")

pub mod auth;
pub mod cgi;
pub mod fence;
pub mod gitbin;
pub mod hook;
pub mod hydrate;
pub mod journal;
pub mod layout;
pub mod repo;
pub mod serve;
pub mod snapshot;
pub mod stream;
pub mod sweep;

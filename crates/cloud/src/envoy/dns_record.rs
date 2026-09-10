//! `dns.*` verb signatures — initial catalog (R409-T6).
//!
//! Four verbs that cover the DNS plane with Cloudflare as the exemplar
//! tier-S provider (W144 §"dns.* — name resolution"):
//!
//! - `dns.record.upsert` — create or update a DNS record in a named zone
//! - `dns.record.list`   — read the records in a zone (R859-F1)
//! - `dns.record.delete` — remove matching records from a zone
//! - `dns.zone.list`    — enumerate accessible zones
//!
//! `dns.record.list` landed with the first production consumer of this
//! catalog — [`crate::reconciler::ensure_passway_apex`], which reconciles a
//! `front_door = "passway"` apex from declared intent. A reconciler cannot be
//! idempotent without reading current state first, and until R859-F1 there was
//! no read verb at all: `dns.zone.list` enumerates zones, not records.
//!
//! ## Multi-valued RRsets (R859-F1)
//!
//! A round-robin apex carries several A records under one name, so
//! `(name, type)` is **not** a unique key there. Two optional fields exist for
//! exactly that shape and default to the pre-R859 behaviour:
//!
//! - [`DnsRecordUpsertInput::match_content`] — match the record to update by
//!   `(name, type, content)` instead of `(name, type)`. Without it, upserting
//!   a second A record at an apex that already has one *rewrites the first*
//!   rather than adding a sibling, silently collapsing the round-robin to one
//!   origin.
//! - [`DnsRecordDeleteInput::content`] — delete only the records carrying that
//!   exact value, so pruning one withdrawn origin does not take its live
//!   siblings with it.
//!
//! Zone resolution is by apex name (e.g. `"yah.dev"`), not by provider-issued
//! zone ID — the adapter owns the name→id lookup so callers stay
//! provider-agnostic. The `type` field follows the RFC 1035 convention
//! (uppercase strings: `"A"`, `"CNAME"`, `"TXT"`, etc.).
//!
//! @yah:ticket(R859-F1, "Domain reconciler arm for front_door = \"passway\": render A records from the ingress plan via dns.* verbs, retire cf-apex-mode.sh as the flip mechanism")
//! @yah:status(review)
//! @yah:at(2026-09-08T19:00:30Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R859)
//! @yah:next("domain.rs header says it plainly: front_door = \"passway\" 'has no reconciler here yet'. Build the arm: domain manifest + IngressPlan.front_doors → the set of public IPs of machines carrying that edge → dns.record.upsert (DNS-only, proxied=false) through the provider-agnostic dns.* verbs. Idempotent, list-first, like ensure_r2_custom_domain.")
//! @yah:next("This dissolves the two-source front_door flip: the field in domains/*.toml becomes the single source and the reconciler renders it, so a flip is one line + apply instead of cf-apex-mode.sh + a manual TOML edit kept honest only by the publish beacon after the fact (it cost 19 days once, R330-B36, and 4 more, R703-B4).")
//! @yah:next("Growing the public fleet organically falls out: adding a machine with the public-ip taint to an edge's machines list adds its A record on the next apply; removing it withdraws.")
//! @yah:next("Keep cf-apex-mode.sh as break-glass (worker/orange flip under attack per W267 tier ladder) — retire it as the routine mechanism, don't delete it.")
//! @yah:next("Tier: Wizard — new reconciler arm with provider seam, apply/validate wiring, and a live-DNS blast radius that needs careful idempotence tests.")
//! @yah:handoff("LANDED. New passway arm in oss/yubaba/crates/cloud/src/reconciler/domain.rs, house pure-planner/IO-applier shape: public_origins() (collated front-door machine names -> machines carrying the public-ip taint -> connect.address, parsed as a public Ipv4Addr), plan_domain_passway() (front_door guard, sort+dedup by address, apex zone via parent_zone_name), diff_apex_records() (upsert/prune against the live A set), deploy_domain_passway() (list-first, skip-when-converged, upsert BEFORE prune, proxied=false always), and ensure_passway_apex() as the entry point yah cloud apply calls. Exported from reconciler/mod.rs. Apply wiring: app/yah/cli/src/cloud.rs:10944 `if dom.front_door != BucketDirect { Skipped }` became a 3-arm match — bucket-direct and passway both reconcile now, worker stays a Skip with a reason naming the Worker pass. domain.rs header sentence 'has no reconciler here yet' replaced.")
//! @yah:handoff("DNS PRIMITIVES (decision 1, plus two additive fields that decision needed). New verb dns.record.list in envoy/dns_record.rs (zone + optional name + optional type -> records with id/name/type/content/ttl/proxied), registered in envoy.rs known_verb_descriptors + the ID assertion list (count 11 -> 12), implemented in provider/cloudflare_envoy.rs against GET /zones/{id}/dns_records via a new CloudflareClient::list_dns_records + pub DnsRecordDetail struct. TWO EXTRA FIELDS WERE UNAVOIDABLE and are the discovered work of this ticket: (a) DnsRecordUpsertInput.match_content (default false = pre-R859 behaviour) — CloudflareClient::upsert_dns_record matches on (name,type) and updates the FIRST match, so upserting a 2nd A record at an apex that already has one REWRITES the first and silently collapses the round-robin to one origin; new delegating CloudflareClient::upsert_dns_record_matching keys on (name,type,content) when set. (b) DnsRecordDeleteInput.content (Option, mirrors the existing record_type filter) — deleting 'the A records at yah.dev' to prune ONE withdrawn origin would take the live siblings with it; new delegating CloudflareClient::delete_dns_records_matching. Both old public signatures are unchanged and delegate, so nothing outside this ticket had to move.")
//! @yah:handoff("TESTS + BASELINE. Baseline measured BEFORE editing at tree anchor 4bed91fe: `cargo test --manifest-path oss/yubaba/crates/cloud/Cargo.toml --features json-schema` = lib 1104 passed / 0 failed / 4 ignored, tests/main.rs 3/0/1, pond_smoke 2/0, doc-tests 0/0/1. After: lib 1121 passed / 0 failed / 4 ignored (+17), other three targets unchanged. Also green: `cargo test -p yah --lib` 1442/0, `cargo test -p yah-agent-tools --lib` 1221/0, `cargo build --workspace` EXIT=0. New pure-planner tests in domain.rs's test module cover every case the dispatch asked for: converged set is a no-op; added machine yields exactly one added record and no prune; removed machine yields exactly one prune (type A) and leaves the survivor untouched; non-public address (100.64/10 tailnet, 10/8, 192.168/16, 127.0.0.1) and unparseable address are errors naming the machine; EMPTY front-door set is an error, not a wipe (`refusing to render an empty apex`). Plus: taint filter keeps only public-ip machines, plan sorts+dedups by address, front_door guard, a proxied record at a desired address is rewritten (not left orange, not pruned), full origin swap produces upsert+prune so the ordering contract holds.")
//! @yah:handoff("ALSO TOUCHED (discovered work, all forced by the two new verb fields). app/yah/desktop/src/cloudflare.rs:210 constructs DnsRecordUpsertInput literally for tunnel CNAME sync — added `match_content: false` with a comment saying why a tunnel hostname is single-valued. crates/yah/agent-tools/src/envoy_tools.rs READ_VERB_IDS gained \"dns.record.list\": it is a pure read, and leaving it out would have had the agent tool surface classify it as a write and gate it behind write approval. scripts/cf-apex-mode.sh: header rewritten per decision 10 — every behaviour KEPT, but it is now labelled break-glass only, with the four jobs that remain its alone enumerated (worker rollback, orange flip under attack, `status` read, the CF-1052 R2-custom-domain diagnostic) and a note that a stale front_door will now actively UNDO an un-declared flip on the next apply rather than merely disagreeing with it. No manifest fields added (decisions 2/3/8), no new global lint in validate.rs (decision 4), R2 and worker arms untouched (decision 9), no schema regen needed (no config type moved; .yah/schema/ holds no envoy verb schemas).")
//! @yah:assumes("Decision 5, recorded as instructed: the apex round-robins across EVERY node in collate_workspace_ingress(...).collation.front_doors whose provider is IngressProvider::Passway and that carries the public-ip taint. It does NOT filter by whether that node actually serves the specific domain's [[routes]]. This matches scripts/cf-apex-mode.sh's CF_ORIGIN_IP list semantics, and is correct while the camp has exactly one passway domain (yah.dev) and one passway edge. A second passway domain fronted by a different subset of nodes would get the union, not its own subset — that is the assumption to revisit first.")
//! @yah:assumes("deploy_domain_passway's I/O path has NOT been exercised against a live Cloudflare account (no creds in this session) — same status the worker arm's doc comment records for itself. The decision logic is fully covered offline; treat the first real `yah cloud apply` against yah.dev as the acceptance test, and run it while the current apex A records are known so a wrong prune is visible immediately.")
//! @yah:gotcha("Peer activity on the shared tree during this session, none of it mine and none needing action: (1) `cargo build --workspace` was transiently RED mid-session on yah-workload-spec (E0425 DURABILITY_ENGINE_ANNOTATION / DURABILITY_SUBJECTS_ANNOTATION undefined) from a peer's half-landed 166-line addition to oss/yah-base/crates/workload-spec/src/lib.rs — it went green on its own once they finished, and the final workspace build is EXIT=0. (2) app/yah/cli/src/cloud.rs carries two hunks that are not mine: the removal of the R856-F8 annotation block from the module header (an archive by another session), separate from my hunk at the domain apply loop. No collision — different regions of the file.")
//! @yah:cleanup("Followup CANDIDATE, deliberately not filed (decision 8 said mention, do not file): the domain manifest has no `use = \"&lt;id&gt;\"` provider slot, so the apply site still hardcodes DOMAIN_CF_PROVIDER = \"cloudflare\" (app/yah/cli/src/cloud.rs:10939). The passway arm is already provider-agnostic ABOVE that line — every read and write goes through the dns.* envoy verbs — so giving domains a provider slot is now purely a config-plumbing change, and it is what would let a second DNS provider (the .yah/envoys/digitalocean sketch exists) serve an apex.")
//! @yah:cleanup("parent_zone_name's two-label heuristic is REUSED here and is fine for this ticket (yah.dev is a two-label apex, so zone == name), but the limitation is unchanged and still noted at domain.rs's deploy_domain_worker caveat: a passway domain under an alias tier (net.yah.dev / com.yah.dev, which are their own CF zones) would resolve to the wrong zone. Not fixed here per the dispatch; the upgrade path is the longest-suffix match against dns.zone.list that parent_zone_name's own doc already names — and dns.zone.list is right there in the catalog now.")
//! @yah:verify("cargo test --manifest-path oss/yubaba/crates/cloud/Cargo.toml --features json-schema  (lib 1121 passed / 0 failed vs baseline 1104/0 at anchor 4bed91fe)")
//! @yah:verify("cargo build --workspace && cargo test -p yah --lib && cargo test -p yah-agent-tools --lib  (all EXIT=0; 1442/0 and 1221/0)")
//! @yah:handoff("PRUNE GATE (Leader's verification finding, fixed). ensure_passway_apex never inspected report.problems, and collate_workspace_ingress returns Ok while SKIPPING an edge whose declaration fails to plan — so a passway edge with a config typo drops its machine from front_doors, which from inside the plan is indistinguishable from an operator withdrawal, and the arm would have pruned that origin's live A record. A typo becoming a DNS withdrawal. Fix, per the decision handed down: fail-closed on withdrawal, fail-open on addition. DomainPasswayPlan gained `origins_complete: bool` (plan_domain_passway takes it as a third arg); ensure_passway_apex sets it from `report.problems.is_empty()` and warns once per problem via IngressProblem::message(). diff_apex_records routes surplus records into a new ApexRecordDiff.withheld_prune instead of prune when the flag is false — upserts are untouched, so growing the fleet still works through another service's broken declaration, and problems never fail the arm. deploy_domain_passway warns naming the withheld records BEFORE the converged early-return (the record stays live either way), and PasswayApexOutcome.withheld_prune carries them to the apply site, which prints `KEPT A <domain> -> <ip> (ingress collation reported problems — run yah cloud validate)`. The empty-set guard stays ahead of the gate: an empty origin set is an error whether or not the collation was clean, so it cannot degrade into a silent everything-withheld apply. deploy_domain_passway's doc comment now states the contract as a third invariant beside list-first and upsert-before-prune.")
//! @yah:handoff("NUMBERS AFTER THE PRUNE GATE, superseding the counts in the TESTS + BASELINE entry above: yah-cloud lib 1124 passed / 0 failed / 4 ignored (was 1121 at the first pass, 1104 at the pre-edit baseline measured at anchor 4bed91fe); tests/main.rs 3/0/1, pond_smoke 2/0, doc-tests 0/0/1 all unchanged; `cargo build --workspace` EXIT=0. Three tests added for the gate: an incomplete collation upserts but withholds every prune (with a clean-collation control on the same inputs proving the gate is what changed the outcome); the empty-origin-set error still fires on an incomplete collation, so the louder failure stays ahead of the quieter one; and a withheld-prune-only diff reports is_converged (no write to make) while still carrying the withheld record. Leader's independent pass measured `cargo test -p yah --lib` at 1444/0 against my 1442/0 — peer drift on the shared tree, not a discrepancy in this work.")
//! @yah:assumes("Both earlier assumes still hold as written; this one sharpens the first. The union-not-subset assumption above and the new prune gate come due at the SAME moment — the second passway edge. Today `report.problems` non-empty plus one passway edge collapses into the guarded empty-set error, so the gate is inert; with two edges it becomes the thing standing between a config typo and a live DNS withdrawal, and the union behaviour becomes the thing deciding which origins a second passway domain publishes. Whoever adds the second passway edge should re-read both together rather than either alone.")
//! @yah:handoff("LEADER SIGN-OFF (independently verified, not taken on the courier's word). Two verification passes by a separate session re-ran the builds and traced the code. Pass 1 confirmed: upsert loop strictly precedes prune loop with provably disjoint sets; empty-origin-set is a hard error, not a wipe; the prune passes BOTH record_type Some(\"A\") and content Some(ip) through cloudflare_envoy.rs into the client-side filter, so MX/TXT/AAAA/CNAME are unreachable; the pre-change upsert_dns_record did take find_dns_record's first (name,type) match, match_content defaults false and only the passway arm sets true; proxied is always false with an existing orange record at a desired address rewritten rather than left; old public signatures delegate unchanged with the sole live caller untouched; dns.record.list registered in the catalog with the ID-assertion count 11 -> 12 and listed in READ_VERB_IDS so it is not gated as a write; the apply site is a real 3-arm match with Worker still a Skip; cf-apex-mode.sh has exactly one comment-only hunk. Pass 2 (after the prune-gate increment) re-confirmed all of it plus the gate itself.")
//! @yah:handoff("Tree anchor at handoff: f086233d6b092de2f32cafad5e0010494078269c — the shared tree as I left it. Diff against it (`git diff f086233d6b092de2f32cafad5e0010494078269c..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:handoff("DISCOVERED DEFECT, found by leader verification and fixed in-run rather than filed. The first-pass arm never inspected report.problems, and collate_workspace_ingress returns Ok while SKIPPING an edge whose declaration fails to plan (validate.rs:870-879) — so a config typo in a passway declaration would drop that machine from front_doors, the arm would read the absence as an operator withdrawal, and it would PRUNE a live A record. A typo becoming a DNS withdrawal is exactly the failure class this ticket exists to remove. Directed fix, landed: gate the PRUNE, not the upsert. DomainPasswayPlan.origins_complete is set from report.problems.is_empty() at its single non-test construction site (domain.rs:671, so the flag cannot be forged); when false, surplus records route into ApexRecordDiff.withheld_prune instead of prune. Upserts are computed above the branch and are unaffected, so growing the fleet keeps working under a broken unrelated declaration; nothing is ever withdrawn from an untrusted picture. Fail-closed on withdrawal, fail-open on addition. The arm does NOT fail on unrelated ingress problems — one broken service declaration must not block DNS apply. warn! naming each withheld record fires BEFORE the converged early-return, so a no-op apply still tells the operator, and PasswayApexOutcome carries them to app/yah/cli/src/cloud.rs:11002-11008 as a KEPT line printed outside the is_noop branch.")
//! @yah:handoff("LIVE ACCEPTANCE RUN AND GREEN — the one item the previous handoff left open is closed, and it is now a repeatable in-tree check rather than a manual procedure. New `oss/yubaba/crates/cloud/tests/passway_apex_live.rs` (`#[ignore]`d, `mod`'d into tests/main.rs) runs the REAL planner over the checked-in `.yah/` tree, reads the REAL yah.dev zone through the REAL `dns.record.list` verb against the REAL Cloudflare account, and runs the REAL `diff_apex_records` over the pair. Result 2026-09-08: `zone yah.dev / name yah.dev; declared 45.32.194.254 (us-south-001), 51.81.85.145 (us-east-001); live 45.32.194.254, 51.81.85.145; diff ApexRecordDiff { upsert: [], prune: [], withheld_prune: [] }` — converged, so `yah cloud apply`'s domain pass has no DNS write to make. That is exactly what the old verify item's \"second apply writes nothing\" was meant to demonstrate, established WITHOUT performing the first apply. Independently corroborated by `dig +short yah.dev A` (same two addresses) and `yah cloud validate` (\"2 node front door(s) collate cleanly\", so origins_complete = true and the prune gate is not masking anything).")
//! @yah:handoff("HOW THE CHECK IS SAFE TO LEAVE RUNNABLE — two small extractions in domain.rs, no behaviour change to any existing path. (1) `ensure_passway_apex` split into `plan_passway_apex(workspace_root, domain) -> Result<DomainPasswayPlan>` (pure: collate + taint/address resolve + plan, no network, no credential, no write path) plus the two-line applier that hands that plan to `deploy_domain_passway`; the `report.problems` prune-gate doc moved down onto the planner, where the code now lives. (2) `deploy_domain_passway`'s credential+list preamble split into private `passway_envoy()` / `read_live_apex()` and a public read-only `list_live_apex_records(workspace_root, provider_id, plan)`. The test calls ONLY those two public functions, so it physically cannot write — `dns.record.upsert` / `dns.record.delete` live in the half it does not touch. That is the point: a failure is a report, never a change, which is what lets the acceptance check live in-tree instead of in a handoff as a thing someone should do by hand one day. Both new symbols exported from reconciler/mod.rs. The apply path is unchanged: one credential resolution, same list-then-diff-then-write order.")
//! @yah:handoff("DISCOVERED WORK: the domain manifest was still teaching the retired mechanism. `.yah/domains/yah-dev.toml`'s \"two shapes, and one command between them\" block told the next reader to flip the apex with `CF_ORIGIN_IP=51.81.85.145,45.32.194.254 scripts/cf-apex-mode.sh grey --apply` — the exact two-source flip this ticket exists to dissolve, sitting in the file whose `front_door` field is now the single source. Comment-only edit (no key changed, `yah cloud validate` re-run green): the passway arrow is now \"set `front_door = \\\"passway\\\"` below and `yah cloud apply`\", with a paragraph saying R859-F1 made this field the mechanism rather than the record of one, that the CF_ORIGIN_IP list is no longer typed by hand anywhere, and that using the script to flip without fixing this line no longer merely disagrees with the manifest — the next apply actively UNDOES it. cf-apex-mode.sh's own header already carried the break-glass framing from the first pass; this is the other half of that sentence, on the file an operator actually opens to do a flip.")
//! @yah:handoff("Tree anchor for this increment: af805057ba632298d3e7e53c0197a164ed413824 (HEAD when the work landed; all five edited files were uncommitted against it). Quote this SHA, not 'HEAD', in any revert instruction. Files: oss/yubaba/crates/cloud/src/reconciler/domain.rs, .../reconciler/mod.rs, .../tests/main.rs, NEW .../tests/passway_apex_live.rs, .yah/domains/yah-dev.toml (comment-only). dns_record.rs is modified only by the board annotation this claim wrote.")
//! @yah:handoff("REVIEW-READY. The one item the previous handoff left open — live acceptance — is closed and green, and is now a repeatable in-tree check rather than a manual procedure someone would have to remember. Everything else in this ticket's prior handoff entries still stands as written and was re-verified green this session.")
//! @yah:verify("LIVE ACCEPTANCE, RUN 2026-09-08, GREEN: `cargo test --manifest-path oss/yubaba/crates/cloud/Cargo.toml --features json-schema --test main -- --ignored --nocapture passway_apex_live` = 1 passed / 0 failed. Real planner + real dns.record.list against the real Cloudflare account: declared {45.32.194.254 us-south-001, 51.81.85.145 us-east-001}, live {45.32.194.254, 51.81.85.145}, diff {upsert: [], prune: [], withheld_prune: []}. The zone already matches the declaration, so the domain pass of `yah cloud apply` writes nothing.")
//! @yah:verify("Corroborated independently of the code under test: `dig +short yah.dev A` returns the same two addresses; `yah cloud validate` reports '2 node front door(s) collate cleanly' (origins_complete = true, so no prune was silently withheld); both front-door machines carry taints = [... \"public-ip\"] with connect.address = the public IPv4 (.yah/infra/machines/us-east-001.toml:103, us-south-001.toml:96).")
//! @yah:verify("cargo test --manifest-path oss/yubaba/crates/cloud/Cargo.toml --features json-schema = lib 1152 passed / 0 failed / 4 ignored; tests/main 3 passed / 0 failed / 2 ignored (was 1 ignored — the new live check is the second); pond_smoke 2/0; doc-tests 0/0/1.")
//! @yah:verify("cargo build --workspace EXIT=0 (twice, 4m21s and 7m07s — the camp's skew guard flagged concurrent peer edits to unrelated yubaba files on the first, hence the re-run). cargo clippy --manifest-path oss/yubaba/crates/cloud/Cargo.toml --features json-schema --all-targets: zero errors, and no new warning at any line this session touched.")
//! @yah:verify("yah cloud validate re-run green AFTER the .yah/domains/yah-dev.toml comment edit, confirming the manifest still parses and cross-resolves.")
//! @yah:assumes("The live check proves the DECISION path and the READ path against real Cloudflare; the WRITE path (dns.record.upsert / dns.record.delete) is still unexercised live, and cannot be exercised without deliberately diverging the apex. Its first real exercise will be the next actual origin change — add or remove a public-ip machine from the passway edge and the next apply is the write-path acceptance test. Watch it with `scripts/cf-apex-mode.sh status` open.")
//! @yah:assumes("I did NOT run a real `yah cloud apply`. Deliberate, and the reason is scope rather than caution: the domain pass is proven a no-op by the check above, while `yah cloud apply` also publishes to R2 and reconciles every service — a far wider outward-facing action than this ticket, and running it would prove nothing about the apex that the check has not already proven.")
//! @yah:gotcha("DEFECT IN THIS TICKET'S OWN SHIPPED CHANGE, found 2026-09-08 by auditing the NOISETABLE camp and fixed here before sign-off. Making the apply site reconcile `passway` (it used to `Skip` every non-bucket-direct door) turns a legitimate state into a fatal apply for any camp that declares `front_door = \\\"passway\\\"` before the passway edge exists. noisetable.com is exactly that: it declares passway, its only ingress edge is a `cloudflare-tunnel` on api.noisetable.com, and its apex is deliberately NXDOMAIN pending a node. The chain, all read not inferred: ensure_passway_apex filters front_doors to IngressProvider::Passway -> empty -> plan_domain_passway's empty-apex guard bails (domain.rs) -> the apply site pushes DomainOutcome::Failed and then `bail!(\\\"apply stopped at first domain failure\\\")` unless --continue-on-error (app/yah/cli/src/cloud.rs:11055-11063). One not-yet-built door would have taken down the publish chain for every service and every other domain in that camp — and noisetable had deliberately engineered `front_door = \\\"passway\\\"` precisely to KEEP that chain green (its manifest says so).")
//! @yah:handoff("FIX FOR THAT DEFECT (refines the dispatch's \\\"EMPTY front-door set is an error\\\" decision rather than reversing it — the decision's PURPOSE was never wipe an apex, and skipping serves that purpose equally, writing nothing at all). The discriminator is drawn at the COLLATION, not at the resolved-address set, because an absent edge and an edge that resolves to nothing want opposite treatment. plan_passway_apex now returns Result&lt;Option&lt;DomainPasswayPlan&gt;&gt;, None = no passway edge collates at all. plan_domain_passway is UNCHANGED and still errors on an empty origin set, so a declared front-door machine that lacks the public-ip taint or carries a private address is still a hard error — an intended door resolving to nothing is a misconfiguration, not an absence. ensure_passway_apex returns Result&lt;Option&lt;PasswayApexOutcome&gt;&gt; and, on None, does ONE more thing before skipping: it reads the live A records at the apex. Empty -&gt; the door was never stood up, skip quietly. Non-empty -&gt; an edge that WAS fronting this apex has vanished from the declaration and those records now point at whatever used to serve; that is a hard error naming every live address. The read is free in practice — this arm only runs inside the domain pass, which already resolved a Cloudflare provider and account_id before entering the loop. read_live_apex was retargeted from (&amp;plan) to (&amp;zone, &amp;name) so the no-plan branch can use it. Apply site prints `no passway ingress edge declared yet and the apex is empty — nothing rendered`.")
//! @yah:verify("AFTER THE NOISETABLE FIX, superseding the counts above: yah-cloud lib 1138 passed / 0 failed / 4 ignored (was 1136; +2 tests). Both new tests pin the discriminator from opposite sides — a_passway_domain_with_no_ingress_edge_plans_to_none_rather_than_erroring builds a tempdir workspace with a services tree and no edge and asserts Ok(None) (empirical, not reasoned: this is the noisetable shape), and a_declared_front_door_that_resolves_to_no_public_address_still_errors declares us-east-001 as a front door WITHOUT the public-ip taint and asserts the empty-apex error still fires, so the fix cannot be read as \\\"empty is always fine\\\". tests/main 3/0/2, pond_smoke 2/0, doc-tests 0/0/1 unchanged. `cargo build --workspace` EXIT=0. LIVE ACCEPTANCE RE-RUN after the signature change and still green — same converged diff on yah.dev, confirming a camp that HAS its door is unaffected by the skip path.")

use serde::{Deserialize, Serialize};

use super::{InternalVerb, VerbCategory};

// ── dns.record.upsert ─────────────────────────────────────────────────────

/// Marker type for the `dns.record.upsert` verb.
pub struct DnsRecordUpsert;

/// Request body for `dns.record.upsert`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct DnsRecordUpsertInput {
    /// Zone apex name, e.g. `"yah.dev"`. The adapter resolves it to a
    /// provider-issued zone ID.
    pub zone: String,
    /// Fully-qualified record name, e.g. `"yubaba.yah.dev"`. Apex records
    /// may also be passed as `"@"` — adapters normalise as needed.
    pub name: String,
    /// DNS record type (`"A"`, `"AAAA"`, `"CNAME"`, `"TXT"`, `"MX"`, …).
    #[serde(rename = "type")]
    pub record_type: String,
    /// Record value: for CNAME the target hostname; for A/AAAA the IP; for
    /// TXT the verbatim string content.
    pub content: String,
    /// TTL in seconds. `1` means "automatic" (effective TTL chosen by the
    /// provider). Defaults to `1`.
    #[serde(default = "ttl_auto")]
    pub ttl: u32,
    /// Route through Cloudflare's reverse proxy (orange-cloud). Only
    /// meaningful on Cloudflare for A/AAAA/CNAME records; adapters for
    /// other providers should ignore this field. Defaults to `false`.
    #[serde(default)]
    pub proxied: bool,
    /// Match the record to replace by `(name, type, content)` rather than
    /// `(name, type)` — R859-F1.
    ///
    /// `false` (the default, and the only shape before R859) is right for a
    /// single-valued name: "whatever CNAME is at `cdn.yah.dev`, make it point
    /// here". `true` is required for a **multi-valued RRset** such as a
    /// round-robin apex, where several A records legitimately share
    /// name+type: it turns the verb into ensure-this-exact-record-exists, so
    /// building a 2-origin apex is two upserts rather than one upsert that
    /// overwrites the other origin.
    #[serde(default)]
    pub match_content: bool,
}

fn ttl_auto() -> u32 {
    1
}

/// Response body for `dns.record.upsert`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct DnsRecordUpsertOutput {
    /// Provider-issued record ID. Stable for the lifetime of the record;
    /// can be used in `dns.record.delete` to target a specific record by ID
    /// instead of name+type once that verb shape grows an `id` field.
    pub id: String,
}

impl InternalVerb for DnsRecordUpsert {
    type Input = DnsRecordUpsertInput;
    type Output = DnsRecordUpsertOutput;
    const ID: &'static str = "dns.record.upsert";
    const CATEGORY: VerbCategory = VerbCategory::Dns;
}

// ── dns.record.delete ─────────────────────────────────────────────────────

/// Marker type for the `dns.record.delete` verb.
pub struct DnsRecordDelete;

/// Request body for `dns.record.delete`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct DnsRecordDeleteInput {
    /// Zone apex name, e.g. `"yah.dev"`.
    pub zone: String,
    /// Record name to delete, e.g. `"yubaba.yah.dev"`.
    pub name: String,
    /// Filter by record type. When absent, all records matching `name` are
    /// deleted regardless of type. Pass `"CNAME"` to delete only CNAME
    /// records for the name, for example.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub record_type: Option<String>,
    /// Filter by exact record value — R859-F1. When absent, every record
    /// matching `name` (and `record_type`) is deleted.
    ///
    /// Present so a caller pruning one member of a multi-valued RRset can name
    /// it: deleting "the A records at `yah.dev`" would take the surviving
    /// origins down with the withdrawn one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

/// Response body for `dns.record.delete`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct DnsRecordDeleteOutput {
    /// Count of records actually deleted. `0` is not an error — the record
    /// may already have been absent (idempotent).
    pub deleted: u32,
}

impl InternalVerb for DnsRecordDelete {
    type Input = DnsRecordDeleteInput;
    type Output = DnsRecordDeleteOutput;
    const ID: &'static str = "dns.record.delete";
    const CATEGORY: VerbCategory = VerbCategory::Dns;
}

// ── dns.record.list ───────────────────────────────────────────────────────

/// Marker type for the `dns.record.list` verb (R859-F1).
pub struct DnsRecordList;

/// Request body for `dns.record.list`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct DnsRecordListInput {
    /// Zone apex name, e.g. `"yah.dev"`.
    pub zone: String,
    /// Restrict to records with this exact name, e.g. `"yah.dev"` for the
    /// apex. When absent, every record in the zone is returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Restrict to one record type (`"A"`, `"CNAME"`, …). When absent, every
    /// type is returned — which is why a caller that only owns the A records
    /// at a name must pass `"A"`: MX and TXT live at the apex too.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub record_type: Option<String>,
}

/// One live DNS record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct DnsRecordEntry {
    /// Provider-issued record ID — the same identifier
    /// [`DnsRecordUpsertOutput::id`] returns.
    pub id: String,
    /// Fully-qualified record name, e.g. `"yah.dev"`.
    pub name: String,
    /// DNS record type (`"A"`, `"CNAME"`, `"TXT"`, …).
    #[serde(rename = "type")]
    pub record_type: String,
    /// Record value: the IP for A/AAAA, the target hostname for CNAME, …
    pub content: String,
    /// TTL in seconds; `1` means the provider chooses.
    #[serde(default = "ttl_auto")]
    pub ttl: u32,
    /// Whether the provider proxies this record (Cloudflare orange-cloud).
    /// Always `false` from providers with no such concept.
    #[serde(default)]
    pub proxied: bool,
}

/// Response body for `dns.record.list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct DnsRecordListOutput {
    /// Matching records, in provider order. An empty list is not an error.
    pub records: Vec<DnsRecordEntry>,
}

impl InternalVerb for DnsRecordList {
    type Input = DnsRecordListInput;
    type Output = DnsRecordListOutput;
    const ID: &'static str = "dns.record.list";
    const CATEGORY: VerbCategory = VerbCategory::Dns;
}

// ── dns.zone.list ─────────────────────────────────────────────────────────

/// Marker type for the `dns.zone.list` verb.
pub struct DnsZoneList;

/// Request body for `dns.zone.list`. Empty — zone listing requires no
/// parameters beyond the adapter's credential scope.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct DnsZoneListInput {}

/// One zone entry in the `dns.zone.list` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct DnsZoneEntry {
    /// Provider-issued zone ID. Opaque; stable within a provider.
    pub id: String,
    /// Zone apex name, e.g. `"yah.dev"`.
    pub name: String,
}

/// Response body for `dns.zone.list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct DnsZoneListOutput {
    pub zones: Vec<DnsZoneEntry>,
}

impl InternalVerb for DnsZoneList {
    type Input = DnsZoneListInput;
    type Output = DnsZoneListOutput;
    const ID: &'static str = "dns.zone.list";
    const CATEGORY: VerbCategory = VerbCategory::Dns;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verb_ids_match_canonical_namespace() {
        assert_eq!(DnsRecordUpsert::ID, "dns.record.upsert");
        assert_eq!(DnsRecordList::ID, "dns.record.list");
        assert_eq!(DnsRecordDelete::ID, "dns.record.delete");
        assert_eq!(DnsZoneList::ID, "dns.zone.list");
        for id in [
            DnsRecordUpsert::ID,
            DnsRecordList::ID,
            DnsRecordDelete::ID,
            DnsZoneList::ID,
        ] {
            assert!(id.starts_with("dns."), "{id}");
        }
    }

    #[test]
    fn verbs_are_under_dns_category() {
        assert_eq!(DnsRecordUpsert::CATEGORY, VerbCategory::Dns);
        assert_eq!(DnsRecordList::CATEGORY, VerbCategory::Dns);
        assert_eq!(DnsRecordDelete::CATEGORY, VerbCategory::Dns);
        assert_eq!(DnsZoneList::CATEGORY, VerbCategory::Dns);
    }

    #[test]
    fn upsert_input_defaults_ttl_to_auto_and_proxied_false() {
        let wire = r#"{"zone":"yah.dev","name":"yubaba.yah.dev","type":"CNAME","content":"t.cfargotunnel.com"}"#;
        let parsed: DnsRecordUpsertInput = serde_json::from_str(wire).unwrap();
        assert_eq!(parsed.ttl, 1, "default TTL should be 1 (automatic)");
        assert!(!parsed.proxied, "default proxied should be false");
        assert!(
            !parsed.match_content,
            "default must stay match-by-(name,type) — R859-F1 added the field"
        );
    }

    /// R859-F1: a round-robin apex needs upserts keyed on content, otherwise
    /// the second origin overwrites the first.
    #[test]
    fn upsert_input_accepts_match_content() {
        let wire = r#"{"zone":"yah.dev","name":"yah.dev","type":"A","content":"51.81.85.145","match_content":true}"#;
        let parsed: DnsRecordUpsertInput = serde_json::from_str(wire).unwrap();
        assert!(parsed.match_content);
    }

    /// R859-F1: pruning one withdrawn origin must not be expressible only as
    /// "delete the A records at the apex".
    #[test]
    fn delete_input_content_filter_is_optional_and_omitted_when_absent() {
        let with_content =
            r#"{"zone":"yah.dev","name":"yah.dev","type":"A","content":"15.204.89.240"}"#;
        let parsed: DnsRecordDeleteInput = serde_json::from_str(with_content).unwrap();
        assert_eq!(parsed.content.as_deref(), Some("15.204.89.240"));

        let bare = DnsRecordDeleteInput {
            zone: "yah.dev".into(),
            name: "yah.dev".into(),
            record_type: Some("A".into()),
            content: None,
        };
        let wire = serde_json::to_value(&bare).unwrap();
        assert!(!wire.as_object().unwrap().contains_key("content"));
    }

    #[test]
    fn record_list_input_omits_absent_filters() {
        let input = DnsRecordListInput {
            zone: "yah.dev".into(),
            ..Default::default()
        };
        let wire = serde_json::to_value(&input).unwrap();
        assert_eq!(wire, serde_json::json!({"zone": "yah.dev"}));
    }

    #[test]
    fn record_list_output_round_trips_with_type_renamed() {
        let out = DnsRecordListOutput {
            records: vec![DnsRecordEntry {
                id: "r1".into(),
                name: "yah.dev".into(),
                record_type: "A".into(),
                content: "51.81.85.145".into(),
                ttl: 1,
                proxied: false,
            }],
        };
        let wire = serde_json::to_value(&out).unwrap();
        assert_eq!(wire["records"][0]["type"], "A");
        assert!(wire["records"][0].get("record_type").is_none());
        let back: DnsRecordListOutput = serde_json::from_value(wire).unwrap();
        assert_eq!(back.records, out.records);
    }

    #[test]
    fn upsert_input_type_renamed_in_wire() {
        let wire = r#"{"zone":"yah.dev","name":"a.yah.dev","type":"A","content":"1.2.3.4","ttl":300,"proxied":true}"#;
        let parsed: DnsRecordUpsertInput = serde_json::from_str(wire).unwrap();
        assert_eq!(parsed.record_type, "A");
        assert_eq!(parsed.ttl, 300);
        assert!(parsed.proxied);
        // Verify the Rust field serializes back as "type".
        let back = serde_json::to_value(&parsed).unwrap();
        assert!(back.get("type").is_some(), "should serialize as 'type'");
        assert!(
            back.get("record_type").is_none(),
            "should not serialize as 'record_type'"
        );
    }

    #[test]
    fn delete_input_type_optional() {
        let with_type = r#"{"zone":"yah.dev","name":"old.yah.dev","type":"CNAME"}"#;
        let parsed: DnsRecordDeleteInput = serde_json::from_str(with_type).unwrap();
        assert_eq!(parsed.record_type.as_deref(), Some("CNAME"));

        let no_type = r#"{"zone":"yah.dev","name":"old.yah.dev"}"#;
        let parsed: DnsRecordDeleteInput = serde_json::from_str(no_type).unwrap();
        assert!(parsed.record_type.is_none());
    }

    #[test]
    fn delete_input_omits_type_when_absent() {
        let input = DnsRecordDeleteInput {
            zone: "z".into(),
            name: "n".into(),
            record_type: None,
            content: None,
        };
        let wire = serde_json::to_value(&input).unwrap();
        assert!(!wire.as_object().unwrap().contains_key("type"));
    }

    #[test]
    fn delete_output_zero_is_not_an_error() {
        let out = DnsRecordDeleteOutput { deleted: 0 };
        let wire = serde_json::to_value(&out).unwrap();
        assert_eq!(wire["deleted"], 0);
    }

    #[test]
    fn zone_list_input_serializes_to_empty_object() {
        let wire = serde_json::to_value(DnsZoneListInput::default()).unwrap();
        assert_eq!(wire, serde_json::json!({}));
    }

    #[test]
    fn zone_list_output_round_trips() {
        let out = DnsZoneListOutput {
            zones: vec![
                DnsZoneEntry {
                    id: "z1".into(),
                    name: "yah.dev".into(),
                },
                DnsZoneEntry {
                    id: "z2".into(),
                    name: "noisetable.com".into(),
                },
            ],
        };
        let wire = serde_json::to_string(&out).unwrap();
        let back: DnsZoneListOutput = serde_json::from_str(&wire).unwrap();
        assert_eq!(back.zones.len(), 2);
        assert_eq!(back.zones[0].name, "yah.dev");
    }

    #[cfg(feature = "json-schema")]
    #[test]
    fn verbs_emit_schemas_via_for_verb() {
        use super::super::VerbDescriptor;

        let upsert = VerbDescriptor::for_verb::<DnsRecordUpsert>();
        assert_eq!(upsert.id, "dns.record.upsert");
        assert!(upsert.input_schema.to_string().contains("content"));

        let delete = VerbDescriptor::for_verb::<DnsRecordDelete>();
        assert_eq!(delete.id, "dns.record.delete");
        assert!(delete.output_schema.to_string().contains("deleted"));

        let list = VerbDescriptor::for_verb::<DnsZoneList>();
        assert_eq!(list.id, "dns.zone.list");
        assert!(list.output_schema.to_string().contains("zones"));

        let records = VerbDescriptor::for_verb::<DnsRecordList>();
        assert_eq!(records.id, "dns.record.list");
        assert!(records.output_schema.to_string().contains("records"));
    }
}

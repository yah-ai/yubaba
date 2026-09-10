//! Publishing the SNI demux's route table from the enrollment set (R779 / W267).
//!
//! [`crate::cert_store`] holds the enrollment set — one `enrolled/<domain>`
//! object per registered domain, naming the per-tenant passway that serves it.
//! `passway-demux` on `:443` routes on a `host=addr` table. This module is the
//! one-way pipe between them: sweep the set, render the table, write it where
//! the demux reloads it.
//!
//! ## Why a file and not a socket
//!
//! The demux is a trust-boundary process that deliberately links no TLS stack
//! and no HTTP client (`sni-demux/src/lib.rs`), and giving it an R2 client and
//! this bucket's credentials would hand a compromise of the *shared* process a
//! read of every tenant's routing — and a set of credentials — that it currently
//! cannot reach. A file it re-reads is the smallest surface that closes the
//! loop: yubaba (which already holds the credentials, and the KEK) writes; the
//! demux reads bytes off local disk.
//!
//! ## Fail-closed, which here means *fail-stale*
//!
//! Two refusals, both about the same failure: this node's view of the bucket is
//! not authority over the fleet's routing.
//!
//! - **A listing failure never writes.** The previous file stays, and the demux
//!   keeps serving the routes it has. An R2 blip must not de-route the fleet.
//! - **An empty render never writes.** A successful listing of an empty bucket
//!   and a bucket pointed at the wrong prefix produce the identical answer, and
//!   one of them is an outage for every tenant. The cost is that unenrolling the
//!   *last* domain does not propagate until the demux is restarted, which is the
//!   right way round.
//!
//! The write itself is tmp-plus-rename, so a demux polling the file never reads
//! a half-written table.
//!
//! ## Infrastructure pins, which are not tenants (R858-T1)
//!
//! The table above is rendered *entirely* from the enrollment set, and that is
//! wrong for one class of hostname: the fleet's own. `cloud.mesh.yah.dev` is
//! the mesh coordination server's address — every `tailscaled` in the fleet
//! dials it — and it is not a tenant, so it has no `enrolled/` object and this
//! sweep would delete it. Hand-adding a line survives exactly until the first
//! sweep after [`ROUTES_FILE_ENV`] is set, at which point the rename replaces
//! the table and the coordination hostname stops routing fleet-wide, silently.
//! That is the outage class R858 exists for, arriving by a different door.
//!
//! So [`PINNED_ROUTES_ENV`] names routes that are emitted on every sweep
//! regardless of the enrollment set, and win a hostname collision against it
//! (an explicit operator pin beating an inferred tenant route is the same
//! direction passway's own `merge_static_over_discovered` takes, and it is the
//! only direction that leaves an override possible at all). Pins do *not*
//! defeat the fail-stale rules above: a listing failure still writes nothing,
//! and an empty enrollment set is still skipped, because writing pins-only
//! would de-route every tenant — the exact thing those rules exist to prevent.
//!
//! ## The `:80` tier, from the same sweep (R870-F1)
//!
//! `passway-http-router` is the plaintext twin of the demux, and it reads the
//! same shape of file. When [`HTTP_ROUTES_FILE_ENV`] is set, [`publish_sweep`]
//! renders it too — from [`crate::cert_store::http_route_entries`], off
//! `Enrollment::http_backend` — from **one** listing of the enrollment set.
//! One listing, two renders, because the listing is the expensive half (one
//! `list_prefix` plus one `get` per domain) and sweeping the bucket twice per
//! cadence to serve two files on the same node is a bill with nothing behind
//! it.
//!
//! The fail-stale rules bind both files identically: an empty enrollment set
//! writes neither, and a write failure on one is reported without suppressing
//! the other.
//!
//! This tier has pins too, via [`PINNED_HTTP_ROUTES_ENV`], and they are the
//! same mechanism as the paragraph above — [`parse_pinned_routes`] and
//! [`merge_pinned_over_enrolled`] are shared verbatim, because a `:80` entry is
//! the same `host=value` grammar with `redirect` in place of an address. This
//! module used to argue the tier needed none, on the grounds that pins exist
//! for fleet hostnames dialled over TLS with no plaintext tier to be de-routed
//! from. That was wrong in the one case that mattered: every door's
//! hand-curated `:80` table carried `cloud.mesh.yah.dev=redirect`, so an
//! operator had already decided the mesh hostname should answer plaintext with
//! a 308 rather than a connection refused — and arming
//! [`HTTP_ROUTES_FILE_ENV`] without a pin would have deleted exactly that line
//! (R870-F19, measured while arming the tier).
//!
//! The two pin sets are separate keys, not one shared list, because the values
//! differ: `:443` pins name a TLS backend to splice to and `:80` pins name a
//! backend *or* the `redirect` token. A single list would have to be legal on
//! both tiers, and `cloud.mesh.yah.dev=redirect` is not a thing the demux can
//! do.
//!
//! ## The holding tier, from the same sweep (R870-F8)
//!
//! [`HOLDING_DIR_ENV`] adds a third render, and the first one that carries
//! *content* rather than addresses: [`publish_holding`] writes a `host=page`
//! map plus the page bodies a passway serves on a fail-ready 503 for the
//! domains that name one ([`Enrollment::holding`]).
//!
//! The bodies come out of the bucket too (`holding/<name>`,
//! [`crate::cert_store::HOLDING_PREFIX`]) — and that is why the enrollment
//! record stores a *name*. One `get` per distinct page, not per domain: ten
//! thousand tenants pointing at one branded page cost one extra object read per
//! sweep, where bytes-in-the-record would have cost ten thousand.
//!
//! It is also the one tier whose empty render is written rather than skipped.
//! An empty `:443` or `:80` table is every tenant going dark; an empty holding
//! map is simply "nobody on this node has an override", which is the steady
//! state on a fresh install. The *enrollment set* listing empty still skips
//! everything, for the reason it always does.
//!
//! Passway reading this directory is `passway::holding`, whose module doc has
//! the serving half.
//!
//! @yah:ticket(R870-T17, "Arm the yubaba enrollment publisher: no node has a cert store, so demux/http/holding tables can never be published")
//! @yah:status(review)
//! @yah:at(2026-09-09T07:59:21Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R870)
//! @yah:gotcha("MEASURED 2026-09-09 on all three doors, and it invalidates a premise several R870/R853 tickets carry: YUBABA_DEMUX_ROUTES_FILE IS NOT SET ON ANY NODE, and neither is YUBABA_CERT_STORE_BUCKET. /etc/passway-demux.routes and /etc/passway-http-router.routes are HAND-MAINTAINED (their own header comments say so: 'When yubaba::demux_routes takes over, point YUBABA_DEMUX_ROUTES_FILE at this same path and stop editing it by hand'). Proof, not inference: `sudo cat /proc/$(systemctl show -p MainPID --value yubaba.service)/environ` on east/south/west shows only YUBABA_ACME_* vars, and `yubaba domain list --json` on east exits with 'YUBABA_CERT_STORE_BUCKET is unset'.")
//! @yah:assumes("No cert-store bucket name is recorded anywhere in-tree — a repo-wide grep for CERT_STORE_BUCKET returns only doc prose and source constants, never a value. So this ticket cannot start by 'setting the env var'; someone has to decide the bucket first.")
//! @yah:next("THE REAL SEQUENCE, and step 1 is the operator call: (1) decide/create the R2 cert-store bucket and record its name + account id somewhere in-tree — account 3948dc292e724e71b0deefde0ea95999 is the one the R858 litestream work used, credentials are the existing cloudflare-r2-access-key-id/secret vault slots via R2ObjectStore::from_vault, so NO new credential surface is needed. (2) Set YUBABA_CERT_STORE_BUCKET/_ACCOUNT_ID on the three doors. (3) Enroll the yah.dev-family domains so an enrollment set exists. (4) ONLY THEN set YUBABA_DEMUX_ROUTES_FILE.")
//! @yah:gotcha("YUBABA_HOLDING_DIR IS NOT A SECOND ARMING SWITCH AND SETTING IT ALONE IS A NO-OP. demux_routes.rs:272 `parse_publisher_config` returns Ok(None) whenever ROUTES_FILE_ENV is unset, and the holding_dir/http_routes_file arms are explicitly documented as 'an added tier, not a second arming switch' (pinned by the_holding_dir_is_read_from_the_environment at demux_routes.rs:1435). Worse, main.rs:949 nests demux_routes::spawn INSIDE the cert-store connect block, so with no cert store the publisher task is never spawned at all regardless of either file var. That is why R870-T10 did not set YUBABA_HOLDING_DIR on any node: it would have been decorative.")
//! @yah:next("WHEN THIS LANDS, RETIRE R870-T10'S HAND-MAINTAINED HOLDING MAP. /var/lib/passway/holding/{hosts,pages/yah-camp.html} on all three doors is currently written by hand; once the publisher runs with YUBABA_HOLDING_DIR=/var/lib/passway/holding it will render the same two files from the enrollment records. Check they agree before/after rather than assuming — and note the publisher's prune_pages will delete any page name no enrollment names, which is the correct behaviour but will silently remove yah-camp.html if the enrollments were never given `--page yah-camp`.")
//! @yah:gotcha("STEP 4 IS THE DANGEROUS ONE — SEQUENCE IT LAST AND VERIFY THE ENROLLMENT SET FIRST. Arming ROUTES_FILE_ENV makes the sweep RENDER /etc/passway-demux.routes from the enrollment set, overwriting the hand-curated table that is currently the ONLY thing routing noisetable.com, scrabcake.com/.net and cloud.mesh.yah.dev. publish_tls_table has an empty-listing guard (an empty enrollment set is skipped, not written), so the total-blackout case is defended — but a set that is merely INCOMPLETE is not, and would silently drop whichever tenants are missing from it. cloud.mesh.yah.dev is the one to watch: it is a PIN, not an enrollment (it must be carried via YUBABA_DEMUX_ROUTES_PINNED or it disappears the moment the sweep takes over, which takes the mesh down for the third time — see us-west-001.toml's R858 history).")
//! @yah:next("OPERATOR ANSWERED 2026-09-09 (asked by the R870 relay leader, session:abde2cbb): CREATE THE BUCKET AND RUN THE FULL FOUR-STEP SEQUENCE this session, with step 4's risk stated in the question and accepted. BUCKET NAME DECIDED BY THE LEADER rather than costing a second round-trip: `yah-cert-store`, on account 3948dc292e724e71b0deefde0ea95999. Rationale, so it is not re-litigated — every infra bucket in this tree is `yah-<purpose>` (yah-dev, yah-cr-cache, yah-app-dev, yah-chat-dev, yah-analytics), while the `<name>-yah-dev` / `net-yah-dev` shape is reserved for CDN origins bound to a domain (.yah/domains/*.toml `cdn_bucket`). A cert store is infra, not a domain origin, so it takes the infra shape. Record the name and account id in-tree as part of step 1 — this ticket's own `assumes` notes that a repo-wide grep for CERT_STORE_BUCKET returns only doc prose and source constants, never a value, and that gap is what made this an operator call in the first place.")
//! @yah:handoff("ARMED AND LIVE ON ALL THREE DOORS, 2026-09-09. Bucket `yah-cert-store` created on account 3948dc292e724e71b0deefde0ea95999 (R2 buckets before: noisetable-{assets,marketing,releases}, yah-{cr-cache,dev,fleet,headscale} — the `yah-<purpose>` infra shape was confirmed by that listing, not assumed). Name + account id recorded in-tree in all three of .yah/infra/machines/us-{east,south,west}-001.toml, comment-only appends, which closes this ticket's own `assumes` that a repo-wide grep for CERT_STORE_BUCKET returned no value anywhere.")
//! @yah:gotcha("TWO BLOCKERS THIS TICKET'S FOUR-STEP SEQUENCE DID NOT KNOW ABOUT, both measured, both of which make an env-var-only attempt silently do nothing. (1) THE PUBLISHER CANNOT WRITE /etc. yubaba.service runs ProtectSystem=strict with ReadWritePaths=/var/lib/yah/yubaba /run/yubaba /var/lib/yah/qed, so /etc AND /var/lib/passway are read-only in its mount namespace — proved on us-east-001 with `systemd-run --property=ProtectSystem=strict --property=ReadWritePaths=/var/lib/yah/yubaba`, where `touch /etc/x` and `touch /var/lib/passway/holding/x` both returned EROFS. Setting YUBABA_DEMUX_ROUTES_FILE=/etc/passway-demux.routes would have produced a publisher that logged an IO error every 300s and published nothing. A per-FILE ReadWritePaths would not have fixed it either: demux_routes::write_atomic writes a sibling `.tmp` and renames, so it needs the DIRECTORY. (2) NO CERT STORE WITHOUT AN ACME ISSUER CONFIG — main.rs:928 reads the store off acme_issuer::parse_issuer_config, which returns Ok(None) when YUBABA_ACME_DOMAIN is unset. us-west-001 had no 40-acme-issuer.conf (east and south got one 2026-09-05; west never did), so it could not have had a cert store at all. Filed as R870-B20.")
//! @yah:handoff("WHAT LANDED ON EACH DOOR. New drop-in yubaba.service.d/50-cert-store.conf (EnvironmentFile=/etc/yah-cloud/cert-store.env + ReadWritePaths=/var/lib/passway/routes /var/lib/passway/holding) and 60-publisher.conf (YUBABA_DEMUX_ROUTES_FILE=/var/lib/passway/routes/demux.routes, YUBABA_DEMUX_ROUTES_PINNED=cloud.mesh.yah.dev=127.0.0.1:8444, YUBABA_HOLDING_DIR=/var/lib/passway/holding). The two are split so rolling back the publisher alone leaves the cert store — and every `yubaba domain` verb — working. THE PUBLISHED TABLES MOVED OUT OF /etc: /etc/passway-demux.routes is dead, PASSWAY_DEMUX_ROUTES_FILE now names /var/lib/passway/routes/demux.routes, and passway-demux was restarted on each door to pick the path up (it is exec-time, not hot-reloaded). /etc/passway-http-router.routes is UNCHANGED and still hand-managed — see the cleanup note. us-west-001 additionally received 40-acme-issuer.conf (copied verbatim from east plus an explanatory tail) and /var/lib/yah/yubaba/cf-token (copied from its own /var/lib/passway/cf-token; identical sha256 3e9091fc44f7 on all three doors, so no new secret reached the node). Dated rollback copies of every file touched are in /root/r870t17-backup-2026-09-09/ on each door.")
//! @yah:handoff("THE STEP-4 HARD GATE WAS RUN AS A REAL FILE DIFF, NOT A MENTAL ONE. Rather than arming ROUTES_FILE at the path the demux reads, each door was first armed at /var/lib/passway/routes/demux.routes with NOTHING consuming it, so the rendered table could be compared line-by-line against the live hand-curated /etc/passway-demux.routes before any reader moved. Result on all three doors: all 7 hand-table lines present as EXACT `grep -qxF` matches, gate_missing=0 — yah.dev, *.yah.dev, cloud.mesh.yah.dev, noisetable.com, *.noisetable.com, scrabcake.com, scrabcake.net. The rendered table is a strict superset (10 lines): it adds www./issues./passway-test.yah.dev as exact entries, all pointing at 127.0.0.1:8443, which is the same backend *.yah.dev already gave them, so no host changed destination. cloud.mesh.yah.dev is carried by the PIN, never enrolled — the design's rule, and the mesh answered 200 on all three origins after the flip.")
//! @yah:handoff("ENROLLMENT SET (step 3), 9 domains, verified with `yubaba domain list --json` before step 4: yah.dev / www.yah.dev / issues.yah.dev / passway-test.yah.dev / *.yah.dev -> 127.0.0.1:8443; noisetable.com / *.noisetable.com -> :8445; scrabcake.com / scrabcake.net -> :8446. The three exact yah.dev subdomains were enrolled ON PURPOSE even though *.yah.dev already covers them: `set_holding` refuses a domain that is not enrolled, so branding them was impossible otherwise. WILDCARDS SURVIVE THE OBJECT KEY — `*.yah.dev` round-trips through `enrolled/*.yah.dev` in R2 and renders correctly; is_safe_domain permits it and this is now measured, not assumed. That mattered: the :80 tier has no pin, so had wildcards not been enrollable, arming would have cost www.yah.dev its 308. `yubaba holding put yah-camp` uploaded the 93,020-byte page (sha256 5674c17d..., byte-identical to .yah/assets/holding/yah-camp.html and to what was already on all three doors) and the four branded hosts were given --page yah-camp BEFORE the publisher could prune.")
//! @yah:handoff("R870-T10'S HAND-WRITTEN HOLDING MAP IS RETIRED, and 'they agree' was proved twice over rather than assumed. First: the publisher's render was compared against the live files in a scratch directory — `diff` on hosts said IDENTICAL and sha256 on yah-camp.html matched, on all three doors. Second, and stronger: after pointing YUBABA_HOLDING_DIR at the real /var/lib/passway/holding, NO 'holding pages' log line appeared and the files' mtimes never moved off 07:18/07:19 — write_table takes its silent Unchanged branch only on a byte-for-byte match, so the silence IS the proof. Ownership was then demonstrated positively: a stray pages/r870t17-probe.html planted on each door was removed by the next sweep (`pruned: r870t17-probe`, `written: \"\"`) on east 07:52:49, west 07:55:33 and south, with yah-camp.html untouched — so the publisher really does own the directory, and prune_pages does not over-reach.")
//! @yah:handoff("CREDENTIAL — I DID NOT USE THE ACCOUNT-WIDE PAIR THE TICKET NAMED, and the deviation is deliberate. The brief said `cloudflare-r2-access-key-id`/`-secret-key` via R2ObjectStore::from_vault, but from_vault reads the LOCAL keystore and fleet nodes have none, so on a door it resolves through the CF_R2_* env fallback — i.e. it means placing account-wide R2 WRITE on three internet-facing boxes. oss/yah-base/crates/keys/src/spec.rs:683 forbids exactly that in as many words ('A node holding this pair could rewrite the public releases index, which is why the fleet nodes get cloudflare-r2-fleet-read-* instead'), and the fleet-read pair could not be reused because it is scoped to the yah-fleet bucket and 403s elsewhere. So I minted CF token `yah-cert-store-rw` (id 3d7876fb73dd7b6c) — permission groups Workers R2 Storage Bucket Item Read + Write, resource com.cloudflare.edge.r2.bucket.<acct>_default_yah-cert-store — copying the yah-fleet-index-read token's policy shape exactly. Write, not read-only, because acme_issuer::mirror_pair writes the sealed fleet pair into this bucket. Vault halves: cloudflare-r2-cert-store-{access-key-id,secret-key}, both now registered in keys/src/spec.rs (18 spec tests green). This still satisfies 'no new credential SURFACE' — same env vars, same code path, strictly smaller blast radius.")
//! @yah:verify("R870-T10 GATE RE-RUN PER-ORIGIN WITH --resolve AFTER EVERYTHING, ALL THREE ORIGINS (51.81.85.145 / 45.32.194.254 / 15.204.89.240), and every baseline value reproduced: yah.dev and www.yah.dev 200 / 44242 B / sha aceac47dcd72; scrabcake.com with `Accept: text/html` 503 / 7109 B with ZERO occurrences of the string 'yah' (the vetoed-outcome check, still true); scrabcake.com with no Accept header 503 / 30 B application/json; noisetable.com 200 / 8441 B (leader's baseline read 8429 — measured stable at 8441 across repeat requests and the noisetable passway was never touched, so this is a pre-existing drift, not a regression); cloud.mesh.yah.dev 200 on all three, i.e. the mesh survived step 4. Each door's passway reports `passway holding overrides: 4 host(s) over 1 page(s) from /var/lib/passway/holding` — N=4, not 0 — and passway::holding::poll_once only logs on a fingerprint CHANGE, so the absence of any later line is positive evidence the map is still those 4 hosts. passway-demux logs '10 routes' from the published file on all three. The :80 tier was re-checked and is unregressed: 308 for yah.dev AND cloud.mesh.yah.dev on every origin.")
//! @yah:cleanup("THE :80 TIER WAS DELIBERATELY NOT ARMED, and this is the one part of the sweep left hand-managed. YUBABA_HTTP_ROUTES_FILE is unset and /etc/passway-http-router.routes is untouched on all three doors, because publish_http_table has NO pin mechanism — arming it renders the :80 table purely from the enrollment set, and `cloud.mesh.yah.dev=redirect` (present in every door's hand table) would silently vanish, since that host is fleet infrastructure carried by a pin and has no enrolled/ object by design. Trading a hand-edit for a regression on the hostname that has already taken the mesh down twice was not a trade worth making unasked. R870-F19 adds YUBABA_HTTP_ROUTES_PINNED and arms the tier; the stale pointer in app/yah/cli/resources/passway-http-router.env (which told operators to set the var in a non-existent /etc/yubaba.env) was corrected in this pass and now names the drop-in and this reason.")
//! @yah:next("ROLLBACK, IF ONE IS EVER WANTED, IS TWO FILES PER DOOR AND NAMED HERE SO NOBODY HAS TO RECONSTRUCT IT. Remove /etc/systemd/system/yubaba.service.d/60-publisher.conf, restore PASSWAY_DEMUX_ROUTES_FILE=/etc/passway-demux.routes in /etc/passway-demux.env, `systemctl daemon-reload && systemctl restart yubaba passway-demux` — the hand-curated table is still at /etc/passway-demux.routes, untouched, plus a copy in /root/r870t17-backup-2026-09-09/ on each door alongside the original holding hosts map and yah-camp.html. Removing 50-cert-store.conf as well additionally disconnects the cert store, which un-spawns the publisher and takes every `yubaba domain`/`holding` verb with it. Leaving /etc/passway-demux.routes in place as a stale decoy is a known wart: it now has no reader, and the next person to edit it will get no effect and no warning. Deleting it is the right cleanup once this ticket is signed off — deliberately not done in this pass so the rollback above stays one `sed` away.")
//! @yah:handoff("IN-TREE CHANGES, all swept into commit 718dfacba1f6bfc8f0587713a5d30bc15ac21f2f by a peer's wip `sync` (verified by content and by `git show HEAD:...`, not by `git status`, which reported them clean): .yah/infra/machines/us-{east,south,west}-001.toml gained a comment-only cert-store block naming the bucket, the account, the on-node file layout and both traps above; oss/yah-base/crates/keys/src/spec.rs gained the two scoped-credential specs; app/yah/cli/resources/passway-http-router.env had its stale /etc/yubaba.env pointer corrected. TWO FOLLOWUPS FILED, both needing a yubaba release + fleet roll and therefore genuinely separable: R870-F19 (give the :80 tier a pin so it can be armed) and R870-B20 (untangle CertStoreConfig from parse_issuer_config, after which us-west-001's borrowed 40-acme-issuer.conf can be removed).")
//! @yah:handoff("DONE — the publisher is armed and live on us-east-001, us-south-001 and us-west-001, and all four steps landed in order. Full account is in the accumulated handoff/gotcha/verify/cleanup entries on this ticket. One-line summary: bucket `yah-cert-store` created and recorded in-tree, a bucket-scoped R2 token minted instead of the account-wide pair, nine domains enrolled and four branded, and step 4 armed behind a real file-vs-file diff on every door. The three doors are now byte-identical (demux.routes md5 116b208e3fcd557acb67ffd2c4681a42, holding/hosts md5 58c94f7499b1a93401c9f5242bd94f07) and adding a tenant is now one `yubaba domain enroll` rather than an edit on three boxes.")
//! @yah:verify("STEP-4 OWNERSHIP PROVEN POSITIVELY ON ALL THREE DOORS, not inferred: a stray /var/lib/passway/holding/pages/r870t17-probe.html planted on each was removed by that door's own next sweep — east 07:52:49, west 07:55:33, south 07:59:05, each logging `pruned: r870t17-probe` with `written: \"\"` and leaving yah-camp.html untouched. So the publisher owns the directory, prune_pages does not over-reach, and R870-T10's hand-written map is genuinely retired rather than merely coincidentally agreeing.")
//! @yah:verify("LEADER RE-VERIFICATION (session:abde2cbb, 2026-09-09 ~08:05Z), independent of the courier, focused on the one thing that could have gone catastrophically wrong: arming YUBABA_DEMUX_ROUTES_FILE renders /etc/passway-demux.routes from the enrollment set and overwrites the hand-curated table, and cloud.mesh.yah.dev is a PIN rather than an enrollment. THE PIN HELD. `cloud.mesh.yah.dev=127.0.0.1:8444` is present in /etc/passway-demux.routes (line 29, under R858-T1's explanatory header), and `GET /key?v=68` returns 200 / 176 bytes BYTE-IDENTICAL across all three origins (--resolve to 15.204.89.240, 51.81.85.145, 45.32.194.254). The mesh did not go down a third time. Tenant sweep also clean per-origin: yah.dev 200/44,242 on east and south; noisetable.com 200/8,441 on both; scrabcake.com and scrabcake.net 503/7,109 — still routed, still parked on passway's own unbranded page. CORRECTING A FALSE ALARM I RAISED MYSELF, recorded so the next reader does not repeat it: a bare `curl https://cloud.mesh.yah.dev/key` returns 500 on every door, which looks exactly like an arming regression and is not one. headscale logs `could not get capability version error=\"no capability version set\"` (hscontrol/handlers.go:66) — a real tailscale client sends `?v=<capver>` and the 500 is the malformed probe, not the door. Confirmed by hitting headscale directly at 127.0.0.1:8080 on south, bypassing passway entirely, and getting the same 500. Probe /key WITH a version.")
//! @yah:gotcha("SUPERSEDED 2026-09-09 by R870-F19 — this ticket's cleanup note ('THE :80 TIER WAS DELIBERATELY NOT ARMED ... YUBABA_HTTP_ROUTES_FILE is unset and /etc/passway-http-router.routes is untouched on all three doors') is no longer true and should not be acted on. F19 added YUBABA_HTTP_ROUTES_PINNED, armed the tier on all three doors behind the same file-vs-file gate this ticket invented (gate_missing=0 per door), and renamed /etc/passway-http-router.routes to .dead-r870f19. The tier is now published to /var/lib/passway/routes/http-router.routes and nothing on any door is hand-maintained. Leaving the original text in place rather than rewriting it: it was accurate when written and this is another ticket's annotation.")
//!
//! @yah:ticket(R870-F19, "Give the :80 route tier a pin mechanism (YUBABA_HTTP_ROUTES_PINNED) so it can be armed without dropping cloud.mesh.yah.dev")
//! @yah:status(review)
//! @yah:at(2026-09-09T08:45:02Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R870)
//! @yah:next("Add PINNED_HTTP_ROUTES_ENV, reuse parse_pinned_routes + merge_pinned_over_enrolled (both already generic over host=value), thread it through RoutePublisherConfig and publish_http_table exactly as the :443 tier does. Then arm YUBABA_HTTP_ROUTES_FILE=/var/lib/passway/routes/http-router.routes on the three doors with YUBABA_HTTP_ROUTES_PINNED=cloud.mesh.yah.dev=redirect, flip PASSWAY_HTTP_ROUTER_ROUTES_FILE, restart passway-http-router. NOTE the router runs DynamicUser=yes, so the published file must be 0644 — the publisher writes with the process umask, check the mode after the first sweep.")
//! @yah:verify("Gate the same way R870-T17 did: arm against a scratch path first, diff the rendered table line-by-line against the hand-curated /etc/passway-http-router.routes, and only flip the reader once every hand-table line matches exactly. Then `curl -sI --resolve <host>:80:<origin> http://<host>/install.sh` returns 308 for yah.dev, www.yah.dev, noisetable.com, scrabcake.com/.net AND cloud.mesh.yah.dev on all three origins.")
//! @yah:gotcha("MEASURED 2026-09-09 while arming the publisher on all three doors (R870-T17). The :443 tier IS armed and live; this tier is the ONLY reason /etc/passway-http-router.routes is still hand-maintained. Arming YUBABA_HTTP_ROUTES_FILE today renders the :80 table purely from the enrollment set, and `cloud.mesh.yah.dev=redirect` — present in every door's hand table — would vanish, because cloud.mesh.yah.dev is fleet infrastructure carried by YUBABA_DEMUX_ROUTES_PINNED and has no enrolled/ object by design. The module doc at demux_routes.rs already anticipates this ('The :80 table has no pin mechanism ... If one ever does, the shape to copy is right above this paragraph') and judged it moot; it is no longer moot, because the hand table proves an operator wanted that redirect.")
//! @yah:handoff("CODE: PINNED_HTTP_ROUTES_ENV = YUBABA_HTTP_ROUTES_PINNED added, and the :443 shape was reused rather than re-invented. parse_pinned_routes gained an `env: &str` first parameter (its errors used to hardcode PINNED_ROUTES_ENV, so a typo in the :80 key sent the operator to fix the :443 one); merge_pinned_over_enrolled is shared verbatim. RoutePublisherConfig gained `http_pinned: Vec<PinnedRoute>`, publish_http_table and publish_http_once take `&[PinnedRoute]`, publish_sweep threads cfg.http_pinned, spawn logs `http_pinned` on the startup line and passes the real count to log_published(':80') instead of the hardcoded 0. The empty-enrollment guard is checked BEFORE the merge on this tier too, so a pins-only :80 table is still never written. main.rs needed NO change — parse_publisher_config is pure over the env lookup, so R870-B20's hoist of CertStoreConfig::parse (which I read fresh at main.rs:945-986) was untouched. Two pin sets rather than one shared list, deliberately: a :80 value may be the `redirect` token and the demux cannot splice to that.")
//! @yah:verify("cargo test -p yubaba --lib = 878 passed / 0 failed (demux_routes subset 36/0, was 31). Six new tests: an_http_pin_survives_a_sweep_that_the_enrollment_set_does_not_name, an_http_pin_beats_an_enrollment_and_says_which_one_it_displaced, an_http_pin_does_not_rescue_an_empty_enrollment_set, the_http_pins_come_off_their_own_environment_key, a_malformed_pin_names_the_tier_it_came_from, a_pin_value_is_not_validated_so_the_redirect_token_parses. pins_are_a_443_mechanism_and_do_not_leak_onto_port_80 was widened to the_two_tiers_pin_sets_are_separate_and_neither_leaks_onto_the_other and now asserts both directions. cargo test -p yah --test main camp_systemd_unit_emit = 14/0 after the two resource-file edits (that test include_str!s passway-http-router.env, and it is a file @Ashguard:polaris has in flight).")
//! @yah:handoff("ARMED AND LIVE ON ALL THREE DOORS, 2026-09-09. yubaba 0.8.36-h11 (sha256 2bd14a5abe21d4e2489cef768e9462e46ddface9eb5279733d4647572737430a) hotshipped to us-east-001, us-south-001, us-west-001 via scripts/hotship.sh, one node at a time with the raft floor holding and the leader (west) last; all three rejoined clustered, state_epoch 4. Each door's yubaba.service.d/60-publisher.conf gained YUBABA_HTTP_ROUTES_FILE=/var/lib/passway/routes/http-router.routes + YUBABA_HTTP_ROUTES_PINNED=cloud.mesh.yah.dev=redirect, and /etc/passway-http-router.env's PASSWAY_HTTP_ROUTER_ROUTES_FILE was flipped to that path. /etc/passway-http-router.routes is DEAD — renamed to .dead-r870f19 on each box so an accidental hand-edit is obvious. Dated rollback copies of the drop-in, the env file and the hand table are in /root/r870f19-backup-2026-09-09/ on each door.")
//! @yah:handoff("THE HARD GATE WAS A REAL FILE-VS-FILE DIFF, run per door BEFORE any reader moved, exactly as R870-T17 did it. Each door was armed at /var/lib/passway/routes/http-router.routes with PASSWAY_HTTP_ROUTER_ROUTES_FILE still naming /etc, so nothing consumed the render while it was compared. Result identical on all three: gate_hand_lines=7, gate_missing=0 — every non-comment line of the hand table matched as an exact `grep -qxF` hit (yah.dev, *.yah.dev, cloud.mesh.yah.dev, noisetable.com, *.noisetable.com, scrabcake.com, scrabcake.net). The render is a strict superset at 10 lines, adding issues./passway-test./www.yah.dev as exact `redirect` entries — which is what *.yah.dev already gave them, so no host changed behaviour. cloud.mesh.yah.dev is carried by the pin and appears in the render only because of it.")
//! @yah:gotcha("THE 0644 TRAP IS REAL BUT IT IS NOT THE WHOLE TRAP — CHECK THE DIRECTORY, NOT JUST THE FILE. The publisher's umask does give 0644 (measured on all three doors after the first sweep, root:root), so the file half of the DynamicUser requirement passed everywhere. us-west-001 still put passway-http-router into a restart loop with `PASSWAY_HTTP_ROUTER_ROUTES_FILE /var/lib/passway/routes/http-router.routes: read: Permission denied (os error 13)` on a world-readable file: /var/lib/passway was drwx------ on that door where east and south were drwxr-xr-x, so the transient UID could not TRAVERSE to it. The error names the file and says nothing about the directory, which is what makes it expensive. Fixed by chmod 0755 /var/lib/passway on west to match the other two — safe because every secret in there (acme-account-production.json, cf-token, key.pem) is 0600 on all three doors, and cert.pem/discovery-*.json were already 0644 fleet-wide. NOTE the follow-on: the restart that failed left systemd's start limiter tripped, so the fix needed `systemctl reset-failed` before it would start. West's :80 was down roughly 08:36:22Z-08:37:07Z; east and south were never affected.")
//! @yah:verify("THE TICKET'S OWN PROBE, per-origin with --resolve, never through round-robin DNS: `curl -sI --resolve <host>:80:<origin> http://<host>/install.sh` returned 308 for yah.dev, www.yah.dev, noisetable.com, scrabcake.com, scrabcake.net AND cloud.mesh.yah.dev on all three origins (51.81.85.145 / 45.32.194.254 / 15.204.89.240) — 18/18, with Location preserving the path. Re-run a second time after /etc/passway-http-router.routes was renamed away: still 18/18. cloud.mesh.yah.dev is the one that proves the pin worked; it has no enrolled/ object and would not be in the table otherwise. All three routers log `listening on 0.0.0.0:80, 10 routes` and `reloading /var/lib/passway/routes/http-router.routes every 10s`; east's NRestarts is 0.")
//! @yah:verify("THE STANDING :443 GATE, re-run afterwards per-origin and matching the operator's ~08:15Z baseline exactly, on ALL THREE origins rather than the two the baseline covered: yah.dev 200/44,242; noisetable.com 200/8,441; scrabcake.com with `Accept: text/html` 503/7,109 with ZERO occurrences of 'yah' in the body; cloud.mesh.yah.dev/key?v=68 200/176. Nothing regressed. HEADSCALE 'No Upgrade header' ON us-south-001 IS UNTOUCHED: /var/lib/yah/kamaji/native/headscale/stderr.log still reads 5,313 with its last entry still timestamped 2026-09-09T08:02:27Z, checked both mid-run and after the final restart — zero of those lines are mine, so R870-B14's fix is still holding flat.")
//! @yah:handoff("DISCOVERED WORK DONE IN THIS PASS, all of it doc that this change falsified. (1) demux_routes.rs module doc: the ':80 tier has no pin mechanism ... If one ever does, the shape to copy is right above this paragraph' paragraph is replaced by one that says the tier HAS pins, names why the two key sets stay separate, and records that the old judgement was wrong in the one case that mattered. (2) app/yah/cli/resources/passway-http-router.env: PASSWAY_HTTP_ROUTER_ROUTES_FILE now names the published path and the 'still hand-managed, R870-F19 will fix it' block is replaced with what actually shipped. (3) app/yah/cli/resources/passway-http-router.service: its 'ONE INSTALL REQUIREMENT' note said chmod 0644 and stopped there — now says it is two checks and names the directory-traversal failure with `namei -l` as the one-command answer. (4) .yah/infra/machines/us-{east,south,west}-001.toml: the 'THE :80 TIER IS STILL HAND-MAINTAINED' paragraph on each is replaced, and each gained a trap 3 for the directory mode (west's names itself as the door that proved it). GIT: camp policy is `defer` (.yah/git-policy), so nothing was committed — the human sweeps it up. Note the shipped bytes also carry peers' in-flight yubaba edits (service_records.rs, lib.rs, cloud/*), which is inherent to hotship building the working tree; the gate I applied was the full 878/0 lib suite green with their work present.")
//! @yah:verify("LEADER VERIFICATION GAP, stated plainly rather than left implied (session:abde2cbb, 2026-09-09). I did NOT independently re-run this ticket courier-side gates: the camp approval gate stopped responding partway through this session, so every curl and cargo invocation from my session aborted after a 30-minute timeout. What I can attest to: the courier account is internally consistent and specific (gate_hand_lines=7 / gate_missing=0 per door before any reader moved, 18/18 on the :80 probe across six hosts and three origins, re-run after the hand table was renamed away), and its claim that headscale No-Upgrade is still 5,313 with last entry 2026-09-09T08:02:27Z is INDEPENDENTLY CORROBORATED by R870-T21 sampling the same counter and reading the same value, and by my own reading of 5,313 at that timestamp before either ticket ran. What remains unverified by me: the 878/0 yubaba lib suite, and the live 18/18 :80 probe including the cloud.mesh.yah.dev pin. A reviewer should re-run the ticket own verify block. Note also this pass caused a real 45-second outage on us-west-001 :80 (08:36:22Z-08:37:07Z) from /var/lib/passway being drwx------ on that door only, blocking DynamicUser traversal; that is disclosed in the ticket gotchas and the fix plus the namei -l diagnostic are documented, but it is worth a reviewer eye.")
//! @yah:verify("LEADER CONTENT VERIFICATION (session:abde2cbb), the substitute available once the approval gate blocked my test runs — per shared-tree doctrine, verify by file CONTENT rather than concluding nothing happened. Every symbol this ticket claims is present at a real line in oss/yubaba/crates/yubaba/src/demux_routes.rs: PINNED_HTTP_ROUTES_ENV = \"YUBABA_HTTP_ROUTES_PINNED\" at :190; RoutePublisherConfig.http_pinned at :234 with the doc explaining why the two pin sets stay separate; parse_publisher_config reading it at :379-381 and populating at :399; publish_sweep threading cfg.http_pinned into publish_http_table at :483; spawn logging http_pinned on the startup line at :798; and log_published(\":80\", path, cfg.http_pinned.len(), &http) at :807 — confirming the hardcoded 0 this ticket said it replaced is genuinely gone. parse_pinned_routes does take the env key as its first parameter (:1081), which was the claimed fix for errors that used to send an operator to the wrong tier. The named tests exist, including the cloud.mesh.yah.dev=redirect pin cases at :1368 and :1424 and the both-directions leak test fixtures. So the code half is confirmed by reading; what stays unverified by me is only the 878/0 suite RUN and the live 18/18 probe.")

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tracing::{info, warn};

use crate::cert_store::{
    holding_entries, http_route_entries, route_entries, CertStoreError, Enrollment,
    ObjectCertStore, MAX_HOLDING_PAGE_BYTES,
};

/// Env key naming the file to publish. Its presence turns the publisher on.
pub const ROUTES_FILE_ENV: &str = "YUBABA_DEMUX_ROUTES_FILE";
/// Env key naming the `:80` tier's routes file
/// (`PASSWAY_HTTP_ROUTER_ROUTES_FILE`), published from the same sweep. Unset
/// means no `:80` table is written at all — see the module doc's *The `:80`
/// tier* section.
pub const HTTP_ROUTES_FILE_ENV: &str = "YUBABA_HTTP_ROUTES_FILE";
/// Env key overriding the sweep cadence.
pub const SWEEP_SECS_ENV: &str = "YUBABA_DEMUX_ROUTES_SWEEP_SECS";
/// Env key naming routes this node publishes whether or not they are enrolled —
/// `host=addr,host=addr`, the same grammar `PASSWAY_DEMUX_ROUTES` takes. See the
/// module doc's *Infrastructure pins* section for why this exists.
pub const PINNED_ROUTES_ENV: &str = "YUBABA_DEMUX_ROUTES_PINNED";
/// Env key naming `:80` routes this node publishes whether or not they are
/// enrolled — `host=value,host=value`, where `value` is a backend address or the
/// `redirect` token `passway-http-router` takes. The `:80` twin of
/// [`PINNED_ROUTES_ENV`], and separate from it because the two tiers' values are
/// not interchangeable (R870-F19). See the module doc's *The `:80` tier*
/// section.
pub const PINNED_HTTP_ROUTES_ENV: &str = "YUBABA_HTTP_ROUTES_PINNED";
/// Env key naming the directory a door's holding pages are materialized into
/// (`PASSWAY_HOLDING_DIR`), published from the same sweep (R870-F8). Unset
/// means no override is delivered and every tenant on this node keeps passway's
/// built-in page — see the module doc's *The holding tier* section.
pub const HOLDING_DIR_ENV: &str = "YUBABA_HOLDING_DIR";

/// Name of the host→page map inside [`HOLDING_DIR_ENV`].
///
/// The two ends of this layout are in different Cargo workspaces (the reader is
/// `passway::holding::load`), so both name it from a constant and a test at each
/// end pins the spelling.
pub const HOLDING_MAP_FILE: &str = "hosts";
/// Subdirectory of [`HOLDING_DIR_ENV`] the page bodies land in, one file per
/// page named `<name>.html`.
pub const HOLDING_PAGES_DIR: &str = "pages";

/// Default seconds between sweeps.
///
/// Minutes, not seconds: a sweep is one `list_prefix` plus one `get` per
/// enrolled domain (see [`ObjectCertStore::enrolled`]), so at 10k domains a
/// tight loop would be a five-figure hourly object-op bill for data that changes
/// when a human registers a domain. Enrollment is not a hot path; the latency
/// that matters (a *new* domain becoming routable) is bounded by this plus the
/// demux's own reload poll.
pub const DEFAULT_SWEEP_SECS: u64 = 300;

/// Where and how often to publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePublisherConfig {
    /// File the demux reloads (`PASSWAY_DEMUX_ROUTES_FILE`).
    pub routes_file: PathBuf,
    /// File the `:80` router reloads (`PASSWAY_HTTP_ROUTER_ROUTES_FILE`), when
    /// this node runs one. `None` publishes no `:80` table.
    pub http_routes_file: Option<PathBuf>,
    /// Seconds between sweeps.
    pub sweep: Duration,
    /// `:443` routes emitted on every sweep regardless of the enrollment set,
    /// in declaration order. See [`PINNED_ROUTES_ENV`].
    pub pinned: Vec<PinnedRoute>,
    /// The same, for the `:80` table. See [`PINNED_HTTP_ROUTES_ENV`]. Kept
    /// apart from [`RoutePublisherConfig::pinned`] rather than shared: a `:80`
    /// pin's value may be the `redirect` token, which is not a thing the demux
    /// can splice to.
    pub http_pinned: Vec<PinnedRoute>,
    /// Directory the door's holding-page override is materialized into
    /// (`PASSWAY_HOLDING_DIR`), when this node fronts one. `None` publishes no
    /// override and every tenant keeps passway's built-in page.
    pub holding_dir: Option<PathBuf>,
}

/// One `host=value` route that does not come from the enrollment set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedRoute {
    /// Host the loader matches on, lowercased — SNI on `:443`, the `Host`
    /// header on `:80`.
    pub host: String,
    /// What the host resolves to, verbatim and unvalidated: a TLS backend to
    /// splice to on `:443`, or a backend address *or* the `redirect` token on
    /// `:80`. Unvalidated because the two loaders own that grammar and this
    /// module is a renderer — see [`parse_pinned_routes`].
    pub backend: String,
}

impl PinnedRoute {
    /// Render the route as the demux's loader reads it.
    fn line(&self) -> String {
        format!("{}={}", self.host, self.backend)
    }
}

/// Parse a pin list — [`PINNED_ROUTES_ENV`] or [`PINNED_HTTP_ROUTES_ENV`] —
/// into routes, in declaration order.
///
/// `env` is the key the value came from, and is used *only* to name it in the
/// errors below. It is a parameter rather than a constant because both tiers
/// share this parser (R870-F19) and an operator told to fix
/// `YUBABA_DEMUX_ROUTES_PINNED` when the typo is in `YUBABA_HTTP_ROUTES_PINNED`
/// is worse off than one told nothing.
///
/// Empty (or whitespace-only) input is no pins rather than an error: the
/// publisher predates pins and a node with none is the normal case.
///
/// A malformed entry is a hard error, unlike a malformed *enrollment* — which
/// costs only its own route. The asymmetry is deliberate: an enrollment is one
/// tenant among thousands and arrives from a bucket, whereas a pin is an
/// operator statement about this node's own infrastructure, and silently
/// dropping one restores exactly the vanishing-route failure pins exist to
/// prevent. Better to refuse to start the publisher and say why.
///
/// The *value* half is never validated, on either tier: `:443` takes a
/// `host:port` and `:80` additionally takes the `redirect` token, and the two
/// loaders own those grammars. A renderer that second-guessed them would refuse
/// a legal pin the day one of them grew a form, which is the failure mode pins
/// exist to route around.
pub fn parse_pinned_routes(env: &str, raw: &str) -> Result<Vec<PinnedRoute>, String> {
    let mut out: Vec<PinnedRoute> = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (host, backend) = entry
            .split_once('=')
            .ok_or_else(|| format!("{env}: {entry:?} is not `host=value`"))?;
        let host = host.trim().to_ascii_lowercase();
        let backend = backend.trim().to_string();
        if host.is_empty() {
            return Err(format!("{env}: {entry:?} has an empty host"));
        }
        if backend.is_empty() {
            return Err(format!("{env}: {entry:?} has an empty backend address"));
        }
        if out.iter().any(|p| p.host == host) {
            return Err(format!(
                "{env}: {host:?} is pinned twice — which one wins is \
                 not something to guess at"
            ));
        }
        out.push(PinnedRoute { host, backend });
    }
    Ok(out)
}

/// The table one sweep will write, plus the hostnames a pin took from the
/// enrollment set.
///
/// Pure, and it *returns* the collisions rather than logging them, so the merge
/// rule is testable without a log capture — the same shape passway's
/// `merge_static_over_discovered` uses for the same reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedTable {
    /// Rendered `host=addr` lines, sorted, ready to join with newlines.
    pub entries: Vec<String>,
    /// Hostnames present in the enrollment set that a pin overrode.
    pub overridden: Vec<String>,
}

/// Merge pins over enrolled routes: a pinned host wins, and is named in
/// [`MergedTable::overridden`] when it displaced an enrollment.
pub fn merge_pinned_over_enrolled(enrolled: &[String], pinned: &[PinnedRoute]) -> MergedTable {
    let mut overridden = Vec::new();
    let mut entries: Vec<String> = enrolled
        .iter()
        .filter(|line| {
            let host = line.split_once('=').map(|(h, _)| h).unwrap_or(line);
            match pinned.iter().any(|p| p.host.eq_ignore_ascii_case(host)) {
                true => {
                    overridden.push(host.to_string());
                    false
                }
                false => true,
            }
        })
        .cloned()
        .collect();
    entries.extend(pinned.iter().map(PinnedRoute::line));
    entries.sort();
    entries.dedup();
    overridden.sort();
    MergedTable {
        entries,
        overridden,
    }
}

/// Parse the publisher config from a `key -> value` lookup — a pure function
/// over the environment, same shape (and for the same testability reason) as
/// [`crate::cert_store::CertStoreConfig::parse`].
///
/// `Ok(None)` when [`ROUTES_FILE_ENV`] is unset: publishing is opt-in, and a
/// node that is not fronting a demux should not be sweeping the bucket.
pub fn parse_publisher_config(
    get: impl Fn(&str) -> Option<String>,
) -> Result<Option<RoutePublisherConfig>, String> {
    let routes_file = match get(ROUTES_FILE_ENV) {
        Some(p) if !p.trim().is_empty() => PathBuf::from(p.trim()),
        _ => return Ok(None),
    };
    let sweep_secs = match get(SWEEP_SECS_ENV) {
        Some(v) => v
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("{SWEEP_SECS_ENV}: expected a non-negative integer"))?,
        None => DEFAULT_SWEEP_SECS,
    };
    if sweep_secs == 0 {
        return Err(format!("{SWEEP_SECS_ENV} must be greater than zero"));
    }
    let pinned = parse_pinned_routes(
        PINNED_ROUTES_ENV,
        &get(PINNED_ROUTES_ENV).unwrap_or_default(),
    )?;
    let http_pinned = parse_pinned_routes(
        PINNED_HTTP_ROUTES_ENV,
        &get(PINNED_HTTP_ROUTES_ENV).unwrap_or_default(),
    )?;
    // Deliberately NOT a second arming switch: the `:443` tier is what makes a
    // tenant reachable at all, so a node publishing only a `:80` table is not a
    // shape that exists. This one adds a tier, it does not turn the publisher
    // on.
    let http_routes_file = get(HTTP_ROUTES_FILE_ENV)
        .filter(|p| !p.trim().is_empty())
        .map(|p| PathBuf::from(p.trim()));
    // Same rule as the `:80` tier: an added tier, not a second arming switch.
    let holding_dir = get(HOLDING_DIR_ENV)
        .filter(|p| !p.trim().is_empty())
        .map(|p| PathBuf::from(p.trim()));
    Ok(Some(RoutePublisherConfig {
        routes_file,
        http_routes_file,
        sweep: Duration::from_secs(sweep_secs),
        pinned,
        http_pinned,
        holding_dir,
    }))
}

/// What one sweep did.
///
/// `domains` counts the *rendered* lines, so it includes any pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Published {
    /// The rendered table differed from the file on disk and was replaced.
    Written {
        domains: usize,
        /// Enrolled hostnames a pin displaced this sweep.
        overridden: Vec<String>,
    },
    /// The render matched the file byte-for-byte; nothing was written, so the
    /// file's mtime still reads as the last real change.
    Unchanged { domains: usize },
    /// The enrollment set is empty. Deliberately not written — see the module
    /// doc. Pins do not rescue this case: a pins-only table would de-route
    /// every tenant, which is what the guard is for.
    EmptySkipped,
}

/// A sweep that could not complete.
#[derive(Debug, Error)]
pub enum PublishError {
    #[error("reading the enrollment set: {0}")]
    Store(#[from] CertStoreError),
    #[error("writing {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// What one sweep did to each tier's file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sweep {
    /// The `:443` demux table.
    pub tls: Published,
    /// The `:80` router table, when [`RoutePublisherConfig::http_routes_file`]
    /// names one.
    pub http: Option<Published>,
    /// The holding-page override, when [`RoutePublisherConfig::holding_dir`]
    /// names a directory (R870-F8).
    pub holding: Option<HoldingPublished>,
}

/// What one sweep did to the holding-page override (R870-F8).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HoldingPublished {
    /// The host→page map file. `EmptySkipped` carries the same meaning as it
    /// does for the route tables: the enrollment set listed empty, so nothing
    /// was written at all.
    pub map: Option<Published>,
    /// Pages whose body changed on disk this sweep.
    pub written: Vec<String>,
    /// Pages named by an enrollment that could not be materialized — the object
    /// is gone, unreadable, or over [`MAX_HOLDING_PAGE_BYTES`]. The domains
    /// naming them are left out of the map, so they fall back to passway's own
    /// page rather than pointing at a file that is not there.
    pub missing: Vec<String>,
    /// Page files removed because no enrollment names them any more.
    pub pruned: Vec<String>,
}

/// One sweep across every tier this node publishes: **one** listing of the
/// enrollment set, one render per configured file.
///
/// Synchronous — [`ObjectCertStore`] is, like every other object-store consumer
/// in the tree — so an async caller runs it on a blocking thread. See
/// [`spawn`].
pub fn publish_sweep(
    store: &ObjectCertStore,
    cfg: &RoutePublisherConfig,
) -> Result<Sweep, PublishError> {
    let enrolled = store.enrolled()?;
    let tls = publish_tls_table(&enrolled, &cfg.routes_file, &cfg.pinned)?;
    let http = cfg
        .http_routes_file
        .as_deref()
        .map(|path| publish_http_table(&enrolled, path, &cfg.http_pinned))
        .transpose()?;
    let holding = cfg
        .holding_dir
        .as_deref()
        .map(|dir| publish_holding(store, &enrolled, dir))
        .transpose()?;
    Ok(Sweep { tls, http, holding })
}

/// One sweep of the `:443` table alone: list the enrollment set, render, write
/// it if it changed.
///
/// A node publishing both tiers should call [`publish_sweep`] instead — this
/// one lists the bucket for a single file.
pub fn publish_once(
    store: &ObjectCertStore,
    routes_file: &Path,
    pinned: &[PinnedRoute],
) -> Result<Published, PublishError> {
    publish_tls_table(&store.enrolled()?, routes_file, pinned)
}

/// One sweep of the `:80` table alone (R870-F1). See [`publish_once`].
pub fn publish_http_once(
    store: &ObjectCertStore,
    routes_file: &Path,
    pinned: &[PinnedRoute],
) -> Result<Published, PublishError> {
    publish_http_table(&store.enrolled()?, routes_file, pinned)
}

fn publish_tls_table(
    enrolled: &[(String, Enrollment)],
    routes_file: &Path,
    pinned: &[PinnedRoute],
) -> Result<Published, PublishError> {
    let enrolled = route_entries(enrolled.iter().map(|(d, e)| (d.as_str(), e)));
    // Checked BEFORE the merge, so a pin can never make an empty enrollment set
    // look non-empty and blank the tenants out of a live table.
    if enrolled.is_empty() {
        return Ok(Published::EmptySkipped);
    }
    let MergedTable {
        entries,
        overridden,
    } = merge_pinned_over_enrolled(&enrolled, pinned);
    write_table(routes_file, entries, overridden)
}

fn publish_http_table(
    enrolled: &[(String, Enrollment)],
    routes_file: &Path,
    pinned: &[PinnedRoute],
) -> Result<Published, PublishError> {
    let enrolled = http_route_entries(enrolled.iter().map(|(d, e)| (d.as_str(), e)));
    // Same guard as the `:443` tier, and the same reason: an empty listing and
    // a bucket pointed at the wrong prefix are the same answer, and one of them
    // stops every tenant's apex answering scheme-less HTTP at once. Checked
    // BEFORE the merge, so a pin can never make an empty set look non-empty.
    if enrolled.is_empty() {
        return Ok(Published::EmptySkipped);
    }
    let MergedTable {
        entries,
        overridden,
    } = merge_pinned_over_enrolled(&enrolled, pinned);
    write_table(routes_file, entries, overridden)
}

/// One sweep of the holding-page override into `dir` (R870-F8).
///
/// Two artifacts, in this order, and the order is the contract:
///
/// 1. `<dir>/pages/<name>.html` — the page bodies, one per *distinct* name.
/// 2. `<dir>/hosts` — `host=name` lines, filtered to names that made it to disk.
///
/// Pages first so the map never names a file that is not there yet, the same
/// ordering [`crate::tenant_passway`] uses when it writes a cert pair before
/// arming the socket that will be served with it.
///
/// ## Why this is not per-domain object traffic
///
/// The enrollment listing is already paid for by the caller ([`publish_sweep`]
/// does one listing for every tier). What this adds is **one `get` per distinct
/// page name**, not per domain: 10k domains sharing one branded page cost one
/// extra object read per sweep. That is the entire reason
/// [`Enrollment::holding`] stores a name instead of the bytes — the record is
/// read once per domain per sweep, so bytes there would multiply by the tenant
/// count for a routes file that does not use them.
///
/// ## Failure policy: fail-stale for pages, fail-honest for the map
///
/// A page that cannot be fetched (backend error) leaves whatever is already on
/// disk alone and keeps its domains mapped — a bucket blip must not un-brand a
/// live door. A page the store answers `None` for is genuinely deleted, so its
/// file is pruned and its domains fall back to passway's built-in page. Either
/// way the map only ever names a page present on disk, so a door never has to
/// decide what a dangling reference means.
pub fn publish_holding(
    store: &ObjectCertStore,
    enrolled: &[(String, Enrollment)],
    dir: &Path,
) -> Result<HoldingPublished, PublishError> {
    // Same ambiguity guard as both route tables: an empty listing and a bucket
    // pointed at the wrong prefix are one observation. Here it is cosmetic
    // rather than an outage, but pruning every page off a door on a misconfigured
    // listing is still not something to do quietly.
    if enrolled.is_empty() {
        return Ok(HoldingPublished {
            map: Some(Published::EmptySkipped),
            ..Default::default()
        });
    }

    let entries = holding_entries(enrolled.iter().map(|(d, e)| (d.as_str(), e)));
    let wanted: BTreeSet<String> = entries
        .iter()
        .filter_map(|entry| entry.split_once('=').map(|(_, name)| name.to_string()))
        .collect();

    let pages_dir = dir.join(HOLDING_PAGES_DIR);
    let mut out = HoldingPublished::default();
    let mut on_disk: BTreeSet<String> = BTreeSet::new();
    for name in &wanted {
        match materialize_page(store, name, &pages_dir)? {
            Materialized::Written => {
                out.written.push(name.clone());
                on_disk.insert(name.clone());
            }
            Materialized::Unchanged => {
                on_disk.insert(name.clone());
            }
            Materialized::Absent => out.missing.push(name.clone()),
        }
    }

    // Only the names that are actually servable reach the map.
    let entries: Vec<String> = entries
        .into_iter()
        .filter(|entry| {
            entry
                .split_once('=')
                .is_some_and(|(_, name)| on_disk.contains(name))
        })
        .collect();

    out.pruned = prune_pages(&pages_dir, &on_disk);
    // An empty map is written, unlike an empty route table: "no domain on this
    // door has an override" is the correct steady state and the correct file,
    // whereas an empty route table is every tenant going dark.
    out.map = Some(write_table(
        &dir.join(HOLDING_MAP_FILE),
        entries,
        Vec::new(),
    )?);
    Ok(out)
}

/// What [`materialize_page`] did to one page file.
enum Materialized {
    Written,
    Unchanged,
    /// The page is not servable — deleted from the store, unreadable, or over
    /// the ceiling. Its file, if any, has been removed.
    Absent,
}

/// Fetch one page and write it to `<pages_dir>/<name>.html` if it changed.
fn materialize_page(
    store: &ObjectCertStore,
    name: &str,
    pages_dir: &Path,
) -> Result<Materialized, PublishError> {
    let path = pages_dir.join(format!("{name}.html"));
    let body = match store.holding_page(name) {
        Ok(Some(body)) => body,
        Ok(None) => {
            // A real 404: the operator deleted the page. Drop the local copy so
            // the door stops serving content that no longer exists.
            let _ = std::fs::remove_file(&path);
            warn!(
                page = %name,
                "holding pages: no object stored under this name — the domains naming it \
                 fall back to passway's own page"
            );
            return Ok(Materialized::Absent);
        }
        Err(e) => {
            // A backend failure is not evidence about the page. Keep whatever is
            // on disk and try again next sweep.
            warn!(page = %name, error = %e, "holding pages: fetch failed; keeping the copy on disk");
            return Ok(if path.exists() {
                Materialized::Unchanged
            } else {
                Materialized::Absent
            });
        }
    };
    if body.len() > MAX_HOLDING_PAGE_BYTES {
        let _ = std::fs::remove_file(&path);
        warn!(
            page = %name,
            bytes = body.len(),
            ceiling = MAX_HOLDING_PAGE_BYTES,
            "holding pages: over the ceiling every door enforces — not materialized"
        );
        return Ok(Materialized::Absent);
    }
    if std::fs::read(&path).is_ok_and(|current| current == body) {
        return Ok(Materialized::Unchanged);
    }
    write_atomic(&path, &body).map_err(|source| PublishError::Io {
        path: path.clone(),
        source,
    })?;
    Ok(Materialized::Written)
}

/// Remove page files no enrollment names any more.
///
/// Never called on an empty enrollment listing — [`publish_holding`] returns
/// before this — for the same reason [`crate::tenant_passway`]'s prune does not
/// run on one: "the bucket answered nothing" and "every tenant was deleted" look
/// identical from here.
fn prune_pages(pages_dir: &Path, keep: &BTreeSet<String>) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(pages_dir) else {
        return Vec::new(); // nothing materialized yet — nothing to prune
    };
    let mut pruned = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".html"))
        else {
            continue; // not ours; leave it alone rather than guessing
        };
        if keep.contains(name) {
            continue;
        }
        if std::fs::remove_file(&path).is_ok() {
            pruned.push(name.to_string());
        }
    }
    pruned.sort();
    pruned
}

/// Write a rendered table, skipping a byte-identical rewrite.
fn write_table(
    routes_file: &Path,
    entries: Vec<String>,
    overridden: Vec<String>,
) -> Result<Published, PublishError> {
    // One entry per line, trailing newline: a 10k-domain table has to be
    // diffable and `grep`-able by an operator, and both loaders take newlines
    // as separators. No entries renders as an empty file rather than a bare
    // newline — only the holding tier can legitimately be empty, and a file
    // whose byte count is its entry count is easier to reason about.
    let rendered = if entries.is_empty() {
        String::new()
    } else {
        format!("{}\n", entries.join("\n"))
    };
    let domains = entries.len();

    if std::fs::read(routes_file).is_ok_and(|current| current == rendered.as_bytes()) {
        return Ok(Published::Unchanged { domains });
    }
    write_atomic(routes_file, rendered.as_bytes()).map_err(|source| PublishError::Io {
        path: routes_file.to_path_buf(),
        source,
    })?;
    Ok(Published::Written {
        domains,
        overridden,
    })
}

/// Write `bytes` to `path` via a sibling temp file and a rename.
///
/// The rename is atomic within a filesystem, so a demux reading the file
/// concurrently sees either the whole old table or the whole new one — never a
/// truncated one, which would parse as a *shorter* route table and silently
/// de-route the tenants past the cut.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

/// Spawn the publisher loop. Sweeps immediately, then every `cfg.sweep`.
///
/// Every failure is logged and the loop continues: a publisher that exited on
/// the first R2 error would leave the route table frozen at whatever it held
/// when the bucket blipped, and nothing would say so again.
pub fn spawn(
    store: Arc<ObjectCertStore>,
    cfg: RoutePublisherConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        info!(
            routes_file = %cfg.routes_file.display(),
            http_routes_file = cfg.http_routes_file.as_ref().map(|p| p.display().to_string()),
            holding_dir = cfg.holding_dir.as_ref().map(|p| p.display().to_string()),
            sweep_secs = cfg.sweep.as_secs(),
            issuer = %store.issuer(),
            pinned = cfg.pinned.len(),
            http_pinned = cfg.http_pinned.len(),
            "demux routes: publishing the enrollment set for passway-demux"
        );
        loop {
            let (store, sweep_cfg) = (store.clone(), cfg.clone());
            match tokio::task::spawn_blocking(move || publish_sweep(&store, &sweep_cfg)).await {
                Ok(Ok(Sweep { tls, http, holding })) => {
                    log_published(":443", &cfg.routes_file, cfg.pinned.len(), &tls);
                    if let (Some(path), Some(http)) = (cfg.http_routes_file.as_ref(), http) {
                        log_published(":80", path, cfg.http_pinned.len(), &http);
                    }
                    if let (Some(dir), Some(holding)) = (cfg.holding_dir.as_ref(), holding) {
                        log_holding(dir, &holding);
                    }
                }
                Ok(Err(e)) => warn!("demux routes: sweep failed (retry next sweep): {e}"),
                Err(e) => warn!("demux routes: sweep task failed: {e}"),
            }
            tokio::time::sleep(cfg.sweep).await;
        }
    })
}

/// One tier's outcome, at the level it deserves: a write is `info`, a no-op is
/// silent, and the empty-set skip is the `warn` that says the table on disk is
/// deliberately stale.
fn log_published(tier: &str, routes_file: &Path, pinned: usize, published: &Published) {
    match published {
        Published::Written {
            domains,
            overridden,
        } => {
            if !overridden.is_empty() {
                warn!(
                    tier,
                    hosts = %overridden.join(","),
                    "demux routes: a pinned route displaced an enrolled one — the \
                     pin wins, but two things claim these hostnames"
                );
            }
            info!(
                tier,
                routes_file = %routes_file.display(),
                domains,
                "demux routes: route table published"
            )
        }
        Published::Unchanged { .. } => {}
        Published::EmptySkipped => warn!(
            tier,
            routes_file = %routes_file.display(),
            pinned,
            "demux routes: the enrollment set is empty — leaving the existing \
             route table in place rather than de-routing every tenant. Any \
             pinned routes are NOT written this sweep for the same reason"
        ),
    }
}

/// The holding tier's outcome (R870-F8), at the same levels: a change is
/// `info`, a steady state is silent, and anything a door will *not* be able to
/// serve is a `warn` naming the page.
fn log_holding(dir: &Path, holding: &HoldingPublished) {
    if !holding.missing.is_empty() {
        warn!(
            dir = %dir.display(),
            pages = %holding.missing.join(","),
            "holding pages: named by an enrollment but not servable — those domains \
             keep passway's built-in page"
        );
    }
    if !holding.written.is_empty() || !holding.pruned.is_empty() {
        info!(
            dir = %dir.display(),
            written = %holding.written.join(","),
            pruned = %holding.pruned.join(","),
            "holding pages: materialized"
        );
    }
    match &holding.map {
        Some(Published::Written { domains, .. }) => info!(
            dir = %dir.display(),
            domains,
            "holding pages: host map published"
        ),
        Some(Published::EmptySkipped) => warn!(
            dir = %dir.display(),
            "holding pages: the enrollment set is empty — leaving the existing map and \
             pages in place rather than un-branding every door on an ambiguous listing"
        ),
        Some(Published::Unchanged { .. }) | None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert_store::Enrollment;
    use std::net::SocketAddr;
    use std::time::{SystemTime, UNIX_EPOCH};
    use yah_object_store::{InMemoryObjectStore, ObjectStore};

    const LE: &str = "https://acme-v02.api.letsencrypt.org/directory";

    fn store() -> (Arc<InMemoryObjectStore>, ObjectCertStore) {
        let mem = Arc::new(InMemoryObjectStore::new());
        let certs = ObjectCertStore::new(mem.clone(), LE);
        (mem, certs)
    }

    fn enrollment(port: u16) -> Enrollment {
        Enrollment::new(
            SocketAddr::from(([127, 0, 0, 1], port)),
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        )
    }

    #[test]
    fn config_is_off_unless_a_routes_file_is_named() {
        assert_eq!(parse_publisher_config(|_| None).unwrap(), None);
        assert_eq!(
            parse_publisher_config(|k| (k == ROUTES_FILE_ENV).then(|| "  ".to_string())).unwrap(),
            None
        );
    }

    #[test]
    fn config_defaults_the_sweep_and_rejects_a_zero_one() {
        let cfg = parse_publisher_config(|k| {
            (k == ROUTES_FILE_ENV).then(|| "/etc/passway/routes".to_string())
        })
        .unwrap()
        .unwrap();
        assert_eq!(cfg.routes_file, PathBuf::from("/etc/passway/routes"));
        assert_eq!(cfg.sweep, Duration::from_secs(DEFAULT_SWEEP_SECS));
        assert!(cfg.pinned.is_empty(), "pins are opt-in");

        let get = |k: &str| match k {
            ROUTES_FILE_ENV => Some("/etc/passway/routes".to_string()),
            SWEEP_SECS_ENV => Some("0".to_string()),
            _ => None,
        };
        assert!(parse_publisher_config(get).is_err(), "a zero sweep is a spin");
    }

    #[test]
    fn publishes_one_entry_per_line_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("routes");
        let (_mem, certs) = store();
        certs.enroll("b.example.com", &enrollment(8444)).unwrap();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();

        assert_eq!(
            publish_once(&certs, &path, &[]).unwrap(),
            Published::Written {
                domains: 2,
                overridden: vec![]
            }
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "a.example.com=127.0.0.1:8443\nb.example.com=127.0.0.1:8444\n"
        );
    }

    #[test]
    fn an_unchanged_set_is_not_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes");
        let (_mem, certs) = store();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();

        assert_eq!(
            publish_once(&certs, &path, &[]).unwrap(),
            Published::Written {
                domains: 1,
                overridden: vec![]
            }
        );
        assert_eq!(
            publish_once(&certs, &path, &[]).unwrap(),
            Published::Unchanged { domains: 1 }
        );
        // And a real change writes again.
        certs.enroll("b.example.com", &enrollment(8444)).unwrap();
        assert_eq!(
            publish_once(&certs, &path, &[]).unwrap(),
            Published::Written {
                domains: 2,
                overridden: vec![]
            }
        );
    }

    #[test]
    fn an_empty_enrollment_set_never_blanks_a_live_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes");
        let (_mem, certs) = store();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();
        publish_once(&certs, &path, &[]).unwrap();

        certs.unenroll("a.example.com").unwrap();
        assert_eq!(
            publish_once(&certs, &path, &[]).unwrap(),
            Published::EmptySkipped
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "a.example.com=127.0.0.1:8443\n",
            "an empty listing must leave the last good table on disk"
        );
    }

    #[test]
    fn a_malformed_enrollment_costs_only_its_own_route() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes");
        let (mem, certs) = store();
        certs.enroll("good.example.com", &enrollment(8443)).unwrap();
        mem.put("enrolled/bad.example.com", b"{".to_vec()).unwrap();

        assert_eq!(
            publish_once(&certs, &path, &[]).unwrap(),
            Published::Written {
                domains: 1,
                overridden: vec![]
            }
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "good.example.com=127.0.0.1:8443\n"
        );
    }

    fn pin(host: &str, backend: &str) -> PinnedRoute {
        PinnedRoute {
            host: host.to_string(),
            backend: backend.to_string(),
        }
    }

    #[test]
    fn pins_parse_in_declaration_order_and_lowercase_the_host() {
        assert_eq!(parse_pinned_routes(PINNED_ROUTES_ENV, "   ").unwrap(), vec![]);
        assert_eq!(
            parse_pinned_routes(
                PINNED_ROUTES_ENV,
                " Cloud.Mesh.YAH.dev=127.0.0.1:8444 , b.example.com=10.0.0.1:443 "
            )
            .unwrap(),
            vec![
                pin("cloud.mesh.yah.dev", "127.0.0.1:8444"),
                pin("b.example.com", "10.0.0.1:443"),
            ]
        );
    }

    #[test]
    fn a_malformed_pin_refuses_to_start_the_publisher() {
        for bad in [
            "cloud.mesh.yah.dev",
            "=127.0.0.1:8444",
            "cloud.mesh.yah.dev=",
        ] {
            let err = parse_pinned_routes(PINNED_ROUTES_ENV, bad).unwrap_err();
            assert!(err.contains(PINNED_ROUTES_ENV), "got {err}");
        }
        let err = parse_pinned_routes(
            PINNED_ROUTES_ENV,
            "a.example.com=1.1.1.1:443,A.example.com=2.2.2.2:443",
        )
        .unwrap_err();
        assert!(err.contains("pinned twice"), "got {err}");
    }

    #[test]
    fn a_malformed_pin_names_the_tier_it_came_from() {
        // R870-F19: the parser is shared by both tiers, so the error has to
        // name the key the operator actually set. Telling someone with a typo
        // in YUBABA_HTTP_ROUTES_PINNED to go fix YUBABA_DEMUX_ROUTES_PINNED
        // sends them to a variable that is correct.
        let err = parse_pinned_routes(PINNED_HTTP_ROUTES_ENV, "cloud.mesh.yah.dev").unwrap_err();
        assert!(err.contains(PINNED_HTTP_ROUTES_ENV), "got {err}");
        assert!(!err.contains(PINNED_ROUTES_ENV), "got {err}");
    }

    #[test]
    fn a_pin_value_is_not_validated_so_the_redirect_token_parses() {
        // The `:80` loader's `redirect` token is not a socket address, and the
        // pin parser must not be the thing that decides it is illegal.
        assert_eq!(
            parse_pinned_routes(PINNED_HTTP_ROUTES_ENV, "cloud.mesh.yah.dev=redirect").unwrap(),
            vec![pin("cloud.mesh.yah.dev", "redirect")]
        );
    }

    #[test]
    fn a_pin_survives_a_sweep_that_the_enrollment_set_does_not_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes");
        let (_mem, certs) = store();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();
        let pins = vec![pin("cloud.mesh.yah.dev", "127.0.0.1:8444")];

        assert_eq!(
            publish_once(&certs, &path, &pins).unwrap(),
            Published::Written {
                domains: 2,
                overridden: vec![]
            }
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "a.example.com=127.0.0.1:8443\ncloud.mesh.yah.dev=127.0.0.1:8444\n",
            "the coordination hostname must not depend on being enrolled"
        );
        // The whole point: a second sweep does not quietly drop it.
        assert_eq!(
            publish_once(&certs, &path, &pins).unwrap(),
            Published::Unchanged { domains: 2 }
        );
    }

    #[test]
    fn a_pin_wins_a_collision_and_names_what_it_displaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes");
        let (_mem, certs) = store();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();
        certs.enroll("b.example.com", &enrollment(8444)).unwrap();

        assert_eq!(
            publish_once(&certs, &path, &[pin("b.example.com", "127.0.0.1:9999")]).unwrap(),
            Published::Written {
                domains: 2,
                overridden: vec!["b.example.com".to_string()]
            }
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "a.example.com=127.0.0.1:8443\nb.example.com=127.0.0.1:9999\n"
        );
    }

    #[test]
    fn pins_never_rescue_an_empty_enrollment_set() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes");
        let (_mem, certs) = store();
        let pins = vec![pin("cloud.mesh.yah.dev", "127.0.0.1:8444")];
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();
        publish_once(&certs, &path, &pins).unwrap();

        certs.unenroll("a.example.com").unwrap();
        assert_eq!(
            publish_once(&certs, &path, &pins).unwrap(),
            Published::EmptySkipped
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "a.example.com=127.0.0.1:8443\ncloud.mesh.yah.dev=127.0.0.1:8444\n",
            "a pins-only table would de-route every tenant — skip, do not rescue"
        );
    }

    #[test]
    fn pins_come_off_the_environment() {
        let get = |k: &str| match k {
            ROUTES_FILE_ENV => Some("/etc/passway-demux.routes".to_string()),
            PINNED_ROUTES_ENV => Some("cloud.mesh.yah.dev=127.0.0.1:8444".to_string()),
            _ => None,
        };
        let cfg = parse_publisher_config(get).unwrap().unwrap();
        assert_eq!(
            cfg.pinned,
            vec![pin("cloud.mesh.yah.dev", "127.0.0.1:8444")]
        );

        let bad = |k: &str| match k {
            ROUTES_FILE_ENV => Some("/etc/passway-demux.routes".to_string()),
            PINNED_ROUTES_ENV => Some("nope".to_string()),
            _ => None,
        };
        assert!(
            parse_publisher_config(bad).is_err(),
            "a malformed pin must not start a publisher that would drop it"
        );
    }

    #[test]
    fn no_temp_file_is_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes");
        let (_mem, certs) = store();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();
        publish_once(&certs, &path, &[]).unwrap();

        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, vec![std::ffi::OsString::from("routes")]);
    }

    #[test]
    fn a_stamp_only_change_does_not_rewrite_the_table() {
        // Enrollment records carry `enrolled_at`, which the render must not
        // include: a table rewritten every sweep would make the demux reload
        // (and an operator's mtime) meaningless.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes");
        let (mem, certs) = store();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();
        publish_once(&certs, &path, &[]).unwrap();

        let later = Enrollment::new(
            SocketAddr::from(([127, 0, 0, 1], 8443)),
            SystemTime::now(),
        );
        mem.put(
            "enrolled/a.example.com",
            serde_json::to_vec(&later).unwrap(),
        )
        .unwrap();
        assert_eq!(
            publish_once(&certs, &path, &[]).unwrap(),
            Published::Unchanged { domains: 1 }
        );
    }

    // ── The `:80` tier (R870-F1) ────────────────────────────────────────────

    fn both_tiers(dir: &std::path::Path) -> RoutePublisherConfig {
        RoutePublisherConfig {
            routes_file: dir.join("demux.routes"),
            http_routes_file: Some(dir.join("http.routes")),
            sweep: Duration::from_secs(DEFAULT_SWEEP_SECS),
            pinned: vec![],
            http_pinned: vec![],
            holding_dir: None,
        }
    }

    #[test]
    fn an_enrolled_domain_with_no_http_backend_publishes_a_redirect_route() {
        // The gap R870-F1 closes: before this, tenant #2 was routable on :443
        // and refused every scheme-less `curl tenant.example/install.sh`.
        let dir = tempfile::tempdir().unwrap();
        let cfg = both_tiers(dir.path());
        let (_mem, certs) = store();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();
        certs
            .enroll(
                "b.example.com",
                &enrollment(8444).with_http_backend(SocketAddr::from(([127, 0, 0, 1], 8081))),
            )
            .unwrap();

        let sweep = publish_sweep(&certs, &cfg).unwrap();
        assert_eq!(
            sweep.tls,
            Published::Written {
                domains: 2,
                overridden: vec![]
            }
        );
        assert_eq!(
            sweep.http,
            Some(Published::Written {
                domains: 2,
                overridden: vec![]
            })
        );
        assert_eq!(
            std::fs::read_to_string(&cfg.routes_file).unwrap(),
            "a.example.com=127.0.0.1:8443\nb.example.com=127.0.0.1:8444\n"
        );
        assert_eq!(
            std::fs::read_to_string(cfg.http_routes_file.as_ref().unwrap()).unwrap(),
            "a.example.com=redirect\nb.example.com=127.0.0.1:8081\n"
        );
    }

    #[test]
    fn a_sweep_with_no_http_file_configured_writes_only_the_443_table() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = RoutePublisherConfig {
            http_routes_file: None,
            ..both_tiers(dir.path())
        };
        let (_mem, certs) = store();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();

        assert_eq!(publish_sweep(&certs, &cfg).unwrap().http, None);
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, vec![std::ffi::OsString::from("demux.routes")]);
    }

    #[test]
    fn an_empty_enrollment_set_blanks_neither_tier() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = both_tiers(dir.path());
        let (_mem, certs) = store();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();
        publish_sweep(&certs, &cfg).unwrap();

        certs.unenroll("a.example.com").unwrap();
        let sweep = publish_sweep(&certs, &cfg).unwrap();
        assert_eq!(sweep.tls, Published::EmptySkipped);
        assert_eq!(sweep.http, Some(Published::EmptySkipped));
        assert_eq!(
            std::fs::read_to_string(cfg.http_routes_file.as_ref().unwrap()).unwrap(),
            "a.example.com=redirect\n",
            "an empty listing must leave the last good :80 table on disk too"
        );
    }

    #[test]
    fn an_unchanged_set_rewrites_neither_tier() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = both_tiers(dir.path());
        let (_mem, certs) = store();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();
        publish_sweep(&certs, &cfg).unwrap();

        let sweep = publish_sweep(&certs, &cfg).unwrap();
        assert_eq!(sweep.tls, Published::Unchanged { domains: 1 });
        assert_eq!(sweep.http, Some(Published::Unchanged { domains: 1 }));
    }

    #[test]
    fn the_two_tiers_pin_sets_are_separate_and_neither_leaks_onto_the_other() {
        // R870-F19 gave `:80` pins of its own, and the keys stayed separate
        // because the values are not interchangeable: `redirect` is not
        // something the demux can splice to, and a shared list would have to be
        // legal on both tiers. So a `:443` pin must NOT appear in the `:80`
        // table, which is what this asserts in both directions.
        let dir = tempfile::tempdir().unwrap();
        let cfg = RoutePublisherConfig {
            pinned: vec![pin("cloud.mesh.yah.dev", "127.0.0.1:8444")],
            http_pinned: vec![pin("mesh-only.example.com", "redirect")],
            ..both_tiers(dir.path())
        };
        let (_mem, certs) = store();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();

        publish_sweep(&certs, &cfg).unwrap();
        assert_eq!(
            std::fs::read_to_string(&cfg.routes_file).unwrap(),
            "a.example.com=127.0.0.1:8443\ncloud.mesh.yah.dev=127.0.0.1:8444\n"
        );
        assert_eq!(
            std::fs::read_to_string(cfg.http_routes_file.as_ref().unwrap()).unwrap(),
            "a.example.com=redirect\nmesh-only.example.com=redirect\n"
        );
    }

    #[test]
    fn an_http_pin_survives_a_sweep_that_the_enrollment_set_does_not_name() {
        // The exact failure R870-F19 exists to prevent: every door's
        // hand-curated `:80` table carried `cloud.mesh.yah.dev=redirect`, and
        // that host has no `enrolled/` object by design, so arming the tier
        // without this would have deleted the line on the first sweep.
        let dir = tempfile::tempdir().unwrap();
        let cfg = RoutePublisherConfig {
            http_pinned: vec![pin("cloud.mesh.yah.dev", "redirect")],
            ..both_tiers(dir.path())
        };
        let (_mem, certs) = store();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();

        let http = publish_sweep(&certs, &cfg).unwrap().http;
        assert_eq!(
            http,
            Some(Published::Written {
                domains: 2,
                overridden: vec![]
            })
        );
        let path = cfg.http_routes_file.clone().unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "a.example.com=redirect\ncloud.mesh.yah.dev=redirect\n"
        );
        // The whole point: a second sweep does not quietly drop it.
        assert_eq!(
            publish_sweep(&certs, &cfg).unwrap().http,
            Some(Published::Unchanged { domains: 2 })
        );
    }

    #[test]
    fn an_http_pin_beats_an_enrollment_and_says_which_one_it_displaced() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = RoutePublisherConfig {
            http_pinned: vec![pin("a.example.com", "127.0.0.1:9090")],
            ..both_tiers(dir.path())
        };
        let (_mem, certs) = store();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();

        assert_eq!(
            publish_sweep(&certs, &cfg).unwrap().http,
            Some(Published::Written {
                domains: 1,
                overridden: vec!["a.example.com".to_string()]
            })
        );
        assert_eq!(
            std::fs::read_to_string(cfg.http_routes_file.as_ref().unwrap()).unwrap(),
            "a.example.com=127.0.0.1:9090\n"
        );
    }

    #[test]
    fn an_http_pin_does_not_rescue_an_empty_enrollment_set() {
        // Same rule as `:443`, checked before the merge: a pins-only `:80`
        // table would de-route every tenant's apex, which is exactly what the
        // empty-set guard exists to prevent.
        let dir = tempfile::tempdir().unwrap();
        let cfg = RoutePublisherConfig {
            http_pinned: vec![pin("cloud.mesh.yah.dev", "redirect")],
            ..both_tiers(dir.path())
        };
        let (_mem, certs) = store();
        certs.enroll("a.example.com", &enrollment(8443)).unwrap();
        publish_sweep(&certs, &cfg).unwrap();

        certs.unenroll("a.example.com").unwrap();
        assert_eq!(
            publish_sweep(&certs, &cfg).unwrap().http,
            Some(Published::EmptySkipped)
        );
        assert_eq!(
            std::fs::read_to_string(cfg.http_routes_file.as_ref().unwrap()).unwrap(),
            "a.example.com=redirect\ncloud.mesh.yah.dev=redirect\n",
            "the last good :80 table stays, pins included"
        );
    }

    #[test]
    fn the_http_pins_come_off_their_own_environment_key() {
        let get = |k: &str| match k {
            ROUTES_FILE_ENV => Some("/var/lib/passway/routes/demux.routes".to_string()),
            HTTP_ROUTES_FILE_ENV => {
                Some("/var/lib/passway/routes/http-router.routes".to_string())
            }
            PINNED_HTTP_ROUTES_ENV => Some("cloud.mesh.yah.dev=redirect".to_string()),
            _ => None,
        };
        let cfg = parse_publisher_config(get).unwrap().unwrap();
        assert_eq!(cfg.http_pinned, vec![pin("cloud.mesh.yah.dev", "redirect")]);
        assert_eq!(cfg.pinned, vec![], "the :443 key was not set");

        let bad = |k: &str| match k {
            ROUTES_FILE_ENV => Some("/var/lib/passway/routes/demux.routes".to_string()),
            PINNED_HTTP_ROUTES_ENV => Some("nope".to_string()),
            _ => None,
        };
        let err = parse_publisher_config(bad).unwrap_err();
        assert!(err.contains(PINNED_HTTP_ROUTES_ENV), "got {err}");
    }

    #[test]
    fn the_http_routes_file_comes_off_the_environment_and_is_optional() {
        let get = |k: &str| match k {
            ROUTES_FILE_ENV => Some("/etc/passway-demux.routes".to_string()),
            HTTP_ROUTES_FILE_ENV => Some(" /etc/passway-http-router.routes ".to_string()),
            _ => None,
        };
        assert_eq!(
            parse_publisher_config(get)
                .unwrap()
                .unwrap()
                .http_routes_file,
            Some(PathBuf::from("/etc/passway-http-router.routes"))
        );

        // Unset, blank, and "set without the :443 file" all mean no :80 table —
        // the last because the demux file is what arms the publisher at all.
        let blank = |k: &str| match k {
            ROUTES_FILE_ENV => Some("/etc/passway-demux.routes".to_string()),
            HTTP_ROUTES_FILE_ENV => Some("  ".to_string()),
            _ => None,
        };
        assert_eq!(
            parse_publisher_config(blank)
                .unwrap()
                .unwrap()
                .http_routes_file,
            None
        );
        assert_eq!(
            parse_publisher_config(|k| (k == HTTP_ROUTES_FILE_ENV)
                .then(|| "/etc/passway-http-router.routes".to_string()))
            .unwrap(),
            None
        );
    }

    // ── The holding tier (R870-F8) ──────────────────────────────────────────

    /// What passway reads: the map, and each page body.
    fn holding_on_disk(dir: &std::path::Path) -> (String, Vec<String>) {
        let map = std::fs::read_to_string(dir.join(HOLDING_MAP_FILE)).unwrap_or_default();
        let mut pages: Vec<String> = std::fs::read_dir(dir.join(HOLDING_PAGES_DIR))
            .map(|entries| {
                entries
                    .flatten()
                    .filter_map(|e| e.file_name().to_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        pages.sort();
        (map, pages)
    }

    #[test]
    fn a_holding_reference_publishes_the_page_beside_a_map_of_who_shows_it() {
        let dir = tempfile::tempdir().unwrap();
        let (_mem, certs) = store();
        certs
            .enroll("a.example.com", &enrollment(8443).with_holding("camp"))
            .unwrap();
        certs
            .enroll("plain.example.com", &enrollment(8444))
            .unwrap();
        certs
            .write_holding_page("camp", b"<!doctype html><p>camp</p>".to_vec())
            .unwrap();

        let out = publish_holding(&certs, &certs.enrolled().unwrap(), dir.path()).unwrap();
        assert_eq!(out.written, vec!["camp".to_string()]);
        assert!(out.missing.is_empty());

        let (map, pages) = holding_on_disk(dir.path());
        // The domain with no override is ABSENT rather than rendered as a
        // token — passway's own page is what an absent entry means.
        assert_eq!(map, "a.example.com=camp\n");
        assert_eq!(pages, vec!["camp.html".to_string()]);
        assert_eq!(
            std::fs::read_to_string(dir.path().join(HOLDING_PAGES_DIR).join("camp.html")).unwrap(),
            "<!doctype html><p>camp</p>"
        );
    }

    /// The cost property the whole design turns on: N domains sharing a page
    /// are N map lines and ONE page file, not N copies.
    #[test]
    fn many_domains_on_one_page_materialize_one_file() {
        let dir = tempfile::tempdir().unwrap();
        let (_mem, certs) = store();
        for i in 0..5 {
            certs
                .enroll(
                    &format!("t{i}.example.com"),
                    &enrollment(8443).with_holding("camp"),
                )
                .unwrap();
        }
        certs
            .write_holding_page("camp", b"<p>camp</p>".to_vec())
            .unwrap();

        publish_holding(&certs, &certs.enrolled().unwrap(), dir.path()).unwrap();
        let (map, pages) = holding_on_disk(dir.path());
        assert_eq!(map.lines().count(), 5);
        assert_eq!(pages, vec!["camp.html".to_string()]);
    }

    #[test]
    fn a_page_that_does_not_exist_keeps_its_domains_out_of_the_map() {
        let dir = tempfile::tempdir().unwrap();
        let (_mem, certs) = store();
        certs
            .enroll("a.example.com", &enrollment(8443).with_holding("gone"))
            .unwrap();

        let out = publish_holding(&certs, &certs.enrolled().unwrap(), dir.path()).unwrap();
        assert_eq!(out.missing, vec!["gone".to_string()]);
        // The map never names a page that is not on disk, so a door never has
        // to decide what a dangling reference means.
        assert_eq!(holding_on_disk(dir.path()).0, "");
    }

    #[test]
    fn an_oversized_page_is_refused_by_the_publisher_too() {
        let dir = tempfile::tempdir().unwrap();
        let (mem, certs) = store();
        certs
            .enroll("a.example.com", &enrollment(8443).with_holding("huge"))
            .unwrap();
        // Straight into the bucket, past `write_holding_page`'s own ceiling —
        // the shape an object written by some other tool would have.
        mem.put("holding/huge", vec![b'x'; MAX_HOLDING_PAGE_BYTES + 1])
            .unwrap();

        let out = publish_holding(&certs, &certs.enrolled().unwrap(), dir.path()).unwrap();
        assert_eq!(out.missing, vec!["huge".to_string()]);
        assert_eq!(holding_on_disk(dir.path()).0, "");
    }

    #[test]
    fn a_second_sweep_over_an_unchanged_set_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (_mem, certs) = store();
        certs
            .enroll("a.example.com", &enrollment(8443).with_holding("camp"))
            .unwrap();
        certs
            .write_holding_page("camp", b"<p>camp</p>".to_vec())
            .unwrap();

        publish_holding(&certs, &certs.enrolled().unwrap(), dir.path()).unwrap();
        let again = publish_holding(&certs, &certs.enrolled().unwrap(), dir.path()).unwrap();
        assert!(
            again.written.is_empty(),
            "an unchanged body is not rewritten"
        );
        assert_eq!(again.map, Some(Published::Unchanged { domains: 1 }));
    }

    #[test]
    fn un_naming_a_page_prunes_it_and_empties_the_map() {
        let dir = tempfile::tempdir().unwrap();
        let (_mem, certs) = store();
        certs
            .enroll("a.example.com", &enrollment(8443).with_holding("camp"))
            .unwrap();
        certs
            .write_holding_page("camp", b"<p>camp</p>".to_vec())
            .unwrap();
        publish_holding(&certs, &certs.enrolled().unwrap(), dir.path()).unwrap();

        certs.set_holding("a.example.com", None).unwrap();
        let out = publish_holding(&certs, &certs.enrolled().unwrap(), dir.path()).unwrap();
        assert_eq!(out.pruned, vec!["camp".to_string()]);
        // An EMPTY map is written, unlike an empty route table: "nobody here
        // has an override" is a real state, and a door must be able to reach it
        // without a restart.
        let (map, pages) = holding_on_disk(dir.path());
        assert_eq!(map, "");
        assert!(pages.is_empty());
    }

    #[test]
    fn an_empty_enrollment_set_touches_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (_mem, certs) = store();
        std::fs::create_dir_all(dir.path().join(HOLDING_PAGES_DIR)).unwrap();
        std::fs::write(dir.path().join(HOLDING_MAP_FILE), "a.example.com=camp\n").unwrap();
        std::fs::write(
            dir.path().join(HOLDING_PAGES_DIR).join("camp.html"),
            "<p>camp</p>",
        )
        .unwrap();

        let out = publish_holding(&certs, &[], dir.path()).unwrap();
        assert_eq!(out.map, Some(Published::EmptySkipped));
        // Same ambiguity guard as the route tables: an empty listing and a
        // bucket pointed at the wrong prefix look identical from here.
        assert_eq!(holding_on_disk(dir.path()).0, "a.example.com=camp\n");
    }

    #[test]
    fn the_holding_dir_is_read_from_the_environment() {
        let get = |k: &str| match k {
            ROUTES_FILE_ENV => Some("/etc/passway-demux.routes".to_string()),
            HOLDING_DIR_ENV => Some(" /var/lib/passway/holding ".to_string()),
            _ => None,
        };
        assert_eq!(
            parse_publisher_config(get).unwrap().unwrap().holding_dir,
            Some(PathBuf::from("/var/lib/passway/holding"))
        );
        // Like the :80 tier, it adds a tier rather than arming the publisher.
        assert_eq!(
            parse_publisher_config(
                |k| (k == HOLDING_DIR_ENV).then(|| "/var/lib/passway/holding".to_string())
            )
            .unwrap(),
            None
        );
    }

    /// The layout is a contract with `passway::holding`, which is in another
    /// Cargo workspace and cannot see these constants. Both ends pin them.
    #[test]
    fn the_layout_matches_what_passway_reads() {
        assert_eq!(HOLDING_MAP_FILE, "hosts");
        assert_eq!(HOLDING_PAGES_DIR, "pages");
    }
}

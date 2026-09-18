//! Centralized Cloudflare credential resolution.
//!
//! Before this module, every Cloudflare reconciler hardcoded two things:
//! the provider file path (`.yah/infra/providers/cloudflare.toml`) and the
//! global keystore slots (`cloudflare-api-token`, plus the R2 S3 keys). That
//! forced one account / one key across the whole workspace — two services
//! could not target different Cloudflare accounts (e.g. `yah.dev` vs a
//! `scrabcake` account), and a single over-broad token was shared by all.
//!
//! [`CfProvider`] resolves credentials from the mirror slot's `use = "<id>"`
//! provider instead. Each service's mirror names its provider; the provider
//! file (`.yah/infra/providers/<id>.toml`) declares its own `account_id` and
//! credential references. The credential fields are `keystore://<slot>` URIs:
//!
//! ```toml
//! id            = "cloudflare-yah"
//! kind          = "cloudflare"
//! account_id    = "…"
//! default_zone  = "yah.dev"
//! credentials   = "keystore://cloudflare-api-token"      # management API token
//! r2_access_key = "keystore://cloudflare-r2-access-key-id"  # optional S3 override
//! r2_secret_key = "keystore://cloudflare-r2-secret-key"     # optional S3 override
//! ```
//!
//! A provider that omits a credential field falls back to the historical
//! global slot, so today's single-provider setup keeps working unchanged —
//! the only required migration is pointing `credentials` at a real slot name.
//!
//! NB isolation caveat: separate *tokens* only give hard isolation across
//! separate Cloudflare *accounts*. Account-scoped grants (Workers Scripts,
//! R2) are account-wide, so two providers sharing one `account_id` are not
//! isolated at the worker/bucket layer regardless of which slot they name.
//!
//! @yah:relay(R891, "Retire the old Cloudflare R2 pair: migrate the non-vault consumers R876-T10 found, then unblock noisetable R131-T19 step 4")
//! @yah:at(2026-09-16T05:20:21Z)
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:gotcha("WHY THIS RELAY EXISTS, AND WHAT IS ALREADY SAFE. R876-T10 enumerated the yah-side consumers of Cloudflare account-wide API token id 92414fa46ea2b8a5f06df51bae1a3512 (name `yah-dev-1a3512`, account 3948dc292e724e71b0deefde0ea95999) and returned NOT SAFE TO DELETE. The vault-slot route is already fully migrated: every slot-name consumer reads the NEW pair (fingerprints f293d33294250d04 / 8d0ad8c9470d48df), and all 17 CF/R2 vault slots were fingerprinted clean. What is NOT migrated is four live consumers reading the OLD pair (38da59ad427a7e1f / 9198605d52642726) by a NON-VAULT route — systemd EnvironmentFiles on the fleet — plus a raw copy of the token in the repo root. Until those move, deleting the token breaks them with no way back, because the R2 secret is SHA-256 of a token value Cloudflare shows once and stores nowhere. The parked slots cloudflare-r2-access-key-id-pre-r131t19 / cloudflare-r2-secret-key-pre-r131t19 hold the old pair and MUST NOT be deleted until this relay closes.")
//! @yah:gotcha("FINGERPRINTS, AND THE RULE THAT MAKES THIS SAFE TO WORK ON. Never print, echo or cat a secret value. The only permitted shape is `<source> | shasum -a 256 | cut -c1-16`, computed ON the host holding the value, comparing 16 hex chars only. OLD pair = 38da59ad427a7e1f (access-key-id) / 9198605d52642726 (secret). NEW pair = f293d33294250d04 / 8d0ad8c9470d48df. A third fingerprint appears in R891-F4: 3e9091fc44f7060b is the `cloudflare-legacy-yah` vault slot, a DIFFERENT credential. Note also that the raw token value and the R2 secret are chained, not independent: sha256(token) == the R2 secret value, which is how R876-T10 proved the repo-root .env copy is the token itself. @Ashguard:coffee re-derived that chain independently before signing T10 off — .env's R2_TOKEN hashes to 9198605d52642726 exactly.")
//! @yah:gotcha("DO NOT READ CLOUDFLARE'S `last_used_on` AS EVIDENCE. The token reports status=active, last_used_on=NULL. That field tracks api.cloudflare.com bearer calls, NOT S3-protocol R2 auth — which is what all four live consumers use — so a null there is consistent with heavy daily use. This clause is R876-T10's inference; the four consumers below are direct on-host measurement and settle the question regardless. (Operational note from that audit: the token metadata endpoint answers via the `cloudflare-legacy-yah` slot; the `cloudflare-api-token` slot returns error 9109 on it.)")
//! @yah:next("DO NOT DELETE THE PARKED VAULT SLOTS cloudflare-r2-access-key-id-pre-r131t19 / cloudflare-r2-secret-key-pre-r131t19 until this relay closes. They hold the old DERIVED pair and are the rollback for every ticket here. Note they are not a full rollback: they do not hold the raw token, which is why R891-B3 exists.")
//! @yah:next("RELAY ACCEPTANCE, in order. R891-T2 (four live fleet units off the old pair) and R891-B3 (.env: raw token to the vault, exports to the new pair) are the two that actually gate the deletion, and T2 comes first — while live units still read the old pair, retiring the last copy of the token is exactly the failure this relay prevents. R891-T4 is an operator call that can run in parallel. R891-B5 and R891-B6 are hygiene found by the same audit and gate nothing. WHEN T2, B3 and T4 are all closed, the answer R876-T10 owed becomes 'safe to delete' — at that point tell the noisetable camp so they can run their R131-T19 step 4. That handoff to the other camp IS this relay's end state; the deletion itself is theirs to perform, never ours.")
//! @yah:gotcha("R891-T1 AND R891-T2 ARE ONE JOB FILED TWICE — read before dispatching, because a wave will otherwise send two agents at four live production units. Byte-identical titles, same parent, and two separate annotation blocks in the same file header (oss/yubaba/crates/yubaba/src/litestream.rs:98 and :106). T2 IS THE STRICT SUPERSET and is the one to keep: it carries the us-east-001 reading trap (yah-scryer.service's EnvironmentFile= lives ONLY in the drop-in 10-snapshot-producer.conf, so reading the main unit gives a confident false negative — resolve with `systemctl show yah-scryer -p EnvironmentFiles`), the us-west consumer enumeration (/etc/yah-cloud/litestream.env on us-west-011/013/014, loaded by an ACTIVE yubaba.service on each plus an ACTIVE litestream-headscale.service on -013 = 4 units across 3 nodes), and the delete-instead-of-rotate arm in its verify. T1 has nothing T2 lacks. RECOMMEND archiving T1; not done from here because this is the noisetable camp and archiving another camp's ticket is an editorial call, not a measurement. Noticed 2026-09-13 by @Ashguard:dove (session:d1d77f29) working noisetable R131-T19, which is the ticket this relay's acceptance hands back to.")
//! @yah:handoff("NOISETABLE HAS PICKED UP THE FLEET MIGRATION — R891-T2 IS CLAIMED AND IN PROGRESS as of 2026-09-15, dispatched by the noisetable R131 relay leader @Ashguard:dove (session:72a389c4) with the operator's explicit authorization to act cross-camp on live production nodes. R891-B3 follows after T2, per this relay's own stated ordering. This is not a land-grab: R891 had sat `open` and UNCLAIMED for three days with all six children untouched, and it is the sole remaining gate on noisetable R131-T19 step 4 (deleting account-wide Cloudflare token 92414fa46ea2b8a5f06df51bae1a3512 / `yah-dev-1a3512`), which is itself the last act of noisetable relay R131. The courier was briefed on both traps this relay records: that `50-r858t5.conf` calls itself a TEMPORARY R858-T5 exercise — so the delete-vs-rotate call comes BEFORE any rotation, and deleting a consumer beats migrating one — and that yah-scryer.service carries no EnvironmentFile= line in its main unit, only in the `10-snapshot-producer.conf` drop-in, so the unit must be resolved with `systemctl show -p EnvironmentFiles` and never by reading the unit. It was also told to delete NOTHING from the vault: the `-pre-r131t19` parking slots are the only way back, and the old Cloudflare token stays alive because its deletion is noisetable's step 4, not this ticket's. R891-T4 remains blocked_on(operator) and untouched. When T2, B3 and T4 close, tell the noisetable camp — R131-T19 is watching this relay.")
//! @yah:gotcha("R891-T1 IS ARCHIVED AS OF 2026-09-15 — the duplicate is resolved, and this supersedes the earlier gotcha on this relay that recommended the archive but declined to perform it. R891-T1 and R891-T2 were the same job filed twice: byte-identical titles, same parent, two annotation blocks in one file header at oss/yubaba/crates/yubaba/src/litestream.rs:98 (T1) and :106 (T2). T2 is the strict superset and is the one kept; T1 carried nothing T2 lacks. The earlier note correctly declined to archive another camp's ticket on a measurement alone — so it was put to the operator as an editorial call and they answered 'archive T1' on 2026-09-15. Performed by the noisetable R131 relay leader @Ashguard:dove (session:72a389c4), because R891 gates noisetable R131-T19 step 4. WHY IT MATTERED: with both live, `yah board ready --relay R891` advertised two identical claimable rows, and a dispatcher working the frontier would have sent TWO agents at the same four live production units (us-east-001 yah-scryer.service, and /etc/yah-cloud/litestream.env on us-west-011/-013/-014). The archived snapshot is preserved in the event shard and remains inspectable via board_show.")
//! @yah:handoff("FLEET-WIDE SWEEP — R891-T2's four consumers were the only ones, now measured across ALL NINE declared nodes rather than the five R876-T10 reached (2026-09-16). Method: both old-pair VALUES piped from `yah keys get cloudflare-r2-{access-key-id,secret-key}-pre-r131t19` into `ssh <node> 'sudo -n grep -rlFI -f - /etc /root /home /var/lib/yah /var/lib/yah-cloud /opt'` — patterns arrive on stdin, only FILENAMES come back, no value is printed in either direction. Zero hits on us-east-001, us-south-001, us-west-001, -002, -003, -011, -013 and -014, all eight with `sudo -n id -u` = 0 confirmed separately so the empty result is a real read and not a permission failure wearing a clean face. This closes R891-B3's @yah:assumes ('reached only 5 of 9 fleet nodes') in the reassuring direction: after T2 the fleet holds no copy of the old pair anywhere those paths reach.")
//! @yah:gotcha("ONE BOUNDED GAP IN THAT SWEEP, NAMED SO NOBODY READS IT AS FLEET-WIDE-CLEAN WITHOUT THE ASTERISK: us-west-015 (yah@192.168.10.15, mesh 100.64.0.7) has NO passwordless sudo — `sudo -n id -u` answers 'a password is required', so its grep ran as the unprivileged `yah` user and could not read root-owned files. The unprivileged pass found nothing, and root SSH is refused (publickey,password,keyboard-interactive). What bounds the gap: 015 is not a systemd box at all (`systemctl` is 'command not found', the login shell is zsh) and it has NO /etc/yah-cloud and NO /etc/yah, so the consumer class this relay is about — a systemd EnvironmentFile — cannot exist there. A root-owned credential file elsewhere on 015 remains formally unchecked. Settle it, if anyone wants it settled, with a sudo-capable credential on that one box.")
//! @yah:handoff("RELAY COMPLETE — THE VERDICT R876-T10 OWED IS NOW **SAFE TO DELETE**, and noisetable R131-T19 step 4 is unblocked (2026-09-16, @Ashguard:vortex session:c8036b0c, one pass). All five children are at review: T2 (four live fleet units migrated and each proven to write to R2 with the new pair), B3 (raw token vaulted as `cloudflare-r2-token-pre-r131t19`, .env rotated and R2_TOKEN retired), T4 (all nine GitHub repo secrets DELETED per the operator's R915 call, not re-set), B5 (record-time redaction landed in the forms writer + five sidecars scrubbed), B6 (dashboard landmine defused and the class closed by a load-time validator). WHAT NOISETABLE SHOULD DO: delete Cloudflare API token 92414fa46ea2b8a5f06df51bae1a3512 (`yah-dev-1a3512`, account 3948dc292e724e71b0deefde0ea95999). Nothing yah-side reads it any more. THE DELETION IS THEIRS TO PERFORM AND WAS NOT PERFORMED HERE — that boundary was the point of this relay and it held. AFTER they confirm the deletion, and only then, the three parking slots may be retired: `cloudflare-r2-access-key-id-pre-r131t19`, `cloudflare-r2-secret-key-pre-r131t19` and the new `cloudflare-r2-token-pre-r131t19`. Until that confirmation they are the whole rollback, and the token slot is the stronger of the two — the derived pair can be reconstructed from the raw token, never the reverse.")
//! @yah:verify("THE FOUR RESIDUAL RISKS, RANKED, so nobody reads 'safe to delete' as 'nothing can go wrong'. (1) ORG-LEVEL GITHUB SECRETS ARE UNCHECKED AND WILL STAY THAT WAY — `GET /orgs/yah-ai/actions/secrets` is 403 for the vault's `github-pat`, and the operator's call was to ignore it. If an org secret holds the old pair it simply stops working at deletion; nothing in this repo runs on push, so the blast radius is a manual workflow_dispatch nobody dispatches. (2) us-west-015 was swept unprivileged (no passwordless sudo, root SSH refused). It is not a systemd box and has no /etc/yah or /etc/yah-cloud, so it cannot hold the consumer class this relay is about, but a root-owned file there is formally unchecked. (3) THE SWEEP IS TEXT-ONLY — `grep -I` skips binaries, so a credential baked into a binary, a database or an archive on any node would not have been found. Nothing suggests one exists; it is simply not something a text sweep can rule out. (4) THE DEV LITESTREAM PATH IS PROVEN TO WRITE, NOT PROVEN TO RESTORE. Each us-west node wrote a snapshot + WAL segment to R2 with the rotated file, but no leadership transition was forced afterwards, so `on_became_leader`'s install -> restore -> deploy ordering has not run against the new credential. R858-T5 proved that leg live on the OLD pair; the credential is the only thing that changed and it is proven good for the same bucket in both directions.")
//!
//! @yah:ticket(R891-B3, "Repo-root .env holds the raw Cloudflare token plus the old R2 pair, and camp-env.sh exports it into every camp session")
//! @yah:status(review)
//! @yah:at(2026-09-16T04:43:18Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R891)
//! @yah:severity(high)
//! @yah:gotcha("MEASURED TWICE, INDEPENDENTLY — by the R876-T10 courier and again by @Ashguard:coffee before sign-off. /Users/leif/ss/yah/.env (untracked, gitignored) contains R2_TOKEN whose SHA-256 IS the old R2 secret value: hashing that derived secret again yields 9198605d52642726, the recorded old-secret fingerprint, exactly. So this file holds not merely the derived key pair but the ONE-TIME-SHOWN TOKEN VALUE ITSELF, which Cloudflare stores nowhere and cannot reissue. app/yah/desktop/camp-env.sh:47-49 sources it with `set -a`, which exports every variable in it into the environment of every camp session on this machine.")
//! @yah:assumes("That .env is the only such copy on this machine. R876-T10's sweep covered the repo tree, .yah/infra, .yah/qed, ~/.config and ~/.aws and found no other — but it reached only 5 of 9 fleet nodes, and the on-node consumers it did find are R891-T2's.")
//! @yah:next("THE DECISION THIS TICKET OWES, and it is genuinely two-sided so do not just pick the tidy one. .env being the sole surviving copy of the raw token means it is ALSO the only true way back if a consumer turns out to need the old value — the parked vault slots cloudflare-r2-access-key-id-pre-r131t19 / cloudflare-r2-secret-key-pre-r131t19 hold only the DERIVED pair, not the token. So 'shred .env' and 'keep .env' are both wrong as stated. The shape that resolves it: move the raw token into a vault slot of its own (it is recovery material, and the vault is where recovery material belongs), rotate .env's exported vars to the NEW pair so no session inherits a credential slated for deletion, and only then treat the old value as retired. Sequence this AFTER R891-T2 — while live units still read the old pair, deleting the last copy of the token is the failure mode this whole relay exists to prevent.")
//! @yah:verify("DONE = (1) `set -a`-sourced .env no longer exports any variable fingerprinting to the OLD pair (38da59ad427a7e1f / 9198605d52642726) — check with the on-host `shasum -a 256 | cut -c1-16` form, never by printing a value; (2) the raw token value is recoverable from a named vault slot, proven by the derivation test (sha256 of the slot's value fingerprints to 9198605d52642726) without the value being printed; (3) a fresh camp session started after the change inherits no old-pair credential. Tier: Cleric.")
//! @yah:handoff("DONE — THE RAW TOKEN IS VAULTED AND .env NO LONGER EXPORTS ANYTHING ON THE OLD PAIR (2026-09-16, @Ashguard:vortex session:c8036b0c). Executed the exact shape this ticket's @yah:next argued for, in order, after R891-T2 closed. (1) The raw account-wide Cloudflare token moved from .env's R2_TOKEN into the new vault slot `cloudflare-r2-token-pre-r131t19`, piped value-to-value (`grep '^R2_TOKEN=' .env | cut -d= -f2- | tr -d '\\\"' | tr -d '\\\\n' | yah keys set …`) so it was never printed, never in argv and never in shell history. (2) .env's R2_ACCESS_KEY / R2_SECRET_KEY rewritten from the vault slots cloudflare-r2-access-key-id / cloudflare-r2-secret-key by a one-shot python script (staged .env.r891-new at 0600 + os.replace, so a failure would have left .env untouched; script deleted after the run). (3) R2_TOKEN's line replaced by a seven-line comment naming the vault slot that now holds it and why it is recovery material — nothing in-tree ever read that variable (repo-wide grep: only W235-remote-qed.md prose uses the name as an example). CLOUDFLARE_KEY (3e9091fc44f7060b, the `cloudflare-legacy-yah` slot) and S3_* are different credentials and were left alone. SIDE EFFECT WORTH KNOWING: .env was mode 0644 — world-readable, holding every credential on this workstation — and is now 0600.")
//! @yah:verify("ALL THREE DONE CRITERIA MEASURED, PLUS THE ASSUMES DISCHARGED. (1) A shell doing exactly what camp-env.sh:47-49 does (`set -a; . ./.env; set +a`) now inherits R2_ACCESS_KEY = f293d33294250d04, R2_SECRET_KEY = 8d0ad8c9470d48df, CLOUDFLARE_KEY = 3e9091fc44f7060b, and `R2_TOKEN` unset — no variable it exports fingerprints to the old pair. (2) THE DERIVATION TEST PASSES AGAINST THE NEW SLOT, which is the proof that the one-time-shown token is genuinely recoverable: `yah keys get cloudflare-r2-token-pre-r131t19 | shasum -a 256 | cut -c1-16` = 0b720112a49d6375 (matches .env's pre-change R2_TOKEN exactly), and hashing its SHA-256 DIGEST again — i.e. fingerprinting the value sha256(token) derives — gives 9198605d52642726, the recorded old-secret fingerprint, to the character. The recovery chain token -> old secret is intact in the vault. (3) THE @yah:assumes IS NOW DISCHARGED, not still assumed: both old-pair values AND the raw token were swept as literal patterns (piped on stdin to `grep -rlFI -f -`, so nothing was written to disk or printed) across the whole repo tree minus target/.git/node_modules, plus ~/.config, ~/.aws, ~/.zshrc, ~/.zshenv, ~/.profile — and across all nine fleet nodes (see R891's handoff). Zero hits for the old SECRET and zero for the raw TOKEN anywhere. Three files did match the old ACCESS KEY ID — crates/yah/forms/src/lib.rs, oss/yubaba/crates/cloud/src/reconciler/cf_creds.rs, oss/kamaji/crates/kamaji-bin/src/server.rs — and every one is board annotation prose, because THE OLD ACCESS KEY ID IS THE TOKEN ID ITSELF: `printf '92414fa46ea2b8a5f06df51bae1a3512' | shasum -a 256 | cut -c1-16` = 38da59ad427a7e1f. That identity is worth carrying forward — the access-key-id half of an R2 pair is a public identifier, never secret material, so only the secret half and the raw token ever needed protecting.")
//!
//! @yah:ticket(R891-T4, "GitHub repo secrets on yah-ai/yah are pre-rotation and unverifiable; org-level secrets were never checked (403)")
//! @yah:at(2026-09-16T05:00:25Z)
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R891)
//! @yah:gotcha("WRITE-ONLY BY DESIGN, SO NO AGENT CAN CLOSE THIS BY MEASUREMENT — that is why it is blocked_on(operator) rather than merely hard. On yah-ai/yah the secrets CF_R2_ACCESS_KEY_ID, CF_R2_SECRET_KEY, CF_R2_ACCOUNT_ID, CLOUDFLARE_TOKEN and R2_ACCESS_KEY ALL report last-updated 2026-06-19, i.e. before the R131-T19 rotation, so the dates say old pair. GitHub never returns a secret's value, so fingerprinting them is impossible from outside. `gh secret list --org yah-ai` returns HTTP 403 for the agent credential, so ORG-level secrets are wholly unchecked and could hold another copy.")
//! @yah:assumes("That 'last updated 2026-06-19' implies the old pair. It is strong circumstantial evidence (the rotation post-dates it) but it is not a fingerprint, and a secret could have been re-set to the same value.")
//! @yah:next("WHY THIS IS NOT SAFELY IGNORABLE EVEN THOUGH NOTHING RUNS ON PUSH. Per CLAUDE.md no workflow in this repo has an `on: push` trigger — but these secrets are consumed by fleet-index.yml:153-156 and smoke.yml:86, both `workflow_dispatch`. Dormant is not dead: the next manual dispatch after the token is deleted fails, and it fails in CI where nobody is watching for a credential error. Treat 'dormant but dispatchable' as live.")
//! @yah:next("THE OPERATOR CALL, phrased so one answer unblocks it: for each of the five repo secrets, either (a) re-set it to the NEW pair (f293d33294250d04 / 8d0ad8c9470d48df) — safe and cheap whether or not it was already correct, and it makes the date evidence moot; or (b) delete it if the consuming workflow is retired. Then run `gh secret list --org yah-ai` with a credential that has org scope and apply the same rule to anything Cloudflare-shaped it returns. Either way the agent-visible state afterwards is a last-updated date AFTER the rotation, which is the only signal an agent can check. Tier: Cleric.")
//! @yah:verify("DONE = all five repo secrets report a last-updated date later than the R131-T19 rotation (or are gone), AND `gh secret list --org yah-ai` has been run by someone with org scope and its Cloudflare-shaped entries dispositioned, AND one `workflow_dispatch` of fleet-index.yml succeeds against R2 afterwards. That last one is the only end-to-end proof available here.")
//! @yah:handoff("OPERATOR ANSWERED, AND THE ANSWER WAS ARM (b) FOR EVERYTHING, NOT JUST THE CLOUDFLARE FIVE. Asked mid-session on 2026-09-16, Leif's words: 'if you get to T4 please note R915 i.e. we can just remove all GitHub repo secrets don't need them'. That is the R915 non-goal applied to this ticket — GitHub is a git remote, QED is the CI, so a repo secret exists to feed a workflow the ecosystem is retiring. DONE: all NINE Actions repo secrets on yah-ai/yah deleted, each a 204, verified by a follow-up list returning total_count 0. They were CF_R2_ACCESS_KEY_ID, CF_R2_ACCOUNT_ID, CF_R2_SECRET_KEY, CLOUDFLARE_TOKEN, R2_ACCESS_KEY (the five this ticket named) plus DEEPSEEK_API_KEY, GROQ_API_KEY, HETZNER_API_TOKEN, OPENROUTER_API_KEY — every one last-updated 2026-06-19T22:40Z, i.e. all pre-rotation. Done via direct REST (`https://api.github.com/repos/yah-ai/yah/actions/secrets/<name>`, DELETE, bearer from the vault slot `github-pat`), NOT via `gh` — this ticket is filed under the decision that retires that tool, so using it here would have been the wrong way to honour the answer. The PAT was piped from the vault to a 0600 temp and removed afterwards; no value was printed.")
//! @yah:verify("TWO OF THREE CRITERIA MET; THE THIRD IS SUPERSEDED BY THE ANSWER, AND THAT IS STATED RATHER THAN QUIETLY DROPPED. (1) 'all five repo secrets report a date later than the rotation OR ARE GONE' — gone, all nine, 204 each, confirmed by a re-list returning total_count 0 with an empty array. (2) 'one workflow_dispatch of fleet-index.yml succeeds against R2 afterwards' — NO LONGER MEANINGFUL AND DELIBERATELY NOT RUN. That criterion assumed arm (a), re-setting the secrets; under arm (b) a dispatch of fleet-index.yml or smoke.yml now fails at its own validate-required-secrets step, by design, because the credentials it wanted are gone and the operator's instruction is that it does not need them. Per CLAUDE.md no workflow in this repo has an `on: push` trigger, releases are cut by local QED recipes, and R915 is removing `gh` from the ecosystem — so a green Actions run is not evidence anyone should be collecting. (3) THE ORG-LEVEL GAP IS STILL OPEN AND IS NOT MINE TO CLOSE: `GET /orgs/yah-ai/actions/secrets` with the vault's `github-pat` returns HTTP 403 'You must be an org admin or have the actions secrets fine-grained permission' — the identical wall R876-T10 hit, now reconfirmed from a different credential and a different route, so it is a permission fact about the token rather than a quirk of `gh`. Anything Cloudflare-shaped at org level remains unchecked and would still be live after the token deletion. Closing it needs an org-admin credential; see R891's own next steps.")
//! @yah:handoff("ORG-LEVEL GAP: ACCEPTED, NOT CLOSED — operator decision, 2026-09-16. Put to Leif as a three-way call (check it yourself / grant the PAT org scope / ignore it) and the answer was IGNORE: org secrets do not gate the token deletion. The reasoning that makes that defensible rather than merely convenient — no workflow in this repo has an `on: push` trigger, releases are cut by local QED recipes writing straight to R2, and R915 is actively removing GitHub from every critical path — so an org secret holding a stale Cloudflare credential can only break a manual `workflow_dispatch` of a workflow nobody dispatches. RECORD IT AS A KNOWN UNKNOWN, not as a clean result: nobody has ever enumerated yah-ai's org-level Actions secrets, and if one holds a copy of the old pair it will simply stop working when noisetable deletes the token. That is the accepted outcome, chosen deliberately.")

use std::path::Path;

use anyhow::{Context, Result};
use workload_spec::{NamespaceId, TenantId};

use crate::config::ProviderConfig;

/// Global fallback slot/env for the management API token when a provider
/// file omits `credentials`. Preserves pre-multi-provider behavior.
const DEFAULT_API_TOKEN_SLOT: &str = "cloudflare-api-token";
const DEFAULT_API_TOKEN_ENV: &str = "CLOUDFLARE_API_TOKEN";

/// Read `[namespaces.<namespace>].<field>` from a provider file, but only when a
/// non-singleton namespace is active (W206 per-namespace override). Returns
/// `None` for the singleton namespace or when the section/field is absent, so
/// single-namespace deployments never touch the `[namespaces]` table.
fn ns_override_in<'a>(
    cfg: &'a ProviderConfig,
    namespace: &NamespaceId,
    field: &str,
) -> Option<&'a str> {
    if namespace.is_singleton() {
        return None;
    }
    cfg.fields
        .get("namespaces")
        .and_then(|n| n.get(namespace.0.as_str()))
        .and_then(|t| t.get(field))
        .and_then(|v| v.as_str())
}

/// A resolved Cloudflare provider: its parsed config file, the resolved
/// `account_id`, and the `(tenant, namespace)` scope it was resolved for.
/// Accessors prefer a `[namespaces.<ns>]` override over the top-level field and
/// derive `(tenant, namespace, provider)`-scoped keystore slots when the
/// provider file leaves a credential unset (W206).
#[derive(Debug)]
pub(crate) struct CfProvider {
    pub cfg: ProviderConfig,
    pub account_id: String,
    provider_id: String,
    tenant: TenantId,
    namespace: NamespaceId,
}

impl CfProvider {
    /// Load `.yah/infra/providers/<provider_id>.toml` for the singleton
    /// `(tenant, namespace)` scope — the pre-W206 behavior. Callers that know
    /// the workload's namespace should use [`CfProvider::resolve_scoped`].
    pub fn resolve(workspace_root: &Path, provider_id: &str) -> Result<Self> {
        Self::resolve_scoped(
            workspace_root,
            provider_id,
            &TenantId::singleton(),
            &NamespaceId::singleton(),
        )
    }

    /// Load `.yah/infra/providers/<provider_id>.toml` and resolve `account_id`
    /// for a specific `(tenant, namespace)` scope. A `[namespaces.<namespace>]`
    /// section in the provider file overrides the top-level `account_id`, and
    /// [`CfProvider::zone`] / credential accessors resolve against the same
    /// scope. Fails before any network I/O so a misconfigured provider is caught
    /// at the top of a reconcile.
    pub fn resolve_scoped(
        workspace_root: &Path,
        provider_id: &str,
        tenant: &TenantId,
        namespace: &NamespaceId,
    ) -> Result<Self> {
        let path = crate::paths::provider_toml(workspace_root, provider_id);
        let cfg = ProviderConfig::load(&path).with_context(|| {
            format!(
                "loading Cloudflare provider `{provider_id}` — expected at {}",
                path.display()
            )
        })?;
        let account_id = ns_override_in(&cfg, namespace, "account_id")
            .or_else(|| cfg.fields.get("account_id").and_then(|v| v.as_str()))
            .with_context(|| {
                format!(
                    "provider `{provider_id}` ({}): missing `account_id` field — \
                     add your Cloudflare account ID (top-level or under \
                     [namespaces.{}])",
                    path.display(),
                    namespace.0,
                )
            })?
            .to_string();
        Ok(Self {
            cfg,
            account_id,
            provider_id: provider_id.to_string(),
            tenant: tenant.clone(),
            namespace: namespace.clone(),
        })
    }

    /// The Cloudflare zone this provider serves for the active namespace:
    /// `[namespaces.<ns>].zone` when set, else the top-level `default_zone`.
    /// `None` when neither is declared (e.g. an R2-only provider).
    ///
    // Consumed once the CF reconcilers become namespace-aware (the F5→T6
    // wiring); until then only the tests exercise it.
    #[allow(dead_code)]
    pub fn zone(&self) -> Option<String> {
        self.ns_override("zone")
            .or_else(|| self.cfg.fields.get("default_zone").and_then(|v| v.as_str()))
            .map(str::to_string)
    }

    /// Management API token — required. Reads the provider's
    /// `credentials = "keystore://<slot>"` when set, else the global default
    /// slot (`cloudflare-api-token` / `$CLOUDFLARE_API_TOKEN`).
    pub fn api_token(&self) -> Result<String> {
        let (slot, env) = self.api_token_slot()?;
        fob::get_or_env(&slot, &env)
            .with_context(|| format!("resolving `{slot}` for provider `{}`", self.provider_id))?
            .with_context(|| {
                format!("`{slot}` not found — `yah keys set {slot} <token>` or export {env}")
            })
    }

    /// Management API token if present, `None` otherwise — for paths where the
    /// token is optional (e.g. CDN cache purge is skipped when unset).
    pub fn api_token_opt(&self) -> Option<String> {
        let (slot, env) = self.api_token_slot().ok()?;
        fob::get_or_env(&slot, &env).ok().flatten()
    }

    /// R2 S3 data-plane keys `(access_key, secret_key)`. Provider fields
    /// `r2_access_key` / `r2_secret_key` override the global R2 slots when set.
    pub fn r2_keys(&self) -> Result<(String, String)> {
        use super::r2_publish::{
            R2_ACCESS_KEY_ENV, R2_ACCESS_KEY_SLOT, R2_SECRET_KEY_ENV, R2_SECRET_KEY_SLOT,
        };
        let (a_slot, a_env) =
            self.field_slot("r2_access_key", R2_ACCESS_KEY_SLOT, R2_ACCESS_KEY_ENV)?;
        let (s_slot, s_env) =
            self.field_slot("r2_secret_key", R2_SECRET_KEY_SLOT, R2_SECRET_KEY_ENV)?;
        let access = fob::get_or_env(&a_slot, &a_env)
            .with_context(|| format!("resolving R2 access key `{a_slot}`"))?
            .with_context(|| {
                format!("R2 access key `{a_slot}` not found — `yah keys set {a_slot}` or export {a_env}")
            })?;
        let secret = fob::get_or_env(&s_slot, &s_env)
            .with_context(|| format!("resolving R2 secret key `{s_slot}`"))?
            .with_context(|| {
                format!("R2 secret key `{s_slot}` not found — `yah keys set {s_slot}` or export {s_env}")
            })?;
        Ok((access, secret))
    }

    /// Resolve the management-token slot/env. Precedence: a
    /// `[namespaces.<ns>].credentials` override, then the top-level typed
    /// `credentials` field, then a scope-derived default slot.
    fn api_token_slot(&self) -> Result<(String, String)> {
        match self
            .ns_override("credentials")
            .map(str::to_string)
            .or_else(|| self.cfg.credentials.clone())
        {
            Some(uri) => self.parse_uri("credentials", &uri),
            None => Ok(self.default_slot(DEFAULT_API_TOKEN_SLOT, DEFAULT_API_TOKEN_ENV)),
        }
    }

    /// Resolve a flattened credential field (e.g. `r2_access_key`) to slot/env.
    /// Precedence: a `[namespaces.<ns>].<field>` override, then the top-level
    /// `<field>`, then the scope-derived default slot.
    fn field_slot(
        &self,
        field: &str,
        default_slot: &str,
        default_env: &str,
    ) -> Result<(String, String)> {
        match self
            .ns_override(field)
            .or_else(|| self.cfg.fields.get(field).and_then(|v| v.as_str()))
        {
            Some(uri) => self.parse_uri(field, uri),
            None => Ok(self.default_slot(default_slot, default_env)),
        }
    }

    /// Read `[namespaces.<active-ns>].<field>` for this provider's scope.
    fn ns_override(&self, field: &str) -> Option<&str> {
        ns_override_in(&self.cfg, &self.namespace, field)
    }

    /// Derive the default keystore slot/env for a credential family when the
    /// provider file leaves it unset. The singleton scope keeps the historical
    /// global slot (pre-W206 back-compat); a non-singleton `(tenant, namespace)`
    /// prefixes the scope onto the slot so co-resident namespaces don't share
    /// one over-broad key — the "keystore keyed by (tenant, namespace,
    /// provider)" rule from W206 (the provider is already baked into the global
    /// slot name, e.g. `cloudflare-api-token`).
    fn default_slot(&self, global_slot: &str, global_env: &str) -> (String, String) {
        let mut parts = vec![];
        if !self.tenant.is_singleton() {
            parts.push(self.tenant.0.as_str());
        }
        if !self.namespace.is_singleton() {
            parts.push(self.namespace.0.as_str());
        }
        if parts.is_empty() {
            return (global_slot.to_string(), global_env.to_string());
        }
        let slot = format!("{}-{global_slot}", parts.join("-"));
        let env = slot.to_uppercase().replace('-', "_");
        (slot, env)
    }

    /// Parse a `keystore://<slot>` credential URI into `(slot, ENV_VAR)`,
    /// deriving the SCREAMING_SNAKE env fallback from the slot name.
    fn parse_uri(&self, field: &str, uri: &str) -> Result<(String, String)> {
        let slot = uri.strip_prefix("keystore://").with_context(|| {
            format!(
                "provider `{}` field `{field}` = {uri:?} must be a `keystore://<slot>` URI",
                self.provider_id
            )
        })?;
        anyhow::ensure!(
            !slot.is_empty() && !slot.contains('/'),
            "provider `{}` field `{field}` = {uri:?} — slot must be a flat kebab-case name \
             (e.g. `keystore://cloudflare-api-token`)",
            self.provider_id
        );
        let env = slot.to_uppercase().replace('-', "_");
        Ok((slot.to_string(), env))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    fn write_provider(root: &Path, id: &str, body: &str) {
        let dir = root.join(".yah/infra/providers");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{id}.toml")), body).unwrap();
    }

    #[test]
    fn resolves_account_id_and_defaults_to_global_slots() {
        let tmp = tempdir().unwrap();
        write_provider(
            tmp.path(),
            "cloudflare",
            "schema_version = 1\nid = \"cloudflare\"\nkind = \"cloudflare\"\naccount_id = \"acct-123\"\ndefault_zone = \"yah.dev\"\n",
        );
        let p = CfProvider::resolve(tmp.path(), "cloudflare").unwrap();
        assert_eq!(p.account_id, "acct-123");
        assert_eq!(p.provider_id, "cloudflare");
        // No `credentials` field → falls back to the global default slot/env.
        assert_eq!(
            p.api_token_slot().unwrap(),
            (
                "cloudflare-api-token".to_string(),
                "CLOUDFLARE_API_TOKEN".to_string()
            )
        );
    }

    #[test]
    fn honors_per_provider_credential_slots() {
        let tmp = tempdir().unwrap();
        write_provider(
            tmp.path(),
            "cloudflare-scrabcake",
            "schema_version = 1\nid = \"cloudflare-scrabcake\"\nkind = \"cloudflare\"\naccount_id = \"acct-scrab\"\ncredentials = \"keystore://cf-token-scrabcake\"\nr2_access_key = \"keystore://scrab-r2-access\"\n",
        );
        let p = CfProvider::resolve(tmp.path(), "cloudflare-scrabcake").unwrap();
        assert_eq!(
            p.api_token_slot().unwrap(),
            (
                "cf-token-scrabcake".to_string(),
                "CF_TOKEN_SCRABCAKE".to_string()
            )
        );
        // Declared r2_access_key overrides; r2_secret_key falls back to global.
        let (a_slot, a_env) = p
            .field_slot("r2_access_key", "default-access", "DEFAULT_ACCESS")
            .unwrap();
        assert_eq!(
            (a_slot.as_str(), a_env.as_str()),
            ("scrab-r2-access", "SCRAB_R2_ACCESS")
        );
        let (s_slot, _) = p
            .field_slot("r2_secret_key", "default-secret", "DEFAULT_SECRET")
            .unwrap();
        assert_eq!(s_slot, "default-secret");
    }

    #[test]
    fn rejects_non_keystore_uri() {
        let tmp = tempdir().unwrap();
        write_provider(
            tmp.path(),
            "bad",
            "schema_version = 1\nid = \"bad\"\nkind = \"cloudflare\"\naccount_id = \"a\"\ncredentials = \"cf-token\"\n",
        );
        let p = CfProvider::resolve(tmp.path(), "bad").unwrap();
        let err = p.api_token_slot().unwrap_err().to_string();
        assert!(err.contains("keystore://"), "got: {err}");
    }

    #[test]
    fn rejects_slot_with_slash() {
        let tmp = tempdir().unwrap();
        write_provider(
            tmp.path(),
            "slashy",
            "schema_version = 1\nid = \"slashy\"\nkind = \"cloudflare\"\naccount_id = \"a\"\ncredentials = \"keystore://cloudflare/yah\"\n",
        );
        let p = CfProvider::resolve(tmp.path(), "slashy").unwrap();
        let err = p.api_token_slot().unwrap_err().to_string();
        assert!(err.contains("flat kebab-case"), "got: {err}");
    }

    #[test]
    fn missing_account_id_errors() {
        let tmp = tempdir().unwrap();
        write_provider(
            tmp.path(),
            "noacct",
            "schema_version = 1\nid = \"noacct\"\nkind = \"cloudflare\"\n",
        );
        let err = CfProvider::resolve(tmp.path(), "noacct")
            .unwrap_err()
            .to_string();
        assert!(err.contains("account_id"), "got: {err}");
        let _ = BTreeMap::<String, String>::new();
    }

    // ─── W206-F5: per-namespace provider config ──────────────────────────────

    /// A provider file with a top-level `yah.dev`/global-slot default plus a
    /// `[namespaces.noisetable]` override for a second zone/account/token.
    const MULTI_NS_PROVIDER: &str = "\
schema_version = 1
id = \"cloudflare\"
kind = \"cloudflare\"
account_id = \"acct-yah\"
default_zone = \"yah.dev\"

[namespaces.noisetable]
account_id = \"acct-nt\"
zone = \"noisetable.com\"
credentials = \"keystore://cf-token-noisetable\"
r2_access_key = \"keystore://nt-r2-access\"
";

    fn ns(s: &str) -> NamespaceId {
        NamespaceId(s.to_string())
    }

    #[test]
    fn singleton_scope_uses_top_level_and_global_slots() {
        let tmp = tempdir().unwrap();
        write_provider(tmp.path(), "cloudflare", MULTI_NS_PROVIDER);
        let p = CfProvider::resolve(tmp.path(), "cloudflare").unwrap();
        assert_eq!(p.account_id, "acct-yah");
        assert_eq!(p.zone().as_deref(), Some("yah.dev"));
        // No scope, no top-level credentials → historical global slot.
        assert_eq!(
            p.api_token_slot().unwrap(),
            (
                "cloudflare-api-token".to_string(),
                "CLOUDFLARE_API_TOKEN".to_string()
            )
        );
    }

    #[test]
    fn namespace_section_overrides_account_zone_and_token() {
        let tmp = tempdir().unwrap();
        write_provider(tmp.path(), "cloudflare", MULTI_NS_PROVIDER);
        let p = CfProvider::resolve_scoped(
            tmp.path(),
            "cloudflare",
            &TenantId::singleton(),
            &ns("noisetable"),
        )
        .unwrap();
        assert_eq!(p.account_id, "acct-nt");
        assert_eq!(p.zone().as_deref(), Some("noisetable.com"));
        // Explicit per-namespace credentials win over any derived slot.
        assert_eq!(
            p.api_token_slot().unwrap(),
            (
                "cf-token-noisetable".to_string(),
                "CF_TOKEN_NOISETABLE".to_string()
            )
        );
        // r2_access_key overridden in the ns section; r2_secret_key unset → the
        // scope-derived default slot (not the bare global).
        let (a_slot, _) = p
            .field_slot("r2_access_key", "global-r2-access", "GLOBAL_R2_ACCESS")
            .unwrap();
        assert_eq!(a_slot, "nt-r2-access");
        let (s_slot, s_env) = p
            .field_slot(
                "r2_secret_key",
                "cloudflare-r2-secret-key",
                "CLOUDFLARE_R2_SECRET_KEY",
            )
            .unwrap();
        assert_eq!(s_slot, "noisetable-cloudflare-r2-secret-key");
        assert_eq!(s_env, "NOISETABLE_CLOUDFLARE_R2_SECRET_KEY");
    }

    #[test]
    fn derived_slot_encodes_tenant_and_namespace() {
        let tmp = tempdir().unwrap();
        // No per-namespace credentials declared → the default must be scoped by
        // (tenant, namespace) so co-residents don't share one over-broad key.
        write_provider(
            tmp.path(),
            "cloudflare",
            "schema_version = 1\nid = \"cloudflare\"\nkind = \"cloudflare\"\naccount_id = \"a\"\n",
        );
        let p = CfProvider::resolve_scoped(
            tmp.path(),
            "cloudflare",
            &TenantId("ss".into()),
            &ns("noisetable"),
        )
        .unwrap();
        assert_eq!(
            p.api_token_slot().unwrap(),
            (
                "ss-noisetable-cloudflare-api-token".to_string(),
                "SS_NOISETABLE_CLOUDFLARE_API_TOKEN".to_string()
            )
        );
    }

    #[test]
    fn namespace_without_a_section_falls_back_to_top_level() {
        // A namespace with no [namespaces.<ns>] section resolves the top-level
        // account/zone but still gets a scope-derived credential slot.
        let tmp = tempdir().unwrap();
        write_provider(tmp.path(), "cloudflare", MULTI_NS_PROVIDER);
        let p = CfProvider::resolve_scoped(
            tmp.path(),
            "cloudflare",
            &TenantId::singleton(),
            &ns("other"),
        )
        .unwrap();
        // namespace "other" has no section → falls back to top-level.
        assert_eq!(p.account_id, "acct-yah");
        assert_eq!(p.zone().as_deref(), Some("yah.dev"));
        // Non-singleton namespace with no explicit creds → scoped default slot.
        assert_eq!(p.api_token_slot().unwrap().0, "other-cloudflare-api-token");
    }
}

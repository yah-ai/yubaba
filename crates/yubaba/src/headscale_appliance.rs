//! The headscale appliance spec (R591-F1).
//!
//! Headscale is the mesh coordinator: the thing every node in the fleet dials
//! to get a mesh. It is an **appliance** in the [`LifecycleArchetype`] sense —
//! exactly one live instance, a stable identity, and durable state (the sqlite
//! DB + `noise_private.key`) that must follow it. What it is *not* is special:
//! once its lifecycle is described as a [`WorkloadSpec`], it is supervised by
//! the same kamaji every other workload on the node runs under, and
//! [`crate::leader`] starts and stops it the way placement starts and stops
//! anything else.
//!
//! ## Why this replaces `systemctl enable --now headscale`
//!
//! On 2026-07-09 a boot-race SIGTERM stopped headscale on us-west-001 and it
//! stayed dead for **seven days**. The raw unit carried `Restart=on-failure`,
//! and `headscale serve` exits **0** on SIGTERM — a graceful shutdown, which
//! `on-failure` by definition does not restart. Two of three raft voters and
//! the operator's laptop fell off the tailnet and nothing brought it back.
//!
//! [`RestartPolicy::Always`] is the fix, and it is a *stronger* guarantee than
//! the `Restart=always` the live unit was hand-patched to on 2026-07-16: the
//! kamaji supervisor treats every exit as restart-worthy regardless of code,
//! and it publishes `WorkloadStatus::Restarting` while it does, so a
//! crash-looping coordinator is visible in `yah cloud workload list` instead of
//! only in the journal of the box that is failing.
//!
//! ## Native, not containerised — and that is deliberate
//!
//! The spec carries [`NATIVE_EXEC_ANNOTATION`], so kamaji forks the host
//! binary at `<headscale_dir>/headscale` rather than pulling an image. Three
//! reasons, in order of weight:
//!
//! 1. **The state is already on the host** — `headscale.db`, `acls.yaml`,
//!    `config.yaml` and `noise_private.key` live in `headscale_dir`, written
//!    there by `POST /headscale/deploy` and replicated by [`crate::litestream`].
//!    A container would need every one of them bind-mounted back in.
//! 2. **It shares the host's network namespace with its front door** — it
//!    binds `127.0.0.1:`[`HEADSCALE_LISTEN_PORT`] and the co-located passway
//!    dials it over loopback (R858-B9). A native process on the host network
//!    needs no port mapping and no netns choreography; a containerised one
//!    would need the loopback path plumbed back in. (Until R858-T1 this read
//!    "it owns privileged host ports" — `0.0.0.0:443` plus `:80` for the Let's
//!    Encrypt HTTP-01 challenge. It owns neither any more.)
//! 3. **Cutover risk** — re-homing the supervisor and changing the execution
//!    substrate in one step would make a failed cutover ambiguous. This ticket
//!    changes *who supervises*; the process itself is byte-identical to what
//!    the systemd unit ran.
//!
//! `image` is identity metadata only for a native workload — nothing is
//! pulled. Same contract the W254 Darwin build leg rides
//! (`velveteen_exec::remote::build_workload_spec`).
//!
//! ## What is NOT here
//!
//! No `noise_private.key` handling, and `secrets` stays empty **on purpose**.
//! That key is the appliance's *identity*, not its data: move the appliance
//! without it and every node's stored server identity mismatches at once. It
//! travels through R600 / W273's raft-replicated cluster secret store — but
//! R858-T2 measured that a `SecretRef::Cluster` + `SecretMount` Cluster→File
//! declaration here would be a silent no-op, because
//! `deploy::secret_mount::materialize_file_secrets` runs only under
//! `POST /workloads/deploy` and [`crate::leader::start_headscale`] deploys
//! straight through the backend. So the read happens in `start_headscale`
//! instead, before the appliance starts, and the bytes land in the *persistent*
//! `headscale_dir` rather than on `/run/yah/secrets` tmpfs. Both halves live in
//! [`crate::headscale_state`]. Do not add a `secrets` entry here expecting it to
//! fire, and do not invent a second secret channel.
//!
//! [`RestartPolicy::Always`]: workload_spec::RestartPolicy::Always
//! [`NATIVE_EXEC_ANNOTATION`]: workload_spec::NATIVE_EXEC_ANNOTATION
//!
//! @yah:ticket(R858-T2, "Carry headscale's noise_private.key through the cluster secret store so the appliance keeps its identity across a move")
//! @yah:status(review)
//! @yah:at(2026-09-06T09:34:45Z)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:parent(R858)
//! @yah:next("Tier: Wizard — getting this wrong is silent and fleet-wide, and the failure is worse than the outage it prevents.")
//! @yah:gotcha("MEASURED ON THE BOX 2026-09-04: /var/lib/yah-cloud/headscale/noise_private.key is 72 bytes, mode 0600, mtime Jun 22, and exists ONLY on us-west-001's local disk. It is the appliance's IDENTITY, not its data — move the appliance without it and EVERY node's stored server identity mismatches at once. That is silent and fleet-wide, i.e. WORSE than the R858 outage, because a restored DB plus a fresh noise key produces a headscale that runs, looks healthy, and rejects every node.")
//! @yah:gotcha("LITESTREAM STRUCTURALLY CANNOT CARRY THIS AND DO NOT INVENT A SECOND SECRET CHANNEL. Both headscale_appliance.rs's module docs (\"What is NOT here\") and litestream.rs's own gotcha already name the mechanism: R600/W273's raft-replicated cluster secret store, SecretRef::Cluster + SecretMount Cluster->File, the same path the TLS certs use. litestream replicates the sqlite DB and nothing else. Note the native-exec interaction: headscale runs fork+exec'd on the host with no mount namespace, so a File-target secret mount materializes to /run/yah/secrets/<ident>/ (yubaba.service grants RuntimeDirectory=yah/secrets for exactly this) and the appliance must be pointed at it rather than at a bind that a native workload has no namespace to receive.")
//! @yah:next("DO R858-T1 FIRST — it shrinks this ticket before you start it. Today the state that must survive a move is {headscale.db, noise_private.key, acme-cache}. Once TLS terminates at the passway doors, the ACME cache stops being state at all, leaving exactly two items: the DB (litestream, built in R858) and this key. Starting here instead means designing carriage for a third artifact that is about to stop existing.")
//! @yah:verify("The acceptance test is the operator's rehearsal, not a unit test: with the key carried, bring us-west-001 down and confirm the headscale that comes up elsewhere is accepted by an EXISTING node — i.e. a node that never re-registered still reaches the tailnet. A fresh node joining proves nothing here; the failure this ticket prevents is specifically that already-registered nodes reject the new server identity.")
//! @yah:gotcha("A FOURTH PIECE OF STATE NOBODY HAS ENUMERATED: `acls.yaml` (77 bytes, mtime Jun 22) sits in /var/lib/yah-cloud/headscale/ beside the DB and the noise key. litestream replicates ONLY headscale.db, so this file is carried by nothing — not the DB, not litestream, not the cluster secret store. A failover to a node without it gets a coordinator with different ACLs, and unlike the noise-key failure that would look healthy AND partially work, which is worse to diagnose. CONFIRM BEFORE ACTING: headscale 0.23 can source policy from a file OR from the database depending on its policy mode, and the config block I read did not include a `policy:` section — so establish whether this file is live or vestigial (`grep -i policy /var/lib/yah-cloud/headscale/config.yaml` on us-west-001) before designing carriage for it. If it IS live it belongs in this ticket's scope; if it is vestigial, delete it so the next reader does not re-discover the same question. Either way the general lesson stands: the appliance's state was enumerated as \"the DB plus the identity\" and that enumeration was incomplete — walk the whole state dir rather than trusting the list.")
//! @yah:next("THE ACLS HALF HAS ITS OWN HOME NOW — R861-T1. If ACLs turn out to be declared and reconciled there, acls.yaml stops being state this ticket has to carry at all: declared config is regenerated on the new node rather than replicated to it, which is strictly better than carrying a file. Do not build carriage for it here until R861-T1 has answered whether the file is even live. The noise key is different and stays in this ticket's scope — it is an IDENTITY, not config, and cannot be regenerated by definition.")
//! @yah:notify_on(R861-T1, "ACLS QUESTION ANSWERED — do not re-run the SSH check this ticket's gotcha asks for. Measured on us-west-001 2026-09-04 by @Ashguard:griffin: config.yaml lines 32-34 are `policy:` / `mode: file` / `path: /var/lib/yah-cloud/headscale/acls.yaml`, so acls.yaml is LIVE, not vestigial, and all three in-tree renderers emit the same. Practical consequence for THIS ticket: while the fleet stays in file mode, acls.yaml is still state a move must carry alongside noise_private.key — R861-T1's reconciler makes drift LOUD but cannot push a policy in file mode (headscale refuses; only database mode accepts PUT /api/v1/policy). It stops being carriable state only once policy.mode flips to database, which R861-T1 deliberately left as an operator call tied to the rehearsal. So keep acls.yaml in your enumeration for now, and drop it the day that flip lands.")
//! @yah:handoff("DONE — the noise key now travels through the raft-replicated cluster secret store, and the appliance refuses to start with the wrong identity rather than starting and silently rejecting the fleet. New module oss/yubaba/crates/yubaba/src/headscale_state.rs holds the SINGLE writer for headscale_dir (write_state_file, owner-only 0600), now also used by the write_b64! macro behind POST /headscale/deploy so there is one write site rather than two. materialize_noise_key is called by start_headscale BEFORE either deploy path, via a ClusterResolver bound to SecretConsumer::of(&appliance_spec). Failure behaviour is loud by design, which is the other half of this relay's lesson: a store-held key that cannot be written or decrypted REFUSES TO START (starting with a wrong identity is worse than not starting); store-lacks-it-but-disk-has-it and store-lacks-it-and-no-disk both log at ERROR naming the seed command and carry on. Nothing ever auto-seeds the store from local disk — during a split-brain the losing node would otherwise publish its own identity over the real one. Seeding rail uses the existing verb, no new one invented: secret name headscale/noise-private-key, vault slot headscale-noise-private-key, declaration written at .yah/infra/secrets/headscale-noise-private-key.toml (encoding utf8, access workloads=[{workload=\"headscale\"}], target /var/lib/yah-cloud/headscale/noise_private.key mode 0o600).")
//! @yah:handoff("Tree anchor at handoff: 0a85122cdb33dbf97ebc04b84e07d9cfc049c0b2 — the shared tree as I left it. Diff against it (`git diff 0a85122cdb33dbf97ebc04b84e07d9cfc049c0b2..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:gotcha("THIS TICKET'S ORIGINAL DESIGN WOULD HAVE SHIPPED A SILENT NO-OP — do not restore it. The ticket said to declare a SecretRef::Cluster + File-target mount on appliance_spec the way the TLS certs do. Measured: materialize_file_secrets (oss/yubaba/crates/yubaba/src/deploy/secret_mount.rs:88) has EXACTLY ONE production caller, deploy_workload_spec behind POST /workloads/deploy (lib.rs:3708); every other reference is #[cfg(test)]. And start_headscale (leader.rs:357) deploys straight through backend.deploy_workload, deliberately bypassing that handler — its own comment at leader.rs:~382 says so. So `secrets: vec![...]` on appliance_spec would have changed nothing at runtime while reviewing as correct. SECOND reason the original design was wrong: a carriage channel ALREADY EXISTED — POST /headscale/deploy takes noise_key_base64 and writes the file (lib.rs:4678), and app/yah/cli/src/mesh.rs:989 reads it for a transplant — so the ticket's own \"do not invent a second secret channel\" instruction was violated by the ticket's own proposal. THIRD: the File-mount route would have opened a real hole. /run/yah/secrets is TMPFS (HOST_ROOT at oss/yah-base/crates/workload-spec/src/lib.rs:3650, RuntimeDirectory=yubaba yah/secrets at app/yah/cli/resources/yubaba.service:154-156), so it is wiped on reboot and a native fork+exec'd headscale starting before yubaba re-materialized would find no key at all. Writing to the persistent headscale_dir instead is why this needed no config-generator change.")
//! @yah:gotcha("TWO QUESTIONS SETTLED BY MEASUREMENT SO NOBODY RE-OPENS THEM. (1) private.key, which sits beside the noise key in all three generators, is NOT identity-bearing and needs NO carriage — headscale v0.23.0's own config-key table (read out of the pinned binary) has only noise.private_key_path and derp.server.private_key_path, with no top-level private_key_path; this camp's mesh dir is a controlled experiment where 0.23 ran a clean serve/shutdown against a config that DOES set the top-level key, minted noise_private.key and never created private.key; and all three generators set derp.server.enabled=false. The file on us-west-001 exists only because an older headscale made it. Recorded in headscale_state.rs's module docs. THAT FINDING PRODUCED R858-B10 — `yah mesh promote` still REQUIRES private.key as a transplant input (mesh.rs:790 bail, :1020 read_b64) and therefore fails preflight on any coordinator that has only ever run 0.23, which is a landmine directly under R858-T8's rehearsal. (2) The self-bootstrap handler at lib.rs:4923-4940 minting its own identity is CORRECT and deliberately stays ungated: lib.rs:4941 states there is no state to transplant because bootstrap creates a new tailnet, and routing it through the gate would fire the fresh-identity ERROR on every legitimate first boot — devaluing the loudest signal in the system, which is exactly the mechanism by which R858's original warnings went unread.")
//! @yah:verify("cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib: 649 passed / 0 failed, against a 639 passed / 0 failed baseline measured before any edit (+10 = the new tests), run twice to a consistent result. Note the baseline was CLEANER than this relay expected — tests::headscale_deploy_downloads_from_url_override at lib.rs:7890, flagged as a pre-existing failure during R858-T1, was already green by the time T2 started, so a peer fixed it in between. cargo check -p yubaba --all-targets is clean apart from two pre-existing unused-import warnings in a peer's crates/cloud/src/reconciler/mesofact_static.rs. One intervening run died on an error[E0758] in fob that was a peer's torn mid-write, not ours — the file on disk had no block-comment markers at all and was 1145 lines against an error citing line 1823; the clean re-run confirms it.")
//! @yah:verify("NOT DONE, STATED PLAINLY: the real key has NOT been seeded and no live node was touched. Nothing here proves carriage end-to-end — the unit tests exercise the resolve/write/refuse paths, not a real failover. The operator steps that remain are (1) read the 72 bytes off us-west-001 at /var/lib/yah-cloud/headscale/noise_private.key, (2) `yah keys set headscale-noise-private-key`, (3) commit .yah/infra/secrets/headscale-noise-private-key.toml, (4) `yah cloud secret put headscale/noise-private-key`. Until (4) lands, every yubaba leader that starts headscale will log the store-lacks-it ERROR — that is the intended, correct signal for the fleet's current state, not a regression. The actual acceptance test is R858-T8's rehearsal, and it is specifically that an ALREADY-REGISTERED node still reaches the tailnet after the coordinator moves; a fresh node joining proves nothing about this ticket.")
//! @yah:handoff("CARRIAGE IS NOW PROVEN ON A REAL SECOND NODE, which is what moved this off handoff — the code was complete at the previous handoff but nothing had exercised it outside unit tests. The four operator steps that handoff named as outstanding have all landed: .yah/infra/secrets/headscale-noise-private-key.toml is committed (3264B, mtime Sep 4 16:31) and the store holds the secret. MEASURED by @Ashguard:libra 2026-09-06 via read-only ssh: /var/lib/yah-cloud/headscale/noise_private.key exists on us-south-001 (45.32.194.254) at 72 bytes, mode 0600, mtime Sep 6 09:08 — materialized by yubaba with NO human action, minutes after R858-T4 placed the headscale binary there. That is the ClusterResolver -> materialize_noise_key path running end to end on a node that had never been hand-promoted, which is exactly what this ticket was built to do.")
//! @yah:verify("cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib = 788 passed / 0 failed, re-run by @Ashguard:libra after R858-T16 landed on top (the 649/0 in the earlier verify is stale; the suite has grown under peers since). NOT PROVEN AND STATED PLAINLY, because it is the half that matters most: no coordinator has actually MOVED, so nothing yet demonstrates that an ALREADY-REGISTERED node still reaches the tailnet after a failover — that remains R858-T8's rehearsal and is not this ticket's to claim. What IS established is the weaker but necessary property: the identity travels to a fresh candidate node automatically and correctly. ALSO MEASURED AND NOT YET EXPLAINED: us-east-001 (debian@51.81.85.145) has the headscale binary but NO noise_private.key, so the carriage fired on south and not on east despite both receiving the binary in the same pass two minutes apart. That asymmetry is recorded on R858-T16 and should be understood before east is treated as a failover target.")

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use workload_spec::{
    ExposeSpec, ImageRef, LifecycleArchetype, MeshExpose, MeshIdent, Millis, NamespaceId,
    ResourceLimits, RestartPolicy, SchemaVersion, StopPolicy, TenantId, TierTag, VolumeMount,
    VolumeSource, WorkloadSpec,
};

/// Mesh identity of the headscale appliance. Stable for the life of the
/// cluster — [`crate::leader`] tears down *by this identity*, so changing it
/// would strand a running appliance under the old name.
pub const HEADSCALE_IDENT: &str = "headscale";

/// DNS-label workload name (no dots — `check_name` rejects them).
pub const HEADSCALE_NAME: &str = "headscale";

/// The **one** port headscale listens on: plain HTTP, loopback, fronted by the
/// fleet's passway doors. R858-B9 collapsed `[443, 80]` — self-terminated TLS
/// plus the Let's Encrypt HTTP-01 challenge — down to this, because R858-T1
/// moved TLS termination out to the doors and the appliance now owns neither
/// privileged port.
///
/// # This constant exists so three sites cannot disagree
///
/// The port used to be a magic literal in three places that nothing forced into
/// agreement: this file's advertised mesh ports (`[443, 80]`),
/// `crate::generate_remote_headscale_config`'s `listen_addr` (`127.0.0.1:8080`)
/// and `crate::probe_headscale_local`'s health URL (`127.0.0.1:8080`). The
/// appliance advertised a mesh exposure that did not exist while the probe
/// silently tracked a different generator — so `/headscale/health` reported a
/// serving coordinator as `"stopped"` (R858-B11). **Do not re-inline it.**
///
/// Measured on us-west-001 2026-09-06 after R858-T1's cutover: `ss -lntp` shows
/// passway-demux on `0.0.0.0:443`, passway on `127.0.0.1:8444`, headscale on
/// `127.0.0.1:8080`, and `:80` free.
///
/// # What this is NOT
///
/// It is **not** the port a front door dials. Remote doors reach the
/// coordinator through west's own demux at its *public* `:443`
/// (`PASSWAY_UPSTREAMS=cloud.mesh.yah.dev=15.204.89.240:443`, TLS + SNI), which
/// is `COORDINATOR_UPSTREAM_PORT` in `app/yah/cli/src/cloud.rs` and stays 443.
/// Only west's co-located passway ever dials this port, over loopback.
///
/// [`crate::generate_bootstrap_headscale_config`] deliberately does **not** use
/// it either — see that function.
pub const HEADSCALE_LISTEN_PORT: u16 = 8080;

/// Graceful-stop budget. `headscale serve` closes its listeners and exits 0 on
/// SIGTERM well inside this; the window exists so an in-flight node
/// registration is not cut mid-write to the sqlite DB.
const STOP_GRACE_SECS: u64 = 30;

/// The executable [`appliance_spec`] tells kamaji to fork.
///
/// Exported because R858-T4's placement probe has to answer "would this node's
/// deploy find its binary?" *before* ownership moves, and the only honest way to
/// ask that is against the same path the deploy will use. Two independent
/// `join("headscale")` calls would agree today and be a silent placement lie the
/// day the layout moves — the probe would call a node ready for a binary the
/// spec no longer forks.
pub fn binary_path(headscale_dir: &Path) -> PathBuf {
    headscale_dir.join("headscale")
}

/// The config file [`appliance_spec`] passes to `headscale serve --config`.
///
/// Exported for the same reason as [`binary_path`], and it is the *second* argv
/// path a candidate node needs on disk. Nothing in the leader path writes it —
/// `POST /headscale/deploy` and `POST /headscale/bootstrap` are its only
/// writers (R858-B9) — so a node that was never promoted has the binary and no
/// config, and forking `headscale serve --config <missing>` is an immediate
/// exit into `RestartPolicy::Always`. Measured on us-south-001 2026-09-06:
/// binary present, noise key materialized by R858-T2, config absent.
///
/// @yah:ticket(R858-T16, "A candidate node has no config.yaml — the appliance's second argv path is written only by the promote handlers")
/// @yah:status(review)
/// @yah:at(2026-09-06T09:29:35Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R858)
/// @yah:gotcha("MEASURED 2026-09-06 (R858-T4). The appliance's argv is `<headscale_dir>/headscale serve --config <headscale_dir>/config.yaml`. R858-T4 put the BINARY on all three voters (v0.23.0, sha256 d9193dad4b070b9b3f6d54c8f14366952944b6e917672c0bc1dfd8f5491287a7, byte-identical on east/south/west) and R858-T2's noise-key carriage is LIVE — a 72-byte noise_private.key materialized itself on us-south-001 at 08:47Z minutes after the binary landed, with no human action. What is still missing on east and south is `config.yaml`, and nothing in the leader path writes it: per R858-B9, `POST /headscale/deploy` (lib.rs:5097) and `POST /headscale/bootstrap` (lib.rs:5379) are its ONLY writers, and `leader::start_headscale` deliberately does not touch it. So a node that was never hand-promoted has one argv path and not the other.")
/// @yah:gotcha("THIS IS ALREADY MODELLED AS A REFUSAL, SO NOTHING IS SILENT — do not read this ticket as an open hole. R858-T4's `leader::probe_native_exec` now checks EVERY path the spec's argv names (`headscale_appliance::binary_path` + `::config_path`, both exported so probe and deploy cannot disagree), and a node missing any of them is `NativeExecCapability::Absent` with a loud error naming the missing path. That is deliberate and it is why east and south are still not candidates despite having the binary: forking `headscale serve --config <missing>` exits immediately and, under `RestartPolicy::Always`, crash-loops — a failure that LOOKS like a successful deploy. A refusal placement can act on is strictly better. Unit test: `leader::tests::a_node_with_the_binary_but_no_config_is_absent`.")
/// @yah:next("DO NOT START THIS BEFORE R858-B9's STEP (4) LANDS. config.yaml is exactly the artifact B9 is reconciling — its own gotcha records that `generate_bootstrap_headscale_config` is now \"the ONLY remaining source of the outage shape\" and that a POST /headscale/deploy against west would overwrite the hand-edited live config and re-decapitate the mesh. Generating a config for a CANDIDATE node means picking which generator is canonical, which is B9's open question, not this ticket's. Read B9's annotation on `headscale_appliance::appliance_spec` first.")
/// @yah:next("THE SHAPE, once B9 settles the generator: `start_headscale` already hydrates the other two pieces of appliance state before starting (litestream restore for the DB, `headscale_state::materialize_noise_key` for the identity), so config.yaml wants the same treatment — rendered into `headscale_dir` on the node about to serve, from the settled generator, at the same point in the same function. That is a THIRD hydration step beside two that already exist, not a new mechanism. Do NOT reach for POST /headscale/deploy to do it: R858-T2's gotcha on that handler records that it is the promote path and it overwrites config.yaml wholesale.")
/// @yah:verify("The acceptance check is `probe_native_exec` returning `Present` on us-south-001 — today it returns `Absent` naming config.yaml, and the other two facts it checks (kamaji native backend attached, binary on disk) are already true there as of 2026-09-06. That verdict is not observable until a yubaba carrying R858-T4 is rolled, so until then check the same two facts by hand: `ssh root@45.32.194.254 'ls -la /var/lib/yah-cloud/headscale/'` should list headscale, noise_private.key AND config.yaml. R858-T8's rehearsal (transfer leadership off west) should not be attempted before that listing is complete.")
/// @yah:gotcha("MEASURED BY @Ashguard:libra 2026-09-06 (read-only ssh, ls only): THIS TICKET'S PREMISE IS INCOMPLETE — east is missing MORE than config.yaml. us-south-001 (45.32.194.254, root@) /var/lib/yah-cloud/headscale/ holds exactly two files: headscale (51593368 bytes, the exact v0.23.0 amd64 asset size) and noise_private.key (72 bytes, 0600, mtime Sep 6 09:08) — so for SOUTH the ticket is right and config.yaml is the only missing argv path. us-east-001 (51.81.85.145, debian@ — root is refused publickey there, note the login differs from south) holds ONLY headscale, with NO noise_private.key and NO config.yaml. So R858-T2's noise-key carriage materialized on south and NOT on east, even though both got the binary in the same T4 pass minutes apart (south 08:44, east 08:46). CONSEQUENCE: rendering config.yaml alone makes SOUTH a candidate but NOT east — east would still fail probe_native_exec, or worse, start with a freshly-minted identity that every registered node rejects, which is exactly the silent fleet-wide failure R858-T2 exists to prevent. Establish WHY the key landed on one voter and not the other before treating east as a failover target; do not assume the same hydration ran everywhere just because the binary did.")
/// @yah:handoff("LANDED — config.yaml is now hydrated by the LEADER PATH, as a third pre-start step beside the litestream DB restore and materialize_noise_key, exactly as the ticket's shape called for. NEW `headscale_state::hydrate_config(headscale_dir, server_url) -> io::Result<ApplianceConfig>` (oss/yubaba/crates/yubaba/src/headscale_state.rs:~330), called from `leader::start_headscale` right after the noise-key refusal and before either start path (leader.rs:~1440). It renders from `generate_remote_headscale_config`, WIDENED to pub(crate) rather than copied (lib.rs:5283) — a second renderer would be a fourth site to disagree, which is the defect R858-B9 spent a ticket collapsing. Its CURRENT raw-string body is used untouched; nothing was re-tidied into a backslash-continued literal. `generate_bootstrap_headscale_config` is NOT used and NOT touched, and no handler is called — this is a pure in-process render into headscale_dir, no POST /headscale/deploy anywhere.")
/// @yah:handoff("HYDRATE-IF-ABSENT IS A DELIBERATE SAFETY CHOICE, NOT TIMIDITY — DO NOT SIMPLIFY IT INTO AN UNCONDITIONAL WRITE. `start_headscale` runs on EVERY leadership acquisition, and us-west-001's live config.yaml was hand-edited 2026-09-06 onto the loopback shape (rollback copy on that node at /var/lib/yah-cloud/headscale/config.yaml.rollback-20260906-073155Z). An unconditional render would silently overwrite it on the next yubaba restart — re-decapitating the mesh through a different door than the one R858-B9's 409 bootstrap guard closed. So: ABSENT -> render (ApplianceConfig::Rendered, info). PRESENT -> left byte-for-byte alone, and drift against what this binary would emit is reported at warn! (KeptWithDrift) rather than corrected, because reconciling a live coordinator's config is an operator's call, not a restart's. The reasoning is written at the function's doc so the next reader cannot mistake it for an oversight. Also KeptInSync (present and identical) and KeptUncheckable (present, nothing to compare against) so the outcome is assertable without a tracing subscriber, the same shape as NoiseIdentity.")
/// @yah:handoff("server_url IS NOT HARDCODED, AND FINDING ITS SOURCE WAS THE ONE REAL DECISION IN THIS TICKET. I checked and the on-node leader path did NOT already know it: ServerState has no server_url, raft replicates none (no such YubabaRequest variant), no `yubaba serve` flag carried one, and the `mesh-url` vault slot (COORDINATOR_URL_SLOT, app/yah/cli/src/cloud.rs:4458) lives at the CONTROL PLANE, not on the node. What DID already exist is `ServerState::headscale_url` (lib.rs:1023) — documented as the coordinator's base URL, read by the operator-bridge preauth path — but NOTHING in production ever set it (grep: only the test builder `with_headscale_url` and the headscale_mock). So I gave that ONE existing field a production source rather than adding a second field meaning the same fact: new `yubaba::HEADSCALE_URL_ENV = \"YUBABA_HEADSCALE_URL\"` (lib.rs:566), read once in main.rs's serve path beside the litestream_s3_url wiring, empty/unset ignored. Env not a baked-in constant for the same reason YUBABA_LITESTREAM_S3_URL is env: yubaba.service ships in the release tarball onto every node of every camp, so a compiled-in mesh domain is one fleet's hostname inside a binary a rig also installs — and a WRONG headscale server_url means every joining node dials a coordinator that is not this one. UNSET renders nothing (ApplianceConfig::Missing, error! naming the env var): guessing the hostname is the exact failure the env var exists to avoid, and the node simply stays a non-candidate, which probe_native_exec already refuses on correctly.")
/// @yah:verify("MEASURED, MY OWN BASELINE ON TREE ANCHOR 2a3bd7ed: `cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib` = 784 passed / 0 failed BEFORE, 788 passed / 0 failed AFTER — the delta is exactly the 4 new tests, no pre-existing test moved. (The leader's 783 was one behind; the tree moved between us, as expected.) `cargo clippy -p yubaba --lib`: no findings on leader.rs, headscale_state.rs or lib.rs. `cargo check -p yubaba --bins`: clean, so the main.rs env wiring compiles. EACH NEW TEST FALSIFIED BY REVERTING THE ARM IT COVERS, two passes, both confirmed FAILING not merely passing. Pass A (write skipped + a hardcoded cloud.mesh.yah.dev fallback substituted for the no-URL refusal): 785 passed / 3 FAILED — leader::tests::a_node_whose_config_was_hydrated_becomes_a_candidate, headscale_state::tests::a_hydrated_config_is_what_the_generator_emits, headscale_state::tests::no_coordinator_url_renders_nothing. Pass B (the `path.exists()` guard removed, i.e. the unconditional write this ticket forbids): 786 passed / 2 FAILED — leader::tests::hydration_leaves_an_existing_config_exactly_as_it_found_it, plus the generator-parity test. Both falsifications were reverted and the final clean run re-measured at 788/0.")
/// @yah:verify("THE FOUR TESTS, and what each pins. leader::tests::a_node_whose_config_was_hydrated_becomes_a_candidate — the positive twin the ticket asked for, sitting beside a_node_with_the_binary_but_no_config_is_absent: it asserts the REFUSAL first (precondition), hydrates, then asserts probe_native_exec_with(caps(true)) flips Absent -> Present. leader::tests::hydration_leaves_an_existing_config_exactly_as_it_found_it — a pre-existing hand-edited config survives byte-for-byte and reports KeptWithDrift. headscale_state::tests::no_coordinator_url_renders_nothing — no server_url renders NO file at all (Missing), rather than a file naming a guessed coordinator. headscale_state::tests::a_hydrated_config_is_what_the_generator_emits — the written bytes equal generate_remote_headscale_config's output exactly, so a second hydration of an untouched node is KeptInSync rather than perpetual drift.")
/// @yah:gotcha("SOURCE ONLY — NOTHING LIVE WAS TOUCHED, and the operational precondition for east is UNCHANGED by this ticket. No ssh, no roll, no deploy, no POST to any node. Once a yubaba carrying this is rolled AND YUBABA_HEADSCALE_URL is set on the node, us-south-001 becomes a candidate (it already has the binary + a 72-byte noise_private.key, measured 2026-09-06). us-east-001 does NOT and MUST NOT: it has ONLY the headscale binary — no noise key, no config — so hydrating its config alone would leave it starting with a freshly-minted identity that every already-registered node rejects, the silent fleet-wide failure R858-T2 exists to prevent. probe_native_exec keeps refusing east on the missing config today; nothing here papers over that, and nothing should until east's identity is carried. NOTE ALSO that setting YUBABA_HEADSCALE_URL has a SECOND reader by design: the operator-bridge preauth path (lib.rs:~4112) currently skips with a warning because headscale_url is None everywhere in production, and it will start POSTing to the coordinator on any node where the env is set. That is the field working as documented, and it is opt-in per node — but it is a behaviour change to expect on the first node that gets the env var, not a surprise to debug.")
/// @yah:handoff("FILES (tree anchor 2a3bd7ed; nothing committed, no git write of any kind): oss/yubaba/crates/yubaba/src/headscale_state.rs (new ApplianceConfig enum + hydrate_config + 2 tests; `warn` added to the tracing import), oss/yubaba/crates/yubaba/src/leader.rs (the call site inside start_headscale + 2 tests in leader::tests), oss/yubaba/crates/yubaba/src/lib.rs (generate_remote_headscale_config -> pub(crate); new HEADSCALE_URL_ENV const; a doc paragraph on ServerState::headscale_url naming its second reader), oss/yubaba/crates/yubaba/src/main.rs (read the env into with_headscale_url in the serve path). No cargo fmt, no reformatting, no drive-by cleanups. Stayed entirely out of oss/turso-backup/* and oss/yubaba/crates/yubaba/src/litestream.rs, which @Ashguard:griffin (session:d27ac15b) holds for R858-S6. ONE PERMISSIONS DECISION worth knowing: hydrate_config writes with a plain std::fs::write, NOT headscale_state::write_state_file (0600) — config.yaml is not key material, and the promote path (crate::headscale_deploy, lib.rs:5131) already writes it with a plain fs::write. A hydrated config and a promoted one must be the same file with the same mode, or a failover changes the appliance's readability under whatever user kamaji forks it as. Incidentally this means the module doc's \"the only place that writes a file into headscale_dir\" was already inaccurate for config.yaml before this ticket; I did not rewrite deploy's write to chase it.")
pub fn config_path(headscale_dir: &Path) -> PathBuf {
    headscale_dir.join("config.yaml")
}

/// Build the headscale appliance [`WorkloadSpec`] for a node whose headscale
/// state lives under `headscale_dir`.
///
/// Pure — no I/O, no host inspection — so the shape is unit-testable off a
/// Linux box. The caller ([`crate::leader::on_became_leader`]) hands the result
/// to whichever backend `ServerState::active_backend` resolves to.
///
/// @yah:ticket(R858-B9, "headscale's behind-a-proxy config binds loopback, so no remote front door can reach it — three places disagree about the port")
/// @yah:status(review)
/// @yah:at(2026-09-06T08:45:32Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R858)
/// @yah:severity(high)
/// @yah:next("TS2021 UPGRADE PASSTHROUGH IS A REAL CONSTRAINT, NOT A DETAIL. lib.rs:4776-4778 records that Cloudflare strips tailscale's Upgrade header and 500s /machine/register, which is why the bootstrap doc at :5117-5121 insists on no CF proxy. A passway door in front of headscale inherits that requirement — prove the door passes Upgrade through end to end before trusting a green /key?v=138, because /key is a plain GET and will pass even if the register path does not.")
/// @yah:gotcha("DO NOT LAND THIS BEFORE THE A RECORD MOVES. This is step (4) of R858-T1's ordering and it is destructive out of order: headscale today serves the live fleet from the BOOTSTRAP config, which binds 0.0.0.0:443 and terminates its own Let's Encrypt TLS (generate_bootstrap_headscale_config, oss/yubaba/crates/yubaba/src/lib.rs:5122-5180, keys at :5139-5146). Flipping it to plain HTTP while cloud.mesh.yah.dev still resolves straight to 15.204.89.240 decapitates the mesh exactly as the 2026-09-03 outage did. Sequence is: doors serve the name, then the A record moves to the door set, THEN this.")
/// @yah:assumes("That the intended end state is one headscale listener on the mesh IP, plain HTTP, fronted by the doors — inferred from generate_remote_headscale_config's own doc at lib.rs:5118-5119 (localhost-only coordinator fronted by a proxy) plus the fact that R858-T1 wired the doors to reach it. Not confirmed with the operator.")
/// @yah:gotcha("THE DEFECT, three places that disagree, all read 2026-09-04. (1) generate_remote_headscale_config (oss/yubaba/crates/yubaba/src/lib.rs:4721-4770) emits `listen_addr: 127.0.0.1:8080` at :4734 — a LOOPBACK bind, so only a door on the same host can reach it and every REMOTE front door is structurally unable to, which is the exact case the follow-placement design exists for. (2) appliance_spec's HEADSCALE_PORTS (this file, `[443, 80]`) advertises the appliance on the mesh at 443/80 — matching NEITHER generator's listen_addr. (3) the health probe at lib.rs:4713 hardcodes `http://127.0.0.1:8080/health`, so it silently follows generator (1) and will lie if the bind moves. front_door_upstream_rule's `port` argument has no production value in-tree, so nothing today forces these three into agreement.")
/// @yah:next("SEQUENCE, and step 1 is what @Ashguard:griffin is waiting on — T1's ingress half is DONE on east and south and cannot proceed to the A record until :443 is free on us-west-001. (1) LIVE, on west, inside the short-outage budget the operator granted 2026-09-05: drop `tls_letsencrypt_hostname` + the HTTP-01 block from /var/lib/yah-cloud/headscale/config.yaml, set `listen_addr: 0.0.0.0:8080`, add the ufw rules (allow 8080 from 100.64.0.0/10, allow from 127.0.0.1, deny otherwise), restart the appliance, confirm `ss -lntp` shows :443 and :80 free and 8080 bound, then ping griffin with the port. This is ssh-recoverable on the node you are standing on and the rollback is the previous config.yaml — take a copy first. (2) Griffin then stands passway-demux + passway-mesh on west with the CO-LOCATED pin 127.0.0.1:8080, and flips east+south's PASSWAY_UPSTREAM_TLS/SNI/port in the same window — the appliance has ONE TLS posture at a time, so a door left on TLS=true after this speaks TLS to a plaintext port and one flipped early speaks plaintext to a TLS port, and both read like proxy bugs. (3) Only then does the A record move onto all three doors. (4) RECONCILE THE CODE with what step 1 did by hand, or the next provision re-creates the disagreement: `generate_remote_headscale_config`'s listen_addr, the bootstrap renderer that actually produced the live file, the advertised-ports constant in headscale_appliance.rs (it still claims [443, 80] and must become the one real port), and `probe_headscale_local`'s hardcoded 127.0.0.1:8080 — that last one is also half of R858-B11, so take them together.")
/// @yah:gotcha("STEP (1) IS DONE LIVE — and this ticket's OWN blocking gotcha is now STALE. Do NOT read \"DO NOT LAND THIS BEFORE THE A RECORD MOVES\" and stop: the A record moved 2026-09-06 (R858-T1), and step (1) was executed on us-west-001 in the same session by @Ashguard:hydra under explicit operator authorization. MEASURED STATE ON WEST NOW: /var/lib/yah-cloud/headscale/config.yaml carries `listen_addr: 127.0.0.1:8080` with all four `tls_letsencrypt_*` keys DELETED; `ss -lntp` shows passway-demux on 0.0.0.0:443, passway on 127.0.0.1:8444, headscale on 127.0.0.1:8080, and :80 free. Rollback copy at /var/lib/yah-cloud/headscale/config.yaml.rollback-20260906-073155Z. WHAT REMAINS OF THIS TICKET IS ONLY STEP (4), THE CODE RECONCILIATION — the live half is spent.")
/// @yah:gotcha("THE THREE-WAY PORT DISAGREEMENT RESOLVED ITSELF IN generate_remote_headscale_config's FAVOUR — so reconcile TOWARD it, do not \"fix\" it. This ticket's defect gotcha calls `listen_addr: 127.0.0.1:8080` (lib.rs:4734) a defect because \"only a door on the same host can reach it and every REMOTE front door is structurally unable to\". That premise is now obsolete: the live design has NO remote door dialing the appliance at all. us-east-001 and us-south-001 now pin `PASSWAY_UPSTREAMS=cloud.mesh.yah.dev=15.204.89.240:443` (west's PUBLIC address, TLS=true, SNI=cloud.mesh.yah.dev) and reach headscale THROUGH west's own demux, so the only process that ever dials the appliance is west's co-located passway over loopback. CONSEQUENCES FOR STEP (4): (a) generate_remote_headscale_config's 127.0.0.1:8080 is CORRECT as written and needs no change; (b) probe_headscale_local's hardcoded http://127.0.0.1:8080/health (lib.rs:4713) is likewise CORRECT and now agrees with the live bind rather than lying; (c) the one genuinely wrong constant is headscale_appliance.rs's `HEADSCALE_PORTS: [u16; 2] = [443, 80]` — the appliance owns NEITHER privileged port any more and advertises a mesh exposure that does not exist; (d) generate_bootstrap_headscale_config is the renderer that actually produced the live 0.0.0.0:443 + HTTP-01 file, and it is now the ONLY remaining source of the outage shape — a POST /headscale/deploy or /headscale/bootstrap against west would overwrite the hand-edited config and re-decapitate the mesh (verified those two handlers, lib.rs:5097 and :5379, are the ONLY writers of config.yaml; leader.rs::start_headscale does not touch it, which is why a plain yubaba restart is safe).")
/// @yah:handoff("DONE — step (4), the code reconciliation, is landed; the live half was already spent by @Ashguard:hydra. Reconciled TOWARD the loopback shape as the ticket's own updated gotcha directed: neither generate_remote_headscale_config's 127.0.0.1:8080 nor probe_headscale_local's URL was 'fixed', because the live design has no remote door dialing the appliance — only west's co-located passway, over loopback. THREE CHANGES. (1) THE ONE CONSTANT: new `HEADSCALE_LISTEN_PORT: u16 = 8080` at oss/yubaba/crates/yubaba/src/headscale_appliance.rs:104, carrying the full rationale (why the three sites disagreed, what it is NOT — it is not the port a front door dials). `HEADSCALE_PORTS: [u16; 2] = [443, 80]` is REMOVED, not corrected: it had exactly one consumer in the whole tree (the appliance_spec's own MeshExpose at :229, verified by grep across oss/ app/ crates/), so a one-element array beside a scalar would have been a fourth site to disagree. (2) ALL THREE SITES NOW DERIVE FROM IT: appliance_spec's advertised mesh ports (`MeshExpose::anonymous_ports([HEADSCALE_LISTEN_PORT])`), generate_remote_headscale_config's `listen_addr: 127.0.0.1:{listen_port}` (lib.rs, via a local binding since inline format args need a bare ident), and probe_headscale_local's health URL (now `format!(\"http://127.0.0.1:{listen_port}/health\")`). No literal 8080 remains at any of the three. (3) THE BOOTSTRAP HAZARD IS FIXED AT THE HANDLER, NOT THE RENDERER, per the leader's call: `generate_bootstrap_headscale_config` is byte-for-byte unchanged and gained a doc section saying WHY 0.0.0.0:443 + HTTP-01 is correct there (the first node of a fresh mesh has no door to be behind; a loopback bind would make it unreachable by the very nodes it exists to enrol). `headscale_bootstrap` now returns 409 CONFLICT when `config.yaml` OR `headscale.db` already exists in the headscale dir, before create_dir_all and before any write, with an error naming /headscale/deploy and `yah mesh promote` as the correct verbs for moving an EXISTING coordinator. `force: bool` (serde default false) is the escape hatch for a bootstrap that died half-written.")
/// @yah:verify("MEASURED BASELINE FIRST, ON THE SHARED TREE: `cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib` = 772 passed / 0 failed BEFORE any edit (the camp build rail flagged that run SUSPECT — @Ashguard:golem modified leader.rs mid-run — so treat 772 as approximate). AFTER: 783 passed / 0 failed, re-run twice to a consistent result. Delta accounting, stated plainly: +5 are mine and are named below; the remaining +6 are peers' tests that landed on the tree between my two runs and are not attributable to this ticket. `cargo check -p yah -p cloud-client --all-targets` = Finished clean; the only warnings are pre-existing and in files I did not touch (a dead `cluster_id` field in the `chip-mine` bin, an unused import in app/yah/cli/examples/sample.rs).")
/// @yah:cleanup("app/yah/cli/resources/kamaji.service:95-101 now carries a FALSE claim and I deliberately did not fix it — the comment justifies CAP_NET_BIND_SERVICE with 'the headscale appliance binds 0.0.0.0:443 and :80', which this ticket just made untrue, and says 'this grant retires with R591-T2'. NOT touched for two reasons: (a) that file is named in R591-F1's own handoff file list and @Ashguard:golem (session:bfcab582) is live on R858-B14 in the adjacent kamaji code, so it is plausibly in their in-flight set; (b) I could NOT establish that the grant is safe to remove — passway_ingress.rs:81 pins `TLS_PORT: u16 = 443` and passway-demux binds 0.0.0.0:443 on west, and I did not determine whether that workload is native-exec (which would inherit the ambient set) or containerised. So the comment's REASON is dead but the GRANT may not be. Whoever picks this up must answer the passway question first; do not delete the capability on the strength of headscale alone.")
pub fn appliance_spec(headscale_dir: &Path) -> WorkloadSpec {
    let bin = binary_path(headscale_dir);
    let config = config_path(headscale_dir);

    let mut annotations = HashMap::new();
    // The marker kamaji routes on: fork the host binary rather than pulling an
    // image. Refused (not silently downgraded to a container) by a kamaji built
    // without `native-exec` or started without `--native-exec-dir`, which is
    // exactly the failure we want — a headscale in a Linux container with none
    // of its state bind-mounted is a wrong answer, not a degraded one.
    annotations.insert(
        workload_spec::NATIVE_EXEC_ANNOTATION.to_string(),
        workload_spec::NATIVE_EXEC_VALUE.to_string(),
    );

    WorkloadSpec {
        schema_version: SchemaVersion::V1,
        name: HEADSCALE_NAME.to_string(),
        // Identity metadata only — a native workload pulls nothing. The tag
        // records which headscale the node was provisioned with; the digest is
        // a required field with no meaning here.
        image: ImageRef {
            registry: "ghcr.io".into(),
            repository: "juanfont/headscale".into(),
            tag: "native".into(),
            digest: workload_spec::testing::test_digest(),
        },
        // kamaji's native path is gated to tier=infra: it runs argv on the host
        // with no sandbox. The mesh coordinator is infrastructure by definition.
        tier: TierTag("infra".into()),
        tenant: TenantId::singleton(),
        namespace: NamespaceId::singleton(),
        replicas: 1,
        command: Some(vec![
            bin.to_string_lossy().into_owned(),
            "serve".to_string(),
            "--config".to_string(),
            config.to_string_lossy().into_owned(),
        ]),
        entrypoint: None,
        workdir: Some(headscale_dir.to_path_buf()),
        user: None,
        env: vec![],
        secrets: vec![],
        // Inert on the native backend (a fork+exec'd process has no mount
        // namespace to mount into), and declared anyway: "a volume that must
        // follow it" is the structural half of W244's appliance definition, so
        // `effective_archetype` agrees with the explicit `archetype` below
        // instead of depending on it. It is also what a reader needs in order
        // to know which directory R591-T3's litestream replication covers.
        volumes: vec![VolumeMount {
            source: VolumeSource::Bind {
                host_path: headscale_dir.to_path_buf(),
            },
            target: headscale_dir.to_path_buf(),
            read_only: false,
        }],
        resources: ResourceLimits {
            memory_mb: 512,
            cpu_millis: 1000,
            ephemeral_storage_mb: 1024,
        },
        depends_on: vec![],
        // R860-T1 added this field; empty here keeps today's behaviour exactly.
        // W338 models the litestream replicator this appliance needs as a
        // `local` + `self` requirement — that's R860-T2/T6, not this line.
        requires: vec![],
        healthcheck: None,
        // THE WHOLE POINT OF THIS TICKET. `Always` restarts on a clean exit 0
        // too — see the module docs for the seven-day outage that `on-failure`
        // produced.
        restart_policy: RestartPolicy::Always,
        archetype: Some(LifecycleArchetype::Appliance),
        stop_policy: StopPolicy {
            signal: 15,
            grace_period: Millis::from_secs(STOP_GRACE_SECS),
        },
        expose: ExposeSpec {
            mesh: MeshExpose {
                identity: MeshIdent(HEADSCALE_IDENT.to_string()),
                ports: MeshExpose::anonymous_ports([HEADSCALE_LISTEN_PORT]),
                allow_from: vec![],
            },
            public: None,
            operator: None,
        },
        labels: HashMap::new(),
        annotations,
    }
}

/// The mesh identity [`appliance_spec`] deploys under, as the type the
/// teardown path takes.
pub fn appliance_ident() -> MeshIdent {
    MeshIdent(HEADSCALE_IDENT.to_string())
}

/// Render one front door's `PASSWAY_UPSTREAMS` entry for the coordinator's
/// hostname (R591-T2) — the sovereign form of "the external identity follows
/// placement". Full rationale, including why the co-located door dialing
/// `127.0.0.1` is a bootstrap-cycle constraint rather than an optimisation,
/// lives on the definition.
///
/// R858-T1 moved the definition down to `local-driver`, which already owns the
/// `PASSWAY_UPSTREAMS` grammar this renders. It had to: the deploy path that
/// finally calls it (`yah cloud ingress`) links `local-driver` but
/// deliberately **not** the full `yubaba` lib, since that pulls openraft, axum
/// and russh into the CLI for one pure six-line function (R483-T5). Re-exported
/// here so this module's API and its four tests below are unchanged.
pub use local_driver::passway_ingress::front_door_upstream_rule;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn spec() -> WorkloadSpec {
        appliance_spec(&PathBuf::from("/var/lib/yah-cloud/headscale"))
    }

    /// The regression the whole ticket exists to prevent: `headscale serve`
    /// exits 0 on SIGTERM, so anything short of `Always` leaves a gracefully
    /// stopped coordinator dead. `OnFailure` is the shape of the systemd unit
    /// that caused the 2026-07-09 outage.
    #[test]
    fn a_graceful_exit_is_restart_worthy() {
        assert_eq!(spec().restart_policy, RestartPolicy::Always);
    }

    #[test]
    fn it_is_a_pinned_non_drainable_appliance() {
        let s = spec();
        assert_eq!(s.archetype, Some(LifecycleArchetype::Appliance));
        // Belt and braces: the pre-R572 inference must reach the same verdict,
        // so a consumer reading `effective_archetype` is not a second opinion.
        assert_eq!(s.effective_archetype(), LifecycleArchetype::Appliance);
        assert_eq!(s.replicas, 1);
    }

    #[test]
    fn it_routes_to_the_native_backend_not_a_container() {
        assert!(spec().wants_native_exec());
    }

    /// R858-B9. Before this, the appliance advertised `[443, 80]` on the mesh
    /// while every generator bound `127.0.0.1:8080` — a mesh exposure that did
    /// not exist, and a service record no consumer could dial. Both privileged
    /// ports now belong to the passway doors; the appliance owns one loopback
    /// port and advertises exactly it.
    #[test]
    fn it_advertises_exactly_the_one_port_it_binds() {
        let ports: Vec<u16> = spec().expose.mesh.numbers();
        assert_eq!(ports, vec![HEADSCALE_LISTEN_PORT]);
        assert!(
            !ports.contains(&443) && !ports.contains(&80),
            "the doors own 443/80 since R858-T1; got {ports:?}"
        );
    }

    /// kamaji's `validate_native_exec_spec` refuses a native deploy outside
    /// tier=infra. A spec that fails this is refused at the UDS, not
    /// downgraded, so the appliance would simply never start.
    #[test]
    fn native_exec_admission_floor_is_satisfied() {
        let s = spec();
        assert_eq!(s.tier.0, "infra");
        // The other two admission rules: no unresolved refs, and no
        // nested-sandbox grant (which has no meaning without a container).
        assert!(s.env.is_empty());
        assert!(!s.wants_nested_sandbox());
    }

    #[test]
    fn argv_names_the_host_binary_and_its_config() {
        let s = spec();
        assert_eq!(
            s.command.as_deref(),
            Some(
                [
                    "/var/lib/yah-cloud/headscale/headscale",
                    "serve",
                    "--config",
                    "/var/lib/yah-cloud/headscale/config.yaml",
                ]
                .map(String::from)
                .as_slice()
            )
        );
        // `entrypoint` unset: kamaji's argv rule is entrypoint ++ command, and
        // a native workload has no image entrypoint to inherit.
        assert!(s.entrypoint.is_none());
    }

    /// The teardown path in `leader.rs` resolves the workload by mesh identity,
    /// so the two must agree or a lost-leadership event leaves the appliance
    /// running on a node that no longer owns it — two live headscales serving
    /// divergent DB state.
    #[test]
    fn deploy_and_teardown_agree_on_the_identity() {
        assert_eq!(spec().expose.mesh.identity, appliance_ident());
    }

    #[test]
    fn the_state_dir_travels_with_the_appliance() {
        let s = spec();
        let dir = PathBuf::from("/var/lib/yah-cloud/headscale");
        assert_eq!(s.workdir.as_ref(), Some(&dir));
        assert_eq!(s.volumes.len(), 1);
        assert_eq!(s.volumes[0].target, dir);
        assert!(!s.volumes[0].read_only, "the sqlite DB is written in place");
    }

    // ── R591-T2: follow-placement front-door rules ──────────────────────────

    const EAST: std::net::Ipv4Addr = std::net::Ipv4Addr::new(100, 64, 0, 3);
    const WEST: std::net::Ipv4Addr = std::net::Ipv4Addr::new(100, 64, 0, 1);

    /// The sovereign shape: DNS never moves, so a front door that does not hold
    /// the appliance proxies across the mesh to whichever node does.
    #[test]
    fn a_remote_front_door_proxies_to_the_placed_node() {
        assert_eq!(
            front_door_upstream_rule("cloud.mesh.yah.dev", WEST, EAST, 443),
            "cloud.mesh.yah.dev=100.64.0.1:443"
        );
    }

    /// THE BOOTSTRAP-CYCLE MITIGATION. The door co-located with the appliance
    /// must not route to the appliance's *mesh* address: that path needs a mesh
    /// to reach the thing that grants meshes, and on a total-fleet cold start
    /// nobody has one. Loopback is the one path that never traverses the mesh,
    /// so the placed node can always bootstrap itself.
    #[test]
    fn the_co_located_front_door_routes_to_loopback() {
        assert_eq!(
            front_door_upstream_rule("cloud.mesh.yah.dev", WEST, WEST, 443),
            "cloud.mesh.yah.dev=127.0.0.1:443"
        );
    }

    /// Every front door is handed a rule for the same hostname — the address
    /// that moves is the upstream, never the DNS record. Asserted across a
    /// two-door fleet so a change that reintroduced per-door hostnames (an
    /// A-record repoint by another name) fails here.
    #[test]
    fn every_front_door_serves_the_same_hostname() {
        let rules: Vec<String> = [EAST, WEST]
            .iter()
            .map(|&door| front_door_upstream_rule("cloud.mesh.yah.dev", WEST, door, 443))
            .collect();
        assert!(rules.iter().all(|r| r.starts_with("cloud.mesh.yah.dev=")));
        // ...and exactly one of them is the loopback door.
        assert_eq!(
            rules.iter().filter(|r| r.contains("127.0.0.1")).count(),
            1,
            "exactly one door is co-located: {rules:?}"
        );
    }

    /// A failover changes which upstream every door dials and nothing else —
    /// no record edit, no new cert, no HTTP-01 challenge.
    #[test]
    fn a_failover_moves_the_upstream_not_the_record() {
        let before = front_door_upstream_rule("cloud.mesh.yah.dev", WEST, EAST, 443);
        let after = front_door_upstream_rule("cloud.mesh.yah.dev", EAST, EAST, 443);
        assert_eq!(before, "cloud.mesh.yah.dev=100.64.0.1:443");
        // East now holds the appliance, so east's own door goes to loopback.
        assert_eq!(after, "cloud.mesh.yah.dev=127.0.0.1:443");
    }

    /// The spec is built per-node from that node's configured headscale dir,
    /// not from a baked-in constant — a test rig and a fleet node disagree
    /// about the path.
    #[test]
    fn the_state_dir_is_not_hardcoded() {
        let s = appliance_spec(&PathBuf::from("/tmp/rig/hs"));
        assert_eq!(
            s.command.as_ref().unwrap()[0],
            "/tmp/rig/hs/headscale".to_string()
        );
    }
}

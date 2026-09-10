//! R859-F2 phase B / R859-F3: turn an `ingress_owner` observation into a real
//! change to public addressing, from inside the fleet.
//!
//! [`floating_ip::plan_ingress_owner_effect`] decides *what* should happen to
//! public ingress; this module is the half that makes it happen on a fleet
//! node. There are two arms, matching W267 §Tier 1's two failover speeds, and
//! they are **independently optional** — a fleet may configure either, both, or
//! neither:
//!
//! - **`Reassign`** (R859-F3, intra-provider, seconds, no DNS propagation and
//!   no cert re-mint): move the floating IP onto the new owner via that
//!   vendor's API. Needs a vendor credential — see [`floating_ip_token_file_env`].
//! - **`Withdraw`** (R859-F2, cross-provider): pull the dead origin's A record
//!   out of the apex and let the survivors take its share. Needs a Cloudflare
//!   credential and a zone — see [`APEX_ENV`].
//!
//! The `Withdraw` arm is the one with a sharp edge, because it writes DNS that
//! something else also writes. Everything below about two writers is about that
//! arm only: a floating IP has exactly one writer, the vendor's API, and no
//! second actor to stay out of step with.
//!
//! # The fleet may only ever SUBTRACT; the declaration may only ever ADD
//!
//! Operator decision 2 (2026-09-08) chose to ship each machine's declaration
//! into its raft member row and write DNS from the fleet, over two rejected
//! alternatives: publishing an exclusion for `yah cloud apply` to consume
//! (automatic in name only — a 3am node loss then waits for a human to run
//! apply, which is the exact pain R859 was filed against), and reusing the
//! elected ACME issuer's Cloudflare credential (which relocates the two-source
//! problem rather than fixing it).
//!
//! What makes two writers of one apex safe is that they write in opposite
//! directions and neither reads the other:
//!
//! - The **fleet** issues one targeted delete — the dead origin's A record at
//!   the apex, matched on content. It never renders the apex, never adds a
//!   record, and never needs the domain manifests, the machine TOMLs or the
//!   ingress collation. It needs three facts: the apex name, the zone, and the
//!   dead machine's public address, and it has all three
//!   ([`crate::raft::MemberInfo::public_address`]).
//! - The **declaration** (`yah cloud apply`, R859-F1's
//!   `plan_domain_passway`) re-adds the record when the box comes back,
//!   because that diff is fail-open on addition and its upserts are ungated.
//!
//! That is the same fail-closed-on-withdrawal / fail-open-on-addition rule both
//! R859 children already enforce, now split across the two actors that each
//! hold the right evidence: the fleet knows what is dead, the declaration knows
//! what should exist.
//!
//! **Do not teach this module to add a record**, and do not teach it to render
//! an apex. The moment it can add, the two writers are in a loop with each
//! other and the apex's contents depend on which one ran last.
//!
//! # Why the withdrawal is content-matched
//!
//! A round-robin apex holds several A records under one name. "Delete the A
//! records at `yah.dev`" would take the *live* origins with it — a total
//! outage in place of the partial one it was trying to fix. So the delete is
//! narrowed to records whose content is exactly the dead machine's public
//! address, which is why [`crate::raft::MemberInfo::public_address`] is a
//! separate declared fact and not the mesh `addr` raft membership already
//! records.
//!
//! # The empty-apex backstop lives one layer up, and is not repeated here
//!
//! R859-F1's `plan_domain_passway` refuses when health exclusion would empty
//! the apex, and `plan_ingress_owner_effect` refuses any withdrawal out of a
//! degraded quorum. This module does not re-implement either check: a second
//! copy of a safety rule is a second thing to keep in sync, and the one that
//! drifts is always the copy. What it *does* enforce is the one precondition
//! only it can see — that the machine being withdrawn has a declared public
//! address at all.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use async_trait::async_trait;
use floating_ip::{
    FloatingIpMachine, FloatingIpProvider, IngressOwnerEffect, OwnerLiveness, FLOATING_IP_PROVIDERS,
};
use serde::Deserialize;

/// Cloudflare's public API root. Overridden by tests against a local stub.
const CLOUDFLARE_API: &str = "https://api.cloudflare.com/client/v4";

/// Everything the effector is allowed to do, and the credentials that let it.
///
/// Env-sourced rather than flag-sourced, mirroring
/// [`acme_issuer::parse_issuer_config`](crate::acme_issuer::parse_issuer_config)
/// exactly: these are credentials plus the scopes they open, delivered per-node
/// by the same `fob`-injected token-file mechanism, whereas
/// `--provider`/`--public-address` are per-machine *declarations* copied from a
/// machine TOML and belong with `--region`. Two different kinds of fact, two
/// different rails, each matching a precedent already in this binary.
///
/// Both arms are `Option`-shaped because they answer different questions and a
/// fleet may want exactly one. A pure Tier-1 fleet (one floating IP, one apex
/// record that never moves) needs the vendor credential and no Cloudflare
/// token; a multi-provider fleet with no floating IP anywhere needs the reverse.
/// Requiring an apex in order to move an IP would have made the R859-F3 arm
/// unreachable for the deployment it was built for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectorConfig {
    /// The apex-withdrawal arm, or `None` when no apex is declared.
    pub apex: Option<ApexConfig>,
    /// The floating-IP arm: provider id → path of that vendor's fob-injected
    /// token file. Empty means no `Reassign` can be applied.
    ///
    /// A map rather than one provider + one token because a floating IP is
    /// zone-bound and a zone is provider-bound, so a fleet spanning two vendors
    /// has two independent floating-IP domains and needs both credentials to
    /// serve either. Keyed by provider id so the lookup at apply time is the
    /// machine's own declared `provider` — no second source of truth about
    /// which vendor a box is on.
    pub floating_ip_token_files: BTreeMap<String, String>,
}

/// Where the apex lives and what may edit it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApexConfig {
    /// The apex record name whose A records this fleet may withdraw from, e.g.
    /// `yah.dev`. Exactly one: a fleet that fronts two apexes would need two
    /// sets of declarations to know which origin belongs to which, and nothing
    /// in the member row says that.
    pub apex: String,
    /// Cloudflare zone id containing [`apex`](Self::apex). Taken directly
    /// rather than looked up by name, for the same reason
    /// `YUBABA_ACME_DNS01_CLOUDFLARE_ZONE_ID` is: a zone-name lookup needs a
    /// broader token, and deriving a zone from an apex is guesswork the moment
    /// the apex is a subdomain.
    pub zone_id: String,
    /// Path to the file holding the Cloudflare API token. A path, not the
    /// token, because that is how `fob` injects a secret into a unit and it
    /// keeps the value out of the process's environment and out of `ps`.
    pub token_file: String,
}

/// Env var that turns the apex-withdrawal arm on. Unset — the default, and
/// every camp today — means the fleet may not touch DNS.
pub const APEX_ENV: &str = "YUBABA_INGRESS_APEX";
/// Env var naming the fob-injected Cloudflare token file.
pub const TOKEN_FILE_ENV: &str = "YUBABA_INGRESS_CLOUDFLARE_TOKEN_FILE";
/// Env var carrying the Cloudflare zone id that contains the apex.
pub const ZONE_ID_ENV: &str = "YUBABA_INGRESS_CLOUDFLARE_ZONE_ID";

/// Env var naming the fob-injected token file for one floating-IP vendor —
/// `YUBABA_INGRESS_HETZNER_TOKEN_FILE`, `..._OVH_...`, `..._VULTR_...`.
///
/// Derived from the provider id rather than listed as three more constants, so
/// a fourth row in [`FLOATING_IP_PROVIDERS`] arms itself on this node without a
/// second edit here. That table is also the *only* set of names read: an
/// unrecognised `YUBABA_INGRESS_FOO_TOKEN_FILE` is ignored, not guessed at.
///
/// A token FILE, not a token, for the same reason [`TOKEN_FILE_ENV`] is one —
/// it is how `fob` injects a secret into a unit, and it keeps the value out of
/// the process environment and out of `ps`. That is a real difference from
/// `FLOATING_IP_PROVIDERS`'s third column (`HETZNER_API_TOKEN` and friends),
/// which is the *operator-laptop* rail `cloud` reads: same secret, different
/// delivery, and the fleet node deliberately does not accept the bare-env form.
pub fn floating_ip_token_file_env(provider: &str) -> String {
    format!(
        "YUBABA_INGRESS_{}_TOKEN_FILE",
        provider.to_ascii_uppercase().replace('-', "_")
    )
}

/// Parse the effector config from a `key -> value` lookup — a pure function
/// over the environment, so it is unit-testable without touching `std::env`.
///
/// `Ok(None)` when neither arm is configured: the effector is opt-in, and a
/// node with no apex and no vendor credential has nothing it could apply.
///
/// Within the apex arm the two companions are required rather than defaulted —
/// a half-configured effector would fail at the moment of a real failover,
/// which is the worst possible time to discover a missing token.
pub fn parse_effector_config(
    get: impl Fn(&str) -> Option<String>,
) -> Result<Option<EffectorConfig>, String> {
    let trimmed = |key: &str| {
        get(key)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };

    let apex = match trimmed(APEX_ENV) {
        Some(apex) => {
            let token_file = trimmed(TOKEN_FILE_ENV)
                .ok_or_else(|| format!("{TOKEN_FILE_ENV} is required when {APEX_ENV} is set"))?;
            let zone_id = trimmed(ZONE_ID_ENV)
                .ok_or_else(|| format!("{ZONE_ID_ENV} is required when {APEX_ENV} is set"))?;
            Some(ApexConfig {
                apex,
                zone_id,
                token_file,
            })
        }
        None => None,
    };

    let floating_ip_token_files: BTreeMap<String, String> = FLOATING_IP_PROVIDERS
        .iter()
        .filter_map(|(id, _, _)| {
            trimmed(&floating_ip_token_file_env(id)).map(|path| (id.to_string(), path))
        })
        .collect();

    if apex.is_none() && floating_ip_token_files.is_empty() {
        return Ok(None);
    }
    Ok(Some(EffectorConfig {
        apex,
        floating_ip_token_files,
    }))
}

/// The one DNS operation the fleet is allowed to perform.
///
/// A trait rather than a concrete client so [`apply_effect`] is testable
/// without a network, and — more to the point — so the *shape* of the fleet's
/// DNS authority is visible in one place. There is exactly one method, it
/// deletes, and it is content-matched. Anything a future change wants to add
/// here should have to argue with the module doc first.
#[async_trait]
pub trait ApexWithdrawal: Send + Sync {
    /// Delete the A records at `apex` whose content is exactly `address`.
    ///
    /// Returns how many records were deleted. **Zero is a success**, not an
    /// error: the record may already be gone because a previous tick withdrew
    /// it, which is the ordinary steady state while a node stays down.
    async fn withdraw_a_record(&self, apex: &str, address: &str) -> Result<u32>;
}

/// Turn a machine into a live floating-IP client for whatever vendor hosts it.
///
/// A trait for the same two reasons [`ApexWithdrawal`] is one — [`apply_effect`]
/// stays testable without a network, and the fleet's whole floating-IP
/// authority is one named surface rather than a `match` buried in an effect
/// arm. It is deliberately *not* `floating_ip_adapters::adapter_for` directly:
/// that function takes a credential, and choosing which credential is precisely
/// the node-local policy this trait exists to hold.
pub trait FloatingIpTransport: Send + Sync {
    /// The adapter that can move `machine`'s floating IP, or a refusal naming
    /// what is missing.
    fn provider_for(&self, machine: &FloatingIpMachine) -> Result<Box<dyn FloatingIpProvider>>;
}

/// [`FloatingIpTransport`] over the node's fob-injected vendor token files.
///
/// Reads each token once at construction rather than per call, the same
/// contract [`CloudflareApexWithdrawal::from_config`] and the ACME issuer's
/// token file have: a rotated token takes effect on the next daemon restart.
pub struct VendorTokens {
    /// provider id → credential. Never logged, never surfaced in an error.
    tokens: BTreeMap<String, String>,
}

impl VendorTokens {
    /// Read every configured vendor token file.
    ///
    /// Fails the whole construction if any one file is unreadable or blank,
    /// rather than dropping that vendor and carrying on: an operator who
    /// pointed [`floating_ip_token_file_env`] at a path believes that provider
    /// is armed, and a silently-disarmed one surfaces as a `NotApplied` during
    /// the failover it was configured for.
    pub fn from_token_files(files: &BTreeMap<String, String>) -> Result<Self> {
        let mut tokens = BTreeMap::new();
        for (provider, path) in files {
            let token = std::fs::read_to_string(path)
                .with_context(|| {
                    format!(
                        "reading the {provider} floating-IP token file {path} (from ${})",
                        floating_ip_token_file_env(provider)
                    )
                })?
                .trim()
                .to_string();
            anyhow::ensure!(
                !token.is_empty(),
                "the {provider} floating-IP token file {path} is empty"
            );
            tokens.insert(provider.clone(), token);
        }
        Ok(Self { tokens })
    }

    /// Construct directly from credentials — the test/embedding path that skips
    /// the file reads.
    pub fn new(tokens: BTreeMap<String, String>) -> Self {
        Self { tokens }
    }
}

impl FloatingIpTransport for VendorTokens {
    fn provider_for(&self, machine: &FloatingIpMachine) -> Result<Box<dyn FloatingIpProvider>> {
        let token = self.tokens.get(&machine.provider).with_context(|| {
            format!(
                "machine {:?} is hosted by {:?}, but this node holds no {} credential — set ${} \
                 to a fob-injected token file (configured: {})",
                machine.name,
                machine.provider,
                machine.provider,
                floating_ip_token_file_env(&machine.provider),
                if self.tokens.is_empty() {
                    "none".to_string()
                } else {
                    self.tokens.keys().cloned().collect::<Vec<_>>().join(", ")
                },
            )
        })?;
        floating_ip_adapters::adapter_for(&machine.provider, token)
    }
}

/// What [`apply_effect`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectOutcome {
    /// A withdrawal was issued. `records_deleted == 0` means it had already
    /// taken effect on an earlier tick.
    Withdrew {
        machine: String,
        address: String,
        records_deleted: u32,
    },
    /// The floating IP now points at `machine` (R859-F3).
    ///
    /// `moved == false` is the idempotent case: it was already there, and
    /// `floating_ip::reconcile_assignment` short-circuited without issuing a
    /// vendor call. Same shape as `records_deleted == 0` above and for the same
    /// reason — the planner re-emits `Reassign` on every tick until the owner
    /// marker advances, so "already correct" must read as success.
    Reassigned {
        machine: String,
        ip_id: String,
        /// `true` iff a vendor reassign call was actually issued.
        moved: bool,
    },
    /// Nothing was commanded — the planner said `NoOp`/`Refuse`, or the effect
    /// is one this actor does not apply. Carries the planner's own reason.
    NotApplied { reason: String },
    /// An action was attempted and the provider call failed. Deliberately
    /// distinct from [`NotApplied`](Self::NotApplied): the caller must not
    /// treat a failed action as a converged one, or a dead origin stays in
    /// the round-robin while the log says the failover ran.
    Failed { reason: String },
}

/// Apply one [`IngressOwnerEffect`] — the IO half of the pure planner.
///
/// `address_of` resolves a machine name to its declared public address; on the
/// fleet that is
/// [`YubabaStateMachine::public_address_for_machine`](crate::raft::YubabaStateMachine::public_address_for_machine).
///
/// `machines` is the fleet's declarations as raft holds them — the same slice
/// `plan_ingress_owner_effect` decided against, re-resolved here rather than
/// carried on the effect. That is the shape `Withdraw` already had and the
/// reason its doc gives: an effect names a *machine*, and turning a machine
/// into an address or into a vendor client is the applier's job. Duplicating
/// either into the effect enum would create a second answer to a question the
/// declaration already settles.
///
/// # Every arm is refused unless it is configured, and says which
///
/// The two arms are independently optional (see [`EffectorConfig`]). A
/// `Reassign` on a node with no vendor credential, or a `Withdraw` on one with
/// no apex, is a [`NotApplied`](EffectOutcome::NotApplied) that names the exact
/// env var to set — never a silent no-op. The distinction from
/// [`Failed`](EffectOutcome::Failed) is load-bearing for the caller: a missing
/// credential will not fix itself on the next tick, a 502 from Hetzner might.
///
/// @yah:ticket(R859-F3, "Make the fleet's Reassign arm real: extract the three floating-IP vendor adapters into a sibling of yah-floating-ip")
/// @yah:phase(P1)
/// @yah:status(review)
/// @yah:at(2026-09-09T04:48:19Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R859)
/// @yah:gotcha("INERT ON TODAY'S FLEET, AND THAT IS WHY IT WAS DEFERRED RATHER THAN BUILT. Every machine in .yah/infra/machines/*.toml declares `provider = \"static\"` (grepped 2026-09-08: us-east-001, us-south-001, us-west-001/002/003/011/013/014/015 — all nine), and `static` has no floating-IP adapter at all; none declares `ingress_floating_ip`. So plan_ingress_owner_effect cannot emit Reassign on this fleet — it returns NoOp(\"declares no ingress_floating_ip\") — and the arm this ticket makes real is unreachable until a hetzner/ovh/vultr box with a floating IP joins. Do not treat a green test suite here as evidence the path works; it needs a live provider box.")
/// @yah:handoff("LANDED, uncommitted. The Reassign arm is real: on a leader tick, an ingress_owner flip onto a machine declaring an ingress_floating_ip now issues the vendor API call that moves the IP, instead of returning a NotApplied naming its own missing transport. Five pieces. (1) NEW crate oss/yubaba/crates/floating-ip-adapters (package yah-floating-ip-adapters, extern name floating_ip_adapters, registered in oss/yubaba/Cargo.toml members): the three FloatingIpProvider impls moved verbatim out of cloud into src/{hetzner,ovh,vultr}.rs with their 17 axum-mock tests, plus a new adapter_for(provider, credential) -> Box<dyn FloatingIpProvider> — the one provider-id-to-client match, so cloud's fob path and yubaba's token-file path build the same client from the same FLOATING_IP_PROVIDERS table. Deps: floating_ip + anyhow + async-trait + serde + serde_json + reqwest (no `stream` feature; nothing here streams a body); axum + tokio dev-only. (2) cloud/src/provider/floating_ip_envoy.rs (NEW) replaces the three deleted adapter files: one blanket `impl<T: FloatingIpProvider + ?Sized> FloatingIpEnvoy for T` in place of three byte-identical inherent floating_ip_assign/floating_ip_status pairs, one dispatch_floating_ip_verb() in place of three identical dispatch bodies (its unsupported-verb refusal now names the provider from FloatingIpProvider::id rather than a hardcoded literal), and three six-line EnvoyAdapter impls. floating_ip_provider_for keeps the fob lookup and delegates construction. provider/mod.rs re-exports the three types at their historical paths, so NO call site outside these files moved. (3) yubaba's ingress_effector gained a FloatingIpTransport seam + VendorTokens (reads each fob-injected vendor token file once at construction, same contract as CloudflareApexWithdrawal), and apply_effect's Reassign arm resolves the machine's declaration, builds the adapter and calls floating_ip::on_ingress_owner_changed. New outcome EffectOutcome::Reassigned{machine, ip_id, moved}. (4) THE CREDENTIAL AXIS: YUBABA_INGRESS_&lt;PROVIDER&gt;_TOKEN_FILE, derived from the provider id via floating_ip_token_file_env() rather than three more constants, so a fourth row in FLOATING_IP_PROVIDERS arms itself with no second edit. An env var outside that table is ignored, not guessed at. (5) app/yah/cli/resources/yubaba.service documents both arms and what each token needs.")
/// @yah:handoff("THE DESIGN CALL THE BRIEF DID NOT NAME, forced by the credential axis: the effector's two arms are now INDEPENDENTLY OPTIONAL. EffectorConfig was {apex, zone_id, token_file} with YUBABA_INGRESS_APEX as the master switch; it is now {apex: Option&lt;ApexConfig&gt;, floating_ip_token_files: BTreeMap&lt;provider, token_file&gt;} and parse_effector_config returns Ok(None) only when NEITHER arm is set. The reason is not tidiness: a Tier-1 fleet moves its front door by floating IP and never touches DNS, so requiring a Cloudflare apex + zone + token in order to move an IP would have made the arm this ticket exists to build unreachable for exactly the deployment it was built for. Pinned by a_floating_ip_arm_with_no_apex_parses_on_its_own. The mirror case is now a real failure mode and is tested too — a_withdrawal_with_no_apex_configured_names_what_is_missing — because before this change it could not happen. IngressEffector::apex() is therefore Option&lt;&amp;str&gt; and CloudflareApexWithdrawal::from_config takes the new ApexConfig.")
/// @yah:handoff("TWO SIGNATURE CHANGES, both forced and both strictly more permissive. (a) floating_ip::reconcile_assignment and on_ingress_owner_changed went from `provider: &amp;dyn FloatingIpProvider` to `&lt;P: FloatingIpProvider + ?Sized&gt;(provider: &amp;P)`. Required, not cosmetic: cloud's blanket FloatingIpEnvoy impl covers `dyn FloatingIpProvider` itself, and a `&amp;dyn` cannot be re-unsized to `&amp;dyn` under a Sized bound. Every existing caller still compiles unchanged. (b) apply_effect took (effect, apex: &amp;str, address_of, withdrawal); it now takes (effect, machines: &amp;[FloatingIpMachine], address_of, apex: Option&lt;(&amp;str, &amp;dyn ApexWithdrawal)&gt;, floating_ip: Option&lt;&amp;dyn FloatingIpTransport&gt;). The `machines` slice is there because IngressOwnerEffect::Reassign carries a machine NAME and an ip_id, not a resolved target — which is deliberate and matches Withdraw's own documented rationale (\"the DNS layer already knows how to turn a declared machine into an address\"). The declaration is what says which vendor hosts the box and which DC it sits in, and resolve_target needs both. scheduler.rs takes floating_ip_machines() ONCE per tick and hands the same slice to planner and effector, so the two halves cannot disagree within a tick.")
/// @yah:verify("Baselines are from R859-F2's recorded numbers where comparable, but the tree has moved under peers since, so treat deltas as approximate and the absolutes as measured. AFTER, all on this tree: yubaba --lib 855 passed / 0 failed (20 of them ingress_effector, up from 11 — the 9 new ones are the Reassign arm and the two-arm config). cloud --features json-schema: 1130 / 0 / 4 ignored on the lib target, plus 3/0/2, 2/0/0, 0/0/1 on the other three. yah-floating-ip: 18 / 0. yah-floating-ip-adapters (NEW): 20 / 0 — the 17 moved mock tests plus 3 for adapter_for. `cargo build --workspace`: EXIT=0. `cargo check --manifest-path oss/yubaba/Cargo.toml -p yubaba -p yah-cloud -p yah-floating-ip -p yah-floating-ip-adapters --all-targets`: clean. `RUSTC_WRAPPER='' cargo run -p xtask -- cluster-epochs`: GREEN, unmoved — cluster_protocol d4b539bd..., state_epoch 5b11870a... My raft/mod.rs edit was a doc comment only and no serialised type moved, so nothing needed re-recording. `./scripts/check-workspace-members.sh`: all 63 members resolve (the new crate included). clippy --all-targets on the new crate: zero hits; clippy on yubaba --lib --tests and cloud --lib: zero hits naming ingress_effector.rs, scheduler.rs or any floating_ip file.")
/// @yah:verify("WHAT THE 9 NEW ingress_effector TESTS PIN, since a count is not evidence. a_reassign_moves_the_floating_ip_onto_the_new_owner — exactly one vendor call, onto the machine the PLANNER named (the arm's whole point, and the one that was a NotApplied until now). a_reassign_to_where_the_ip_already_is_issues_no_vendor_call — zero calls, at the seam that actually runs in production rather than one layer down; the planner re-emits Reassign every tick until the owner marker advances, so this path runs constantly against a converged fleet. a_failed_vendor_reassign_is_failed_not_reassigned — keeps a failed move retryable, because scheduler.rs refuses to advance previous_ingress_owner past a Failed. a_reassign_with_no_transport_names_the_missing_credential — the pre-R859-F3 shape, kept deliberately: an unappliable Reassign may never degrade into silence. a_reassign_onto_a_vendor_this_node_has_no_credential_for_is_refused — a Hetzner token must not be pointed at an OVH box. a_reassign_naming_an_undeclared_machine_refuses_instead_of_guessing — reuses R859-F2's resolve_ingress_owner refusal at the effector, so the /etc/hostname-vs-machine-name mismatch (R841's `vps-4c1efa56` for `us-west-001`) refuses rather than misfiring a public IP. vendor_tokens_refuses_an_unheld_provider_by_name, the_vendor_token_file_env_is_derived_from_the_provider_id, a_floating_ip_arm_with_no_apex_parses_on_its_own, a_withdrawal_with_no_apex_configured_names_what_is_missing, every_registry_vendor_arms_independently_and_unknown_ones_are_ignored. In the adapters crate: every_row_of_the_registry_has_a_constructor_here — a FLOATING_IP_PROVIDERS row without a constructor is a machine that validates clean and then cannot be failed over, which is silent everywhere else. In cloud: the_envoy_id_is_the_provider_id_for_every_adapter, and an_unknown_verb_is_refused_and_names_the_provider (the drift the three-copy collapse removes).")
/// @yah:gotcha("STILL INERT ON TODAY'S FLEET, and the remaining gap is now purely OPERATOR CONFIGURATION, not code. Re-grepped 2026-09-08: all nine .yah/infra/machines/*.toml still declare provider = \"static\" and none declares ingress_floating_ip, so plan_ingress_owner_effect returns NoOp and this arm is never entered. Beyond that, R859-F2's own gotcha at cloud/src/provider/floating_ip.rs records that fleet flags are hand-rolled per node into a systemd drop-in (.yah/infra/cloud-init/dev-raft-node.sh:97 writes the whole `yubaba serve …` line) — NOTHING renders --provider/--location/--ingress-floating-ip from the machine TOML, and --region is not passed on the dev-raft boxes today. So arming this needs, per node: the four declaration flags on the ExecStart AND a YUBABA_INGRESS_&lt;PROVIDER&gt;_TOKEN_FILE line in /etc/yah-cloud/ingress.env (which R858's measurement at app/yah/cli/src/mesh.rs:117 says does not exist on us-east-001 — the acme.env and litestream.env EnvironmentFile lines already resolve to nothing there). A green suite here is evidence the logic is right against mocked vendor APIs; it is NOT evidence the path works, which needs a live hetzner/ovh/vultr box with a real floating IP.")
/// @yah:gotcha("OVH IS NOW LINKED INTO THE FLEET DAEMON AND ITS AUTH IS STILL A PLACEHOLDER. floating_ip_adapters::ovh's module doc carries the warning verbatim from where it lived in cloud: OVH signs with an application key + secret + consumer key and a timestamped HMAC, not the bare `X-Ovh-Consumer` header this adapter sends. That was tolerable when the only caller was an operator-driven envoy verb; it is a sharper edge now that a raft leader can invoke it unattended. Two things keep it contained and neither is an accident: the adapter is only reachable if an operator deliberately sets YUBABA_INGRESS_OVH_TOKEN_FILE, and its EnvoyAdapter tier stays Tier::A (not S) with a doc comment saying why. Swap in real OVH request signing before pointing it at anything live.")
/// @yah:handoff("FILES (all uncommitted; tree anchor 24d24042d537b453e01d330ac185445398ec74a9 — quote that SHA, not HEAD, in any restore instruction). NEW: oss/yubaba/crates/floating-ip-adapters/{Cargo.toml,src/lib.rs,src/hetzner.rs,src/ovh.rs,src/vultr.rs}; oss/yubaba/crates/cloud/src/provider/floating_ip_envoy.rs. DELETED: oss/yubaba/crates/cloud/src/provider/{hetzner,ovh,vultr}_floating_ip.rs (moved, not lost — their bodies and every one of their tests are in the new crate). MODIFIED: oss/yubaba/Cargo.toml (members), cloud/Cargo.toml (+floating_ip_adapters; corrected the axum comment, which no longer covers the floating-ip mocks), cloud/src/provider/{mod.rs,floating_ip.rs}, floating-ip/src/lib.rs (two signatures generic over ?Sized + three doc sections that my own move had just made false), yubaba/Cargo.toml (+floating_ip_adapters), yubaba/src/{ingress_effector.rs,scheduler.rs,main.rs}, yubaba/src/raft/mod.rs (MemberInfo::location's doc said \"nothing on the fleet path reads it today\" — this ticket is what made that a lie, so it now says what reads it), app/yah/cli/resources/yubaba.service. COLLISION CHECK: raft/store.rs and main.rs both showed as changed mid-build; I diffed both — store.rs carries ONLY @Ashguard:coffee's R869 annotation edits (I did not touch that file), and main.rs's only non-mine content is untouched. Peers active during this session and NOT interfered with: @Ashguard:eclipse and @Miravel:polaris on R870 (tenant-streamer, kamaji-bin), @Ashguard:coffee on R869 (raft/store.rs), @Ashguard:spade on chat (app/yah/cli/src/cloud.rs).")
/// @yah:gotcha("TWO PRE-EXISTING BREAKAGES ON THE SHARED TREE, neither mine, both confirmed foreign before I stopped attributing to myself. (1) `cargo check --workspace --all-targets` fails on app/yah/cli/src/cloud.rs:16055 and :16057 — `cannot find value `dir` in this scope`, in a #[cfg(test)] body. @Ashguard:spade was running `cargo test -p yah --lib -- cloud::tests::writes_the_full_tier1_file_set cloud::tests::the_scaffolds_runtime` against exactly that region while I worked. I never touched app/yah/cli/src/. `cargo check --workspace` and `cargo build --workspace` (non-test targets) are both GREEN. (2) `cargo check --manifest-path oss/yubaba/Cargo.toml --all-targets` fails on three `dyn ObjectStore doesn't implement Debug` errors in tenant-streamer/src/lib.rs:222/230/246 — @Ashguard:eclipse's live R870 work, which the build-input hasher flagged as modifying under me on five separate runs. I scoped my all-targets check to -p yubaba -p yah-cloud -p yah-floating-ip -p yah-floating-ip-adapters instead, which is clean. Separately, cloud's asset_journal::tests::append_creates_file_and_writes_jsonl failed ONCE under the full parallel run and passed on a targeted re-run and on every subsequent full run — a flake in a file this ticket does not touch.")
/// @yah:assumes("The three vendor adapters' wire shapes are unchanged from R594-F5 — they were moved verbatim, not rewritten, and their mock suites moved with them. Nothing here has ever been exercised against a live Hetzner, OVH or Vultr API, so \"the request shape is right\" remains an assumption inherited from R594-F5, not a measurement this ticket added.")
pub async fn apply_effect(
    effect: &IngressOwnerEffect,
    machines: &[FloatingIpMachine],
    address_of: impl Fn(&str) -> Option<String>,
    apex: Option<(&str, &dyn ApexWithdrawal)>,
    floating_ip: Option<&dyn FloatingIpTransport>,
) -> EffectOutcome {
    match effect {
        IngressOwnerEffect::Withdraw { machine, reason } => {
            let Some((apex, withdrawal)) = apex else {
                return EffectOutcome::NotApplied {
                    reason: format!(
                        "{reason}, but this node has no apex configured, so the dead origin was \
                         NOT withdrawn from DNS. Set ${APEX_ENV} (plus ${TOKEN_FILE_ENV} and \
                         ${ZONE_ID_ENV}) to arm the withdrawal arm."
                    ),
                };
            };
            let Some(address) = address_of(machine) else {
                return EffectOutcome::NotApplied {
                    reason: format!(
                        "{reason}, but {machine} declares no public address, so there is no A \
                         record to withdraw. A content-matched delete is the only shape allowed \
                         here — deleting by name would take the surviving origins with it. Set \
                         --public-address on that node (R859-F2 phase A)."
                    ),
                };
            };
            match withdrawal.withdraw_a_record(apex, &address).await {
                Ok(records_deleted) => EffectOutcome::Withdrew {
                    machine: machine.clone(),
                    address,
                    records_deleted,
                },
                Err(e) => EffectOutcome::Failed {
                    reason: format!("withdrawing {address} ({machine}) from {apex} failed: {e:#}"),
                },
            }
        }
        IngressOwnerEffect::Reassign { machine, ip_id } => {
            let Some(transport) = floating_ip else {
                return EffectOutcome::NotApplied {
                    reason: format!(
                        "ingress moved to {machine}, which declares floating IP {ip_id} — but this \
                         node holds no floating-IP credential, so the reassign was NOT performed. \
                         Set ${} (or the equivalent for that machine's provider) to a fob-injected \
                         token file. Until then, move the IP by hand with \
                         `yah cloud envoy floating_ip.assign`.",
                        floating_ip_token_file_env("hetzner"),
                    ),
                };
            };
            // The declaration, not the effect, is what says which vendor hosts
            // this box and which DC it sits in — `resolve_target` needs both,
            // and the effect carries neither by design.
            let facts = match floating_ip::resolve_ingress_owner(machine, machines) {
                Ok(m) => m,
                Err(e) => {
                    return EffectOutcome::NotApplied {
                        reason: format!(
                            "ingress moved to {machine} (floating IP {ip_id}), but its declaration \
                             could not be resolved, so the reassign was NOT performed: {e:#}"
                        ),
                    }
                }
            };
            let provider = match transport.provider_for(facts) {
                Ok(p) => p,
                Err(e) => {
                    return EffectOutcome::NotApplied {
                        reason: format!(
                            "ingress moved to {machine} (floating IP {ip_id}), but no floating-IP \
                             transport could be built, so the reassign was NOT performed: {e:#}"
                        ),
                    }
                }
            };
            // `on_ingress_owner_changed` is resolve + reconcile: it refuses a
            // cross-zone move before issuing anything, and short-circuits to
            // zero vendor calls when the IP is already where it belongs.
            match floating_ip::on_ingress_owner_changed(provider.as_ref(), facts, ip_id).await {
                Ok(outcome) => EffectOutcome::Reassigned {
                    machine: machine.clone(),
                    ip_id: ip_id.clone(),
                    moved: outcome.reassigned,
                },
                Err(e) => EffectOutcome::Failed {
                    reason: format!(
                        "reassigning floating IP {ip_id} onto {machine} ({}) failed: {e:#}",
                        facts.provider
                    ),
                },
            }
        }
        IngressOwnerEffect::Refuse { reason } | IngressOwnerEffect::NoOp { reason } => {
            EffectOutcome::NotApplied {
                reason: reason.clone(),
            }
        }
    }
}

/// Turn "which node runs the ingress owner" plus the hysteresis's verdict on
/// that node into the planner's [`OwnerLiveness`].
///
/// Split out of the scheduler tick because it is the one place the *direction*
/// of the liveness channel can be got wrong, and getting it wrong withdraws a
/// live origin. Two absences collapse into
/// [`Unconfirmed`](OwnerLiveness::Unconfirmed) and neither may ever read as
/// down:
///
/// - `node` is `None` — the `ingress_owner` string matches no member row, so
///   there is no node whose liveness to consult. A missing member row is not
///   evidence a box is dead; it is evidence the map is incomplete, which is the
///   ordinary state of a node that has not finished registering.
/// - `committed` is `None` — the hysteresis has not dwelled long enough either
///   way. That is the freshly-elected-leader case (its tracker is empty), and
///   `plan_ingress_owner_effect` requires positive `ConfirmedDown` evidence
///   before it will withdraw anything.
pub fn owner_liveness(
    node: Option<crate::raft::YubabaNodeId>,
    committed: impl Fn(crate::raft::YubabaNodeId) -> Option<crate::lease_detector::Confirmed>,
) -> OwnerLiveness {
    use crate::lease_detector::Confirmed;
    match node.and_then(committed) {
        Some(Confirmed::Down) => OwnerLiveness::ConfirmedDown,
        Some(Confirmed::Up) => OwnerLiveness::ConfirmedUp,
        None => OwnerLiveness::Unconfirmed,
    }
}

/// The apex plus the transport allowed to subtract from it — what
/// [`scheduler`](crate::scheduler) holds when the effector is configured.
///
/// `None` at the call site (the default, and every camp that has not set
/// [`APEX_ENV`]) means the scheduler tick does not plan an ingress effect at
/// all. That is deliberately a *whole-feature* off switch rather than a
/// no-op transport: a planner running with nothing to apply would log a
/// failover decision on every tick of every cluster that will never act on one.
pub struct IngressEffector {
    /// The apex-withdrawal arm — the apex name and the transport allowed to
    /// subtract from it. `None` when no apex is configured.
    apex: Option<(String, std::sync::Arc<dyn ApexWithdrawal>)>,
    /// The floating-IP arm. `None` when this node holds no vendor credential.
    floating_ip: Option<std::sync::Arc<dyn FloatingIpTransport>>,
}

impl IngressEffector {
    /// Assemble from whichever arms are armed.
    ///
    /// Both `None` is representable and inert rather than rejected: the caller
    /// that would construct one ([`parse_effector_config`]) already returns
    /// `Ok(None)` in that case, so making this a `Result` would add a second
    /// place to state the same rule.
    pub fn new(
        apex: Option<(String, std::sync::Arc<dyn ApexWithdrawal>)>,
        floating_ip: Option<std::sync::Arc<dyn FloatingIpTransport>>,
    ) -> Self {
        Self { apex, floating_ip }
    }

    /// Build the production effector: a Cloudflare transport over the config's
    /// zone and fob-injected token, plus a vendor client per configured
    /// floating-IP credential.
    pub fn from_config(config: &EffectorConfig) -> Result<Self> {
        let apex = config
            .apex
            .as_ref()
            .map(|cfg| -> Result<_> {
                Ok((
                    cfg.apex.clone(),
                    std::sync::Arc::new(CloudflareApexWithdrawal::from_config(cfg)?)
                        as std::sync::Arc<dyn ApexWithdrawal>,
                ))
            })
            .transpose()?;
        let floating_ip = if config.floating_ip_token_files.is_empty() {
            None
        } else {
            Some(std::sync::Arc::new(VendorTokens::from_token_files(
                &config.floating_ip_token_files,
            )?) as std::sync::Arc<dyn FloatingIpTransport>)
        };
        Ok(Self::new(apex, floating_ip))
    }

    /// The apex record this effector may withdraw from, if it may withdraw at
    /// all.
    pub fn apex(&self) -> Option<&str> {
        self.apex.as_ref().map(|(name, _)| name.as_str())
    }

    /// [`apply_effect`] against this effector's configured arms.
    pub async fn apply(
        &self,
        effect: &IngressOwnerEffect,
        machines: &[FloatingIpMachine],
        address_of: impl Fn(&str) -> Option<String>,
    ) -> EffectOutcome {
        apply_effect(
            effect,
            machines,
            address_of,
            self.apex
                .as_ref()
                .map(|(name, w)| (name.as_str(), w.as_ref())),
            self.floating_ip.as_deref(),
        )
        .await
    }
}

/// [`ApexWithdrawal`] over Cloudflare's DNS API.
///
/// Two calls, both zone-scoped: list the A records at the apex, then delete the
/// ones whose content matches. That is the entire wire surface, which is the
/// point — `cloud::provider::cloudflare::CloudflareClient` can do R2, Workers,
/// tunnels and token minting, and none of that belongs on a fleet node.
pub struct CloudflareApexWithdrawal {
    http: reqwest::Client,
    token: String,
    zone_id: String,
    base_url: String,
}

impl CloudflareApexWithdrawal {
    /// Build from a config, reading the token out of its `fob`-injected file.
    ///
    /// The read happens once at construction rather than per call: a rotated
    /// token takes effect on the next daemon restart, which is the same
    /// contract the ACME issuer's token file has.
    pub fn from_config(config: &ApexConfig) -> Result<Self> {
        let token = std::fs::read_to_string(&config.token_file)
            .with_context(|| format!("reading Cloudflare token file {}", config.token_file))?
            .trim()
            .to_string();
        anyhow::ensure!(
            !token.is_empty(),
            "Cloudflare token file {} is empty",
            config.token_file
        );
        Ok(Self {
            http: reqwest::Client::new(),
            token,
            zone_id: config.zone_id.clone(),
            base_url: CLOUDFLARE_API.to_string(),
        })
    }

    /// Point at a stub server instead of `api.cloudflare.com`.
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Construct directly from a token — the test/embedding path that skips
    /// the file read.
    pub fn new(token: impl Into<String>, zone_id: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            token: token.into(),
            zone_id: zone_id.into(),
            base_url: CLOUDFLARE_API.to_string(),
        }
    }
}

#[derive(Deserialize)]
struct CfPage<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    #[serde(default = "Vec::new")]
    result: Vec<T>,
}

#[derive(Deserialize)]
struct CfUnit {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
}

#[derive(Deserialize)]
struct CfError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct CfDnsRecord {
    id: String,
    content: String,
}

fn cf_ok(success: bool, errors: &[CfError]) -> Result<()> {
    anyhow::ensure!(
        success,
        "cloudflare API rejected the call: {}",
        if errors.is_empty() {
            "no error detail returned".to_string()
        } else {
            errors
                .iter()
                .map(|e| format!("[{}] {}", e.code, e.message))
                .collect::<Vec<_>>()
                .join("; ")
        }
    );
    Ok(())
}

#[async_trait]
impl ApexWithdrawal for CloudflareApexWithdrawal {
    async fn withdraw_a_record(&self, apex: &str, address: &str) -> Result<u32> {
        let listed: CfPage<CfDnsRecord> = self
            .http
            .get(format!(
                "{}/zones/{}/dns_records?name={apex}&type=A&per_page=100",
                self.base_url, self.zone_id
            ))
            .bearer_auth(&self.token)
            .send()
            .await
            .with_context(|| format!("listing A records at {apex}"))?
            .json()
            .await
            .with_context(|| format!("decoding the A records at {apex}"))?;
        cf_ok(listed.success, &listed.errors)?;

        // The content match is the safety property, applied here rather than
        // trusted to the query string: Cloudflare's list endpoint filters on
        // `content` too, but a filter that silently stopped working would
        // delete the whole round-robin. Matching locally means the worst a
        // broken filter can do is return records this loop then declines to
        // touch.
        let doomed: Vec<String> = listed
            .result
            .into_iter()
            .filter(|r| r.content == address)
            .map(|r| r.id)
            .collect();

        let mut deleted = 0u32;
        for id in &doomed {
            let resp: CfUnit = self
                .http
                .delete(format!(
                    "{}/zones/{}/dns_records/{id}",
                    self.base_url, self.zone_id
                ))
                .bearer_auth(&self.token)
                .send()
                .await
                .with_context(|| format!("deleting A record {id} ({address}) at {apex}"))?
                .json()
                .await
                .with_context(|| format!("decoding the delete of A record {id} at {apex}"))?;
            cf_ok(resp.success, &resp.errors)?;
            deleted += 1;
        }
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use floating_ip::{FloatingIpState, FloatingIpTarget};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    /// Records what it was asked to withdraw, so a test can assert on the
    /// *arguments* — which apex, which address — rather than only on the
    /// outcome. Getting the address wrong is the failure mode that matters:
    /// it deletes a living origin.
    #[derive(Default)]
    struct FakeWithdrawal {
        calls: Mutex<Vec<(String, String)>>,
        deleted: u32,
        fail: bool,
    }

    #[async_trait]
    impl ApexWithdrawal for FakeWithdrawal {
        async fn withdraw_a_record(&self, apex: &str, address: &str) -> Result<u32> {
            self.calls
                .lock()
                .unwrap()
                .push((apex.to_string(), address.to_string()));
            if self.fail {
                anyhow::bail!("cloudflare said no");
            }
            Ok(self.deleted)
        }
    }

    /// The apex arm, wired to `yah.dev` — the shape `apply_effect` takes.
    fn apex(w: &FakeWithdrawal) -> Option<(&str, &dyn ApexWithdrawal)> {
        Some(("yah.dev", w))
    }

    fn addresses<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |m| {
            pairs
                .iter()
                .find(|(name, _)| *name == m)
                .map(|(_, addr)| addr.to_string())
        }
    }

    fn hetzner_machine(name: &str) -> FloatingIpMachine {
        FloatingIpMachine {
            name: name.into(),
            provider: "hetzner".into(),
            location: Some("hil".into()),
            region: Some("us-west".into()),
            ingress_floating_ip: Some("fip-42".into()),
        }
    }

    /// A vendor client with no network: `resolve_target` derives an attach id
    /// from the machine name, and the reassign call count is shared with the
    /// test so "zero vendor calls" can be asserted rather than inferred.
    struct StubProvider {
        zone: String,
        attached: Mutex<Option<String>>,
        calls: Arc<AtomicU32>,
        fail: bool,
    }

    #[async_trait]
    impl FloatingIpProvider for StubProvider {
        fn id(&self) -> &'static str {
            "hetzner"
        }
        async fn resolve_target(&self, machine: &FloatingIpMachine) -> Result<FloatingIpTarget> {
            Ok(FloatingIpTarget {
                attach_id: format!("srv-{}", machine.name),
                zone: self.zone.clone(),
            })
        }
        async fn current_assignment(&self, _ip_id: &str) -> Result<FloatingIpState> {
            Ok(FloatingIpState {
                zone: self.zone.clone(),
                attached_to: self.attached.lock().unwrap().clone(),
            })
        }
        async fn reassign(&self, _ip_id: &str, target: &FloatingIpTarget) -> Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                anyhow::bail!("hetzner said no");
            }
            *self.attached.lock().unwrap() = Some(target.attach_id.clone());
            Ok(())
        }
    }

    /// Stands in for [`VendorTokens`]: holds a credential for `hetzner` only,
    /// so the "this node has no credential for that vendor" refusal is
    /// exercised with the same code path a real mixed-provider fleet takes.
    struct StubTransport {
        zone: &'static str,
        attached: Option<String>,
        calls: Arc<AtomicU32>,
        fail: bool,
    }

    impl StubTransport {
        fn new(calls: &Arc<AtomicU32>) -> Self {
            Self {
                zone: "us-west",
                attached: Some("srv-old".into()),
                calls: calls.clone(),
                fail: false,
            }
        }
    }

    impl FloatingIpTransport for StubTransport {
        fn provider_for(&self, machine: &FloatingIpMachine) -> Result<Box<dyn FloatingIpProvider>> {
            anyhow::ensure!(
                machine.provider == "hetzner",
                "this node holds no {} credential — set ${}",
                machine.provider,
                floating_ip_token_file_env(&machine.provider),
            );
            Ok(Box::new(StubProvider {
                zone: self.zone.to_string(),
                attached: Mutex::new(self.attached.clone()),
                calls: self.calls.clone(),
                fail: self.fail,
            }))
        }
    }

    #[tokio::test]
    async fn a_withdrawal_deletes_the_dead_origins_own_address() {
        let fake = FakeWithdrawal {
            deleted: 1,
            ..Default::default()
        };
        let out = apply_effect(
            &IngressOwnerEffect::Withdraw {
                machine: "us-west-001".into(),
                reason: "confirmed down".into(),
            },
            &[],
            addresses(&[
                ("us-west-001", "15.204.89.240"),
                ("us-east-001", "51.81.85.145"),
            ]),
            apex(&fake),
            None,
        )
        .await;
        assert_eq!(
            out,
            EffectOutcome::Withdrew {
                machine: "us-west-001".into(),
                address: "15.204.89.240".into(),
                records_deleted: 1,
            }
        );
        // The address handed to the transport is the DEAD machine's, not a
        // survivor's. This is the assertion the whole feature turns on.
        assert_eq!(
            *fake.calls.lock().unwrap(),
            vec![("yah.dev".to_string(), "15.204.89.240".to_string())]
        );
    }

    /// The steady state while a node stays down: the planner keeps emitting
    /// `Withdraw` every tick because the owner is still confirmed dead, and
    /// every tick after the first deletes nothing. That must read as success,
    /// or the effector would log a failure on every tick of a working
    /// failover.
    #[tokio::test]
    async fn a_repeated_withdrawal_deleting_nothing_is_still_a_success() {
        let fake = FakeWithdrawal::default();
        let out = apply_effect(
            &IngressOwnerEffect::Withdraw {
                machine: "us-west-001".into(),
                reason: "confirmed down".into(),
            },
            &[],
            addresses(&[("us-west-001", "15.204.89.240")]),
            apex(&fake),
            None,
        )
        .await;
        assert!(matches!(
            out,
            EffectOutcome::Withdrew {
                records_deleted: 0,
                ..
            }
        ));
    }

    /// A machine with no declared public address cannot be withdrawn, and the
    /// effector must not reach for a substitute. There is exactly one address
    /// that may be deleted and if it is unknown the correct action is none —
    /// a dead origin in DNS is a partial outage, a wrongly-deleted one is
    /// somebody else's.
    #[tokio::test]
    async fn an_undeclared_public_address_refuses_instead_of_guessing() {
        let fake = FakeWithdrawal::default();
        let out = apply_effect(
            &IngressOwnerEffect::Withdraw {
                machine: "us-west-002".into(),
                reason: "confirmed down".into(),
            },
            &[],
            addresses(&[("us-west-001", "15.204.89.240")]),
            apex(&fake),
            None,
        )
        .await;
        match out {
            EffectOutcome::NotApplied { reason } => {
                assert!(reason.contains("us-west-002"), "{reason}");
                assert!(reason.contains("no public address"), "{reason}");
            }
            other => panic!("expected NotApplied, got {other:?}"),
        }
        assert!(
            fake.calls.lock().unwrap().is_empty(),
            "nothing may be deleted when the address is unknown"
        );
    }

    /// R859-F3 made the two arms independently optional, which creates a new
    /// way to be half-armed: a floating-IP-only node that is asked to withdraw.
    /// It must name the env vars that would arm it, not read as "nothing to do".
    #[tokio::test]
    async fn a_withdrawal_with_no_apex_configured_names_what_is_missing() {
        let out = apply_effect(
            &IngressOwnerEffect::Withdraw {
                machine: "us-west-001".into(),
                reason: "confirmed down".into(),
            },
            &[],
            addresses(&[("us-west-001", "15.204.89.240")]),
            None,
            None,
        )
        .await;
        match out {
            EffectOutcome::NotApplied { reason } => {
                assert!(reason.contains(APEX_ENV), "{reason}");
                assert!(reason.contains("NOT withdrawn"), "{reason}");
            }
            other => panic!("expected NotApplied, got {other:?}"),
        }
    }

    /// A failed provider call is `Failed`, never `Withdrew`. The caller uses
    /// that distinction to keep retrying rather than recording a failover that
    /// did not happen.
    #[tokio::test]
    async fn a_failed_provider_call_is_reported_as_failed_not_withdrawn() {
        let fake = FakeWithdrawal {
            fail: true,
            ..Default::default()
        };
        let out = apply_effect(
            &IngressOwnerEffect::Withdraw {
                machine: "us-west-001".into(),
                reason: "confirmed down".into(),
            },
            &[],
            addresses(&[("us-west-001", "15.204.89.240")]),
            apex(&fake),
            None,
        )
        .await;
        match out {
            EffectOutcome::Failed { reason } => assert!(reason.contains("cloudflare said no")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    /// `Refuse` and `NoOp` carry the planner's reason through unchanged, so
    /// the operator-facing log line names which of the planner's paths was
    /// taken rather than a generic "nothing happened".
    #[tokio::test]
    async fn a_refusal_carries_the_planners_own_reason_through() {
        let fake = FakeWithdrawal::default();
        for effect in [
            IngressOwnerEffect::Refuse {
                reason: "quorum is degraded: 1 of 3 voters down".into(),
            },
            IngressOwnerEffect::NoOp {
                reason: "quorum is degraded: 1 of 3 voters down".into(),
            },
        ] {
            let out = apply_effect(&effect, &[], addresses(&[]), apex(&fake), None).await;
            assert_eq!(
                out,
                EffectOutcome::NotApplied {
                    reason: "quorum is degraded: 1 of 3 voters down".into()
                }
            );
        }
        assert!(fake.calls.lock().unwrap().is_empty());
    }

    // ── R859-F3: the Reassign arm ────────────────────────────────────────────

    /// The arm that was a `NotApplied` until R859-F3. One vendor call, and the
    /// IP ends up on the machine the planner named — not on the old owner, and
    /// not on whichever box the transport happened to resolve first.
    #[tokio::test]
    async fn a_reassign_moves_the_floating_ip_onto_the_new_owner() {
        let calls = Arc::new(AtomicU32::new(0));
        let transport = StubTransport::new(&calls);
        let out = apply_effect(
            &IngressOwnerEffect::Reassign {
                machine: "edge-a".into(),
                ip_id: "fip-42".into(),
            },
            &[hetzner_machine("edge-a")],
            addresses(&[]),
            None,
            Some(&transport),
        )
        .await;
        assert_eq!(
            out,
            EffectOutcome::Reassigned {
                machine: "edge-a".into(),
                ip_id: "fip-42".into(),
                moved: true,
            }
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// The planner re-emits `Reassign` on every tick until the owner marker
    /// advances, so the effector runs this path repeatedly against a converged
    /// fleet. It must cost zero vendor calls — the same idempotency the three
    /// adapter suites pin one layer down, asserted here at the seam that
    /// actually runs in production.
    #[tokio::test]
    async fn a_reassign_to_where_the_ip_already_is_issues_no_vendor_call() {
        let calls = Arc::new(AtomicU32::new(0));
        let transport = StubTransport {
            attached: Some("srv-edge-a".into()),
            ..StubTransport::new(&calls)
        };
        let out = apply_effect(
            &IngressOwnerEffect::Reassign {
                machine: "edge-a".into(),
                ip_id: "fip-42".into(),
            },
            &[hetzner_machine("edge-a")],
            addresses(&[]),
            None,
            Some(&transport),
        )
        .await;
        assert!(
            matches!(out, EffectOutcome::Reassigned { moved: false, .. }),
            "expected an idempotent no-op, got {out:?}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    /// A vendor call that fails is `Failed`, never `Reassigned` — the same
    /// distinction the withdrawal arm draws, and for the same reason: the
    /// scheduler will not advance its owner marker past a `Failed`, so the
    /// next tick re-decides instead of recording a move that never happened.
    #[tokio::test]
    async fn a_failed_vendor_reassign_is_failed_not_reassigned() {
        let calls = Arc::new(AtomicU32::new(0));
        let transport = StubTransport {
            fail: true,
            ..StubTransport::new(&calls)
        };
        let out = apply_effect(
            &IngressOwnerEffect::Reassign {
                machine: "edge-a".into(),
                ip_id: "fip-42".into(),
            },
            &[hetzner_machine("edge-a")],
            addresses(&[]),
            None,
            Some(&transport),
        )
        .await;
        match out {
            EffectOutcome::Failed { reason } => {
                assert!(reason.contains("hetzner said no"), "{reason}");
                assert!(reason.contains("fip-42"), "{reason}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    /// A node with no vendor credential must say which env var would arm it.
    /// This is the shape the arm had for its whole pre-R859-F3 life, kept
    /// deliberately: an unappliable `Reassign` may never degrade into silence.
    #[tokio::test]
    async fn a_reassign_with_no_transport_names_the_missing_credential() {
        let out = apply_effect(
            &IngressOwnerEffect::Reassign {
                machine: "edge-a".into(),
                ip_id: "fip-42".into(),
            },
            &[hetzner_machine("edge-a")],
            addresses(&[]),
            None,
            None,
        )
        .await;
        match out {
            EffectOutcome::NotApplied { reason } => {
                assert!(reason.contains("fip-42"), "{reason}");
                assert!(reason.contains("NOT performed"), "{reason}");
                assert!(reason.contains("TOKEN_FILE"), "{reason}");
            }
            other => panic!("expected NotApplied, got {other:?}"),
        }
    }

    /// A credential for the wrong vendor is not a credential. The refusal names
    /// the provider and its env var rather than falling back to whichever token
    /// this node happens to hold — pointing a Hetzner token at an OVH box is an
    /// authentication failure at best and a wrong-IP move at worst.
    #[tokio::test]
    async fn a_reassign_onto_a_vendor_this_node_has_no_credential_for_is_refused() {
        let calls = Arc::new(AtomicU32::new(0));
        let transport = StubTransport::new(&calls);
        let mut machine = hetzner_machine("edge-b");
        machine.provider = "vultr".into();
        let out = apply_effect(
            &IngressOwnerEffect::Reassign {
                machine: "edge-b".into(),
                ip_id: "fip-42".into(),
            },
            &[machine],
            addresses(&[]),
            None,
            Some(&transport),
        )
        .await;
        match out {
            EffectOutcome::NotApplied { reason } => {
                assert!(reason.contains("vultr"), "{reason}");
                assert!(reason.contains("NOT performed"), "{reason}");
            }
            other => panic!("expected NotApplied, got {other:?}"),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    /// The effect names a machine; the declarations say which vendor and which
    /// DC that machine is. If raft names an owner nothing declares, there is no
    /// vendor to call and guessing one would move a public IP onto the wrong
    /// box — the outage this whole path exists to prevent.
    #[tokio::test]
    async fn a_reassign_naming_an_undeclared_machine_refuses_instead_of_guessing() {
        let calls = Arc::new(AtomicU32::new(0));
        let transport = StubTransport::new(&calls);
        let out = apply_effect(
            &IngressOwnerEffect::Reassign {
                machine: "vps-4c1efa56".into(),
                ip_id: "fip-42".into(),
            },
            &[hetzner_machine("edge-a")],
            addresses(&[]),
            None,
            Some(&transport),
        )
        .await;
        match out {
            EffectOutcome::NotApplied { reason } => {
                assert!(reason.contains("vps-4c1efa56"), "{reason}");
                assert!(reason.contains("NOT performed"), "{reason}");
            }
            other => panic!("expected NotApplied, got {other:?}"),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    /// The env-var name is derived from the provider id, so this is the one
    /// place the derivation can be checked against the literal strings an
    /// operator will actually put in a unit file.
    #[test]
    fn the_vendor_token_file_env_is_derived_from_the_provider_id() {
        assert_eq!(
            floating_ip_token_file_env("hetzner"),
            "YUBABA_INGRESS_HETZNER_TOKEN_FILE"
        );
        assert_eq!(
            floating_ip_token_file_env("ovh"),
            "YUBABA_INGRESS_OVH_TOKEN_FILE"
        );
        assert_eq!(
            floating_ip_token_file_env("vultr"),
            "YUBABA_INGRESS_VULTR_TOKEN_FILE"
        );
    }

    /// [`VendorTokens`] refuses a vendor it holds nothing for, and names both
    /// the env var to set and what it *does* hold — the two facts an operator
    /// staring at a failover log needs.
    #[test]
    fn vendor_tokens_refuses_an_unheld_provider_by_name() {
        let tokens =
            VendorTokens::new(BTreeMap::from([("hetzner".to_string(), "tok".to_string())]));
        assert!(tokens.provider_for(&hetzner_machine("edge-a")).is_ok());

        let mut ovh = hetzner_machine("edge-b");
        ovh.provider = "ovh".into();
        let msg = match tokens.provider_for(&ovh) {
            Ok(_) => panic!("built an OVH client from a Hetzner-only token set"),
            Err(e) => format!("{e:#}"),
        };
        assert!(msg.contains("YUBABA_INGRESS_OVH_TOKEN_FILE"), "{msg}");
        assert!(msg.contains("hetzner"), "should name what IS held: {msg}");
    }

    /// The liveness channel may only ever VETO. Both ways of not knowing —
    /// an `ingress_owner` that maps to no node, and a node the hysteresis has
    /// not committed — must read as `Unconfirmed`, because the withdrawal path
    /// requires positive `ConfirmedDown` evidence and reading absence as death
    /// would pull a live origin out of the round-robin.
    #[test]
    fn not_knowing_is_never_confirmed_down() {
        use crate::lease_detector::Confirmed;
        assert_eq!(
            owner_liveness(None, |_| Some(Confirmed::Down)),
            OwnerLiveness::Unconfirmed,
            "an ingress_owner that matches no member row has no liveness at all — it must not \
             borrow some other node's"
        );
        assert_eq!(
            owner_liveness(Some(1), |_| None),
            OwnerLiveness::Unconfirmed
        );
        assert_eq!(
            owner_liveness(Some(1), |_| Some(Confirmed::Down)),
            OwnerLiveness::ConfirmedDown
        );
        assert_eq!(
            owner_liveness(Some(1), |_| Some(Confirmed::Up)),
            OwnerLiveness::ConfirmedUp
        );
    }

    #[test]
    fn the_effector_is_off_unless_an_arm_is_declared() {
        assert_eq!(parse_effector_config(|_| None), Ok(None));
        // A blank value is "unset", not "an apex named empty string".
        assert_eq!(
            parse_effector_config(|k| (k == APEX_ENV).then(|| "   ".to_string())),
            Ok(None)
        );
        // Likewise for a vendor token file: a blank path arms nothing.
        assert_eq!(
            parse_effector_config(
                |k| (k == floating_ip_token_file_env("hetzner")).then(|| "  ".to_string())
            ),
            Ok(None)
        );
    }

    /// Half-configured is refused at startup, not at 3am. A missing token
    /// would otherwise surface for the first time during the failover it was
    /// meant to perform.
    #[test]
    fn a_declared_apex_with_no_credential_is_refused_at_parse_time() {
        let err = parse_effector_config(|k| (k == APEX_ENV).then(|| "yah.dev".to_string()))
            .expect_err("a bare apex must not configure an effector");
        assert!(err.contains(TOKEN_FILE_ENV), "{err}");

        let err = parse_effector_config(|k| match k {
            APEX_ENV => Some("yah.dev".to_string()),
            TOKEN_FILE_ENV => Some("/run/fob/cf-token".to_string()),
            _ => None,
        })
        .expect_err("a token with no zone must not configure an effector");
        assert!(err.contains(ZONE_ID_ENV), "{err}");
    }

    #[test]
    fn a_fully_declared_apex_arm_parses() {
        assert_eq!(
            parse_effector_config(|k| match k {
                APEX_ENV => Some("  yah.dev  ".to_string()),
                TOKEN_FILE_ENV => Some("/run/fob/cf-token".to_string()),
                ZONE_ID_ENV => Some("zone-123".to_string()),
                _ => None,
            }),
            Ok(Some(EffectorConfig {
                apex: Some(ApexConfig {
                    apex: "yah.dev".into(),
                    zone_id: "zone-123".into(),
                    token_file: "/run/fob/cf-token".into(),
                }),
                floating_ip_token_files: BTreeMap::new(),
            }))
        );
    }

    /// A Tier-1 fleet moves its front door by floating IP and never touches
    /// DNS. Requiring an apex to arm the vendor arm would have made R859-F3
    /// unreachable for exactly the deployment it was built for, so this asserts
    /// the vendor arm stands alone.
    #[test]
    fn a_floating_ip_arm_with_no_apex_parses_on_its_own() {
        assert_eq!(
            parse_effector_config(|k| (k == floating_ip_token_file_env("hetzner"))
                .then(|| " /run/fob/hetzner-token ".to_string())),
            Ok(Some(EffectorConfig {
                apex: None,
                floating_ip_token_files: BTreeMap::from([(
                    "hetzner".to_string(),
                    "/run/fob/hetzner-token".to_string()
                )]),
            }))
        );
    }

    /// A fleet spanning two vendors has two floating-IP domains and needs both
    /// credentials; an env var outside the registry is ignored rather than
    /// guessed at, so a typo disarms loudly instead of arming something else.
    #[test]
    fn every_registry_vendor_arms_independently_and_unknown_ones_are_ignored() {
        let cfg = parse_effector_config(|k| match k {
            k if k == floating_ip_token_file_env("hetzner") => Some("/run/fob/hz".into()),
            k if k == floating_ip_token_file_env("vultr") => Some("/run/fob/vultr".into()),
            "YUBABA_INGRESS_DIGITALOCEAN_TOKEN_FILE" => Some("/run/fob/do".into()),
            _ => None,
        })
        .unwrap()
        .expect("two vendor credentials must arm the effector");
        assert_eq!(cfg.apex, None);
        assert_eq!(
            cfg.floating_ip_token_files.keys().collect::<Vec<_>>(),
            vec!["hetzner", "vultr"],
            "digitalocean has no floating-IP adapter, so its token file arms nothing"
        );
    }
}

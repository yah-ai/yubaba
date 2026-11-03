//! **Deployed-credential drift** — the deployer's half of environment
//! fingerprints (R866, W337 §5).
//!
//! A credential a cloud workload uses is resolved from the operator's vault at
//! `yah cloud apply` and shipped to the node by value. That splits rot in two:
//! the vault copy going bad (a local `yah keys doctor` probe catches it), and
//! the *deployed* copy drifting from the vault copy — rotated in the vault and
//! never re-applied, or re-applied and never restarted. In the second case the
//! vault probe is green and the service is down. This module is that second
//! case and only that case.
//!
//! ## The shape
//!
//! 1. At apply, [`stamp`] adds two variables to the workload's environment:
//!    [`KEY_ENV`] — a key derived for this one mirror by [`mirror_key`] — and
//!    [`VARS_ENV`], the declared names to fingerprint.
//! 2. The workload reports `HMAC-SHA256(key, value)` for each listed name in
//!    its status document's `env_fingerprint` map
//!    ([`crate::proc_control::ProcStatus::env_fingerprint`]), over the existing
//!    process-control rail — no bespoke health endpoint.
//! 3. `yah cloud mirror status <service> --env <env>` re-derives the same key,
//!    fingerprints what the vault resolves to *now*, and [`compare`]s.
//!
//! No value and no value length crosses the wire in either direction: a
//! fingerprint is fixed-width and keyed by a secret the status document's
//! reader does not hold.
//!
//! ## Why the key is derived, not random per apply
//!
//! The comparison happens later, on a machine that must recompute the
//! fingerprint of the vault's current value — so it needs the key the workload
//! was given. Three places could hold it, and two are wrong:
//!
//! - **In the status document** — then anyone who can read `/_yah/status`
//!   holds key and digest together and can brute-force a low-entropy value
//!   offline. A salted fast hash of a password, published. Refused.
//! - **Read back from the node** — `GET /workloads/{ident}/spec` redacts env
//!   values precisely so secrets do not travel back (`spec_redact.rs`), and
//!   punching a hole for this one variable is the shape of a future leak.
//! - **Re-derived from a root in the operator's vault** — what this does.
//!   [`ROOT_SLOT`] holds 32 random bytes, minted on the first apply that needs
//!   it; each mirror's key is an HMAC of that root over the mirror's name, so
//!   a workload that leaks its key exposes no other mirror's fingerprints.
//!
//! Losing or regenerating the root makes every deployed fingerprint read as
//! drift until the next apply. That misdiagnosis is loud and its remedy
//! (re-apply) is the correct one anyway, which is why it is accepted rather
//! than guarded with a key id on the wire.
//!
//! @arch:see(.yah/docs/working/W337-credential-health-and-rotation.md)
//! @arch:see(.yah/docs/working/W315-process-control-channel.md)

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use hmac::Mac;

/// Variable carrying the key a workload fingerprints its environment under.
/// Wire-identical to `procctl::ENV_FINGERPRINT_KEY_ENV`.
pub const KEY_ENV: &str = "YAH_ENV_FINGERPRINT_KEY";

/// Variable listing, comma-separated, the names a workload fingerprints.
/// Wire-identical to `procctl::ENV_FINGERPRINT_VARS_ENV`.
pub const VARS_ENV: &str = "YAH_ENV_FINGERPRINT_VARS";

/// Vault slot holding the root every mirror's key is derived from.
pub const ROOT_SLOT: &str = "env-fingerprint-key";

/// Domain-separation prefix for [`mirror_key`]. Versioned so a future change
/// to the derivation cannot collide with keys already deployed.
const DERIVATION_CONTEXT: &str = "yah/env-fingerprint/v1";

/// Fingerprint one value: lowercase hex of `HMAC-SHA256(key, value)`, both as
/// UTF-8 bytes. The producer-side rule is the same one-liner in every
/// language; see `procctl::env_fingerprint`, whose test vector this module
/// pins too.
pub fn fingerprint(key: &str, value: &str) -> String {
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key.as_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(value.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// The key one mirror's workloads are handed: `HMAC(root, "yah/env-fingerprint/v1/<service>/<env>")`.
pub fn mirror_key(root: &str, service: &str, env: &str) -> String {
    fingerprint(root, &format!("{DERIVATION_CONTEXT}/{service}/{env}"))
}

/// A fresh root for [`ROOT_SLOT`]: 32 bytes from the OS RNG, hex-encoded.
pub fn mint_root() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).context("reading the OS random source")?;
    Ok(hex::encode(bytes))
}

/// Ask the workload to fingerprint `declared` names under `key`, by adding
/// [`KEY_ENV`] and [`VARS_ENV`] to its environment.
///
/// `declared` is the mirror's own declaration — not every variable the deploy
/// sets — because the comparison re-resolves exactly those sources later.
/// A mirror that declares either reserved name itself is refused: silently
/// overwriting a declaration is the class of surprise the bundle tier refuses
/// everywhere else, and keeping it would make the comparison meaningless.
pub fn stamp<'a>(
    serve_env: &mut BTreeMap<String, String>,
    declared: impl IntoIterator<Item = &'a String>,
    key: &str,
) -> Result<()> {
    for reserved in [KEY_ENV, VARS_ENV] {
        if serve_env.contains_key(reserved) {
            bail!(
                "{reserved} is reserved — `yah cloud apply` sets it to report credential drift \
                 (R866). Remove it from [providers.bundle.env]."
            );
        }
    }
    let names: Vec<&str> = declared.into_iter().map(String::as_str).collect();
    if names.is_empty() {
        return Ok(());
    }
    serve_env.insert(KEY_ENV.to_string(), key.to_string());
    serve_env.insert(VARS_ENV.to_string(), names.join(","));
    Ok(())
}

/// How one declared variable compares between the vault and the running
/// workload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The workload runs with what the vault resolves to now.
    InSync,
    /// The workload runs with a different value — the vault was rotated after
    /// the last apply, or an apply never reached the running process.
    Drifted,
    /// Declared, but the running workload reports no such variable — declared
    /// since the last apply, or unset in the process.
    NotRunning,
    /// The running workload reports it, but the mirror no longer declares it.
    NoLongerDeclared,
    /// The workload reports no fingerprints at all: a runtime that predates
    /// R866, or a deploy made before `apply` started stamping the key.
    NotReported,
    /// The source does not resolve on this machine (`env:` unset here, vault
    /// slot absent), so there is nothing to compare against.
    Unresolved,
}

impl Verdict {
    /// Confirmed drift. The deployed copy is known to differ from the
    /// declaration.
    pub fn is_drift(&self) -> bool {
        matches!(self, Self::Drifted | Self::NotRunning | Self::NoLongerDeclared)
    }

    /// Anything short of a verified match. A `--drift` view keeps these, so
    /// "no drift" is only ever printed when every variable was actually
    /// compared — an unverifiable row hidden from a drift filter is a clean
    /// negative nobody earned.
    pub fn needs_attention(&self) -> bool {
        *self != Self::InSync
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::InSync => "in sync",
            Self::Drifted => "DRIFT: running value differs from the vault",
            Self::NotRunning => "DRIFT: declared, not in the running process",
            Self::NoLongerDeclared => "DRIFT: running, no longer declared",
            Self::NotReported => "unverified: workload reports no fingerprints",
            Self::Unresolved => "unverified: source does not resolve here",
        }
    }
}

/// Compare what the mirror declares against what the workload reports.
///
/// `expected` maps each declared name to its value resolved on this machine
/// now (`None` when it does not resolve). `reported` is the workload's
/// `env_fingerprint` map. Every declared name gets a verdict, plus every
/// reported name the mirror no longer declares.
pub fn compare(
    key: &str,
    expected: &BTreeMap<String, Option<String>>,
    reported: &BTreeMap<String, String>,
) -> BTreeMap<String, Verdict> {
    let mut out: BTreeMap<String, Verdict> = expected
        .iter()
        .map(|(name, value)| {
            let verdict = if reported.is_empty() {
                Verdict::NotReported
            } else {
                match (value, reported.get(name)) {
                    (None, _) => Verdict::Unresolved,
                    (Some(_), None) => Verdict::NotRunning,
                    (Some(v), Some(fp)) if fingerprint(key, v) == *fp => Verdict::InSync,
                    (Some(_), Some(_)) => Verdict::Drifted,
                }
            };
            (name.clone(), verdict)
        })
        .collect();
    for name in reported.keys() {
        out.entry(name.clone()).or_insert(Verdict::NoLongerDeclared);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same vector procctl and mesofact pin, produced by Python's stdlib. If
    /// the deployer and a producer disagree on the rule, every row on the
    /// live fleet reads as drift — this is where that fails instead.
    #[test]
    fn fingerprint_matches_the_cross_language_vector() {
        assert_eq!(
            fingerprint("yah-test-key", "s3cr3t-value"),
            "d09f5c67f9abb684a6ec49836260cac2e1d44d86006107e2efc47d381ad93635"
        );
    }

    /// Pinned so a refactor cannot silently re-key every deployed workload.
    #[test]
    fn the_mirror_key_derivation_is_stable() {
        assert_eq!(
            mirror_key(&"00".repeat(32), "yah-analytics", "prod"),
            "a901d03bb7f4acd80336f496fe0e6461bf29de5444ee78245f2eab6c2021320c"
        );
        let root = "00".repeat(32);
        assert_ne!(
            mirror_key(&root, "yah-analytics", "prod"),
            mirror_key(&root, "yah-analytics", "staging"),
            "one mirror's key must not unlock another's fingerprints"
        );
    }

    #[test]
    fn a_minted_root_is_32_random_bytes() {
        let (a, b) = (mint_root().unwrap(), mint_root().unwrap());
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }

    #[test]
    fn stamp_lists_only_declared_names_and_never_their_values() {
        let declared: BTreeMap<String, String> = [
            ("R2_SECRET".to_string(), "vault:cloudflare-r2-secret-key".to_string()),
            ("R2_ENDPOINT".to_string(), "vault:cloudflare-r2-endpoint".to_string()),
        ]
        .into();
        let mut env: BTreeMap<String, String> = [
            ("R2_SECRET".to_string(), "hunter2-the-secret".to_string()),
            ("R2_ENDPOINT".to_string(), "https://r2.example".to_string()),
            ("MESOFACT_ROUTE_HEADERS".to_string(), "[]".to_string()),
        ]
        .into();
        stamp(&mut env, declared.keys(), "mirror-key").unwrap();
        assert_eq!(env[KEY_ENV], "mirror-key");
        assert_eq!(env[VARS_ENV], "R2_ENDPOINT,R2_SECRET");
        assert!(!env[VARS_ENV].contains("hunter2"));
    }

    #[test]
    fn stamp_adds_nothing_when_nothing_is_declared() {
        let mut env = BTreeMap::new();
        stamp(&mut env, std::iter::empty(), "k").unwrap();
        assert!(env.is_empty());
    }

    #[test]
    fn a_mirror_may_not_declare_the_reserved_names() {
        let mut env: BTreeMap<String, String> = [(KEY_ENV.to_string(), "mine".to_string())].into();
        let err = stamp(&mut env, std::iter::empty(), "k").unwrap_err();
        assert!(err.to_string().contains("reserved"), "{err}");
    }

    fn expected(pairs: &[(&str, Option<&str>)]) -> BTreeMap<String, Option<String>> {
        pairs
            .iter()
            .map(|(n, v)| (n.to_string(), v.map(str::to_string)))
            .collect()
    }

    /// The case R866 exists for: the vault was rotated, nobody re-applied, the
    /// workload still runs the old value.
    #[test]
    fn a_rotated_vault_value_reads_as_drift() {
        let reported = [("SECRET".to_string(), fingerprint("k", "old-value"))].into();
        let got = compare("k", &expected(&[("SECRET", Some("new-value"))]), &reported);
        assert_eq!(got["SECRET"], Verdict::Drifted);
        assert!(got["SECRET"].is_drift());
    }

    #[test]
    fn a_matching_value_is_in_sync() {
        let reported = [("SECRET".to_string(), fingerprint("k", "v"))].into();
        let got = compare("k", &expected(&[("SECRET", Some("v"))]), &reported);
        assert_eq!(got["SECRET"], Verdict::InSync);
        assert!(!got["SECRET"].needs_attention());
    }

    #[test]
    fn declared_unreported_and_reported_undeclared_are_both_drift() {
        let reported = [
            ("KEPT".to_string(), fingerprint("k", "v")),
            ("REMOVED".to_string(), fingerprint("k", "x")),
        ]
        .into();
        let got = compare(
            "k",
            &expected(&[("KEPT", Some("v")), ("ADDED", Some("y"))]),
            &reported,
        );
        assert_eq!(got["KEPT"], Verdict::InSync);
        assert_eq!(got["ADDED"], Verdict::NotRunning);
        assert_eq!(got["REMOVED"], Verdict::NoLongerDeclared);
    }

    /// A runtime that predates R866 reports nothing. That is "unverified",
    /// never "in sync" — and never drift either, since nothing was compared.
    #[test]
    fn a_workload_that_reports_nothing_is_unverified_not_clean() {
        let got = compare("k", &expected(&[("SECRET", Some("v"))]), &BTreeMap::new());
        assert_eq!(got["SECRET"], Verdict::NotReported);
        assert!(!got["SECRET"].is_drift());
        assert!(got["SECRET"].needs_attention());
    }

    #[test]
    fn an_unresolvable_source_is_unverified() {
        let reported = [("SECRET".to_string(), fingerprint("k", "v"))].into();
        let got = compare("k", &expected(&[("SECRET", None)]), &reported);
        assert_eq!(got["SECRET"], Verdict::Unresolved);
        assert!(!got["SECRET"].is_drift());
    }
}

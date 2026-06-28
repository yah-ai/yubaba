//! Env-var contract for the auth surface — W159 §Development mode + §Not
//! supported.
//!
//! Two operating modes; no third "auth off" escape hatch:
//!
//! - `YAH_DEV_AUTH=mock` → [`AuthMode::Mock`] — spawn the in-process issuer.
//! - `YAH_CHEERS_ISSUER=https://…` → [`AuthMode::Real { issuer }`] — fetch the
//!   real cheers JWKS.
//!
//! `YAH_AUTH=off` (and any other unrecognised `YAH_AUTH` value) returns
//! [`AuthModeError::BypassRefused`] — the verifier code path stays in place
//! in dev exactly so unauthed paths never leak into integration tests
//! pass-by-accident.
//!
//! Returns [`AuthMode::Unconfigured`] when neither dev nor prod issuer is set
//! — the caller decides whether that's fatal (production camp daemon: yes)
//! or fine (CI / one-shot tools that don't make boundary-crossing calls).

use std::ffi::OsStr;
use std::str::FromStr;

use thiserror::Error;

/// Resolved auth mode for the current process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMode {
    /// Real cheers AS — fetch its JWKS, verify production tokens.
    Real { issuer: String },
    /// In-process mock (W159 Mode 1) — spawn via [`crate::MockIssuer::spawn`].
    Mock,
    /// No issuer configured. Caller decides whether this is fatal.
    Unconfigured,
}

/// Failure modes for [`AuthMode::from_env`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthModeError {
    /// `YAH_AUTH` was set to a value other than `on`. Per W159 the verifier
    /// is non-optional; the only way to skip it would be to skip cheers
    /// entirely (use `YAH_DEV_AUTH=mock` instead).
    #[error(
        "YAH_AUTH={0:?} is rejected: the cheers verifier is non-optional. \
         Set YAH_DEV_AUTH=mock for the in-process dev issuer, or \
         YAH_CHEERS_ISSUER=https://… for the real one."
    )]
    BypassRefused(String),

    /// Both `YAH_DEV_AUTH=mock` and `YAH_CHEERS_ISSUER=…` were set. Ambiguous
    /// — refuse rather than pick one silently.
    #[error("YAH_DEV_AUTH=mock and YAH_CHEERS_ISSUER cannot both be set")]
    Ambiguous,

    /// `YAH_DEV_AUTH` was set to something other than `mock`.
    #[error("YAH_DEV_AUTH={0:?} is not a recognised value; expected 'mock'")]
    UnknownDevAuth(String),
}

impl AuthMode {
    /// Read the env-var triple. Convenience wrapper around
    /// [`Self::from_env_with`] using `std::env::var_os`.
    pub fn from_env() -> Result<Self, AuthModeError> {
        Self::from_env_with(|k| std::env::var_os(k))
    }

    /// Same as [`Self::from_env`] but pulls values through a caller-supplied
    /// lookup — lets tests drive the mode-selection state machine without
    /// poisoning the process env (which `std::env::set_var` does globally
    /// and not even mutex-safely after Rust 1.80).
    pub fn from_env_with<F>(mut lookup: F) -> Result<Self, AuthModeError>
    where
        F: FnMut(&'static str) -> Option<std::ffi::OsString>,
    {
        let yah_auth = lookup("YAH_AUTH");
        let dev_auth = lookup("YAH_DEV_AUTH");
        let issuer = lookup("YAH_CHEERS_ISSUER");

        // YAH_AUTH is the bypass-refusal canary. Only the unset case or the
        // explicit "on" value lets verification proceed; anything else is a
        // wire-contract violation.
        if let Some(v) = yah_auth {
            let s = os_to_string(&v);
            if s != "on" {
                return Err(AuthModeError::BypassRefused(s));
            }
        }

        let dev = dev_auth
            .as_deref()
            .map(os_to_string_ref)
            .filter(|s| !s.is_empty());
        let real_issuer = issuer
            .as_deref()
            .map(os_to_string_ref)
            .filter(|s| !s.is_empty());

        match (dev, real_issuer) {
            (Some(dev), Some(_)) if dev == "mock" => Err(AuthModeError::Ambiguous),
            (Some(dev), _) if dev != "mock" => Err(AuthModeError::UnknownDevAuth(dev)),
            (Some(_), None) => Ok(Self::Mock),
            (None, Some(issuer)) => Ok(Self::Real { issuer }),
            (None, None) => Ok(Self::Unconfigured),
            // The (Some(dev), Some(_)) arm above already handles the "both
            // set with dev=mock" case; this is unreachable but the matcher
            // can't see that without the explicit arm.
            _ => unreachable!("env triple resolved above"),
        }
    }
}

fn os_to_string(v: &OsStr) -> String {
    v.to_string_lossy().into_owned()
}

fn os_to_string_ref(v: &OsStr) -> String {
    v.to_string_lossy().into_owned()
}

impl FromStr for AuthMode {
    type Err = AuthModeError;

    /// Lets a caller bypass the env-var lookup entirely (e.g. when an
    /// explicit `--auth-mode mock` CLI flag is preferred). The string is
    /// interpreted as the value of `YAH_DEV_AUTH` would be — `mock` /
    /// `<issuer-url>` / `""` for unconfigured.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "" => Ok(Self::Unconfigured),
            "mock" => Ok(Self::Mock),
            other if other.starts_with("http://") || other.starts_with("https://") => {
                Ok(Self::Real {
                    issuer: other.to_string(),
                })
            }
            other => Err(AuthModeError::UnknownDevAuth(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::ffi::OsString;

    fn env_of(pairs: &[(&'static str, &str)]) -> impl FnMut(&'static str) -> Option<OsString> {
        let map: HashMap<&'static str, OsString> = pairs
            .iter()
            .map(|(k, v)| (*k, OsString::from(*v)))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn unconfigured_when_no_vars() {
        let m = AuthMode::from_env_with(env_of(&[])).unwrap();
        assert_eq!(m, AuthMode::Unconfigured);
    }

    #[test]
    fn dev_mock_picks_mock_mode() {
        let m = AuthMode::from_env_with(env_of(&[("YAH_DEV_AUTH", "mock")])).unwrap();
        assert_eq!(m, AuthMode::Mock);
    }

    #[test]
    fn cheers_issuer_picks_real_mode() {
        let m = AuthMode::from_env_with(env_of(&[(
            "YAH_CHEERS_ISSUER",
            "https://cheers.staging",
        )]))
        .unwrap();
        assert_eq!(
            m,
            AuthMode::Real {
                issuer: "https://cheers.staging".into()
            }
        );
    }

    #[test]
    fn yah_auth_on_is_allowed() {
        let m =
            AuthMode::from_env_with(env_of(&[("YAH_AUTH", "on"), ("YAH_DEV_AUTH", "mock")]))
                .unwrap();
        assert_eq!(m, AuthMode::Mock);
    }

    #[test]
    fn yah_auth_off_is_refused() {
        let err = AuthMode::from_env_with(env_of(&[("YAH_AUTH", "off")])).unwrap_err();
        assert!(matches!(err, AuthModeError::BypassRefused(v) if v == "off"));
    }

    #[test]
    fn yah_auth_any_unknown_value_is_refused() {
        let err = AuthMode::from_env_with(env_of(&[("YAH_AUTH", "skip")])).unwrap_err();
        assert!(matches!(err, AuthModeError::BypassRefused(v) if v == "skip"));
    }

    #[test]
    fn dev_mock_plus_cheers_issuer_is_ambiguous() {
        let err = AuthMode::from_env_with(env_of(&[
            ("YAH_DEV_AUTH", "mock"),
            ("YAH_CHEERS_ISSUER", "https://cheers.staging"),
        ]))
        .unwrap_err();
        assert!(matches!(err, AuthModeError::Ambiguous));
    }

    #[test]
    fn unknown_dev_auth_value_is_rejected() {
        let err = AuthMode::from_env_with(env_of(&[("YAH_DEV_AUTH", "bogus")])).unwrap_err();
        assert!(matches!(err, AuthModeError::UnknownDevAuth(v) if v == "bogus"));
    }

    #[test]
    fn empty_env_values_treated_as_unset() {
        // Some shells set empty strings instead of unsetting. Treat them
        // the same as unset so a stale "export YAH_DEV_AUTH=" doesn't
        // surprise the caller.
        let m = AuthMode::from_env_with(env_of(&[("YAH_DEV_AUTH", "")])).unwrap();
        assert_eq!(m, AuthMode::Unconfigured);
    }

    #[test]
    fn from_str_round_trips() {
        assert_eq!(AuthMode::from_str("").unwrap(), AuthMode::Unconfigured);
        assert_eq!(AuthMode::from_str("mock").unwrap(), AuthMode::Mock);
        assert_eq!(
            AuthMode::from_str("https://cheers.example").unwrap(),
            AuthMode::Real {
                issuer: "https://cheers.example".into()
            }
        );
        assert!(AuthMode::from_str("nope").is_err());
    }
}

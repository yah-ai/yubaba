//! Request auth (W363 §5): camp-minted cheers PASETO v4.public, verified here
//! against the git key's public half. This process holds verify material only.

use anyhow::{bail, Context, Result};
use cheers_core::yah_scopes;
use cheers_verify::{kid_for, PasetoV4PublicVerifier};
use std::path::Path;

/// Which side of the protocol a request is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `upload-pack` (fetch/clone): needs `git:read`.
    Read,
    /// `receive-pack` (push): needs `git:read` and `git:write`.
    Write,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    /// No `Authorization: Bearer` header. 401.
    Missing,
    /// Signature, kid, expiry or shape. 401.
    Invalid(String),
    /// Valid token for a different issuer, audience or scope. 403.
    Forbidden(String),
}

/// Which ref namespaces a push token may write (W366 §5, R978-F4). Carried as
/// the `git:write-qed` / `git:write-relays` / `git:write-heads` /
/// `git:write-camp-host` scopes beside `git:write`; the scope grammar has no
/// room for a ref glob, so the grant is a fixed vocabulary of classes rather
/// than a free-form prefix list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RefGrant {
    /// `refs/qed/**`: QED run refs.
    pub qed: bool,
    /// `refs/relays/**`: away-relay tips.
    pub relays: bool,
    /// `refs/heads/*` and `refs/tags/*`: the lander.
    pub heads: bool,
    /// `refs/camp-host/**`: a planned host move's park (W368 §7, R975-F22).
    /// [`GitAuth::authorize`] admits it only beside a `git_ref` claim of
    /// `refs/camp-host/<camp_id>/`, so in effect it is one camp's subtree.
    #[serde(default)]
    pub camp_host: bool,
}

/// The ref family a camp's handover park lives under (W368 §7).
pub const CAMP_HOST_PREFIX: &str = "refs/camp-host/";

impl RefGrant {
    pub const NONE: RefGrant = RefGrant { qed: false, relays: false, heads: false, camp_host: false };

    fn from_scopes(scope: &[cheers_core::Scope]) -> Self {
        let g = RefGrant {
            qed: scope.contains(&yah_scopes::GIT_WRITE_QED),
            relays: scope.contains(&yah_scopes::GIT_WRITE_RELAYS),
            heads: scope.contains(&yah_scopes::GIT_WRITE_HEADS),
            camp_host: scope.contains(&yah_scopes::GIT_WRITE_CAMP_HOST),
        };
        if g != RefGrant::NONE {
            return g;
        }
        // R978-F4 roll-order allowance. A `git:write` token with
        // no ref scope is a pre-R978-F4 camp token, whose only legitimate
        // writer was QED, so it is admitted as refs/qed/** and never
        // refs/heads/*. Delete this fallback (return `g` as is) once every
        // camp binary mints ref scopes.
        RefGrant { qed: true, ..RefGrant::NONE }
    }

    /// The `$FLEET_GIT_REFS` form handed to http-backend (and so to the hooks).
    pub fn to_env(self) -> String {
        let mut v = Vec::new();
        if self.qed {
            v.push("qed");
        }
        if self.relays {
            v.push("relays");
        }
        if self.heads {
            v.push("heads");
        }
        if self.camp_host {
            v.push("camp-host");
        }
        v.join(",")
    }

    /// Inverse of [`RefGrant::to_env`]; an unknown word grants nothing.
    pub fn from_env(s: &str) -> Self {
        let mut g = RefGrant::NONE;
        for w in s.split(',').map(str::trim) {
            match w {
                "qed" => g.qed = true,
                "relays" => g.relays = true,
                "heads" => g.heads = true,
                "camp-host" => g.camp_host = true,
                _ => {}
            }
        }
        g
    }
}

/// Whether `git_ref` binds a `git:write-camp-host` token to one camp:
/// `refs/camp-host/<camp_id>/` or a ref under it, with a non-empty id.
fn is_camp_bound(git_ref: &str) -> bool {
    git_ref
        .strip_prefix(CAMP_HOST_PREFIX)
        .and_then(|rest| rest.split_once('/'))
        .is_some_and(|(camp_id, _)| !camp_id.is_empty() && camp_id != "." && camp_id != "..")
}

/// What a verified request is allowed to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The token's `sub`, for `REMOTE_USER`.
    pub sub: String,
    pub refs: RefGrant,
    /// The token's `git_ref` claim (R969-T12): the one ref, or `/`-terminated
    /// prefix, it may write. Narrows `refs`; `None` leaves it as is.
    pub only: Option<String>,
}

pub struct GitAuth {
    verifier: PasetoV4PublicVerifier,
    kid: String,
    iss: String,
}

impl GitAuth {
    pub fn from_public_key(key: &[u8; 32], iss: &str) -> Result<Self> {
        let verifier = PasetoV4PublicVerifier::from_public_key(key)
            .map_err(|e| anyhow::anyhow!("loading the git verify key: {e}"))?;
        Ok(Self { verifier, kid: kid_for(key), iss: iss.to_string() })
    }

    /// Read the verify key from a file: 32 raw bytes (what `yah cloud secret
    /// put` writes for an `encoding = "hex"` secret) or 64 hex digits.
    pub fn from_key_file(path: &Path, iss: &str) -> Result<Self> {
        let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let key: [u8; 32] = if raw.len() == 32 {
            raw.try_into().expect("length checked")
        } else {
            let text = String::from_utf8(raw).context("verify key is neither 32 raw bytes nor hex")?;
            decode_hex32(text.trim())?
        };
        Self::from_public_key(&key, iss)
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Check one request's `Authorization` header for `op` on `repo`; returns
    /// the token's `sub` (for `REMOTE_USER`) and its write [`RefGrant`].
    pub fn authorize(
        &self,
        authorization: Option<&str>,
        repo: &str,
        op: Op,
        now: i64,
    ) -> std::result::Result<Grant, AuthError> {
        let token = authorization
            .and_then(|h| h.strip_prefix("Bearer ").or_else(|| h.strip_prefix("bearer ")))
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or(AuthError::Missing)?;
        let claims = self
            .verifier
            .verify_mcp_at(token, now, &self.kid)
            .map_err(|e| AuthError::Invalid(e.to_string()))?;
        if claims.iss != self.iss {
            return Err(AuthError::Forbidden(format!("issuer {:?} is not {:?}", claims.iss, self.iss)));
        }
        let want_aud = format!("fleet-git/{repo}");
        if claims.aud != want_aud {
            return Err(AuthError::Forbidden(format!(
                "token audience {:?} does not match {want_aud:?}",
                claims.aud
            )));
        }
        if !claims.scope.contains(&yah_scopes::GIT_READ) {
            return Err(AuthError::Forbidden("token lacks git:read".into()));
        }
        if op == Op::Write && !claims.scope.contains(&yah_scopes::GIT_WRITE) {
            return Err(AuthError::Forbidden("push needs git:write".into()));
        }
        if claims.git_ref.as_deref().is_some_and(|r| !r.starts_with("refs/")) {
            return Err(AuthError::Forbidden(format!("git_ref {:?} is not under refs/", claims.git_ref)));
        }
        let refs = RefGrant::from_scopes(&claims.scope);
        // R975-F22: the family scope alone would let one camp's host move
        // another camp's park, so it counts only when the token is bound to one
        // camp's subtree. Refused outright rather than dropped: a token minted
        // without the claim is a minting bug, and should say so at the push.
        if refs.camp_host && !claims.git_ref.as_deref().is_some_and(is_camp_bound) {
            return Err(AuthError::Forbidden(format!(
                "git:write-camp-host needs a git_ref claim naming {CAMP_HOST_PREFIX}<camp_id>/, got {:?}",
                claims.git_ref
            )));
        }
        Ok(Grant { sub: claims.sub.to_string(), refs, only: claims.git_ref })
    }
}

fn decode_hex32(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        bail!("verify key hex must be 64 digits, got {}", s.len());
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).context("verify key is not hex")?;
    }
    Ok(out)
}

/// Token minting for this crate's tests. Production tokens come from the
/// camp (`app/yah/cli/src/cloud_cheers.rs`, `git_push_token`).
#[cfg(test)]
pub(crate) mod testkey {
    use pasetors::keys::{AsymmetricKeyPair, AsymmetricPublicKey, Generate};
    use pasetors::version4::V4;

    pub struct TestIssuer {
        pair: AsymmetricKeyPair<V4>,
    }

    impl TestIssuer {
        pub fn new() -> Self {
            Self { pair: AsymmetricKeyPair::<V4>::generate().unwrap() }
        }
        pub fn public(&self) -> [u8; 32] {
            let p: &AsymmetricPublicKey<V4> = &self.pair.public;
            p.as_bytes().try_into().unwrap()
        }
        pub fn mint(&self, iss: &str, aud: &str, scopes: &[&str], exp: i64) -> String {
            self.mint_ref(iss, aud, scopes, exp, None)
        }
        /// [`Self::mint`] with the `git_ref` claim (R969-T12).
        pub fn mint_ref(&self, iss: &str, aud: &str, scopes: &[&str], exp: i64, git_ref: Option<&str>) -> String {
            let kid = cheers_verify::kid_for(&self.public());
            let mut payload = serde_json::json!({
                "iss": iss, "aud": aud, "sub": "user:tester", "iat": 0, "exp": exp,
                "jti": "t", "scope": scopes,
            });
            if let Some(r) = git_ref {
                payload["git_ref"] = r.into();
            }
            let footer = serde_json::json!({ "kid": kid });
            pasetors::version4::PublicToken::sign(
                &self.pair.secret,
                payload.to_string().as_bytes(),
                Some(footer.to_string().as_bytes()),
                None,
            )
            .unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkey::TestIssuer;
    use super::*;

    #[test]
    fn checks_issuer_audience_scope_and_expiry() {
        let iss = TestIssuer::new();
        let auth = GitAuth::from_public_key(&iss.public(), "yah-camp").unwrap();
        let push = iss.mint("yah-camp", "fleet-git/yah", &["git:read", "git:write"], 1000);
        let fetch = iss.mint("yah-camp", "fleet-git/yah", &["git:read"], 1000);
        let bearer = |t: &str| format!("Bearer {t}");

        let g = auth.authorize(Some(&bearer(&push)), "yah", Op::Write, 10).unwrap();
        assert_eq!(g.sub, "user:tester");
        // No ref scope: the roll-order allowance, refs/qed/** only.
        assert_eq!(g.refs, RefGrant { qed: true, ..RefGrant::NONE });
        assert!(auth.authorize(Some(&bearer(&fetch)), "yah", Op::Read, 10).is_ok());
        assert!(matches!(
            auth.authorize(Some(&bearer(&fetch)), "yah", Op::Write, 10),
            Err(AuthError::Forbidden(_))
        ));
        assert!(matches!(
            auth.authorize(Some(&bearer(&push)), "other", Op::Read, 10),
            Err(AuthError::Forbidden(_))
        ));
        let wrong_iss = iss.mint("someone", "fleet-git/yah", &["git:read"], 1000);
        assert!(matches!(
            auth.authorize(Some(&bearer(&wrong_iss)), "yah", Op::Read, 10),
            Err(AuthError::Forbidden(_))
        ));
        assert!(matches!(
            auth.authorize(Some(&bearer(&push)), "yah", Op::Read, 2000),
            Err(AuthError::Invalid(_))
        ));
        assert_eq!(auth.authorize(None, "yah", Op::Read, 10), Err(AuthError::Missing));

        let other = TestIssuer::new();
        let forged = other.mint("yah-camp", "fleet-git/yah", &["git:read", "git:write"], 1000);
        assert!(matches!(
            auth.authorize(Some(&bearer(&forged)), "yah", Op::Write, 10),
            Err(AuthError::Invalid(_))
        ));
    }

    #[test]
    fn ref_scopes_become_the_grant() {
        let iss = TestIssuer::new();
        let auth = GitAuth::from_public_key(&iss.public(), "yah-camp").unwrap();
        let grant = |scopes: &[&str]| {
            let t = iss.mint("yah-camp", "fleet-git/yah", scopes, 1000);
            auth.authorize(Some(&format!("Bearer {t}")), "yah", Op::Write, 10).unwrap().refs
        };
        let base = ["git:read", "git:write"];
        let with = |extra: &[&'static str]| [&base[..], extra].concat();
        assert_eq!(grant(&with(&["git:write-heads"])), RefGrant { heads: true, ..RefGrant::NONE });
        assert_eq!(
            grant(&with(&["git:write-relays", "git:write-qed"])),
            RefGrant { qed: true, relays: true, ..RefGrant::NONE }
        );
        assert_eq!(RefGrant::from_env(&RefGrant { qed: true, heads: true, ..RefGrant::NONE }.to_env()).heads, true);
        let ch = RefGrant { camp_host: true, ..RefGrant::NONE };
        assert_eq!(ch.to_env(), "camp-host");
        assert_eq!(RefGrant::from_env(&ch.to_env()), ch);
        assert_eq!(RefGrant::from_env(""), RefGrant::NONE);
        assert_eq!(RefGrant::from_env("nonsense"), RefGrant::NONE);
    }

    /// R975-F22: `git:write-camp-host` is honoured only beside a `git_ref`
    /// claim naming one camp's `refs/camp-host/<camp_id>/`; the grant then
    /// confines it there (the hook's `check_ref_claim` + `check_policy`).
    #[test]
    fn camp_host_scope_needs_a_camp_bound_claim() {
        let iss = TestIssuer::new();
        let auth = GitAuth::from_public_key(&iss.public(), "yah-camp").unwrap();
        let scopes = ["git:read", "git:write", "git:write-camp-host"];
        let authz = |git_ref: Option<&str>| {
            let t = iss.mint_ref("yah-camp", "fleet-git/yah", &scopes, 1000, git_ref);
            auth.authorize(Some(&format!("Bearer {t}")), "yah", Op::Write, 10)
        };
        let g = authz(Some("refs/camp-host/c1/")).unwrap();
        assert_eq!(g.refs, RefGrant { camp_host: true, ..RefGrant::NONE });
        assert_eq!(g.only.as_deref(), Some("refs/camp-host/c1/"));
        assert!(authz(Some("refs/camp-host/c1/park")).is_ok(), "an exact park ref is camp-bound too");
        for unbound in [None, Some("refs/camp-host/"), Some("refs/camp-host/c1"), Some("refs/camp-host//park"),
            Some("refs/camp-host/../x/"), Some("refs/qed/run-1/"), Some("refs/heads/camp")]
        {
            assert!(matches!(authz(unbound), Err(AuthError::Forbidden(_))), "{unbound:?} was admitted");
        }
        // A token without the scope may still carry a claim elsewhere; nothing changes for it.
        let relay = iss.mint_ref("yah-camp", "fleet-git/yah", &["git:read", "git:write", "git:write-relays"], 1000, Some("refs/relays/R1/"));
        let g = auth.authorize(Some(&format!("Bearer {relay}")), "yah", Op::Write, 10).unwrap();
        assert!(!g.refs.camp_host);
    }

    #[test]
    fn key_file_accepts_raw_and_hex() {
        let iss = TestIssuer::new();
        let dir = tempfile::tempdir().unwrap();
        let raw = dir.path().join("raw");
        std::fs::write(&raw, iss.public()).unwrap();
        let hex = dir.path().join("hex");
        let h: String = iss.public().iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(&hex, format!("{h}\n")).unwrap();
        let a = GitAuth::from_key_file(&raw, "yah-camp").unwrap();
        let b = GitAuth::from_key_file(&hex, "yah-camp").unwrap();
        assert_eq!(a.kid(), b.kid());
    }
}

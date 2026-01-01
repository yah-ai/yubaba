//! `yah-app.toml` schema, parser, closed-set `required_when` evaluator,
//! `.yah/apps.toml` registry, and workspace discovery (R470-T7).
//!
//! **Two-tier model (W193):** assets are declared by services in
//! `workload.toml`; apps declare which aliases they consume here. The two
//! files live independently so external apps that only *consume* content-
//! addressed assets don't need a `service.toml`.
//!
//! # `yah-app.toml` example
//!
//! ```toml
//! schema_version = 1
//! name = "yah-desktop"
//!
//! [[asset_dep]]
//! alias = "whisper-default-coreml"
//! required_when = "target_os == \"macos\""
//! purpose = "Local dictation (WhisperKit ANE path)"
//!
//! [[asset_dep]]
//! alias = "whisper-default-ggml"
//! required_when = "target_os != \"macos\""
//! purpose = "Local dictation (whisper.cpp ggml path)"
//! ```

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// ── Predicate DSL ──────────────────────────────────────────────────────────

/// Comparison operator for `target_os` and `target_arch` predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
}

/// A parsed `required_when` predicate — eagerly validated at load time.
///
/// Closed predicate set — no user-defined extensions:
/// - `target_os == "value"` / `target_os != "value"`
/// - `target_arch == "value"` / `target_arch != "value"`
/// - `feature("name")` — feature flag enabled in [`HostContext`]
/// - `env("VAR")` — environment variable `VAR` is set and non-empty
/// - `!pred`, `pred && pred`, `pred || pred`, `(pred)`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    TargetOs(CmpOp, String),
    TargetArch(CmpOp, String),
    Feature(String),
    Env(String),
    Not(Box<Predicate>),
    And(Box<Predicate>, Box<Predicate>),
    Or(Box<Predicate>, Box<Predicate>),
}

impl Predicate {
    /// Evaluate this predicate against a host context.
    pub fn evaluate(&self, ctx: &HostContext) -> bool {
        match self {
            Predicate::TargetOs(CmpOp::Eq, v) => ctx.target_os == *v,
            Predicate::TargetOs(CmpOp::Ne, v) => ctx.target_os != *v,
            Predicate::TargetArch(CmpOp::Eq, v) => ctx.target_arch == *v,
            Predicate::TargetArch(CmpOp::Ne, v) => ctx.target_arch != *v,
            Predicate::Feature(f) => ctx.features.contains(f.as_str()),
            Predicate::Env(var) => ctx.env.get(var.as_str()).is_some_and(|v| !v.is_empty()),
            Predicate::Not(inner) => !inner.evaluate(ctx),
            Predicate::And(a, b) => a.evaluate(ctx) && b.evaluate(ctx),
            Predicate::Or(a, b) => a.evaluate(ctx) || b.evaluate(ctx),
        }
    }
}

/// Runtime host context for evaluating [`Predicate`]s.
#[derive(Debug, Clone)]
pub struct HostContext {
    /// OS name (e.g. `"macos"`, `"linux"`, `"windows"`).
    pub target_os: String,
    /// CPU architecture (e.g. `"aarch64"`, `"x86_64"`).
    pub target_arch: String,
    /// Enabled feature flags (app-level capability gates).
    pub features: HashSet<String>,
    /// Environment variables to check for `env("VAR")` predicates.
    pub env: HashMap<String, String>,
}

impl HostContext {
    /// Build a context from the current process environment and compile-time
    /// OS / arch constants. `features` and extra env vars may be injected for
    /// testing or for app-level capability gates.
    pub fn current() -> Self {
        Self {
            target_os: std::env::consts::OS.to_string(),
            target_arch: std::env::consts::ARCH.to_string(),
            features: HashSet::new(),
            env: std::env::vars().collect(),
        }
    }
}

// ── RequiredWhen — eagerly-parsed serde newtype ────────────────────────────

/// A `required_when` value: the raw TOML string paired with its parsed
/// [`Predicate`]. Serialises back to the original string; parse errors surface
/// at deserialization time so typos never silently-skip a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredWhen {
    pub raw: String,
    pub predicate: Predicate,
}

impl RequiredWhen {
    pub fn parse(s: &str) -> Result<Self> {
        let predicate = parse_predicate(s)
            .with_context(|| format!("in required_when = \"{s}\""))?;
        Ok(Self { raw: s.to_string(), predicate })
    }

    pub fn evaluate(&self, ctx: &HostContext) -> bool {
        self.predicate.evaluate(ctx)
    }
}

impl Serialize for RequiredWhen {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for RequiredWhen {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = RequiredWhen;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a required_when predicate string")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<RequiredWhen, E> {
                // Use {e:#} to include the full anyhow error chain in the serde message.
                RequiredWhen::parse(v).map_err(|e| de::Error::custom(format!("{e:#}")))
            }
        }
        d.deserialize_str(V)
    }
}

// ── Predicate parser ───────────────────────────────────────────────────────

fn parse_predicate(input: &str) -> Result<Predicate> {
    let mut p = Parser::new(input);
    let pred = p.parse_or()?;
    p.expect_eof()?;
    Ok(pred)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Ident(String),
    Str(String),
    EqEq,
    BangEq,
    And,
    Or,
    Bang,
    LParen,
    RParen,
    Eof,
}

struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Self { src: src.as_bytes(), pos: 0 }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.src.len() && self.src[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn next(&mut self) -> Result<Token> {
        self.skip_ws();
        if self.pos >= self.src.len() {
            return Ok(Token::Eof);
        }
        match self.src[self.pos] {
            b'=' if self.src.get(self.pos + 1) == Some(&b'=') => {
                self.pos += 2;
                Ok(Token::EqEq)
            }
            b'!' if self.src.get(self.pos + 1) == Some(&b'=') => {
                self.pos += 2;
                Ok(Token::BangEq)
            }
            b'&' if self.src.get(self.pos + 1) == Some(&b'&') => {
                self.pos += 2;
                Ok(Token::And)
            }
            b'|' if self.src.get(self.pos + 1) == Some(&b'|') => {
                self.pos += 2;
                Ok(Token::Or)
            }
            b'!' => {
                self.pos += 1;
                Ok(Token::Bang)
            }
            b'(' => {
                self.pos += 1;
                Ok(Token::LParen)
            }
            b')' => {
                self.pos += 1;
                Ok(Token::RParen)
            }
            b'"' => {
                self.pos += 1;
                let start = self.pos;
                while self.pos < self.src.len() && self.src[self.pos] != b'"' {
                    if self.src[self.pos] == b'\\' {
                        self.pos += 1; // skip escaped char
                    }
                    self.pos += 1;
                }
                if self.pos >= self.src.len() {
                    bail!("unterminated string literal");
                }
                let s = std::str::from_utf8(&self.src[start..self.pos])
                    .context("invalid UTF-8 in string literal")?
                    .to_string();
                self.pos += 1; // consume closing "
                Ok(Token::Str(s))
            }
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let start = self.pos;
                while self.pos < self.src.len()
                    && (self.src[self.pos].is_ascii_alphanumeric()
                        || self.src[self.pos] == b'_')
                {
                    self.pos += 1;
                }
                let ident = std::str::from_utf8(&self.src[start..self.pos])
                    .context("invalid UTF-8 in identifier")?
                    .to_string();
                Ok(Token::Ident(ident))
            }
            c => bail!("unexpected character '{}'", c as char),
        }
    }

    fn peek(&mut self) -> Result<Token> {
        let saved = self.pos;
        let tok = self.next()?;
        self.pos = saved;
        Ok(tok)
    }
}

struct Parser<'a> {
    lex: Lexer<'a>,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self { lex: Lexer::new(input) }
    }

    fn expect_eof(&mut self) -> Result<()> {
        match self.lex.next()? {
            Token::Eof => Ok(()),
            tok => bail!("unexpected token {tok:?} at end of predicate"),
        }
    }

    // or_expr = and_expr ('||' and_expr)*
    fn parse_or(&mut self) -> Result<Predicate> {
        let mut lhs = self.parse_and()?;
        while self.lex.peek()? == Token::Or {
            self.lex.next()?;
            let rhs = self.parse_and()?;
            lhs = Predicate::Or(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    // and_expr = not_expr ('&&' not_expr)*
    fn parse_and(&mut self) -> Result<Predicate> {
        let mut lhs = self.parse_not()?;
        while self.lex.peek()? == Token::And {
            self.lex.next()?;
            let rhs = self.parse_not()?;
            lhs = Predicate::And(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    // not_expr = '!' not_expr | atom
    fn parse_not(&mut self) -> Result<Predicate> {
        if self.lex.peek()? == Token::Bang {
            self.lex.next()?;
            Ok(Predicate::Not(Box::new(self.parse_not()?)))
        } else {
            self.parse_atom()
        }
    }

    // atom = '(' predicate ')' | target_os_pred | target_arch_pred | feature_pred | env_pred
    fn parse_atom(&mut self) -> Result<Predicate> {
        match self.lex.next()? {
            Token::LParen => {
                let inner = self.parse_or()?;
                match self.lex.next()? {
                    Token::RParen => Ok(inner),
                    tok => bail!("expected ')' but got {tok:?}"),
                }
            }
            Token::Ident(name) => match name.as_str() {
                "target_os" => {
                    let op = self.parse_cmp_op()?;
                    let val = self.expect_str()?;
                    Ok(Predicate::TargetOs(op, val))
                }
                "target_arch" => {
                    let op = self.parse_cmp_op()?;
                    let val = self.expect_str()?;
                    Ok(Predicate::TargetArch(op, val))
                }
                "feature" => {
                    self.expect_lparen()?;
                    let name = self.expect_str()?;
                    self.expect_rparen()?;
                    Ok(Predicate::Feature(name))
                }
                "env" => {
                    self.expect_lparen()?;
                    let var = self.expect_str()?;
                    self.expect_rparen()?;
                    Ok(Predicate::Env(var))
                }
                other => bail!(
                    "unknown predicate '{other}' — valid atoms are: \
                     target_os, target_arch, feature, env"
                ),
            },
            tok => bail!("expected predicate atom, got {tok:?}"),
        }
    }

    fn parse_cmp_op(&mut self) -> Result<CmpOp> {
        match self.lex.next()? {
            Token::EqEq => Ok(CmpOp::Eq),
            Token::BangEq => Ok(CmpOp::Ne),
            tok => bail!("expected '==' or '!=' but got {tok:?}"),
        }
    }

    fn expect_str(&mut self) -> Result<String> {
        match self.lex.next()? {
            Token::Str(s) => Ok(s),
            tok => bail!("expected a quoted string but got {tok:?}"),
        }
    }

    fn expect_lparen(&mut self) -> Result<()> {
        match self.lex.next()? {
            Token::LParen => Ok(()),
            tok => bail!("expected '(' but got {tok:?}"),
        }
    }

    fn expect_rparen(&mut self) -> Result<()> {
        match self.lex.next()? {
            Token::RParen => Ok(()),
            tok => bail!("expected ')' but got {tok:?}"),
        }
    }
}

// ── AppManifest (yah-app.toml) ─────────────────────────────────────────────

/// One declared dependency row in a `yah-app.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssetDep {
    /// Logical alias name, workspace-globally unique (e.g. `whisper-default-coreml`).
    pub alias: String,
    /// Optional guard evaluated against the current host. When absent the dep
    /// is always required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_when: Option<RequiredWhen>,
    /// Human-readable description shown in the status panel.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

impl AssetDep {
    /// Whether this dep is required on `ctx`. Absent `required_when` → always required.
    pub fn required_here(&self, ctx: &HostContext) -> bool {
        self.required_when.as_ref().map_or(true, |rw| rw.evaluate(ctx))
    }
}

/// Parsed `yah-app.toml` — consumer-side declaration of alias dependencies.
///
/// File lives at `<app-root>/yah-app.toml`, sibling to `Cargo.toml` or
/// `package.json`. Discovered via `.yah/apps.toml` registry or a
/// `find`-style walk when the registry is absent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppManifest {
    pub schema_version: u32,
    pub name: String,
    #[serde(default, rename = "asset_dep")]
    pub asset_deps: Vec<AssetDep>,
}

impl AppManifest {
    /// Load `<app_root>/yah-app.toml`. Returns `Err` if the file is missing
    /// or malformed — including any invalid `required_when` expression.
    pub fn load(app_root: &Path) -> Result<Self> {
        let path = app_root.join("yah-app.toml");
        let src = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&src)
            .with_context(|| format!("parsing {}", path.display()))
    }

    /// Save this manifest to `<app_root>/yah-app.toml`.
    pub fn save(&self, app_root: &Path) -> Result<()> {
        let path = app_root.join("yah-app.toml");
        let src = toml::to_string_pretty(self)
            .context("serializing AppManifest")?;
        std::fs::write(&path, src)
            .with_context(|| format!("writing {}", path.display()))
    }
}

// ── AppsRegistry (.yah/apps.toml) ─────────────────────────────────────────

/// One entry in `.yah/apps.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppRegistryEntry {
    pub name: String,
    /// Path to the app root, relative to the workspace root.
    pub path: PathBuf,
}

/// `.yah/apps.toml` — registry of app roots for fast discovery.
///
/// `yah cloud apps add <path>` appends an entry; `yah cloud apps scan`
/// auto-discovers `yah-app.toml` files up to `maxdepth=4`. When the
/// registry file doesn't exist, [`AppsRegistry::discover`] falls back to
/// the walk automatically.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AppsRegistry {
    #[serde(default, rename = "apps")]
    pub entries: Vec<AppRegistryEntry>,
}

impl AppsRegistry {
    /// Load from `<workspace>/.yah/apps.toml`. Returns an empty registry
    /// when the file doesn't exist — not an error.
    pub fn load(workspace_root: &Path) -> Result<Self> {
        let path = crate::paths::apps_registry(workspace_root);
        match std::fs::read_to_string(&path) {
            Ok(src) => toml::from_str(&src)
                .with_context(|| format!("parsing {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Save to `<workspace>/.yah/apps.toml`, creating the `.yah/` dir if needed.
    pub fn save(&self, workspace_root: &Path) -> Result<()> {
        let path = crate::paths::apps_registry(workspace_root);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let src = toml::to_string_pretty(self).context("serializing AppsRegistry")?;
        std::fs::write(&path, src)
            .with_context(|| format!("writing {}", path.display()))
    }

    /// Add an entry. Does not write to disk — call [`save`](Self::save) after.
    pub fn add(&mut self, name: impl Into<String>, path: impl Into<PathBuf>) {
        let name = name.into();
        let path = path.into();
        if let Some(e) = self.entries.iter_mut().find(|e| e.name == name) {
            e.path = path;
        } else {
            self.entries.push(AppRegistryEntry { name, path });
        }
    }

    /// Remove by name. Returns `true` if an entry was removed.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.name != name);
        self.entries.len() < before
    }
}

// ── Discovery ─────────────────────────────────────────────────────────────

/// Discover all `yah-app.toml` files in the workspace.
///
/// Uses `.yah/apps.toml` when present; falls back to a `find`-style walk
/// with `maxdepth = 4` for zero-config single-app projects.
pub fn discover_app_manifests(workspace_root: &Path) -> Result<Vec<(PathBuf, AppManifest)>> {
    let registry = AppsRegistry::load(workspace_root)?;
    if !registry.entries.is_empty() {
        let mut results = Vec::new();
        for entry in &registry.entries {
            let app_root = workspace_root.join(&entry.path);
            match AppManifest::load(&app_root) {
                Ok(manifest) => results.push((app_root, manifest)),
                Err(e) => {
                    tracing::warn!(
                        name = %entry.name,
                        path = %entry.path.display(),
                        error = %e,
                        "skipping app manifest that failed to load"
                    );
                }
            }
        }
        return Ok(results);
    }

    // Fallback: walk the workspace tree up to maxdepth=4.
    find_yah_app_tomls(workspace_root, 4)
        .map(|paths| {
            paths
                .into_iter()
                .filter_map(|app_root| {
                    AppManifest::load(&app_root)
                        .map(|m| (app_root, m))
                        .map_err(|e| {
                            tracing::debug!(error = %e, "skipping unparseable yah-app.toml");
                            e
                        })
                        .ok()
                })
                .collect()
        })
}

/// Walk `root` up to `max_depth` directory levels and return the *parent
/// directories* of every `yah-app.toml` found (i.e. the app roots).
///
/// Skips hidden directories (`.git`, `.yah`, `target`, `node_modules`).
pub fn find_yah_app_tomls(root: &Path, max_depth: usize) -> Result<Vec<PathBuf>> {
    let mut results = Vec::new();
    walk_for_yah_app(root, 0, max_depth, &mut results)?;
    Ok(results)
}

fn walk_for_yah_app(dir: &Path, depth: usize, max_depth: usize, out: &mut Vec<PathBuf>) -> Result<()> {
    if dir.join("yah-app.toml").is_file() {
        out.push(dir.to_path_buf());
    }
    if depth >= max_depth {
        return Ok(());
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("reading dir {}", dir.display())),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // Skip common noise directories.
        if matches!(name.as_ref(), ".git" | ".yah" | "target" | "node_modules" | ".build" | ".cache") {
            continue;
        }
        walk_for_yah_app(&path, depth + 1, max_depth, out)?;
    }
    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn macos_ctx() -> HostContext {
        HostContext {
            target_os: "macos".into(),
            target_arch: "aarch64".into(),
            features: HashSet::new(),
            env: HashMap::new(),
        }
    }

    fn linux_ctx() -> HostContext {
        HostContext {
            target_os: "linux".into(),
            target_arch: "x86_64".into(),
            features: HashSet::new(),
            env: HashMap::new(),
        }
    }

    // ── Predicate parsing ──────────────────────────────────────────────────

    #[test]
    fn app_manifest_parse_target_os_eq() {
        let p = parse_predicate(r#"target_os == "macos""#).unwrap();
        assert_eq!(p, Predicate::TargetOs(CmpOp::Eq, "macos".into()));
        assert!(p.evaluate(&macos_ctx()));
        assert!(!p.evaluate(&linux_ctx()));
    }

    #[test]
    fn app_manifest_parse_target_os_ne() {
        let p = parse_predicate(r#"target_os != "macos""#).unwrap();
        assert_eq!(p, Predicate::TargetOs(CmpOp::Ne, "macos".into()));
        assert!(!p.evaluate(&macos_ctx()));
        assert!(p.evaluate(&linux_ctx()));
    }

    #[test]
    fn app_manifest_parse_target_arch() {
        let p = parse_predicate(r#"target_arch == "aarch64""#).unwrap();
        assert!(p.evaluate(&macos_ctx()));
        assert!(!p.evaluate(&linux_ctx()));
    }

    #[test]
    fn app_manifest_parse_feature() {
        let p = parse_predicate(r#"feature("mlx")"#).unwrap();
        assert_eq!(p, Predicate::Feature("mlx".into()));
        let mut ctx = macos_ctx();
        assert!(!p.evaluate(&ctx));
        ctx.features.insert("mlx".into());
        assert!(p.evaluate(&ctx));
    }

    #[test]
    fn app_manifest_parse_env() {
        let p = parse_predicate(r#"env("CI")"#).unwrap();
        assert_eq!(p, Predicate::Env("CI".into()));
        let mut ctx = macos_ctx();
        assert!(!p.evaluate(&ctx));
        ctx.env.insert("CI".into(), "true".into());
        assert!(p.evaluate(&ctx));
        // Empty value = not set.
        ctx.env.insert("CI".into(), "".into());
        assert!(!p.evaluate(&ctx));
    }

    #[test]
    fn app_manifest_parse_not() {
        let p = parse_predicate(r#"!target_os == "windows""#).unwrap();
        assert!(p.evaluate(&macos_ctx()));
        assert!(p.evaluate(&linux_ctx()));
        let windows = HostContext {
            target_os: "windows".into(),
            target_arch: "x86_64".into(),
            features: HashSet::new(),
            env: HashMap::new(),
        };
        assert!(!p.evaluate(&windows));
    }

    #[test]
    fn app_manifest_parse_and() {
        let p = parse_predicate(r#"target_os == "macos" && target_arch == "aarch64""#).unwrap();
        assert!(p.evaluate(&macos_ctx()));
        let x86_mac = HostContext { target_arch: "x86_64".into(), ..macos_ctx() };
        assert!(!p.evaluate(&x86_mac));
        assert!(!p.evaluate(&linux_ctx()));
    }

    #[test]
    fn app_manifest_parse_or() {
        let p = parse_predicate(r#"target_os == "macos" || target_os == "linux""#).unwrap();
        assert!(p.evaluate(&macos_ctx()));
        assert!(p.evaluate(&linux_ctx()));
        let windows = HostContext { target_os: "windows".into(), ..linux_ctx() };
        assert!(!p.evaluate(&windows));
    }

    #[test]
    fn app_manifest_parse_grouped() {
        let p = parse_predicate(
            r#"(target_os == "macos" || target_os == "linux") && target_arch == "aarch64""#,
        )
        .unwrap();
        assert!(p.evaluate(&macos_ctx())); // macos + aarch64
        assert!(!p.evaluate(&linux_ctx())); // linux + x86_64
        let arm_linux = HostContext { target_arch: "aarch64".into(), ..linux_ctx() };
        assert!(p.evaluate(&arm_linux));
    }

    #[test]
    fn app_manifest_unknown_predicate_errors() {
        let err = parse_predicate(r#"cpu == "arm""#).unwrap_err();
        assert!(err.to_string().contains("unknown predicate 'cpu'"), "{err}");
    }

    #[test]
    fn app_manifest_unterminated_string_errors() {
        let err = parse_predicate(r#"target_os == "macos"#).unwrap_err();
        assert!(err.to_string().contains("unterminated"), "{err}");
    }

    // ── RequiredWhen serde ─────────────────────────────────────────────────

    #[test]
    fn app_manifest_required_when_round_trips_via_toml() {
        #[derive(Serialize, Deserialize)]
        struct Wrapper {
            required_when: RequiredWhen,
        }
        let src = r#"required_when = 'target_os == "macos"'"#;
        let w: Wrapper = toml::from_str(src).unwrap();
        assert_eq!(w.required_when.raw, r#"target_os == "macos""#);
        assert!(w.required_when.evaluate(&macos_ctx()));
        assert!(!w.required_when.evaluate(&linux_ctx()));

        let back = toml::to_string_pretty(&w).unwrap();
        let w2: Wrapper = toml::from_str(&back).unwrap();
        assert_eq!(w2.required_when, w.required_when);
    }

    #[test]
    fn app_manifest_invalid_required_when_rejected_at_parse() {
        #[derive(Debug, Deserialize)]
        struct Wrapper {
            required_when: RequiredWhen,
        }
        let src = r#"required_when = 'cpu == "arm"'"#;
        let err = toml::from_str::<Wrapper>(src).unwrap_err();
        assert!(err.to_string().contains("unknown predicate 'cpu'"), "{err}");
    }

    // ── AppManifest load/save ──────────────────────────────────────────────

    #[test]
    fn app_manifest_load_save_round_trip() {
        let dir = tempdir().unwrap();
        let manifest = AppManifest {
            schema_version: 1,
            name: "yah-desktop".into(),
            asset_deps: vec![
                AssetDep {
                    alias: "whisper-default-coreml".into(),
                    required_when: Some(
                        RequiredWhen::parse(r#"target_os == "macos""#).unwrap(),
                    ),
                    purpose: Some("Local dictation (WhisperKit ANE path)".into()),
                },
                AssetDep {
                    alias: "whisper-default-ggml".into(),
                    required_when: Some(
                        RequiredWhen::parse(r#"target_os != "macos""#).unwrap(),
                    ),
                    purpose: None,
                },
            ],
        };

        manifest.save(dir.path()).unwrap();
        let loaded = AppManifest::load(dir.path()).unwrap();
        assert_eq!(loaded, manifest);
    }

    #[test]
    fn app_manifest_required_here_respects_predicate() {
        let dep = AssetDep {
            alias: "whisper-default-coreml".into(),
            required_when: Some(RequiredWhen::parse(r#"target_os == "macos""#).unwrap()),
            purpose: None,
        };
        assert!(dep.required_here(&macos_ctx()));
        assert!(!dep.required_here(&linux_ctx()));
    }

    #[test]
    fn app_manifest_no_required_when_always_required() {
        let dep = AssetDep {
            alias: "shared-model".into(),
            required_when: None,
            purpose: None,
        };
        assert!(dep.required_here(&macos_ctx()));
        assert!(dep.required_here(&linux_ctx()));
    }

    // ── AppsRegistry ──────────────────────────────────────────────────────

    #[test]
    fn apps_registry_load_returns_empty_when_missing() {
        let dir = tempdir().unwrap();
        let reg = AppsRegistry::load(dir.path()).unwrap();
        assert!(reg.entries.is_empty());
    }

    #[test]
    fn apps_registry_add_save_load_round_trip() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".yah")).unwrap();

        let mut reg = AppsRegistry::default();
        reg.add("yah-desktop", "app/yah/desktop");
        reg.add("yah-cli", "app/yah/cli");
        reg.save(dir.path()).unwrap();

        let loaded = AppsRegistry::load(dir.path()).unwrap();
        assert_eq!(loaded.entries.len(), 2);
        assert_eq!(loaded.entries[0].name, "yah-desktop");
        assert_eq!(loaded.entries[1].name, "yah-cli");
    }

    #[test]
    fn apps_registry_add_updates_existing_entry() {
        let mut reg = AppsRegistry::default();
        reg.add("yah-desktop", "old/path");
        reg.add("yah-desktop", "new/path");
        assert_eq!(reg.entries.len(), 1);
        assert_eq!(reg.entries[0].path, PathBuf::from("new/path"));
    }

    #[test]
    fn apps_registry_remove_works() {
        let mut reg = AppsRegistry::default();
        reg.add("a", "a/");
        reg.add("b", "b/");
        assert!(reg.remove("a"));
        assert!(!reg.remove("a")); // idempotent
        assert_eq!(reg.entries.len(), 1);
        assert_eq!(reg.entries[0].name, "b");
    }

    // ── Discovery ─────────────────────────────────────────────────────────

    #[test]
    fn find_yah_app_tomls_discovers_at_multiple_depths() {
        let dir = tempdir().unwrap();
        let app1 = dir.path().join("app/desktop");
        let app2 = dir.path().join("app/cli");
        std::fs::create_dir_all(&app1).unwrap();
        std::fs::create_dir_all(&app2).unwrap();
        std::fs::write(app1.join("yah-app.toml"), "").unwrap();
        std::fs::write(app2.join("yah-app.toml"), "").unwrap();

        let found = find_yah_app_tomls(dir.path(), 4).unwrap();
        assert_eq!(found.len(), 2);
        assert!(found.contains(&app1));
        assert!(found.contains(&app2));
    }

    #[test]
    fn find_yah_app_tomls_respects_max_depth() {
        let dir = tempdir().unwrap();
        // depth 3 — should be found
        let shallow = dir.path().join("a/b/c");
        // depth 5 — should be skipped with maxdepth=4
        let deep = dir.path().join("a/b/c/d/e");
        std::fs::create_dir_all(&shallow).unwrap();
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(shallow.join("yah-app.toml"), "").unwrap();
        std::fs::write(deep.join("yah-app.toml"), "").unwrap();

        let found = find_yah_app_tomls(dir.path(), 4).unwrap();
        assert!(found.contains(&shallow), "shallow should be found");
        assert!(!found.contains(&deep), "deep should be skipped");
    }

    #[test]
    fn discover_app_manifests_uses_registry_when_present() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".yah")).unwrap();

        let app_dir = dir.path().join("myapp");
        std::fs::create_dir_all(&app_dir).unwrap();
        let manifest = AppManifest {
            schema_version: 1,
            name: "myapp".into(),
            asset_deps: vec![],
        };
        manifest.save(&app_dir).unwrap();

        let mut reg = AppsRegistry::default();
        reg.add("myapp", "myapp");
        reg.save(dir.path()).unwrap();

        let found = discover_app_manifests(dir.path()).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1.name, "myapp");
    }

    #[test]
    fn discover_app_manifests_falls_back_to_find_when_no_registry() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".yah")).unwrap();

        let app_dir = dir.path().join("apps/desktop");
        std::fs::create_dir_all(&app_dir).unwrap();
        let manifest = AppManifest {
            schema_version: 1,
            name: "desktop".into(),
            asset_deps: vec![],
        };
        manifest.save(&app_dir).unwrap();

        let found = discover_app_manifests(dir.path()).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1.name, "desktop");
    }
}

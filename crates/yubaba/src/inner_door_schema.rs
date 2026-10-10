//! R876-B20: never hand a node's passway a route table it cannot read.
//!
//! The inner door's routes file is rendered off-node (`cloud::inner_door`,
//! which writes the MINIMUM `schema_version` that expresses the table: 1, or 2
//! once a mount `discover`s) and written on-node by kamaji when it spawns the
//! door. passway and yubaba are separately released, so the table can name a
//! schema the node's installed passway does not read — yubaba 0.8.43 shipped
//! without a matching passway and crash-looped staging.noisetable.com's door
//! on `unknown field discover`.
//!
//! This is the node-side gate: `POST /workloads/deploy` and
//! `/workloads/validate` ask the installed binary which schemas it reads
//! (`passway --path-routes-schemas`) and refuse an inner-door spec naming any
//! other. Refusing at admission means kamaji is never handed the spec, so the
//! routes file already on disk — the one the running door serves — is left as
//! it was.
//!
//! The two path constants below mirror `cloud::inner_door`'s. yubaba does not
//! link `cloud` at runtime (see `Cargo.toml`'s `floating_ip` note), so they are
//! restated rather than imported; the renderer's tests pin the same values.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

/// `cloud::inner_door::INNER_DOOR_BINARY`.
pub const INNER_DOOR_BINARY: &str = "/usr/local/bin/passway";
/// `cloud::inner_door::ROUTES_DIR`.
pub const ROUTES_DIR: &str = "/var/lib/passway/routes";

/// The flag passway answers with the schemas it reads
/// (`passway::path_routes_file::SCHEMAS_FLAG`).
pub const SCHEMAS_FLAG: &str = "--path-routes-schemas";

/// How long [`PasswaySchemaProbe`] waits for an answer. An older passway
/// ignores the flag and tries to start a door; run with an empty environment it
/// panics on its missing TLS config within milliseconds, and this bounds the
/// case where it does not.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// The schemas a passway binary reads, as it answers [`SCHEMAS_FLAG`]
/// (`path-routes-schemas 1 2`). `None` for any other output.
pub fn parse_schemas_line(stdout: &str) -> Option<BTreeSet<u32>> {
    let rest = stdout.trim().strip_prefix("path-routes-schemas ")?;
    let set = rest
        .split_whitespace()
        .map(|v| v.parse().ok())
        .collect::<Option<BTreeSet<u32>>>()?;
    (!set.is_empty()).then_some(set)
}

/// What a passway that gave no answer reads: v1 only. Every passway predating
/// the flag reads v1; none is promised to read anything newer.
fn silent_passway() -> BTreeSet<u32> {
    [1].into()
}

/// Refuse an inner-door spec whose route table names a `schema_version` the
/// node's passway cannot read. `readable` answers for a binary path and is
/// only called when the spec is an inner door with a versioned table.
///
/// `None` = admit. A spec that is not an inner door, or a table whose version
/// cannot be read off it, is admitted: the first is none of this check's
/// business and the second is passway's own boot refusal to make.
pub fn refusal(
    spec: &workload_spec::WorkloadSpec,
    readable: impl FnOnce(&Path) -> BTreeSet<u32>,
) -> Option<String> {
    let binary = spec.command.as_ref()?.first()?;
    if binary != INNER_DOOR_BINARY {
        return None;
    }
    #[derive(serde::Deserialize)]
    struct Version {
        schema_version: u32,
    }
    let needed = spec
        .files
        .iter()
        .filter(|f| f.path.starts_with(ROUTES_DIR))
        .filter_map(|f| serde_json::from_str::<Version>(&f.content).ok())
        .map(|v| v.schema_version)
        .max()?;
    let reads = readable(Path::new(binary));
    if reads.contains(&needed) {
        return None;
    }
    Some(format!(
        "inner-door route table needs path-routes schema {needed}, but this node's passway \
         ({binary}) reads {reads:?}. Refusing to write a table it would crash-loop on; the \
         existing routes file is left as it was. Ship passway alongside yubaba (R876-B20)"
    ))
}

/// Asks a passway binary which schemas it reads, at most once per
/// (path, mtime, size): a reconcile does not exec on every pass, and a
/// replaced binary is asked again.
#[derive(Default)]
pub struct PasswaySchemaProbe {
    cache: Mutex<HashMap<PathBuf, (SystemTime, u64, BTreeSet<u32>)>>,
}

impl PasswaySchemaProbe {
    /// The schemas `binary` reads. Any failure to get a well-formed answer —
    /// missing binary, unknown flag, nonzero exit, timeout, unparseable output
    /// — reads as v1 only.
    pub fn readable(&self, binary: &Path) -> BTreeSet<u32> {
        let Ok(meta) = std::fs::metadata(binary) else {
            return silent_passway();
        };
        let Ok(mtime) = meta.modified() else {
            return probe(binary, PROBE_TIMEOUT).unwrap_or_else(silent_passway);
        };
        if let Some((m, s, set)) = self.cache.lock().unwrap().get(binary) {
            if *m == mtime && *s == meta.len() {
                return set.clone();
            }
        }
        let set = probe(binary, PROBE_TIMEOUT).unwrap_or_else(silent_passway);
        self.cache
            .lock()
            .unwrap()
            .insert(binary.to_path_buf(), (mtime, meta.len(), set.clone()));
        set
    }
}

/// Run `binary --path-routes-schemas` with an empty environment and stdin,
/// killing it at `timeout`.
fn probe(binary: &Path, timeout: Duration) -> Option<BTreeSet<u32>> {
    use std::io::Read;
    let mut child = Command::new(binary)
        .arg(SCHEMAS_FLAG)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    if !status.success() {
        return None;
    }
    let mut out = String::new();
    child.stdout.take()?.read_to_string(&mut out).ok()?;
    parse_schemas_line(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn door_spec(schema: u32) -> workload_spec::WorkloadSpec {
        let mut spec = workload_spec::TenantPasswayWorkload::cold("noisetable.com", "127.0.0.1:14210")
            .jit_spec("passway-inner-noisetable");
        spec.command = Some(vec![INNER_DOOR_BINARY.into()]);
        spec.files = vec![workload_spec::InlineFile {
            path: Path::new(ROUTES_DIR).join("noisetable.routes.json"),
            content: format!(
                r#"{{"schema_version":{schema},"routes":[{{"mount":"","discover":{{"ident":"x","yubaba":["http://y:7443"]}}}}]}}"#
            ),
            mode: Some(0o600),
        }];
        spec
    }

    #[test]
    fn a_v1_only_passway_refuses_a_discover_table_by_name() {
        let spec = door_spec(2);
        let mut asked = None;
        let refusal = refusal(&spec, |bin| {
            asked = Some(bin.to_path_buf());
            [1].into()
        })
        .expect("a v2 table onto a v1-only passway must be refused");
        assert_eq!(asked.as_deref(), Some(Path::new(INNER_DOOR_BINARY)));
        assert!(refusal.contains("needs path-routes schema 2"), "{refusal}");
        assert!(refusal.contains("reads {1}"), "{refusal}");
        assert!(refusal.contains("Ship passway alongside yubaba"), "{refusal}");
    }

    #[test]
    fn a_passway_that_reads_the_tables_schema_admits_it() {
        assert_eq!(refusal(&door_spec(2), |_| [1, 2].into()), None);
        assert_eq!(refusal(&door_spec(1), |_| [1].into()), None);
    }

    #[test]
    fn a_spec_that_is_not_an_inner_door_is_never_probed() {
        let mut spec = door_spec(2);
        spec.command = Some(vec!["/usr/bin/other".into()]);
        assert_eq!(refusal(&spec, |_| panic!("must not probe a non-door spec")), None);
    }

    #[test]
    fn only_a_well_formed_schemas_line_is_an_answer() {
        assert_eq!(parse_schemas_line("path-routes-schemas 1 2\n"), Some([1, 2].into()));
        assert_eq!(parse_schemas_line("path-routes-schemas\n"), None);
        assert_eq!(parse_schemas_line("path-routes-schemas 1 x"), None);
        assert_eq!(parse_schemas_line("thread 'main' panicked"), None);
        assert_eq!(parse_schemas_line(""), None);
    }

    /// No answer — a missing binary, one exiting nonzero — reads as v1 only.
    #[cfg(unix)]
    #[test]
    fn a_passway_with_no_answer_reads_v1_only() {
        let probe_ = PasswaySchemaProbe::default();
        assert_eq!(probe_.readable(Path::new("/nonexistent/passway")), [1].into());
        assert_eq!(probe_.readable(Path::new("/usr/bin/false")), [1].into());
    }
}

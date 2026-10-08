//! R605-F37: the ONE owner of yubaba's sovereign unit flags on a node.
//!
//! A machine's sovereign facts are declared in two camp files —
//! `.yah/infra/machines/<name>.toml` (`sovereign_group`,
//! `sovereign_participation`) and `.yah/infra/sovereign-groups/<group>.toml`
//! (the voter list) — and the daemon reads none of them. They reach a node as
//! a systemd drop-in, and this module is the only thing that writes one:
//! [`render`] is a pure function of those two files, with no node access, and
//! [`check_live`] compares its output against what `systemctl cat yubaba`
//! reports before a roll installs anything.
//!
//! # Why `Environment=`, not `ExecStart=`
//!
//! Recorded decision. Before this module the flags lived in a hand-rolled
//! `95-sovereign-group.conf` that re-declares the whole `ExecStart=` (R911-T6),
//! and that line also carries every other flag the node runs with — raft id,
//! raft dir, `--scryer-endpoint` on us-east-001, `--cluster-profile rig` on the
//! dev Pis. A renderer that owned an `ExecStart=` would have to own all of
//! those too, or drop them: exactly the R858-T4 outage, where a drop-in's
//! `ExecStart=` silently shed `--native-exec-dir` (see the header of
//! `app/yah/cli/resources/kamaji.service`). So the rendered drop-in carries
//! ONLY `Environment=YUBABA_SOVEREIGN_*` lines, which `yubaba serve` reads as
//! the env fallback of `--sovereign-group` / `--sovereign-participation` /
//! `--sovereign-voters`, and never touches `ExecStart=`. It is also the
//! version-safe direction: a yubaba that predates a flag ignores an unknown
//! environment variable, where clap refuses an unknown flag and the unit fails
//! to start (R605-F35's roll-order gotcha).
//!
//! It is written as [`DROPIN_NAME`] (`90-sovereign.conf`), not over the live
//! `95-sovereign-group.conf`: replacing that file would remove the `ExecStart=`
//! it carries and fall back to an earlier drop-in's command line, which on
//! prod is not known to carry the same flags. The legacy literal
//! `--sovereign-*` flags in today's `ExecStart=` win over the environment
//! (clap: argv beats env), so [`check_live`] refuses whenever one DISAGREES
//! with the render, and reports agreeing ones as [`Legacy`] — a shadowing copy
//! to strip once every node runs an env-capable yubaba, never a second source.
//!
//! [`Legacy`]: LiveFinding::LegacyLiteral

use std::fmt::Write as _;

use anyhow::{bail, Result};
use workload_spec::sovereign::Participation;

use crate::config::{MachineConfig, SovereignGroupConfig};

/// Directory the drop-in lives in on a node.
pub const DROPIN_DIR: &str = "/etc/systemd/system/yubaba.service.d";
/// File name of the rendered drop-in.
pub const DROPIN_NAME: &str = "90-sovereign.conf";

/// `YUBABA_SOVEREIGN_GROUP` — env spelling of `--sovereign-group`.
pub const ENV_GROUP: &str = "YUBABA_SOVEREIGN_GROUP";
/// `YUBABA_SOVEREIGN_PARTICIPATION` — env spelling of `--sovereign-participation`.
pub const ENV_PARTICIPATION: &str = "YUBABA_SOVEREIGN_PARTICIPATION";
/// `YUBABA_SOVEREIGN_VOTERS` — env spelling of `--sovereign-voters`.
pub const ENV_VOTERS: &str = "YUBABA_SOVEREIGN_VOTERS";

/// The node-side script that retires the legacy literal `--sovereign-*` flags
/// once the installed yubaba reads the env form. Read its header for the
/// exact sequence. The one copy every roll path pipes.
pub const RETIRE_LITERALS_SCRIPT: &str = include_str!("sovereign_retire.sh");

/// Full path of the drop-in on a node.
pub fn dropin_path() -> String {
    format!("{DROPIN_DIR}/{DROPIN_NAME}")
}

/// The sovereign facts one node's yubaba runs with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SovereignFlags {
    pub group: String,
    pub participation: Participation,
    /// The group's voter raft ids, sorted. Empty = the group seats nobody.
    pub voters: Vec<u64>,
}

/// The flags `machine` should run with, or `None` when it declares no
/// sovereign group (then no drop-in belongs on it).
///
/// Errors — never guesses — when the machine names a group with no
/// `.yah/infra/sovereign-groups/<group>.toml`.
pub fn flags_for(
    groups: &[SovereignGroupConfig],
    machine: &MachineConfig,
) -> Result<Option<SovereignFlags>> {
    let Some(group) = machine.sovereign_group.as_deref() else {
        return Ok(None);
    };
    let Some(decl) = groups.iter().find(|g| g.name == group) else {
        bail!(
            "{} declares sovereign_group = \"{group}\" but there is no \
             .yah/infra/sovereign-groups/{group}.toml — refusing to render its drop-in",
            machine.name
        );
    };
    let mut voters: Vec<u64> = decl.voters.iter().map(|v| v.raft_node_id).collect();
    voters.sort_unstable();
    Ok(Some(SovereignFlags {
        group: group.to_string(),
        participation: machine.sovereign_participation,
        voters,
    }))
}

/// Render the drop-in text for `flags`. Pure; the header names the machine so
/// a reader on the node knows which declaration it came from.
pub fn render_flags(machine: &str, flags: &SovereignFlags) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "# R605-F37 — rendered by `yah cloud sovereign-dropin {machine}`. DO NOT EDIT ON THE NODE:"
    );
    s.push_str(
        "# a roll refuses when this file disagrees with the render. Source of truth:\n\
         # .yah/infra/machines/<name>.toml + .yah/infra/sovereign-groups/<group>.toml.\n\
         # Environment= only; never re-declares the command line — see\n\
         # oss/yubaba/crates/cloud/src/sovereign_unit.rs.\n\
         [Service]\n",
    );
    let _ = writeln!(s, "Environment={ENV_GROUP}={}", flags.group);
    let _ = writeln!(s, "Environment={ENV_PARTICIPATION}={}", flags.participation);
    if !flags.voters.is_empty() {
        let ids: Vec<String> = flags.voters.iter().map(u64::to_string).collect();
        let _ = writeln!(s, "Environment={ENV_VOTERS}={}", ids.join(","));
    }
    s
}

/// [`flags_for`] + [`render_flags`]: the drop-in `machine` should carry, or
/// `None` when none belongs on it.
pub fn render(groups: &[SovereignGroupConfig], machine: &MachineConfig) -> Result<Option<String>> {
    Ok(flags_for(groups, machine)?.map(|f| render_flags(&machine.name, &f)))
}

/// One file of `systemctl cat` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    pub path: String,
    pub body: String,
}

/// Split `systemctl cat <unit>` output into its files. Each file is introduced
/// by a `# /path/to/file` line.
pub fn parse_systemctl_cat(text: &str) -> Vec<Fragment> {
    let mut out: Vec<Fragment> = Vec::new();
    for line in text.lines() {
        if let Some(path) = line.strip_prefix("# /") {
            let path = path.trim();
            if !path.contains(char::is_whitespace)
                && (path.ends_with(".service") || path.ends_with(".conf"))
            {
                out.push(Fragment {
                    path: format!("/{path}"),
                    body: String::new(),
                });
                continue;
            }
        }
        if let Some(f) = out.last_mut() {
            f.body.push_str(line);
            f.body.push('\n');
        }
    }
    out
}

/// `Key=value` assignments in a unit body, with `\`-continued lines joined.
fn assignments(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut pending = String::new();
    for raw in body.lines() {
        let line = raw.trim_end();
        if pending.is_empty() && (line.trim_start().starts_with('#') || line.trim_start().starts_with(';')) {
            continue;
        }
        if let Some(cont) = line.strip_suffix('\\') {
            pending.push_str(cont);
            pending.push(' ');
            continue;
        }
        pending.push_str(line);
        let full = std::mem::take(&mut pending);
        if let Some((k, v)) = full.trim().split_once('=') {
            out.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    out
}

/// The effective `ExecStart=` across all fragments: an empty assignment resets,
/// the last non-empty one after the last reset wins.
pub fn effective_exec_start(frags: &[Fragment]) -> Option<String> {
    let mut cur: Option<String> = None;
    for f in frags {
        for (k, v) in assignments(&f.body) {
            if k == "ExecStart" {
                cur = if v.is_empty() { None } else { Some(v) };
            }
        }
    }
    cur
}

/// Literal `--sovereign-*` flags on an ExecStart line, as (flag, value).
fn literal_sovereign_flags(exec: &str) -> Vec<(String, String)> {
    let toks: Vec<&str> = exec.split_whitespace().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        let t = toks[i];
        if let Some(rest) = t.strip_prefix("--sovereign-") {
            if let Some((name, val)) = rest.split_once('=') {
                out.push((format!("--sovereign-{name}"), val.to_string()));
            } else {
                let val = toks.get(i + 1).copied().unwrap_or("").to_string();
                out.push((t.to_string(), val));
                i += 1;
            }
        }
        i += 1;
    }
    out
}

/// One thing [`check_live`] noticed on the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveFinding {
    /// The effective `ExecStart=` carries a literal flag that AGREES with the
    /// render. Shadows the drop-in (argv beats env) but changes nothing.
    LegacyLiteral { flag: String, value: String },
}

/// What a roll should do with the drop-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Live already equals the render (including "neither has one").
    NoOp,
    /// Write the render: the drop-in is absent, or a change was accepted.
    Install,
    /// Delete the drop-in: the machine no longer declares a group and the
    /// operator accepted the change.
    Remove,
    /// Refuse the roll. `why` names the disagreement; `diff` shows it.
    Refuse { why: String, diff: String },
}

/// The full result of [`check_live`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveCheck {
    pub verdict: Verdict,
    pub findings: Vec<LiveFinding>,
}

fn line_diff(live: &str, rendered: &str) -> String {
    let mut s = format!("--- live {}\n+++ rendered\n", dropin_path());
    let live_lines: Vec<&str> = live.lines().collect();
    let rend_lines: Vec<&str> = rendered.lines().collect();
    for l in &live_lines {
        if !rend_lines.contains(l) {
            let _ = writeln!(s, "-{l}");
        }
    }
    for l in &rend_lines {
        if !live_lines.contains(l) {
            let _ = writeln!(s, "+{l}");
        }
    }
    s
}

fn flag_value_matches(flag: &str, value: &str, want: Option<&SovereignFlags>) -> bool {
    let Some(want) = want else { return false };
    match flag {
        "--sovereign-group" => value == want.group,
        "--sovereign-participation" => value == want.participation.as_str(),
        "--sovereign-voters" => {
            let mut got: Vec<u64> = value.split(',').filter_map(|v| v.trim().parse().ok()).collect();
            got.sort_unstable();
            got == want.voters && value.split(',').count() == got.len()
        }
        _ => false,
    }
}

/// Compare a node's live yubaba unit (`systemctl cat yubaba.service` output)
/// with the render for its machine.
///
/// Refuses on any unexplained difference: a hand-edited drop-in, another
/// fragment setting `YUBABA_SOVEREIGN_*`, or a literal `--sovereign-*` flag in
/// the effective `ExecStart=` that disagrees with the render. `accept_change`
/// explains a differing (or orphaned) drop-in as an intended declaration
/// change; it never explains a disagreeing literal flag or a foreign
/// `Environment=`, because installing the drop-in would not fix either.
pub fn check_live(
    machine: &str,
    want: Option<&SovereignFlags>,
    live_cat: &str,
    accept_change: bool,
) -> LiveCheck {
    let frags = parse_systemctl_cat(live_cat);
    let ours = dropin_path();
    let rendered = want.map(|f| render_flags(machine, f));
    let mut findings = Vec::new();

    // A second owner of the environment variables.
    for f in frags.iter().filter(|f| f.path != ours) {
        for (k, v) in assignments(&f.body) {
            if k == "Environment"
                && [ENV_GROUP, ENV_PARTICIPATION, ENV_VOTERS]
                    .iter()
                    .any(|e| v.contains(&format!("{e}=")))
            {
                return LiveCheck {
                    verdict: Verdict::Refuse {
                        why: format!(
                            "{} sets YUBABA_SOVEREIGN_* — only {ours} may; remove it by hand",
                            f.path
                        ),
                        diff: format!("--- {}\n{}", f.path, f.body),
                    },
                    findings,
                };
            }
        }
    }

    // Literal flags in the effective command line win over the env.
    if let Some(exec) = effective_exec_start(&frags) {
        for (flag, value) in literal_sovereign_flags(&exec) {
            if flag_value_matches(&flag, &value, want) {
                findings.push(LiveFinding::LegacyLiteral { flag, value });
            } else {
                let wanted = match (want, flag.as_str()) {
                    (None, _) => "nothing (the machine declares no sovereign_group)".to_string(),
                    (Some(w), "--sovereign-group") => w.group.clone(),
                    (Some(w), "--sovereign-participation") => w.participation.to_string(),
                    (Some(w), "--sovereign-voters") => w
                        .voters
                        .iter()
                        .map(u64::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                    (Some(_), _) => "no such flag".to_string(),
                };
                return LiveCheck {
                    verdict: Verdict::Refuse {
                        why: format!(
                            "the effective ExecStart= passes `{flag} {value}` but the declarations \
                             render {wanted}; argv beats the drop-in's env, so installing it would \
                             not take effect — fix the ExecStart= drop-in by hand (keep every other flag)"
                        ),
                        diff: format!("-{flag} {value}\n+{flag} {wanted}\n"),
                    },
                    findings,
                };
            }
        }
    }

    let live = frags.iter().find(|f| f.path == ours).map(|f| f.body.as_str());
    let verdict = match (live, rendered.as_deref()) {
        (None, None) => Verdict::NoOp,
        (None, Some(_)) => Verdict::Install,
        (Some(l), Some(r)) if l.trim_end() == r.trim_end() => Verdict::NoOp,
        (Some(l), Some(r)) => {
            if accept_change {
                Verdict::Install
            } else {
                Verdict::Refuse {
                    why: format!(
                        "{ours} on the node differs from the render — a hand edit or an \
                         unrolled declaration change; re-run with --accept-sovereign-change \
                         if the declarations are what you mean"
                    ),
                    diff: line_diff(l, r),
                }
            }
        }
        (Some(l), None) => {
            if accept_change {
                Verdict::Remove
            } else {
                Verdict::Refuse {
                    why: format!(
                        "{ours} exists on the node but {machine} declares no sovereign_group; \
                         re-run with --accept-sovereign-change to remove it"
                    ),
                    diff: line_diff(l, ""),
                }
            }
        }
    };
    LiveCheck { verdict, findings }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags() -> SovereignFlags {
        SovereignFlags {
            group: "dev".into(),
            participation: Participation::In,
            voters: vec![11, 13, 14],
        }
    }

    fn cat(extra: &str) -> String {
        format!(
            "# /etc/systemd/system/yubaba.service\n[Service]\nExecStart=/usr/local/bin/yubaba serve\n\
             # /etc/systemd/system/yubaba.service.d/95-sovereign-group.conf\n[Service]\nExecStart=\n\
             ExecStart=/usr/local/bin/yubaba serve --raft-node-id 11 --cluster-profile rig --sovereign-group dev\n{extra}"
        )
    }

    #[test]
    fn render_carries_only_environment_lines() {
        let r = render_flags("us-west-011", &flags());
        assert!(!r.contains("ExecStart"));
        assert!(r.contains("Environment=YUBABA_SOVEREIGN_GROUP=dev\n"));
        assert!(r.contains("Environment=YUBABA_SOVEREIGN_PARTICIPATION=in\n"));
        assert!(r.contains("Environment=YUBABA_SOVEREIGN_VOTERS=11,13,14\n"));
    }

    #[test]
    fn absent_dropin_with_agreeing_literal_installs_and_notes_the_legacy_flag() {
        let c = check_live("us-west-011", Some(&flags()), &cat(""), false);
        assert_eq!(c.verdict, Verdict::Install);
        assert_eq!(
            c.findings,
            vec![LiveFinding::LegacyLiteral {
                flag: "--sovereign-group".into(),
                value: "dev".into()
            }]
        );
    }

    #[test]
    fn identical_dropin_is_a_noop() {
        let live = cat(&format!("# {}\n{}", dropin_path(), render_flags("us-west-011", &flags())));
        assert_eq!(check_live("us-west-011", Some(&flags()), &live, false).verdict, Verdict::NoOp);
    }

    #[test]
    fn hand_edited_dropin_refuses_with_a_diff_unless_accepted() {
        let edited = render_flags("us-west-011", &flags()).replace("11,13,14", "11,13");
        let live = cat(&format!("# {}\n{edited}", dropin_path()));
        match check_live("us-west-011", Some(&flags()), &live, false).verdict {
            Verdict::Refuse { diff, .. } => {
                assert!(diff.contains("-Environment=YUBABA_SOVEREIGN_VOTERS=11,13\n"));
                assert!(diff.contains("+Environment=YUBABA_SOVEREIGN_VOTERS=11,13,14\n"));
            }
            v => panic!("expected refuse, got {v:?}"),
        }
        assert_eq!(check_live("us-west-011", Some(&flags()), &live, true).verdict, Verdict::Install);
    }

    #[test]
    fn a_disagreeing_literal_flag_refuses_even_when_accepted() {
        let live = cat("").replace("--sovereign-group dev", "--sovereign-group prod");
        assert!(matches!(
            check_live("us-west-011", Some(&flags()), &live, true).verdict,
            Verdict::Refuse { .. }
        ));
        let live = cat("").replace("--sovereign-group dev", "--sovereign-group dev --sovereign-voters 11,13");
        assert!(matches!(
            check_live("us-west-011", Some(&flags()), &live, false).verdict,
            Verdict::Refuse { .. }
        ));
    }

    #[test]
    fn a_foreign_environment_owner_refuses() {
        let live = cat("# /etc/systemd/system/yubaba.service.d/99-x.conf\n[Service]\nEnvironment=YUBABA_SOVEREIGN_VOTERS=1\n");
        assert!(matches!(
            check_live("us-west-011", Some(&flags()), &live, true).verdict,
            Verdict::Refuse { .. }
        ));
    }

    #[test]
    fn a_reset_execstart_drops_earlier_literals() {
        let live = "# /etc/systemd/system/yubaba.service\n[Service]\nExecStart=/y serve --sovereign-group prod\n\
                    # /etc/systemd/system/yubaba.service.d/40-raft.conf\n[Service]\nExecStart=\nExecStart=/y serve \\\n  --raft-node-id 11\n";
        let c = check_live("us-west-011", Some(&flags()), live, false);
        assert_eq!(c.verdict, Verdict::Install);
        assert!(c.findings.is_empty());
    }

    #[test]
    fn the_retire_script_is_gated_on_the_installed_binary_reading_the_env() {
        let s = RETIRE_LITERALS_SCRIPT;
        let gate = s.find("grep -q YUBABA_SOVEREIGN_VOTERS").expect("env gate");
        let strip = s.find("sed -i").expect("strip step");
        assert!(gate < strip, "the gate must run before any edit");
        assert!(s.contains("--sovereign-(group|participation|voters)"));
        assert!(!s.contains("systemctl restart"), "the caller owns the restart");
    }

    #[test]
    fn no_group_and_no_dropin_is_a_noop() {
        let live = "# /etc/systemd/system/yubaba.service\n[Service]\nExecStart=/y serve\n";
        assert_eq!(check_live("us-west-002", None, live, false).verdict, Verdict::NoOp);
    }
}

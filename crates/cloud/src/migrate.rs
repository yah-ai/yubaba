//! W305/R742-F3 — planning a workload's move between sovereign groups.
//!
//! `yah cloud migrate <workload> --to <sovereign-group>` is the verb that keeps
//! *environment* off the node. Without it, "run dev on the Pis" quietly becomes
//! "dev lives on the Pis forever", and the pressure to encode the environment
//! as a property of hardware — the mistake W305 exists to undo — comes straight
//! back.
//!
//! # This module plans; it does not move
//!
//! Operator call, 2026-08-15: migrate **computes and refuses**, the operator
//! executes. The reason is that the stateful half has no substrate under it. A
//! [`VolumeSource::Named`] materialises as a host bind at
//! `/var/lib/yah/kamaji/volumes/<name>` (`kamaji-containerd-core`), and there
//! is no volume export/import/snapshot route anywhere in yubaba or kamaji — so
//! "the volume has to follow" means inventing node-to-node data movement on a
//! live fleet. That is its own design (atomicity, checksums, enforcing
//! at-most-one-live across the cut) and its own relay.
//!
//! What is *not* deferred is the correctness story. Everything that can be
//! decided from the declarations is decided here and fails loud:
//! which group a workload may go to, which box in it will take the workload,
//! which volumes must follow and which must deliberately not, which ordering
//! the two archetype halves require, and the four ways the move is refused
//! outright. A [`MigrationPlan`] is a pure function of the camp's TOML plus the
//! observed placement — no network, no credentials.
//!
//! # The two halves
//!
//! The ticket's framing, and it falls straight out of [`LifecycleArchetype`]:
//!
//! - **Stateful** ([`LifecycleArchetype::Appliance`]) — a volume that must
//!   follow, at most one live instance, not drainable. The move is therefore
//!   **stop → copy → start**, and the downtime is inherent rather than
//!   incidental: starting the target first would put two live instances on a
//!   workload whose whole archetype is "there is only ever one".
//! - **Fungible** ([`LifecycleArchetype::Server`] / [`LifecycleArchetype::Job`])
//!   — no state to move. The move is **start → verify → stop**, which has no
//!   downtime, and there is no copy step at all.
//!
//! Rendering one procedure for both would have to pick one ordering, and either
//! choice is wrong for the other half.
//!
//! @arch:see(.yah/docs/working/W305-sovereign-groups-environments-edges.md)

use std::fmt;
use std::path::PathBuf;

use serde::Serialize;

use workload_spec::{LifecycleArchetype, SecretRef, VolumeSource, WorkloadSpec};

use crate::config::{CloudConfig, MachineConfig};

/// Host directory kamaji binds a [`VolumeSource::Named`] from.
///
/// Duplicated from `kamaji-containerd-core` rather than imported: `cloud` has
/// no kamaji dependency (and should not grow one to render a path into a
/// procedure the operator runs by hand). [`named_volume_path`] is the only
/// reader, and `a_named_volume_renders_the_kamaji_host_path` pins the string so
/// a change on the kamaji side surfaces as a test failure here rather than as
/// an operator rsyncing an empty directory.
pub const KAMAJI_VOLUME_ROOT: &str = "/var/lib/yah/kamaji/volumes";

/// Absolute host path backing the named volume `name`.
pub fn named_volume_path(name: &str) -> String {
    format!("{KAMAJI_VOLUME_ROOT}/{name}")
}

/// Why a migration cannot be planned.
///
/// Every variant names the thing to fix, not just the complaint — the same bar
/// `check_inert_taints` and `judge_join` hold themselves to. A refusal an
/// operator cannot act on trains them to pass `--force`, which is how the
/// guard stops being a guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationRefusal {
    /// No `.yah/infra/workloads/<name>.toml`.
    UnknownWorkload { name: String, declared: Vec<String> },

    /// No machine declares `sovereign_group = "<group>"`. Indistinguishable
    /// from a typo, so the declared vocabulary is named.
    UnknownGroup {
        group: String,
        declared: Vec<String>,
    },

    /// The workload is not running anywhere the camp can see. Migration moves
    /// something; placing it for the first time is a different verb.
    NotDeployed { workload: String },

    /// Every observed instance is already in the target group.
    AlreadyInGroup {
        workload: String,
        group: String,
        machines: Vec<String>,
    },

    /// More than one source machine outside the target group.
    ///
    /// For an [`LifecycleArchetype::Appliance`] this is a *pre-existing*
    /// violation — at most one live instance is the archetype's defining
    /// property — and migrating would carry it across the cut. For the fungible
    /// half it is merely ambiguous: which replica moves first is a decision the
    /// planner has no basis to make.
    MultipleSources {
        workload: String,
        archetype: LifecycleArchetype,
        machines: Vec<String>,
    },

    /// The spec declares a fungible archetype *and* carries durable volumes.
    ///
    /// The declaration says "drop and reschedule me"; the volumes say "I have
    /// state". Rescheduling wins, and the state is silently left behind — so
    /// this is refused rather than planned. Note that
    /// [`WorkloadSpec::effective_archetype`] cannot catch it: its inference
    /// only runs when `archetype` is absent, and an explicit `archetype =
    /// "server"` overrides exactly the volume signal that would have inferred
    /// `Appliance`.
    FungibleWithDurableVolumes {
        workload: String,
        archetype: LifecycleArchetype,
        volumes: Vec<String>,
    },

    /// The group has members, but none of them admits the workload.
    ///
    /// Carries the message from [`CloudConfig::admit_workload_in_group`], which
    /// names the failing axes and the candidate machines. The live case this
    /// exists for is `no-appliance` on a dev node (W305 finding 2): a migration
    /// verb must fail here for the same reason `yah cloud apply` would, not
    /// route around the taint because the operator asked nicely.
    NoAdmissibleTarget {
        workload: String,
        group: String,
        reason: String,
    },
}

impl fmt::Display for MigrationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownWorkload { name, declared } => write!(
                f,
                "no workload '{name}' in .yah/infra/workloads/ — declared: {}",
                list_or_none(declared)
            ),
            Self::UnknownGroup { group, declared } => write!(
                f,
                "no machine declares sovereign_group = \"{group}\" — declared groups: {}. \
                 A group is the set of machines naming it, so migrating to one that \
                 nothing declares would place the workload nowhere; stamp a machine in \
                 .yah/infra/machines/<name>.toml first.",
                list_or_none(declared)
            ),
            Self::NotDeployed { workload } => write!(
                f,
                "workload '{workload}' is not running on any declared machine — nothing to \
                 migrate. To place it for the first time use \
                 `yah cloud workload deploy {workload} <machine>`; pass `--from <machine>` \
                 if it is running somewhere this camp cannot reach."
            ),
            Self::AlreadyInGroup {
                workload,
                group,
                machines,
            } => write!(
                f,
                "workload '{workload}' is already in sovereign group '{group}' (on {}) — \
                 nothing to do",
                machines.join(", ")
            ),
            Self::MultipleSources {
                workload,
                archetype,
                machines,
            } => {
                write!(
                    f,
                    "workload '{workload}' is live on {} machines outside the target group \
                     ({}), and this plans one move at a time — re-run with \
                     `--from <machine>`.",
                    machines.len(),
                    machines.join(", ")
                )?;
                if matches!(archetype, LifecycleArchetype::Appliance) {
                    write!(
                        f,
                        " NOTE: '{workload}' is an appliance, whose defining property is at \
                         most one live instance. Two is a violation that predates this \
                         migration — resolve it before moving, or the move carries it \
                         across the cut."
                    )?;
                }
                Ok(())
            }
            Self::FungibleWithDurableVolumes {
                workload,
                archetype,
                volumes,
            } => write!(
                f,
                "workload '{workload}' declares archetype = \"{}\" but mounts durable \
                 volume(s) [{}]. A fungible workload is dropped and rescheduled, so the \
                 target would come up with empty storage and the data would be silently \
                 left on the source. Declare `archetype = \"appliance\"` if the state \
                 matters, or drop the volume if it does not.",
                archetype.taint_key(),
                volumes.join(", ")
            ),
            Self::NoAdmissibleTarget {
                workload,
                group,
                reason,
            } => write!(
                f,
                "no machine in sovereign group '{group}' admits workload '{workload}': \
                 {reason}"
            ),
        }
    }
}

impl std::error::Error for MigrationRefusal {}

fn list_or_none<S: AsRef<str>>(items: &[S]) -> String {
    if items.is_empty() {
        "(none)".to_string()
    } else {
        items
            .iter()
            .map(|s| s.as_ref())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// What happens to one declared volume mount when the workload moves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum VolumeDisposition {
    /// [`VolumeSource::Named`] — camp-managed state that must be copied. This
    /// is what "the volume has to follow" means concretely.
    Copy {
        name: String,
        host_path: String,
        mounted_at: PathBuf,
    },
    /// [`VolumeSource::Bind`] — an operator-managed host path. The camp did not
    /// create it and cannot know whether it is reproducible on the target, so
    /// it is surfaced as a precondition rather than copied blindly.
    Precondition {
        host_path: PathBuf,
        mounted_at: PathBuf,
    },
    /// [`VolumeSource::Tmpfs`] — discarded on stop by definition. Listed
    /// explicitly, and *not* silently omitted, so nobody hunts for it on the
    /// source box or rsyncs a ramdisk.
    Discard { mounted_at: PathBuf, size_mb: u32 },
}

impl VolumeDisposition {
    /// Whether this mount carries state that a move must account for.
    /// Tmpfs does not; the other two do.
    pub fn is_durable(&self) -> bool {
        !matches!(self, Self::Discard { .. })
    }

    /// Short label used in refusals and rendered output.
    pub fn label(&self) -> String {
        match self {
            Self::Copy { name, .. } => name.clone(),
            Self::Precondition { host_path, .. } => host_path.display().to_string(),
            Self::Discard { mounted_at, .. } => format!("tmpfs:{}", mounted_at.display()),
        }
    }
}

/// A precondition the move depends on that this planner cannot satisfy or
/// verify, stated so it is done *before* the cut rather than discovered after.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Precondition {
    /// One line naming what must be true.
    pub what: String,
    /// Why it bites — the failure the operator gets if it is skipped.
    pub because: String,
}

/// One ordered step of the rendered procedure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MigrationStep {
    /// What this step accomplishes.
    pub what: String,
    /// The command to run, when there is one to give. `None` for steps that
    /// are a judgement rather than an invocation ("confirm it is serving").
    pub command: Option<String>,
}

impl MigrationStep {
    fn narrate(what: impl Into<String>) -> Self {
        Self {
            what: what.into(),
            command: None,
        }
    }

    fn run(what: impl Into<String>, command: impl Into<String>) -> Self {
        Self {
            what: what.into(),
            command: Some(command.into()),
        }
    }
}

/// A checked, ordered move of one workload from one machine to another in a
/// different sovereign group.
///
/// Produced by [`plan_migration`], executed by the operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MigrationPlan {
    pub workload: String,
    pub archetype: LifecycleArchetype,
    /// True for [`LifecycleArchetype::Appliance`] — decides the step ordering
    /// and whether there is a copy at all.
    pub stateful: bool,

    pub source_machine: String,
    pub source_group: Option<String>,
    pub source_ssh: Option<String>,
    pub source_yubaba: Option<String>,

    pub target_machine: String,
    pub target_group: String,
    pub target_ssh: Option<String>,
    pub target_yubaba: Option<String>,

    pub volumes: Vec<VolumeDisposition>,
    pub preconditions: Vec<Precondition>,
    pub steps: Vec<MigrationStep>,
}

impl MigrationPlan {
    /// Volumes that must be copied for the move to preserve state.
    pub fn volumes_to_copy(&self) -> impl Iterator<Item = &VolumeDisposition> {
        self.volumes
            .iter()
            .filter(|v| matches!(v, VolumeDisposition::Copy { .. }))
    }

    /// Whether the move takes the workload down. True for the stateful half by
    /// construction — see the module header.
    pub fn incurs_downtime(&self) -> bool {
        self.stateful
    }
}

/// Plan the move of `workload` into sovereign group `to_group`.
///
/// `observed` is the set of machine names the workload is currently live on, as
/// seen by the caller — the CLI either probes the fleet or takes it from
/// `--from`. It is an input rather than something this function discovers so
/// the planner stays pure: same TOML plus same observation ⇒ same plan, with no
/// network in the middle.
///
/// Returns [`MigrationRefusal`] rather than a bare error because every refusal
/// is a distinct, actionable diagnosis and callers (and tests) should be able
/// to match on which one fired.
pub fn plan_migration(
    cfg: &CloudConfig,
    workload: &str,
    to_group: &str,
    observed: &[String],
) -> Result<MigrationPlan, MigrationRefusal> {
    let wl = cfg
        .workload(workload)
        .ok_or_else(|| MigrationRefusal::UnknownWorkload {
            name: workload.to_string(),
            declared: cfg
                .workloads
                .iter()
                .map(|w| w.spec.name.clone())
                .collect(),
        })?;
    let spec = &wl.spec;

    // The group must exist as a declaration before anything else is worth
    // saying — every later diagnosis would otherwise be downstream of a typo.
    let members = cfg.machines_in_group(to_group);
    if members.is_empty() {
        return Err(MigrationRefusal::UnknownGroup {
            group: to_group.to_string(),
            declared: cfg
                .declared_sovereign_groups()
                .into_iter()
                .map(String::from)
                .collect(),
        });
    }

    if observed.is_empty() {
        return Err(MigrationRefusal::NotDeployed {
            workload: workload.to_string(),
        });
    }

    // Split the observation by whether it is already where it is going.
    let in_group: Vec<String> = observed
        .iter()
        .filter(|name| {
            cfg.machine(name)
                .and_then(|m| m.sovereign_group.as_deref())
                == Some(to_group)
        })
        .cloned()
        .collect();
    let sources: Vec<String> = observed
        .iter()
        .filter(|name| !in_group.contains(name))
        .cloned()
        .collect();

    if sources.is_empty() {
        return Err(MigrationRefusal::AlreadyInGroup {
            workload: workload.to_string(),
            group: to_group.to_string(),
            machines: in_group,
        });
    }

    let archetype = spec.effective_archetype();

    if sources.len() > 1 {
        return Err(MigrationRefusal::MultipleSources {
            workload: workload.to_string(),
            archetype,
            machines: sources,
        });
    }

    let volumes = dispositions(spec);
    let stateful = matches!(archetype, LifecycleArchetype::Appliance);

    // A declared-fungible workload carrying durable state is a contradiction
    // the move would resolve by losing the data. See the refusal's doc.
    if !stateful {
        let durable: Vec<String> = volumes
            .iter()
            .filter(|v| v.is_durable())
            .map(|v| v.label())
            .collect();
        if !durable.is_empty() {
            return Err(MigrationRefusal::FungibleWithDurableVolumes {
                workload: workload.to_string(),
                archetype,
                volumes: durable,
            });
        }
    }

    // Same admission seam as `yah cloud apply`, narrowed to the group.
    let target =
        cfg.admit_workload_in_group(spec, to_group)
            .map_err(|e| MigrationRefusal::NoAdmissibleTarget {
                workload: workload.to_string(),
                group: to_group.to_string(),
                reason: e.to_string(),
            })?;

    let source_name = sources[0].clone();
    let source = cfg.machine(&source_name);

    let preconditions = preconditions(spec, &volumes, &source_name, &target.name, to_group);
    let steps = steps(
        workload,
        stateful,
        &volumes,
        source,
        &source_name,
        target,
    );

    Ok(MigrationPlan {
        workload: workload.to_string(),
        archetype,
        stateful,
        source_group: source.and_then(|m| m.sovereign_group.clone()),
        source_ssh: source.and_then(|m| m.connect.as_ref().map(|c| c.ssh.clone())),
        source_yubaba: source.and_then(|m| m.yubaba_url()),
        source_machine: source_name,
        target_machine: target.name.clone(),
        target_group: to_group.to_string(),
        target_ssh: target.connect.as_ref().map(|c| c.ssh.clone()),
        target_yubaba: target.yubaba_url(),
        volumes,
        preconditions,
        steps,
    })
}

/// Classify every declared mount. Order follows the spec so the rendered plan
/// reads in the same order as the file the operator is looking at.
fn dispositions(spec: &WorkloadSpec) -> Vec<VolumeDisposition> {
    spec.volumes
        .iter()
        .map(|v| match &v.source {
            VolumeSource::Named { name } => VolumeDisposition::Copy {
                name: name.clone(),
                host_path: named_volume_path(name),
                mounted_at: v.target.clone(),
            },
            VolumeSource::Bind { host_path } => VolumeDisposition::Precondition {
                host_path: host_path.clone(),
                mounted_at: v.target.clone(),
            },
            VolumeSource::Tmpfs { size_mb } => VolumeDisposition::Discard {
                mounted_at: v.target.clone(),
                size_mb: *size_mb,
            },
        })
        .collect()
}

/// Facts that must hold before the cut, which this planner can detect but not
/// satisfy.
fn preconditions(
    spec: &WorkloadSpec,
    volumes: &[VolumeDisposition],
    source: &str,
    target: &str,
    to_group: &str,
) -> Vec<Precondition> {
    let mut out = Vec::new();

    // THE CROSS-GROUP SECRET PRECONDITION, and the one most likely to be
    // missed. W305 parks per-group KEKs as out of scope on the grounds that
    // CLUSTER_KEK_SLOT is one hardcoded vault slot per camp, so both groups
    // seal under the same root — true, and it is only half the story. A
    // cluster secret is read "from the local raft replica"
    // (yubaba::secrets::ClusterResolver), and a sovereign group is by
    // definition a separate raft. Same KEK, different store: the ciphertext
    // simply is not there. The workload deploys and then fails to resolve.
    let cluster_secrets: Vec<String> = spec
        .secrets
        .iter()
        .filter_map(|s| match &s.source {
            SecretRef::Cluster { name } => Some(name.clone()),
            _ => None,
        })
        .collect();
    if !cluster_secrets.is_empty() {
        out.push(Precondition {
            what: format!(
                "re-put cluster secret(s) [{}] into sovereign group '{to_group}': \
                 `yah cloud secret put <name> --machine <raft leader of {to_group}>`",
                cluster_secrets.join(", ")
            ),
            because: "a cluster secret is decrypted from the LOCAL raft replica, and a \
                      sovereign group is a separate raft. The camp KEK is shared, so the \
                      record would decrypt — but it is not replicated across groups, so \
                      it is absent. The workload deploys and then fails to start on a \
                      missing secret."
                .to_string(),
        });
    }

    for v in volumes {
        if let VolumeDisposition::Precondition {
            host_path,
            mounted_at,
        } = v
        {
            out.push(Precondition {
                what: format!(
                    "ensure {} exists on {target} with the contents {mounted_at:?} expects",
                    host_path.display()
                ),
                because: "a bind mount is an operator-managed host path. The camp did not \
                          create it and has no way to know whether it is reproducible on \
                          another box, so it is not copied automatically — an empty \
                          directory would mount cleanly and lose the data silently."
                    .to_string(),
            });
        }
    }

    // The image has to be resolvable on the target under the exact ref kamaji
    // asks for. This is not speculative: it is recorded as the live trap in
    // .yah/infra/workloads/yah-cloud-admin.toml, where pulling the plain tag
    // leaves containerd keyed on a name kamaji never requests.
    out.push(Precondition {
        what: format!(
            "pre-pull the image on {target} under the exact `repo:tag@digest` ref \
             (not the bare tag)"
        ),
        because: "automatic pulling at admission is unbuilt, and a pull of the plain tag \
                  leaves containerd's image store keyed on a name kamaji never asks for — \
                  the deploy still fails 'image not found in containerd … pre-pull \
                  required'."
            .to_string(),
    });

    // Cross-group moves cross a raft boundary and often an architecture one:
    // the prod boxes are x86 and the dev group is Pis.
    out.push(Precondition {
        what: format!(
            "confirm the image architecture matches {target} (the source is {source})"
        ),
        because: "sovereign groups in this fleet differ by hardware — prod is x86 and the \
                  dev group is aarch64 Pis — so an image that runs on the source may have \
                  no matching platform on the target."
            .to_string(),
    });

    out
}

/// Render the ordered procedure. The ordering *is* the archetype distinction —
/// see the module header for why the two halves cannot share one.
fn steps(
    workload: &str,
    stateful: bool,
    volumes: &[VolumeDisposition],
    source: Option<&MachineConfig>,
    source_name: &str,
    target: &MachineConfig,
) -> Vec<MigrationStep> {
    let mut out = Vec::new();

    let source_yubaba = source
        .and_then(|m| m.yubaba_url())
        .unwrap_or_else(|| format!("<{source_name} yubaba url>"));
    let source_ssh = source
        .and_then(|m| m.connect.as_ref().map(|c| c.ssh.clone()))
        .unwrap_or_else(|| format!("<{source_name} ssh target>"));
    let target_ssh = target
        .connect
        .as_ref()
        .map(|c| c.ssh.clone())
        .unwrap_or_else(|| format!("<{} ssh target>", target.name));

    // There is no `yah cloud workload stop`. The route exists
    // (POST /workloads/{ident}/destroy, wrapped by MeshYubabaClient::teardown)
    // but no CLI verb reaches it, and the ident is assigned server-side at
    // deploy — so the procedure looks it up rather than guessing it. Rendering
    // a `yah` command that does not exist would be worse than a curl.
    let find_ident = MigrationStep::run(
        format!("find the server-assigned ident for '{workload}' on {source_name}"),
        format!("curl -s {source_yubaba}/workloads"),
    );
    let destroy = MigrationStep::run(
        format!("stop '{workload}' on {source_name}"),
        format!("curl -X POST {source_yubaba}/workloads/<ident>/destroy"),
    );
    let deploy = MigrationStep::run(
        format!("deploy '{workload}' onto {}", target.name),
        format!("yah cloud workload deploy {workload} {}", target.name),
    );
    let health = MigrationStep::narrate(format!(
        "confirm '{workload}' is healthy on {} before doing anything else",
        target.name
    ));

    if stateful {
        // Stop → copy → start. An appliance has at most one live instance, so
        // the source must be down before the target comes up; the downtime is
        // the archetype's, not this procedure's.
        out.push(MigrationStep::narrate(format!(
            "NOTE: '{workload}' is stateful — this move takes it DOWN. The source must \
             stop before the target starts, because an appliance is defined by having at \
             most one live instance."
        )));
        out.push(find_ident);
        out.push(destroy);
        out.push(MigrationStep::narrate(
            "confirm the container is gone on the source before copying — copying a \
             volume out from under a running writer is how a half-written state file \
             reaches the target",
        ));

        for v in volumes {
            match v {
                VolumeDisposition::Copy {
                    name, host_path, ..
                } => {
                    out.push(MigrationStep::run(
                        format!("copy volume '{name}' to {}", target.name),
                        format!(
                            "rsync -aHAX --numeric-ids --delete \
                             {source_ssh}:{host_path}/ {target_ssh}:{host_path}/"
                        ),
                    ));
                }
                VolumeDisposition::Precondition { host_path, .. } => {
                    out.push(MigrationStep::narrate(format!(
                        "bind mount {} is operator-managed and is NOT copied — see \
                         preconditions",
                        host_path.display()
                    )));
                }
                VolumeDisposition::Discard {
                    mounted_at,
                    size_mb,
                } => {
                    out.push(MigrationStep::narrate(format!(
                        "tmpfs at {} ({size_mb} MiB) is discarded by design — do not copy it",
                        mounted_at.display()
                    )));
                }
            }
        }

        out.push(deploy);
        out.push(health);
        out.push(MigrationStep::narrate(format!(
            "LAST, and only after the target is verified healthy: remove the stale volume \
             data on {source_name}. Deliberately manual and deliberately last — it is the \
             one step with no undo, and keeping it is the whole rollback."
        )));
    } else {
        // Start → verify → stop. Nothing durable moves, so the new instance can
        // be proven before the old one goes away and the move costs no downtime.
        out.push(MigrationStep::narrate(format!(
            "NOTE: '{workload}' is fungible — no state moves and there is no downtime. \
             The target comes up first so it can be proven before the source is dropped."
        )));
        out.push(deploy);
        out.push(health);
        out.push(find_ident);
        out.push(destroy);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::{tempdir, TempDir};

    /// Fixtures go through `CloudConfig::load` rather than being hand-built,
    /// so every one of them is a workload TOML that would actually load —
    /// including `load_workloads`' shape validation. A struct literal would let
    /// a test pass on a spec no operator could write.
    struct Camp {
        dir: TempDir,
    }

    impl Camp {
        fn new() -> Self {
            Self {
                dir: tempdir().unwrap(),
            }
        }

        fn root(&self) -> &Path {
            self.dir.path()
        }

        /// A machine, optionally stamped into a sovereign group.
        fn machine(self, name: &str, group: Option<&str>) -> Self {
            self.machine_with(name, group, "")
        }

        fn machine_with(self, name: &str, group: Option<&str>, extra: &str) -> Self {
            let dir = self.root().join(".yah/infra/machines");
            std::fs::create_dir_all(&dir).unwrap();
            let group_line = group
                .map(|g| format!("sovereign_group = \"{g}\"\n"))
                .unwrap_or_default();
            std::fs::write(
                dir.join(format!("{name}.toml")),
                format!(
                    "name = \"{name}\"\nprovider = \"static\"\nmesh_tags = []\n\
                     {group_line}{extra}\n\
                     [connect]\naddress = \"10.0.0.1\"\nssh = \"root@{name}\"\n\
                     identity_file = \"~/.ssh/yah\"\n\
                     yubaba = \"http://{name}:7443\"\n"
                ),
            )
            .unwrap();
            self
        }

        /// A workload. `extra` carries the archetype / volumes / secrets under
        /// test; everything else is the minimum a spec needs to load.
        fn workload(self, name: &str, extra: &str) -> Self {
            let dir = self.root().join(".yah/infra/workloads");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join(format!("{name}.toml")),
                format!(
                    "schema_version = 1\nname = \"{name}\"\ntier = \"infra\"\n\
                     replicas = 1\nrestart_policy = \"always\"\n\
                     {extra}\n\
                     [image]\nregistry = \"cr.yah.dev\"\nrepository = \"{name}\"\n\
                     tag = \"v1\"\ndigest = \"sha256:abc\"\n\
                     [resources]\nmemory_mb = 128\ncpu_millis = 100\n\
                     ephemeral_storage_mb = 64\n\
                     [stop_policy]\nsignal = 15\ngrace_period = 10000\n\
                     [expose.mesh]\nidentity = \"{name}\"\nports = [8080]\nallow_from = []\n"
                ),
            )
            .unwrap();
            self
        }

        fn load(&self) -> CloudConfig {
            CloudConfig::load(self.root()).expect("fixture camp must load")
        }
    }

    const NAMED_VOLUME: &str = "[[volumes]]\nsource = { named = { name = \"pgdata\" } }\n\
                                target = \"/var/lib/postgresql\"\nread_only = false\n";

    #[test]
    fn a_named_volume_renders_the_kamaji_host_path() {
        // Pins the string duplicated from kamaji-containerd-core. If kamaji
        // moves its volume root, this fails here rather than an operator
        // rsyncing an empty directory.
        assert_eq!(
            named_volume_path("pgdata"),
            "/var/lib/yah/kamaji/volumes/pgdata"
        );
    }

    #[test]
    fn an_unknown_group_names_the_declared_vocabulary() {
        let camp = Camp::new()
            .machine("a", Some("prod"))
            .machine("b", Some("dev"))
            .workload("svc", "archetype = \"server\"");
        let cfg = camp.load();

        // A case typo is the realistic way this fires, and it must not read as
        // "the group is empty".
        let err = plan_migration(&cfg, "svc", "Dev", &["a".into()]).unwrap_err();
        let MigrationRefusal::UnknownGroup { declared, .. } = &err else {
            panic!("expected UnknownGroup, got {err:?}");
        };
        assert_eq!(declared, &["dev".to_string(), "prod".to_string()]);
        let msg = err.to_string();
        assert!(msg.contains("dev") && msg.contains("prod"), "{msg}");
    }

    #[test]
    fn an_undeployed_workload_is_refused_naming_the_deploy_verb() {
        let camp = Camp::new()
            .machine("a", Some("dev"))
            .workload("svc", "archetype = \"server\"");
        let err = plan_migration(&camp.load(), "svc", "dev", &[]).unwrap_err();
        assert!(matches!(err, MigrationRefusal::NotDeployed { .. }));
        assert!(err.to_string().contains("yah cloud workload deploy svc"));
    }

    #[test]
    fn a_workload_already_in_the_target_group_is_a_no_op() {
        let camp = Camp::new()
            .machine("a", Some("dev"))
            .machine("b", Some("prod"))
            .workload("svc", "archetype = \"server\"");
        let err = plan_migration(&camp.load(), "svc", "dev", &["a".into()]).unwrap_err();
        assert!(matches!(err, MigrationRefusal::AlreadyInGroup { .. }));
    }

    #[test]
    fn two_live_appliance_instances_are_refused_as_a_pre_existing_violation() {
        let camp = Camp::new()
            .machine("a", Some("prod"))
            .machine("b", Some("prod"))
            .machine("c", Some("dev"))
            .workload("db", &format!("archetype = \"appliance\"\n{NAMED_VOLUME}"));

        let err =
            plan_migration(&camp.load(), "db", "dev", &["a".into(), "b".into()]).unwrap_err();
        assert!(matches!(err, MigrationRefusal::MultipleSources { .. }));
        let msg = err.to_string();
        assert!(msg.contains("at most one live instance"), "{msg}");
        assert!(msg.contains("--from"), "{msg}");
    }

    #[test]
    fn a_declared_server_with_a_named_volume_is_refused_not_silently_rescheduled() {
        // The trap effective_archetype cannot catch: an explicit
        // `archetype = "server"` overrides the volume signal that would
        // otherwise have inferred Appliance, so the reschedule would come up
        // with empty storage.
        let camp = Camp::new()
            .machine("a", Some("prod"))
            .machine("b", Some("dev"))
            .workload("cache", &format!("archetype = \"server\"\n{NAMED_VOLUME}"));

        let err = plan_migration(&camp.load(), "cache", "dev", &["a".into()]).unwrap_err();
        let MigrationRefusal::FungibleWithDurableVolumes { volumes, .. } = &err else {
            panic!("expected FungibleWithDurableVolumes, got {err:?}");
        };
        assert_eq!(volumes, &["pgdata".to_string()]);
        assert!(err.to_string().contains("silently left on the source"));
    }

    #[test]
    fn a_tmpfs_on_a_fungible_workload_is_not_durable_and_does_not_refuse() {
        let camp = Camp::new().machine("a", Some("prod")).machine("b", Some("dev")).workload(
            "svc",
            "archetype = \"server\"\n[[volumes]]\n\
             source = { tmpfs = { size_mb = 64 } }\ntarget = \"/scratch\"\nread_only = false\n",
        );

        let plan =
            plan_migration(&camp.load(), "svc", "dev", &["a".into()]).expect("tmpfs is not state");
        assert!(!plan.stateful);
        assert_eq!(plan.volumes_to_copy().count(), 0);

        // The disposition is carried on the plan (and rendered) rather than
        // omitted, so nobody goes looking for the mount on the box. It is
        // deliberately NOT a step: the fungible procedure has no volume
        // action, and a step that says "do nothing" is noise in a checklist.
        assert_eq!(
            plan.volumes,
            vec![VolumeDisposition::Discard {
                mounted_at: PathBuf::from("/scratch"),
                size_mb: 64,
            }]
        );
        assert!(!plan.volumes[0].is_durable());
        assert!(plan
            .steps
            .iter()
            .any(|s| s.what.contains("no state moves")));
    }

    #[test]
    fn a_repelling_taint_in_the_target_group_refuses_through_the_admission_seam() {
        // W305 finding 2, the case this must not route around: the dev node
        // repels appliances, so a stateful migration onto it has to fail for
        // the same reason `yah cloud apply` would.
        let camp = Camp::new()
            .machine("a", Some("prod"))
            .machine_with("b", Some("dev"), "taints = [\"no-appliance\"]")
            .workload("db", &format!("archetype = \"appliance\"\n{NAMED_VOLUME}"));

        let err = plan_migration(&camp.load(), "db", "dev", &["a".into()]).unwrap_err();
        let MigrationRefusal::NoAdmissibleTarget { reason, .. } = &err else {
            panic!("expected NoAdmissibleTarget, got {err:?}");
        };
        assert!(reason.contains('b'), "must name the candidate: {reason}");
    }

    #[test]
    fn the_stateful_half_stops_before_it_copies_and_copies_before_it_starts() {
        let camp = Camp::new()
            .machine("a", Some("prod"))
            .machine("b", Some("dev"))
            .workload("db", &format!("archetype = \"appliance\"\n{NAMED_VOLUME}"));

        let plan = plan_migration(&camp.load(), "db", "dev", &["a".into()]).unwrap();
        assert!(plan.stateful && plan.incurs_downtime());
        assert_eq!(plan.volumes_to_copy().count(), 1);
        assert_eq!(plan.target_machine, "b");
        assert_eq!(plan.source_group.as_deref(), Some("prod"));

        let idx = |needle: &str| {
            plan.steps
                .iter()
                .position(|s| {
                    s.command.as_deref().unwrap_or("").contains(needle) || s.what.contains(needle)
                })
                .unwrap_or_else(|| panic!("no step matching {needle}: {:#?}", plan.steps))
        };
        let (stop, copy, start) = (idx("/destroy"), idx("rsync"), idx("workload deploy"));
        assert!(
            stop < copy && copy < start,
            "stateful ordering must be stop({stop}) → copy({copy}) → start({start})"
        );

        // The rsync must name both real SSH targets and the kamaji host path,
        // or it is not a command anyone can run.
        let rsync = plan.steps[copy].command.as_deref().unwrap();
        assert!(rsync.contains("root@a:/var/lib/yah/kamaji/volumes/pgdata/"), "{rsync}");
        assert!(rsync.contains("root@b:/var/lib/yah/kamaji/volumes/pgdata/"), "{rsync}");
    }

    #[test]
    fn the_fungible_half_starts_before_it_stops_and_never_copies() {
        let camp = Camp::new()
            .machine("a", Some("prod"))
            .machine("b", Some("dev"))
            .workload("svc", "archetype = \"server\"");

        let plan = plan_migration(&camp.load(), "svc", "dev", &["a".into()]).unwrap();
        assert!(!plan.stateful && !plan.incurs_downtime());
        assert!(
            !plan
                .steps
                .iter()
                .any(|s| s.command.as_deref().unwrap_or("").contains("rsync")),
            "the fungible half has nothing to copy"
        );

        let idx = |needle: &str| {
            plan.steps
                .iter()
                .position(|s| s.command.as_deref().unwrap_or("").contains(needle))
                .unwrap_or_else(|| panic!("no step matching {needle}: {:#?}", plan.steps))
        };
        assert!(
            idx("workload deploy") < idx("/destroy"),
            "fungible ordering must be start → stop, so the target is proven first"
        );
    }

    #[test]
    fn a_cluster_secret_raises_the_cross_group_raft_precondition() {
        // The half W305's out-of-scope note does not cover: the KEK is shared
        // across groups, the raft store is not.
        let camp = Camp::new().machine("a", Some("prod")).machine("b", Some("dev")).workload(
            "svc",
            "archetype = \"server\"\n[[secrets]]\n\
             source = { cluster = { name = \"cheers/cloud-admin/verify-key\" } }\n\
             target = { file = { path = \"/run/secrets/k\", mode = 256 } }\n",
        );

        let plan = plan_migration(&camp.load(), "svc", "dev", &["a".into()]).unwrap();
        let p = plan
            .preconditions
            .iter()
            .find(|p| p.what.contains("cluster secret"))
            .expect("cluster secret precondition must be raised");
        assert!(p.what.contains("cheers/cloud-admin/verify-key"), "{p:?}");
        assert!(p.because.contains("separate raft"), "{p:?}");
    }

    #[test]
    fn a_bind_mount_is_a_precondition_and_is_never_rsynced() {
        let camp = Camp::new().machine("a", Some("prod")).machine("b", Some("dev")).workload(
            "db",
            "archetype = \"appliance\"\n[[volumes]]\n\
             source = { bind = { host_path = \"/srv/data\" } }\n\
             target = \"/data\"\nread_only = false\n",
        );

        let plan = plan_migration(&camp.load(), "db", "dev", &["a".into()]).unwrap();
        assert_eq!(plan.volumes_to_copy().count(), 0);
        assert!(plan
            .preconditions
            .iter()
            .any(|p| p.what.contains("/srv/data")));
        assert!(
            !plan
                .steps
                .iter()
                .any(|s| s.command.as_deref().unwrap_or("").contains("/srv/data")),
            "an operator-managed host path must never be rsynced blindly"
        );
    }
}

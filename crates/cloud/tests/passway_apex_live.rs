//! Live acceptance check for the sovereign apex reconciler (R859-F1).
//!
//! R859-F1 shipped with every decision it makes covered offline and its I/O leg
//! covered nowhere: the handoff's one outstanding verify item was "run `yah
//! cloud apply` against yah.dev, then run it again and confirm it writes
//! nothing." That is a live-DNS acceptance test, and the reason it stayed
//! unrun is that the only way to perform it was to point the *writing* code
//! path at the live apex and watch.
//!
//! This is the same assertion without that. It runs the real planner
//! ([`plan_passway_apex`]) over the checked-in `.yah/` tree, reads the real
//! zone through the real `dns.record.list` verb
//! ([`list_live_apex_records`]) against the real Cloudflare account, and runs
//! the real [`diff_apex_records`] over the pair. If the diff is converged then
//! `yah cloud apply` has no write to make — which is exactly what the second
//! apply in that verify item was supposed to demonstrate, established without
//! performing the first.
//!
//! **It cannot write.** The two functions it calls are the read half of
//! `deploy_domain_passway`; the `dns.record.upsert` / `dns.record.delete` calls
//! live in the half it does not touch. So a failure here is a report, never a
//! change — which is what makes it safe to leave runnable in-tree instead of
//! described in a handoff as a thing someone should do by hand one day.
//!
//! ```text
//! cargo test --manifest-path oss/yubaba/crates/cloud/Cargo.toml \
//!   --test main -- --ignored --nocapture passway_apex_live
//! ```
//!
//! `#[ignore]`d because it needs network and the `cloudflare-mesofact-static`
//! keystore slot (`.yah/infra/providers/cloudflare.toml`), neither of which a
//! plain `cargo test` should assume.
//!
//! # What a failure means
//!
//! Not necessarily a bug. The declaration and the live zone genuinely disagree,
//! and the fix depends on which one is right:
//!
//! - **Someone edited DNS by hand** (or ran `scripts/cf-apex-mode.sh` as
//!   break-glass and left it). The reconciler is correct and an apply will
//!   converge the zone back onto the declaration — that is the whole point of
//!   R859-F1, and this failure is it doing its job loudly instead of an
//!   `apply` doing it silently.
//! - **The declaration moved and no apply has run yet.** Same verdict, opposite
//!   direction: run the apply.
//! - **The planner resolved origins the operator did not intend.** That is the
//!   real bug, and the printed plan/live/diff triple below is what tells the
//!   three cases apart — read it before running an apply.

use std::path::{Path, PathBuf};

use cloud::config::FrontDoor;
use cloud::reconciler::{diff_apex_records, list_live_apex_records, plan_passway_apex};
use cloud::CloudConfig;

/// The one passway domain this camp serves (`.yah/domains/yah-dev.toml`).
const DOMAIN: &str = "yah-dev";

/// Matches `DOMAIN_CF_PROVIDER` at the `yah cloud apply` domain-pass site —
/// domains have no `use = "<id>"` slot yet, so both sides hardcode the
/// conventional provider id.
const PROVIDER: &str = "cloudflare";

/// Walk up for the yah workspace root, exactly as `live_workspace_smoke` does —
/// returns `None` in the standalone export mirror, where there is no `.yah/`.
fn workspace_root() -> Option<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .find(|p| p.join(".yah/services").is_dir())
        .map(Path::to_path_buf)
}

#[tokio::test]
#[ignore = "live: reads the real Cloudflare zone (needs network + the cloudflare keystore slot)"]
async fn live_apex_already_matches_the_declaration() {
    let Some(root) = workspace_root() else {
        eprintln!("skipping: no .yah/services/ in any ancestor of CARGO_MANIFEST_DIR");
        return;
    };

    let cfg = CloudConfig::load(&root)
        .unwrap_or_else(|e| panic!("CloudConfig::load({}): {e:#}", root.display()));
    let dom = cfg
        .domain(DOMAIN)
        .unwrap_or_else(|| panic!("`{DOMAIN}` domain manifest missing"));

    // A break-glass rollback to the Worker door is a legitimate state, not a
    // regression — skip rather than fail, so this check can't turn an operator's
    // deliberate rollback into a red test.
    if dom.front_door != FrontDoor::Passway {
        eprintln!(
            "skipping: {DOMAIN} declares front_door = \"{}\", so the passway arm does not \
             own this apex right now",
            dom.front_door.as_str()
        );
        return;
    }

    let plan = plan_passway_apex(&root, dom)
        .unwrap_or_else(|e| panic!("planning the {} apex from declared config: {e:#}", dom.domain))
        .unwrap_or_else(|| {
            panic!(
                "no passway ingress edge collates onto {} — this camp's apex is supposed to be \
                 served by one (`yah cloud validate` should report front doors). A `None` here \
                 means the edge was removed from the declaration.",
                dom.domain
            )
        });
    let live = list_live_apex_records(&root, PROVIDER, &plan)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "reading live A records at {} through dns.record.list: {e:#}",
                dom.domain
            )
        });
    let diff = diff_apex_records(&plan, &live);

    // Printed unconditionally (`--nocapture`) — on a pass this is the record of
    // what the live apex was when the check last passed, which is the thing a
    // future operator wants when the answer changes.
    println!("zone      {} / name {}", plan.zone, plan.name);
    println!(
        "declared  {}",
        plan.origins
            .iter()
            .map(|o| format!("{} ({})", o.address, o.machine))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "live      {}",
        live.iter()
            .map(|r| format!("{}{}", r.content, if r.proxied { " [proxied]" } else { "" }))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("diff      {diff:?}");

    assert!(
        !plan.origins.is_empty(),
        "planner resolved no origins — plan_domain_passway's empty-apex guard should have \
         made this an Err, so reaching here means that guard regressed"
    );

    assert!(
        diff.is_converged(),
        "live apex at {} disagrees with the declaration — `yah cloud apply` would upsert {:?} \
         and prune {:?}. Read this file's header before applying: the declaration is not \
         automatically the right side.",
        dom.domain,
        diff.upsert,
        diff.prune
    );

    assert!(
        diff.withheld_prune.is_empty(),
        "prunes withheld at {}: {:?}. The ingress collation reported problems, so an origin's \
         absence could not be trusted as a withdrawal — run `yah cloud validate` and fix the \
         reported declaration.",
        dom.domain,
        diff.withheld_prune
    );

    // The grey door's defining property (W267), asserted directly rather than
    // inferred. Today it is redundant — `diff_apex_records` treats a proxied
    // record at a desired address as an upsert and one at any other address as
    // surplus, so a converged diff already implies no proxied record survives.
    // It is here anyway because that is an implementation detail of a function
    // this check is meant to be able to catch: if the diff ever stops counting
    // `proxied` as a mismatch, an orange apex would read as converged and this
    // is the line that would still fail.
    for record in &live {
        assert!(
            !record.proxied,
            "live A {} -> {} is PROXIED — the sovereign apex must be DNS-only (W267). \
             `scripts/cf-apex-mode.sh` orange flip left behind?",
            dom.domain, record.content
        );
    }
}

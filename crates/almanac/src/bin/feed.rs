// almanac-feed — the on-node feed-fetch tier (R330-F31).
//
// Runs one or more almanac feeds on a cadence next to the tenant's own
// `mesofact serve --revalidate` receiver: fetch from the source adapter, write
// the artifact into the workload root, and — only when the payload actually
// changed — POST the local receiver so it re-renders and republishes.
//
// Deliberately NOT a server. W225 §4 retires the standalone almanac *receiver*;
// the public `/revalidate` endpoint is mesofact's. This binary is the surviving
// *fetcher* half (R535-T2) and listens on nothing. See `almanac::fetch` for the
// full rationale.
//
// Usage:
//   almanac-feed --project-root <dir> --receiver <url> [--project-prefix <path>]
//                [--interval-secs N] --feed <feed-toml> [--feed <feed-toml> …]
//
//   --project-root  where each feed's artifact is written. On a node this is the
//                   materialized bundle's `app/` dir — the same root the
//                   receiver resolves `data_inputs` against.
//   --project-prefix workspace-relative path of the project `--project-root`
//                   materializes (e.g. `app/yah/web/marketing`). Feeds declare
//                   `emit.artifact` workspace-relative; this strips the prefix so
//                   the artifact lands where the route's `data_inputs` names it.
//                   Omit when the two roots already coincide.
//   --receiver      base URL of the local receiver, e.g. http://127.0.0.1:3001.
//   --interval-secs seconds between ticks (default 300). `0` runs one tick and
//                   exits — the shape to use from a cron/one-shot caller.
//   --feed          the literal contents of a `.yah/almanac/<name>.toml` feed
//                   definition. Repeatable. Passed by value rather than by path
//                   because the node has no copy of the camp's `.yah/` tree.
//
// Env:
//   ALMANAC_MIRROR_KEY  bearer the receiver requires. Env, not argv, so the
//                       secret never shows up in `ps`.

use std::path::PathBuf;
use std::time::Duration;

use yah_almanac::fetch::{FeedFetcher, HttpPoke, NoPoke};
use yah_almanac::FeedConfig;

const DEFAULT_INTERVAL_SECS: u64 = 300;

struct Args {
    project_root: PathBuf,
    project_prefix: Option<PathBuf>,
    receiver: Option<String>,
    interval: Duration,
    feeds: Vec<FeedConfig>,
}

fn usage() -> String {
    "usage: almanac-feed --project-root <dir> [--receiver <url>] \
     [--project-prefix <path>] [--interval-secs <n>] \
     --feed <feed-toml> [--feed <feed-toml> …]\n\
     \n\
     --receiver is required for the resident tier; omit it only with \
     --interval-secs 0 (one-shot, fetch-only: writes artifacts, pokes no one)."
        .to_string()
}

fn parse_args() -> anyhow::Result<Args> {
    let mut project_root: Option<PathBuf> = None;
    let mut project_prefix: Option<PathBuf> = None;
    let mut receiver: Option<String> = None;
    let mut interval_secs = DEFAULT_INTERVAL_SECS;
    let mut feeds = Vec::new();

    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        // Every flag here takes a value; a missing one is a deploy bug worth
        // failing loudly on rather than defaulting past.
        let mut value = || {
            argv.next()
                .ok_or_else(|| anyhow::anyhow!("{flag} needs a value\n{}", usage()))
        };
        match flag.as_str() {
            "--project-root" => project_root = Some(PathBuf::from(value()?)),
            "--project-prefix" => project_prefix = Some(PathBuf::from(value()?)),
            "--receiver" => receiver = Some(value()?),
            "--interval-secs" => {
                let raw = value()?;
                interval_secs = raw
                    .parse()
                    .map_err(|e| anyhow::anyhow!("--interval-secs {raw:?}: {e}"))?;
            }
            "--feed" => {
                let raw = value()?;
                let cfg: FeedConfig = toml::from_str(&raw)
                    .map_err(|e| anyhow::anyhow!("--feed is not a valid feed definition: {e}"))?;
                feeds.push(cfg);
            }
            "-h" | "--help" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown argument {other:?}\n{}", usage()),
        }
    }

    let project_root =
        project_root.ok_or_else(|| anyhow::anyhow!("--project-root is required\n{}", usage()))?;
    // `--receiver` is required for the RESIDENT tier (a node sidecar that
    // never pokes anyone is silent staleness), but optional for the one-shot
    // producer shape, where the caller builds and publishes the tree itself
    // and there is nothing serving yet to notify (R330-T32).
    if receiver.is_none() && interval_secs != 0 {
        anyhow::bail!(
            "--receiver is required unless --interval-secs 0 (one-shot fetch-only)\n{}",
            usage()
        );
    }
    // A fetcher with no feeds would idle forever looking healthy while nothing
    // on the node ever refreshes — the exact silent-staleness this tier exists
    // to prevent.
    if feeds.is_empty() {
        anyhow::bail!("at least one --feed is required\n{}", usage());
    }

    Ok(Args {
        project_root,
        project_prefix,
        receiver,
        interval: Duration::from_secs(interval_secs),
        feeds,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                // `almanac_feed` (this bin's own target) MUST be in the
                // default filter: the one-shot path reports why a tick failed
                // via tracing::error! from here, not from the library. With
                // only `yah_almanac=info` a CI caller saw the bare bail
                // ("feed(s) failed: releases") and no reason at all.
                .unwrap_or_else(|_| {
                    tracing_subscriber::EnvFilter::new("yah_almanac=info,almanac_feed=info")
                }),
        )
        .init();

    let args = parse_args()?;
    let mirror_key = std::env::var("ALMANAC_MIRROR_KEY").ok().filter(|k| !k.is_empty());

    tracing::info!(
        project_root = %args.project_root.display(),
        project_prefix = ?args.project_prefix,
        receiver = ?args.receiver,
        interval_secs = args.interval.as_secs(),
        feeds = ?args.feeds.iter().map(|f| f.feed.name.as_str()).collect::<Vec<_>>(),
        mirror_key = mirror_key.is_some(),
        "almanac-feed starting",
    );

    // Whether anything was actually poked is not derivable downstream: a
    // changed feed reports its route either way, because `NoPoke` still names
    // the route it would have poked. Remember it here so the one-shot summary
    // can tell the truth about it.
    let has_receiver = args.receiver.is_some();
    let poke: Box<dyn yah_almanac::fetch::RevalidatePoke> = match args.receiver {
        Some(base) => Box::new(HttpPoke::new(base, mirror_key)),
        None => Box::new(NoPoke),
    };
    let fetcher = FeedFetcher::new(
        args.feeds,
        args.project_root,
        args.project_prefix,
        poke,
    );

    if args.interval.is_zero() {
        // One-shot mode: report a failed tick through the exit code so a
        // cron/CI caller sees it.
        let mut failed = Vec::new();
        for outcome in fetcher.run_once().await {
            match (&outcome.error, &outcome.poked) {
                (Some(err), _) => {
                    tracing::error!(feed = %outcome.feed, %err, "almanac feed tick failed");
                    failed.push(outcome.feed);
                }
                // Don't claim a poke that did not happen. In one-shot mode the
                // usual caller has no receiver at all (it writes the artifact
                // and hands the tree to a build step), and "receiver poked" is
                // then exactly the wrong thing to read while working out why a
                // page did not refresh.
                (None, Some(route)) if has_receiver => {
                    tracing::info!(feed = %outcome.feed, %route, "almanac feed changed — receiver poked")
                }
                (None, Some(route)) => {
                    tracing::info!(
                        feed = %outcome.feed,
                        %route,
                        "almanac feed changed — artifact written, no receiver to poke"
                    )
                }
                // A fetch-only feed (`on_change = reload`, R707-F4) has no route
                // to poke, so it lands here even when the artifact DID change.
                // Reading "unchanged" off a tick that just rewrote the fleet
                // index is exactly the wrong thing to see while working out why
                // a consumer looks stale, so branch on `changed` rather than on
                // the absence of a poke.
                (None, None) if outcome.changed => tracing::info!(
                    feed = %outcome.feed,
                    "almanac feed changed — artifact written; this feed pokes no one, its \
                     consumer re-reads the artifact"
                ),
                (None, None) => tracing::info!(feed = %outcome.feed, "almanac feed unchanged"),
            }
        }
        if !failed.is_empty() {
            anyhow::bail!("feed(s) failed: {}", failed.join(", "));
        }
        return Ok(());
    }

    fetcher.run_forever(args.interval).await
}

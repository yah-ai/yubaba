// almanac-serve — pond-tier almanac receiver binary (R455-F2, R330-F11 re-home).
//
// Thin shell over [`almanac::serve::run`] — reads env knobs into a
// [`ServeConfig`] and hands off. In-process embedders (cloud-tier
// mesofact-runner workload, tests) call `almanac::serve::run` directly.
//
// Env knobs (all optional):
//   ALMANAC_PORT            HTTP port (default 4323)
//   ALMANAC_DIR             directory containing feed .toml files
//   ALMANAC_PROJECT_ROOT    where feed artifacts are written (default /data)
//   ALMANAC_SERVICE_ID      service id for mirror binding (e.g. "yah-marketing")
//   ALMANAC_ENV             mirror environment label (default "pond")
//   ALMANAC_MIRROR_KEY      static bearer secret for /revalidate auth

use std::path::PathBuf;

use almanac::ServeConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("almanac=info".parse()?),
        )
        .init();

    let cfg = ServeConfig {
        port: std::env::var("ALMANAC_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(4323),
        almanac_dir: std::env::var("ALMANAC_DIR").ok().map(PathBuf::from),
        project_root: PathBuf::from(
            std::env::var("ALMANAC_PROJECT_ROOT").unwrap_or_else(|_| "/data".into()),
        ),
        service_id: std::env::var("ALMANAC_SERVICE_ID").ok(),
        env_label: std::env::var("ALMANAC_ENV").unwrap_or_else(|_| "pond".into()),
        mirror_key: std::env::var("ALMANAC_MIRROR_KEY").ok(),
    };

    almanac::serve::run(cfg).await
}

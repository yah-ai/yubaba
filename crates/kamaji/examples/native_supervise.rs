//! Supervise one host binary under the Native kamaji backend — the
//! harness-facing face of `Backend::Native` (W199 shape 1, inlined).
//!
//! ```text
//! native_supervise --name cheers-auth --state-dir /tmp/kamaji \
//!     --env DATABASE_URL=/path/db.sqlite --env PORT=8745 \
//!     -- /path/to/server --flag
//! ```
//!
//! Deploys the workload, prints the `DeployResult` as one JSON line on
//! stdout, then waits. On SIGTERM/SIGINT it tears the workload down
//! (SIGTERM → grace → SIGKILL) and exits 0. If the workload exits on its
//! own first, prints the terminal state and exits 1.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use kamaji::native::NativeRuntime;
use kamaji::{Kamaji, MeshAssignment, WorkloadStatus};
use workload_spec::{
    EnvValue, EnvVar, ExposeSpec, ImageRef, MeshExpose, MeshIdent, Millis, ResourceLimits,
    RestartPolicy, SchemaVersion, StopPolicy, TierTag, WorkloadSpec,
};

fn usage() -> ! {
    eprintln!(
        "usage: native_supervise --name <ident> --state-dir <dir> [--env K=V]... [--workdir <dir>] -- <program> [args...]"
    );
    std::process::exit(2);
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1).peekable();
    let mut name = None;
    let mut state_dir = None;
    let mut env: Vec<EnvVar> = Vec::new();
    let mut workdir = None;
    let mut argv: Vec<String> = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--name" => name = args.next(),
            "--state-dir" => state_dir = args.next(),
            "--workdir" => workdir = args.next(),
            "--env" => {
                let Some(kv) = args.next() else { usage() };
                let Some((k, v)) = kv.split_once('=') else { usage() };
                env.push(EnvVar {
                    name: k.to_string(),
                    value: EnvValue::Literal { value: v.to_string() },
                });
            }
            "--" => {
                argv.extend(args.by_ref());
                break;
            }
            _ => usage(),
        }
    }
    let (Some(name), Some(state_dir)) = (name, state_dir) else { usage() };
    if argv.is_empty() {
        usage();
    }

    let spec = WorkloadSpec {
        schema_version: SchemaVersion::V1,
        name: name.clone(),
        image: ImageRef {
            registry: "localhost".into(),
            repository: format!("native/{name}"),
            tag: "dev".into(),
            digest: workload_spec::testing::test_digest(),
        },
        tier: TierTag("infra".into()),
        replicas: 1,
        command: Some(argv),
        entrypoint: None,
        workdir: workdir.map(Into::into),
        user: None,
        env,
        secrets: vec![],
        volumes: vec![],
        resources: ResourceLimits { memory_mb: 512, cpu_shares: 512, ephemeral_storage_mb: 512 },
        depends_on: vec![],
        healthcheck: None,
        restart_policy: RestartPolicy::Never,
        stop_policy: StopPolicy { signal: 15, grace_period: Millis::from_secs(5) },
        expose: ExposeSpec {
            mesh: MeshExpose {
                identity: MeshIdent(name.clone()),
                ports: vec![],
                allow_from: vec![],
            },
            public: None,
            operator: None,
        },
        labels: Default::default(),
        annotations: Default::default(),
    };

    let runtime = Arc::new(NativeRuntime::new(&state_dir));
    let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
    let ident = spec.expose.mesh.identity.clone();

    let deployed = runtime.deploy_workload(&spec, &mesh).await?;
    println!("{}", serde_json::to_string(&deployed)?);
    eprintln!("[native_supervise] {} running as pid {}", ident.0, deployed.task_pid);

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = sigterm.recv() => break,
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                let Some(state) = runtime.get_workload(&ident).await? else { break };
                if state.status.is_terminal() {
                    eprintln!("[native_supervise] workload reached terminal state: {:?}", state.status);
                    let code = i32::from(!matches!(state.status, WorkloadStatus::Stopped));
                    runtime.teardown_workload(&ident).await?;
                    std::process::exit(code);
                }
            }
        }
    }

    eprintln!("[native_supervise] shutting down {}", ident.0);
    runtime.teardown_workload(&ident).await?;
    Ok(())
}

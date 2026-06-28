use cloud::provider::MachineProvider;
use yubaba::runtime::ContainerRuntime;
use warden_test_macros::test_with_provider;
#[allow(unused, dead_code)]
async fn __inner_workload_deploy<P, R>(_p: P, _rt: R)
where
    P: MachineProvider,
    R: ContainerRuntime,
{
}
#[::tokio::test]
#[allow(non_snake_case)]
async fn workload_deploy__local() {
    let p = match cloud::provider::local_docker::LocalDockerProvider::connect().await {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "[test_with_provider] local provider unavailable (skipping {}__local): {}",
                stringify!(workload_deploy),
                e
            );
            return;
        }
    };
    let rt = match yubaba::runtime::containerd::ContainerdRuntime::connect().await {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!(
                "[test_with_provider] local runtime unavailable (skipping {}__local): {}",
                stringify!(workload_deploy),
                e
            );
            return;
        }
    };
    __inner_workload_deploy(p, rt).await;
}
#[::tokio::test]
#[ignore = "smoke tier — set YAH_SMOKE=1 and required secrets to run"]
async fn workload_deploy__smoke() {
    if ::std::env::var("YAH_SMOKE").as_deref() != Ok("1") {
        eprintln!(
            "[test_with_provider] smoke variant {}__smoke: YAH_SMOKE!=1, skipping (run with YAH_SMOKE=1 cargo test -- --ignored to exercise this tier)",
            stringify!(workload_deploy)
        );
        return;
    }
    let p = cloud::provider::hetzner::HetznerDriver::from_default_sources().expect(
        "HetznerDriver credentials missing — export HETZNER_API_TOKEN (see `yah cloud secrets` for the full credential contract)",
    );
    let rt = yubaba::runtime::DummyRuntime;
    __inner_workload_deploy(p, rt).await;
}

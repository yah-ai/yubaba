use cloud::provider::MachineProvider;
use warden::runtime::ContainerRuntime;
use warden_test_macros::test_with_provider;

#[test_with_provider(local, smoke)]
async fn workload_deploy<P, R>(_p: P, _rt: R)
where
    P: MachineProvider,
    R: ContainerRuntime,
{
}

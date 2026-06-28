//! Backend probe-at-init (R484-T3, W199 §Backend availability).
//!
//! [`BackendAvailability::probe`] connect()-tests well-known docker /
//! containerd UDS paths and reports which backends are usable. The result is
//! cached on the Kamaji instance — callers that ask for an absent backend
//! get a structured [`BackendUnavailable`] error carrying an install hint
//! instead of a panic / opaque connection error.
//!
//! The probe is **passive**: it only checks socket reachability, not the
//! gRPC / CLI handshake. A reachable socket can still belong to a broken
//! daemon; the first real call will surface that. The point here is to
//! quickly reject "docker isn't installed" / "containerd not running" so the
//! camp can show install UI before queuing a workload.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::UnixStream;
use tokio::time::timeout;

use crate::{Backend, BackendUnavailable};

/// Outcome of probing one backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendProbe {
    pub backend: Backend,
    pub available: bool,
    /// Reachable socket path when `available == true`.
    pub socket_path: Option<PathBuf>,
    /// Human-readable detail (paths tried, env var honored, etc.).
    pub detail: String,
    /// Install hint surfaced when `available == false`. `None` when the
    /// backend is available or has no install-side remediation.
    pub install_hint: Option<String>,
}

impl BackendProbe {
    fn available(backend: Backend, socket_path: PathBuf, detail: String) -> Self {
        Self {
            backend,
            available: true,
            socket_path: Some(socket_path),
            detail,
            install_hint: None,
        }
    }

    fn unavailable(backend: Backend, detail: String, install_hint: Option<String>) -> Self {
        Self {
            backend,
            available: false,
            socket_path: None,
            detail,
            install_hint,
        }
    }

    /// Convert this probe result into a [`BackendUnavailable`] when
    /// `available == false`. Returns `Ok(())` otherwise.
    pub fn require(&self) -> Result<(), BackendUnavailable> {
        if self.available {
            Ok(())
        } else {
            Err(BackendUnavailable {
                backend: self.backend,
                detail: self.detail.clone(),
                install_hint: self.install_hint.clone(),
            })
        }
    }
}

/// Result of probing every backend known to Kamaji.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendAvailability {
    pub native: BackendProbe,
    pub containerd: BackendProbe,
    pub docker: BackendProbe,
}

impl BackendAvailability {
    /// Probe every backend with default search paths. Honors
    /// `DOCKER_HOST` and `CONTAINERD_ADDRESS` when those env vars name a
    /// `unix://` socket.
    pub async fn probe() -> Self {
        let native = probe_native();
        let containerd = probe_containerd(default_containerd_paths()).await;
        let docker = probe_docker(default_docker_paths()).await;
        Self {
            native,
            containerd,
            docker,
        }
    }

    /// Look up a specific backend's probe result.
    pub fn get(&self, backend: Backend) -> &BackendProbe {
        match backend {
            Backend::Native => &self.native,
            Backend::Containerd => &self.containerd,
            Backend::Docker => &self.docker,
        }
    }

    /// Demand a specific backend is available. Returns `BackendUnavailable`
    /// with the install hint when it isn't.
    pub fn require(&self, backend: Backend) -> Result<&BackendProbe, BackendUnavailable> {
        let p = self.get(backend);
        p.require()?;
        Ok(p)
    }
}

const CONNECT_TIMEOUT: Duration = Duration::from_millis(250);

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn strip_unix_scheme(s: &str) -> &str {
    s.strip_prefix("unix://").unwrap_or(s)
}

fn default_docker_paths() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    if let Ok(env) = std::env::var("DOCKER_HOST") {
        let p = strip_unix_scheme(&env);
        if !p.is_empty() && !p.contains("://") {
            paths.push(PathBuf::from(p));
        }
    }
    paths.push(PathBuf::from("/var/run/docker.sock"));
    if let Some(home) = home_dir() {
        paths.push(home.join(".docker/run/docker.sock")); // Docker Desktop (macOS)
        paths.push(home.join(".orbstack/run/docker.sock")); // OrbStack
        paths.push(home.join(".colima/default/docker.sock")); // Colima default
        paths.push(home.join(".lima/default/sock/docker.sock")); // Lima
    }
    paths
}

fn default_containerd_paths() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    if let Ok(env) = std::env::var("CONTAINERD_ADDRESS") {
        let p = strip_unix_scheme(&env);
        if !p.is_empty() && !p.contains("://") {
            paths.push(PathBuf::from(p));
        }
    }
    paths.push(PathBuf::from("/run/containerd/containerd.sock"));
    paths.push(PathBuf::from("/var/run/containerd/containerd.sock"));
    if let Some(home) = home_dir() {
        paths.push(home.join(".colima/default/containerd.sock"));
    }
    paths
}

fn docker_install_hint() -> String {
    "Install Docker Desktop, OrbStack, or Colima (https://docs.docker.com/get-docker/)".into()
}

fn containerd_install_hint() -> String {
    "Install containerd (Linux: `apt install containerd` or equivalent; \
     macOS: `colima start --runtime containerd`)"
        .into()
}

fn probe_native() -> BackendProbe {
    // Native fork+exec is always available — no daemon to probe. The cgroup
    // + pidfd machinery the supervisor uses is Linux-only, but constructing
    // the backend itself never fails.
    BackendProbe::available(
        Backend::Native,
        PathBuf::new(),
        "native backend has no socket; fork+exec is always available".into(),
    )
}

async fn try_connect(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    matches!(
        timeout(CONNECT_TIMEOUT, UnixStream::connect(path)).await,
        Ok(Ok(_))
    )
}

async fn probe_containerd(paths: Vec<PathBuf>) -> BackendProbe {
    for path in &paths {
        if try_connect(path).await {
            return BackendProbe::available(
                Backend::Containerd,
                path.clone(),
                format!("connected to {}", path.display()),
            );
        }
    }
    let tried = paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    BackendProbe::unavailable(
        Backend::Containerd,
        format!("no containerd socket reachable (tried: {tried})"),
        Some(containerd_install_hint()),
    )
}

async fn probe_docker(paths: Vec<PathBuf>) -> BackendProbe {
    for path in &paths {
        if try_connect(path).await {
            return BackendProbe::available(
                Backend::Docker,
                path.clone(),
                format!("connected to {}", path.display()),
            );
        }
    }
    let tried = paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    BackendProbe::unavailable(
        Backend::Docker,
        format!("no docker socket reachable (tried: {tried})"),
        Some(docker_install_hint()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn native_always_available() {
        let p = probe_native();
        assert!(p.available);
        assert_eq!(p.backend, Backend::Native);
        assert!(p.install_hint.is_none());
    }

    #[tokio::test]
    async fn missing_docker_socket_yields_install_hint() {
        let tmp = TempDir::new().unwrap();
        let phantom = tmp.path().join("nope.sock");
        let p = probe_docker(vec![phantom]).await;
        assert!(!p.available);
        assert!(p.install_hint.as_deref().unwrap().contains("Docker"));
        let err = p.require().unwrap_err();
        assert_eq!(err.backend, Backend::Docker);
        assert!(err.install_hint.is_some());
    }

    #[tokio::test]
    async fn missing_containerd_socket_yields_install_hint() {
        let tmp = TempDir::new().unwrap();
        let phantom = tmp.path().join("nope.sock");
        let p = probe_containerd(vec![phantom]).await;
        assert!(!p.available);
        assert!(p.install_hint.as_deref().unwrap().contains("containerd"));
    }

    #[tokio::test]
    async fn reachable_socket_marks_available() {
        let tmp = TempDir::new().unwrap();
        let sock = tmp.path().join("test.sock");
        let _listener = UnixListener::bind(&sock).unwrap();
        let p = probe_docker(vec![sock.clone()]).await;
        assert!(p.available);
        assert_eq!(p.socket_path.as_deref(), Some(sock.as_path()));
        assert!(p.require().is_ok());
    }

    #[tokio::test]
    async fn first_reachable_path_wins() {
        let tmp = TempDir::new().unwrap();
        let missing = tmp.path().join("missing.sock");
        let present = tmp.path().join("present.sock");
        let _listener = UnixListener::bind(&present).unwrap();
        let p = probe_containerd(vec![missing, present.clone()]).await;
        assert!(p.available);
        assert_eq!(p.socket_path.as_deref(), Some(present.as_path()));
    }

    #[tokio::test]
    async fn availability_require_routes_per_backend() {
        let tmp = TempDir::new().unwrap();
        let phantom = tmp.path().join("nope.sock");
        let avail = BackendAvailability {
            native: probe_native(),
            containerd: probe_containerd(vec![phantom.clone()]).await,
            docker: probe_docker(vec![phantom]).await,
        };
        assert!(avail.require(Backend::Native).is_ok());
        let docker_err = avail.require(Backend::Docker).unwrap_err();
        assert_eq!(docker_err.backend, Backend::Docker);
        let cd_err = avail.require(Backend::Containerd).unwrap_err();
        assert_eq!(cd_err.backend, Backend::Containerd);
    }

    #[test]
    fn docker_paths_honor_docker_host_env() {
        // SAFETY: tests are single-threaded under #[test] but we still scope
        // the env mutation tightly.
        let prev = std::env::var_os("DOCKER_HOST");
        std::env::set_var("DOCKER_HOST", "unix:///tmp/explicit-docker.sock");
        let paths = default_docker_paths();
        match prev {
            Some(v) => std::env::set_var("DOCKER_HOST", v),
            None => std::env::remove_var("DOCKER_HOST"),
        }
        assert_eq!(paths.first().unwrap(), &PathBuf::from("/tmp/explicit-docker.sock"));
    }

    #[test]
    fn containerd_paths_honor_address_env() {
        let prev = std::env::var_os("CONTAINERD_ADDRESS");
        std::env::set_var("CONTAINERD_ADDRESS", "unix:///tmp/explicit-cd.sock");
        let paths = default_containerd_paths();
        match prev {
            Some(v) => std::env::set_var("CONTAINERD_ADDRESS", v),
            None => std::env::remove_var("CONTAINERD_ADDRESS"),
        }
        assert_eq!(paths.first().unwrap(), &PathBuf::from("/tmp/explicit-cd.sock"));
    }
}

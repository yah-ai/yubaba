//! End-to-end test: W164 derived-static-asset pipeline (R438-T8).
//!
//! Validates the full derive path — upstream fetch → transform → S3 upload —
//! without docker. Both the "upstream" HTTP server and the S3 bucket are served
//! by in-process axum HTTP servers.  Runs in CI unconditionally.
//!
//! ## Scenario
//!
//! Three reconciler runs against the same temporary workspace:
//!
//! **Run 1 — cold caches, empty bucket**
//! - `materialize_fetch`: cache MISS → downloads blob + writes `.yah/cache/derive/fetch/<hash>.bin`
//! - `materialize_transform`: cache MISS → `MockCopyExecutor` invoked once + output cached
//! - HEAD `test-bucket/model.bin` → 404 → PUT → `uploaded`
//!
//! **Run 2 — warm caches, full bucket**
//! - `materialize_fetch`: cache HIT → returns cached path, zero HTTP calls
//! - `materialize_transform`: cache HIT → cached path returned, executor NOT called
//! - HEAD `test-bucket/model.bin` → 200 → `already_synced`
//!
//! **Run 3 — post-prune (cache deleted, S3 object evicted)**
//! - `materialize_fetch`: cache MISS → re-downloads
//! - `materialize_transform`: cache MISS → executor invoked again
//! - BLAKE3 of re-materialized bytes **matches the declared hash** — proves
//!   determinism: `MockCopyExecutor` is a pure copy, so fixed input → fixed
//!   output.  A non-deterministic executor would surface as a hard BLAKE3
//!   mismatch error rather than silently uploading different bytes.
//! - HEAD `test-bucket/model.bin` → 404 → PUT → bytes bit-identical to run 1

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::{Path as AxumPath, Request, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Router;
use cloud::{
    MirrorConfig, MirrorProviderSlot, MirrorShape, Provider, ReconcileCtx, Reconciler,
    ServiceComponent, ServiceConfig, StaticAssetReconciler,
};
use task::executor::{ExecContext, ExecEvent, ExecOutcome, ForgeExecutor, ForgeExecutorError};
use task::{ForgeCommand, ForgeStatus};
use tempfile::tempdir;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::Mutex;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn blake3_hex(data: &[u8]) -> String {
    hex::encode(blake3::hash(data).as_bytes())
}

/// Pinned digest sentinel for test recipes — avoids bare-tag rejection by the
/// `ImageRef` parser (R438-T3).  64 hex chars, all-a's.
const TEST_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// ── MockCopyExecutor ──────────────────────────────────────────────────────────

/// `ForgeExecutor` that copies `argv[1]` (input path) to `argv[2]` (output path)
/// byte-for-byte.  Models a **deterministic, pure** transform: same input always
/// yields the same output, so the declared `blake3` in the workload can be set
/// to the upstream fetch hash.
///
/// Tracks the invocation count via a shared `Arc<Mutex<u32>>` so tests can
/// assert that cache-HITs suppress execution.
struct MockCopyExecutor {
    invocations: Arc<Mutex<u32>>,
}

impl MockCopyExecutor {
    fn new() -> (Arc<Self>, Arc<Mutex<u32>>) {
        let inv = Arc::new(Mutex::new(0u32));
        let me = Arc::new(Self { invocations: inv.clone() });
        (me, inv)
    }
}

#[async_trait]
impl ForgeExecutor for MockCopyExecutor {
    async fn execute(
        &self,
        spec: task::ForgeSpec,
        _ctx: ExecContext,
        _sink: Option<UnboundedSender<ExecEvent>>,
    ) -> Result<ExecOutcome, ForgeExecutorError> {
        *self.invocations.lock().await += 1;
        let ForgeCommand::Subprocess { argv, .. } = &spec.command else {
            return Err(ForgeExecutorError::Unsupported("mock handles Subprocess only"));
        };
        // Test recipe format: ["./copy", "<in>", "<out>"]
        let in_path = argv
            .get(1)
            .ok_or(ForgeExecutorError::Unsupported("argv[1] missing — expected input path"))?;
        let out_path = argv
            .get(2)
            .ok_or(ForgeExecutorError::Unsupported("argv[2] missing — expected output path"))?;
        let bytes = std::fs::read(in_path).map_err(ForgeExecutorError::Io)?;
        std::fs::write(out_path, &bytes).map_err(ForgeExecutorError::Io)?;
        Ok(ExecOutcome {
            status: ForgeStatus::Done { exit_code: 0, ended_at: 0 },
            stderr_tail: String::new(),
        })
    }
}

// ── Fake S3 server ────────────────────────────────────────────────────────────

type S3Store = Arc<Mutex<HashMap<String, Vec<u8>>>>;

/// Minimal S3-compatible HTTP handler.  Ignores SigV4 auth headers — the fake
/// server only cares about method × path.
///
/// - `GET /*path`  → returns stored bytes or 404.
/// - `HEAD /*path` → 200 if key present, 404 otherwise.
/// - `PUT /*path`  → stores request body, returns 200.
async fn s3_handler(
    State(store): State<S3Store>,
    AxumPath(path): AxumPath<String>,
    request: Request,
) -> impl IntoResponse {
    let method = request.method().clone();
    let body = axum::body::to_bytes(request.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap_or_default();

    match method.as_str() {
        "GET" => {
            let store = store.lock().await;
            match store.get(&path) {
                Some(data) => (StatusCode::OK, Bytes::from(data.clone())).into_response(),
                None => StatusCode::NOT_FOUND.into_response(),
            }
        }
        "HEAD" => {
            let store = store.lock().await;
            if store.contains_key(&path) {
                StatusCode::OK.into_response()
            } else {
                StatusCode::NOT_FOUND.into_response()
            }
        }
        "PUT" => {
            store.lock().await.insert(path, body.to_vec());
            StatusCode::OK.into_response()
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

async fn start_fake_s3() -> (u16, S3Store) {
    let store: S3Store = Arc::new(Mutex::new(HashMap::new()));
    let app = Router::new()
        .route("/{*path}", axum::routing::any(s3_handler))
        .with_state(store.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (port, store)
}

/// Serves deterministic `bytes` at `/blob.bin`.
async fn start_fake_upstream(bytes: Vec<u8>) -> String {
    let bytes = Arc::new(bytes);
    let app = Router::new().route(
        "/blob.bin",
        axum::routing::get(move || {
            let b = bytes.clone();
            async move { Bytes::from(b.as_ref().clone()) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}/blob.bin")
}

// ── Test workspace ────────────────────────────────────────────────────────────

struct TestWorkspace {
    _tmp: tempfile::TempDir,
    workspace_root: std::path::PathBuf,
    service: ServiceConfig,
    component: ServiceComponent,
    mirror: MirrorConfig,
}

impl TestWorkspace {
    fn new(s3_port: u16) -> Self {
        let tmp = tempdir().unwrap();
        let workspace_root = tmp.path().to_path_buf();
        std::fs::create_dir_all(workspace_root.join("app/assets/model")).unwrap();

        let mut fields = BTreeMap::new();
        fields.insert("api_port".to_string(), toml::Value::Integer(s3_port as i64));
        fields.insert("bucket".to_string(), toml::Value::String("test-bucket".to_string()));
        let mut providers = BTreeMap::new();
        providers.insert(
            "object_store".to_string(),
            MirrorProviderSlot::Inline {
                kind: Provider::MinioContainer,
                fields,
            },
        );

        Self {
            service: ServiceConfig {
                schema_version: 1,
                name: "test-svc".to_string(),
                domain: "test.local".to_string(),
                components: vec![],
            },
            component: ServiceComponent {
                id: "model-assets".to_string(),
                kind: "static-asset".to_string(),
                path: "app/assets/model".to_string(),
                role: "assets".to_string(),
                publishes: None,
                wave: 0,
            },
            mirror: MirrorConfig {
                schema_version: 1,
                shape: MirrorShape::Local,
                providers,
                asset_aliases: BTreeMap::new(),
            },
            workspace_root,
            _tmp: tmp,
        }
    }

    fn ctx(&self) -> ReconcileCtx<'_> {
        ReconcileCtx {
            workspace_root: &self.workspace_root,
            service: &self.service,
            component: &self.component,
            mirror: &self.mirror,
            env: "test",
        }
    }

    /// Write `app/assets/model/workload.toml` with a single derive-mode asset.
    /// The transform recipe is `test-copy` (written by `write_recipe`).
    fn write_workload(&self, upstream_url: &str, fetch_hash: &str, output_hash: &str) {
        let content = format!(
            r#"kind = "static-asset"
schema_version = "V1"

[[asset]]
filename = "model.bin"
blake3 = "{output_hash}"

[asset.derive.fetch]
url     = "{upstream_url}"
blake3  = "{fetch_hash}"
license = "mit"

[asset.derive.transform]
recipe = "test-copy"
params = {{}}
"#
        );
        std::fs::write(
            self.workspace_root.join("app/assets/model/workload.toml"),
            content,
        )
        .unwrap();
    }

    /// Write `.yah/qed/transforms/test-copy.toml`.
    ///
    /// The recipe uses a 3-element argv so `MockCopyExecutor` can extract
    /// in-path (`argv[1]`) and out-path (`argv[2]`) without shell interpretation.
    fn write_recipe(&self) {
        let dir = self.workspace_root.join(".yah/qed/transforms");
        std::fs::create_dir_all(&dir).unwrap();
        let content = format!(
            r#"name  = "test-copy"
label = "copy input to output (test fixture)"
image = "ghcr.io/test/copy:v1@sha256:{TEST_DIGEST}"

[placement]
location = "local"
runtime  = "container"

[[steps]]
name = "copy"
argv = ["./copy", "{{{{YAH_TRANSFORM_IN_0}}}}", "{{{{YAH_TRANSFORM_OUT}}}}"]
"#
        );
        std::fs::write(dir.join("test-copy.toml"), content).unwrap();
    }

    /// Delete the derive cache so the next run is fully cold.
    fn delete_derive_cache(&self) {
        let cache = self.workspace_root.join(".yah/cache/derive");
        std::fs::remove_dir_all(&cache).ok();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Full W164 derive pipeline: upload → skip → prune → reproducible re-upload.
///
/// See module-level doc for the three-run scenario.
#[tokio::test]
async fn derive_pipeline_upload_skip_prune_reproducibility() {
    let upstream_body = b"deterministic-fake-fp16-model-content-for-derive-e2e";
    let fetch_hash = blake3_hex(upstream_body);
    // MockCopyExecutor outputs bytes identical to input, so output hash = fetch hash.
    let output_hash = fetch_hash.clone();

    let upstream_url = start_fake_upstream(upstream_body.to_vec()).await;
    let (s3_port, s3_store) = start_fake_s3().await;

    let ws = TestWorkspace::new(s3_port);
    ws.write_recipe();
    ws.write_workload(&upstream_url, &fetch_hash, &output_hash);

    let (mock, inv) = MockCopyExecutor::new();

    // ── Run 1: cold caches, empty bucket ─────────────────────────────────────
    StaticAssetReconciler::new()
        .with_executor(mock.clone() as Arc<dyn ForgeExecutor>)
        .up(ws.ctx())
        .await
        .expect("run 1 must succeed");

    assert_eq!(*inv.lock().await, 1, "executor invoked exactly once on cold MISS");
    {
        let s = s3_store.lock().await;
        let keys: Vec<_> = s.keys().collect();
        assert!(
            s.contains_key("test-bucket/model.bin"),
            "model.bin must be PUT after run 1; S3 keys: {keys:?}",
        );
        let uploaded_hash = blake3_hex(s.get("test-bucket/model.bin").unwrap());
        assert_eq!(
            uploaded_hash, output_hash,
            "uploaded bytes must match declared BLAKE3",
        );
    }

    // ── Run 2: warm caches, full bucket ──────────────────────────────────────
    StaticAssetReconciler::new()
        .with_executor(mock.clone() as Arc<dyn ForgeExecutor>)
        .up(ws.ctx())
        .await
        .expect("run 2 must succeed");

    // Invocation count must not increase — both caches were HIT.
    assert_eq!(
        *inv.lock().await,
        1,
        "executor must NOT be re-invoked when both fetch and transform caches hit",
    );

    // ── Run 3: prune derive cache + evict S3 object → re-upload ──────────────
    ws.delete_derive_cache();
    s3_store.lock().await.remove("test-bucket/model.bin");

    let (mock3, inv3) = MockCopyExecutor::new();
    StaticAssetReconciler::new()
        .with_executor(mock3 as Arc<dyn ForgeExecutor>)
        .up(ws.ctx())
        .await
        .expect("post-prune run must succeed");

    assert_eq!(*inv3.lock().await, 1, "executor re-invoked after prune (fresh cold MISS)");
    {
        let s = s3_store.lock().await;
        let re_uploaded = s
            .get("test-bucket/model.bin")
            .expect("model.bin must be re-uploaded after prune + S3 eviction");
        let re_hash = blake3_hex(re_uploaded);
        assert_eq!(
            re_hash, output_hash,
            "re-uploaded bytes must have identical BLAKE3 — reproducibility verified",
        );
    }
}

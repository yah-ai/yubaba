//! @arch:layer(core)
//! @arch:role(net)
//!
//! **Hosted-camp push dispatch** — W122:205's "yubaba cloud users: yubaba
//! itself holds the FCM creds and dispatches pushes", for the camps
//! [`crate::hosted_camps`] enumerates.
//!
//! Part of R726-F9 under relay R726.
//!
//! ## Why this speaks a protocol instead of calling a crate
//!
//! The FCM sender, the device-token store and the relay's accept loop
//! already exist in the monorepo's `crates/yah/push-relay` (R726-F7).
//! **yubaba cannot depend on it**, and that is a structural fact rather
//! than a preference: `oss/yubaba` is an independent Cargo workspace that
//! has to resolve standalone from crates.io when `scripts/export-oss.sh`
//! pushes the mirror (yah CLAUDE.md §"Co-developed OSS repos"), every one
//! of its cross-repo deps points at a sibling `oss/*` crate, and
//! `push-relay` is `publish = false`. A path dep into `crates/yah/` would
//! break the export the first time anyone ran it.
//!
//! So the seam is the wire, exactly as [`crate::camp_rpc`] mirrors
//! `rpc-ssh`'s ALPN rather than sharing a crate with it. yubaba speaks
//! `push-relay`'s protocol as a client; the relay keeps doing the FCM
//! work. **Nothing here re-implements FCM** — there is no OAuth
//! assertion, no service-account parse and no `fcm.googleapis.com` call
//! in this file, and there should never be one.
//!
//! ## Where the credential lives
//!
//! "yubaba holds the FCM creds" is about the *deployment*, not the
//! process: for a cloud camp the relay is co-located on the yubaba node,
//! so the service account sits on that machine and no camp ever holds
//! one. [`PushDispatchConfig::fcm_credentials`] is the operator's
//! declaration of which secret slot that is — a `keystore://<slot>` URI,
//! the same convention `yah-cloud`'s provider configs use, resolved
//! against [`crate::secrets::SECRET_STORE_ROOT`] like any other
//! per-machine yubaba secret. yubaba validates and reports the reference;
//! it never reads the bytes, because the process that needs them is the
//! relay.
//!
//! ## Mirrored constants
//!
//! [`PUSH_RELAY_ALPN_STR`], [`PushFrame`] and [`MobilePushPayload`] are
//! **mirrors** of `push_relay::protocol` / `rpc::MobilePushPayload`. A
//! mismatch fails at ALPN negotiation or as a relay-side parse error — if
//! you change a spelling on one side, change it here too. The tests below
//! pin the serialized form for exactly that reason.
//!
//! ## What is untested here
//!
//! The live send is **not** exercised: this camp holds no FCM
//! service-account credential, so no test in this file reaches Google.
//! What is tested is the request shape against a mock transport, which is
//! the half that drifts. Treat "a real device received a notification" as
//! unverified until someone runs it with a credential.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader};

/// ALPN of the relay protocol. **Mirrored** from
/// `push_relay::protocol::PUSH_RELAY_ALPN_STR`.
pub const PUSH_RELAY_ALPN_STR: &str = "yah/push-relay/1";

/// See [`PUSH_RELAY_ALPN_STR`].
pub const PUSH_RELAY_ALPN: &[u8] = PUSH_RELAY_ALPN_STR.as_bytes();

/// Largest frame either direction. Mirrors
/// `push_relay::protocol::MAX_FRAME_BYTES`.
pub const MAX_FRAME_BYTES: usize = 16 * 1024;

/// Characters of agent text allowed to leave the node in a push. Mirrors
/// `rpc::MOBILE_PUSH_PREVIEW_MAX`.
pub const MOBILE_PUSH_PREVIEW_MAX: usize = 120;

/// Prefix of a credential reference, matching the convention
/// `yah-cloud`'s `ProviderConfig::credentials` uses.
pub const KEYSTORE_SCHEME: &str = "keystore://";

// ── Wire types (mirrored — see the module header) ────────────────────────────

/// What a push is about. One variant today; an enum rather than a bool so
/// the Kotlin side can switch on it as new kinds land.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MobilePushKind {
    Gate,
}

/// The entire push payload (W122:179-191). Mirrors
/// `rpc::MobilePushPayload`, including its deliberate lack of a
/// `rename_all`: the field names are the keys the FCM data message and
/// the Android deep-link builder read, so they are plain snake_case.
///
/// Six fields and no free-form map is the point — there is nowhere for a
/// tool's arguments to be smuggled out of the camp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobilePushPayload {
    pub kind: MobilePushKind,
    pub camp_id: String,
    pub session_id: String,
    pub gate_id: String,
    /// Tool *name* only — never its arguments.
    pub tool: String,
    /// At most [`MOBILE_PUSH_PREVIEW_MAX`] characters. Build through
    /// [`MobilePushPayload::gate`], which truncates; a struct literal
    /// bypasses the guarantee this type exists for.
    pub preview: String,
}

impl MobilePushPayload {
    pub fn gate(
        camp_id: impl Into<String>,
        session_id: impl Into<String>,
        gate_id: impl Into<String>,
        tool: impl Into<String>,
        preview: &str,
    ) -> Self {
        Self {
            kind: MobilePushKind::Gate,
            camp_id: camp_id.into(),
            session_id: session_id.into(),
            gate_id: gate_id.into(),
            tool: tool.into(),
            preview: truncate_push_preview(preview),
        }
    }
}

/// Truncate to [`MOBILE_PUSH_PREVIEW_MAX`] **characters** (a byte slice
/// would panic mid-codepoint), collapsing newlines so the notification
/// renders on one line. Mirrors `rpc::truncate_push_preview`.
pub fn truncate_push_preview(text: &str) -> String {
    let one_line: String = text
        .chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect();
    let trimmed = one_line.trim();
    if trimmed.chars().count() <= MOBILE_PUSH_PREVIEW_MAX {
        return trimmed.to_string();
    }
    trimmed.chars().take(MOBILE_PUSH_PREVIEW_MAX).collect()
}

/// The one request this side sends — `push_relay::protocol::RelayRequest`
/// is internally tagged on `op`, so a struct carrying `op: "push"`
/// serializes to bytes the relay deserializes into its `Push` variant.
///
/// Register / unregister are deliberately absent: a device registers
/// itself with the relay, and a node that could forge registrations on a
/// camp's behalf is a wider blast radius than this lane needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushFrame {
    /// Always [`PUSH_OP`].
    pub op: String,
    pub camp_id: String,
    /// Narrows the fanout to one identity's devices. `None` means every
    /// device registered on the camp, which is what a gate raised by an
    /// agent rather than by a person amounts to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    pub payload: MobilePushPayload,
}

/// The `op` tag value of `push_relay::protocol::RelayRequest::Push`.
pub const PUSH_OP: &str = "push";

impl PushFrame {
    pub fn new(camp_id: impl Into<String>, payload: MobilePushPayload) -> Self {
        Self {
            op: PUSH_OP.to_string(),
            camp_id: camp_id.into(),
            user_id: None,
            payload,
        }
    }

    pub fn for_user(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }
}

/// What the relay answered. Mirrors the arms of
/// `push_relay::protocol::RelayResponse` this side can receive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum PushOutcome {
    Pushed {
        /// Devices FCM accepted the message for.
        delivered: usize,
        /// Tokens FCM reported dead, now dropped from the relay's store.
        pruned: usize,
        /// Sends that failed for some other reason. Non-zero means a gate
        /// may have gone unannounced.
        failed: usize,
    },
    Error {
        message: String,
    },
    /// An answer to an op this side never sends. Kept as a variant so a
    /// relay newer than this node is a legible response rather than a
    /// parse error.
    #[serde(other)]
    Unexpected,
}

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum PushError {
    #[error("push relay address: {0}")]
    Address(String),
    #[error("push relay dial: {0}")]
    Dial(String),
    #[error("push relay transport: {0}")]
    Io(String),
    #[error("push relay frame: {0}")]
    Frame(String),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("push relay refused: {0}")]
    Refused(String),
    #[error("{0}")]
    Config(String),
}

// ── Configuration ────────────────────────────────────────────────────────────

/// Where the relay is and which credential slot backs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushDispatchConfig {
    /// Hex `NodeId` of the relay process. For a cloud camp this is
    /// normally this same machine — co-location is a deployment fact, not
    /// a different code path.
    pub node_id: String,
    /// Direct addresses to try before the relay lane.
    #[serde(default)]
    pub direct_addrs: Vec<SocketAddr>,
    /// Pins the relay's iroh relay home, when the operator runs one.
    #[serde(default)]
    pub relay_url: Option<String>,
    /// `keystore://<slot>` naming the FCM service-account JSON the
    /// co-located relay reads. Declarative: yubaba validates the shape
    /// and reports it, and never reads the secret — see the module
    /// header.
    #[serde(default)]
    pub fcm_credentials: Option<String>,
}

impl PushDispatchConfig {
    pub fn new(node_id: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            direct_addrs: Vec::new(),
            relay_url: None,
            fcm_credentials: None,
        }
    }

    pub fn with_fcm_credentials(mut self, uri: impl Into<String>) -> Self {
        self.fcm_credentials = Some(uri.into());
        self
    }

    /// The store-relative key [`crate::secrets::LocalFileResolver`] would
    /// read the service account from, or `None` when the operator
    /// declared no credential.
    ///
    /// Rejects anything that is not a flat kebab-case slot, matching
    /// `yah-cloud`'s `CfProvider::parse_uri`: a slot containing `/` or
    /// `..` would walk out of the secret store, and one that is empty
    /// names nothing.
    pub fn fcm_credential_slot(&self) -> Result<Option<String>, PushError> {
        let Some(uri) = self.fcm_credentials.as_deref() else {
            return Ok(None);
        };
        let slot = uri.strip_prefix(KEYSTORE_SCHEME).ok_or_else(|| {
            PushError::Config(format!(
                "fcm credentials {uri:?} must be a `{KEYSTORE_SCHEME}<slot>` URI"
            ))
        })?;
        if slot.is_empty() || slot.contains('/') || slot.contains("..") {
            return Err(PushError::Config(format!(
                "fcm credentials {uri:?} — slot must be a flat kebab-case name \
                 (e.g. `{KEYSTORE_SCHEME}fcm-service-account`)"
            )));
        }
        Ok(Some(slot.to_string()))
    }

    /// Resolve to the address mshr dials, failing on a malformed NodeId
    /// or relay URL here rather than at connect time.
    pub fn endpoint_addr(
        &self,
        endpoint_resolves_bare_node_ids: bool,
    ) -> Result<mshr::EndpointAddr, PushError> {
        let node_id = mshr::NodeId::from_str(self.node_id.trim()).map_err(|e| {
            PushError::Address(format!("malformed NodeId {:?}: {e}", self.node_id))
        })?;
        let mut addr = mshr::EndpointAddr::new(node_id);
        if let Some(url) = &self.relay_url {
            let relay: mshr::RelayUrl = url
                .parse()
                .map_err(|e| PushError::Address(format!("malformed relay url {url:?}: {e}")))?;
            addr = addr.with_relay_url(relay);
        }
        for direct in &self.direct_addrs {
            addr = addr.with_ip_addr(*direct);
        }
        if addr.is_empty() && !endpoint_resolves_bare_node_ids {
            return Err(PushError::Address(format!(
                "push relay {} has neither a direct address nor a relay url, and this node's \
                 mshr endpoint has no discovery lane — a bare NodeId cannot be resolved.",
                self.node_id
            )));
        }
        Ok(addr)
    }
}

// ── Transport seam ───────────────────────────────────────────────────────────

/// One request frame in, one response frame out.
///
/// A trait rather than a concrete mshr dial so the request shape is
/// testable without a relay, an endpoint, or an FCM credential — which
/// this camp does not have. Both sides are whole newline-free JSON lines;
/// the framing newline is the transport's business.
#[async_trait::async_trait]
pub trait PushTransport: Send + Sync {
    async fn call(&self, frame: &str) -> Result<String, PushError>;
}

/// The real transport: one QUIC connection per push over mshr.
///
/// A fresh connection per call rather than a pool, for the reason
/// `push_relay::client` gives: gates are human-paced, and a long-lived
/// connection from every node to the relay is a connection table the
/// relay would have to bound for throughput it never sees.
pub struct MshrPushTransport {
    endpoint: mshr::Endpoint,
    addr: mshr::EndpointAddr,
}

impl MshrPushTransport {
    /// Build on an endpoint this process already owns, so the node keeps
    /// one NodeId and one UDP socket.
    pub fn new(endpoint: mshr::Endpoint, config: &PushDispatchConfig) -> Result<Self, PushError> {
        let addr = config.endpoint_addr(endpoint.resolves_bare_node_ids())?;
        Ok(Self { endpoint, addr })
    }
}

#[async_trait::async_trait]
impl PushTransport for MshrPushTransport {
    async fn call(&self, frame: &str) -> Result<String, PushError> {
        let conn = self
            .endpoint
            .connect_alpn(self.addr.clone(), PUSH_RELAY_ALPN)
            .await
            .map_err(|e| PushError::Dial(format!("{}: {e}", self.addr.id)))?;

        let (mut send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| PushError::Io(format!("open_bi: {e}")))?;

        let mut bytes = frame.as_bytes().to_vec();
        bytes.push(b'\n');
        send.write_all(&bytes)
            .await
            .map_err(|e| PushError::Io(format!("writing request: {e}")))?;
        send.finish()
            .map_err(|e| PushError::Io(format!("finishing request stream: {e}")))?;

        let mut reader = BufReader::new(recv);
        let line = read_capped_line(&mut reader).await?;
        conn.close(0u32.into(), b"done");
        line.ok_or_else(|| PushError::Frame("relay closed before answering".into()))
    }
}

/// Read one newline-terminated frame, refusing anything over
/// [`MAX_FRAME_BYTES`]. An uncapped `read_line` against a broken or
/// hostile peer is an unbounded allocation.
///
/// Same shape as [`crate::camp_rpc`]'s hello reader — `fill_buf` /
/// `consume` rather than `read_line`, so the cap is checked as bytes
/// arrive instead of after the allocation has already happened.
async fn read_capped_line<R>(reader: &mut R) -> Result<Option<String>, PushError>
where
    R: AsyncBufRead + Unpin,
{
    let mut out: Vec<u8> = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|e| PushError::Io(format!("reading response: {e}")))?;
        if available.is_empty() {
            return Ok(if out.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(&out).into_owned())
            });
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            out.extend_from_slice(&available[..pos]);
            reader.consume(pos + 1);
            return Ok(Some(String::from_utf8_lossy(&out).into_owned()));
        }
        let taken = available.len();
        out.extend_from_slice(available);
        reader.consume(taken);
        if out.len() > MAX_FRAME_BYTES {
            return Err(PushError::Frame(format!(
                "response frame exceeded {MAX_FRAME_BYTES} bytes without a newline"
            )));
        }
    }
}

// ── The dispatcher ───────────────────────────────────────────────────────────

/// Sends a hosted camp's gates to the relay that fans them out.
///
/// Holds no credential and no device table: both belong to the relay, and
/// keeping them there is what lets a camp — or a node hosting one — be
/// compromised without taking the FCM service account with it.
pub struct PushDispatcher {
    config: PushDispatchConfig,
    transport: Arc<dyn PushTransport>,
}

impl PushDispatcher {
    pub fn new(config: PushDispatchConfig, transport: Arc<dyn PushTransport>) -> Self {
        Self { config, transport }
    }

    /// Build the production dispatcher on an endpoint this node owns.
    pub fn over_mshr(
        endpoint: mshr::Endpoint,
        config: PushDispatchConfig,
    ) -> Result<Self, PushError> {
        // Validate the credential reference at construction, not at the
        // first gate: a typo'd slot that only surfaces the first time
        // someone is waiting on an approval is the worst possible time to
        // learn about it.
        config.fcm_credential_slot()?;
        let transport = MshrPushTransport::new(endpoint, &config)?;
        Ok(Self::new(config, Arc::new(transport)))
    }

    pub fn config(&self) -> &PushDispatchConfig {
        &self.config
    }

    /// Fan a gate out to every device registered on `camp_id`.
    ///
    /// `camp_id` is a [`crate::hosted_camps::HostedCamp::id`] — the same
    /// id `/camps` published and the phone registered its token under, so
    /// the two sides agree without a second mapping table.
    pub async fn notify_gate(
        &self,
        camp_id: &str,
        session_id: &str,
        gate_id: &str,
        tool: &str,
        preview: &str,
    ) -> Result<PushOutcome, PushError> {
        let payload = MobilePushPayload::gate(camp_id, session_id, gate_id, tool, preview);
        self.send(PushFrame::new(camp_id, payload)).await
    }

    /// Same, narrowed to one identity's devices.
    pub async fn notify_gate_for_user(
        &self,
        camp_id: &str,
        user_id: &str,
        session_id: &str,
        gate_id: &str,
        tool: &str,
        preview: &str,
    ) -> Result<PushOutcome, PushError> {
        let payload = MobilePushPayload::gate(camp_id, session_id, gate_id, tool, preview);
        self.send(PushFrame::new(camp_id, payload).for_user(user_id))
            .await
    }

    /// Serialize, send, parse. `Error` from the relay becomes
    /// [`PushError::Refused`] rather than an `Ok` a caller could ignore.
    async fn send(&self, frame: PushFrame) -> Result<PushOutcome, PushError> {
        let line = serde_json::to_string(&frame)?;
        debug_assert!(!line.contains('\n'), "frames are newline-delimited");
        let response = self.transport.call(&line).await?;
        match serde_json::from_str::<PushOutcome>(response.trim())? {
            PushOutcome::Error { message } => Err(PushError::Refused(message)),
            other => Ok(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Records what was sent and replays a canned answer. This is the
    /// whole of the test rig: no endpoint, no relay, no credential.
    struct MockTransport {
        sent: Mutex<Vec<String>>,
        reply: String,
    }

    impl MockTransport {
        fn replying(reply: &str) -> Arc<Self> {
            Arc::new(Self {
                sent: Mutex::new(Vec::new()),
                reply: reply.to_string(),
            })
        }

        fn last(&self) -> String {
            self.sent.lock().unwrap().last().cloned().expect("a send")
        }
    }

    #[async_trait::async_trait]
    impl PushTransport for MockTransport {
        async fn call(&self, frame: &str) -> Result<String, PushError> {
            self.sent.lock().unwrap().push(frame.to_string());
            Ok(self.reply.clone())
        }
    }

    fn dispatcher(mock: Arc<MockTransport>) -> PushDispatcher {
        PushDispatcher::new(PushDispatchConfig::new("ab".repeat(32)), mock)
    }

    #[tokio::test]
    async fn gate_push_serializes_to_the_relays_push_frame() {
        let mock = MockTransport::replying(
            r#"{"result":"pushed","delivered":2,"pruned":0,"failed":0}"#,
        );
        let out = dispatcher(mock.clone())
            .notify_gate("camp-a", "sess-1", "gate-7", "Bash", "ls -la")
            .await
            .unwrap();
        assert_eq!(
            out,
            PushOutcome::Pushed {
                delivered: 2,
                pruned: 0,
                failed: 0
            }
        );

        let sent: serde_json::Value = serde_json::from_str(&mock.last()).unwrap();
        assert_eq!(sent["op"], "push");
        assert_eq!(sent["camp_id"], "camp-a");
        // Absent, not null: the relay's `user_id` is
        // `skip_serializing_if = "Option::is_none"` on both sides.
        assert!(sent.get("user_id").is_none());
        assert_eq!(sent["payload"]["kind"], "gate");
        assert_eq!(sent["payload"]["camp_id"], "camp-a");
        assert_eq!(sent["payload"]["session_id"], "sess-1");
        assert_eq!(sent["payload"]["gate_id"], "gate-7");
        assert_eq!(sent["payload"]["tool"], "Bash");
        assert_eq!(sent["payload"]["preview"], "ls -la");
    }

    #[tokio::test]
    async fn a_user_scoped_push_carries_the_user_id() {
        let mock =
            MockTransport::replying(r#"{"result":"pushed","delivered":1,"pruned":0,"failed":0}"#);
        dispatcher(mock.clone())
            .notify_gate_for_user("camp-a", "user-9", "s", "g", "Edit", "src/lib.rs")
            .await
            .unwrap();
        let sent: serde_json::Value = serde_json::from_str(&mock.last()).unwrap();
        assert_eq!(sent["user_id"], "user-9");
    }

    #[tokio::test]
    async fn the_payload_never_carries_more_than_the_six_fields() {
        let mock =
            MockTransport::replying(r#"{"result":"pushed","delivered":0,"pruned":0,"failed":0}"#);
        dispatcher(mock.clone())
            .notify_gate("c", "s", "g", "Bash", "rm -rf /tmp/x")
            .await
            .unwrap();
        let sent: serde_json::Value = serde_json::from_str(&mock.last()).unwrap();
        let payload = sent["payload"].as_object().unwrap();
        let mut keys: Vec<&str> = payload.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(
            keys,
            vec!["camp_id", "gate_id", "kind", "preview", "session_id", "tool"],
            "a seventh field is a channel for tool arguments to leave the camp"
        );
    }

    #[tokio::test]
    async fn preview_is_truncated_and_flattened_on_the_send_path() {
        let mock =
            MockTransport::replying(r#"{"result":"pushed","delivered":0,"pruned":0,"failed":0}"#);
        let long = format!("first\nsecond {}", "x".repeat(400));
        dispatcher(mock.clone())
            .notify_gate("c", "s", "g", "Bash", &long)
            .await
            .unwrap();
        let sent: serde_json::Value = serde_json::from_str(&mock.last()).unwrap();
        let preview = sent["payload"]["preview"].as_str().unwrap();
        assert_eq!(preview.chars().count(), MOBILE_PUSH_PREVIEW_MAX);
        assert!(!preview.contains('\n'));
        assert!(preview.starts_with("first second "));
    }

    #[tokio::test]
    async fn a_relay_error_is_an_error_not_a_silent_ok() {
        let mock = MockTransport::replying(r#"{"result":"error","message":"no such camp"}"#);
        let err = dispatcher(mock)
            .notify_gate("c", "s", "g", "Bash", "ls")
            .await
            .unwrap_err();
        assert!(matches!(err, PushError::Refused(m) if m == "no such camp"), );
    }

    #[tokio::test]
    async fn an_unknown_result_tag_parses_rather_than_exploding() {
        let mock = MockTransport::replying(r#"{"result":"registered","app_install_id":"i","replaced":false}"#);
        let out = dispatcher(mock)
            .notify_gate("c", "s", "g", "Bash", "ls")
            .await
            .unwrap();
        assert_eq!(out, PushOutcome::Unexpected);
    }

    #[test]
    fn keystore_uris_resolve_to_a_flat_slot() {
        let cfg = PushDispatchConfig::new("ab".repeat(32))
            .with_fcm_credentials("keystore://fcm-service-account");
        assert_eq!(
            cfg.fcm_credential_slot().unwrap().as_deref(),
            Some("fcm-service-account")
        );
    }

    #[test]
    fn no_credential_declared_is_not_an_error() {
        let cfg = PushDispatchConfig::new("ab".repeat(32));
        assert_eq!(cfg.fcm_credential_slot().unwrap(), None);
    }

    #[test]
    fn a_credential_that_is_not_a_keystore_uri_is_refused() {
        for bad in [
            "/etc/fcm.json",
            "keystore://",
            "keystore://cloudflare/yah",
            "keystore://../../etc/shadow",
        ] {
            let cfg = PushDispatchConfig::new("ab".repeat(32)).with_fcm_credentials(bad);
            assert!(
                cfg.fcm_credential_slot().is_err(),
                "{bad:?} should not resolve to a slot"
            );
        }
    }

    #[test]
    fn a_malformed_node_id_fails_before_any_dial() {
        let cfg = PushDispatchConfig::new("not-a-node-id");
        assert!(matches!(
            cfg.endpoint_addr(true),
            Err(PushError::Address(_))
        ));
    }

    #[test]
    fn the_payload_wire_form_round_trips() {
        let p = MobilePushPayload::gate("c", "s", "g", "Bash", "ls");
        let line = serde_json::to_string(&p).unwrap();
        let back: MobilePushPayload = serde_json::from_str(&line).unwrap();
        assert_eq!(back, p);
        assert_eq!(serde_json::to_string(&back).unwrap(), line);
    }
}

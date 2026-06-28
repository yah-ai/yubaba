//! `messaging.*` verb signatures — outbound channel catalog (R409-T12).
//!
//! Three verbs for outbound message dispatch. Exemplar providers:
//! - Email: Resend, SendGrid, AWS SES
//! - SMS: Twilio, Vonage
//! - Webhook: plain HTTP (any URL)
//!
//! - `messaging.email.send`       — send a transactional email
//! - `messaging.sms.send`         — send an SMS message
//! - `messaging.webhook.dispatch` — POST a JSON payload to a URL
//!
//! The webhook verb is intentionally simple — it covers the "notify this
//! URL" pattern used by CI integrations, chat bots, and alert routing without
//! prescribing a specific event schema.

use serde::{Deserialize, Serialize};

use super::{InternalVerb, VerbCategory};

// ── messaging.email.send ──────────────────────────────────────────────────

/// Marker type for `messaging.email.send`.
pub struct MessagingEmailSend;

/// Request body for `messaging.email.send`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct MessagingEmailSendInput {
    /// Sender address, e.g. `"yah <noreply@yah.dev>"` or `"noreply@yah.dev"`.
    pub from: String,
    /// Recipient addresses. At least one required.
    pub to: Vec<String>,
    /// Email subject line.
    pub subject: String,
    /// HTML body. At least one of `html` or `text` should be provided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    /// Plain-text body fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Reply-to address. `None` defaults to the sender.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
}

/// Response body for `messaging.email.send`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct MessagingEmailSendOutput {
    /// Provider-issued message ID.
    pub id: String,
}

impl InternalVerb for MessagingEmailSend {
    type Input = MessagingEmailSendInput;
    type Output = MessagingEmailSendOutput;
    const ID: &'static str = "messaging.email.send";
    const CATEGORY: VerbCategory = VerbCategory::Messaging;
}

// ── messaging.sms.send ────────────────────────────────────────────────────

/// Marker type for `messaging.sms.send`.
pub struct MessagingSmsSend;

/// Request body for `messaging.sms.send`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct MessagingSmsSendInput {
    /// Sender phone number (E.164 format, e.g. `"+15555550100"`) or
    /// alphanumeric sender ID where supported.
    pub from: String,
    /// Recipient phone number in E.164 format, e.g. `"+15555550101"`.
    pub to: String,
    /// Message body. Providers may split long messages into multiple SMS
    /// segments.
    pub body: String,
}

/// Response body for `messaging.sms.send`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct MessagingSmsSendOutput {
    /// Provider-issued message SID or ID.
    pub id: String,
    /// Delivery status at send time: `"queued"`, `"sent"`, `"failed"`,
    /// `"unknown"`. Async delivery confirmation is out of scope.
    pub status: String,
}

impl InternalVerb for MessagingSmsSend {
    type Input = MessagingSmsSendInput;
    type Output = MessagingSmsSendOutput;
    const ID: &'static str = "messaging.sms.send";
    const CATEGORY: VerbCategory = VerbCategory::Messaging;
}

// ── messaging.webhook.dispatch ────────────────────────────────────────────

/// Marker type for `messaging.webhook.dispatch`.
pub struct MessagingWebhookDispatch;

/// Request body for `messaging.webhook.dispatch`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct MessagingWebhookDispatchInput {
    /// Target URL. Must be HTTPS in production.
    pub url: String,
    /// JSON payload to POST.
    pub payload: serde_json::Value,
    /// Additional HTTP headers to include (e.g. `Authorization`,
    /// `X-Custom-Header`). `None` sends no extra headers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<std::collections::BTreeMap<String, String>>,
}

/// Response body for `messaging.webhook.dispatch`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct MessagingWebhookDispatchOutput {
    /// HTTP status code returned by the target server.
    pub status_code: u16,
    /// `true` when `status_code` is in the 2xx range.
    pub ok: bool,
}

impl InternalVerb for MessagingWebhookDispatch {
    type Input = MessagingWebhookDispatchInput;
    type Output = MessagingWebhookDispatchOutput;
    const ID: &'static str = "messaging.webhook.dispatch";
    const CATEGORY: VerbCategory = VerbCategory::Messaging;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verb_ids_match_canonical_namespace() {
        for id in [
            MessagingEmailSend::ID,
            MessagingSmsSend::ID,
            MessagingWebhookDispatch::ID,
        ] {
            assert!(id.starts_with("messaging."), "{id}");
        }
    }

    #[test]
    fn verbs_are_under_messaging_category() {
        assert_eq!(MessagingEmailSend::CATEGORY, VerbCategory::Messaging);
        assert_eq!(MessagingSmsSend::CATEGORY, VerbCategory::Messaging);
        assert_eq!(MessagingWebhookDispatch::CATEGORY, VerbCategory::Messaging);
    }

    #[test]
    fn email_send_optional_fields_omitted() {
        let input = MessagingEmailSendInput {
            from: "noreply@yah.dev".into(),
            to: vec!["user@example.com".into()],
            subject: "Hello".into(),
            html: Some("<p>Hi</p>".into()),
            text: None,
            reply_to: None,
        };
        let wire = serde_json::to_value(&input).unwrap();
        assert!(!wire.as_object().unwrap().contains_key("text"));
        assert!(!wire.as_object().unwrap().contains_key("reply_to"));
        assert_eq!(wire["html"], "<p>Hi</p>");
    }

    #[test]
    fn email_send_to_is_vec() {
        let wire = r#"{"from":"a@b.com","to":["x@y.com","z@w.com"],"subject":"S"}"#;
        let parsed: MessagingEmailSendInput = serde_json::from_str(wire).unwrap();
        assert_eq!(parsed.to.len(), 2);
    }

    #[test]
    fn sms_send_round_trips() {
        let input = MessagingSmsSendInput {
            from: "+15550100".into(),
            to: "+15550101".into(),
            body: "Hello".into(),
        };
        let wire = serde_json::to_string(&input).unwrap();
        let back: MessagingSmsSendInput = serde_json::from_str(&wire).unwrap();
        assert_eq!(back.to, "+15550101");
    }

    #[test]
    fn webhook_dispatch_payload_accepts_arbitrary_json() {
        let wire = r#"{"url":"https://hook.example.com","payload":{"event":"deploy","sha":"abc"}}"#;
        let parsed: MessagingWebhookDispatchInput = serde_json::from_str(wire).unwrap();
        assert_eq!(parsed.payload["event"], "deploy");
        assert!(parsed.headers.is_none());
    }

    #[test]
    fn webhook_dispatch_output_ok_reflects_status() {
        let ok = MessagingWebhookDispatchOutput {
            status_code: 200,
            ok: true,
        };
        let err = MessagingWebhookDispatchOutput {
            status_code: 503,
            ok: false,
        };
        assert_eq!(serde_json::to_value(&ok).unwrap()["ok"], true);
        assert_eq!(serde_json::to_value(&err).unwrap()["status_code"], 503);
    }

    #[cfg(feature = "json-schema")]
    #[test]
    fn verbs_emit_schemas_via_for_verb() {
        use super::super::VerbDescriptor;

        let email = VerbDescriptor::for_verb::<MessagingEmailSend>();
        assert_eq!(email.id, "messaging.email.send");
        assert!(email.input_schema.to_string().contains("subject"));

        let sms = VerbDescriptor::for_verb::<MessagingSmsSend>();
        assert_eq!(sms.id, "messaging.sms.send");

        let webhook = VerbDescriptor::for_verb::<MessagingWebhookDispatch>();
        assert_eq!(webhook.id, "messaging.webhook.dispatch");
        assert!(webhook.output_schema.to_string().contains("status_code"));
    }
}

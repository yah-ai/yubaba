//! `payments.*` verb signatures — billing surface catalog (R409-T12).
//!
//! Three verbs for the payments plane. Per W144, this is a yubaba-side
//! category — the fractal puts payments verbs on the yubaba host, not the
//! yah camp host. The shapes are designed for Stripe, Lemon Squeezy, and
//! Paddle as exemplar providers.
//!
//! - `payments.charge.create`       — create a one-time charge / payment intent
//! - `payments.subscription.upsert` — create or update a subscription
//! - `payments.webhook.verify`      — verify a provider webhook signature
//!
//! `webhook.verify` is intentionally read-only (pure HMAC check). The
//! `secret` field carries a sensitive value — adapters must never log it.

use serde::{Deserialize, Serialize};

use super::{InternalVerb, VerbCategory};

// ── payments.charge.create ────────────────────────────────────────────────

/// Marker type for `payments.charge.create`.
pub struct PaymentsChargeCreate;

/// Request body for `payments.charge.create`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct PaymentsChargeCreateInput {
    /// Charge amount in the smallest currency unit (cents for USD/EUR, etc.).
    pub amount_cents: u64,
    /// ISO 4217 currency code, lowercase: `"usd"`, `"eur"`, `"gbp"`, etc.
    pub currency: String,
    /// Human-readable description shown on receipts. Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Provider-issued customer ID to attach this charge to. `None` for
    /// guest / anonymous charges (provider-dependent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
}

/// Response body for `payments.charge.create`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct PaymentsChargeCreateOutput {
    /// Provider-issued charge or payment-intent ID.
    pub id: String,
    /// Lifecycle status: `"succeeded"`, `"pending"`, `"failed"`.
    pub status: String,
    /// Client secret for client-side confirmation (Stripe's
    /// `PaymentIntent.client_secret`). `None` for providers that do not
    /// require a two-step client confirmation flow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

impl InternalVerb for PaymentsChargeCreate {
    type Input = PaymentsChargeCreateInput;
    type Output = PaymentsChargeCreateOutput;
    const ID: &'static str = "payments.charge.create";
    const CATEGORY: VerbCategory = VerbCategory::Payments;
}

// ── payments.subscription.upsert ─────────────────────────────────────────

/// Marker type for `payments.subscription.upsert`.
pub struct PaymentsSubscriptionUpsert;

/// Request body for `payments.subscription.upsert`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct PaymentsSubscriptionUpsertInput {
    /// Provider-issued customer ID.
    pub customer_id: String,
    /// Provider-specific price or plan ID (Stripe price, Lemon Squeezy
    /// variant, Paddle price ID).
    pub price_id: String,
    /// Seat / licence quantity. Defaults to `1` when absent.
    #[serde(default = "quantity_one")]
    pub quantity: u32,
}

fn quantity_one() -> u32 {
    1
}

/// Response body for `payments.subscription.upsert`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct PaymentsSubscriptionUpsertOutput {
    /// Provider-issued subscription ID.
    pub id: String,
    /// Lifecycle status: `"active"`, `"trialing"`, `"past_due"`,
    /// `"cancelled"`, `"unknown"`.
    pub status: String,
    /// RFC 3339 end of the current billing period. `None` when the
    /// provider doesn't return it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_period_end: Option<String>,
}

impl InternalVerb for PaymentsSubscriptionUpsert {
    type Input = PaymentsSubscriptionUpsertInput;
    type Output = PaymentsSubscriptionUpsertOutput;
    const ID: &'static str = "payments.subscription.upsert";
    const CATEGORY: VerbCategory = VerbCategory::Payments;
}

// ── payments.webhook.verify ───────────────────────────────────────────────

/// Marker type for `payments.webhook.verify`.
pub struct PaymentsWebhookVerify;

/// Request body for `payments.webhook.verify`.
///
/// The `secret` field carries the endpoint's signing secret — adapters must
/// never log this value. HMAC verification is adapter-side and
/// network-free; no provider API call is made.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct PaymentsWebhookVerifyInput {
    /// Raw request body bytes as a string (UTF-8). Some providers sign the
    /// exact bytes, so pass the body before any JSON parsing.
    pub payload: String,
    /// Value of the provider's signature header (e.g. `Stripe-Signature`,
    /// `X-Signature`).
    pub signature: String,
    /// Webhook endpoint signing secret. Treat as a credential; do not log.
    pub secret: String,
}

/// Response body for `payments.webhook.verify`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct PaymentsWebhookVerifyOutput {
    /// `true` if the signature is valid.
    pub valid: bool,
    /// Provider event type extracted from the payload (e.g.
    /// `"payment_intent.succeeded"`). `None` when verification failed or
    /// the type cannot be extracted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
}

impl InternalVerb for PaymentsWebhookVerify {
    type Input = PaymentsWebhookVerifyInput;
    type Output = PaymentsWebhookVerifyOutput;
    const ID: &'static str = "payments.webhook.verify";
    const CATEGORY: VerbCategory = VerbCategory::Payments;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verb_ids_match_canonical_namespace() {
        for id in [
            PaymentsChargeCreate::ID,
            PaymentsSubscriptionUpsert::ID,
            PaymentsWebhookVerify::ID,
        ] {
            assert!(id.starts_with("payments."), "{id}");
        }
    }

    #[test]
    fn verbs_are_under_payments_category() {
        assert_eq!(PaymentsChargeCreate::CATEGORY, VerbCategory::Payments);
        assert_eq!(PaymentsSubscriptionUpsert::CATEGORY, VerbCategory::Payments);
        assert_eq!(PaymentsWebhookVerify::CATEGORY, VerbCategory::Payments);
    }

    #[test]
    fn charge_create_optional_fields_omitted() {
        let input = PaymentsChargeCreateInput {
            amount_cents: 1000,
            currency: "usd".into(),
            description: None,
            customer_id: None,
        };
        let wire = serde_json::to_value(&input).unwrap();
        assert!(!wire.as_object().unwrap().contains_key("description"));
        assert!(!wire.as_object().unwrap().contains_key("customer_id"));
    }

    #[test]
    fn subscription_upsert_defaults_quantity_to_one() {
        let wire = r#"{"customer_id":"cus_1","price_id":"price_1"}"#;
        let parsed: PaymentsSubscriptionUpsertInput = serde_json::from_str(wire).unwrap();
        assert_eq!(parsed.quantity, 1);
    }

    #[test]
    fn webhook_verify_output_omits_event_type_on_failure() {
        let out = PaymentsWebhookVerifyOutput {
            valid: false,
            event_type: None,
        };
        let wire = serde_json::to_value(&out).unwrap();
        assert_eq!(wire["valid"], false);
        assert!(!wire.as_object().unwrap().contains_key("event_type"));
    }

    #[test]
    fn webhook_verify_output_includes_event_type_on_success() {
        let out = PaymentsWebhookVerifyOutput {
            valid: true,
            event_type: Some("payment_intent.succeeded".into()),
        };
        let wire = serde_json::to_value(&out).unwrap();
        assert_eq!(wire["valid"], true);
        assert_eq!(wire["event_type"], "payment_intent.succeeded");
    }

    #[cfg(feature = "json-schema")]
    #[test]
    fn verbs_emit_schemas_via_for_verb() {
        use super::super::VerbDescriptor;

        let charge = VerbDescriptor::for_verb::<PaymentsChargeCreate>();
        assert_eq!(charge.id, "payments.charge.create");
        assert!(charge.input_schema.to_string().contains("amount_cents"));

        let sub = VerbDescriptor::for_verb::<PaymentsSubscriptionUpsert>();
        assert_eq!(sub.id, "payments.subscription.upsert");

        let verify = VerbDescriptor::for_verb::<PaymentsWebhookVerify>();
        assert_eq!(verify.id, "payments.webhook.verify");
        assert!(verify.output_schema.to_string().contains("valid"));
    }
}

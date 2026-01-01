//! Domain-level reconciler — `.yah/domains/*.toml` → live Cloudflare state.
//!
//! Today's only shape is the **R2 custom-domain** binding: a domain whose
//! `cdn_bucket` field names an R2 bucket and which has no `[[routes]]`.
//! Cloudflare's R2 Custom Domains API binds the hostname to the bucket and
//! writes the CNAME into the parent zone automatically when the zone lives
//! on the same account — no DNS-side call is needed here.
//!
//! Worker-routed domains (e.g. `yah-dev.toml`, `app-yah-dev.toml`, which
//! carry `[[routes]]`) are out of scope for this module; they get DNS +
//! route management through the Worker reconciler.

use anyhow::{Context, Result};
use tracing::{debug, info};

use crate::CloudflareClient;

/// Bind `domain` as a custom domain on `bucket_name`. Idempotent — does
/// nothing when the binding is already present, regardless of `enabled`
/// state (CF reflects newly-added bindings as `enabled: true` immediately;
/// disabling is an explicit dashboard action we don't undo here).
///
/// Resolves the Cloudflare API token from the `cloudflare-api-token`
/// keystore slot (or `CLOUDFLARE_API_TOKEN` env). Mirrors the list-first
/// pattern of `static_asset::ensure_r2_bucket` so the apply loop is safe
/// to re-run.
///
/// Required token scopes: `Workers R2 Storage: Edit` and `Zone: Read`
/// (the latter because the API requires the zone id of the parent zone —
/// CF writes the CNAME there). The caller does NOT need `DNS: Edit`; CF
/// provisions the record itself when the binding is created.
pub async fn ensure_r2_custom_domain(
    account_id: &str,
    bucket_name: &str,
    domain: &str,
) -> Result<()> {
    let api_token = keys::get_or_env("cloudflare-api-token", "CLOUDFLARE_API_TOKEN")
        .context("resolving cloudflare-api-token")?
        .context(
            "cloudflare-api-token not found — set via `yah keys set cloudflare-api-token` \
             or export CLOUDFLARE_API_TOKEN",
        )?;
    let cf = CloudflareClient::new(api_token);
    let existing = cf
        .list_r2_custom_domains(account_id, bucket_name)
        .await
        .with_context(|| {
            format!("listing R2 custom domains on bucket {bucket_name:?}")
        })?;
    if existing.iter().any(|d| d.domain == domain) {
        debug!(domain, bucket_name, "R2 custom domain already bound — skipping");
        return Ok(());
    }
    let zone_name = parent_zone_name(domain);
    let zone_id = cf
        .zone_id_for_name(zone_name)
        .await
        .with_context(|| format!("resolving zone id for {zone_name:?}"))?;
    cf.add_r2_custom_domain(account_id, bucket_name, domain, &zone_id)
        .await
        .with_context(|| {
            format!("binding R2 custom domain {domain:?} → bucket {bucket_name:?}")
        })?;
    info!(domain, bucket_name, zone_name, "R2 custom domain bound");
    Ok(())
}

/// Heuristic: the parent CF zone of `domain` is its last two labels.
///
/// `cdn.yah.dev` → `yah.dev`; `yah.dev` → `yah.dev` (already apex). This is
/// correct for every yah-owned zone today (all are two-label apexes). If a
/// future workspace registers a three-label zone (e.g. `staging.yah.dev`
/// as its own CF zone) and binds a subdomain under it, this will resolve
/// to the wrong zone — swap in a longest-suffix match against
/// `list_zones()` when that day arrives.
fn parent_zone_name(domain: &str) -> &str {
    let last_dot = domain.rfind('.');
    let Some(last_dot) = last_dot else {
        return domain; // single-label — let CF surface the bad input
    };
    if let Some(prev_dot) = domain[..last_dot].rfind('.') {
        &domain[prev_dot + 1..]
    } else {
        domain // already a two-label apex
    }
}

#[cfg(test)]
mod tests {
    use super::parent_zone_name;

    #[test]
    fn parent_zone_strips_one_label_off_subdomain() {
        assert_eq!(parent_zone_name("cdn.yah.dev"), "yah.dev");
        assert_eq!(parent_zone_name("app.yah.dev"), "yah.dev");
    }

    #[test]
    fn parent_zone_returns_self_for_apex() {
        assert_eq!(parent_zone_name("yah.dev"), "yah.dev");
    }

    #[test]
    fn parent_zone_strips_only_first_label_for_deeper_subdomain() {
        // Two-label heuristic: yah-side zones are all two-label apexes today.
        assert_eq!(parent_zone_name("a.b.yah.dev"), "yah.dev");
    }
}

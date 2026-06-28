//! `yubaba-test-macros` — `#[test_with_provider]` proc macro.
//!
//! ## Usage
//!
//! ```rust,ignore
//! #[test_with_provider(local, smoke)]
//! async fn my_test<P, R>(p: P, rt: R)
//! where
//!     P: cloud::provider::MachineProvider,
//!     R: yubaba::runtime::ContainerRuntime,
//! {
//!     let cluster = warden_test_harness::test_cluster(&p, 2).await.unwrap();
//!     let yubaba = cluster.yubaba(0);
//!     // ...
//! }
//! ```
//!
//! Expands to `my_test__local` (runs by default) and `my_test__smoke`
//! (`#[ignore]` until `YAH_SMOKE=1`).
//!
//! ## Tiers
//!
//! | Tier | Provider | Runtime | Gate |
//! |------|----------|---------|------|
//! | `local` | `LocalDockerProvider` | `ContainerdRuntime` | skips gracefully when colima socket missing |
//! | `smoke` | `HetznerDriver` | `ContainerdRuntime` | `#[ignore]` + `YAH_SMOKE=1` guard |
//!
//! ## Variant naming
//!
//! `<fn_name>__local` / `<fn_name>__smoke` — the double-underscore suffix
//! lets cargo's `--filter` flag catch a whole tier at once:
//!
//! ```bash
//! cargo test --test integration -- --local     # all local variants
//! cargo test --test integration -- --ignored   # all smoke variants
//! ```
//!
//! @arch:see(.yah/docs/architecture/A053-yah-yubaba-integration-testing.md)

use proc_macro::TokenStream;
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
    ItemFn, Token,
};

// ── Attribute argument parsing ────────────────────────────────────────────────

/// Parsed tier list from the macro attribute, e.g. `(local, smoke)`.
struct TierList(Vec<String>);

impl Parse for TierList {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let idents: Punctuated<Ident, Token![,]> = Punctuated::parse_terminated(input)?;
        Ok(TierList(idents.into_iter().map(|i| i.to_string()).collect()))
    }
}

// ── Proc macro ────────────────────────────────────────────────────────────────

/// Expand one async test function into per-tier variants.
///
/// The annotated function must be `async` and may carry generic parameters
/// `<P: MachineProvider, R: ContainerRuntime>`. The macro renames the
/// original to `__inner_<name>` and emits one `#[tokio::test]` wrapper per
/// requested tier.
///
/// See module-level docs for usage and tier semantics.
#[proc_macro_attribute]
pub fn test_with_provider(attr: TokenStream, item: TokenStream) -> TokenStream {
    let TierList(tiers) = parse_macro_input!(attr as TierList);

    if tiers.is_empty() {
        return syn::Error::new(
            Span::call_site(),
            "test_with_provider requires at least one tier: `local`, `smoke`, or both",
        )
        .to_compile_error()
        .into();
    }

    let mut input_fn = parse_macro_input!(item as ItemFn);

    // Validate: must be async.
    if input_fn.sig.asyncness.is_none() {
        return syn::Error::new_spanned(
            &input_fn.sig.fn_token,
            "test_with_provider: annotated function must be `async`",
        )
        .to_compile_error()
        .into();
    }

    let fn_name = input_fn.sig.ident.clone();
    let inner_name = Ident::new(&format!("__inner_{}", fn_name), fn_name.span());

    // Rename the original function to `__inner_<name>`.
    input_fn.sig.ident = inner_name.clone();
    // Strip visibility — the inner function is a private implementation detail.
    input_fn.vis = syn::Visibility::Inherited;

    let mut out = TokenStream2::new();

    // Emit the (renamed) inner function.
    out.extend(quote! {
        #[allow(unused, dead_code)]
        #input_fn
    });

    // Emit one wrapper per requested tier.
    for tier in &tiers {
        match tier.as_str() {
            "local" => out.extend(emit_local_variant(&fn_name, &inner_name)),
            "smoke" => out.extend(emit_smoke_variant(&fn_name, &inner_name)),
            other => {
                return syn::Error::new(
                    Span::call_site(),
                    format!(
                        "test_with_provider: unknown tier `{other}` — valid tiers are `local`, `smoke`"
                    ),
                )
                .to_compile_error()
                .into();
            }
        }
    }

    out.into()
}

// ── Tier variant emitters ─────────────────────────────────────────────────────

/// Emit the `__local` wrapper.
///
/// Constructs `LocalDockerProvider` + `ContainerdRuntime` using absolute crate
/// paths (`::cloud::...`, `::yubaba::...`). The caller's Cargo.toml must have
/// `cloud` (with `local-docker` feature) and `yubaba` (with
/// `containerd-integration` feature) as dev-dependencies.
///
/// The variant skips gracefully (with `eprintln!` + early return) when either
/// socket is unreachable, keeping `cargo test` green on machines without Colima.
fn emit_local_variant(fn_name: &Ident, inner_name: &Ident) -> TokenStream2 {
    let variant_name = Ident::new(&format!("{fn_name}__local"), fn_name.span());

    quote! {
        #[::tokio::test]
        #[allow(non_snake_case)]
        async fn #variant_name() {
            let p = match cloud::provider::local_docker::LocalDockerProvider::connect().await {
                Ok(p) => p,
                Err(e) => {
                    eprintln!(
                        "[test_with_provider] local provider unavailable (skipping {}__local): {}",
                        stringify!(#fn_name), e
                    );
                    return;
                }
            };
            let rt = match ::kamaji::containerd::ContainerdRuntime::connect().await {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!(
                        "[test_with_provider] local runtime unavailable (skipping {}__local): {}",
                        stringify!(#fn_name), e
                    );
                    return;
                }
            };
            #inner_name(p, rt).await;
        }
    }
}

/// Emit the `__smoke` wrapper.
///
/// Always carries `#[ignore]` so it is excluded from the default test run.
/// At runtime the wrapper additionally checks `YAH_SMOKE == "1"` and returns
/// silently if not set — this handles the case where `-- --ignored` is passed
/// without `YAH_SMOKE=1` (e.g., a stray `cargo test -- --ignored` in a dev
/// environment without Hetzner credentials).
///
/// The `ContainerRuntime` parameter is filled with `DummyRuntime` — smoke
/// tests provision real Hetzner machines via cloud-init, and the
/// `ContainerRuntime` trait impl is only used by the local in-process tier.
/// Using `DummyRuntime` avoids requiring a live containerd socket on the
/// test-runner machine.
fn emit_smoke_variant(fn_name: &Ident, inner_name: &Ident) -> TokenStream2 {
    let variant_name = Ident::new(&format!("{fn_name}__smoke"), fn_name.span());

    quote! {
        #[::tokio::test]
        #[allow(non_snake_case)]
        #[ignore = "smoke tier — set YAH_SMOKE=1 and required secrets to run"]
        async fn #variant_name() {
            if ::std::env::var("YAH_SMOKE").as_deref() != Ok("1") {
                eprintln!(
                    "[test_with_provider] smoke variant {}__smoke: YAH_SMOKE!=1, skipping \
                     (run with YAH_SMOKE=1 cargo test -- --ignored to exercise this tier)",
                    stringify!(#fn_name)
                );
                return;
            }
            let p = cloud::provider::hetzner::HetznerDriver::from_default_sources()
                .expect(
                    "HetznerDriver credentials missing — export HETZNER_API_TOKEN \
                     (see `yah cloud secrets` for the full credential contract)"
                );
            // Smoke tier provisions real machines via cloud-init; the runtime
            // is not used locally. DummyRuntime satisfies the generic bound
            // without requiring a local containerd socket.
            let rt = yubaba::runtime::DummyRuntime;
            #inner_name(p, rt).await;
        }
    }
}

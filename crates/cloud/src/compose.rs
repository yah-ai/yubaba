//! Podman Compose file generation for yah-cloud service deployments (R040-F7).
//!
//! Translates `MachineConfig` + `LegacyServiceConfig[]` into a ready-to-deploy
//! `ComposeBundle` containing:
//!
//! - `compose.yml`: Podman Compose (Docker Compose v3-compatible) stack
//! - `Caddyfile`: Caddy reverse-proxy config for `mesh_only: false` services
//!   (omitted when all services are mesh-only)
//!
//! ## Tier isolation
//! Services share a Compose network named after the machine's first `tier:*`
//! tag (`tier:t2` → network `tier-t2`). Tier isolation at the software layer
//! (Postgres roles, Headscale ACL tags) is the camp owner's responsibility;
//! this just scopes the container network so different-tier stacks on the
//! same host are not bridged together.
//!
//! ## Tenant isolation (W206 / R558-T2)
//! When a machine hosts services from a single tenant (the common, degenerate
//! case — every [`LegacyServiceConfig::tenant`] is the singleton), the scheme
//! above is unchanged. When it hosts services from **two or more distinct
//! tenants**, the network splits per tenant: each service joins
//! `<tenant>-<tier>` (e.g. `ss-tier-t2`, `noisetable-tier-t2`) so cross-tenant
//! stacks on the same host are not bridged together. The shared Caddy ingress
//! joins every tenant network so a single reverse proxy still reaches any
//! public service. See [`NetworkPlan`].
//!
//! ## Caddy reverse proxy
//! `mesh_only: false` services are exposed through a Caddy container that
//! Cloudflare orange-cloud (or a Cloudflare Tunnel via R040-F15) terminates
//! in front of. Caddy is chosen over nginx because it handles TLS from
//! Cloudflare origin certs without extra config, and its reverse_proxy
//! directive handles service discovery by container name.
//!
//! ## mesh_only services
//! Services with `mesh_only: true` use `expose:` only (no host-port
//! binding). They are reachable within the Compose network and, once
//! R040-F16 lands its `bind_interface` plumbing, directly via Tailscale.

use std::collections::BTreeSet;

use crate::config::{LegacyServiceConfig, MachineConfig};
use crate::mesh_service;

/// A rendered compose bundle ready to push to the yubaba's `POST /compose`.
#[derive(Debug, Clone)]
pub struct ComposeBundle {
    /// Podman compose YAML (Docker Compose v3-compatible).
    pub compose_yaml: String,
    /// Caddy reverse-proxy config — `None` when all services are `mesh_only`.
    pub caddyfile: Option<String>,
    /// Shell commands the yubaba must execute after writing compose files —
    /// typically ufw rules for services that have `bind_interface` set.
    /// Commands are executed in order via `sh -c`; failures are logged but
    /// do not abort the deploy (ufw may not be installed on dev machines).
    pub firewall_cmds: Vec<String>,
}

/// Generate a `ComposeBundle` for a machine's full service set.
///
/// `services` is the union of all declared services across the mirrors the
/// machine hosts. Pass an optional `public_hostname` (e.g.
/// `"pdx.cloud.noisetable.example"`) to get a domain-named Caddyfile; omit
/// it and Caddy falls back to port-based listeners (useful for staging / when
/// `cloud_domain` isn't set yet in `mirrors/<camp>.toml`).
pub fn generate_compose_bundle(
    machine: &MachineConfig,
    services: &[LegacyServiceConfig],
    public_hostname: Option<&str>,
) -> ComposeBundle {
    let compose_yaml = build_compose_yaml(machine, services);
    let caddyfile = build_caddyfile(services, public_hostname);
    let firewall_cmds = collect_firewall_cmds(services);
    ComposeBundle {
        compose_yaml,
        caddyfile,
        firewall_cmds,
    }
}

/// Derive the primary Compose network name from the machine's tier tag.
/// Falls back to `"yah-cloud"` when no `tier:*` tag is present.
fn machine_network(machine: &MachineConfig) -> String {
    machine
        .mesh_tags
        .iter()
        .find_map(|t| t.strip_prefix("tier:"))
        .map(|tier| format!("tier-{tier}"))
        .unwrap_or_else(|| "yah-cloud".to_string())
}

/// How a machine's services map onto Compose bridge networks (W206 / R558-T2).
///
/// Single-tenant (degenerate) machines keep the historical
/// one-network-per-machine scheme: every service joins the tier-derived
/// [`machine_network`] (`tier-t2`, or `yah-cloud` when the machine carries no
/// `tier:*` tag). When a machine hosts services from **two or more distinct
/// tenants**, the network is split per tenant — each service joins
/// `<tenant>-<base>` (e.g. `ss-tier-t2`, `noisetable-tier-t2`) so cross-tenant
/// stacks on the same host are not bridged together. The shared Caddy ingress
/// joins every declared network so it can still reach any public service.
///
/// The tenant prefix uses the base network (`tier-t2`) as a suffix rather than
/// replacing it, keeping the tier legible in the network name and the
/// single-tenant output byte-identical to the pre-T2 renderer.
struct NetworkPlan {
    base: String,
    multi_tenant: bool,
}

impl NetworkPlan {
    fn derive(machine: &MachineConfig, services: &[LegacyServiceConfig]) -> Self {
        let base = machine_network(machine);
        let distinct_tenants: BTreeSet<&str> =
            services.iter().map(|s| s.tenant.0.as_str()).collect();
        NetworkPlan {
            base,
            multi_tenant: distinct_tenants.len() > 1,
        }
    }

    /// Network the given service joins.
    fn network_for(&self, svc: &LegacyServiceConfig) -> String {
        if self.multi_tenant {
            format!("{}-{}", svc.tenant.0, self.base)
        } else {
            self.base.clone()
        }
    }

    /// All distinct networks to declare in the compose `networks:` block and
    /// attach the shared Caddy ingress to. Sorted for deterministic output.
    fn declared(&self, services: &[LegacyServiceConfig]) -> Vec<String> {
        if !self.multi_tenant {
            return vec![self.base.clone()];
        }
        services
            .iter()
            .map(|s| self.network_for(s))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

fn build_compose_yaml(machine: &MachineConfig, services: &[LegacyServiceConfig]) -> String {
    let plan = NetworkPlan::derive(machine, services);
    let declared = plan.declared(services);

    let mut out = String::new();
    out.push_str("# Generated by `yah cloud service deploy` — do not edit manually.\n");
    out.push_str(&format!(
        "# Machine: {} | Location: {}\n",
        machine.name,
        machine.location()
    ));
    out.push_str("version: \"3.8\"\n\n");

    let has_public = services.iter().any(|s| !s.mesh_only);

    if !services.is_empty() || has_public {
        out.push_str("services:\n");
    }

    for svc in services {
        append_service(&mut out, svc, &plan.network_for(svc));
    }

    if has_public {
        append_caddy_service(&mut out, &declared);
    }

    // Networks block — one entry per declared network (a single tier network
    // when single-tenant, one `<tenant>-<tier>` network per tenant otherwise).
    out.push_str("networks:\n");
    for net in &declared {
        out.push_str(&format!("  {net}:\n"));
        out.push_str("    driver: bridge\n");
    }

    if has_public {
        out.push_str("\nvolumes:\n");
        out.push_str("  caddy_data:\n");
    }

    out
}

fn append_service(out: &mut String, svc: &LegacyServiceConfig, network: &str) {
    out.push_str(&format!("  {}:\n", svc.name));
    out.push_str(&format!("    image: {}:{}\n", svc.image, svc.version));
    out.push_str("    restart: unless-stopped\n");

    // Services with bind_interface use the host network stack directly so they
    // can bind to a specific interface (e.g. tailscale0). In host mode the
    // container is not joined to the compose bridge network and expose: is a
    // no-op, so both are omitted.
    if let Some(iface) = &svc.bind_interface {
        out.push_str("    network_mode: \"host\"\n");
        // Emit env_file so the process picks up POSTGRES_LISTEN_ADDRESSES (or
        // equivalent) that cloud-init writes at first boot from `tailscale ip`.
        out.push_str(&format!(
            "    env_file:\n      - {}\n",
            mesh_service::MESH_IP_ENV_FILE,
        ));
        // Annotate with the pg_hba hint so operators know what to configure.
        out.push_str(&format!(
            "    # bind_interface={iface}: use host network + tailscale0 IP. \
             Apply pg_hba snippet from `yah cloud service recipe postgres`.\n",
        ));

        if !svc.env.is_empty() {
            out.push_str("    environment:\n");
            let mut pairs: Vec<(&String, &String)> = svc.env.iter().collect();
            pairs.sort_by_key(|(k, _)| k.as_str());
            for (k, v) in pairs {
                let escaped = v.replace('"', "\\\"");
                out.push_str(&format!("      {k}: \"{escaped}\"\n"));
            }
        }
        out.push('\n');
        return;
    }

    if !svc.env.is_empty() {
        out.push_str("    environment:\n");
        let mut pairs: Vec<(&String, &String)> = svc.env.iter().collect();
        pairs.sort_by_key(|(k, _)| k.as_str());
        for (k, v) in pairs {
            let escaped = v.replace('"', "\\\"");
            out.push_str(&format!("      {k}: \"{escaped}\"\n"));
        }
    }

    if !svc.ports.is_empty() {
        out.push_str("    expose:\n");
        for p in &svc.ports {
            out.push_str(&format!("      - \"{}\"\n", p.container));
        }
    }

    out.push_str(&format!("    networks:\n      - {network}\n\n"));
}

/// Collect ufw firewall commands for all services that declare a `bind_interface`.
/// Each such service gets an `allow in on <iface> port <port>` + `deny <port>`
/// pair, mirroring the yubaba-7443 pattern established in `mirror.yml`.
fn collect_firewall_cmds(services: &[LegacyServiceConfig]) -> Vec<String> {
    let mut cmds = Vec::new();
    for svc in services {
        if let Some(iface) = &svc.bind_interface {
            for port in &svc.ports {
                cmds.extend(mesh_service::ufw_rules_for_mesh_port(iface, port.container));
            }
        }
    }
    cmds
}

fn append_caddy_service(out: &mut String, networks: &[String]) {
    out.push_str("  caddy:\n");
    out.push_str("    image: caddy:2-alpine\n");
    out.push_str("    restart: unless-stopped\n");
    out.push_str("    ports:\n");
    out.push_str("      - \"80:80\"\n");
    out.push_str("      - \"443:443\"\n");
    out.push_str("    volumes:\n");
    out.push_str("      - /etc/yah-cloud/Caddyfile:/etc/caddy/Caddyfile:ro\n");
    out.push_str("      - caddy_data:/data\n");
    // Caddy joins every tenant network so a single ingress can reverse-proxy
    // public services regardless of which tenant they belong to.
    out.push_str("    networks:\n");
    for net in networks {
        out.push_str(&format!("      - {net}\n"));
    }
    out.push('\n');
}

/// Build a Caddyfile for non-mesh_only services. Returns `None` when all
/// services are mesh-only.
///
/// When `hostname` is supplied each service gets a named virtual host
/// (`<hostname>` for the first service, `<service>.<hostname>` for the
/// rest). Without a hostname Caddy uses `:port` placeholders so the stack
/// is immediately testable — operators swap in the real domain once
/// Cloudflare DNS is wired (SECRETS.md).
fn build_caddyfile(services: &[LegacyServiceConfig], hostname: Option<&str>) -> Option<String> {
    let public: Vec<&LegacyServiceConfig> = services.iter().filter(|s| !s.mesh_only).collect();
    if public.is_empty() {
        return None;
    }

    let mut out = String::new();
    out.push_str("# Generated by `yah cloud service deploy` — do not edit manually.\n");

    if hostname.is_none() {
        out.push_str("# Set cloud_domain in mirrors/<camp>.toml for named virtual hosts.\n");
        out.push_str("# Example: pdx.cloud.noisetable.example { reverse_proxy service:8080 }\n");
    }
    out.push('\n');

    for (i, svc) in public.iter().enumerate() {
        let first_port = first_port(svc);
        let site = match hostname {
            Some(h) if i == 0 => h.to_string(),
            Some(h) => format!("{}.{h}", svc.name),
            None => format!(":{first_port}"),
        };
        out.push_str(&format!("{site} {{\n"));
        out.push_str(&format!("    reverse_proxy {}:{first_port}\n", svc.name));
        out.push_str("}\n\n");
    }

    Some(out)
}

fn first_port(svc: &LegacyServiceConfig) -> u16 {
    svc.ports.first().map(|p| p.container).unwrap_or(80)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BucketSpec, LegacyServiceConfig, MachineConfig, PortMapping}; // PortMapping used in test constructors
    use std::collections::HashMap;

    fn machine(tags: &[&str]) -> MachineConfig {
        MachineConfig {
            name: "test-pdx-1".into(),
            provider: "hetzner".into(),
            location: Some("pdx".into()),
            server_type: Some("cpx22".into()),
            hosts_mirrors: vec!["noisetable".into()],
            mesh_tags: tags.iter().map(|t| t.to_string()).collect(),
            region: None,
            zone: None,
            arch: None,
            bucket: Some(BucketSpec {
                name: "test-assets-pdx-1".into(),
                public_read: false,
            }),
            hostkey_fingerprint: None,
            ssh_keys: vec![],
            cloudflared: None,
            hosts_operator_bridge: false,
            connect: None,
            allocatable: None,
            taints: vec![],
        }
    }

    fn service(name: &str, mesh_only: bool) -> LegacyServiceConfig {
        LegacyServiceConfig {
            name: name.into(),
            image: format!("ghcr.io/test/{name}"),
            version: "v1.0.0".into(),
            env: HashMap::new(),
            ports: vec![PortMapping {
                host: 8080,
                container: 8080,
            }],
            mesh_only,
            bind_interface: None,
            tenant: workload_spec::TenantId::singleton(),
        }
    }

    fn mesh_bound_service(name: &str, port: u16) -> LegacyServiceConfig {
        LegacyServiceConfig {
            name: name.into(),
            image: format!("ghcr.io/test/{name}"),
            version: "v1.0.0".into(),
            env: HashMap::new(),
            ports: vec![PortMapping {
                host: port,
                container: port,
            }],
            mesh_only: true,
            bind_interface: Some("tailscale0".into()),
            tenant: workload_spec::TenantId::singleton(),
        }
    }

    #[test]
    fn mesh_only_service_has_no_caddy() {
        let m = machine(&["tier:t2"]);
        let svcs = [service("asset-registry", true)];
        let bundle = generate_compose_bundle(&m, &svcs, None);
        assert!(
            !bundle.compose_yaml.contains("caddy:"),
            "caddy should not appear"
        );
        assert!(bundle.caddyfile.is_none(), "no Caddyfile for mesh-only");
    }

    #[test]
    fn public_service_includes_caddy_and_caddyfile() {
        let m = machine(&["tier:t2"]);
        let svcs = [service("asset-registry", false)];
        let bundle = generate_compose_bundle(&m, &svcs, None);
        assert!(
            bundle.compose_yaml.contains("caddy:"),
            "caddy missing from compose"
        );
        assert!(
            bundle.compose_yaml.contains("caddy_data:"),
            "volume missing"
        );
        assert!(
            bundle.caddyfile.is_some(),
            "Caddyfile expected for public service"
        );
    }

    #[test]
    fn tier_tag_becomes_network_name() {
        let m = machine(&["region:pdx", "tier:t2"]);
        let svcs: [LegacyServiceConfig; 0] = [];
        let bundle = generate_compose_bundle(&m, &svcs, None);
        assert!(
            bundle.compose_yaml.contains("tier-t2:"),
            "network name mismatch"
        );
        assert!(
            !bundle.compose_yaml.contains("yah-cloud:"),
            "fallback network present"
        );
    }

    #[test]
    fn no_tier_tag_falls_back_to_yah_cloud_network() {
        let m = machine(&["region:pdx"]);
        let svcs: [LegacyServiceConfig; 0] = [];
        let bundle = generate_compose_bundle(&m, &svcs, None);
        assert!(
            bundle.compose_yaml.contains("yah-cloud:"),
            "fallback network missing"
        );
    }

    fn tenant_service(name: &str, tenant: &str, mesh_only: bool) -> LegacyServiceConfig {
        LegacyServiceConfig {
            name: name.into(),
            image: format!("ghcr.io/test/{name}"),
            version: "v1.0.0".into(),
            env: HashMap::new(),
            ports: vec![PortMapping {
                host: 8080,
                container: 8080,
            }],
            mesh_only,
            bind_interface: None,
            tenant: workload_spec::TenantId(tenant.into()),
        }
    }

    #[test]
    fn single_tenant_keeps_one_shared_network() {
        // Two services, both the singleton tenant → one shared tier network,
        // no per-tenant split (R558-T2 degenerate case is byte-identical).
        let m = machine(&["tier:t2"]);
        let svcs = [service("a", true), service("b", true)];
        let yaml = generate_compose_bundle(&m, &svcs, None).compose_yaml;
        assert!(
            yaml.contains("tier-t2:"),
            "shared tier network expected:\n{yaml}"
        );
        assert!(
            !yaml.contains("-tier-t2:"),
            "no tenant-prefixed network when single-tenant:\n{yaml}"
        );
    }

    #[test]
    fn multi_tenant_splits_into_per_tenant_networks() {
        let m = machine(&["tier:t2"]);
        let svcs = [
            tenant_service("yah-api", "ss", true),
            tenant_service("nt-api", "noisetable", true),
        ];
        let yaml = generate_compose_bundle(&m, &svcs, None).compose_yaml;
        assert!(yaml.contains("ss-tier-t2:"), "ss network missing:\n{yaml}");
        assert!(
            yaml.contains("noisetable-tier-t2:"),
            "noisetable network missing:\n{yaml}"
        );
        assert!(
            yaml.contains("      - ss-tier-t2\n"),
            "yah-api should join the ss network:\n{yaml}"
        );
        assert!(
            yaml.contains("      - noisetable-tier-t2\n"),
            "nt-api should join the noisetable network:\n{yaml}"
        );
        assert!(
            !yaml.contains("      - tier-t2\n"),
            "no service joins the bare tier network when multi-tenant:\n{yaml}"
        );
    }

    #[test]
    fn multi_tenant_caddy_joins_every_tenant_network() {
        let m = machine(&["tier:t2"]);
        // Public (mesh_only=false) services across two tenants → the shared
        // Caddy ingress must join both tenant networks to reach them.
        let svcs = [
            tenant_service("yah-web", "ss", false),
            tenant_service("nt-web", "noisetable", false),
        ];
        let yaml = generate_compose_bundle(&m, &svcs, None).compose_yaml;
        assert!(yaml.contains("caddy:"), "caddy present for public services");
        // Isolate Caddy's own `networks:` list: it sits between its
        // `caddy_data:/data` volume line and the top-level `networks:` block.
        let after_caddy_vol = yaml.split("- caddy_data:/data").nth(1).expect("caddy volumes");
        let caddy_nets = after_caddy_vol.split("\nnetworks:").next().unwrap();
        assert!(
            caddy_nets.contains("- ss-tier-t2"),
            "caddy joins ss network:\n{yaml}"
        );
        assert!(
            caddy_nets.contains("- noisetable-tier-t2"),
            "caddy joins noisetable network:\n{yaml}"
        );
    }

    #[test]
    fn image_includes_version() {
        let m = machine(&[]);
        let svcs = [service("asset-registry", true)];
        let bundle = generate_compose_bundle(&m, &svcs, None);
        assert!(bundle
            .compose_yaml
            .contains("ghcr.io/test/asset-registry:v1.0.0"));
    }

    #[test]
    fn env_vars_are_rendered_sorted() {
        let m = machine(&[]);
        let mut env = HashMap::new();
        env.insert("ZEBRA".into(), "last".into());
        env.insert("ALPHA".into(), "first".into());
        let svc = LegacyServiceConfig {
            name: "myservice".into(),
            image: "img".into(),
            version: "v1".into(),
            env,
            ports: vec![],
            mesh_only: true,
            bind_interface: None,
            tenant: workload_spec::TenantId::singleton(),
        };
        let bundle = generate_compose_bundle(&m, &[svc], None);
        let yaml = &bundle.compose_yaml;
        assert!(yaml.contains("ALPHA: \"first\""), "ALPHA missing");
        assert!(yaml.contains("ZEBRA: \"last\""), "ZEBRA missing");
        // Sorted: ALPHA before ZEBRA
        let alpha_pos = yaml.find("ALPHA").unwrap();
        let zebra_pos = yaml.find("ZEBRA").unwrap();
        assert!(alpha_pos < zebra_pos, "env vars not sorted");
    }

    #[test]
    fn ports_become_expose() {
        let m = machine(&[]);
        let svcs = [service("svc", true)];
        let bundle = generate_compose_bundle(&m, &svcs, None);
        assert!(bundle.compose_yaml.contains("expose:\n      - \"8080\""));
    }

    #[test]
    fn caddyfile_uses_hostname_when_provided() {
        let m = machine(&[]);
        let svcs = [service("api", false)];
        let bundle = generate_compose_bundle(&m, &svcs, Some("pdx.cloud.example.com"));
        let cf = bundle.caddyfile.unwrap();
        assert!(
            cf.contains("pdx.cloud.example.com {"),
            "hostname missing from Caddyfile"
        );
        assert!(
            cf.contains("reverse_proxy api:8080"),
            "reverse_proxy missing"
        );
    }

    #[test]
    fn caddyfile_uses_port_placeholder_when_no_hostname() {
        let m = machine(&[]);
        let svcs = [service("api", false)];
        let bundle = generate_compose_bundle(&m, &svcs, None);
        let cf = bundle.caddyfile.unwrap();
        assert!(cf.contains(":8080 {"), "port placeholder missing");
    }

    #[test]
    fn multiple_public_services_get_subdomains() {
        let m = machine(&[]);
        let svcs = [service("api", false), service("admin", false)];
        let bundle = generate_compose_bundle(&m, &svcs, Some("pdx.cloud.example.com"));
        let cf = bundle.caddyfile.unwrap();
        // First gets the bare hostname, rest get subdomain prefix
        assert!(cf.contains("pdx.cloud.example.com {"));
        assert!(cf.contains("admin.pdx.cloud.example.com {"));
    }

    #[test]
    fn mixed_services_only_routes_public_in_caddyfile() {
        let m = machine(&[]);
        let svcs = [service("public-svc", false), service("mesh-svc", true)];
        let bundle = generate_compose_bundle(&m, &svcs, None);
        let cf = bundle.caddyfile.as_deref().unwrap();
        assert!(
            cf.contains("public-svc"),
            "public service missing from Caddyfile"
        );
        assert!(
            !cf.contains("mesh-svc"),
            "mesh-only service leaked into Caddyfile"
        );
    }

    // ── bind_interface (R040-F16) ────────────────────────────────────────────

    #[test]
    fn bind_interface_emits_network_mode_host() {
        let m = machine(&["tier:t2"]);
        let svcs = [mesh_bound_service("postgres", 5432)];
        let bundle = generate_compose_bundle(&m, &svcs, None);
        assert!(
            bundle.compose_yaml.contains("network_mode: \"host\""),
            "host mode missing:\n{}",
            bundle.compose_yaml,
        );
    }

    #[test]
    fn bind_interface_emits_env_file_for_mesh_ip() {
        let m = machine(&[]);
        let svcs = [mesh_bound_service("postgres", 5432)];
        let bundle = generate_compose_bundle(&m, &svcs, None);
        assert!(
            bundle.compose_yaml.contains(mesh_service::MESH_IP_ENV_FILE),
            "env_file missing from compose yaml:\n{}",
            bundle.compose_yaml,
        );
    }

    #[test]
    fn bind_interface_service_not_in_bridge_network() {
        let m = machine(&["tier:t2"]);
        let svcs = [mesh_bound_service("postgres", 5432)];
        let bundle = generate_compose_bundle(&m, &svcs, None);
        // The "networks:" block at the top level is still present (for caddy etc.),
        // but the postgres service entry must NOT have a `networks:` directive.
        let svc_block_end = bundle
            .compose_yaml
            .find("network_mode: \"host\"")
            .expect("network_mode:host missing");
        let after = &bundle.compose_yaml[svc_block_end..];
        // The postgres block ends with a blank line; there must not be a "networks:" line
        // before that blank line.
        let blank = after.find("\n\n").unwrap_or(after.len());
        let postgres_block = &after[..blank];
        assert!(
            !postgres_block.contains("networks:\n      -"),
            "bind_interface service should not be added to the bridge network:\n{}",
            postgres_block,
        );
    }

    #[test]
    fn bind_interface_service_has_no_expose_block() {
        let m = machine(&[]);
        let svcs = [mesh_bound_service("postgres", 5432)];
        let bundle = generate_compose_bundle(&m, &svcs, None);
        // In network_mode:host, expose: is meaningless — ensure it's omitted.
        let svc_start = bundle.compose_yaml.find("  postgres:").unwrap();
        let svc_end = bundle.compose_yaml[svc_start..]
            .find("\n\n")
            .map(|i| svc_start + i)
            .unwrap_or(bundle.compose_yaml.len());
        let block = &bundle.compose_yaml[svc_start..svc_end];
        assert!(
            !block.contains("expose:"),
            "expose: must be omitted in host mode:\n{block}"
        );
    }

    #[test]
    fn bind_interface_populates_firewall_cmds() {
        let m = machine(&[]);
        let svcs = [mesh_bound_service("postgres", 5432)];
        let bundle = generate_compose_bundle(&m, &svcs, None);
        assert_eq!(
            bundle.firewall_cmds.len(),
            2,
            "expected 2 ufw rules: {:?}",
            bundle.firewall_cmds
        );
        assert!(bundle.firewall_cmds[0].contains("allow in on tailscale0 to any port 5432"));
        assert!(bundle.firewall_cmds[1].contains("deny 5432"));
    }

    #[test]
    fn no_bind_interface_produces_empty_firewall_cmds() {
        let m = machine(&[]);
        let svcs = [service("api", false), service("worker", true)];
        let bundle = generate_compose_bundle(&m, &svcs, None);
        assert!(
            bundle.firewall_cmds.is_empty(),
            "no bind_interface → no firewall cmds"
        );
    }

    #[test]
    fn multiple_bound_services_accumulate_firewall_cmds() {
        let m = machine(&[]);
        let svcs = [
            mesh_bound_service("postgres", 5432),
            mesh_bound_service("nats", 4222),
        ];
        let bundle = generate_compose_bundle(&m, &svcs, None);
        // 2 rules per service × 2 services = 4
        assert_eq!(
            bundle.firewall_cmds.len(),
            4,
            "unexpected rules: {:?}",
            bundle.firewall_cmds
        );
        let all = bundle.firewall_cmds.join("\n");
        assert!(all.contains("5432"), "postgres rules missing");
        assert!(all.contains("4222"), "nats rules missing");
    }

    #[test]
    fn bind_interface_service_excluded_from_caddyfile() {
        let m = machine(&[]);
        // A pg service has bind_interface + mesh_only:true — must NOT appear in Caddyfile.
        let svcs = [mesh_bound_service("postgres", 5432), service("api", false)];
        let bundle = generate_compose_bundle(&m, &svcs, None);
        let cf = bundle.caddyfile.as_deref().unwrap();
        assert!(
            !cf.contains("postgres"),
            "bound service must not be in Caddyfile"
        );
        assert!(cf.contains("api"), "public service missing from Caddyfile");
    }
}

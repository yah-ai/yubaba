//! Recipe helpers for stateful services bound exclusively to the Headscale mesh
//! (R040-F16).
//!
//! Inter-node TCP (Postgres primary↔replica, NATS clusters, etc.) lives on the
//! WireGuard mesh, not on Hetzner public IPs. Each node has a stable
//! `100.64.x.x` mesh IP that survives box replacement, so connection strings
//! and pg_hba.conf never need to churn when a CPX-22 is rebuilt.
//!
//! ## Standard pattern for a mesh-bound port
//!
//! ```text
//! ServiceConfig {
//!     name: "postgres",
//!     bind_interface: Some("tailscale0"),
//!     mesh_only: true,
//!     ...
//! }
//! ```
//!
//! The compose renderer emits `network_mode: "host"` for such a service.
//! Pair it with the ufw rules from [`ufw_rules_for_mesh_port`] (applied by the
//! warden's `POST /compose` via the `firewall_cmds` field) and the pg_hba
//! snippet from [`pg_hba_snippet`] (injected into the Postgres container via
//! a mounted config volume or env).
//!
//! ## First-boot POSTGRES_LISTEN_ADDRESSES
//!
//! Postgres must bind to the node's tailscale mesh IP, not `0.0.0.0`. Since
//! the IP is only known at boot time, cloud-init or a systemd `ExecStartPre`
//! can resolve it:
//!
//! ```yaml
//! # cloud-init write_files
//! - path: /etc/yah-cloud/mesh-ip.env
//!   content: ""   # overwritten by runcmd below
//!
//! runcmd:
//!   - sh -c 'echo "POSTGRES_LISTEN_ADDRESSES=$(tailscale ip --4)" > /etc/yah-cloud/mesh-ip.env'
//! ```
//!
//! Then reference `env_file: [/etc/yah-cloud/mesh-ip.env]` in the compose
//! service block. The compose renderer sets this automatically when
//! `bind_interface` is set on a service that exposes port 5432.

/// Tailscale/Headscale CGNAT subnet — all mesh peers have addresses in this range.
pub const MESH_SUBNET: &str = "100.64.0.0/10";

/// The network interface name that carries Tailscale/Headscale mesh traffic.
pub const TAILSCALE_IFACE: &str = "tailscale0";

/// The env file path written by cloud-init that holds the node's mesh IP.
/// Referenced as `env_file` in compose when `bind_interface` is set.
pub const MESH_IP_ENV_FILE: &str = "/etc/yah-cloud/mesh-ip.env";

/// Generate a `pg_hba.conf` block that allows connections from any mesh peer.
///
/// `mesh_subnet` is normally [`MESH_SUBNET`] (`100.64.0.0/10`); override
/// for testing or non-standard CGNAT ranges.
///
/// The returned string is ready to append to or replace the service section of
/// `pg_hba.conf`. It allows:
/// - All application users (`all`) from any mesh address.
/// - Replication users (`replication`) from any mesh address (needed for
///   streaming replication between the primary and standby nodes).
///
/// Both rows use `scram-sha-256`, which is the Postgres 16 default and is
/// more secure than `md5`. Set `password_encryption = scram-sha-256` in
/// `postgresql.conf` to match.
pub fn pg_hba_snippet(mesh_subnet: &str) -> String {
    format!(
        "# pg_hba.conf — mesh subnet ({mesh_subnet})\n\
         # Allow app connections from any mesh peer (WireGuard-encrypted on the wire).\n\
         host    all             all             {mesh_subnet}           scram-sha-256\n\
         # Allow replication from any mesh peer (streaming replica sync).\n\
         host    replication     all             {mesh_subnet}           scram-sha-256\n",
    )
}

/// Generate the ufw commands needed to make port `port` reachable only on
/// interface `iface` (typically `tailscale0`), blocking all other ingress.
///
/// Returns two commands: the interface-specific allow, then a blanket deny.
/// ufw evaluates rules in insertion order — the interface-scoped allow must
/// be added **before** the blanket deny or it will never be reached.
///
/// This mirrors the pattern used for yah-warden's 7443 port in `mirror.yml`:
/// ```text
/// ufw allow in on tailscale0 to any port 7443
/// ufw deny 7443
/// ```
pub fn ufw_rules_for_mesh_port(iface: &str, port: u16) -> Vec<String> {
    vec![
        format!("ufw allow in on {iface} to any port {port}"),
        format!("ufw deny {port}"),
    ]
}

/// Build the cloud-init `runcmd` lines that write the mesh IP env file at
/// first boot.  Append these to a machine's `mirror.yml` `runcmd` block to
/// make `POSTGRES_LISTEN_ADDRESSES` available to the compose stack via
/// `env_file: [{MESH_IP_ENV_FILE}]`.
pub fn mesh_ip_env_runcmd() -> Vec<String> {
    vec![
        format!(
            "sh -c 'echo \"POSTGRES_LISTEN_ADDRESSES=$(tailscale ip --4)\" > {MESH_IP_ENV_FILE}'"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pg_hba_snippet_contains_mesh_subnet() {
        let s = pg_hba_snippet(MESH_SUBNET);
        assert!(s.contains(MESH_SUBNET), "subnet missing from snippet");
        assert!(s.contains("scram-sha-256"), "auth method missing");
        assert!(s.contains("replication"), "replication row missing");
        assert!(s.contains("host    all"), "app-user row missing");
    }

    #[test]
    fn pg_hba_snippet_custom_subnet() {
        let s = pg_hba_snippet("10.0.0.0/8");
        assert!(s.contains("10.0.0.0/8"));
        assert!(!s.contains(MESH_SUBNET));
    }

    #[test]
    fn ufw_rules_for_mesh_port_produces_two_commands() {
        let rules = ufw_rules_for_mesh_port("tailscale0", 5432);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0], "ufw allow in on tailscale0 to any port 5432");
        assert_eq!(rules[1], "ufw deny 5432");
    }

    #[test]
    fn ufw_rules_allow_before_deny() {
        let rules = ufw_rules_for_mesh_port(TAILSCALE_IFACE, 5432);
        // allow must come first so ufw sees the interface-specific rule before the blanket deny
        assert!(rules[0].starts_with("ufw allow"), "allow must be first");
        assert!(rules[1].starts_with("ufw deny"), "deny must be second");
    }

    #[test]
    fn ufw_rules_for_arbitrary_port() {
        let rules = ufw_rules_for_mesh_port("tailscale0", 4222);
        assert!(rules[0].contains("4222"));
        assert!(rules[1].contains("4222"));
    }

    #[test]
    fn mesh_ip_env_runcmd_references_env_file_path() {
        let cmds = mesh_ip_env_runcmd();
        assert_eq!(cmds.len(), 1);
        assert!(cmds[0].contains(MESH_IP_ENV_FILE));
        assert!(cmds[0].contains("tailscale ip --4"));
    }
}

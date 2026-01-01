use std::path::PathBuf;

use workload_spec::{SecretMount, SecretRef, SecretTarget};

/// Tests that SecretRef serialization never leaks secret values — only
/// references (paths / names) appear in the JSON.
mod secrets {
    use super::*;

    #[test]
    fn local_file_serializes_path_only() {
        let mount = SecretMount {
            source: SecretRef::LocalFile {
                path: PathBuf::from("api-key"),
            },
            target: SecretTarget::EnvVar { name: "API_KEY".into() },
        };

        let json = serde_json::to_string(&mount).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let source = &parsed["source"];
        assert_eq!(source["type"], "local_file", "source.type must be local_file");

        // Path reference appears
        assert!(json.contains("api-key"), "path reference must be in JSON");

        // No value bytes under any common field names
        assert!(source.get("value").is_none(), "secret value must not appear in JSON");
        assert!(source.get("contents").is_none(), "secret contents must not appear in JSON");
        assert!(source.get("data").is_none(), "secret data must not appear in JSON");
        assert!(source.get("bytes").is_none(), "secret bytes must not appear in JSON");
    }

    #[test]
    fn cluster_secret_serializes_name_only() {
        let mount = SecretMount {
            source: SecretRef::Cluster {
                name: "cluster-db-password".into(),
            },
            target: SecretTarget::File {
                path: PathBuf::from("/run/secrets/db"),
                mode: 0o600,
            },
        };

        let json = serde_json::to_string(&mount).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let source = &parsed["source"];
        assert_eq!(source["type"], "cluster");
        assert_eq!(source["name"], "cluster-db-password");

        assert!(source.get("value").is_none(), "secret value must not appear in JSON");
        assert!(source.get("data").is_none(), "secret data must not appear in JSON");
    }

    #[test]
    fn env_var_target_serializes_name_not_value() {
        let target = SecretTarget::EnvVar {
            name: "DATABASE_PASSWORD".into(),
        };
        let json = serde_json::to_string(&target).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["type"], "env_var");
        assert_eq!(parsed["name"], "DATABASE_PASSWORD");
        assert!(parsed.get("value").is_none(), "secret value must not appear in target JSON");
    }

    #[test]
    fn file_target_serializes_path_and_mode_not_content() {
        let target = SecretTarget::File {
            path: PathBuf::from("/run/secrets/tls.crt"),
            mode: 0o400,
        };
        let json = serde_json::to_string(&target).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["type"], "file");
        assert!(json.contains("tls.crt"), "target path must be in JSON");
        assert!(parsed.get("content").is_none(), "file content must not appear");
        assert!(parsed.get("bytes").is_none(), "file bytes must not appear");
    }

    #[test]
    fn local_file_round_trips_without_modification() {
        let original = SecretMount {
            source: SecretRef::LocalFile {
                path: PathBuf::from("secrets/api-key"),
            },
            target: SecretTarget::File {
                path: PathBuf::from("/run/secrets/api"),
                mode: 0o400,
            },
        };

        let json = serde_json::to_string(&original).unwrap();
        let decoded: SecretMount = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn cluster_round_trips_without_modification() {
        let original = SecretMount {
            source: SecretRef::Cluster {
                name: "stripe-api-key".into(),
            },
            target: SecretTarget::EnvVar {
                name: "STRIPE_SECRET_KEY".into(),
            },
        };

        let json = serde_json::to_string(&original).unwrap();
        let decoded: SecretMount = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn debug_output_contains_only_path_reference_not_value() {
        let mount = SecretMount {
            source: SecretRef::LocalFile {
                path: PathBuf::from("api-key"),
            },
            target: SecretTarget::EnvVar { name: "KEY".into() },
        };

        let debug = format!("{mount:?}");
        // The path reference appears
        assert!(debug.contains("api-key"), "path must be in Debug output");
        // The type names are correct (no phantom value fields)
        assert!(debug.contains("SecretMount"), "SecretMount in debug");
        assert!(debug.contains("LocalFile"), "LocalFile in debug");
        // No base64-like long strings that might indicate encoded value content
        // (structural — SecretRef::LocalFile has no value field, so nothing to leak)
        for part in debug.split_whitespace() {
            assert!(
                part.len() < 128,
                "suspiciously long token in Debug output (possible value leak?): {part}"
            );
        }
    }
}

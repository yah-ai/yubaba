//! One-shot verifier — parses app/yah/desktop/assets/whisper/workload.toml
//! through the Workload envelope + shape validator. Used during R422-F11
//! pickup to confirm the scaffolded TOML deserializes correctly.
//!
//! `cargo run -p workload-spec --example parse_whisper_toml`

fn main() {
    let path = "app/yah/desktop/assets/whisper/workload.toml";
    let src = std::fs::read_to_string(path).expect("read workload.toml");
    let w: workload_spec::Workload = toml::from_str(&src).expect("parse Workload envelope");
    match w {
        workload_spec::Workload::StaticAsset(s) => {
            println!("parsed as StaticAsset");
            println!("  assets:  {}", s.assets.len());
            println!("  aliases: {}", s.aliases.len());
            workload_spec::validate::shape_static_asset(&s).expect("shape_static_asset");
            println!("shape validation: ok");
        }
        other => panic!("expected StaticAsset, got something else: {other:?}"),
    }

    // Also exercise the populated shape — what the operator gets after
    // uncommenting the [[asset]] row + [aliases] entry in the scaffold.
    // Confirms the comment block in workload.toml describes a parseable
    // shape (catches schema drift between the scaffold's docstring and
    // the live StaticAssetWorkload type).
    let populated = r#"
schema_version = "V1"
kind = "static-asset"

[[asset]]
filename = "whisper/distil-large-v3-q5_1.bin"
source   = "sources/distil-large-v3-q5_1.bin"
blake3   = "0000000000000000000000000000000000000000000000000000000000000000"

[aliases]
"whisper-default" = "whisper/distil-large-v3-q5_1.bin"
"#;
    let w: workload_spec::Workload =
        toml::from_str(populated).expect("parse populated shape");
    match w {
        workload_spec::Workload::StaticAsset(s) => {
            assert_eq!(s.assets.len(), 1);
            assert_eq!(s.aliases.len(), 1);
            workload_spec::validate::shape_static_asset(&s)
                .expect("populated shape passes shape validation");
            println!("populated-shape verifier: ok");
        }
        other => panic!("populated shape didn't dispatch to StaticAsset: {other:?}"),
    }
}

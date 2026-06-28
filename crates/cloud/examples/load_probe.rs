//! Diagnostic: load CloudConfig for a camp root and print services +
//! mirror keys (or the parse error spawn_appliances swallows).
fn main() {
    let root = std::env::args()
        .nth(1)
        .expect("usage: load_probe <camp_root>");
    match cloud::config::CloudConfig::load(std::path::Path::new(&root)) {
        Ok(cfg) => {
            for (name, svc) in &cfg.services {
                println!(
                    "service {name}: mirrors={:?}",
                    svc.mirrors.keys().collect::<Vec<_>>()
                );
            }
            if cfg.services.is_empty() {
                println!("no services loaded");
            }
        }
        Err(e) => println!("LOAD ERROR: {e:#}"),
    }
}

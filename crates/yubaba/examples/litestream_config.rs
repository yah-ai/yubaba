//! Print the litestream config `litestream::generate_config` emits, so a live
//! exercise can feed litestream the REAL bytes instead of a hand-typed
//! lookalike.
//!
//! R858-T5 exists because R591-T3's malformed-YAML defect was invisible to a
//! test that only asked whether a substring appeared. A live run that types the
//! config out by hand reproduces that class exactly: it proves litestream
//! accepts *some* config, not the one the fleet writes. This example closes
//! that gap — pipe its stdout straight to the node.
//!
//! ```sh
//! cargo run -p yubaba --example litestream_config -- \
//!   /var/lib/yah-cloud/headscale/headscale.db \
//!   's3://yah-headscale/dev?endpoint=https://<acct>.r2.cloudflarestorage.com'
//! ```

use std::path::PathBuf;

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(db), Some(url)) = (args.next(), args.next()) else {
        eprintln!("usage: litestream_config <headscale-db-path> <s3-url>");
        std::process::exit(2);
    };
    print!("{}", yubaba::litestream::generate_config(&PathBuf::from(db), &url));
}

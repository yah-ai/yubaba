// Exists for exactly one line: tell cargo that `YAH_HOTSHIP_VERSION` is an
// input to this crate's compilation.
//
// `option_env!` is expanded at compile time, but cargo does not know that
// without being told — so without this, changing the variable (or setting it
// for the first time) would NOT invalidate a cached build, and a hot ship
// would happily install a binary still carrying the previous stamp. That is
// the precise failure this whole mechanism exists to prevent, so it would be a
// particularly bad one to reintroduce here.
//
// See `yubaba::VERSION` for why the override exists at all.
fn main() {
    println!("cargo:rerun-if-env-changed=YAH_HOTSHIP_VERSION");
}

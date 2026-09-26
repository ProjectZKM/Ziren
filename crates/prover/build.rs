//! Build script: tell cargo to rebuild when the bundled VK maps change.
//!
//! Without this, `include_bytes!("../vk_map.bin")` in `src/lib.rs`
//! silently uses the stale baked-in copy after a `regen_basefold_vks_for_tests`
//! run, so VERIFY_VK=true keeps reading the old hashes.

fn main() {
    println!("cargo:rerun-if-changed=vk_map.bin");
    println!("cargo:rerun-if-changed=dummy_vk_map.bin");
}

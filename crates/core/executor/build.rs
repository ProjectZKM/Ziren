//! Build-time cfg gate for the MIPS-executor JIT.
//!
//! Sets `cfg(zkm_native_executor_available)` on every Linux x86_64
//! build (so dependent code can detect *capability*) and
//! `cfg(zkm_use_native_executor)` only when JIT use is actually
//! desired (no `profiling` feature).
//!
//! Mirrors SP1's `crates/core/executor/build.rs`.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Re-emit on cargo feature flips.
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_PROFILING");

    println!("cargo::rustc-check-cfg=cfg(zkm_native_executor_available)");
    println!("cargo::rustc-check-cfg=cfg(zkm_use_native_executor)");
    println!("cargo::rustc-check-cfg=cfg(zkm_use_portable_executor)");

    #[cfg(all(target_arch = "x86_64", target_endian = "little", target_os = "linux"))]
    println!("cargo:rustc-cfg=zkm_native_executor_available");

    #[cfg(all(
        target_arch = "x86_64",
        target_endian = "little",
        target_os = "linux",
        not(feature = "profiling")
    ))]
    println!("cargo:rustc-cfg=zkm_use_native_executor");

    #[cfg(not(all(
        target_arch = "x86_64",
        target_endian = "little",
        target_os = "linux",
        not(feature = "profiling")
    )))]
    println!("cargo:rustc-cfg=zkm_use_portable_executor");
}

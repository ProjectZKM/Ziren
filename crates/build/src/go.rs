use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Generate a Go build overlay that patches the Go runtime for zkVM execution.
///
/// This patches `runtime.nanotime1`, `runtime.walltime`, and `runtime.usleep` to avoid
/// unnecessary syscalls in the deterministic zkVM environment. This is a general
/// optimization for any Go program, not specific to any particular guest.
///
/// The generated `overlay.json` is written to `out_dir` and the path is returned.
/// Returns `None` if the overlay source files are not found.
///
/// # Resolution order for the overlay source directory:
/// 1. `ZIREN_GO_OVERLAY_DIR` env var — explicit override
/// 2. `ZKM_DIR` env var — Ziren repo root + `crates/go-runtime/zkvm_overlay`
/// 3. Relative to this crate's `CARGO_MANIFEST_DIR` — for in-tree builds
///
/// # Arguments
///
/// * `out_dir` - Directory to write the generated `go_overlay.json` to (typically `OUT_DIR`).
///
/// # Example
///
/// In your host `build.rs`:
/// ```ignore
/// let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
/// let overlay = zkm_build::generate_go_overlay(&out_dir);
///
/// let mut cmd = Command::new("go");
/// cmd.arg("build").arg("-tags").arg("ziren");
/// if let Some(overlay_path) = &overlay {
///     cmd.arg("-overlay").arg(overlay_path);
/// }
/// cmd.arg(".")
///     .env("GOOS", "linux")
///     .env("GOARCH", "mipsle")
///     .env("GOMIPS", "softfloat");
/// ```
pub fn generate_go_overlay(out_dir: &Path) -> Option<PathBuf> {
    let overlay_dir = if let Ok(p) = env::var("ZIREN_GO_OVERLAY_DIR") {
        PathBuf::from(p)
    } else if let Ok(zkm_dir) = env::var("ZKM_DIR") {
        PathBuf::from(zkm_dir).join("crates/go-runtime/zkvm_overlay")
    } else {
        // zkm-build lives at crates/build/, so go two levels up to repo root.
        let build_crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        build_crate_dir.join("../go-runtime/zkvm_overlay")
    };

    let patched_file = overlay_dir.join("runtime/sys_linux_mipsx.s");
    if !patched_file.exists() {
        println!(
            "cargo:warning=Go runtime overlay not found at {}, skipping",
            patched_file.display()
        );
        return None;
    }
    let patched_file = patched_file.canonicalize().unwrap();
    println!("cargo:rerun-if-changed={}", patched_file.display());

    // Detect the Go toolchain's runtime source path.
    let go_root = Command::new("go")
        .arg("env")
        .arg("GOROOT")
        .output()
        .expect("failed to run `go env GOROOT`");
    let go_root = String::from_utf8(go_root.stdout).unwrap().trim().to_string();
    let original_file = PathBuf::from(&go_root).join("src/runtime/sys_linux_mipsx.s");

    // Write overlay.json to OUT_DIR.
    let overlay_path = out_dir.join("go_overlay.json");
    let overlay_json = format!(
        "{{\n  \"Replace\": {{\n    \"{}\": \"{}\"\n  }}\n}}\n",
        original_file.display(),
        patched_file.display(),
    );
    std::fs::write(&overlay_path, overlay_json).unwrap();
    Some(overlay_path)
}

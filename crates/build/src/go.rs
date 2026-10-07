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
/// The overlay replaces a file of the Go installation that builds the guest, so it applies
/// only when GOROOT is resolved the way that build resolves it. This function asks the `go`
/// on `PATH` from the current directory, with the ambient environment. When the guest is
/// built in another directory (whose `go.mod` may select a toolchain) or with its own
/// `GOTOOLCHAIN`, use [`generate_go_overlay_for`] with that directory and environment.
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
    generate_go_overlay_for(out_dir, Path::new("."), &[])
}

/// [`generate_go_overlay`] for a guest built in `module_dir` with `envs` set on the `go
/// build` command: GOROOT is resolved there and with those variables, so a `toolchain`
/// line in the guest's `go.mod` or a pinned `GOTOOLCHAIN` selects the same Go installation
/// as the build, and the overlay replaces the runtime file that build reads.
///
/// ```ignore
/// let envs = [("GOOS", "linux"), ("GOARCH", "mipsle"), ("GOMIPS", "softfloat"), ("GOTOOLCHAIN", "go1.25.4")];
/// let overlay = zkm_build::generate_go_overlay_for(&out_dir, Path::new("../guest"), &envs);
/// let mut cmd = Command::new("go");
/// cmd.arg("build").arg("-tags").arg("ziren");
/// if let Some(overlay_path) = &overlay {
///     cmd.arg("-overlay").arg(overlay_path);
/// }
/// cmd.arg(".").current_dir("../guest").envs(envs);
/// ```
pub fn generate_go_overlay_for(
    out_dir: &Path,
    module_dir: &Path,
    envs: &[(&str, &str)],
) -> Option<PathBuf> {
    let overlay_dir = if let Ok(p) = env::var("ZIREN_GO_OVERLAY_DIR") {
        PathBuf::from(p)
    } else if let Ok(zkm_dir) = env::var("ZKM_DIR") {
        PathBuf::from(zkm_dir).join("crates/go-runtime/zkvm_overlay")
    } else {
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

    // the GOROOT of the toolchain that builds the guest: resolved where it is built, with its
    // environment (a different Go installation would read a different runtime file, and the
    // overlay would silently not apply)
    let go_env = Command::new("go")
        .arg("env")
        .arg("GOROOT")
        .arg("GOMODCACHE")
        .current_dir(module_dir)
        .envs(envs.iter().copied())
        .output()
        .expect("failed to run `go env GOROOT GOMODCACHE`");
    let go_env = String::from_utf8(go_env.stdout).unwrap();
    let mut go_env = go_env.lines().map(str::trim);
    let go_root = go_env.next().unwrap_or_default().to_string();
    let go_mod_cache = go_env.next().unwrap_or_default();
    // A toolchain that `go` downloaded (because the installed one is older than the `toolchain`
    // line or `GOTOOLCHAIN` asks for) lives in the module cache, and `go build` refuses an
    // overlay there. Without the overlay the guest's `exit` never commits the public values, so
    // no proof of it verifies: stop here instead.
    if !go_mod_cache.is_empty() && Path::new(&go_root).starts_with(go_mod_cache) {
        panic!(
            "the Go toolchain that builds the guest ({go_root}) was downloaded into the module \
             cache, where `go build` cannot apply the zkVM runtime overlay; install that Go \
             version and put its `go` first on PATH"
        );
    }
    let original_file = PathBuf::from(&go_root).join("src/runtime/sys_linux_mipsx.s");
    if !original_file.exists() {
        println!(
            "cargo:warning=Go runtime file {} not found: the zkVM overlay will not apply",
            original_file.display()
        );
    }

    let overlay_path = out_dir.join("go_overlay.json");
    let overlay_json = format!(
        "{{\n  \"Replace\": {{\n    \"{}\": \"{}\"\n  }}\n}}\n",
        original_file.display(),
        patched_file.display(),
    );
    std::fs::write(&overlay_path, overlay_json).unwrap();
    Some(overlay_path)
}

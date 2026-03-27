use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Use local go-ethereum if GETH_DIR is set, otherwise clone from GitHub.
    let geth_dir = if let Ok(dir) = env::var("GETH_DIR") {
        let p = PathBuf::from(dir);
        assert!(p.exists(), "GETH_DIR does not exist: {}", p.display());
        p
    } else {
        let default_dir = out_dir.join("go-ethereum");
        if !default_dir.exists() {
            println!("cloning go-ethereum (un-pinned HEAD)...");
            let status = Command::new("git")
                .args([
                    "clone",
                    "--depth",
                    "1",
                    "https://github.com/ethereum/go-ethereum.git",
                    default_dir.to_str().unwrap(),
                ])
                .status()
                .expect("failed to execute git clone");
            if !status.success() {
                panic!("git clone go-ethereum failed");
            }
        }
        default_dir
    };

    let keeper_dir = geth_dir.join("cmd/keeper");
    assert!(
        keeper_dir.exists(),
        "keeper directory not found: {}",
        keeper_dir.display()
    );

    // Use zkm-build to generate the Go runtime overlay for zkVM.
    let overlay_path = zkm_build::generate_go_overlay(&out_dir);
    let mut cmd = Command::new("go");
    cmd.arg("build")
        .arg("-tags")
        .arg("ziren");
    if let Some(overlay) = &overlay_path {
        cmd.arg("-overlay").arg(overlay);
    }
    cmd.arg(".")
        .current_dir(&keeper_dir)
        .env("GOOS", "linux")
        .env("GOARCH", "mipsle")
        .env("GOMIPS", "softfloat");
    let status = cmd.status().expect("failed to run go build");

    if !status.success() {
        panic!("go build failed");
    }

    let keeper_path = keeper_dir.join("keeper");
    let elf_dest_path = out_dir.join("keeper.elf");
    std::fs::copy(&keeper_path, &elf_dest_path).unwrap();

    // Rerun if local geth source changes.
    if let Ok(dir) = env::var("GETH_DIR") {
        rerun_if_changed_recursive(&Path::new(&dir).join("cmd/keeper"));
        rerun_if_changed_recursive(&Path::new(&dir).join("crypto"));
        rerun_if_changed_recursive(&Path::new(&dir).join("core/vm"));
        rerun_if_changed_recursive(&Path::new(&dir).join("core/stateless"));
    }
    println!("cargo:rerun-if-changed=build.rs");
}

fn rerun_if_changed_recursive(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rerun_if_changed_recursive(&path);
        } else if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "go" || ext == "s" {
                    println!("cargo:rerun-if-changed={}", path.display());
                }
            }
        }
    }
}

use std::path::Path;

use cargo_metadata::Metadata;
use chrono::Local;

pub(crate) fn current_datetime() -> String {
    let now = Local::now();
    now.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Re-run the cargo command if the Cargo.toml or Cargo.lock file changes.
pub(crate) fn cargo_rerun_if_changed(metadata: &Metadata, program_dir: &Path) {
    let dirs = vec![
        program_dir.join("src"),
        program_dir.join("bin"),
        program_dir.join("build.rs"),
        program_dir.join("Cargo.toml"),
    ];
    for dir in dirs {
        if dir.exists() {
            if let Ok(canonical_path) = dir.canonicalize() {
                println!("cargo::rerun-if-changed={}", canonical_path.display());
            } else {
                println!(
                    "cargo::warning=Could not canonicalize path: {dir:?}, using original path"
                );
                println!("cargo::rerun-if-changed={}", dir.display());
            }
        }
    }

    for package in &metadata.packages {
        let manifest = Path::new(package.manifest_path.as_str());
        if let Some(dir) = manifest.parent() {
            for sub in ["src", "bin"] {
                let path = dir.join(sub);
                if path.exists() {
                    println!("cargo::rerun-if-changed={}", path.display());
                }
            }
        }
    }

    println!("cargo::rerun-if-changed={}", metadata.workspace_root.join("Cargo.lock").as_str());

    for package in &metadata.packages {
        for dependency in &package.dependencies {
            if let Some(path) = &dependency.path {
                println!("cargo::rerun-if-changed={}", path.as_str());
            }
        }
    }
}

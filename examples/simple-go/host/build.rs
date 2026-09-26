use std::path::Path;
use std::process::Command;

fn main() {
    let go_src = Path::new("../guest");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");

    let overlay_path = zkm_build::generate_go_overlay(Path::new(&out_dir));
    let mut cmd = Command::new("go");
    cmd.arg("build").arg("-tags").arg("ziren");
    if let Some(overlay) = &overlay_path {
        cmd.arg("-overlay").arg(overlay);
    }
    cmd.arg(".")
        .current_dir(go_src)
        .env("GOOS", "linux")
        .env("GOARCH", "mipsle")
        .env("GOMIPS", "softfloat")
        .env("GOTOOLCHAIN", "go1.25.4");

    let status = cmd.status().expect("failed to build simple go guest");
    if !status.success() {
        panic!("go build failed");
    }

    println!("cargo:rerun-if-changed=../guest");
}

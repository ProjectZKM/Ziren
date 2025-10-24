use std::path::Path;
use std::process::Command;

fn main() {
    let go_src = Path::new("../guest");
    let status = Command::new("go")
        .arg("build")
        .arg(".")
        .current_dir(go_src)
        .env("GOOS", "linux")
        .env("GOARCH", "mipsle")
        .env("GOMIPS", "softfloat")
        .status()
        .expect("failed to build simple go guest");

    if !status.success() {
        panic!("go build failed");
    }

    println!("cargo:rerun-if-changed=../guest");
}

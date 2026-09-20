use std::path::Path;
use std::process::Command;

fn main() {
    let go_src = Path::new("../guest");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");

    // Build against the zkVM Go runtime overlay, the way examples/keeper does.
    // Without it the guest links stock `runtime/sys_linux_mipsx.s`, whose
    // `runtime·exit` issues a raw exit_group; the zkVM commit-then-halt path
    // (zkvm.RuntimeExit -> 8 x SyscallCommit -> SyscallExit) is then reachable
    // only through the `reflect.ValueOf` keep-alive in zkvm_runtime's init(),
    // which Go >= 1.25 prunes -- so the guest publishes no
    // committed_value_digest and every proof fails InvalidPublicValues.
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

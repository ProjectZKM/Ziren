use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let geth_dir = out_dir.join("go-ethereum");

    if !geth_dir.exists() {
        println!("cloning go-ethereum (un-pinned HEAD)...");

        let status = Command::new("git")
            .args([
                "clone",
                "--depth",
                "1",
                "https://github.com/ethereum/go-ethereum.git",
                geth_dir.to_str().unwrap(),
            ])
            .status()
            .expect("failed to execute git clone");

        if !status.success() {
            panic!("git clone go-ethereum failed");
        }
    }

    let keeper_dir = geth_dir.join("cmd/keeper");

    let status = Command::new("go")
        .arg("build")
        .arg("-tags")
        .arg("ziren")
        .arg(".")
        .current_dir(&keeper_dir)
        .env("GOOS", "linux")
        .env("GOARCH", "mipsle")
        .env("GOMIPS", "softfloat")
        .status()
        .expect("failed to run go build");

    if !status.success() {
        panic!("go build failed");
    }

    let keeper_path = geth_dir.join("cmd/keeper/keeper");
    let elf_dest_dir = "/tmp/keeper.elf";
    std::fs::copy(&keeper_path, &elf_dest_dir).unwrap();

    println!("cargo:rerun-if-changed=build.rs");
}

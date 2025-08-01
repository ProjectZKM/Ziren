use anyhow::{Context, Result};
use cargo_metadata::camino::Utf8PathBuf;
use std::{
    io::{BufRead, BufReader},
    path::Path,
    process::{exit, Command, Stdio},
    thread,
};

use crate::{BuildArgs, BUILD_TARGET};

/// Get the arguments to build the program with the arguments from the [`BuildArgs`] struct.
pub(crate) fn get_program_build_args(args: &BuildArgs) -> Vec<String> {
    let mut build_args = vec![
        "build".to_string(),
        "--release".to_string(),
        "--target".to_string(),
        BUILD_TARGET.to_string(),
    ];

    if args.ignore_rust_version {
        build_args.push("--ignore-rust-version".to_string());
    }

    build_args.push("-Ztrim-paths".to_string());

    for p in &args.packages {
        build_args.push("-p".to_string());
        build_args.push(p.to_string());
    }

    for b in &args.binaries {
        build_args.push("--bin".to_string());
        build_args.push(b.to_string());
    }

    if args.no_default_features {
        build_args.push("--no-default-features".to_string());
    }

    if !args.features.is_empty() {
        build_args.push("--features".to_string());
        build_args.push(args.features.join(","));
    }

    if args.locked {
        build_args.push("--locked".to_string());
    }

    build_args
}

/// Rust flags for compilation of C libraries.
pub(crate) fn get_rust_compiler_flags(args: &BuildArgs) -> String {
    let mut rust_flags = vec![
        "-C".to_string(),
        "target-cpu=mips32r2".to_string(),
        "-C".to_string(),
        "target-feature=+crt-static".to_string(),
        "-C".to_string(),
        "link-arg=-nostdlib".to_string(),
        "-C".to_string(),
        "link-arg=-g".to_string(),
        //"-C".to_string(),
        //"link-arg=-nostartfiles".to_string(),
        "-C".to_string(),
        "link-arg=--entry=main".to_string(),
    ];

    for flag in &args.rustflags {
        rust_flags.push("--C".to_string());
        rust_flags.push(flag.to_string());
    }

    for l in &args.libraries {
        rust_flags.push("--C".to_string());
        let library_path = Path::new(l).to_path_buf();
        let library_path: Utf8PathBuf =
            library_path.try_into().expect("Failed to convert PathBuf to Utf8PathBuf");
        let canonicalized_library_path =
            library_path.canonicalize().expect("Failed to canonicalize library path");
        rust_flags.push(format!("link-arg={}", canonicalized_library_path.display()));
    }
    rust_flags.join("\x1f")
}

/// Execute the command and handle the output depending on the context.
pub(crate) fn execute_command(mut command: Command) -> Result<()> {
    // Add necessary tags for stdout and stderr from the command.
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn command")?;
    let stdout = BufReader::new(child.stdout.take().unwrap());
    let stderr = BufReader::new(child.stderr.take().unwrap());

    // Add prefix to the output of the process depending on the context.
    let msg = "[zkm] ";

    // Pipe stdout and stderr to the parent process with [docker] prefix
    let stdout_handle = thread::spawn(move || {
        stdout.lines().for_each(|line| {
            println!("{} {}", msg, line.unwrap());
        });
    });
    stderr.lines().for_each(|line| {
        eprintln!("{} {}", msg, line.unwrap());
    });
    stdout_handle.join().unwrap();

    // Wait for the child process to finish and check the result.
    let result = child.wait()?;
    if !result.success() {
        // Error message is already printed by cargo.
        exit(result.code().unwrap_or(1))
    }
    Ok(())
}

use std::env;
use std::process::Command;

use crate::{BuildArgs, HELPER_TARGET_SUBDIR};
use cargo_metadata::camino::Utf8PathBuf;

use super::utils::{get_program_build_args, get_rust_compiler_flags};

/// Get the command to build the program locally.
pub(crate) fn create_local_command(
    args: &BuildArgs,
    program_dir: &Utf8PathBuf,
    program_metadata: &cargo_metadata::Metadata,
) -> Command {
    let mut command = Command::new("cargo");
    let canonicalized_program_dir =
        program_dir.canonicalize().expect("Failed to canonicalize program directory");

    // When executing the local command:
    // 1. Set the target directory to a subdirectory of the program's target directory to avoid
    //    build
    // conflicts with the parent process. Source: https://github.com/rust-lang/cargo/issues/6412
    // 2. Set the rustup toolchain to Ziren.
    // 3. Set the encoded rust flags.
    // 4. Remove the rustc configuration, otherwise in a build script it will attempt to compile the
    //    program with the toolchain of the normal build process, rather than the Ziren toolchain.

    // The guest target `mipsel-zkm-zkvm-elf` exists only in the Ziren toolchain, so it has to be
    // selected explicitly.  Inside a build script cargo exports `RUSTUP_TOOLCHAIN` and `RUSTC` for
    // the toolchain compiling the HOST crate, and both take precedence over the default toolchain
    // and over any `rust-toolchain` file here --- which is what step 4 above has always claimed to
    // handle and never did.  The symptom is
    //   error loading target specification: could not find specification for target
    //   "mipsel-zkm-zkvm-elf"
    // and it stayed hidden for as long as the build script never actually reran.
    let toolchain = env::var("ZKM_GUEST_TOOLCHAIN").unwrap_or_else(|_| "zkm".to_string());

    command
        .current_dir(canonicalized_program_dir)
        .env("RUSTUP_TOOLCHAIN", toolchain)
        .env_remove("RUSTC")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env("CARGO_ENCODED_RUSTFLAGS", get_rust_compiler_flags(args))
        .env("CARGO_TARGET_DIR", program_metadata.target_directory.join(HELPER_TARGET_SUBDIR))
        .args(get_program_build_args(args));

    if let Some(zkm_cc) = env::var_os("ZIREN_ZKM_CC") {
        command.env("CC", zkm_cc);
    }

    command
}

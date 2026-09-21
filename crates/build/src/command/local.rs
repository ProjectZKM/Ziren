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

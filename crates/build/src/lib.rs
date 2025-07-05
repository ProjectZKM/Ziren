mod build;
mod command;
mod utils;
use build::build_program_internal;
pub use build::{execute_build_program, generate_elf_paths};

use clap::Parser;

pub const BUILD_TARGET: &str = "mipsel-zkm-zkvm-elf";
pub const DEFAULT_OUTPUT_DIR: &str = "elf";
pub const HELPER_TARGET_SUBDIR: &str = "elf-compilation";

/// Compile a Ziren program.
///
/// Additional arguments are useful for configuring the build process, including options for
/// specifying binary and ELF names, ignoring Rust version checks, and enabling specific
/// features.
#[derive(Clone, Parser, Debug)]
pub struct BuildArgs {
    #[clap(
        long,
        action,
        value_delimiter = ',',
        help = "Space or comma separated list of features to activate"
    )]
    pub features: Vec<String>,
    #[clap(
        long,
        action,
        value_delimiter = ',',
        help = "Space or comma separated list of extra flags to invokes `rustc` with"
    )]
    pub rustflags: Vec<String>,
    #[clap(long, action, help = "Do not activate the `default` feature")]
    pub no_default_features: bool,
    #[clap(long, action, help = "Ignore `rust-version` specification in packages")]
    pub ignore_rust_version: bool,
    #[clap(long, action, help = "Assert that `Cargo.lock` will remain unchanged")]
    pub locked: bool,
    #[clap(
        short,
        long,
        action,
        help = "Build only the specified packages",
        num_args = 1..
    )]
    pub packages: Vec<String>,
    #[clap(
        alias = "bin",
        long,
        action,
        help = "Build only the specified binaries",
        num_args = 1..
    )]
    pub binaries: Vec<String>,
    #[clap(long, action, help = "ELF binary name", default_value = "")]
    pub elf_name: String,
    #[clap(
        alias = "out-dir",
        long,
        action,
        help = "Copy the compiled ELF to this directory",
        default_value = DEFAULT_OUTPUT_DIR
    )]
    pub output_directory: String,
    #[clap(
        long,
        action,
        value_delimiter = ',',
        help = "Space or comma separated list of static C/C++ libraries to be linked"
    )]
    pub libraries: Vec<String>,
}

// Implement default args to match clap defaults.
impl Default for BuildArgs {
    fn default() -> Self {
        Self {
            features: vec![],
            rustflags: vec![],
            ignore_rust_version: false,
            packages: vec![],
            binaries: vec![],
            libraries: vec![],
            elf_name: "".to_string(),
            output_directory: DEFAULT_OUTPUT_DIR.to_string(),
            locked: false,
            no_default_features: false,
        }
    }
}

/// Builds the program if the program at the specified path, or one of its dependencies, changes.
///
/// This function monitors the program and its dependencies for changes. If any changes are
/// detected, it triggers a rebuild of the program.
///
/// # Arguments
///
/// * `path` - A string slice that holds the path to the program directory.
///
/// This function is useful for automatically rebuilding the program during development
/// when changes are made to the source code or its dependencies.
///
/// Set the `ZKM_SKIP_PROGRAM_BUILD` environment variable to `true` to skip building the program.
pub fn build_program(path: &str) {
    build_program_internal(path, None)
}

/// Builds the program with the given arguments if the program at path, or one of its dependencies,
/// changes.
///
/// # Arguments
///
/// * `path` - A string slice that holds the path to the program directory.
/// * `args` - A [`BuildArgs`] struct that contains various build configuration options.
///
/// Set the `ZKM_SKIP_PROGRAM_BUILD` environment variable to `true` to skip building the program.
pub fn build_program_with_args(path: &str, args: BuildArgs) {
    build_program_internal(path, Some(args))
}

#[macro_export]
macro_rules! include_elf {
    ($arg:tt) => {
        include_bytes!(env!(concat!("ZKM_ELF_", $arg)))
    };
}

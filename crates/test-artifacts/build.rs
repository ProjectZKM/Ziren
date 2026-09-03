use std::{
    io::{Error, Result},
    path::PathBuf,
};

use zkm_build::build_program_with_args;

fn build_workspace(dir_name: &str) -> Result<()> {
    let workspace_path =
        [env!("CARGO_MANIFEST_DIR"), dir_name].iter().collect::<PathBuf>().canonicalize()?;

    build_program_with_args(
        workspace_path.to_str().ok_or_else(|| {
            Error::other(format!("expected {workspace_path:?} to be valid UTF-8"))
        })?,
        Default::default(),
    );

    Ok(())
}

fn main() -> Result<()> {
    build_workspace("guests")?;

    // `hello-world-imm-wrap-vk` lives in its own workspace.
    build_workspace("guests-imm-wrap-vk")?;

    Ok(())
}

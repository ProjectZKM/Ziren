use anyhow::Result;
use clap::Parser;
use zkm_build::{execute_build_program, BuildArgs};

#[derive(Parser)]
#[command(name = "build", about = "Compile a Ziren program")]
pub struct BuildCmd {
    #[command(flatten)]
    build_args: BuildArgs,
}

impl BuildCmd {
    pub fn run(&self) -> Result<()> {
        execute_build_program(&self.build_args, None)?;

        Ok(())
    }
}

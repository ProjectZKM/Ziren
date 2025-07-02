use anyhow::Result;
use clap::{Parser, Subcommand};
use zkm_cli::{
    commands::{build::BuildCmd, new::NewCmd, vkey::VkeyCmd},
    ZKM_VERSION_MESSAGE,
};

#[derive(Parser)]
#[command(name = "cargo", bin_name = "cargo")]
pub enum Cargo {
    Prove(ProveCli),
}

#[derive(clap::Args)]
#[command(author, about, long_about = None, args_conflicts_with_subcommands = true, version = ZKM_VERSION_MESSAGE)]
pub struct ProveCli {
    #[command(subcommand)]
    pub command: ProveCliCommands,
}

#[derive(Subcommand)]
pub enum ProveCliCommands {
    New(NewCmd),
    Build(BuildCmd),
    Vkey(VkeyCmd),
}

fn main() -> Result<()> {
    let Cargo::Prove(args) = Cargo::parse();

    match args.command {
        ProveCliCommands::New(cmd) => cmd.run(),
        ProveCliCommands::Build(cmd) => cmd.run(),
        ProveCliCommands::Vkey(cmd) => cmd.run(),
    }
}

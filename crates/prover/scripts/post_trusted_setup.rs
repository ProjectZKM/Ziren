use std::path::PathBuf;

use clap::Parser;
use zkm_core_machine::utils::setup_logger;
use zkm_recursion_gnark_ffi::{Groth16Bn254Prover, PlonkBn254Prover};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    build_dir: PathBuf,
    /// Render the PLONK contracts of `build_dir` instead of the Groth16 ones.
    #[clap(long)]
    plonk: bool,
}

pub fn main() {
    setup_logger();
    let args = Args::parse();
    if args.plonk {
        PlonkBn254Prover::build_contracts(args.build_dir);
    } else {
        Groth16Bn254Prover::build_contracts(args.build_dir);
    }
}

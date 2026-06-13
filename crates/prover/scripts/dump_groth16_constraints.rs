// DR23 measure-only helper: generate a fresh wrap proof (CPU dummy), build the
// gnark outer-circuit constraints + witness, and serialize them to
// constraints.json + groth16_witness.json — WITHOUT the heavy groth16
// DummySetup/prove. The go-side TestMainGroth16 (frontend.Compile +
// GetNbConstraints) then measures the R1CS count structurally, exactly the way
// DR19's 25,151,698 was obtained (build_groth16_bn254 writes the same two files
// before its DummySetup).
use std::{fs::File, io::Write, path::PathBuf};

use clap::Parser;
use zkm_core_machine::utils::setup_logger;
use zkm_prover::build::{build_constraints_and_witness, dummy_proof};
use zkm_recursion_gnark_ffi::witness::GnarkWitness;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    build_dir: PathBuf,
}

pub fn main() {
    setup_logger();
    let args = Args::parse();
    std::fs::create_dir_all(&args.build_dir).expect("create build dir");

    let (wrap_vk, wrapped_proof) = dummy_proof();
    let (constraints, witness) = build_constraints_and_witness(&wrap_vk, &wrapped_proof);

    let serialized = serde_json::to_string(&constraints).unwrap();
    let constraints_path = args.build_dir.join("constraints.json");
    File::create(&constraints_path).unwrap().write_all(serialized.as_bytes()).unwrap();

    let gnark_witness = GnarkWitness::new(witness);
    let serialized = serde_json::to_string(&gnark_witness).unwrap();
    let witness_path = args.build_dir.join("groth16_witness.json");
    File::create(&witness_path).unwrap().write_all(serialized.as_bytes()).unwrap();

    println!("[dr23] wrote constraints ({} ops) + witness to {:?}", constraints.len(), args.build_dir);
}

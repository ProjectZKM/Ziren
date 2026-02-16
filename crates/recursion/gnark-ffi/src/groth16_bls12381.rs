use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

use crate::{
    ffi::{
        build_groth16_bls12381, prove_groth16_bls12381, test_groth16_bls12381,
        verify_groth16_bls12381,
    },
    witness::GnarkWitness,
    Groth16Bls12381Proof,
};

use anyhow::Result;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use zkm_recursion_compiler::{
    constraints::Constraint,
    ir::{Config, Witness},
};

/// A prover that can generate Groth16 proofs over BLS12-381 using bindings to Gnark.
#[derive(Debug, Clone)]
pub struct Groth16Bls12381Prover;

impl Groth16Bls12381Prover {
    /// Creates a new [Groth16Bls12381Prover].
    pub fn new() -> Self {
        Self
    }

    pub fn get_vkey_hash(build_dir: &Path) -> [u8; 32] {
        let vkey_path = build_dir.join("groth16_bls12381_vk.bin");
        let vk_bin_bytes = std::fs::read(vkey_path).unwrap();
        Sha256::digest(vk_bin_bytes).into()
    }

    /// Executes the prover in testing mode with a circuit definition and witness.
    pub fn test<C: Config>(constraints: Vec<Constraint>, witness: Witness<C>) {
        let serialized = serde_json::to_string(&constraints).unwrap();

        let mut constraints_file = tempfile::NamedTempFile::new().unwrap();
        constraints_file.write_all(serialized.as_bytes()).unwrap();

        let mut witness_file = tempfile::NamedTempFile::new().unwrap();
        let gnark_witness = GnarkWitness::new(witness);
        let serialized = serde_json::to_string(&gnark_witness).unwrap();
        witness_file.write_all(serialized.as_bytes()).unwrap();

        test_groth16_bls12381(
            witness_file.path().to_str().unwrap(),
            constraints_file.path().to_str().unwrap(),
        )
    }

    /// Builds the Groth16(BLS12-381) circuit locally.
    pub fn build<C: Config>(constraints: Vec<Constraint>, witness: Witness<C>, build_dir: PathBuf) {
        let serialized = serde_json::to_string(&constraints).unwrap();

        let constraints_path = build_dir.join("constraints.json");
        let mut file = File::create(constraints_path).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();

        let witness_path = build_dir.join("groth16_bls12381_witness.json");
        let gnark_witness = GnarkWitness::new(witness);
        let mut file = File::create(witness_path).unwrap();
        let serialized = serde_json::to_string(&gnark_witness).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();

        build_groth16_bls12381(build_dir.to_str().unwrap());
    }

    /// Generates a Groth16(BLS12-381) proof given a witness.
    pub fn prove<C: Config>(
        &self,
        witness: Witness<C>,
        build_dir: PathBuf,
    ) -> Groth16Bls12381Proof {
        let mut witness_file = tempfile::NamedTempFile::new().unwrap();
        let gnark_witness = GnarkWitness::new(witness);
        let serialized = serde_json::to_string(&gnark_witness).unwrap();
        witness_file.write_all(serialized.as_bytes()).unwrap();

        let mut proof = prove_groth16_bls12381(
            build_dir.to_str().unwrap(),
            witness_file.path().to_str().unwrap(),
        );
        proof.groth16_vkey_hash = Self::get_vkey_hash(&build_dir);
        proof
    }

    /// Verify a Groth16(BLS12-381) proof and public inputs.
    pub fn verify(
        &self,
        proof: &Groth16Bls12381Proof,
        vkey_hash: &BigUint,
        committed_values_digest: &BigUint,
        build_dir: &Path,
    ) -> Result<()> {
        if proof.groth16_vkey_hash != Self::get_vkey_hash(build_dir) {
            return Err(anyhow::anyhow!(
                "Proof vkey hash does not match circuit vkey hash, it was generated with a different circuit."
            ));
        }
        verify_groth16_bls12381(
            build_dir
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Failed to convert build dir to string"))?,
            &proof.raw_proof,
            &vkey_hash.to_string(),
            &committed_values_digest.to_string(),
        )
        .map_err(|e| anyhow::anyhow!("failed to verify proof: {e}"))
    }
}

impl Default for Groth16Bls12381Prover {
    fn default() -> Self {
        Self::new()
    }
}

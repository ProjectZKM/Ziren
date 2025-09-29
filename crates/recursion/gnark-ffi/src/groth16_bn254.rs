use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use crate::{
    ffi::{build_groth16_bn254, prove_groth16_bn254, test_groth16_bn254, verify_groth16_bn254},
    witness::GnarkWitness,
    Groth16Bn254Proof,
};

use anyhow::Result;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use zkm_core_machine::ZKM_CIRCUIT_VERSION;
use zkm_recursion_compiler::{
    constraints::Constraint,
    ir::{Config, Witness},
};

/// A prover that can generate proofs with the PLONK protocol using bindings to Gnark.
#[derive(Debug, Clone)]
pub struct Groth16Bn254Prover;

/// A prover that can generate proofs with the Groth16 protocol using bindings to Gnark.
impl Groth16Bn254Prover {
    /// Creates a new [Groth16Bn254Prover].
    pub fn new() -> Self {
        Self
    }

    pub fn get_vkey_hash(build_dir: &Path) -> [u8; 32] {
        let vkey_path = build_dir.join("groth16_vk.bin");
        let vk_bin_bytes = std::fs::read(vkey_path).unwrap();
        Sha256::digest(vk_bin_bytes).into()
    }

    /// Executes the prover in testing mode with a circuit definition and witness.
    pub fn test<C: Config>(constraints: Vec<Constraint>, witness: Witness<C>) {
        let serialized = serde_json::to_string(&constraints).unwrap();

        // Write constraints.
        let mut constraints_file = tempfile::NamedTempFile::new().unwrap();
        constraints_file.write_all(serialized.as_bytes()).unwrap();

        // Write witness.
        let mut witness_file = tempfile::NamedTempFile::new().unwrap();
        let gnark_witness = GnarkWitness::new(witness);
        let serialized = serde_json::to_string(&gnark_witness).unwrap();
        witness_file.write_all(serialized.as_bytes()).unwrap();

        test_groth16_bn254(
            witness_file.path().to_str().unwrap(),
            constraints_file.path().to_str().unwrap(),
        )
    }

    pub fn build_contracts(build_dir: PathBuf) {
        // Write the corresponding asset files to the build dir.
        let zkm_verifier_path = build_dir.join("ZKMVerifierGroth16.sol");
        let vkey_hash = Self::get_vkey_hash(&build_dir);
        let zkm_verifier_str = include_str!("../assets/ZKMVerifierGroth16.txt")
            .replace("{ZKM_CIRCUIT_VERSION}", ZKM_CIRCUIT_VERSION)
            .replace("{VERIFIER_HASH}", format!("0x{}", hex::encode(vkey_hash)).as_str())
            .replace("{PROOF_SYSTEM}", "Groth16");
        let mut zkm_verifier_file = File::create(zkm_verifier_path).unwrap();
        zkm_verifier_file.write_all(zkm_verifier_str.as_bytes()).unwrap();

        let groth16_verifier_path = build_dir.join("Groth16Verifier.sol");
        Self::modify_groth16_verifier(&groth16_verifier_path);
    }

    /// Builds the Groth16 circuit locally.
    pub fn build<C: Config>(constraints: Vec<Constraint>, witness: Witness<C>, build_dir: PathBuf) {
        let serialized = serde_json::to_string(&constraints).unwrap();

        // Write constraints.
        let constraints_path = build_dir.join("constraints.json");
        let mut file = File::create(constraints_path).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();

        // Write witness.
        let witness_path = build_dir.join("groth16_witness.json");
        let gnark_witness = GnarkWitness::new(witness);
        let mut file = File::create(witness_path).unwrap();
        let serialized = serde_json::to_string(&gnark_witness).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();

        // Build the circuit.
        build_groth16_bn254(build_dir.to_str().unwrap());

        // Build the contracts.
        Self::build_contracts(build_dir);
    }

    /// Generates a Groth16 proof given a witness.
    pub fn prove<C: Config>(&self, witness: Witness<C>, build_dir: PathBuf) -> Groth16Bn254Proof {
        // Write witness.
        let mut witness_file = tempfile::NamedTempFile::new().unwrap();
        let gnark_witness = GnarkWitness::new(witness);
        let serialized = serde_json::to_string(&gnark_witness).unwrap();
        witness_file.write_all(serialized.as_bytes()).unwrap();

        let mut proof =
            prove_groth16_bn254(build_dir.to_str().unwrap(), witness_file.path().to_str().unwrap());
        proof.groth16_vkey_hash = Self::get_vkey_hash(&build_dir);
        proof
    }

    /// Verify a Groth16proof and verify that the supplied vkey_hash and committed_values_digest
    /// match.
    pub fn verify(
        &self,
        proof: &Groth16Bn254Proof,
        vkey_hash: &BigUint,
        committed_values_digest: &BigUint,
        build_dir: &Path,
    ) -> Result<()> {
        if proof.groth16_vkey_hash != Self::get_vkey_hash(build_dir) {
            return Err(anyhow::anyhow!(
                "Proof vkey hash does not match circuit vkey hash, it was generated with a different circuit."
            ));
        }
        verify_groth16_bn254(
            build_dir
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Failed to convert build dir to string"))?,
            &proof.raw_proof,
            &vkey_hash.to_string(),
            &committed_values_digest.to_string(),
        )
        .map_err(|e| anyhow::anyhow!("failed to verify proof: {e}"))
    }

    /// Modify the Groth16Verifier so that it works with the ZKMVerifier.
    fn modify_groth16_verifier(file_path: &Path) {
        let mut content = String::new();
        File::open(file_path).unwrap().read_to_string(&mut content).unwrap();

        content = content
            .replace("pragma solidity ^0.8.0;", "pragma solidity ^0.8.20;")
            .replace("contract Verifier {", "contract Groth16Verifier {")
            .replace("function verifyProof(", "function Verify(");

        let mut file = File::create(file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
    }
}

impl Default for Groth16Bn254Prover {
    fn default() -> Self {
        Self::new()
    }
}

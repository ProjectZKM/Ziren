use crate::{DvSnarkBn254Proof, Groth16Bls12381Proof, Groth16Bn254Proof, PlonkBn254Proof};

fn native_required() -> ! {
    panic!("zkm-recursion-gnark-ffi requires feature `native`")
}

pub fn build_plonk_bn254(_data_dir: &str) {
    native_required()
}

pub fn prove_plonk_bn254(_data_dir: &str, _witness_path: &str) -> PlonkBn254Proof {
    native_required()
}

pub fn verify_plonk_bn254(
    _data_dir: &str,
    _proof: &str,
    _vkey_hash: &str,
    _committed_values_digest: &str,
) -> Result<(), String> {
    native_required()
}

pub fn test_plonk_bn254(_witness_json: &str, _constraints_json: &str) {
    native_required()
}

pub fn build_groth16_bn254(_data_dir: &str) {
    native_required()
}

pub fn prove_groth16_bn254(_data_dir: &str, _witness_path: &str) -> Groth16Bn254Proof {
    native_required()
}

pub fn verify_groth16_bn254(
    _data_dir: &str,
    _proof: &str,
    _vkey_hash: &str,
    _committed_values_digest: &str,
) -> Result<(), String> {
    native_required()
}

pub fn test_groth16_bn254(_witness_json: &str, _constraints_json: &str) {
    native_required()
}

pub fn build_groth16_bls12381(_data_dir: &str) {
    native_required()
}

pub fn prove_groth16_bls12381(_data_dir: &str, _witness_path: &str) -> Groth16Bls12381Proof {
    native_required()
}

pub fn verify_groth16_bls12381(
    _data_dir: &str,
    _proof: &str,
    _vkey_hash: &str,
    _committed_values_digest: &str,
) -> Result<(), String> {
    native_required()
}

pub fn test_groth16_bls12381(_witness_json: &str, _constraints_json: &str) {
    native_required()
}

pub fn build_dvsnark_bn254(_data_dir: &str, _store_dir: &str) {
    native_required()
}

pub fn prove_dvsnark_bn254(
    _data_dir: &str,
    _witness_path: &str,
    _store_dir: &str,
) -> DvSnarkBn254Proof {
    native_required()
}

pub fn test_koalabear_poseidon2() {
    native_required()
}

use p3_koala_bear::KoalaBear;
use std::{
    borrow::Borrow,
    fs::{metadata, File},
    io::Write,
    path::PathBuf,
};
use zkm_core_executor::ZKMContext;
use zkm_core_machine::io::ZKMStdin;
use zkm_recursion_circuit::{
    hash::FieldHasherVariable,
    machine::{
        wrap_basefold::{verify_wrap_basefold_core, ZKMWrapBasefoldWitnessValues},
        PublicValuesOutputDigest, ZKMMerkleProofWitnessValues, ZKMWrapBasefoldWitnessVariable,
    },
};
use zkm_recursion_compiler::{
    config::OuterConfig,
    constraints::{Constraint, ConstraintCompiler},
    ir::Builder,
};

pub use zkm_recursion_core::stark::{outer_perm, zkm_dev_mode, zkm_imm_wrap_vk_mode};
use zkm_recursion_core::{air::RecursionPublicValues, hash_vkey_with_part_vk};

pub use zkm_recursion_circuit::witness::{OuterWitness, Witnessable};

use zkm_pcs::{ShardProof, StarkVerifyingKey, ZKMProverOpts};
use zkm_recursion_gnark_ffi::{DvSnarkBn254Prover, Groth16Bn254Prover, PlonkBn254Prover};

use crate::{
    utils::{koalabear_bytes_to_bn254, koalabears_to_bn254, words_to_bytes},
    OuterSC, WrapAir, ZKMProver,
};

pub const PART_STARK_VK_PATH: &str = "part_stark_vk.bin";

/// Tries to build the PLONK artifacts inside the development directory.
pub fn try_build_plonk_bn254_artifacts_dev(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
) -> PathBuf {
    let build_dir = plonk_bn254_artifacts_dev_dir();
    println!("[zkm] building plonk bn254 artifacts in development mode");
    build_plonk_bn254_artifacts(template_vk, template_proof, &build_dir);
    build_dir
}

/// Tries to build the groth16 bn254 artifacts in the current environment.
pub fn try_build_groth16_bn254_artifacts_dev(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
) -> PathBuf {
    let build_dir = groth16_bn254_artifacts_dev_dir();
    println!("[zkm] building groth16 bn254 artifacts in development mode");
    build_groth16_bn254_artifacts(template_vk, template_proof, &build_dir);
    build_dir
}

/// Tries to build the dv-snark bn254 artifacts in the current environment.
pub fn try_build_dvsnark_bn254_artifacts_dev(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
    store_dir: &PathBuf,
) -> PathBuf {
    tracing::info!("build dvsnark artifacts dev");
    let build_dir = dvsnark_bn254_artifacts_dev_dir();

    let r1cs_to_dvsnark_path = store_dir.join("r1cs_to_dvsnark");
    let r1cs_cached_path = store_dir.join("r1cs_cached");

    let mut r1cs_to_dvsnark_content_exist = false;
    if let Ok(md) = metadata(&r1cs_to_dvsnark_path) {
        if md.len() > 1024 {
            r1cs_to_dvsnark_content_exist = true;
        }
    }

    let mut r1cs_cached_content_exist = false;
    if let Ok(md) = metadata(&r1cs_cached_path) {
        if md.len() > 1024 {
            r1cs_cached_content_exist = true;
        }
    }

    if r1cs_cached_content_exist && r1cs_to_dvsnark_content_exist {
        println!("[zkm] build dir contains cached r1cs");
        return build_dir; // early return if content already exist
    }

    println!("[zkm] building dv-snark bn254 artifacts in development mode");
    build_dvsnark_bn254_artifacts(template_vk, template_proof, &build_dir, store_dir);
    build_dir
}

/// Gets the directory where the PLONK artifacts are installed in development mode.
pub fn plonk_bn254_artifacts_dev_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".zkm").join("circuits").join("dev")
}

/// Gets the directory where the groth16 artifacts are installed in development mode.
pub fn groth16_bn254_artifacts_dev_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".zkm").join("circuits").join("dev")
}

/// Gets the directory where the dv-snark artifacts are installed in development mode.
pub fn dvsnark_bn254_artifacts_dev_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".zkm").join("circuits").join("dev")
}

/// Build the plonk bn254 artifacts to the given directory for the given verification key and
/// template proof.
pub fn build_plonk_bn254_artifacts(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
    build_dir: impl Into<PathBuf>,
) {
    let build_dir = build_dir.into();
    std::fs::create_dir_all(&build_dir).expect("failed to create build directory");
    let (constraints, witness) = build_constraints_and_witness(template_vk, template_proof);
    PlonkBn254Prover::build(constraints, witness, build_dir);
}

/// Build the groth16 bn254 artifacts to the given directory for the given verification key and
/// template proof.
pub fn build_groth16_bn254_artifacts(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
    build_dir: impl Into<PathBuf>,
) {
    let build_dir = build_dir.into();
    std::fs::create_dir_all(&build_dir).expect("failed to create build directory");
    let (constraints, witness) = build_constraints_and_witness(template_vk, template_proof);
    Groth16Bn254Prover::build(constraints, witness, build_dir.clone());

    // Serialize the part vk to a file
    let serialized = bincode::serialize(&template_vk.part_vk()).unwrap();
    let path = build_dir.join(PART_STARK_VK_PATH);
    let mut file = File::create(path).unwrap();
    file.write_all(&serialized).unwrap();
}

/// Build the dv-snark bn254 artifacts to the given directory for the given verification key and
/// template proof.
pub fn build_dvsnark_bn254_artifacts(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
    build_dir: impl Into<PathBuf>,
    store_dir: impl Into<PathBuf>,
) {
    let build_dir = build_dir.into();
    let store_dir = store_dir.into();
    std::fs::create_dir_all(&build_dir).expect("failed to create build directory");
    std::fs::create_dir_all(&store_dir).expect("failed to create store directory");
    let (constraints, witness) = build_constraints_and_witness(template_vk, template_proof);
    DvSnarkBn254Prover::build(constraints, witness, build_dir, store_dir);
}

/// Builds the plonk bn254 artifacts to the given directory.
///
/// This may take a while as it needs to first generate a dummy proof and then it needs to compile
/// the circuit.
pub fn build_plonk_bn254_artifacts_with_dummy(build_dir: impl Into<PathBuf>) {
    let (wrap_vk, wrapped_proof) = dummy_proof();
    crate::build::build_plonk_bn254_artifacts(&wrap_vk, &wrapped_proof, build_dir.into());
}

/// Builds the groth16 bn254 artifacts to the given directory.
///
/// This may take a while as it needs to first generate a dummy proof and then it needs to compile
/// the circuit.
pub fn build_groth16_bn254_artifacts_with_dummy(build_dir: impl Into<PathBuf>) {
    let (wrap_vk, wrapped_proof) = dummy_proof();
    crate::build::build_groth16_bn254_artifacts(&wrap_vk, &wrapped_proof, build_dir.into());
}

/// Build the verifier constraints and template witness for the circuit.
pub fn build_constraints_and_witness(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
) -> (Vec<Constraint>, OuterWitness<OuterConfig>) {
    tracing::info!("building verifier constraints");
    // #H (BaseFold-over-BN254 wrap port): the wrap STARK is proved over
    // BaseFold-BN254; the gnark outer circuit verifies its basefold shard proof.
    let basefold_proof = *template_proof.basefold_shard_proof.clone().expect(
        "build_constraints_and_witness: wrap proof missing basefold_shard_proof \
             (the outer ring must be a BaseFold config)",
    );
    let vk_merkle_data = ZKMMerkleProofWitnessValues::<OuterSC>::dummy(1, 1);
    let template_input = ZKMWrapBasefoldWitnessValues {
        vks_and_proofs: vec![(template_vk.clone(), basefold_proof)],
        vk_merkle_data,
    };
    let constraints =
        tracing::info_span!("wrap circuit").in_scope(|| build_outer_circuit(&template_input));

    let pv: &RecursionPublicValues<KoalaBear> = template_proof.public_values.as_slice().borrow();
    let mut vkey_hash = koalabears_to_bn254(&pv.zkm_vk_digest);

    if zkm_imm_wrap_vk_mode() {
        vkey_hash = hash_vkey_with_part_vk(&template_vk.part_vk(), vkey_hash);
    }

    let committed_values_digest_bytes: [KoalaBear; 32] =
        words_to_bytes(&pv.committed_value_digest).try_into().unwrap();
    let committed_values_digest = koalabear_bytes_to_bn254(&committed_values_digest_bytes);

    tracing::info!("building template witness");
    let mut witness = OuterWitness::default();
    template_input.write(&mut witness);
    witness.write_committed_values_digest(committed_values_digest);
    witness.write_vkey_hash(vkey_hash);

    (constraints, witness)
}

/// Generate a dummy proof that we can use to build the circuit. We need this to know the shape of
/// the proof.
pub fn dummy_proof() -> (StarkVerifyingKey<OuterSC>, ShardProof<OuterSC>) {
    let elf = include_bytes!("../elf/mipsel-zkm-zkvm-elf");

    tracing::info!("initializing prover");
    let prover: ZKMProver = ZKMProver::new();
    let opts = ZKMProverOpts::default();
    let context = ZKMContext::default();

    tracing::info!("setup elf");
    let (_, pk_d, program, vk) = prover.setup(elf);

    tracing::info!("prove core");
    let mut stdin = ZKMStdin::new();
    stdin.write(&500u32);
    let core_proof = prover.prove_core(&pk_d, program, &stdin, opts, context).unwrap();

    tracing::info!("compress");
    let compressed_proof = prover.compress(&vk, core_proof, vec![], opts).unwrap();

    tracing::info!("shrink");
    let shrink_proof = prover.shrink(compressed_proof, opts).unwrap();

    tracing::info!("wrap");
    let wrapped_proof = prover.wrap_bn254(shrink_proof, opts).unwrap();

    (wrapped_proof.vk, wrapped_proof.proof)
}

fn build_outer_circuit(template_input: &ZKMWrapBasefoldWitnessValues<OuterSC>) -> Vec<Constraint> {
    let wrap_machine = WrapAir::wrap_machine(OuterSC::default());
    // PER-STAGE cube: the outer (gnark/BN254) circuit verifies the WRAP
    // proof; the verifier asserts `zerocheck_proof.point.dim ==
    // pcs_max_log_row_count`, so build with the input proof's zerocheck dim
    // (floored at BASE=22).  NO-OP for FIX-on (input dim ≤ 22).  The proof
    // type is `BasefoldShardProof<InnerVal, InnerChallenge>` for both rings.
    let base = zkm_pcs::shard_level::verifier::BasefoldShardVerifier::production_default()
        .max_log_row_count;
    let in_dim = template_input
        .vks_and_proofs
        .iter()
        .map(|(_vk, proof)| proof.zerocheck_proof.point_and_eval.0.len())
        .max()
        .unwrap_or(0);
    let max_log_row_count = base.max(in_dim);
    if max_log_row_count != base {
        eprintln!(
            "PERSTAGE-CUBE build[outer_bn254]: base={base} input_zc_dim={in_dim} \
             -> cube={max_log_row_count} (FIX-off input proof above base)"
        );
    }

    let wrap_span = tracing::debug_span!("build wrap circuit").entered();
    let mut builder = Builder::<OuterConfig>::default();

    // Template vk for the commit/pc_start binding.
    let template_vk = template_input.vks_and_proofs.first().unwrap().0.clone();
    // Read the BaseFold wrap witness.
    let input = template_input.read(&mut builder);
    let ZKMWrapBasefoldWitnessVariable {
        vks_and_proofs,
        chip_cumulative_sums_per_input,
        chip_heights_per_input,
        vk_merkle_data: _,
    } = input;

    if !zkm_imm_wrap_vk_mode() {
        // Constrain the witnessed vk to the template (commit + pc_start). This +
        // the public vkey_hash bind the wrap vk (gnark layer skips the vk-merkle,
        // mirroring SP1WrapVerifier).
        let vk = &vks_and_proofs.first().unwrap().0;
        let cap: &[_] = template_vk.commit.as_ref();
        let expected_commitment = [builder.eval(cap[0][0])];
        OuterSC::assert_digest_eq(&mut builder, expected_commitment, vk.commitment);
        builder.assert_felt_eq(vk.pc_start, template_vk.pc_start);
    }

    // #H (BaseFold-over-BN254 wrap port): verify the wrap STARK proof over the
    // BaseFold jagged-PCS on BN254 via the merkle-free core (plain shard verify).
    let [(vk_legacy, proof_tuple)] = vks_and_proofs.try_into().ok().unwrap();
    verify_wrap_basefold_core::<OuterConfig, OuterSC, WrapAir<KoalaBear>>(
        &mut builder,
        vk_legacy,
        proof_tuple,
        chip_cumulative_sums_per_input,
        chip_heights_per_input,
        &wrap_machine,
        max_log_row_count,
        PublicValuesOutputDigest::Root,
    );

    let mut backend = ConstraintCompiler::<OuterConfig>::default();
    let operations = backend.emit(builder.into_operations());
    wrap_span.exit();

    operations
}

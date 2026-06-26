//! UNTRACKED G1 measurement (#88/#82): build the SINGLE-SHARD normalize program
//! from a dummy and print a stable content digest of the serialized program.
//! Run on the current tree AND at HEAD (git stash) to prove the normalize
//! program is BYTE-IDENTICAL (the single-shard collapse removed only dead
//! multi-shard branches).
use std::hash::{Hash, Hasher};

use zkm_core_machine::mips::MipsAir;
use zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2;
use zkm_pcs::shape::OrderedShape;
use zkm_recursion_circuit::machine::{
    basefold_programs::build_normalize_basefold_program, ZKMCoreBasefoldWitnessValues,
    ZKMRecursionShape,
};

fn main() {
    let config = KoalaBearPoseidon2::default();
    let machine = MipsAir::<p3_koala_bear::KoalaBear>::machine(config);
    let max_log_row_count =
        zkm_pcs::shard_level::verifier::BasefoldShardVerifier::production_default()
            .max_log_row_count;

    // A few representative single-shard normalize shapes (one per cluster-ish
    // chip-set). All arity-1.
    let shapes: Vec<(&str, ZKMRecursionShape)> = vec![
        (
            "addsub_h4",
            ZKMRecursionShape {
                proof_shapes: vec![OrderedShape::from_log2_heights(&[("AddSub".to_string(), 4)])],
                is_complete: false,
            },
        ),
        (
            "addsub_bitwise_h3",
            ZKMRecursionShape {
                proof_shapes: vec![OrderedShape::from_log2_heights(&[
                    ("AddSub".to_string(), 3),
                    ("Bitwise".to_string(), 3),
                ])],
                is_complete: false,
            },
        ),
        (
            "cpu_h8",
            ZKMRecursionShape {
                proof_shapes: vec![OrderedShape::from_log2_heights(&[
                    ("Cpu".to_string(), 8),
                    ("AddSub".to_string(), 6),
                    ("Bitwise".to_string(), 5),
                ])],
                is_complete: false,
            },
        ),
    ];

    for (label, shape) in &shapes {
        let witness =
            ZKMCoreBasefoldWitnessValues::<KoalaBearPoseidon2>::dummy(&machine, shape);
        let program = build_normalize_basefold_program::<MipsAir<p3_koala_bear::KoalaBear>>(
            &machine,
            &witness,
            max_log_row_count,
        );
        let bytes = bincode::serialize(&program).expect("serialize program");
        let mut h = std::collections::hash_map::DefaultHasher::new();
        bytes.hash(&mut h);
        let digest = h.finish();
        println!(
            "G1_NORMALIZE label={label} instr={} bytes={} digest={:#018x}",
            program.instruction_count(),
            bytes.len(),
            digest
        );
    }
}

//! Count the operations of the wrap circuit, by opcode.
//!
//! ```text
//! wrap_circuit_census
//! ```
//!
//! Proves the template program through the wrap, builds the outer circuit
//! over that proof and prints how many of each operation it holds.  The size
//! of the gnark circuit follows these counts, the extension products, the
//! inverses and the hash permutations first, so a change of schedule or of
//! field can be sized here without compiling the circuit.  With
//! `WRAP_CENSUS_GROTH16=1` it then compiles and proves the circuit for
//! Groth16, which logs the constraint count.

use std::collections::BTreeMap;

use zkm_pcs::{ShardProof, StarkVerifyingKey};
use zkm_prover::{
    build::{build_constraints_and_witness, dummy_proof, wrap_circuit_operations},
    OuterSC,
};
use zkm_recursion_compiler::{config::OuterConfig, ir::DslIr};

const KINDS: [&str; 6] =
    ["MulE", "MulEF", "MulF", "DivE", "CircuitFelt2Var", "CircuitPoseidon2Permute"];

type PhaseCounts = Vec<(String, [usize; KINDS.len() + 1])>;

/// Adds the operations of `ops`, nested blocks included, to the phase the
/// verifier's markers put them in: the two outermost markers name it.
fn count_phases(ops: &[DslIr<OuterConfig>], stack: &mut Vec<String>, phases: &mut PhaseCounts) {
    for op in ops {
        match op {
            DslIr::CycleTrackerV2Enter(name) => stack.push(name.clone()),
            DslIr::CycleTrackerV2Exit => {
                stack.pop();
            }
            DslIr::Parallel(blocks) => {
                for block in blocks {
                    count_phases(&block.ops.vec, stack, phases);
                }
            }
            _ => {
                let phase = if stack.is_empty() {
                    "(outside)".to_string()
                } else {
                    stack[..stack.len().min(2)].join("/")
                };
                let debug = format!("{op:?}");
                let name = debug.split('(').next().unwrap_or("");
                let name = name.strip_suffix('I').unwrap_or(name);
                let index = match phases.iter().position(|(p, _)| *p == phase) {
                    Some(index) => index,
                    None => {
                        phases.push((phase, [0; KINDS.len() + 1]));
                        phases.len() - 1
                    }
                };
                let counts = &mut phases[index].1;
                counts[KINDS.len()] += 1;
                if let Some(kind) = KINDS.iter().position(|k| *k == name) {
                    counts[kind] += 1;
                }
            }
        }
    }
}

/// The operations each phase of the verifier emits: the products, inverses
/// and hashes, which set the circuit's size.
fn phase_census(vk: &StarkVerifyingKey<OuterSC>, proof: &ShardProof<OuterSC>) {
    let operations = wrap_circuit_operations(vk, proof);
    let mut phases = PhaseCounts::new();
    count_phases(&operations.vec, &mut vec![], &mut phases);
    let header = KINDS.map(|k| format!("{k:>9.9}")).join(" ");
    println!("wrap phases: {:<42} {:>8} {header}", "", "all");
    for (phase, counts) in phases {
        let row: Vec<String> = counts[..KINDS.len()].iter().map(|c| format!("{c:>9}")).collect();
        println!("wrap phases: {:<42} {:>8} {}", phase, counts[KINDS.len()], row.join(" "));
    }
}

fn main() {
    zkm_core_machine::utils::setup_logger();
    let lsh = zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize;
    let wrap = zkm_pcs::whir::jagged::wrap_whir_config(lsh);
    let queries: Vec<usize> = wrap.round_parameters.iter().map(|r| r.num_queries).collect();
    println!(
        "wrap schedule: first rate 2^-{}, folds {:?}, queries {:?} then {} final",
        wrap.starting_log_inv_rate,
        wrap.round_parameters.iter().map(|r| r.folding_factor).collect::<Vec<_>>(),
        &queries[..queries.len() - 1],
        wrap.final_queries,
    );

    let (vk, proof) = dummy_proof();
    let j = &proof.jagged_shard_proof;
    println!(
        "wrap proof: {} chips, {} bytes",
        j.opened_values.chips.len(),
        bincode::serialized_size(&proof).unwrap()
    );
    phase_census(&vk, &proof);
    let (constraints, witness) = build_constraints_and_witness(&vk, &proof);
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for constraint in &constraints {
        *counts.entry(format!("{:?}", constraint.opcode)).or_default() += 1;
    }
    let mut counts: Vec<(String, usize)> = counts.into_iter().collect();
    counts.sort_by(|a, b| b.1.cmp(&a.1));
    println!("wrap circuit: {} operations", constraints.len());
    for (opcode, count) in counts {
        println!("    {opcode:<28} {count}");
    }
    if std::env::var("WRAP_CENSUS_GROTH16").is_ok_and(|v| v == "1") {
        println!("wrap circuit: compiling for Groth16, the constraint count follows");
        zkm_recursion_gnark_ffi::Groth16Bn254Prover::test(constraints, witness);
    }
}

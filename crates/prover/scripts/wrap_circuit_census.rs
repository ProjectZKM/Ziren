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
//! field can be sized here without compiling the circuit.

use std::collections::BTreeMap;

use zkm_prover::build::{build_constraints_and_witness, dummy_proof};

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
    let (constraints, _) = build_constraints_and_witness(&vk, &proof);
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
}

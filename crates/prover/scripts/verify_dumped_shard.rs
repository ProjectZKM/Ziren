//! Verify a shard proof that production dumped, with the HOST verifier.
//!
//! When the fused leaf refuses to execute a core shard proof twice, the worker
//! writes that proof to `ZIREN_LEAF_FAIL_DIR` (`prover/src/worker/core.rs`).
//! The retry already establishes that the failure is a deterministic property
//! of the proof rather than of the walk; this decides WHICH side is wrong:
//!
//!   host REJECTS  -> the core prover emitted an invalid shard proof and the
//!                    in-circuit verifier was right to refuse it;
//!   host ACCEPTS  -> the proof is sound and the IN-CIRCUIT verifier diverges
//!                    from the host, i.e. production is losing honest blocks.
//!
//! The shard is verified alone, so the cross-shard bookkeeping of the full
//! `ZKMProver::verify` (shard numbering, global cumulative sum) is neither run
//! nor expected to hold -- only this shard's own PCS/AIR verdict.
//!
//! Run:
//!   cargo run --release -p zkm-prover --bin verify_dumped_shard -- <proof.bin> <vk.bin>

use core::borrow::Borrow;

use p3_challenger::CanObserve;
use zkm_pcs::{MachineProver, ShardProof, StarkGenericConfig, Verifier};
use zkm_prover::{
    components::DefaultProverComponents, CoreSC, HashableKey, ZKMProver, ZKMVerifyingKey,
};

fn main() {
    let mut args = std::env::args().skip(1);
    let proof_path = args.next().expect("usage: verify_dumped_shard <proof.bin> <vk.bin>");
    let vk_path = args.next().expect("usage: verify_dumped_shard <proof.bin> <vk.bin>");

    let proof: ShardProof<CoreSC> = bincode::deserialize(
        &std::fs::read(&proof_path).unwrap_or_else(|e| panic!("read {proof_path}: {e}")),
    )
    .unwrap_or_else(|e| panic!("decode {proof_path}: {e}"));
    let vk: ZKMVerifyingKey = bincode::deserialize(
        &std::fs::read(&vk_path).unwrap_or_else(|e| panic!("read {vk_path}: {e}")),
    )
    .unwrap_or_else(|e| panic!("decode {vk_path}: {e}"));

    let prover = ZKMProver::<DefaultProverComponents>::new();
    let machine = prover.core_prover.machine();
    let chips = machine.shard_chips_named(&proof.jagged_shard_proof.chip_heights).collect::<Vec<_>>();
    let prep_chip_dims = machine.preprocessed_chip_dims();

    println!("proof   : {proof_path}");
    println!("chips   : {}", chips.len());

    // The verdict is only as good as the verifying key: the challenger is
    // SEEDED from it, so a key belonging to another program resamples
    // `alpha`/`beta` and makes even an honest proof look unbalanced.  A single
    // REJECT therefore proves nothing on its own.  Try every candidate key and
    // report each verdict, so a rejection under the right key is
    // distinguishable from a rejection caused by the wrong one.
    let verdict = |label: &str, key: &ZKMVerifyingKey| {
        // Exactly `StarkMachine::verify`'s per-shard setup: the verifying key
        // observed into a fresh challenger, then this shard's public values.
        let mut challenger = machine.config().challenger();
        key.vk.observe_into(&mut challenger);
        challenger.observe_slice(&proof.public_values[0..machine.num_pv_elts()]);
        let result = Verifier::verify_shard(
            machine.config(),
            &key.vk,
            &chips,
            &prep_chip_dims,
            &mut challenger,
            &proof,
            machine.recursion_pins(),
        );
        println!("vk[{label}] hash: {:?}", key.hash_koalabear());
        match result {
            Ok(()) => println!("  VERDICT: ACCEPT -- sound under this key; the circuit diverges"),
            Err(e) => println!("  VERDICT: REJECT -- {e:?}"),
        }
    };

    // The failing check is a balance between the LogUp-GKR sums and the
    // public-values digest, so print the public values themselves: a shard
    // whose PV slots do not describe its own trace is the shape a filling race
    // would leave behind.
    {
        use zkm_pcs::air::PublicValues;
        use zkm_pcs::Word;
        let pv: &PublicValues<Word<_>, _> = proof.public_values.as_slice().borrow();
        println!("-- public values --");
        println!("  shard              : {}", pv.shard);
        println!("  execution_shard    : {}", pv.execution_shard);
        println!("  start_pc / next_pc : {} / {}", pv.start_pc, pv.next_pc);
        println!("  exit_code          : {}", pv.exit_code);
        println!("  committed_digest   : {:?}", pv.committed_value_digest);
        println!("  deferred_digest    : {:?}", pv.deferred_proofs_digest);
        println!(
            "  prev_init/fin bits : {:?} / {:?}",
            pv.previous_init_addr_bits, pv.previous_finalize_addr_bits
        );
        println!(
            "  last_init/fin bits : {:?} / {:?}",
            pv.last_init_addr_bits, pv.last_finalize_addr_bits
        );
        println!("  global_cumulative  : {:?}", pv.global_cumulative_sum);
    }

    verdict("file", &vk);

    // The key the running client actually ships is the one `setup` derives from
    // the guest ELF it loads, so derive it here rather than trusting a `vk.bin`
    // that any later run overwrites.
    if let Some(elf_path) = args.next() {
        let elf = std::fs::read(&elf_path).unwrap_or_else(|e| panic!("read {elf_path}: {e}"));
        let (_, _, _, derived) = prover.setup(&elf);
        verdict("elf", &derived);
    }
}

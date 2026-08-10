//! FORGERY MATRIX for the single-shard-normalize design.
//!
//! Loads a REAL honest compose (ComposeBasefold) witness + a REAL honest
//! normalize (CoreBasefold) witness dumped by a FIX-off `compress` run
//! serialized compose input, then for each attack mutates the
//! witness and RUNS the in-circuit program on the host runtime
//! (`RecursionRuntime::run`).  An in-circuit assert that catches the forgery
//! traps the runtime (DivF/DivE/range-check); honest runs must stay GREEN.
//!
//! This is the SAME run-program-with-witness mechanism as the in-tree
//! `s7b_compose_trip_replay` test — it exercises the EXACT in-circuit asserts
//! the production prover compiles, without the cost of a full STARK proof.
//!
//! Run:
//!   COMPOSE_DUMP=/tmp/allinput_compose_h1_i4.bin \
//!   CORE_DUMP=/tmp/allinput_core_0.bin \
//!   FIX_RECURSION_SHAPES=true VERIFY_VK=false \
//!   cargo run --release -p zkm-prover --example g4_forgery_matrix
//!
//! NOTE: a child's public_values are Fiat-Shamir-observed by the per-child
//! crypto verify (compress_basefold.rs:548-551) AND bound by the in-circuit
//! `digest` re-check.  For the CROSS-CHILD chain attacks (drop/dup/reorder) the
//! REMAINING children are byte-untouched, so their transcript+digest stay
//! self-consistent and the rejection is attributable to the PV-CHAIN assert
//! (the only thing that sees the cross-child relationship).  For single-child
//! field forgeries (range/is_first/contains) we ALSO recompute the digest so it
//! is not the catcher; those remain transcript-bound (over-determined) — the
//! point is they are REJECTED, which proves the assert is not the sole guard
//! but is present.

use std::borrow::{Borrow, BorrowMut};

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2 as InnerSC;
use zkm_pcs::MachineProver;
use zkm_pcs::{Challenge, Val};
use zkm_prover::components::DefaultProverComponents;
use zkm_prover::utils::recursion_public_values_digest;
use zkm_prover::ZKMProver;
use zkm_recursion_circuit::machine::{
    ZKMCompressBasefoldWitnessValues, ZKMCoreBasefoldWitnessValues,
};
use zkm_recursion_circuit::witness::Witnessable;
use zkm_pcs::air::PublicValues as MipsPublicValues;
use zkm_pcs::Word;
use zkm_recursion_compiler::config::InnerConfig;
use zkm_recursion_core::air::RecursionPublicValues;
use zkm_recursion_core::Runtime as RecursionRuntime;

type KB = KoalaBear;

/// Run a compose witness on the host runtime; returns Ok(()) on clean run,
/// Err(msg) on trap.
fn run_compose(
    prover: &ZKMProver<DefaultProverComponents>,
    input: &ZKMCompressBasefoldWitnessValues<InnerSC>,
) -> Result<(), String> {
    let program = prover.compose_program_basefold(input);
    let mut witness_stream = Vec::new();
    Witnessable::<InnerConfig>::write(input, &mut witness_stream);
    let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
        program,
        prover.compress_prover.config().perm.clone(),
    );
    runtime.witness_stream = witness_stream.into();
    runtime.run().map_err(|e| e.to_string())
}

/// Run a normalize (core) witness on the host runtime.
fn run_core(
    prover: &ZKMProver<DefaultProverComponents>,
    input: &ZKMCoreBasefoldWitnessValues<InnerSC>,
) -> Result<(), String> {
    let program = prover.recursion_program_basefold(input);
    let mut witness_stream = Vec::new();
    Witnessable::<InnerConfig>::write(input, &mut witness_stream);
    let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
        program,
        prover.compress_prover.config().perm.clone(),
    );
    runtime.witness_stream = witness_stream.into();
    runtime.run().map_err(|e| e.to_string())
}

/// Recompute and re-stamp the in-circuit `digest` of a child's public_values
/// after a PV field mutation, so the digest re-check is NOT the catcher
/// (isolates the targeted chain/range/flag assert as far as the transcript
/// allows).
fn restamp_digest(config: &InnerSC, pv_vec: &mut Vec<KB>) {
    let pv: &RecursionPublicValues<KB> = pv_vec.as_slice().borrow();
    let mut pv_copy = *pv;
    let d = recursion_public_values_digest(config, &pv_copy);
    pv_copy.digest = d;
    let pv_mut: &mut RecursionPublicValues<KB> = pv_vec.as_mut_slice().borrow_mut();
    *pv_mut = pv_copy;
}

fn report(label: &str, res: &Result<(), String>, expect_reject: bool) -> bool {
    let rejected = res.is_err();
    let tag = match res {
        Ok(()) => "ACCEPTED(clean run)".to_string(),
        Err(e) => {
            let short: String = e.chars().take(180).collect();
            format!("REJECTED(trap: {short})")
        }
    };
    let ok = rejected == expect_reject;
    println!(
        "[G4] {label}: {tag} -- expected={} => {}",
        if expect_reject { "REJECT" } else { "ACCEPT" },
        if ok { "PASS" } else { "**FAIL**" }
    );
    ok
}

fn main() {
    // NOTE: do NOT set ZKM_DEBUG=true here — it makes the compiler println!
    // every one of the ~1M program instructions (compiler.rs:845), producing a
    // multi-hundred-MB log per run.  The runtime trap Err message is enough to
    // distinguish honest(clean)/forged(trap) for the matrix.
    let prover = ZKMProver::<DefaultProverComponents>::new();
    let config = InnerSC::default();
    let mut all_pass = true;

    // ───────────────────────── COMPOSE (cross-shard chain) ─────────────────
    let compose_path = std::env::var("COMPOSE_DUMP")
        .unwrap_or_else(|_| "/tmp/allinput_compose_h1_i4.bin".to_string());
    let bytes = std::fs::read(&compose_path)
        .unwrap_or_else(|e| panic!("read COMPOSE_DUMP {compose_path}: {e}"));
    let honest: ZKMCompressBasefoldWitnessValues<InnerSC> =
        bincode::deserialize(&bytes).expect("deserialize compose witness");
    let arity = honest.vks_and_proofs.len();
    println!(
        "[G4] loaded compose witness {compose_path}: arity={arity} is_complete={}",
        honest.is_complete
    );

    // sanity: print the child start/next shard chain.
    for (k, (_, sp)) in honest.vks_and_proofs.iter().enumerate() {
        let pv: &RecursionPublicValues<KB> = sp.public_values.as_slice().borrow();
        println!(
            "[G4]   child[{k}] start_shard={} next_shard={} contains_exec={} start_pc={} next_pc={}",
            pv.start_shard.as_canonical_u32(),
            pv.next_shard.as_canonical_u32(),
            pv.contains_execution_shard.as_canonical_u32(),
            pv.start_pc.as_canonical_u32(),
            pv.next_pc.as_canonical_u32(),
        );
    }

    // (honest control)
    all_pass &= report("compose/HONEST", &run_compose(&prover, &honest), false);

    if arity >= 2 {
        // (b) DROP a shard: remove the last child. The remaining children's
        // transcripts/digests are untouched, so rejection is the PV-CHAIN /
        // cumulative-sum (the dropped child's global sum no longer cancels).
        {
            let mut forged = honest.clone();
            forged.vks_and_proofs.pop();
            all_pass &= report("compose/(b) DROP a child", &run_compose(&prover, &forged), true);
        }
        // (c) DUPLICATE a shard: repeat child[0]. Chain breaks
        // (_shard==start_shard) and/or cumsum != 0.
        {
            let mut forged = honest.clone();
            let dup = forged.vks_and_proofs[0].clone();
            forged.vks_and_proofs.insert(1, dup);
            all_pass &= report("compose/(c) DUPLICATE child[0]", &run_compose(&prover, &forged), true);
        }
        // (d) REORDER shards: swap child[0] and child[1]. pc/_shard chain or
        // cumsum rejects (children byte-untouched → chain is the catcher).
        {
            let mut forged = honest.clone();
            forged.vks_and_proofs.swap(0, 1);
            all_pass &= report("compose/(d) REORDER child[0]<->child[1]", &run_compose(&prover, &forged), true);
        }
    } else {
        println!("[G4] compose arity<2 — skipping drop/dup/reorder (need >=2 children); pick a deeper compose dump");
    }

    // (e) OUT-OF-RANGE shard index (GAP-1 litmus): set a child's next_shard to
    // a near-modulus value > 2^MAX_LOG_NUMBER_OF_SHARDS, re-stamp digest. The
    // NEW per-input range_check_felt on start/next shard must reject.
    {
        let mut forged = honest.clone();
        let k = forged.vks_and_proofs.len() - 1;
        let pv_vec = &mut forged.vks_and_proofs[k].1.public_values;
        {
            let pv: &mut RecursionPublicValues<KB> = pv_vec.as_mut_slice().borrow_mut();
            // p-1 ~ 2^31, far above 2^16 = MAX_NUMBER_OF_SHARDS.
            pv.next_shard = KB::from_u32(KB::ORDER_U32 - 1);
        }
        restamp_digest(&config, pv_vec);
        all_pass &= report(
            "compose/(e) OUT-OF-RANGE next_shard=p-1 (GAP-1 range-check)",
            &run_compose(&prover, &forged),
            true,
        );
    }

    // (g) flip contains_execution_shard on the CPU child (claim no execution
    // shard). Re-stamp digest. The boolean/first-exec logic + chain rejects.
    {
        let mut forged = honest.clone();
        // find a child with contains_execution_shard == 1.
        let cpu_k = forged.vks_and_proofs.iter().position(|(_, sp)| {
            let pv: &RecursionPublicValues<KB> = sp.public_values.as_slice().borrow();
            pv.contains_execution_shard == KB::ONE
        });
        if let Some(k) = cpu_k {
            let pv_vec = &mut forged.vks_and_proofs[k].1.public_values;
            {
                let pv: &mut RecursionPublicValues<KB> = pv_vec.as_mut_slice().borrow_mut();
                pv.contains_execution_shard = KB::ZERO;
            }
            restamp_digest(&config, pv_vec);
            all_pass &= report(
                "compose/(g) flip contains_execution_shard 1->0",
                &run_compose(&prover, &forged),
                true,
            );
        } else {
            println!("[G4] no child with contains_execution_shard==1 — skipping (g)");
        }
    }

    // ───────────────────────── CORE / NORMALIZE (single-shard) ─────────────
    if let Ok(core_path) = std::env::var("CORE_DUMP") {
        let cbytes = std::fs::read(&core_path)
            .unwrap_or_else(|e| panic!("read CORE_DUMP {core_path}: {e}"));
        let core_honest: ZKMCoreBasefoldWitnessValues<InnerSC> =
            bincode::deserialize(&cbytes).expect("deserialize core witness");
        println!(
            "[G4] loaded core witness {core_path}: shard_proofs={} is_first_shard={}",
            core_honest.shard_proofs.len(),
            core_honest.is_first_shard
        );
        // single-shard invariant:
        assert_eq!(
            core_honest.shard_proofs.len(),
            1,
            "core dump must be single-shard (the #88/#82 normalize is arity-1)"
        );
        all_pass &= report("core/HONEST", &run_core(&prover, &core_honest), false);

        // NOTE: the normalize verifies a CORE shard proof, whose
        // `public_values` is the MIPS `PublicValues` (NOT RecursionPublicValues)
        // — borrow it with the correct layout.
        {
            let pv: &MipsPublicValues<Word<KB>, KB> =
                core_honest.shard_proofs[0].public_values.as_slice().borrow();
            println!(
                "[G4]   core child MIPS PV: shard={} start_pc={} exit_code={}",
                pv.shard.as_canonical_u32(),
                pv.start_pc.as_canonical_u32(),
                pv.exit_code.as_canonical_u32(),
            );
        }

        // (f) is_first binds: flip the WITNESSED is_first_shard felt (not a PV —
        // transcript-neutral, so the is_first binds at core_basefold.rs:688
        // (is_first*(initial_shard-1)==0) / :644 (assert_felt_ne((1-is_first)*
        // initial_shard, 1)) are the catcher).  For a first shard (shard==1),
        // flipping is_first true->false trips assert_felt_ne; a non-first shard
        // (shard!=1) claiming is_first=true trips the (initial_shard-1) bind.
        {
            let mut forged = core_honest.clone();
            forged.is_first_shard = !forged.is_first_shard;
            all_pass &= report(
                "core/(f) flip is_first_shard (is_first binds)",
                &run_core(&prover, &forged),
                true,
            );
        }

        // (e') CORE out-of-range shard index: the single-shard normalize
        // range_check_felt(MIPS public_values.shard, MAX_LOG_NUMBER_OF_SHARDS)
        // must reject a near-modulus shard.  (The MIPS shard PV is bound by the
        // core shard's own transcript+LogUp, so this is over-determined — the
        // point is REJECTION; the same range_check mechanism is cleanly
        // isolated at compose/(e).)
        {
            let mut forged = core_honest.clone();
            let pv_vec = &mut forged.shard_proofs[0].public_values;
            let pv: &mut MipsPublicValues<Word<KB>, KB> = pv_vec.as_mut_slice().borrow_mut();
            pv.shard = KB::from_u32(KB::ORDER_U32 - 1);
            all_pass &= report(
                "core/(e') OUT-OF-RANGE MIPS shard=p-1 (normalize range-check)",
                &run_core(&prover, &forged),
                true,
            );
        }
    } else {
        println!("[G4] CORE_DUMP unset — skipping normalize (core) forgeries (f)/(e')");
    }

    println!(
        "[G4] ====== MATRIX {} ======",
        if all_pass { "ALL PASS" } else { "HAD FAILURES" }
    );
    if !all_pass {
        std::process::exit(1);
    }
}

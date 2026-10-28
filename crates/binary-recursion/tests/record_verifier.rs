//! Plonky3's verifier, run over traced values on a real machine proof,
//! accepts it and records the verification as a program.

use core::array;
use core::borrow::Borrow;
use std::sync::Arc;

use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::{KoalaBear, Poseidon2InternalLayerKoalaBear};
use p3_multi_stark::verify;
use zkm_binary_recursion::challenger::TracedChallenger;
use zkm_binary_recursion::config::{lift_key, reread, TracedConfig, TracedProof};
use zkm_binary_recursion::tape::kind_index;
use zkm_binary_recursion::{queries, record, Traced, F};
use zkm_binary_recursion::{Op, Operand, Tape};
use zkm_binary_stark::machine::public_values::PublicValuesAir;
use zkm_binary_stark::machine::RecursionMachine;
use zkm_binary_stark::{BinarySchedule, TRANSCRIPT_DOMAIN};
use zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2;
use zkm_recursion_core::air::Block;
use zkm_recursion_core::air::{RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS};
use zkm_recursion_core::runtime::instruction as instr;
use zkm_recursion_core::{
    Address, BaseAluOpcode, Instruction, MemAccessKind, RawProgram, RecursionProgram, Runtime,
    DIGEST_SIZE,
};

type EF = BinomialExtensionField<KoalaBear, 4>;

/// `n` additions and multiplications of operands read as hints, then a
/// commitment to a digest of small constants.  The program is the same for
/// every witness, so so are its tables' shapes and its key.
fn program(n: usize) -> RecursionProgram<KoalaBear> {
    let mut instructions = Vec::new();
    let mut addr = 0u32;
    for _ in 0..n {
        let a: [u32; 4] = array::from_fn(|k| addr + k as u32);
        addr += 4;
        instructions.extend([
            Instruction::Hint(instr::HintInstr {
                output_addrs_mults: vec![
                    (Address(KoalaBear::from_u32(a[0])), KoalaBear::TWO),
                    (Address(KoalaBear::from_u32(a[1])), KoalaBear::TWO),
                ],
            }),
            instr::base_alu(BaseAluOpcode::AddF, 0, a[2], a[0], a[1]),
            instr::base_alu(BaseAluOpcode::MulF, 0, a[3], a[0], a[1]),
        ]);
    }
    let addrs: [u32; RECURSIVE_PROOF_NUM_PV_ELTS] = array::from_fn(|i| addr + i as u32);
    let pv_addrs: &RecursionPublicValues<u32> = addrs.as_slice().borrow();
    let digest_addrs = pv_addrs.digest;
    instructions.extend(addrs.iter().map(|&a| {
        let word = digest_addrs.iter().position(|&d| d == a);
        let value = word.map_or(KoalaBear::ZERO, |w| KoalaBear::from_u32(w as u32 + 1));
        instr::mem_single(MemAccessKind::Write, u32::from(word.is_some()), a, value)
    }));
    instructions.push(instr::commit_public_values(pv_addrs));
    let mut program =
        RecursionProgram::new(RawProgram::from_linear(instructions), 0, Vec::new(), None);
    program.total_memory = program.computed_total_memory();
    program
}

/// The verification of a proof of `program(16)` on the witness drawn from
/// `seed`, recorded: the tape, with the drawn indices and how many each
/// user took.
fn recorded(seed: u32) -> (Tape, usize, usize, usize) {
    let n = 16;
    let program = Arc::new(program(n));
    let mut runtime = Runtime::<KoalaBear, EF, Poseidon2InternalLayerKoalaBear<16>>::new(
        program.clone(),
        KoalaBearPoseidon2::new().perm,
    );
    runtime.witness_stream = (0..2 * n as u32)
        .map(|i| Block::from(KoalaBear::from_u32(i.wrapping_mul(2_654_435_761) ^ seed)))
        .collect();
    runtime.run().expect("the program runs");
    let execution = runtime.record;

    let schedule = BinarySchedule::default();
    let machine = RecursionMachine::new(&program, &schedule).expect("machine");
    let proof = machine.prove(&execution).expect("the execution proves");
    let digest: [u32; DIGEST_SIZE] = PublicValuesAir::digest(&execution);
    machine.verify(&proof, &digest).expect("the proof verifies natively");

    let (main, preprocessed) = machine.shapes();
    let config = TracedConfig::new(&main, &preprocessed, &schedule).expect("traced config");
    let vk = lift_key(machine.verifying_key());

    let started = std::time::Instant::now();
    let profiling = std::env::var_os("TAPE_PROFILE").is_some();
    let ((verdict, (drawn, merkle, point), profile), tape) = record(|| {
        if profiling {
            zkm_binary_recursion::tape::profile(97);
        }
        let public: [Traced; DIGEST_SIZE] =
            RecursionMachine::public_values(&digest).map(Traced::input);
        let proof: TracedProof = reread(&proof);
        let instances = machine.verifier_instances(&vk, &public);
        let mut challenger = TracedChallenger::new(TRANSCRIPT_DOMAIN);
        let verdict =
            verify(&config, instances, &proof, 0, &mut challenger).map_err(|e| format!("{e:?}"));
        (verdict, queries::take(), zkm_binary_recursion::tape::take_profile())
    });
    if let Some(profile) = profile {
        for (signature, muls, bytes) in profile.by_signature(4).into_iter().take(16) {
            println!(
                "    mul ~{muls:>7} hashed {bytes:>8} B  {}",
                &signature[..signature.len().min(120)]
            );
        }
    }
    verdict.expect("the traced verifier accepts");
    println!(
        "seed {seed}: recorded in {:.2} s: {} ops, {} variables, {} inputs, {} hashed bytes; {} indices drawn",
        started.elapsed().as_secs_f64(),
        tape.ops.len(),
        tape.values.len(),
        tape.inputs.len(),
        tape.hashed_bytes(),
        drawn.len(),
    );
    (tape, drawn.len(), merkle, point)
}

/// The recorded program accepts its own inputs, reproducing every value,
/// and rejects the inputs with any one of a spread of them changed.
#[test]
fn records_the_verification_of_a_machine_proof() {
    let (tape, drawn, merkle, point) = recorded(0);
    assert_eq!((merkle, point), (drawn, drawn), "every drawn index is used by both users");
    for (kind, count) in Tape::KINDS.iter().zip(tape.census()) {
        println!("  {kind:>14}: {count}");
    }
    println!("  garbled: {}", tape.and_gates());

    let reads = tape.read_counts();
    let read_vars = reads.iter().filter(|&&r| r > 0).count();
    let total_reads: u64 = reads.iter().map(|&r| u64::from(r)).sum();
    let max_reads = reads.iter().max().copied().unwrap_or(0);
    println!(
        "{} variables, {read_vars} read, {total_reads} reads, at most {max_reads} of one",
        reads.len()
    );
    let mut by_kind = [[0u64; 2]; Tape::KINDS.len()];
    let (mut var_var_muls, mut fusable_adds) = (0u64, 0u64);
    let mut defining: Vec<usize> = vec![usize::MAX; tape.values.len()];
    for (i, (op, defined)) in tape.ops.iter().zip(&tape.defined).enumerate() {
        if let Some(var) = defined {
            defining[*var as usize] = i;
        }
        for operand in Tape::operands(op) {
            let is_const = matches!(operand, Operand::Const(_));
            by_kind[kind_index(op)][usize::from(is_const)] += 1;
        }
        match op {
            Op::Mul(Operand::Var(_), Operand::Var(_)) => var_var_muls += 1,
            Op::Add(..) => {
                let fed = Tape::operands(op).iter().any(|operand| match operand {
                    Operand::Var(v) => {
                        reads[*v as usize] == 1
                            && matches!(tape.ops.get(defining[*v as usize]), Some(Op::Add(..)))
                    }
                    Operand::Const(_) => false,
                });
                fusable_adds += u64::from(fed);
            }
            _ => {}
        }
    }
    println!("{var_var_muls} products of two variables; {fusable_adds} additions fed by a single-use addition");
    for (kind, [vars, consts]) in Tape::KINDS.iter().zip(by_kind) {
        if vars + consts > 0 {
            println!("  {kind:>14} operands: {vars} variables, {consts} constants");
        }
    }

    let values = tape.run(&tape.inputs).expect("the program accepts its own inputs");
    assert!(values == tape.values, "the run reproduces the recorded values");

    let n = tape.inputs.len();
    let mut rejected = 0;
    let picks: Vec<usize> = (0..64).map(|k| k * (n - 1) / 63).collect();
    for &i in &picks {
        let mut inputs = tape.inputs.clone();
        inputs[i] += F::ONE;
        let verdict = tape.run(&inputs);
        assert!(verdict.is_err(), "changing input {i} of {n} must be rejected");
        rejected += 1;
    }
    println!("{rejected} single-input changes rejected");
}

/// Proofs of two executions of one program on different witnesses record
/// the same program: the same operations on the same variables and
/// constants, so the program depends on the key, never on a proof.
#[test]
fn the_program_is_the_same_for_every_proof_of_a_shape() {
    let (a, ..) = recorded(0);
    let (b, ..) = recorded(0x5eed);
    let kind = |op: &zkm_binary_recursion::Op| core::mem::discriminant(op);
    if let Some(i) = a.ops.iter().zip(&b.ops).position(|(x, y)| kind(x) != kind(y)) {
        for j in i.saturating_sub(6)..i + 4 {
            println!("{j}: {:?}\n    {:?}", a.ops[j], b.ops[j]);
        }
    }
    assert_eq!(a.ops.len(), b.ops.len(), "the same number of operations");
    assert_eq!(a.inputs.len(), b.inputs.len(), "the same number of inputs");
    let differing = a.ops.iter().zip(&b.ops).filter(|(x, y)| x != y).count();
    let first = a.ops.iter().zip(&b.ops).position(|(x, y)| x != y);
    println!("{differing} of {} operations differ; first at {first:?}", a.ops.len());
    if let Some(i) = first {
        println!("  {:?}\n  {:?}", a.ops[i], b.ops[i]);
    }
    assert_eq!(differing, 0, "the program is the same for both proofs");
}

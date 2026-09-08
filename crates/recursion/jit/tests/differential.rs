//! The JIT against the production interpreter, on the same program.
//!
//! The fragment tests in `x86.rs` prove the arithmetic matches `p3_field`.
//! This proves the whole emission matches `Runtime::execute_one` — the
//! addressing, the three zero lanes `Block::from` writes, the event layout
//! and its offsets — by running one program both ways and comparing every
//! word of memory and every event.
//!
//! A JIT that got any of this subtly wrong would not crash.  It would
//! produce a well-formed proof of a different statement, so nothing short
//! of a word-for-word comparison against the interpreter is evidence.

#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use std::sync::Arc;

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_koala_bear::Poseidon2InternalLayerKoalaBear;
use zkm_pcs::{koala_bear_poseidon2::KoalaBearPoseidon2, StarkGenericConfig};
use zkm_recursion_core::runtime::{instruction as instr, Instruction, RecursionProgram, Runtime};
use zkm_recursion_core::{Address, BaseAluInstr, BaseAluIo, BaseAluOpcode, MemAccessKind};

type SC = KoalaBearPoseidon2;
type F = <SC as StarkGenericConfig>::Val;
type EF = <SC as StarkGenericConfig>::Challenge;

fn addr(a: u32) -> Address<F> {
    Address(F::from_u32(a))
}

/// A program of `BaseAlu` Add/Sub/Mul over a deterministic address pattern,
/// preceded by the constant writes that seed its inputs.
fn build_program(n: usize) -> (RecursionProgram<F>, u32) {
    let mut instrs: Vec<Instruction<F>> = Vec::new();

    // Seed 8 constants; `Mem` is not JIT-able yet, so the seeds go in as
    // memory-constant instructions the JIT will reject -- which is exactly
    // why the test compiles the ALU-only tail separately (see below).
    let seeds: [u32; 8] = [1, 2, 3, 5, 7, 11, 13, 0];
    for (i, s) in seeds.iter().enumerate() {
        instrs.push(instr::mem(MemAccessKind::Write, 1, i as u32, *s));
    }

    let mut next = seeds.len() as u32;
    let mut s: u64 = 0x9e37_79b9_7f4a_7c15;
    for _ in 0..n {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let a = ((s >> 33) as u32) % next;
        let b = ((s >> 13) as u32) % next;
        let opcode = match (s >> 3) % 3 {
            0 => BaseAluOpcode::AddF,
            1 => BaseAluOpcode::SubF,
            _ => BaseAluOpcode::MulF,
        };
        instrs.push(Instruction::BaseAlu(BaseAluInstr {
            opcode,
            mult: F::ONE,
            addrs: BaseAluIo { out: addr(next), in1: addr(a), in2: addr(b) },
        }));
        next += 1;
    }

    let mut program = RecursionProgram::<F>::default();
    program.seq_blocks = zkm_recursion_core::runtime::RawProgram {
        seq_blocks: vec![zkm_recursion_core::runtime::SeqBlock::Basic(
            zkm_recursion_core::runtime::BasicBlock { instrs },
        )],
    };
    program.total_memory = program.computed_total_memory();
    (program, next)
}

#[test]
fn the_jit_reproduces_the_interpreter_word_for_word() {
    const N: usize = 4096;
    let (program, total) = build_program(N);
    let program = Arc::new(program);

    // ── the interpreter ──────────────────────────────────────────────
    let mut runtime =
        Runtime::<F, EF, Poseidon2InternalLayerKoalaBear<16>>::new(program.clone(), SC::new().perm);
    runtime.run().expect("interpreter");
    let want_events = runtime.record.base_alu_events.clone();
    assert_eq!(want_events.len(), N, "every ALU instruction should emit one event");

    // ── the JIT ──────────────────────────────────────────────────────
    // Compile only the ALU tail: the seeding `Mem` writes are not emitted
    // by this phase, so the test performs them directly into the same flat
    // memory the emitted code addresses.
    let (analyzed, _counts) = program.seq_blocks.clone().analyze();
    let alu_only = zkm_recursion_core::runtime::RawProgram {
        seq_blocks: vec![zkm_recursion_core::runtime::SeqBlock::Basic(
            zkm_recursion_core::runtime::BasicBlock {
                instrs: analyzed
                    .iter()
                    .filter(|ai| matches!(ai.inner(), Instruction::BaseAlu(_)))
                    .cloned()
                    .collect(),
            },
        )],
    };
    let compiled = zkm_recursion_jit::compile::compile(&alu_only).expect("compile");
    assert_eq!(compiled.emitted, N);

    // Flat memory, seeded the way the `Mem` instructions would have.
    let mut mem = vec![0u32; (total as usize + 1) * 4];
    for (i, s) in [1u32, 2, 3, 5, 7, 11, 13, 0].iter().enumerate() {
        // Montgomery form, as the runtime stores it.
        let v: u32 = unsafe { std::mem::transmute::<KoalaBear, u32>(F::from_u32(*s)) };
        mem[i * 4] = v;
    }
    let mut events = vec![0u32; N * 3];
    unsafe {
        compiled.run(mem.as_mut_ptr().cast::<u8>(), events.as_mut_ptr().cast::<u8>());
    }

    // ── compare ──────────────────────────────────────────────────────
    for (i, want) in want_events.iter().enumerate() {
        let got = &events[i * 3..i * 3 + 3];
        let w: [u32; 3] = unsafe {
            [
                std::mem::transmute::<KoalaBear, u32>(want.out),
                std::mem::transmute::<KoalaBear, u32>(want.in1),
                std::mem::transmute::<KoalaBear, u32>(want.in2),
            ]
        };
        assert_eq!(got, w, "event {i} diverged (out, in1, in2)");
    }

    // And the memory the interpreter left behind, cell for cell -- this is
    // what catches a missed zero lane, which no event comparison would see.
    for a in 0..total as usize {
        let want = runtime.memory.mr(addr(a as u32)).val;
        for lane in 0..4 {
            let w: u32 = unsafe { std::mem::transmute::<KoalaBear, u32>(want.0[lane]) };
            assert_eq!(mem[a * 4 + lane], w, "memory[{a}].lane[{lane}] diverged");
        }
    }
}

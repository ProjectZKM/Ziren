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
        let mut b = ((s >> 13) as u32) % next;
        // Div included deliberately: it is 16.8% of BaseAlu on a real leaf
        // program, so a test without it would exercise a path no real
        // program takes.  `in2` is drawn from the live addresses, so zero
        // divisors do occur — seed 7 is zero and every result feeds back in.
        let opcode = match (s >> 3) % 4 {
            0 => BaseAluOpcode::AddF,
            1 => BaseAluOpcode::SubF,
            2 => BaseAluOpcode::MulF,
            _ => BaseAluOpcode::DivF,
        };
        if opcode == BaseAluOpcode::DivF {
            // Divide by one of the non-zero seeds.  A random live address
            // can hold zero, and the INTERPRETER rejects that program, so a
            // comparison test cannot use one; the zero-divisor outcomes get
            // their own test below.
            b = ((s >> 45) as u32) % 6;
        }
        instrs.push(Instruction::BaseAlu(BaseAluInstr {
            opcode,
            mult: F::ONE,
            addrs: BaseAluIo { out: addr(next), in1: addr(a), in2: addr(b) },
        }));
        next += 1;
    }

    let raw = zkm_recursion_core::runtime::RawProgram {
        seq_blocks: vec![zkm_recursion_core::runtime::SeqBlock::Basic(
            zkm_recursion_core::runtime::BasicBlock { instrs },
        )],
    };
    let mut program = RecursionProgram::<F>::new(raw, 0, Vec::new(), None);
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
    let analyzed = &program.seq_blocks;
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
    let status =
        unsafe { compiled.run(mem.as_mut_ptr().cast::<u8>(), events.as_mut_ptr().cast::<u8>()) };
    assert_eq!(
        status,
        zkm_recursion_jit::compile::STATUS_OK,
        "the interpreter accepted this program, so the JIT must too"
    );

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

/// The three zero-divisor outcomes, which are a soundness assertion rather
/// than arithmetic: the interpreter returns one for `0/0`, returns zero for a
/// dead `DivF` whose result is never read, and errors otherwise.  A JIT that
/// got the last one wrong would silently accept a program the interpreter
/// refuses.
#[test]
fn the_zero_divisor_outcomes_match() {
    // (in1, mult, is_assert) -> expected
    struct Case {
        in1: u32,
        mult: u32,
        want_status: u32,
        want_out: Option<u32>,
    }
    let cases = [
        // 0 / 0 == 1, and the interpreter accepts it.
        Case { in1: 0, mult: 1, want_status: 0, want_out: Some(1) },
        // Dead DivF (mult == 0, not an assert): result never read, so zero.
        Case { in1: 13, mult: 0, want_status: 0, want_out: Some(0) },
        // Live DivF by zero: must trip.
        Case { in1: 13, mult: 1, want_status: 1, want_out: None },
    ];

    for (i, c) in cases.iter().enumerate() {
        let mut instrs: Vec<Instruction<F>> = vec![
            instr::mem(MemAccessKind::Write, 1, 0, c.in1),
            instr::mem(MemAccessKind::Write, 1, 1, 0), // the zero divisor
        ];
        instrs.push(Instruction::BaseAlu(BaseAluInstr {
            opcode: BaseAluOpcode::DivF,
            mult: F::from_u32(c.mult),
            addrs: BaseAluIo { out: addr(2), in1: addr(0), in2: addr(1) },
        }));

        let raw = zkm_recursion_core::runtime::RawProgram {
            seq_blocks: vec![zkm_recursion_core::runtime::SeqBlock::Basic(
                zkm_recursion_core::runtime::BasicBlock { instrs },
            )],
        };
        let mut program = RecursionProgram::<F>::new(raw, 0, Vec::new(), None);
        program.total_memory = program.computed_total_memory();
        let program = Arc::new(program);

        // What the interpreter does with it.
        let mut runtime = Runtime::<F, EF, Poseidon2InternalLayerKoalaBear<16>>::new(
            program.clone(),
            SC::new().perm,
        );
        let interp = runtime.run();
        assert_eq!(
            interp.is_err(),
            c.want_status != 0,
            "case {i}: interpreter and expectation disagree ({interp:?})"
        );

        // What the JIT does with it.
        let analyzed = &program.seq_blocks;
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
        let mut mem = vec![0u32; 4 * 4];
        mem[0] = unsafe { std::mem::transmute::<KoalaBear, u32>(F::from_u32(c.in1)) };
        mem[4] = 0;
        let mut events = vec![0u32; 3];
        let status = unsafe {
            compiled.run(mem.as_mut_ptr().cast::<u8>(), events.as_mut_ptr().cast::<u8>())
        };
        assert_eq!(status, c.want_status, "case {i}: status");
        if let Some(w) = c.want_out {
            let want = unsafe { std::mem::transmute::<KoalaBear, u32>(F::from_u32(w)) };
            assert_eq!(mem[2 * 4], want, "case {i}: quotient");
        }
    }
}

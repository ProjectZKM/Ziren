//! The batch-inversion plan must be a pure speed change.
//!
//! `RecursionProgram::new` builds a `div_plan` that hoists a basic block's
//! `DivF` divisors to block entry and inverts them all at once (Montgomery's
//! trick).  These tests run the same program twice — once with the plan the
//! constructor derived, once with it emptied so the walk falls back to
//! `try_inverse` per instruction — and require identical execution records.
//!
//! The awkward cases are the ones the plan has to get right: a zero divisor
//! (no inverse; a zero entry is the sentinel), a dead division (`mult = 0`,
//! whose result is never read), and a division whose divisor is produced
//! inside the same block (which must make the WHOLE block fall back, since
//! the plan is all-or-nothing).

#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use std::sync::Arc;

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::Poseidon2InternalLayerKoalaBear;
use zkm_pcs::{koala_bear_poseidon2::KoalaBearPoseidon2, StarkGenericConfig};
use zkm_recursion_core::runtime::{
    instruction as instr, DivPlan, Instruction, RecursionProgram, Runtime,
};
use zkm_recursion_core::{
    Address, BaseAluInstr, BaseAluIo, BaseAluOpcode, MemAccessKind,
};
use zkm_recursion_core::runtime::{BasicBlock, RawProgram, SeqBlock};

type SC = KoalaBearPoseidon2;
type F = <SC as StarkGenericConfig>::Val;
type EF = <SC as StarkGenericConfig>::Challenge;

fn addr(a: u32) -> Address<F> {
    Address(F::from_u32(a))
}

fn div(out: u32, in1: u32, in2: u32, mult: u32) -> Instruction<F> {
    Instruction::BaseAlu(BaseAluInstr {
        opcode: BaseAluOpcode::DivF,
        mult: F::from_u32(mult),
        addrs: BaseAluIo { out: addr(out), in1: addr(in1), in2: addr(in2) },
    })
}

fn mul(out: u32, in1: u32, in2: u32) -> Instruction<F> {
    Instruction::BaseAlu(BaseAluInstr {
        opcode: BaseAluOpcode::MulF,
        mult: F::ONE,
        addrs: BaseAluIo { out: addr(out), in1: addr(in1), in2: addr(in2) },
    })
}

/// Build a program of consecutive basic blocks.  Two blocks is the minimum
/// that exercises hoisting at all: a divisor written in the SAME block as the
/// division it feeds is by definition not live at that block's entry, so a
/// single-block program hoists nothing.  Real recursion programs have
/// 340-466 blocks and hoist 99.98% of their divisors.
fn build(blocks: Vec<Vec<Instruction<F>>>) -> RecursionProgram<F> {
    let raw = RawProgram {
        seq_blocks: blocks.into_iter().map(|instrs| SeqBlock::Basic(BasicBlock { instrs })).collect(),
    };
    let mut program = RecursionProgram::<F>::new(raw, 0, Vec::new(), None);
    program.total_memory = program.computed_total_memory();
    program
}

/// Total divisors the plan hoists, so a test cannot pass by hoisting nothing.
fn hoisted(program: &RecursionProgram<F>) -> usize {
    fn count(plans: &[DivPlan<F>]) -> usize {
        plans
            .iter()
            .map(|p| match p {
                DivPlan::Basic(a) => a.len(),
                DivPlan::Parallel(subs) => subs.iter().map(|s| count(s)).sum(),
            })
            .sum()
    }
    count(&program.div_plan)
}

/// Run once with the derived plan and once with it removed; the two
/// execution records must agree.
fn assert_same_with_and_without_plan(program: RecursionProgram<F>) -> usize {
    let perm = SC::new().perm;
    let n_hoisted = hoisted(&program);

    let mut unplanned = program.clone();
    unplanned.div_plan = Vec::new();

    let mut with = Runtime::<F, EF, Poseidon2InternalLayerKoalaBear<16>>::new(
        Arc::new(program),
        perm.clone(),
    );
    with.run().expect("planned walk");

    let mut without =
        Runtime::<F, EF, Poseidon2InternalLayerKoalaBear<16>>::new(Arc::new(unplanned), perm);
    without.run().expect("unplanned walk");

    assert_eq!(
        with.record.base_alu_events, without.record.base_alu_events,
        "batch inversion changed the base-ALU events"
    );
    assert_eq!(with.record.mem_var_events, without.record.mem_var_events);
    n_hoisted
}

/// The ordinary case: several divisions by values written before the block's
/// divisions, interleaved with other arithmetic so the cursor has to track
/// execution order rather than instruction index.
#[test]
fn plain_divisions_match_the_per_instruction_walk() {
    let setup: Vec<Instruction<F>> = (0..8)
        .map(|i| instr::mem(MemAccessKind::Write, 1, i as u32, 3 + 2 * i as u32))
        .collect();
    let mut body: Vec<Instruction<F>> = Vec::new();
    let mut next = 8u32;
    for i in 0..8u32 {
        body.push(div(next, i % 8, (i + 3) % 8, 1));
        next += 1;
        body.push(mul(next, next - 1, i % 8));
        next += 1;
    }
    assert_eq!(assert_same_with_and_without_plan(build(vec![setup, body])), 8);
}

/// A zero divisor has no inverse.  The batch carries it through as a zero,
/// which the `DivF` arm reads as the sentinel and handles exactly as the
/// un-hoisted path does — here `0/0`, which the runtime defines as one.
#[test]
fn a_zero_divisor_falls_back_to_the_out_of_domain_rule() {
    let setup: Vec<Instruction<F>> = vec![
        instr::mem(MemAccessKind::Write, 1, 0, 0), // the zero divisor
        instr::mem(MemAccessKind::Write, 1, 1, 7),
        instr::mem(MemAccessKind::Write, 1, 2, 0), // a zero dividend
    ];
    // 0/0 -> 1 by the runtime's rule; 7/0 with mult = 0 -> 0 (dead result).
    // A live division on either side, so the zeros must not poison the chain.
    let body = vec![div(3, 1, 1, 1), div(4, 2, 0, 1), div(5, 1, 0, 0), div(6, 1, 1, 1)];
    assert_eq!(assert_same_with_and_without_plan(build(vec![setup, body])), 4);
}

/// A divisor produced inside the block cannot be gathered at block entry, so
/// the plan gives the block up entirely — including the divisions that could
/// have been hoisted.  Nothing is hoisted here, and the answers still match.
#[test]
fn an_in_block_divisor_makes_the_whole_block_fall_back() {
    let setup: Vec<Instruction<F>> = (0..4)
        .map(|i| instr::mem(MemAccessKind::Write, 1, i as u32, 5 + i as u32))
        .collect();
    // The first is hoistable on its own...
    // ...but the second divides by address 4, which the first just wrote.
    let body = vec![div(4, 0, 1, 1), div(5, 2, 4, 1)];
    let program = build(vec![setup, body]);
    assert_eq!(hoisted(&program), 0, "the block must be given up, not partly hoisted");
    assert_same_with_and_without_plan(program);
}

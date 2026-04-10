//! Shared mipstest-derived instruction regression definitions.
//!
//! This crate is the single source of truth for instruction suites that should run through both:
//! - executor integration tests in `zkm-core-executor`
//! - prover integration tests in `zkm-core-machine`
//!
//! To add a new shared suite:
//! 1. Add a focused module in this crate with the case data, program builder, and executor checks.
//! 2. Re-export its suite constant from this file.
//! 3. Register it once in `for_each_instruction_suite!`.
//!
//! Executor-only edge cases that intentionally do not have prover parity should stay outside this
//! crate.

use zkm_core_executor::{Instruction, Opcode, Program, Register};

mod cloclz;
mod div;
mod maddsub;
mod misc;
mod rotate;

pub use cloclz::{N80_CLO, N81_CLZ};
pub use div::{N44_DIV, N45_DIVU};
pub use maddsub::{N67_MADD, N68_MADDU, N69_MSUB, N70_MSUBU};
pub use misc::{N71_SEB, N72_SEH, N73_WSBH, N74_INS, N75_EXT};
pub use rotate::{N78_ROTR, N79_ROTRV};

/// Shared interface used by the generated executor and prover test runners.
#[allow(clippy::len_without_is_empty)]
pub trait InstructionTestSuite {
    fn name(&self) -> &'static str;
    fn len(&self) -> usize;
    fn case_name(&self, index: usize) -> &'static str;
    fn program(&self, index: usize) -> Program;
    fn assert_executor(&self, index: usize, read_reg: &mut dyn FnMut(Register) -> u32);
}

fn imm_program(dst: Register, src: Register, input: u32, opcode: Opcode, op_c: u32) -> Program {
    Program::new(
        vec![
            Instruction::new(Opcode::ADD, src as u8, 0, input, false, true),
            Instruction::new(opcode, dst as u8, src as u32, op_c, false, true),
        ],
        0,
        0,
    )
}

fn encode_ins(pos: u32, size: u32) -> u32 {
    ((pos + size - 1) << 5) | pos
}

fn encode_ext(pos: u32, size: u32) -> u32 {
    ((size - 1) << 5) | pos
}

#[macro_export]
macro_rules! for_each_instruction_suite {
    ($callback:ident) => {
        $callback!(n44_div, $crate::N44_DIV);
        $callback!(n45_divu, $crate::N45_DIVU);
        $callback!(n67_madd, $crate::N67_MADD);
        $callback!(n68_maddu, $crate::N68_MADDU);
        $callback!(n69_msub, $crate::N69_MSUB);
        $callback!(n70_msubu, $crate::N70_MSUBU);
        $callback!(n71_seb, $crate::N71_SEB);
        $callback!(n72_seh, $crate::N72_SEH);
        $callback!(n73_wsbh, $crate::N73_WSBH);
        $callback!(n74_ins, $crate::N74_INS);
        $callback!(n75_ext, $crate::N75_EXT);
        $callback!(n78_rotr, $crate::N78_ROTR);
        $callback!(n79_rotrv, $crate::N79_ROTRV);
        $callback!(n80_clo, $crate::N80_CLO);
        $callback!(n81_clz, $crate::N81_CLZ);
    };
}

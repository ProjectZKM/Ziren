use columns::NUM_MISC_INSTR_COLS;
use p3_air::BaseAir;

pub mod air;
pub mod columns;
pub mod trace;

#[derive(Default)]
pub struct MiscInstrsChip;

impl<F> BaseAir<F> for MiscInstrsChip {
    fn width(&self) -> usize {
        NUM_MISC_INSTR_COLS
    }
}

#[cfg(test)]
mod tests {

    use crate::{utils, utils::run_test};

    use zkm_core_executor::{Instruction, Opcode, Program};

    use zkm_stark::CpuProver;

    #[test]
    fn test_misc_prove() {
        utils::setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 0xf, false, true),
            Instruction::new(Opcode::ADD, 28, 0, 0x8F8F, false, true),
            Instruction::new(Opcode::SEXT, 30, 29, 0, false, true),
            Instruction::new(Opcode::SEXT, 31, 28, 0, false, true),
            Instruction::new(Opcode::SEXT, 0, 28, 0, false, true),
            Instruction::new(Opcode::SEXT, 30, 29, 1, false, true),
            Instruction::new(Opcode::SEXT, 31, 28, 1, false, true),
            Instruction::new(Opcode::SEXT, 0, 28, 1, false, true),
            Instruction::new(Opcode::EXT, 30, 28, 0x21, false, true),
            Instruction::new(Opcode::EXT, 30, 31, 0x1EF, false, true),
            Instruction::new(Opcode::EXT, 0, 28, 0x21, false, true),
            Instruction::new(Opcode::INS, 30, 29, 0x21, false, true),
            Instruction::new(Opcode::INS, 30, 31, 0x3EF, false, true),
            Instruction::new(Opcode::INS, 0, 29, 0x21, false, true),
            Instruction::new(Opcode::MADDU, 32, 31, 31, false, false),
            Instruction::new(Opcode::MADDU, 32, 29, 31, false, false),
            Instruction::new(Opcode::MADDU, 32, 29, 0, false, false),
            Instruction::new(Opcode::MSUBU, 32, 31, 31, false, false),
            Instruction::new(Opcode::MSUBU, 32, 29, 31, false, false),
            Instruction::new(Opcode::MSUBU, 32, 29, 0, false, false),
            Instruction::new(Opcode::MADD, 32, 31, 31, false, false),
            Instruction::new(Opcode::MADD, 32, 29, 31, false, false),
            Instruction::new(Opcode::MADD, 32, 29, 0, false, false),
            Instruction::new(Opcode::MSUB, 32, 31, 31, false, false),
            Instruction::new(Opcode::MSUB, 32, 29, 31, false, false),
            Instruction::new(Opcode::MSUB, 32, 29, 0, false, false),
            Instruction::new(Opcode::TEQ, 28, 29, 0, false, true),
            Instruction::new(Opcode::TEQ, 28, 0, 0, false, true),
            Instruction::new(Opcode::TEQ, 0, 28, 0, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    /// Test INS instruction with width=32 (lsb=0, msb=31), the edge case fixed
    /// by splitting the SRL into two steps to keep each shift amount in [0, 31].
    #[test]
    fn test_ins_offset_32() {
        utils::setup_logger();
        // INS c encoding: lsb | (msb << 5)
        // width = msb - lsb + 1
        let instructions = vec![
            // Set up source registers with non-trivial values.
            Instruction::new(Opcode::ADD, 29, 0, 0xDEAD, false, true),
            Instruction::new(Opcode::ADD, 28, 0, 0xBEEF, false, true),
            // width=32: lsb=0, msb=31 -> c = 0 | (31 << 5) = 0x3E0
            Instruction::new(Opcode::INS, 30, 29, 0x3E0, false, true),
            // width=32 with different registers
            Instruction::new(Opcode::INS, 31, 28, 0x3E0, false, true),
            // width=32 with zero dest
            Instruction::new(Opcode::INS, 0, 29, 0x3E0, false, true),
            // width=31: lsb=0, msb=30 -> c = 0 | (30 << 5) = 0x3C0
            Instruction::new(Opcode::INS, 30, 28, 0x3C0, false, true),
            // width=1: lsb=0, msb=0 -> c = 0
            Instruction::new(Opcode::INS, 30, 29, 0x0, false, true),
            // width=1: lsb=31, msb=31 -> c = 31 | (31 << 5) = 0x3FF
            Instruction::new(Opcode::INS, 30, 28, 0x3FF, false, true),
            // width=16: lsb=8, msb=23 -> c = 8 | (23 << 5) = 0x2E8
            Instruction::new(Opcode::INS, 30, 29, 0x2E8, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test::<CpuProver<_, _>>(program).unwrap();
    }
}

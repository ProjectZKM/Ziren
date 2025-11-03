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
}

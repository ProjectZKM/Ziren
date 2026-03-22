use zkm_core_executor::{Instruction, Opcode, Program, Register};

use crate::InstructionTestSuite;

struct RotateCase {
    name: &'static str,
    input: u32,
    shift: u32,
    expected: u32,
}

macro_rules! rotate_suite {
    ($name:ident, $const_name:ident, $suite_name:literal, $cases:ident, $var_shift:expr) => {
        pub struct $name;
        pub const $const_name: $name = $name;
        impl InstructionTestSuite for $name {
            fn name(&self) -> &'static str {
                $suite_name
            }
            fn len(&self) -> usize {
                $cases.len()
            }
            fn case_name(&self, index: usize) -> &'static str {
                $cases[index].name
            }
            fn program(&self, index: usize) -> Program {
                let case = &$cases[index];
                if $var_shift {
                    Program::new(
                        vec![
                            Instruction::new(
                                Opcode::ADD,
                                Register::T0 as u8,
                                0,
                                case.input,
                                false,
                                true,
                            ),
                            Instruction::new(
                                Opcode::ADD,
                                Register::T2 as u8,
                                0,
                                case.shift,
                                false,
                                true,
                            ),
                            Instruction::new(
                                Opcode::ROR,
                                Register::T1 as u8,
                                Register::T0 as u32,
                                Register::T2 as u32,
                                false,
                                false,
                            ),
                        ],
                        0,
                        0,
                    )
                } else {
                    Program::new(
                        vec![
                            Instruction::new(
                                Opcode::ADD,
                                Register::T0 as u8,
                                0,
                                case.input,
                                false,
                                true,
                            ),
                            Instruction::new(
                                Opcode::ROR,
                                Register::T1 as u8,
                                Register::T0 as u32,
                                case.shift,
                                false,
                                true,
                            ),
                        ],
                        0,
                        0,
                    )
                }
            }
            fn assert_executor(&self, index: usize, read_reg: &mut dyn FnMut(Register) -> u32) {
                let case = &$cases[index];
                assert_eq!(read_reg(Register::T0), case.input, "{}: source preserved", case.name);
                if $var_shift {
                    assert_eq!(
                        read_reg(Register::T2),
                        case.shift,
                        "{}: shift preserved",
                        case.name
                    );
                }
                assert_eq!(read_reg(Register::T1), case.expected, "{}: result mismatch", case.name);
            }
        }
    };
}

rotate_suite!(N78Rotr, N78_ROTR, "n78_rotr", N78_ROTR_CASES, false);
const N78_ROTR_CASES: &[RotateCase] = &[
    RotateCase { name: "shift_0_a", input: 0x2078b9d6, shift: 0, expected: 0x2078b9d6 },
    RotateCase { name: "shift_8_a", input: 0x42d2be62, shift: 8, expected: 0x6242d2be },
    RotateCase { name: "shift_16_a", input: 0x77bd6d3d, shift: 16, expected: 0x6d3d77bd },
    RotateCase { name: "shift_31_a", input: 0x1602dc92, shift: 31, expected: 0x2c05b924 },
];

rotate_suite!(N79Rotrv, N79_ROTRV, "n79_rotrv", N79_ROTRV_CASES, true);
const N79_ROTRV_CASES: &[RotateCase] = &[
    RotateCase { name: "shift_0_a", input: 0x33a75dcb, shift: 0, expected: 0x33a75dcb },
    RotateCase { name: "shift_8_a", input: 0x605e7f06, shift: 8, expected: 0x06605e7f },
    RotateCase { name: "shift_16_a", input: 0x2f1fd039, shift: 16, expected: 0xd0392f1f },
    RotateCase { name: "shift_31_a", input: 0x01851abe, shift: 31, expected: 0x030a357c },
];

use crate::{imm_program, InstructionTestSuite};
use zkm_core_executor::{Opcode, Register};

struct CountCase {
    name: &'static str,
    input: u32,
    expected: u32,
}

macro_rules! count_suite {
    ($name:ident, $const_name:ident, $suite_name:literal, $opcode:expr, $cases:ident) => {
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
            fn program(&self, index: usize) -> zkm_core_executor::Program {
                imm_program(Register::T1, Register::T0, $cases[index].input, $opcode, 0)
            }
            fn assert_executor(&self, index: usize, read_reg: &mut dyn FnMut(Register) -> u32) {
                let case = &$cases[index];
                assert_eq!(read_reg(Register::T0), case.input, "{}: source preserved", case.name);
                assert_eq!(read_reg(Register::T1), case.expected, "{}: result mismatch", case.name);
            }
        }
    };
}

count_suite!(N80Clo, N80_CLO, "n80_clo", Opcode::CLO, N80_CLO_CASES);
const N80_CLO_CASES: &[CountCase] = &[
    CountCase { name: "all_ones", input: 0xffffffff, expected: 0x20 },
    CountCase { name: "nonleading", input: 0x6df76b1b, expected: 0x00 },
    CountCase { name: "all_but_lowest_zero", input: 0xfffffffe, expected: 0x1f },
    CountCase { name: "mid_range", input: 0xff0afc07, expected: 0x08 },
    CountCase { name: "all_zero", input: 0x00000000, expected: 0x00 },
    CountCase { name: "two_leading_ones", input: 0xda2bc144, expected: 0x02 },
];

count_suite!(N81Clz, N81_CLZ, "n81_clz", Opcode::CLZ, N81_CLZ_CASES);
const N81_CLZ_CASES: &[CountCase] = &[
    CountCase { name: "all_zero", input: 0x00000000, expected: 0x20 },
    CountCase { name: "single_low_bit", input: 0x00000001, expected: 0x1f },
    CountCase { name: "mid_small", input: 0x012d0938, expected: 0x07 },
    CountCase { name: "high_bit_set", input: 0xf290b311, expected: 0x00 },
    CountCase { name: "one_leading_zero", input: 0x759e9df5, expected: 0x01 },
    CountCase { name: "two_leading_zeros", input: 0x27fe67d3, expected: 0x02 },
];

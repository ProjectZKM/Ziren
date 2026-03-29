use zkm_core_executor::{Instruction, Opcode, Program, Register};

use crate::{encode_ext, encode_ins, imm_program, InstructionTestSuite};

struct UnaryCase {
    name: &'static str,
    input: u32,
    expected: u32,
}

macro_rules! unary_suite {
    ($name:ident, $const_name:ident, $suite_name:literal, $opcode:expr, $op_c:expr, $cases:ident) => {
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
                imm_program(Register::T1, Register::T0, $cases[index].input, $opcode, $op_c)
            }
            fn assert_executor(&self, index: usize, read_reg: &mut dyn FnMut(Register) -> u32) {
                let case = &$cases[index];
                assert_eq!(read_reg(Register::T0), case.input, "{}: source preserved", case.name);
                assert_eq!(read_reg(Register::T1), case.expected, "{}: result mismatch", case.name);
            }
        }
    };
}

unary_suite!(N71Seb, N71_SEB, "n71_seb", Opcode::SEXT, 0, N71_SEB_CASES);
const N71_SEB_CASES: &[UnaryCase] = &[
    UnaryCase { name: "vector_00", input: 0x4e5885b6, expected: 0xffffffb6 },
    UnaryCase { name: "vector_01", input: 0x3296a156, expected: 0x00000056 },
    UnaryCase { name: "vector_02", input: 0x473412a6, expected: 0xffffffa6 },
    UnaryCase { name: "vector_03", input: 0x70aa193f, expected: 0x0000003f },
    UnaryCase { name: "vector_04", input: 0x000000b5, expected: 0xffffffb5 },
    UnaryCase { name: "vector_05", input: 0x0000000d, expected: 0x0000000d },
    UnaryCase { name: "vector_06", input: 0x00000092, expected: 0xffffff92 },
    UnaryCase { name: "vector_07", input: 0x000000ec, expected: 0xffffffec },
    UnaryCase { name: "vector_08", input: 0x00008907, expected: 0x00000007 },
    UnaryCase { name: "vector_09", input: 0x00002e75, expected: 0x00000075 },
    UnaryCase { name: "vector_10", input: 0x000025a7, expected: 0xffffffa7 },
    UnaryCase { name: "vector_11", input: 0x000039b5, expected: 0xffffffb5 },
];

unary_suite!(N72Seh, N72_SEH, "n72_seh", Opcode::SEXT, 1, N72_SEH_CASES);
const N72_SEH_CASES: &[UnaryCase] = &[
    UnaryCase { name: "vector_00", input: 0x75ce8687, expected: 0xffff8687 },
    UnaryCase { name: "vector_01", input: 0x4367c83e, expected: 0xffffc83e },
    UnaryCase { name: "vector_02", input: 0x7b268d2a, expected: 0xffff8d2a },
    UnaryCase { name: "vector_03", input: 0x15044d0d, expected: 0x00004d0d },
    UnaryCase { name: "vector_04", input: 0x00000055, expected: 0x00000055 },
    UnaryCase { name: "vector_05", input: 0x00000088, expected: 0x00000088 },
    UnaryCase { name: "vector_06", input: 0x000000dc, expected: 0x000000dc },
    UnaryCase { name: "vector_07", input: 0x00000009, expected: 0x00000009 },
    UnaryCase { name: "vector_08", input: 0x0000d199, expected: 0xffffd199 },
    UnaryCase { name: "vector_09", input: 0x0000d033, expected: 0xffffd033 },
    UnaryCase { name: "vector_10", input: 0x00006b13, expected: 0x00006b13 },
    UnaryCase { name: "vector_11", input: 0x00006670, expected: 0x00006670 },
    UnaryCase { name: "vector_12", input: 0x00f2020c, expected: 0x0000020c },
    UnaryCase { name: "vector_13", input: 0x00fbabd6, expected: 0xffffabd6 },
    UnaryCase { name: "vector_14", input: 0x00f0eeab, expected: 0xffffeeab },
    UnaryCase { name: "vector_15", input: 0x00f9f413, expected: 0xfffff413 },
];

unary_suite!(N73Wsbh, N73_WSBH, "n73_wsbh", Opcode::WSBH, 0, N73_WSBH_CASES);
const N73_WSBH_CASES: &[UnaryCase] = &[
    UnaryCase { name: "vector_00", input: 0x287b78ef, expected: 0x7b28ef78 },
    UnaryCase { name: "vector_01", input: 0x181e0b04, expected: 0x1e18040b },
    UnaryCase { name: "vector_02", input: 0x79025ad8, expected: 0x0279d85a },
    UnaryCase { name: "vector_03", input: 0x503c59fc, expected: 0x3c50fc59 },
];

pub struct N74Ins;
pub const N74_INS: N74Ins = N74Ins;

struct InsCase {
    name: &'static str,
    expected: u32,
    source: u32,
    initial: u32,
    pos: u32,
    size: u32,
}

impl InstructionTestSuite for N74Ins {
    fn name(&self) -> &'static str {
        "n74_ins"
    }
    fn len(&self) -> usize {
        N74_INS_CASES.len()
    }
    fn case_name(&self, index: usize) -> &'static str {
        N74_INS_CASES[index].name
    }
    fn program(&self, index: usize) -> Program {
        let case = &N74_INS_CASES[index];
        Program::new(
            vec![
                Instruction::new(Opcode::ADD, Register::T0 as u8, 0, case.source, false, true),
                Instruction::new(Opcode::ADD, Register::T1 as u8, 0, case.initial, false, true),
                Instruction::new(
                    Opcode::INS,
                    Register::T1 as u8,
                    Register::T0 as u32,
                    encode_ins(case.pos, case.size),
                    false,
                    true,
                ),
            ],
            0,
            0,
        )
    }
    fn assert_executor(&self, index: usize, read_reg: &mut dyn FnMut(Register) -> u32) {
        let case = &N74_INS_CASES[index];
        assert_eq!(read_reg(Register::T0), case.source, "{}: source preserved", case.name);
        assert_eq!(read_reg(Register::T1), case.expected, "{}: result mismatch", case.name);
    }
}

const N74_INS_CASES: &[InsCase] = &[
    InsCase {
        name: "small_interior",
        expected: 0x561d90a9,
        source: 0x7f8ef599,
        initial: 0x561e90a9,
        pos: 16,
        size: 2,
    },
    InsCase {
        name: "high_end",
        expected: 0x4a9a8c2b,
        source: 0x00af69a6,
        initial: 0x2a9a8c2b,
        pos: 29,
        size: 2,
    },
    InsCase {
        name: "bit31_boundary",
        expected: 0x07aaee30,
        source: 0x47969d08,
        initial: 0x07aaee30,
        pos: 31,
        size: 1,
    },
    InsCase {
        name: "wide_upper",
        expected: 0x100a67cd,
        source: 0x53080533,
        initial: 0x1353abcd,
        pos: 9,
        size: 22,
    },
    InsCase {
        name: "near_full_31",
        expected: 0x15ff759d,
        source: 0x0affbace,
        initial: 0x17d04d85,
        pos: 1,
        size: 31,
    },
    InsCase {
        name: "near_full_30",
        expected: 0x29c799ef,
        source: 0x4a71e67b,
        initial: 0x5b173f93,
        pos: 2,
        size: 30,
    },
    InsCase {
        name: "near_full_29",
        expected: 0x3e354cc5,
        source: 0x27c6a998,
        initial: 0x124a20bd,
        pos: 3,
        size: 29,
    },
    InsCase {
        name: "full_width_a",
        expected: 0x535d7797,
        source: 0x535d7797,
        initial: 0x5ea30063,
        pos: 0,
        size: 32,
    },
    InsCase {
        name: "full_width_b",
        expected: 0x313209e7,
        source: 0x313209e7,
        initial: 0x1d2d81ad,
        pos: 0,
        size: 32,
    },
    InsCase {
        name: "top_bit_noop",
        expected: 0x0d609402,
        source: 0x64cb2596,
        initial: 0x0d609402,
        pos: 31,
        size: 1,
    },
];

pub struct N75Ext;
pub const N75_EXT: N75Ext = N75Ext;

struct ExtCase {
    name: &'static str,
    expected: u32,
    source: u32,
    pos: u32,
    size: u32,
}

impl InstructionTestSuite for N75Ext {
    fn name(&self) -> &'static str {
        "n75_ext"
    }
    fn len(&self) -> usize {
        N75_EXT_CASES.len()
    }
    fn case_name(&self, index: usize) -> &'static str {
        N75_EXT_CASES[index].name
    }
    fn program(&self, index: usize) -> Program {
        let case = &N75_EXT_CASES[index];
        Program::new(
            vec![
                Instruction::new(Opcode::ADD, Register::T0 as u8, 0, case.source, false, true),
                Instruction::new(
                    Opcode::EXT,
                    Register::T1 as u8,
                    Register::T0 as u32,
                    encode_ext(case.pos, case.size),
                    false,
                    true,
                ),
            ],
            0,
            0,
        )
    }
    fn assert_executor(&self, index: usize, read_reg: &mut dyn FnMut(Register) -> u32) {
        let case = &N75_EXT_CASES[index];
        assert_eq!(read_reg(Register::T0), case.source, "{}: source preserved", case.name);
        assert_eq!(read_reg(Register::T1), case.expected, "{}: result mismatch", case.name);
    }
}

const N75_EXT_CASES: &[ExtCase] = &[
    ExtCase {
        name: "interior_window",
        expected: 0x00000407,
        source: 0x101f5494,
        pos: 18,
        size: 11,
    },
    ExtCase { name: "full_width_a", expected: 0x76d3b816, source: 0x76d3b816, pos: 0, size: 32 },
    ExtCase { name: "high_single_bit", expected: 0x00000000, source: 0x3475095d, pos: 31, size: 1 },
    ExtCase { name: "top_half", expected: 0x000010eb, source: 0x10eb4cbc, pos: 16, size: 16 },
    ExtCase { name: "wide_middle", expected: 0x0020e24c, source: 0x20e24ccf, pos: 8, size: 24 },
    ExtCase { name: "full_width_b", expected: 0x745a3a5b, source: 0x745a3a5b, pos: 0, size: 32 },
];

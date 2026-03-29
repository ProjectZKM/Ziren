use zkm_core_executor::{Instruction, Opcode, Program, Register};

use crate::InstructionTestSuite;

pub struct N44Div;
pub const N44_DIV: N44Div = N44Div;

struct DivCase {
    name: &'static str,
    lhs: u32,
    rhs: u32,
    expected_lo: u32,
    expected_hi: u32,
}

const N44_DIV_CASES: &[DivCase] = &[
    DivCase {
        name: "mipstest_00",
        lhs: 0x56bedfa4,
        rhs: 0x20831400,
        expected_lo: 0x00000002,
        expected_hi: 0x15b8b7a4,
    },
    DivCase {
        name: "mipstest_01",
        lhs: 0xfda5ea8a,
        rhs: 0xfac1873c,
        expected_lo: 0x00000000,
        expected_hi: 0xfda5ea8a,
    },
    DivCase {
        name: "mipstest_02",
        lhs: 0x53eb4a70,
        rhs: 0x07e13dd1,
        expected_lo: 0x0000000a,
        expected_hi: 0x051ee046,
    },
    DivCase {
        name: "mipstest_03",
        lhs: 0x323676e0,
        rhs: 0xdc3a3f10,
        expected_lo: 0xffffffff,
        expected_hi: 0x0e70b5f0,
    },
    DivCase {
        name: "mipstest_04",
        lhs: 0xc3e0f060,
        rhs: 0xe9c97944,
        expected_lo: 0x00000002,
        expected_hi: 0xf04dfdd8,
    },
    DivCase {
        name: "mipstest_05",
        lhs: 0x7c7b85f2,
        rhs: 0xdb7e6dc0,
        expected_lo: 0xfffffffd,
        expected_hi: 0x0ef6cf32,
    },
    DivCase {
        name: "mipstest_06",
        lhs: 0x3bbf1da0,
        rhs: 0xe73f9eea,
        expected_lo: 0xfffffffe,
        expected_hi: 0x0a3e5b74,
    },
    DivCase {
        name: "mipstest_07",
        lhs: 0x8786a50c,
        rhs: 0x412dc050,
        expected_lo: 0xffffffff,
        expected_hi: 0xc8b4655c,
    },
    DivCase {
        name: "mipstest_08",
        lhs: 0xee98aaf8,
        rhs: 0x36730f80,
        expected_lo: 0x00000000,
        expected_hi: 0xee98aaf8,
    },
    DivCase {
        name: "mipstest_09",
        lhs: 0x68d65d90,
        rhs: 0xd6d52b70,
        expected_lo: 0xfffffffe,
        expected_hi: 0x1680b470,
    },
    DivCase {
        name: "mipstest_10",
        lhs: 0x17779850,
        rhs: 0x511b1fba,
        expected_lo: 0x00000000,
        expected_hi: 0x17779850,
    },
    DivCase {
        name: "mipstest_11",
        lhs: 0x7bfc98c0,
        rhs: 0xdffb8d8c,
        expected_lo: 0xfffffffd,
        expected_hi: 0x1bef4164,
    },
    DivCase {
        name: "zero_dividend_0",
        lhs: 0x00000000,
        rhs: 0xa7bb1ef0,
        expected_lo: 0x00000000,
        expected_hi: 0x00000000,
    },
    DivCase {
        name: "zero_dividend_1",
        lhs: 0x00000000,
        rhs: 0x3050efec,
        expected_lo: 0x00000000,
        expected_hi: 0x00000000,
    },
    DivCase {
        name: "zero_dividend_2",
        lhs: 0x00000000,
        rhs: 0x94e29c00,
        expected_lo: 0x00000000,
        expected_hi: 0x00000000,
    },
    DivCase {
        name: "positive_over_neg_one",
        lhs: 5,
        rhs: (-1i32) as u32,
        expected_lo: (-5i32) as u32,
        expected_hi: 0,
    },
    DivCase {
        name: "negative_over_neg_one",
        lhs: (-5i32) as u32,
        rhs: (-1i32) as u32,
        expected_lo: 5,
        expected_hi: 0,
    },
    DivCase {
        name: "int_max_over_neg_one",
        lhs: i32::MAX as u32,
        rhs: (-1i32) as u32,
        expected_lo: (-(i32::MAX)) as u32,
        expected_hi: 0,
    },
    DivCase {
        name: "negative_sample_over_neg_one",
        lhs: (-123456789i32) as u32,
        rhs: (-1i32) as u32,
        expected_lo: 123456789u32,
        expected_hi: 0,
    },
    DivCase {
        name: "int_min_divisor",
        lhs: 5,
        rhs: i32::MIN as u32,
        expected_lo: 0,
        expected_hi: 5,
    },
];

impl InstructionTestSuite for N44Div {
    fn name(&self) -> &'static str {
        "n44_div"
    }
    fn len(&self) -> usize {
        N44_DIV_CASES.len()
    }
    fn case_name(&self, index: usize) -> &'static str {
        N44_DIV_CASES[index].name
    }
    fn program(&self, index: usize) -> Program {
        let case = &N44_DIV_CASES[index];
        Program::new(
            vec![
                Instruction::new(Opcode::ADD, Register::T0 as u8, 0, case.lhs, false, true),
                Instruction::new(Opcode::ADD, Register::T1 as u8, 0, case.rhs, false, true),
                Instruction::new(
                    Opcode::DIV,
                    Register::LO as u8,
                    Register::T0 as u32,
                    Register::T1 as u32,
                    false,
                    false,
                ),
            ],
            0,
            0,
        )
    }
    fn assert_executor(&self, index: usize, read_reg: &mut dyn FnMut(Register) -> u32) {
        let case = &N44_DIV_CASES[index];
        assert_eq!(read_reg(Register::T0), case.lhs, "{}: DIV should preserve lhs", case.name);
        assert_eq!(read_reg(Register::T1), case.rhs, "{}: DIV should preserve rhs", case.name);
        assert_eq!(read_reg(Register::LO), case.expected_lo, "{}: DIV LO mismatch", case.name);
        assert_eq!(read_reg(Register::HI), case.expected_hi, "{}: DIV HI mismatch", case.name);
    }
}

pub struct N45Divu;
pub const N45_DIVU: N45Divu = N45Divu;

const N45_DIVU_CASES: &[DivCase] = &[
    DivCase {
        name: "mipstest_00",
        lhs: 0x4e775a80,
        rhs: 0xb26795ec,
        expected_lo: 0x00000000,
        expected_hi: 0x4e775a80,
    },
    DivCase {
        name: "mipstest_01",
        lhs: 0x4e888700,
        rhs: 0xf0d84fce,
        expected_lo: 0x00000000,
        expected_hi: 0x4e888700,
    },
    DivCase {
        name: "mipstest_02",
        lhs: 0x01dea048,
        rhs: 0xf2c74100,
        expected_lo: 0x00000000,
        expected_hi: 0x01dea048,
    },
    DivCase {
        name: "mipstest_03",
        lhs: 0x77e68950,
        rhs: 0x8b0ddad0,
        expected_lo: 0x00000000,
        expected_hi: 0x77e68950,
    },
    DivCase {
        name: "mipstest_04",
        lhs: 0x72013c68,
        rhs: 0x48cb8680,
        expected_lo: 0x00000001,
        expected_hi: 0x2935b5e8,
    },
    DivCase {
        name: "mipstest_05",
        lhs: 0x7fb2e9a0,
        rhs: 0xc9af5700,
        expected_lo: 0x00000000,
        expected_hi: 0x7fb2e9a0,
    },
    DivCase {
        name: "mipstest_06",
        lhs: 0xd7042938,
        rhs: 0x018a7078,
        expected_lo: 0x0000008b,
        expected_hi: 0x00d91810,
    },
    DivCase {
        name: "mipstest_07",
        lhs: 0xbf81441b,
        rhs: 0x704e3f24,
        expected_lo: 0x00000001,
        expected_hi: 0x4f3304f7,
    },
    DivCase {
        name: "mipstest_08",
        lhs: 0xeb5994e6,
        rhs: 0x622f1558,
        expected_lo: 0x00000002,
        expected_hi: 0x26fb6a36,
    },
    DivCase {
        name: "mipstest_09",
        lhs: 0x11176c40,
        rhs: 0x8128af78,
        expected_lo: 0x00000000,
        expected_hi: 0x11176c40,
    },
    DivCase {
        name: "mipstest_10",
        lhs: 0x32893870,
        rhs: 0xab09b9c0,
        expected_lo: 0x00000000,
        expected_hi: 0x32893870,
    },
    DivCase {
        name: "mipstest_11",
        lhs: 0x403c60c0,
        rhs: 0x6fe79f00,
        expected_lo: 0x00000000,
        expected_hi: 0x403c60c0,
    },
    DivCase {
        name: "zero_dividend_0",
        lhs: 0x00000000,
        rhs: 0xbea685ab,
        expected_lo: 0x00000000,
        expected_hi: 0x00000000,
    },
    DivCase {
        name: "zero_dividend_1",
        lhs: 0x00000000,
        rhs: 0x207ed850,
        expected_lo: 0x00000000,
        expected_hi: 0x00000000,
    },
    DivCase {
        name: "zero_dividend_2",
        lhs: 0x00000000,
        rhs: 0x72c14afa,
        expected_lo: 0x00000000,
        expected_hi: 0x00000000,
    },
    DivCase {
        name: "zero_dividend_3",
        lhs: 0x00000000,
        rhs: 0xae5365c0,
        expected_lo: 0x00000000,
        expected_hi: 0x00000000,
    },
    DivCase {
        name: "zero_dividend_4",
        lhs: 0x00000000,
        rhs: 0x9670f9f0,
        expected_lo: 0x00000000,
        expected_hi: 0x00000000,
    },
    DivCase {
        name: "zero_dividend_5",
        lhs: 0x00000000,
        rhs: 0x8e85bf30,
        expected_lo: 0x00000000,
        expected_hi: 0x00000000,
    },
    DivCase {
        name: "zero_dividend_6",
        lhs: 0x00000000,
        rhs: 0x11f1eca7,
        expected_lo: 0x00000000,
        expected_hi: 0x00000000,
    },
    DivCase {
        name: "int_min_bitpattern_divisor",
        lhs: 5,
        rhs: i32::MIN as u32,
        expected_lo: 0,
        expected_hi: 5,
    },
];

impl InstructionTestSuite for N45Divu {
    fn name(&self) -> &'static str {
        "n45_divu"
    }
    fn len(&self) -> usize {
        N45_DIVU_CASES.len()
    }
    fn case_name(&self, index: usize) -> &'static str {
        N45_DIVU_CASES[index].name
    }
    fn program(&self, index: usize) -> Program {
        let case = &N45_DIVU_CASES[index];
        Program::new(
            vec![
                Instruction::new(Opcode::ADD, Register::T0 as u8, 0, case.lhs, false, true),
                Instruction::new(Opcode::ADD, Register::T1 as u8, 0, case.rhs, false, true),
                Instruction::new(
                    Opcode::DIVU,
                    Register::LO as u8,
                    Register::T0 as u32,
                    Register::T1 as u32,
                    false,
                    false,
                ),
            ],
            0,
            0,
        )
    }
    fn assert_executor(&self, index: usize, read_reg: &mut dyn FnMut(Register) -> u32) {
        let case = &N45_DIVU_CASES[index];
        assert_eq!(read_reg(Register::T0), case.lhs, "{}: DIVU should preserve lhs", case.name);
        assert_eq!(read_reg(Register::T1), case.rhs, "{}: DIVU should preserve rhs", case.name);
        assert_eq!(read_reg(Register::LO), case.expected_lo, "{}: DIVU LO mismatch", case.name);
        assert_eq!(read_reg(Register::HI), case.expected_hi, "{}: DIVU HI mismatch", case.name);
    }
}

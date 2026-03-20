use zkm_core_executor::{Executor, Instruction, Opcode, Program, Register};
use zkm_stark::ZKMCoreOpts;

#[derive(Clone, Copy, Debug)]
struct DivuCase {
    lhs: u32,
    rhs: u32,
    expected_lo: u32,
    expected_hi: u32,
}

/// Build the smallest program that isolates unsigned `DIVU`.
///
/// The program loads the dividend and divisor into `t0` and `t1`, executes `DIVU`, then leaves
/// the quotient in `LO` and the remainder in `HI`.
fn divu_program(case: DivuCase) -> Program {
    let instructions = vec![
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
    ];
    Program::new(instructions, 0, 0)
}

/// Regression vectors copied from `mipstest/insttest/src/n45_divu.S`.
///
/// These include cases where the quotient is zero, multi-bit quotients, large unsigned dividends,
/// and the zero-dividend boundary vectors from the end of the assembly test.
#[test]
fn n45_divu_vectors() {
    let cases = [
        DivuCase {
            lhs: 0x4e775a80,
            rhs: 0xb26795ec,
            expected_lo: 0x00000000,
            expected_hi: 0x4e775a80,
        },
        DivuCase {
            lhs: 0x4e888700,
            rhs: 0xf0d84fce,
            expected_lo: 0x00000000,
            expected_hi: 0x4e888700,
        },
        DivuCase {
            lhs: 0x01dea048,
            rhs: 0xf2c74100,
            expected_lo: 0x00000000,
            expected_hi: 0x01dea048,
        },
        DivuCase {
            lhs: 0x77e68950,
            rhs: 0x8b0ddad0,
            expected_lo: 0x00000000,
            expected_hi: 0x77e68950,
        },
        DivuCase {
            lhs: 0x72013c68,
            rhs: 0x48cb8680,
            expected_lo: 0x00000001,
            expected_hi: 0x2935b5e8,
        },
        DivuCase {
            lhs: 0x7fb2e9a0,
            rhs: 0xc9af5700,
            expected_lo: 0x00000000,
            expected_hi: 0x7fb2e9a0,
        },
        DivuCase {
            lhs: 0xd7042938,
            rhs: 0x018a7078,
            expected_lo: 0x0000008b,
            expected_hi: 0x00d91810,
        },
        DivuCase {
            lhs: 0xbf81441b,
            rhs: 0x704e3f24,
            expected_lo: 0x00000001,
            expected_hi: 0x4f3304f7,
        },
        DivuCase {
            lhs: 0xeb5994e6,
            rhs: 0x622f1558,
            expected_lo: 0x00000002,
            expected_hi: 0x26fb6a36,
        },
        DivuCase {
            lhs: 0x11176c40,
            rhs: 0x8128af78,
            expected_lo: 0x00000000,
            expected_hi: 0x11176c40,
        },
        DivuCase {
            lhs: 0x32893870,
            rhs: 0xab09b9c0,
            expected_lo: 0x00000000,
            expected_hi: 0x32893870,
        },
        DivuCase {
            lhs: 0x403c60c0,
            rhs: 0x6fe79f00,
            expected_lo: 0x00000000,
            expected_hi: 0x403c60c0,
        },
        DivuCase {
            lhs: 0x00000000,
            rhs: 0xbea685ab,
            expected_lo: 0x00000000,
            expected_hi: 0x00000000,
        },
        DivuCase {
            lhs: 0x00000000,
            rhs: 0x207ed850,
            expected_lo: 0x00000000,
            expected_hi: 0x00000000,
        },
        DivuCase {
            lhs: 0x00000000,
            rhs: 0x72c14afa,
            expected_lo: 0x00000000,
            expected_hi: 0x00000000,
        },
        DivuCase {
            lhs: 0x00000000,
            rhs: 0xae5365c0,
            expected_lo: 0x00000000,
            expected_hi: 0x00000000,
        },
        DivuCase {
            lhs: 0x00000000,
            rhs: 0x9670f9f0,
            expected_lo: 0x00000000,
            expected_hi: 0x00000000,
        },
        DivuCase {
            lhs: 0x00000000,
            rhs: 0x8e85bf30,
            expected_lo: 0x00000000,
            expected_hi: 0x00000000,
        },
        DivuCase {
            lhs: 0x00000000,
            rhs: 0x11f1eca7,
            expected_lo: 0x00000000,
            expected_hi: 0x00000000,
        },
    ];

    for (i, case) in cases.into_iter().enumerate() {
        let mut runtime = Executor::new(divu_program(case), ZKMCoreOpts::default());
        runtime.run_very_fast().unwrap();

        assert_eq!(runtime.register(Register::T0), case.lhs, "case {i}: DIVU should preserve lhs");
        assert_eq!(runtime.register(Register::T1), case.rhs, "case {i}: DIVU should preserve rhs");
        assert_eq!(runtime.register(Register::LO), case.expected_lo, "case {i}: DIVU LO mismatch");
        assert_eq!(runtime.register(Register::HI), case.expected_hi, "case {i}: DIVU HI mismatch");
    }
}

use std::panic::{catch_unwind, AssertUnwindSafe};

use zkm_core_executor::{ExecutionError, Executor, Instruction, Opcode, Program, Register};
use zkm_stark::ZKMCoreOpts;

#[derive(Clone, Copy, Debug)]
struct DivCase {
    lhs: u32,
    rhs: u32,
    expected_lo: u32,
    expected_hi: u32,
}

/// Build the smallest program that isolates signed `DIV`.
///
/// The program loads the dividend and divisor into `t0` and `t1`, executes `DIV`, then leaves
/// the quotient in `LO` and the remainder in `HI`.
fn div_program(case: DivCase) -> Program {
    let instructions = vec![
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
    ];
    Program::new(instructions, 0, 0)
}

/// Regression vectors copied from `mipstest/insttest/src/n44_div.S`.
///
/// These include positive and negative signed divisions, divisors larger than the dividend, and
/// the zero-dividend boundary vectors from the end of the assembly test.
#[test]
fn n44_div_vectors() {
    let cases = [
        DivCase {
            lhs: 0x56bedfa4,
            rhs: 0x20831400,
            expected_lo: 0x00000002,
            expected_hi: 0x15b8b7a4,
        },
        DivCase {
            lhs: 0xfda5ea8a,
            rhs: 0xfac1873c,
            expected_lo: 0x00000000,
            expected_hi: 0xfda5ea8a,
        },
        DivCase {
            lhs: 0x53eb4a70,
            rhs: 0x07e13dd1,
            expected_lo: 0x0000000a,
            expected_hi: 0x051ee046,
        },
        DivCase {
            lhs: 0x323676e0,
            rhs: 0xdc3a3f10,
            expected_lo: 0xffffffff,
            expected_hi: 0x0e70b5f0,
        },
        DivCase {
            lhs: 0xc3e0f060,
            rhs: 0xe9c97944,
            expected_lo: 0x00000002,
            expected_hi: 0xf04dfdd8,
        },
        DivCase {
            lhs: 0x7c7b85f2,
            rhs: 0xdb7e6dc0,
            expected_lo: 0xfffffffd,
            expected_hi: 0x0ef6cf32,
        },
        DivCase {
            lhs: 0x3bbf1da0,
            rhs: 0xe73f9eea,
            expected_lo: 0xfffffffe,
            expected_hi: 0x0a3e5b74,
        },
        DivCase {
            lhs: 0x8786a50c,
            rhs: 0x412dc050,
            expected_lo: 0xffffffff,
            expected_hi: 0xc8b4655c,
        },
        DivCase {
            lhs: 0xee98aaf8,
            rhs: 0x36730f80,
            expected_lo: 0x00000000,
            expected_hi: 0xee98aaf8,
        },
        DivCase {
            lhs: 0x68d65d90,
            rhs: 0xd6d52b70,
            expected_lo: 0xfffffffe,
            expected_hi: 0x1680b470,
        },
        DivCase {
            lhs: 0x17779850,
            rhs: 0x511b1fba,
            expected_lo: 0x00000000,
            expected_hi: 0x17779850,
        },
        DivCase {
            lhs: 0x7bfc98c0,
            rhs: 0xdffb8d8c,
            expected_lo: 0xfffffffd,
            expected_hi: 0x1bef4164,
        },
        DivCase {
            lhs: 0x00000000,
            rhs: 0xa7bb1ef0,
            expected_lo: 0x00000000,
            expected_hi: 0x00000000,
        },
        DivCase {
            lhs: 0x00000000,
            rhs: 0x3050efec,
            expected_lo: 0x00000000,
            expected_hi: 0x00000000,
        },
        DivCase {
            lhs: 0x00000000,
            rhs: 0x94e29c00,
            expected_lo: 0x00000000,
            expected_hi: 0x00000000,
        },
    ];

    for (i, case) in cases.into_iter().enumerate() {
        let mut runtime = Executor::new(div_program(case), ZKMCoreOpts::default());
        runtime.run_very_fast().unwrap();

        assert_eq!(runtime.register(Register::T0), case.lhs, "case {i}: DIV should preserve lhs");
        assert_eq!(runtime.register(Register::T1), case.rhs, "case {i}: DIV should preserve rhs");
        assert_eq!(runtime.register(Register::LO), case.expected_lo, "case {i}: DIV LO mismatch");
        assert_eq!(runtime.register(Register::HI), case.expected_hi, "case {i}: DIV HI mismatch");
    }
}

/// Hand-written signed division cases for divisor `-1` that do not hit the `INT_MIN / -1`
/// overflow path.
#[test]
fn n44_div_negative_one_divisor_vectors() {
    let cases = [
        DivCase { lhs: 5, rhs: (-1i32) as u32, expected_lo: (-5i32) as u32, expected_hi: 0 },
        DivCase { lhs: (-5i32) as u32, rhs: (-1i32) as u32, expected_lo: 5, expected_hi: 0 },
        DivCase {
            lhs: i32::MAX as u32,
            rhs: (-1i32) as u32,
            expected_lo: (-(i32::MAX)) as u32,
            expected_hi: 0,
        },
        DivCase {
            lhs: (-123456789i32) as u32,
            rhs: (-1i32) as u32,
            expected_lo: 123456789u32,
            expected_hi: 0,
        },
    ];

    for (i, case) in cases.into_iter().enumerate() {
        let mut runtime = Executor::new(div_program(case), ZKMCoreOpts::default());
        runtime.run_very_fast().unwrap();

        assert_eq!(runtime.register(Register::T0), case.lhs, "case {i}: DIV should preserve lhs");
        assert_eq!(runtime.register(Register::T1), case.rhs, "case {i}: DIV should preserve rhs");
        assert_eq!(runtime.register(Register::LO), case.expected_lo, "case {i}: DIV LO mismatch");
        assert_eq!(runtime.register(Register::HI), case.expected_hi, "case {i}: DIV HI mismatch");
    }
}

/// `DIV` should trap on a zero divisor before it attempts the arithmetic.
#[test]
fn n44_div_by_zero_traps() {
    let case = DivCase { lhs: 0x1234_5678, rhs: 0x0000_0000, expected_lo: 0, expected_hi: 0 };

    let mut runtime = Executor::new(div_program(case), ZKMCoreOpts::default());
    let err = runtime.run_very_fast().unwrap_err();
    assert!(matches!(err, ExecutionError::ExceptionOrTrap()));
}

/// Signed `INT_MIN / -1` is the unique overflow case.
///
/// The machine AIR models this explicitly, but the executor currently performs raw Rust signed
/// division, so this edge case panics in debug builds instead of returning a normal result.
#[test]
fn n44_div_int_min_overflow_panics() {
    let case =
        DivCase { lhs: i32::MIN as u32, rhs: (-1i32) as u32, expected_lo: 0, expected_hi: 0 };

    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut runtime = Executor::new(div_program(case), ZKMCoreOpts::default());
        let _ = runtime.run_very_fast();
    }));

    assert!(result.is_err(), "INT_MIN / -1 should currently panic in the executor");
}

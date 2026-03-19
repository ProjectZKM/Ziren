use zkm_core_executor::{Executor, Instruction, Opcode, Program, Register};
use zkm_stark::ZKMCoreOpts;

#[derive(Clone, Copy, Debug)]
struct MaddCase {
    initial_lo: u32,
    initial_hi: u32,
    lhs: u32,
    rhs: u32,
    expected_lo: u32,
    expected_hi: u32,
}

/// Build the smallest program that isolates `MADD`.
///
/// The program:
/// 1. Seeds `LO` and `HI` with the accumulator input from the original mipstest vector.
/// 2. Loads the multiplicands into `t0` and `t1`.
/// 3. Executes `MADD t0, t1`, which adds the signed product into the 64-bit `HI:LO` accumulator.
fn madd_program(case: MaddCase) -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, Register::LO as u8, 0, case.initial_lo, false, true),
        Instruction::new(Opcode::ADD, Register::HI as u8, 0, case.initial_hi, false, true),
        Instruction::new(Opcode::ADD, Register::T0 as u8, 0, case.lhs, false, true),
        Instruction::new(Opcode::ADD, Register::T1 as u8, 0, case.rhs, false, true),
        Instruction::new(
            Opcode::MADD,
            Register::LO as u8,
            Register::T0 as u32,
            Register::T1 as u32,
            false,
            false,
        ),
    ];
    Program::new(instructions, 0, 0)
}

/// Representative regression vectors copied from `mipstest/insttest/src/n67_madd.S`.
///
/// These keep the executor check focused on signed multiply-add semantics with non-trivial initial
/// `HI:LO` state, rather than trying to duplicate the entire assembly test file here.
#[test]
fn n67_madd_vectors() {
    let cases = [
        MaddCase {
            initial_lo: 0x0a7d6700,
            initial_hi: 0x2668999b,
            lhs: 0x397b048a,
            rhs: 0x54a890ae,
            expected_lo: 0x91381ccc,
            expected_hi: 0x396ad04f,
        },
        MaddCase {
            initial_lo: 0x2c4ab983,
            initial_hi: 0x40b6172c,
            lhs: 0x18948ec7,
            rhs: 0x309bef68,
            expected_lo: 0x9c6d835b,
            expected_hi: 0x4560eae0,
        },
        MaddCase {
            initial_lo: 0x73a03616,
            initial_hi: 0x48366d2a,
            lhs: 0x37171000,
            rhs: 0x72087790,
            expected_lo: 0xa9093616,
            expected_hi: 0x60c084bd,
        },
        MaddCase {
            initial_lo: 0x3c346552,
            initial_hi: 0x343e506b,
            lhs: 0x3b27039d,
            rhs: 0x1d702944,
            expected_lo: 0x8fd58006,
            expected_hi: 0x3b0ba66e,
        },
        MaddCase {
            initial_lo: 0x2a1d5195,
            initial_hi: 0x4001710d,
            lhs: 0x587207ed,
            rhs: 0x15cff245,
            expected_lo: 0xa5fa7e76,
            expected_hi: 0x478aa39b,
        },
        MaddCase {
            initial_lo: 0x3ee63c79,
            initial_hi: 0x75a97460,
            lhs: 0x6009cc79,
            rhs: 0x0792849b,
            expected_lo: 0x5e456dbc,
            expected_hi: 0x7880b04d,
        },
        MaddCase {
            initial_lo: 0x0db7cd22,
            initial_hi: 0x3562eba3,
            lhs: 0x4d95e8cb,
            rhs: 0x2244946b,
            expected_lo: 0xf1e175fb,
            expected_hi: 0x3fc59d5a,
        },
        MaddCase {
            initial_lo: 0x6bb2429d,
            initial_hi: 0x522494df,
            lhs: 0x32ca89cd,
            rhs: 0x762fa99e,
            expected_lo: 0x444ea423,
            expected_hi: 0x6997653a,
        },
        MaddCase {
            initial_lo: 0x788d2e7a,
            initial_hi: 0x6c458e57,
            lhs: 0x4ad83a4c,
            rhs: 0x24d7e7fe,
            expected_lo: 0x7d8599e2,
            expected_hi: 0x770b15f6,
        },
    ];

    for (i, case) in cases.into_iter().enumerate() {
        let mut runtime = Executor::new(madd_program(case), ZKMCoreOpts::default());
        runtime.run_very_fast().unwrap();

        assert_eq!(runtime.register(Register::T0), case.lhs, "case {i}: MADD should preserve lhs");
        assert_eq!(runtime.register(Register::T1), case.rhs, "case {i}: MADD should preserve rhs");
        assert_eq!(runtime.register(Register::LO), case.expected_lo, "case {i}: MADD LO mismatch");
        assert_eq!(runtime.register(Register::HI), case.expected_hi, "case {i}: MADD HI mismatch");
    }
}

use zkm_core_executor::{Executor, Instruction, Opcode, Program, Register};
use zkm_stark::ZKMCoreOpts;

#[derive(Clone, Copy, Debug)]
struct MsubCase {
    initial_lo: u32,
    initial_hi: u32,
    lhs: u32,
    rhs: u32,
    expected_lo: u32,
    expected_hi: u32,
}

/// Build the smallest program that isolates `MSUB`.
fn msub_program(case: MsubCase) -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, Register::LO as u8, 0, case.initial_lo, false, true),
        Instruction::new(Opcode::ADD, Register::HI as u8, 0, case.initial_hi, false, true),
        Instruction::new(Opcode::ADD, Register::T0 as u8, 0, case.lhs, false, true),
        Instruction::new(Opcode::ADD, Register::T1 as u8, 0, case.rhs, false, true),
        Instruction::new(
            Opcode::MSUB,
            Register::LO as u8,
            Register::T0 as u32,
            Register::T1 as u32,
            false,
            false,
        ),
    ];
    Program::new(instructions, 0, 0)
}

/// Representative regression vectors copied from `mipstest/insttest/src/n69_msub.S`.
#[test]
fn n69_msub_vectors() {
    let cases = [
        MsubCase {
            initial_lo: 0x7c85bcc6,
            initial_hi: 0x19f7e5ff,
            lhs: 0x78865b5f,
            rhs: 0x599f4abd,
            expected_lo: 0xe3e9d1a3,
            expected_hi: 0xefc63198,
        },
        MsubCase {
            initial_lo: 0x37ec76ea,
            initial_hi: 0x0e043668,
            lhs: 0x559ca251,
            rhs: 0x6fbcdb0b,
            expected_lo: 0x38da326f,
            expected_hi: 0xe8a623bf,
        },
        MsubCase {
            initial_lo: 0x4d923ad9,
            initial_hi: 0x683cff69,
            lhs: 0x0951d141,
            rhs: 0x01a35299,
            expected_lo: 0x09425900,
            expected_hi: 0x682dbb7e,
        },
        MsubCase {
            initial_lo: 0x3b647945,
            initial_hi: 0x6847824b,
            lhs: 0x3d7013de,
            rhs: 0x4d93f3e4,
            expected_lo: 0xf23d0d8d,
            expected_hi: 0x55a94a6d,
        },
        MsubCase {
            initial_lo: 0x7b12f87a,
            initial_hi: 0x29806ea5,
            lhs: 0x69006754,
            rhs: 0x0c49a091,
            expected_lo: 0x5a4ff1e6,
            expected_hi: 0x247636d4,
        },
        MsubCase {
            initial_lo: 0x11c775c0,
            initial_hi: 0x458d5fa6,
            lhs: 0x69d32b3f,
            rhs: 0x1f3849d1,
            expected_lo: 0x5e443051,
            expected_hi: 0x38a588b4,
        },
        MsubCase {
            initial_lo: 0x612f23a1,
            initial_hi: 0x57f24d0a,
            lhs: 0x247c0390,
            rhs: 0x12de921a,
            expected_lo: 0xbbaea701,
            expected_hi: 0x5541dc6c,
        },
        MsubCase {
            initial_lo: 0x49f30e58,
            initial_hi: 0x6cb87b7b,
            lhs: 0x3dd17708,
            rhs: 0x4678cb1e,
            expected_lo: 0xf643c368,
            expected_hi: 0x5bb409b2,
        },
        MsubCase {
            initial_lo: 0x06b0617b,
            initial_hi: 0x3657d268,
            lhs: 0x201815dc,
            rhs: 0x54429c54,
            expected_lo: 0xfebf254b,
            expected_hi: 0x2bc7916c,
        },
    ];

    for (i, case) in cases.into_iter().enumerate() {
        let mut runtime = Executor::new(msub_program(case), ZKMCoreOpts::default());
        runtime.run_very_fast().unwrap();

        assert_eq!(runtime.register(Register::T0), case.lhs, "case {i}: MSUB should preserve lhs");
        assert_eq!(runtime.register(Register::T1), case.rhs, "case {i}: MSUB should preserve rhs");
        assert_eq!(runtime.register(Register::LO), case.expected_lo, "case {i}: MSUB LO mismatch");
        assert_eq!(runtime.register(Register::HI), case.expected_hi, "case {i}: MSUB HI mismatch");
    }
}

use zkm_core_executor::{Executor, Instruction, Opcode, Program, Register};
use zkm_stark::ZKMCoreOpts;

#[derive(Clone, Copy, Debug)]
struct MadduCase {
    initial_lo: u32,
    initial_hi: u32,
    lhs: u32,
    rhs: u32,
    expected_lo: u32,
    expected_hi: u32,
}

/// Build the smallest program that isolates `MADDU`.
fn maddu_program(case: MadduCase) -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, Register::LO as u8, 0, case.initial_lo, false, true),
        Instruction::new(Opcode::ADD, Register::HI as u8, 0, case.initial_hi, false, true),
        Instruction::new(Opcode::ADD, Register::T0 as u8, 0, case.lhs, false, true),
        Instruction::new(Opcode::ADD, Register::T1 as u8, 0, case.rhs, false, true),
        Instruction::new(
            Opcode::MADDU,
            Register::LO as u8,
            Register::T0 as u32,
            Register::T1 as u32,
            false,
            false,
        ),
    ];
    Program::new(instructions, 0, 0)
}

/// Representative regression vectors copied from `mipstest/insttest/src/n68_maddu.S`.
#[test]
fn n68_maddu_vectors() {
    let cases = [
        MadduCase {
            initial_lo: 0x73b1491b,
            initial_hi: 0x71ff0918,
            lhs: 0x65425edb,
            rhs: 0x0c9bf6de,
            expected_lo: 0xbcfefd05,
            expected_hi: 0x76fbd65f,
        },
        MadduCase {
            initial_lo: 0x2047112c,
            initial_hi: 0x7ee80821,
            lhs: 0x0731ad0f,
            rhs: 0x5335e6d8,
            expected_lo: 0x84c78fd4,
            expected_hi: 0x813ea702,
        },
        MadduCase {
            initial_lo: 0x2a5d13d9,
            initial_hi: 0x7ffa28d0,
            lhs: 0x3009e9be,
            rhs: 0x1e8c94cc,
            expected_lo: 0x454d2f41,
            expected_hi: 0x85b5b38c,
        },
        MadduCase {
            initial_lo: 0x11090066,
            initial_hi: 0x48b27be5,
            lhs: 0x1d78e4f7,
            rhs: 0x3439632e,
            expected_lo: 0x444ca9c8,
            expected_hi: 0x4eb5a5bd,
        },
        MadduCase {
            initial_lo: 0x5e24ba18,
            initial_hi: 0x77f430c8,
            lhs: 0x3f6f7613,
            rhs: 0x40ed4951,
            expected_lo: 0x48ab811b,
            expected_hi: 0x880adaa8,
        },
        MadduCase {
            initial_lo: 0x72b428cd,
            initial_hi: 0x0cc53f61,
            lhs: 0x43e8ddd9,
            rhs: 0x010acbba,
            expected_lo: 0xf54a6b77,
            expected_hi: 0x0d0c0562,
        },
        MadduCase {
            initial_lo: 0x35b7d2af,
            initial_hi: 0x1420501e,
            lhs: 0x285e7267,
            rhs: 0x47e0c1cf,
            expected_lo: 0xb975faf8,
            expected_hi: 0x1f75f30c,
        },
        MadduCase {
            initial_lo: 0x7412502a,
            initial_hi: 0x64ee20b8,
            lhs: 0x291fc80c,
            rhs: 0x67c39946,
            expected_lo: 0xe6762f72,
            expected_hi: 0x75995609,
        },
        MadduCase {
            initial_lo: 0x56ed29d0,
            initial_hi: 0x0e6226e7,
            lhs: 0x745f9024,
            rhs: 0x77343afc,
            expected_lo: 0x8ef73540,
            expected_hi: 0x44925121,
        },
    ];

    for (i, case) in cases.into_iter().enumerate() {
        let mut runtime = Executor::new(maddu_program(case), ZKMCoreOpts::default());
        runtime.run_very_fast().unwrap();

        assert_eq!(runtime.register(Register::T0), case.lhs, "case {i}: MADDU should preserve lhs");
        assert_eq!(runtime.register(Register::T1), case.rhs, "case {i}: MADDU should preserve rhs");
        assert_eq!(runtime.register(Register::LO), case.expected_lo, "case {i}: MADDU LO mismatch");
        assert_eq!(runtime.register(Register::HI), case.expected_hi, "case {i}: MADDU HI mismatch");
    }
}

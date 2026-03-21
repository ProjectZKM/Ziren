use zkm_core_executor::{Executor, Instruction, Opcode, Program, Register};
use zkm_stark::ZKMCoreOpts;

#[derive(Clone, Copy, Debug)]
struct MsubuCase {
    initial_lo: u32,
    initial_hi: u32,
    lhs: u32,
    rhs: u32,
    expected_lo: u32,
    expected_hi: u32,
}

/// Build the smallest program that isolates `MSUBU`.
fn msubu_program(case: MsubuCase) -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, Register::LO as u8, 0, case.initial_lo, false, true),
        Instruction::new(Opcode::ADD, Register::HI as u8, 0, case.initial_hi, false, true),
        Instruction::new(Opcode::ADD, Register::T0 as u8, 0, case.lhs, false, true),
        Instruction::new(Opcode::ADD, Register::T1 as u8, 0, case.rhs, false, true),
        Instruction::new(
            Opcode::MSUBU,
            Register::LO as u8,
            Register::T0 as u32,
            Register::T1 as u32,
            false,
            false,
        ),
    ];
    Program::new(instructions, 0, 0)
}

/// Representative regression vectors copied from `mipstest/insttest/src/n70_msubu.S`.
#[test]
fn n70_msubu_vectors() {
    let cases = [
        MsubuCase {
            initial_lo: 0x5452d6af,
            initial_hi: 0x5fbebdd0,
            lhs: 0x5d9c545a,
            rhs: 0x0ae10bc7,
            expected_lo: 0x311366b9,
            expected_hi: 0x5bc457d0,
        },
        MsubuCase {
            initial_lo: 0x3ea8ed79,
            initial_hi: 0x29b2c6ac,
            lhs: 0x56d5d6f5,
            rhs: 0x6b83cfa7,
            expected_lo: 0x49fa98a6,
            expected_hi: 0x053aaff7,
        },
        MsubuCase {
            initial_lo: 0x2e90e5a0,
            initial_hi: 0x29382232,
            lhs: 0x6ca4314e,
            rhs: 0x45b923e9,
            expected_lo: 0x33045ba2,
            expected_hi: 0x0ba14f03,
        },
        MsubuCase {
            initial_lo: 0x2cdae22d,
            initial_hi: 0x58f3bbfa,
            lhs: 0x66d5ac3d,
            rhs: 0x4e233c0e,
            expected_lo: 0x56762ad7,
            expected_hi: 0x39907a29,
        },
        MsubuCase {
            initial_lo: 0x0dc8bbc4,
            initial_hi: 0x0b1895d5,
            lhs: 0x047970cf,
            rhs: 0x5cdf31c2,
            expected_lo: 0xc2d89fe6,
            expected_hi: 0x09790aa2,
        },
        MsubuCase {
            initial_lo: 0x4ead2a6b,
            initial_hi: 0x0c2622be,
            lhs: 0x1ef74e6e,
            rhs: 0x30a2ddf2,
            expected_lo: 0x4894106f,
            expected_hi: 0x064410b1,
        },
        MsubuCase {
            initial_lo: 0x4cc6b886,
            initial_hi: 0x7239aacc,
            lhs: 0x5d3e9a76,
            rhs: 0x2e76e485,
            expected_lo: 0xb34b6138,
            expected_hi: 0x614d1cf3,
        },
        MsubuCase {
            initial_lo: 0x4939b078,
            initial_hi: 0x3ee1b043,
            lhs: 0x75922c69,
            rhs: 0x66ab20a0,
            expected_lo: 0x082dced8,
            expected_hi: 0x0fbadaf2,
        },
        MsubuCase {
            initial_lo: 0x5ddab2e7,
            initial_hi: 0x02cd0f9c,
            lhs: 0x37d476ed,
            rhs: 0x322d8997,
            expected_lo: 0x8a3ab81c,
            expected_hi: 0xf7dba207,
        },
    ];

    for (i, case) in cases.into_iter().enumerate() {
        let mut runtime = Executor::new(msubu_program(case), ZKMCoreOpts::default());
        runtime.run_very_fast().unwrap();

        assert_eq!(runtime.register(Register::T0), case.lhs, "case {i}: MSUBU should preserve lhs");
        assert_eq!(runtime.register(Register::T1), case.rhs, "case {i}: MSUBU should preserve rhs");
        assert_eq!(runtime.register(Register::LO), case.expected_lo, "case {i}: MSUBU LO mismatch");
        assert_eq!(runtime.register(Register::HI), case.expected_hi, "case {i}: MSUBU HI mismatch");
    }
}

use zkm_core_executor::{Executor, Instruction, Opcode, Program, Register};
use zkm_stark::ZKMCoreOpts;

#[derive(Clone, Copy, Debug)]
struct SebCase {
    input: u32,
    expected: u32,
}

/// Build the smallest program that isolates `SEB`.
fn seb_program(input: u32) -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, Register::T0 as u8, 0, input, false, true),
        Instruction::new(Opcode::SEXT, Register::T1 as u8, Register::T0 as u32, 0, false, true),
    ];
    Program::new(instructions, 0, 0)
}

/// Regression vectors copied from `mipstest/insttest/src/n71_seb.S`.
///
/// These cover both sign-producing and non-sign-producing low-byte cases, including values where
/// the upper 24 bits are already non-zero and should be discarded before extension.
#[test]
fn n71_seb_vectors() {
    let cases = [
        SebCase { input: 0x4e5885b6, expected: 0xffffffb6 },
        SebCase { input: 0x3296a156, expected: 0x00000056 },
        SebCase { input: 0x473412a6, expected: 0xffffffa6 },
        SebCase { input: 0x70aa193f, expected: 0x0000003f },
        SebCase { input: 0x000000b5, expected: 0xffffffb5 },
        SebCase { input: 0x0000000d, expected: 0x0000000d },
        SebCase { input: 0x00000092, expected: 0xffffff92 },
        SebCase { input: 0x000000ec, expected: 0xffffffec },
        SebCase { input: 0x00008907, expected: 0x00000007 },
        SebCase { input: 0x00002e75, expected: 0x00000075 },
        SebCase { input: 0x000025a7, expected: 0xffffffa7 },
        SebCase { input: 0x000039b5, expected: 0xffffffb5 },
    ];

    for (i, case) in cases.into_iter().enumerate() {
        let mut runtime = Executor::new(seb_program(case.input), ZKMCoreOpts::default());
        runtime.run_very_fast().unwrap();

        assert_eq!(
            runtime.register(Register::T0),
            case.input,
            "case {i}: SEB should preserve the source"
        );
        assert_eq!(
            runtime.register(Register::T1),
            case.expected,
            "case {i}: SEB({:#010x})",
            case.input
        );
    }
}

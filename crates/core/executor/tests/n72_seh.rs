use zkm_core_executor::{Executor, Instruction, Opcode, Program, Register};
use zkm_stark::ZKMCoreOpts;

#[derive(Clone, Copy, Debug)]
struct SehCase {
    input: u32,
    expected: u32,
}

/// Build the smallest program that isolates `SEH`.
fn seh_program(input: u32) -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, Register::T0 as u8, 0, input, false, true),
        Instruction::new(Opcode::SEXT, Register::T1 as u8, Register::T0 as u32, 1, false, true),
    ];
    Program::new(instructions, 0, 0)
}

/// Regression vectors copied from `mipstest/insttest/src/n72_seh.S`.
///
/// These exercise 16-bit sign extension around the `0x8000` boundary and ensure the high half of
/// the source word is ignored.
#[test]
fn n72_seh_vectors() {
    let cases = [
        SehCase { input: 0x75ce8687, expected: 0xffff8687 },
        SehCase { input: 0x4367c83e, expected: 0xffffc83e },
        SehCase { input: 0x7b268d2a, expected: 0xffff8d2a },
        SehCase { input: 0x15044d0d, expected: 0x00004d0d },
        SehCase { input: 0x00000055, expected: 0x00000055 },
        SehCase { input: 0x00000088, expected: 0x00000088 },
        SehCase { input: 0x000000dc, expected: 0x000000dc },
        SehCase { input: 0x00000009, expected: 0x00000009 },
        SehCase { input: 0x0000d199, expected: 0xffffd199 },
        SehCase { input: 0x0000d033, expected: 0xffffd033 },
        SehCase { input: 0x00006b13, expected: 0x00006b13 },
        SehCase { input: 0x00006670, expected: 0x00006670 },
        SehCase { input: 0x00f2020c, expected: 0x0000020c },
        SehCase { input: 0x00fbabd6, expected: 0xffffabd6 },
        SehCase { input: 0x00f0eeab, expected: 0xffffeeab },
        SehCase { input: 0x00f9f413, expected: 0xfffff413 },
    ];

    for (i, case) in cases.into_iter().enumerate() {
        let mut runtime = Executor::new(seh_program(case.input), ZKMCoreOpts::default());
        runtime.run_very_fast().unwrap();

        assert_eq!(
            runtime.register(Register::T0),
            case.input,
            "case {i}: SEH should preserve the source"
        );
        assert_eq!(
            runtime.register(Register::T1),
            case.expected,
            "case {i}: SEH({:#010x})",
            case.input
        );
    }
}

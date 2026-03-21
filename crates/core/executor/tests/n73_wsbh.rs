use zkm_core_executor::{Executor, Instruction, Opcode, Program, Register};
use zkm_stark::ZKMCoreOpts;

#[derive(Clone, Copy, Debug)]
struct WsbhCase {
    input: u32,
    expected: u32,
}

/// Build the smallest program that isolates `WSBH`.
fn wsbh_program(input: u32) -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, Register::T0 as u8, 0, input, false, true),
        Instruction::new(Opcode::WSBH, Register::T1 as u8, Register::T0 as u32, 0, false, true),
    ];
    Program::new(instructions, 0, 0)
}

/// Regression vectors copied from `mipstest/insttest/src/n73_wsbh.S`.
///
/// This checks the byte swap within each 16-bit halfword without crossing the halfword boundary.
#[test]
fn n73_wsbh_vectors() {
    let cases = [
        WsbhCase { input: 0x287b78ef, expected: 0x7b28ef78 },
        WsbhCase { input: 0x181e0b04, expected: 0x1e18040b },
        WsbhCase { input: 0x79025ad8, expected: 0x0279d85a },
        WsbhCase { input: 0x503c59fc, expected: 0x3c50fc59 },
    ];

    for (i, case) in cases.into_iter().enumerate() {
        let mut runtime = Executor::new(wsbh_program(case.input), ZKMCoreOpts::default());
        runtime.run_very_fast().unwrap();

        assert_eq!(
            runtime.register(Register::T0),
            case.input,
            "case {i}: WSBH should preserve the source"
        );
        assert_eq!(
            runtime.register(Register::T1),
            case.expected,
            "case {i}: WSBH({:#010x})",
            case.input
        );
    }
}

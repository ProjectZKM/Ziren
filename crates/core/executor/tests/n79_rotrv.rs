use zkm_core_executor::{Executor, Instruction, Opcode, Program, Register};
use zkm_stark::ZKMCoreOpts;

#[derive(Clone, Copy, Debug)]
struct RotrvCase {
    input: u32,
    shift: u32,
    expected: u32,
}

/// Build the smallest program that isolates `ROTRV`.
fn rotrv_program(case: RotrvCase) -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, Register::T0 as u8, 0, case.input, false, true),
        Instruction::new(Opcode::ADD, Register::T2 as u8, 0, case.shift, false, true),
        Instruction::new(
            Opcode::ROR,
            Register::T1 as u8,
            Register::T0 as u32,
            Register::T2 as u32,
            false,
            false,
        ),
    ];
    Program::new(instructions, 0, 0)
}

/// Regression vectors copied from `mipstest/insttest/src/n79_rotrv.S`.
///
/// This mirrors the immediate rotate coverage but routes the shift through a register to ensure
/// the variable-shift path matches `ROTR`.
#[test]
fn n79_rotrv_vectors() {
    let cases = [
        RotrvCase { input: 0x33a75dcb, shift: 0, expected: 0x33a75dcb },
        RotrvCase { input: 0x3c5c2ff1, shift: 0, expected: 0x3c5c2ff1 },
        RotrvCase { input: 0x54a5ce58, shift: 1, expected: 0x2a52e72c },
        RotrvCase { input: 0x4329f007, shift: 1, expected: 0xa194f803 },
        RotrvCase { input: 0x07dff7b7, shift: 2, expected: 0xc1f7fded },
        RotrvCase { input: 0x37db4cf8, shift: 2, expected: 0x0df6d33e },
        RotrvCase { input: 0x5356a41d, shift: 3, expected: 0xaa6ad483 },
        RotrvCase { input: 0x032447bc, shift: 3, expected: 0x806488f7 },
        RotrvCase { input: 0x44ed49f9, shift: 4, expected: 0x944ed49f },
        RotrvCase { input: 0x4b32841c, shift: 4, expected: 0xc4b32841 },
        RotrvCase { input: 0x7de97573, shift: 5, expected: 0x9bef4bab },
        RotrvCase { input: 0x4b1429b4, shift: 5, expected: 0xa258a14d },
        RotrvCase { input: 0x43743c2a, shift: 6, expected: 0xa90dd0f0 },
        RotrvCase { input: 0x41b41f5b, shift: 6, expected: 0x6d06d07d },
        RotrvCase { input: 0x52c1fb95, shift: 7, expected: 0x2aa583f7 },
        RotrvCase { input: 0x4cd32714, shift: 7, expected: 0x2899a64e },
        RotrvCase { input: 0x605e7f06, shift: 8, expected: 0x06605e7f },
        RotrvCase { input: 0x4563a4de, shift: 8, expected: 0xde4563a4 },
        RotrvCase { input: 0x66ea1db9, shift: 9, expected: 0xdcb3750e },
        RotrvCase { input: 0x10a04d73, shift: 9, expected: 0xb9885026 },
        RotrvCase { input: 0x66845254, shift: 10, expected: 0x9519a114 },
        RotrvCase { input: 0x5b125631, shift: 10, expected: 0x8c56c495 },
        RotrvCase { input: 0x73e5eef9, shift: 11, expected: 0xdf2e7cbd },
        RotrvCase { input: 0x207fb6b3, shift: 11, expected: 0xd6640ff6 },
        RotrvCase { input: 0x2f5c03d0, shift: 12, expected: 0x3d02f5c0 },
        RotrvCase { input: 0x68d5d654, shift: 12, expected: 0x65468d5d },
        RotrvCase { input: 0x2acaa7ed, shift: 13, expected: 0x3f695655 },
        RotrvCase { input: 0x75240b5c, shift: 13, expected: 0x5ae3a920 },
        RotrvCase { input: 0x0330c357, shift: 14, expected: 0x0d5c0cc3 },
        RotrvCase { input: 0x72c3a048, shift: 14, expected: 0x8121cb0e },
        RotrvCase { input: 0x5a35436f, shift: 15, expected: 0x86deb46a },
        RotrvCase { input: 0x36d82123, shift: 15, expected: 0x42466db0 },
        RotrvCase { input: 0x2f1fd039, shift: 16, expected: 0xd0392f1f },
        RotrvCase { input: 0x2edb11c7, shift: 16, expected: 0x11c72edb },
        RotrvCase { input: 0x7a02112a, shift: 17, expected: 0x08953d01 },
        RotrvCase { input: 0x36ffc7f1, shift: 17, expected: 0xe3f89b7f },
        RotrvCase { input: 0x66b65ebf, shift: 18, expected: 0x97afd9ad },
        RotrvCase { input: 0x4d58b547, shift: 18, expected: 0x2d51d356 },
        RotrvCase { input: 0x3a240fad, shift: 19, expected: 0x81f5a744 },
        RotrvCase { input: 0x2ba3a8b9, shift: 19, expected: 0x75172574 },
        RotrvCase { input: 0x188b3964, shift: 20, expected: 0xb3964188 },
        RotrvCase { input: 0x380d8520, shift: 20, expected: 0xd8520380 },
        RotrvCase { input: 0x76b7d26d, shift: 21, expected: 0xbe936bb5 },
        RotrvCase { input: 0x5bff758e, shift: 21, expected: 0xfbac72df },
        RotrvCase { input: 0x79c1a47c, shift: 22, expected: 0x0691f1e7 },
        RotrvCase { input: 0x4979ce02, shift: 22, expected: 0xe7380925 },
        RotrvCase { input: 0x28d29ca2, shift: 23, expected: 0xa5394451 },
        RotrvCase { input: 0x5a202382, shift: 23, expected: 0x404704b4 },
        RotrvCase { input: 0x0edd72e0, shift: 24, expected: 0xdd72e00e },
        RotrvCase { input: 0x0fbcba5c, shift: 24, expected: 0xbcba5c0f },
        RotrvCase { input: 0x6ac070f6, shift: 25, expected: 0x60387b35 },
        RotrvCase { input: 0x7561c535, shift: 25, expected: 0xb0e29aba },
        RotrvCase { input: 0x6acf108d, shift: 26, expected: 0xb3c4235a },
        RotrvCase { input: 0x5ea65fef, shift: 26, expected: 0xa997fbd7 },
        RotrvCase { input: 0x15e17be8, shift: 27, expected: 0xbc2f7d02 },
        RotrvCase { input: 0x1a2b145d, shift: 27, expected: 0x45628ba3 },
        RotrvCase { input: 0x477c3643, shift: 28, expected: 0x77c36434 },
        RotrvCase { input: 0x40ac23d5, shift: 28, expected: 0x0ac23d54 },
        RotrvCase { input: 0x0f4f1fb9, shift: 29, expected: 0x7a78fdc8 },
        RotrvCase { input: 0x4aacf99b, shift: 29, expected: 0x5567ccda },
        RotrvCase { input: 0x336fc41d, shift: 30, expected: 0xcdbf1074 },
        RotrvCase { input: 0x69846329, shift: 30, expected: 0xa6118ca5 },
        RotrvCase { input: 0x01851abe, shift: 31, expected: 0x030a357c },
        RotrvCase { input: 0x628f9457, shift: 31, expected: 0xc51f28ae },
    ];

    for (i, case) in cases.into_iter().enumerate() {
        let mut runtime = Executor::new(rotrv_program(case), ZKMCoreOpts::default());
        runtime.run_very_fast().unwrap();

        assert_eq!(
            runtime.register(Register::T0),
            case.input,
            "case {i}: ROTRV should preserve the source"
        );
        assert_eq!(
            runtime.register(Register::T2),
            case.shift,
            "case {i}: ROTRV should preserve the shift register"
        );
        assert_eq!(
            runtime.register(Register::T1),
            case.expected,
            "case {i}: ROTRV({:#010x}, shift={})",
            case.input,
            case.shift,
        );
    }
}

use zkm_core_executor::{Executor, Instruction, Opcode, Program, Register};
use zkm_stark::ZKMCoreOpts;

#[derive(Clone, Copy, Debug)]
struct RotrCase {
    input: u32,
    shift: u32,
    expected: u32,
}

/// Build the smallest program that isolates `ROTR`.
fn rotr_program(case: RotrCase) -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, Register::T0 as u8, 0, case.input, false, true),
        Instruction::new(
            Opcode::ROR,
            Register::T1 as u8,
            Register::T0 as u32,
            case.shift,
            false,
            true,
        ),
    ];
    Program::new(instructions, 0, 0)
}

/// Regression vectors copied from `mipstest/insttest/src/n78_rotr.S`.
///
/// The vector list spans every shift count from 0 through 31 so both trivial and wraparound
/// rotations are covered.
#[test]
fn n78_rotr_vectors() {
    let cases = [
        RotrCase { input: 0x2078b9d6, shift: 0, expected: 0x2078b9d6 },
        RotrCase { input: 0x0bfb8d73, shift: 0, expected: 0x0bfb8d73 },
        RotrCase { input: 0x661ec910, shift: 1, expected: 0x330f6488 },
        RotrCase { input: 0x10de566c, shift: 1, expected: 0x086f2b36 },
        RotrCase { input: 0x391c83eb, shift: 2, expected: 0xce4720fa },
        RotrCase { input: 0x3312df8c, shift: 2, expected: 0x0cc4b7e3 },
        RotrCase { input: 0x6be66e9b, shift: 3, expected: 0x6d7ccdd3 },
        RotrCase { input: 0x0df7044a, shift: 3, expected: 0x41bee089 },
        RotrCase { input: 0x007bf5cd, shift: 4, expected: 0xd007bf5c },
        RotrCase { input: 0x4a859311, shift: 4, expected: 0x14a85931 },
        RotrCase { input: 0x3509f9b7, shift: 5, expected: 0xb9a84fcd },
        RotrCase { input: 0x42c0917d, shift: 5, expected: 0xea16048b },
        RotrCase { input: 0x6b3e5537, shift: 6, expected: 0xddacf954 },
        RotrCase { input: 0x390c05ed, shift: 6, expected: 0xb4e43017 },
        RotrCase { input: 0x101e326d, shift: 7, expected: 0xda203c64 },
        RotrCase { input: 0x3bc62435, shift: 7, expected: 0x6a778c48 },
        RotrCase { input: 0x42d2be62, shift: 8, expected: 0x6242d2be },
        RotrCase { input: 0x772e472e, shift: 8, expected: 0x2e772e47 },
        RotrCase { input: 0x311a8803, shift: 9, expected: 0x01988d44 },
        RotrCase { input: 0x47db0f7e, shift: 9, expected: 0xbf23ed87 },
        RotrCase { input: 0x01185a81, shift: 10, expected: 0xa0404616 },
        RotrCase { input: 0x5e1bf15f, shift: 10, expected: 0x57d786fc },
        RotrCase { input: 0x75173ab4, shift: 11, expected: 0x568ea2e7 },
        RotrCase { input: 0x2a49560d, shift: 11, expected: 0xc1a5492a },
        RotrCase { input: 0x652c8ed5, shift: 12, expected: 0xed5652c8 },
        RotrCase { input: 0x4144d2e2, shift: 12, expected: 0x2e24144d },
        RotrCase { input: 0x767bd46a, shift: 13, expected: 0xa353b3de },
        RotrCase { input: 0x2b857aba, shift: 13, expected: 0xd5d15c2b },
        RotrCase { input: 0x43cca916, shift: 14, expected: 0xa4590f32 },
        RotrCase { input: 0x6bc1dfca, shift: 14, expected: 0x7f29af07 },
        RotrCase { input: 0x27cebaf6, shift: 15, expected: 0x75ec4f9d },
        RotrCase { input: 0x644562ed, shift: 15, expected: 0xc5dac88a },
        RotrCase { input: 0x77bd6d3d, shift: 16, expected: 0x6d3d77bd },
        RotrCase { input: 0x0ded8406, shift: 16, expected: 0x84060ded },
        RotrCase { input: 0x7523b959, shift: 17, expected: 0xdcacba91 },
        RotrCase { input: 0x30d9f128, shift: 17, expected: 0xf894186c },
        RotrCase { input: 0x41006392, shift: 18, expected: 0x18e49040 },
        RotrCase { input: 0x610a27f4, shift: 18, expected: 0x89fd1842 },
        RotrCase { input: 0x3ed0f572, shift: 19, expected: 0x1eae47da },
        RotrCase { input: 0x417c595f, shift: 19, expected: 0x8b2be82f },
        RotrCase { input: 0x2b8fbb06, shift: 20, expected: 0xfbb062b8 },
        RotrCase { input: 0x73daef2a, shift: 20, expected: 0xaef2a73d },
        RotrCase { input: 0x043ceadc, shift: 21, expected: 0xe756e021 },
        RotrCase { input: 0x16ce103d, shift: 21, expected: 0x7081e8b6 },
        RotrCase { input: 0x2ce6f517, shift: 22, expected: 0x9bd45cb3 },
        RotrCase { input: 0x145b1d49, shift: 22, expected: 0x6c752451 },
        RotrCase { input: 0x52943472, shift: 23, expected: 0x2868e4a5 },
        RotrCase { input: 0x6fb9b37a, shift: 23, expected: 0x7366f4df },
        RotrCase { input: 0x0b896477, shift: 24, expected: 0x8964770b },
        RotrCase { input: 0x03aebc75, shift: 24, expected: 0xaebc7503 },
        RotrCase { input: 0x3794c2f8, shift: 25, expected: 0xca617c1b },
        RotrCase { input: 0x0ca1bef8, shift: 25, expected: 0x50df7c06 },
        RotrCase { input: 0x61caadd5, shift: 26, expected: 0x72ab7558 },
        RotrCase { input: 0x2cabfdac, shift: 26, expected: 0x2aff6b0b },
        RotrCase { input: 0x36eb1505, shift: 27, expected: 0xdd62a0a6 },
        RotrCase { input: 0x46f73caa, shift: 27, expected: 0xdee79548 },
        RotrCase { input: 0x6df0d08e, shift: 28, expected: 0xdf0d08e6 },
        RotrCase { input: 0x2d66e970, shift: 28, expected: 0xd66e9702 },
        RotrCase { input: 0x727cb764, shift: 29, expected: 0x93e5bb23 },
        RotrCase { input: 0x31bd79a5, shift: 29, expected: 0x8debcd29 },
        RotrCase { input: 0x1928c93a, shift: 30, expected: 0x64a324e8 },
        RotrCase { input: 0x1a4b725a, shift: 30, expected: 0x692dc968 },
        RotrCase { input: 0x1602dc92, shift: 31, expected: 0x2c05b924 },
        RotrCase { input: 0x10e63677, shift: 31, expected: 0x21cc6cee },
    ];

    for (i, case) in cases.into_iter().enumerate() {
        let mut runtime = Executor::new(rotr_program(case), ZKMCoreOpts::default());
        runtime.run_very_fast().unwrap();

        assert_eq!(
            runtime.register(Register::T0),
            case.input,
            "case {i}: ROTR should preserve the source"
        );
        assert_eq!(
            runtime.register(Register::T1),
            case.expected,
            "case {i}: ROTR({:#010x}, shift={})",
            case.input,
            case.shift,
        );
    }
}

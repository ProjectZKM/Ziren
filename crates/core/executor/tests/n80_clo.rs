use zkm_core_executor::{Executor, Instruction, Opcode, Program, Register};
use zkm_stark::ZKMCoreOpts;

#[derive(Clone, Copy, Debug)]
struct CloCase {
    input: u32,
    expected: u32,
}

/// Build the smallest program that isolates `CLO`.
fn clo_program(input: u32) -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, Register::T0 as u8, 0, input, false, true),
        Instruction::new(Opcode::CLO, Register::T1 as u8, Register::T0 as u32, 0, false, true),
    ];
    Program::new(instructions, 0, 0)
}

/// Regression vectors copied from `mipstest/insttest/src/n80_clo.S`.
///
/// These cover the full range from `32` leading ones down to zero, including alternating edge
/// patterns near the sign bit and values with exactly one leading one.
#[test]
fn n80_clo_vectors() {
    let cases = [
        CloCase { input: 0xffffffff, expected: 0x00000020 },
        CloCase { input: 0x6df76b1b, expected: 0x00000000 },
        CloCase { input: 0xffffffff, expected: 0x00000020 },
        CloCase { input: 0x71d4858c, expected: 0x00000000 },
        CloCase { input: 0xfffffffd, expected: 0x0000001e },
        CloCase { input: 0x2d3733cc, expected: 0x00000000 },
        CloCase { input: 0xfffffffb, expected: 0x0000001d },
        CloCase { input: 0x44095238, expected: 0x00000000 },
        CloCase { input: 0xfffffff9, expected: 0x0000001d },
        CloCase { input: 0x7a00d5f0, expected: 0x00000000 },
        CloCase { input: 0xfffffffa, expected: 0x0000001d },
        CloCase { input: 0x6284ff80, expected: 0x00000000 },
        CloCase { input: 0xfffffff5, expected: 0x0000001c },
        CloCase { input: 0x23980b80, expected: 0x00000000 },
        CloCase { input: 0xffffffea, expected: 0x0000001b },
        CloCase { input: 0x75f36c00, expected: 0x00000000 },
        CloCase { input: 0xfffffffe, expected: 0x0000001f },
        CloCase { input: 0x03a00600, expected: 0x00000000 },
        CloCase { input: 0xfffffef1, expected: 0x00000017 },
        CloCase { input: 0x61fa8600, expected: 0x00000000 },
        CloCase { input: 0xfffffeec, expected: 0x00000017 },
        CloCase { input: 0x27752000, expected: 0x00000000 },
        CloCase { input: 0xfffffbb9, expected: 0x00000015 },
        CloCase { input: 0x40ff0000, expected: 0x00000000 },
        CloCase { input: 0xfffff29f, expected: 0x00000014 },
        CloCase { input: 0x770d5000, expected: 0x00000000 },
        CloCase { input: 0xffffebff, expected: 0x00000013 },
        CloCase { input: 0x70cee000, expected: 0x00000000 },
        CloCase { input: 0xffffff47, expected: 0x00000018 },
        CloCase { input: 0x43288000, expected: 0x00000000 },
        CloCase { input: 0xffffb591, expected: 0x00000011 },
        CloCase { input: 0x7c5c0000, expected: 0x00000000 },
        CloCase { input: 0xfffff10c, expected: 0x00000014 },
        CloCase { input: 0x5dce0000, expected: 0x00000000 },
        CloCase { input: 0xffff26db, expected: 0x00000010 },
        CloCase { input: 0x723c0000, expected: 0x00000000 },
        CloCase { input: 0xfffde7a6, expected: 0x0000000e },
        CloCase { input: 0x4f540000, expected: 0x00000000 },
        CloCase { input: 0xfff9faa9, expected: 0x0000000d },
        CloCase { input: 0x73680000, expected: 0x00000000 },
        CloCase { input: 0xfff8cb18, expected: 0x0000000d },
        CloCase { input: 0x24c00000, expected: 0x00000000 },
        CloCase { input: 0xfff1b378, expected: 0x0000000c },
        CloCase { input: 0x64a00000, expected: 0x00000000 },
        CloCase { input: 0xffe02dbd, expected: 0x0000000b },
        CloCase { input: 0x40400000, expected: 0x00000000 },
        CloCase { input: 0xffd35955, expected: 0x0000000a },
        CloCase { input: 0x5d800000, expected: 0x00000000 },
        CloCase { input: 0xff0afc07, expected: 0x00000008 },
        CloCase { input: 0x37000000, expected: 0x00000000 },
        CloCase { input: 0xfe27acf8, expected: 0x00000007 },
        CloCase { input: 0x00000000, expected: 0x00000000 },
        CloCase { input: 0xfd3cbc16, expected: 0x00000006 },
        CloCase { input: 0x38000000, expected: 0x00000000 },
        CloCase { input: 0xfd2b72b9, expected: 0x00000006 },
        CloCase { input: 0x30000000, expected: 0x00000000 },
        CloCase { input: 0xffb69594, expected: 0x00000009 },
        CloCase { input: 0x30000000, expected: 0x00000000 },
        CloCase { input: 0xfeaacc5c, expected: 0x00000007 },
        CloCase { input: 0x20000000, expected: 0x00000000 },
        CloCase { input: 0xfeb9bae1, expected: 0x00000007 },
        CloCase { input: 0x40000000, expected: 0x00000000 },
        CloCase { input: 0xda2bc144, expected: 0x00000002 },
        CloCase { input: 0x00000000, expected: 0x00000000 },
    ];

    for (i, case) in cases.into_iter().enumerate() {
        let mut runtime = Executor::new(clo_program(case.input), ZKMCoreOpts::default());
        runtime.run_very_fast().unwrap();

        assert_eq!(
            runtime.register(Register::T0),
            case.input,
            "case {i}: CLO should preserve the source"
        );
        assert_eq!(
            runtime.register(Register::T1),
            case.expected,
            "case {i}: CLO({:#010x})",
            case.input
        );
    }
}

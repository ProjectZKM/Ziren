use zkm_core_executor::{Executor, Instruction, Opcode, Program, Register};
use zkm_stark::ZKMCoreOpts;

#[derive(Clone, Copy, Debug)]
struct ClzCase {
    input: u32,
    expected: u32,
}

/// Build the smallest program that isolates `CLZ`.
fn clz_program(input: u32) -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, Register::T0 as u8, 0, input, false, true),
        Instruction::new(Opcode::CLZ, Register::T1 as u8, Register::T0 as u32, 0, false, true),
    ];
    Program::new(instructions, 0, 0)
}

/// Regression vectors copied from `mipstest/insttest/src/n81_clz.S`.
///
/// These cover the full range from `32` leading zeros down to zero, including powers of two,
/// dense mid-word values, and a final top-bit-set case.
#[test]
fn n81_clz_vectors() {
    let cases = [
        ClzCase { input: 0x00000000, expected: 0x00000020 },
        ClzCase { input: 0x00000000, expected: 0x00000020 },
        ClzCase { input: 0x00000000, expected: 0x00000020 },
        ClzCase { input: 0x00000000, expected: 0x00000020 },
        ClzCase { input: 0x00000001, expected: 0x0000001f },
        ClzCase { input: 0x00000000, expected: 0x00000020 },
        ClzCase { input: 0x00000003, expected: 0x0000001e },
        ClzCase { input: 0x00000002, expected: 0x0000001e },
        ClzCase { input: 0x0000000d, expected: 0x0000001c },
        ClzCase { input: 0x00000006, expected: 0x0000001d },
        ClzCase { input: 0x00000014, expected: 0x0000001b },
        ClzCase { input: 0x00000004, expected: 0x0000001d },
        ClzCase { input: 0x0000003c, expected: 0x0000001a },
        ClzCase { input: 0x00000039, expected: 0x0000001a },
        ClzCase { input: 0x00000067, expected: 0x00000019 },
        ClzCase { input: 0x0000001a, expected: 0x0000001b },
        ClzCase { input: 0x0000006e, expected: 0x00000019 },
        ClzCase { input: 0x00000083, expected: 0x00000018 },
        ClzCase { input: 0x0000018a, expected: 0x00000017 },
        ClzCase { input: 0x0000014c, expected: 0x00000017 },
        ClzCase { input: 0x000002eb, expected: 0x00000016 },
        ClzCase { input: 0x000000bc, expected: 0x00000018 },
        ClzCase { input: 0x000004dd, expected: 0x00000015 },
        ClzCase { input: 0x000000a7, expected: 0x00000018 },
        ClzCase { input: 0x000008dd, expected: 0x00000014 },
        ClzCase { input: 0x00000113, expected: 0x00000017 },
        ClzCase { input: 0x00000981, expected: 0x00000014 },
        ClzCase { input: 0x00001df5, expected: 0x00000013 },
        ClzCase { input: 0x00002b2a, expected: 0x00000012 },
        ClzCase { input: 0x0000299f, expected: 0x00000012 },
        ClzCase { input: 0x00006b9a, expected: 0x00000011 },
        ClzCase { input: 0x00005740, expected: 0x00000011 },
        ClzCase { input: 0x0000baf6, expected: 0x00000010 },
        ClzCase { input: 0x00004f51, expected: 0x00000011 },
        ClzCase { input: 0x0001197a, expected: 0x0000000f },
        ClzCase { input: 0x0000731b, expected: 0x00000011 },
        ClzCase { input: 0x0000fea1, expected: 0x00000010 },
        ClzCase { input: 0x0003a415, expected: 0x0000000e },
        ClzCase { input: 0x0004deb6, expected: 0x0000000d },
        ClzCase { input: 0x00062afe, expected: 0x0000000d },
        ClzCase { input: 0x0001235b, expected: 0x0000000f },
        ClzCase { input: 0x0005b54a, expected: 0x0000000d },
        ClzCase { input: 0x001bb9e2, expected: 0x0000000b },
        ClzCase { input: 0x0005f6d8, expected: 0x0000000d },
        ClzCase { input: 0x00235843, expected: 0x0000000a },
        ClzCase { input: 0x003c18ca, expected: 0x0000000a },
        ClzCase { input: 0x007ceff2, expected: 0x00000009 },
        ClzCase { input: 0x0018a8b1, expected: 0x0000000b },
        ClzCase { input: 0x00bd724d, expected: 0x00000008 },
        ClzCase { input: 0x0077fb7c, expected: 0x00000009 },
        ClzCase { input: 0x008fc5fd, expected: 0x00000008 },
        ClzCase { input: 0x012d0938, expected: 0x00000007 },
        ClzCase { input: 0x0175ec38, expected: 0x00000007 },
        ClzCase { input: 0x00dfdada, expected: 0x00000008 },
        ClzCase { input: 0x0340f1df, expected: 0x00000006 },
        ClzCase { input: 0x01640515, expected: 0x00000007 },
        ClzCase { input: 0x082c4bee, expected: 0x00000004 },
        ClzCase { input: 0x01c0db60, expected: 0x00000007 },
        ClzCase { input: 0x077fe30a, expected: 0x00000005 },
        ClzCase { input: 0x0975f718, expected: 0x00000004 },
        ClzCase { input: 0x0f2584ff, expected: 0x00000004 },
        ClzCase { input: 0x25f04ea4, expected: 0x00000002 },
        ClzCase { input: 0x38554e58, expected: 0x00000002 },
        ClzCase { input: 0x02963ff5, expected: 0x00000006 },
        ClzCase { input: 0x759e9df5, expected: 0x00000001 },
        ClzCase { input: 0x27fe67d3, expected: 0x00000002 },
        ClzCase { input: 0x00000000, expected: 0x00000020 },
        ClzCase { input: 0xf290b311, expected: 0x00000000 },
    ];

    for (i, case) in cases.into_iter().enumerate() {
        let mut runtime = Executor::new(clz_program(case.input), ZKMCoreOpts::default());
        runtime.run_very_fast().unwrap();

        assert_eq!(
            runtime.register(Register::T0),
            case.input,
            "case {i}: CLZ should preserve the source"
        );
        assert_eq!(
            runtime.register(Register::T1),
            case.expected,
            "case {i}: CLZ({:#010x})",
            case.input
        );
    }
}

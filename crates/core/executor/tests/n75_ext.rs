use zkm_core_executor::{Executor, Instruction, Opcode, Program, Register};
use zkm_stark::ZKMCoreOpts;

#[derive(Clone, Copy, Debug)]
struct ExtCase {
    expected: u32,
    source: u32,
    pos: u32,
    size: u32,
}

/// Encode the `EXT` immediate in the executor's internal `(size - 1, lsb)` layout.
fn encode_ext(pos: u32, size: u32) -> u32 {
    assert!((1..=32).contains(&size));
    assert!(pos < 32);
    assert!(pos + size <= 32);
    ((size - 1) << 5) | pos
}

/// Build the smallest program that isolates `EXT`.
fn ext_program(case: ExtCase) -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, Register::T0 as u8, 0, case.source, false, true),
        Instruction::new(
            Opcode::EXT,
            Register::T1 as u8,
            Register::T0 as u32,
            encode_ext(case.pos, case.size),
            false,
            true,
        ),
    ];
    Program::new(instructions, 0, 0)
}

/// Regression vectors copied from `mipstest/insttest/src/n75_ext.S`.
///
/// These cover single-bit extracts, mid-word windows, and the full-width `pos = 0, size = 32`
/// case where `EXT` should return the source unchanged.
#[test]
fn n75_ext_vectors() {
    let cases = [
        ExtCase { expected: 0x00000407, source: 0x101f5494, pos: 18, size: 11 },
        ExtCase { expected: 0x00000403, source: 0x4386201c, pos: 3, size: 12 },
        ExtCase { expected: 0x0001c4cb, source: 0x0e2659f8, pos: 11, size: 21 },
        ExtCase { expected: 0x00000004, source: 0x4ebdcb4b, pos: 28, size: 4 },
        ExtCase { expected: 0x000007dd, source: 0x4d7dd2b4, pos: 12, size: 12 },
        ExtCase { expected: 0x00014316, source: 0x2ca18b07, pos: 7, size: 17 },
        ExtCase { expected: 0x000001fc, source: 0x0fe71482, pos: 19, size: 12 },
        ExtCase { expected: 0x000001d9, source: 0x04d9fb36, pos: 5, size: 9 },
        ExtCase { expected: 0x0000034e, source: 0x35c69c97, pos: 9, size: 12 },
        ExtCase { expected: 0x00001ff0, source: 0x2aefff0c, pos: 4, size: 13 },
        ExtCase { expected: 0x0000003a, source: 0x3a2662d6, pos: 24, size: 7 },
        ExtCase { expected: 0x00000181, source: 0x581eb3d0, pos: 20, size: 10 },
        ExtCase { expected: 0x00000001, source: 0x0ad621d3, pos: 13, size: 3 },
        ExtCase { expected: 0x00000001, source: 0x6f0b8cb3, pos: 24, size: 1 },
        ExtCase { expected: 0x00000c85, source: 0x6cc85362, pos: 12, size: 14 },
        ExtCase { expected: 0x00000000, source: 0x6a25ebf9, pos: 19, size: 2 },
        ExtCase { expected: 0x00000004, source: 0x013e69cb, pos: 22, size: 8 },
        ExtCase { expected: 0x00000085, source: 0x63c85094, pos: 12, size: 9 },
        ExtCase { expected: 0x00000000, source: 0x45a8bb07, pos: 3, size: 5 },
        ExtCase { expected: 0x00000006, source: 0x29437cd2, pos: 15, size: 3 },
        ExtCase { expected: 0x00000324, source: 0x4233e48e, pos: 5, size: 10 },
        ExtCase { expected: 0x000001e6, source: 0x3cc183dc, pos: 21, size: 10 },
        ExtCase { expected: 0x0000012a, source: 0x3112552e, pos: 9, size: 9 },
        ExtCase { expected: 0x00000003, source: 0x3dcb0f6a, pos: 28, size: 4 },
        ExtCase { expected: 0x00000000, source: 0x09f92fc3, pos: 30, size: 1 },
        ExtCase { expected: 0x00000000, source: 0x5e2d8768, pos: 23, size: 2 },
        ExtCase { expected: 0x0000000d, source: 0x7ba83e34, pos: 2, size: 4 },
        ExtCase { expected: 0x00000014, source: 0x0a436673, pos: 23, size: 5 },
        ExtCase { expected: 0x00000001, source: 0x403a17f7, pos: 30, size: 2 },
        ExtCase { expected: 0x00002761, source: 0x4ec246e5, pos: 17, size: 14 },
        ExtCase { expected: 0x00000000, source: 0x7baf1356, pos: 31, size: 1 },
        ExtCase { expected: 0x00000005, source: 0x571fd1e0, pos: 28, size: 4 },
        ExtCase { expected: 0x000006a8, source: 0x249aa29f, pos: 10, size: 13 },
        ExtCase { expected: 0x00000004, source: 0x7245df8a, pos: 20, size: 5 },
        ExtCase { expected: 0x00000001, source: 0x0edf53ee, pos: 23, size: 2 },
        ExtCase { expected: 0x00000000, source: 0x47e4d27e, pos: 31, size: 1 },
        ExtCase { expected: 0x0000013e, source: 0x49f7e641, pos: 19, size: 11 },
        ExtCase { expected: 0x00000e8e, source: 0x24ffa3bb, pos: 6, size: 12 },
        ExtCase { expected: 0x00000001, source: 0x5dd60620, pos: 30, size: 1 },
        ExtCase { expected: 0x05483541, source: 0x2a41aa09, pos: 3, size: 29 },
        ExtCase { expected: 0x0000001a, source: 0x35328e82, pos: 25, size: 7 },
        ExtCase { expected: 0x76d3b816, source: 0x76d3b816, pos: 0, size: 32 },
        ExtCase { expected: 0x00000ccf, source: 0x333da43a, pos: 18, size: 14 },
        ExtCase { expected: 0x00000006, source: 0x0d35f573, pos: 25, size: 7 },
        ExtCase { expected: 0x000010eb, source: 0x10eb4cbc, pos: 16, size: 16 },
        ExtCase { expected: 0x0000250f, source: 0x4a1e2663, pos: 17, size: 15 },
        ExtCase { expected: 0x00001bf8, source: 0x37f0ab68, pos: 17, size: 15 },
        ExtCase { expected: 0x00000000, source: 0x61a48528, pos: 31, size: 1 },
        ExtCase { expected: 0x0020e24c, source: 0x20e24ccf, pos: 8, size: 24 },
        ExtCase { expected: 0x00001eed, source: 0x3dda5e6d, pos: 17, size: 15 },
        ExtCase { expected: 0x745a3a5b, source: 0x745a3a5b, pos: 0, size: 32 },
        ExtCase { expected: 0x00000000, source: 0x3475095d, pos: 31, size: 1 },
    ];

    for (i, case) in cases.into_iter().enumerate() {
        let mut runtime = Executor::new(ext_program(case), ZKMCoreOpts::default());
        runtime.run_very_fast().unwrap();

        assert_eq!(
            runtime.register(Register::T0),
            case.source,
            "case {i}: EXT should preserve the source"
        );
        assert_eq!(
            runtime.register(Register::T1),
            case.expected,
            "case {i}: EXT({:#010x}, pos={}, size={})",
            case.source,
            case.pos,
            case.size,
        );
    }
}

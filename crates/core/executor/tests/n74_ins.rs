use zkm_core_executor::{Executor, Instruction, Opcode, Program, Register};
use zkm_stark::ZKMCoreOpts;

#[derive(Clone, Copy, Debug)]
struct InsCase {
    /// Expected value in the destination register after executing `INS`.
    expected: u32,
    /// Source register value whose low `size` bits are inserted.
    source: u32,
    /// Initial destination register value before the insertion.
    initial: u32,
    /// Least-significant bit position of the insertion window.
    pos: u32,
    /// Width of the insertion window in bits.
    size: u32,
}

/// Encode the `INS` immediate in the same layout as the instruction stream:
/// `c = lsb | (msb << 5)`, where `msb = pos + size - 1`.
fn encode_ins(pos: u32, size: u32) -> u32 {
    assert!((1..=32).contains(&size));
    let msb = pos + size - 1;
    assert!(msb < 32);
    (msb << 5) | pos
}

/// Build the smallest program that isolates the `INS` behavior under test.
///
/// The program:
/// 1. Loads the source word into `t0`.
/// 2. Loads the initial destination word into `t1`.
/// 3. Executes `INS t1, t0, c`, so the executor updates `t1` while leaving `t0` unchanged.
fn ins_program(case: InsCase) -> Program {
    let instructions = vec![
        // Seed `t0` with the word providing the bits that will be inserted.
        Instruction::new(Opcode::ADD, Register::T0 as u8, 0, case.source, false, true),
        // Seed `t1` with the destination word whose selected bit window will be overwritten.
        Instruction::new(Opcode::ADD, Register::T1 as u8, 0, case.initial, false, true),
        // Execute the insertion using the encoded `(lsb, msb)` immediate.
        Instruction::new(
            Opcode::INS,
            Register::T1 as u8,
            Register::T0 as u32,
            encode_ins(case.pos, case.size),
            false,
            true,
        ),
    ];
    Program::new(instructions, 0, 0)
}

/// Regression vectors copied from `https://github.com/nju-mips/mipstest/blob/master/insttest/src/n74_ins.S`.
///
/// These cases exercise plain mid-word insertions as well as boundary conditions:
/// single-bit inserts, wide inserts, and full-width `pos = 0, size = 32` replacements.
/// For each vector we check the two observable `INS` semantics that matter here:
/// - the source register is preserved
/// - the destination register matches the expected post-insert word
#[test]
fn n74_ins_vectors() {
    let cases = [
        // Small interior insertion: replace two bits in the middle of the destination word.
        InsCase { expected: 0x561d90a9, source: 0x7f8ef599, initial: 0x561e90a9, pos: 16, size: 2 },
        InsCase { expected: 0x38021245, source: 0x358b8480, initial: 0x3a521245, pos: 20, size: 7 },
        InsCase { expected: 0x27db2103, source: 0x0409f67b, initial: 0x26732103, pos: 19, size: 6 },
        InsCase { expected: 0x5dde9b56, source: 0x4535b777, initial: 0x5d629b56, pos: 18, size: 8 },
        InsCase { expected: 0x642229dd, source: 0x32a16e44, initial: 0x6402a9dd, pos: 15, size: 7 },
        // High-end insertion near the MSB without covering the full top word.
        InsCase { expected: 0x4a9a8c2b, source: 0x00af69a6, initial: 0x2a9a8c2b, pos: 29, size: 2 },
        InsCase {
            expected: 0x1da58354,
            source: 0x48ec7da5,
            initial: 0x0e4d8354,
            pos: 16,
            size: 13,
        },
        // Single-bit insertion at bit 31: checks the top-bit boundary and a no-op outcome.
        InsCase { expected: 0x07aaee30, source: 0x47969d08, initial: 0x07aaee30, pos: 31, size: 1 },
        InsCase { expected: 0x28cd46b0, source: 0x5dc97ed9, initial: 0x28cd46b0, pos: 19, size: 1 },
        InsCase { expected: 0x44afdd07, source: 0x631f58f5, initial: 0x44afdd07, pos: 23, size: 1 },
        InsCase { expected: 0x50bff56b, source: 0x6b22fe0b, initial: 0x50bff56b, pos: 10, size: 1 },
        InsCase {
            expected: 0x2c30671d,
            source: 0x2e2290c1,
            initial: 0x2caca71d,
            pos: 14,
            size: 13,
        },
        InsCase {
            expected: 0x7a03e9fd,
            source: 0x10af50fa,
            initial: 0x7a19b1fd,
            pos: 10,
            size: 11,
        },
        InsCase { expected: 0x02e54a27, source: 0x24b43e28, initial: 0x02e55a67, pos: 6, size: 8 },
        InsCase { expected: 0x765b2d76, source: 0x1132ddbb, initial: 0x425b2d76, pos: 25, size: 6 },
        InsCase { expected: 0x0a06e9b9, source: 0x4a061ba6, initial: 0x0a128fb9, pos: 6, size: 17 },
        InsCase { expected: 0x32693d59, source: 0x32dfd669, initial: 0x36693d59, pos: 25, size: 2 },
        InsCase { expected: 0x03406e31, source: 0x7b191a60, initial: 0x03496e31, pos: 15, size: 5 },
        InsCase {
            expected: 0x38e70bda,
            source: 0x5409639c,
            initial: 0x3ce18bda,
            pos: 14,
            size: 14,
        },
        InsCase { expected: 0x5b1f97bc, source: 0x698e32f7, initial: 0x5b1f06dc, pos: 3, size: 14 },
        InsCase { expected: 0x0fb2078d, source: 0x5538b8d9, initial: 0x0fce078d, pos: 17, size: 6 },
        InsCase {
            expected: 0x20fa2a57,
            source: 0x12b361f4,
            initial: 0x23fe2a57,
            pos: 15,
            size: 12,
        },
        InsCase { expected: 0x1cd77fa8, source: 0x665957cd, initial: 0x17277fa8, pos: 20, size: 8 },
        InsCase { expected: 0x1c0ec7da, source: 0x213a0f61, initial: 0x1c9ec7da, pos: 19, size: 5 },
        // Wide insertion that spans most of the upper word while preserving the low tail.
        InsCase { expected: 0x100a67cd, source: 0x53080533, initial: 0x1353abcd, pos: 9, size: 22 },
        InsCase { expected: 0x674193f8, source: 0x169d19fe, initial: 0x674193f8, pos: 31, size: 1 },
        InsCase { expected: 0xe97205ed, source: 0x24231fd2, initial: 0x4af205ed, pos: 23, size: 9 },
        InsCase { expected: 0x4fc2655b, source: 0x26110cc9, initial: 0x4fc2655b, pos: 26, size: 1 },
        InsCase { expected: 0x138b6743, source: 0x5f906ce8, initial: 0x138b154b, pos: 3, size: 15 },
        InsCase {
            expected: 0x5cf44f72,
            source: 0x37893fa2,
            initial: 0x5cc46f72,
            pos: 13,
            size: 11,
        },
        InsCase { expected: 0x1f5f78d9, source: 0x73ebef1b, initial: 0x12d9c901, pos: 3, size: 26 },
        InsCase { expected: 0x26711dd6, source: 0x2f7890db, initial: 0x267118d6, pos: 7, size: 5 },
        InsCase { expected: 0x5358f976, source: 0x39c4c4a3, initial: 0x5358f970, pos: 1, size: 2 },
        InsCase { expected: 0x04feeda0, source: 0x3a9a8d68, initial: 0x04feeda0, pos: 27, size: 1 },
        InsCase { expected: 0x7f0f38d3, source: 0x4ff0f38d, initial: 0x27dace33, pos: 4, size: 27 },
        InsCase { expected: 0x0e5dd6bf, source: 0x779d338e, initial: 0x745dd6bf, pos: 24, size: 7 },
        InsCase { expected: 0x66d2829c, source: 0x07e8ec0a, initial: 0x6682829c, pos: 19, size: 4 },
        InsCase { expected: 0x6f9b7de0, source: 0x4346f20e, initial: 0x5f9b7de0, pos: 28, size: 2 },
        InsCase { expected: 0x2d51b87f, source: 0x727546e1, initial: 0x2b96cdff, pos: 6, size: 21 },
        InsCase {
            expected: 0x3f9b5bed,
            source: 0x5207e6d6,
            initial: 0x3598c3ed,
            pos: 10,
            size: 18,
        },
        InsCase { expected: 0xed10236c, source: 0x08f1bd5d, initial: 0x7510236c, pos: 27, size: 5 },
        InsCase {
            expected: 0xb14f110c,
            source: 0x438c4ac5,
            initial: 0x7a0f110c,
            pos: 22,
            size: 10,
        },
        InsCase { expected: 0x93f0009a, source: 0x2249f800, initial: 0x4a00049a, pos: 9, size: 23 },
        InsCase { expected: 0x028204f0, source: 0x0eb8f805, initial: 0x400204f0, pos: 23, size: 9 },
        InsCase {
            expected: 0xb3b10ae9,
            source: 0x0316cec4,
            initial: 0x314dcae9,
            pos: 14,
            size: 18,
        },
        // Near-full-width insertions: keep only the lowest 1/2/3 destination bits.
        InsCase { expected: 0x15ff759d, source: 0x0affbace, initial: 0x17d04d85, pos: 1, size: 31 },
        InsCase { expected: 0x29c799ef, source: 0x4a71e67b, initial: 0x5b173f93, pos: 2, size: 30 },
        InsCase { expected: 0x3e354cc5, source: 0x27c6a998, initial: 0x124a20bd, pos: 3, size: 29 },
        // Full-width replacement: `INS` should copy the entire source when `pos = 0, size = 32`.
        InsCase { expected: 0x535d7797, source: 0x535d7797, initial: 0x5ea30063, pos: 0, size: 32 },
        InsCase {
            expected: 0x9579b450,
            source: 0x25655e6d,
            initial: 0x143bc450,
            pos: 10,
            size: 22,
        },
        // Same full-width edge case with a different source/destination pair.
        InsCase { expected: 0x313209e7, source: 0x313209e7, initial: 0x1d2d81ad, pos: 0, size: 32 },
        // Final top-bit-only insert: another bit-31 boundary case, here also ending as a no-op.
        InsCase { expected: 0x0d609402, source: 0x64cb2596, initial: 0x0d609402, pos: 31, size: 1 },
    ];

    for (i, case) in cases.into_iter().enumerate() {
        // `run_very_fast` is enough for this regression because we are checking executor semantics
        // only; the proof path is covered separately.
        let mut runtime = Executor::new(ins_program(case), ZKMCoreOpts::default());
        runtime.run_very_fast().unwrap();

        // `INS` reads from the source register but should not mutate it.
        assert_eq!(
            runtime.register(Register::T0),
            case.source,
            "case {i}: INS should not modify the source register",
        );
        // The destination register should match the reference result from the original test vector.
        assert_eq!(
            runtime.register(Register::T1),
            case.expected,
            "case {i}: INS({:#010x}, {:#010x}, pos={}, size={})",
            case.source,
            case.initial,
            case.pos,
            case.size,
        );
    }
}

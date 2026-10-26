//! The Blake3 compression chip of the recursion machine: one compression
//! per row on byte limbs, which the Blake3 ring's verifier asks for by the
//! hash of every Merkle path and transcript step it checks.
//!
//! Words are four byte limbs.  XOR is one `Xor` byte lookup per limb.  A
//! rotation by 16 or 8 bits is a limb permutation and costs nothing.  The
//! XOR feeding a 12- or 7-bit rotation is not materialised: one fused
//! `XorShr4` or `XorShr7` lookup per limb returns the high and low parts of
//! the XOR of the two operand limbs, which the rotation recombines linearly.
//! An addition keeps only the result limbs, the carries linear in the
//! operands and constrained boolean for two operands and to `{0, 1, 2}` for
//! three.  Every addition result is an operand of a later byte lookup, which
//! bounds it to a byte, so it needs no range check of its own; the inputs
//! are range checked with `U8Range` lookups two limbs at a time.  The lookups
//! go to the machine's [`ByteChip`](super::byte::ByteChip).
//!
//! A state word crossing from one G function to the next is re-read from its
//! columns at each use rather than carried as one expression, so no
//! expression outlives its G function and the zerocheck evaluation can be
//! cut at every G boundary.
//!
//! Memory holds the inputs and outputs as 16-bit limbs, two per word; a row
//! exchanges each limb as the linear combination of its two bytes.  The
//! counter's low word, the block length and the flags are the instruction's
//! immediates; the counter's high word is zero, a hash the verifier computes
//! being far below 2^32 chunks.
//!
//! The IV words are `is_real · IV`, so an all-zero padding row satisfies
//! every constraint without gating them by `is_real`, which keeps the degree
//! at three.

use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use zkm_core_machine::utils::next_multiple_of_32_rows;
use zkm_derive::AlignedBorrow;
use zkm_pcs::air::{BaseAirBuilder, ByteAirBuilder, MachineAir};
use zkm_pcs::Word;

use crate::builder::ZKMRecursionAirBuilder;
use crate::chips::byte::{ByteLookup, ByteOp};
use crate::chips::mem::MemoryAccessColsChips;
use crate::instruction::Instruction;
use crate::{
    Address, Blake3CompressEvent, ExecutionRecord, RecursionProgram, BLAKE3_BLOCK_LIMBS,
    BLAKE3_CV_LIMBS, BLAKE3_OUT_LIMBS,
};

/// The Blake3 IV.
pub const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

/// The message permutation applied between rounds.
pub const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// The state words each of a round's eight G functions reads.
pub const G_LANES: [[usize; 4]; 8] = [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15],
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14],
];

/// Rounds of a compression.
pub const ROUNDS: usize = 7;

/// `SCHEDULE[r][i]`: the block word that is message word `i` in round `r`.
#[must_use]
pub fn schedule() -> [[usize; 16]; ROUNDS] {
    let mut s = [[0usize; 16]; ROUNDS];
    for (i, v) in s[0].iter_mut().enumerate() {
        *v = i;
    }
    for r in 1..ROUNDS {
        for i in 0..16 {
            s[r][i] = s[r - 1][MSG_PERMUTATION[i]];
        }
    }
    s
}

/// The limbs of a 12- or 7-bit rotation of an XOR: per limb, the high and
/// low parts of the XOR split at the rotation's bit offset.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct RotCols<T> {
    pub shift: Word<T>,
    pub carry: Word<T>,
}

/// One G function.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct GCols<T> {
    pub a1: Word<T>,
    pub x1: Word<T>,
    pub c1: Word<T>,
    pub r2: RotCols<T>,
    pub a2: Word<T>,
    pub x3: Word<T>,
    pub c2: Word<T>,
    pub r4: RotCols<T>,
}

/// One compression.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Blake3Cols<T> {
    pub is_real: T,
    pub cv: [Word<T>; 8],
    pub block: [Word<T>; 16],
    pub block_len: Word<T>,
    pub flags: Word<T>,
    pub counter: Word<T>,
    pub g: [[GCols<T>; 8]; ROUNDS],
    pub out: [Word<T>; 8],
}

/// Columns of [`Blake3Cols`].
pub const NUM_BLAKE3_COLS: usize = size_of::<Blake3Cols<u8>>();

/// The program's part of a row: where the limbs live, how often the
/// outputs are read, and the immediates.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Blake3PreprocessedCols<T: Copy> {
    pub chaining_value: [Address<T>; BLAKE3_CV_LIMBS],
    pub block: [Address<T>; BLAKE3_BLOCK_LIMBS],
    pub output: [MemoryAccessColsChips<T>; BLAKE3_OUT_LIMBS],
    pub block_len: T,
    pub flags: T,
    pub counter: T,
    pub is_real_neg: T,
}

/// Columns of [`Blake3PreprocessedCols`].
pub const NUM_BLAKE3_PREPROCESSED_COLS: usize = size_of::<Blake3PreprocessedCols<u8>>();

/// The chip.
#[derive(Clone, Copy, Debug, Default)]
pub struct Blake3CompressChip;

/// One compression's inputs as words.
#[derive(Clone, Copy, Debug)]
pub struct CompressInput {
    pub cv: [u32; 8],
    pub block: [u32; 16],
    pub counter: u32,
    pub block_len: u32,
    pub flags: u32,
}

/// The words of an event's limbs.
#[must_use]
pub fn compress_input<F: PrimeField32>(event: &Blake3CompressEvent<F>) -> CompressInput {
    let word = |limbs: &[F]| limbs[0].as_canonical_u32() | (limbs[1].as_canonical_u32() << 16);
    CompressInput {
        cv: core::array::from_fn(|i| word(&event.io.chaining_value[2 * i..])),
        block: core::array::from_fn(|i| word(&event.io.block[2 * i..])),
        counter: event.counter.as_canonical_u32(),
        block_len: event.block_len.as_canonical_u32(),
        flags: event.flags.as_canonical_u32(),
    }
}

/// The compression on native words: the sixteen-word state after seven
/// rounds.
#[must_use]
pub fn compress_state(input: &CompressInput) -> [u32; 16] {
    let mut v = [0u32; 16];
    v[..8].copy_from_slice(&input.cv);
    v[8..12].copy_from_slice(&IV[..4]);
    v[12] = input.counter;
    v[14] = input.block_len;
    v[15] = input.flags;
    for sr in schedule().iter() {
        for (j, lane) in G_LANES.iter().enumerate() {
            let [a, b, c, d] = *lane;
            let mx = input.block[sr[2 * j]];
            let my = input.block[sr[2 * j + 1]];
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(mx);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(12);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(my);
            v[d] = (v[d] ^ v[a]).rotate_right(8);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(7);
        }
    }
    v
}

fn word<F: PrimeCharacteristicRing>(x: u32) -> Word<F> {
    Word(x.to_le_bytes().map(F::from_u8))
}

/// The lookups that range check a word, two bytes at a time.
fn record_range(x: u32, lookup: &mut impl FnMut(ByteLookup)) {
    let b = x.to_le_bytes();
    for k in 0..2 {
        lookup(ByteLookup { op: ByteOp::U8Range, b: b[2 * k], c: b[2 * k + 1] });
    }
}

/// `x ^ y`, with its lookups.
fn record_xor(x: u32, y: u32, lookup: &mut impl FnMut(ByteLookup)) -> u32 {
    let (xb, yb) = (x.to_le_bytes(), y.to_le_bytes());
    for i in 0..4 {
        lookup(ByteLookup { op: ByteOp::Xor, b: xb[i], c: yb[i] });
    }
    x ^ y
}

/// The fused operation of a rotation by `rotation` bits.
fn xor_shr_op(rotation: usize) -> ByteOp {
    match rotation % 8 {
        4 => ByteOp::XorShr4,
        7 => ByteOp::XorShr7,
        _ => unreachable!("Blake3 rotates by 12 or 7 bits through the table"),
    }
}

/// The witness of a 12- or 7-bit rotation of `x ^ y`, with its fused
/// lookups, and the rotated word.
fn fill_xor_rot<F: PrimeCharacteristicRing>(
    cols: &mut RotCols<F>,
    x: u32,
    y: u32,
    rotation: usize,
    lookup: &mut impl FnMut(ByteLookup),
) -> u32 {
    let nbytes = rotation / 8;
    let nbits = rotation % 8;
    let (xb, yb) = (x.to_le_bytes(), y.to_le_bytes());
    let mask = (1u8 << nbits) - 1;
    for i in 0..4 {
        let k = (i + nbytes) % 4;
        let z = xb[k] ^ yb[k];
        cols.shift.0[i] = F::from_u8(z >> nbits);
        cols.carry.0[i] = F::from_u8(z & mask);
        lookup(ByteLookup { op: xor_shr_op(rotation), b: xb[k], c: yb[k] });
    }
    (x ^ y).rotate_right(rotation as u32)
}

/// Fill one row for `input`, reporting each byte lookup the row makes to
/// `lookup`, and return the output words.
pub fn populate_row<F: PrimeCharacteristicRing>(
    cols: &mut Blake3Cols<F>,
    input: &CompressInput,
    lookup: &mut impl FnMut(ByteLookup),
) -> [u32; 8] {
    cols.is_real = F::ONE;
    for i in 0..8 {
        cols.cv[i] = word(input.cv[i]);
        record_range(input.cv[i], lookup);
    }
    for i in 0..16 {
        cols.block[i] = word(input.block[i]);
        record_range(input.block[i], lookup);
    }
    cols.block_len = word(input.block_len);
    record_range(input.block_len, lookup);
    cols.flags = word(input.flags);
    record_range(input.flags, lookup);
    cols.counter = word(input.counter);
    record_range(input.counter, lookup);
    let mut v = [0u32; 16];
    v[..8].copy_from_slice(&input.cv);
    v[8..12].copy_from_slice(&IV[..4]);
    v[12] = input.counter;
    v[14] = input.block_len;
    v[15] = input.flags;
    for (r, sr) in schedule().iter().enumerate() {
        for (j, lane) in G_LANES.iter().enumerate() {
            let [a, b, c, d] = *lane;
            let mx = input.block[sr[2 * j]];
            let my = input.block[sr[2 * j + 1]];
            let g = &mut cols.g[r][j];
            let a1 = v[a].wrapping_add(v[b]).wrapping_add(mx);
            g.a1 = word(a1);
            let x1 = record_xor(v[d], a1, lookup);
            g.x1 = word(x1);
            let d1 = x1.rotate_right(16);
            let c1 = v[c].wrapping_add(d1);
            g.c1 = word(c1);
            let b1 = fill_xor_rot(&mut g.r2, v[b], c1, 12, lookup);
            let a2 = a1.wrapping_add(b1).wrapping_add(my);
            g.a2 = word(a2);
            let x3 = record_xor(d1, a2, lookup);
            g.x3 = word(x3);
            let d2 = x3.rotate_right(8);
            let c2 = c1.wrapping_add(d2);
            g.c2 = word(c2);
            let b2 = fill_xor_rot(&mut g.r4, b1, c2, 7, lookup);
            v[a] = a2;
            v[b] = b2;
            v[c] = c2;
            v[d] = d2;
        }
    }
    let mut out = [0u32; 8];
    for i in 0..8 {
        out[i] = record_xor(v[i], v[i + 8], lookup);
        cols.out[i] = word(out[i]);
    }
    out
}

impl<F: Field> BaseAir<F> for Blake3CompressChip {
    fn width(&self) -> usize {
        NUM_BLAKE3_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for Blake3CompressChip {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    type Error = crate::RecursionChipError;

    fn name(&self) -> String {
        "Blake3Compress".to_string()
    }

    fn generate_dependencies(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        Some(next_multiple_of_32_rows(
            input.blake3_compress_events.len(),
            input.fixed_rows(self),
            <Self as MachineAir<F>>::name(self).as_str(),
        ))
    }

    fn generate_trace(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        let events = &input.blake3_compress_events;
        let padded_nb_rows = self.num_rows(input).unwrap();
        let mut values = vec![F::ZERO; padded_nb_rows * NUM_BLAKE3_COLS];
        values[..events.len() * NUM_BLAKE3_COLS]
            .par_chunks_mut(NUM_BLAKE3_COLS)
            .zip_eq(events)
            .for_each(|(row, event)| {
                let cols: &mut Blake3Cols<F> = row.borrow_mut();
                let out = populate_row(cols, &compress_input(event), &mut |_| {});
                let expected: [u32; 8] = core::array::from_fn(|i| {
                    event.io.output[2 * i].as_canonical_u32()
                        | (event.io.output[2 * i + 1].as_canonical_u32() << 16)
                });
                debug_assert_eq!(out, expected, "the row recomputes the event's output");
            });
        Ok(RowMajorMatrix::new(values, NUM_BLAKE3_COLS))
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }

    fn preprocessed_width(&self) -> usize {
        NUM_BLAKE3_PREPROCESSED_COLS
    }

    fn preprocessed_num_rows(&self, program: &Self::Program, instrs_len: usize) -> Option<usize> {
        Some(next_multiple_of_32_rows(
            instrs_len,
            program.fixed_rows(self),
            <Self as MachineAir<F>>::name(self).as_str(),
        ))
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let instrs = program
            .iter_instructions()
            .filter_map(|instruction| match instruction {
                Instruction::Blake3Compress(instr) => Some(instr.as_ref()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let padded_nb_rows = self.preprocessed_num_rows(program, instrs.len()).unwrap();
        let mut values = vec![F::ZERO; padded_nb_rows * NUM_BLAKE3_PREPROCESSED_COLS];
        values[..instrs.len() * NUM_BLAKE3_PREPROCESSED_COLS]
            .par_chunks_mut(NUM_BLAKE3_PREPROCESSED_COLS)
            .zip_eq(instrs)
            .for_each(|(row, instr)| {
                *row.borrow_mut() = Blake3PreprocessedCols {
                    chaining_value: instr.addrs.chaining_value,
                    block: instr.addrs.block,
                    output: core::array::from_fn(|i| MemoryAccessColsChips {
                        addr: instr.addrs.output[i],
                        mult: instr.mults[i],
                    }),
                    block_len: instr.block_len,
                    flags: instr.flags,
                    counter: instr.counter,
                    is_real_neg: F::NEG_ONE,
                };
            });
        Some(RowMajorMatrix::new(values, NUM_BLAKE3_PREPROCESSED_COLS))
    }
}

type E<AB> = <AB as AirBuilder>::Expr;
type WE<AB> = [E<AB>; 4];

fn we<AB: AirBuilder>(w: &Word<AB::Var>) -> WE<AB> {
    core::array::from_fn(|i| w.0[i].into())
}

/// The 16-bit limb `half` of a word: its two bytes.
fn limb<AB: AirBuilder>(w: &Word<AB::Var>, half: usize) -> E<AB> {
    E::<AB>::from(w.0[2 * half]) + E::<AB>::from(w.0[2 * half + 1]) * AB::F::from_u32(256)
}

/// An address as an expression, so a value given as an expression can be
/// sent to it.
fn address<AB: AirBuilder>(addr: Address<AB::Var>) -> Address<E<AB>> {
    Address(addr.0.into())
}

/// The value of a word.
fn value<AB: AirBuilder>(w: &Word<AB::Var>) -> E<AB> {
    (0..4).map(|i| E::<AB>::from(w.0[i]) * AB::F::from_u32(1 << (8 * i))).sum()
}

fn range_u8<AB: BaseAirBuilder>(builder: &mut AB, w: &WE<AB>, m: &E<AB>) {
    for k in 0..2 {
        builder.send_byte(
            E::<AB>::from_u8(ByteOp::U8Range.opcode()),
            E::<AB>::ZERO,
            w[2 * k].clone(),
            w[2 * k + 1].clone(),
            m.clone(),
        );
    }
}

fn xor<AB: BaseAirBuilder>(
    builder: &mut AB,
    out: &Word<AB::Var>,
    x: &WE<AB>,
    y: &WE<AB>,
    m: &E<AB>,
) -> WE<AB> {
    for i in 0..4 {
        builder.send_byte(
            E::<AB>::from_u8(ByteOp::Xor.opcode()),
            out.0[i],
            x[i].clone(),
            y[i].clone(),
            m.clone(),
        );
    }
    we::<AB>(out)
}

fn rot_bytes<AB: AirBuilder>(x: WE<AB>, nbytes: usize) -> WE<AB> {
    core::array::from_fn(|i| x[(i + nbytes) % 4].clone())
}

/// The word a 12- or 7-bit rotation's limbs recombine to.
fn rot_value<AB: AirBuilder>(cols: &RotCols<AB::Var>, rotation: usize) -> WE<AB> {
    let mult = AB::F::from_u32(1 << (8 - rotation % 8));
    core::array::from_fn(|i| {
        E::<AB>::from(cols.shift.0[i]) + E::<AB>::from(cols.carry.0[(i + 1) % 4]) * mult.clone()
    })
}

/// `(x ^ y)` rotated right by 12 or 7 bits: one fused lookup per limb splits
/// the limbs' XOR at the bit offset, and the halves recombine linearly.
fn xor_rot_bits<AB: BaseAirBuilder>(
    builder: &mut AB,
    cols: &RotCols<AB::Var>,
    x: &WE<AB>,
    y: &WE<AB>,
    rotation: usize,
    m: &E<AB>,
) -> WE<AB> {
    let nbytes = rotation / 8;
    let op = xor_shr_op(rotation);
    for i in 0..4 {
        builder.send_byte_pair(
            E::<AB>::from_u8(op.opcode()),
            cols.shift.0[i],
            cols.carry.0[i],
            x[(i + nbytes) % 4].clone(),
            y[(i + nbytes) % 4].clone(),
            m.clone(),
        );
    }
    rot_value::<AB>(cols, rotation)
}

fn add2<AB: BaseAirBuilder>(
    builder: &mut AB,
    out: &Word<AB::Var>,
    x: &WE<AB>,
    y: &WE<AB>,
) -> WE<AB> {
    let inv = AB::F::from_u32(256).inverse();
    let mut carry = E::<AB>::ZERO;
    for i in 0..4 {
        carry = (x[i].clone() + y[i].clone() - out.0[i].into() + carry) * inv;
        builder.assert_bool(carry.clone());
    }
    we::<AB>(out)
}

fn add3<AB: BaseAirBuilder>(
    builder: &mut AB,
    out: &Word<AB::Var>,
    x: &WE<AB>,
    y: &WE<AB>,
    z: &WE<AB>,
) -> WE<AB> {
    let inv = AB::F::from_u32(256).inverse();
    let mut carry = E::<AB>::ZERO;
    for i in 0..4 {
        carry = (x[i].clone() + y[i].clone() + z[i].clone() - out.0[i].into() + carry) * inv;
        builder.assert_zero(
            carry.clone() * (carry.clone() - E::<AB>::ONE) * (carry.clone() - E::<AB>::from_u8(2)),
        );
    }
    we::<AB>(out)
}

/// Where a state word lives, so it is re-read from its columns at each use.
#[derive(Clone, Copy)]
enum Src<V> {
    /// A word column.
    Col(Word<V>),
    /// A word column rotated by whole bytes.
    RotBytes(Word<V>, usize),
    /// A 12- or 7-bit rotation's limbs.
    RotBits(RotCols<V>, usize),
    /// `is_real` times a constant word.
    Const(u32),
}

fn read<AB: AirBuilder>(src: &Src<AB::Var>, m: &E<AB>) -> WE<AB> {
    match src {
        Src::Col(w) => we::<AB>(w),
        Src::RotBytes(w, n) => rot_bytes::<AB>(we::<AB>(w), *n),
        Src::RotBits(cols, rotation) => rot_value::<AB>(cols, *rotation),
        Src::Const(x) => {
            let b = x.to_le_bytes();
            core::array::from_fn(|k| m.clone() * AB::F::from_u8(b[k]))
        }
    }
}

impl<AB> Air<AB> for Blake3CompressChip
where
    AB: ZKMRecursionAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &Blake3Cols<AB::Var> = (*local).borrow();
        let prep = builder.preprocessed().clone();
        let prep_local = prep.current_slice();
        let prep_local: &Blake3PreprocessedCols<AB::Var> = (*prep_local).borrow();
        let m: E<AB> = local.is_real.into();
        builder.assert_bool(local.is_real);

        for w in local.cv.iter().chain(local.block.iter()).chain([
            &local.block_len,
            &local.flags,
            &local.counter,
        ]) {
            range_u8(builder, &we::<AB>(w), &m);
        }
        builder.assert_eq(value::<AB>(&local.block_len), prep_local.block_len);
        builder.assert_eq(value::<AB>(&local.flags), prep_local.flags);
        builder.assert_eq(value::<AB>(&local.counter), prep_local.counter);

        for i in 0..BLAKE3_CV_LIMBS {
            builder.send_single(
                address::<AB>(prep_local.chaining_value[i]),
                limb::<AB>(&local.cv[i / 2], i % 2),
                prep_local.is_real_neg,
            );
        }
        for i in 0..BLAKE3_BLOCK_LIMBS {
            builder.send_single(
                address::<AB>(prep_local.block[i]),
                limb::<AB>(&local.block[i / 2], i % 2),
                prep_local.is_real_neg,
            );
        }
        for i in 0..BLAKE3_OUT_LIMBS {
            builder.send_single(
                address::<AB>(prep_local.output[i].addr),
                limb::<AB>(&local.out[i / 2], i % 2),
                prep_local.output[i].mult,
            );
        }

        let mut v: [Src<AB::Var>; 16] = [Src::Const(0); 16];
        for (slot, w) in v.iter_mut().zip(local.cv.iter()) {
            *slot = Src::Col(*w);
        }
        for (slot, iv) in v[8..12].iter_mut().zip(IV.iter()) {
            *slot = Src::Const(*iv);
        }
        v[12] = Src::Col(local.counter);
        v[14] = Src::Col(local.block_len);
        v[15] = Src::Col(local.flags);
        for (r, sr) in schedule().iter().enumerate() {
            for (j, lane) in G_LANES.iter().enumerate() {
                let [a, b, c, d] = *lane;
                let g = &local.g[r][j];
                let mx = we::<AB>(&local.block[sr[2 * j]]);
                let my = we::<AB>(&local.block[sr[2 * j + 1]]);
                let va = read::<AB>(&v[a], &m);
                let vb = read::<AB>(&v[b], &m);
                let vc = read::<AB>(&v[c], &m);
                let vd = read::<AB>(&v[d], &m);
                let a1 = add3(builder, &g.a1, &va, &vb, &mx);
                let x1 = xor(builder, &g.x1, &vd, &a1, &m);
                let d1 = rot_bytes::<AB>(x1, 2);
                let c1 = add2(builder, &g.c1, &vc, &d1);
                let b1 = xor_rot_bits(builder, &g.r2, &vb, &c1, 12, &m);
                let a2 = add3(builder, &g.a2, &a1, &b1, &my);
                let x3 = xor(builder, &g.x3, &d1, &a2, &m);
                let d2 = rot_bytes::<AB>(x3, 1);
                let c2 = add2(builder, &g.c2, &c1, &d2);
                xor_rot_bits(builder, &g.r4, &b1, &c2, 7, &m);
                v[a] = Src::Col(g.a2);
                v[b] = Src::RotBits(g.r4, 7);
                v[c] = Src::Col(g.c2);
                v[d] = Src::RotBytes(g.x3, 1);
            }
        }
        for i in 0..8 {
            let lo = read::<AB>(&v[i], &m);
            let hi = read::<AB>(&v[i + 8], &m);
            xor(builder, &local.out[i], &lo, &hi, &m);
        }
    }
}

#[cfg(test)]
mod tests {
    use p3_koala_bear::KoalaBear;
    use rand::Rng;

    use super::*;
    use crate::machine::tests::run_recursion_test_machines;
    use crate::runtime::instruction as instr;
    use crate::{MemAccessKind, RawProgram};

    /// The chip's compression is the runtime's.
    #[test]
    fn compress_state_matches_the_runtime() {
        let mut rng = rand::thread_rng();
        for _ in 0..16 {
            let input = CompressInput {
                cv: core::array::from_fn(|_| rng.gen()),
                block: core::array::from_fn(|_| rng.gen()),
                counter: rng.gen_range(0..1 << 20),
                block_len: rng.gen_range(0..=64),
                flags: rng.gen_range(0..16),
            };
            let v = compress_state(&input);
            let out: [u32; 8] = core::array::from_fn(|i| v[i] ^ v[i + 8]);
            let expected = crate::runtime::blake3::compress(
                &input.cv,
                &input.block,
                u64::from(input.counter),
                input.block_len,
                input.flags,
            );
            assert_eq!(out, expected[..8]);
        }
    }

    /// A program writing two compressions' limbs, compressing, and reading
    /// the outputs proves under every machine.
    #[test]
    fn blake3_compress_program() {
        type F = KoalaBear;
        let mut rng = rand::thread_rng();
        let mut instructions = Vec::new();
        let mut next_addr = 1u32;
        for _ in 0..2 {
            let cv: [u32; 8] = core::array::from_fn(|_| rng.gen());
            let block: [u32; 16] = core::array::from_fn(|_| rng.gen());
            let counter: u32 = rng.gen_range(0..1 << 20);
            let block_len = 64;
            let flags = 11;
            let limbs = |words: &[u32]| -> Vec<u32> {
                words.iter().flat_map(|w| [w & 0xFFFF, w >> 16]).collect()
            };
            let cv_limbs = limbs(&cv);
            let block_limbs = limbs(&block);
            let cv_addrs: [u32; BLAKE3_CV_LIMBS] = core::array::from_fn(|i| next_addr + i as u32);
            next_addr += BLAKE3_CV_LIMBS as u32;
            let block_addrs: [u32; BLAKE3_BLOCK_LIMBS] =
                core::array::from_fn(|i| next_addr + i as u32);
            next_addr += BLAKE3_BLOCK_LIMBS as u32;
            let out_addrs: [u32; BLAKE3_OUT_LIMBS] = core::array::from_fn(|i| next_addr + i as u32);
            next_addr += BLAKE3_OUT_LIMBS as u32;
            for (i, &addr) in cv_addrs.iter().enumerate() {
                instructions.push(instr::mem(MemAccessKind::Write, 1, addr, cv_limbs[i]));
            }
            for (i, &addr) in block_addrs.iter().enumerate() {
                instructions.push(instr::mem(MemAccessKind::Write, 1, addr, block_limbs[i]));
            }
            instructions.push(instr::blake3_compress(
                [1; BLAKE3_OUT_LIMBS],
                out_addrs,
                cv_addrs,
                block_addrs,
                counter,
                block_len,
                flags,
            ));
            let out =
                crate::runtime::blake3::compress(&cv, &block, u64::from(counter), block_len, flags);
            let out_limbs = limbs(&out[..8]);
            for (i, &addr) in out_addrs.iter().enumerate() {
                instructions.push(instr::mem(MemAccessKind::Read, 1, addr, out_limbs[i]));
            }
        }
        let program =
            RecursionProgram::<F>::new(RawProgram::from_linear(instructions), 0, Vec::new(), None);
        run_recursion_test_machines(program);
    }
}

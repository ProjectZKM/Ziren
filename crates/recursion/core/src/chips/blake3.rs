//! The Blake3 compression chip of the recursion machine: one compression
//! per row on byte limbs, which the Blake3 ring's verifier asks for by the
//! hash of every Merkle path and transcript step it checks.
//!
//! Words are four byte limbs.  XOR is one `XOR` byte lookup per limb.  A
//! rotation by 16 or 8 bits is a limb permutation and costs nothing; a
//! rotation by 12 or 7 bits is one `ShrCarry` lookup per limb with the result
//! recombined linearly.  An addition keeps only the result limbs: the carries
//! are linear in the operands, constrained boolean for two operands and to
//! `{0, 1, 2}` for three, and the result limbs are range checked with
//! `U8Range` lookups two limbs at a time.  The lookups go to the machine's
//! [`ByteChip`](super::byte::ByteChip).
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
use zkm_core_executor::{events::ByteLookupEvent, ByteOpcode};
use zkm_core_machine::utils::next_multiple_of_32_rows;
use zkm_derive::AlignedBorrow;
use zkm_pcs::air::{BaseAirBuilder, ByteAirBuilder, MachineAir};
use zkm_pcs::Word;

use crate::builder::ZKMRecursionAirBuilder;
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

/// The `ShrCarry` limbs of a 12- or 7-bit rotation.
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
    pub x2: Word<T>,
    pub r2: RotCols<T>,
    pub a2: Word<T>,
    pub x3: Word<T>,
    pub c2: Word<T>,
    pub x4: Word<T>,
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
fn record_range(x: u32, lookup: &mut impl FnMut(ByteLookupEvent)) {
    let b = x.to_le_bytes();
    for k in 0..2 {
        lookup(ByteLookupEvent::new(ByteOpcode::U8Range, 0, 0, b[2 * k], b[2 * k + 1]));
    }
}

/// `x ^ y`, with its lookups.
fn record_xor(x: u32, y: u32, lookup: &mut impl FnMut(ByteLookupEvent)) -> u32 {
    let (xb, yb, ob) = (x.to_le_bytes(), y.to_le_bytes(), (x ^ y).to_le_bytes());
    for i in 0..4 {
        lookup(ByteLookupEvent::new(ByteOpcode::XOR, u16::from(ob[i]), 0, xb[i], yb[i]));
    }
    x ^ y
}

/// The witness of a 12- or 7-bit rotation of `x`, with its lookups, and
/// the rotated word.
fn fill_rot<F: PrimeCharacteristicRing>(
    cols: &mut RotCols<F>,
    x: u32,
    rotation: usize,
    lookup: &mut impl FnMut(ByteLookupEvent),
) -> u32 {
    let nbytes = rotation / 8;
    let nbits = rotation % 8;
    let xb = x.to_le_bytes();
    let mask = (1u8 << nbits) - 1;
    for i in 0..4 {
        let b = xb[(i + nbytes) % 4];
        let (shift, carry) = (b >> nbits, b & mask);
        cols.shift.0[i] = F::from_u8(shift);
        cols.carry.0[i] = F::from_u8(carry);
        lookup(ByteLookupEvent::new(ByteOpcode::ShrCarry, u16::from(shift), carry, b, nbits as u8));
    }
    x.rotate_right(rotation as u32)
}

/// Fill one row for `input`, reporting each byte lookup the row makes to
/// `lookup`, and return the output words.
pub fn populate_row<F: PrimeCharacteristicRing>(
    cols: &mut Blake3Cols<F>,
    input: &CompressInput,
    lookup: &mut impl FnMut(ByteLookupEvent),
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
            record_range(a1, lookup);
            let x1 = record_xor(v[d], a1, lookup);
            g.x1 = word(x1);
            let d1 = x1.rotate_right(16);
            let c1 = v[c].wrapping_add(d1);
            g.c1 = word(c1);
            record_range(c1, lookup);
            let x2 = record_xor(v[b], c1, lookup);
            g.x2 = word(x2);
            let b1 = fill_rot(&mut g.r2, x2, 12, lookup);
            let a2 = a1.wrapping_add(b1).wrapping_add(my);
            g.a2 = word(a2);
            record_range(a2, lookup);
            let x3 = record_xor(d1, a2, lookup);
            g.x3 = word(x3);
            let d2 = x3.rotate_right(8);
            let c2 = c1.wrapping_add(d2);
            g.c2 = word(c2);
            record_range(c2, lookup);
            let x4 = record_xor(b1, c2, lookup);
            g.x4 = word(x4);
            let b2 = fill_rot(&mut g.r4, x4, 7, lookup);
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
            E::<AB>::from_u8(ByteOpcode::U8Range as u8),
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
            E::<AB>::from_u8(ByteOpcode::XOR as u8),
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

fn rot_bits<AB: BaseAirBuilder>(
    builder: &mut AB,
    cols: &RotCols<AB::Var>,
    x: &WE<AB>,
    rotation: usize,
    m: &E<AB>,
) -> WE<AB> {
    let nbytes = rotation / 8;
    let nbits = rotation % 8;
    let mult = AB::F::from_u32(1 << (8 - nbits));
    for i in 0..4 {
        builder.send_byte_pair(
            E::<AB>::from_u8(ByteOpcode::ShrCarry as u8),
            cols.shift.0[i],
            cols.carry.0[i],
            x[(i + nbytes) % 4].clone(),
            E::<AB>::from_usize(nbits),
            m.clone(),
        );
    }
    core::array::from_fn(|i| {
        E::<AB>::from(cols.shift.0[i]) + E::<AB>::from(cols.carry.0[(i + 1) % 4]) * mult
    })
}

fn add2<AB: BaseAirBuilder>(
    builder: &mut AB,
    out: &Word<AB::Var>,
    x: &WE<AB>,
    y: &WE<AB>,
    m: &E<AB>,
) -> WE<AB> {
    let inv = AB::F::from_u32(256).inverse();
    let mut carry = E::<AB>::ZERO;
    for i in 0..4 {
        carry = (x[i].clone() + y[i].clone() - out.0[i].into() + carry) * inv;
        builder.assert_bool(carry.clone());
    }
    let w = we::<AB>(out);
    range_u8(builder, &w, m);
    w
}

fn add3<AB: BaseAirBuilder>(
    builder: &mut AB,
    out: &Word<AB::Var>,
    x: &WE<AB>,
    y: &WE<AB>,
    z: &WE<AB>,
    m: &E<AB>,
) -> WE<AB> {
    let inv = AB::F::from_u32(256).inverse();
    let mut carry = E::<AB>::ZERO;
    for i in 0..4 {
        carry = (x[i].clone() + y[i].clone() + z[i].clone() - out.0[i].into() + carry) * inv;
        builder.assert_zero(
            carry.clone() * (carry.clone() - E::<AB>::ONE) * (carry.clone() - E::<AB>::from_u8(2)),
        );
    }
    let w = we::<AB>(out);
    range_u8(builder, &w, m);
    w
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

        let mut v: Vec<WE<AB>> = Vec::with_capacity(16);
        for i in 0..8 {
            v.push(we::<AB>(&local.cv[i]));
        }
        for iv in IV.iter().take(4) {
            let b = iv.to_le_bytes();
            v.push(core::array::from_fn(|k| m.clone() * AB::F::from_u8(b[k])));
        }
        v.push(we::<AB>(&local.counter));
        v.push(core::array::from_fn(|_| E::<AB>::ZERO));
        v.push(we::<AB>(&local.block_len));
        v.push(we::<AB>(&local.flags));
        let block: Vec<WE<AB>> = local.block.iter().map(|w| we::<AB>(w)).collect();
        for (r, sr) in schedule().iter().enumerate() {
            for (j, lane) in G_LANES.iter().enumerate() {
                let [a, b, c, d] = *lane;
                let g = &local.g[r][j];
                let mx = &block[sr[2 * j]];
                let my = &block[sr[2 * j + 1]];
                let a1 = add3(builder, &g.a1, &v[a], &v[b], mx, &m);
                let x1 = xor(builder, &g.x1, &v[d], &a1, &m);
                let d1 = rot_bytes::<AB>(x1, 2);
                let c1 = add2(builder, &g.c1, &v[c], &d1, &m);
                let x2 = xor(builder, &g.x2, &v[b], &c1, &m);
                let b1 = rot_bits(builder, &g.r2, &x2, 12, &m);
                let a2 = add3(builder, &g.a2, &a1, &b1, my, &m);
                let x3 = xor(builder, &g.x3, &d1, &a2, &m);
                let d2 = rot_bytes::<AB>(x3, 1);
                let c2 = add2(builder, &g.c2, &c1, &d2, &m);
                let x4 = xor(builder, &g.x4, &b1, &c2, &m);
                let b2 = rot_bits(builder, &g.r4, &x4, 7, &m);
                v[a] = a2;
                v[b] = b2;
                v[c] = c2;
                v[d] = d2;
            }
        }
        for i in 0..8 {
            let lo = v[i].clone();
            let hi = v[i + 8].clone();
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

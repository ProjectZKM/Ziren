//! The arithmetic fixture: one row proves one modular add, subtract and
//! multiply of two KoalaBear elements, under the stage.  It is the
//! differential test of [`crate::word`] against integer arithmetic, and the
//! unit of cost every recursion chip over bits is built from.

use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_matrix::dense::RowMajorMatrix;
use zkm_derive::AlignedBorrow;

use crate::word::{
    eval_add, eval_mul, eval_sub, exprs, fill_add, fill_mul, fill_sub, AddCols, MulCols, SubCols,
    Word, KB_BITS,
};

/// One row: the operands and the three results with their witnesses.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct KbArithCols<T> {
    /// The left operand.
    pub a: Word<T>,
    /// The right operand.
    pub b: Word<T>,
    /// `a + b mod p`.
    pub add: AddCols<T>,
    /// `a - b mod p`.
    pub sub: SubCols<T>,
    /// `a * b mod p`.
    pub mul: MulCols<T>,
}

/// Columns of [`KbArithCols`].
pub const NUM_KB_ARITH_COLS: usize = size_of::<KbArithCols<u8>>();

/// The fixture AIR.
#[derive(Clone, Copy, Debug, Default)]
pub struct KbArithAir;

impl<F> BaseAir<F> for KbArithAir {
    fn width(&self) -> usize {
        NUM_KB_ARITH_COLS
    }
}

impl<AB: AirBuilder> Air<AB> for KbArithAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &KbArithCols<AB::Var> = main.current_slice().borrow();
        for bit in local.a.iter().chain(local.b.iter()) {
            builder.assert_bool(*bit);
        }
        let a = exprs::<AB, KB_BITS>(&local.a);
        let b = exprs::<AB, KB_BITS>(&local.b);
        eval_add(builder, &a, &b, &local.add);
        eval_sub(builder, &a, &b, &local.sub);
        eval_mul(builder, &a, &b, &local.mul);
    }
}

/// The packed Boolean trace of `pairs`, one row each; `pairs.len()` is a
/// power of two.
///
/// Block `r / 64` of the trace is row `r / 64` of the matrix, and within a
/// word bit `r % 64` is row `r`, which is the layout
/// `Table::from_packed_bits` reads.
#[must_use]
pub fn generate_packed(pairs: &[(u32, u32)]) -> RowMajorMatrix<u64> {
    assert!(pairs.len().is_power_of_two(), "rows are padded to a power of two");
    let blocks = pairs.len().div_ceil(64);
    let mut words = vec![0u64; blocks * NUM_KB_ARITH_COLS];
    let mut row = vec![0u8; NUM_KB_ARITH_COLS];
    for (r, &(a, b)) in pairs.iter().enumerate() {
        row.fill(0);
        fill_row(a, b, &mut row);
        let block = &mut words[(r / 64) * NUM_KB_ARITH_COLS..(r / 64 + 1) * NUM_KB_ARITH_COLS];
        for (word, &bit) in block.iter_mut().zip(&row) {
            *word |= u64::from(bit) << (r % 64);
        }
    }
    RowMajorMatrix::new(words, NUM_KB_ARITH_COLS)
}

/// Fill `row` with the witness of `a` and `b`, returning the three results.
pub fn fill_row(a: u32, b: u32, row: &mut [u8]) -> (u32, u32, u32) {
    let cols: &mut KbArithCols<u8> = row.borrow_mut();
    cols.a = crate::word::bits_le::<KB_BITS>(u64::from(a));
    cols.b = crate::word::bits_le::<KB_BITS>(u64::from(b));
    let add = fill_add(a, b, &mut cols.add);
    let sub = fill_sub(a, b, &mut cols.sub);
    let mul = fill_mul(a, b, &mut cols.mul);
    (add, sub, mul)
}

#[cfg(test)]
mod tests {
    use p3_sumcheck::layout::Table;
    use p3_sumcheck::TableShape;

    use super::*;
    use crate::word::KB_PRIME;
    use crate::{keys, prove, security, verify_proof, BinarySchedule, F};

    /// Deterministic operand pairs below `p`.
    fn pairs(n: usize) -> Vec<(u32, u32)> {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            ((state >> 33) as u32) % KB_PRIME
        };
        (0..n).map(|_| (next(), next())).collect()
    }

    #[test]
    fn rows_match_integer_arithmetic() {
        let mut row = vec![0u8; NUM_KB_ARITH_COLS];
        for (a, b) in
            pairs(64).into_iter().chain([(KB_PRIME - 1, KB_PRIME - 1), (0, 0), (1, KB_PRIME - 1)])
        {
            let (add, sub, mul) = fill_row(a, b, &mut row);
            let (a, b, p) = (u64::from(a), u64::from(b), u64::from(KB_PRIME));
            assert_eq!(u64::from(add), (a + b) % p);
            assert_eq!(u64::from(sub), (a + p - b) % p);
            assert_eq!(u64::from(mul), (a * b) % p);
        }
    }

    /// `2^8` random rows prove and verify under the stage, and a trace with
    /// one operand bit flipped does not.
    #[test]
    fn arith_rows_prove_and_tampering_fails() {
        let log_height = 8;
        let air = KbArithAir;
        let shape = TableShape::new(log_height, NUM_KB_ARITH_COLS);
        let schedule = BinarySchedule::default();
        let config = schedule.config(&air, shape).expect("schedule fits the AIR");
        let (pk, vk) = keys(&config, &air).expect("keys");
        let bits = security(&config, &air, &vk, log_height, schedule.security_bits)
            .expect("the schedule reaches the target");
        let words = generate_packed(&pairs(1 << log_height));
        let started = std::time::Instant::now();
        let proof =
            prove(&config, &air, &pk, Table::<F>::from_packed_bits(words.clone(), log_height))
                .expect("proof");
        let prove_secs = started.elapsed().as_secs_f64();
        verify_proof(&config, &air, &vk, log_height, &proof).expect("verifies");
        println!(
            "arith 2^{log_height} rows x {NUM_KB_ARITH_COLS} bits: {bits:.2} bits, {} proof bytes, prove {prove_secs:.1} s",
            crate::encode(&proof).len()
        );

        let mut tampered = words;
        tampered.values[0] ^= 1;
        let rejected =
            match prove(&config, &air, &pk, Table::<F>::from_packed_bits(tampered, log_height)) {
                Err(_) => true,
                Ok(proof) => verify_proof(&config, &air, &vk, log_height, &proof).is_err(),
            };
        assert!(rejected, "a flipped operand bit must not verify");
    }
}

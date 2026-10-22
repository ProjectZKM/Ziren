use itertools::Itertools;
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;

use zkm_recursion_compiler::ir::{Builder, Config, Felt};
use zkm_recursion_core::air::RecursionPublicValues;

/// Assertions on recursion public values which represent a complete proof.
///
/// The assertions consist of checking all the expected boundary conditions from a compress proof
/// that represents the end of the recursion tower. The global hash chain must end at the digest
/// every shard's global challenge was derived from, and the shards' global sums must cancel.
pub(crate) fn assert_complete<C: Config<F = KoalaBear>>(
    builder: &mut Builder<C>,
    public_values: &RecursionPublicValues<Felt<C::F>>,
    is_complete: Felt<C::F>,
) {
    let RecursionPublicValues {
        deferred_proofs_digest,
        next_pc,
        start_shard,
        next_shard,
        start_execution_shard,
        start_reconstruct_deferred_digest,
        end_reconstruct_deferred_digest,
        global_chain_end,
        global_h_star,
        global_sum,
        contains_execution_shard,
        ..
    } = public_values;

    builder.assert_felt_eq(is_complete * (is_complete - C::F::ONE), C::F::ZERO);

    builder.assert_felt_eq(is_complete * *next_pc, C::F::ZERO);

    builder.assert_felt_eq(is_complete * (*start_shard - C::F::ONE), C::F::ZERO);

    builder.assert_felt_ne(is_complete * *next_shard, C::F::ONE);

    builder.assert_felt_eq(is_complete * (*contains_execution_shard - C::F::ONE), C::F::ZERO);
    builder.assert_felt_eq(is_complete * (*start_execution_shard - C::F::ONE), C::F::ZERO);

    for start_digest_word in start_reconstruct_deferred_digest {
        builder.assert_felt_eq(is_complete * *start_digest_word, C::F::ZERO);
    }

    for (end_digest_word, deferred_digest_word) in
        end_reconstruct_deferred_digest.iter().zip_eq(deferred_proofs_digest.iter())
    {
        builder
            .assert_felt_eq(is_complete * (*end_digest_word - *deferred_digest_word), C::F::ZERO);
    }

    for (end, h_star) in global_chain_end.iter().zip_eq(global_h_star.iter()) {
        builder.assert_felt_eq(is_complete * (*end - *h_star), C::F::ZERO);
    }

    for coefficient in global_sum {
        builder.assert_felt_eq(is_complete * *coefficient, C::F::ZERO);
    }
}

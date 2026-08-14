use std::fmt::Debug;
use std::iter::{repeat, zip};

use itertools::Itertools;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_koala_bear::KoalaBear;

use p3_bn254_fr::Bn254;
use p3_symmetric::Permutation;
use zkm_pcs::inner_perm;
use zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2;
use zkm_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Config, DslIr, Ext, Felt, Var},
};
use zkm_recursion_core::stark::{outer_perm, OUTER_MULTI_FIELD_CHALLENGER_WIDTH};
use zkm_recursion_core::{stark::KoalaBearPoseidon2Outer, DIGEST_SIZE};
use zkm_recursion_core::{HASH_RATE, PERMUTATION_WIDTH};

use crate::{
    challenger::{reduce_32, POSEIDON_2_BB_RATE},
    CircuitConfig,
};

pub trait FieldHasher<F: Field> {
    type Digest: Copy + Default + Eq + Ord + Copy + Debug + Send + Sync;

    fn constant_compress(input: [Self::Digest; 2]) -> Self::Digest;
}

pub trait Poseidon2KoalaBearHasherVariable<C: CircuitConfig> {
    fn poseidon2_permute(
        builder: &mut Builder<C>,
        state: [Felt<C::F>; PERMUTATION_WIDTH],
    ) -> [Felt<C::F>; PERMUTATION_WIDTH];

    /// Applies the Poseidon2 hash function to the given array.
    ///
    /// Reference: [p3_symmetric::PaddingFreeSponge]
    fn poseidon2_hash(builder: &mut Builder<C>, input: &[Felt<C::F>]) -> [Felt<C::F>; DIGEST_SIZE] {
        // static_assert(RATE < WIDTH)
        let mut state = core::array::from_fn(|_| builder.eval(C::F::ZERO));
        for input_chunk in input.chunks(HASH_RATE) {
            state[..input_chunk.len()].copy_from_slice(input_chunk);
            state = Self::poseidon2_permute(builder, state);
        }
        let digest: [Felt<C::F>; DIGEST_SIZE] = state[..DIGEST_SIZE].try_into().unwrap();
        digest
    }
}

pub trait FieldHasherVariable<C: CircuitConfig>: FieldHasher<C::F> {
    type DigestVariable: Clone + Copy;

    /// Whether this ring carries the jagged geometry HASH-BIND
    /// (`modified_commitment = compress([raw_root, hash(counts)])`) and must
    /// re-bind it in-circuit inside
    /// [`crate::shard_basefold::BasefoldShardVerifier::verify_shard`].
    ///
    /// The INNER KoalaBear rings (core/compress/shrink) carry a real MODIFIED
    /// (FS-observed) digest distinct from the RAW commit root — they MUST run
    /// the rebind (that's where the count↔commitment soundness lives), so the
    /// default is `true`.
    ///
    /// The OUTER BN254 (gnark wrap) ring's commitment IS the raw wrap root —
    /// there are NO jagged counts to hash-bind for the wrap proof, so its lift
    /// carries `modified == original` (a documented placeholder, see
    /// `lift_jagged_basefold_bundle_outer`).  Running the rebind there would
    /// assert `compress([original, hash(counts)]) == original`, which is FALSE
    /// (a BN254 Poseidon2 digest can never equal one of its preimages) — so the
    /// outer impl overrides this to `false`.
    fn jagged_hash_bind_in_circuit() -> bool {
        true
    }

    fn hash(builder: &mut Builder<C>, input: &[Felt<C::F>]) -> Self::DigestVariable;

    fn compress(builder: &mut Builder<C>, input: [Self::DigestVariable; 2])
        -> Self::DigestVariable;

    fn assert_digest_eq(builder: &mut Builder<C>, a: Self::DigestVariable, b: Self::DigestVariable);

    // Encountered many issues trying to make the following two parametrically polymorphic.
    fn select_chain_digest(
        builder: &mut Builder<C>,
        should_swap: C::Bit,
        input: [Self::DigestVariable; 2],
    ) -> [Self::DigestVariable; 2];

    fn print_digest(builder: &mut Builder<C>, digest: Self::DigestVariable);

    /// Promote a *constant* raw digest (host-side [`FieldHasher::Digest`])
    /// into the in-circuit [`Self::DigestVariable`] via builder constants.
    /// Inner (KoalaBear): `[KoalaBear;8]` -> `[Felt<KoalaBear>;8]`.
    /// Outer (BN254): `[Bn254;1]` -> `[Var<Bn254>;1]`.
    ///
    /// #H (BaseFold-over-BN254 wrap port): the lift paths carry the
    /// host BaseFold bundle's digests as raw field constants (not
    /// witness-stream reads), so this bridges raw -> variable in a
    /// digest-type-generic way.
    fn const_digest(
        builder: &mut Builder<C>,
        digest: <Self as FieldHasher<C::F>>::Digest,
    ) -> Self::DigestVariable;

    /// Build a *raw* host digest ([`FieldHasher::Digest`]) from a
    /// host-side inner KoalaBear root ([`KoalaBear; 8`]).  Used by the
    /// inner BaseFold bundle lift (which reads KoalaBear MMCS roots).
    /// Inner: identity.  Outer (BN254): unreachable from the inner
    /// bundle path — returns the default digest (the OUTER ring lifts
    /// its BN254 bundle through a dedicated path; the inner-root
    /// conversion is never the soundness-binding digest there).
    fn digest_from_koalabear_root(
        root: [p3_koala_bear::KoalaBear; 8],
    ) -> <Self as FieldHasher<C::F>>::Digest;

    /// #H (BaseFold-over-BN254 wrap port): ring-aware lift of a host
    /// `EvaluationProof::Bytes` payload into the in-circuit
    /// `JaggedPcsProofVariable`.
    ///
    /// The INNER ring (`KoalaBearPoseidon2`) payload is a
    /// `JaggedBasefoldBundle` (KoalaBear MMCS) — the default impl routes to
    /// [`crate::jagged_pcs_lift::lift_evaluation_proof_bytes`].
    ///
    /// The OUTER ring (`KoalaBearPoseidon2Outer`) payload is a
    /// `JaggedBasefoldBundleGeneric<OuterValMmcs>` carrying REAL BN254
    /// commitments — the override deserializes the outer bundle and lifts its
    /// BN254 round commitments via
    /// [`crate::shard_level_witness::lift_jagged_basefold_bundle_outer`], so
    /// the in-circuit challenger observes the same BN254 digests the host
    /// outer verifier absorbs (the all-zero placeholder for those
    /// commitments was the residual gnark constraint failure).
    //
    // Both lift dispatchers are REQUIRED (no default body).  A
    // default that delegated to the inner const/witness lifts would need
    // `Self::DigestVariable = [Felt;8]`, and a restrictive where-clause on a
    // trait method propagates to EVERY caller (breaking the SC-generic wrap
    // core for the outer ring).  Making them required lets each ring's impl
    // supply a body specialized to its concrete `DigestVariable`.
    fn lift_evaluation_proof_bytes_dispatch(
        builder: &mut Builder<C>,
        bytes: &[u8],
        max_log_row_count: usize,
        column_counts_by_round: &[Vec<usize>],
    ) -> crate::jagged_circuit::JaggedPcsProofVariable<
        crate::basefold_verifier::RecursiveBasefoldProof<
            Felt<C::F>,
            Ext<C::F, C::EF>,
            Self::DigestVariable,
        >,
        Self::DigestVariable,
        C::F,
        C::EF,
    >
    where
        C: CircuitConfig<F = KoalaBear, EF = zkm_pcs::InnerChallenge>,
        Self: Sized;

    /// Ring-aware Bundle dispatch: lift a WITNESSED inner
    /// jagged-basefold bundle (the value-independent production path) into the
    /// in-circuit [`crate::jagged_circuit::JaggedPcsProofVariable`].
    ///
    /// The INNER ring witnesses the bundle via
    /// [`crate::shard_level_witness::lift_jagged_basefold_bundle`] (digests as
    /// `[Felt;8]`).  The OUTER ring (`KoalaBearPoseidon2Outer`) supplies a
    /// structural placeholder: its wrap shard proof is always carried as
    /// `EvaluationProof::Bytes` (BN254), so the `LiftedEvalProof::Bundle` arm is
    /// dead for the outer instantiation and never executed — the override only
    /// needs to TYPE-CHECK with `Self::DigestVariable = [Var<Bn254>; 1]`.  This
    /// is the escape hatch that lets the SC-generic
    /// `verify_wrap_basefold_core` compile for both rings.
    #[allow(clippy::too_many_arguments)]
    fn lift_bundle_dispatch(
        builder: &mut Builder<C>,
        host: &zkm_pcs::jagged_pcs::jagged::JaggedBasefoldBundle,
        basefold_proof: crate::basefold_verifier::RecursiveBasefoldProof<
            Felt<C::F>,
            Ext<C::F, C::EF>,
            [Felt<C::F>; 8],
        >,
        sumcheck: crate::partial_sumcheck::PartialSumcheckProof<Ext<C::F, C::EF>>,
        jagged_eval: crate::partial_sumcheck::PartialSumcheckProof<Ext<C::F, C::EF>>,
        expected_eval: Ext<C::F, C::EF>,
        commit_root: [Felt<C::F>; 8],
        // Hash-bind: the MODIFIED (FS-observed) digest = main_commitment.
        // The inner impl threads it into modified_commitments; the outer impl
        // (dead bundle arm) ignores it.
        modified_commitment: [Felt<C::F>; 8],
        // Rounds committed BEFORE the main one, as (raw root, key digest) — the
        // preprocessed round.  Empty on a machine with no preprocessed traces.
        preceding_commitments: &[([Felt<C::F>; 8], [Felt<C::F>; 8])],
        // Each round's stacking-padding column heights.
        padding_heights: &[Vec<Felt<C::F>>],
        max_log_row_count: usize,
        column_counts_by_round: &[Vec<usize>],
        row_counts_by_round: Option<&[Vec<usize>]>,
        // Per-chip WITNESSED height felts (2^log_h, from the
        // opened `degree`) so the inner bundle lift reconstructs
        // col_prefix_sums / row_counts value-independently.  The outer
        // (BN254) impl's bundle arm is dead and ignores it.
        chip_height_felts: Option<&[Felt<C::F>]>,
    ) -> crate::jagged_circuit::JaggedPcsProofVariable<
        crate::basefold_verifier::RecursiveBasefoldProof<
            Felt<C::F>,
            Ext<C::F, C::EF>,
            Self::DigestVariable,
        >,
        Self::DigestVariable,
        C::F,
        C::EF,
    >
    where
        C: CircuitConfig<F = KoalaBear, EF = zkm_pcs::InnerChallenge>,
        Self: Sized;

    /// P2c-for-outer (value-independent gnark wrap): lift a WITNESSED OUTER
    /// (BN254) jagged-basefold bundle into the in-circuit
    /// [`crate::jagged_circuit::JaggedPcsProofVariable`].
    ///
    /// The OUTER ring (`KoalaBearPoseidon2Outer`) routes to
    /// [`crate::shard_level_witness::lift_jagged_basefold_bundle_outer`] with the
    /// witnessed proof values (no const-bake → the gnark R1CS is
    /// value-independent).  The INNER ring never produces a
    /// `LiftedEvalProof::OuterBundle`, so its impl is a dead structural
    /// placeholder — the escape hatch that lets the SC-generic
    /// `verify_wrap_basefold_core` compile for both rings (mirrors
    /// `lift_bundle_dispatch`).
    #[allow(clippy::too_many_arguments)]
    fn lift_outer_bundle_dispatch(
        builder: &mut Builder<C>,
        host: &zkm_pcs::jagged_pcs::jagged::JaggedBasefoldBundleGeneric<
            zkm_recursion_core::stark::OuterValMmcs,
        >,
        basefold_proof: crate::basefold_verifier::RecursiveBasefoldProof<
            Felt<C::F>,
            Ext<C::F, C::EF>,
            [zkm_recursion_compiler::ir::Var<C::N>; 1],
        >,
        sumcheck: crate::partial_sumcheck::PartialSumcheckProof<Ext<C::F, C::EF>>,
        jagged_eval: crate::partial_sumcheck::PartialSumcheckProof<Ext<C::F, C::EF>>,
        expected_eval: Ext<C::F, C::EF>,
        commit_root: [zkm_recursion_compiler::ir::Var<C::N>; 1],
        max_log_row_count: usize,
        column_counts_by_round: &[Vec<usize>],
        row_counts_by_round: Option<&[Vec<usize>]>,
    ) -> crate::jagged_circuit::JaggedPcsProofVariable<
        crate::basefold_verifier::RecursiveBasefoldProof<
            Felt<C::F>,
            Ext<C::F, C::EF>,
            Self::DigestVariable,
        >,
        Self::DigestVariable,
        C::F,
        C::EF,
    >
    where
        C: CircuitConfig<F = KoalaBear, EF = zkm_pcs::InnerChallenge>,
        Self: Sized;

    /// Ring-aware chip-height-bits derivation for the SC-generic wrap
    /// verifier.  INNER ring: WITNESSED (from the opened `degree`,
    /// value-independent — keeps the witnessed vk verifiable).  OUTER/gnark ring:
    /// BAKED from the RAW `chip_heights` — the gnark constraint compiler has
    /// no `CircuitV2HintBitsF`, and the gnark circuit is a single
    /// artifact whose inputs have canonical shapes, so value-dependence
    /// is moot there (earlier baked behavior preserved).
    fn chip_height_bits_dispatch(
        builder: &mut Builder<C>,
        chip_names: &[String],
        opened_values: &crate::basefold_chip_opened_values::BasefoldShardOpenedValuesVariable<C>,
        chip_heights: &std::collections::BTreeMap<String, usize>,
        max_log_row_count: usize,
    ) -> Vec<(String, Vec<Felt<C::F>>)>
    where
        C: CircuitConfig<F = KoalaBear, EF = zkm_pcs::InnerChallenge>,
        Self: Sized;
}

impl FieldHasher<KoalaBear> for KoalaBearPoseidon2 {
    type Digest = [KoalaBear; DIGEST_SIZE];

    fn constant_compress(input: [Self::Digest; 2]) -> Self::Digest {
        let mut pre_iter = input.into_iter().flatten().chain(repeat(KoalaBear::ZERO));
        let mut pre = core::array::from_fn(move |_| pre_iter.next().unwrap());
        (inner_perm()).permute_mut(&mut pre);
        pre[..DIGEST_SIZE].try_into().unwrap()
    }
}

impl<C: CircuitConfig<F = KoalaBear>> Poseidon2KoalaBearHasherVariable<C> for KoalaBearPoseidon2 {
    fn poseidon2_permute(
        builder: &mut Builder<C>,
        input: [Felt<<C>::F>; PERMUTATION_WIDTH],
    ) -> [Felt<<C>::F>; PERMUTATION_WIDTH] {
        builder.poseidon2_permute_v2(input)
    }
}

impl<C: CircuitConfig> Poseidon2KoalaBearHasherVariable<C> for KoalaBearPoseidon2Outer {
    fn poseidon2_permute(
        builder: &mut Builder<C>,
        state: [Felt<<C>::F>; PERMUTATION_WIDTH],
    ) -> [Felt<<C>::F>; PERMUTATION_WIDTH] {
        let state: [Felt<_>; PERMUTATION_WIDTH] = state.map(|x| builder.eval(x));
        builder.push_op(DslIr::CircuitPoseidon2PermuteKoalaBear(Box::new(state)));
        state
    }
}

impl<C: CircuitConfig<F = KoalaBear, Bit = Felt<KoalaBear>>> FieldHasherVariable<C>
    for KoalaBearPoseidon2
{
    type DigestVariable = [Felt<KoalaBear>; DIGEST_SIZE];

    fn hash(builder: &mut Builder<C>, input: &[Felt<<C as Config>::F>]) -> Self::DigestVariable {
        <Self as Poseidon2KoalaBearHasherVariable<C>>::poseidon2_hash(builder, input)
    }

    fn compress(
        builder: &mut Builder<C>,
        input: [Self::DigestVariable; 2],
    ) -> Self::DigestVariable {
        builder.poseidon2_compress_v2(input.into_iter().flatten())
    }

    fn assert_digest_eq(
        builder: &mut Builder<C>,
        a: Self::DigestVariable,
        b: Self::DigestVariable,
    ) {
        zip(a, b).for_each(|(e1, e2)| builder.assert_felt_eq(e1, e2));
    }

    fn select_chain_digest(
        builder: &mut Builder<C>,
        should_swap: <C as CircuitConfig>::Bit,
        input: [Self::DigestVariable; 2],
    ) -> [Self::DigestVariable; 2] {
        let result0: [Felt<KoalaBear>; DIGEST_SIZE] = core::array::from_fn(|_| builder.uninit());
        let result1: [Felt<KoalaBear>; DIGEST_SIZE] = core::array::from_fn(|_| builder.uninit());

        (0..DIGEST_SIZE).for_each(|i| {
            builder.push_op(DslIr::Select(
                should_swap,
                result0[i],
                result1[i],
                input[0][i],
                input[1][i],
            ));
        });

        [result0, result1]
    }

    fn print_digest(builder: &mut Builder<C>, digest: Self::DigestVariable) {
        for d in digest.iter() {
            builder.print_f(*d);
        }
    }

    fn const_digest(
        builder: &mut Builder<C>,
        digest: <Self as FieldHasher<KoalaBear>>::Digest,
    ) -> Self::DigestVariable {
        core::array::from_fn(|i| builder.constant(digest[i]))
    }

    fn digest_from_koalabear_root(
        root: [KoalaBear; 8],
    ) -> <Self as FieldHasher<KoalaBear>>::Digest {
        // Inner digest IS [KoalaBear; 8] — identity.
        root
    }

    // The INNER ring's lift dispatchers.  `Self::DigestVariable`
    // is concretely `[Felt<KoalaBear>; 8]` here, so the const/witness lifts
    // (which require that) type-check directly.
    fn lift_evaluation_proof_bytes_dispatch(
        builder: &mut Builder<C>,
        bytes: &[u8],
        max_log_row_count: usize,
        column_counts_by_round: &[Vec<usize>],
    ) -> crate::jagged_circuit::JaggedPcsProofVariable<
        crate::basefold_verifier::RecursiveBasefoldProof<
            Felt<C::F>,
            Ext<C::F, C::EF>,
            Self::DigestVariable,
        >,
        Self::DigestVariable,
        C::F,
        C::EF,
    >
    where
        C: CircuitConfig<F = KoalaBear, EF = zkm_pcs::InnerChallenge>,
        Self: Sized,
    {
        crate::jagged_pcs_lift::lift_evaluation_proof_bytes::<C, Self>(
            builder,
            bytes,
            max_log_row_count,
            column_counts_by_round,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn lift_bundle_dispatch(
        builder: &mut Builder<C>,
        host: &zkm_pcs::jagged_pcs::jagged::JaggedBasefoldBundle,
        basefold_proof: crate::basefold_verifier::RecursiveBasefoldProof<
            Felt<C::F>,
            Ext<C::F, C::EF>,
            [Felt<C::F>; 8],
        >,
        sumcheck: crate::partial_sumcheck::PartialSumcheckProof<Ext<C::F, C::EF>>,
        jagged_eval: crate::partial_sumcheck::PartialSumcheckProof<Ext<C::F, C::EF>>,
        expected_eval: Ext<C::F, C::EF>,
        commit_root: [Felt<C::F>; 8],
        modified_commitment: [Felt<C::F>; 8],
        // Rounds committed BEFORE the main one, as (raw root, key digest) — the
        // preprocessed round.  Empty on a machine with no preprocessed traces.
        preceding_commitments: &[([Felt<C::F>; 8], [Felt<C::F>; 8])],
        // Each round's stacking-padding column heights.
        padding_heights: &[Vec<Felt<C::F>>],
        max_log_row_count: usize,
        column_counts_by_round: &[Vec<usize>],
        row_counts_by_round: Option<&[Vec<usize>]>,
        chip_height_felts: Option<&[Felt<C::F>]>,
    ) -> crate::jagged_circuit::JaggedPcsProofVariable<
        crate::basefold_verifier::RecursiveBasefoldProof<
            Felt<C::F>,
            Ext<C::F, C::EF>,
            Self::DigestVariable,
        >,
        Self::DigestVariable,
        C::F,
        C::EF,
    >
    where
        C: CircuitConfig<F = KoalaBear, EF = zkm_pcs::InnerChallenge>,
        Self: Sized,
    {
        crate::shard_level_witness::lift_jagged_basefold_bundle::<C, Self>(
            builder,
            host,
            basefold_proof,
            sumcheck,
            jagged_eval,
            expected_eval,
            commit_root,
            modified_commitment,
            preceding_commitments,
            padding_heights,
            max_log_row_count,
            column_counts_by_round,
            row_counts_by_round,
            // Witnessed per-chip heights forwarded from the
            // SC-generic wrap verifier (None = baked fallback).
            chip_height_felts,
        )
    }

    /// P2c-for-outer: the INNER ring never carries a `LiftedEvalProof::Outer
    /// Bundle` (it's an inner KoalaBear bundle, lifted via `lift_bundle_dispatch`).
    /// This arm is dead — build a structural `[Felt;8]` placeholder so the
    /// SC-generic `verify_wrap_basefold_core` type-checks for the inner ring.
    #[allow(clippy::too_many_arguments)]
    fn lift_outer_bundle_dispatch(
        builder: &mut Builder<C>,
        _host: &zkm_pcs::jagged_pcs::jagged::JaggedBasefoldBundleGeneric<
            zkm_recursion_core::stark::OuterValMmcs,
        >,
        _basefold_proof: crate::basefold_verifier::RecursiveBasefoldProof<
            Felt<C::F>,
            Ext<C::F, C::EF>,
            [zkm_recursion_compiler::ir::Var<C::N>; 1],
        >,
        _sumcheck: crate::partial_sumcheck::PartialSumcheckProof<Ext<C::F, C::EF>>,
        _jagged_eval: crate::partial_sumcheck::PartialSumcheckProof<Ext<C::F, C::EF>>,
        _expected_eval: Ext<C::F, C::EF>,
        _commit_root: [zkm_recursion_compiler::ir::Var<C::N>; 1],
        max_log_row_count: usize,
        column_counts_by_round: &[Vec<usize>],
        _row_counts_by_round: Option<&[Vec<usize>]>,
    ) -> crate::jagged_circuit::JaggedPcsProofVariable<
        crate::basefold_verifier::RecursiveBasefoldProof<
            Felt<C::F>,
            Ext<C::F, C::EF>,
            Self::DigestVariable,
        >,
        Self::DigestVariable,
        C::F,
        C::EF,
    >
    where
        C: CircuitConfig<F = KoalaBear, EF = zkm_pcs::InnerChallenge>,
        Self: Sized,
    {
        crate::jagged_pcs_lift::lift_empty_placeholder::<C, Self>(
            builder,
            max_log_row_count,
            column_counts_by_round,
        )
    }

    fn chip_height_bits_dispatch(
        builder: &mut Builder<C>,
        chip_names: &[String],
        opened_values: &crate::basefold_chip_opened_values::BasefoldShardOpenedValuesVariable<C>,
        _chip_heights: &std::collections::BTreeMap<String, usize>,
        max_log_row_count: usize,
    ) -> Vec<(String, Vec<Felt<C::F>>)>
    where
        C: CircuitConfig<F = KoalaBear, EF = zkm_pcs::InnerChallenge>,
    {
        // INNER ring: WITNESSED (value-independent).
        crate::shard_proof_variable_lift::chip_height_bits_from_opened_degrees::<C>(
            builder,
            chip_names,
            opened_values,
            max_log_row_count,
        )
    }
}

pub const BN254_DIGEST_SIZE: usize = 1;

impl FieldHasher<KoalaBear> for KoalaBearPoseidon2Outer {
    type Digest = [Bn254; BN254_DIGEST_SIZE];

    fn constant_compress(input: [Self::Digest; 2]) -> Self::Digest {
        let mut state = [input[0][0], input[1][0], Bn254::ZERO];
        outer_perm().permute_mut(&mut state);
        [state[0]; BN254_DIGEST_SIZE]
    }
}

impl<C: CircuitConfig<F = KoalaBear, N = Bn254, Bit = Var<Bn254>>> FieldHasherVariable<C>
    for KoalaBearPoseidon2Outer
{
    type DigestVariable = [Var<Bn254>; BN254_DIGEST_SIZE];

    /// OUTER (gnark wrap) ring: the wrap commitment is the RAW BN254 root with
    /// no jagged counts to hash-bind, so the lift carries `modified == original`
    /// and the in-circuit rebind must be skipped (else it would assert
    /// `compress([original, hash]) == original`, the gnark AssertEqV failure).
    fn jagged_hash_bind_in_circuit() -> bool {
        false
    }

    fn hash(builder: &mut Builder<C>, input: &[Felt<<C as Config>::F>]) -> Self::DigestVariable {
        assert!(C::N::bits() == p3_bn254_fr::Bn254::bits());
        assert!(C::F::bits() == p3_koala_bear::KoalaBear::bits());
        let num_f_elms = C::N::bits() / C::F::bits();
        let mut state: [Var<C::N>; OUTER_MULTI_FIELD_CHALLENGER_WIDTH] =
            [builder.eval(C::N::ZERO), builder.eval(C::N::ZERO), builder.eval(C::N::ZERO)];
        for block_chunk in &input.iter().chunks(POSEIDON_2_BB_RATE) {
            for (chunk_id, chunk) in (&block_chunk.chunks(num_f_elms)).into_iter().enumerate() {
                let chunk = chunk.copied().collect::<Vec<_>>();
                state[chunk_id] = reduce_32(builder, chunk.as_slice());
            }
            builder.push_op(DslIr::CircuitPoseidon2Permute(state))
        }

        [state[0]; BN254_DIGEST_SIZE]
    }

    fn compress(
        builder: &mut Builder<C>,
        input: [Self::DigestVariable; 2],
    ) -> Self::DigestVariable {
        let state: [Var<C::N>; OUTER_MULTI_FIELD_CHALLENGER_WIDTH] =
            [builder.eval(input[0][0]), builder.eval(input[1][0]), builder.eval(C::N::ZERO)];
        builder.push_op(DslIr::CircuitPoseidon2Permute(state));
        [state[0]; BN254_DIGEST_SIZE]
    }

    fn assert_digest_eq(
        builder: &mut Builder<C>,
        a: Self::DigestVariable,
        b: Self::DigestVariable,
    ) {
        zip(a, b).for_each(|(e1, e2)| builder.assert_var_eq(e1, e2));
    }

    fn select_chain_digest(
        builder: &mut Builder<C>,
        should_swap: <C as CircuitConfig>::Bit,
        input: [Self::DigestVariable; 2],
    ) -> [Self::DigestVariable; 2] {
        let result0: [Var<_>; BN254_DIGEST_SIZE] = core::array::from_fn(|j| {
            let result = builder.uninit();
            builder.push_op(DslIr::CircuitSelectV(should_swap, input[1][j], input[0][j], result));
            result
        });
        let result1: [Var<_>; BN254_DIGEST_SIZE] = core::array::from_fn(|j| {
            let result = builder.uninit();
            builder.push_op(DslIr::CircuitSelectV(should_swap, input[0][j], input[1][j], result));
            result
        });

        [result0, result1]
    }

    fn print_digest(builder: &mut Builder<C>, digest: Self::DigestVariable) {
        for d in digest.iter() {
            builder.print_v(*d);
        }
    }

    fn const_digest(
        builder: &mut Builder<C>,
        digest: <Self as FieldHasher<KoalaBear>>::Digest,
    ) -> Self::DigestVariable {
        core::array::from_fn(|i| builder.constant(digest[i]))
    }

    fn digest_from_koalabear_root(
        _root: [KoalaBear; 8],
    ) -> <Self as FieldHasher<KoalaBear>>::Digest {
        // OUTER ring digests are BN254 and come from the dedicated
        // outer bundle lift; the inner-KoalaBear-root conversion is
        // never the binding digest here.
        <Self as FieldHasher<KoalaBear>>::Digest::default()
    }

    fn lift_evaluation_proof_bytes_dispatch(
        builder: &mut Builder<C>,
        bytes: &[u8],
        max_log_row_count: usize,
        column_counts_by_round: &[Vec<usize>],
    ) -> crate::jagged_circuit::JaggedPcsProofVariable<
        crate::basefold_verifier::RecursiveBasefoldProof<
            Felt<C::F>,
            Ext<C::F, C::EF>,
            Self::DigestVariable,
        >,
        Self::DigestVariable,
        C::F,
        C::EF,
    >
    where
        C: CircuitConfig<F = KoalaBear, EF = zkm_pcs::InnerChallenge>,
        Self: Sized,
    {
        // OUTER ring: deserialize the BN254 bundle and lift its real
        // commitments.  Falls back to the structural zero placeholder only
        // if deserialization fails (empty/placeholder paths).
        //
        // P2c-for-outer: the PRODUCTION outer wrap path no longer reaches this
        // bytes lift — `BasefoldShardProof::read` now witnesses the outer bundle
        // into a `LiftedEvalProof::OuterBundle` (value-independent), and
        // `verify_wrap_basefold_core` lifts it via `lift_outer_bundle_dispatch`.
        // This bytes arm survives only as the empty/deserialize-failure fallback
        // (the OuterBundle read returns None there), so it builds the structural
        // placeholder (it has no witnessed values to thread).
        let _ = bytes;
        crate::jagged_pcs_lift::lift_empty_placeholder::<C, Self>(
            builder,
            max_log_row_count,
            column_counts_by_round,
        )
    }

    /// The OUTER ring never carries a `LiftedEvalProof::Bundle`
    /// (its wrap shard proof is `Bytes`/BN254), so this arm is dead — build a
    /// structural `[Var<Bn254>;1]` placeholder so the SC-generic
    /// `verify_wrap_basefold_core` type-checks for the outer instantiation.
    #[allow(clippy::too_many_arguments)]
    fn lift_bundle_dispatch(
        builder: &mut Builder<C>,
        _host: &zkm_pcs::jagged_pcs::jagged::JaggedBasefoldBundle,
        _basefold_proof: crate::basefold_verifier::RecursiveBasefoldProof<
            Felt<C::F>,
            Ext<C::F, C::EF>,
            [Felt<C::F>; 8],
        >,
        _sumcheck: crate::partial_sumcheck::PartialSumcheckProof<Ext<C::F, C::EF>>,
        _jagged_eval: crate::partial_sumcheck::PartialSumcheckProof<Ext<C::F, C::EF>>,
        _expected_eval: Ext<C::F, C::EF>,
        _commit_root: [Felt<C::F>; 8],
        _modified_commitment: [Felt<C::F>; 8],
        _preceding_commitments: &[([Felt<C::F>; 8], [Felt<C::F>; 8])],
        _padding_heights: &[Vec<Felt<C::F>>],
        max_log_row_count: usize,
        column_counts_by_round: &[Vec<usize>],
        _row_counts_by_round: Option<&[Vec<usize>]>,
        _chip_height_felts: Option<&[Felt<C::F>]>,
    ) -> crate::jagged_circuit::JaggedPcsProofVariable<
        crate::basefold_verifier::RecursiveBasefoldProof<
            Felt<C::F>,
            Ext<C::F, C::EF>,
            Self::DigestVariable,
        >,
        Self::DigestVariable,
        C::F,
        C::EF,
    >
    where
        C: CircuitConfig<F = KoalaBear, EF = zkm_pcs::InnerChallenge>,
        Self: Sized,
    {
        crate::jagged_pcs_lift::lift_empty_placeholder::<C, Self>(
            builder,
            max_log_row_count,
            column_counts_by_round,
        )
    }

    /// P2c-for-outer: lift the WITNESSED outer BN254 bundle (value-independent
    /// gnark wrap).  Routes to `lift_jagged_basefold_bundle_outer` with the
    /// witnessed proof values pre-read from the gnark stream.
    #[allow(clippy::too_many_arguments)]
    fn lift_outer_bundle_dispatch(
        builder: &mut Builder<C>,
        host: &zkm_pcs::jagged_pcs::jagged::JaggedBasefoldBundleGeneric<
            zkm_recursion_core::stark::OuterValMmcs,
        >,
        basefold_proof: crate::basefold_verifier::RecursiveBasefoldProof<
            Felt<C::F>,
            Ext<C::F, C::EF>,
            [zkm_recursion_compiler::ir::Var<C::N>; 1],
        >,
        sumcheck: crate::partial_sumcheck::PartialSumcheckProof<Ext<C::F, C::EF>>,
        jagged_eval: crate::partial_sumcheck::PartialSumcheckProof<Ext<C::F, C::EF>>,
        expected_eval: Ext<C::F, C::EF>,
        commit_root: [zkm_recursion_compiler::ir::Var<C::N>; 1],
        max_log_row_count: usize,
        column_counts_by_round: &[Vec<usize>],
        row_counts_by_round: Option<&[Vec<usize>]>,
    ) -> crate::jagged_circuit::JaggedPcsProofVariable<
        crate::basefold_verifier::RecursiveBasefoldProof<
            Felt<C::F>,
            Ext<C::F, C::EF>,
            Self::DigestVariable,
        >,
        Self::DigestVariable,
        C::F,
        C::EF,
    >
    where
        C: CircuitConfig<F = KoalaBear, EF = zkm_pcs::InnerChallenge>,
        Self: Sized,
    {
        crate::shard_level_witness::lift_jagged_basefold_bundle_outer::<C>(
            builder,
            host,
            basefold_proof,
            sumcheck,
            jagged_eval,
            expected_eval,
            commit_root,
            max_log_row_count,
            column_counts_by_round,
            row_counts_by_round,
        )
    }

    fn chip_height_bits_dispatch(
        builder: &mut Builder<C>,
        chip_names: &[String],
        _opened_values: &crate::basefold_chip_opened_values::BasefoldShardOpenedValuesVariable<C>,
        chip_heights: &std::collections::BTreeMap<String, usize>,
        max_log_row_count: usize,
    ) -> Vec<(String, Vec<Felt<C::F>>)>
    where
        C: CircuitConfig<F = KoalaBear, EF = zkm_pcs::InnerChallenge>,
    {
        // OUTER/gnark ring: BAKED from the RAW chip_heights — the gnark
        // constraint compiler has no CircuitV2HintBitsF, and the single
        // gnark artifact's inputs have canonical shapes (earlier baked wrap
        // behavior preserved on this ring).
        crate::shard_proof_variable_lift::chip_height_bits_from_heights::<C>(
            builder,
            chip_names,
            chip_heights,
            max_log_row_count,
        )
    }
}

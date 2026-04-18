//! Per-chip jagged BaseFold (E3 scaffold).
//!
//! Port target: [`/tmp/sp1/slop/crates/jagged/`](file:///tmp/sp1/slop/crates/jagged/)
//! (2265 LOC across 10 files).  This module is the Ziren-side
//! equivalent of `slop_jagged::basefold` — committing per-chip
//! `PaddedMle`s instead of a single materialized dense vector.
//!
//! # Architectural shift from D1 (dense) to E3 (per-chip)
//!
//! **D1 (current default `prove_jagged_basefold`):**
//!
//! ```text
//! chip_traces
//!   ↓ materialize_dense_jagged (4N bytes)
//! dense_q: Vec<F>
//!   ├→ .clone() ── commit_basefold_late_binding ─→ BaseFold stacked PCS (single Mle)
//!   └→ &dense_q ── prove_jagged_reduction ──────→ z* (dim = log_dense_size), q_at_z
//!                                                  ↓
//!                                         open BaseFold at z* (single point)
//! ```
//!
//! Memory profile: 2 × 4N for dense + its clone, plus stacked PCS
//! stripes (4 MB / stripe).  OOM-safe because of the stripe streaming.
//!
//! **E3 (target — `prove_jagged_basefold_per_chip`):**
//!
//! ```text
//! chip_traces
//!   ↓ pad each to PaddedMle<F> over max_log_row_count variables
//! per_chip_mles: Vec<PaddedMle<F>>
//!   ↓ commit via Stacked PCS (heterogeneous batch — already works)
//! commitment + per-chip prover data
//!   ↓ per-chip row-MLE evaluations y_{c,j} (same as D1 path)
//!   ↓ jagged sumcheck reduction (NEW — see port checklist below)
//! z_row (dim = max_log_row_count), z_col (dim = log_total_cols), per-chip eval claims
//!   ↓ BaseFold open at (z_row, z_col) — stacked PCS natively supports this
//! ```
//!
//! Memory profile: eliminates the dense_q 4N allocation entirely.
//! Per-chip data stays in its original layout throughout.
//!
//! # Port checklist
//!
//! | SP1 file | LOC | Purpose | Ziren target |
//! |---|---|---|---|
//! | `jagged/src/populate.rs` | 23 | partial_jagged_multilinear builder | TODO |
//! | `jagged/src/long.rs` | 211 | LongMle: virtual concatenation of per-chip MLEs | ✅ [`long`] (Ziren-convention variant: first-var-first, MSB fold dispatches on shape) |
//! | `jagged/src/hadamard.rs` | 224 | HadamardProduct sumcheck term (base · jagged) | TODO |
//! | `jagged/src/poly.rs` | 763 | Jagged polynomial representation + evals | TODO |
//! | `jagged/src/multi_to_uni.rs` | 45 | Multivariate → univariate sumcheck conversion | TODO |
//! | `jagged/src/sumcheck.rs` | 39 | jagged_sumcheck_poly wrapper | TODO |
//! | `jagged/src/prover.rs:106-160` | 55 | commit_multilinears (+ chip-info-hash mix-in) | ✅ [`commit_multilinears_per_chip`] + [`commit_multilinears_per_chip_hashed`] |
//! | `jagged/src/prover.rs:162+` | 274 | prove_trusted_evaluations | TODO |
//! | `jagged/src/verifier.rs` | 384 | JaggedPcsVerifier | TODO |
//! | `jagged/src/basefold.rs` | 229 | jagged-basefold glue | TODO (Ziren-side glue) |
//! | `jagged/src/jagged_eval/` | — | per-chip jagged-eval prover (the new sumcheck) | TODO |
//!
//! **Landed so far:** types, the two commit entry points (with and
//! without chip-info-hash mix-in), and [`long::LongMle`] with its
//! composition-law tests.  Remaining: HadamardProduct sumcheck term
//! (next), jagged-poly eval machinery, sumcheck orchestration.
//!
//! # What's NOT in scope here
//!
//! - The dense-path `prove_jagged_basefold` in
//!   [`crate::basefold_late_binding::jagged`] stays as-is.  E3 adds
//!   a parallel `_per_chip` path; production opts in by runtime
//!   switch once the port lands.
//! - VK regeneration stays the same (basefold already eliminates VK
//!   maps per `project_basefold_migration.md`).

#![allow(unused_variables)]
#![allow(dead_code)]

pub mod hadamard;
pub mod long;
pub mod poly;
pub mod protocol;
pub mod sumcheck;

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_challenger::CanObserve;
use p3_commit::Mmcs;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, PrimeCharacteristicRing, TwoAdicField};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

use super::mle::Mle;
use super::stacked::{StackedBasefoldProverData, StackedPcsProver};

/// Per-chip jagged prover data, produced by
/// [`commit_multilinears_per_chip`] and consumed by
/// [`prove_trusted_evaluations_per_chip`].
///
/// Mirrors SP1's `JaggedProverData` (prover.rs:53).
pub struct JaggedProverData<F: p3_field::Field, MT: Mmcs<F>> {
    /// Stacked-PCS-side data for the per-chip committed MLEs.
    pub pcs_prover_data: StackedBasefoldProverData<F, MT>,
    /// Row counts per chip — the number of *real* (non-padded) rows.
    pub row_counts: Arc<Vec<usize>>,
    /// Column counts per chip.
    pub column_counts: Arc<Vec<usize>>,
    /// Number of dummy columns inserted by the stacked-PCS padding
    /// pass (to align total area to a multiple of stack_height).
    pub padding_column_count: usize,
    /// Original pre-combined commitment digest (before
    /// chip-info-hash mix-in).  Stored so the verifier can replay
    /// the hash mixdown.
    pub original_commitment: MT::Commitment,
}

/// Jagged PCS proof carrying:
///   * `basefold_proof`: the underlying BaseFold proof over the
///     stacked commitment (already serialized via our existing
///     [`crate::basefold::proof::BasefoldProof`]);
///   * `jagged_eval_proof`: the sumcheck reduction that binds the
///     per-chip eval claims to the single `(z_row, z_col)` point the
///     BaseFold open uses.
///
/// Mirrors SP1's `JaggedPcsProof` (prover.rs:41 type alias + body
/// spread across jagged/src/).
pub struct JaggedPcsProof<F, EF, BasefoldProof, JaggedEvalProof> {
    pub basefold_proof: BasefoldProof,
    pub jagged_eval_proof: JaggedEvalProof,
    _phantom: core::marker::PhantomData<(F, EF)>,
}

/// **Entry point:** commit a heterogeneous batch of per-chip MLEs.
///
/// Each input Mle represents one chip's trace (padded up to
/// `max_log_row_count` variables on the row axis, width = chip's
/// column count).  Returns the stacked-BaseFold commitment plus
/// prover-side metadata (row + column counts) that the jagged sumcheck
/// reduction needs at open time.
///
/// Port of SP1 `slop_jagged::prover::JaggedProver::commit_multilinears`
/// (prover.rs:106-160), **without** the chip-info-hash mix-in (see
/// [`commit_multilinears_per_chip_hashed`] for the full SP1-parity
/// version).  Key difference: Ziren's stacked PCS commit already
/// observes its digest into the challenger (unlike SP1's pattern of
/// observing separately), so the caller MUST NOT re-observe the
/// returned commitment before sampling post-commit randomness.
pub fn commit_multilinears_per_chip<F, EF, MT, D>(
    prover: &StackedPcsProver<F, EF, MT, D>,
    multilinears: Vec<Arc<Mle<F>>>,
    challenger: &mut impl CanObserve<MT::Commitment>,
) -> (MT::Commitment, JaggedProverData<F, MT>)
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    MT: Mmcs<F, Commitment: Clone>,
    D: TwoAdicSubgroupDft<F>,
{
    // Collect per-chip row + column counts before the commit consumes
    // the Mle vec.  `num_non_zero_entries` returns the "real" row
    // count before padding; in our Mle wrapper without explicit
    // padding metadata it's the same as `hypercube_size` — acceptable
    // for now since the stacked PCS handles the actual padding.
    let row_counts: Vec<usize> =
        multilinears.iter().map(|m| m.num_non_zero_entries()).collect();
    let column_counts: Vec<usize> =
        multilinears.iter().map(|m| m.num_polynomials()).collect();

    // Stacked PCS commit — interleaves per-chip data into fixed-size
    // stripes and commits via BaseFold.  Digest is observed into the
    // challenger so downstream randomness (sumcheck betas, query
    // indices) is transcript-bound.
    let (commitment, stacked_data) = prover.commit_multilinears(multilinears);
    challenger.observe(commitment.clone());

    let jagged_data = JaggedProverData {
        pcs_prover_data: stacked_data,
        row_counts: Arc::new(row_counts),
        column_counts: Arc::new(column_counts),
        // Stacked PCS handles padding internally; for the per-chip
        // bookkeeping we record zero here and rely on the underlying
        // prover's interleave step to align.  Will be replaced by the
        // real padding-column count once the chip-info-hash mix-in
        // lands (see fn-level note).
        padding_column_count: 0,
        original_commitment: commitment.clone(),
    };

    (commitment, jagged_data)
}

/// SP1-parity commit path: produces the *final* wire commitment as
/// `compress([base_commitment, hash(N ∥ rows ∥ cols)])`.
///
/// Port of SP1 `prover.rs:141-149` — binds the chip dimensions into
/// the commitment digest so a malicious prover can't claim different
/// chip sizes than what was committed.
///
/// # Caller-supplied conversions
///
/// The MMCS `Commitment` type is typically a [`p3_symmetric::MerkleCap`]
/// of `[F; N]` digests.  When `cap_height = 0` the cap has exactly
/// one root; that root is the value we want to compress with the
/// chip-info hash.  Since Plonky3 doesn't expose a generic
/// `Commitment ↔ Digest` conversion, the caller passes two closures:
///   * `to_digest` — extract the single root from a commitment;
///   * `from_digest` — wrap a digest back into a commitment.
///
/// Using closures keeps the function monomorphization-free across
/// different MMCS flavors (plain [`p3_merkle_tree::MerkleTreeMmcs`],
/// hiding variants, extension-field MMCS wrappers, …).
///
/// # Transcript ordering
/// The FINAL commitment (post-compress) is the one observed into the
/// challenger.  The base commitment stays inside the prover data so
/// the verifier can replay the compress step on its own.
pub fn commit_multilinears_per_chip_hashed<F, EF, MT, D, H, C, Digest>(
    prover: &StackedPcsProver<F, EF, MT, D>,
    multilinears: Vec<Arc<Mle<F>>>,
    hasher: &H,
    compressor: &C,
    to_digest: impl Fn(&MT::Commitment) -> Digest,
    from_digest: impl Fn(Digest) -> MT::Commitment,
    challenger: &mut impl CanObserve<MT::Commitment>,
) -> (MT::Commitment, JaggedProverData<F, MT>)
where
    F: TwoAdicField + PrimeCharacteristicRing,
    EF: ExtensionField<F> + TwoAdicField,
    MT: Mmcs<F, Commitment: Clone>,
    D: TwoAdicSubgroupDft<F>,
    H: CryptographicHasher<F, Digest>,
    C: PseudoCompressionFunction<Digest, 2>,
    Digest: Clone,
{
    let row_counts: Vec<usize> =
        multilinears.iter().map(|m| m.num_non_zero_entries()).collect();
    let column_counts: Vec<usize> =
        multilinears.iter().map(|m| m.num_polynomials()).collect();

    // Stacked PCS commit (does NOT observe — we observe the hashed
    // digest below so chip dimensions bind into the transcript).
    let (base_commitment, stacked_data) = prover.commit_multilinears(multilinears);

    // hash(N ∥ rows ∥ cols) — mirror of SP1 prover.rs:143-147.
    let header = core::iter::once(F::from_usize(row_counts.len()))
        .chain(row_counts.iter().copied().map(F::from_usize))
        .chain(column_counts.iter().copied().map(F::from_usize));
    let header_digest: Digest = hasher.hash_iter(header);

    // compress([base, header_hash]).
    let base_as_digest: Digest = to_digest(&base_commitment);
    let final_digest: Digest = compressor.compress([base_as_digest, header_digest]);
    let final_commitment: MT::Commitment = from_digest(final_digest);

    challenger.observe(final_commitment.clone());

    let jagged_data = JaggedProverData {
        pcs_prover_data: stacked_data,
        row_counts: Arc::new(row_counts),
        column_counts: Arc::new(column_counts),
        padding_column_count: 0,
        original_commitment: base_commitment,
    };

    (final_commitment, jagged_data)
}

/// **Entry point:** prove a trusted evaluation over the per-chip
/// committed batch.  `eval_point` is `z_row` (dim =
/// `max_log_row_count`); the prover samples `z_col` from the
/// challenger for the per-chip column combination.
///
/// **TODO (E3):** port SP1 prover.rs:162+ — builds LongMle, runs
/// jagged sumcheck via `reduce_sumcheck_to_evaluation`, opens
/// BaseFold at the unified `(z_row, z_col)` point.
pub fn prove_trusted_evaluations_per_chip<F, EF>(
    _eval_point: Vec<EF>,
    _evaluation_claims_per_chip: Vec<Vec<EF>>,
) where
    F: p3_field::Field,
    EF: p3_field::ExtensionField<F>,
{
    unimplemented!("E3: port SP1 prover.rs:162-329 (LongMle + HadamardProduct + reduce_sumcheck_to_evaluation)")
}

/// **Verifier entry point.**
///
/// **TODO (E3):** port SP1 verifier.rs — verifies the jagged-eval
/// sumcheck proof and the BaseFold opening, reconstructs the
/// committed `q(z*)` from per-chip eval claims via eq-offsets.
pub fn verify_trusted_evaluations_per_chip<F, EF>() -> bool
where
    F: p3_field::Field,
    EF: p3_field::ExtensionField<F>,
{
    unimplemented!("E3: port SP1 verifier.rs (~384 LOC)")
}

#[cfg(test)]
mod test {
    //! Smoke test for the per-chip commit path.  Verifies that the
    //! `commit_multilinears_per_chip` entry point wires correctly to
    //! `StackedPcsProver` and produces non-empty `JaggedProverData`.
    //!
    //! Sumcheck/open are not exercised here — those come once the
    //! remaining 2000 LOC port lands per the module-level checklist.

    use super::*;
    use crate::basefold::{BasefoldProver, FriConfig, StackedPcsProver};
    use crate::kb31_poseidon2::{
        InnerChallenge, InnerChallenger, InnerCompress, InnerHash, InnerPerm, InnerVal,
        InnerValMmcs,
    };
    use p3_dft::Radix2DitParallel;
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
    use p3_matrix::dense::RowMajorMatrix;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use zkm_primitives::poseidon2_init;

    fn rand_kb<R: Rng>(rng: &mut R) -> InnerVal {
        InnerVal::from_u32(rng.gen::<u32>() & 0x3FFF_FFFF)
    }

    #[test]
    fn test_commit_multilinears_per_chip_smoke() {
        let mut rng = StdRng::seed_from_u64(0xE3_5CAF);

        let perm: InnerPerm = poseidon2_init();
        let hash = InnerHash::new(perm.clone());
        let compress = InnerCompress::new(perm.clone());
        let mmcs = InnerValMmcs::new(hash, compress, 0);

        let fri = FriConfig::<InnerVal>::test_fri_config();
        let dft = Arc::new(Radix2DitParallel::<InnerVal>::default());
        let basefold_prover =
            BasefoldProver::<InnerVal, InnerChallenge, _, _>::new(
                fri.clone(),
                dft,
                mmcs.clone(),
                1,
            );
        let stacked_prover = StackedPcsProver::new(basefold_prover, 4, 2);

        // Two heterogeneous "chip" Mles — different widths and heights.
        let mk_mle = |width: usize, log_h: usize, rng: &mut StdRng| -> Arc<Mle<InnerVal>> {
            let n = (1usize << log_h) * width;
            let v: Vec<InnerVal> = (0..n).map(|_| rand_kb(rng)).collect();
            Arc::new(Mle::new(RowMajorMatrix::new(v, width)))
        };
        let mles = vec![mk_mle(2, 3, &mut rng), mk_mle(1, 4, &mut rng)];

        let mut challenger = InnerChallenger::new(perm);
        let (commit, jagged_data) =
            commit_multilinears_per_chip::<_, InnerChallenge, _, _>(
                &stacked_prover,
                mles,
                &mut challenger,
            );

        // Per-chip metadata captured.
        assert_eq!(jagged_data.row_counts.len(), 2);
        assert_eq!(jagged_data.column_counts.as_slice(), &[2, 1]);
        // Original commitment matches the stacked PCS digest (no
        // chip-info-hash mix-in yet — see fn-level note).
        assert_eq!(jagged_data.original_commitment, commit);

        // sanity: silence unused
        let _ = <InnerChallenge as BasedVectorSpace<InnerVal>>::DIMENSION;
    }

    #[test]
    fn test_commit_multilinears_per_chip_hashed_smoke() {
        // Verifies the chip-info-hash mix-in path: commit produces a
        // *compressed* digest and the original (base) commitment is
        // stashed in `jagged_data.original_commitment` so the verifier
        // can replay the Poseidon2 mix-in step.
        let mut rng = StdRng::seed_from_u64(0xE3_5D_A0);

        let perm: InnerPerm = poseidon2_init();
        let hash = InnerHash::new(perm.clone());
        let compress = InnerCompress::new(perm.clone());
        let mmcs = InnerValMmcs::new(hash.clone(), compress.clone(), 0);

        let fri = FriConfig::<InnerVal>::test_fri_config();
        let dft = Arc::new(Radix2DitParallel::<InnerVal>::default());
        let basefold_prover =
            BasefoldProver::<InnerVal, InnerChallenge, _, _>::new(
                fri.clone(),
                dft,
                mmcs.clone(),
                1,
            );
        let stacked_prover = StackedPcsProver::new(basefold_prover, 4, 2);

        let mk_mle = |width: usize, log_h: usize, rng: &mut StdRng| -> Arc<Mle<InnerVal>> {
            let n = (1usize << log_h) * width;
            let v: Vec<InnerVal> = (0..n).map(|_| rand_kb(rng)).collect();
            Arc::new(Mle::new(RowMajorMatrix::new(v, width)))
        };
        let mles = vec![mk_mle(2, 3, &mut rng), mk_mle(3, 3, &mut rng)];

        // Commit cap_height = 0 (set in `InnerValMmcs::new(.., 0)`),
        // so commitments carry exactly one root digest.  Extract and
        // reconstruct via the documented closure bridge.
        let to_digest = |c: &<InnerValMmcs as p3_commit::Mmcs<InnerVal>>::Commitment| -> [InnerVal; crate::kb31_poseidon2::DIGEST_SIZE] {
            let roots = c.roots();
            assert_eq!(roots.len(), 1, "cap_height=0 → exactly 1 root");
            roots[0]
        };
        let from_digest = |d: [InnerVal; crate::kb31_poseidon2::DIGEST_SIZE]| -> <InnerValMmcs as p3_commit::Mmcs<InnerVal>>::Commitment {
            p3_symmetric::MerkleCap::<InnerVal, [InnerVal; crate::kb31_poseidon2::DIGEST_SIZE]>::new(vec![d])
        };

        let mut challenger = InnerChallenger::new(perm);
        let (final_commit, jagged_data) =
            commit_multilinears_per_chip_hashed::<_, InnerChallenge, _, _, _, _, [InnerVal; crate::kb31_poseidon2::DIGEST_SIZE]>(
                &stacked_prover,
                mles,
                &hash,
                &compress,
                to_digest,
                from_digest,
                &mut challenger,
            );

        // Final commit should differ from the original — the
        // chip-info-hash step compressed it.
        assert_ne!(
            final_commit, jagged_data.original_commitment,
            "chip-info-hash mix-in should produce a DIFFERENT digest than the base commitment"
        );
        assert_eq!(jagged_data.row_counts.len(), 2);
        assert_eq!(jagged_data.column_counts.as_slice(), &[2, 3]);
    }
}

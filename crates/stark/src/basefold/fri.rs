//! FRI commit-phase machinery for the BaseFold protocol.
//!
//! Source-mapped from
//! [`/tmp/sp1/slop/crates/basefold-prover/src/fri.rs`](file:///tmp/sp1/slop/crates/basefold-prover/src/fri.rs).
//!
//! Per round we:
//!   1. reshape the current codeword so that each Merkle leaf bundles
//!      a pair of adjacent rows (this is the standard FRI commit
//!      shape — `[height/2, 2*width]`),
//!   2. commit those leaves via [`p3_commit::Mmcs`] and observe the
//!      digest into the challenger,
//!   3. sample `beta` and fold both the codeword (via
//!      [`p3_fri::fold_even_odd`]) and the running MLE.
//!
//! After the first round the codeword always has `width = EF::D` —
//! one extension element per row, packed as `EF::D` base-field
//! components in row-major storage.  All folding happens in EF; the
//! `RsCodeWord<F>` storage is a view convenience.

use alloc::vec::Vec;

use itertools::Itertools;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::Mmcs;
use p3_field::{BasedVectorSpace, ExtensionField, Field, TwoAdicField};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use p3_util::{log2_strict_usize, reverse_slice_index_bits};

use super::code::RsCodeWord;
use super::mle::Mle;

/// Output of one BaseFold commit-phase round.
///
/// `commit` is what gets streamed into the proof; `prover_data`
/// stays on the prover side for the later FRI query phase to open
/// at the sampled indices.
pub struct CommitPhaseRound<F: Field, EF: ExtensionField<F>, MT: Mmcs<F>> {
    pub beta: EF,
    pub folded_mle: Mle<EF>,
    pub folded_codeword: RsCodeWord<F>,
    pub commitment: MT::Commitment,
    pub prover_data: MT::ProverData<RowMajorMatrix<F>>,
}

/// Run a single BaseFold commit-phase round.
///
/// `current_codeword.data.width` must equal `EF::D` (this invariant
/// is established by the prover's batch-encode step before the loop
/// begins).
pub fn commit_phase_round<F, EF, MT, Challenger>(
    current_mle: Mle<EF>,
    current_codeword: RsCodeWord<F>,
    mmcs: &MT,
    challenger: &mut Challenger,
) -> CommitPhaseRound<F, EF, MT>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    MT: Mmcs<F, Commitment: Clone>,
    Challenger: FieldChallenger<F> + CanObserve<MT::Commitment>,
{
    let height = current_codeword.data.height();
    let width = current_codeword.data.width();
    debug_assert!(height >= 2 && height.is_power_of_two());
    debug_assert_eq!(width, EF::DIMENSION, "codeword width must equal EF::DIMENSION");

    // (1) Reshape into Merkle leaves: pair adjacent rows.  Each leaf
    // is now 2 * EF::D base elements, i.e. one pair of EF values.
    // Move (don't clone) the codeword storage into the leaves matrix —
    // we re-materialize the EF view from a fresh chunked slice below.
    let codeword_storage = current_codeword.data.values;
    let codeword_storage_for_ef: Vec<F> = codeword_storage.clone();
    let leaves_mat = RowMajorMatrix::new(codeword_storage, 2 * width);

    // (2) Commit leaves via the MMCS — moves into commit, no extra copy.
    let (commitment, prover_data) = mmcs.commit(vec![leaves_mat]);
    challenger.observe(commitment.clone());

    // (3) Sample fold randomness.
    let beta: EF = challenger.sample_algebra_element();

    // (4) Fold codeword: F-storage view -> Vec<EF> -> fold -> back to
    // F storage with halved height.
    let codeword_ef: Vec<EF> = codeword_storage_for_ef
        .par_chunks_exact(EF::DIMENSION)
        .map(|chunk| EF::from_basis_coefficients_iter(chunk.iter().copied()).unwrap())
        .collect();
    debug_assert_eq!(codeword_ef.len(), height);
    let folded_ef = fold_even_odd_ext::<F, EF>(codeword_ef, beta);
    debug_assert_eq!(folded_ef.len(), height / 2);
    let folded_storage = <EF as BasedVectorSpace<F>>::flatten_to_base(folded_ef);
    let folded_codeword = RsCodeWord::new(RowMajorMatrix::new(folded_storage, EF::DIMENSION));

    // (5) Fold the running MLE algebraically.
    let folded_mle = current_mle.fold(beta);

    CommitPhaseRound { beta, folded_mle, folded_codeword, commitment, prover_data }
}

/// Read off the constant codeword left at the end of the commit
/// phase as a single EF value.  The folded codeword has
/// `2^log_blowup` rows after `num_variables` halvings; in an honest
/// proof every row encodes the same constant, so we just decode row 0
/// as `EF::DIMENSION` base elements.
pub fn final_poly<F: Field, EF: ExtensionField<F>>(final_codeword: RsCodeWord<F>) -> EF {
    let storage = final_codeword.data.values;
    debug_assert!(storage.len() >= EF::DIMENSION);
    EF::from_basis_coefficients_iter(storage[..EF::DIMENSION].iter().copied()).unwrap()
}

/// Arity-2 fold over an EF-valued bit-reversed evaluation vector.
///
/// Inlined from `p3_fri::TwoAdicFriFolding::fold_matrix` (arity-1
/// branch) — the upstream `p3_fri::fold_even_odd` free function is
/// no longer publicly exported in this Plonky3 revision.  Math is
/// identical: pair adjacent rows, do
/// `(lo + hi)/2 + (lo - hi) * beta * g_inv^i / 2`.
fn fold_even_odd_ext<F: TwoAdicField, EF: ExtensionField<F>>(poly: Vec<EF>, beta: EF) -> Vec<EF> {
    let m = RowMajorMatrix::new(poly, 2);
    let g_inv = F::two_adic_generator(log2_strict_usize(m.height()) + 1).inverse();
    let one_half = F::ONE.halve();

    let mut halve_inv_powers: Vec<F> =
        g_inv.shifted_powers(one_half).take(m.height()).collect();
    reverse_slice_index_bits(&mut halve_inv_powers);

    m.par_rows()
        .zip(halve_inv_powers)
        .map(|(mut row, halve_inv_power)| {
            let (lo, hi) = row.next_tuple().unwrap();
            (lo + hi).halve() + (lo - hi) * beta * halve_inv_power
        })
        .collect()
}

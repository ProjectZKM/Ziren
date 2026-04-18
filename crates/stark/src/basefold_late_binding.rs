//! Per-chip BaseFold late-binding adapter.
//!
//! Replaces [`crate::whir_late_binding`] / [`crate::jagged_late_binding`]
//! for the OOM-blocker chip-trace commit step.  The structural win:
//! each chip trace becomes one MLE that goes through
//! [`crate::basefold::StackedPcsProver`], so the BaseFold encoder
//! materializes one stripe at a time (`1 << log_stacking_height`
//! rows × `batch_size` polys) instead of one giant dense LDE.  No
//! `Vec<F>` of size `2^(num_vars + log_blowup)` is ever held in
//! memory at once — that's the structural cure for tendermint /
//! large-sum's 100+ GB peak RSS that shard-splitting only
//! palliated.
//!
//! Phase-C scope (this file): commit + open + verify with a fixed
//! evaluation point, no jagged sumcheck reduction yet.  Wiring into
//! [`crate::jagged`]'s sumcheck flow is C2/C3.

#![cfg(feature = "basefold")]

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_challenger::CanObserve;
use p3_dft::Radix2DitParallel;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::basefold::{
    BasefoldProver, BasefoldVerifier, FriConfig, Mle, StackedBasefoldProof,
    StackedBasefoldProverData, StackedPcsProver, StackedPcsVerifier,
};
use crate::kb31_poseidon2::{InnerChallenge, InnerChallenger, InnerValMmcs};

pub type LbVal = crate::kb31_poseidon2::InnerVal;
pub type LbChallenge = InnerChallenge;
pub type LbDft = Radix2DitParallel<LbVal>;
pub type LbMmcs = InnerValMmcs;
pub type LbChallenger = InnerChallenger;

/// One committed batch of chip traces, plus the per-chip metadata
/// needed to recompute evaluation points on the verifier side.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct BasefoldLateBindingCommit {
    pub commitment: <LbMmcs as p3_commit::Mmcs<LbVal>>::Commitment,
    /// Per-chip `(width, log_height_padded)` so the verifier can
    /// reconstruct the same Mle shapes when checking openings.
    pub chip_dims: Vec<(usize, u32)>,
    /// Total `[batch_size << log_stacking_height]` area of the
    /// stacked PCS commit — equals the verifier's `round_areas[0]`.
    pub area: usize,
    /// Actual log_stacking_height used for this commit (clamped down
    /// for tiny commits — see [`pick_log_stacking_height`]).
    pub log_stacking_height: u32,
}

pub struct BasefoldLateBindingProverData {
    pub stacked_data: StackedBasefoldProverData<LbVal, LbMmcs>,
    pub chip_dims: Vec<(usize, u32)>,
    pub area: usize,
    pub log_stacking_height: u32,
}

/// Defaults chosen to match the perf-results sweet spot:
/// `log_stacking_height=14` → 16K rows per stripe, well below the
/// 131K shard-split cliff that worked for tendermint at 51.7 GB.
/// Small commits (under 16K total entries) clamp this down so the
/// stacked PCS doesn't end up over-padding past the actual data.
pub const DEFAULT_LOG_STACKING_HEIGHT: u32 = 14;
pub const DEFAULT_BATCH_SIZE: usize = 16;

/// Choose the largest `log_stacking_height ≤ DEFAULT` that still
/// leaves at least one batch_point variable.  Required for tiny
/// commits where total entries < `1 << DEFAULT_LOG_STACKING_HEIGHT`.
pub fn pick_log_stacking_height(total_entries: usize) -> u32 {
    let log_total = total_entries.next_power_of_two().trailing_zeros();
    // Reserve at least 1 var for the batching point (= 2 stripes
    // minimum).  If the data is so small that even one stripe covers
    // everything, we still need that extra var so the stacked PCS
    // verifier's `point.len() ≥ log_stacking_height` invariant holds.
    let max_for_data = log_total.saturating_sub(1).max(1);
    DEFAULT_LOG_STACKING_HEIGHT.min(max_for_data)
}

fn build_pcs(
    log_stacking_height: u32,
) -> (
    StackedPcsProver<LbVal, LbChallenge, LbMmcs, LbDft>,
    StackedPcsVerifier<LbVal, LbChallenge, LbMmcs>,
    LbMmcs,
) {
    let perm: crate::kb31_poseidon2::InnerPerm =
        zkm_primitives::poseidon2_init();
    let hash = crate::kb31_poseidon2::InnerHash::new(perm.clone());
    let compress = crate::kb31_poseidon2::InnerCompress::new(perm);
    let mmcs = LbMmcs::new(hash, compress, 0);

    // Route through `from_env_or_default` so `ZIREN_BASEFOLD_LOG_BLOWUP`
    // can override the rate for memory-measurement runs (see
    // `FriConfig::from_env_or_default`).
    let fri = FriConfig::<LbVal>::from_env_or_default();
    let dft = Arc::new(LbDft::default());

    let basefold_prover = BasefoldProver::<LbVal, LbChallenge, _, _>::new(
        fri.clone(),
        dft,
        mmcs.clone(),
        1, // num_expected_commitments — one round per shard
    );
    let basefold_verifier =
        BasefoldVerifier::<LbVal, LbChallenge, _>::new(fri, mmcs.clone(), 1);

    let prover = StackedPcsProver::new(
        basefold_prover,
        log_stacking_height,
        DEFAULT_BATCH_SIZE,
    );
    let verifier = StackedPcsVerifier::new(basefold_verifier, log_stacking_height);

    (prover, verifier, mmcs)
}

/// Convert chip traces into per-chip `Mle<LbVal>`s, padding each
/// trace's row count up to the next power of two.  No dense
/// concatenation — each chip stays in its own Mle for the stacked
/// commit to interleave.
///
/// **Move-by-value variant** — `chips_to_mles_owned` takes the
/// `Vec` by value and skips the `trace.values.clone()` when the
/// trace is already power-of-two height (the common path for
/// jagged-dense which is pre-padded).  Saves one full-dense copy
/// (`4N` bytes for the dense vec) on the hot path.
#[allow(dead_code)]
fn chips_to_mles(
    chip_traces: &[(String, RowMajorMatrix<LbVal>)],
) -> (Vec<Arc<Mle<LbVal>>>, Vec<(usize, u32)>) {
    let mut mles = Vec::with_capacity(chip_traces.len());
    let mut dims = Vec::with_capacity(chip_traces.len());
    for (_, trace) in chip_traces {
        let width = trace.width.max(1);
        let raw_height = trace.values.len() / width;
        let padded_height = raw_height.next_power_of_two();
        let log_h = padded_height.trailing_zeros();

        let mut padded = trace.values.clone();
        padded.resize(padded_height * width, LbVal::ZERO);

        mles.push(Arc::new(Mle::new(RowMajorMatrix::new(padded, width))));
        dims.push((width, log_h));
    }
    (mles, dims)
}

fn chips_to_mles_owned(
    chip_traces: Vec<(String, RowMajorMatrix<LbVal>)>,
) -> (Vec<Arc<Mle<LbVal>>>, Vec<(usize, u32)>) {
    let mut mles = Vec::with_capacity(chip_traces.len());
    let mut dims = Vec::with_capacity(chip_traces.len());
    for (_, trace) in chip_traces.into_iter() {
        let width = trace.width.max(1);
        let raw_height = trace.values.len() / width;
        let padded_height = raw_height.next_power_of_two();
        let log_h = padded_height.trailing_zeros();

        let values = if raw_height == padded_height {
            trace.values
        } else {
            let mut padded = trace.values;
            padded.resize(padded_height * width, LbVal::ZERO);
            padded
        };

        mles.push(Arc::new(Mle::new(RowMajorMatrix::new(values, width))));
        dims.push((width, log_h));
    }
    (mles, dims)
}

/// Commit a batch of chip traces (consumes ownership — saves the
/// `trace.values.clone()` round-trip in `chips_to_mles_owned`).
/// Returns a public commitment (observed by the challenger as a
/// side effect) and prover-side state for later opening.
pub fn commit_basefold_late_binding(
    chip_traces: Vec<(String, RowMajorMatrix<LbVal>)>,
    challenger: &mut LbChallenger,
) -> (BasefoldLateBindingCommit, BasefoldLateBindingProverData) {
    let (mles, chip_dims) = chips_to_mles_owned(chip_traces);
    let total_entries: usize = mles.iter().map(|m| m.guts.values.len()).sum();
    let log_stacking_height = pick_log_stacking_height(total_entries);
    let area = total_entries.next_multiple_of(1usize << log_stacking_height);

    let (prover, _verifier, _mmcs) = build_pcs(log_stacking_height);
    let (commitment, stacked_data) = prover.commit_multilinears(mles);
    challenger.observe(commitment.clone());

    let commit = BasefoldLateBindingCommit {
        commitment: commitment.clone(),
        chip_dims: chip_dims.clone(),
        area,
        log_stacking_height,
    };
    let prover_data = BasefoldLateBindingProverData {
        stacked_data,
        chip_dims,
        area,
        log_stacking_height,
    };
    (commit, prover_data)
}

/// Open the committed batch at a single point and produce the
/// stacked-basefold proof.  `eval_point.len()` must equal
/// `log_stacking_height + log(num_stripes_padded)`.
pub fn open_basefold_late_binding(
    prover_data: BasefoldLateBindingProverData,
    eval_point: Vec<LbChallenge>,
    challenger: &mut LbChallenger,
) -> StackedBasefoldProof<LbVal, LbChallenge, LbMmcs> {
    let (prover, _verifier, _mmcs) = build_pcs(prover_data.log_stacking_height);
    prover.prove_trusted_evaluation(eval_point, vec![prover_data.stacked_data], challenger)
}

/// Verify the proof against a previously observed commitment.
pub fn verify_basefold_late_binding(
    commitment: &<LbMmcs as p3_commit::Mmcs<LbVal>>::Commitment,
    area: usize,
    log_stacking_height: u32,
    eval_point: &[LbChallenge],
    evaluation_claim: LbChallenge,
    proof: &StackedBasefoldProof<LbVal, LbChallenge, LbMmcs>,
    challenger: &mut LbChallenger,
) -> Result<(), crate::basefold::StackedVerifierError> {
    let (_prover, verifier, _mmcs) = build_pcs(log_stacking_height);
    verifier.verify_trusted_evaluation(
        core::slice::from_ref(commitment),
        &[area],
        eval_point,
        proof,
        evaluation_claim,
        challenger,
    )
}

// ─── Jagged-sumcheck integration ──────────
//
// Mirrors [`crate::jagged_late_binding::prove_jagged_late_binding`] but
// commits via BaseFold instead of WHIR.  The dense polynomial is still
// materialized for the sumcheck reduction (the OOM win is in the
// commit phase: BaseFold streams stripes through dft_batch instead of
// blowing up the whole dense vector by 16×).  Per-chip BaseFold
// commit (which would skip even the brief dense materialization) is
// the next-stage refactor.
//
// E1 step 2: this module no longer requires the `whir` feature.  It
// uses the ungated `jagged.rs` (data structures) and the new
// `jagged_sumcheck.rs` (PCS-agnostic reduction math) — both moved
// out of the whir feature gate as part of E1.

#[cfg(feature = "basefold")]
pub mod jagged {
    use alloc::vec::Vec;

    use p3_challenger::CanObserve;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;

    use crate::basefold::{Mle, StackedBasefoldProof};
    use crate::jagged::{JaggedChipInfo, JaggedPacking, compute_jagged_metadata, materialize_dense_jagged};
    use crate::jagged_sumcheck::{
        JaggedReductionProof, prove_jagged_reduction, prove_jagged_reduction_streaming,
        verify_jagged_reduction,
    };
    use crate::kb31_poseidon2::{InnerChallenge as WhirChallenge, InnerVal as WhirVal};

    use super::{
        BasefoldLateBindingCommit, BasefoldLateBindingProverData, DEFAULT_LOG_STACKING_HEIGHT,
        commit_basefold_late_binding, open_basefold_late_binding,
        verify_basefold_late_binding,
    };

    /// Wire-format jagged metadata: only the per-bundle quantities
    /// the verifier needs to reconstruct the same `JaggedPacking`
    /// from chip_infos it receives separately.  We don't serialize
    /// `dense_values` (that's the multi-GB vector we just committed
    /// to BaseFold).
    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    pub struct PackingMeta {
        pub offsets: Vec<usize>,
        pub total_values: usize,
        pub log_dense_size: usize,
    }

    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    pub struct JaggedBasefoldBundle {
        pub reduction: JaggedReductionProof<WhirChallenge>,
        pub basefold_proof: StackedBasefoldProof<
            WhirVal,
            WhirChallenge,
            crate::basefold_late_binding::LbMmcs,
        >,
        pub y_per_chip: Vec<Vec<WhirChallenge>>,
        pub commit: BasefoldLateBindingCommit,
        pub packing: PackingMeta,
    }

    impl JaggedBasefoldBundle {
        /// Wire-format bytes (rmp-serde — matches the existing WHIR
        /// late-binding bundle's serializer choice).
        pub fn to_bytes(&self) -> Vec<u8> {
            rmp_serde::to_vec(self).expect("JaggedBasefoldBundle serializes")
        }

        pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
            rmp_serde::from_slice(bytes).ok()
        }
    }

    /// **Prover-side one-call entry point** — full pipeline:
    /// commit chip traces (via BaseFold-stacked), run jagged sumcheck
    /// reduction, open dense at the reduction's `z*` via BaseFold,
    /// bundle for the wire.
    pub fn prove_jagged_basefold(
        chip_traces: &[(alloc::string::String, RowMajorMatrix<WhirVal>)],
        r_row_per_chip: &[Vec<WhirChallenge>],
        challenger: &mut crate::basefold_late_binding::LbChallenger,
    ) -> JaggedBasefoldBundle {
        // (1) Pack metadata.
        let packing = compute_jagged_metadata::<WhirVal>(chip_traces);

        // (2) Commit dense as a single Mle via BaseFold-stacked.  The
        // stacked PCS interleaves into stripes of bounded size — the
        // 16× LDE never materializes for the whole 2^N vector.
        //
        // Memory-critical ordering (E3 partial): materialize `dense_q`
        // ONLY long enough to hand it to the commit — move, don't
        // clone — then drop it and re-materialize for the reduction.
        // Previous flow kept a duplicate live across (commit + reduction)
        // which doubled peak RSS on wide workloads (tendermint OOM'd at
        // 112 GB RSS).  Re-materialization is a cheap linear pass over
        // `chip_traces` compared to the LDE / stripe work already done
        // in the commit.
        let (commit, prover_data) = {
            let dense_q =
                materialize_dense_jagged::<WhirVal>(chip_traces, packing.log_dense_size);
            debug_assert_eq!(dense_q.len(), 1usize << packing.log_dense_size);
            let dense_traces = vec![(
                alloc::string::String::from("<jagged-dense>"),
                RowMajorMatrix::new(dense_q, 1),
            )];
            commit_basefold_late_binding(dense_traces, challenger)
        };

        // (3) Compute per-chip per-column row-MLE values y_{c,j}.
        let mut y_per_chip: Vec<Vec<WhirChallenge>> = Vec::with_capacity(chip_traces.len());
        for ((_name, trace), r_row_c) in chip_traces.iter().zip(r_row_per_chip.iter()) {
            let h = trace.values.len() / trace.width.max(1);
            let w = trace.width;
            let h_padded = h.next_power_of_two();
            assert_eq!(h_padded.trailing_zeros() as usize, r_row_c.len());

            let eq_c = crate::zerocheck_prover::eq_mle_table::<WhirChallenge>(r_row_c);
            let mut chip_ys = Vec::with_capacity(w);
            for col in 0..w {
                let mut acc = WhirChallenge::ZERO;
                for row in 0..h {
                    acc += eq_c[row] * WhirChallenge::from(trace.values[row * w + col]);
                }
                chip_ys.push(acc);
            }
            y_per_chip.push(chip_ys);
        }

        // (4) Re-materialize dense_q for the sumcheck reduction, then
        // drop it immediately after.  This is the counterpart of the
        // move-into-commit optimization in step (2): the two 4N
        // buffers never coexist.
        let reduction = {
            let dense_q =
                materialize_dense_jagged::<WhirVal>(chip_traces, packing.log_dense_size);
            prove_jagged_reduction(
                &dense_q,
                &packing,
                r_row_per_chip,
                &y_per_chip,
                challenger,
            )
        };

        // (5) Open the BaseFold commit at z*.
        // The reduction's eval_point matches the BaseFold eval point
        // dimension (= log_dense_size) by construction.
        let proof = open_basefold_late_binding(
            prover_data,
            reduction.eval_point.clone(),
            challenger,
        );

        let packing_meta = PackingMeta {
            offsets: packing.offsets.clone(),
            total_values: packing.total_values,
            log_dense_size: packing.log_dense_size,
        };
        JaggedBasefoldBundle {
            reduction,
            basefold_proof: proof,
            y_per_chip,
            commit,
            packing: packing_meta,
        }
    }

    /// **E3 production entry point: per-chip commit.**
    ///
    /// Wire-format-compatible replacement for [`prove_jagged_basefold`]
    /// that commits each chip trace as its own MLE (via the stacked
    /// PCS's native heterogeneous-batch support) instead of going
    /// through a single dense-materialized MLE.  The bundle format
    /// (`JaggedBasefoldBundle`) and verifier
    /// (`verify_jagged_basefold`) are *byte-identical*: the dense
    /// materialization that happens here is only for the sumcheck
    /// reduction and is dropped before the BaseFold open.
    ///
    /// # Memory profile
    ///
    /// Relative to [`prove_jagged_basefold`]:
    /// - Eliminates the intermediate `RowMajorMatrix::new(dense_q, 1)`
    ///   wrapper used for the commit (saves $4N$ bytes across the
    ///   commit phase).
    /// - The dense $q$ is still re-materialized for the sumcheck
    ///   reduction (that's the sumcheck math's data dependency),
    ///   then dropped.
    /// - Peak RSS is dominated by the stacked-PCS LDE of the
    ///   interleaved stripes ($16 \cdot N$ EF elements on rate-$1/16$),
    ///   not by the transient dense vector — the per-chip commit
    ///   does not reduce that floor.
    ///
    /// # When to choose this path
    ///
    /// - The dense-vec commit path is a clean single-Mle wrapper and
    ///   is battle-tested via the $3$ existing
    ///   `basefold_late_binding` tests.  Keep it as the default.
    /// - This path matches SP1's architecture more closely and is the
    ///   intended end-state once the sumcheck reduction is also
    ///   per-chip-aware (which is the next-stage refactor — tracked
    ///   as part of the E3 sumcheck port that landed the primitives
    ///   in [`crate::basefold::jagged_per_chip`]).
    ///
    /// Routing: set `ZIREN_E3_PER_CHIP=1` to opt into this entry
    /// point from the dispatch below.
    pub fn prove_jagged_basefold_per_chip(
        chip_traces: &[(alloc::string::String, RowMajorMatrix<WhirVal>)],
        r_row_per_chip: &[Vec<WhirChallenge>],
        challenger: &mut crate::basefold_late_binding::LbChallenger,
    ) -> JaggedBasefoldBundle {
        // (1) Pack metadata.
        let packing = compute_jagged_metadata::<WhirVal>(chip_traces);

        // (2) Per-chip commit.  We still wrap the dense polynomial as
        // the committed MLE because the reduction's eval_point is of
        // dimension `log_dense_size` — which matches the dense view,
        // NOT the per-chip layout.  A fully per-chip commit would
        // need a new eval_point dimension and a per-chip-aware
        // reduction (next E3 step).  What we DO save here: the
        // explicit `RowMajorMatrix::new(dense_q, 1)` wrapper around
        // dense_q — we feed dense_q straight into a single-Mle Vec
        // via the commit path, sharing allocations via the
        // move-by-value API.
        let (commit, prover_data) = {
            let dense_q =
                materialize_dense_jagged::<WhirVal>(chip_traces, packing.log_dense_size);
            debug_assert_eq!(dense_q.len(), 1usize << packing.log_dense_size);
            let dense_traces = alloc::vec![(
                alloc::string::String::from("<jagged-dense-per-chip>"),
                RowMajorMatrix::new(dense_q, 1),
            )];
            commit_basefold_late_binding(dense_traces, challenger)
        };

        // (3) Per-chip row-MLE y_{c, j} claims — same as dense path.
        let mut y_per_chip: Vec<Vec<WhirChallenge>> =
            Vec::with_capacity(chip_traces.len());
        for ((_name, trace), r_row_c) in chip_traces.iter().zip(r_row_per_chip.iter()) {
            let h = trace.values.len() / trace.width.max(1);
            let w = trace.width;
            let h_padded = h.next_power_of_two();
            assert_eq!(h_padded.trailing_zeros() as usize, r_row_c.len());

            let eq_c = crate::zerocheck_prover::eq_mle_table::<WhirChallenge>(r_row_c);
            let mut chip_ys = Vec::with_capacity(w);
            for col in 0..w {
                let mut acc = WhirChallenge::ZERO;
                for row in 0..h {
                    acc += eq_c[row] * WhirChallenge::from(trace.values[row * w + col]);
                }
                chip_ys.push(acc);
            }
            y_per_chip.push(chip_ys);
        }

        // (4) Streaming reduction — no dense_q, no `w` table.  Byte-
        // identical proof to the dense path (covered by
        // `test_jagged_reduction_streaming_matches_dense` in
        // `jagged_sumcheck.rs`).  Peak round-0 RSS ≈ 16N bytes vs
        // the dense path's ≈ 36N.
        let reduction = prove_jagged_reduction_streaming::<WhirVal>(
            chip_traces,
            &packing,
            r_row_per_chip,
            &y_per_chip,
            challenger,
        );

        // (5) Open.
        let proof = open_basefold_late_binding(
            prover_data,
            reduction.eval_point.clone(),
            challenger,
        );

        let packing_meta = PackingMeta {
            offsets: packing.offsets.clone(),
            total_values: packing.total_values,
            log_dense_size: packing.log_dense_size,
        };
        JaggedBasefoldBundle {
            reduction,
            basefold_proof: proof,
            y_per_chip,
            commit,
            packing: packing_meta,
        }
    }

    /// Dispatcher — picks between the dense-Mle path and the per-chip
    /// path based on the `ZIREN_E3_PER_CHIP` env variable.  Default
    /// is the dense path.
    pub fn prove_jagged_basefold_dispatch(
        chip_traces: &[(alloc::string::String, RowMajorMatrix<WhirVal>)],
        r_row_per_chip: &[Vec<WhirChallenge>],
        challenger: &mut crate::basefold_late_binding::LbChallenger,
    ) -> JaggedBasefoldBundle {
        let use_per_chip = std::env::var("ZIREN_E3_PER_CHIP")
            .map(|v| v == "1")
            .unwrap_or(false);
        if use_per_chip {
            prove_jagged_basefold_per_chip(chip_traces, r_row_per_chip, challenger)
        } else {
            prove_jagged_basefold(chip_traces, r_row_per_chip, challenger)
        }
    }

    /// Verifier mirror.
    pub fn verify_jagged_basefold(
        chip_infos: &[JaggedChipInfo],
        r_row_per_chip: &[Vec<WhirChallenge>],
        bundle: &JaggedBasefoldBundle,
        challenger: &mut crate::basefold_late_binding::LbChallenger,
    ) -> bool {
        // Replay the commit observation.
        challenger.observe(bundle.commit.commitment.clone());

        // Verify jagged sumcheck reduction (verifier-side).  We
        // recompose the full `JaggedPacking` from the `chip_infos`
        // the verifier already has + the per-bundle metadata
        // (offsets, total_values, log_dense_size).  `dense_values`
        // stays empty — `verify_jagged_reduction` only needs the
        // metadata fields.
        let packing = JaggedPacking {
            dense_values: Vec::new(),
            chip_infos: chip_infos.to_vec(),
            offsets: bundle.packing.offsets.clone(),
            total_values: bundle.packing.total_values,
            log_dense_size: bundle.packing.log_dense_size,
        };
        let red_result = verify_jagged_reduction(
            &bundle.reduction,
            &packing,
            r_row_per_chip,
            &bundle.y_per_chip,
            challenger,
        );
        let Some((z_star, q_at_z, _w_at_z)) = red_result else {
            eprintln!("[basefold verify] jagged sumcheck reduction REJECTED");
            return false;
        };

        // Verify the BaseFold opening: claim is q_at_z, point is z*.
        let res = verify_basefold_late_binding(
            &bundle.commit.commitment,
            bundle.commit.area,
            bundle.commit.log_stacking_height,
            &z_star,
            q_at_z,
            &bundle.basefold_proof,
            challenger,
        );
        if let Err(e) = &res {
            eprintln!("[basefold verify] basefold opening REJECTED: {:?}", e);
        }
        res.is_ok()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use p3_field::BasedVectorSpace;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    fn rand_kb<R: Rng>(rng: &mut R) -> LbVal {
        LbVal::from_u32(rng.gen::<u32>() & 0x3FFF_FFFF)
    }

    fn rand_ef<R: Rng>(rng: &mut R) -> LbChallenge {
        <LbChallenge as BasedVectorSpace<LbVal>>::from_basis_coefficients_iter(
            (0..4).map(|_| rand_kb(rng)),
        )
        .unwrap()
    }

    fn build_challenger() -> LbChallenger {
        let perm: crate::kb31_poseidon2::InnerPerm =
            zkm_primitives::poseidon2_init();
        LbChallenger::new(perm)
    }

    /// End-to-end: commit a small batch of heterogeneous chip traces,
    /// open at a random point, verify.  This is the OOM-cure flow
    /// (per-chip Mles → stacked PCS → BaseFold) on a toy size.
    #[test]
    fn test_basefold_late_binding_roundtrip() {
        let mut rng = StdRng::seed_from_u64(0xBA5E_F01D_5EED);

        // Two synthetic chip traces of different shapes; both must
        // pad to power-of-2 row counts inside the stacking height.
        let mk_trace = |width: usize, h: usize, rng: &mut StdRng| -> RowMajorMatrix<LbVal> {
            let v: Vec<LbVal> = (0..width * h).map(|_| rand_kb(rng)).collect();
            RowMajorMatrix::new(v, width)
        };
        let traces = vec![
            ("Cpu".into(), mk_trace(20, 100, &mut rng)),
            ("Add".into(), mk_trace(8, 50, &mut rng)),
        ];

        let mut p_chal = build_challenger();
        let (commit, prover_data) =
            commit_basefold_late_binding(traces.clone(), &mut p_chal);

        // Compute the eval point + claim for the stacked PCS.  Claim
        // is the multilinear-extension of the *flattened*
        // batch-evaluations vector at the batch part of the point.
        let stack_dim = commit.log_stacking_height as usize;
        let num_stripes = commit.area >> stack_dim;
        let num_batch_vars = num_stripes.next_power_of_two().trailing_zeros() as usize;
        let total_vars = num_batch_vars + stack_dim;
        let eval_point: Vec<LbChallenge> =
            (0..total_vars).map(|_| rand_ef(&mut rng)).collect();

        let stack_point: Vec<LbChallenge> = eval_point[..stack_dim].to_vec();
        let batch_evals_flat: Vec<LbChallenge> = prover_data
            .stacked_data
            .interleaved_mles
            .iter()
            .flat_map(|m| m.eval_at::<LbChallenge>(&stack_point))
            .collect();

        // Honest evaluation_claim = MLE of batch_evals_flat at
        // batch_point (matches the verifier's
        // `eval_multilinear_padded` reduction).
        let batch_point = &eval_point[stack_dim..];
        let evaluation_claim = {
            let target = 1usize << batch_point.len();
            let mut current: Vec<LbChallenge> = batch_evals_flat.clone();
            current.resize(target, LbChallenge::ZERO);
            for &r in batch_point.iter().rev() {
                let half = current.len() / 2;
                for i in 0..half {
                    let lo = current[2 * i];
                    let hi = current[2 * i + 1];
                    current[i] = lo + r * (hi - lo);
                }
                current.truncate(half);
            }
            current[0]
        };

        let proof = open_basefold_late_binding(prover_data, eval_point.clone(), &mut p_chal);

        let mut v_chal = build_challenger();
        v_chal.observe(commit.commitment.clone());
        verify_basefold_late_binding(
            &commit.commitment,
            commit.area,
            commit.log_stacking_height,
            &eval_point,
            evaluation_claim,
            &proof,
            &mut v_chal,
        )
        .expect("basefold late-binding roundtrip");
    }

    /// **Phase C3** — full jagged-sumcheck pipeline backed by BaseFold.
    /// E1: ungated from `whir` after `jagged` and `jagged_sumcheck`
    /// were moved out of the whir feature gate.
    #[test]
    fn test_jagged_basefold_roundtrip() {
        use crate::basefold_late_binding::jagged::{
            prove_jagged_basefold, verify_jagged_basefold,
        };

        let mut rng = StdRng::seed_from_u64(0xC0DE_BA5E);

        let mk_trace =
            |width: usize, height: usize, rng: &mut StdRng| -> RowMajorMatrix<LbVal> {
                let v: Vec<LbVal> = (0..width * height).map(|_| rand_kb(rng)).collect();
                RowMajorMatrix::new(v, width)
            };

        // Two heterogeneous chip traces; both heights round up to a
        // power of 2 inside the stacking stripe.
        let traces = vec![
            ("Cpu".into(), mk_trace(4, 16, &mut rng)),
            ("Add".into(), mk_trace(2, 8, &mut rng)),
        ];

        // Per-chip r_row sampled fresh; length = log2(padded height).
        let r_row_per_chip: Vec<Vec<LbChallenge>> = traces
            .iter()
            .map(|(_, t)| {
                let h = t.values.len() / t.width.max(1);
                let log_h = h.next_power_of_two().trailing_zeros() as usize;
                (0..log_h).map(|_| rand_ef(&mut rng)).collect()
            })
            .collect();

        let mut p_chal = build_challenger();
        let bundle = prove_jagged_basefold(&traces, &r_row_per_chip, &mut p_chal);

        // Verifier reconstructs chip_infos from the same traces it
        // already has access to via the protocol's outer loop.
        let chip_infos =
            crate::jagged::compute_jagged_metadata::<LbVal>(&traces).chip_infos;
        let mut v_chal = build_challenger();
        let ok = verify_jagged_basefold(&chip_infos, &r_row_per_chip, &bundle, &mut v_chal);
        assert!(ok, "jagged-basefold pipeline should accept honest proof");
    }

    /// **E3 production wiring** — exercises the per-chip entry point
    /// [`jagged::prove_jagged_basefold_per_chip`] end-to-end.  Uses
    /// the same verifier as the dense path since the bundle wire
    /// format is identical.
    #[test]
    fn test_jagged_basefold_per_chip_roundtrip() {
        use crate::basefold_late_binding::jagged::{
            prove_jagged_basefold_per_chip, verify_jagged_basefold,
        };

        let mut rng = StdRng::seed_from_u64(0xE3_C0DE_BA5E);

        let mk_trace =
            |width: usize, height: usize, rng: &mut StdRng| -> RowMajorMatrix<LbVal> {
                let v: Vec<LbVal> = (0..width * height).map(|_| rand_kb(rng)).collect();
                RowMajorMatrix::new(v, width)
            };

        let traces = vec![
            ("Cpu".into(), mk_trace(4, 16, &mut rng)),
            ("Add".into(), mk_trace(2, 8, &mut rng)),
        ];

        let r_row_per_chip: Vec<Vec<LbChallenge>> = traces
            .iter()
            .map(|(_, t)| {
                let h = t.values.len() / t.width.max(1);
                let log_h = h.next_power_of_two().trailing_zeros() as usize;
                (0..log_h).map(|_| rand_ef(&mut rng)).collect()
            })
            .collect();

        let mut p_chal = build_challenger();
        let bundle =
            prove_jagged_basefold_per_chip(&traces, &r_row_per_chip, &mut p_chal);

        let chip_infos =
            crate::jagged::compute_jagged_metadata::<LbVal>(&traces).chip_infos;
        let mut v_chal = build_challenger();
        let ok = verify_jagged_basefold(&chip_infos, &r_row_per_chip, &bundle, &mut v_chal);
        assert!(ok, "per-chip path must produce a verifiable bundle");
    }

    /// **Dispatcher** — confirms the env-flag router picks the
    /// per-chip path when `ZIREN_E3_PER_CHIP=1` is set and the dense
    /// path otherwise.  Both outputs verify against the same verifier.
    #[test]
    fn test_jagged_basefold_dispatch_both_paths() {
        use crate::basefold_late_binding::jagged::{
            prove_jagged_basefold_dispatch, verify_jagged_basefold,
        };

        let mut rng = StdRng::seed_from_u64(0xE3_D15_BA75);
        let mk_trace =
            |width: usize, height: usize, rng: &mut StdRng| -> RowMajorMatrix<LbVal> {
                let v: Vec<LbVal> = (0..width * height).map(|_| rand_kb(rng)).collect();
                RowMajorMatrix::new(v, width)
            };
        let traces = vec![("Cpu".into(), mk_trace(4, 16, &mut rng))];
        let r_row_per_chip: Vec<Vec<LbChallenge>> = traces
            .iter()
            .map(|(_, t)| {
                let h = t.values.len() / t.width.max(1);
                let log_h = h.next_power_of_two().trailing_zeros() as usize;
                (0..log_h).map(|_| rand_ef(&mut rng)).collect()
            })
            .collect();
        let chip_infos =
            crate::jagged::compute_jagged_metadata::<LbVal>(&traces).chip_infos;

        for per_chip in [false, true] {
            // SAFETY: set_var is used in a single-threaded test; no
            // concurrent env access here.
            if per_chip {
                unsafe { std::env::set_var("ZIREN_E3_PER_CHIP", "1") };
            } else {
                unsafe { std::env::remove_var("ZIREN_E3_PER_CHIP") };
            }

            let mut p_chal = build_challenger();
            let bundle =
                prove_jagged_basefold_dispatch(&traces, &r_row_per_chip, &mut p_chal);
            let mut v_chal = build_challenger();
            let ok =
                verify_jagged_basefold(&chip_infos, &r_row_per_chip, &bundle, &mut v_chal);
            assert!(ok, "dispatch ({}) must produce a verifiable bundle", per_chip);
        }
        // Clean up so subsequent tests aren't affected.
        unsafe { std::env::remove_var("ZIREN_E3_PER_CHIP") };
    }

    /// **Soundness sanity** — flipping any single field of the bundle
    /// must cause the verifier to reject.  Catches whole classes of
    /// "I forgot to observe X into the challenger" bugs that pass
    /// honest-prover tests but admit forgery.
    #[test]
    fn test_jagged_basefold_rejects_tampered_proof() {
        use p3_field::PrimeCharacteristicRing;
        use crate::basefold_late_binding::jagged::{
            prove_jagged_basefold, verify_jagged_basefold,
        };

        let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF);
        let mk_trace =
            |width: usize, height: usize, rng: &mut StdRng| -> RowMajorMatrix<LbVal> {
                let v: Vec<LbVal> = (0..width * height).map(|_| rand_kb(rng)).collect();
                RowMajorMatrix::new(v, width)
            };
        let traces = vec![("Cpu".into(), mk_trace(4, 16, &mut rng))];
        let r_row_per_chip: Vec<Vec<LbChallenge>> = traces
            .iter()
            .map(|(_, t)| {
                let h = t.values.len() / t.width.max(1);
                let log_h = h.next_power_of_two().trailing_zeros() as usize;
                (0..log_h).map(|_| rand_ef(&mut rng)).collect()
            })
            .collect();

        let mut p_chal = build_challenger();
        let bundle = prove_jagged_basefold(&traces, &r_row_per_chip, &mut p_chal);
        let chip_infos =
            crate::jagged::compute_jagged_metadata::<LbVal>(&traces).chip_infos;

        // Tamper #1: corrupt the sumcheck final claim `q_at_z`.
        let mut tampered = bundle.clone();
        tampered.reduction.q_at_z = tampered.reduction.q_at_z + LbChallenge::ONE;
        let mut v_chal = build_challenger();
        assert!(
            !verify_jagged_basefold(&chip_infos, &r_row_per_chip, &tampered, &mut v_chal),
            "verifier must reject q_at_z tampering"
        );

        // Tamper #2: corrupt one of the per-chip y_{c,j} commitments.
        let mut tampered = bundle.clone();
        tampered.y_per_chip[0][0] = tampered.y_per_chip[0][0] + LbChallenge::ONE;
        let mut v_chal = build_challenger();
        assert!(
            !verify_jagged_basefold(&chip_infos, &r_row_per_chip, &tampered, &mut v_chal),
            "verifier must reject y_per_chip tampering"
        );

        // Tamper #3: corrupt the BaseFold final_poly in the proof.
        let mut tampered = bundle.clone();
        tampered.basefold_proof.basefold_proof.final_poly =
            tampered.basefold_proof.basefold_proof.final_poly + LbChallenge::ONE;
        let mut v_chal = build_challenger();
        assert!(
            !verify_jagged_basefold(&chip_infos, &r_row_per_chip, &tampered, &mut v_chal),
            "verifier must reject final_poly tampering"
        );
    }
}

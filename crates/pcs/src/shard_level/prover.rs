//! Shard-level prover assembly: transcript prologue → LogUp-GKR →
//! zerocheck → bridge observe → jagged-PCS → assemble.

use p3_challenger::CanObserve;
use p3_field::{BasedVectorSpace, ExtensionField, PrimeCharacteristicRing, PrimeField};
use p3_matrix::dense::RowMajorMatrix;

use super::shard_proof::{FoldOrientation, JaggedShardProof};
use crate::air::MachineAir;
use crate::prover::ShardData;
use crate::shard_level::row_gkr::top_level::prove_shard_logup_gkr_rows;
use crate::shard_level::zerocheck_prover::prove_shard_zerocheck;
use crate::{Challenge, Chip, ShardOpenedValues, StarkGenericConfig, Val};

/// Commits the shard's main round and returns `(C_main, precompute)`.
///
/// `main_traces` is keyed by chip name, so a trace cannot be paired with the
/// wrong chip; the round commits in the map's (name) order. `pin` is the main
/// round's area pin, `None` on a machine that commits at its natural area.
///
/// `C_main` is what the transcript observes. On the inner ring it binds the
/// packing geometry, `C_main = compress(root, H(n ‖ (h_i)_i ‖ (w_i)_i))`; on the
/// outer ring it is the root itself. The precompute is what the jagged open
/// proves against, and the open does not observe the commitment again.
///
/// The traces are borrowed: each is relabelled in place, and no cell is copied.
pub fn commit_traces<SC>(
    main_traces: &crate::traces::Traces<Val<SC>>,
    pin: Option<crate::jagged::AreaPin>,
) -> (
    [Val<SC>; 8],
    crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<<SC as crate::BasefoldRing>::BfMmcs>,
)
where
    SC: StarkGenericConfig + crate::BasefoldRing,
    Val<SC>: PrimeField + 'static,
    Challenge<SC>: ExtensionField<Val<SC>> + 'static,
    SC::Challenger: 'static,
{
    use crate::{BasefoldRing, InnerChallenge, InnerVal};
    use core::any::TypeId;

    assert!(
        TypeId::of::<Val<SC>>() == TypeId::of::<InnerVal>()
            && TypeId::of::<Challenge<SC>>() == TypeId::of::<InnerChallenge>(),
        "commit_traces: requires Val==KoalaBear / \
         Challenge==KoalaBear^4 (shared by inner + outer rings)",
    );
    let is_inner =
        TypeId::of::<SC::Challenger>() == TypeId::of::<crate::jagged_pcs::JaggedChallenger>();

    let named_inner: alloc::vec::Vec<crate::jagged_pcs::jagged::ChipTraceView> = main_traces
        .iter()
        .map(|(name, pm)| {
            let pm_inner: crate::multilinear::PaddedMle<InnerVal> = unsafe {
                core::mem::transmute_copy::<
                    crate::multilinear::PaddedMle<Val<SC>>,
                    crate::multilinear::PaddedMle<InnerVal>,
                >(&core::mem::ManuallyDrop::new(pm.clone()))
            };
            (name.clone(), pm_inner)
        })
        .collect();

    let (main_commitment, precomputed_generic): (
        [Val<SC>; 8],
        crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
            <SC as crate::BasefoldRing>::BfMmcs,
        >,
    ) = if is_inner {
        let precomputed =
            <crate::koala_bear_poseidon2::KoalaBearPoseidon2 as BasefoldRing>::commit_multilinears(
                &named_inner,
                pin,
            );
        let raw_root_inner: [InnerVal; 8] =
            crate::jagged_pcs::basefold_commit_digest(&precomputed.commit);

        let digest_inner: [InnerVal; 8] = crate::jagged_pcs::jagged_hash_bind_from_jagged_packing(
            raw_root_inner,
            &precomputed.packing,
        );
        let main_commitment: [Val<SC>; 8] =
            unsafe { core::mem::transmute_copy::<[InnerVal; 8], [Val<SC>; 8]>(&digest_inner) };

        let precomputed_generic: crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
            <SC as crate::BasefoldRing>::BfMmcs,
        > = {
            let any: Box<dyn core::any::Any> = Box::new(precomputed);
            *any.downcast().unwrap_or_else(|_| {
                panic!(
                    "commit_traces: inner build path produces a \
                     JaggedMmcs precompute == SC::BfMmcs"
                )
            })
        };
        (main_commitment, precomputed_generic)
    } else {
        let precomputed_generic = <SC as BasefoldRing>::commit_multilinears(&named_inner, pin);
        let digest_jv: [crate::jagged_pcs::JaggedVal; 8] =
            <SC as BasefoldRing>::digest_felts(&precomputed_generic.commit.original_commitment);
        let main_commitment: [Val<SC>; 8] = unsafe {
            core::mem::transmute_copy::<[crate::jagged_pcs::JaggedVal; 8], [Val<SC>; 8]>(&digest_jv)
        };
        (main_commitment, precomputed_generic)
    };

    drop(named_inner);

    (main_commitment, precomputed_generic)
}

/// Proves one shard from host-resident traces.
///
/// The transcript, in order:
///
/// ```text
///   observe  pv, C_main, n, (h_i, |name_i|, name_i)_{i<n}      prologue
///   LogUp-GKR, ending in the openings g_i(ζ)
///   sample   α, β
///   zerocheck at the cube {0,1}^m, λ drawn inside, reducing to z*
///   observe  n, (prep_i(z*), main_i(z*))_{i<n}                  name order
///   jagged open of the preprocessed and main rounds at z*
/// ```
///
/// with `h_i` the raw row count of chip `i` and `m = max_log_row_count`.
/// Everything the shard contributes arrives on `data`. A device prover runs
/// the same sequence over resident traces and must emit the same bytes.
#[allow(clippy::too_many_arguments)]
pub fn prove_shard_with_data<SC, A>(
    data: crate::prover::ShardData<'_, SC, A>,
    challenger: &mut SC::Challenger,
) -> JaggedShardProof<Val<SC>, Challenge<SC>>
where
    SC: StarkGenericConfig + crate::BasefoldRing,
    A: MachineAir<Val<SC>> + crate::shard_level::basefold_constraint_folder::ShardProvableAir<SC>,
    Val<SC>: PrimeField + 'static,
    Challenge<SC>: ExtensionField<Val<SC>> + 'static,
    SC::Challenger:
        'static
            + p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
            + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
            + CanObserve<
                <<SC as crate::BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                    crate::jagged_pcs::JaggedVal,
                >>::Commitment,
            >,
{
    let ShardData {
        chips,
        main_pin,
        preprocessed_traces,
        preprocessed_commit_data,
        main_traces,
        public_values,
        commit_data,
    } = data;
    let orientation = crate::shard_level::shard_proof::FoldOrientation::Msb;
    let max_log_row_count =
        crate::shard_level::verifier::JaggedShardVerifier::production_default().max_log_row_count;
    debug_assert!(
        main_traces.values().all(|pm| pm.num_variables() as usize == max_log_row_count),
        "prove_shard_with_data: main_traces padded to a cube != the fixed \
         max_log_row_count {max_log_row_count}",
    );
    let shared_trace_mles_vec: Vec<crate::multilinear::PaddedMle<Val<SC>>> = chips
        .iter()
        .map(|chip| {
            let name = chip.name();
            match main_traces.get(&name) {
                Some(pm) => pm.clone(),
                None => panic!("prove_shard_with_data: chip {name} missing from main_traces",),
            }
        })
        .collect();
    let shared_trace_mles: &[crate::multilinear::PaddedMle<Val<SC>>] =
        shared_trace_mles_vec.as_slice();
    debug_assert_eq!(
        chips.len(),
        shared_trace_mles.len(),
        "chips and shared_trace_mles must be parallel arrays",
    );

    let trace_views: Vec<crate::multilinear::PaddedMle<Val<SC>>> = shared_trace_mles.to_vec();
    let chip_cum_tails: Vec<Option<Vec<Val<SC>>>> = chips.iter().map(|_| None).collect();
    let n_chips = chips.len();
    let _shard_span = tracing::info_span!("prove shard with data", chips = n_chips).entered();

    let (main_commitment, precomputed_commit) = {
        let _span = tracing::info_span!("commit traces").entered();
        match commit_data {
            Some(retained) => (retained.main_commitment, retained.precomputed),
            None => commit_traces::<SC>(&main_traces, main_pin),
        }
    };

    {
        observe_transcript_prologue::<SC, A>(
            challenger,
            &public_values,
            &main_commitment,
            chips,
            shared_trace_mles,
        );
    }
    let _t_logup_gkr = std::time::Instant::now();
    let logup_gkr_proof = {
        let _span = tracing::info_span!("logup gkr proof").entered();
        prove_shard_logup_gkr_rows::<Val<SC>, Challenge<SC>, A, SC::Challenger>(
            chips,
            preprocessed_traces,
            max_log_row_count,
            challenger,
            shared_trace_mles,
        )
    };
    tracing::info!(
        elapsed_ms = _t_logup_gkr.elapsed().as_millis() as u64,
        chips = n_chips,
        phase = "logup_gkr",
        "shard phase done"
    );

    let _t_zerocheck = std::time::Instant::now();
    let (alpha, gkr_batch_open) =
        crate::shard_level::zerocheck_prover::sample_zerocheck_batching_challenges::<SC>(
            challenger,
        );

    let (zerocheck_proof, trace_at_z) = {
        let _span = tracing::info_span!("zerocheck").entered();
        let (zerocheck_proof, trace_at_z) = prove_shard_zerocheck::<SC, A>(
            chips,
            preprocessed_traces,
            &public_values,
            alpha,
            gkr_batch_open,
            &logup_gkr_proof.logup_evaluations,
            max_log_row_count,
            challenger,
            shared_trace_mles,
        );

        observe_zerocheck_openings_from_residual::<SC, A>(challenger, chips, &trace_at_z);

        (zerocheck_proof, trace_at_z)
    };
    tracing::info!(
        elapsed_ms = _t_zerocheck.elapsed().as_millis() as u64,
        chips = n_chips,
        phase = "zerocheck",
        "shard phase done"
    );

    let open_heights: Vec<Option<usize>> = shared_trace_mles
        .iter()
        .map(|pm| if pm.inner().is_none() { pm.metadata_height() } else { None })
        .collect();

    let prep_chip_infos = &preprocessed_commit_data.packing.chip_infos;
    let mut preprocessed_named: Vec<(String, crate::multilinear::PaddedMle<Val<SC>>)> =
        Vec::with_capacity(prep_chip_infos.len());
    let mut preprocessed_claims: Vec<Vec<Challenge<SC>>> =
        Vec::with_capacity(prep_chip_infos.len());
    for info in prep_chip_infos.iter() {
        let idx = chips
            .iter()
            .position(|c| MachineAir::<Val<SC>>::name(*c) == info.name)
            .unwrap_or_else(|| {
                panic!(
                    "preprocessed round: committed chip {} is absent from the shard's \
                 chip set — the proving key and the shard disagree",
                    info.name,
                )
            });
        preprocessed_named.push((info.name.clone(), preprocessed_traces[idx].clone()));
        let evals = trace_at_z.get(&info.name).unwrap_or_else(|| {
            panic!("preprocessed round: chip {} has no zerocheck residual", info.name)
        });
        assert!(
            evals.len() >= info.column_count,
            "preprocessed round: chip {} residual is {} wide but the commit has {} \
         preprocessed columns",
            info.name,
            evals.len(),
            info.column_count,
        );
        preprocessed_claims.push(evals[..info.column_count].to_vec());
    }

    let residual_y: Vec<Vec<Challenge<SC>>> = compute_residual_y_openings::<SC, A>(
        chips,
        &trace_views,
        preprocessed_traces,
        &trace_at_z,
        &logup_gkr_proof.logup_evaluations,
        &open_heights,
    );

    let _t_prove_eval_claims = std::time::Instant::now();
    let evaluation_proof = {
        let _span = tracing::info_span!("prove evaluation claims").entered();
        crate::shard_level::prover::prove_trusted_evaluations::<SC, A>(
            chips,
            &preprocessed_named,
            preprocessed_claims,
            preprocessed_commit_data,
            &trace_views,
            &zerocheck_proof.point_and_eval.0,
            challenger,
            precomputed_commit,
            residual_y,
            &[],
        )
    };
    tracing::info!(
        elapsed_ms = _t_prove_eval_claims.elapsed().as_millis() as u64,
        chips = n_chips,
        phase = "prove_evaluation_claims",
        "shard phase done"
    );

    let chip_heights = build_chip_heights::<SC, A>(chips, shared_trace_mles);

    let opened_values =
        build_opened_values::<SC, A>(chips, trace_at_z, &chip_heights, max_log_row_count);

    let chip_cumulative_sums =
        build_chip_cumulative_sums::<SC, A>(chips, shared_trace_mles, &chip_cum_tails);

    assemble_jagged_shard_proof::<SC>(
        public_values,
        main_commitment,
        logup_gkr_proof,
        zerocheck_proof,
        opened_values,
        chip_heights,
        chip_cumulative_sums,
        evaluation_proof,
        orientation,
    )
}

// Shared NON-DEVICE shard-driver orchestration helpers, `pub` so the
// ziren-gpu device-native drivers reuse them instead of duplicating.  Each
// helper's operation order + observe/sample sequence must stay in lockstep
// with the inline driver above (the drivers must emit byte-identical proofs).

/// Per-chip RAW height for the transcript prologue + the proof's
/// `chip_heights` map (the observed felt is the raw
/// `num_real_entries`, 0 allowed for an unexercised chip — NOT its
/// ceil-log2).  Device-residency aware: a device chip's REAL height is
/// baked into its dummy MLE (`metadata_height()`), floored at 1 — the
/// device dummy's VirtualGeq floor.  This is the SINGLE source for the
/// observe, the proof map and the degree-bit decomposition; deriving any
/// of them separately risks a transcript-vs-proof desync.
#[inline]
pub fn raw_chip_height<F: p3_field::Field>(pm: &crate::multilinear::PaddedMle<F>) -> usize {
    if pm.inner().is_some() {
        pm.num_real_entries()
    } else {
        pm.metadata_height().unwrap_or(0).max(1)
    }
}

/// ceil(log2(h)) with `ceil_log2(0) == 0` — the shared geometry
/// derivation for consumers that need a LOG height (shape lookups,
/// `log_degree`) from the RAW `chip_heights` value.  Kept separate from
/// the transcript felt: the prologue observes the RAW height, never this.
#[inline]
pub fn ceil_log2(h: usize) -> usize {
    if h <= 1 {
        0
    } else if h.is_power_of_two() {
        h.trailing_zeros() as usize
    } else {
        (usize::BITS - h.leading_zeros()) as usize
    }
}

/// Stage-1 transcript prologue.  Observes, in order:
/// `public_values → main_commitment → num_chips → per-chip {height_felt,
/// name_len, name_bytes}`.  These are the ONLY challenger writes of the
/// prologue; the device-native drivers call this to reproduce the exact
/// Fiat-Shamir binding of the shard's chip-set identity + per-chip row count.
pub fn observe_transcript_prologue<SC, A>(
    challenger: &mut SC::Challenger,
    public_values: &[Val<SC>],
    main_commitment: &[Val<SC>; 8],
    chips: &[&Chip<Val<SC>, A>],
    shared_trace_mles: &[crate::multilinear::PaddedMle<Val<SC>>],
) where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>,
{
    for &pv in public_values.iter() {
        challenger.observe(pv);
    }
    for &c in main_commitment.iter() {
        challenger.observe(c);
    }
    let num_chips = Val::<SC>::from_u64(chips.len() as u64);
    challenger.observe(num_chips);
    assert_eq!(
        chips.len(),
        shared_trace_mles.len(),
        "observe_transcript_prologue: chips/shared_trace_mles must be parallel",
    );
    for (chip, pm) in chips.iter().zip(shared_trace_mles.iter()) {
        let h = raw_chip_height(pm);
        challenger.observe(Val::<SC>::from_u64(h as u64));

        let name_bytes = chip.name();
        let len_felt = Val::<SC>::from_u64(name_bytes.len() as u64);
        challenger.observe(len_felt);
        for byte in name_bytes.bytes() {
            challenger.observe(Val::<SC>::from_u64(byte as u64));
        }
    }
}

/// Observe a LENGTH-PREFIXED extension-field slice.
///
/// Observes the element COUNT as one felt, then each element's basis
/// coefficients.  The prefix is what removes the parsing ambiguity between
/// two adjacent opening slices — without it, a prover free to move a column
/// between two chips (or between the preprocessed and main halves of one
/// chip) reaches the same transcript state from different opening vectors.
pub fn observe_length_prefixed_ext<F, EF, Challenger>(challenger: &mut Challenger, data: &[EF])
where
    F: p3_field::PrimeField,
    EF: BasedVectorSpace<F>,
    Challenger: p3_challenger::FieldChallenger<F>,
{
    challenger.observe(F::from_u64(data.len() as u64));
    for v in data.iter() {
        for basis in v.as_basis_coefficients_slice() {
            challenger.observe(*basis);
        }
    }
}

/// Observe the LogUp-GKR trace openings `O_{i,k} = T̃_{i,k}(anchor)`.
///
/// Called after the GKR walk fixes `anchor` and before any zerocheck
/// challenge `α, γ, λ` is sampled.  Absorbs `|chips|`, then per chip (name
/// order) the length-prefixed preprocessed openings, the openings at the
/// trailing `log h` coordinates, and the openings at the full point.
///
/// # Why before `α, γ, λ`
///
/// The verifier checks
///
/// ```text
///   Σ_i λ^i Σ_k γ^k O_{i,k}  =  Σ_i λ^i [ C̃_{α,i}(anchor) + Σ_k γ^k T̃_{i,k}(anchor) ]
/// ```
///
/// With `O` fixed first, both sides are polynomials in `α, γ, λ` and
/// Schwartz–Zippel forces `O = T̃(anchor)` and `Σ_i λ^i C̃_{α,i} = 0`.  With
/// the challenges known first, it is one linear equation in `|O|` unknowns,
/// solvable for an `O` that absorbs a nonzero constraint sum; the LogUp
/// last-layer check adds only two scalar equations on the interaction columns.
///
/// Both opening sets are absorbed, each length-prefixed, so the binding holds
/// whichever one the stage's claim uses.
pub fn observe_logup_gkr_openings<F, EF, Challenger>(
    challenger: &mut Challenger,
    num_chips: usize,
    logup_evaluations: &crate::shard_level::types::LogUpEvaluations<EF>,
) where
    F: p3_field::PrimeField,
    EF: BasedVectorSpace<F>,
    Challenger: p3_challenger::FieldChallenger<F>,
{
    challenger.observe(F::from_u64(num_chips as u64));
    for opening in logup_evaluations.chip_openings.values() {
        observe_length_prefixed_ext::<F, EF, Challenger>(
            challenger,
            opening.preprocessed_trace_evaluations_full.as_deref().unwrap_or(&[]),
        );
        observe_length_prefixed_ext::<F, EF, Challenger>(
            challenger,
            opening.main_trace_evaluations_full.as_deref().unwrap_or(&[]),
        );
    }
}

/// Observe slot **2** — the zerocheck openings (trace@z\*).
///
/// Observes the sumcheck's `component_poly_evals` right after the zerocheck
/// sumcheck returns and before the jagged phase — the `airs.len()` felt, then
/// per chip the length-prefixed preprocessed and main openings — so the
/// jagged phase's challenges are sampled with the openings they are meant to
/// be opening already bound.
///
/// `per_chip` yields `(preprocessed@z*, main@z*)` per chip in NAME order —
/// on the prover from the zerocheck residual `trace_at_z` split at each chip's
/// `preprocessed_width`, on the verifier from `opened_values.chips` (which
/// `build_opened_values` emits name-sorted with exactly that split).
pub fn observe_zerocheck_openings<'a, F, EF, Challenger, I>(
    challenger: &mut Challenger,
    num_chips: usize,
    per_chip: I,
) where
    F: p3_field::PrimeField,
    EF: BasedVectorSpace<F> + 'a,
    Challenger: p3_challenger::FieldChallenger<F>,
    I: IntoIterator<Item = (&'a [EF], &'a [EF])>,
{
    challenger.observe(F::from_u64(num_chips as u64));
    for (prep, main) in per_chip {
        observe_length_prefixed_ext::<F, EF, Challenger>(challenger, prep);
        observe_length_prefixed_ext::<F, EF, Challenger>(challenger, main);
    }
}

/// Prover-side adapter for [`observe_zerocheck_openings`]: split the zerocheck
/// residual `trace_at_z` (prep-then-main concatenated per chip) at each chip's
/// `preprocessed_width` and feed the pairs in NAME order — the same split and
/// the same order [`build_opened_values`] uses to build the `opened_values` the
/// verifier observes.
pub fn observe_zerocheck_openings_from_residual<SC, A>(
    challenger: &mut SC::Challenger,
    chips: &[&Chip<Val<SC>, A>],
    trace_at_z: &std::collections::BTreeMap<String, Vec<Challenge<SC>>>,
) where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>,
    Val<SC>: p3_field::PrimeField,
    Challenge<SC>: BasedVectorSpace<Val<SC>>,
{
    let mut name_sorted: Vec<&&Chip<Val<SC>, A>> = chips.iter().collect();
    name_sorted.sort_by_key(|a| MachineAir::<Val<SC>>::name(**a));
    observe_zerocheck_openings::<Val<SC>, Challenge<SC>, SC::Challenger, _>(
        challenger,
        chips.len(),
        name_sorted.iter().map(|chip| {
            let name = MachineAir::<Val<SC>>::name(**chip);
            let prep_width = MachineAir::<Val<SC>>::preprocessed_width(**chip);
            let evals: &[Challenge<SC>] =
                trace_at_z.get(&name).map(|v| v.as_slice()).unwrap_or(&[]);
            let split = prep_width.min(evals.len());
            evals.split_at(split)
        }),
    );
}

/// Splice D2H-rematerialized device traces into the shared host trace store.
///
/// A device-resident chip has an EMPTY host `PaddedMle` (`inner() == None`);
/// when `eager_device_remat` carries a matrix for one, rebuild its `Mle` from
/// those cells.  Every other chip is an `Arc` bump.
///
/// The remat slots are almost always `None`: `compute_skip_device_d2h` is
/// `prospective_log_dense >= ZIREN_GPU_JAGGED_PCS_MIN_LOG_SIZE`, which
/// defaults to 0 and so is always true, leaving the eager D2H for the one case
/// where a device chip has no provider height.  On the pure-host driver every
/// slot is `None` by construction, making this `shared_trace_mles.to_vec()`.
///
/// This function exists only because a device trace cannot yet BE a
/// `PaddedMle<F, CudaBackend>` — see the `MleBaseBackend` work; once it can,
/// there is nothing left to splice.
pub fn splice_device_remat_traces<SC>(
    shared_trace_mles: &[crate::multilinear::PaddedMle<Val<SC>>],
    eager_device_remat: &[Option<RowMajorMatrix<Val<SC>>>],
) -> Vec<crate::multilinear::PaddedMle<Val<SC>>>
where
    SC: StarkGenericConfig,
{
    splice_device_remat_traces_owned::<SC>(shared_trace_mles, eager_device_remat.to_vec())
}

/// [`splice_device_remat_traces`] consuming the rematerialized matrices: a
/// present matrix moves into its `PaddedMle` with no copy of its cells.
pub fn splice_device_remat_traces_owned<SC>(
    shared_trace_mles: &[crate::multilinear::PaddedMle<Val<SC>>],
    eager_device_remat: Vec<Option<RowMajorMatrix<Val<SC>>>>,
) -> Vec<crate::multilinear::PaddedMle<Val<SC>>>
where
    SC: StarkGenericConfig,
{
    shared_trace_mles
        .iter()
        .zip(eager_device_remat)
        .map(|(pm, remat)| {
            if pm.inner().is_none() {
                if let Some(m) = remat {
                    let h = m.values.len().checked_div(m.width).unwrap_or(0);
                    let log_h = if h <= 1 { 0 } else { h.next_power_of_two().ilog2() };
                    let mle = std::sync::Arc::new(crate::basefold::Mle::from_row_major(m));
                    return crate::multilinear::PaddedMle::padded_with_zeros(mle, log_h);
                }
                return pm.clone();
            }
            pm.clone()
        })
        .collect()
}

/// The jagged column claims `y_i = T̃_i(z)`, read from the zerocheck residual.
///
/// The residual `trace_at_z[chip] = (prep ‖ main)(z)` already holds `T̃_i(z)`
/// as its last `w_i` entries, so no multilinear evaluation is recomputed; the
/// result is transcript-silent.
///
/// `heights[i]` is chip `i`'s row count when its commit trace is empty
/// (device-resident); a missing entry means `h_i = 0`.  Output `i` is empty
/// when `w_i = 0` and `[0; w_i]` when `h_i = 0`.
///
/// # Panics
/// When the chip slices are not parallel, a chip has no residual, or a
/// residual's width is not `prep_i + w_i`.
pub fn compute_residual_y_openings<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    commit_traces: &[crate::multilinear::PaddedMle<Val<SC>>],
    preprocessed_traces: &[crate::multilinear::PaddedMle<Val<SC>>],
    trace_at_z: &std::collections::BTreeMap<String, Vec<Challenge<SC>>>,
    logup_evaluations: &crate::shard_level::types::LogUpEvaluations<Challenge<SC>>,
    heights: &[Option<usize>],
) -> Vec<Vec<Challenge<SC>>>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>,
{
    assert!(
        !logup_evaluations.chip_openings.is_empty(),
        "compute_residual_y_openings: LogUp-GKR produced no chip openings",
    );
    assert_eq!(
        chips.len(),
        commit_traces.len(),
        "compute_residual_y_openings: chips/commit_traces must be parallel",
    );
    assert_eq!(
        chips.len(),
        preprocessed_traces.len(),
        "compute_residual_y_openings: chips/preprocessed_traces must be parallel",
    );
    let mut out: Vec<Vec<Challenge<SC>>> = Vec::with_capacity(chips.len());
    for (idx, ((chip, ctrace), ptrace)) in
        chips.iter().zip(commit_traces.iter()).zip(preprocessed_traces.iter()).enumerate()
    {
        let name = MachineAir::<Val<SC>>::name(*chip);
        let (ctrace_values, ctrace_width) = crate::jagged::real_cells(ctrace);
        let (w, h) = if ctrace_width == 0 {
            let dev_h = heights.get(idx).copied().flatten().unwrap_or(0);
            let dev_w = trace_at_z
                .get(&name)
                .map(|evals| evals.len().saturating_sub(ptrace.num_polynomials()))
                .unwrap_or(0);
            (dev_w, dev_h)
        } else {
            let w = ctrace_width;
            (w, ctrace_values.len() / w)
        };
        if w == 0 {
            out.push(Vec::new());
            continue;
        }
        if h == 0 {
            out.push(vec![Challenge::<SC>::ZERO; w]);
            continue;
        }
        let prep_cols = ptrace.num_polynomials();
        let evals = trace_at_z.get(&name).unwrap_or_else(|| {
            panic!(
                "compute_residual_y_openings: chip {name} has no zerocheck residual — \
                 the zerocheck and the commit disagree on the chip set",
            )
        });
        assert_eq!(
            evals.len(),
            prep_cols + w,
            "compute_residual_y_openings: chip {name} residual is {} wide but the chip \
             has {prep_cols} preprocessed + {w} main columns",
            evals.len(),
        );
        out.push(evals[prep_cols..].to_vec());
    }
    out
}

/// Per-chip RAW height map (the value stored on the proof as
/// `chip_heights`, observed in the Phase-1 prologue AND the VirtualGeq
/// threshold feeding the `opened_values` degree-bit decomposition),
/// device-residency aware.  MUST agree with the Phase-1 prologue observe +
/// the verifier re-observe — all three read [`raw_chip_height`].
pub fn build_chip_heights<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    shared_trace_mles: &[crate::multilinear::PaddedMle<Val<SC>>],
) -> std::collections::BTreeMap<String, usize>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>,
{
    let mut chip_heights = std::collections::BTreeMap::new();
    assert_eq!(
        chips.len(),
        shared_trace_mles.len(),
        "build_chip_heights: chips/shared_trace_mles must be parallel",
    );
    for (chip, pm) in chips.iter().zip(shared_trace_mles.iter()) {
        let h = raw_chip_height(pm);
        let name = MachineAir::<Val<SC>>::name(*chip);
        chip_heights.insert(name, h);
    }
    chip_heights
}

/// Per-chip trace@z opened values, emitted in chip-NAME order (matching the
/// recursion `opened_values.chips` BTreeMap key order).
/// `trace_at_z` is prep-then-main per chip; the REAL height's big-endian bit
/// decomposition is carried via the `quotient` slot for the recursion
/// `full_geq` degree.
pub fn build_opened_values<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    mut trace_at_z: std::collections::BTreeMap<String, Vec<Challenge<SC>>>,
    chip_heights: &std::collections::BTreeMap<String, usize>,
    max_log_row_count: usize,
) -> ShardOpenedValues<Val<SC>, Challenge<SC>>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>,
{
    let mut name_sorted: Vec<&&Chip<Val<SC>, A>> = chips.iter().collect();
    name_sorted.sort_by_key(|a| MachineAir::<Val<SC>>::name(**a));
    let chip_opened: Vec<crate::types::ChipOpenedValues<Val<SC>, Challenge<SC>>> = name_sorted
        .iter()
        .map(|chip| {
            let name = MachineAir::<Val<SC>>::name(**chip);
            let prep_width = MachineAir::<Val<SC>>::preprocessed_width(**chip);
            let mut prep_local: Vec<Challenge<SC>> = trace_at_z.remove(&name).unwrap_or_default();
            let split = prep_width.min(prep_local.len());
            let main_local = prep_local.split_off(split);
            let height = *chip_heights.get(&name).unwrap_or(&0);
            let log_degree = ceil_log2(height);
            let bit_len = max_log_row_count + 1;
            let degree_bits: Vec<Challenge<SC>> = (0..bit_len)
                .map(|i| {
                    let shift = bit_len - 1 - i;
                    let bit = if shift < usize::BITS as usize { (height >> shift) & 1 } else { 0 };
                    if bit == 1 {
                        Challenge::<SC>::ONE
                    } else {
                        Challenge::<SC>::ZERO
                    }
                })
                .collect();
            crate::types::ChipOpenedValues {
                preprocessed: crate::types::AirOpenedValues { local: prep_local, next: Vec::new() },
                main: crate::types::AirOpenedValues { local: main_local, next: Vec::new() },
                permutation: crate::types::AirOpenedValues { local: Vec::new(), next: Vec::new() },
                quotient: vec![degree_bits],
                global_cumulative_sum: crate::septic_digest::SepticDigest::<Val<SC>>::zero(),
                local_cumulative_sum: Challenge::<SC>::ZERO,
                log_degree,
            }
        })
        .collect();
    ShardOpenedValues { chips: chip_opened }
}

/// Per-chip (local, global) cumulative sums.  `local` is ZERO
/// (the basefold path doesn't materialize the permutation trace); `global`
/// reads the RAW per-chip cells at their raw heights (device chips use the
/// early-captured provider TAIL, `chip_cum_tails`).
pub fn build_chip_cumulative_sums<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    shared_trace_mles: &[crate::multilinear::PaddedMle<Val<SC>>],
    chip_cum_tails: &[Option<Vec<Val<SC>>>],
) -> std::collections::BTreeMap<
    String,
    crate::shard_level::shard_proof::ChipCumulativeSums<Val<SC>, Challenge<SC>>,
>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>,
{
    assert_eq!(
        chips.len(),
        shared_trace_mles.len(),
        "build_chip_cumulative_sums: chips/shared_trace_mles must be parallel",
    );
    assert_eq!(
        chips.len(),
        chip_cum_tails.len(),
        "build_chip_cumulative_sums: chips/chip_cum_tails must be parallel",
    );
    chips
        .iter()
        .zip(shared_trace_mles.iter())
        .zip(chip_cum_tails.iter())
        .map(|((chip, pm), tail)| {
            let name = MachineAir::<Val<SC>>::name(*chip);
            let global = if let Some(tail14) = tail {
                crate::shard_level::zerocheck_prover::chip_global_cumulative_sum_from_tail(
                    *chip, tail14,
                )
            } else {
                let vals: &[Val<SC>] = pm.real_trace_ref().map(|tr| tr.values).unwrap_or(&[]);
                crate::shard_level::zerocheck_prover::chip_global_cumulative_sum_from_values(
                    *chip, vals,
                )
            };
            let local = Challenge::<SC>::ZERO;
            (name, crate::shard_level::shard_proof::ChipCumulativeSums { local, global })
        })
        .collect()
}

/// The final `JaggedShardProof` construction.  Derives
/// the witnessed per-round row/padding-column counts and the RAW
/// BaseFold root (`jagged_original_commitment`) from `evaluation_proof`, then
/// moves every piece into the proof.  PURE DATA — no transcript.
#[allow(clippy::too_many_arguments)]
pub fn assemble_jagged_shard_proof<SC>(
    public_values: Vec<Val<SC>>,
    main_commitment: [Val<SC>; 8],
    logup_gkr_proof: crate::shard_level::types::LogupGkrProof<Val<SC>, Challenge<SC>>,
    zerocheck_proof: crate::shard_level::types::PartialSumcheckProof<Challenge<SC>>,
    opened_values: ShardOpenedValues<Val<SC>, Challenge<SC>>,
    chip_heights: std::collections::BTreeMap<String, usize>,
    chip_cumulative_sums: std::collections::BTreeMap<
        String,
        crate::shard_level::shard_proof::ChipCumulativeSums<Val<SC>, Challenge<SC>>,
    >,
    evaluation_proof: crate::shard_level::shard_proof::EvaluationProof,
    orientation: FoldOrientation,
) -> JaggedShardProof<Val<SC>, Challenge<SC>>
where
    SC: StarkGenericConfig,
{
    let (row_counts, padding_column_counts): (Vec<Vec<usize>>, Vec<usize>) = match &evaluation_proof
    {
        crate::shard_level::shard_proof::EvaluationProof::Bundle(bundle) => {
            let (rc, pcc) = crate::jagged::derive_row_and_padding_counts(
                &bundle.packing.column_counts,
                &bundle.packing.offsets,
                bundle.packing.total_values,
            );
            (vec![rc], vec![pcc])
        }
        _ => (Vec::new(), Vec::new()),
    };

    let jagged_original_commitment: [Val<SC>; 8] = match &evaluation_proof {
        crate::shard_level::shard_proof::EvaluationProof::Bundle(bundle) => {
            let raw_inner = crate::jagged_pcs::basefold_commit_digest(&bundle.commit);
            unsafe { core::mem::transmute_copy::<[crate::InnerVal; 8], [Val<SC>; 8]>(&raw_inner) }
        }
        _ => main_commitment,
    };

    let (preprocessed_original_commitment, preprocessed_row_counts): ([Val<SC>; 8], Vec<Val<SC>>) =
        match &evaluation_proof {
            crate::shard_level::shard_proof::EvaluationProof::Bundle(bundle)
                if !bundle.preceding_commits.is_empty()
                    && bundle.packing.round_counts.len() >= 2 =>
            {
                let raw_inner =
                    crate::jagged_pcs::basefold_commit_digest_felts(&bundle.preceding_commits[0]);
                let raw = unsafe {
                    core::mem::transmute_copy::<[crate::InnerVal; 8], [Val<SC>; 8]>(&raw_inner)
                };
                let heights: Vec<Val<SC>> = bundle.packing.round_counts[0]
                    .iter()
                    .map(|(h, _w)| Val::<SC>::from_usize(*h))
                    .collect();
                (raw, heights)
            }
            _ => ([Val::<SC>::ZERO; 8], Vec::new()),
        };

    let padding_row_heights: Vec<Vec<Val<SC>>> = match &evaluation_proof {
        crate::shard_level::shard_proof::EvaluationProof::Bundle(bundle) => bundle
            .packing
            .padding_heights
            .iter()
            .map(|round| round.iter().map(|h| Val::<SC>::from_usize(*h)).collect())
            .collect(),
        _ => Vec::new(),
    };

    JaggedShardProof {
        public_values,
        main_commitment,
        padding_row_heights,
        logup_gkr_proof,
        zerocheck_proof,
        opened_values,
        chip_heights,
        chip_cumulative_sums,
        evaluation_proof,
        fold_orientation: orientation,
        row_counts,
        padding_column_counts,
        jagged_original_commitment,
        preprocessed_original_commitment,
        preprocessed_row_counts,
    }
}

/// Prove the trusted evaluations `y_k = T̃_k(z_row)` for every global column
/// `k` of the preprocessed and main rounds, the openings zerocheck consumed.
///
/// Let `Q` be the dense polynomial of both rounds in the order
/// `[preprocessed, main]`, each padded to its stacking area, and let column `k`
/// start at packed offset `o_k`.  After the openings are observed, one fresh
/// `z_col` is sampled for all columns of both rounds, and with
/// `W[o_k + j] = χ_k(z_col)·χ_j(z_row)`
///
/// ```text
///   t = Σ_k χ_k(z_col)·y_k = Σ_x Q[x]·W[x].
/// ```
///
/// The jagged sumcheck reduces `t` to `Q(r)·W(r)`, the jagged-evaluation proof
/// gives `W(r)` from the offsets, `z_row`, `z_col` and `r`, and the PCS opening
/// proves `Q(r)` against every round commitment.
///
/// * `main_traces`: borrowed views of the committed traces, never copied.
/// * `precomputed_commit`: the main commit, whose digest the transcript
///   already observed, so it is not observed again.
/// * `pre_y_per_chip[i]`: chip `i`'s `w_i` main-column claims; `w_i` zeros when
///   `h_i = 0`, empty only when `w_i = 0`.
/// * `heights[i]`: `h_i` of a chip whose commit trace is empty; a missing entry
///   means `h_i = 1`.
///
/// The ring-specific open is [`crate::BasefoldRing::prove_jagged_open`]; both
/// rings open the claims above.
///
/// # Panics
/// Unless `Val<SC> = KoalaBear` and `Challenge<SC> = KoalaBear⁴`, which makes
/// every `Val<SC> → InnerVal` reinterpret a layout-identical relabel; and
/// when `|chips| ≠ |main_traces|`.
#[allow(clippy::too_many_arguments)]
pub fn prove_trusted_evaluations<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    preprocessed_named: &[(String, crate::multilinear::PaddedMle<Val<SC>>)],
    preprocessed_claims: Vec<Vec<Challenge<SC>>>,
    preprocessed_commit: &crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
        <SC as crate::BasefoldRing>::BfMmcs,
    >,
    main_traces: &[crate::multilinear::PaddedMle<Val<SC>>],
    shared_eval_point: &[Challenge<SC>],
    challenger: &mut SC::Challenger,
    precomputed_commit: crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
        <SC as crate::BasefoldRing>::BfMmcs,
    >,
    pre_y_per_chip: Vec<Vec<Challenge<SC>>>,
    heights: &[Option<usize>],
) -> crate::shard_level::shard_proof::EvaluationProof
where
    SC: StarkGenericConfig + crate::BasefoldRing,
    A: MachineAir<Val<SC>>,
    Val<SC>: PrimeField + 'static,
    Challenge<SC>: ExtensionField<Val<SC>> + 'static,
    SC::Challenger:
        'static
            + p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
            + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
            + p3_challenger::CanObserve<
                <<SC as crate::BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                    crate::jagged_pcs::JaggedVal,
                >>::Commitment,
            >,
{
    use crate::{BasefoldRing, InnerChallenge, InnerVal};
    use core::any::TypeId;

    assert!(
        TypeId::of::<Val<SC>>() == TypeId::of::<InnerVal>()
            && TypeId::of::<Challenge<SC>>() == TypeId::of::<InnerChallenge>(),
        "prove_trusted_evaluations requires Val==KoalaBear /          Challenge==KoalaBear^4 (shared by inner + outer rings) for the trace/point          transmutes below",
    );

    unsafe fn reinterpret_vec<A, B>(v: alloc::vec::Vec<A>) -> alloc::vec::Vec<B> {
        let mut v = core::mem::ManuallyDrop::new(v);
        alloc::vec::Vec::from_raw_parts(v.as_mut_ptr() as *mut B, v.len(), v.capacity())
    }

    assert_eq!(
        chips.len(),
        main_traces.len(),
        "prove_trusted_evaluations: chips/main_traces must be parallel",
    );

    let r_row_per_chip: Vec<Vec<InnerChallenge>> = chips
        .iter()
        .zip(main_traces.iter())
        .enumerate()
        .map(|(i, (_chip, pm))| {
            let (tvals, twidth) = crate::jagged::real_cells(pm);
            let main_height = tvals
                .len()
                .checked_div(twidth)
                .unwrap_or_else(|| heights.get(i).copied().flatten().unwrap_or(1));
            let log_h = main_height.max(1).next_power_of_two().trailing_zeros() as usize;
            let slice: &[Challenge<SC>] = if shared_eval_point.len() >= log_h {
                &shared_eval_point[shared_eval_point.len() - log_h..]
            } else {
                shared_eval_point
            };
            unsafe { reinterpret_vec::<Challenge<SC>, InnerChallenge>(slice.to_vec()) }
        })
        .collect();

    let chip_traces: Vec<crate::jagged_pcs::jagged::ChipTraceView> = chips
        .iter()
        .zip(main_traces.iter())
        .map(|(chip, pm)| {
            let name = chip.name();
            let pm_inner: crate::multilinear::PaddedMle<InnerVal> = unsafe {
                core::mem::transmute_copy::<
                    crate::multilinear::PaddedMle<Val<SC>>,
                    crate::multilinear::PaddedMle<InnerVal>,
                >(&core::mem::ManuallyDrop::new(pm.clone()))
            };
            (name, pm_inner)
        })
        .collect();

    let z_row: &[InnerChallenge] = unsafe {
        core::slice::from_raw_parts(
            shared_eval_point.as_ptr() as *const InnerChallenge,
            shared_eval_point.len(),
        )
    };

    let pre_y_inner: Vec<Vec<InnerChallenge>> = pre_y_per_chip
        .into_iter()
        .map(|v| unsafe { reinterpret_vec::<Challenge<SC>, InnerChallenge>(v) })
        .collect();

    let prep_r_row_per_chip: Vec<Vec<InnerChallenge>> = preprocessed_named
        .iter()
        .map(|(_name, pm)| {
            let (tvals, twidth) = crate::jagged::real_cells(pm);
            let h = tvals.len().checked_div(twidth).unwrap_or(1);
            let log_h = h.max(1).next_power_of_two().trailing_zeros() as usize;
            let slice: &[Challenge<SC>] = if shared_eval_point.len() >= log_h {
                &shared_eval_point[shared_eval_point.len() - log_h..]
            } else {
                shared_eval_point
            };
            unsafe { reinterpret_vec::<Challenge<SC>, InnerChallenge>(slice.to_vec()) }
        })
        .collect();
    let prep_chip_traces: Vec<crate::jagged_pcs::jagged::ChipTraceView> = preprocessed_named
        .iter()
        .map(|(name, pm)| {
            let pm_inner: crate::multilinear::PaddedMle<InnerVal> = unsafe {
                core::mem::transmute_copy::<
                    crate::multilinear::PaddedMle<Val<SC>>,
                    crate::multilinear::PaddedMle<InnerVal>,
                >(&core::mem::ManuallyDrop::new(pm.clone()))
            };
            (name.clone(), pm_inner)
        })
        .collect();
    let prep_claims_inner: Vec<Vec<InnerChallenge>> = preprocessed_claims
        .into_iter()
        .map(|v| unsafe { reinterpret_vec::<Challenge<SC>, InnerChallenge>(v) })
        .collect();

    let mut rounds: Vec<crate::jagged_pcs::jagged::JaggedOpenRound<'_, _>> = Vec::with_capacity(2);
    if !prep_chip_traces.is_empty() {
        rounds.push(crate::jagged_pcs::jagged::JaggedOpenRound {
            chip_traces: &prep_chip_traces,
            r_row_per_chip: &prep_r_row_per_chip,
            claims: prep_claims_inner,
            precomputed: preprocessed_commit,
        });
    }
    rounds.push(crate::jagged_pcs::jagged::JaggedOpenRound {
        chip_traces: &chip_traces,
        r_row_per_chip: &r_row_per_chip,
        claims: pre_y_inner,
        precomputed: &precomputed_commit,
    });
    <SC as BasefoldRing>::prove_jagged_open(z_row, rounds, challenger)
}

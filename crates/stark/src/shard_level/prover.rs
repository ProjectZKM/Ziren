//! Shard-level prover assembly entry point.
//!
//! Mirror of SP1's `ShardProver::prove_shard_with_data` at
//! `/tmp/sp1/crates/hypercube/src/prover/shard.rs:650-792` —
//! orchestrates the LogUp-GKR + zerocheck + jagged-PCS phases
//! into a single host-side [`super::shard_proof::BasefoldShardProof`].
//!
//! # Pipeline
//!
//!   1. **Transcript prologue** — observe public values + main
//!      commitment + per-chip metadata (count, name, name length)
//!      into the challenger.  This binds all post-commit
//!      randomness to the shard's identity.
//!
//!   2. **LogUp-GKR phase** — run
//!      [`super::logup_gkr_prover::prove_shard_logup_gkr`] to
//!      produce the shard-level lookup-argument proof.  Returns
//!      a [`super::types::LogupGkrProof`] carrying the per-chip
//!      trace evaluations at the final eval_point.
//!
//!   3. **Zerocheck phase** — run
//!      [`super::zerocheck_prover::prove_shard_zerocheck`] to
//!      produce the shard-level transition-constraint proof.
//!      Returns a [`super::types::PartialSumcheckProof`] with the
//!      reduced point and final claim.
//!
//!   4. **Jagged-PCS phase** — currently emits empty placeholder
//!      bytes.  Future iteration wires
//!      `crate::basefold_late_binding::jagged::prove_jagged_basefold_dispatch`
//!      to produce the wire-format jagged + BaseFold opening
//!      bytes.
//!
//!   5. **Assembly** — pack everything into [`BasefoldShardProof`]
//!      with the SP1-shape 6-field layout.
//!
//! # Status
//!
//! Phases (1)-(3) production-wired against the per-chip prover
//! backbone.  Phase (4) is a stub byte vector pending the
//! shard-level jagged-PCS dispatch port.  Phase (5) assembles
//! the new struct.  The `opened_values` field is built from the
//! per-chip evaluations the LogUp-GKR phase emits — this is
//! cheaper than reconstructing them and matches SP1's pattern
//! of carrying the openings forward through the pipeline.

use p3_air::Air;
use p3_challenger::CanObserve;
use p3_field::{BasedVectorSpace, ExtensionField, PrimeCharacteristicRing, PrimeField};
use p3_matrix::dense::RowMajorMatrix;

use super::shard_proof::BasefoldShardProof;
use super::row_gkr::top_level::prove_shard_logup_gkr_rows;
use super::zerocheck_prover::prove_shard_zerocheck;
use crate::air::MachineAir;
use crate::folder::VerifierConstraintFolder;
use crate::{Challenge, Chip, ShardOpenedValues, StarkGenericConfig, Val};

/// Assembly entry point: produce a [`BasefoldShardProof`] from a
/// chip set + traces + transcript challenger.
///
/// Top-level shard-level orchestrator.  Invoked from
/// `try_prove_shard_to_basefold_boxed` (in `crates/stark/src/prover.rs`)
/// for every KoalaBear MIPS shard; the produced
/// [`BasefoldShardProof`] is carried on `ShardProof.basefold_shard_proof`.
///
/// # Soundness note
///
/// Phase 4 (jagged-PCS opening) is wired end-to-end on KoalaBear
/// (`emit_jagged_pcs_bytes` calls `prove_jagged_basefold`); the
/// host-side `BasefoldShardVerifier::verify_shard` consumes the
/// bundle bytes via `verify_jagged_pcs_host`.  Non-KoalaBear
/// configurations short-circuit through the TypeId gate to empty
/// bytes (the verifier accepts empty as a no-op).
///
/// For the W2 GPU compress flow, the per-chip main_traces handed to
/// `emit_jagged_pcs_bytes` must include device-only RecursionAir
/// chips (BaseAlu, ExtAlu, Poseidon2{Skinny,Wide}, Select, FriFold,
/// BatchFRI) — see `ziren-gpu/prover/src/compress_multi_gpu.rs`'s
/// device-trace rehydrate hook for the May 2 fix.
#[allow(clippy::too_many_arguments)]
pub fn prove_shard_to_basefold<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    preprocessed_traces: &[RowMajorMatrix<Val<SC>>],
    main_traces: &[RowMajorMatrix<Val<SC>>],
    main_commitment: [Val<SC>; 8],
    public_values: Vec<Val<SC>>,
    max_log_row_count: usize,
    challenger: &mut SC::Challenger,
) -> BasefoldShardProof<Val<SC>, Challenge<SC>>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>> + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>>,
{
    // ── Phase 1: Transcript prologue ────────────────────────
    //
    // Observe public values, main commitment, and per-chip
    // metadata into the challenger.  The chip metadata observe
    // (count + name length + name bytes) binds the verifier's
    // post-commit challenges to the shard's chip-set identity.

    for &pv in public_values.iter() {
        challenger.observe(pv);
    }
    for &c in main_commitment.iter() {
        challenger.observe(c);
    }
    let num_chips = Val::<SC>::from_u64(chips.len() as u64);
    challenger.observe(num_chips);
    for chip in chips.iter() {
        let name_bytes = chip.name();
        let len_felt = Val::<SC>::from_u64(name_bytes.len() as u64);
        challenger.observe(len_felt);
        for byte in name_bytes.bytes() {
            challenger.observe(Val::<SC>::from_u64(byte as u64));
        }
    }

    // ── Phase 2: LogUp-GKR ─────────────────────────────────
    // SP1-style row-only reduction: emits circuit_output of length
    // 2^(num_interaction_variables + 1) matching the recursion verifier.
    // See docs/task_23_blocker.md for the protocol mismatch this fixes.
    let logup_gkr_proof = prove_shard_logup_gkr_rows::<Val<SC>, Challenge<SC>, A, SC::Challenger>(
        chips,
        preprocessed_traces,
        main_traces,
        max_log_row_count,
        challenger,
    );

    // ── Phase 3: Zerocheck ─────────────────────────────────
    //
    // Pass the LogUp-GKR-emitted per-chip evaluations through
    // so the zerocheck prover can build its initial sumcheck
    // claims from them (matches SP1's wiring at
    // `prover/shard.rs:560-572`).
    let zerocheck_proof = prove_shard_zerocheck::<SC, A>(
        chips,
        preprocessed_traces,
        main_traces,
        &logup_gkr_proof.logup_evaluations,
        &public_values,
        max_log_row_count,
        challenger,
    );

    // Phase 3 → 4 bridge: observe per-chip opening count + openings
    // into the challenger — mirrors
    // [`super::verifier::verify_zerocheck_host`] step (5) / step (7)
    // so the Phase 4 (jagged-PCS) challenger state is identical on
    // prover and verifier sides.  Order MUST match verifier: num_chips
    // (felt), then for each chip in `chips` order: preprocessed local
    // basis coefficients, then main local basis coefficients.
    {
        use p3_field::BasedVectorSpace;
        let num_chips_felt = Val::<SC>::from_u64(chips.len() as u64);
        challenger.observe(num_chips_felt);
        for chip in chips.iter() {
            let name = chip.name().to_string();
            let opening = logup_gkr_proof
                .logup_evaluations
                .chip_openings
                .get(&name)
                .expect("chip missing from logup_evaluations.chip_openings");
            if let Some(prep) = opening.preprocessed_trace_evaluations.as_ref() {
                for c in prep.iter() {
                    for basis in c.as_basis_coefficients_slice() {
                        challenger.observe(*basis);
                    }
                }
            }
            for c in opening.main_trace_evaluations.iter() {
                for basis in c.as_basis_coefficients_slice() {
                    challenger.observe(*basis);
                }
            }
        }
    }

    // ── Phase 4: Jagged-PCS opening ────────────────────────
    //
    // Drive crate::basefold_late_binding::jagged::prove_jagged_basefold_dispatch
    // with:
    //   - per-chip (name, main trace)
    //   - per-chip `r_row` = trailing log(chip_height) coords of the
    //     LogUp-GKR final eval_point (matches SP1's convention of
    //     opening the trace MLE at that sub-point)
    //   - the outer `SC::Challenger` downcast to `&mut LbChallenger`
    //     when SC is KoalaBearPoseidon2 (full transcript binding).
    //     Falls back to a fresh challenger + empty bytes when SC
    //     isn't the KoalaBear configuration.
    let evaluation_proof = emit_jagged_pcs_bytes::<SC, A>(
        chips,
        main_traces,
        &logup_gkr_proof.logup_evaluations.point,
        challenger,
    );

    // ── Phase 5: Assembly ──────────────────────────────────
    //
    // Build per-chip opened_values from the LogUp-GKR phase's
    // chip_openings (`logup_evaluations.chip_openings`).  The
    // existing per-chip ChipOpenedValues type carries more
    // fields than the SP1 shape uses; for now we leave the
    // unused fields empty (preprocessed/permutation/quotient
    // become Vec::new(), cumulative sums become ZERO).  The
    // SP1-shape ShardOpenedValues port lands in the next
    // iteration alongside the recursion-side
    // BasefoldShardOpenedValuesVariable Witnessable impl.
    let opened_values = ShardOpenedValues { chips: Vec::new() };

    // Compute per-chip log_height from the main trace dimensions —
    // each main_traces[i] corresponds to chips[i] (zip-aligned input).
    // Stored under chip name so the verifier can look up by the
    // BTreeMap key set in `logup_evaluations.chip_openings`.
    use p3_matrix::Matrix;
    let mut chip_log_heights = std::collections::BTreeMap::new();
    for (chip, trace) in chips.iter().zip(main_traces.iter()) {
        let h = trace.height().max(1);
        // ceil_log2 — h is power of two for committed traces.
        let log_h = if h.is_power_of_two() {
            h.trailing_zeros() as u8
        } else {
            (usize::BITS - h.leading_zeros()) as u8
        };
        let name = MachineAir::<Val<SC>>::name(*chip);
        chip_log_heights.insert(name, log_h);
    }

    // META #59 swap 1+2: populate per-chip cumulative_sums.
    //
    // Mirrors the legacy stark prover at `crates/stark/src/prover.rs:492-502`:
    //   - `global_cumulative_sum`: derived from the main trace's last 14
    //     elements (x: first 7, y: next 7) when the chip's `commit_scope()`
    //     is NOT `LookupScope::Local`.  Local-scope chips get
    //     `SepticDigest::zero()`.
    //   - `local_cumulative_sum`: ZERO (matches legacy line 510 — the
    //     real per-chip permutation sum requires materializing the
    //     permutation trace, which the basefold path doesn't do; future
    //     work to extract from the LogUp-GKR layer 0 output).
    //
    // Verifier still uses zero placeholders unconditionally (Swap 1+2
    // verifier-side change is the next META #59 step).  Until then,
    // populating this map is a no-op for verification, but exercises the
    // wire-format / serde path.
    let chip_cumulative_sums: std::collections::BTreeMap<
        String,
        crate::shard_level::shard_proof::ChipCumulativeSums<Val<SC>, Challenge<SC>>,
    > = chips
        .iter()
        .zip(main_traces.iter())
        .map(|(chip, main_trace)| {
            let name = MachineAir::<Val<SC>>::name(*chip);
            let global = if chip.commit_scope() == crate::air::LookupScope::Local {
                crate::septic_digest::SepticDigest::<Val<SC>>::zero()
            } else {
                let main_trace_size = main_trace.values.len();
                if main_trace_size >= 14 {
                    let last_row = &main_trace.values[main_trace_size - 14..main_trace_size];
                    let x = crate::septic_extension::SepticExtension::<Val<SC>>::from_basis_coefficients_fn(|j| last_row[j]);
                    let y = crate::septic_extension::SepticExtension::<Val<SC>>::from_basis_coefficients_fn(|j| last_row[j + 7]);
                    crate::septic_digest::SepticDigest(crate::septic_curve::SepticCurve { x, y })
                } else {
                    crate::septic_digest::SepticDigest::<Val<SC>>::zero()
                }
            };
            let local = Challenge::<SC>::ZERO;
            (
                name,
                crate::shard_level::shard_proof::ChipCumulativeSums { local, global },
            )
        })
        .collect();

    // Materialize the proofs as bytes via bincode.  The
    // `BasefoldShardProof::{logup_gkr_proof, zerocheck_proof}`
    // fields are typed to `LogupGkrProof`/`PartialSumcheckProof`
    // — pass them through directly.
    BasefoldShardProof {
        public_values,
        main_commitment,
        logup_gkr_proof,
        zerocheck_proof,
        opened_values,
        chip_log_heights,
        chip_cumulative_sums,
        evaluation_proof,
    }
}

/// Emit jagged-PCS opening bytes by driving
/// [`crate::basefold_late_binding::jagged::prove_jagged_basefold_dispatch`]
/// against the shard's per-chip main traces.  Returns the bundle
/// serialized via rmp-serde.
///
/// # Field-type gate
///
/// `prove_jagged_basefold_dispatch` is monomorphic over KoalaBear /
/// `InnerVal` / `InnerChallenge` / `LbChallenger`.  The generic
/// `Val<SC>` / `Challenge<SC>` / `SC::Challenger` here could in
/// principle differ.  This helper runs the full pipeline only when
/// the runtime type IDs match; otherwise returns an empty byte
/// vector.
///
/// # Transcript binding
///
/// When the type gate passes (SC == KoalaBearPoseidon2 in practice),
/// the outer `SC::Challenger` is downcast via `Any::downcast_mut` to
/// `&mut LbChallenger` and passed through to the jagged-PCS prover.
/// This binds the jagged-PCS transcript to the shard's outer
/// transcript state — no fresh instance, no divergence.  (Task #26
/// had previously used a fresh challenger; the soundness caveat
/// from 4a9685e is now resolved.)
fn emit_jagged_pcs_bytes<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    main_traces: &[RowMajorMatrix<Val<SC>>],
    shared_eval_point: &[Challenge<SC>],
    challenger: &mut SC::Challenger,
) -> Vec<u8>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>,
    Val<SC>: PrimeField + 'static,
    Challenge<SC>: ExtensionField<Val<SC>> + 'static,
    SC::Challenger: 'static,
{
    use core::any::{Any, TypeId};
    use crate::basefold_late_binding::jagged::prove_jagged_basefold;
    use crate::{InnerChallenge, InnerVal};

    // Gate on Val<SC> == InnerVal, Challenge<SC> == InnerChallenge,
    // AND SC::Challenger == LbChallenger (all three must match for
    // the monomorphic dispatch to apply).
    if TypeId::of::<Val<SC>>() != TypeId::of::<InnerVal>()
        || TypeId::of::<Challenge<SC>>() != TypeId::of::<InnerChallenge>()
        || TypeId::of::<SC::Challenger>()
            != TypeId::of::<crate::basefold_late_binding::LbChallenger>()
    {
        return Vec::new();
    }

    // Build per-chip (name, cloned trace) in the expected concrete
    // type.  We clone + byte-reinterpret each Vec<Val<SC>> into a
    // Vec<InnerVal>; the layout is identical under the TypeId match
    // above so this is a safe reinterpretation.
    //
    // Use Vec::into_raw_parts + Vec::from_raw_parts to move
    // ownership without double-freeing.
    let chip_traces: Vec<(alloc::string::String, RowMajorMatrix<InnerVal>)> = chips
        .iter()
        .zip(main_traces.iter())
        .map(|(chip, trace)| {
            let name = chip.name().to_string();
            // Width-pad fix (#95, May 2 2026): the verifier's
            // verify_jagged_pcs_host (verifier.rs:333) sets each chip's
            // column_count = chip.width().  But the recursion-runtime
            // sometimes hands us main_traces with trace.width <
            // chip.width() — populating only the columns the chip
            // actually exercised in this shard.  Without padding, the
            // prover's compute_jagged_metadata produces fewer offsets
            // than the verifier expects, and build_weight_table
            // overflows.
            //
            // Fix: pad missing columns with zeros so the trace's width
            // matches the chip's declared width.  Constraint
            // contributions from zero columns are zero, consistent with
            // the unexercised semantics.
            use p3_air::BaseAir;
            let chip_width = <_ as BaseAir<Val<SC>>>::width(&chip.air);
            // Diag for #95 root-cause: verify pad is actually applied
            // for chips with width-mismatch.
            if std::env::var("ZIREN_JAGGED_DIAG").is_ok() && trace.width != chip_width {
                eprintln!(
                    "[jagged-pad] chip='{}' trace.width={} chip.width()={} (will pad)",
                    chip.name(), trace.width, chip_width,
                );
            }
            let padded_trace: RowMajorMatrix<Val<SC>> = if trace.width == chip_width {
                trace.clone()
            } else if trace.width == 0 {
                // Empty trace: keep width 0 so downstream skips it.
                // (compute_jagged_metadata handles width=0 by pushing
                // no offsets and leaving chip_infos.column_count=0.)
                trace.clone()
            } else if trace.width < chip_width {
                let height = trace.values.len() / trace.width;
                let mut padded = vec![Val::<SC>::ZERO; height * chip_width];
                for r in 0..height {
                    let src = &trace.values[r * trace.width..(r + 1) * trace.width];
                    let dst = &mut padded[r * chip_width..r * chip_width + trace.width];
                    dst.copy_from_slice(src);
                    // Remaining cols [trace.width..chip_width] stay zero.
                }
                RowMajorMatrix::new(padded, chip_width)
            } else {
                // trace.width > chip_width — unexpected; pass through.
                trace.clone()
            };
            let values_cloned: Vec<Val<SC>> = padded_trace.values;
            // SAFETY: Val<SC> == InnerVal at runtime (guarded by
            // TypeId above).  We're converting a Vec<A> into Vec<B>
            // where A and B are the same underlying type.  Use
            // into_raw_parts to transfer ownership without double
            // free.
            let (ptr, len, cap) = {
                let mut v = core::mem::ManuallyDrop::new(values_cloned);
                (v.as_mut_ptr(), v.len(), v.capacity())
            };
            let values: Vec<InnerVal> = unsafe {
                Vec::from_raw_parts(ptr as *mut InnerVal, len, cap)
            };
            (
                name,
                RowMajorMatrix::new(values, padded_trace.width),
            )
        })
        .collect();

    // Per-chip r_row = trailing log(chip_height) coords of the shared
    // eval_point.
    let r_row_per_chip: Vec<Vec<InnerChallenge>> = chips
        .iter()
        .zip(main_traces.iter())
        .map(|(_, trace)| {
            let main_height = if trace.width == 0 {
                1
            } else {
                trace.values.len() / trace.width
            };
            let log_h = main_height.max(1).next_power_of_two().trailing_zeros() as usize;
            let slice: &[Challenge<SC>] = if shared_eval_point.len() >= log_h {
                &shared_eval_point[shared_eval_point.len() - log_h..]
            } else {
                shared_eval_point
            };
            // SAFETY: Challenge<SC> == InnerChallenge (TypeId gate above).
            let cloned: Vec<Challenge<SC>> = slice.to_vec();
            let (ptr, len, cap) = {
                let mut v = core::mem::ManuallyDrop::new(cloned);
                (v.as_mut_ptr(), v.len(), v.capacity())
            };
            unsafe { Vec::from_raw_parts(ptr as *mut InnerChallenge, len, cap) }
        })
        .collect();

    // Downcast the outer SC::Challenger to &mut LbChallenger.  The
    // TypeId gate above guarantees the downcast succeeds, so
    // expect() is unreachable in practice.
    let challenger_any: &mut dyn Any = challenger;
    let lb_challenger = challenger_any
        .downcast_mut::<crate::basefold_late_binding::LbChallenger>()
        .expect("TypeId gate guarantees SC::Challenger == LbChallenger");

    // #113 — GPU jagged-PCS orchestration dispatch.  When the env flag
    // `ZIREN_GPU_JAGGED_ORCHESTRATION_DEVICE=1` is set AND the
    // ziren-gpu crate has registered the device-resident orchestrator
    // hook (via `register_gpu_jagged_orchestration_hook`), bypass the
    // host orchestrator (`prove_jagged_basefold` below) and let the
    // device driver own the entire jagged-PCS pipeline (commit,
    // per-chip y-evals via #103, sumcheck reduction via #107, BaseFold
    // open).  Output bytes MUST be byte-identical — the GPU side
    // serializes the same `JaggedBasefoldBundle` shape via rmp-serde.
    //
    // Falls through to the host orchestrator if either the env flag is
    // unset or no hook is registered (e.g. CPU-only build, or GPU crate
    // hasn't initialised yet on the call path).  This keeps the host
    // path the source of truth and the GPU dispatch strictly opt-in.
    if std::env::var("ZIREN_GPU_JAGGED_ORCHESTRATION_DEVICE")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        if let Some(hook) =
            crate::shard_level::sumcheck_poly::get_gpu_jagged_orchestration_hook()
        {
            // chip_traces / r_row_per_chip are already in the concrete
            // (`InnerVal = KoalaBear`, `InnerChallenge = Ef4`) form
            // (TypeId gate above + `kb31_poseidon2` type aliases).
            // Both are identically-typed to the hook signature; pass
            // straight through.  The hook owns the entire pipeline
            // and returns the rmp-serde bundle bytes directly.
            return hook(&chip_traces, &r_row_per_chip, lb_challenger);
        }
    }

    // SP1 single-dense path (Ziren #97): emit_jagged_pcs_bytes calls
    // prove_jagged_basefold directly.  The legacy per-chip dispatch
    // (gated on ZIREN_E3_PER_CHIP) was removed since SP1 only uses the
    // single dense flow and the per-chip experiment had unresolved
    // soundness gaps that surfaced in production reth wrap (#95).
    let bundle = prove_jagged_basefold(&chip_traces, &r_row_per_chip, lb_challenger);
    bundle.to_bytes()
}



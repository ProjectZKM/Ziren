//! Structural signatures of a recursion stage's witness.
//!
//! A recursion program is compiled from the HOST-side projection of its
//! witness: the builder walks the witness once, emitting one fixed op
//! sequence per variable-length collection it meets, and every field VALUE
//! becomes a `Hint` read.  Two witnesses therefore compile to byte-identical
//! programs when their variable-length collections agree pointwise —
//! independently of the values those collections hold.
//!
//! The functions here hash exactly that projection, in `Witnessable::write`
//! order, so a program cache keyed on the resulting `u64` is sound:
//!
//! ```text
//! shape_key(a) == shape_key(b)  ⟹  program(a) == program(b)   (bytes)
//! ```
//!
//! The converse is not claimed and is not needed — two keys mapping to one
//! program only costs a duplicate build, which the program-identity-keyed
//! proving-key cache absorbs downstream.
//!
//! The key is NOT a cryptographic commitment: a chance 64-bit collision would
//! still mis-key the cache.  What it must guarantee is that no *structural*
//! dimension is silently omitted — a coverage property, not a hash-strength
//! one.  `ZIREN_VERIFY_PROGRAM_CACHE=1` rebuilds and byte-compares on every
//! cache hit, which is how coverage is checked empirically.

use std::hash::{Hash, Hasher};

use zkm_pcs::shard_level::shard_proof::{BasefoldShardProof, EvaluationProof};
use zkm_pcs::{InnerChallenge, InnerVal};

/// Hash the structural dimensions of one `BasefoldShardProof`, in the order
/// its `Witnessable::write` impl
/// (`crates/recursion/circuit/src/shard_level_witness.rs`) walks them.
///
/// Shared by the Normalize and Compose keys: both stages witness the same
/// proof type, the Normalize stage over `shard_proofs` and the Compose stage
/// over the second half of each `vks_and_proofs` pair.
pub fn hash_shard_proof_structure<H: Hasher>(
    sp: &BasefoldShardProof<InnerVal, InnerChallenge>,
    h: &mut H,
) {
    // Write order:
    //   main_commitment (fixed [F; 8])
    //   public_values   (Vec<F>)
    //   logup_gkr_proof (LogupGkrProof)
    //   zerocheck_proof (PartialSumcheckProof)
    //   evaluation_proof (inline-witnessed bundle)
    //   opened_values
    sp.public_values.len().hash(h);

    // LogupGkrProof::write order:
    //   circuit_output  (LogUpGkrOutput { numerator, denominator })
    //   round_proofs    (Vec<LogupGkrRoundProof>)
    //   logup_evaluations (LogUpEvaluations { point, chip_openings })
    //   witness         (single F — fixed)
    let lgkr = &sp.logup_gkr_proof;
    lgkr.circuit_output.numerator.len().hash(h);
    lgkr.circuit_output.denominator.len().hash(h);
    lgkr.round_proofs.len().hash(h);
    for round in lgkr.round_proofs.iter() {
        // Each round writes 4 fixed EFs + a sumcheck proof.
        round.sumcheck_proof.univariate_polys.len().hash(h);
        for poly in round.sumcheck_proof.univariate_polys.iter() {
            poly.coefficients.len().hash(h);
        }
        // point_and_eval.0 (point: Vec<EF>) is also variable.
        round.sumcheck_proof.point_and_eval.0.len().hash(h);
    }
    // logup_evaluations
    lgkr.logup_evaluations.point.len().hash(h);
    lgkr.logup_evaluations.chip_openings.len().hash(h);
    for (name, eval) in lgkr.logup_evaluations.chip_openings.iter() {
        // chip_openings is a BTreeMap — iteration order is sorted, matching
        // the `Witnessable::write` traversal.  The KEY SET is itself a
        // compile-time input: the verifier filters the machine's chips by
        // these names and derives `column_counts_by_round` from the survivors,
        // so chip-set drift changes the emitted ops.
        name.hash(h);
        eval.main_trace_evaluations.len().hash(h);
        // Option<Vec<EF>> — discriminant + len.
        match &eval.preprocessed_trace_evaluations {
            Some(v) => {
                1u8.hash(h);
                v.len().hash(h);
            }
            None => 0u8.hash(h),
        }
    }

    // zerocheck_proof (PartialSumcheckProof)
    sp.zerocheck_proof.univariate_polys.len().hash(h);
    for poly in sp.zerocheck_proof.univariate_polys.iter() {
        poly.coefficients.len().hash(h);
    }
    sp.zerocheck_proof.point_and_eval.0.len().hash(h);

    // evaluation_proof — the jagged-BaseFold bundle, inline-witnessed by
    // `read_basefold_proof_from_stream` + the two sumchecks + `q_at_z`, so
    // every length below lands in the witness stream and in the emitted
    // instruction count.
    hash_evaluation_proof(&sp.evaluation_proof, h);

    // opened_values — written last, via `basefold_opened_values_from_host`.
    sp.opened_values.chips.len().hash(h);
    for chip in sp.opened_values.chips.iter() {
        chip.preprocessed.local.len().hash(h);
        chip.main.local.len().hash(h);
        // `degree` is carried host-side in `quotient[0]`; the Horner
        // recomposition in `chip_height_bits_from_opened_degrees` emits one
        // op per entry, so its length is structural.
        chip.quotient.first().map(|q| q.len()).unwrap_or(0).hash(h);
    }

    // chip_cumulative_sums (BTreeMap) — witnessed after the proofs, in the
    // same per-input loop, by both stages' `Witnessable::write`.
    sp.chip_cumulative_sums.len().hash(h);
    for (name, _) in sp.chip_cumulative_sums.iter() {
        name.hash(h);
        // Each ChipCumulativeSums has fixed shape (Ext + SepticDigest of
        // [F; 7] × 2) — no varlen.
    }
}

/// Hash the structural dimensions of a shard proof's jagged-BaseFold
/// evaluation proof, in `Witnessable::write` order.
///
/// Split out so the per-group (`G >= 2`) split bundle and the group-0 bundle
/// share one traversal.
fn hash_evaluation_proof<H: Hasher>(proof: &EvaluationProof, h: &mut H) {
    match proof {
        EvaluationProof::Empty => 0u8.hash(h),
        // The `Bytes` arm is CONST-LIFTED (baked), not witnessed, so the
        // byte length is itself structural.
        EvaluationProof::Bytes(b) => {
            1u8.hash(h);
            b.len().hash(h);
        }
        EvaluationProof::Bundle(bundle) => {
            2u8.hash(h);
            // Group-0 packing.  `log_dense_size` (= L) drives every length
            // below; hash it explicitly so the key NAMES the dimension even
            // if a derived length is ever refactored away.
            //
            // `offsets` contributes its LENGTH only.  Its VALUES are the
            // cumulative per-column cell offsets, i.e. a running sum of the
            // shard's per-chip HEIGHTS — and the inner lift reconstructs
            // `col_prefix_sums` / `row_counts` in-circuit from the WITNESSED
            // height felts rather than baking these (the baked path is the
            // Bn254 outer wrap circuit, which does not go through this key).
            // Hashing the values would therefore split the key on a dimension
            // the program does not see: MEASURED over 189 reth leaves, the
            // values took 162 distinct settings across only 52 distinct
            // programs, while the remaining components partition those leaves
            // into exactly 52 classes.
            //
            // `column_counts` keeps its VALUES: they are a function of the
            // chip set, constant within a program class, so covering them is
            // free.
            bundle.packing.log_dense_size.hash(h);
            bundle.packing.offsets.len().hash(h);
            bundle.packing.column_counts.hash(h);

            hash_stacked_basefold(&bundle.basefold_proof, h);

            // reduction (JaggedReductionProof) — L rounds, L-long point.
            bundle.reduction.rounds.len().hash(h);
            bundle.reduction.eval_point.len().hash(h);

            // jagged-eval sub-sumcheck — 2*(L+1) rounds.
            let je = &bundle.jagged_eval.partial_sumcheck_proof;
            je.univariate_polys.len().hash(h);
            for poly in je.univariate_polys.iter() {
                poly.coefficients.len().hash(h);
            }
            je.point_and_eval.0.len().hash(h);

            // y_per_chip — per-chip per-column row-MLE values.
            bundle.y_per_chip.len().hash(h);
            for y in bundle.y_per_chip.iter() {
                y.len().hash(h);
            }

            // Per-round split (G >= 2) extra groups.  Empty on the default
            // G == 1 path, so the key is unchanged there.
            bundle.extra_reduction.len().hash(h);
            for r in bundle.extra_reduction.iter() {
                r.rounds.len().hash(h);
                r.eval_point.len().hash(h);
            }
            bundle.extra_basefold_proof.len().hash(h);
            for bp in bundle.extra_basefold_proof.iter() {
                hash_stacked_basefold(bp, h);
            }
            bundle.extra_packing.len().hash(h);
            for p in bundle.extra_packing.iter() {
                p.log_dense_size.hash(h);
                p.offsets.len().hash(h);
                p.column_counts.hash(h);
            }
        }
    }
}

/// Structural dimensions of a `StackedBasefoldProof` — the BaseFold round
/// count, query/Merkle path lengths and stacked batch widths, all of which
/// are inline-witnessed by `read_basefold_proof_from_stream`.
fn hash_stacked_basefold<H: Hasher>(
    stacked: &zkm_pcs::basefold::stacked::StackedBasefoldProof<
        InnerVal,
        InnerChallenge,
        zkm_pcs::jagged_pcs::JaggedMmcs,
    >,
    h: &mut H,
) {
    let bf = &stacked.basefold_proof;
    bf.univariate_messages.len().hash(h);
    bf.fri_commitments.len().hash(h);
    for openings in [
        &bf.component_polynomials_query_openings_and_proofs,
        &bf.query_phase_openings_and_proofs,
    ] {
        openings.len().hash(h);
        for round in openings.iter() {
            round.leaves.len().hash(h);
            for leaf in round.leaves.iter() {
                leaf.values.len().hash(h);
                for v in leaf.values.iter() {
                    v.len().hash(h);
                }
                // Merkle path length tracks the codeword height.
                leaf.proof.len().hash(h);
            }
        }
    }
    // batch_evaluations: outer = commit rounds, inner = num_stripes
    // = 2^(log_dense_size - log_stacking_height).
    stacked.batch_evaluations.len().hash(h);
    for row in stacked.batch_evaluations.iter() {
        row.len().hash(h);
    }
}


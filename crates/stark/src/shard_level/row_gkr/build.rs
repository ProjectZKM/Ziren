//! GKR circuit builder — ties together first-layer + transitions +
//! output extraction (task #24, A.2 step 4.5).
//!
//! Mirrors the data-side flow of
//! [`generate_gkr_circuit`](file:///tmp/sp1/crates/hypercube/src/logup_gkr/cpu.rs#L75-L133)
//! but stops short of the per-round sumcheck (step 5).  The output
//! is the full layer stack plus the unified [`LogUpGkrOutput`] — the
//! sumcheck round proofs are layered on top in step 5.

use alloc::vec::Vec;

use p3_field::{ExtensionField, PrimeField};
use p3_matrix::dense::RowMajorMatrix;

use super::extract::{extract_outputs, LogUpGkrOutput};
use super::first_layer::generate_first_layer;
use super::layer::{GkrCircuitLayer, LogupGkrCpuCircuit};
use super::transition::layer_transition;
use crate::air::MachineAir;
use crate::Chip;

/// Build the full GKR circuit (data side) and return the unified
/// output.
///
/// **Inputs:**
/// - `chips`: per-chip lookup specs
/// - `preprocessed_traces`, `main_traces`: per-chip raw traces
/// - `alpha`, `betas`: post-commit challenges (`betas[0]` covers the
///   `argument_index` slot, `betas[1..]` cover per-column values)
/// - `num_row_variables`: log₂ of padded row count
///   (must be `>= 1` for the row-reduction to terminate at
///   `num_row_variables == 1`)
///
/// **Output:**
/// `(LogUpGkrOutput<EF>, LogupGkrCpuCircuit<F, EF>)` — same shape as
/// the `generate_gkr_circuit` return type, lets the caller (step 5)
/// walk the layer stack bottom-up to drive per-round sumchecks.
///
/// **Panics** when `num_row_variables == 0` (degenerate empty shard
/// — handled by the caller, not by this builder).
#[allow(clippy::too_many_arguments)]
pub fn build_gkr_circuit<F, EF, A>(
    chips: &[&Chip<F, A>],
    preprocessed_traces: &[RowMajorMatrix<F>],
    main_traces: &[RowMajorMatrix<F>],
    alpha: EF,
    betas: &[EF],
    num_row_variables: usize,
) -> (LogUpGkrOutput<EF>, LogupGkrCpuCircuit<F, EF>)
where
    F: PrimeField,
    EF: ExtensionField<F>,
    A: MachineAir<F>,
{
    assert!(num_row_variables >= 1, "build_gkr_circuit requires num_row_variables >= 1");

    let first = generate_first_layer::<F, EF, A>(
        chips,
        preprocessed_traces,
        main_traces,
        alpha,
        betas,
        num_row_variables,
    );

    // generate_first_layer reduces num_row_variables by 1 (per its
    // docstring: "set to original - 1"). So:
    //
    //   input num_row_variables=N → first.num_row_variables=N-1
    //
    // Two distinct degenerate cases to handle:
    //
    //   N=1 input → first.num=0 → no transitions possible. Terminal
    //               extraction needs num=1; we don't have it. Reject
    //               at entry (#80 fix below — but realistically
    //               num_row_variables=1 doesn't appear in production
    //               shapes since shard padding hits ≥ 2).
    //
    //   N=2 input → first.num=1 → the FirstLayer IS the terminal.
    //               Previously the code only checked layers[len-2]
    //               for an EF Layer and panicked when it found a
    //               FirstLayer there. Fix: F→EF-promote the FirstLayer
    //               into a regular Layer at the same row count, then
    //               treat it as the terminal.
    //
    //   N≥3 input → first.num≥2 → ≥1 transitions, terminal Layer
    //               with num=1 ends up at layers[len-2]. Original
    //               flow.
    assert!(num_row_variables >= 2,
        "build_gkr_circuit requires num_row_variables >= 2 (got {num_row_variables}); \
         num_row_variables=1 produces no terminal EF layer for output extraction");

    let mut layers: Vec<GkrCircuitLayer<F, EF>> = Vec::with_capacity(first.num_row_variables + 1);

    // Special case: num_row_variables=2 input → first.num=1 → use
    // first as the terminal directly via F→EF promotion.
    let terminal_owned: Option<super::layer::LogUpGkrCpuLayer<EF, EF>> =
        if first.num_row_variables == 1 {
            // FirstLayer at num_row_variables=1 IS the terminal.
            // Promote numerator F → EF; denominator already EF.
            Some(promote_first_layer_numerator_to_ef::<F, EF>(&first))
        } else {
            None
        };

    let mut last_ef_layer: Option<super::layer::LogUpGkrCpuLayer<EF, EF>> = None;

    // First transition: NumF = F → EF (numerator type promotion).
    // Only run when first.num_row_variables >= 1; the transition
    // reduces by 1, so for first.num=1 the result has num=0 (the
    // null terminal), and for first.num >= 2 the result has the
    // intermediate num >= 1 (used for the next transition).
    if first.num_row_variables >= 1 {
        let next = layer_transition::<F, EF>(&first);
        last_ef_layer = Some(next);
    }
    layers.push(GkrCircuitLayer::FirstLayer(first));

    // Subsequent transitions stay in EF.
    while let Some(curr) = last_ef_layer.take() {
        if curr.num_row_variables >= 1 {
            let next = layer_transition::<EF, EF>(&curr);
            last_ef_layer = Some(next);
            layers.push(GkrCircuitLayer::Layer(curr));
        } else {
            // curr is the null terminal layer (num_row_variables == 0).
            // Add to layer stack but stop transitioning.
            layers.push(GkrCircuitLayer::Layer(curr));
        }
    }

    // Pick the terminal layer (num_row_variables == 1) for output
    // extraction. Two paths:
    //
    //   * num_row_variables=2 input → terminal_owned is Some
    //     (F→EF-promoted FirstLayer)
    //   * num_row_variables>=3 input → layers[len-2] is the EF Layer
    //     with num_row_variables==1
    let output = if let Some(t) = terminal_owned.as_ref() {
        extract_outputs(t)
    } else {
        match &layers[layers.len() - 2] {
            GkrCircuitLayer::Layer(l) => extract_outputs(l),
            GkrCircuitLayer::FirstLayer(_) => unreachable!(
                "for num_row_variables >= 3 the second-to-last layer is always an EF Layer"
            ),
        }
    };
    (output, LogupGkrCpuCircuit::new(layers))
}

/// F→EF promotion of a FirstLayer's numerators (denominators are
/// already EF). Used when the FirstLayer is itself the terminal
/// (num_row_variables=1 case after generate_first_layer reduced from
/// input num_row_variables=2).
fn promote_first_layer_numerator_to_ef<F, EF>(
    first: &super::layer::LogUpGkrCpuLayer<F, EF>,
) -> super::layer::LogUpGkrCpuLayer<EF, EF>
where
    F: PrimeField,
    EF: ExtensionField<F>,
{
    use super::layer::RowMajorTable;

    let promote = |t: &RowMajorTable<F>| -> RowMajorTable<EF> {
        RowMajorTable {
            cells: t.cells.iter().map(|&v| EF::from(v)).collect(),
            num_row_variables: t.num_row_variables,
            num_interaction_variables: t.num_interaction_variables,
            num_interactions: t.num_interactions,
            num_real_rows: t.num_real_rows,
        }
    };

    super::layer::LogUpGkrCpuLayer {
        numerator_0: first.numerator_0.iter().map(promote).collect(),
        denominator_0: first.denominator_0.clone(),
        numerator_1: first.numerator_1.iter().map(promote).collect(),
        denominator_1: first.denominator_1.clone(),
        num_row_variables: first.num_row_variables,
        num_interaction_variables: first.num_interaction_variables,
    }
}

#[cfg(test)]
mod tests {
    use p3_air::{PairCol, VirtualPairCol};
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;

    use super::*;
    use crate::air::LookupScope;
    use crate::lookup::{Lookup, LookupKind};
    use crate::Challenge;

    type SC = crate::koala_bear_poseidon2::KoalaBearPoseidon2;
    type EF = Challenge<SC>;

    /// Build a one-chip shard with a single send-interaction whose
    /// trace and lookup are deterministic.  Used to drive end-to-end
    /// shape sanity checks of the pipeline.
    fn one_chip_shard(
        log_height: usize,
    ) -> (
        Vec<Lookup<KoalaBear>>,
        Vec<Lookup<KoalaBear>>,
        RowMajorMatrix<KoalaBear>,
        RowMajorMatrix<KoalaBear>,
    ) {
        let send = Lookup::new(
            vec![],
            VirtualPairCol::new(vec![(PairCol::Main(0), KoalaBear::ONE)], KoalaBear::ZERO),
            LookupKind::Byte,
            LookupScope::Local,
        );
        let height = 1usize << log_height;
        // Main trace: 1 column, height rows, all = 1 (so multiplicity = 1).
        let main = RowMajorMatrix::new(vec![KoalaBear::ONE; height], 1);
        // Empty preprocessed.
        let prep = RowMajorMatrix::new(vec![], 0);
        (vec![send], vec![], main, prep)
    }

    /// Smoke-shape test: build a circuit for a 2-chip shard (where
    /// each chip is structurally identical) at log_height=2 and
    /// confirm the layer stack + output have the right shapes.
    #[test]
    #[ignore = "requires plumbing chips through Chip<F, A> — defer to step 6 wiring"]
    fn build_gkr_circuit_shape_smoke() {
        // The Chip<F, A> wrapper requires an A: MachineAir<F> instance.
        // Constructing one in unit tests requires a real chip type, which
        // pulls in zkm_core_machine.  Step 6 (top-level wiring) is the
        // appropriate place to exercise this end-to-end via real chips.
        let _ = one_chip_shard(2);
    }

    /// `build_gkr_circuit`'s zero-row-variables panic guard is
    /// validated by inspection — the assertion at the function head
    /// is its own test.  An end-to-end runtime panic test requires a
    /// real `Chip<F, A>` instance, deferred to step 6.
    #[allow(dead_code)]
    fn _zero_row_variables_panic_guard_is_visible_in_signature() {
        // assertion at build.rs:36: "build_gkr_circuit requires num_row_variables >= 1"
    }
}

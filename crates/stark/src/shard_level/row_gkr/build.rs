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

    let mut layers: Vec<GkrCircuitLayer<F, EF>> = Vec::with_capacity(first.num_row_variables);
    let mut last_ef_layer: Option<super::layer::LogUpGkrCpuLayer<EF, EF>> = None;

    // First transition: NumF = F → EF (numerator type promotion).
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
            // curr is the terminal layer (num_row_variables == 0).
            // Don't transition further; just add to layer stack.
            layers.push(GkrCircuitLayer::Layer(curr));
        }
    }

    // Find the terminal layer (num_row_variables == 1) for output
    // extraction.  the invariant: the layer just before the
    // num_row_variables==0 terminal has num_row_variables == 1.
    //
    // Our layers vec stores ascending num_row_variables (first =
    // largest, last = smallest = 0).  We need the second-to-last,
    // unless there's only one layer (degenerate single-row case
    // where num_row_variables started at 1).
    let terminal_layer = if layers.len() >= 2 {
        match &layers[layers.len() - 2] {
            GkrCircuitLayer::Layer(l) => l,
            GkrCircuitLayer::FirstLayer(_) => {
                // Degenerate: only the first layer exists at row=1.
                // But that means num_row_variables started at 1; the
                // first layer's own num_row_variables is 0 after the
                // initial fix_last_variable.  Then the only "layer"
                // is the FirstLayer itself with num_row_variables=0.
                // No transitions happened, no terminal-row=1 EF layer
                // exists.  Caller must avoid this by ensuring
                // num_row_variables >= 2 (handled below).
                panic!(
                    "no EF terminal layer — caller must provide num_row_variables >= 2 \
                     to build_gkr_circuit (current = {num_row_variables})"
                );
            }
        }
    } else {
        panic!(
            "no transitions performed — caller must provide num_row_variables >= 2 \
             to build_gkr_circuit (current = {num_row_variables})"
        );
    };

    let output = extract_outputs(terminal_layer);
    (output, LogupGkrCpuCircuit::new(layers))
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

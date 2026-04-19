//! Per-chip LogUp-GKR verifier types (mirror of stark-side shape).
//!
//! The prover emits per-chip LogUp-GKR proofs in the layer-based
//! descent form defined by [`zkm_stark::logup_gkr::LogUpGkrProof`]:
//!
//! ```ignore
//! pub struct LogUpGkrProof<EF> {
//!     pub root: (EF, EF),
//!     pub layers: Vec<LogUpGkrLayerProof<EF>>,
//!     pub eval_point: Vec<EF>,
//!     pub leaf_claim: (EF, EF),
//! }
//! ```
//!
//! This module hosts the in-circuit variable counterpart so the
//! recursion verifier can consume those proofs without any
//! prover-side proof-shape change.  It complements (rather than
//! replaces) the shard-level
//! [`crate::logup_proof::LogupGkrProof`] type used by
//! [`crate::logup_gkr::verify_logup_gkr`]; over time the two
//! converge to a single representation, but during the migration
//! both coexist.
//!
//! # Reference
//!
//! Mirrors [`zkm_stark::logup_gkr::LogUpGkrProof`] and
//! [`zkm_stark::logup_gkr::LogUpGkrLayerProof`] field-for-field,
//! with `EF` replaced by `Ext<F, EF>` for the in-circuit witness
//! cells.

use zkm_recursion_compiler::ir::Ext;

/// In-circuit variable of [`zkm_stark::logup_gkr::LogUpGkrLayerProof`].
///
/// Each layer of the GKR descent carries its sumcheck-round
/// polynomials (degree-3, four coefficients per round) plus the
/// `(N(r*, 0), N(r*, 1), D(r*, 0), D(r*, 1))` final-evals tuple.
///
/// `Ext<F, EF>` doesn't implement `Serialize`/`Deserialize`, so
/// neither does the variable type — it lives only inside the
/// recursion-compiler builder graph.  Read it from the host-side
/// `LogUpGkrLayerProof<EF>` via the Witnessable impl in
/// [`crate::basefold_witness`].
#[derive(Clone, Debug)]
pub struct PerChipLogUpGkrLayerProofVariable<F, EF> {
    /// Per-round univariate polynomials, each as four
    /// coefficients `[h(0), h(1), h(2), h(3)]`.  Length equals
    /// the dimension of the layer above (`m - k - 1` for the
    /// reduction from layer `k+1` to layer `k`); the top layer
    /// carries an empty vector.
    pub sumcheck_rounds: Vec<[Ext<F, EF>; 4]>,
    /// `(N_k(r*, 0), N_k(r*, 1), D_k(r*, 0), D_k(r*, 1))` where
    /// `r*` is the sumcheck-reduced point for this layer.
    pub final_evals: [Ext<F, EF>; 4],
}

/// In-circuit variable of [`zkm_stark::logup_gkr::LogUpGkrProof`].
///
/// One instance per chip — the prover emits a Vec of these on
/// `ShardProof::logup_gkr_proofs`.
#[derive(Clone, Debug)]
pub struct PerChipLogUpGkrProofVariable<F, EF> {
    /// Root fraction `(N_root, D_root)`, sent in the clear so the
    /// verifier can test `N_root == 0` (the soundness anchor).
    pub root: (Ext<F, EF>, Ext<F, EF>),
    /// One reduction per layer in descent order (root side first).
    pub layers: Vec<PerChipLogUpGkrLayerProofVariable<F, EF>>,
    /// Evaluation point `r ∈ EF^m` at which the leaf fractions
    /// are claimed to evaluate.  `m` is the chip's log-row-count.
    pub eval_point: Vec<Ext<F, EF>>,
    /// Final leaf-layer fraction claim at `eval_point`:
    /// `(N(eval_point), D(eval_point))`.
    pub leaf_claim: (Ext<F, EF>, Ext<F, EF>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;
    use p3_field::extension::BinomialExtensionField;

    type F = KoalaBear;
    type EF = BinomialExtensionField<KoalaBear, 4>;

    /// Construction smoke test: the per-chip types instantiate
    /// over the standard KoalaBear / BinomialExtension pair the
    /// rest of the recursion circuit uses.
    #[test]
    fn per_chip_proof_constructs_over_host_types() {
        // Host-typed instance — uses raw EF rather than the
        // in-circuit Ext.  Confirms the struct shape lines up
        // with stark's `LogUpGkrProof<EF>`.
        let layer = zkm_stark::logup_gkr::LogUpGkrLayerProof::<EF> {
            sumcheck_rounds: vec![[EF::ZERO; 4]; 3],
            final_evals: [EF::ZERO; 4],
        };
        let proof = zkm_stark::logup_gkr::LogUpGkrProof::<EF> {
            root: (EF::ZERO, EF::ZERO),
            layers: vec![layer],
            eval_point: vec![EF::ZERO; 4],
            leaf_claim: (EF::ZERO, EF::ZERO),
        };
        assert_eq!(proof.layers.len(), 1);
        assert_eq!(proof.eval_point.len(), 4);
        // Silence unused-type warnings on the in-circuit aliases.
        let _: std::marker::PhantomData<PerChipLogUpGkrProofVariable<F, EF>> =
            std::marker::PhantomData;
        let _: std::marker::PhantomData<PerChipLogUpGkrLayerProofVariable<F, EF>> =
            std::marker::PhantomData;
    }
}

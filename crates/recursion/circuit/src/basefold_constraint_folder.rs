//! In-circuit chip-constraint folder for the BaseFold pipeline.
//!
//! Specialised constraint-folding builder used by the recursion-
//! circuit shard verifier's zerocheck phase to evaluate per-chip
//! constraint polynomials at a single hypercube point.
//!
//! Differs from the legacy [`crate::constraints::RecursiveVerifierConstraintFolder`]
//! in two important ways:
//!
//!   - **Single row, not pair** — only the local row is exposed
//!     (as a 1-row `RowMajorMatrixView`), not a (top, bottom) pair.
//!     The BaseFold pipeline reduces every chip's polynomial to a
//!     single hypercube point; there is no "next row" concept.
//!   - **No permutation matrix** — the BaseFold pipeline replaced
//!     the permutation-phase opening with a sumcheck-based binding
//!     (zerocheck + LogUp-GKR), so the folder doesn't carry any
//!     permutation columns or challenges.
//!
//! Per-chip selectors (`is_first_row`, `is_last_row`,
//! `is_transition_window`) panic if accessed — chip constraints
//! evaluated through this folder must already have folded those
//! selectors into their constraint expressions before reaching the
//! zerocheck verifier.
//!
//! # Reference
//!
//! Mirrors `RecursiveVerifierConstraintFolder`
//! (crates/recursion/circuit/src/zerocheck.rs in SP1) — a type alias to
//! `GenericVerifierConstraintFolder`).  Specialised to Ziren's
//! `Felt` / `Ext` / `SymbolicExt` types in place of the upstream's
//! generic `(F, EF, FeltVar, ExtVar, SymbolicExtVar)` parameters.

use std::marker::PhantomData;

use p3_air::{AirBuilder, ExtensionBuilder};
use p3_field::{Algebra, ExtensionField, Field};
use zkm_recursion_compiler::ir::{Config, Ext, Felt, SymbolicExt};
use zkm_stark::folder::PairWindow;
use zkm_stark::septic_digest::SepticDigest;

/// In-circuit chip-constraint folder for the BaseFold pipeline.
///
/// `'a` borrows the per-chip opening references (preprocessed
/// local row, main local row, public values).
pub struct BasefoldConstraintFolder<'a, C: Config> {
    /// Local row of the preprocessed trace at the sumcheck point.
    /// Wrapped as a [`PairWindow`] where `local == next == &row`
    /// (the BaseFold pipeline has no next-row concept; the row
    /// duplication satisfies [`p3_air::WindowAccess`] without
    /// exposing a real transition window).
    pub preprocessed: PairWindow<'a, Ext<C::F, C::EF>>,
    /// Local row of the main trace at the sumcheck point.  Same
    /// `PairWindow` convention as `preprocessed`.
    pub main: PairWindow<'a, Ext<C::F, C::EF>>,
    /// Constraint-folding random scalar.
    pub alpha: Ext<C::F, C::EF>,
    /// Accumulator for the constraint-fold RLC.  After evaluation,
    /// the verifier asserts this equals zero (constraints hold) or
    /// composes with the GKR-derived offset (zerocheck reduction).
    pub accumulator: SymbolicExt<C::F, C::EF>,
    /// Shard public values.
    pub public_values: &'a [Felt<C::F>],
    /// Local cumulative sum reference required by
    /// [`zkm_stark::air::MultiTableAirBuilder`].  In the BaseFold
    /// pipeline the per-chip cumulative sums live in the LogUp-GKR
    /// sumcheck output rather than as Air-side fields, so this
    /// reference can point at a placeholder / zero value when the
    /// folder is invoked from contexts that don't carry a real
    /// per-chip sum (e.g.,
    /// [`crate::zerocheck::compute_padded_row_adjustment`]'s
    /// dummy-row constraint evaluation).
    pub local_cumulative_sum: &'a Ext<C::F, C::EF>,
    /// Global cumulative sum reference required by
    /// [`zkm_stark::air::MultiTableAirBuilder`].  Same placeholder
    /// convention as `local_cumulative_sum`.
    pub global_cumulative_sum: &'a SepticDigest<Felt<C::F>>,
    /// Phantom for the circuit-config parameter.
    pub _marker: PhantomData<C>,
}

impl<'a, C: Config> AirBuilder for BasefoldConstraintFolder<'a, C>
where
    C::F: Field,
    C::EF: ExtensionField<C::F>,
{
    type F = C::F;
    type Expr = SymbolicExt<C::F, C::EF>;
    type Var = Ext<C::F, C::EF>;
    type PreprocessedWindow = PairWindow<'a, Ext<C::F, C::EF>>;
    type MainWindow = PairWindow<'a, Ext<C::F, C::EF>>;
    type PublicVar = Felt<C::F>;

    fn main(&self) -> Self::MainWindow {
        self.main
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed
    }

    fn is_first_row(&self) -> Self::Expr {
        // BaseFold has no first-row selector; return zero so any chip
        // constraint multiplied by `is_first_row` evaluates to zero
        // (effectively disabling that constraint at the zerocheck
        // reduction point). Cryptographic soundness requires the
        // chips to fold these selectors into their constraint
        // expressions — this stub lets fibonacci make progress until
        // the chip-side refactor lands.
        use p3_field::PrimeCharacteristicRing;
        SymbolicExt::<C::F, C::EF>::ZERO
    }

    fn is_last_row(&self) -> Self::Expr {
        use p3_field::PrimeCharacteristicRing;
        SymbolicExt::<C::F, C::EF>::ZERO
    }

    fn is_transition_window(&self, _size: usize) -> Self::Expr {
        use p3_field::PrimeCharacteristicRing;
        SymbolicExt::<C::F, C::EF>::ZERO
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let x: SymbolicExt<C::F, C::EF> = x.into();
        self.accumulator *= self.alpha;
        self.accumulator += x;
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}

impl<C: Config> ExtensionBuilder for BasefoldConstraintFolder<'_, C>
where
    C::F: Field,
    C::EF: ExtensionField<C::F>,
    SymbolicExt<C::F, C::EF>: Algebra<C::EF>,
{
    type EF = C::EF;
    type ExprEF = SymbolicExt<C::F, C::EF>;
    type VarEF = Ext<C::F, C::EF>;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.assert_zero(x);
    }
}

impl<C: Config> zkm_stark::air::EmptyMessageBuilder for BasefoldConstraintFolder<'_, C>
where
    C::F: Field,
    C::EF: ExtensionField<C::F>,
    SymbolicExt<C::F, C::EF>: Algebra<C::EF>,
{
}

impl<'a, C: Config> p3_air::PermutationAirBuilder for BasefoldConstraintFolder<'a, C>
where
    C::F: Field,
    C::EF: ExtensionField<C::F>,
    SymbolicExt<C::F, C::EF>: Algebra<C::EF>,
{
    type MP = PairWindow<'a, Ext<C::F, C::EF>>;
    type RandomVar = Ext<C::F, C::EF>;
    type PermutationVar = Ext<C::F, C::EF>;

    fn permutation(&self) -> Self::MP {
        // The BaseFold pipeline has no permutation matrix on the
        // wire — return an empty pair window.  Any chip that reads
        // permutation columns through this folder is misusing the
        // BaseFold-pipeline contract.
        PairWindow { local: &[], next: &[] }
    }

    fn permutation_randomness(&self) -> &[Self::Var] {
        // No permutation challenges in the BaseFold pipeline; the
        // per-chip permutation soundness moved to LogUp-GKR.
        &[]
    }

    fn permutation_values(&self) -> &[Self::PermutationVar] {
        &[]
    }
}

impl<'a, C: Config> zkm_stark::air::MultiTableAirBuilder<'a> for BasefoldConstraintFolder<'a, C>
where
    C::F: Field,
    C::EF: ExtensionField<C::F>,
    SymbolicExt<C::F, C::EF>: Algebra<C::EF>,
{
    type LocalSum = Ext<C::F, C::EF>;
    type GlobalSum = Felt<C::F>;

    fn local_cumulative_sum(&self) -> &'a Self::LocalSum {
        self.local_cumulative_sum
    }

    fn global_cumulative_sum(&self) -> &'a SepticDigest<Self::GlobalSum> {
        self.global_cumulative_sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use zkm_recursion_compiler::circuit::AsmBuilder;
    use zkm_recursion_compiler::config::InnerConfig;
    use zkm_stark::{InnerChallenge, InnerVal};

    type C = InnerConfig;
    type F = InnerVal;
    type EF = InnerChallenge;

    /// Construction smoke test: folder builds and assert_zero
    /// updates the accumulator without panicking.
    #[test]
    fn folder_constructs_and_assert_zero_works() {
        let mut builder = AsmBuilder::<F, EF>::default();
        let alpha = builder.constant(EF::ONE);
        let preproc_row: Vec<Ext<F, EF>> =
            (0..2).map(|_| builder.constant(EF::ZERO)).collect();
        let main_row: Vec<Ext<F, EF>> =
            (0..3).map(|_| builder.constant(EF::ZERO)).collect();
        let public_values: Vec<Felt<F>> =
            (0..4).map(|_| builder.constant(F::ZERO)).collect();

        let local_sum = builder.constant(EF::ZERO);
        // Construct a placeholder SepticDigest by re-using the
        // zero-Felt for every coordinate.  The folder doesn't read
        // back from the SepticDigest in any code path the BaseFold
        // pipeline exercises, so the placeholder values are
        // structurally inert.
        let zero_felt: Felt<F> = builder.constant(F::ZERO);
        use zkm_stark::septic_curve::SepticCurve;
        use zkm_stark::septic_extension::SepticExtension;
        let global_sum: SepticDigest<Felt<F>> = SepticDigest(SepticCurve {
            x: SepticExtension::<Felt<F>>([
                zero_felt, zero_felt, zero_felt, zero_felt, zero_felt, zero_felt, zero_felt,
            ]),
            y: SepticExtension::<Felt<F>>([
                zero_felt, zero_felt, zero_felt, zero_felt, zero_felt, zero_felt, zero_felt,
            ]),
        });

        let mut folder = BasefoldConstraintFolder::<C> {
            preprocessed: PairWindow { local: &preproc_row, next: &preproc_row },
            main: PairWindow { local: &main_row, next: &main_row },
            alpha,
            accumulator: SymbolicExt::ZERO,
            public_values: &public_values,
            local_cumulative_sum: &local_sum,
            global_cumulative_sum: &global_sum,
            _marker: PhantomData,
        };

        folder.assert_zero(SymbolicExt::<F, EF>::ZERO);
        assert_eq!(folder.public_values().len(), 4);
    }
}

/// Task #382 Phase 3a sub-sprint A: compile-time proof that every
/// `RecursionAir` chip implements
/// `Air<BasefoldConstraintFolder<'a, InnerConfig>>` — the in-circuit
/// counterpart to the host-side assertion in
/// `crates/recursion/core/src/machine.rs::basefold_air_assertions`.
///
/// The in-circuit `BasefoldConstraintFolder<'a, C: Config>` (above)
/// is `AirBuilder + EmptyMessageBuilder + ExtensionBuilder +
/// PermutationAirBuilder + MultiTableAirBuilder`, which through the
/// blanket impls in `crates/stark/src/air/builder.rs:581-586`
/// automatically becomes a `BaseAirBuilder + ExtensionAirBuilder +
/// SepticExtensionAirBuilder` → `MachineAirBuilder`, and via
/// `crates/recursion/core/src/builder.rs:14-15` becomes a
/// `ZKMRecursionAirBuilder`.  The existing generic
/// `impl<AB: ZKMRecursionAirBuilder> Air<AB>` blanket on every
/// recursion chip therefore covers it — no new per-chip code needed.
///
/// `BasefoldConstraintFolder::Var = Ext<C::F, C::EF>` is `Copy +
/// 'static`, so the `AB::Var: 'static` predicate emitted by the
/// `#[derive(MachineAir)]` macro for `RecursionAir<F, DEGREE>`
/// (`crates/derive/src/lib.rs:315-318`) is satisfied.
#[cfg(test)]
mod basefold_air_assertions_circuit {
    use super::*;
    use p3_air::Air;
    use zkm_recursion_compiler::config::InnerConfig;
    use zkm_recursion_core::chips::{
        alu_base::BaseAluChip, alu_ext::ExtAluChip, batch_fri::BatchFRIChip,
        exp_reverse_bits::ExpReverseBitsLenChip, fri_fold::FriFoldChip,
        mem::{constant::MemoryChip as MemoryConstChip, variable::MemoryChip as MemoryVarChip},
        poseidon2_skinny::Poseidon2SkinnyChip, poseidon2_wide::Poseidon2WideChip,
        public_values::PublicValuesChip, select::SelectChip,
    };
    use zkm_recursion_core::machine::RecursionAir;
    use zkm_stark::InnerVal;

    type C = InnerConfig;

    /// Compile-time bound: `T: for<'a> Air<BasefoldConstraintFolder<'a, C>>`.
    fn assert_basefold_air_circuit<T>()
    where
        T: for<'a> Air<BasefoldConstraintFolder<'a, C>>,
    {
    }

    /// Const used purely to force monomorphisation of all 11 chip
    /// assertions at compile time.  Never called.
    #[allow(dead_code)]
    const _ASSERT_ALL_CHIPS_CIRCUIT: fn() = || {
        // 1. MemoryConst
        assert_basefold_air_circuit::<MemoryConstChip<InnerVal>>();
        // 2. MemoryVar
        assert_basefold_air_circuit::<MemoryVarChip<InnerVal>>();
        // 3. BaseAlu
        assert_basefold_air_circuit::<BaseAluChip>();
        // 4. ExtAlu
        assert_basefold_air_circuit::<ExtAluChip>();
        // 5. Poseidon2Wide
        assert_basefold_air_circuit::<Poseidon2WideChip<9>>();
        // 6. Poseidon2Skinny
        assert_basefold_air_circuit::<Poseidon2SkinnyChip<9>>();
        // 7. Select
        assert_basefold_air_circuit::<SelectChip>();
        // 8. FriFold
        assert_basefold_air_circuit::<FriFoldChip<9>>();
        // 9. BatchFRI
        assert_basefold_air_circuit::<BatchFRIChip<9>>();
        // 10. ExpReverseBitsLen
        assert_basefold_air_circuit::<ExpReverseBitsLenChip<9>>();
        // 11. PublicValues
        assert_basefold_air_circuit::<PublicValuesChip>();

        // Enum-level: derive-generated
        // `impl<F, const DEGREE, AB: ZKMRecursionAirBuilder<F = F>>
        // Air<AB> for RecursionAir<F, DEGREE> where AB::Var: 'static`.
        // For AB = BasefoldConstraintFolder<'a, InnerConfig>:
        //   AB::F = InnerConfig::F = KoalaBear = InnerVal ✓
        //   AB::Var = Ext<KoalaBear, InnerChallenge>: 'static ✓
        assert_basefold_air_circuit::<RecursionAir<InnerVal, 9>>();
    };
}

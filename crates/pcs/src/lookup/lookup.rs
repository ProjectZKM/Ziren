use core::fmt::{Debug, Display};
use core::ops::Mul;

use p3_air::VirtualPairCol;
use p3_field::{Field, PrimeCharacteristicRing};

use crate::air::LookupScope;

/// A lookup or a permutation argument.
#[derive(Clone)]
pub struct Lookup<F: Field> {
    /// The values of the lookup.
    pub values: Vec<VirtualPairCol<F>>,
    /// The multiplicity of the lookup.
    pub multiplicity: VirtualPairCol<F>,
    /// The kind of lookup.
    pub kind: LookupKind,
    /// The scope of the lookup.
    pub scope: LookupScope,
}

/// The type of a lookup argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LookupKind {
    /// Lookup with the memory table, such as read and write.
    Memory = 1,

    /// Lookup with the program table, loading an instruction at a given pc address.
    Program = 2,

    /// Lookup with instruction oracle.
    Instruction = 3,

    /// Lookup with the byte lookup table for byte operations.
    Byte = 4,

    /// Requesting a range check for a given value and range.
    Range = 5,

    /// Lookup with a syscall.
    Syscall = 6,

    /// Lookup with the global table.
    Global = 7,

    /// Lookup connecting syscall result and argument bytes between SyscallInstrsChip,
    /// SyscallChip, and SysLinuxChip.
    SyscallResult = 8,

    /// CPU-state chaining bus (clk, pc).  Each instruction-bearing row
    /// `receive_state`s its current (clk, pc) and `send_state`s the next
    /// (clk', next_pc); the LogUp multiset balance forces consecutive
    /// rows to chain — the local-only replacement for the legacy
    /// `when_transition(local.next_pc == next.pc)` constraints.
    /// Boundary endpoints (initial / final pc, clk) are emitted by the
    /// public-values AIR.
    State = 9,

    /// Running global-digest accumulation chain.  Each `GlobalChip` row
    /// receives `(index, running_digest)` and sends
    /// `(index+1, running_digest + this_point)`; anchored at both ends by
    /// the public-values AIR.
    GlobalAccumulation = 10,

    /// Global-memory-init ordering control bus (index, prev_addr, valid).
    MemoryGlobalInitControl = 11,

    /// Global-memory-finalize ordering control bus.
    MemoryGlobalFinalizeControl = 12,

    /// Generic per-row state-chaining bus for MULTI-ROW precompiles
    /// (sha256 compress/extend, keccak sponge, …).  A control chip seeds
    /// the initial state at `index = 0` and drains the final state at the
    /// terminal index; each worker row receives `state @ index` and sends
    /// `state @ index + 1`, so the per-row ordering is pinned by lookup
    /// multiplicity instead of the legacy `when_first_row`/`when_transition`
    /// machinery (which the single-row BaseFold zerocheck folder cannot
    /// evaluate).  A leading precompile-ID field in the tuple isolates each
    /// precompile's chain (e.g. SHA_COMPRESS sends only balance SHA_COMPRESS
    /// receives), so a single kind serves all multi-row precompiles.
    PrecompileChain = 13,
}

impl LookupKind {
    /// Returns all kinds of lookups.
    #[must_use]
    pub fn all_kinds() -> Vec<LookupKind> {
        vec![
            LookupKind::Memory,
            LookupKind::Program,
            LookupKind::Instruction,
            LookupKind::Byte,
            LookupKind::Range,
            LookupKind::Syscall,
            LookupKind::Global,
            LookupKind::SyscallResult,
            LookupKind::State,
            LookupKind::GlobalAccumulation,
            LookupKind::MemoryGlobalInitControl,
            LookupKind::MemoryGlobalFinalizeControl,
        ]
    }

    /// Whether this kind's multiset is closed by endpoints emitted from
    /// the public-values AIR (rather than balancing entirely within the
    /// trace).
    #[must_use]
    pub fn appears_in_eval_public_values(&self) -> bool {
        matches!(
            self,
            LookupKind::Byte
                | LookupKind::State
                | LookupKind::GlobalAccumulation
                | LookupKind::MemoryGlobalInitControl
                | LookupKind::MemoryGlobalFinalizeControl
        )
    }
}

impl<F: Field> Lookup<F> {
    /// Create a new lookup.
    pub const fn new(
        values: Vec<VirtualPairCol<F>>,
        multiplicity: VirtualPairCol<F>,
        kind: LookupKind,
        scope: LookupScope,
    ) -> Self {
        Self { values, multiplicity, kind, scope }
    }

    /// The index of the argument in the lookup table.
    pub const fn argument_index(&self) -> usize {
        self.kind as usize
    }

    /// Evaluate this lookup's `(numerator, denominator)` fraction from a
    /// point-evaluation of the chip's traces.
    ///
    /// Computes:
    ///
    /// ```text
    ///   numerator   = multiplicity.constant + Σ_w weight·col_eval     (UNSIGNED)
    ///   denominator = α + β₀·argument_index + Σ_k βₖ·values[k-1]_eval
    /// ```
    ///
    /// The numerator is returned UNSIGNED (the send/receive sign is applied
    /// by the caller — the LogUp last-layer reconstruction in
    /// `verify_logup_gkr_host` negates it for receives).  This is the host/circuit-shared
    /// generic analog of the base-field-only prover helper
    /// `generate_interaction_vals` (`row_gkr/first_layer.rs`), which folds
    /// the sign in eagerly because it only ever serves the prover.
    ///
    /// `betas[0]` is the `argument_index` weight; `betas[1..]` are the
    /// per-value weights (the partial-lagrange table over the beta seed,
    /// `eq_mle_table`).  `prep`/`main`
    /// are the per-chip preprocessed/main trace evaluations at the
    /// LogUp-GKR opening point (`Var = EF` for the host verifier today,
    /// `Var = Ext<_>` for the recursion circuit in Phase 2).
    ///
    /// Generic so a single definition serves the host reconstruction now
    /// and the in-circuit reconstruction later.
    pub fn eval<Expr, Var>(
        &self,
        prep: Option<&[Var]>,
        main: &[Var],
        alpha: Expr,
        betas: &[Expr],
    ) -> (Expr, Expr)
    where
        F: Into<Expr>,
        Expr: PrimeCharacteristicRing + Mul<F, Output = Expr> + Clone,
        Var: Into<Expr> + Copy,
    {
        let empty: &[Var] = &[];
        let prep_slice = prep.unwrap_or(empty);

        // Numerator = signed (later) multiplicity, evaluated as a virtual column.
        let numerator: Expr = self.multiplicity.apply::<Expr, Var>(prep_slice, main);

        // Denominator = α + β₀·argument_index + Σ_k βₖ·v_k.
        let mut betas_iter = betas.iter().cloned();
        let mut denominator: Expr = alpha
            + betas_iter.next().expect("at least one beta (argument_index slot)")
                * Expr::from_usize(self.argument_index());
        for (column, beta) in self.values.iter().zip(betas_iter) {
            let v: Expr = column.apply::<Expr, Var>(prep_slice, main);
            denominator = denominator + v * beta;
        }

        (numerator, denominator)
    }
}

impl<F: Field> Debug for Lookup<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lookup")
            .field("kind", &self.kind)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl Display for LookupKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LookupKind::Memory => write!(f, "Memory"),
            LookupKind::Program => write!(f, "Program"),
            LookupKind::Instruction => write!(f, "Instruction"),
            LookupKind::Byte => write!(f, "Byte"),
            LookupKind::Range => write!(f, "Range"),
            LookupKind::Syscall => write!(f, "Syscall"),
            LookupKind::Global => write!(f, "Global"),
            LookupKind::SyscallResult => write!(f, "SyscallResult"),
            LookupKind::State => write!(f, "State"),
            LookupKind::GlobalAccumulation => write!(f, "GlobalAccumulation"),
            LookupKind::MemoryGlobalInitControl => write!(f, "MemoryGlobalInitControl"),
            LookupKind::MemoryGlobalFinalizeControl => write!(f, "MemoryGlobalFinalizeControl"),
            LookupKind::PrecompileChain => write!(f, "PrecompileChain"),
        }
    }
}

#[cfg(test)]
mod eval_tests {
    use p3_air::VirtualPairCol;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    use super::*;
    use crate::air::LookupScope;

    type EF = p3_field::extension::BinomialExtensionField<KoalaBear, 4>;

    // `Lookup::eval` (generic, UNSIGNED numerator) must agree with the prover's
    // base-field analog `generate_interaction_vals` (signed eagerly) on the SAME
    // interaction + openings.  This anchors the host/circuit-shared `eval` to the
    // proven prover hot path WITHOUT a full prove, so a math regression in `eval`
    // is caught cheaply (independently of the heavy core gate-(b)/(c) tests).
    #[test]
    fn eval_matches_generate_interaction_vals_send_and_receive() {
        // Interaction: multiplicity = main[0]; values = [main[1], 2*main[2]+3].
        let lookup = Lookup::<KoalaBear> {
            values: vec![
                VirtualPairCol::single_main(1),
                VirtualPairCol::new_main(vec![(2, KoalaBear::from_u32(2))], KoalaBear::from_u32(3)),
            ],
            multiplicity: VirtualPairCol::single_main(0),
            kind: LookupKind::Byte, // argument_index = 4
            scope: LookupScope::Local,
        };

        // Treat the prover's base-field row as the EF opening point (lift).
        let main_base: Vec<KoalaBear> =
            vec![KoalaBear::from_u32(5), KoalaBear::from_u32(7), KoalaBear::from_u32(9)];
        let main_ef: Vec<EF> = main_base.iter().map(|&v| EF::from(v)).collect();

        let alpha = EF::from_u32(11);
        // betas: argument_index slot + two value slots.
        let betas = vec![EF::from_u32(13), EF::from_u32(17), EF::from_u32(19)];

        // `Lookup::eval` (Var = EF), unsigned numerator.
        let (num_eval, den_eval) = lookup.eval::<EF, EF>(None, &main_ef, alpha, &betas);

        // Prover analog (base field), signed numerator.
        let (num_gen_send, den_gen) =
            crate::shard_level::row_gkr::first_layer::generate_interaction_vals::<KoalaBear, EF>(
                &lookup,
                &[],
                &main_base,
                true,
                alpha,
                &betas,
            );
        let (num_gen_recv, _) = crate::shard_level::row_gkr::first_layer::generate_interaction_vals::<
            KoalaBear,
            EF,
        >(&lookup, &[], &main_base, false, alpha, &betas);

        // Denominators must match exactly.
        assert_eq!(den_eval, den_gen, "denominator: eval vs generate_interaction_vals");
        // `eval` numerator is unsigned; send = +num, receive = -num.
        assert_eq!(num_eval, EF::from(num_gen_send), "send numerator");
        assert_eq!(-num_eval, EF::from(num_gen_recv), "receive numerator");

        // Spot-check the formula: den = alpha + b0*4 + b1*7 + b2*(2*9+3).
        let expected_den = alpha
            + betas[0] * EF::from_u32(4)
            + betas[1] * EF::from_u32(7)
            + betas[2] * EF::from_u32(2 * 9 + 3);
        assert_eq!(den_eval, expected_den, "denominator formula");
        assert_eq!(num_eval, EF::from_u32(5), "numerator = multiplicity main[0]");
    }
}

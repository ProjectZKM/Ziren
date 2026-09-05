use std::ops::{Add, AddAssign};

use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use zkm_pcs::{
    air::{LookupScope, MachineAir, PicusInfo},
    shape::OrderedShape,
    Chip, StarkGenericConfig, StarkMachine, PROOF_MAX_NUM_PVS,
};

use crate::{
    chips::{
        alu_base::{BaseAluChip, NUM_BASE_ALU_ENTRIES_PER_ROW},
        alu_ext::{ExtAluChip, NUM_EXT_ALU_ENTRIES_PER_ROW},
        ext2felt::Ext2FeltChip,
        mem::{
            constant::NUM_CONST_MEM_ENTRIES_PER_ROW, variable::NUM_VAR_MEM_ENTRIES_PER_ROW,
            MemoryConstChip, MemoryVarChip,
        },
        poseidon2_wide::Poseidon2WideChip,
        public_values::{PublicValuesChip, PUB_VALUES_LOG_HEIGHT},
        select::SelectChip,
    },
    instruction::{HintBitsInstr, HintExt2FeltsInstr, HintInstr},
    shape::RecursionShape, Instruction, RecursionProgram, D,
};

#[derive(zkm_derive::MachineAir)]
#[zkm_core_path = "zkm_core_machine"]
#[execution_record_path = "crate::ExecutionRecord<F>"]
#[program_path = "crate::RecursionProgram<F>"]
#[builder_path = "crate::builder::ZKMRecursionAirBuilder<F = F>"]
#[error_path = "crate::RecursionChipError"]
#[eval_trait_bound = "AB::Var: 'static"]
pub enum RecursionAir<F: PrimeField32 + BinomiallyExtendable<D>, const DEGREE: usize> {
    MemoryConst(MemoryConstChip<F>),
    MemoryVar(MemoryVarChip<F>),
    BaseAlu(BaseAluChip),
    ExtAlu(ExtAluChip),
    Poseidon2Wide(Poseidon2WideChip<DEGREE>),
    Select(SelectChip),
    Ext2Felt(Ext2FeltChip<F>),
    PublicValues(PublicValuesChip),
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RecursionAirEventCount {
    pub mem_const_events: usize,
    pub mem_var_events: usize,
    pub base_alu_events: usize,
    pub ext_alu_events: usize,
    pub poseidon2_wide_events: usize,
    pub fri_fold_events: usize,
    pub batch_fri_events: usize,
    pub select_events: usize,
    pub exp_reverse_bits_len_events: usize,
    /// One per `Ext2Felts` instruction (the constrained decomposition chip).
    pub ext2felt_events: usize,
    /// Counter for commit_pv_hash events (CommitPublicValues match arm
    /// in `Runtime::run`). Populated by
    /// `AddAssign<&Instruction>` so `UnsafeRecord::new` can pre-size
    /// the vec once the runtime walker swaps to offset-based writes.
    pub commit_pv_hash_events: usize,
}

impl<F: PrimeField32 + BinomiallyExtendable<D>, const DEGREE: usize> RecursionAir<F, DEGREE> {
    /// Get a machine with all chips, except the dummy chip.

    /// Get a machine with all chips, except the dummy chip.

    /// A machine with dyunamic chip sizes that includes the wide variant of the Poseidon2 chip.
    pub fn compress_machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
        let chips = [
            RecursionAir::MemoryConst(MemoryConstChip::default()),
            RecursionAir::MemoryVar(MemoryVarChip::default()),
            RecursionAir::BaseAlu(BaseAluChip),
            RecursionAir::ExtAlu(ExtAluChip),
            RecursionAir::Poseidon2Wide(Poseidon2WideChip::<DEGREE>),
            // BatchFRI and ExpReverseBitsLen are retired from the BaseFold
            // compress/shrink machine. Both carry `when_transition` /
            // padded-row AIR constraints that `BasefoldConstraintFolder`
            // cannot evaluate (it has no row selectors — `unimplemented!`).
            // BatchFRI emits zero events on this path: its only emitter,
            // the legacy `TwoAdicFriPcs` FRI verifier (`C::batch_fri`), is
            // retired, and BaseFold never exercises it. ExpReverseBitsLen
            // is now lowered inline to ALU/Select ops in
            // `InnerConfig::exp_reverse_bits` (circuit/lib.rs), so it too
            // emits zero events here. Both chips remain in the legacy-FRI
            // `wrap_machine` / `machine_*_with_all_chips`, which use the
            // row-selector STARK prover.
            RecursionAir::Select(SelectChip),
            RecursionAir::Ext2Felt(Ext2FeltChip::default()),
            RecursionAir::PublicValues(PublicValuesChip),
        ]
        .map(Chip::new)
        .into_iter()
        .collect::<Vec<_>>();
        // NO AREA PIN.  Compress used to raise every reduce shard's committed
        // dense to `2^RECURSION_LOG_TRACE_AREA`, on the premise that one fixed
        // jagged geometry collapses the compose VK to f(chip-set, arity).  It
        // does not: the pin is a FLOOR, and measured, every real child's natural
        // area already passes it — children commit at 150994944 and 218103808
        // and the floor never binds — so the geometry was never fixed and the
        // padding only ever cost the SMALL children, which it rounded up to
        // 2^27 for nothing.  SP1 has no such pin.
        StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
    }

    pub fn shrink_machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
        // SHRINK's chip set is FROZEN at the pre-`Ext2Felt` compress set: the
        // shrink proof's structure is what the BN254 wrap R1CS — and through
        // it the gnark ceremony — is built over, so a chip added to compress
        // must NOT appear here.  Shrink programs correspondingly keep the
        // legacy `HintExt2Felts` + monomial re-binding (see `ext2felt_v2`).
        let chips = [
            RecursionAir::MemoryConst(MemoryConstChip::default()),
            RecursionAir::MemoryVar(MemoryVarChip::default()),
            RecursionAir::BaseAlu(BaseAluChip),
            RecursionAir::ExtAlu(ExtAluChip),
            RecursionAir::Poseidon2Wide(Poseidon2WideChip::<DEGREE>),
            RecursionAir::Select(SelectChip),
            RecursionAir::PublicValues(PublicValuesChip),
        ]
        .map(Chip::new)
        .into_iter()
        .collect::<Vec<_>>();
        StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
    }

    /// A machine with dynamic chip sizes that includes the skinny variant of the Poseidon2 chip.
    ///
    /// This machine assumes that the `shrink` stage has a fixed shape, so there is no need to
    /// fix the trace sizes.
    pub fn wrap_machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
        // #H (BaseFold-over-BN254 wrap port): the wrap STARK now proves via
        // BaseFold, so its
        // machine must be selector-free, exactly like the compress/shrink
        // BaseFold machine. The legacy wrap chip set used `Poseidon2Skinny`
        // (poseidon2_skinny/air.rs has when_first_row/when_transition AIR
        // constraints) and `BatchFRI` (FRI verifier chip, also row-selector +
        // padded-row constrained) — both `unimplemented!` in
        // `BasefoldConstraintFolder`. On the BaseFold path the wrap program
        // (`verify_wrap_basefold`) emits zero BatchFRI events and uses the wide
        // Poseidon2, so the FRI-free compress/shrink chip set is correct here.
        let chips = [
            RecursionAir::MemoryConst(MemoryConstChip::default()),
            RecursionAir::MemoryVar(MemoryVarChip::default()),
            RecursionAir::BaseAlu(BaseAluChip),
            RecursionAir::ExtAlu(ExtAluChip),
            RecursionAir::Poseidon2Wide(Poseidon2WideChip::<DEGREE>),
            RecursionAir::Select(SelectChip),
            RecursionAir::PublicValues(PublicValuesChip),
        ]
        .map(Chip::new)
        .into_iter()
        .collect::<Vec<_>>();
        StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
    }

    pub fn shrink_shape() -> RecursionShape {
        // Row counts, not log2 heights — a recursion shape pins rows exactly
        // (`next_multiple_of_32_rows`).  Written as `1 << n` because that is
        // what these were, and shrink is FROZEN: nothing re-tunes it.
        let shape: std::collections::BTreeMap<String, usize> = [
            (Self::MemoryVar(MemoryVarChip::default()), 1 << 18),
            (Self::Select(SelectChip), 1 << 18),
            (Self::MemoryConst(MemoryConstChip::default()), 1 << 17),
            // BatchFRI / ExpReverseBitsLen are no longer in the BaseFold
            // compress/shrink *machine* (see `compress_machine`), but their
            (Self::BaseAlu(BaseAluChip), 1 << 17),
            (Self::ExtAlu(ExtAluChip), 1 << 15),
            (Self::Poseidon2Wide(Poseidon2WideChip::<DEGREE>), 1 << 16),
            (Self::PublicValues(PublicValuesChip), 1 << PUB_VALUES_LOG_HEIGHT),
        ]
        .into_iter()
        .map(|(chip, rows)| (chip.name(), rows))
        .collect();
        RecursionShape { inner: shape }
    }

    pub fn heights(program: &RecursionProgram<F>) -> Vec<(String, usize)> {
        let heights = program
            .iter_instructions()
            .fold(RecursionAirEventCount::default(), |heights, instruction| heights + instruction);

        [
            (
                Self::MemoryConst(MemoryConstChip::default()),
                heights.mem_const_events.div_ceil(NUM_CONST_MEM_ENTRIES_PER_ROW),
            ),
            (
                Self::MemoryVar(MemoryVarChip::default()),
                heights.mem_var_events.div_ceil(NUM_VAR_MEM_ENTRIES_PER_ROW),
            ),
            (
                Self::BaseAlu(BaseAluChip),
                heights.base_alu_events.div_ceil(NUM_BASE_ALU_ENTRIES_PER_ROW),
            ),
            (
                Self::ExtAlu(ExtAluChip),
                heights.ext_alu_events.div_ceil(NUM_EXT_ALU_ENTRIES_PER_ROW),
            ),
            (Self::Poseidon2Wide(Poseidon2WideChip::<DEGREE>), heights.poseidon2_wide_events),
            (Self::Select(SelectChip), heights.select_events),
            (Self::Ext2Felt(Ext2FeltChip::default()), heights.ext2felt_events),
            (Self::PublicValues(PublicValuesChip), PUB_VALUES_LOG_HEIGHT),
        ]
        .map(|(chip, log_height)| (chip.name(), log_height))
        .to_vec()
    }
}

impl<F> AddAssign<&Instruction<F>> for RecursionAirEventCount {
    #[inline]
    fn add_assign(&mut self, rhs: &Instruction<F>) {
        match rhs {
            Instruction::BaseAlu(_) => self.base_alu_events += 1,
            Instruction::ExtAlu(_) => self.ext_alu_events += 1,
            Instruction::Mem(_) => self.mem_const_events += 1,
            Instruction::Poseidon2(_) => self.poseidon2_wide_events += 1,
            Instruction::Select(_) => self.select_events += 1,
            // Runtime emits ONE event per instruction (the event carries
            // `exp: Vec<F>` of all bits). Was over-counting by exp.len();
            // benign for push-based reserve, but UB-prone for offset
            // writes via UnsafeRecord (uninit slots → bad transmute).
            Instruction::Hint(HintInstr { output_addrs_mults })
            | Instruction::HintBits(HintBitsInstr {
                output_addrs_mults,
                input_addr: _, // No receive lookup for the hint operation
            }) => self.mem_var_events += output_addrs_mults.len(),
            Instruction::HintExt2Felts(HintExt2FeltsInstr {
                output_addrs_mults,
                input_addr: _, // No receive lookup for the hint operation
            }) => self.mem_var_events += output_addrs_mults.len(),
            Instruction::Ext2Felts(_) => self.ext2felt_events += 1,
            // FriFold runtime emits ps_at_z.len() events per instruction
            // (one per polynomial in the batch); was off-by-default-1. Benign
            // for push-based reserve, but UB-prone for offset writes via
            // UnsafeRecord (uninit slots → bad transmute).
            Instruction::HintAddCurve(instr) => {
                self.mem_var_events += instr.output_x_addrs_mults.len();
                self.mem_var_events += instr.output_y_addrs_mults.len();
            }
            // Populate the new counters so `UnsafeRecord::new` can
            // pre-size these vecs once the runtime walker swaps to
            // offset-based writes. CommitPublicValues emits exactly
            // one commit_pv_hash event per instruction.
            Instruction::CommitPublicValues(_) => self.commit_pv_hash_events += 1,
            Instruction::Print(_) => {}
        }
    }
}

impl<F> Add<&Instruction<F>> for RecursionAirEventCount {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: &Instruction<F>) -> Self::Output {
        self += rhs;
        self
    }
}

impl From<RecursionShape> for OrderedShape {
    fn from(value: RecursionShape) -> Self {
        value.inner.into_iter().collect()
    }
}

/// Compile-time proof that every
/// `RecursionAir` chip implements
/// `Air<BasefoldConstraintFolder<'a, KoalaBear, InnerChallenge, InnerChallenge>>`.
///
/// The host-side `BasefoldConstraintFolder` (defined at
/// `zkm-pcs::shard_level::basefold_constraint_folder`) is
/// `AirBuilder + EmptyMessageBuilder`, which by way of the blanket impls
/// `AB: AirBuilder<F: Field> + MessageBuilder<AirLookup<...>> => BaseAirBuilder`
/// (`crates/pcs/src/air/builder.rs:581`) and
/// `AB: BaseAirBuilder => RecursionAirBuilder` (`crates/recursion/core/src/builder.rs:15`)
/// and `AB: RecursionAirBuilder => ZKMRecursionAirBuilder` (`crates/recursion/core/src/builder.rs:14`)
/// automatically becomes a `ZKMRecursionAirBuilder` — so the existing
/// generic `impl<AB: ZKMRecursionAirBuilder> Air<AB> for ChipName` on
/// every recursion chip already covers it.  No new per-chip code is
/// required; these assertions just make the bound resolution explicit
/// and act as a regression guard if any chip's bounds tighten.
///
/// The in-circuit folder
/// (`zkm-recursion-circuit::basefold_constraint_folder`) lives in a
/// downstream crate, so its assertion lives in `zkm-recursion-circuit`
/// (see `crates/recursion/circuit/src/basefold_constraint_folder.rs`).
#[cfg(test)]
mod basefold_air_assertions {
    use super::*;
    use crate::chips::{
        alu_base::BaseAluChip,
        alu_ext::ExtAluChip,
        mem::{constant::MemoryChip as MemoryConstChip, variable::MemoryChip as MemoryVarChip},
        poseidon2_wide::Poseidon2WideChip,
        public_values::PublicValuesChip,
        select::SelectChip,
    };
    use p3_air::Air;
    use p3_koala_bear::KoalaBear;
    use zkm_pcs::{
        shard_level::basefold_constraint_folder::BasefoldConstraintFolder, InnerChallenge,
    };

    /// Compile-time bound: `T: for<'a> Air<BasefoldConstraintFolder<'a, KoalaBear, InnerChallenge, InnerChallenge>>`.
    fn assert_basefold_air<T>()
    where
        T: for<'a> Air<BasefoldConstraintFolder<'a, KoalaBear, InnerChallenge, InnerChallenge>>,
    {
    }

    /// Const used purely to force monomorphisation of every chip's
    /// `Air<BasefoldConstraintFolder>` bound at compile time.  Never called --
    /// the body is type-checked, which is the whole point, so it needs
    /// `allow(dead_code)` to keep the helper it references alive.
    /// Covers the 7 production chips plus the `RecursionAir` enum.
    #[allow(dead_code)]
    const _ASSERT_ALL_CHIPS: fn() = || {
        // 1. MemoryConst
        assert_basefold_air::<MemoryConstChip<KoalaBear>>();
        // 2. MemoryVar
        assert_basefold_air::<MemoryVarChip<KoalaBear>>();
        // 3. BaseAlu
        assert_basefold_air::<BaseAluChip>();
        // 4. ExtAlu
        assert_basefold_air::<ExtAluChip>();
        // 5. Poseidon2Wide (DEGREE=9, the production const)
        assert_basefold_air::<Poseidon2WideChip<9>>();
        // 6. Select
        assert_basefold_air::<SelectChip>();
        // 7. PublicValues
        assert_basefold_air::<PublicValuesChip>();

        // Enum-level: the `#[derive(MachineAir)]` macro emits a generic
        // `impl<AB: ZKMRecursionAirBuilder<F = F>, AB::Var: 'static>
        // Air<AB> for RecursionAir<F, DEGREE>` (`crates/derive/src/lib.rs:320-328`).
        // For `AB = BasefoldConstraintFolder<'a, KoalaBear, InnerChallenge>`,
        // `AB::F = KoalaBear` matches `F = KoalaBear` and `AB::Var =
        // InnerChallenge: 'static`, so the bound resolves.
        assert_basefold_air::<RecursionAir<KoalaBear, 9>>();
    };
}

#[cfg(test)]
pub mod tests {

    use std::{iter::once, sync::Arc};

    use crate::machine::RecursionAir;
    use p3_field::{
        extension::{BinomialExtensionField, HasFrobenius},
        BasedVectorSpace, Field, PrimeCharacteristicRing,
    };
    use p3_koala_bear::Poseidon2InternalLayerKoalaBear;
    use rand::prelude::*;
    use zkm_pcs::{koala_bear_poseidon2::KoalaBearPoseidon2, StarkGenericConfig};
    use zkm_test_fixtures::run_test_machine;

    use crate::{
        runtime::{
            instruction as instr, BaseAluOpcode, ExtAluOpcode, Instruction, RecursionProgram,
            Runtime,
        },
        MemAccessKind, D,
    };

    type SC = KoalaBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    type A = RecursionAir<F, 3>;
    type B = RecursionAir<F, 9>;

    /// Runs the given program on machines that use the wide and skinny Poseidon2 chips.
    pub fn run_recursion_test_machines(mut program: RecursionProgram<F>) {
        // Programs assembled directly from instructions (as these tests do)
        // never run the compiler, which is what normally sets `total_memory`.
        // `Runtime::new` sizes its `ParMemVec` from it and the vec never grows,
        // so leaving it at `Default::default()` makes the first memory write
        // panic with "address N out of bounds (len=0)".
        if program.total_memory == 0 {
            program.total_memory = program.computed_total_memory();
        }
        let program = Arc::new(program);
        let mut runtime = Runtime::<F, EF, Poseidon2InternalLayerKoalaBear<16>>::new(
            program.clone(),
            SC::new().perm,
        );
        runtime.run().unwrap();

        // Prove with the production chip set.
        let machine = A::compress_machine(KoalaBearPoseidon2::default());
        let (pk, vk) = machine.setup(&program);
        let result = run_test_machine(vec![runtime.record], machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {e:?}");
        }
    }

    fn test_instructions(instructions: Vec<Instruction<F>>) {
        let program = RecursionProgram {
            seq_blocks: crate::RawProgram::from_linear(instructions),
            ..Default::default()
        };
        run_recursion_test_machines(program);
    }

    #[test]
    pub fn fibonacci() {
        let n = 10;

        let instructions = once(instr::mem(MemAccessKind::Write, 1, 0, 0))
            .chain(once(instr::mem(MemAccessKind::Write, 2, 1, 1)))
            .chain((2..=n).map(|i| instr::base_alu(BaseAluOpcode::AddF, 2, i, i - 2, i - 1)))
            .chain(once(instr::mem(MemAccessKind::Read, 1, n - 1, 34)))
            .chain(once(instr::mem(MemAccessKind::Read, 2, n, 55)))
            .collect::<Vec<_>>();

        test_instructions(instructions);
    }

    #[test]
    #[should_panic]
    pub fn div_nonzero_by_zero() {
        let instructions = vec![
            instr::mem(MemAccessKind::Write, 1, 0, 0),
            instr::mem(MemAccessKind::Write, 1, 1, 1),
            instr::base_alu(BaseAluOpcode::DivF, 1, 2, 1, 0),
            instr::mem(MemAccessKind::Read, 1, 2, 1),
        ];

        test_instructions(instructions);
    }

    #[test]
    pub fn div_zero_by_zero() {
        let instructions = vec![
            instr::mem(MemAccessKind::Write, 1, 0, 0),
            instr::mem(MemAccessKind::Write, 1, 1, 0),
            instr::base_alu(BaseAluOpcode::DivF, 1, 2, 1, 0),
            instr::mem(MemAccessKind::Read, 1, 2, 1),
        ];

        test_instructions(instructions);
    }

    #[test]
    pub fn field_norm() {
        let mut instructions = Vec::new();

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut addr = 0;
        for _ in 0..100 {
            let inner: [F; 4] =
                std::iter::repeat_with(|| core::array::from_fn(|_| F::from_u64(rng.gen::<u64>())))
                    .find(|xs| !xs.iter().all(F::is_zero))
                    .unwrap();
            let x = BinomialExtensionField::<F, D>::from_basis_coefficients_slice(&inner).unwrap();
            let gal = x.galois_orbit();

            let mut acc = BinomialExtensionField::ONE;

            instructions.push(instr::mem_ext(MemAccessKind::Write, 1, addr, acc));
            for conj in gal {
                instructions.push(instr::mem_ext(MemAccessKind::Write, 1, addr + 1, conj));
                instructions.push(instr::ext_alu(ExtAluOpcode::MulE, 1, addr + 2, addr, addr + 1));

                addr += 2;
                acc *= conj;
            }
            let base_cmp: F = acc.as_basis_coefficients_slice()[0];
            instructions.push(instr::mem_single(MemAccessKind::Read, 1, addr, base_cmp));
            addr += 1;
        }

        test_instructions(instructions);
    }
}

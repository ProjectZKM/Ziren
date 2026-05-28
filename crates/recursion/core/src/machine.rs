use std::ops::{Add, AddAssign};

use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use zkm_stark::{
    air::{LookupScope, MachineAir, PicusInfo},
    shape::OrderedShape,
    Chip, StarkGenericConfig, StarkMachine, PROOF_MAX_NUM_PVS,
};

use crate::{
    chips::{
        alu_base::{BaseAluChip, NUM_BASE_ALU_ENTRIES_PER_ROW},
        alu_ext::{ExtAluChip, NUM_EXT_ALU_ENTRIES_PER_ROW},
        batch_fri::BatchFRIChip,
        exp_reverse_bits::ExpReverseBitsLenChip,
        fri_fold::FriFoldChip,
        mem::{
            constant::NUM_CONST_MEM_ENTRIES_PER_ROW, variable::NUM_VAR_MEM_ENTRIES_PER_ROW,
            MemoryConstChip, MemoryVarChip,
        },
        poseidon2_skinny::Poseidon2SkinnyChip,
        poseidon2_wide::Poseidon2WideChip,
        public_values::{PublicValuesChip, PUB_VALUES_LOG_HEIGHT},
        select::SelectChip,
    },
    instruction::{HintAddCurveInstr, HintBitsInstr, HintExt2FeltsInstr, HintInstr},
    shape::RecursionShape,
    ExpReverseBitsInstr, Instruction, RecursionProgram, D,
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
    Poseidon2Skinny(Poseidon2SkinnyChip<DEGREE>),
    Poseidon2Wide(Poseidon2WideChip<DEGREE>),
    Select(SelectChip),
    FriFold(FriFoldChip<DEGREE>),
    BatchFRI(BatchFRIChip<DEGREE>),
    ExpReverseBitsLen(ExpReverseBitsLenChip<DEGREE>),
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
    pub prefix_sum_checks_events: usize,
    pub select_events: usize,
    pub exp_reverse_bits_len_events: usize,
    /// Counter for commit_pv_hash events (CommitPublicValues match arm
    /// in `Runtime::run`). Populated by
    /// `AddAssign<&Instruction>` so `UnsafeRecord::new` can pre-size
    /// the vec once the runtime walker swaps to offset-based writes.
    pub commit_pv_hash_events: usize,
}

impl<F: PrimeField32 + BinomiallyExtendable<D>, const DEGREE: usize> RecursionAir<F, DEGREE> {
    /// Get a machine with all chips, except the dummy chip.
    pub fn machine_wide_with_all_chips<SC: StarkGenericConfig<Val = F>>(
        config: SC,
    ) -> StarkMachine<SC, Self> {
        let chips = [
            RecursionAir::MemoryConst(MemoryConstChip::default()),
            RecursionAir::MemoryVar(MemoryVarChip::default()),
            RecursionAir::BaseAlu(BaseAluChip),
            RecursionAir::ExtAlu(ExtAluChip),
            RecursionAir::Poseidon2Wide(Poseidon2WideChip::<DEGREE>),
            RecursionAir::FriFold(FriFoldChip::<DEGREE>::default()),
            RecursionAir::BatchFRI(BatchFRIChip::<DEGREE>),
            RecursionAir::Select(SelectChip),
            RecursionAir::ExpReverseBitsLen(ExpReverseBitsLenChip::<DEGREE>),
            RecursionAir::PublicValues(PublicValuesChip),
        ]
        .map(Chip::new)
        .into_iter()
        .collect::<Vec<_>>();
        StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
    }

    /// Get a machine with all chips, except the dummy chip.
    pub fn machine_skinny_with_all_chips<SC: StarkGenericConfig<Val = F>>(
        config: SC,
    ) -> StarkMachine<SC, Self> {
        let chips = [
            RecursionAir::MemoryConst(MemoryConstChip::default()),
            RecursionAir::MemoryVar(MemoryVarChip::default()),
            RecursionAir::BaseAlu(BaseAluChip),
            RecursionAir::ExtAlu(ExtAluChip),
            RecursionAir::Poseidon2Skinny(Poseidon2SkinnyChip::<DEGREE>::default()),
            RecursionAir::FriFold(FriFoldChip::<DEGREE>::default()),
            RecursionAir::BatchFRI(BatchFRIChip::<DEGREE>),
            RecursionAir::Select(SelectChip),
            RecursionAir::ExpReverseBitsLen(ExpReverseBitsLenChip::<DEGREE>),
            RecursionAir::PublicValues(PublicValuesChip),
        ]
        .map(Chip::new)
        .into_iter()
        .collect::<Vec<_>>();
        StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
    }

    /// A machine with dyunamic chip sizes that includes the wide variant of the Poseidon2 chip.
    pub fn compress_machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
        let chips = [
            RecursionAir::MemoryConst(MemoryConstChip::default()),
            RecursionAir::MemoryVar(MemoryVarChip::default()),
            RecursionAir::BaseAlu(BaseAluChip),
            RecursionAir::ExtAlu(ExtAluChip),
            RecursionAir::Poseidon2Wide(Poseidon2WideChip::<DEGREE>),
            RecursionAir::BatchFRI(BatchFRIChip::<DEGREE>),
            RecursionAir::Select(SelectChip),
            RecursionAir::ExpReverseBitsLen(ExpReverseBitsLenChip::<DEGREE>),
            RecursionAir::PublicValues(PublicValuesChip),
        ]
        .map(Chip::new)
        .into_iter()
        .collect::<Vec<_>>();
        StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
    }

    pub fn shrink_machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
        Self::compress_machine(config)
    }

    /// A machine with dynamic chip sizes that includes the skinny variant of the Poseidon2 chip.
    ///
    /// This machine assumes that the `shrink` stage has a fixed shape, so there is no need to
    /// fix the trace sizes.
    pub fn wrap_machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
        let chips = [
            RecursionAir::MemoryConst(MemoryConstChip::default()),
            RecursionAir::MemoryVar(MemoryVarChip::default()),
            RecursionAir::BaseAlu(BaseAluChip),
            RecursionAir::ExtAlu(ExtAluChip),
            RecursionAir::Poseidon2Skinny(Poseidon2SkinnyChip::<DEGREE>::default()),
            RecursionAir::BatchFRI(BatchFRIChip::<DEGREE>),
            RecursionAir::Select(SelectChip),
            RecursionAir::PublicValues(PublicValuesChip),
        ]
        .map(Chip::new)
        .into_iter()
        .collect::<Vec<_>>();
        StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS)
    }

    pub fn shrink_shape() -> RecursionShape {
        let shape: std::collections::BTreeMap<String, usize> = [
            (Self::MemoryVar(MemoryVarChip::default()), 18),
            (Self::Select(SelectChip), 18),
            (Self::MemoryConst(MemoryConstChip::default()), 17),
            (Self::BatchFRI(BatchFRIChip::<DEGREE>), 17),
            (Self::BaseAlu(BaseAluChip), 17),
            (Self::ExtAlu(ExtAluChip), 15),
            (Self::ExpReverseBitsLen(ExpReverseBitsLenChip::<DEGREE>), 17),
            (Self::Poseidon2Wide(Poseidon2WideChip::<DEGREE>), 16),
            (Self::PublicValues(PublicValuesChip), PUB_VALUES_LOG_HEIGHT),
        ]
        .into_iter()
        .map(|(chip, log_height)| (chip.name(), log_height))
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
            (Self::BatchFRI(BatchFRIChip::<DEGREE>), heights.batch_fri_events),
            (Self::Select(SelectChip), heights.select_events),
            (
                Self::ExpReverseBitsLen(ExpReverseBitsLenChip::<DEGREE>),
                heights.exp_reverse_bits_len_events,
            ),
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
            Instruction::ExpReverseBitsLen(ExpReverseBitsInstr { .. }) => {
                self.exp_reverse_bits_len_events += 1
            }
            Instruction::Hint(HintInstr { output_addrs_mults })
            | Instruction::HintBits(HintBitsInstr {
                output_addrs_mults,
                input_addr: _, // No receive lookup for the hint operation
            }) => self.mem_var_events += output_addrs_mults.len(),
            Instruction::HintExt2Felts(HintExt2FeltsInstr {
                output_addrs_mults,
                input_addr: _, // No receive lookup for the hint operation
            }) => self.mem_var_events += output_addrs_mults.len(),
            // FriFold runtime emits ps_at_z.len() events per instruction
            // (one per polynomial in the batch); was off-by-default-1. Benign
            // for push-based reserve, but UB-prone for offset writes via
            // UnsafeRecord (uninit slots → bad transmute).
            Instruction::FriFold(instr) => {
                self.fri_fold_events += instr.ext_vec_addrs.ps_at_z.len()
            }
            Instruction::BatchFRI(instr) => {
                self.batch_fri_events += instr.base_vec_addrs.p_at_x.len()
            }
            Instruction::PrefixSumChecks(instr) => {
                self.prefix_sum_checks_events += instr.addrs.x1.len()
            }
            Instruction::HintAddCurve(HintAddCurveInstr {
                output_x_addrs_mults,
                output_y_addrs_mults,
                ..
            }) => {
                self.mem_var_events += output_x_addrs_mults.len();
                self.mem_var_events += output_y_addrs_mults.len();
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

/// Task #382 Phase 3a sub-sprint A: compile-time proof that every
/// `RecursionAir` chip implements
/// `Air<BasefoldConstraintFolder<'a, KoalaBear, InnerChallenge>>`.
///
/// The host-side `BasefoldConstraintFolder` (defined at
/// `zkm-stark::shard_level::basefold_constraint_folder`) is
/// `AirBuilder + EmptyMessageBuilder`, which by way of the blanket impls
/// `AB: AirBuilder<F: Field> + MessageBuilder<AirLookup<...>> => BaseAirBuilder`
/// (`crates/stark/src/air/builder.rs:581`) and
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
        alu_base::BaseAluChip, alu_ext::ExtAluChip, batch_fri::BatchFRIChip,
        exp_reverse_bits::ExpReverseBitsLenChip, fri_fold::FriFoldChip,
        mem::{constant::MemoryChip as MemoryConstChip, variable::MemoryChip as MemoryVarChip},
        poseidon2_skinny::Poseidon2SkinnyChip, poseidon2_wide::Poseidon2WideChip,
        public_values::PublicValuesChip, select::SelectChip,
    };
    use p3_air::Air;
    use p3_koala_bear::KoalaBear;
    use zkm_stark::{
        shard_level::basefold_constraint_folder::BasefoldConstraintFolder, InnerChallenge,
    };

    /// Compile-time bound: `T: for<'a> Air<BasefoldConstraintFolder<'a, KoalaBear, InnerChallenge>>`.
    fn assert_basefold_air<T>()
    where
        T: for<'a> Air<BasefoldConstraintFolder<'a, KoalaBear, InnerChallenge>>,
    {
    }

    /// Const used purely to force monomorphisation of all 11 chip
    /// assertions at compile time.  Never called.
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
        // 6. Poseidon2Skinny (DEGREE=9)
        assert_basefold_air::<Poseidon2SkinnyChip<9>>();
        // 7. Select
        assert_basefold_air::<SelectChip>();
        // 8. FriFold (DEGREE=9)
        assert_basefold_air::<FriFoldChip<9>>();
        // 9. BatchFRI (DEGREE=9)
        assert_basefold_air::<BatchFRIChip<9>>();
        // 10. ExpReverseBitsLen (DEGREE=9)
        assert_basefold_air::<ExpReverseBitsLenChip<9>>();
        // 11. PublicValues
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
        BasedVectorSpace, Field, PrimeCharacteristicRing, ExtensionField,
    };
    use p3_koala_bear::Poseidon2InternalLayerKoalaBear;
    use rand::prelude::*;
    use zkm_core_machine::utils::run_test_machine;
    use zkm_stark::{koala_bear_poseidon2::KoalaBearPoseidon2, StarkGenericConfig};

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
    pub fn run_recursion_test_machines(program: RecursionProgram<F>) {
        let program = Arc::new(program);
        let mut runtime = Runtime::<F, EF, Poseidon2InternalLayerKoalaBear<16>>::new(
            program.clone(),
            SC::new().perm,
        );
        runtime.run().unwrap();

        // Run with the poseidon2 wide chip.
        let machine = A::machine_wide_with_all_chips(KoalaBearPoseidon2::default());
        let (pk, vk) = machine.setup(&program);
        let result = run_test_machine(vec![runtime.record.clone()], machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {e:?}");
        }

        // Run with the poseidon2 skinny chip.
        let skinny_machine =
            B::machine_skinny_with_all_chips(KoalaBearPoseidon2::ultra_compressed());
        let (pk, vk) = skinny_machine.setup(&program);
        let result = run_test_machine(vec![runtime.record], skinny_machine, pk, vk);
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
            let inner: [F; 4] = std::iter::repeat_with(|| {
                core::array::from_fn(|_| F::from_u64(rng.gen::<u64>()))
            })
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

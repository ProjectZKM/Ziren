use std::collections::BTreeMap;
use std::marker::PhantomData;

use hashbrown::HashMap;

use itertools::Itertools;
use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use serde::{Deserialize, Serialize};
use zkm_stark::{air::MachineAir, shape::OrderedShape};

use crate::{
    chips::{
        alu_base::BaseAluChip,
        alu_ext::ExtAluChip,
        batch_fri::BatchFRIChip,
        exp_reverse_bits::ExpReverseBitsLenChip,
        mem::{MemoryConstChip, MemoryVarChip},
        poseidon2_wide::Poseidon2WideChip,
        public_values::{PublicValuesChip, PUB_VALUES_LOG_HEIGHT},
        select::SelectChip,
    },
    machine::RecursionAir,
    RecursionProgram, D,
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecursionShape {
    /// Per-chip log2 height.  `BTreeMap` (not `HashMap`) so the
    /// iteration order is deterministic across processes — without
    /// this, the recursion-compiler emits opcodes in a per-process-
    /// random order, the resulting wrap_program's compiled hint
    /// sequence shifts, and the witness writer (which walks the
    /// real proof's deterministic Vec layout) desyncs at runtime.
    /// Symptom: `OodEvaluationMismatch on chip MemoryVar` /
    /// `Poseidon2WideDeg3` flakes ~50% of fresh `cargo test` runs.
    pub(crate) inner: BTreeMap<String, usize>,
}

impl RecursionShape {
    pub fn clone_into_hash_map(&self) -> HashMap<String, usize> {
        self.inner.iter().map(|(k, v)| (k.clone(), *v)).collect()
    }
}

impl From<HashMap<String, usize>> for RecursionShape {
    fn from(value: HashMap<String, usize>) -> Self {
        Self { inner: value.into_iter().collect() }
    }
}

impl From<BTreeMap<String, usize>> for RecursionShape {
    fn from(value: BTreeMap<String, usize>) -> Self {
        Self { inner: value }
    }
}

pub struct RecursionShapeConfig<F, A> {
    allowed_shapes: Vec<HashMap<String, usize>>,
    _marker: PhantomData<(F, A)>,
}

impl<F: PrimeField32 + BinomiallyExtendable<D>, const DEGREE: usize>
    RecursionShapeConfig<F, RecursionAir<F, DEGREE>>
{
    pub fn fix_shape(&self, program: &mut RecursionProgram<F>) {
        let heights = RecursionAir::<F, DEGREE>::heights(program);

        let mut closest_shape = None;

        for shape in self.allowed_shapes.iter() {
            // If any of the heights is greater than the shape, continue.
            let mut valid = true;
            for (name, height) in heights.iter() {
                if *height > (1 << shape.get(name).unwrap()) {
                    valid = false;
                }
            }

            if !valid {
                continue;
            }

            closest_shape = Some(shape.clone());
            break;
        }

        if let Some(shape) = closest_shape {
            let shape = RecursionShape { inner: shape.into_iter().collect() };
            *program.shape_mut() = Some(shape);
        } else {
            panic!("no shape found for heights: {heights:?}");
        }
    }

    pub fn get_all_shape_combinations(
        &self,
        batch_size: usize,
    ) -> impl Iterator<Item = Vec<OrderedShape>> + '_ {
        (0..batch_size)
            .map(|_| {
                self.allowed_shapes
                    .iter()
                    .cloned()
                    .map(|map| map.into_iter().collect::<OrderedShape>())
            })
            .multi_cartesian_product()
    }

    pub fn union_config_with_extra_room(&self) -> Self {
        let mut map = HashMap::new();
        for shape in self.allowed_shapes.clone() {
            for key in shape.keys() {
                let current = map.get(key).unwrap_or(&0);
                map.insert(key.clone(), *current.max(shape.get(key).unwrap()));
            }
        }
        map.values_mut().for_each(|x| *x += 2);
        map.insert("PublicValues".to_string(), 4);
        Self { allowed_shapes: vec![map], _marker: PhantomData }
    }

    pub fn from_hash_map(hash_map: &HashMap<String, usize>) -> Self {
        Self { allowed_shapes: vec![hash_map.clone()], _marker: PhantomData }
    }

    pub fn first(&self) -> Option<&HashMap<String, usize>> {
        self.allowed_shapes.first()
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<D>, const DEGREE: usize> Default
    for RecursionShapeConfig<F, RecursionAir<F, DEGREE>>
{
    fn default() -> Self {
        // Get the names of all the recursion airs to make the shape specification more readable.
        let mem_const = RecursionAir::<F, DEGREE>::MemoryConst(MemoryConstChip::default()).name();
        let mem_var = RecursionAir::<F, DEGREE>::MemoryVar(MemoryVarChip::default()).name();
        let base_alu = RecursionAir::<F, DEGREE>::BaseAlu(BaseAluChip).name();
        let ext_alu = RecursionAir::<F, DEGREE>::ExtAlu(ExtAluChip).name();
        let poseidon2_wide =
            RecursionAir::<F, DEGREE>::Poseidon2Wide(Poseidon2WideChip::<DEGREE>).name();
        let batch_fri = RecursionAir::<F, DEGREE>::BatchFRI(BatchFRIChip::<DEGREE>).name();
        let select = RecursionAir::<F, DEGREE>::Select(SelectChip).name();
        let exp_reverse_bits_len =
            RecursionAir::<F, DEGREE>::ExpReverseBitsLen(ExpReverseBitsLenChip::<DEGREE>).name();
        let public_values = RecursionAir::<F, DEGREE>::PublicValues(PublicValuesChip).name();

        // Specify allowed shapes.
        let allowed_shapes = [
            // Fastest shape.
            [
                (mem_var.clone(), 18),
                (select.clone(), 18),
                (mem_const.clone(), 16),
                (batch_fri.clone(), 17),
                (base_alu.clone(), 15),
                (ext_alu.clone(), 15),
                (exp_reverse_bits_len.clone(), 17),
                (poseidon2_wide.clone(), 16),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            // Second fastest shape.
            [
                (mem_var.clone(), 19),
                (select.clone(), 19),
                (mem_const.clone(), 17),
                (batch_fri.clone(), 19),
                (base_alu.clone(), 16),
                (ext_alu.clone(), 16),
                (exp_reverse_bits_len.clone(), 18),
                (poseidon2_wide.clone(), 17),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            [
                (mem_var.clone(), 20),
                (select.clone(), 20),
                (mem_const.clone(), 18),
                (batch_fri.clone(), 21),
                (base_alu.clone(), 16),
                (ext_alu.clone(), 19),
                (exp_reverse_bits_len.clone(), 18),
                (poseidon2_wide.clone(), 18),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            // Basefold normalize-sized shape.  The basefold normalize
            // program produces ~660K instructions with chip heights:
            // MemoryConst≈33842, MemoryVar≈11253, BaseAlu≈74980,
            // ExtAlu≈70969, Poseidon2WideDeg3≈2012,
            // ExpReverseBitsLen≈24, PublicValues≈4.  Powers-of-two
            // log_heights with headroom: BaseAlu/ExtAlu→17,
            // MemoryConst→16, MemoryVar→14 (rounded up to legacy
            // minimum of 18 to share with smaller shapes).  This entry
            // lets `fix_shape` succeed for basefold programs once
            // task #51 / #59 enable that path; today the basefold
            // builder skips fix_shape entirely.
            [
                (mem_var.clone(), 18),
                (select.clone(), 18),
                (mem_const.clone(), 17),
                (batch_fri.clone(), 21),
                (base_alu.clone(), 18),
                (ext_alu.clone(), 18),
                (exp_reverse_bits_len.clone(), 18),
                (poseidon2_wide.clone(), 18),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            // Bundle-lift compose level h=0 (#256). Sized to fit observed
            // tendermint h=0 panic heights (MemoryConst=149K log≈18,
            // Select=158K log≈18, BaseAlu=91K log≈17, ExtAlu=94K log≈17).
            // No headroom on binding dimensions — each +1 cap doubles
            // trace area which propagates through compose prove cost.
            // If a workload panics shape.rs:91 here, ratchet up the
            // specific offender rather than padding all of them.
            [
                (mem_var.clone(), 18),
                (select.clone(), 18),
                (mem_const.clone(), 18),
                (batch_fri.clone(), 21),
                (base_alu.clone(), 17),
                (ext_alu.clone(), 17),
                (exp_reverse_bits_len.clone(), 18),
                (poseidon2_wide.clone(), 18),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            // Bundle-lift compose level h=1+ (#256). Sized to fit observed
            // tendermint h=1 panic heights (MemoryConst=376K log≈19,
            // Select=316K log≈19, ExtAlu=307K log≈19, BaseAlu=183K
            // log≈18). Same no-headroom rationale as h=0; ratchet specific
            // offenders if a deeper-tree workload panics here.
            [
                (mem_var.clone(), 19),
                (select.clone(), 19),
                (mem_const.clone(), 19),
                (batch_fri.clone(), 21),
                (base_alu.clone(), 18),
                (ext_alu.clone(), 19),
                (exp_reverse_bits_len.clone(), 18),
                (poseidon2_wide.clone(), 18),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
        ]
        .map(HashMap::from)
        .to_vec();
        Self { allowed_shapes, _marker: PhantomData }
    }
}

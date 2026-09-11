use std::collections::BTreeMap;
use std::marker::PhantomData;

use hashbrown::HashMap;

use itertools::Itertools;
use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use serde::{Deserialize, Serialize};
use zkm_pcs::{air::MachineAir, shape::OrderedShape};

use crate::{
    chips::{
        alu_base::BaseAluChip,
        alu_ext::ExtAluChip,
        ext2felt::Ext2FeltChip,
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
    /// The pin class the program commits under
    /// (`zkm_pcs::jagged::RECURSION_PIN_CLASSES`), settled with the rows by
    /// `RecursionShapeConfig::fix_shape_kind`; `None` = the machine's default.
    #[serde(default)]
    pub pins: Option<zkm_pcs::jagged::RecursionPins>,
}

impl RecursionShape {
    pub fn clone_into_hash_map(&self) -> HashMap<String, usize> {
        self.inner.iter().map(|(k, v)| (k.clone(), *v)).collect()
    }
}

impl From<HashMap<String, usize>> for RecursionShape {
    fn from(value: HashMap<String, usize>) -> Self {
        Self { inner: value.into_iter().collect(), pins: None }
    }
}

impl From<BTreeMap<String, usize>> for RecursionShape {
    fn from(value: BTreeMap<String, usize>) -> Self {
        Self { inner: value, pins: None }
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
        self.fix_shape_kind(program, "unknown");
    }

    /// [`Self::fix_shape`], told which recursion stage is asking: the ROOT
    /// (`compose-root`) always takes the largest pin class; every other kind
    /// only labels the diagnostic line.
    pub fn fix_shape_kind(&self, program: &mut RecursionProgram<F>, kind: &str) {
        let heights = RecursionAir::<F, DEGREE>::heights(program);
        let shape = Self::organic_shape(&heights);
        // The pin class: the smallest both rounds fit — except the ROOT
        // (`compose-root`), which always takes the largest so the shrink
        // program, and through it the wrap circuit, sees one root geometry.
        let own = Self::class_for_rows(&shape).unwrap_or_else(|| {
            panic!("recursion {kind} program: its rows fit no pin class: {shape:?}")
        });
        let class =
            if kind == "compose-root" { zkm_pcs::jagged::RecursionPins::LAST_CLASS } else { own };
        if std::env::var("ZIREN_FIXSHAPE_DIAG").is_ok() {
            let (mw, pw) = Self::round_widths();
            let cells: u128 = shape
                .iter()
                .map(|(n, r)| {
                    ((mw.get(n).copied().unwrap_or(0) + pw.get(n).copied().unwrap_or(0)) as u128)
                        * (*r as u128)
                })
                .sum();
            let mut organic: Vec<(String, usize)> =
                heights.iter().map(|(n, h)| (n.clone(), *h)).collect();
            organic.sort();
            let rows: Vec<(String, usize)> = shape.iter().map(|(n, r)| (n.clone(), *r)).collect();
            eprintln!("FIXSHAPE kind={kind} band_index={class} cells={cells} organic={organic:?} -> band={rows:?}");
        }
        *program.shape_mut() = Some(RecursionShape {
            inner: shape,
            pins: Some(zkm_pcs::jagged::RecursionPins::class(class)),
        });
    }

    /// The per-chip MAIN and PREPROCESSED widths of the recursion machine.
    fn round_widths() -> (BTreeMap<String, usize>, BTreeMap<String, usize>) {
        let airs = [
            RecursionAir::<F, DEGREE>::MemoryConst(MemoryConstChip::default()),
            RecursionAir::<F, DEGREE>::MemoryVar(MemoryVarChip::default()),
            RecursionAir::<F, DEGREE>::BaseAlu(BaseAluChip),
            RecursionAir::<F, DEGREE>::ExtAlu(ExtAluChip),
            RecursionAir::<F, DEGREE>::Poseidon2Wide(Poseidon2WideChip::<DEGREE>),
            RecursionAir::<F, DEGREE>::Select(SelectChip),
            RecursionAir::<F, DEGREE>::Ext2Felt(Ext2FeltChip::default()),
            RecursionAir::<F, DEGREE>::PublicValues(PublicValuesChip),
        ];
        let main = airs.iter().map(|a| (a.name(), p3_air::BaseAir::<F>::width(a))).collect();
        let prep =
            airs.iter().map(|a| (a.name(), MachineAir::<F>::preprocessed_width(a))).collect();
        (main, prep)
    }

    /// The pin class a program with these ROW counts commits under: the
    /// smallest whose pins hold both rounds' stacking-rounded areas
    /// (`zkm_pcs::jagged::RecursionPins::class_for_committed`).  Mirrors
    /// `StarkMachine::pins_for_rows`.
    pub fn class_for_rows(rows: &BTreeMap<String, usize>) -> Option<usize> {
        let (mw, pw) = Self::round_widths();
        let log_stack = zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize;
        let main: usize = rows.iter().map(|(n, r)| r * mw.get(n).copied().unwrap_or(0)).sum();
        let prep: usize = rows.iter().map(|(n, r)| r * pw.get(n).copied().unwrap_or(0)).sum();
        zkm_pcs::jagged::RecursionPins::class_for_committed(
            zkm_pcs::jagged::committed_dense_len(main, log_stack),
            zkm_pcs::jagged::committed_dense_len(prep, log_stack),
        )
    }

    /// THE shape of a recursion program: its own heights, each rounded up to
    /// a multiple of 32 (`next_multiple_of_32_rows`), the public-values chip
    /// at its fixed `2^PUB_VALUES_LOG_HEIGHT` rows.  Nothing is padded to a
    /// common shape: every leaf, compose and deferred proof commits under a
    /// pin class (`zkm_pcs::jagged::RECURSION_PIN_CLASSES`, the smallest its
    /// rows fit), so the program verifying it reads the class's geometry, not
    /// these rows, and the padding a common shape proved (a median leaf filled
    /// 28% of the single shape) is gone.  The row cube
    /// (`2^max_log_row_count`) is the only cap; a program past it cannot be
    /// proved at all.
    pub fn organic_shape(heights: &[(String, usize)]) -> BTreeMap<String, usize> {
        let public_values = RecursionAir::<F, DEGREE>::PublicValues(PublicValuesChip).name();
        let cube = 1usize
            << zkm_pcs::shard_level::verifier::BasefoldShardVerifier::production_default()
                .max_log_row_count;
        heights
            .iter()
            .map(|(name, height)| {
                let rows = if *name == public_values {
                    1 << PUB_VALUES_LOG_HEIGHT
                } else {
                    height.max(&1).next_multiple_of(32)
                };
                assert!(
                    rows <= cube,
                    "recursion chip {name} needs {rows} rows, past the row cube {cube}",
                );
                (name.clone(), rows)
            })
            .collect()
    }

    /// A shape as the [`OrderedShape`] the enumeration and the dummy-proof
    /// path consume.  For RECURSION shapes an `OrderedShape` carries exact
    /// ROW counts (`dummy_basefold_vk_and_shard_proof_rows`), so this is the
    /// identity on the values — the shape is not a power of two and must not
    /// be rounded to one.
    pub fn as_ordered_shape(shape: &HashMap<String, usize>) -> OrderedShape {
        shape.iter().map(|(name, rows)| (name.clone(), *rows)).collect()
    }

    pub fn get_all_shape_combinations(
        &self,
        batch_size: usize,
    ) -> impl Iterator<Item = Vec<OrderedShape>> + '_ {
        (0..batch_size)
            .map(|_| self.allowed_shapes.iter().map(Self::as_ordered_shape))
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
        // "Extra room" on a ROW count is multiplicative, not `+= 2`: the map
        // used to hold log2 heights, where `+= 2` meant 4x.  Keep that headroom.
        map.values_mut().for_each(|x| *x = (*x * 4).next_multiple_of(32));
        map.insert("PublicValues".to_string(), 1 << PUB_VALUES_LOG_HEIGHT);
        Self { allowed_shapes: vec![map], _marker: PhantomData }
    }

    pub fn from_hash_map(hash_map: &HashMap<String, usize>) -> Self {
        Self { allowed_shapes: vec![hash_map.clone()], _marker: PhantomData }
    }

    pub fn first(&self) -> Option<&HashMap<String, usize>> {
        self.allowed_shapes.first()
    }

    /// One DUMMY shape per pin class, in class order: the rows a dummy child
    /// of that class is built at (`ZKMProofShape::generate`, the compose
    /// pre-warm).  The program verifying such a child reads the class's
    /// pinned geometry, so these rows only have to LAND in the class.
    pub fn all_shapes(&self) -> &[HashMap<String, usize>] {
        &self.allowed_shapes
    }

    /// The pin class a program with these heights takes (its index into
    /// [`Self::all_shapes`]): the choice [`Self::fix_shape_kind`] makes for a
    /// non-root program, exposed so a caller can learn it without committing
    /// to it.  Kept under its historical name for the pipeline's band API.
    pub fn band_index_for(&self, heights: &[(String, usize)]) -> Option<usize> {
        Self::class_for_rows(&Self::organic_shape(heights))
    }

    /// The class that holds every class in `indices`: classes form a chain,
    /// so it is the largest.  The pipeline settles a sibling group on it and
    /// keys the group's programs by it (`ZKMProver::band_keyed`).
    pub fn dominating_band_index(&self, indices: &[usize]) -> Option<usize> {
        // Pin classes form a chain: the largest dominates.
        let best = indices.iter().copied().max()?;
        (best < self.allowed_shapes.len()).then_some(best)
    }

    /// [`Self::fix_shape_kind`] for a caller that settled a sibling-group
    /// class: a node's OWN class is a function of its rows (its siblings'
    /// classes are covered by the parent's class-tuple programs), so `index`
    /// is only validated, not applied.
    pub fn fix_shape_at(&self, program: &mut RecursionProgram<F>, index: usize) {
        // Bands are gone: a program is always proved at its own rows
        // (`organic_shape`); the index is the caller's settled band, kept for
        // API compatibility with the multi-GPU pipeline's group settling.
        assert!(index < self.allowed_shapes.len(), "recursion pin class {index} does not exist");
        self.fix_shape_kind(program, "forced");
    }

    /// The organic heights of a built program, for [`Self::band_index_for`].
    pub fn program_heights(program: &RecursionProgram<F>) -> Vec<(String, usize)> {
        RecursionAir::<F, DEGREE>::heights(program)
            .iter()
            .map(|(n, h)| (n.clone(), *h))
            .collect()
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
        let select = RecursionAir::<F, DEGREE>::Select(SelectChip).name();
        let public_values = RecursionAir::<F, DEGREE>::PublicValues(PublicValuesChip).name();
        let ext2felt = RecursionAir::<F, DEGREE>::Ext2Felt(Ext2FeltChip::default()).name();

        // One DUMMY shape per pin class (`zkm_pcs::jagged::RECURSION_PIN_CLASSES`),
        // smallest class first.  ROW COUNTS, exact (a chip is padded to the
        // number written here, `next_multiple_of_32_rows`), nothing a power of
        // two.  A real node is proved at its OWN rows and commits under the
        // smallest class both of its rounds fit; a dummy child stands in for
        // such a node when a compose program is built ahead of it
        // (`ZKMProofShape::generate`, the pre-warm), and the program reads
        // the class's pinned geometry rather than these rows, so all a dummy
        // shape has to do is land in its class — asserted below.
        //
        // Class 1 is the single shape that replaced the bands (SP1 style,
        // sized from 1,020 production nodes on Sep 11: per-chip maxima
        // MemoryVar 248,877 / Select 140,960 / Poseidon2 66,236 set by the
        // arity-4 compose, BaseAlu 452,760 / ExtAlu 578,441 / Ext2Felt 61,166
        // by a leaf verifying the largest core shard); it commits both rounds
        // at 2^26.  Class 0 is its half, landing both rounds at 2^25.  The
        // SHRINK shape is separate: FROZEN in `zkm_prover::ZKMProver::shrink_shape`.
        let rows = |n: usize| -> usize {
            assert!(n % 32 == 0, "recursion shape rows must be a multiple of 32: {n}");
            n
        };
        // One entry per PIN CLASS (`zkm_pcs::jagged::RECURSION_PIN_CLASSES`),
        // smallest first: the rows a DUMMY child of that class is built at
        // (the program verifying it reads the class's pinned geometry, not
        // these rows).  Class 1 is the single shape above; class 0 is its
        // half, which lands both rounds at 2^25.
        let allowed_shapes = vec![
            HashMap::from([
                (mem_var.clone(), rows(131_072)),
                (select.clone(), rows(73_728)),
                (mem_const.clone(), rows(2_048)),
                (base_alu.clone(), rows(253_536)),
                (ext_alu.clone(), rows(323_936)),
                (poseidon2_wide.clone(), rows(34_816)),
                (ext2felt.clone(), rows(34_272)),
                (public_values.clone(), 1 << PUB_VALUES_LOG_HEIGHT),
            ]),
            HashMap::from([
                (mem_var.clone(), rows(262_144)),
                (select.clone(), rows(147_456)),
                (mem_const.clone(), rows(4_096)),
                (base_alu.clone(), rows(507_072)),
                (ext_alu.clone(), rows(647_872)),
                (poseidon2_wide.clone(), rows(69_632)),
                (ext2felt.clone(), rows(68_512)),
                (public_values.clone(), 1 << PUB_VALUES_LOG_HEIGHT),
            ]),
        ];
        assert_eq!(allowed_shapes.len(), zkm_pcs::jagged::RECURSION_PIN_CLASSES.len());
        for (index, shape) in allowed_shapes.iter().enumerate() {
            let rows: BTreeMap<String, usize> =
                shape.iter().map(|(n, r)| (n.clone(), *r)).collect();
            assert_eq!(
                Self::class_for_rows(&rows),
                Some(index),
                "the class-{index} dummy shape must land in class {index}",
            );
        }
        // No dummy shape may exceed the row cube every recursion stage proves
        // at: `PaddedMle::padded` asserts the padded rows fit `2^cube`.
        let cube = zkm_pcs::shard_level::verifier::BasefoldShardVerifier::production_default()
            .max_log_row_count;
        for shape in allowed_shapes.iter() {
            for (name, rows) in shape.iter() {
                assert!(
                    *rows <= (1 << cube),
                    "recursion dummy shape {name} = {rows} rows exceeds the row cube 2^{cube}",
                );
            }
        }
        Self { allowed_shapes, _marker: PhantomData }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_koala_bear::KoalaBear;
    use zkm_pcs::jagged::{RecursionPins, RECURSION_PIN_CLASSES};

    type Cfg = RecursionShapeConfig<KoalaBear, RecursionAir<KoalaBear, 3>>;

    #[test]
    fn dummy_shapes_land_in_their_class_and_the_root_takes_the_last() {
        let cfg = Cfg::default();
        assert_eq!(cfg.all_shapes().len(), RECURSION_PIN_CLASSES.len());
        for (index, shape) in cfg.all_shapes().iter().enumerate() {
            let rows: BTreeMap<String, usize> =
                shape.iter().map(|(n, r)| (n.clone(), *r)).collect();
            assert_eq!(Cfg::class_for_rows(&rows), Some(index));
            let heights: Vec<(String, usize)> = rows.iter().map(|(n, r)| (n.clone(), *r)).collect();
            assert_eq!(cfg.band_index_for(&heights), Some(index));
        }
        assert_eq!(cfg.dominating_band_index(&[0, 1, 0]), Some(1));
        assert_eq!(cfg.dominating_band_index(&[0]), Some(0));
        assert_eq!(cfg.dominating_band_index(&[7]), None);
        assert_eq!(RecursionPins::LAST_CLASS, RECURSION_PIN_CLASSES.len() - 1);
    }

    #[test]
    fn organic_rows_are_multiples_of_32_with_fixed_public_values() {
        let pv = RecursionAir::<KoalaBear, 3>::PublicValues(PublicValuesChip).name();
        let heights = vec![
            ("ExtAlu".to_string(), 33usize),
            (pv.clone(), 1usize),
            ("Select".to_string(), 0usize),
        ];
        let rows = Cfg::organic_shape(&heights);
        assert_eq!(rows["ExtAlu"], 64);
        assert_eq!(rows["Select"], 32);
        assert_eq!(rows[&pv], 1 << PUB_VALUES_LOG_HEIGHT);
        // A few rows of every chip is a class-0 program.
        assert_eq!(Cfg::class_for_rows(&rows), Some(0));
    }
}

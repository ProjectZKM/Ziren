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
    /// Per-chip COMMITTED width: the main trace width plus the preprocessed
    /// one, because a recursion proof commits both rounds and a band pads
    /// both to the same per-chip height.  The spread is wide —
    /// `Poseidon2WideDeg3` is 362 cells/row against `MemoryConst`'s 13 — so a
    /// band's cost is nothing like its row count, and picking a band by rows
    /// (or by list position) systematically over-pays on the wide chips.
    fn committed_widths() -> BTreeMap<String, usize> {
        [
            RecursionAir::<F, DEGREE>::MemoryConst(MemoryConstChip::default()),
            RecursionAir::<F, DEGREE>::MemoryVar(MemoryVarChip::default()),
            RecursionAir::<F, DEGREE>::BaseAlu(BaseAluChip),
            RecursionAir::<F, DEGREE>::ExtAlu(ExtAluChip),
            RecursionAir::<F, DEGREE>::Poseidon2Wide(Poseidon2WideChip::<DEGREE>),
            RecursionAir::<F, DEGREE>::Select(SelectChip),
            RecursionAir::<F, DEGREE>::Ext2Felt(Ext2FeltChip::default()),
            RecursionAir::<F, DEGREE>::PublicValues(PublicValuesChip),
        ]
        .into_iter()
        .map(|air| {
            let width =
                p3_air::BaseAir::<F>::width(&air) + MachineAir::<F>::preprocessed_width(&air);
            (air.name(), width)
        })
        .collect()
    }

    /// The cells a program pays if it is snapped onto `shape`: Σ over chips of
    /// committed width × padded height.  This is what every device buffer
    /// downstream is sized from (the jagged commit's dense length, and through
    /// it the sumcheck tables), so it is the right thing to minimize.
    fn band_cells(shape: &HashMap<String, usize>, widths: &BTreeMap<String, usize>) -> u128 {
        shape
            .iter()
            .map(|(name, rows)| (widths.get(name).copied().unwrap_or(1) as u128) * (*rows as u128))
            .sum()
    }

    pub fn fix_shape(&self, program: &mut RecursionProgram<F>) {
        self.fix_shape_kind(program, "unknown");
    }

    /// [`Self::fix_shape`], told which recursion stage is asking.
    ///
    /// The kind is what makes the choice legible: a compose node's children all
    /// come from one stage, so whether those children share a band is a
    /// property of that stage's band selection, not of any one program.
    pub fn fix_shape_kind(&self, program: &mut RecursionProgram<F>, kind: &str) {
        let heights = RecursionAir::<F, DEGREE>::heights(program);
        let shape = Self::organic_shape(&heights);
        if std::env::var("ZIREN_FIXSHAPE_DIAG").is_ok() {
            let widths = Self::committed_widths();
            let cells: u128 = shape
                .iter()
                .map(|(n, r)| (widths.get(n).copied().unwrap_or(1) as u128) * (*r as u128))
                .sum();
            let mut organic: Vec<(String, usize)> =
                heights.iter().map(|(n, h)| (n.clone(), *h)).collect();
            organic.sort();
            let rows: Vec<(String, usize)> = shape.iter().map(|(n, r)| (n.clone(), *r)).collect();
            eprintln!("FIXSHAPE kind={kind} band_index=0 cells={cells} organic={organic:?} -> band={rows:?}");
        }
        *program.shape_mut() = Some(RecursionShape { inner: shape });
    }

    /// THE shape of a recursion program: its own heights, each rounded up to
    /// a multiple of 32 (`next_multiple_of_32_rows`), the public-values chip
    /// at its fixed `2^PUB_VALUES_LOG_HEIGHT` rows.  Nothing is snapped to a
    /// band: every leaf, compose and deferred proof commits under the
    /// compress machine's area pins (`zkm_pcs::jagged::RECURSION_PINS`), so
    /// the program verifying it does not read these rows, and the padding the
    /// old bands proved (a median leaf filled 28% of the single shape) is
    /// gone.  The row cube (`2^max_log_row_count`) is the only cap; a program
    /// past it cannot be proved at all.
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

    /// Every band a program can be snapped onto.
    pub fn all_shapes(&self) -> &[HashMap<String, usize>] {
        &self.allowed_shapes
    }

    /// The cheapest band a program with these heights fits, by index into
    /// [`Self::all_shapes`].  This is the choice [`Self::fix_shape_kind`] makes
    /// on its own; exposed so a caller can learn it WITHOUT committing to it.
    pub fn band_index_for(&self, heights: &[(String, usize)]) -> Option<usize> {
        let widths = Self::committed_widths();
        let mut best: Option<(usize, u128)> = None;
        for (index, shape) in self.allowed_shapes.iter().enumerate() {
            let fits =
                heights.iter().all(|(name, height)| *height <= shape.get(name).copied().unwrap_or(0));
            if !fits {
                continue;
            }
            let cells = Self::band_cells(shape, &widths);
            if best.map_or(true, |(_, c)| cells < c) {
                best = Some((index, cells));
            }
        }
        best.map(|(i, _)| i)
    }

    /// The cheapest band that DOMINATES every band in `indices` — one whose
    /// per-chip caps are at least as tall as all of theirs.
    ///
    /// A compose program is traced over its children's proof shapes, so its
    /// verifying key is enumerable only when those shapes agree.  Snapping a
    /// node's children onto a common band is what makes them agree, and this
    /// picks the cheapest band that can hold all of them.  Bands do not form a
    /// chain, so this is a search, not a maximum: the answer need not be any of
    /// the inputs, and may not exist.
    pub fn dominating_band_index(&self, indices: &[usize]) -> Option<usize> {
        let widths = Self::committed_widths();
        let mut required: HashMap<String, usize> = HashMap::new();
        for i in indices {
            for (name, rows) in self.allowed_shapes.get(*i)?.iter() {
                let slot = required.entry(name.clone()).or_insert(0);
                *slot = (*slot).max(*rows);
            }
        }
        let mut best: Option<(usize, u128)> = None;
        for (index, shape) in self.allowed_shapes.iter().enumerate() {
            let covers = required
                .iter()
                .all(|(name, need)| shape.get(name).copied().unwrap_or(0) >= *need);
            if !covers {
                continue;
            }
            let cells = Self::band_cells(shape, &widths);
            if best.map_or(true, |(_, c)| cells < c) {
                best = Some((index, cells));
            }
        }
        best.map(|(i, _)| i)
    }

    /// Snap `program` onto band `index` regardless of what it would have chosen
    /// for itself — the caller has a reason the program cannot see.
    pub fn fix_shape_at(&self, program: &mut RecursionProgram<F>, index: usize) {
        // Bands are gone: a program is always proved at its own rows
        // (`organic_shape`); the index is the caller's settled band, kept for
        // API compatibility with the multi-GPU pipeline's group settling.
        assert!(index < self.allowed_shapes.len(), "recursion band {index} does not exist");
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

        // THE recursion shape — one, not a list of bands.  ROW COUNTS: a
        // chip is padded to exactly the number written here
        // (`next_multiple_of_32_rows`), and nothing below is a power of two.
        //
        // SP1 pads every recursion proof to a single shape
        // (`crates/prover/compress_shape.json`, rows rounded to a multiple of
        // 32), and that is what makes a compose program a function of its
        // ARITY alone: `get_all_shape_combinations` yields one combination per
        // batch size, so the enumeration emits `Compose(1..=REDUCE_BATCH_SIZE)`
        // + Deferred + Shrink, every sibling group is homogeneous by
        // construction, and the pre-warm builds a handful of programs instead
        // of one per band tuple.  (Five bands, Sep 10-11: leaf card time -35%
        // but the compose keys went 2-3 -> 21-45 per block because sibling
        // groups mixed bands, and the wall did not move.)
        //
        // SIZED FROM ORGANIC HEIGHTS, the way SP1 builds its shape: 1,020
        // production recursion nodes (reth, 8 cards, `ZIREN_FIXSHAPE_DIAG=1`,
        // Sep 11) give per-chip maxima — rows are events / entries-per-row —
        //
        //   chip                max      p99      p50   who sets the max
        //   MemoryVar       248,877  248,877  110,247   the arity-4 compose
        //   Select          140,960  140,960   35,144   the arity-4 compose
        //   Poseidon2       66,236    66,236   24,467   the arity-4 compose
        //   BaseAlu         452,760  438,253  109,714   a leaf (core verify)
        //   ExtAlu          578,441  566,378  170,828   a leaf (core verify)
        //   Ext2Felt        61,166    61,149   16,947   a leaf (core verify)
        //   MemoryConst        226      226      136   constants
        //
        // The compose programs are deterministic in the shape (p99 == max),
        // so their rows carry ~5% and are re-checked by the fixed-point probe
        // (`zkm_prover::tests::single_shape_fixed_point`: build the compose
        // and deferred programs at arities 1..=4 against THIS shape and
        // assert they fit).  Leaf heights vary with the core shard's committed
        // structure, and the largest core shards are area-capped, so the
        // observed maxima are near the ceiling; they carry ~12%.  Against the
        // old power-of-two band (ExtAlu 2^20, BaseAlu/MemoryVar/Select 2^19,
        // Poseidon2/Ext2Felt 2^17: 183,816,368 committed cells) this is the
        // cells the survey's p50 program actually needs, roughly halved.
        //
        // ⚠ If a program overflows a cap, `fix_shape` panics
        // (`no shape found`).  RAISE THE CAP and regenerate the vk_map — do
        // not restore a band list.  The SHRINK shape is unaffected: it is
        // FROZEN in `zkm_prover::ZKMProver::shrink_shape`.
        let rows = |n: usize| -> usize {
            assert!(n % 32 == 0, "recursion shape rows must be a multiple of 32: {n}");
            n
        };
        let allowed_shapes = vec![HashMap::from([
            (mem_var.clone(), rows(262_144)),
            (select.clone(), rows(147_456)),
            (mem_const.clone(), rows(4_096)),
            (base_alu.clone(), rows(507_072)),
            (ext_alu.clone(), rows(647_872)),
            (poseidon2_wide.clone(), rows(69_632)),
            (ext2felt.clone(), rows(68_512)),
            (public_values.clone(), 1 << PUB_VALUES_LOG_HEIGHT),
        ])];
        // No band may exceed the row cube every recursion stage proves at:
        // `PaddedMle::padded` asserts the padded rows fit `2^cube`, so a taller
        // band is a shape nothing can be snapped onto.
        let cube = zkm_pcs::shard_level::verifier::BasefoldShardVerifier::production_default()
            .max_log_row_count;
        for shape in allowed_shapes.iter() {
            for (name, rows) in shape.iter() {
                assert!(
                    *rows <= (1 << cube),
                    "recursion band {name} = {rows} rows exceeds the row cube 2^{cube}",
                );
            }
        }
        Self { allowed_shapes, _marker: PhantomData }
    }
}

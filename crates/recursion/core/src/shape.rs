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
        let widths = Self::committed_widths();

        // Snap onto the CHEAPEST band that fits, not the first one listed.
        //
        // Bands are per-chip caps and a program's organic heights are wildly
        // uneven, so the bands do not form a chain: the list holds several
        // incomparable profiles (ALU-heavy compose levels, Select-heavy
        // bundle-lift levels) and there is no ordering under which "first that
        // fits" is also "smallest that fits".  Taking the first match made the
        // list position load-bearing — every band carried a comment pleading
        // for it to be placed before or after some other one — and still lost:
        // a reth compose level whose ExtAlu was 0.5% over 2^21 fell through to
        // the row-cube band and padded its committed area 2.2×, which is the
        // whole of that stage's device working set.  Scoring every fitting
        // band and keeping the cheapest makes list order cosmetic, so a new
        // tightly-fitting band can only ever help.
        let mut closest_shape: Option<&HashMap<String, usize>> = None;
        let mut closest_cells = u128::MAX;
        let mut closest_index = usize::MAX;

        for (index, shape) in self.allowed_shapes.iter().enumerate() {
            // If any of the heights is greater than the shape, continue.
            let fits = heights.iter().all(|(name, height)| *height <= *shape.get(name).unwrap());
            if !fits {
                continue;
            }

            let cells = Self::band_cells(shape, &widths);
            if cells < closest_cells {
                closest_cells = cells;
                closest_shape = Some(shape);
                closest_index = index;
            }
        }

        if let Some(shape) = closest_shape {
            if std::env::var("ZIREN_FIXSHAPE_DIAG").is_ok() {
                let mut organic: Vec<(String, usize)> =
                    heights.iter().map(|(n, h)| (n.clone(), *h)).collect();
                organic.sort();
                let mut band: Vec<(String, usize)> =
                    shape.iter().map(|(n, h)| (n.clone(), *h)).collect();
                band.sort();
                eprintln!(
                    "FIXSHAPE kind={kind} band_index={closest_index} cells={closest_cells} \
organic={organic:?} -> band={band:?}"
                );
            }
            let shape = RecursionShape { inner: shape.clone().into_iter().collect() };
            *program.shape_mut() = Some(shape);
        } else {
            panic!("no shape found for heights: {heights:?}");
        }
    }

    /// A shape's per-chip ROW counts as the log2 heights an [`OrderedShape`]
    /// speaks.
    ///
    /// The enumeration and dummy-proof path (`OrderedShape`, and the
    /// `(String, u8)` pairs `dummy/basefold_shard_proof.rs` takes) is still
    /// written in log2 heights, so the row counts a shape now carries are
    /// bridged here.  It is exact for the power-of-two shapes shipped today;
    /// teaching that path exact rows is what a single tight shape needs, and is
    /// the next step of the port.
    pub fn as_log2_ordered_shape(shape: &HashMap<String, usize>) -> OrderedShape {
        shape.iter().map(|(name, rows)| (name.clone(), rows.next_power_of_two().ilog2() as usize))
            .collect()
    }

    pub fn get_all_shape_combinations(
        &self,
        batch_size: usize,
    ) -> impl Iterator<Item = Vec<OrderedShape>> + '_ {
        (0..batch_size)
            .map(|_| self.allowed_shapes.iter().map(Self::as_log2_ordered_shape))
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
        let shape = self
            .allowed_shapes
            .get(index)
            .unwrap_or_else(|| panic!("recursion band {index} does not exist"));
        let heights = RecursionAir::<F, DEGREE>::heights(program);
        for (name, height) in heights.iter() {
            let cap = shape.get(name).copied().unwrap_or(0);
            assert!(
                *height <= cap,
                "recursion band {index} caps {name} at {cap} rows but the program needs {height}",
            );
        }
        // Same diagnostic as `fix_shape_kind` — a forced snap was previously
        // invisible, which hid the organic heights of every leaf (leaves are
        // always band-forced for sibling agreement).
        if std::env::var("ZIREN_FIXSHAPE_DIAG").is_ok() {
            let widths = Self::committed_widths();
            let cells = Self::band_cells(shape, &widths);
            let mut organic: Vec<(String, usize)> =
                heights.iter().map(|(n, h)| (n.clone(), *h)).collect();
            organic.sort();
            let mut band: Vec<(String, usize)> =
                shape.iter().map(|(n, h)| (n.clone(), *h)).collect();
            band.sort();
            eprintln!(
                "FIXSHAPE kind=forced band_index={index} cells={cells} \
organic={organic:?} -> band={band:?}"
            );
        }
        *program.shape_mut() = Some(RecursionShape { inner: shape.clone().into_iter().collect() });
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

        // Specify allowed shapes.
        //
        // ⚠ These are ROW COUNTS, not log2 heights — the `1 << n` spellings keep
        // the retune history below readable, but a chip is now padded to exactly
        // the number written here (`next_multiple_of_32_rows`).  Powers of two
        // are what the bands happened to be; nothing requires it any more, which
        // is the whole point: a single shape tight enough for every program is
        // what makes a compose program a function of its ARITY alone (SP1's
        // `Compose(arity)`), and that is what lets adjacent ranges merge at any
        // depth instead of behind a per-layer barrier.
        //
        // ORDER IS COSMETIC.  `fix_shape` scores every band a program fits and
        // keeps the cheapest by committed cells, so a band never has to be
        // positioned to win or lose a match; the list is kept roughly
        // ascending only to read well.
        //
        // A band costs the compress vk enumeration exactly SIX shapes —
        // `ZKMProofShape::generate` builds compose children by replicating ONE
        // band across the batch (`vec![band; arity]`), so it emits arity
        // 1..=`REDUCE_BATCH_SIZE` plus one Deferred and one Shrink per band,
        // and nothing cartesian.
        //
        // ⚠ BUT THE BUDGET IS NOT THE BANDS' TO SPEND.  The normalize shapes
        // dominate the map and their count is driven by `MAX_BLOCKS` in
        // `zkm_prover::shapes`, which is derived from `ELEMENT_THRESHOLD` — so
        // raising the shard-area cap consumes vk-merkle capacity.  Measured
        // (`zkm_prover::tests::enumeration_size_probe`): at the 260,000,000
        // threshold the map was 2651 of 4096; at 500,000,000 it is **3922 of
        // 4096**.  That leaves ~174 shapes = room for about **29 more bands**,
        // not the ~240 the earlier figure implied.  Anything that raises
        // `ELEMENT_THRESHOLD` or adds bands must re-run that test — it is the
        // only guard, and the map is now at 96% of a capacity that cannot be
        // tuned (the tree height is baked into every enumerated program).
        // Aug26 RETUNE (reth diag, `ZIREN_FIXSHAPE_DIAG=1`, forced+chosen
        // maxima over 101 distinct programs after the Ext2Felt chip landed):
        //   - MemoryConst is 12 on every non-cube band: the constant cache
        //     collapsed the pool to ~280 distinct writes (observed organic max
        //     213), and the old 2^19 cap was 6.7M cells of pure padding per
        //     program.  The 2^19s in the older comments below predate the
        //     cache.
        //   - Band 0's Poseidon2WideDeg3 drops to 17: leaf max 67,177 and
        //     compose max 68,686 fit 2^17 at ~1.9x, and at 362 committed
        //     cells/row the old 2^18 cap was 63% of the whole band.
        //   - Ext2Felt is 16 on the bands reth was observed on (0/2/6, max
        //     42,548) and stays 17 elsewhere (deferred programs on band 7
        //     measured 68,288).
        // A program that stops fitting a lowered cap falls to the next
        // cheapest band that fits — the fits-check keeps this safe; only the
        // padding economics change.  The SHRINK shape is unaffected: it is
        // FROZEN in `zkm_prover::ZKMProver::shrink_shape`, decoupled from
        // these tables.
        // THE recursion shape — one, not a list of bands.
        //
        // SP1 pads every recursion proof to a single shape
        // (`crates/prover/compress_shape.json`), and that is what makes a
        // compose program a function of its ARITY alone:
        // `get_all_shape_combinations` yields exactly one combination per batch
        // size, so the enumeration emits `Compose(1..=REDUCE_BATCH_SIZE)` +
        // Deferred + Shrink — the same set SP1 enumerates. A tree whose nodes
        // share one program per arity can merge adjacent proof RANGES at any
        // depth, instead of draining one layer before starting the next.
        //
        // WHICH shape is decided by a FIXED POINT, and it is measured, not
        // argued: a compose program is traced over its children, so raising the
        // shape raises the organic heights of the program that verifies it.
        // The shape has to hold still under one round of that.
        // `ZIREN_FIXSHAPE_DIAG=1` on the pre-warm (9 bands x arities 1..=4)
        // gives both sides:
        //
        //   children at the old band 0 (MemoryVar 2^18) -> arity-4 compose
        //     needs MemoryVar 321_545 and Select 488_448.  NOT a fixed point:
        //     measured by trying it, `no shape found for heights` at
        //     `fix_shape` on the first arity-4 pre-warm pair.
        //   children at the shape below      -> arity-4 compose needs
        //     MemoryVar 447_323 · Select 488_448 · ExtAlu 295_245 ·
        //     BaseAlu 282_019 · Poseidon2WideDeg3 116_424 · Ext2Felt 42_548 ·
        //     MemoryConst 213.  All fit.  FIXED POINT.
        //
        // It costs 134_926_512 committed cells against band 0's 95_080_624 —
        // but it is the ONLY self-consistent single shape among the nine, and
        // it replaces all of them, including the 2^22 row-cube band at ~4x.
        //
        // ⚠ Every cap here is a power of two only because the dummy-proof path
        // (`OrderedShape`, and the `(String, u8)` pairs
        // `dummy/basefold_shard_proof.rs` takes) still speaks log2 heights, so
        // `as_log2_ordered_shape` has to be exact.  The organic maxima above
        // are 15-45% below these caps; teaching that path exact row counts
        // recovers that, and the chips already pad to whatever row count is
        // written here (`next_multiple_of_32_rows`).
        //
        // ⚠ reth's normalize verifies far larger core shards than the fibonacci
        // e2e this was gated on. If it overflows, RAISE THE CAPS here — do not
        // restore the band list. A second shape is a second compose program per
        // arity, and the layer barrier comes back with it.
        let allowed_shapes = [[
            (mem_var.clone(), 1 << 19),
            (select.clone(), 1 << 19),
            (mem_const.clone(), 1 << 12),
            (base_alu.clone(), 1 << 19),
            (ext_alu.clone(), 1 << 19),
            (poseidon2_wide.clone(), 1 << 17),
            (ext2felt.clone(), 1 << 16),
            (public_values.clone(), 1 << PUB_VALUES_LOG_HEIGHT),
        ]]
        .map(HashMap::from)
        .to_vec();
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

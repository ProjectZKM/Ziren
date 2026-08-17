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
            .map(|(name, log_height)| {
                (widths.get(name).copied().unwrap_or(1) as u128) << *log_height
            })
            .sum()
    }

    pub fn fix_shape(&self, program: &mut RecursionProgram<F>) {
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

        for shape in self.allowed_shapes.iter() {
            // If any of the heights is greater than the shape, continue.
            let fits =
                heights.iter().all(|(name, height)| *height <= (1 << shape.get(name).unwrap()));
            if !fits {
                continue;
            }

            let cells = Self::band_cells(shape, &widths);
            if cells < closest_cells {
                closest_cells = cells;
                closest_shape = Some(shape);
            }
        }

        if let Some(shape) = closest_shape {
            if std::env::var("ZIREN_FIXSHAPE_DIAG").is_ok() {
                let mut organic: Vec<(String, usize)> =
                    heights.iter().map(|(n, h)| (n.clone(), *h)).collect();
                organic.sort();
                let mut band: Vec<(String, usize)> =
                    shape.iter().map(|(n, h)| (n.clone(), 1usize << h)).collect();
                band.sort();
                eprintln!("FIXSHAPE organic={organic:?} -> band={band:?} cells={closest_cells}");
            }
            let shape = RecursionShape { inner: shape.clone().into_iter().collect() };
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
        let select = RecursionAir::<F, DEGREE>::Select(SelectChip).name();
        let public_values = RecursionAir::<F, DEGREE>::PublicValues(PublicValuesChip).name();

        // Specify allowed shapes.
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
        let allowed_shapes = [
            // Bundle-lift compose level h=0. Tendermint bundle-lift's
            // first compose level (lift outputs → arity-4 compose)
            // panics shape.rs:91 with chip heights none of the above
            // shapes fit. Observed:
            //   MemoryConst≈149290 (log≈18), Select≈157920 (log≈18),
            //   BaseAlu≈91431 (log≈17), ExtAlu≈93619 (log≈17).
            // Caps with 1-bit headroom on binding dimensions for reth/
            // geth headroom. Placed before the larger cap below so h=0
            // compose programs prefer this smaller cap and pay less
            // padding.
            [
                (mem_var.clone(), 18),
                (select.clone(), 19),
                (mem_const.clone(), 19),
                (base_alu.clone(), 18),
                (ext_alu.clone(), 18),
                (poseidon2_wide.clone(), 18),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            // SELECT-HEAVY deep compose band (tendermint + goat).  The 100-bit
            // BaseFold params (inner blowup 1->2, 94->124 queries, +1 Merkle
            // level) grew the compose-tree verify circuit past the
            // component-opening band, and every compose level converges to the
            // same maxima for both programs (47-shard TM and 10-shard goat
            // produce identical compose vectors once inputs are fixed-shape).
            // Measured maxima over tendermint's whole compose tree
            // (`ZIREN_FIXSHAPE_DIAG=1`): Select 1,182,816 (2^21),
            // MemoryVar 778,723 (2^20), BaseAlu 521,377 (2^20),
            // ExtAlu 448,221 (2^19), MemoryConst 275,464 (2^19),
            // Poseidon2WideDeg3 172,988 (2^18).  Caps sit exactly one power of
            // two above each, so the deepest level pads ~1.9x instead of ~8x.
            // Select is the dimension that separates this profile from the
            // ALU-heavy reth ladder below: here it is the TALLEST chip, there
            // it sits at 2^19 while the ALUs run to 2^22.
            [
                (mem_var.clone(), 20),
                (select.clone(), 21),
                (mem_const.clone(), 19),
                (base_alu.clone(), 20),
                (ext_alu.clone(), 19),
                (poseidon2_wide.clone(), 18),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            // ── ALU-HEAVY COMPOSE LADDER (reth) ────────────────────────────
            //
            // reth's compose tree has a profile none of the bands above fit
            // without gross over-pad: BaseAlu/ExtAlu climb from 2^19 to 2^22
            // while Select stays pinned at 295,616 rows (2^19) and
            // Poseidon2WideDeg3 never passes 94,556 (2^17).  The bands above
            // are all Select-heavy — the cheapest of them that fits a level
            // whose ExtAlu is 2^21 is the uniform 2^21 band, which pads Select
            // 7.1x and MemoryConst 5.9x, and one level whose ExtAlu overshot
            // 2^21 by 0.5% had nothing left but the row cube and padded 2.2x
            // overall.  Committed area is what every device buffer is sized
            // from, so that over-pad WAS the compress-stage VRAM ceiling: the
            // jagged sumcheck's two fold tables are `2^log_dense` EF4 each, and
            // at the cube band a single one asked for 8576 MiB.
            //
            // Measured organic heights, one rung per level family
            // (`ZIREN_FIXSHAPE_DIAG=1` over a 275-shard reth core proof):
            //   BaseAlu   414,870 / 499,692 /   986,148 / 1,691,933
            //   ExtAlu    384,077 / 598,386 /   963,739 / 2,106,820
            //   MemoryVar 275,575 / 294,148 /   420,213 /   674,004
            //   MemConst  107,246 / 120,672 /   205,098 /   354,448
            //   Poseidon2  50,464 /  54,182 /    67,531 /    94,556
            //   Select    295,616 (every level)
            // The rungs cap MemoryConst/MemoryVar/Select generously — they are
            // 13, 12 and 13 cells per row, so a spare bit costs almost nothing
            // — and Poseidon2WideDeg3/ExtAlu tightly, at 362 and 88 cells per
            // row.  Each rung is scored against every other band by
            // `fix_shape`, so a level takes one of these only when it is
            // genuinely cheaper than the Select-heavy profiles.
            [
                (mem_var.clone(), 20),
                (select.clone(), 20),
                (mem_const.clone(), 19),
                (base_alu.clone(), 19),
                (ext_alu.clone(), 19),
                (poseidon2_wide.clone(), 17),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            [
                (mem_var.clone(), 20),
                (select.clone(), 20),
                (mem_const.clone(), 19),
                (base_alu.clone(), 20),
                (ext_alu.clone(), 20),
                (poseidon2_wide.clone(), 17),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            [
                (mem_var.clone(), 20),
                (select.clone(), 20),
                (mem_const.clone(), 19),
                (base_alu.clone(), 21),
                (ext_alu.clone(), 21),
                (poseidon2_wide.clone(), 18),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            // CAPPED AT THE ROW CUBE.  Every recursion stage proves at a
            // FIXED `max_log_row_count` (22 — `ZKMProver::pcs_max_log_row_count`),
            // and a chip's trace is wrapped as `PaddedMle::padded(inner, cube,
            // ..)`, which asserts the padded rows fit `2^cube`.  A band taller
            // than the cube therefore cannot be padded TO: measured, tendermint
            // compose snapped onto the old `base_alu = 23` entry and died with
            // "PaddedMle::padded: real rows 8388608 exceed 2^num_variables
            // 4194304" (`crates/pcs/src/multilinear/padded.rs:155`).  The old
            // 23/24 caps came from a natural-height sweep taken before the cube
            // was pinned; a program whose ORGANIC height really exceeded the
            // cube could not be proven at all, so nothing is lost by capping.
            [
                (mem_var.clone(), 22),
                (select.clone(), 21),
                (mem_const.clone(), 22),
                (base_alu.clone(), 22),
                (ext_alu.clone(), 22),
                (poseidon2_wide.clone(), 20),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
        ]
        .map(HashMap::from)
        .to_vec();
        // No band may exceed the row cube every recursion stage proves at:
        // `PaddedMle::padded` asserts the padded rows fit `2^cube`, so a taller
        // band is a shape nothing can be snapped onto.
        let cube = zkm_pcs::shard_level::verifier::BasefoldShardVerifier::production_default()
            .max_log_row_count;
        for shape in allowed_shapes.iter() {
            for (name, log_height) in shape.iter() {
                assert!(
                    *log_height <= cube,
                    "recursion band {name} = 2^{log_height} exceeds the row cube 2^{cube}",
                );
            }
        }
        Self { allowed_shapes, _marker: PhantomData }
    }
}

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
            if std::env::var("ZIREN_FIXSHAPE_DIAG").is_ok() {
                let mut organic: Vec<(String, usize)> =
                    heights.iter().map(|(n, h)| (n.clone(), *h)).collect();
                organic.sort();
                let mut band: Vec<(String, usize)> =
                    shape.iter().map(|(n, h)| (n.clone(), 1usize << h)).collect();
                band.sort();
                eprintln!("FIXSHAPE organic={organic:?} -> band={band:?}");
            }
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
        let select = RecursionAir::<F, DEGREE>::Select(SelectChip).name();
        let public_values = RecursionAir::<F, DEGREE>::PublicValues(PublicValuesChip).name();

        // Specify allowed shapes.
        let allowed_shapes = [
            // No tiny bands below 2^17 (pre-basefold, ~10s-of-K-instruction
            // programs): every basefold recursion program
            // is >= 2^17 per chip, so they never matched and only emitted
            // unreachable vks into the enumeration.
            // Basefold normalize-sized shape.  The basefold normalize
            // program produces ~660K instructions with chip heights:
            // MemoryConst≈33842, MemoryVar≈11253, BaseAlu≈74980,
            // ExtAlu≈70969, Poseidon2WideDeg3≈2012,
            // ExpReverseBitsLen≈24, PublicValues≈4.  Powers-of-two
            // log_heights with headroom: BaseAlu/ExtAlu→17,
            // MemoryConst→16, MemoryVar→14 (rounded up to a
            // minimum of 18 to share with smaller shapes).  This entry
            // lets `fix_shape` succeed for basefold programs when
            // that path is enabled; the basefold
            // builder otherwise skips fix_shape entirely.
            [
                (mem_var.clone(), 18),
                (select.clone(), 18),
                (mem_const.clone(), 17),
                (base_alu.clone(), 18),
                (ext_alu.clone(), 18),
                (poseidon2_wide.clone(), 18),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
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
            // Bundle-lift compose level h=1+. Each compose tree
            // level grows: h=0 outputs become h=1 inputs, h=1 compose
            // verifies them and produces bigger chip heights still.
            // Tendermint h=1 panic showed roughly 2× h=0:
            //   MemoryConst≈375959 (log≈19), Select≈315840 (log≈19),
            //   ExtAlu≈306869 (log≈19), BaseAlu≈182828 (log≈18),
            //   MemoryVar≈102404 (log≈17), Poseidon2WideDeg3≈59776 (log≈16).
            // Bigger caps fit h=1 + h=2 + reth/geth deeper trees.
            [
                (mem_var.clone(), 19),
                (select.clone(), 20),
                (mem_const.clone(), 20),
                (base_alu.clone(), 19),
                (ext_alu.clone(), 20),
                (poseidon2_wide.clone(), 18),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            // Component-opening band: the component-opening witnessing (bound
            // initial_eval + Merkle binding) grew compose programs past
            // the older caps (observed fib compose: MemoryVar 663k -> 20,
            // ExtAlu 865k -> 20).  One-bit headroom on the binding dims.
            [
                (mem_var.clone(), 20),
                (select.clone(), 20),
                (mem_const.clone(), 20),
                (base_alu.clone(), 20),
                (ext_alu.clone(), 21),
                (poseidon2_wide.clone(), 19),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            // Soundness compose band (TM + goat).  The 100-bit
            // BaseFold params (inner blowup 1->2, 94->124 queries, +1
            // Merkle level) grew the compose-tree verify circuit past the
            // component-opening band: every compose level (height 1..n)
            // converges to the SAME maxima for both tendermint and goat
            // (47-shard TM and 10-shard goat produce identical compose
            // vectors once inputs are fixed-shape).  Observed (max over
            // all levels, FROM_DUMP probe):
            //   Select=1091552 (log21 -- THE binding overflow, was capped
            //   at 20), MemoryVar=689763 (log20), ExtAlu=345152 (log19),
            //   BaseAlu=344339 (log19), MemoryConst=252755 (log18),
            //   Poseidon2WideDeg3=158830 (log18).  Only Select overflowed
            //   the component-opening band; this clone bumps Select 20->21
            //   (next power of two above 1.09M = 2.10M, ~1.9x headroom)
            //   and keeps every other chip at the component-opening caps
            //   (which already cover the observed heights with headroom).
            // Placed LAST so smaller programs (fib/first-layer/reth/geth
            // shallow compose) still prefer the smaller bands above and
            // pay less padding; only Select>2^20 compose programs reach it.
            // Height-agnostic FIX-off band, a strict superset of the
            // component-opening band (ExtAlu 24>=21,
            // Select 21=21, MemoryVar/MemoryConst 22>=20, BaseAlu 23>=20,
            // Poseidon2WideDeg3 20>=19) so we keep FIVE bands total — adding a
            // 6th blew the Compress cartesian product (bands^REDUCE_BATCH = 6^4
            // = 1296) past the VK_MERKLE_TREE_HEIGHT 2^11 pre-flight at
            // shapes.rs:197 (2762 > 2048); 5 bands -> 5^4 -> 1986 < 2048 fits.
            // Per-chip maxima of the NATURAL recursion heights measured across
            // all 1202 FIX-off shapes (`find_recursion_shapes --measure`):
            // ExtAlu 24, BaseAlu 23, MemoryConst/MemoryVar 22, Select 21,
            // Poseidon2WideDeg3 20 (BatchFRI/ExpReverseBitsLen measured 0/unused,
            // kept at 21/18). Capped at ExtAlu 2^24 = KoalaBear
            // two-adicity. This band is what lets `fix_shape` accept FIX-off
            // (`FIX_CORE_SHAPES=false`) proofs, whose recursion heights reach
            // ExtAlu ~2^24 (a max band of ExtAlu 2^21 would reject them at
            // shape.rs:91 "no shape found").
            // Soundness compose band.  The comment above describes a band that
            // bumps Select 20->21 and keeps every other chip at the
            // component-opening caps — it was never actually added, so the next
            // thing a deep compose level could snap onto was the row-cube band
            // below, which over-pads by 8-16x and runs the card out of memory.
            // Measured maxima over tendermint's whole compose tree
            // (`ZIREN_FIXSHAPE_DIAG=1`): Select 1,182,816 (2^21),
            // MemoryVar 778,723 (2^20), BaseAlu 521,377 (2^20),
            // ExtAlu 448,221 (2^19), MemoryConst 275,464 (2^19),
            // Poseidon2WideDeg3 172,988 (2^18).  Caps sit exactly one power of
            // two above each, so the deepest level pads ~1.9x instead of ~8x.
            [
                (mem_var.clone(), 20),
                (select.clone(), 21),
                (mem_const.clone(), 19),
                (base_alu.clone(), 20),
                (ext_alu.clone(), 19),
                (poseidon2_wide.clone(), 18),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            // One step up, for compose trees deeper than tendermint's (reth).
            // A strict superset of the band above and a strict subset of the
            // row-cube band below, so a program that overflows the tuned band
            // pays 2x rather than jumping straight to the cube.
            [
                (mem_var.clone(), 21),
                (select.clone(), 21),
                (mem_const.clone(), 21),
                (base_alu.clone(), 21),
                (ext_alu.clone(), 21),
                (poseidon2_wide.clone(), 19),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            // CAPPED AT THE ROW CUBE.  Every recursion stage proves at a
            // FIXED `max_log_row_count` (22 — `ZKMProver::perstage_base_cube`),
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

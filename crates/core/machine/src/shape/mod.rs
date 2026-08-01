use std::collections::BTreeMap;
use std::str::FromStr;

use hashbrown::HashMap;
use itertools::Itertools;
use num::Integer;
use p3_field::PrimeField32;
use p3_util::log2_ceil_usize;
use thiserror::Error;

use zkm_core_executor::{ExecutionRecord, MipsAirId, Program};
use zkm_pcs::{
    air::MachineAir,
    shape::{OrderedShape, Shape, ShapeCluster},
    MachineRecord,
};

use super::mips::mips_chips::SyscallChip;
use crate::{
    global::GlobalChip,
    memory::{MemoryLocalChip, NUM_LOCAL_MEMORY_ENTRIES_PER_ROW},
    mips::MipsAir,
};

/// The set of maximal shapes.
///
/// These shapes define the "worst-case" shapes for typical shards that are proving `mips`
/// execution. We use a variant of a cartesian product of the allowed log heights to generate
/// smaller shapes from these ones.
const MAXIMAL_SHAPES: &[u8] = include_bytes!("maximal_shapes.json");

/// The set of tiny shapes.
///
/// These shapes are used to optimize performance for smaller programs.
const SMALL_SHAPES: &[u8] = include_bytes!("small_shapes.json");

/// A configuration for what shapes are allowed to be used by the prover.
#[derive(Debug)]
pub struct CoreShapeConfig<F: PrimeField32> {
    partial_preprocessed_shapes: ShapeCluster<MipsAirId>,
    partial_core_shapes: BTreeMap<usize, Vec<ShapeCluster<MipsAirId>>>,
    partial_memory_shapes: ShapeCluster<MipsAirId>,
    partial_precompile_shapes: HashMap<MipsAir<F>, (usize, Vec<usize>)>,
    partial_small_shapes: Vec<ShapeCluster<MipsAirId>>,
    costs: HashMap<MipsAirId, usize>,
}

impl<F: PrimeField32> CoreShapeConfig<F> {
    /// Fix the preprocessed shape of the proof.
    pub fn fix_preprocessed_shape(&self, program: &mut Program) -> Result<(), CoreShapeError> {
        // If the preprocessed shape is already fixed, return an error.
        if program.preprocessed_shape.is_some() {
            return Err(CoreShapeError::PreprocessedShapeAlreadyFixed);
        }

        // Get the heights of the preprocessed chips and find a shape that fits.
        let preprocessed_heights = MipsAir::<F>::preprocessed_heights(program);
        let preprocessed_shape = self
            .partial_preprocessed_shapes
            .find_shape(&preprocessed_heights)
            .ok_or(CoreShapeError::PreprocessedShapeError)?;

        // Set the preprocessed shape.
        program.preprocessed_shape = Some(preprocessed_shape);

        Ok(())
    }

    /// Return the per-chip CLUSTER-MAXIMAL shape (the
    /// band-cap) that a core record with these `heights` lifts to — WITHOUT
    /// mutating any record or padding any trace.
    ///
    /// This is the read-only sibling of [`Self::fix_shape`]'s core-record cluster
    /// search: it returns the same minimal-LDE cluster shape (each chip at its
    /// cluster band height ≥ its actual height) that `fix_shape` would extend the
    /// record to, but returns it instead of applying it. The jagged PCS commit
    /// pads to THIS shape's per-chip heights so the recursion normalize program
    /// (built from the cluster's maximal shape) — and hence its VK — depends on
    /// the chip-SET only, allowing FIX_CORE_SHAPES to be retired (the core STARK
    /// still proves at the ACTUAL heights; only the jagged commit pads).
    ///
    /// Iterates ALL bands: `ShapeCluster::find_shape` already returns `None` for a
    /// band whose caps a chip exceeds, so the min-area fitting shape across all
    /// bands equals `fix_shape`'s `range(log2_shard_size..)` result (the skipped
    /// smaller bands never fit the CPU chip). Returns `None` if no band fits
    /// (the over-large case `fix_shape` also rejects).
    pub fn find_core_shape(
        &self,
        heights: &[(MipsAirId, usize)],
    ) -> Option<Shape<MipsAirId>> {
        let mut minimal_shape = None;
        let mut minimal_area = usize::MAX;
        for clusters in self.partial_core_shapes.values() {
            for cluster in clusters.iter() {
                if let Some(shape) = cluster.find_shape(heights) {
                    let area = self.estimate_lde_size(&shape);
                    if area < minimal_area {
                        minimal_area = area;
                        minimal_shape = Some(shape);
                    }
                }
            }
        }
        minimal_shape
    }

    /// Read-only computation of the FULL
    /// canonical CLUSTER shape a core record lifts to — the exact same shape
    /// `fix_shape` + [`canonicalize_shape_to_cluster`] would produce under
    /// `FIX_CORE_SHAPES=true`, but WITHOUT mutating the record or padding any
    /// trace.  Mirrors every `fix_shape` branch (packed-small / plain-core)
    /// plus the preprocessed (Byte/Program) shape and the stacked-cluster
    /// canonicalization, returning the per-chip cluster band-cap `log_height`
    /// map (incl. the missing canonical-cluster chips at log-height 1).
    ///
    /// Why a separate function from [`Self::find_core_shape`]: `find_core_shape`
    /// only searches `partial_core_shapes` over the present CORE chips, so it
    /// (a) selects a DIFFERENT cluster than `fix_shape`'s packed-small branch
    /// for a CPU+memory shard, and (b) never covers the non-core chips
    /// (Byte/Program/MemoryGlobal*/Global) nor the missing event-driven chips.
    /// The jagged COMMIT must pad to THIS shape (chip-SET + heights) so the
    /// FIX-off normalize VK equals the FIX-on canonical cluster VK in the
    /// production vk_map.
    ///
    /// Returns `None` when no cluster fits (the over-large case `fix_shape`
    /// also rejects) — the caller then keeps legacy own-height packing.
    pub fn find_canonical_cluster_shape(
        &self,
        record: &ExecutionRecord,
    ) -> Option<Shape<MipsAirId>> {
        // Preprocessed (Byte / Program) shape — either already fixed on the
        // program (FIX-on) or computed read-only here (FIX-off, None).
        let prep: Shape<MipsAirId> = match record.program.preprocessed_shape.as_ref() {
            Some(s) => s.clone(),
            None => {
                let prep_heights = MipsAir::<F>::preprocessed_heights(&record.program);
                self.partial_preprocessed_shapes.find_shape(&prep_heights)?
            }
        };
        let has_cpu = record.contains_cpu();
        let is_packed = has_cpu
            && (!record.global_memory_finalize_events.is_empty()
                || !record.global_memory_initialize_events.is_empty());
        // Precompile sub-family coverage: a no-CPU precompile shard
        // (e.g. an in-guest sha256 output-commit shard carrying ONLY ShaExtend,
        // not ShaCompress) is a SUB-FAMILY of its whole precompile-family
        // cluster.  The core/packed branches below `return None` for no-CPU
        // records, which leaves the shard committed at its raw sub-family
        // chip-set whose normalize VK is NOT enumerated (the enum emits one
        // cluster per WHOLE family).  Lift it UP to the whole-family cluster
        // here (same SP1 `smallest_cluster`-superset model the core path uses):
        // build the shard's precompile shape, then `canonicalize_shape` injects
        // the missing family chips so the committed chip-SET == the enumerated
        // whole-family cluster == IN-MAP.
        if !has_cpu
            && record.global_memory_initialize_events.is_empty()
            && record.global_memory_finalize_events.is_empty()
        {
            return self.precompile_canonical_cluster_shape(prep, record);
        }
        let mut heights = MipsAir::<F>::core_heights(record);
        if is_packed {
            heights.extend(MipsAir::<F>::memory_heights(record));
        }
        let log2_shard_size = record.cpu_events.len().next_power_of_two().ilog2() as usize;
        self.canonical_cluster_from_parts(prep, has_cpu, is_packed, &heights, log2_shard_size)
    }

    /// Precompile sub-family coverage: canonical-cluster shape for a
    /// no-CPU precompile shard.  Mirrors the precompile branch of
    /// [`Self::fix_shape`] (the same `partial_precompile_shapes` +
    /// `get_precompile_shapes` band-cap search), unioned with `prep` and then
    /// lifted to the WHOLE-family cluster via [`canonicalize_shape`].  The
    /// committed shard then presents the whole-family chip-SET (sub-family
    /// shards get the absent family chips injected at log-1 by the band-cap
    /// guard's missing-chip injection), so its FIX-off normalize VK equals the
    /// enumerated whole-family cluster VK in the production vk_map.
    ///
    /// Returns `None` when the record carries no precompile events at all (no
    /// band-cap installed → legacy own-height packing, as before).
    fn precompile_canonical_cluster_shape(
        &self,
        prep: Shape<MipsAirId>,
        record: &ExecutionRecord,
    ) -> Option<Shape<MipsAirId>> {
        let mut shape = prep;
        // Find the precompile worker air whose events this record carries and
        // run the SAME band-cap fitting search as `fix_shape`'s precompile arm.
        for (air, (memory_events_per_row, allowed_log2_heights)) in
            self.partial_precompile_shapes.iter()
        {
            let Some((height, num_memory_local_events, num_global_events)) =
                air.precompile_heights(record)
            else {
                continue;
            };
            for allowed_log2_height in allowed_log2_heights {
                let allowed_height = 1usize << allowed_log2_height;
                if height <= allowed_height {
                    for cand in
                        self.get_precompile_shapes(air, *memory_events_per_row, *allowed_log2_height)
                    {
                        let mem_events_height = cand[2].1;
                        let global_events_height = cand[3].1;
                        if num_memory_local_events.div_ceil(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW)
                            <= (1 << mem_events_height)
                            && num_global_events <= (1 << global_events_height)
                        {
                            shape.extend(
                                cand.iter()
                                    .map(|x| (MipsAirId::from_str(&x.0).unwrap(), x.1)),
                            );
                            // Lift the sub-family shard to its whole-family
                            // cluster (inject the absent family chips at log-1).
                            canonicalize_shape(&mut shape);
                            return Some(shape);
                        }
                    }
                }
            }
            // The precompile worker is present but no band fits — fall through
            // to None (legacy own-height packing; `fix_shape` would error here,
            // but the FIX-off band-cap is best-effort).
            return None;
        }
        None
    }

    /// Precompile sub-family coverage: NAME-based sibling of
    /// [`Self::precompile_canonical_cluster_shape`], for the enum / gate side
    /// (`_from_ordered` / `_from_raw`) which holds a chip NAME -> raw-rows map
    /// rather than a record.  The committed shard pads each PRESENT chip to its
    /// own raw height and injects the absent whole-family chips at log-1, so the
    /// canonical shape is `prep ∪ {present precompile-shard chips at their
    /// log-height} ∪ {missing family chips at log-1}` (`canonicalize_shape`).
    /// This matches the chip-SET the real-proof band-cap path produces.
    ///
    /// `raw` maps chip NAME -> RAW row count (2^log_h).  Returns `None` if the
    /// shard carries no recognizable precompile worker chip.
    fn precompile_canonical_cluster_shape_from_names(
        &self,
        prep: Shape<MipsAirId>,
        raw: &std::collections::BTreeMap<String, usize>,
    ) -> Option<Shape<MipsAirId>> {
        // A precompile shard is identified by carrying SyscallPrecompile (the
        // worker-syscall chip every precompile shard emits) plus at least one
        // precompile worker chip (anything that is neither a core/memory chip
        // nor a preprocessed chip).  We rebuild the shape from the present
        // chip NAMEs at their raw log-heights, then canonicalize up.
        let mut shape = prep;
        let mut saw_precompile_worker = false;
        for (name, rows) in raw.iter() {
            if *rows == 0 {
                continue;
            }
            let Ok(id) = MipsAirId::from_str(name) else { continue };
            // Skip the preprocessed chips already in `prep`.
            if matches!(id, MipsAirId::Program | MipsAirId::Byte) {
                continue;
            }
            let log_h = rows.next_power_of_two().trailing_zeros() as usize;
            shape.insert(id, log_h);
            // Any chip outside the core/memory set that is not the shared
            // SyscallPrecompile/MemoryLocal/Global plumbing marks this as a
            // genuine precompile shard.
            if !matches!(
                id,
                MipsAirId::SyscallPrecompile
                    | MipsAirId::MemoryLocal
                    | MipsAirId::Global
                    | MipsAirId::SyscallCore
            ) && !Self::is_core_or_memory_id(id)
            {
                saw_precompile_worker = true;
            }
        }
        if !saw_precompile_worker {
            return None;
        }
        canonicalize_shape(&mut shape);
        Some(shape)
    }

    /// Whether `id` is a core-execution or global-memory chip (NOT a precompile
    /// worker).  Used to distinguish precompile-shard worker chips from the
    /// shared core/memory plumbing.
    fn is_core_or_memory_id(id: MipsAirId) -> bool {
        matches!(
            id,
            MipsAirId::Cpu
                | MipsAirId::Branch
                | MipsAirId::Jump
                | MipsAirId::MovCond
                | MipsAirId::MiscInstrs
                | MipsAirId::MemoryLoadNarrow
                | MipsAirId::MemoryLoadWord
                | MipsAirId::MemoryStoreNarrow
                | MipsAirId::MemoryStoreWord
                | MipsAirId::MemoryUnaligned
                | MipsAirId::SyscallInstrs
                | MipsAirId::DivRem
                | MipsAirId::AddSub
                | MipsAirId::Bitwise
                | MipsAirId::Mul
                | MipsAirId::ShiftRight
                | MipsAirId::ShiftLeft
                | MipsAirId::Lt
                | MipsAirId::CloClz
                | MipsAirId::MemoryGlobalInit
                | MipsAirId::MemoryGlobalFinalize
        )
    }

    /// `OrderedShape` (chip NAME -> raw log_height) sibling of
    /// [`Self::find_canonical_cluster_shape`], for the VK-enumeration / gate
    /// side (which holds a proof's `sp.shape()`, not a record).  Reconstructs
    /// the per-chip event-height vectors from the raw heights (2^log_h, which
    /// maps to the SAME pow-2 band cap as the real row count) and runs the
    /// IDENTICAL branch + canonicalize logic, so the dummy bundle is packed at
    /// the exact heights the real FIX-off commit used.
    pub fn find_canonical_cluster_shape_from_ordered(
        &self,
        os: &zkm_pcs::shape::OrderedShape,
    ) -> Option<Shape<MipsAirId>> {
        use std::collections::BTreeMap;
        // Raw row count per present chip NAME (2^log_h).
        let raw: BTreeMap<String, usize> =
            os.inner.iter().map(|(n, h)| (n.clone(), 1usize << *h)).collect();
        let get = |id: &MipsAirId| -> usize { raw.get(&id.to_string()).copied().unwrap_or(0) };
        let has_cpu = get(&MipsAirId::Cpu) > 0;
        let is_packed = has_cpu
            && (get(&MipsAirId::MemoryGlobalInit) > 0
                || get(&MipsAirId::MemoryGlobalFinalize) > 0);
        // Preprocessed (Byte / Program) shape from their raw heights.
        let prep_heights: Vec<(MipsAirId, usize)> = [MipsAirId::Program, MipsAirId::Byte]
            .into_iter()
            .map(|id| (id, get(&id)))
            .collect();
        let prep = self.partial_preprocessed_shapes.find_shape(&prep_heights)?;
        // Precompile sub-family coverage: no-CPU precompile shard.
        if !has_cpu
            && get(&MipsAirId::MemoryGlobalInit) == 0
            && get(&MipsAirId::MemoryGlobalFinalize) == 0
        {
            return self.precompile_canonical_cluster_shape_from_names(prep, &raw);
        }
        // Core heights (same MipsAirIds + order as MipsAir::core_heights), then
        // memory heights for the packed branch (same as MipsAir::memory_heights).
        let core_ids = [
            MipsAirId::Cpu, MipsAirId::Branch, MipsAirId::Jump, MipsAirId::MovCond,
            MipsAirId::MiscInstrs, MipsAirId::MemoryLoadNarrow, MipsAirId::MemoryLoadWord,
            MipsAirId::MemoryStoreNarrow, MipsAirId::MemoryStoreWord,
            MipsAirId::MemoryUnaligned, MipsAirId::SyscallInstrs,
            MipsAirId::DivRem, MipsAirId::AddSub, MipsAirId::Bitwise, MipsAirId::Mul,
            MipsAirId::ShiftRight, MipsAirId::ShiftLeft, MipsAirId::Lt, MipsAirId::MemoryLocal,
            MipsAirId::CloClz, MipsAirId::Global, MipsAirId::SyscallCore,
        ];
        let mut heights: Vec<(MipsAirId, usize)> =
            core_ids.iter().map(|id| (*id, get(id))).collect();
        if is_packed {
            heights.push((MipsAirId::MemoryGlobalInit, get(&MipsAirId::MemoryGlobalInit)));
            heights.push((MipsAirId::MemoryGlobalFinalize, get(&MipsAirId::MemoryGlobalFinalize)));
            heights.push((
                MipsAirId::Global,
                get(&MipsAirId::MemoryGlobalInit) + get(&MipsAirId::MemoryGlobalFinalize),
            ));
        }
        let log2_shard_size = get(&MipsAirId::Cpu).next_power_of_two().ilog2() as usize;
        self.canonical_cluster_from_parts(prep, has_cpu, is_packed, &heights, log2_shard_size)
    }

    /// RAW-event-count sibling of
    /// [`Self::find_canonical_cluster_shape`] for the VK-enumeration side.
    ///
    /// `find_canonical_cluster_shape_from_ordered` reconstructs heights from a
    /// proof's `chip_log_heights` (= `2^log` POST-padding row counts), which
    /// ROUNDS UP and so can land a low-count CPU-shard chip (e.g. `MiscInstrs`
    /// with 0 real events shows up as `2^1`) in a DIFFERENT min-area cluster
    /// than the record path picks — producing a divergent canonical shape (the
    /// CPU-shard membership-gate failure).  This variant takes the PRE-padding
    /// RAW event counts directly (chip NAME -> raw rows), exactly the values
    /// `MipsAir::core_heights`/`memory_heights` feed `find_canonical_cluster_
    /// shape`, so the enum can sweep faithful raw profiles and reproduce the
    /// record path's canonical shapes byte-for-byte.  Absent chips are 0.
    pub fn find_canonical_cluster_shape_from_raw(
        &self,
        raw: &std::collections::BTreeMap<String, usize>,
    ) -> Option<Shape<MipsAirId>> {
        let get = |id: &MipsAirId| -> usize { raw.get(&id.to_string()).copied().unwrap_or(0) };
        let has_cpu = get(&MipsAirId::Cpu) > 0;
        let is_packed = has_cpu
            && (get(&MipsAirId::MemoryGlobalInit) > 0
                || get(&MipsAirId::MemoryGlobalFinalize) > 0);
        let prep_heights: Vec<(MipsAirId, usize)> = [MipsAirId::Program, MipsAirId::Byte]
            .into_iter()
            .map(|id| (id, get(&id)))
            .collect();
        let prep = self.partial_preprocessed_shapes.find_shape(&prep_heights)?;
        // Precompile sub-family coverage: no-CPU precompile shard.
        if !has_cpu
            && get(&MipsAirId::MemoryGlobalInit) == 0
            && get(&MipsAirId::MemoryGlobalFinalize) == 0
        {
            return self.precompile_canonical_cluster_shape_from_names(prep, raw);
        }
        let core_ids = [
            MipsAirId::Cpu, MipsAirId::Branch, MipsAirId::Jump, MipsAirId::MovCond,
            MipsAirId::MiscInstrs, MipsAirId::MemoryLoadNarrow, MipsAirId::MemoryLoadWord,
            MipsAirId::MemoryStoreNarrow, MipsAirId::MemoryStoreWord,
            MipsAirId::MemoryUnaligned, MipsAirId::SyscallInstrs,
            MipsAirId::DivRem, MipsAirId::AddSub, MipsAirId::Bitwise, MipsAirId::Mul,
            MipsAirId::ShiftRight, MipsAirId::ShiftLeft, MipsAirId::Lt, MipsAirId::MemoryLocal,
            MipsAirId::CloClz, MipsAirId::Global, MipsAirId::SyscallCore,
        ];
        let mut heights: Vec<(MipsAirId, usize)> =
            core_ids.iter().map(|id| (*id, get(id))).collect();
        if is_packed {
            heights.push((MipsAirId::MemoryGlobalInit, get(&MipsAirId::MemoryGlobalInit)));
            heights.push((MipsAirId::MemoryGlobalFinalize, get(&MipsAirId::MemoryGlobalFinalize)));
            heights.push((
                MipsAirId::Global,
                get(&MipsAirId::MemoryGlobalInit) + get(&MipsAirId::MemoryGlobalFinalize),
            ));
        }
        let log2_shard_size = get(&MipsAirId::Cpu).next_power_of_two().ilog2() as usize;
        self.canonical_cluster_from_parts(prep, has_cpu, is_packed, &heights, log2_shard_size)
    }

    /// Enumerate the FULL SET of canonical-cluster shapes
    /// a FIX-off core proof can lift to — config-driven, proof-independent.
    ///
    /// Every real normalize child's jagged commit is padded to
    /// `find_canonical_cluster_shape(record)`, which is exactly ONE cluster's
    /// band-cap shape (per-chip cluster cap for present chips + canonicalize's
    /// missing chips at log-1 + the fitting preprocessed Program band).  The
    /// min-area search just picks WHICH cluster for a given record; the union
    /// over ALL clusters (here) is a SUPERSET that contains every reachable
    /// canonical shape — so the recursion vk_map built from these covers every
    /// FIX-off normalize VK.  We drive `find_canonical_cluster_shape_from_raw`
    /// with each cluster's own band-cap as the raw profile, so the returned
    /// shape is byte-identical to the record path (the min-area search re-picks
    /// that same cluster since the profile equals its caps), then sweep the
    /// preprocessed Program bands (Byte is fixed at 2^16).
    ///
    /// Covers BOTH the plain-core clusters (`partial_core_shapes`, keyed by
    /// log_shard_size) and the packed-small clusters (`partial_small_shapes`).
    pub fn enumerate_canonical_cluster_shapes(&self) -> Vec<Shape<MipsAirId>> {
        use std::collections::{BTreeMap, BTreeSet};
        // Preprocessed Program bands to sweep (Byte fixed at its single band).
        let prog_bands: Vec<usize> = self
            .partial_preprocessed_shapes
            .iter()
            .find(|(air, _)| **air == MipsAirId::Program)
            .map(|(_, hs)| hs.iter().filter_map(|h| *h).collect())
            .unwrap_or_default();
        let byte_band: usize = self
            .partial_preprocessed_shapes
            .iter()
            .find(|(air, _)| **air == MipsAirId::Byte)
            .and_then(|(_, hs)| hs.last().copied().flatten())
            .unwrap_or(16);

        // Build a raw profile from a cluster's band-caps: each chip at 2^cap
        // (so `find_shape` re-selects this cluster), plus the swept Program /
        // fixed Byte band.  Memory-cluster (packed) chips are included so the
        // packed-small branch fires when MemoryGlobalInit/Finalize are capped.
        let raw_from_cluster = |cluster: &ShapeCluster<MipsAirId>,
                                prog: usize|
         -> BTreeMap<String, usize> {
            let mut raw: BTreeMap<String, usize> = BTreeMap::new();
            raw.insert(MipsAirId::Program.to_string(), 1usize << prog);
            raw.insert(MipsAirId::Byte.to_string(), 1usize << byte_band);
            for (air, hs) in cluster.iter() {
                if let Some(cap) = hs.last().copied().flatten() {
                    raw.insert(air.to_string(), 1usize << cap);
                }
            }
            raw
        };

        let mut out: BTreeSet<Vec<(String, usize)>> = BTreeSet::new();
        let mut emit = |shape: Shape<MipsAirId>| {
            let mut v: Vec<(String, usize)> =
                shape.iter().map(|(a, h)| (a.to_string(), *h)).collect();
            v.sort();
            out.insert(v);
        };

        for clusters in self.partial_core_shapes.values() {
            for cluster in clusters.iter() {
                for &prog in &prog_bands {
                    let raw = raw_from_cluster(cluster, prog);
                    if let Some(shape) = self.find_canonical_cluster_shape_from_raw(&raw) {
                        emit(shape);
                    }
                }
            }
        }
        for cluster in self.partial_small_shapes.iter() {
            for &prog in &prog_bands {
                let raw = raw_from_cluster(cluster, prog);
                if let Some(shape) = self.find_canonical_cluster_shape_from_raw(&raw) {
                    emit(shape);
                }
            }
        }

        out.into_iter()
            .map(|v| {
                v.into_iter()
                    .filter_map(|(n, h)| MipsAirId::from_str(&n).ok().map(|id| (id, h)))
                    .collect::<Shape<MipsAirId>>()
            })
            .collect()
    }

    /// FAST sibling of [`Self::enumerate_canonical_cluster_shapes`].
    ///
    /// O(clusters · chips) instead of O(clusters²): the slow variant drives
    /// `find_canonical_cluster_shape_from_raw` per (cluster, prog), each of which
    /// re-runs the min-area search over ALL ~28.5K small clusters (≈ billions of
    /// `find_shape` calls, > 3 min, did not finish).  This variant emits each
    /// cluster's OWN band-cap canonical shape directly (per-chip cap heights +
    /// swept Program / fixed Byte + `canonicalize_shape`), no search — ~1s.
    ///
    /// ⚠️ NOT output-equivalent to the slow variant — it OVER-EMITS.  The slow
    /// (and the real-proof `find_canonical_cluster_shape`) min-area search
    /// COLLAPSES many cluster-cap profiles onto the SAME smallest-area canonical
    /// shape; this variant skips that collapse, so it emits each cluster's raw
    /// band-cap shape (~70K, vastly over the 2048 vk_map budget) instead of the
    /// small collapsed set.  It is therefore a building block, NOT a drop-in
    /// enumeration: a faithful fast enumeration still needs to reproduce the
    /// min-area COLLAPSE.  Retained for that follow-up
    /// and for cheap per-cluster band-cap inspection.
    pub fn enumerate_canonical_cluster_shapes_fast(&self) -> Vec<Shape<MipsAirId>> {
        use std::collections::BTreeSet;
        use std::collections::BTreeSet as Set;
        let prog_bands: Vec<usize> = self
            .partial_preprocessed_shapes
            .iter()
            .find(|(air, _)| **air == MipsAirId::Program)
            .map(|(_, hs)| hs.iter().filter_map(|h| *h).collect())
            .unwrap_or_default();
        let byte_band: usize = self
            .partial_preprocessed_shapes
            .iter()
            .find(|(air, _)| **air == MipsAirId::Byte)
            .and_then(|(_, hs)| hs.last().copied().flatten())
            .unwrap_or(16);

        // Build the canonicalize cluster ID-sets ONCE (the per-call
        // `canonicalize_shape` rebuilds `build_mips_machine_shape()` every
        // invocation — fatal at 28.5K·4 calls).  Each entry is one cluster's
        // MipsAirId set; canonicalization picks the smallest superset of the
        // present chips and adds its missing chips at log-1.
        let canon_clusters: Vec<Set<MipsAirId>> =
            zkm_pcs::stacked_shapes::build_mips_machine_shape()
                .chip_clusters
                .iter()
                .map(|c| c.iter().filter_map(|n| MipsAirId::from_str(n).ok()).collect())
                .collect();
        let canonicalize = |shape: &mut Shape<MipsAirId>| {
            let present: Set<MipsAirId> = shape.iter().map(|(k, _)| *k).collect();
            let mut best: Option<&Set<MipsAirId>> = None;
            for ids in canon_clusters.iter() {
                if present.is_subset(ids)
                    && best.as_ref().map(|b| ids.len() < b.len()).unwrap_or(true)
                {
                    best = Some(ids);
                }
            }
            if let Some(cluster) = best {
                for id in cluster.iter() {
                    if !present.contains(id) {
                        shape.insert(*id, 1);
                    }
                }
            }
        };

        // A cluster's own canonical shape: each chip at its band-cap log-height
        // (`hs.last()`), plus Program (swept) / Byte (fixed), then canonicalize
        // (superset-cluster missing chips at log-1).  No min-area search.
        let cluster_canonical = |cluster: &ShapeCluster<MipsAirId>, prog: usize| -> Shape<MipsAirId> {
            let mut shape: Shape<MipsAirId> = Shape::new(HashMap::new());
            shape.insert(MipsAirId::Program, prog);
            shape.insert(MipsAirId::Byte, byte_band);
            for (air, hs) in cluster.iter() {
                if let Some(cap) = hs.last().copied().flatten() {
                    shape.insert(*air, cap);
                }
            }
            canonicalize(&mut shape);
            shape
        };

        let mut out: BTreeSet<Vec<(String, usize)>> = BTreeSet::new();
        let mut emit = |shape: Shape<MipsAirId>| {
            let mut v: Vec<(String, usize)> =
                shape.iter().map(|(a, h)| (a.to_string(), *h)).collect();
            v.sort();
            out.insert(v);
        };
        for clusters in self.partial_core_shapes.values() {
            for cluster in clusters.iter() {
                for &prog in &prog_bands {
                    emit(cluster_canonical(cluster, prog));
                }
            }
        }
        for cluster in self.partial_small_shapes.iter() {
            for &prog in &prog_bands {
                emit(cluster_canonical(cluster, prog));
            }
        }

        out.into_iter()
            .map(|v| {
                v.into_iter()
                    .filter_map(|(n, h)| MipsAirId::from_str(&n).ok().map(|id| (id, h)))
                    .collect::<Shape<MipsAirId>>()
            })
            .collect()
    }

    /// Shared core of [`Self::find_canonical_cluster_shape`] and its
    /// `_from_ordered` sibling: run the `fix_shape` branch (packed-small /
    /// plain-core) over `heights`, union the preprocessed shape, then apply the
    /// stacked-cluster canonicalization.
    fn canonical_cluster_from_parts(
        &self,
        prep: Shape<MipsAirId>,
        has_cpu: bool,
        is_packed: bool,
        heights: &[(MipsAirId, usize)],
        log2_shard_size: usize,
    ) -> Option<Shape<MipsAirId>> {
        let mut shape = prep;
        if is_packed {
            // Packed-small branch: min-area shape over partial_small_shapes.
            let mut minimal_shape = None;
            let mut minimal_area = usize::MAX;
            for cluster in self.partial_small_shapes.iter() {
                if let Some(s) = cluster.find_shape(heights) {
                    let area = self.estimate_lde_size(&s);
                    if area < minimal_area {
                        minimal_area = area;
                        minimal_shape = Some(s);
                    }
                }
            }
            shape.extend(minimal_shape?);
        } else if has_cpu {
            // Plain-core branch: min-area shape over partial_core_shapes range.
            let mut minimal_shape = None;
            let mut minimal_area = usize::MAX;
            for (_, clusters) in self.partial_core_shapes.range(log2_shard_size..) {
                for cluster in clusters.iter() {
                    if let Some(s) = cluster.find_shape(heights) {
                        let area = self.estimate_lde_size(&s);
                        if area < minimal_area {
                            minimal_area = area;
                            minimal_shape = Some(s.clone());
                        }
                    }
                }
            }
            shape.extend(minimal_shape?);
        } else {
            // No-CPU records are not produced on the FIX-off core band-cap path.
            return None;
        }
        // Stacked-cluster canonicalization: extend with the missing chips of the
        // smallest superset cluster at log-height 1.
        canonicalize_shape(&mut shape);
        Some(shape)
    }

    /// Fix the shape of the proof.
    pub fn fix_shape(&self, record: &mut ExecutionRecord) -> Result<(), CoreShapeError> {
        if record.program.preprocessed_shape.is_none() {
            return Err(CoreShapeError::PreprocessedShapeMissing);
        }
        if record.shape.is_some() {
            return Err(CoreShapeError::ShapeAlreadyFixed);
        }

        // Set the shape of the chips with prepcoded shapes to match the preprocessed shape from the
        // program.
        record.shape.clone_from(&record.program.preprocessed_shape);

        // If this is a packed "core" record where the cpu events are alongside the memory init and
        // finalize events, try to fix the shape using the tiny shapes.
        if record.contains_cpu()
            && (!record.global_memory_finalize_events.is_empty()
                || !record.global_memory_initialize_events.is_empty())
        {
            // Get the heights of the core airs in the record.
            let mut heights = MipsAir::<F>::core_heights(record);
            heights.extend(MipsAir::<F>::memory_heights(record));

            // Try to find a shape fitting within at least one of the candidate shapes.
            let mut minimal_shape = None;
            let mut minimal_area = usize::MAX;
            let mut minimal_cluster = None;
            for (i, cluster) in self.partial_small_shapes.iter().enumerate() {
                if let Some(shape) = cluster.find_shape(&heights) {
                    if self.estimate_lde_size(&shape) < minimal_area {
                        minimal_area = self.estimate_lde_size(&shape);
                        minimal_shape = Some(shape);
                        minimal_cluster = Some(i);
                    }
                }
            }

            if let Some(shape) = minimal_shape {
                let shard = record.public_values.shard;
                tracing::info!(
                    "Shard Lifted: Index={}, Cluster={}",
                    shard,
                    minimal_cluster.unwrap()
                );
                for (air, height) in heights.iter() {
                    if shape.contains(air) {
                        tracing::info!(
                            "Chip {:<20}: {:<3} -> {:<3}",
                            air,
                            log2_ceil_usize(*height),
                            shape.log2_height(air).unwrap(),
                        );
                    }
                }
                record.shape.as_mut().unwrap().extend(shape);
                return Ok(());
            }

            // No shape found, so return an error.
            return Err(CoreShapeError::ShapeError(
                heights
                    .into_iter()
                    .map(|(air, height)| (air.to_string(), log2_ceil_usize(height)))
                    .collect(),
            ));
        }

        // If this is a normal "core" record, try to fix the shape as such.
        if record.contains_cpu() {
            // Get the heights of the core airs in the record.
            let heights = MipsAir::<F>::core_heights(record);

            // Try to find the smallest shape fitting within at least one of the candidate shapes.
            let log2_shard_size = record.cpu_events.len().next_power_of_two().ilog2() as usize;
            let mut minimal_shape = None;
            let mut minimal_area = usize::MAX;
            let mut minimal_cluster = None;
            for (_, clusters) in self.partial_core_shapes.range(log2_shard_size..) {
                for (i, cluster) in clusters.iter().enumerate() {
                    if let Some(shape) = cluster.find_shape(&heights) {
                        if self.estimate_lde_size(&shape) < minimal_area {
                            minimal_area = self.estimate_lde_size(&shape);
                            minimal_shape = Some(shape.clone());
                            minimal_cluster = Some(i);
                        }
                    }
                }
            }

            if let Some(shape) = minimal_shape {
                let shard = record.public_values.shard;
                let cluster = minimal_cluster.unwrap();
                tracing::info!("Shard Lifted: Index={}, Cluster={}", shard, cluster);

                for (air, height) in heights.iter() {
                    if shape.contains(air) {
                        tracing::info!(
                            "Chip {:<20}: {:<3} -> {:<3}",
                            air,
                            log2_ceil_usize(*height),
                            shape.log2_height(air).unwrap(),
                        );
                    }
                }
                record.shape.as_mut().unwrap().extend(shape);
                return Ok(());
            }

            // No shape found, so return an error.
            tracing::info!(
                "No shape found for core record with heights: {:?}",
                heights
                    .into_iter()
                    .map(|(air, height)| (air.to_string(), log2_ceil_usize(height)))
                    .collect::<HashMap<_, _>>()
            );

            return Err(CoreShapeError::ShapeError(record.stats()));
        }

        // If the record is a does not have the CPU chip and is a global memory init/finalize
        // record, try to fix the shape as such.
        if !record.global_memory_initialize_events.is_empty()
            || !record.global_memory_finalize_events.is_empty()
        {
            let heights = MipsAir::<F>::memory_heights(record);
            let shape = self
                .partial_memory_shapes
                .find_shape(&heights)
                .ok_or(CoreShapeError::ShapeError(record.stats()))?;
            record.shape.as_mut().unwrap().extend(shape);
            return Ok(());
        }

        // Try to fix the shape as a precompile record.
        for (air, (memory_events_per_row, allowed_log2_heights)) in
            self.partial_precompile_shapes.iter()
        {
            if let Some((height, num_memory_local_events, num_global_events)) =
                air.precompile_heights(record)
            {
                for allowed_log2_height in allowed_log2_heights {
                    let allowed_height = 1 << allowed_log2_height;
                    if height <= allowed_height {
                        for shape in self.get_precompile_shapes(
                            air,
                            *memory_events_per_row,
                            *allowed_log2_height,
                        ) {
                            let mem_events_height = shape[2].1;
                            let global_events_height = shape[3].1;
                            if num_memory_local_events.div_ceil(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW)
                                <= (1 << mem_events_height)
                                && num_global_events <= (1 << global_events_height)
                            {
                                record.shape.as_mut().unwrap().extend(
                                    shape.iter().map(|x| (MipsAirId::from_str(&x.0).unwrap(), x.1)),
                                );
                                return Ok(());
                            }
                        }
                    }
                }
                tracing::error!(
                    "Cannot find shape for precompile {:?}, height {:?}, and mem events {:?}",
                    air.name(),
                    height,
                    num_memory_local_events
                );
                return Err(CoreShapeError::ShapeError(record.stats()));
            }
        }

        Err(CoreShapeError::PrecompileNotIncluded(record.stats()))
    }

    fn get_precompile_shapes(
        &self,
        air: &MipsAir<F>,
        memory_events_per_row: usize,
        allowed_log2_height: usize,
    ) -> Vec<Vec<(String, usize)>> {
        // TODO: This is a temporary fix to the shape, concretely fix this
        (1..=4 * air.rows_per_event())
            .rev()
            .map(|rows_per_event| {
                let num_local_mem_events =
                    ((1 << allowed_log2_height) * memory_events_per_row).div_ceil(rows_per_event);
                // The `SyscallPrecompile` chip — and any `PrecompileChain`
                // control chip — emit exactly 1 row per syscall, so they share
                // this height.
                let syscall_height = ((1 << allowed_log2_height)
                    .div_ceil(&air.rows_per_event())
                    .next_power_of_two()
                    .ilog2() as usize)
                    .max(4);
                // NOTE: the worker / SyscallPrecompile / MemoryLocal / Global
                // entries stay at indices 0 / 1 / 2 / 3 so the caller's
                // `shape[2]` (mem) and `shape[3]` (global) indexing is preserved;
                // the optional control chip is appended at index 4.
                let mut shape = vec![
                    (air.name(), allowed_log2_height),
                    (
                        MipsAir::<F>::SyscallPrecompile(SyscallChip::precompile()).name(),
                        syscall_height,
                    ),
                    (
                        MipsAir::<F>::MemoryLocal(MemoryLocalChip::new()).name(),
                        (num_local_mem_events
                            .div_ceil(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW)
                            .next_power_of_two()
                            .ilog2() as usize)
                            .max(4),
                    ),
                    (
                        MipsAir::<F>::Global(GlobalChip).name(),
                        ((2 * num_local_mem_events
                            + (1 << allowed_log2_height).div_ceil(&air.rows_per_event()))
                        .next_power_of_two()
                        .ilog2() as usize)
                            .max(4),
                    ),
                ];
                // Bus-ported precompiles (sha256-compress/extend, garble) pair the
                // worker with a control chip that bookends the PrecompileChain
                // state bus.  It emits 1 row per syscall and MUST be present in the
                // shard's shape, otherwise `Shape::included` drops it and the
                // worker's bus sends have no matching receives (unbalanced LogUp).
                if let Some(control) = air.precompile_control_air() {
                    shape.push((control.name(), syscall_height));
                }
                shape
            })
            .filter(|shape| shape[3].1 <= 22)
            .collect::<Vec<_>>()
    }

    fn generate_all_shapes_from_allowed_log_heights(
        allowed_log_heights: impl IntoIterator<Item = (String, Vec<Option<usize>>)>,
    ) -> impl Iterator<Item = OrderedShape> {
        allowed_log_heights
            .into_iter()
            .map(|(name, heights)| heights.into_iter().map(move |height| (name.clone(), height)))
            .multi_cartesian_product()
            .map(|iter| {
                iter.into_iter()
                    .filter_map(|(name, maybe_height)| {
                        maybe_height.map(|log_height| (name, log_height))
                    })
                    .collect::<OrderedShape>()
            })
    }

    /// Legacy per-chip cartesian enumeration of all possible shard
    /// shapes.  Produces ~1.25M shapes for MIPS.  **Superseded** by
    /// `zkm_pcs::stacked_shapes::create_all_input_shapes` (≤ 5,000
    /// shapes, size-class quantization) which is the sole path
    /// used by `ZKMProofShape::generate` for VK generation.
    ///
    /// This function is retained for the pre-existing `#[ignore]`d
    /// test at `test_making_shapes` and for any diagnostic callers
    /// that specifically need the per-chip cartesian view.
    pub fn all_shapes(&self) -> impl Iterator<Item = OrderedShape> + '_ {
        let preprocessed_heights = self
            .partial_preprocessed_shapes
            .iter()
            .map(|(air, heights)| (air.to_string(), heights.clone()))
            .collect::<HashMap<_, _>>();

        let mut memory_heights = self
            .partial_memory_shapes
            .iter()
            .map(|(air, heights)| (air.to_string(), heights.clone()))
            .collect::<HashMap<_, _>>();
        memory_heights.extend(preprocessed_heights.clone());

        let precompile_only_shapes = self.partial_precompile_shapes.iter().flat_map(
            move |(air, (mem_events_per_row, allowed_log_heights))| {
                allowed_log_heights.iter().flat_map(move |allowed_log_height| {
                    self.get_precompile_shapes(air, *mem_events_per_row, *allowed_log_height)
                })
            },
        );

        let precompile_shapes =
            Self::generate_all_shapes_from_allowed_log_heights(preprocessed_heights.clone())
                .flat_map(move |preprocessed_shape| {
                    precompile_only_shapes.clone().map(move |precompile_shape| {
                        preprocessed_shape
                            .clone()
                            .into_iter()
                            .chain(precompile_shape)
                            .collect::<OrderedShape>()
                    })
                });

        self.partial_core_shapes
            .values()
            .flatten()
            .chain(self.partial_small_shapes.iter())
            .flat_map(move |allowed_log_heights| {
                Self::generate_all_shapes_from_allowed_log_heights({
                    let mut log_heights = allowed_log_heights
                        .iter()
                        .map(|(air, heights)| (air.to_string(), heights.clone()))
                        .collect::<HashMap<_, _>>();
                    log_heights.extend(preprocessed_heights.clone());
                    log_heights
                })
            })
            .chain(Self::generate_all_shapes_from_allowed_log_heights(memory_heights))
            .chain(precompile_shapes)
    }

    pub fn maximal_core_shapes(&self, max_log_shard_size: usize) -> Vec<Shape<MipsAirId>> {
        let max_shard_size: usize = core::cmp::max(
            1 << max_log_shard_size,
            1 << self.partial_core_shapes.keys().min().unwrap(),
        );

        let log_shard_size = max_shard_size.ilog2() as usize;
        debug_assert_eq!(1 << log_shard_size, max_shard_size);
        let max_preprocessed = self
            .partial_preprocessed_shapes
            .iter()
            .map(|(air, allowed_heights)| {
                (air.to_string(), allowed_heights.last().unwrap().unwrap())
            })
            .collect::<HashMap<_, _>>();

        let max_core_shapes =
            self.partial_core_shapes[&log_shard_size].iter().map(|allowed_log_heights| {
                max_preprocessed
                    .clone()
                    .into_iter()
                    .chain(allowed_log_heights.iter().flat_map(|(air, allowed_heights)| {
                        allowed_heights
                            .last()
                            .unwrap()
                            .map(|log_height| (air.to_string(), log_height))
                    }))
                    .map(|(air, log_height)| (MipsAirId::from_str(&air).unwrap(), log_height))
                    .collect::<Shape<MipsAirId>>()
            });

        max_core_shapes.collect()
    }

    pub fn maximal_core_plus_precompile_shapes(
        &self,
        max_log_shard_size: usize,
    ) -> Vec<Shape<MipsAirId>> {
        let max_preprocessed = self
            .partial_preprocessed_shapes
            .iter()
            .map(|(air, allowed_heights)| {
                (air.to_string(), allowed_heights.last().unwrap().unwrap())
            })
            .collect::<HashMap<_, _>>();

        let precompile_only_shapes = self.partial_precompile_shapes.iter().flat_map(
            move |(air, (mem_events_per_row, allowed_log_heights))| {
                self.get_precompile_shapes(
                    air,
                    *mem_events_per_row,
                    *allowed_log_heights.last().unwrap(),
                )
            },
        );

        let precompile_shapes: Vec<Shape<MipsAirId>> = precompile_only_shapes
            .map(|x| {
                max_preprocessed
                    .clone()
                    .into_iter()
                    .chain(x)
                    .map(|(air, log_height)| (MipsAirId::from_str(&air).unwrap(), log_height))
                    .collect::<Shape<MipsAirId>>()
            })
            .filter(|shape| shape.log2_height(&MipsAirId::Global).unwrap() < 21)
            .collect();

        self.maximal_core_shapes(max_log_shard_size).into_iter().chain(precompile_shapes).collect()
    }

    fn estimate_lde_size(&self, shape: &Shape<MipsAirId>) -> usize {
        shape.iter().map(|(air, height)| self.costs[air] * (1 << height)).sum()
    }

}

impl<F: PrimeField32> Default for CoreShapeConfig<F> {
    fn default() -> Self {
        // Load the maximal shapes.
        let maximal_shapes = std::env::var("MAXIMAL_SHAPES_FILE")
            .ok()
            .map(|file| std::fs::read(file).expect("Failed to read MAXIMAL_SHAPES_FILE"))
            .unwrap_or_else(|| MAXIMAL_SHAPES.to_vec());
        let maximal_shapes: BTreeMap<usize, Vec<Shape<MipsAirId>>> =
            serde_json::from_slice(&maximal_shapes).unwrap();

        let small_shapes = std::env::var("SMALL_SHAPES_FILE")
            .ok()
            .map(|file| std::fs::read(file).expect("Failed to read SMALL_SHAPES_FILE"))
            .unwrap_or_else(|| SMALL_SHAPES.to_vec());
        let small_shapes: Vec<Shape<MipsAirId>> = serde_json::from_slice(&small_shapes).unwrap();

        // Set the allowed preprocessed log2 heights.
        let allowed_preprocessed_log2_heights = HashMap::from([
            (MipsAirId::Program, vec![Some(19), Some(20), Some(21), Some(22)]),
            (MipsAirId::Byte, vec![Some(16)]),
        ]);

        // Generate the clusters from the maximal shapes and register them indexed by log2 shard
        //  size.
        let mut core_allowed_log2_heights = BTreeMap::new();
        for (log2_shard_size, maximal_shapes) in maximal_shapes {
            let mut clusters = vec![];

            for maximal_shape in maximal_shapes.iter() {
                let cluster = derive_cluster_from_maximal_shape(maximal_shape);
                clusters.push(cluster);
            }

            core_allowed_log2_heights.insert(log2_shard_size, clusters);
        }

        // Set the memory init and finalize heights.
        let memory_allowed_log2_heights = HashMap::from(
            [
                (
                    MipsAirId::MemoryGlobalInit,
                    vec![None, Some(10), Some(16), Some(18), Some(19), Some(20), Some(21)],
                ),
                (
                    MipsAirId::MemoryGlobalFinalize,
                    vec![None, Some(10), Some(16), Some(18), Some(19), Some(20), Some(21)],
                ),
                (MipsAirId::Global, vec![None, Some(11), Some(17), Some(19), Some(21), Some(22)]),
            ]
            .map(|(air, log_heights)| (air, log_heights)),
        );

        let mut precompile_allowed_log2_heights = HashMap::new();
        let precompile_heights = (3..21).collect::<Vec<_>>();
        for (air, memory_events_per_row) in
            MipsAir::<F>::precompile_airs_with_memory_events_per_row()
        {
            precompile_allowed_log2_heights
                .insert(air, (memory_events_per_row, precompile_heights.clone()));
        }

        Self {
            partial_preprocessed_shapes: ShapeCluster::new(allowed_preprocessed_log2_heights),
            partial_core_shapes: core_allowed_log2_heights,
            partial_memory_shapes: ShapeCluster::new(memory_allowed_log2_heights),
            partial_precompile_shapes: precompile_allowed_log2_heights,
            partial_small_shapes: small_shapes
                .into_iter()
                .map(|x| {
                    ShapeCluster::new(x.into_iter().map(|(k, v)| (k, vec![Some(v)])).collect())
                })
                .collect(),
            costs: serde_json::from_str(include_str!(
                "../../../executor/src/artifacts/mips_costs.json"
            ))
            .unwrap(),
        }
    }
}

fn derive_cluster_from_maximal_shape(shape: &Shape<MipsAirId>) -> ShapeCluster<MipsAirId> {
    // We first define a heuristic to derive the log heights from the maximal shape.
    let log2_gap_from_22 = 22 - shape.log2_height(&MipsAirId::Cpu).unwrap();
    let min_log2_height_threshold = 18 - log2_gap_from_22;
    let log2_height_buffer = 10;
    let heuristic = |maximal_log2_height: Option<usize>, min_offset: usize| {
        if let Some(maximal_log2_height) = maximal_log2_height {
            let tallest_log2_height = std::cmp::max(maximal_log2_height, min_log2_height_threshold);
            let shortest_log2_height = tallest_log2_height.saturating_sub(min_offset);

            (shortest_log2_height..=tallest_log2_height).map(Some).collect::<Vec<_>>()
        } else {
            vec![None, Some(log2_height_buffer)]
        }
    };

    let mut maybe_log2_heights = HashMap::new();

    let cpu_log_height = shape.log2_height(&MipsAirId::Cpu);
    maybe_log2_heights.insert(MipsAirId::Cpu, heuristic(cpu_log_height, 0));

    let addsub_log_height = shape.log2_height(&MipsAirId::AddSub);
    maybe_log2_heights.insert(MipsAirId::AddSub, heuristic(addsub_log_height, 0));

    let lt_log_height = shape.log2_height(&MipsAirId::Lt);
    maybe_log2_heights.insert(MipsAirId::Lt, heuristic(lt_log_height, 0));

    let memory_local_log_height = shape.log2_height(&MipsAirId::MemoryLocal);
    maybe_log2_heights.insert(MipsAirId::MemoryLocal, heuristic(memory_local_log_height, 0));

    let divrem_log_height = shape.log2_height(&MipsAirId::DivRem);
    maybe_log2_heights.insert(MipsAirId::DivRem, heuristic(divrem_log_height, 1));

    let bitwise_log_height = shape.log2_height(&MipsAirId::Bitwise);
    maybe_log2_heights.insert(MipsAirId::Bitwise, heuristic(bitwise_log_height, 1));

    let mul_log_height = shape.log2_height(&MipsAirId::Mul);
    maybe_log2_heights.insert(MipsAirId::Mul, heuristic(mul_log_height, 1));

    let shift_right_log_height = shape.log2_height(&MipsAirId::ShiftRight);
    maybe_log2_heights.insert(MipsAirId::ShiftRight, heuristic(shift_right_log_height, 1));

    let shift_left_log_height = shape.log2_height(&MipsAirId::ShiftLeft);
    maybe_log2_heights.insert(MipsAirId::ShiftLeft, heuristic(shift_left_log_height, 1));

    let cloclz_log_height = shape.log2_height(&MipsAirId::CloClz);
    maybe_log2_heights.insert(MipsAirId::CloClz, heuristic(cloclz_log_height, 0));

    let branch_log_height = shape.log2_height(&MipsAirId::Branch);
    maybe_log2_heights.insert(MipsAirId::Branch, heuristic(branch_log_height, 0));

    let jump_log_height = shape.log2_height(&MipsAirId::Jump);
    maybe_log2_heights.insert(MipsAirId::Jump, heuristic(jump_log_height, 0));

    let syscall_log_height = shape.log2_height(&MipsAirId::SyscallInstrs);
    maybe_log2_heights.insert(MipsAirId::SyscallInstrs, heuristic(syscall_log_height, 0));

    for memory_id in [
        MipsAirId::MemoryLoadNarrow,
        MipsAirId::MemoryLoadWord,
        MipsAirId::MemoryStoreNarrow,
        MipsAirId::MemoryStoreWord,
        MipsAirId::MemoryUnaligned,
    ] {
        let memory_log_height = shape.log2_height(&memory_id);
        maybe_log2_heights.insert(memory_id, heuristic(memory_log_height, 0));
    }

    let movcond_log_height = shape.log2_height(&MipsAirId::MovCond);
    maybe_log2_heights.insert(MipsAirId::MovCond, heuristic(movcond_log_height, 0));

    let misc_log_height = shape.log2_height(&MipsAirId::MiscInstrs);
    maybe_log2_heights.insert(MipsAirId::MiscInstrs, heuristic(misc_log_height, 0));

    let syscall_core_log_height = shape.log2_height(&MipsAirId::SyscallCore);
    maybe_log2_heights.insert(MipsAirId::SyscallCore, heuristic(syscall_core_log_height, 0));

    let global_log_height = shape.log2_height(&MipsAirId::Global);
    maybe_log2_heights.insert(MipsAirId::Global, heuristic(global_log_height, 1));

    assert!(maybe_log2_heights.len() >= shape.len(), "not all chips were included in the shape");

    ShapeCluster::new(maybe_log2_heights)
}

#[derive(Debug, Error)]
pub enum CoreShapeError {
    #[error("no preprocessed shape found")]
    PreprocessedShapeError,
    #[error("Preprocessed shape already fixed")]
    PreprocessedShapeAlreadyFixed,
    #[error("no shape found {0:?}")]
    ShapeError(HashMap<String, usize>),
    #[error("Preprocessed shape missing")]
    PreprocessedShapeMissing,
    #[error("Shape already fixed")]
    ShapeAlreadyFixed,
    #[error("Precompile not included in allowed shapes {0:?}")]
    PrecompileNotIncluded(HashMap<String, usize>),
}

#[cfg(test)]
pub mod tests {
    use std::sync::Arc;

    use hashbrown::HashSet;
    use zkm_pcs::{Dom, MachineProver, StarkGenericConfig};

    use super::*;

    fn create_dummy_program(shape: &Shape<MipsAirId>) -> Program {
        let mut program = Program::new(vec![], 1 << 5, 1 << 5);
        program.preprocessed_shape = Some(shape.clone());
        program
    }

    fn create_dummy_record(shape: &Shape<MipsAirId>) -> ExecutionRecord {
        let program = Arc::new(create_dummy_program(shape));
        let mut record = ExecutionRecord::new(program);
        record.shape = Some(shape.clone());
        record
    }

    fn try_generate_dummy_proof<SC: StarkGenericConfig, P: MachineProver<SC, MipsAir<SC::Val>>>(
        prover: &P,
        shape: &Shape<MipsAirId>,
    ) where
        SC::Val: PrimeField32,
        Dom<SC>: core::fmt::Debug,
    {
        let program = create_dummy_program(shape);
        let record = create_dummy_record(shape);

        // Try doing setup.
        let (pk, _) = prover.setup(&program);

        // Try to generate traces.
        let main_traces = prover.generate_traces(&record).unwrap();

        // Try to commit the traces.  No recursion AREA PIN
        // (CORE shape-probe → NATURAL own-area).
        let main_data = prover.commit(&record, main_traces, None, None);

        let mut challenger = prover.machine().config().challenger();

        // Try to "open".
        prover.open(&pk, main_data, &mut challenger).unwrap();
    }

    /// The enumerated canonical-cluster set must CONTAIN
    /// the CPU-shard canonical shape a real FIX-off fib-1k core proof lifts to
    /// (captured via [REALCANON]: `MiscInstrs=1` etc.).  Fast, no proving.
    #[test]
    fn enumerate_canonical_contains_fib_cpu_shard() {
        use p3_koala_bear::KoalaBear;
        let cfg = CoreShapeConfig::<KoalaBear>::default();
        let set: std::collections::BTreeSet<Vec<(String, usize)>> = cfg
            .enumerate_canonical_cluster_shapes_fast()
            .into_iter()
            .map(|s| {
                let mut v: Vec<(String, usize)> =
                    s.iter().map(|(id, h)| (id.to_string(), *h)).collect();
                v.sort();
                v
            })
            .collect();
        eprintln!("[ENUMCANON] set size = {}", set.len());
        // The REALCANON the fib-1k CPU shard padded to (from prove.rs probe).
        let mut want: Vec<(String, usize)> = vec![
            ("AddSub", 13), ("Bitwise", 12), ("Branch", 11), ("Byte", 16),
            ("CloClz", 10), ("Cpu", 14), ("DivRem", 10), ("Global", 9),
            ("Jump", 10), ("Lt", 12), ("LoadNarrow", 10), ("LoadWord", 10), ("StoreNarrow", 10), ("StoreWord", 10), ("MemoryUnaligned", 10), ("MemoryLocal", 10),
            ("MiscInstrs", 1), ("MovCond", 10), ("Mul", 10), ("Program", 19),
            ("ShiftLeft", 9), ("ShiftRight", 9), ("SyscallCore", 10),
            ("SyscallInstrs", 10),
        ]
        .into_iter()
        .map(|(n, h)| (n.to_string(), h))
        .collect();
        want.sort();
        // Match by chip-SET; print the closest candidate for diagnosis.
        let want_set: Vec<String> = {
            let mut v: Vec<String> = want.iter().map(|(n, _)| n.clone()).collect();
            v.sort();
            v
        };
        let same_set: Vec<&Vec<(String, usize)>> = set
            .iter()
            .filter(|c| {
                let mut v: Vec<String> = c.iter().map(|(n, _)| n.clone()).collect();
                v.sort();
                v == want_set
            })
            .collect();
        eprintln!("[ENUMCANON] candidates with matching chip-set = {}", same_set.len());
        for c in same_set.iter().take(4) {
            eprintln!("[ENUMCANON] cand = {c:?}");
        }
        // FINDING (REPORT, not a pass/fail gate): the cluster-CAP
        // fast enumeration does NOT contain the fib-1k CPU-shard REALCANON.
        // REALCANON's per-chip heights are CLAMPED to the record's per-chip raw
        // counts (e.g. MiscInstrs=1 = canonicalize default for a 0-event chip;
        // AddSub=13, Mul=10 = per-chip smallest band >= raw), whereas the
        // cap-enum emits each chip at its cluster band-CAP (MiscInstrs=10, ...).
        // The normalize VK is per-chip-height SENSITIVE, so the cap variant !=
        // the real VK.  This is the residual divergence: a config-driven
        // enumeration cannot reproduce arbitrary per-chip CLAMPED heights
        // without the per-chip cartesian (cap-only already = 69,832 shapes >
        // the 2^11 budget).  The faithful fix is the height-agnostic recursion
        // port (normalize VK becomes chip-SET-only).
        let contains = set.contains(&want);
        eprintln!(
            "[ENUMCANON] FINDING: cap-enum contains REALCANON = {contains} \
             (expected false — per-chip CLAMPED heights are not cap-enumerable)"
        );
    }

    /// `find_canonical_cluster_shape_from_raw` on the fib-1k
    /// CPU shard's RAW event counts (from [REALCANON] core_heights_raw) MUST
    /// reproduce the REALCANON canonical shape (MiscInstrs=1 etc.) byte-for-byte
    /// — the RAW path treats a 0-event chip as truly absent (canonicalize -> 1),
    /// unlike the `_from_ordered` path which over-rounds 0 events to 2^1 and
    /// lands a divergent cluster (the CPU-shard membership-gate failure).  Fast.
    #[test]
    fn raw_canonical_matches_fib_cpu_realcanon() {
        use p3_koala_bear::KoalaBear;
        let cfg = CoreShapeConfig::<KoalaBear>::default();
        // RAW event counts the fib-1k CPU shard actually had (prove.rs probe).
        let raw: BTreeMap<String, usize> = [
            ("AddSub", 4860), ("Bitwise", 2127), ("Branch", 1121), ("CloClz", 1),
            ("Cpu", 8369), ("DivRem", 1000), ("Global", 450), ("Jump", 70),
            ("Lt", 3296), ("LoadNarrow", 501), ("LoadWord", 501), ("StoreNarrow", 501), ("StoreWord", 501), ("MemoryUnaligned", 501), ("MemoryLocal", 51),
            ("MiscInstrs", 0), ("MovCond", 26), ("Mul", 1003), ("ShiftLeft", 107),
            ("ShiftRight", 30), ("SyscallCore", 24), ("SyscallInstrs", 24),
            // Preprocessed raw heights (Program from its instruction count band,
            // Byte at its 2^16 table) — feed the prep find_shape.
            ("Program", 1 << 14), ("Byte", 1 << 16),
        ]
        .into_iter()
        .map(|(n, h)| (n.to_string(), h))
        .collect();
        let got = cfg
            .find_canonical_cluster_shape_from_raw(&raw)
            .expect("raw canonical should fit a cluster");
        let mut got_v: Vec<(String, usize)> =
            got.iter().map(|(id, h)| (id.to_string(), *h)).collect();
        got_v.sort();
        let mut want: Vec<(String, usize)> = vec![
            ("AddSub", 13), ("Bitwise", 12), ("Branch", 11), ("Byte", 16),
            ("CloClz", 10), ("Cpu", 14), ("DivRem", 10), ("Global", 9),
            ("Jump", 10), ("Lt", 12), ("LoadNarrow", 10), ("LoadWord", 10), ("StoreNarrow", 10), ("StoreWord", 10), ("MemoryUnaligned", 10), ("MemoryLocal", 10),
            ("MiscInstrs", 1), ("MovCond", 10), ("Mul", 10), ("Program", 19),
            ("ShiftLeft", 9), ("ShiftRight", 9), ("SyscallCore", 10),
            ("SyscallInstrs", 10),
        ]
        .into_iter()
        .map(|(n, h)| (n.to_string(), h))
        .collect();
        want.sort();
        eprintln!("[RAWCANON] got ={got_v:?}");
        eprintln!("[RAWCANON] want={want:?}");
        assert_eq!(got_v, want, "[RAWCANON] raw canonical != fib CPU REALCANON");
        eprintln!("[RAWCANON] PASS — raw path reproduces REALCANON");
    }

    /// Does a per-machine-cluster RAW SWEEP (cheap, ~26
    /// clusters × heights) that DROPS absent/0-event chips and lifts via
    /// `find_canonical_cluster_shape_from_raw` PRODUCE the fib-1k CPU-shard
    /// REALCANON?  This is the candidate FIX for `generate()`'s `small_shapes`
    /// (vs the lossy `_from_ordered` sweep that pins 0-event chips at log-1).
    /// Fast (no proving); reports the swept set size + REALCANON membership.
    #[test]
    fn raw_sweep_produces_fib_cpu_realcanon() {
        use p3_koala_bear::KoalaBear;
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::stacked_shapes::{build_mips_machine_shape, types::consts};
        let cfg = CoreShapeConfig::<KoalaBear>::default();
        let machine = MipsAir::<KoalaBear>::machine(
            zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2::default(),
        );
        let chips_by_name: BTreeMap<String, _> =
            machine.chips().iter().map(|c| (c.name(), c)).collect();
        let ms = build_mips_machine_shape();

        let mut set: std::collections::BTreeSet<Vec<(String, usize)>> = Default::default();
        let mut swept = 0usize;
        for cluster in &ms.chip_clusters {
            let names: Vec<String> = cluster
                .iter()
                .filter(|n| chips_by_name.contains_key(*n))
                .cloned()
                .collect();
            if names.is_empty() {
                continue;
            }
            // Filler = byte-lookup-FREE non-Byte chip (varies with area); the
            // rest are pinned: Byte at its 2^16 table, the byte-lookup chips at
            // a minimal PRESENT count.  KEY vs the lossy sweep: we build a RAW
            // count map and only INCLUDE present chips (absent => 0 => the raw
            // canonical canonicalizes them at log-1, matching the record path).
            let fillers: std::collections::HashSet<&String> = names
                .iter()
                .filter(|n| {
                    n.as_str() != "Byte" && chips_by_name[n.as_str()].num_sent_byte_lookups() == 0
                })
                .collect();
            for h in 1..=consts::CORE_MAX_LOG_ROW_COUNT {
                let mut raw: BTreeMap<String, usize> = BTreeMap::new();
                for n in &names {
                    let v = if fillers.contains(n) {
                        1usize << h
                    } else if n == "Byte" {
                        1usize << 16
                    } else {
                        // byte-lookup chip present at a minimal count
                        2usize
                    };
                    raw.insert(n.clone(), v);
                }
                if !raw.contains_key("Program") {
                    raw.insert("Program".to_string(), 1usize << 14);
                }
                swept += 1;
                if let Some(shape) = cfg.find_canonical_cluster_shape_from_raw(&raw) {
                    let mut v: Vec<(String, usize)> = shape
                        .iter()
                        .map(|(id, h)| (id.to_string(), *h))
                        .filter(|(n, _)| chips_by_name.contains_key(n))
                        .collect();
                    v.sort();
                    if !v.is_empty() {
                        set.insert(v);
                    }
                }
            }
        }
        let mut want: Vec<(String, usize)> = vec![
            ("AddSub", 13), ("Bitwise", 12), ("Branch", 11), ("Byte", 16),
            ("CloClz", 10), ("Cpu", 14), ("DivRem", 10), ("Global", 9),
            ("Jump", 10), ("Lt", 12), ("LoadNarrow", 10), ("LoadWord", 10), ("StoreNarrow", 10), ("StoreWord", 10), ("MemoryUnaligned", 10), ("MemoryLocal", 10),
            ("MiscInstrs", 1), ("MovCond", 10), ("Mul", 10), ("Program", 19),
            ("ShiftLeft", 9), ("ShiftRight", 9), ("SyscallCore", 10),
            ("SyscallInstrs", 10),
        ]
        .into_iter()
        .map(|(n, h)| (n.to_string(), h))
        .collect();
        want.sort();
        let contains = set.contains(&want);
        eprintln!(
            "[RAWSWEEP] swept={swept} distinct_canonical={} REALCANON_in_set={contains}",
            set.len()
        );
        // Diagnose: show CPU-set candidates if REALCANON missing.
        if !contains {
            let want_set: Vec<String> = want.iter().map(|(n, _)| n.clone()).collect();
            for c in set.iter().filter(|c| {
                let cs: Vec<String> = c.iter().map(|(n, _)| n.clone()).collect();
                cs == want_set
            }) {
                eprintln!("[RAWSWEEP] same-chipset cand = {c:?}");
            }
        }
    }

    #[test]
    #[ignore]
    fn test_making_shapes() {
        use p3_koala_bear::KoalaBear;
        let shape_config = CoreShapeConfig::<KoalaBear>::default();
        let num_shapes = shape_config.all_shapes().collect::<HashSet<_>>().len();
        assert!(num_shapes < 1 << 24);
        for shape in shape_config.all_shapes() {
            println!("{shape:?}");
        }
        println!("There are {num_shapes} core shapes");
    }

    /// Probe: for a FIXED chip-SET,
    /// is the per-chip canonical-cluster BAND-CAP height INVARIANT across
    /// different RAW height profiles (= different program lengths)?  If YES the
    /// targeted DivEAssert fix (round raw height UP to cluster band-cap
    /// in-circuit, keyed on the witnessed chip-set) is enumerability-safe (the
    /// band-cap is f(chip-set) only).  If NO (the band-cap moves with raw
    /// heights), the fix re-breaks the program-length-dependent VK and must be
    /// abandoned for the SP1-faithful hash-bound port.
    #[test]
    fn step0_bandcap_invariance_for_fixed_chipset() {
        use p3_koala_bear::KoalaBear;
        let cfg = CoreShapeConfig::<KoalaBear>::default();
        // The fib-1k CPU shard chip-SET (same names as raw_canonical_matches_*),
        // here used as a FIXED chip-set whose RAW heights we sweep.
        let names: Vec<&str> = vec![
            "AddSub", "Bitwise", "Branch", "CloClz", "Cpu", "DivRem", "Global",
            "Jump", "Lt", "LoadNarrow", "LoadWord", "StoreNarrow", "StoreWord",
            "MemoryUnaligned", "MemoryLocal", "MiscInstrs", "MovCond",
            "Mul", "ShiftLeft", "ShiftRight", "SyscallCore", "SyscallInstrs",
        ];
        // Several RAW height profiles, ALL with the SAME chip-set present (every
        // chip has >=1 event so it is genuinely present, never canonicalized
        // away), but with very different magnitudes — mimicking short vs long
        // programs.  Program prep band swept too (14/15/16 -> 19/20/21).
        // (cpu_events, addsub, lt, mul, divrem, mem_local, program_raw_log)
        let profiles: Vec<(&str, BTreeMap<String, usize>)> = {
            let mk = |cpu: usize, big: usize, mid: usize, small: usize, prog_log: usize| {
                let mut m: BTreeMap<String, usize> = BTreeMap::new();
                for n in &names {
                    let v = match *n {
                        "Cpu" => cpu,
                        "AddSub" | "Lt" | "Mul" | "DivRem" => big,
                        "Bitwise" | "Branch" | "LoadNarrow" | "LoadWord" | "StoreNarrow" | "StoreWord" | "MemoryUnaligned" | "Global" => mid,
                        _ => small,
                    };
                    m.insert(n.to_string(), v.max(1));
                }
                m.insert("Program".to_string(), 1usize << prog_log);
                m.insert("Byte".to_string(), 1usize << 16);
                m
            };
            vec![
                ("tiny",   mk(8369, 4860, 1000, 24, 14)),
                ("small",  mk(20000, 10000, 3000, 60, 14)),
                ("medium", mk(120000, 60000, 20000, 500, 15)),
                ("large",  mk(900000, 400000, 100000, 4000, 16)),
                ("xlarge", mk(3500000, 1500000, 400000, 20000, 16)),
            ]
        };

        let mut results: Vec<(String, Vec<(String, usize)>)> = Vec::new();
        for (tag, raw) in &profiles {
            match cfg.find_canonical_cluster_shape_from_raw(raw) {
                Some(shape) => {
                    let mut v: Vec<(String, usize)> =
                        shape.iter().map(|(id, h)| (id.to_string(), *h)).collect();
                    v.sort();
                    eprintln!("[STEP0] {tag}: canonical={v:?}");
                    results.push((tag.to_string(), v));
                }
                None => {
                    eprintln!("[STEP0] {tag}: NO cluster fits (None)");
                    results.push((tag.to_string(), vec![]));
                }
            }
        }

        // Compare per-chip band-cap across profiles for chips PRESENT in all.
        // Build name -> set of distinct band-caps observed.
        use std::collections::{BTreeMap as BM, BTreeSet};
        let mut per_chip: BM<String, BTreeSet<usize>> = BM::new();
        let mut chipset_per_profile: Vec<BTreeSet<String>> = Vec::new();
        for (_tag, v) in &results {
            let mut cs = BTreeSet::new();
            for (n, h) in v {
                cs.insert(n.clone());
                per_chip.entry(n.clone()).or_default().insert(*h);
            }
            chipset_per_profile.push(cs);
        }
        // Report chip-set drift (canonicalization could add/drop chips).
        let base_cs = &chipset_per_profile[0];
        let mut chipset_invariant = true;
        for (i, cs) in chipset_per_profile.iter().enumerate() {
            if cs != base_cs {
                chipset_invariant = false;
                eprintln!(
                    "[STEP0] chip-SET DIFFERS at profile {}: only_here={:?} missing_here={:?}",
                    i,
                    cs.difference(base_cs).collect::<Vec<_>>(),
                    base_cs.difference(cs).collect::<Vec<_>>(),
                );
            }
        }
        eprintln!("[STEP0] chipset_invariant={chipset_invariant}");

        let mut bandcap_invariant = true;
        for (n, caps) in &per_chip {
            if caps.len() > 1 {
                bandcap_invariant = false;
                eprintln!("[STEP0] chip {n}: band-caps VARY across profiles = {caps:?}");
            }
        }
        eprintln!(
            "[STEP0] VERDICT: bandcap_invariant_for_fixed_chipset={bandcap_invariant} \
             (true => fix is enumerability-safe; false => fix re-breaks #82)"
        );

        // ESCAPE-HATCH CHECK: would rounding to the cluster's MAXIMAL per-chip
        // cap (hs.last(), a truly chip-set-keyed value) match the host's
        // committed geometry?  The host commits at find_canonical_cluster_shape
        // = the min-area FITTING shape (varies above), NOT the maximal.  Print
        // the maximal-cap shape that the SAME chip-set would map to, to show it
        // differs from the per-profile committed shapes (so a chip-set-only
        // round-up cannot equal the host offsets).
        {
            // Take the 'tiny' profile's selected cluster band-caps vs 'medium'
            // — if even the maximal cap were used, all profiles would share it,
            // but the host does NOT use the maximal (it uses the fitting shape),
            // so matching the host still requires the height-dependent value.
            let nonempty: Vec<&(String, Vec<(String, usize)>)> =
                results.iter().filter(|(_, v)| !v.is_empty()).collect();
            if nonempty.len() >= 2 {
                let a = &nonempty[0].1;
                let b = &nonempty[nonempty.len() - 1].1;
                let differ: Vec<String> = a
                    .iter()
                    .zip(b.iter())
                    .filter(|((n1, h1), (n2, h2))| n1 == n2 && h1 != h2)
                    .map(|((n, h1), (_, h2))| format!("{n}:{h1}->{h2}"))
                    .collect();
                eprintln!(
                    "[STEP0] host-committed shapes DIFFER between '{}' and '{}' on {} chips: {:?}",
                    nonempty[0].0, nonempty[nonempty.len() - 1].0, differ.len(), differ
                );
            }
        }
        // Do NOT assert — this is a diagnostic probe; the printout is the result.
    }

    #[test]
    fn test_dummy_record() {
        use crate::utils::setup_logger;
        use p3_koala_bear::KoalaBear;
        use zkm_pcs::{koala_bear_poseidon2::KoalaBearPoseidon2, CpuProver};

        type SC = KoalaBearPoseidon2;
        type A = MipsAir<KoalaBear>;

        setup_logger();

        let preprocessed_log_heights = [(MipsAirId::Program, 10), (MipsAirId::Byte, 16)];

        let core_log_heights = [
            (MipsAirId::Cpu, 11),
            (MipsAirId::DivRem, 11),
            (MipsAirId::AddSub, 10),
            (MipsAirId::Bitwise, 10),
            (MipsAirId::Mul, 10),
            (MipsAirId::ShiftRight, 10),
            (MipsAirId::ShiftLeft, 10),
            (MipsAirId::Lt, 10),
            (MipsAirId::CloClz, 10),
            (MipsAirId::MemoryLocal, 10),
            (MipsAirId::SyscallCore, 10),
            (MipsAirId::Global, 10),
        ];

        let height_map =
            preprocessed_log_heights.into_iter().chain(core_log_heights).collect::<HashMap<_, _>>();

        let shape = Shape::new(height_map);

        // Try generating preprocessed traces.
        let config = SC::default();
        let machine = A::machine(config);
        let prover = CpuProver::new(machine);

        try_generate_dummy_proof(&prover, &shape);
    }

    /// canonicalize_shape_to_cluster must pad a raw event-driven
    /// main_exec shard (missing the optional CloClz/DivRem/Syscall* chips) UP
    /// to the full 20-chip main_exec cluster, so the GPU multi-shard prove path
    /// (which calls this) presents the canonical chip set to the recursion
    /// vk_map. Without this, the raw
    /// 16/18-chip variants produce normalize vks not in the map ("vk not
    /// allowed").
    #[test]
    fn canonicalize_pads_main_exec_to_cluster() {
        // A raw main_exec-family shard with only 16 of the 20 chips
        // (no CloClz, DivRem, SyscallCore, SyscallInstrs — event-driven drop).
        let raw: Vec<(MipsAirId, usize)> = vec![
            (MipsAirId::AddSub, 21),
            (MipsAirId::Bitwise, 16),
            (MipsAirId::Branch, 17),
            (MipsAirId::Byte, 16),
            (MipsAirId::Cpu, 21),
            (MipsAirId::Global, 16),
            (MipsAirId::Jump, 17),
            (MipsAirId::Lt, 18),
            (MipsAirId::MemoryLoadNarrow, 20),
            (MipsAirId::MemoryLoadWord, 20),
            (MipsAirId::MemoryStoreNarrow, 20),
            (MipsAirId::MemoryStoreWord, 20),
            (MipsAirId::MemoryUnaligned, 20),
            (MipsAirId::MemoryLocal, 17),
            (MipsAirId::MiscInstrs, 17),
            (MipsAirId::MovCond, 17),
            (MipsAirId::Mul, 17),
            (MipsAirId::Program, 19),
            (MipsAirId::ShiftLeft, 16),
            (MipsAirId::ShiftRight, 16),
        ];
        let shape = Shape::<MipsAirId>::from_log2_heights(
            &raw.iter().map(|(k, h)| (*k, *h)).collect::<Vec<_>>(),
        );
        let mut record = create_dummy_record(&shape);
        assert_eq!(record.shape.as_ref().unwrap().len(), 16, "precondition: raw 16 chips");

        canonicalize_shape_to_cluster(&mut record);

        let canon = record.shape.as_ref().unwrap();
        // The full main_exec cluster has 20 chips; the 4 event-driven ones must
        // now be present (at log-height 1) while the originals are untouched.
        for must in [
            MipsAirId::CloClz,
            MipsAirId::DivRem,
            MipsAirId::SyscallCore,
            MipsAirId::SyscallInstrs,
        ] {
            assert!(canon.contains(&must), "canonicalize must add {must:?}");
        }
        assert_eq!(canon.len(), 20, "canonicalized main_exec must have 20 chips, got {}", canon.len());
        // Originals preserved at their real heights.
        assert_eq!(*canon.iter().find(|(k, _)| **k == MipsAirId::Cpu).unwrap().1, 21);
        assert_eq!(*canon.iter().find(|(k, _)| **k == MipsAirId::AddSub).unwrap().1, 21);
    }

    /// Precompile sub-family coverage: a no-CPU sha256 shard carrying
    /// only ShaExtend (+ control) — an in-guest sha256 output-commit splits the
    /// sha256 family across shards — must canonicalize UP to the WHOLE sha256
    /// family cluster (inject ShaCompress + ShaCompressControl), so its FIX-off
    /// normalize VK lands on the enumerated whole-family cluster VK.  Without this
    /// handling `find_canonical_cluster_shape_from_raw` returns `None` for this shard
    /// (the `canonical_cluster_from_parts` no-CPU branch is `return None`),
    /// leaving the sub-family chip-set un-enumerated.
    #[test]
    fn precompile_subfamily_canonicalizes_to_whole_family() {
        use std::collections::BTreeMap;
        use std::str::FromStr;
        let cfg = CoreShapeConfig::<p3_koala_bear::KoalaBear>::default();

        // The exact sub-family shard the task describes: ShaExtend WITHOUT
        // ShaCompress.  Raw row counts (the `_from_raw` input convention).
        let raw: BTreeMap<String, usize> = [
            ("Byte", 1 << 16),
            ("Program", 1 << 19),
            ("Global", 128),
            ("MemoryLocal", 16),
            ("SyscallPrecompile", 16),
            ("ShaExtend", 64),
            ("ShaExtendControl", 16),
        ]
        .into_iter()
        .map(|(n, h)| (n.to_string(), h))
        .collect();

        let shape = cfg
            .find_canonical_cluster_shape_from_raw(&raw)
            .expect("precompile sub-family shard must canonicalize to a cluster (was None)");
        let present: std::collections::BTreeSet<String> =
            shape.iter().map(|(id, _)| id.to_string()).collect();

        // The whole sha256 family chips must ALL be present (the two absent
        // worker/control chips injected by `canonicalize_shape`).
        for must in [
            "ShaExtend",
            "ShaExtendControl",
            "ShaCompress",
            "ShaCompressControl",
            "SyscallPrecompile",
            "MemoryLocal",
            "Global",
            "Byte",
            "Program",
        ] {
            assert!(present.contains(must), "canonicalized shard must contain {must}; got {present:?}");
        }
        // The injected ShaCompress chips sit at log-height 1 (zero-event pad).
        assert_eq!(
            *shape.iter().find(|(id, _)| id.to_string() == "ShaCompress").unwrap().1,
            1,
            "injected ShaCompress must be at log-height 1"
        );
        // No CORE-execution chips leak in (the smallest superset is the precompile
        // cluster, NOT the legacy core+sha union).
        for forbidden in ["Cpu", "AddSub", "DivRem", "MemoryGlobalInit"] {
            assert!(
                !present.contains(forbidden),
                "precompile cluster must NOT contain core chip {forbidden}; got {present:?}"
            );
        }
        // The resulting chip-SET must equal a WHOLE-family precompile cluster in
        // build_mips_machine_shape (== what the enum `generate()` emits), so the
        // normalize VK is in-map.
        let machine_shape = zkm_pcs::stacked_shapes::build_mips_machine_shape();
        let present_ids: std::collections::BTreeSet<MipsAirId> =
            present.iter().filter_map(|n| MipsAirId::from_str(n).ok()).collect();
        let enumerated = machine_shape.chip_clusters.iter().any(|c| {
            let ids: std::collections::BTreeSet<MipsAirId> =
                c.iter().filter_map(|n| MipsAirId::from_str(n).ok()).collect();
            ids == present_ids
        });
        assert!(
            enumerated,
            "canonicalized precompile chip-SET must equal an enumerated cluster; got {present_ids:?}"
        );
    }

    /// Precompile sub-family coverage is GENERAL across all
    /// precompile families and across ANY sub-family of a family (the SP1
    /// `smallest_cluster`-superset model collapses every sub-family of a family
    /// to the SAME whole-family cluster, so the reachable set is BOUNDED — one
    /// enumerated cluster per family, NOT combinatorial).  Each case here is a
    /// no-CPU precompile shard carrying a STRICT SUBSET of its family's chips;
    /// after canonicalization the chip-SET must equal an enumerated cluster.
    #[test]
    fn precompile_subfamily_coverage_is_general_and_bounded() {
        use std::collections::BTreeMap;
        use std::str::FromStr;
        let cfg = CoreShapeConfig::<p3_koala_bear::KoalaBear>::default();
        let machine_shape = zkm_pcs::stacked_shapes::build_mips_machine_shape();
        let base = |extra: &[(&str, usize)]| -> BTreeMap<String, usize> {
            let mut m: BTreeMap<String, usize> = [
                ("Byte", 1 << 16),
                ("Program", 1 << 18),
                ("Global", 128),
                ("MemoryLocal", 16),
                ("SyscallPrecompile", 16),
            ]
            .into_iter()
            .map(|(n, h)| (n.to_string(), h))
            .collect();
            for (n, h) in extra {
                m.insert(n.to_string(), *h);
            }
            m
        };
        // (label, present-precompile-subset) — each a STRICT subset of its family.
        let cases: &[(&str, &[(&str, usize)])] = &[
            // sha256: the OTHER half (ShaCompress-only, no ShaExtend).
            ("sha256_compress_only", &[("ShaCompress", 64), ("ShaCompressControl", 16)]),
            // keccak worker WITHOUT its control twin.
            ("keccak_worker_only", &[("KeccakSponge", 32)]),
            // secp256k1: only AddAssign (no Double/Decompress).
            ("k256_add_only", &[("Secp256k1AddAssign", 32)]),
            // ed25519: only EdAddAssign (no EdDecompress).
            ("ed25519_add_only", &[("EdAddAssign", 32)]),
        ];
        for (label, extra) in cases {
            let raw = base(extra);
            let shape = cfg.find_canonical_cluster_shape_from_raw(&raw).unwrap_or_else(|| {
                panic!("[{label}] sub-family shard must canonicalize to a cluster (was None)")
            });
            let present_ids: std::collections::BTreeSet<MipsAirId> =
                shape.iter().map(|(id, _)| *id).collect();
            let enumerated = machine_shape.chip_clusters.iter().any(|c| {
                let ids: std::collections::BTreeSet<MipsAirId> =
                    c.iter().filter_map(|n| MipsAirId::from_str(n).ok()).collect();
                ids == present_ids
            });
            assert!(
                enumerated,
                "[{label}] canonicalized chip-SET must equal an enumerated cluster; got {present_ids:?}"
            );
        }
    }
}

/// Canonicalize a fixed record shape UP to the smallest stacked-shapes
/// cluster that contains its chip set (VERIFY_VK multi-shard coverage).
///
/// Chip sets are event-driven: a guest that never executes (say) a MISC
/// instruction drops `MiscInstrs` from its execution shards, so the
/// per-shard chip-set space is combinatorial and can never be fully
/// pre-enumerated into the vk_map.  SP1 solves this by making core
/// shapes carry the FULL cluster chip set (zero-event chips emit
/// shape-height padding traces — Ziren tracegen already honors this via
/// `fixed_log2_rows`).  This post-pass extends `record.shape` with the
/// missing cluster chips at log-height 1 so every shard of a given type
/// presents the canonical chip set to the recursion layer.
///
/// No-op when the record has no shape or no cluster contains its set
/// (the recursion vk lookup will then fail loudly with the digest).
pub fn canonicalize_shape_to_cluster(record: &mut ExecutionRecord) {
    let Some(shape) = record.shape.as_mut() else { return };
    canonicalize_shape(shape);
}

/// `Shape`-level core of [`canonicalize_shape_to_cluster`]: extend `shape`
/// with the missing chips of the smallest superset stacked-shapes cluster at
/// log-height 1.  Shared by the record post-pass (FIX-on) and the read-only
/// [`CoreShapeConfig::find_canonical_cluster_shape`] (FIX-off band-cap).
pub fn canonicalize_shape(shape: &mut Shape<MipsAirId>) {
    use std::collections::BTreeSet;
    use std::str::FromStr;
    let present: BTreeSet<MipsAirId> = shape.iter().map(|(k, _)| *k).collect();
    let clusters = zkm_pcs::stacked_shapes::build_mips_machine_shape().chip_clusters;
    // Parse each cluster's names into MipsAirIds (skip names without a
    // live machine id) and pick the smallest superset cluster.
    let mut best: Option<BTreeSet<MipsAirId>> = None;
    for cluster in clusters.iter() {
        let ids: BTreeSet<MipsAirId> = cluster
            .iter()
            .filter_map(|n| MipsAirId::from_str(n).ok())
            .collect();
        if present.is_subset(&ids)
            && best.as_ref().map(|b| ids.len() < b.len()).unwrap_or(true)
        {
            best = Some(ids);
        }
    }
    if let Some(cluster) = best {
        for id in cluster {
            if !present.contains(&id) {
                shape.insert(id, 1);
            }
        }
    }
}

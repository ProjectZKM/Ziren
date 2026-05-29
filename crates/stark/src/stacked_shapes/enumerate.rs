//! Shape enumeration helpers (the task phase 2 — tactic (b)).
//!
//! Produces the concrete list of `CoreProofShape`s used to index the
//! VK map.  Under tactic (b), shapes are quantized to a small number
//! of "size-class bands" per chip cluster, giving ~thousands of
//! representative shapes instead of the ~1.25M per-chip cartesian
//! currently produced by [`crate::shape::CoreShapeConfig::all_shapes`].
//!
//! This module doesn't take a dependency on `zkm_core_machine` (would
//! be a circular dep) — chip names are supplied as string literals,
//! derived from analysis of `crates/core/machine/src/mips/mod.rs`.
//!
//! ## Cluster list
//!
//! Curated from Ziren's MIPS chip inventory + the chip_clusters
//! pattern:
//!
//! | Cluster              | Chip family                                              |
//! |----------------------|----------------------------------------------------------|
//! | `cluster_preprocessed` | `Program`, `Byte` — always present                     |
//! | `cluster_core_base`  | CPU + ALU + mem-instrs + syscall-core (plumbing)         |
//! | `cluster_memory`     | `cluster_core_base` ∪ memory init/finalize + global      |
//! | `cluster_keccak`     | core + KeccakSponge                                      |
//! | `cluster_sha256`     | core + Sha256Extend + Sha256Compress                     |
//! | `cluster_poseidon2`  | core + Poseidon2Permute                                  |
//! | `cluster_k256`       | core + Secp256k1 add/double/decompress                   |
//! | `cluster_p256`       | core + Secp256r1 add/double/decompress                   |
//! | `cluster_bn254`      | core + Bn254 add/double/fp/fp2                           |
//! | `cluster_bls12_381`  | core + Bls12_381 add/double/decompress/fp/fp2            |
//! | `cluster_ed25519`    | core + Ed25519 add/decompress                            |
//! | `cluster_uint256`    | core + Uint256Mul + U256x2048Mul                         |
//!
//! ~12 clusters.  At ~10-20 size classes × ~5 padding-col variants
//! each, the enumeration produces roughly 600-1200 shapes — a
//! ~1000-2000× reduction from the current 1.25M.

use std::collections::BTreeSet;

use super::types::{consts, CoreProofShape, MachineShape, ZKMNormalizeInputShape};

/// The small set of always-present chip names shared by every
/// cluster (preprocessed-only chips).
fn preprocessed_chips() -> &'static [&'static str] {
    &["Program", "Byte"]
}

/// Baseline core-CPU chip set that every workload includes.  This is
/// the smallest practical shard shape (degenerate tiny programs).
fn core_base_chips() -> &'static [&'static str] {
    &[
        "Cpu",
        "AddSub",
        "Bitwise",
        "Mul",
        "DivRem",
        "Lt",
        "CloClz",
        "ShiftLeft",
        "ShiftRight",
        "Branch",
        "Jump",
        "MemoryInstrs",
        "MemoryLocal",
        "MovCond",
        "MiscInstrs",
        "SyscallInstrs",
        "SyscallCore",
    ]
}

/// #517 / Phase A: "minimal core" subset for simple CPU programs that
/// don't exercise every ALU/control chip.  Real-shard chips are filtered
/// by `MachineAir::included(&shard)` (e.g.
/// `crates/core/machine/src/alu/clo_clz/mod.rs:168` — CloClz only
/// included when `cloclz_events` non-empty).  A fibonacci-style
/// arithmetic loop calls `AddSub` + `DivRem` + `Branch` + `Jump` +
/// `MemoryInstrs` + `MemoryLocal` + `SyscallCore`/`SyscallInstrs` + the
/// `Cpu` clock — strict subset of [`core_base_chips`].  Without this
/// cluster the runtime shape_key (which hashes chip names + per-chip
/// widths in `LogUpEvaluations.chip_openings`) misses every enumerator
/// dummy keyed on the 17-chip `core_base` set.  See `#516`
/// `project_optionC_enumerator_fix.md` for the missing-VK trace.
fn minimal_core_chips() -> &'static [&'static str] {
    &[
        "Cpu",
        "AddSub",
        "DivRem",
        "Branch",
        "Jump",
        "MemoryInstrs",
        "MemoryLocal",
        "MiscInstrs",
        "SyscallInstrs",
        "SyscallCore",
    ]
}

/// Memory-shard chip set — adds the global memory init/finalize chips
/// that only appear in the first and last shards.
fn memory_cluster_extras() -> &'static [&'static str] {
    &["MemoryGlobalInit", "MemoryGlobalFinalize", "Global"]
}

/// #517: bare memory-boundary chip set (no CPU/ALU).  When
/// `pack_memory_events_into_last_record` is false (e.g. when the
/// program emits precompile shards) `record::split` emits a dedicated
/// shard containing only global memory + the `Global` infrastructure
/// chip.  Mirrors SP1's `memory_boundary_cluster`
/// (`/tmp/sp1/crates/core/machine/src/riscv/mod.rs:391`).
fn memory_boundary_only_extras() -> &'static [&'static str] {
    &["MemoryGlobalInit", "MemoryGlobalFinalize", "Global"]
}

/// #517: shared per-precompile-shard infrastructure (no CPU/ALU).
/// Mirrors SP1's `base_precompile_cluster`
/// (`/tmp/sp1/crates/core/machine/src/riscv/mod.rs:324`).  Precompile
/// shards never contain `Cpu` (see
/// `crates/core/machine/src/cpu/trace.rs:107` —
/// `Cpu::included = shard.contains_cpu()`); they include only the
/// precompile-specific chips + `SyscallPrecompile` + `MemoryLocal` +
/// `Global`.
fn precompile_base_chips() -> &'static [&'static str] {
    &["SyscallPrecompile", "MemoryLocal", "Global"]
}

/// Per-precompile chip family extras.  Each is added on top of
/// `core_base_chips` to form a precompile-specific cluster.
///
/// Names must match `MachineAir::name()` outputs exactly — see
/// `crates/core/machine/src/syscall/precompiles/*/trace.rs` and
/// `weierstrass_*.rs` for sources.  `ZKMProofShape::generate` filters
/// shapes against the live machine's chip set as defense-in-depth, but
/// keeping this list correct lets `to_ordered_shape` produce the
/// expected per-cluster shapes.
fn precompile_families() -> &'static [(&'static str, &'static [&'static str])] {
    &[
        ("keccak", &["KeccakSponge"]),
        ("sha256", &["ShaExtend", "ShaCompress"]),
        ("poseidon2", &["Poseidon2Permute"]),
        (
            "k256",
            &[
                "Secp256k1AddAssign",
                "Secp256k1DoubleAssign",
                "Secp256k1Decompress",
            ],
        ),
        (
            "p256",
            &[
                "Secp256r1AddAssign",
                "Secp256r1DoubleAssign",
                "Secp256r1Decompress",
            ],
        ),
        (
            "bn254",
            &[
                "Bn254AddAssign",
                "Bn254DoubleAssign",
                "Bn254FpOpAssign",
                "Bn254Fp2MulAssign",
                "Bn254Fp2AddSubAssign",
            ],
        ),
        (
            "bls12_381",
            &[
                "Bls12381AddAssign",
                "Bls12381DoubleAssign",
                "Bls12381Decompress",
                "Bls12381FpOpAssign",
                // Note: upstream ID has typo `Bls12831` (should be `Bls12381`).
                // Carry the typo so chip names match the live machine.
                "Bls12831Fp2MulAssign",
                "Bls12831Fp2AddSubAssign",
            ],
        ),
        ("ed25519", &["EdAddAssign", "EdDecompress"]),
        ("uint256", &["Uint256MulMod", "U256XU2048Mul"]),
        ("boolean_circuit_garble", &["BooleanCircuitGarble"]),
        ("syslinux", &["SysLinux"]),
    ]
}

fn set_from(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

fn extend_cluster(base: &BTreeSet<String>, extra: &[&str]) -> BTreeSet<String> {
    let mut s = base.clone();
    for name in extra {
        s.insert(name.to_string());
    }
    s
}

/// Build the full [`MachineShape`] for Ziren — curated clusters
/// covering every production workload class.
///
/// #517: post-Phase-A this returns ~28 clusters (was 13 in #516):
/// 4 core variants × {bare, +memory_boundary} + 1 memory-boundary-only
/// + 12 precompile-only clusters (no CPU, mirrors SP1's structure).
/// See `project_enumerator_chipset_axis.md`.
#[must_use]
pub fn build_mips_machine_shape() -> MachineShape {
    let preprocessed = set_from(preprocessed_chips());
    let core_base = {
        let mut s = preprocessed.clone();
        for name in core_base_chips() {
            s.insert(name.to_string());
        }
        s
    };
    let minimal_core = {
        let mut s = preprocessed.clone();
        for name in minimal_core_chips() {
            s.insert(name.to_string());
        }
        s
    };
    let memory = extend_cluster(&core_base, memory_cluster_extras());
    let memory_minimal = extend_cluster(&minimal_core, memory_cluster_extras());
    // Memory-boundary-only cluster (no CPU/ALU) — for shards that
    // contain only global memory init/finalize events.
    let memory_only =
        extend_cluster(&preprocessed, memory_boundary_only_extras());
    // Per-precompile base (preprocessed + SyscallPrecompile +
    // MemoryLocal + Global; no CPU).
    let precompile_base = extend_cluster(&preprocessed, precompile_base_chips());

    let mut clusters: Vec<BTreeSet<String>> = vec![
        // Core variants (no precompile chips).
        minimal_core.clone(),
        memory_minimal.clone(),
        core_base.clone(),
        memory.clone(),
        // Memory-boundary-only (no CPU).
        memory_only,
    ];
    // Per-precompile clusters: WITH core_base (matches legacy
    // 13-cluster enumeration — keep for backwards compat so workloads
    // already covered by #516 stay covered).
    for (_, extras) in precompile_families() {
        clusters.push(extend_cluster(&memory, extras));
    }
    // #517: per-precompile clusters WITHOUT core_base (matches SP1's
    // per-precompile shard pattern — these fire when a program emits
    // dedicated precompile shards).
    for (_, extras) in precompile_families() {
        clusters.push(extend_cluster(&precompile_base, extras));
    }

    MachineShape::new(clusters)
}

/// Maximum (preprocessed_multiple, main_multiple) bound — SP1 derives
/// these dynamically from `MAX_PROGRAM_SIZE × NUM_PREPROCESSED_COLS`
/// and `PADDED_ELEMENT_THRESHOLD` (potentially hundreds). Ziren caps
/// at a tractable value here so the resulting vk_map.bin stays under
/// ~20K entries (full SP1-style derivation requires a separate regen
/// budget; current cap covers all real programs observed in the
/// production test suite).
///
/// SP1 reference:
/// `max_main_multiple_for_preprocessed_multiple`.
const MAX_AREA_MULTIPLE: usize = 12;

/// Per-preprocessed cap on main_multiple. SP1's formula:
/// `(PADDED_ELEMENT_THRESHOLD - p * 2^STACK).div_ceil(2^STACK)`. Here
/// we use a flat cap; main_multiple ranges over `1..=MAX_AREA_MULTIPLE`
/// independent of `p`. This keeps the cartesian bounded but covers
/// any real program whose `main_area / 2^21 ≤ 32`.
fn max_main_multiple_for_preprocessed(_p: usize) -> usize {
    MAX_AREA_MULTIPLE
}

/// Padding column variants. SP1's `max_num_padding_cols` is
/// `(2^LOG_STACKING_HEIGHT).div_ceil(2^CORE_MAX_LOG_ROW_COUNT)`;
/// in Ziren both shift by 21 vs 22 → ratio 0.5, ceil = 1.
/// SP1 enumerates `1..=max_num_padding_cols` (range `[1, 1]`).
/// We extend slightly to cover trace-width edge cases observed in
/// real programs (precompile-heavy clusters can need more paddings).
pub fn padding_col_variants() -> Vec<usize> {
    vec![0, 1, 2, 4, 8]
}

/// Backwards-compat shim — kept so external callers don't break.
/// Returns the consecutive-integer enumeration used by
/// `create_all_input_shapes`.
pub fn area_multiples() -> Vec<usize> {
    (1..=MAX_AREA_MULTIPLE).collect()
}

/// Backwards-compat shim — full integer cartesian instead of
/// power-of-2 banded diagonal.
pub fn size_class_bands() -> Vec<(usize, usize)> {
    let mut out = Vec::with_capacity(MAX_AREA_MULTIPLE * MAX_AREA_MULTIPLE);
    for p in 1..=MAX_AREA_MULTIPLE {
        for a in 1..=max_main_multiple_for_preprocessed(p) {
            out.push((p, a));
        }
    }
    out
}

/// Produce every `CoreProofShape` — the top-level enumeration entry
/// point. Now mirrors SP1's
/// `create_all_input_shapes`
/// using **consecutive integer** ranges for `preprocessed_multiple`
/// and `main_multiple` instead of Ziren's previous power-of-2-only
/// `[1, 2, 4, 8, 16, 32]`. The power-of-2 list missed real programs
/// like hello_world whose actual shape sits between powers (e.g.
/// `prep_mult=3` or `main_mult=5`), causing "Invalid verification
/// key" lookups.
#[must_use]
pub fn create_all_input_shapes(machine_shape: &MachineShape) -> Vec<CoreProofShape> {
    let paddings = padding_col_variants();
    let unit: usize = 1usize << consts::LOG_STACKING_HEIGHT;

    let est_capacity = machine_shape.chip_clusters.len()
        * MAX_AREA_MULTIPLE
        * MAX_AREA_MULTIPLE
        * paddings.len()
        * paddings.len();
    let mut out: Vec<CoreProofShape> = Vec::with_capacity(est_capacity);
    for cluster in &machine_shape.chip_clusters {
        for prep_mult in 1..=MAX_AREA_MULTIPLE {
            for main_mult in 1..=max_main_multiple_for_preprocessed(prep_mult) {
                for prep_pad in &paddings {
                    for main_pad in &paddings {
                        out.push(CoreProofShape {
                            shard_chip_names: cluster.clone(),
                            preprocessed_area: prep_mult * unit,
                            main_area: main_mult * unit,
                            preprocessed_padding_cols: *prep_pad,
                            main_padding_cols: *main_pad,
                        });
                    }
                }
            }
        }
    }
    out
}

/// Wrap a [`CoreProofShape`] into a Normalize-stage input shape.
/// The stacking/FRI parameters are fixed to the constants defined in
/// [`super::types::consts`].
#[must_use]
pub fn normalize_input_shape_from_core(shape: CoreProofShape) -> ZKMNormalizeInputShape {
    ZKMNormalizeInputShape {
        proof_shapes: vec![shape],
        max_log_row_count: consts::CORE_MAX_LOG_ROW_COUNT,
        log_blowup: consts::LOG_BLOWUP,
        log_stacking_height: consts::LOG_STACKING_HEIGHT as usize,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_shape_has_expected_cluster_count() {
        let ms = build_mips_machine_shape();
        // #517 (Phase A): post-restructure clusters =
        //   2 minimal-core (bare + memory_boundary)
        // + 2 core_base    (bare + memory_boundary)
        // + 1 memory_boundary_only
        // + 12 per-precompile WITH core (legacy)
        // + 12 per-precompile WITHOUT core (SP1-style)
        // = 29.  (Was 13 in #516.)
        let pc = precompile_families().len();
        assert_eq!(ms.chip_clusters.len(), 5 + 2 * pc);
    }

    #[test]
    fn all_clusters_contain_preprocessed_chips() {
        let ms = build_mips_machine_shape();
        for cluster in &ms.chip_clusters {
            assert!(cluster.contains("Program"), "cluster missing Program: {:?}", cluster);
            assert!(cluster.contains("Byte"), "cluster missing Byte: {:?}", cluster);
        }
    }

    /// #517: not every cluster contains Cpu after Phase A — the
    /// memory-boundary-only + precompile-only clusters intentionally
    /// have no CPU (mirrors runtime shard boundaries).  At least one
    /// cluster MUST contain Cpu so simple CPU workloads have a target.
    #[test]
    fn at_least_one_cluster_contains_core_cpu() {
        let ms = build_mips_machine_shape();
        assert!(
            ms.chip_clusters.iter().any(|c| c.contains("Cpu")),
            "no cluster contains Cpu — simple CPU workloads have no target",
        );
    }

    /// #517: the memory-boundary-only cluster covers shards emitted by
    /// `record::split` when `pack_memory_events_into_last_record` is
    /// false.  Verify it exists + has the right shape (no Cpu, has
    /// MemoryGlobal*).
    #[test]
    fn memory_boundary_only_cluster_present() {
        let ms = build_mips_machine_shape();
        let mbo = ms.chip_clusters.iter().find(|c| {
            !c.contains("Cpu")
                && c.contains("MemoryGlobalInit")
                && c.contains("MemoryGlobalFinalize")
        });
        assert!(mbo.is_some(), "memory_boundary_only cluster missing");
    }

    #[test]
    fn shape_enumeration_count_is_tractable() {
        let ms = build_mips_machine_shape();
        let shapes = create_all_input_shapes(&ms);
        // #517: MAX_AREA_MULTIPLE=12 with ~29 clusters →
        // 29 × 12 × 12 × 5 × 5 = 104,400 shapes. Bumped cap to 120K
        // (was 50K when only 13 clusters).
        assert!(
            shapes.len() <= 120_000,
            "shape count {} exceeds 120000 — tune MAX_AREA_MULTIPLE/paddings",
            shapes.len()
        );
        assert!(shapes.len() >= 100, "shape count {} too small — missing clusters?", shapes.len());
    }

    #[test]
    fn size_class_bands_are_monotone_in_main_for_fixed_prep() {
        let bands = size_class_bands();
        // For any fixed prep multiple, main_mult entries should be non-decreasing.
        // After SP1-style port: prep ranges over [1..=MAX_AREA_MULTIPLE].
        for prep in 1..=MAX_AREA_MULTIPLE {
            let mut mains: Vec<usize> = bands
                .iter()
                .filter(|(p, _)| *p == prep)
                .map(|(_, m)| *m)
                .collect();
            let sorted = mains.clone();
            mains.sort();
            assert_eq!(mains, sorted, "bands for prep={} are not monotone in main", prep);
        }
    }

    /// Regression for #75: hello_world produced an
    /// (preprocessed_multiple, main_multiple) combination not on
    /// powers-of-2, so the old `area_multiples = [1,2,4,8,16,32]`
    /// enumeration missed its shape and "Invalid verification key"
    /// fired. Now consecutive integers `1..=MAX_AREA_MULTIPLE` are
    /// enumerated (matching SP1's
    /// `create_all_input_shapes`).
    #[test]
    fn area_multiples_are_consecutive_integers() {
        let ms = area_multiples();
        let expected: Vec<usize> = (1..=MAX_AREA_MULTIPLE).collect();
        assert_eq!(ms, expected, "area_multiples must be consecutive integers");
    }
}

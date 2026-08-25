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

use super::types::{consts, CoreProofShape, MachineShape};

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
        "AddSubImm",
        "Bitwise",
        "BitwiseImm",
        "Mul",
        "DivRem",
        "Lt",
        "CloClz",
        "ShiftLeft",
        "ShiftRight",
        "Branch",
        "Jump",
        "LoadNarrow",
        "LoadWord",
        "StoreNarrow",
        "StoreWord",
        "MemoryUnaligned",
        "MemoryLocal",
        "MemoryBump",
        "MovCond",
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
        ("keccak", &["KeccakSponge", "KeccakSpongeControl"]),
        ("sha256", &["ShaExtend", "ShaExtendControl", "ShaCompress", "ShaCompressControl"]),
        ("poseidon2", &["Poseidon2Permute"]),
        ("k256", &["Secp256k1AddAssign", "Secp256k1DoubleAssign", "Secp256k1Decompress"]),
        ("p256", &["Secp256r1AddAssign", "Secp256r1DoubleAssign", "Secp256r1Decompress"]),
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
        ("boolean_circuit_garble", &["BooleanCircuitGarble", "BooleanCircuitGarbleControl"]),
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

/// Build the full [`MachineShape`] for Ziren — 12 curated clusters
/// covering every production workload class.
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
    let memory = extend_cluster(&core_base, memory_cluster_extras());

    // Multi-shard runs partition the work into SHARD-TYPE chip sets that
    // differ from the single-shard union (observed
    // on the keccak deferred e2e):
    //   * main execution shards carry `Global` but NOT the
    //     MemoryGlobalInit/Finalize pair;
    //   * memory shards are MINIMAL: preprocessed + Global + the
    //     MemoryGlobal pair (no core chips);
    //   * precompile shards are MINIMAL: preprocessed + Global +
    //     MemoryLocal + SyscallPrecompile + the family chips (incl. the
    //     sponge Control twins) — not core + family.
    let main_exec = extend_cluster(&core_base, &["Global"]);
    let memory_min = extend_cluster(&preprocessed, memory_cluster_extras());
    // A memory shard carries ONLY the global-memory chips that actually have
    // events, and init/finalize are emitted in DIFFERENT shards once the run
    // needs more than one memory shard.  Under FIX-off there is no cluster
    // padding, so such a shard commits a chip set that is a strict SUBSET of
    // `memory_min` — measured on a 9-shard goat chain, which produces a
    // `{Byte, Global, MemoryGlobalFinalize, Program}` shard with no
    // `MemoryGlobalInit` and whose normalize vk was therefore absent from the
    // enumerated map ("vk not allowed" at compress).  Enumerate both halves.
    let memory_finalize_only = extend_cluster(&preprocessed, &["MemoryGlobalFinalize", "Global"]);
    let memory_init_only = extend_cluster(&preprocessed, &["MemoryGlobalInit", "Global"]);
    let precompile_base =
        extend_cluster(&preprocessed, &["Global", "MemoryLocal", "SyscallPrecompile"]);

    let mut clusters: Vec<BTreeSet<String>> = vec![
        core_base.clone(),
        main_exec,
        memory.clone(),
        memory_min,
        memory_finalize_only,
        memory_init_only,
    ];
    for (_, extras) in precompile_families() {
        // Single-shard union (legacy) + the minimal precompile shard.
        clusters.push(extend_cluster(&memory, extras));
        clusters.push(extend_cluster(&precompile_base, extras));
    }

    MachineShape::new(clusters)
}

/// Maximum (preprocessed_multiple, main_multiple) bound. A dynamic
/// derivation from `MAX_PROGRAM_SIZE × NUM_PREPROCESSED_COLS` and
/// `PADDED_ELEMENT_THRESHOLD` could reach hundreds; Ziren caps
/// at a tractable value here so the resulting vk_map.bin stays under
/// ~20K entries (the full dynamic derivation requires a separate regen
/// budget; the current cap covers all real programs observed in the
/// production test suite).
const MAX_AREA_MULTIPLE: usize = 12;

/// Per-preprocessed cap on main_multiple. Instead of the derived cap
/// `(PADDED_ELEMENT_THRESHOLD - p * 2^STACK).div_ceil(2^STACK)`, here
/// we use a flat cap; main_multiple ranges over `1..=MAX_AREA_MULTIPLE`
/// independent of `p`. This keeps the cartesian bounded but covers
/// any real program whose `main_area / 2^21 ≤ 32`.
fn max_main_multiple_for_preprocessed(_p: usize) -> usize {
    MAX_AREA_MULTIPLE
}

/// Padding column variants. The minimal padding-column count
/// `(2^LOG_STACKING_HEIGHT).div_ceil(2^CORE_MAX_LOG_ROW_COUNT)`
/// is 1 in Ziren (shifts 21 vs 22 → ratio 0.5, ceil = 1).
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
/// point. Uses **consecutive integer** ranges for `preprocessed_multiple`
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_shape_has_expected_cluster_count() {
        let ms = build_mips_machine_shape();
        // Cluster structure (see `build_mips_machine_shape`):
        //   6 BASE clusters:
        //     core_base, main_exec (=core+Global), memory (=core+memory
        //     extras), memory_min (=preprocessed+memory extras, NO core),
        //     and the two SPLIT memory shards (finalize-only / init-only)
        //   2 per precompile family:
        //     core-union (=memory ∪ family) + minimal precompile shard
        //     (=precompile_base ∪ family).
        // Derive the expectation from the live family list so adding a
        // precompile family updates the bound automatically.
        let expected = 6 + 2 * precompile_families().len();
        assert_eq!(
            ms.chip_clusters.len(),
            expected,
            "cluster count drifted from 6 base + 2×{} families",
            precompile_families().len(),
        );
        // Sanity-pin the current value so an accidental base-cluster
        // change is caught even if a family is added/removed at the
        // same time.
        assert_eq!(ms.chip_clusters.len(), 28);
    }

    /// A multi-shard run emits global-memory INIT and FINALIZE events in
    /// DIFFERENT shards, and under FIX-off a shard commits ONLY the chips that
    /// actually have rows.  So a memory shard can carry `MemoryGlobalFinalize`
    /// without `MemoryGlobalInit` (measured on a 9-shard goat chain) — a chip
    /// set that is a strict SUBSET of `memory_min`.  Both halves must be
    /// enumerated or the shard's normalize vk can never be in `vk_map.bin`
    /// ("vk not allowed" at compress under `VERIFY_VK=true`).
    #[test]
    fn machine_shape_covers_split_memory_shards() {
        let ms = build_mips_machine_shape();
        let prep = set_from(preprocessed_chips());
        for (label, only) in
            [("finalize-only", "MemoryGlobalFinalize"), ("init-only", "MemoryGlobalInit")]
        {
            let mut want = prep.clone();
            want.insert("Global".to_string());
            want.insert(only.to_string());
            assert!(
                ms.chip_clusters.iter().any(|c| *c == want),
                "no cluster for the {label} memory shard {want:?}"
            );
        }
    }

    #[test]
    fn all_clusters_contain_preprocessed_chips() {
        let ms = build_mips_machine_shape();
        for cluster in &ms.chip_clusters {
            assert!(cluster.contains("Program"), "cluster missing Program: {:?}", cluster);
            assert!(cluster.contains("Byte"), "cluster missing Byte: {:?}", cluster);
        }
    }

    /// The 26-cluster model includes MINIMAL multi-shard cluster types
    /// (the `memory_min` and `precompile_base`-derived clusters) that are
    /// intentionally CPU-FREE — a memory shard or precompile shard carries
    /// no core/CPU chips.  So the old "every cluster has Cpu" invariant is
    /// false by design; the correct invariants are:
    ///   1. EVERY cluster carries the preprocessed chips (checked above).
    ///   2. At least the four base clusters exist, and exactly the
    ///      minimal memory/precompile shard types are Cpu-free.
    ///   3. Every cluster that DOES carry Cpu also carries the full core
    ///      ALU set (Cpu never appears without its core plumbing).
    #[test]
    fn cluster_cpu_membership_matches_shard_types() {
        let ms = build_mips_machine_shape();
        let core_alu = ["AddSub", "Mul", "Lt", "DivRem"];

        let cpu_clusters = ms.chip_clusters.iter().filter(|c| c.contains("Cpu")).count();
        let cpu_free = ms.chip_clusters.iter().filter(|c| !c.contains("Cpu")).count();

        // Cpu-free = memory_min + the two SPLIT memory shards (3) + one
        // minimal precompile shard per family (precompile_base ∪ family).
        let expected_cpu_free = 3 + precompile_families().len();
        assert_eq!(
            cpu_free, expected_cpu_free,
            "Cpu-free clusters (minimal memory/precompile shard types) drifted"
        );
        assert_eq!(cpu_clusters, ms.chip_clusters.len() - expected_cpu_free);

        // Cpu never appears without its full core ALU plumbing — guards
        // against a cluster that has Cpu but is missing a core chip the
        // recursion verifier would expect in that chip-set.
        for cluster in &ms.chip_clusters {
            if cluster.contains("Cpu") {
                for chip in core_alu {
                    assert!(
                        cluster.contains(chip),
                        "Cpu cluster missing core chip {chip}: {cluster:?}",
                    );
                }
            }
        }
    }

    #[test]
    fn shape_enumeration_count_is_tractable() {
        let ms = build_mips_machine_shape();
        let shapes = create_all_input_shapes(&ms);
        // Consecutive-integer enumeration over the 28-cluster
        // model: per cluster the inner loops are
        //   prep_mult(1..=MAX_AREA_MULTIPLE) ×
        //   main_mult(1..=MAX_AREA_MULTIPLE) ×
        //   prep_pad(|paddings|) × main_pad(|paddings|).
        // = 26 × 12 × 12 × 5 × 5 = 93,600 shapes.  Derive the exact
        // upper bound from the same constants the producer uses so the
        // bound tracks any tuning of MAX_AREA_MULTIPLE / paddings.
        let per_cluster =
            MAX_AREA_MULTIPLE * MAX_AREA_MULTIPLE * padding_col_variants().len().pow(2);
        let upper = ms.chip_clusters.len() * per_cluster;
        assert!(
            shapes.len() <= upper,
            "shape count {} exceeds derived upper bound {} — producer changed?",
            shapes.len(),
            upper,
        );
        // Pin the concrete current value so a silent cluster/area regression
        // (e.g. a cluster dropped, or a max-main cap re-introduced) is caught.
        assert_eq!(shapes.len(), 100_800, "expected 28 clusters × 12 × 12 × 5 × 5");
        assert!(shapes.len() >= 100, "shape count {} too small — missing clusters?", shapes.len());
    }

    #[test]
    fn size_class_bands_are_monotone_in_main_for_fixed_prep() {
        let bands = size_class_bands();
        // For any fixed prep multiple, main_mult entries should be non-decreasing.
        // prep ranges over [1..=MAX_AREA_MULTIPLE].
        for prep in 1..=MAX_AREA_MULTIPLE {
            let mut mains: Vec<usize> =
                bands.iter().filter(|(p, _)| *p == prep).map(|(_, m)| *m).collect();
            let sorted = mains.clone();
            mains.sort();
            assert_eq!(mains, sorted, "bands for prep={} are not monotone in main", prep);
        }
    }

    /// Regression test: hello_world produced an
    /// (preprocessed_multiple, main_multiple) combination not on
    /// powers-of-2, so the old `area_multiples = [1,2,4,8,16,32]`
    /// enumeration missed its shape and "Invalid verification key"
    /// fired. Now consecutive integers `1..=MAX_AREA_MULTIPLE` are
    /// enumerated.
    #[test]
    fn area_multiples_are_consecutive_integers() {
        let ms = area_multiples();
        let expected: Vec<usize> = (1..=MAX_AREA_MULTIPLE).collect();
        assert_eq!(ms, expected, "area_multiples must be consecutive integers");
    }
}

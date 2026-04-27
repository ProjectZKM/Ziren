//! Shape enumeration helpers (task #20 phase 2 — tactic (b)).
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

    let mut clusters: Vec<BTreeSet<String>> = vec![core_base.clone(), memory.clone()];
    for (_, extras) in precompile_families() {
        clusters.push(extend_cluster(&memory, extras));
    }

    MachineShape::new(clusters)
}

/// Area multiples used to enumerate `(preprocessed_multiple,
/// main_multiple)` combinations.  Areas are measured in
/// stacking-height multiples (`2^LOG_STACKING_HEIGHT = 2^21 = ~2.1M
/// cells` per unit).
///
/// The full free cartesian over this list × itself matches
/// [`sp1_prover::shapes::create_all_input_shapes`](file:///tmp/sp1/crates/prover/src/shapes.rs#L580),
/// replacing the previous hand-picked `size_class_bands` which
/// dropped real-program (prep_area, main_area) points and produced
/// vk_maps missing fibonacci-style compress shapes.
pub fn area_multiples() -> Vec<usize> {
    vec![1, 2, 4, 8, 16, 32]
}

/// Free cartesian of `(preprocessed_multiple, main_multiple)` —
/// matches SP1's enumeration shape rather than Ziren's old banded
/// diagonal.
pub fn size_class_bands() -> Vec<(usize, usize)> {
    let m = area_multiples();
    let mut out = Vec::with_capacity(m.len() * m.len());
    for p in &m {
        for a in &m {
            out.push((*p, *a));
        }
    }
    out
}

/// Padding column variants to enumerate.  In the upstream pipeline the
/// padding is determined by the area + stacking stripe size; Ziren's
/// variant stays simple and enumerates a fixed set up to the max allowed
/// by `2^LOG_STACKING_HEIGHT / 2^CORE_MAX_LOG_ROW_COUNT`.
pub fn padding_col_variants() -> Vec<usize> {
    // Typical padding column widths — trace widths are usually
    // 32-512 cols, so we only need a few representative paddings.
    vec![0, 1, 2, 4, 8]
}

/// Produce every `CoreProofShape` under tactic (b) — the top-level
/// enumeration entry point.  Mirrors
/// [`sp1_prover::shapes::create_all_input_shapes`](file:///tmp/sp1/crates/prover/src/shapes.rs#L580)
/// but uses size-class bands instead of free preprocessed_multiple ×
/// main_multiple cartesian.
#[must_use]
pub fn create_all_input_shapes(machine_shape: &MachineShape) -> Vec<CoreProofShape> {
    let bands = size_class_bands();
    let paddings = padding_col_variants();
    let unit: usize = 1usize << consts::LOG_STACKING_HEIGHT;

    let mut out: Vec<CoreProofShape> = Vec::new();
    for cluster in &machine_shape.chip_clusters {
        for (prep_mult, main_mult) in &bands {
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
        // 2 base (core-only, core+memory) + 11 precompile families.
        assert_eq!(ms.chip_clusters.len(), 13);
    }

    #[test]
    fn all_clusters_contain_preprocessed_chips() {
        let ms = build_mips_machine_shape();
        for cluster in &ms.chip_clusters {
            assert!(cluster.contains("Program"), "cluster missing Program: {:?}", cluster);
            assert!(cluster.contains("Byte"), "cluster missing Byte: {:?}", cluster);
        }
    }

    #[test]
    fn all_clusters_contain_core_cpu() {
        let ms = build_mips_machine_shape();
        for cluster in &ms.chip_clusters {
            assert!(cluster.contains("Cpu"), "cluster missing Cpu: {:?}", cluster);
        }
    }

    #[test]
    fn shape_enumeration_count_is_tractable() {
        let ms = build_mips_machine_shape();
        let shapes = create_all_input_shapes(&ms);
        // Upper-bound sanity: 13 clusters × 36 (6×6 area cartesian)
        // × 5 × 5 padding = 11,700. Leave headroom.
        assert!(
            shapes.len() <= 20_000,
            "shape count {} exceeds 20000 — tune clusters/multiples/paddings",
            shapes.len()
        );
        assert!(shapes.len() >= 100, "shape count {} too small — missing clusters?", shapes.len());
    }

    #[test]
    fn size_class_bands_are_monotone_in_main_for_fixed_prep() {
        let bands = size_class_bands();
        // For any fixed prep multiple, main_mult entries should be non-decreasing.
        for &prep in &[1usize, 2, 4, 8, 16, 32] {
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
}

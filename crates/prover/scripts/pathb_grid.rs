//! Normalize-shape grid computation.
//! Replicates the EXACT `shape_at_log_dense` / `log_dense_of` logic from
//! `ZKMProofShape::generate` (shapes.rs small_shapes loop) to compute, per
//! cluster, l_min and the FULL achievable L range up to a cap, and the total
//! distinct normalize-shape count for several window/cap settings.  No VK
//! building — pure combinatorics, so it is fast.
//!
//! Run:
//!   cargo run --release -p zkm-prover --example pathb_grid

use std::collections::{BTreeMap, HashSet};

use p3_koala_bear::KoalaBear;
use zkm_core_machine::mips::MipsAir;
use zkm_pcs::air::MachineAir;
use zkm_pcs::shape::OrderedShape;
use zkm_pcs::stacked_shapes::{build_mips_machine_shape, types::consts};
use zkm_prover::CoreSC;

fn main() {
    let core_machine = MipsAir::machine(CoreSC::default());
    let chips_by_name: BTreeMap<String, _> =
        core_machine.chips().iter().map(|c| (c.name(), c)).collect();
    let machine_shape = build_mips_machine_shape();
    let cube = consts::CORE_MAX_LOG_ROW_COUNT;

    let chip_width = |name: &str| -> usize {
        chips_by_name
            .get(name)
            .map(|c| p3_air::BaseAir::<KoalaBear>::width(*c).max(1))
            .unwrap_or(1)
    };
    let log_dense_of = |os: &OrderedShape| -> usize {
        let total: usize = os
            .inner
            .iter()
            .map(|(name, log_h)| chip_width(name) * (1usize << *log_h))
            .sum();
        if total == 0 {
            0
        } else {
            total.next_power_of_two().trailing_zeros() as usize
        }
    };
    // total_values (= Sum width * 2^h) for AreaOutOfBounds (< 2^30) check.
    let total_values_of = |os: &OrderedShape| -> u128 {
        os.inner
            .iter()
            .map(|(name, log_h)| (chip_width(name) as u128) * (1u128 << *log_h))
            .sum()
    };

    // EXACT port of the shape_at_log_dense closure (shapes.rs:565-616).
    let shape_at_log_dense =
        |names: &[String], fillers: &HashSet<&String>, target: usize| -> Option<OrderedShape> {
            let mut heights: Vec<(String, usize)> = names
                .iter()
                .map(|n| {
                    let h = if n == "Byte" { 16 } else { 1 };
                    (n.clone(), h)
                })
                .collect();
            let area_of = |hs: &[(String, usize)]| -> u128 {
                hs.iter().map(|(n, h)| (chip_width(n) as u128) * (1u128 << *h)).sum()
            };
            let cap_area: u128 = 1u128 << target;
            let mut filler_idx: Vec<usize> = heights
                .iter()
                .enumerate()
                .filter(|(_, (n, _))| fillers.contains(n))
                .map(|(i, _)| i)
                .collect();
            filler_idx.sort_by(|&a, &b| heights[a].0.cmp(&heights[b].0));
            for &i in &filler_idx {
                let mut best = 1usize;
                for h in 1..=cube {
                    let mut trial = heights.clone();
                    trial[i].1 = h;
                    if area_of(&trial) <= cap_area {
                        best = h;
                    } else {
                        break;
                    }
                }
                heights[i].1 = best;
            }
            let os = OrderedShape::from_log2_heights(&heights);
            if log_dense_of(&os) == target {
                Some(os)
            } else {
                None
            }
        };

    // Per-cluster prep (names + fillers), matching generate().
    struct Clu {
        idx: usize,
        names: Vec<String>,
        fillers_owned: Vec<String>,
    }
    let mut clusters: Vec<Clu> = Vec::new();
    for (ci, cluster) in machine_shape.chip_clusters.iter().enumerate() {
        let names: Vec<String> =
            cluster.iter().filter(|n| chips_by_name.contains_key(*n)).cloned().collect();
        if names.is_empty() {
            continue;
        }
        let fillers_owned: Vec<String> = names
            .iter()
            .filter(|n| {
                n.as_str() != "Byte" && chips_by_name[n.as_str()].num_sent_byte_lookups() == 0
            })
            .cloned()
            .collect();
        clusters.push(Clu { idx: ci, names, fillers_owned });
    }

    // Compute the grid for a given (window, hard_cap) pair, replicating the
    // generate() small_shapes loop (including the shared cross-cluster dedup).
    let count_grid = |window: usize, hard_cap: usize, verbose: bool| -> (usize, usize, usize) {
        let mut by_shape: BTreeMap<Vec<(String, usize)>, OrderedShape> = BTreeMap::new();
        let mut global_lmin = usize::MAX;
        let mut global_lmax = 0usize;
        for clu in &clusters {
            let fillers: HashSet<&String> = clu.fillers_owned.iter().collect();
            // l_min: first feasible target in 1..=hard_cap.
            let mut l_min = None;
            for target in 1..=hard_cap {
                if shape_at_log_dense(&clu.names, &fillers, target).is_some() {
                    l_min = Some(target);
                    break;
                }
            }
            let Some(l_min) = l_min else { continue };
            let l_max = (l_min + window).min(hard_cap);
            let mut cl_shapes = 0usize;
            let mut cl_lmax_real = l_min;
            for target in l_min..=l_max {
                if let Some(os) = shape_at_log_dense(&clu.names, &fillers, target) {
                    // AreaOutOfBounds: a real proof at this shape must have
                    // total_values < 2^30 to be provable+verifiable.
                    if total_values_of(&os) >= (1u128 << 30) {
                        continue;
                    }
                    cl_lmax_real = target;
                    let mut inner = os.inner.clone();
                    inner.sort();
                    if by_shape.insert(inner.clone(), OrderedShape { inner }).is_none() {
                        cl_shapes += 1;
                    }
                }
            }
            global_lmin = global_lmin.min(l_min);
            global_lmax = global_lmax.max(cl_lmax_real);
            if verbose {
                println!(
                    "  cluster {:>2} chips={:>2} fillers={:>2} l_min={:>2} l_max={:>2} new_shapes={}",
                    clu.idx,
                    clu.names.len(),
                    clu.fillers_owned.len(),
                    l_min,
                    cl_lmax_real,
                    cl_shapes
                );
            }
        }
        let normalize = by_shape.len();
        (normalize, global_lmin, global_lmax)
    };

    println!("clusters (non-empty) = {}", clusters.len());
    println!();

    // Baseline: window=8, hard_cap=28.
    let (n_base, lmin_b, lmax_b) = count_grid(8, 28, false);
    println!(
        "BASELINE  window=8  hard_cap=28 : normalize_shapes={} (global l_min={} l_max={})  +6 (compress4+def1+shr1) = TOTAL {}",
        n_base, lmin_b, lmax_b, n_base + 6
    );
    println!();

    // Complete grid candidates (window effectively unbounded; hard_cap binds).
    for cap in [28usize, 29, 30] {
        println!("=== COMPLETE window=BIG hard_cap={} (per-cluster verbose) ===", cap);
        let (n, lmin, lmax) = count_grid(usize::MAX / 4, cap, true);
        println!(
            "COMPLETE  hard_cap={} : normalize_shapes={} (global l_min={} l_max={})  +6 = TOTAL {}  [<=2048? {}]",
            cap,
            n,
            lmin,
            lmax,
            n + 6,
            (n + 6) <= 2048
        );
        println!();
    }

    // Also report the per-cluster L spans at cap=30 for the report.
    println!("=== per-cluster L span (cap=30) ===");
    for clu in &clusters {
        let fillers: HashSet<&String> = clu.fillers_owned.iter().collect();
        let mut l_min = None;
        for target in 1..=30 {
            if shape_at_log_dense(&clu.names, &fillers, target).is_some() {
                l_min = Some(target);
                break;
            }
        }
        let Some(l_min) = l_min else { continue };
        let mut achievable: Vec<usize> = Vec::new();
        for target in l_min..=30 {
            if let Some(os) = shape_at_log_dense(&clu.names, &fillers, target) {
                if total_values_of(&os) < (1u128 << 30) {
                    achievable.push(target);
                }
            }
        }
        let mut sample_names = clu.names.clone();
        sample_names.sort();
        let tag = sample_names
            .iter()
            .filter(|n| {
                !["Program", "Byte", "Cpu", "AddSub", "Bitwise", "Mul", "DivRem", "Lt"]
                    .contains(&n.as_str())
            })
            .take(2)
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "  cluster {:>2} chips={:>2} L_achievable={:?} span={} tag=[{}]",
            clu.idx,
            clu.names.len(),
            achievable,
            achievable.len(),
            tag
        );
    }
}

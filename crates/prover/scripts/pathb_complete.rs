//! COMPLETENESS probe (cheap; no heavy proving).
//!
//! Proves the enumeration gap is closed for a real, arbitrary-height
//! shard at L = 29 (which a windowed enum with cap 28 misses):
//!   1. Build the normalize VK for the GREEDY enum shape at (cluster, L=29)
//!      [= what generate() emits] and for a DIFFERENT height distribution at the
//!      SAME (cluster, L=29) [= a "real" shard the enum did NOT explicitly
//!      enumerate].
//!   2. Assert VK_greedy == VK_other  (height-INDEPENDENCE given (cluster,L) —
//!      so ANY real shard landing at L=29 produces this exact key).
//!   3. Assert VK ∈ NEW(274) map and VK ∉ OLD(240) map  (gap-filling key).
//!
//! Run with the SAME convention the regen used (byte-identical VKs):
//!   FIX_CORE_SHAPES=true FIX_RECURSION_SHAPES=true VERIFY_VK=false PATHB_L=29 \
//!   pathb_complete

use std::collections::{BTreeMap, HashSet};

use p3_koala_bear::KoalaBear;
use zkm_core_machine::mips::MipsAir;
use zkm_pcs::air::MachineAir;
use zkm_pcs::shape::OrderedShape;
use zkm_pcs::stacked_shapes::{build_mips_machine_shape, types::consts};
use zkm_pcs::{MachineProver, DIGEST_SIZE};
use zkm_prover::components::DefaultProverComponents;
use zkm_prover::shapes::{ZKMCompressProgramShape, ZKMProofShape};
use zkm_prover::{CoreSC, HashableKey, ZKMProver, VK_MERKLE_TREE_HEIGHT};

fn main() {
    let target_l: usize =
        std::env::var("PATHB_L").ok().and_then(|s| s.parse().ok()).unwrap_or(29);

    let prover = ZKMProver::<DefaultProverComponents>::new();
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
    let log_dense_of = |inner: &[(String, usize)]| -> usize {
        let total: usize = inner.iter().map(|(n, h)| chip_width(n) * (1usize << *h)).sum();
        if total == 0 { 0 } else { total.next_power_of_two().trailing_zeros() as usize }
    };
    let shape_at = |names: &[String], fillers: &HashSet<&String>, target: usize| -> Option<Vec<(String, usize)>> {
        let mut heights: Vec<(String, usize)> =
            names.iter().map(|n| (n.clone(), if n == "Byte" { 16 } else { 1 })).collect();
        let area_of = |hs: &[(String, usize)]| -> u128 {
            hs.iter().map(|(n, h)| (chip_width(n) as u128) * (1u128 << *h)).sum()
        };
        let cap: u128 = 1u128 << target;
        let mut fidx: Vec<usize> = heights
            .iter()
            .enumerate()
            .filter(|(_, (n, _))| fillers.contains(n))
            .map(|(i, _)| i)
            .collect();
        fidx.sort_by(|&a, &b| heights[a].0.cmp(&heights[b].0));
        for &i in &fidx {
            let mut best = 1usize;
            for h in 1..=cube {
                let mut t = heights.clone();
                t[i].1 = h;
                if area_of(&t) <= cap { best = h } else { break }
            }
            heights[i].1 = best;
        }
        if log_dense_of(&heights) == target { Some(heights) } else { None }
    };

    // Pick a cluster that reaches target_l with >= 2 fillers (so a distinct
    // height profile exists).
    let mut chosen: Option<(usize, Vec<String>, Vec<String>)> = None;
    for (ci, cluster) in machine_shape.chip_clusters.iter().enumerate() {
        let names: Vec<String> =
            cluster.iter().filter(|n| chips_by_name.contains_key(*n)).cloned().collect();
        if names.is_empty() { continue; }
        let fillers_owned: Vec<String> = names
            .iter()
            .filter(|n| {
                n.as_str() != "Byte" && chips_by_name[n.as_str()].num_sent_byte_lookups() == 0
            })
            .cloned()
            .collect();
        let fillers: HashSet<&String> = fillers_owned.iter().collect();
        if fillers_owned.len() >= 2 && shape_at(&names, &fillers, target_l).is_some() {
            chosen = Some((ci, names, fillers_owned));
            break;
        }
    }
    let (ci, names, fillers_owned) =
        chosen.expect("no cluster reaches target L with >= 2 fillers");
    let fillers: HashSet<&String> = fillers_owned.iter().collect();
    let a = shape_at(&names, &fillers, target_l).unwrap();
    println!(
        "[COMPLETE] cluster {ci} chips={} fillers={} target_L={target_l}",
        names.len(),
        fillers_owned.len()
    );

    // shape_B: a DISTINCT height profile at the SAME L (perturb i down, j up).
    let fidx: Vec<usize> =
        a.iter().enumerate().filter(|(_, (n, _))| fillers.contains(n)).map(|(i, _)| i).collect();
    let mut b: Option<Vec<(String, usize)>> = None;
    'outer: for &i in &fidx {
        if a[i].1 <= 1 { continue; }
        for &j in &fidx {
            if i == j { continue; }
            for up in 1..=3usize {
                let mut t = a.clone();
                t[i].1 -= 1;
                if t[j].1 + up > cube { continue; }
                t[j].1 += up;
                if log_dense_of(&t) == target_l && t != a {
                    b = Some(t);
                    break 'outer;
                }
            }
        }
    }
    let b = b.expect("could not construct a distinct height profile at target L");

    let vk_of = |inner: &[(String, usize)]| -> [KoalaBear; DIGEST_SIZE] {
        let os = OrderedShape::from_log2_heights(inner);
        let cs = ZKMCompressProgramShape::from_proof_shape(
            ZKMProofShape::Recursion(vec![os]),
            VK_MERKLE_TREE_HEIGHT,
        );
        let program = prover.program_from_shape(cs, None);
        prover.compress_prover.setup(&program).1.hash_koalabear()
    };

    let da = vk_of(&a);
    let db = vk_of(&b);
    let show = |v: &[(String, usize)]| -> Vec<(String, usize)> {
        v.iter().filter(|(n, _)| fillers.contains(n)).cloned().collect()
    };
    println!("[COMPLETE] shape_A (greedy enum)   fillers={:?}", show(&a));
    println!("[COMPLETE] shape_B (distinct prof) fillers={:?}", show(&b));
    println!("[COMPLETE] VK_A = {da:?}");
    println!("[COMPLETE] VK_B = {db:?}");
    let height_indep = da == db;
    println!("[COMPLETE] height_independence (VK_A == VK_B at same (cluster,L)) = {height_indep}");

    let old: BTreeMap<[KoalaBear; DIGEST_SIZE], usize> = bincode::deserialize(
        &std::fs::read("/data/stephen/pathb_work/vk_map_OLD_240_ff101dee.bin").unwrap(),
    )
    .unwrap();
    let new: BTreeMap<[KoalaBear; DIGEST_SIZE], usize> = bincode::deserialize(
        &std::fs::read("/data/stephen/pathb_work/out/vk_map.bin").unwrap(),
    )
    .unwrap();
    println!(
        "[COMPLETE] VK_A: in OLD(240)={} in NEW(274)={}",
        old.contains_key(&da),
        new.contains_key(&da)
    );
    println!(
        "[COMPLETE] VK_B: in OLD(240)={} in NEW(274)={}  (VK_B = a real arbitrary-height L={target_l} shard's key)",
        old.contains_key(&db),
        new.contains_key(&db)
    );

    let gap_closed = height_indep && new.contains_key(&db) && !old.contains_key(&db);
    println!(
        "[COMPLETE] ===== L={target_l} GAP {} =====",
        if gap_closed {
            "CLOSED: a real arbitrary-height L=29 shard's normalize VK is now IN-MAP (was MISSING from the old 240-map)"
        } else {
            "NOT demonstrated"
        }
    );
    if !gap_closed {
        std::process::exit(1);
    }
}

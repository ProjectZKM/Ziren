use std::{collections::BTreeSet, sync::Arc};

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use serde::{Deserialize, Serialize};
use zkm_pcs::{shape::OrderedShape, MachineProver};
use zkm_recursion_circuit::machine::ZKMCoreWitnessValues;
use zkm_recursion_core::RecursionProgram;

use crate::{components::ZKMProverComponents, ZKMProver};

/// The shapes of the recursion programs the binary compress runs: the
/// normalize (leaf) programs, one per core shard class.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ZKMProofShape {
    /// A normalize (leaf) class representative: one core shard whose chips sit
    /// at exactly these (name, row count) pairs — rows, not log heights, so a
    /// representative can land on any committed-block bucket.
    Normalize(OrderedShape),
}

/// The witness shape of an enumerated normalize class: exact rows per chip.
#[derive(Debug, Clone, Hash)]
pub struct ZKMNormalizeShape {
    pub rows: Vec<(String, usize)>,
}

#[derive(Debug, Clone, Hash)]
pub enum ZKMCompressProgramShape {
    Normalize(ZKMNormalizeShape),
}

/// The core (MIPS) machine the normalize shapes are enumerated over.
pub type CoreMachine =
    zkm_pcs::StarkMachine<crate::CoreSC, zkm_core_machine::mips::MipsAir<KoalaBear>>;

const LOG_STACK: usize = zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize;

/// The `Program` table sizes enumerated: `2^10` rows up to the row cube.
/// Every program below `2^10` instructions shares the smallest bucket's class.
const PROGRAM_LOG_ROWS: std::ops::RangeInclusive<usize> =
    10..=zkm_pcs::stacked_shapes::consts::CORE_MAX_LOG_ROW_COUNT;

/// A core chip's name and its two round widths.
struct CoreChipDims {
    name: String,
    main_width: usize,
    prep_width: usize,
}

fn core_chip_dims(machine: &CoreMachine) -> Vec<CoreChipDims> {
    use p3_air::BaseAir;
    use zkm_pcs::air::MachineAir;
    machine
        .chips()
        .iter()
        .map(|c| CoreChipDims {
            name: <_ as MachineAir<KoalaBear>>::name(c),
            main_width: <_ as BaseAir<KoalaBear>>::width(&c.air),
            prep_width: <_ as MachineAir<KoalaBear>>::preprocessed_width(c),
        })
        .collect()
}

/// The fixed table height of a preprocessed chip: `Byte` is the full `2^16`
/// byte-pair table, `Range` the `2^11` range table, and `Program` the program
/// padded to `2^program_log_rows`.  Every other chip is event-driven.
fn table_log_rows(name: &str, program_log_rows: usize) -> Option<usize> {
    match name {
        "Program" => Some(program_log_rows),
        "Byte" => Some(16),
        "Range" => Some(11),
        _ => None,
    }
}

/// The committed-block buckets of `zkm_pcs::jagged::committed_dense_len` up
/// to the one holding `max_blocks`: `1, 2, 3, 4, 8, 16, 24, …`.
fn main_buckets(max_blocks: usize) -> Vec<usize> {
    let top = zkm_pcs::jagged::committed_dense_len(max_blocks << LOG_STACK, LOG_STACK) >> LOG_STACK;
    let mut out: Vec<usize> = (1..=4).filter(|b| *b <= top).collect();
    let mut b = 8;
    while b <= top {
        out.push(b);
        b += 8;
    }
    out
}

impl ZKMProofShape {
    /// Every shape the binary compress runs a program of.
    pub fn generate_all(machine: &CoreMachine) -> Vec<Self> {
        Self::generate_normalize(machine)
    }

    /// The normalize (leaf) shapes: one representative per
    /// `(chip cluster, preprocessed bucket, main bucket)` of the core machine —
    /// the three quantities a core shard's proof geometry, hence the normalize
    /// program verifying it, hence its verifying key, are a function of.
    ///
    /// A shard's chip set is one of the machine's clusters
    /// (`zkm_pcs::stacked_shapes::build_mips_machine_shape`); each of its two
    /// committed rounds lands on a block bucket of
    /// `zkm_pcs::jagged::committed_dense_len`; and under
    /// `zkm_pcs::jagged::unpinned_pad_columns` the padding-column count is a
    /// function of the bucket.  Heights themselves are witnessed, so every
    /// height vector inside one class yields the same program.  The
    /// representative keeps the preprocessed chips at their table sizes
    /// (`Program` at `2^k` rows, `Byte` at `2^16`, `Range` at `2^11`) and fills
    /// the rest of the bucket with the cluster's other chips, widest first,
    /// each up to the row cube; a bucket the cluster cannot fill (or cannot
    /// stay under) has no shard and is skipped.
    pub fn generate_normalize(machine: &CoreMachine) -> Vec<Self> {
        let dims = core_chip_dims(machine);
        let block = 1usize << zkm_pcs::stacked_shapes::consts::LOG_STACKING_HEIGHT;
        let max_log_rows = zkm_pcs::stacked_shapes::consts::CORE_MAX_LOG_ROW_COUNT;
        let machine_names: BTreeSet<String> = dims.iter().map(|d| d.name.clone()).collect();
        let clusters: BTreeSet<BTreeSet<String>> =
            zkm_pcs::stacked_shapes::build_mips_machine_shape()
                .chip_clusters
                .into_iter()
                .map(|c| c.intersection(&machine_names).cloned().collect())
                .collect();
        let mut out = Vec::new();
        for cluster in clusters.iter() {
            let mut seen_prep: BTreeSet<usize> = BTreeSet::new();
            for program_log_rows in PROGRAM_LOG_ROWS {
                let table_rows = |name: &str| table_log_rows(name, program_log_rows);
                let fixed: Vec<(&CoreChipDims, usize)> = dims
                    .iter()
                    .filter(|d| cluster.contains(&d.name))
                    .filter_map(|d| table_rows(&d.name).map(|log_h| (d, 1usize << log_h)))
                    .collect();
                let prep_total: usize = fixed.iter().map(|(d, h)| d.prep_width * h).sum();
                let prep_blocks =
                    zkm_pcs::jagged::committed_dense_len(prep_total, LOG_STACK) / block;
                if !seen_prep.insert(prep_blocks) {
                    continue;
                }
                let fixed_main: usize = fixed.iter().map(|(d, h)| d.main_width * h).sum();
                let mut fill: Vec<&CoreChipDims> = dims
                    .iter()
                    .filter(|d| cluster.contains(&d.name) && table_rows(&d.name).is_none())
                    .collect();
                fill.sort_by(|a, b| b.main_width.cmp(&a.main_width).then(a.name.cmp(&b.name)));
                let one_row_each: usize = fill.iter().map(|d| d.main_width).sum();
                // The executor's area budget counts unpadded events. Trace padding,
                // especially Keccak's power-of-two rows, can exceed that budget.
                // Enumerate through the jagged verifier's round-area ceiling.
                let max_main = 1usize << zkm_pcs::jagged::MAX_ROUND_LOG_AREA;
                for blocks in main_buckets(max_main.div_ceil(block)) {
                    let hi = blocks * block;
                    let lo = zkm_pcs::jagged::previous_bucket_blocks(blocks) * block;
                    if fixed_main + one_row_each > hi {
                        continue;
                    }
                    let mut remaining = hi - fixed_main - one_row_each;
                    let mut rows: Vec<(String, usize)> =
                        fixed.iter().map(|(d, h)| (d.name.clone(), *h)).collect();
                    for d in fill.iter() {
                        let extra = (remaining / d.main_width).min((1usize << max_log_rows) - 1);
                        remaining -= d.main_width * extra;
                        rows.push((d.name.clone(), 1 + extra));
                    }
                    let total = hi - remaining;
                    if total <= lo || zkm_pcs::jagged::committed_dense_len(total, LOG_STACK) != hi {
                        continue;
                    }
                    out.push(Self::Normalize(OrderedShape { inner: rows }));
                }
            }
        }
        out
    }

    /// The class of a real core shard at `rows` (name, row count): its chip
    /// set and the committed block counts of its preprocessed and main
    /// rounds — the key [`Self::generate_normalize`] enumerates on.
    pub fn normalize_class(
        machine: &CoreMachine,
        rows: &[(String, usize)],
    ) -> (BTreeSet<String>, usize, usize) {
        let dims = core_chip_dims(machine);
        let block = 1usize << zkm_pcs::stacked_shapes::consts::LOG_STACKING_HEIGHT;
        let (mut prep, mut main) = (0usize, 0usize);
        for (name, h) in rows {
            if let Some(d) = dims.iter().find(|d| d.name == *name) {
                prep += d.prep_width * h;
                main += d.main_width * h;
            }
        }
        (
            rows.iter().map(|(n, _)| n.clone()).collect(),
            zkm_pcs::jagged::committed_dense_len(prep, LOG_STACK) / block,
            zkm_pcs::jagged::committed_dense_len(main, LOG_STACK) / block,
        )
    }

    /// Placeholder keys for the recursion half of the key tree when
    /// `vk_map.bin` is not loaded (`VERIFY_VK=false`): one per normalize class.
    pub fn dummy_vk_map(
        machine: &CoreMachine,
    ) -> std::collections::BTreeMap<crate::VkDigest, usize> {
        Self::generate_normalize(machine)
            .into_iter()
            .enumerate()
            .map(|(i, _)| {
                let digest: crate::VkDigest = core::array::from_fn(|_| KoalaBear::from_usize(i));
                (digest, i)
            })
            .collect()
    }
}

impl ZKMCompressProgramShape {
    pub fn from_proof_shape(shape: ZKMProofShape) -> Self {
        match shape {
            ZKMProofShape::Normalize(shape) => {
                Self::Normalize(ZKMNormalizeShape { rows: shape.inner })
            }
        }
    }
}

impl<C: ZKMProverComponents> ZKMProver<C> {
    /// The recursion program of an enumerated shape.
    pub fn program_from_shape(
        &self,
        shape: ZKMCompressProgramShape,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        match shape {
            ZKMCompressProgramShape::Normalize(shape) => {
                let input = ZKMCoreWitnessValues::dummy_rows(
                    self.core_prover.machine(),
                    &shape.rows,
                    false,
                );
                self.recursion_program(&input).0
            }
        }
    }
}

#[cfg(test)]
mod normalize_enumeration_tests {
    use super::*;
    use crate::components::DefaultProverComponents;
    use std::{collections::BTreeMap, sync::atomic::Ordering};

    /// One real leaf of the production census: whether it was the first shard
    /// and its per-chip row counts.
    struct CensusLeaf {
        first: bool,
        rows: Vec<(String, usize)>,
    }

    fn parse_census(path: &str) -> Vec<CensusLeaf> {
        let text = std::fs::read_to_string(path).expect("census file");
        let mut seen: BTreeSet<(bool, String)> = BTreeSet::new();
        let mut out = Vec::new();
        for line in text.lines() {
            let field = |key: &str| -> Option<&str> {
                line.split_whitespace().find_map(|w| w.strip_prefix(key))
            };
            let (Some(first), Some(heights)) = (field("first="), field("heights=")) else {
                continue;
            };
            let first = first == "true";
            if !seen.insert((first, heights.to_string())) {
                continue;
            }
            let rows: Vec<(String, usize)> = heights
                .split(',')
                .filter_map(|kv| kv.split_once(':'))
                .map(|(n, h)| (n.to_string(), h.parse().expect("row count")))
                .collect();
            out.push(CensusLeaf { first, rows });
        }
        out
    }

    fn shape_rows(shape: &ZKMProofShape) -> Vec<(String, usize)> {
        let ZKMProofShape::Normalize(os) = shape;
        os.inner.clone()
    }

    /// The enumeration is one shape per class and stays inside the tree.
    #[test]
    fn normalize_enumeration_is_one_per_class() {
        zkm_core_machine::utils::setup_logger();
        let prover = ZKMProver::<DefaultProverComponents>::new_with_vk_verification(Some(false));
        let machine = prover.core_prover.machine();
        let shapes = ZKMProofShape::generate_normalize(machine);
        let mut classes = BTreeSet::new();
        for shape in shapes.iter() {
            let class = ZKMProofShape::normalize_class(machine, &shape_rows(shape));
            assert!(classes.insert(class.clone()), "class enumerated twice: {class:?}");
        }
        tracing::info!("normalize shapes {} of 2^{}", shapes.len(), crate::VK_MERKLE_TREE_HEIGHT);
        assert!(shapes.len() <= 1 << crate::VK_MERKLE_TREE_HEIGHT);
    }

    #[test]
    fn normalize_enumeration_covers_padded_keccak_shard() {
        let prover = ZKMProver::<DefaultProverComponents>::new_with_vk_verification(Some(false));
        let machine = prover.core_prover.machine();
        // Block 26,181,835: a shard whose Keccak padding takes the main round
        // past the executor-budget-based enumeration limit.
        let rows: Vec<(String, usize)> = [
            ("Byte", 65_536),
            ("Global", 441_056),
            ("KeccakSponge", 262_144),
            ("KeccakSpongeControl", 8_192),
            ("MemoryLocal", 55_136),
            ("Program", 1_048_576),
            ("Range", 2_048),
            ("SyscallPrecompile", 32),
        ]
        .into_iter()
        .map(|(name, height)| (name.to_owned(), height))
        .collect();
        let class = ZKMProofShape::normalize_class(machine, &rows);
        assert_eq!((class.1, class.2), (8, 336));
        assert!(ZKMProofShape::generate_normalize(machine)
            .iter()
            .any(|shape| ZKMProofShape::normalize_class(machine, &shape_rows(shape)) == class));
    }

    /// Every leaf the production census recorded (`ZIREN_CENSUS_FILE`, lines
    /// with `first=` and `heights=`) falls in an enumerated class, and its
    /// normalize program is byte-identical to the class representative's; the
    /// first-shard flag, being a witness, does not move the program either.
    ///
    /// `ZIREN_CENSUS_FILE=census.txt cargo test -r -p zkm-prover
    ///  normalize_enumeration_covers_census -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn normalize_enumeration_covers_census() {
        zkm_core_machine::utils::setup_logger();
        let path = std::env::var("ZIREN_CENSUS_FILE").expect("ZIREN_CENSUS_FILE");
        let per_class: usize =
            std::env::var("ZIREN_CENSUS_PER_CLASS").ok().and_then(|s| s.parse().ok()).unwrap_or(3);
        let threads: usize =
            std::env::var("ZIREN_CENSUS_THREADS").ok().and_then(|s| s.parse().ok()).unwrap_or(8);
        let leaves = parse_census(&path);
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let machine = prover.core_prover.machine();
        let representatives: BTreeMap<_, ZKMProofShape> =
            ZKMProofShape::generate_normalize(machine)
                .into_iter()
                .map(|s| (ZKMProofShape::normalize_class(machine, &shape_rows(&s)), s))
                .collect();

        let mut by_class: BTreeMap<_, Vec<&CensusLeaf>> = BTreeMap::new();
        for leaf in leaves.iter() {
            by_class
                .entry(ZKMProofShape::normalize_class(machine, &leaf.rows))
                .or_default()
                .push(leaf);
        }
        let missing: Vec<_> =
            by_class.keys().filter(|c| !representatives.contains_key(*c)).cloned().collect();
        for class in missing.iter() {
            tracing::error!(
                "class not enumerated: chips {} prep {} main {}",
                class.0.len(),
                class.1,
                class.2
            );
        }

        let jobs: Vec<(&CensusLeaf, &ZKMProofShape)> = by_class
            .iter()
            .filter_map(|(class, ls)| representatives.get(class).map(|rep| (ls, rep)))
            .flat_map(|(ls, rep)| ls.iter().take(per_class).map(move |l| (*l, rep)))
            .collect();
        let mismatched = std::sync::atomic::AtomicUsize::new(0);
        let first_moved = std::sync::atomic::AtomicUsize::new(0);
        let next = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..threads {
                s.spawn(|| loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some((leaf, rep)) = jobs.get(i) else { break };
                    let mut real = ZKMCoreWitnessValues::dummy_rows(machine, &leaf.rows, false);
                    real.is_first_shard = leaf.first;
                    let (_, real_digest) = prover.recursion_program(&real);
                    real.is_first_shard = !leaf.first;
                    let (_, flipped_digest) = prover.recursion_program(&real);
                    let rep_input =
                        ZKMCoreWitnessValues::dummy_rows(machine, &shape_rows(rep), false);
                    let (_, rep_digest) = prover.recursion_program(&rep_input);
                    if real_digest != rep_digest {
                        mismatched.fetch_add(1, Ordering::Relaxed);
                        tracing::error!(
                            "program differs from its class representative: {:?}",
                            leaf.rows
                        );
                    }
                    if real_digest != flipped_digest {
                        first_moved.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });
        let mismatched = mismatched.load(Ordering::Relaxed);
        let first_moved = first_moved.load(Ordering::Relaxed);
        tracing::info!(
            "census leaves {} in {} classes; representatives {}; checked {}; missing classes {}; \
             mismatched {}; first-flag moved {}",
            leaves.len(),
            by_class.len(),
            representatives.len(),
            jobs.len(),
            missing.len(),
            mismatched,
            first_moved
        );
        assert!(missing.is_empty() && mismatched == 0 && first_moved == 0);
    }
}

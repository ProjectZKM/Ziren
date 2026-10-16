//! Deferred-shard planning over event REFERENCES instead of events.
//!
//! [`ExecutionRecord::split`] decides where the deferred (precompile +
//! global-memory) events of a program are cut into shards. It needs the
//! events in hand. A controller that never holds the records — the shards
//! were replayed elsewhere, from trace chunks — still has to make the same
//! decision, and hand each cut to whoever owns the events. This module is
//! that decision, expressed over per-event WEIGHTS and artifact handles:
//! the greedy grouping `split` applies to a prefix of the event stream is a
//! prefix of the grouping it applies to the whole, so feeding it one chunk's
//! events at a time, in chunk order, cuts exactly where a single call over
//! the concatenation would.
//!
//! Two rules are shared with `split` through [`precompile_split_weight`] and
//! [`precompile_split_threshold`], so the record path and the plan path
//! cannot drift apart.

use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};
use zkm_pcs::SplitOpts;

use crate::{
    events::{
        MemoryInitializeFinalizeEvent, PrecompileEvent, SyscallEvent,
        NUM_LOCAL_MEMORY_ENTRIES_PER_ROW_EXEC,
    },
    executor::{CORE_SHARD_HEIGHT_THRESHOLD, MAX_PROGRAM_SIZE},
    syscalls::{precompiles::keccak::sponge::GENERAL_BLOCK_SIZE_U32S, SyscallCode},
    ExecutionRecord, MipsAirId, Program,
};

/// The per-code threshold `split` cuts precompile shards at.
///
/// A code with a cost model ([`area_split_threshold`]) is cut where its shard
/// fills the area budget, and never below the count threshold it had before.
#[must_use]
pub fn precompile_split_threshold(code: SyscallCode, opts: &SplitOpts) -> usize {
    match code {
        SyscallCode::KECCAK_SPONGE => opts.keccak,
        SyscallCode::SHA_EXTEND => opts.sha_extend,
        SyscallCode::SHA_COMPRESS => opts.sha_compress,
        _ => area_split_threshold(code, opts.element_threshold)
            .map_or(opts.deferred, |n| n.max(opts.deferred)),
    }
}

/// The AIR that proves a 256-bit Weierstrass point operation, and the words
/// one event touches: both points for an add, the one point for a double.
///
/// These codes are cut by area because a point operation is cheap per event:
/// at the shared count threshold their shards held a small fraction of the
/// area budget, so a signature-heavy block spent many mostly empty shards on
/// them.  The model was checked against measured secp256k1 shards; secp256r1
/// and bn254 use the same AIR layout and word count, so they share it.
///
/// Other curve and field precompiles keep the count threshold because none of
/// them has been measured.  Each also touches a different set of words:
/// BLS12-381 points are 384-bit, decompress reads a compressed point and
/// writes the other coordinate, Ed25519 has its own AIR, and uint256 and the
/// field operations also read a modulus.  Each would need its own word count
/// and a measured check before it is cut by area, since a model that
/// overestimates the count could push a shard past the height cap.
fn weierstrass_air_and_words(code: SyscallCode) -> Option<(MipsAirId, usize)> {
    let point = zkm_curves::NUM_WORDS_EC_POINT;
    Some(match code {
        SyscallCode::SECP256K1_ADD => (MipsAirId::Secp256k1AddAssign, 2 * point),
        SyscallCode::SECP256K1_DOUBLE => (MipsAirId::Secp256k1DoubleAssign, point),
        SyscallCode::SECP256R1_ADD => (MipsAirId::Secp256r1AddAssign, 2 * point),
        SyscallCode::SECP256R1_DOUBLE => (MipsAirId::Secp256r1DoubleAssign, point),
        SyscallCode::BN254_ADD => (MipsAirId::Bn254AddAssign, 2 * point),
        SyscallCode::BN254_DOUBLE => (MipsAirId::Bn254DoubleAssign, point),
        _ => return None,
    })
}

/// Main columns of the byte table, which every shard carries at 2^16 rows.
pub const BYTE_MAIN_COLS: usize = 10;
/// Main columns of the program table, which every shard carries at one row
/// per instruction.
pub const PROGRAM_MAIN_COLS: usize = 1;

/// How many events of `code` one deferred shard holds when it is cut by area,
/// or `None` for a code without a cost model here (it keeps its count
/// threshold).
///
/// One event costs a row of its own AIR, a local-memory entry per touched
/// word (four to a row), two global rows per touched word plus two for the
/// syscall, and a precompile-syscall row; each row is charged its AIR's width
/// from `mips_costs`.  The precompile's own trace is padded only to a
/// multiple of 32 (`num_rows`, which the GPU trace generator follows too);
/// a fixed shape would pad it to a power of two, which this does not model.
/// The byte and program tables are in every shard and come off the budget
/// first, the program table at `MAX_PROGRAM_SIZE` rows since the program is
/// not known here.  (`mips_costs` charges both their preprocessed columns
/// too, which are not main-trace area.)  The global AIR is the tallest, so it also bounds the count by the per-chip
/// height cap the core shards are cut at.  Rounded down to a multiple of 32.
fn area_split_threshold(code: SyscallCode, element_threshold: usize) -> Option<usize> {
    static COSTS: std::sync::OnceLock<hashbrown::HashMap<MipsAirId, usize>> =
        std::sync::OnceLock::new();
    let (air, words) = weierstrass_air_and_words(code)?;
    let costs = COSTS.get_or_init(crate::mips_costs);
    let global_rows = 2 * words + 2;
    let per_event = costs[&air]
        + words.div_ceil(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW_EXEC) * costs[&MipsAirId::MemoryLocal]
        + global_rows * costs[&MipsAirId::Global]
        + costs[&MipsAirId::SyscallPrecompile];
    let fixed = (1 << 16) * BYTE_MAIN_COLS + MAX_PROGRAM_SIZE * PROGRAM_MAIN_COLS;
    let budget = element_threshold.saturating_sub(fixed);
    let by_height = CORE_SHARD_HEIGHT_THRESHOLD as usize / global_rows;
    Some((budget / per_event).min(by_height) / 32 * 32)
}

/// The weight one precompile event contributes towards its code's threshold.
///
/// Keccak shards are cut by WORK (blocks absorbed), every other code by
/// count. `None` means the code is cut by count.
#[must_use]
pub fn precompile_split_weight(code: SyscallCode, event: &PrecompileEvent) -> Option<usize> {
    match code {
        SyscallCode::KECCAK_SPONGE => Some(match event {
            PrecompileEvent::KeccakSponge(e) => e.input_len_u32s as usize / GENERAL_BLOCK_SIZE_U32S,
            _ => 0,
        }),
        _ => None,
    }
}

/// A contiguous run of events inside one artifact: `[from, to)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventSlice {
    /// Whatever the owner of the events uses to find them again.
    pub artifact: String,
    pub from: u32,
    pub to: u32,
}

/// One deferred shard, as the controller wants it built.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// The variants differ in size because one carries its event slices inline.
// Boxing it would add an allocation per deferred shard on the planning path.
#[allow(clippy::large_enum_variant)]
pub enum DeferredShardPlan {
    /// A precompile shard: one syscall code, its events in stream order.
    Precompile { code: SyscallCode, slices: Vec<EventSlice> },
    /// A global-memory shard: `opts.memory` init and finalize events each
    /// (addr-sorted), and the address bits `split` stamps on its public
    /// values.
    Memory {
        init: Vec<EventSlice>,
        finalize: Vec<EventSlice>,
        previous_init_addr_bits: [u32; 32],
        last_init_addr_bits: [u32; 32],
        previous_finalize_addr_bits: [u32; 32],
        last_finalize_addr_bits: [u32; 32],
    },
}

/// One addr-sorted global-memory event stream, described by its owner.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryEventsDesc {
    pub artifact: String,
    pub count: u32,
    /// The address of the LAST event of every `opts.memory`-sized chunk of
    /// the stream, in order — the only addresses the shard public values
    /// need. See [`MemoryEventsDesc::describe`].
    pub boundary_addrs: Vec<u32>,
}

impl MemoryEventsDesc {
    /// Describe an addr-SORTED event stream the caller stored under `artifact`.
    #[must_use]
    pub fn describe(
        artifact: String,
        events: &[MemoryInitializeFinalizeEvent],
        memory: usize,
    ) -> Self {
        let boundary_addrs = events
            .chunks(memory.max(1))
            .map(|c| c.last().expect("chunks are non-empty").addr)
            .collect();
        Self { artifact, count: events.len() as u32, boundary_addrs }
    }
}

#[derive(Clone, Copy, Debug)]
struct PendingEvent {
    artifact: u32,
    index: u32,
    weight: u32,
}

/// The controller's mirror of the `deferred` record `split` consumes.
#[derive(Debug)]
pub struct DeferredPlanner {
    opts: SplitOpts,
    artifacts: Vec<String>,
    // Ordered by code so the shard order is a function of the events, not of
    // a hash map's iteration order (which is what `split` has).
    pending: BTreeMap<SyscallCode, VecDeque<PendingEvent>>,
    memory: Option<(MemoryEventsDesc, MemoryEventsDesc)>,
}

impl DeferredPlanner {
    #[must_use]
    pub fn new(opts: SplitOpts) -> Self {
        Self { opts, artifacts: Vec::new(), pending: BTreeMap::new(), memory: None }
    }

    fn artifact_id(&mut self, artifact: &str) -> u32 {
        if let Some(i) = self.artifacts.iter().rposition(|a| a == artifact) {
            return i as u32;
        }
        self.artifacts.push(artifact.to_string());
        (self.artifacts.len() - 1) as u32
    }

    /// Append one chunk's events of `code`, stored under `artifact` in stream
    /// order; `weights` gives every event's [`precompile_split_weight`] (any
    /// value for a count-cut code).
    pub fn push_precompile(
        &mut self,
        code: SyscallCode,
        artifact: &str,
        weights: impl IntoIterator<Item = u32>,
    ) {
        let a = self.artifact_id(artifact);
        let q = self.pending.entry(code).or_default();
        for (i, w) in weights.into_iter().enumerate() {
            q.push_back(PendingEvent { artifact: a, index: i as u32, weight: w });
        }
    }

    /// The program's global-memory init/finalize streams (terminal chunk only).
    pub fn push_memory(&mut self, init: MemoryEventsDesc, finalize: MemoryEventsDesc) {
        self.memory = Some((init, finalize));
    }

    /// Mirror of `ExecutionRecord::split(last, None, opts)`: the shards that
    /// call would cut now, in order, leaving the remainder pending.
    pub fn split(&mut self, last: bool) -> Vec<DeferredShardPlan> {
        let mut shards = Vec::new();
        let opts = self.opts;
        for (&code, q) in self.pending.iter_mut() {
            let threshold = precompile_split_threshold(code, &opts);
            let by_weight = matches!(code, SyscallCode::KECCAK_SPONGE);
            loop {
                let mut n = 0usize;
                let mut acc = 0usize;
                let mut full = false;
                for e in q.iter() {
                    if by_weight {
                        if acc + e.weight as usize > threshold && n > 0 {
                            full = true;
                            break;
                        }
                        acc += e.weight as usize;
                        n += 1;
                    } else {
                        n += 1;
                        if n == threshold {
                            full = true;
                            break;
                        }
                    }
                }
                if !full {
                    if last && n > 0 {
                        shards.push(Self::cut(&self.artifacts, code, q, n));
                    }
                    break;
                }
                shards.push(Self::cut(&self.artifacts, code, q, n));
            }
        }
        self.pending.retain(|_, q| !q.is_empty());

        if last {
            if let Some((init, fin)) = self.memory.take() {
                let m = opts.memory.max(1);
                let n_init = init.count as usize;
                let n_fin = fin.count as usize;
                let n_chunks = n_init.div_ceil(m).max(n_fin.div_ceil(m));
                let bits = |addr: u32| core::array::from_fn(|i| (addr >> i) & 1);
                let mut init_bits = [0u32; 32];
                let mut fin_bits = [0u32; 32];
                for i in 0..n_chunks {
                    let slice = |desc: &MemoryEventsDesc, n: usize| -> Vec<EventSlice> {
                        let from = (i * m).min(n);
                        let to = ((i + 1) * m).min(n);
                        if from == to {
                            Vec::new()
                        } else {
                            vec![EventSlice {
                                artifact: desc.artifact.clone(),
                                from: from as u32,
                                to: to as u32,
                            }]
                        }
                    };
                    let init_slice = slice(&init, n_init);
                    let fin_slice = slice(&fin, n_fin);
                    let previous_init_addr_bits = init_bits;
                    if !init_slice.is_empty() {
                        init_bits = bits(init.boundary_addrs[i]);
                    }
                    let previous_finalize_addr_bits = fin_bits;
                    if !fin_slice.is_empty() {
                        fin_bits = bits(fin.boundary_addrs[i]);
                    }
                    shards.push(DeferredShardPlan::Memory {
                        init: init_slice,
                        finalize: fin_slice,
                        previous_init_addr_bits,
                        last_init_addr_bits: init_bits,
                        previous_finalize_addr_bits,
                        last_finalize_addr_bits: fin_bits,
                    });
                }
            }
        }
        shards
    }

    fn cut(
        artifacts: &[String],
        code: SyscallCode,
        q: &mut VecDeque<PendingEvent>,
        n: usize,
    ) -> DeferredShardPlan {
        let mut slices: Vec<EventSlice> = Vec::new();
        for e in q.drain(..n) {
            match slices.last_mut() {
                Some(s) if s.artifact == artifacts[e.artifact as usize] && s.to == e.index => {
                    s.to += 1
                }
                _ => slices.push(EventSlice {
                    artifact: artifacts[e.artifact as usize].clone(),
                    from: e.index,
                    to: e.index + 1,
                }),
            }
        }
        DeferredShardPlan::Precompile { code, slices }
    }

    /// Whether anything is still pending (a non-terminal remainder).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty() && self.memory.is_none()
    }
}

impl ExecutionRecord {
    /// The record `split` builds for one precompile shard.
    #[must_use]
    pub fn precompile_shard(
        program: std::sync::Arc<Program>,
        code: SyscallCode,
        events: Vec<(SyscallEvent, PrecompileEvent)>,
    ) -> Self {
        let mut record = ExecutionRecord::new(program);
        record.precompile_events.insert(code, events);
        record
    }

    /// The record `split` builds for one global-memory shard (the public
    /// values' address bits are the caller's — they come from the plan).
    #[must_use]
    pub fn memory_shard(
        program: std::sync::Arc<Program>,
        init: Vec<MemoryInitializeFinalizeEvent>,
        finalize: Vec<MemoryInitializeFinalizeEvent>,
    ) -> Self {
        let mut record = ExecutionRecord::new(program);
        record.global_memory_initialize_events = init;
        record.global_memory_finalize_events = finalize;
        record
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> SplitOpts {
        SplitOpts::new(8)
    }

    #[test]
    fn count_cut_matches_chunks_exact_across_pushes() {
        let mut p = DeferredPlanner::new(opts());
        p.push_precompile(SyscallCode::BN254_FP_ADD, "a", vec![1; 5]);
        assert!(p.split(false).is_empty());
        p.push_precompile(SyscallCode::BN254_FP_ADD, "b", vec![1; 7]);
        let s = p.split(false);
        assert_eq!(
            s,
            vec![DeferredShardPlan::Precompile {
                code: SyscallCode::BN254_FP_ADD,
                slices: vec![
                    EventSlice { artifact: "a".into(), from: 0, to: 5 },
                    EventSlice { artifact: "b".into(), from: 0, to: 3 }
                ]
            }]
        );
        p.push_precompile(SyscallCode::BN254_FP_ADD, "c", vec![1; 4]);
        let s = p.split(true);
        assert_eq!(
            s,
            vec![DeferredShardPlan::Precompile {
                code: SyscallCode::BN254_FP_ADD,
                slices: vec![
                    EventSlice { artifact: "b".into(), from: 3, to: 7 },
                    EventSlice { artifact: "c".into(), from: 0, to: 4 }
                ]
            }]
        );
        assert!(p.is_empty());
    }

    #[test]
    fn weierstrass_codes_are_cut_by_area() {
        let opts = SplitOpts::new(1 << 15);
        let double = precompile_split_threshold(SyscallCode::SECP256K1_DOUBLE, &opts);
        let add = precompile_split_threshold(SyscallCode::SECP256K1_ADD, &opts);
        // A double touches half the words of an add, so more of them fit.
        assert!(double > add && add > opts.deferred);
        assert_eq!(double % 32, 0);
        // The global AIR, two rows per touched word plus two, stays under the
        // per-chip height cap.
        let words = zkm_curves::NUM_WORDS_EC_POINT;
        assert!(add * (4 * words + 2) <= CORE_SHARD_HEIGHT_THRESHOLD as usize);
        assert!(double * (2 * words + 2) <= CORE_SHARD_HEIGHT_THRESHOLD as usize);
        // A code without a cost model keeps its count threshold.
        assert_eq!(precompile_split_threshold(SyscallCode::BN254_FP_ADD, &opts), opts.deferred);
    }

    #[test]
    fn weight_cut_is_greedy_like_split() {
        let mut p = DeferredPlanner::new(opts());
        p.push_precompile(SyscallCode::KECCAK_SPONGE, "k", vec![1, 1, 1, 2, 2]);
        let s = p.split(false);
        let ranges: Vec<(u32, u32)> = s
            .iter()
            .map(|x| match x {
                DeferredShardPlan::Precompile { slices, .. } => (slices[0].from, slices[0].to),
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(ranges, vec![(0, 2), (2, 3), (3, 4)]);
        let s = p.split(true);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn memory_shards_carry_split_addr_bits() {
        let mut p = DeferredPlanner::new(opts());
        let init = MemoryEventsDesc {
            artifact: "i".into(),
            count: 1000,
            boundary_addrs: vec![0x1ff, 0x3e7],
        };
        let fin = MemoryEventsDesc {
            artifact: "f".into(),
            count: 600,
            boundary_addrs: vec![0x7ff, 0xfff],
        };
        p.push_memory(init, fin);
        let s = p.split(true);
        assert_eq!(s.len(), 2);
        let bits = |addr: u32| -> [u32; 32] { core::array::from_fn(|i| (addr >> i) & 1) };
        match &s[0] {
            DeferredShardPlan::Memory {
                init,
                finalize,
                previous_init_addr_bits,
                last_init_addr_bits,
                previous_finalize_addr_bits,
                last_finalize_addr_bits,
            } => {
                assert_eq!(init[0].to - init[0].from, 512);
                assert_eq!(finalize[0].to - finalize[0].from, 512);
                assert_eq!(*previous_init_addr_bits, [0; 32]);
                assert_eq!(*last_init_addr_bits, bits(0x1ff));
                assert_eq!(*previous_finalize_addr_bits, [0; 32]);
                assert_eq!(*last_finalize_addr_bits, bits(0x7ff));
            }
            _ => unreachable!(),
        }
        match &s[1] {
            DeferredShardPlan::Memory {
                init,
                finalize,
                previous_init_addr_bits,
                last_init_addr_bits,
                previous_finalize_addr_bits,
                last_finalize_addr_bits,
            } => {
                assert_eq!((init[0].from, init[0].to), (512, 1000));
                assert_eq!((finalize[0].from, finalize[0].to), (512, 600));
                assert_eq!(*previous_init_addr_bits, bits(0x1ff));
                assert_eq!(*last_init_addr_bits, bits(0x3e7));
                assert_eq!(*previous_finalize_addr_bits, bits(0x7ff));
                assert_eq!(*last_finalize_addr_bits, bits(0xfff));
            }
            _ => unreachable!(),
        }
    }
}

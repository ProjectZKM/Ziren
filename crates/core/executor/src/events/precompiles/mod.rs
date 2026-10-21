mod ec;
mod edwards;
mod fptower;
mod keccak_sponge;
mod linux;
mod poseidon2_permute;
mod sha256_compress;
mod sha256_extend;
mod u256x2048_mul;
mod uint256;
use super::{MemoryLocalEvent, MemoryRecord, SyscallEvent};
use crate::syscalls::SyscallCode;
pub use ec::*;
pub use edwards::*;
pub use fptower::*;
use hashbrown::{HashMap, HashSet};
pub use keccak_sponge::*;
pub use linux::*;
pub use poseidon2_permute::*;
use serde::{Deserialize, Serialize};
pub use sha256_compress::*;
pub use sha256_extend::*;
use strum::{EnumIter, IntoEnumIterator};
pub use u256x2048_mul::*;
pub use uint256::*;

#[derive(Clone, Debug, Serialize, Deserialize, EnumIter)]
/// Precompile event.  There should be one variant for every precompile syscall.
pub enum PrecompileEvent {
    /// Sha256 extend precompile event.
    ShaExtend(ShaExtendEvent),
    /// Sha256 compress precompile event.
    ShaCompress(ShaCompressEvent),
    /// Keccak sponge precompile event.
    KeccakSponge(KeccakSpongeEvent),
    /// Edwards curve add precompile event.
    EdAdd(EllipticCurveAddEvent),
    /// Edwards curve decompress precompile event.
    EdDecompress(EdDecompressEvent),
    /// Secp256k1 curve add precompile event.
    Secp256k1Add(EllipticCurveAddEvent),
    /// Secp256k1 curve double precompile event.
    Secp256k1Double(EllipticCurveDoubleEvent),
    /// Secp256k1 curve decompress precompile event.
    Secp256k1Decompress(EllipticCurveDecompressEvent),
    /// Secp256r1 curve add precompile event.
    Secp256r1Add(EllipticCurveAddEvent),
    /// Secp256r1 curve double precompile event.
    Secp256r1Double(EllipticCurveDoubleEvent),
    /// Secp256r1 curve decompress precompile event.
    Secp256r1Decompress(EllipticCurveDecompressEvent),
    /// K256 curve decompress precompile event.
    K256Decompress(EllipticCurveDecompressEvent),
    /// Bn254 curve add precompile event.
    Bn254Add(EllipticCurveAddEvent),
    /// Bn254 curve double precompile event.
    Bn254Double(EllipticCurveDoubleEvent),
    /// Bn254 base field operation precompile event.
    Bn254Fp(FpOpEvent),
    /// Bn254 quadratic field add/sub precompile event.
    Bn254Fp2AddSub(Fp2AddSubEvent),
    /// Bn254 quadratic field mul precompile event.
    Bn254Fp2Mul(Fp2MulEvent),
    /// Bls12-381 curve add precompile event.
    Bls12381Add(EllipticCurveAddEvent),
    /// Bls12-381 curve double precompile event.
    Bls12381Double(EllipticCurveDoubleEvent),
    /// Bls12-381 curve decompress precompile event.
    Bls12381Decompress(EllipticCurveDecompressEvent),
    /// Bls12-381 base field operation precompile event.
    Bls12381Fp(FpOpEvent),
    /// Bls12-381 quadratic field add/sub precompile event.
    Bls12381Fp2AddSub(Fp2AddSubEvent),
    /// Bls12-381 quadratic field mul precompile event.
    Bls12381Fp2Mul(Fp2MulEvent),
    /// Uint256 mul precompile event.
    Uint256Mul(Uint256MulEvent),
    /// U256XU2048 mul precompile event.
    U256xU2048Mul(U256xU2048MulEvent),
    /// Poseidon2 permutation precompile event.
    Poseidon2Permute(Poseidon2PermuteEvent),
    /// linux precompile event.
    Linux(LinuxEvent),
}

/// Trait to retrieve all the local memory events from a vec of precompile events.
pub trait PrecompileLocalMemory {
    /// Get an iterator of all the local memory events.
    fn get_local_mem_events(&self) -> impl IntoIterator<Item = &MemoryLocalEvent>;
}

impl PrecompileEvent {
    /// The local memory events of this precompile call.
    #[must_use]
    pub fn local_mem_access(&self) -> &[MemoryLocalEvent] {
        match self {
            PrecompileEvent::ShaExtend(e) => &e.local_mem_access,
            PrecompileEvent::ShaCompress(e) => &e.local_mem_access,
            PrecompileEvent::KeccakSponge(e) => &e.local_mem_access,
            PrecompileEvent::EdDecompress(e) => &e.local_mem_access,
            PrecompileEvent::Secp256k1Add(e)
            | PrecompileEvent::Secp256r1Add(e)
            | PrecompileEvent::EdAdd(e)
            | PrecompileEvent::Bn254Add(e)
            | PrecompileEvent::Bls12381Add(e) => &e.local_mem_access,
            PrecompileEvent::Secp256k1Double(e)
            | PrecompileEvent::Secp256r1Double(e)
            | PrecompileEvent::Bn254Double(e)
            | PrecompileEvent::Bls12381Double(e) => &e.local_mem_access,
            PrecompileEvent::Secp256k1Decompress(e)
            | PrecompileEvent::Secp256r1Decompress(e)
            | PrecompileEvent::K256Decompress(e)
            | PrecompileEvent::Bls12381Decompress(e) => &e.local_mem_access,
            PrecompileEvent::Uint256Mul(e) => &e.local_mem_access,
            PrecompileEvent::U256xU2048Mul(e) => &e.local_mem_access,
            PrecompileEvent::Bls12381Fp(e) | PrecompileEvent::Bn254Fp(e) => &e.local_mem_access,
            PrecompileEvent::Bls12381Fp2AddSub(e) | PrecompileEvent::Bn254Fp2AddSub(e) => {
                &e.local_mem_access
            }
            PrecompileEvent::Bls12381Fp2Mul(e) | PrecompileEvent::Bn254Fp2Mul(e) => {
                &e.local_mem_access
            }
            PrecompileEvent::Poseidon2Permute(e) => &e.local_mem_access,
            PrecompileEvent::Linux(e) => &e.local_mem_access,
        }
    }

    /// The local memory events of this precompile call, mutably.
    pub fn local_mem_access_mut(&mut self) -> &mut Vec<MemoryLocalEvent> {
        match self {
            PrecompileEvent::ShaExtend(e) => &mut e.local_mem_access,
            PrecompileEvent::ShaCompress(e) => &mut e.local_mem_access,
            PrecompileEvent::KeccakSponge(e) => &mut e.local_mem_access,
            PrecompileEvent::EdDecompress(e) => &mut e.local_mem_access,
            PrecompileEvent::Secp256k1Add(e)
            | PrecompileEvent::Secp256r1Add(e)
            | PrecompileEvent::EdAdd(e)
            | PrecompileEvent::Bn254Add(e)
            | PrecompileEvent::Bls12381Add(e) => &mut e.local_mem_access,
            PrecompileEvent::Secp256k1Double(e)
            | PrecompileEvent::Secp256r1Double(e)
            | PrecompileEvent::Bn254Double(e)
            | PrecompileEvent::Bls12381Double(e) => &mut e.local_mem_access,
            PrecompileEvent::Secp256k1Decompress(e)
            | PrecompileEvent::Secp256r1Decompress(e)
            | PrecompileEvent::K256Decompress(e)
            | PrecompileEvent::Bls12381Decompress(e) => &mut e.local_mem_access,
            PrecompileEvent::Uint256Mul(e) => &mut e.local_mem_access,
            PrecompileEvent::U256xU2048Mul(e) => &mut e.local_mem_access,
            PrecompileEvent::Bls12381Fp(e) | PrecompileEvent::Bn254Fp(e) => &mut e.local_mem_access,
            PrecompileEvent::Bls12381Fp2AddSub(e) | PrecompileEvent::Bn254Fp2AddSub(e) => {
                &mut e.local_mem_access
            }
            PrecompileEvent::Bls12381Fp2Mul(e) | PrecompileEvent::Bn254Fp2Mul(e) => {
                &mut e.local_mem_access
            }
            PrecompileEvent::Poseidon2Permute(e) => &mut e.local_mem_access,
            PrecompileEvent::Linux(e) => &mut e.local_mem_access,
        }
    }
}

impl PrecompileLocalMemory for Vec<(SyscallEvent, PrecompileEvent)> {
    fn get_local_mem_events(&self) -> impl IntoIterator<Item = &MemoryLocalEvent> {
        self.iter().flat_map(|(_, event)| event.local_mem_access().iter())
    }
}

/// A record of all the precompile events.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrecompileEvents {
    events: HashMap<SyscallCode, Vec<(SyscallEvent, PrecompileEvent)>>,
}

impl Default for PrecompileEvents {
    fn default() -> Self {
        let mut events = HashMap::new();
        for syscall_code in SyscallCode::iter() {
            if syscall_code.should_send() == 1 || syscall_code.linux_sys() != 0 {
                events.insert(syscall_code, Vec::new());
            }
        }

        Self { events }
    }
}

impl PrecompileEvents {
    pub(crate) fn append(&mut self, other: &mut PrecompileEvents) {
        for (syscall, events) in other.events.iter_mut() {
            if !events.is_empty() {
                self.events.entry(*syscall).or_default().append(events);
            }
        }
    }

    #[inline]
    /// Add a precompile event for a given syscall code.
    pub fn add_event(
        &mut self,
        syscall_code: SyscallCode,
        syscall_event: SyscallEvent,
        event: PrecompileEvent,
    ) {
        assert!(syscall_code.should_send() == 1 || syscall_code.linux_sys() != 0);
        self.events.entry(syscall_code).or_default().push((syscall_event, event));
    }

    /// Checks if the precompile events are empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Get all the precompile events.
    pub fn all_events(&self) -> impl Iterator<Item = &(SyscallEvent, PrecompileEvent)> {
        self.events.values().flatten()
    }

    #[inline]
    /// Insert a vector of precompile events for a given syscall code.
    pub(crate) fn insert(
        &mut self,
        syscall_code: SyscallCode,
        events: Vec<(SyscallEvent, PrecompileEvent)>,
    ) {
        assert!(syscall_code.should_send() == 1 || syscall_code.linux_sys() != 0);
        self.events.insert(syscall_code, events);
    }

    /// Get the number of precompile events.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    #[inline]
    pub(crate) fn into_iter(
        self,
    ) -> impl Iterator<Item = (SyscallCode, Vec<(SyscallEvent, PrecompileEvent)>)> {
        self.events.into_iter()
    }

    /// The events by syscall code (hash-map order: not stable across runs).
    #[inline]
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = (&SyscallCode, &Vec<(SyscallEvent, PrecompileEvent)>)> {
        self.events.iter()
    }

    /// Get all the precompile events for a given syscall code.
    #[inline]
    #[must_use]
    pub fn get_events(
        &self,
        syscall_code: SyscallCode,
    ) -> Option<&Vec<(SyscallEvent, PrecompileEvent)>> {
        assert!(syscall_code.should_send() == 1 || syscall_code.linux_sys() != 0);
        self.events.get(&syscall_code)
    }

    /// Folds each local memory event whose initial access is the final access
    /// of an earlier local event on the same address in this record into that
    /// earlier event, and returns how many events it removed.
    ///
    /// No access to the address falls between two such events, so the
    /// precompile chips' own accesses chain them inside the shard: the earlier
    /// event's final access and the later event's initial access are one access
    /// record, received and sent once each on the local memory bus and sent and
    /// received once each on the global bus.  One event from the earlier
    /// initial access to the later final access leaves both buses with the
    /// same balance, two global interactions and a local memory entry fewer.
    /// Consecutive calls of one precompile family (an elliptic-curve scalar
    /// multiplication's doubles and adds on one accumulator) chain this way.
    pub fn merge_chained_local_mem_events(&mut self) -> usize {
        type Slot = (SyscallCode, usize, usize);
        let mut order: Vec<(u32, u32, SyscallCode, usize)> = self
            .events
            .iter()
            .flat_map(|(code, events)| {
                events.iter().enumerate().map(|(i, (s, _))| (s.shard, s.clk, *code, i))
            })
            .collect();
        order.sort_unstable_by_key(|&(shard, clk, _, _)| (shard, clk));

        let mut open: HashMap<u32, (Slot, MemoryRecord)> = HashMap::new();
        let mut finals: HashMap<Slot, MemoryRecord> = HashMap::new();
        let mut dropped: HashSet<Slot> = HashSet::new();
        for (_, _, code, i) in order {
            for (k, local) in self.events[&code][i].1.local_mem_access().iter().enumerate() {
                let initial = local.initial_mem_access;
                match open.get_mut(&local.addr) {
                    Some((head, last))
                        if (last.shard, last.timestamp, last.value)
                            == (initial.shard, initial.timestamp, initial.value) =>
                    {
                        *last = local.final_mem_access;
                        finals.insert(*head, local.final_mem_access);
                        dropped.insert((code, i, k));
                    }
                    _ => {
                        open.insert(local.addr, ((code, i, k), local.final_mem_access));
                    }
                }
            }
        }
        if dropped.is_empty() {
            return 0;
        }

        for (code, events) in self.events.iter_mut() {
            for (i, (_, event)) in events.iter_mut().enumerate() {
                let locals = event.local_mem_access_mut();
                for (k, local) in locals.iter_mut().enumerate() {
                    if let Some(last) = finals.get(&(*code, i, k)) {
                        local.final_mem_access = *last;
                    }
                }
                let mut k = 0;
                locals.retain(|_| {
                    let keep = !dropped.contains(&(*code, i, k));
                    k += 1;
                    keep
                });
            }
        }
        dropped.len()
    }

    /// Get all the local events from all the precompile events.
    pub(crate) fn get_local_mem_events(&self) -> impl Iterator<Item = &MemoryLocalEvent> {
        let mut iterators = Vec::new();

        for (_, events) in self.events.iter() {
            iterators.push(events.get_local_mem_events());
        }

        iterators.into_iter().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::MemoryWriteRecord;

    fn access(shard: u32, timestamp: u32, value: u32) -> MemoryRecord {
        MemoryRecord { shard, timestamp, value }
    }

    fn local(addr: u32, initial: MemoryRecord, last: MemoryRecord) -> MemoryLocalEvent {
        MemoryLocalEvent { addr, initial_mem_access: initial, final_mem_access: last }
    }

    fn call(
        shard: u32,
        clk: u32,
        locals: Vec<MemoryLocalEvent>,
    ) -> (SyscallEvent, PrecompileEvent) {
        let syscall = SyscallEvent {
            pc: 0,
            next_pc: 0,
            shard,
            clk,
            a_record: MemoryWriteRecord::default(),
            a_record_is_real: false,
            syscall_id: 0,
            arg1: 0,
            arg2: 0,
            is_instruction: 0,
            recv_next_pc: 0,
            b_record: None.into(),
            c_record: None.into(),
        };
        let event = Uint256MulEvent { shard, clk, local_mem_access: locals, ..Default::default() };
        (syscall, PrecompileEvent::Uint256Mul(event))
    }

    fn add(
        events: &mut PrecompileEvents,
        code: SyscallCode,
        (syscall, event): (SyscallEvent, PrecompileEvent),
    ) {
        events.add_event(code, syscall, event);
    }

    fn locals(events: &PrecompileEvents) -> Vec<(u32, (u32, u32, u32), (u32, u32, u32))> {
        let mut v: Vec<_> = events
            .get_local_mem_events()
            .map(|e| {
                let (i, f) = (e.initial_mem_access, e.final_mem_access);
                (e.addr, (i.shard, i.timestamp, i.value), (f.shard, f.timestamp, f.value))
            })
            .collect();
        v.sort_unstable();
        v
    }

    #[test]
    fn merge_folds_chained_local_events_across_codes_in_time_order() {
        let (a, b) = (0x1000, 0x2000);
        let mut events = PrecompileEvents::default();
        add(
            &mut events,
            SyscallCode::SECP256K1_DOUBLE,
            call(2, 8, vec![local(a, access(2, 4, 9), access(2, 8, 10))]),
        );
        add(
            &mut events,
            SyscallCode::SECP256K1_ADD,
            call(1, 20, vec![local(a, access(1, 5, 7), access(1, 20, 8))]),
        );
        add(
            &mut events,
            SyscallCode::SECP256K1_DOUBLE,
            call(
                1,
                40,
                vec![
                    local(b, access(1, 3, 1), access(1, 40, 2)),
                    local(a, access(1, 20, 8), access(1, 40, 9)),
                ],
            ),
        );
        add(
            &mut events,
            SyscallCode::SECP256K1_ADD,
            call(2, 12, vec![local(a, access(2, 8, 10), access(2, 12, 11))]),
        );

        assert_eq!(events.merge_chained_local_mem_events(), 2);
        assert_eq!(
            locals(&events),
            vec![
                (a, (1, 5, 7), (1, 40, 9)),
                (a, (2, 4, 9), (2, 12, 11)),
                (b, (1, 3, 1), (1, 40, 2)),
            ]
        );
        assert_eq!(events.merge_chained_local_mem_events(), 0);
    }
}

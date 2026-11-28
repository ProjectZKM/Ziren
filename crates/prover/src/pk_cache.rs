//! Recursion proving keys, cached by the setup digest of their program, and
//! the guard that lets one thread build a key while others wait for it.

use crate::*;

/// Program-identity-keyed recursion proving keys, capped so the retained
/// WHIR data cannot grow without bound.
///
/// Eviction is least-recently-used.  A prover process is long-lived — the
/// core workers of a multi-device prover stay up across blocks — and
/// consecutive blocks reach largely the same programs (the compose set is fixed; the normalize set
/// follows the core shard shapes, which recur across blocks 62-91% of the
/// time), so once the cap holds a block's working set the key asked for
/// longest ago is the one least likely to be asked for again.  Below the
/// working set no order helps: a block walks its programs cyclically, and
/// both LRU and insertion order then evict each key just before its next
/// use — a repeated block hits ZERO times, which is what the old cap of 24
/// did (see [`RecursionPkCache::capacity`]).  The program cache keeps
/// insertion order for exactly that regime, see [`RecursionProgramCache`].
#[derive(Default)]
pub struct RecursionPkCache {
    pub(crate) entries:
        BTreeMap<[u8; 32], Arc<(StarkProvingKey<InnerSC>, StarkVerifyingKey<InnerSC>)>>,
    /// Least-recently-used first.
    order: std::collections::VecDeque<[u8; 32]>,
    /// Digests that must never be evicted.
    ///
    /// The compose programs are a small FIXED set, (child classes, arity), reached in
    /// every block; pinning them means their setup is paid once per PROCESS
    /// whatever the cap does to the normalize keys.
    pinned: std::collections::BTreeSet<[u8; 32]>,
    /// Keys some thread is building right now: a second thread that misses on
    /// one of these waits for the build instead of repeating it.
    in_flight: std::collections::BTreeSet<[u8; 32]>,
    pub hits: u64,
    pub misses: u64,
    /// Keys built by [`ZKMProver::recursion_pk_cached`].
    pub builds: u64,
    /// Lookups that waited for another thread's build of the same key.
    pub waits: u64,
}

impl RecursionPkCache {
    /// How many distinct programs' keys to retain.
    ///
    /// The default holds a whole block's working set: a reth block reaches
    /// ~91 distinct programs in one process, or ~45 per single-device core
    /// worker at 2 devices.  Below that a repeated block misses on every
    /// normalize node, and a miss is a full `setup` on the card thread:
    /// MEASURED on reth at 2 devices, cap 24 -> 38 misses per worker per block =
    /// 4.3-5.0 s of a ~89 s core stage; above the working set the repeated
    /// blocks miss 0 times and run 83.6-87.6 s (7 blocks, 4 runs).  The price
    /// is host memory — each retained key is a few hundred MiB of preprocessed
    /// traces plus their MLE form, and a 2-device worker sat at 80-92 GiB RSS —
    /// which the boxes this prover targets have.  Set it to 0 to hold nothing
    /// (which recovers the build-a-key-per-node behaviour, for measurement).
    fn capacity() -> usize {
        std::env::var("ZIREN_RECURSION_PK_CACHE_SIZE")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(96)
    }

    /// Mark a digest as never-evict.  Called before the key exists: the
    /// pre-warm knows WHICH programs are worth keeping without having to build
    /// their keys, so the first node to need one pays the setup and every later
    /// block gets it free.
    fn pin(&mut self, key: [u8; 32]) {
        self.pinned.insert(key);
    }

    pub(crate) fn get(
        &mut self,
        key: &[u8; 32],
    ) -> Option<Arc<(StarkProvingKey<InnerSC>, StarkVerifyingKey<InnerSC>)>> {
        match self.entries.get(key) {
            Some(v) => {
                self.hits += 1;
                if let Some(pos) = self.order.iter().position(|k| k == key) {
                    self.order.remove(pos);
                    self.order.push_back(*key);
                }
                Some(Arc::clone(v))
            }
            None => {
                self.misses += 1;
                None
            }
        }
    }

    pub(crate) fn insert(
        &mut self,
        key: [u8; 32],
        pk: StarkProvingKey<InnerSC>,
        vk: StarkVerifyingKey<InnerSC>,
    ) -> Arc<(StarkProvingKey<InnerSC>, StarkVerifyingKey<InnerSC>)> {
        if let Some(v) = self.entries.get(&key) {
            return Arc::clone(v);
        }
        let value = Arc::new((pk, vk));
        self.entries.insert(key, Arc::clone(&value));
        self.order.push_back(key);
        let mut examined = 0usize;
        while self.order.len() > Self::capacity() && examined < self.order.len() {
            let Some(old) = self.order.pop_front() else { break };
            if self.pinned.contains(&old) {
                self.order.push_back(old);
                examined += 1;
                continue;
            }
            self.entries.remove(&old);
            examined = 0;
        }
        value
    }
}

/// Clears a key's in-flight mark and wakes the waiters, on the success path
/// and on unwind alike, so a failed build never leaves waiters asleep.
struct InFlightGuard<'a, C: ZKMProverComponents> {
    prover: &'a ZKMProver<C>,
    key: [u8; 32],
}

impl<C: ZKMProverComponents> Drop for InFlightGuard<'_, C> {
    fn drop(&mut self) {
        self.prover.recursion_pks_cache.lock().unwrap().in_flight.remove(&self.key);
        self.prover.recursion_pk_cache_ready.notify_all();
    }
}

impl<C: ZKMProverComponents> ZKMProver<C> {
    /// The key for `program`, as the recursion pk cache sees it.
    pub fn recursion_pk_cache_key(program: &RecursionProgram<KoalaBear>) -> [u8; 32] {
        zkm_recursion_core::setup_digest(program)
    }

    /// The cached `(pk, vk)` for a program, if its key has been built before.
    /// The returned `Arc` is cheap to clone and a device prover holds it
    /// for one node.
    pub fn recursion_pk_cache_get(
        &self,
        key: &[u8; 32],
    ) -> Option<Arc<(StarkProvingKey<InnerSC>, StarkVerifyingKey<InnerSC>)>> {
        self.recursion_pks_cache.lock().unwrap().get(key)
    }

    /// Publish a freshly built key.  Returns the `Arc` that is actually in the
    /// cache, so a caller that lost a race uses the canonical key rather than
    /// its own copy.
    /// Keep this program's key for the life of the process — see
    /// [`RecursionPkCache::pin`].
    pub fn pin_recursion_pk(&self, key: [u8; 32]) {
        self.recursion_pks_cache.lock().unwrap().pin(key);
    }

    pub fn recursion_pk_cache_insert(
        &self,
        key: [u8; 32],
        pk: StarkProvingKey<InnerSC>,
        vk: StarkVerifyingKey<InnerSC>,
    ) -> Arc<(StarkProvingKey<InnerSC>, StarkVerifyingKey<InnerSC>)> {
        self.recursion_pks_cache.lock().unwrap().insert(key, pk, vk)
    }

    /// Hits and misses since the process started, for the stage report.
    pub fn recursion_pk_cache_counts(&self) -> (u64, u64) {
        let g = self.recursion_pks_cache.lock().unwrap();
        (g.hits, g.misses)
    }

    /// The `(pk, vk)` of `program` through the recursion pk cache, built by
    /// `build` on a miss.
    ///
    /// Concurrent misses on one key build it once: the first thread marks the
    /// key in flight and builds outside the lock, later threads wait on
    /// [`Self::recursion_pk_cache_ready`] and take the published `Arc`.  The
    /// key is the program's setup digest, so a cached pair is the pair `setup`
    /// would rebuild for the same program.
    pub fn recursion_pk_cached(
        &self,
        program: &RecursionProgram<KoalaBear>,
        build: impl FnOnce() -> (StarkProvingKey<InnerSC>, StarkVerifyingKey<InnerSC>),
    ) -> Arc<(StarkProvingKey<InnerSC>, StarkVerifyingKey<InnerSC>)> {
        let key = Self::recursion_pk_cache_key(program);
        let mut g = self.recursion_pks_cache.lock().unwrap();
        if let Some(v) = g.get(&key) {
            return v;
        }
        while g.in_flight.contains(&key) {
            g.waits += 1;
            g = self.recursion_pk_cache_ready.wait(g).unwrap();
            if let Some(v) = g.entries.get(&key) {
                return Arc::clone(v);
            }
        }
        g.in_flight.insert(key);
        drop(g);
        let guard = InFlightGuard { prover: self, key };
        let (pk, vk) = build();
        let mut g = self.recursion_pks_cache.lock().unwrap();
        g.builds += 1;
        let value = g.insert(key, pk, vk);
        tracing::debug!(
            hits = g.hits,
            misses = g.misses,
            builds = g.builds,
            waits = g.waits,
            "recursion pk cache"
        );
        drop(g);
        drop(guard);
        value
    }
}

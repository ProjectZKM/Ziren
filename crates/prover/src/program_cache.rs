//! The recursion program caches and the program builders behind them.
//!
//! The caches are unconditional: they are keyed by a structural signature of
//! their input, so a hit returns a program the builder would have produced
//! byte-for-byte.  `ZIREN_VERIFY_PROGRAM_CACHE=1` checks that property, and
//! `ZIREN_PROGRAM_CACHE_DIR` shares the programs across processes.

/// Cache-divergence audit — ON only under `ZIREN_VERIFY_PROGRAM_CACHE=1`.
///
/// Rebuilds the program and bincode byte-compares it against the cached copy
/// on EVERY cache hit, turning the caches' soundness condition
///
/// ```text
/// shape_key(a) == shape_key(b)  ⟹  program(a) == program(b)
/// ```
///
/// into a checked assertion.  It doubles the program-build work by
/// construction, so it is a bring-up / CI tool and never on by default.
pub fn program_cache_audit_enabled() -> bool {
    zkm_pcs::diagnostics::env_flag("ZIREN_VERIFY_PROGRAM_CACHE", false)
}

// Cross-block / cross-process disk cache.
//
// The in-memory program cache is a field on the `ZKMProver`, so it warms
// across the blocks ONE process proves — but a fresh process (a restart, or a
// per-block worker) starts cold and re-pays the builds.  `ZIREN_PROGRAM_
// CACHE_DIR=<dir>` backs the same shape_key -> program map with files under
// `<dir>`, so any process sharing the directory reuses what an earlier one
// built.
//
// SOUNDNESS: a stale program served for a shape_key whose emitted ops changed
// would be a forged-circuit bug.  The files therefore live under a subdirectory
// named by a fingerprint of the RUNNING EXECUTABLE — any recompile changes the
// binary, hence the fingerprint, hence a cold directory.  A process that
// cannot read its executable has no fingerprint and runs without the disk cache.  A file can thus only
// be reused by the exact build that wrote it, which is precisely the
// cross-block/cross-process reuse we want and nothing wider.  `ZIREN_VERIFY_
// PROGRAM_CACHE=1` still byte-checks every in-memory hit, disk-loaded included.

use crate::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

/// Disk-cache reuse counters, for the stage report.
pub static DISK_HITS: AtomicU64 = AtomicU64::new(0);
pub static DISK_STORES: AtomicU64 = AtomicU64::new(0);

/// A fingerprint of the running executable — cheap and rebuild-sensitive: any
/// recompile rewrites the binary, changing (len, hash-of-bytes).  Non-crypto is
/// fine; it only has to CHANGE on a code change, not resist forgery.
///
/// An error when the executable cannot be read: a constant in its place
/// would let different builds share one directory.
fn binary_fingerprint() -> std::io::Result<u64> {
    use std::hash::{Hash, Hasher};
    let bytes = std::env::current_exe().and_then(std::fs::read)?;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.len().hash(&mut h);
    bytes.hash(&mut h);
    Ok(h.finish())
}

/// The fingerprinted directory, or `None` when the disk cache is disabled.
/// Created on first use.
pub fn disk_cache_dir() -> Option<&'static PathBuf> {
    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    DIR.get_or_init(|| {
        let base = std::env::var_os("ZIREN_PROGRAM_CACHE_DIR")?;
        let fingerprint = match binary_fingerprint() {
            Ok(fingerprint) => fingerprint,
            Err(e) => {
                tracing::warn!(
                    "program disk cache disabled: cannot read the running executable: {e}"
                );
                return None;
            }
        };
        let dir = PathBuf::from(base).join(format!("fp-{fingerprint:016x}"));
        if let Err(e) = std::fs::create_dir_all(&dir) {
            tracing::warn!("program disk cache: cannot create {}: {e}", dir.display());
            return None;
        }
        tracing::info!("program disk cache: {}", dir.display());
        Some(dir)
    })
    .as_ref()
}

fn entry_path(dir: &std::path::Path, stage: &str, key: u64) -> PathBuf {
    dir.join(format!("{stage}-{key:016x}.bin"))
}

/// Load a program from disk, or `None` on miss / any read-or-decode error
/// (a corrupt or partial file must fall back to a rebuild, never crash).
pub fn disk_load<F: serde::de::DeserializeOwned>(
    stage: &str,
    key: u64,
) -> Option<zkm_recursion_core::RecursionProgram<F>> {
    load_from(disk_cache_dir()?, stage, key)
}

fn load_from<F: serde::de::DeserializeOwned>(
    dir: &std::path::Path,
    stage: &str,
    key: u64,
) -> Option<zkm_recursion_core::RecursionProgram<F>> {
    let path = entry_path(dir, stage, key);
    let bytes = std::fs::read(&path).ok()?;
    match bincode::deserialize::<zkm_recursion_core::RecursionProgram<F>>(&bytes) {
        Ok(p) => {
            if let Err(e) = p.seq_blocks.validate_offsets(&p.event_counts) {
                tracing::warn!(
                    "program disk cache: {} fails its offset invariant ({e}); rebuilding",
                    path.display()
                );
                return None;
            }
            DISK_HITS.fetch_add(1, Ordering::Relaxed);
            Some(p)
        }
        Err(e) => {
            tracing::warn!("program disk cache: corrupt {}: {e}; rebuilding", path.display());
            None
        }
    }
}

/// Write a program to disk atomically (tmp + rename), so a concurrent reader
/// never sees a partial file.  Best-effort: a write failure is logged, not
/// fatal — the in-memory cache still holds the program.
///
/// The caller stores after a load that gave nothing, so an entry already at
/// the path is one the load rejected, or one another process of this build
/// wrote meanwhile: the rename replaces it either way.
pub fn disk_store<F: serde::Serialize>(
    stage: &str,
    key: u64,
    program: &zkm_recursion_core::RecursionProgram<F>,
) {
    if let Some(dir) = disk_cache_dir() {
        store_into(dir, stage, key, program);
    }
}

fn store_into<F: serde::Serialize>(
    dir: &std::path::Path,
    stage: &str,
    key: u64,
    program: &zkm_recursion_core::RecursionProgram<F>,
) {
    static WRITES: AtomicU64 = AtomicU64::new(0);
    let path = entry_path(dir, stage, key);
    let bytes = match bincode::serialize(program) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("program disk cache: serialize failed for {stage} {key:#x}: {e}");
            return;
        }
    };
    let tmp = dir.join(format!(
        "{stage}-{key:016x}.{}.{}.tmp",
        std::process::id(),
        WRITES.fetch_add(1, Ordering::Relaxed)
    ));
    if std::fs::write(&tmp, &bytes).is_ok() && std::fs::rename(&tmp, &path).is_ok() {
        DISK_STORES.fetch_add(1, Ordering::Relaxed);
    } else {
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Shape-keyed recursion programs, capped so a workload with a wide shape
/// spread cannot grow the map without bound.
///
/// A recursion tree walks its layers in order and never returns to an
/// earlier one, so insertion order is also least-likely-to-be-asked-again
/// order and is what the eviction uses.
///
/// Each entry is a program with its shape and pins set, beside its setup
/// digest.
#[derive(Default)]
pub struct RecursionProgramCache {
    /// The cached program AND its `setup_digest`.  Hashing a program is not
    /// cheap -- SHA-256 over the whole serialized instruction stream, ~291 ms
    /// for a 7.1M-instruction node, 73.7 s summed over a reth compress tree --
    /// and the digest is a pure function of the bytes, so a cache HIT already
    /// knows it.  Computed once at insert, beside the `Arc` it describes.
    entries: BTreeMap<u64, (Arc<RecursionProgram<KoalaBear>>, [u8; 32])>,
    order: std::collections::VecDeque<u64>,
    pub hits: u64,
    pub misses: u64,
    /// Builds thrown away because another thread finished the SAME shape first.
    ///
    /// `cached_program` releases the cache lock before calling `build()`, so
    /// concurrent nodes of one shape each construct a full program and all but
    /// one discard it in [`Self::insert`].  That is pure waste, and its size
    /// decides whether a single-flight gate is worth the nested-blocking risk
    /// of holding a lock across the build — so count it before building one.
    pub dup_builds: u64,
}

impl RecursionProgramCache {
    /// How many distinct programs to retain.  A layer contributes a handful
    /// of distinct shapes, so a small cap still holds a whole layer; set it
    /// to 0 to hold nothing, which recovers the build-per-node behaviour for
    /// measurement.
    ///
    /// Default 128 (`ZIREN_RECURSION_PROGRAM_CACHE_SIZE` overrides).  The pk
    /// cache is sized separately, to a block's working set (see
    /// [`RecursionPkCache::capacity`]).  A cache cannot change what is proven:
    /// the cached program is the one a rebuild would produce.
    ///
    /// Eviction is insertion-ordered, not LRU: a tree walks its layers in
    /// order, so the access pattern is cyclic over more distinct shapes than
    /// the cache holds, and for a cyclic pattern LRU evicts exactly the entry
    /// wanted next.  (The pk cache is LRU because its cap exceeds the
    /// per-block working set.)
    pub(crate) fn capacity() -> usize {
        std::env::var("ZIREN_RECURSION_PROGRAM_CACHE_SIZE")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(128)
    }

    pub(crate) fn get(&mut self, key: u64) -> Option<(Arc<RecursionProgram<KoalaBear>>, [u8; 32])> {
        match self.entries.get(&key) {
            Some((v, d)) => {
                self.hits += 1;
                Some((Arc::clone(v), *d))
            }
            None => {
                self.misses += 1;
                None
            }
        }
    }

    /// First writer wins: a racing builder for the same shape discards its
    /// own copy rather than replacing one other nodes already hold.
    pub(crate) fn insert(
        &mut self,
        key: u64,
        program: Arc<RecursionProgram<KoalaBear>>,
    ) -> (Arc<RecursionProgram<KoalaBear>>, [u8; 32]) {
        if let Some((v, d)) = self.entries.get(&key) {
            self.dup_builds += 1;
            return (Arc::clone(v), *d);
        }
        let digest = zkm_recursion_core::setup_digest(&*program);
        self.entries.insert(key, (Arc::clone(&program), digest));
        self.order.push_back(key);
        while self.order.len() > Self::capacity() {
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
            }
        }
        (program, digest)
    }
}

impl<C: ZKMProverComponents> ZKMProver<C> {
    /// Settle a recursion program's rows and pin class — see
    /// [`RecursionShapeConfig::fix_shape_kind`].  A no-op without a shape
    /// config (`FIX_RECURSION_SHAPES=false`), which gives up vk enumerability.
    fn fix_recursion_shape_kind(&self, program: &mut RecursionProgram<KoalaBear>, kind: &str) {
        if let Some(config) = self.compress_shape_config.as_ref() {
            config.fix_shape_kind(program, kind);
        }
    }

    /// Build the Normalize recursion program and its
    /// `setup_digest` (the proving-key cache key).
    ///
    /// The program is snapped through [`Self::fix_recursion_shape`], which
    /// keeps its verifying key inside `ZKMProofShape::generate`'s enumerated
    /// space.  Programs are cached by shape (see
    /// [`Self::normalize_programs_cache`]): many core shards share
    /// one program.  The digest is cached with it, since hashing a
    /// multi-million-instruction program is expensive.
    pub fn recursion_program(
        &self,
        input: &ZKMCoreWitnessValues<CoreSC>,
    ) -> (Arc<RecursionProgram<KoalaBear>>, [u8; 32]) {
        if zkm_pcs::diagnostics::shape_events_enabled() {
            let mut names: Vec<&str> = input
                .shard_proofs
                .iter()
                .flat_map(|sp| sp.chip_heights.keys().map(String::as_str))
                .collect();
            names.sort_unstable();
            names.dedup();
            let heights: Vec<String> = input
                .shard_proofs
                .iter()
                .flat_map(|sp| sp.chip_heights.iter().map(|(n, h)| format!("{n}:{h}")))
                .collect();
            let packing: Vec<String> = input
                .shard_proofs
                .iter()
                .map(|sp| match &sp.evaluation_proof {
                    zkm_pcs::shard_level::shard_proof::EvaluationProof::Bundle(b) => format!(
                        "L={} noff={} cc={:?}",
                        b.packing.log_dense_size,
                        b.packing.offsets.len(),
                        b.packing.column_counts,
                    ),
                    other => (if matches!(
                        other,
                        zkm_pcs::shard_level::shard_proof::EvaluationProof::Empty
                    ) {
                        "empty"
                    } else {
                        "bytes"
                    })
                    .to_string(),
                })
                .collect();
            let rounds: Vec<String> = input
                .shard_proofs
                .iter()
                .map(|sp| match &sp.evaluation_proof {
                    zkm_pcs::shard_level::shard_proof::EvaluationProof::Bundle(b) => {
                        format!(
                            "stripes={:?}",
                            b.whir_proof
                                .batch_evaluations
                                .iter()
                                .map(|r| r.len())
                                .collect::<Vec<_>>(),
                        )
                    }
                    _ => "nobundle".to_string(),
                })
                .collect();
            let dims: Vec<String> = input
                .shard_proofs
                .iter()
                .map(|sp| {
                    zkm_recursion_circuit::machine::shape_signature::describe_shard_proof_structure(
                        sp,
                    )
                    .into_iter()
                    .filter(|(n, _)| !n.starts_with("cc") && !n.starts_with("h."))
                    .map(|(n, v)| format!("{n}={v}"))
                    .collect::<Vec<_>>()
                    .join(" ")
                })
                .collect();
            tracing::debug!(
                target: zkm_pcs::diagnostics::SHAPE_TARGET,
                stage = "normalize",
                shape_key = format_args!("{:016x}", input.shape_key()),
                first = input.is_first_shard,
                chips = names.join(","),
                packing = packing.join(" | "),
                stripes = rounds.join(" | "),
                dims = dims.join(" | "),
                heights = heights.join(","),
                "program shape"
            );
        }
        self.cached_program(
            &self.normalize_programs_cache,
            self.verification_keyed(input.shape_key()),
            "normalize",
            || self.build_normalize_program_uncached(input),
        )
    }

    /// The program that verifies the global proofs of `input`, cached by
    /// their number and shapes: the table slots of each and their chips.
    pub fn global_round_program(
        &self,
        input: &zkm_recursion_circuit::machine::ZKMGlobalRoundWitnessValues<CoreSC>,
    ) -> (Arc<RecursionProgram<KoalaBear>>, [u8; 32]) {
        self.cached_program(
            &self.global_programs_cache,
            self.verification_keyed(input.shape_key()),
            "global",
            || self.build_global_round_program_uncached(input),
        )
    }

    /// Uncached body of [`Self::global_round_program`]: the program with its
    /// shape and pins set, which the cache audit also rebuilds.
    pub(crate) fn build_global_round_program_uncached(
        &self,
        input: &zkm_recursion_circuit::machine::ZKMGlobalRoundWitnessValues<CoreSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        let mut program = zkm_recursion_circuit::machine::programs::build_global_round_program(
            self.core_prover.machine(),
            input,
            self.core_prover.machine().max_log_row_count(),
        );
        self.fix_recursion_shape_kind(&mut program, "normalize");
        Arc::new(program)
    }

    /// The program that verifies a global proof of `shape`, built from the
    /// shape alone: the program, under the same cache key,
    /// [`Self::global_round_program`] gives for a real proof of as many
    /// rounds of the shape's chips at the shape's stacking blocks.
    pub fn global_round_program_for_shape(
        &self,
        shape: &zkm_recursion_circuit::machine::ZKMGlobalRoundShape,
    ) -> (Arc<RecursionProgram<KoalaBear>>, [u8; 32]) {
        self.global_round_program(
            &zkm_recursion_circuit::machine::ZKMGlobalRoundWitnessValues::dummy(
                self.core_prover.machine(),
                shape,
            ),
        )
    }

    /// `shape_key` with the prover's `vk_verification` folded in, the key
    /// every program cache (in memory and on disk) is addressed by:
    /// `vk_verification` selects the instructions the program emits
    /// (`value_assertions`), so a program built under one setting is a
    /// different program, with a different verifying key, from the same shape
    /// built under the other.
    pub(crate) fn verification_keyed(&self, shape_key: u64) -> u64 {
        if self.vk_verification {
            shape_key ^ 0x5851_F42D_4C95_7F2D
        } else {
            shape_key
        }
    }

    /// Uncached body of [`Self::recursion_program`]: the program with its
    /// shape and pins set, which the cache audit also rebuilds.
    pub(crate) fn build_normalize_program_uncached(
        &self,
        input: &ZKMCoreWitnessValues<CoreSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        let max_log_row_count = self.core_prover.machine().max_log_row_count();
        let mut program =
            build_normalize_program(self.core_prover.machine(), input, max_log_row_count);
        self.fix_recursion_shape_kind(
            &mut program,
            if input.is_complete { "normalize-root" } else { "normalize" },
        );
        Arc::new(program)
    }

    /// Shared cache wrapper for the shape-keyed recursion program caches.
    ///
    /// Sound exactly when `shape_key` is injective on program bytes; under
    /// `ZIREN_VERIFY_PROGRAM_CACHE=1` every hit, in memory or on disk,
    /// rebuilds the program through no cache at all and bincode
    /// byte-compares, which turns that condition into a checked assertion.
    pub(crate) fn cached_program(
        &self,
        cache: &Mutex<RecursionProgramCache>,
        cache_key: u64,
        stage: &'static str,
        build: impl Fn() -> Arc<RecursionProgram<KoalaBear>>,
    ) -> (Arc<RecursionProgram<KoalaBear>>, [u8; 32]) {
        let audit = crate::program_cache::program_cache_audit_enabled();
        let cached = cache.lock().unwrap().get(cache_key);
        if let Some((cached, digest)) = cached {
            if audit {
                let fresh = build();
                let cached_bytes =
                    bincode::serialize(&*cached).expect("program cache: serialize cached");
                let fresh_bytes =
                    bincode::serialize(&*fresh).expect("program cache: serialize fresh");
                assert_eq!(
                    cached_bytes, fresh_bytes,
                    "{stage} program cache divergence at shape_key={cache_key:#018x}: two \
                     inputs collided in shape_key but produced different programs — extend \
                     shape_key to cover the diverging field",
                );
            }
            return (cached, digest);
        }
        if let Some(program) = crate::program_cache::disk_load::<KoalaBear>(stage, cache_key) {
            let program = Arc::new(program);
            if audit {
                let fresh = build();
                assert_eq!(
                    bincode::serialize(&*program).expect("serialize disk-loaded"),
                    bincode::serialize(&*fresh).expect("serialize fresh"),
                    "{stage} DISK cache divergence at shape_key={cache_key:#018x}: a cached \
                     file does not match a fresh build — the binary fingerprint should have \
                     prevented this",
                );
            }
            return cache.lock().unwrap().insert(cache_key, program);
        }
        let program = build();
        crate::program_cache::disk_store(stage, cache_key, &*program);
        cache.lock().unwrap().insert(cache_key, program)
    }

    /// `(disk_hits, disk_stores)` for the cross-process program cache.
    pub fn recursion_program_disk_counts(&self) -> (u64, u64) {
        use std::sync::atomic::Ordering;
        (
            crate::program_cache::DISK_HITS.load(Ordering::Relaxed),
            crate::program_cache::DISK_STORES.load(Ordering::Relaxed),
        )
    }

    /// `(normalize_dup_builds, compose_dup_builds)` — see
    /// [`RecursionProgramCache::dup_builds`].
    pub fn recursion_program_dup_builds(&self) -> (u64, u64) {
        let n = self.normalize_programs_cache.lock().unwrap();
        let c = self.compose_programs_cache.lock().unwrap();
        (n.dup_builds, c.dup_builds)
    }

    /// Hits and misses of the normalize and compose program caches, for the
    /// stage report: `(normalize_hits, normalize_misses, compose_hits, compose_misses)`.
    pub fn recursion_program_cache_counts(&self) -> (u64, u64, u64, u64) {
        let n = self.normalize_programs_cache.lock().unwrap();
        let c = self.compose_programs_cache.lock().unwrap();
        (n.hits, n.misses, c.hits, c.misses)
    }

    /// Build the Compose recursion program and its `setup_digest`
    /// (the proving-key cache key).
    ///
    /// Programs and digests are cached by shape (see
    /// [`Self::compose_programs_cache`]).
    pub fn compose_program(
        &self,
        input: &ZKMCompressWitnessValues<InnerSC>,
    ) -> (Arc<RecursionProgram<KoalaBear>>, [u8; 32]) {
        if zkm_pcs::diagnostics::shape_events_enabled() {
            tracing::debug!(
                target: zkm_pcs::diagnostics::SHAPE_TARGET,
                stage = "compose",
                shape_key = format_args!("{:016x}", input.shape_key()),
                key = format_args!("{:016x}", self.verification_keyed(input.shape_key())),
                components = input.shape_diag(),
                "program shape"
            );
        }
        self.cached_program(
            &self.compose_programs_cache,
            self.verification_keyed(input.shape_key()),
            "compose",
            || self.build_compose_program_uncached(input),
        )
    }

    /// Uncached body of [`Self::compose_program`]: the program with its
    /// shape and pins set, which the cache audit also rebuilds.
    pub(crate) fn build_compose_program_uncached(
        &self,
        input: &ZKMCompressWitnessValues<InnerSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        let max_log_row_count = self.compress_prover.machine().max_log_row_count();
        let mut program = build_compose_program(
            self.compress_prover.machine(),
            input,
            max_log_row_count,
            self.vk_verification,
            PublicValuesOutputDigest::Reduce,
        );
        self.fix_recursion_shape_kind(
            &mut program,
            if input.is_complete { "compose-root" } else { "compose" },
        );
        Arc::new(program)
    }

    /// Build the Deferred recursion program.
    pub fn deferred_program(
        &self,
        input: &ZKMDeferredWitnessValues<CompressedSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        let max_log_row_count = self.root_prover.machine().max_log_row_count();
        let mut program = build_deferred_program(
            self.root_prover.machine(),
            input,
            max_log_row_count,
            self.vk_verification,
        );
        self.fix_recursion_shape_kind(&mut program, "deferred");
        Arc::new(program)
    }
}

#[cfg(test)]
mod disk_tests {
    use super::{entry_path, load_from, store_into};
    use p3_koala_bear::KoalaBear;
    use zkm_recursion_core::RecursionProgram;

    /// A store after a rejected load replaces the entry: the next load gives
    /// the stored program again, and no tmp file is left behind.
    #[test]
    fn store_replaces_a_corrupt_entry() {
        let dir = std::env::temp_dir().join(format!("zkm-program-cache-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let program = RecursionProgram::<KoalaBear> { total_memory: 7, ..Default::default() };
        let stored = bincode::serialize(&program).unwrap();
        store_into(&dir, "compose", 5, &program);
        let path = entry_path(&dir, "compose", 5);
        assert_eq!(std::fs::read(&path).unwrap(), stored);

        std::fs::write(&path, &stored[..stored.len() / 2]).unwrap();
        assert!(load_from::<KoalaBear>(&dir, "compose", 5).is_none());
        store_into(&dir, "compose", 5, &program);
        let loaded = load_from::<KoalaBear>(&dir, "compose", 5).expect("the replaced entry loads");
        assert_eq!(bincode::serialize(&loaded).unwrap(), stored);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

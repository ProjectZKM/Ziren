//! Bring-up switches for the recursion program caches.
//!
//! The caches themselves are unconditional: they are keyed by a structural
//! signature of their input, so a hit returns a program the builder would
//! have produced byte-for-byte, and correctness does not depend on a profile.
//! What remains here is the audit that CHECKS that property.

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
    match std::env::var("ZIREN_VERIFY_PROGRAM_CACHE") {
        Ok(v) => v == "1" || v.eq_ignore_ascii_case("true"),
        Err(_) => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────
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
// binary, hence the fingerprint, hence a cold directory.  A file can thus only
// be reused by the exact build that wrote it, which is precisely the
// cross-block/cross-process reuse we want and nothing wider.  `ZIREN_VERIFY_
// PROGRAM_CACHE=1` still byte-checks every in-memory hit, disk-loaded included.

use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// Disk-cache reuse counters, for the stage report.
pub static DISK_HITS: AtomicU64 = AtomicU64::new(0);
pub static DISK_STORES: AtomicU64 = AtomicU64::new(0);

/// A fingerprint of the running executable — cheap and rebuild-sensitive: any
/// recompile rewrites the binary, changing (len, hash-of-bytes).  Non-crypto is
/// fine; it only has to CHANGE on a code change, not resist forgery.
fn binary_fingerprint() -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    match std::env::current_exe().and_then(std::fs::read) {
        Ok(bytes) => {
            bytes.len().hash(&mut h);
            bytes.hash(&mut h);
        }
        // No exe (unusual) -> a fixed fallback; the dir still isolates by env.
        Err(_) => 0u64.hash(&mut h),
    }
    h.finish()
}

/// The fingerprinted directory, or `None` when the disk cache is disabled.
/// Created on first use.
pub fn disk_cache_dir() -> Option<&'static PathBuf> {
    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    DIR.get_or_init(|| {
        let base = std::env::var_os("ZIREN_PROGRAM_CACHE_DIR")?;
        let dir = PathBuf::from(base).join(format!("fp-{:016x}", binary_fingerprint()));
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
    let dir = disk_cache_dir()?;
    let path = entry_path(dir, stage, key);
    let bytes = std::fs::read(&path).ok()?;
    match bincode::deserialize(&bytes) {
        Ok(p) => {
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
pub fn disk_store<F: serde::Serialize>(
    stage: &str,
    key: u64,
    program: &zkm_recursion_core::RecursionProgram<F>,
) {
    let Some(dir) = disk_cache_dir() else { return };
    let path = entry_path(dir, stage, key);
    if path.exists() {
        return;
    }
    let bytes = match bincode::serialize(program) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("program disk cache: serialize failed for {stage} {key:#x}: {e}");
            return;
        }
    };
    // Unique tmp name so concurrent writers do not collide on the rename source.
    let tmp = dir.join(format!("{stage}-{key:016x}.{}.tmp", std::process::id()));
    if std::fs::write(&tmp, &bytes).is_ok() && std::fs::rename(&tmp, &path).is_ok() {
        DISK_STORES.fetch_add(1, Ordering::Relaxed);
    } else {
        let _ = std::fs::remove_file(&tmp);
    }
}

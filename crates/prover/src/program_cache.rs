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

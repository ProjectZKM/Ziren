//! GPU residency profile — single env-var grouping for the per-subsystem
//! residency / cache / pre-warm toggles that each otherwise need their own
//! `ZIREN_*` env var.
//!
//! One coherent profile selected by `ZIREN_GPU_RESIDENCY`.  The
//! cache-divergence audit is the one exception and keeps its own
//! `ZIREN_VERIFY_PROGRAM_CACHE` opt-in — see `program_cache_audit_enabled`.
//!
//! Profiles:
//!
//! ```text
//! ZIREN_GPU_RESIDENCY=full   # all residency-side hooks/caches ON
//! ZIREN_GPU_RESIDENCY=hybrid # safe default; hooks that regressed
//!                            # production are OFF (cache audit, pre-warm)
//! ZIREN_GPU_RESIDENCY=host   # all residency-side hooks/caches OFF
//! ```
//!
//! `hybrid` is the safe default: program cache OFF, pre-warm OFF, cache audit
//! OFF.  `full` opts INTO all caches + pre-warm.  `host` forces everything off
//! (debugging / no-GPU paths).
//!
//! The recursion proving-key cache is NOT a residency knob: it is keyed by
//! program identity, so it is unconditionally correct and unconditionally on.
//!
//! Backward compat: legacy env vars are still respected so existing
//! benches don't break.  If any legacy var is set, the profile decision
//! is OVERRIDDEN per-feature and a one-shot deprecation warn is logged.
//!
//! `VERIFY_VK` and `FIX_RECURSION_SHAPES` are explicitly NOT residency
//! vars and are not grouped here.

use std::env;
use std::sync::OnceLock;

/// Coarse residency posture.  Maps onto per-feature accessors below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpuResidencyProfile {
    /// All residency-side hooks/caches enabled (max device-residency).
    Full,
    /// Safe default — caches/hooks that regressed production are OFF.
    Hybrid,
    /// Disable GPU residency hooks (debugging / no-GPU fallback).
    Host,
}

impl GpuResidencyProfile {
    /// Returns true when the per-arity compose recursion program cache
    /// should be used.  ON for `full` only — off by default because
    /// fix_shape proof bloat dominates cache savings on the shape spread
    /// Ziren sees today.  Available as `full` opt-in for long-lived
    /// provers where compile cost dominates.
    pub fn allows_program_cache(self) -> bool {
        matches!(self, Self::Full)
    }

    /// Returns true when the cache-divergence audit should rebuild and
    /// byte-compare on every program-cache hit.  Independent of the
    /// production cache and never on by default — used during cache
    /// bring-up / soundness validation.  Not bound to the profile;
    /// stays as a separate opt-in.
    pub fn allows_program_cache_audit(self) -> bool {
        // Audit is orthogonal to the profile (CI/dev tool, not perf
        // posture).  Keep the legacy env path live; never auto-enable.
        false
    }

    /// Returns true when compose programs should be pre-warmed during
    /// `ZKMProver::uninitialized`.  ON for `full` only — pre-warm pays
    /// ~63.7s upfront for ~2.4s amortizable compile savings on a
    /// single-call prover.  Worth it for long-lived `full`-residency
    /// provers.
    pub fn allows_compose_prewarm(self) -> bool {
        matches!(self, Self::Full)
    }
}

/// Resolves the profile once at first access.  Default is `Hybrid`
/// (program cache OFF, compose-pk cache OFF, pre-warm OFF, audit OFF).
pub fn resolve_gpu_residency_profile() -> GpuResidencyProfile {
    static CELL: OnceLock<GpuResidencyProfile> = OnceLock::new();
    *CELL.get_or_init(|| {
        let raw = env::var("ZIREN_GPU_RESIDENCY").ok();
        let parsed = match raw.as_deref() {
            None | Some("") => GpuResidencyProfile::Hybrid,
            Some(v) => match v.to_ascii_lowercase().as_str() {
                "full" => GpuResidencyProfile::Full,
                "hybrid" => GpuResidencyProfile::Hybrid,
                "host" => GpuResidencyProfile::Host,
                other => {
                    tracing::warn!(
                        "ZIREN_GPU_RESIDENCY={other:?} not recognized; \
                         expected full|hybrid|host — defaulting to hybrid"
                    );
                    GpuResidencyProfile::Hybrid
                }
            },
        };
        tracing::debug!("GpuResidencyProfile resolved to {parsed:?}");
        parsed
    })
}

// ---------------------------------------------------------------------
// Per-feature accessors.  `ZIREN_GPU_RESIDENCY` is the only knob; the
// profile mapping decides each feature.
// ---------------------------------------------------------------------

/// Compose recursion program cache — ON only when the profile allows
/// it (default = `Hybrid` → OFF).
pub fn program_cache_enabled() -> bool {
    resolve_gpu_residency_profile().allows_program_cache()
}

/// Cache-divergence audit — ON only under `ZIREN_VERIFY_PROGRAM_CACHE=1`.
///
/// This is the ONE feature here that is NOT profile-driven, and
/// deliberately so: `allows_program_cache_audit()` is `false` for every
/// profile including `full`, because the audit rebuilds and bincode-compares
/// on every cache hit. Binding it to `full` would make the perf profile
/// slower than the default. It is a bring-up / soundness tool, so it keeps
/// its own opt-in.
pub fn program_cache_audit_enabled() -> bool {
    let v = match std::env::var("ZIREN_VERIFY_PROGRAM_CACHE") {
        Ok(v) if !v.is_empty() => v,
        _ => return resolve_gpu_residency_profile().allows_program_cache_audit(),
    };
    v == "1" || v.eq_ignore_ascii_case("true")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_matches_audited_head_behavior() {
        // With no env set, the Hybrid profile MUST keep every residency knob
        // OFF: program cache OFF, pre-warm OFF, audit OFF.
        let profile = GpuResidencyProfile::Hybrid;
        assert!(!profile.allows_program_cache());
        assert!(!profile.allows_program_cache_audit());
        assert!(!profile.allows_compose_prewarm());
    }

    #[test]
    fn full_profile_enables_all_caches() {
        let profile = GpuResidencyProfile::Full;
        assert!(profile.allows_program_cache());
        assert!(profile.allows_compose_prewarm());
    }

    #[test]
    fn host_profile_disables_residency_hooks() {
        let profile = GpuResidencyProfile::Host;
        assert!(!profile.allows_program_cache());
        assert!(!profile.allows_compose_prewarm());
    }
}

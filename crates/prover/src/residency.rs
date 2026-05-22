//! GPU residency profile — single env-var grouping for the per-subsystem
//! residency / cache / pre-warm toggles that previously had one
//! `ZIREN_*` env each.
//!
//! Replaces the per-subsystem toggle set:
//!
//! - `ZIREN_PROGRAM_CACHE`         (compose recursion program cache)
//! - `ZIREN_VERIFY_PROGRAM_CACHE`  (cache audit — opt-in independent)
//! - `ZIREN_COMPOSE_PK_CACHE`      (compose host-pk cache)
//! - `ZIREN_ENABLE_COMPOSE_PREWARM` (compose program pre-warm on startup)
//!
//! with one coherent profile selected by `ZIREN_GPU_RESIDENCY`:
//!
//! ```text
//! ZIREN_GPU_RESIDENCY=full   # all residency-side hooks/caches ON
//! ZIREN_GPU_RESIDENCY=hybrid # safe default; hooks that regressed
//!                            # production are OFF (cache audit, pre-warm)
//! ZIREN_GPU_RESIDENCY=host   # all residency-side hooks/caches OFF
//! ```
//!
//! `hybrid` is the default and reproduces the audited-HEAD behavior
//! (May 21 2026, packed-default flip): program cache OFF, compose-pk
//! cache OFF, pre-warm OFF, cache audit OFF.  `full` opts INTO all
//! caches + pre-warm.  `host` forces everything off (debugging /
//! no-GPU paths).
//!
//! Backward compat: legacy env vars are still respected so existing
//! benches don't break.  If any legacy var is set, the profile decision
//! is OVERRIDDEN per-feature and a one-shot deprecation warn is logged.
//!
//! `VERIFY_VK`, `FIX_CORE_SHAPES`, `FIX_RECURSION_SHAPES` are explicitly
//! NOT residency vars and are not grouped here.

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
    /// Returns true when the compose host-pk cache should be consulted
    /// (host side) and populated (GPU dispatch side).  ON for `full`
    /// only — `hybrid` keeps the audited-HEAD default (OFF) intact so
    /// no production behavior shifts on profile defaulting.  The cache
    /// is documented as sound post-#373 / May 19 audit (see
    /// project_recursion_phase_gpu_audit.md); long-lived GPU provers
    /// can opt into `full` to enable it.
    pub fn allows_compose_pk_cache(self) -> bool {
        matches!(self, Self::Full)
    }

    /// Returns true when the per-arity compose recursion program cache
    /// should be used.  ON for `full` only — the cache was reverted
    /// from default-on in #256 (project_256_cache_perf_reverted.md)
    /// because fix_shape proof bloat dominates cache savings on the
    /// shape spread Ziren sees today.  Available as `full` opt-in for
    /// long-lived provers where compile cost dominates.
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
    /// single-call prover per project_gap_prewarm_regression_diagnosis.md
    /// (May 21 2026).  Worth it for long-lived `full`-residency provers.
    pub fn allows_compose_prewarm(self) -> bool {
        matches!(self, Self::Full)
    }
}

/// Resolves the profile once at first access.  Default is `Hybrid`,
/// matching audited-HEAD behavior (program cache OFF, compose-pk cache
/// OFF, pre-warm OFF, audit OFF — see `cc12a29` packed-default flip).
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
// Per-feature accessors.  Each accessor first checks the legacy env
// var; if set, it wins and emits a one-shot deprecation warning.
// Otherwise the profile mapping decides.
// ---------------------------------------------------------------------

fn legacy_bool(var: &str) -> Option<bool> {
    let v = env::var(var).ok()?;
    if v.is_empty() {
        return None;
    }
    Some(v == "1" || v.eq_ignore_ascii_case("true"))
}

fn warn_once(slot: &OnceLock<()>, msg: &str) {
    slot.get_or_init(|| {
        tracing::warn!("{msg}");
    });
}

/// Compose host-pk cache — ON when `ZIREN_COMPOSE_PK_CACHE=1` (legacy)
/// or when the profile allows it (default = `Hybrid` → OFF; only
/// `Full` enables it).  Hybrid keeps audited-HEAD default behavior.
pub fn compose_pk_cache_enabled() -> bool {
    static WARN: OnceLock<()> = OnceLock::new();
    if let Some(v) = legacy_bool("ZIREN_COMPOSE_PK_CACHE") {
        warn_once(
            &WARN,
            "ZIREN_COMPOSE_PK_CACHE is deprecated; use \
             ZIREN_GPU_RESIDENCY=full|hybrid|host (set to full to \
             opt into the compose-pk cache)",
        );
        return v;
    }
    resolve_gpu_residency_profile().allows_compose_pk_cache()
}

/// Compose recursion program cache — ON when `ZIREN_PROGRAM_CACHE=1`
/// (legacy) or when the profile allows it (default = `Hybrid` → OFF).
pub fn program_cache_enabled() -> bool {
    static WARN: OnceLock<()> = OnceLock::new();
    if let Some(v) = legacy_bool("ZIREN_PROGRAM_CACHE") {
        warn_once(
            &WARN,
            "ZIREN_PROGRAM_CACHE is deprecated; use \
             ZIREN_GPU_RESIDENCY=full to opt into per-arity compose \
             program caching",
        );
        return v;
    }
    resolve_gpu_residency_profile().allows_program_cache()
}

/// Cache-divergence audit — ON when `ZIREN_VERIFY_PROGRAM_CACHE=1`
/// (legacy).  Profile is not consulted; the audit is a CI/dev tool
/// orthogonal to perf posture.
pub fn program_cache_audit_enabled() -> bool {
    // No warn — this variable is a bring-up / soundness tool, not a
    // residency knob.  Keep it untouched for future cache work.
    legacy_bool("ZIREN_VERIFY_PROGRAM_CACHE").unwrap_or(false)
        || resolve_gpu_residency_profile().allows_program_cache_audit()
}

/// Compose program pre-warm on startup — ON when
/// `ZIREN_ENABLE_COMPOSE_PREWARM=1` (legacy) or when the profile
/// allows it (default = `Hybrid` → OFF).
pub fn compose_prewarm_enabled() -> bool {
    static WARN: OnceLock<()> = OnceLock::new();
    if let Some(v) = legacy_bool("ZIREN_ENABLE_COMPOSE_PREWARM") {
        warn_once(
            &WARN,
            "ZIREN_ENABLE_COMPOSE_PREWARM is deprecated; use \
             ZIREN_GPU_RESIDENCY=full to opt into compose-program \
             pre-warm at process startup",
        );
        return v;
    }
    resolve_gpu_residency_profile().allows_compose_prewarm()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_matches_audited_head_behavior() {
        // Defaults at audited HEAD (083e6f63 / bd51dbce, May 21 2026):
        //   program cache: OFF, compose-pk cache: OFF, pre-warm: OFF,
        //   audit: OFF.
        //
        // After this refactor with no env set, the Hybrid profile
        // MUST reproduce: program cache OFF, pre-warm OFF, audit OFF,
        // compose-pk cache OFF — all four residency knobs were OFF
        // by default at the audited HEAD and Phase 4 must not flip
        // any of them.
        let profile = GpuResidencyProfile::Hybrid;
        assert!(!profile.allows_program_cache());
        assert!(!profile.allows_program_cache_audit());
        assert!(!profile.allows_compose_prewarm());
        assert!(!profile.allows_compose_pk_cache());
    }

    #[test]
    fn full_profile_enables_all_caches() {
        let profile = GpuResidencyProfile::Full;
        assert!(profile.allows_program_cache());
        assert!(profile.allows_compose_pk_cache());
        assert!(profile.allows_compose_prewarm());
    }

    #[test]
    fn host_profile_disables_residency_hooks() {
        let profile = GpuResidencyProfile::Host;
        assert!(!profile.allows_program_cache());
        assert!(!profile.allows_compose_pk_cache());
        assert!(!profile.allows_compose_prewarm());
    }
}

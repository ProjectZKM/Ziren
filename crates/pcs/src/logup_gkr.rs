//! LogUp-GKR: proof-of-work grinding for the lookup argument.
//!
//! The LogUp-GKR argument proves the sum-of-fractions identity
//!
//! ```text
//!   Σ_{i ∈ senders} m_i / (α - f_i)  =  Σ_{j ∈ receivers} m_j / (α - f_j)
//! ```
//!
//! where `m_*` are multiplicities and `f_*` are lookup fingerprints.  The
//! prover and verifier for that argument live in [`crate::shard_level`]; this
//! module holds the grinding hook the two sides share.  The grind is applied
//! before either side samples its first GKR challenge, so prover and verifier
//! must consume the challenger identically or every downstream alpha/beta
//! diverges.

use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_field::Field;

/// Proof-of-work grinding difficulty (in bits) applied at the start of the
/// LogUp-GKR argument. The prover grinds
/// for a witness that, once absorbed, makes the challenger emit
/// `GKR_GRINDING_BITS` leading zero bits; the verifier re-checks the witness
/// before sampling any GKR challenge.
pub const GKR_GRINDING_BITS: usize = 12;

/// Config-aware GKR proof-of-work grinding.
///
/// The production Inner challenger ([`crate::InnerChallenger`], a
/// `DuplexChallenger` over KoalaBear) actually grinds. Every other
/// challenger — notably the Outer/BN254 `MultiField32Challenger` used by
/// the gnark-verified wrap (which is never recursion-verified, so its GKR
/// grinding witness is never checked in-circuit) — returns a no-op
/// `F::ZERO`.
///
/// A blanket impl over `FieldChallenger` means callers need NO extra trait
/// bound, avoiding a `GrindingChallenger` bound cascade through the entire
/// prove stack (the Outer challenger is not a `GrindingChallenger`, so a
/// hard bound would break the wrap path).
pub trait GkrGrind<F> {
    /// Prover side: grind a witness (real for the Inner challenger, `F::ZERO`
    /// no-op otherwise). Observes the witness into the challenger (Inner).
    fn gkr_grind(&mut self, bits: usize) -> F;
    /// Verifier side (host): re-observe + check the witness, EXACTLY matching
    /// `gkr_grind`'s challenger consumption so alpha/beta stay consistent.
    /// Real check for the Inner challenger; no-op (accept) otherwise — because
    /// the Outer/wrap `gkr_grind` observed nothing, the verifier must too.
    fn gkr_check_witness(&mut self, bits: usize, witness: F) -> bool;
}

impl<F, C> GkrGrind<F> for C
where
    F: Field + 'static,
    C: FieldChallenger<F> + 'static,
{
    fn gkr_grind(&mut self, bits: usize) -> F {
        use core::any::{Any, TypeId};
        if TypeId::of::<F>() == TypeId::of::<crate::InnerVal>() {
            if let Some(c) = (self as &mut dyn Any).downcast_mut::<crate::InnerChallenger>() {
                // `InnerChallenger: GrindingChallenger<Witness = InnerVal>`.
                // Use the DETERMINISTIC grind
                // (smallest-index witness via find_first) instead of plonky3's
                // nondeterministic `grind` (find_any) so the GKR pow witness —
                // observed into the challenger — is reproducible.  Otherwise
                // every subsequent GKR alpha/beta (and the whole logup_gkr
                // proof) varies run-to-run (valid-but-different compress proofs).
                let w: crate::InnerVal = crate::basefold::prover::deterministic_grind(c, bits);
                // SAFETY: the TypeId guard proves `F == InnerVal` on this path.
                return unsafe { core::mem::transmute_copy::<crate::InnerVal, F>(&w) };
            }
        }
        F::ZERO
    }

    fn gkr_check_witness(&mut self, bits: usize, witness: F) -> bool {
        use core::any::{Any, TypeId};
        if TypeId::of::<F>() == TypeId::of::<crate::InnerVal>() {
            if let Some(c) = (self as &mut dyn Any).downcast_mut::<crate::InnerChallenger>() {
                // SAFETY: the TypeId guard proves `F == InnerVal` on this path.
                let w: crate::InnerVal =
                    unsafe { core::mem::transmute_copy::<F, crate::InnerVal>(&witness) };
                // Observes `w` + samples + checks the leading `bits` are zero —
                // same challenger consumption as the prover's `grind`.
                return c.check_witness(bits, w);
            }
        }
        true
    }
}

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
//! module holds the difficulty the two sides share.  The grind is applied
//! before either side samples its first GKR challenge, so prover and verifier
//! must consume the challenger identically or every downstream alpha/beta
//! diverges.
//!
//! Both rings grind.  A `GkrGrind` trait used to live here to make the grind
//! "config-aware" -- real for the inner challenger, `F::ZERO` and no observe
//! for the outer/wrap one -- while `docs/soundness/ziren.soundcalc.toml`
//! credited wrap with `grinding_bits_lookup = 16` regardless, so the published
//! 100-bit figure described a transcript the protocol did not execute.  The
//! premise for the split ("the outer challenger is not a `GrindingChallenger`")
//! was false: the wrap BaseFold open grinds `pow_bits = 22` through that very
//! trait.  The hook is gone so the split cannot come back by accident; both
//! sides now call `GrindingChallenger` directly.

/// Proof-of-work grinding difficulty (in bits) applied at the start of the
/// LogUp-GKR argument. The prover grinds
/// for a witness that, once absorbed, makes the challenger emit
/// `GKR_GRINDING_BITS` leading zero bits; the verifier re-checks the witness
/// before sampling any GKR challenge.  16 is what the 100-bit provable
/// schedule needs (docs/soundness/): at 0 the LogUp-GKR term scores 84, and
/// the total is the minimum over terms.  It costs ~43 ms/shard in the
/// deterministic search.
pub const GKR_GRINDING_BITS: usize = 16;

use p3_challenger::GrindingChallenger;

/// `F == JaggedVal` at every instantiation, checked rather than assumed.
///
/// Every `StarkGenericConfig` in the tree is KoalaBear-based, so `Val<SC>` and
/// the concrete `JaggedVal` the challenger grinds at are the same type — but
/// that equality is not provable at a generic call site, and the challenger's
/// `Witness` is declared concretely. The `TypeId` equality is exactly the
/// identity that makes the reinterpretation below sound, so it is asserted, not
/// silently assumed, and a config that ever violates it fails loudly here
/// instead of grinding into a different field.
#[inline]
fn as_jagged_val<F: p3_field::Field + 'static>(w: crate::jagged_pcs::JaggedVal) -> F {
    assert_eq!(
        core::any::TypeId::of::<F>(),
        core::any::TypeId::of::<crate::jagged_pcs::JaggedVal>(),
        "LogUp-GKR grinding requires Val<SC> == JaggedVal (every config is KoalaBear-based)",
    );
    // SAFETY: the assert above establishes `F == JaggedVal`.
    unsafe { core::mem::transmute_copy::<crate::jagged_pcs::JaggedVal, F>(&w) }
}

#[inline]
fn from_f<F: p3_field::Field + 'static>(w: F) -> crate::jagged_pcs::JaggedVal {
    assert_eq!(
        core::any::TypeId::of::<F>(),
        core::any::TypeId::of::<crate::jagged_pcs::JaggedVal>(),
        "LogUp-GKR grinding requires Val<SC> == JaggedVal (every config is KoalaBear-based)",
    );
    // SAFETY: as above.
    unsafe { core::mem::transmute_copy::<F, crate::jagged_pcs::JaggedVal>(&w) }
}

/// Prover side: grind `bits` of proof of work and observe the witness.
///
/// DETERMINISTIC (smallest-index witness) rather than p3's `grind`, which is
/// `find_any`: the witness is observed into the challenger, so a
/// nondeterministic one makes every downstream alpha/beta — and the whole
/// LogUp-GKR proof — vary run to run.
pub fn gkr_grind<F, C>(challenger: &mut C, bits: usize) -> F
where
    F: p3_field::Field + 'static,
    C: GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal> + 'static,
{
    as_jagged_val(crate::basefold::prover::deterministic_grind(challenger, bits))
}

/// Verifier side: re-observe the witness and check the `bits` leading zeros,
/// consuming the challenger exactly as [`gkr_grind`] did.
pub fn gkr_check_witness<F, C>(challenger: &mut C, bits: usize, witness: F) -> bool
where
    F: p3_field::Field + 'static,
    C: GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal> + 'static,
{
    challenger.check_witness(bits, from_f(witness))
}

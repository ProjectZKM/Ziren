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
//! Both rings (inner and outer/wrap) grind through `GrindingChallenger`
//! directly, so the transcript matches the soundness model
//! (soundcalc's `ziren.toml`, `grinding_bits_lookup`) on every ring.

/// Proof-of-work grinding difficulty (in bits) applied at the start of the
/// LogUp-GKR argument. The prover grinds
/// for a witness that, once absorbed, makes the challenger emit
/// `gkr_grinding_bits()` leading zero bits; the verifier re-checks the witness
/// before sampling any GKR challenge.  The LogUp-GKR term scores 84 bits with
/// no grind and the grind is the only lever on it -- queries cannot buy it --
/// so it carries the whole distance to the per-component target: 16 bits put
/// the term at 100, which is the minimum-component convention, and 22 put it at
/// 106, which is what a union above 100 needs.
pub fn gkr_grinding_bits() -> usize {
    crate::params::env_usize("ZIREN_LOGUP_GRINDING_BITS", 22)
}

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
    unsafe { core::mem::transmute_copy::<crate::jagged_pcs::JaggedVal, F>(&w) }
}

/// Inverse of [`as_jagged_val`]; the reinterpret is sound by the same asserted
/// identity `F = JaggedVal`.
#[inline]
fn from_f<F: p3_field::Field + 'static>(w: F) -> crate::jagged_pcs::JaggedVal {
    assert_eq!(
        core::any::TypeId::of::<F>(),
        core::any::TypeId::of::<crate::jagged_pcs::JaggedVal>(),
        "LogUp-GKR grinding requires Val<SC> == JaggedVal (every config is KoalaBear-based)",
    );
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

#[cfg(test)]
mod tests {
    use super::*;
    use p3_challenger::{CanObserve, CanSample};
    use p3_field::PrimeCharacteristicRing;

    use crate::jagged_pcs::{JaggedChallenger, JaggedVal};

    /// A challenger seeded so the grind starts from a non-trivial state, and
    /// reproducible so prover and verifier can be given the SAME state.
    fn seeded() -> JaggedChallenger {
        let perm = zkm_primitives::poseidon2_init();
        let mut ch = JaggedChallenger::new(perm);
        ch.observe(JaggedVal::from_u32(0xA11CE));
        ch.observe(JaggedVal::from_u32(0xB0B));
        ch
    }

    /// The grinding witness is what makes the LogUp-GKR transcript cost work to
    /// steer.  This check has been a no-op on a ring before: the override
    /// asserted nothing, so any witness passed and the challenger was left
    /// un-advanced.  These pin both halves of the property — an honest witness
    /// is accepted, and a witness off by one is not — so a no-op cannot pass
    /// them.
    #[test]
    fn gkr_grinding_witness_roundtrips() {
        let mut prover = seeded();
        let witness: JaggedVal = gkr_grind(&mut prover, gkr_grinding_bits());

        let mut verifier = seeded();
        assert!(
            gkr_check_witness(&mut verifier, gkr_grinding_bits(), witness),
            "the honest grinding witness must be accepted, or the negative case below \
             proves nothing"
        );
    }

    /// The assertion a no-op cannot pass.
    ///
    /// Accept/reject alone does not separate a grind from a stub: a stub that
    /// returns zero and observes nothing still "round-trips" against a stub
    /// checker, and it is still deterministic. What separates them is whether
    /// the challenger MOVED, because every subsequent alpha and beta is drawn
    /// from that state. The wrap ring's copy of this is
    /// `zkm_recursion_core::stark::config::wrap_gkr_grind` (zkm-pcs cannot
    /// import `OuterSC`).
    #[test]
    fn gkr_grind_advances_the_transcript() {
        let mut ungrinded = seeded();
        let before: JaggedVal = ungrinded.sample();

        let mut prover = seeded();
        let _witness: JaggedVal = gkr_grind(&mut prover, gkr_grinding_bits());
        let after: JaggedVal = prover.sample();

        assert_ne!(
            before, after,
            "the LogUp-GKR grind must advance the transcript; one that leaves the challenger \
             untouched costs nothing to produce, while the soundness report counts 16 bits \
             for it",
        );
    }

    /// The prover and the verifier must leave the transcript in the SAME state:
    /// that is what "the verifier consumes the challenger exactly as the prover
    /// did" means for every challenge drawn afterwards.
    #[test]
    fn gkr_grind_and_check_leave_the_same_state() {
        let mut prover = seeded();
        let witness: JaggedVal = gkr_grind(&mut prover, gkr_grinding_bits());

        let mut verifier = seeded();
        assert!(gkr_check_witness(&mut verifier, gkr_grinding_bits(), witness));

        let p: JaggedVal = prover.sample();
        let v: JaggedVal = verifier.sample();
        assert_eq!(p, v, "prover and verifier must agree on the post-grind state");
    }

    /// NEGATIVE: one off-by-one witness.  `check_witness` observes the witness
    /// and requires the squeezed challenge's low `gkr_grinding_bits()` to be zero,
    /// so a different witness re-seeds the sponge and (except with probability
    /// 2^-16) fails.
    #[test]
    fn gkr_grinding_rejects_a_tampered_witness() {
        let mut prover = seeded();
        let witness: JaggedVal = gkr_grind(&mut prover, gkr_grinding_bits());

        let mut verifier = seeded();
        assert!(
            !gkr_check_witness(&mut verifier, gkr_grinding_bits(), witness + JaggedVal::ONE),
            "a tampered grinding witness must be rejected",
        );
    }

    /// The grind is DETERMINISTIC (smallest-index witness), not `find_any`:
    /// the witness is observed into the challenger, so a nondeterministic one
    /// would make every downstream alpha/beta — and the whole LogUp-GKR proof —
    /// vary run to run.
    /// The search returns the SMALLEST valid witness, which is what makes the
    /// transcript independent of how the search was scheduled or split.
    ///
    /// It matters because the search runs over growing windows rather than over
    /// the whole prime field: a window that returned any valid witness instead
    /// of its least one would still verify, and the proof bytes would then vary
    /// with the window size.  The check is exhaustive below the witness, so it
    /// fails on exactly that.
    #[test]
    fn the_grind_returns_the_smallest_witness() {
        use p3_field::{integers::QuotientMap, PrimeField64};
        for bits in [6usize, 11] {
            let mut ground = seeded();
            let witness: JaggedVal = gkr_grind(&mut ground, bits);
            let found = witness.as_canonical_u64();
            for i in 0..found {
                let candidate =
                    unsafe { <JaggedVal as QuotientMap<u64>>::from_canonical_unchecked(i) };
                let mut probe = seeded();
                assert!(
                    !probe.check_witness(bits, candidate),
                    "index {i} also passes at bits={bits}, so {found} is not the smallest",
                );
            }
        }
    }

    #[test]
    fn gkr_grinding_is_deterministic() {
        let mut a = seeded();
        let mut b = seeded();
        let wa: JaggedVal = gkr_grind(&mut a, gkr_grinding_bits());
        let wb: JaggedVal = gkr_grind(&mut b, gkr_grinding_bits());
        assert_eq!(wa, wb, "the grind must be reproducible across runs");
        let na: JaggedVal = a.sample();
        let nb: JaggedVal = b.sample();
        assert_eq!(na, nb, "the post-grind challenger state must be reproducible");
    }
}

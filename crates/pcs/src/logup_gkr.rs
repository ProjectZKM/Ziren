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

/// Proof-of-work grinding difficulty (in bits) of the cross-shard global
/// challenge: the prover grinds for a witness that, absorbed after `h_star`,
/// makes the challenger emit this many leading zero bits before `(α_g, β_g)`
/// is sampled. The challenge is drawn once per execution and fingerprints every
/// global lookup of every shard, so its error grows with the execution's global
/// lookups rather than one shard's.
pub fn global_grinding_bits() -> usize {
    crate::params::env_usize("ZIREN_GLOBAL_GRINDING_BITS", 22)
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
    C: GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal> + Clone + Sync + 'static,
{
    as_jagged_val(crate::whir::grind::deterministic_grind(challenger, bits))
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

/// The cross-shard LogUp challenge: the `(α_g, β_g)` every shard of one
/// execution uses for its global-scope lookups
/// ([`crate::air::LookupScope::Global`]), in place of its own `(α, β)`.
///
/// It is derived from a single digest `h_star` that binds every shard's
/// global-round commitment, so it is fixed before any shard proof starts and
/// is the same in every shard. Each shard's transcript absorbs `h_star` first,
/// which ties the proof to the statement whose global lookups it closes.
/// `betas` is the eq-table of the β seed, sized by the machine's widest
/// global lookup ([`crate::StarkMachine::global_beta_seed_dim`]), so the
/// fingerprint of a global message is the same in every shard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalChallenge<F, EF> {
    /// The digest the challenge is derived from.
    pub h_star: [F; 8],
    /// `α_g`.
    pub alpha: EF,
    /// `β_g`: `betas[0]` weights the lookup kind, `betas[k + 1]` the
    /// message's `k`-th value.
    pub betas: alloc::vec::Vec<EF>,
    /// The proof-of-work witness absorbed after `h_star`
    /// ([`global_grinding_bits`]).
    pub pow_witness: F,
}

/// Separates the global challenge's derivation from every other use of a
/// fresh challenger.
pub const GLOBAL_CHALLENGE_DOMAIN: u32 = 0x4742_4c47;

/// Separates the global digest from every other use of the verifying key's
/// transcript.
pub const GLOBAL_DIGEST_DOMAIN: u32 = 0x4744_4754;

/// Separates a step of the global hash chain from every other use of a fresh
/// challenger.
pub const GLOBAL_CHAIN_DOMAIN: u32 = 0x4743_484e;

/// Separates the digest of the global hash chain's lane heads from every
/// other use of a fresh challenger.
pub const GLOBAL_LANES_DOMAIN: u32 = 0x474c_4e53;

/// The lanes of the global hash chain. Each lane is a hash chain of its own:
/// a shard's global round extends one lane, which its prover chooses, by one
/// [`global_chain_step`]. A prover with several devices gives each device a
/// lane, so that consecutive rounds of a lane are rounds of one device.
pub const GLOBAL_CHAIN_LANES: usize = 8;

/// The heads of the lanes of the global hash chain.
pub type GlobalLanes<F> = [[F; 8]; GLOBAL_CHAIN_LANES];

/// The head `h_0` every lane of the global hash chain starts at, sampled
/// from `challenger`: the machine's challenger after it has observed the
/// verifying key.
pub fn global_digest<F, C>(mut challenger: C) -> [F; 8]
where
    F: p3_field::Field,
    C: p3_challenger::FieldChallenger<F>,
{
    challenger.observe(F::from_u32(GLOBAL_DIGEST_DOMAIN));
    core::array::from_fn(|_| challenger.sample())
}

/// The value of the global hash chain whose lane heads are `lanes`: their
/// digest. `challenger` must be a fresh challenger of the machine's
/// configuration.
///
/// The digest is collision resistant, so a chain value fixes every lane
/// head, and its domain keeps it apart from a [`global_chain_step`].
pub fn global_lanes_digest<F, C>(mut challenger: C, lanes: &GlobalLanes<F>) -> [F; 8]
where
    F: p3_field::Field,
    C: p3_challenger::FieldChallenger<F>,
{
    challenger.observe(F::from_u32(GLOBAL_LANES_DOMAIN));
    for head in lanes {
        challenger.observe_slice(head);
    }
    core::array::from_fn(|_| challenger.sample())
}

/// The lane of each shard's global round when the rounds take the lanes in
/// turn, in shard order: `committed` says of each shard whether it commits a
/// round. A shard without one is given lane 0, which nothing reads.
pub fn round_robin_global_lanes(committed: impl IntoIterator<Item = bool>) -> alloc::vec::Vec<u8> {
    let mut next = 0usize;
    committed
        .into_iter()
        .map(|committed| {
            if !committed {
                return 0;
            }
            let lane = next as u8;
            next = (next + 1) % GLOBAL_CHAIN_LANES;
            lane
        })
        .collect()
}

/// `log2` of the global lookups one unit of a proof's count stands for.
///
/// The global sums cancel when each message is sent as often as it is
/// received modulo the field's characteristic `p`. That is equality only
/// while neither number can reach `p`, so the verifiers count the global
/// lookups of each direction, sends and receives, and reject a proof that
/// may hold `p` of them. They count in units, so that the count stays far
/// below `p` and adds without wrapping: a round of `n` lookups counts
/// [`global_lookup_units`]`(n)`, more than `n / 2^GLOBAL_LOOKUP_UNIT_BITS`,
/// and a proof counts at most [`max_global_lookup_units`].
pub const GLOBAL_LOOKUP_UNIT_BITS: usize = 10;

/// The units a global round of at most `lookups` lookups in either
/// direction adds to its proof's count.
pub const fn global_lookup_units(lookups: u64) -> u64 {
    (lookups >> GLOBAL_LOOKUP_UNIT_BITS) + 1
}

/// The most units the global rounds of one proof may count: rounds within
/// it hold fewer lookups in either direction than the characteristic of `F`.
pub const fn max_global_lookup_units<F: p3_field::PrimeField32>() -> u64 {
    (F::ORDER_U32 as u64 - 1) >> GLOBAL_LOOKUP_UNIT_BITS
}

/// What a shard's global round binds ahead of the global challenge: the
/// round's commitment, and the names and heights of its chips in name order.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(bound(serialize = "F: serde::Serialize", deserialize = "F: serde::Deserialize<'de>"))]
pub struct GlobalRoundBinding<F> {
    /// The round's commitment `C_global`.
    pub commitment: [F; 8],
    /// `(name, height)` of every chip the round commits.
    pub chips: alloc::vec::Vec<(alloc::string::String, usize)>,
}

/// The most global rounds one global proof opens: each in a table slot of its
/// own, committed as one of the proof's trace rounds.
pub const MAX_GLOBAL_ROUNDS_PER_PROOF: usize = 8;

/// The weight of the global rounds one global proof opens, at most, unless
/// it opens a single round. A round weighs the stacking blocks it commits
/// plus [`GLOBAL_ROUND_FIXED_BLOCKS`].
///
/// The recursion program that verifies the proof has to fit a recursion pin
/// class (`crate::jagged::RECURSION_PIN_CLASSES`), and it grows with the rows
/// its queries open: every first-round query of a global proof opens one row
/// of each block of each round. Measured on mainnet blocks with one round to
/// a proof, a round of 8 blocks costs the program 10,792 hash rows and one of
/// 232 blocks 71,224, so 270 rows a block and 32 blocks' worth besides; the
/// largest class holds about 200,000 hash rows, 740 in this weight, and the
/// bound leaves a fifth of it free.
pub const GLOBAL_BLOCKS_PER_PROGRAM: usize = 576;

/// What a global round weighs besides its blocks: the part of verifying its
/// global proof that does not grow with the round.
pub const GLOBAL_ROUND_FIXED_BLOCKS: usize = 32;

/// Cuts the consecutive global rounds of one lane into the groups that one
/// global proof each opens, in order. `rounds` holds the shape and the
/// stacking blocks of each round. A group holds rounds of one shape, at most
/// `max_rounds` of them, and weighs at most [`GLOBAL_BLOCKS_PER_PROGRAM`]
/// unless it is a single round.
pub fn global_round_groups<S: PartialEq>(
    rounds: &[(S, usize)],
    max_rounds: usize,
) -> alloc::vec::Vec<core::ops::Range<usize>> {
    let mut groups: alloc::vec::Vec<core::ops::Range<usize>> = alloc::vec::Vec::new();
    let mut weight = 0;
    for (round, (shape, blocks)) in rounds.iter().enumerate() {
        let round_weight = blocks + GLOBAL_ROUND_FIXED_BLOCKS;
        match groups.last_mut() {
            Some(group)
                if group.len() < max_rounds
                    && rounds[group.start].0 == *shape
                    && weight + round_weight <= GLOBAL_BLOCKS_PER_PROGRAM =>
            {
                group.end += 1;
                weight += round_weight;
            }
            _ => {
                groups.push(round..round + 1);
                weight = round_weight;
            }
        }
    }
    groups
}

/// One step of a lane of the global hash chain: the lane's head `h_prev`
/// extended by a shard's global round, `None` for a shard without one.
/// `challenger` must be a fresh challenger of the machine's configuration.
pub fn global_chain_step<F, C>(
    mut challenger: C,
    h_prev: &[F; 8],
    round: Option<&GlobalRoundBinding<F>>,
) -> [F; 8]
where
    F: p3_field::Field,
    C: p3_challenger::FieldChallenger<F>,
{
    challenger.observe(F::from_u32(GLOBAL_CHAIN_DOMAIN));
    challenger.observe_slice(h_prev);
    match round {
        None => challenger.observe(F::ZERO),
        Some(round) => {
            challenger.observe(F::ONE);
            challenger.observe_slice(&round.commitment);
            challenger.observe(F::from_u64(round.chips.len() as u64));
            for (name, height) in &round.chips {
                challenger.observe(F::from_u64(*height as u64));
                challenger.observe(F::from_u64(name.len() as u64));
                for byte in name.bytes() {
                    challenger.observe(F::from_u64(u64::from(byte)));
                }
            }
        }
    }
    core::array::from_fn(|_| challenger.sample())
}

impl<F, EF> GlobalChallenge<F, EF>
where
    F: p3_field::Field + 'static,
    EF: p3_field::ExtensionField<F> + Send + Sync,
{
    /// Prover side: absorbs the domain and `h_star` on `challenger`, which
    /// must be a fresh challenger of the machine's configuration, grinds the
    /// proof-of-work witness and samples the challenge. The witness is never
    /// zero: a recursion proof that holds no global proof carries zero there.
    pub fn grind<C>(mut challenger: C, h_star: [F; 8], beta_seed_dim: usize) -> Self
    where
        C: p3_challenger::FieldChallenger<F>
            + GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
            + Clone
            + Sync
            + 'static,
    {
        Self::absorb(&mut challenger, &h_star);
        let absorbed = challenger.clone();
        let mut pow_witness: F = gkr_grind(&mut challenger, global_grinding_bits());
        if pow_witness.is_zero() {
            loop {
                pow_witness += F::ONE;
                challenger = absorbed.clone();
                if gkr_check_witness(&mut challenger, global_grinding_bits(), pow_witness) {
                    break;
                }
            }
        }
        Self::sample(challenger, h_star, beta_seed_dim, pow_witness)
    }

    /// Verifier side: the challenge of `h_star` and `pow_witness`, or `None`
    /// when the witness is zero or fails the proof of work. `challenger` must
    /// be a fresh challenger of the machine's configuration.
    pub fn derive<C>(
        mut challenger: C,
        h_star: [F; 8],
        pow_witness: F,
        beta_seed_dim: usize,
    ) -> Option<Self>
    where
        C: p3_challenger::FieldChallenger<F>
            + GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
            + 'static,
    {
        if pow_witness.is_zero() {
            return None;
        }
        Self::absorb(&mut challenger, &h_star);
        gkr_check_witness(&mut challenger, global_grinding_bits(), pow_witness)
            .then(|| Self::sample(challenger, h_star, beta_seed_dim, pow_witness))
    }

    fn absorb<C: p3_challenger::FieldChallenger<F>>(challenger: &mut C, h_star: &[F; 8]) {
        challenger.observe(F::from_u32(GLOBAL_CHALLENGE_DOMAIN));
        challenger.observe_slice(h_star);
    }

    fn sample<C: p3_challenger::FieldChallenger<F>>(
        mut challenger: C,
        h_star: [F; 8],
        beta_seed_dim: usize,
        pow_witness: F,
    ) -> Self {
        let alpha: EF = challenger.sample_algebra_element::<EF>();
        let seed: alloc::vec::Vec<EF> =
            (0..beta_seed_dim).map(|_| challenger.sample_algebra_element::<EF>()).collect();
        let betas = if seed.is_empty() {
            alloc::vec![EF::ONE]
        } else {
            crate::zerocheck_prover::eq_mle_table::<EF>(&seed)
        };
        Self { h_star, alpha, betas, pow_witness }
    }

    /// The `(α, β)` pair a lookup of `scope` uses: this challenge for
    /// a global lookup, `local` otherwise.
    pub fn select<'a>(
        global: Option<&'a Self>,
        scope: crate::air::LookupScope,
        local: (EF, &'a [EF]),
    ) -> Option<(EF, &'a [EF])> {
        match scope {
            crate::air::LookupScope::Global => global.map(|g| (g.alpha, g.betas.as_slice())),
            crate::air::LookupScope::Local => Some(local),
        }
    }
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

    /// The rounds of a large block, as `(shape, stacking blocks)`: small
    /// rounds fill a proof by count, a change of shape starts a proof, the
    /// memory shards' rounds of 232 blocks go two to a proof (four of them in
    /// one proof fit no pin class), and a round past the whole budget still
    /// gets a proof of its own.
    #[test]
    fn global_round_groups_bound_what_a_proof_opens() {
        let mut rounds: alloc::vec::Vec<(u8, usize)> = alloc::vec![(0, 8)];
        rounds.extend([(1, 8); 19]);
        rounds.extend([(2, 232); 5]);
        rounds.push((3, 1024));
        rounds.push((3, 1024));
        let groups = global_round_groups(&rounds, MAX_GLOBAL_ROUNDS_PER_PROOF);
        assert_eq!(
            groups,
            alloc::vec![0..1, 1..9, 9..17, 17..20, 20..22, 22..24, 24..25, 25..26, 26..27]
        );
        assert_eq!(global_round_groups(&rounds[1..20], 3).len(), 7);
    }

    /// A chain step binds the previous digest, whether the shard has a global
    /// round, the round's commitment, and every chip's name and height.
    #[test]
    fn global_chain_step_binds_the_round() {
        let fresh = || JaggedChallenger::new(zkm_primitives::poseidon2_init());
        let h0 = [JaggedVal::from_u32(1); 8];
        let round = GlobalRoundBinding {
            commitment: [JaggedVal::from_u32(7); 8],
            chips: alloc::vec![("MemoryLocal".into(), 32), ("SyscallCore".into(), 4)],
        };
        let base = global_chain_step(fresh(), &h0, Some(&round));
        assert_eq!(global_chain_step(fresh(), &h0, Some(&round)), base);

        let mut altered = alloc::vec![global_chain_step(fresh(), &h0, None)];
        let mut h1 = h0;
        h1[5] = JaggedVal::from_u32(2);
        altered.push(global_chain_step(fresh(), &h1, Some(&round)));
        let mut r = round.clone();
        r.commitment[3] = JaggedVal::from_u32(8);
        altered.push(global_chain_step(fresh(), &h0, Some(&r)));
        let mut r = round.clone();
        r.chips[0].1 = 33;
        altered.push(global_chain_step(fresh(), &h0, Some(&r)));
        let mut r = round.clone();
        r.chips[1].0 = "SyscallPrecompile".into();
        altered.push(global_chain_step(fresh(), &h0, Some(&r)));
        let mut r = round.clone();
        r.chips.pop();
        altered.push(global_chain_step(fresh(), &h0, Some(&r)));
        let r = GlobalRoundBinding { chips: alloc::vec::Vec::new(), ..round.clone() };
        altered.push(global_chain_step(fresh(), &h0, Some(&r)));

        for (i, h) in altered.iter().enumerate() {
            assert_ne!(*h, base, "alteration {i} left the chain step unchanged");
        }
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

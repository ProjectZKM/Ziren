//! The protocol profile: the parameters and event orders that decide what a
//! transcript looks like, and one digest over all of them.
//!
//! Two binaries that disagree about any of these do not fail — they diverge.
//! The prover grinds and samples over one sequence and the verifier replays
//! another, so every downstream challenge differs and the proof is rejected for
//! a reason that names none of this. ZR-26 is the worked example: absorbing the
//! claim vector before the batching point forked the transcript, moved every
//! recursion verifying key, and made a mixed deployment of the two repositories
//! reject every proof the other produced.
//!
//! The digest exists so that disagreement is a startup error instead of a
//! mysterious verification failure. It is a statement about the PROTOCOL, not
//! about the build: two different builds of the same protocol agree, and a
//! rebuild that changes an entry below does not.
//!
//! # What is covered
//!
//! Two kinds of thing, absorbed in this order:
//!
//! 1. [`TRANSCRIPT_PROFILE`] — named scalars and event ORDERS. An order has no
//!    natural value, so it carries a revision counter bumped by hand when the
//!    order moves.
//! 2. The production PCS configurations themselves, field by field, read from
//!    the same constructors the provers call.
//!
//! The second exists because the first cannot be trusted to be complete. A
//! hand-written list of constants omits whatever nobody remembered to add —
//! fold schedules, query counts, OOD counts, rates, folding proof-of-work —
//! and a digest that silently misses a transcript parameter is worse than no
//! digest, because it licenses the mixed deployment it was built to refuse.
//! Absorbing the structs means a new field is covered by construction and a
//! changed one moves the digest whether or not anybody edited this file.
//!
//! The BaseFold inner configuration is read through `from_env_or_default`, so
//! an environment that overrides the query count moves the digest. That is the
//! intended behaviour: it is a different transcript.
//!
//! The `profile_digest_is_pinned` test fails on any change, so every move is a
//! reviewed one.

use alloc::vec::Vec;

use p3_field::PrimeCharacteristicRing;
use p3_symmetric::CryptographicHasher;

use crate::jagged_pcs::{JaggedVal, DEFAULT_LOG_STACKING_HEIGHT};

/// One named quantity the transcript depends on.
///
/// The name is hashed alongside the value, so moving a value between entries
/// changes the digest even when the multiset of values does not.
pub type ProfileEntry = (&'static str, u64);

/// Every transcript-affecting parameter and event order, in a fixed order.
///
/// The first group has natural values. The second has none — an event order is
/// not a number — so each carries a revision that is incremented when that
/// order changes, with the finding or change that moved it named beside it.
pub const TRANSCRIPT_PROFILE: &[ProfileEntry] = &[
    // Parameters.
    ("jagged.log_stacking_height", DEFAULT_LOG_STACKING_HEIGHT as u64),
    ("basefold.batch_grinding_bits", crate::basefold::config::BATCH_GRINDING_BITS as u64),
    ("logup_gkr.grinding_bits", crate::logup_gkr::GKR_GRINDING_BITS as u64),
    // Event orders.
    //
    // rev 1: BaseFold absorbs the per-stripe claim vector BEFORE batch grinding
    //        and before the batching point (ZR-26). Before that the batching
    //        Lagrange vector was known to a prover that had not yet chosen the
    //        claims, and the two linear equations were solvable.
    ("basefold.claims_before_batching_point", 1),
    // rev 1: the shard prologue absorbs public values, the main commitment, the
    //        chip count, then each chip's raw height and name.
    ("shard.prologue_order", 1),
    // rev 1: a round's commitment is `compress([raw_root, hash(counts)])` over
    //        the ring's own hasher, so the digest states the geometry.
    ("jagged.geometry_hash_bind", 1),
];

/// The profile digest: `hash(len ‖ ⟨name bytes, value⟩ …)` over
/// [`TRANSCRIPT_PROFILE`], with the repository's own Poseidon2-KoalaBear
/// sponge, so a consumer needs nothing this crate does not already provide.
///
/// Values are absorbed as two 31-bit halves because a `u64` does not fit one
/// KoalaBear element; splitting rather than reducing keeps distinct values
/// distinct.
pub fn transcript_profile_digest() -> [JaggedVal; 8] {
    let perm: crate::kb31_poseidon2::InnerPerm = zkm_primitives::poseidon2_init();
    let hasher = crate::kb31_poseidon2::InnerHash::new(perm);

    let mut felts: Vec<JaggedVal> = Vec::new();
    felts.push(JaggedVal::from_canonical_usize(TRANSCRIPT_PROFILE.len()));
    for (name, value) in TRANSCRIPT_PROFILE {
        felts.push(JaggedVal::from_canonical_usize(name.len()));
        felts.extend(name.bytes().map(JaggedVal::from_u8));
        push_u64(&mut felts, *value);
    }

    // The production PCS configurations, field by field.  Read from the
    // constructors the provers call, so a parameter cannot be in the protocol
    // and absent from its digest.
    absorb_whir_config(
        &mut felts,
        &crate::whir::jagged::core_whir_config(DEFAULT_LOG_STACKING_HEIGHT as usize),
    );
    absorb_fri_config(&mut felts, &crate::basefold::FriConfig::<JaggedVal>::from_env_or_default());
    absorb_fri_config(&mut felts, &crate::basefold::FriConfig::<JaggedVal>::wrap_fri_config());

    hasher.hash_iter(felts)
}

/// A `u64` as two 31-bit halves: one does not fit a KoalaBear element, and
/// splitting rather than reducing keeps distinct values distinct.
fn push_u64(felts: &mut Vec<JaggedVal>, value: u64) {
    felts.push(JaggedVal::from_canonical_u32((value & 0x7FFF_FFFF) as u32));
    felts.push(JaggedVal::from_canonical_u32(((value >> 31) & 0x7FFF_FFFF) as u32));
}

/// A length-prefixed run of `usize`, so a shorter vector cannot alias a longer
/// one that happens to start the same way.
fn push_usizes(felts: &mut Vec<JaggedVal>, values: &[usize]) {
    felts.push(JaggedVal::from_canonical_usize(values.len()));
    for &v in values {
        push_u64(felts, v as u64);
    }
}

/// Every field of a WHIR configuration that the transcript depends on: the
/// starting domain and rate, the OOD counts, the fold schedule, the per-round
/// query and proof-of-work counts, and the final round.
fn absorb_whir_config(felts: &mut Vec<JaggedVal>, cfg: &crate::whir::config::WhirConfig) {
    push_u64(felts, cfg.starting_ood_samples as u64);
    push_u64(felts, cfg.starting_log_inv_rate as u64);
    push_u64(felts, cfg.starting_interleaved_log_height as u64);
    push_u64(felts, cfg.starting_domain_log_size as u64);
    push_usizes(felts, &cfg.starting_folding_pow_bits);
    felts.push(JaggedVal::from_canonical_usize(cfg.round_parameters.len()));
    for r in cfg.round_parameters.iter() {
        push_u64(felts, r.folding_factor as u64);
        push_u64(felts, r.evaluation_domain_log_size as u64);
        push_u64(felts, r.queries_pow_bits as u64);
        push_usizes(felts, &r.pow_bits);
        push_u64(felts, r.num_queries as u64);
        push_u64(felts, r.ood_samples as u64);
        push_u64(felts, r.log_inv_rate as u64);
    }
    push_u64(felts, cfg.final_poly_log_degree as u64);
    push_u64(felts, cfg.final_queries as u64);
    push_u64(felts, cfg.final_pow_bits as u64);
    push_usizes(felts, &cfg.final_folding_pow_bits);
}

/// Every field of a BaseFold/FRI configuration that the transcript depends on.
fn absorb_fri_config(felts: &mut Vec<JaggedVal>, cfg: &crate::basefold::FriConfig<JaggedVal>) {
    push_u64(felts, cfg.log_blowup as u64);
    push_u64(felts, cfg.num_queries as u64);
    push_u64(felts, cfg.proof_of_work_bits as u64);
    push_u64(felts, cfg.log_folding_arity as u64);
}

/// The profile digest as a lowercase hex string, for logs, deployment metadata
/// and cross-process comparison.
#[must_use]
pub fn transcript_profile_digest_hex() -> alloc::string::String {
    use core::fmt::Write;
    use p3_field::PrimeField32;
    let mut s = alloc::string::String::with_capacity(64);
    for f in transcript_profile_digest() {
        let _ = write!(s, "{:08x}", f.as_canonical_u32());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The digest is pinned so that a transcript change cannot be an accident.
    ///
    /// A failure here is not a bug in this test: it means an entry in
    /// [`TRANSCRIPT_PROFILE`] moved, which means the transcript moved, which
    /// means every recursion verifying key and every artifact derived from one
    /// has to be regenerated and the two repositories have to ship together.
    /// Update the constant below in the same commit that makes the change, and
    /// say in the message which entry moved and why.
    #[test]
    fn profile_digest_is_pinned() {
        assert_eq!(
            transcript_profile_digest_hex(),
            "2968c9ff1a0811a467451d5f36fd9b167220bef01d686dcb4771800c2700a372",
            "the transcript profile changed -- see this test's documentation",
        );
    }

    /// Two entries that swap values must not produce the same digest: the name
    /// is part of what is hashed, not just a label in the source.
    #[test]
    fn the_name_is_part_of_the_digest() {
        let perm: crate::kb31_poseidon2::InnerPerm = zkm_primitives::poseidon2_init();
        let hasher = crate::kb31_poseidon2::InnerHash::new(perm);
        let digest_of = |entries: &[ProfileEntry]| -> [JaggedVal; 8] {
            let mut felts: Vec<JaggedVal> = Vec::new();
            felts.push(JaggedVal::from_canonical_usize(entries.len()));
            for (name, value) in entries {
                felts.push(JaggedVal::from_canonical_usize(name.len()));
                felts.extend(name.bytes().map(JaggedVal::from_u8));
                felts.push(JaggedVal::from_canonical_u32((value & 0x7FFF_FFFF) as u32));
                felts.push(JaggedVal::from_canonical_u32(((value >> 31) & 0x7FFF_FFFF) as u32));
            }
            hasher.hash_iter(felts)
        };
        let a: &[ProfileEntry] = &[("alpha", 1), ("beta", 2)];
        let b: &[ProfileEntry] = &[("alpha", 2), ("beta", 1)];
        assert_ne!(digest_of(a), digest_of(b), "swapping values must move the digest");

        let c: &[ProfileEntry] = &[("beta", 1), ("alpha", 2)];
        assert_ne!(digest_of(b), digest_of(c), "reordering entries must move the digest");
    }

    /// Coverage is by construction; this is the check that it actually is.
    ///
    /// Each mutation moves ONE field of the production WHIR configuration --
    /// the fold schedule, a round's query count, its OOD count, its rate, its
    /// query proof-of-work, and the final round's queries and degree -- and
    /// every one of them must move the absorbed stream. A field the absorb
    /// forgot would leave its mutation invisible, which is exactly the failure
    /// a hand-written constant list makes easy.
    #[test]
    fn every_whir_parameter_moves_the_digest() {
        let base = crate::whir::jagged::core_whir_config(DEFAULT_LOG_STACKING_HEIGHT as usize);
        let absorbed = |cfg: &crate::whir::config::WhirConfig| -> Vec<JaggedVal> {
            let mut f = Vec::new();
            absorb_whir_config(&mut f, cfg);
            f
        };
        let honest = absorbed(&base);
        assert!(!base.round_parameters.is_empty(), "the production schedule has rounds");

        let mutations: Vec<(&str, fn(&mut crate::whir::config::WhirConfig))> = alloc::vec![
            ("starting_ood_samples", |c| c.starting_ood_samples += 1),
            ("starting_log_inv_rate", |c| c.starting_log_inv_rate += 1),
            ("starting_domain_log_size", |c| c.starting_domain_log_size += 1),
            ("starting_interleaved_log_height", |c| c.starting_interleaved_log_height += 1),
            ("starting_folding_pow_bits", |c| c.starting_folding_pow_bits.push(1)),
            ("round folding_factor", |c| c.round_parameters[0].folding_factor += 1),
            ("round num_queries", |c| c.round_parameters[0].num_queries += 1),
            ("round ood_samples", |c| c.round_parameters[0].ood_samples += 1),
            ("round log_inv_rate", |c| c.round_parameters[0].log_inv_rate += 1),
            ("round queries_pow_bits", |c| c.round_parameters[0].queries_pow_bits += 1),
            ("round pow_bits", |c| c.round_parameters[0].pow_bits.push(1)),
            ("round evaluation_domain_log_size", |c| {
                c.round_parameters[0].evaluation_domain_log_size += 1
            }),
            ("round count", |c| {
                let r = c.round_parameters[0].clone();
                c.round_parameters.push(r);
            }),
            ("final_poly_log_degree", |c| c.final_poly_log_degree += 1),
            ("final_queries", |c| c.final_queries += 1),
            ("final_pow_bits", |c| c.final_pow_bits += 1),
            ("final_folding_pow_bits", |c| c.final_folding_pow_bits.push(1)),
        ];
        for (name, mutate) in mutations {
            let mut cfg = base.clone();
            mutate(&mut cfg);
            assert_ne!(
                absorbed(&cfg),
                honest,
                "changing {name} left the profile digest unmoved, so that parameter is \
                 outside the digest that claims to cover the transcript"
            );
        }
    }

    /// The same for the BaseFold configuration.
    #[test]
    fn every_fri_parameter_moves_the_digest() {
        let base = crate::basefold::FriConfig::<JaggedVal>::wrap_fri_config();
        let absorbed = |cfg: &crate::basefold::FriConfig<JaggedVal>| -> Vec<JaggedVal> {
            let mut f = Vec::new();
            absorb_fri_config(&mut f, cfg);
            f
        };
        let honest = absorbed(&base);
        let mutations: Vec<(&str, fn(&mut crate::basefold::FriConfig<JaggedVal>))> = alloc::vec![
            ("log_blowup", |c| c.log_blowup += 1),
            ("num_queries", |c| c.num_queries += 1),
            ("proof_of_work_bits", |c| c.proof_of_work_bits += 1),
            ("log_folding_arity", |c| c.log_folding_arity += 1),
        ];
        for (name, mutate) in mutations {
            let mut cfg = base.clone();
            mutate(&mut cfg);
            assert_ne!(absorbed(&cfg), honest, "changing {name} left the digest unmoved");
        }
    }

    /// Every entry's name must be distinct, or the digest cannot say which
    /// parameter a value belongs to.
    #[test]
    fn profile_entry_names_are_unique() {
        let mut names: Vec<&str> = TRANSCRIPT_PROFILE.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "TRANSCRIPT_PROFILE has a duplicate name");
    }
}

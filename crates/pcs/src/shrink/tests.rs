use super::*;
use crate::basefold::Mle;
use crate::whir::stacked::{StackedWhirProof, StackedWhirProver, StackedWhirVerifier};
use p3_challenger::{CanObserve, CanSample};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use std::sync::Arc;

#[test]
fn standard_hash_vectors() {
    let hex = |x: [u8; 32]| x.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        hex(Sha256Suite::hash(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(Blake3Suite::hash(b"abc")),
        "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
    );
    assert_eq!(
        hex(Keccak256Suite::hash(b"abc")),
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    );
}

fn key<S: HashSuite>() -> crate::StarkVerifyingKey<CompactShrink<S>> {
    crate::StarkVerifyingKey {
        commit: p3_symmetric::MerkleCap::new(vec![[7; 32]]),
        pc_start: Val::ONE,
        initial_global_cumulative_sum: Default::default(),
        chip_information: vec![],
        chip_ordering: Default::default(),
    }
}

#[test]
fn descriptor_binds_suite_and_trusted_key_snapshot() {
    let mut original = key::<Keccak256Suite>();
    let approved = ShrinkVerifierData::from_trusted_key(original.clone());
    original.pc_start += Val::ONE;
    assert_ne!(approved.id(), &shrink_key_digest(&original));
    assert_eq!(approved.id(), &shrink_key_digest(approved.vk()));
    assert_eq!(approved.suite_id(), Keccak256Suite::ID);
    let sha = ShrinkVerifierData::from_trusted_key(key::<Sha256Suite>());
    let blake = ShrinkVerifierData::from_trusted_key(key::<Blake3Suite>());
    assert_ne!(approved.id(), sha.id());
    assert_ne!(approved.id(), blake.id());
    assert_ne!(sha.id(), blake.id());
}

#[derive(Clone, Copy, Debug, Default)]
struct ChangedBoundary;
impl HashSuite for ChangedBoundary {
    const ID: &'static str = Keccak256Suite::ID;
    const TRANSCRIPT_DOMAIN: &'static [u8] = Keccak256Suite::TRANSCRIPT_DOMAIN;
    const ROOT_DOMAIN: &'static [u8] = Keccak256Suite::ROOT_DOMAIN;
    const KEY_DOMAIN: &'static [u8] = Keccak256Suite::KEY_DOMAIN;
    const ABSORB_CAP_BYTES: usize = 99;
    fn hash(bytes: &[u8]) -> [u8; 32] {
        Keccak256Suite::hash(bytes)
    }
}

#[test]
fn descriptor_binds_transcript_conventions_beyond_hash_name() {
    assert_ne!(
        shrink_key_digest(&key::<Keccak256Suite>()),
        shrink_key_digest(&key::<ChangedBoundary>())
    );
}

/// Small component proof only: the production CompactShrink profile is unchanged.
fn round_trip<S: HashSuite, Wrong: HashSuite>() {
    let n = 9;
    let cfg = crate::whir::jagged::whir_config_for_stack(n, 3, 0);
    let prover = StackedWhirProver::<Val, Challenge, _, _>::new(
        compact_mmcs::<S>(),
        Arc::new(CompactDft::default()),
        cfg.clone(),
        n as u32,
    );
    let stripe = |seed| {
        Arc::new(Mle::from_row_major(RowMajorMatrix::new(
            (0..1usize << n).map(|i| Val::from_usize(i * 31 + seed)).collect(),
            1,
        )))
    };
    let a = prover.commit_stripes(vec![stripe(1), stripe(9)]);
    let b = prover.commit_stripes(vec![stripe(19)]);
    let point = (0..n).map(|i| Challenge::from_u32(i as u32 + 2)).collect::<Vec<_>>();
    let mut pc = CompactChallenger::<S>::new();
    // Real callers authenticate these observations before the PCS entry.
    pc.observe(a.commitment.clone());
    pc.observe(b.commitment.clone());
    let proof = prover.prove_trusted_evaluation(
        Arc::new(p3_dft::Radix2DitParallel::<Challenge>::default()),
        point.clone(),
        &[&a, &b],
        &mut pc,
    );
    let roots = vec![a.commitment.clone(), b.commitment.clone()];
    let verifier =
        StackedWhirVerifier::<Val, Challenge, _>::new(compact_mmcs::<S>(), cfg.clone(), n as u32);
    let verify = |p: &StackedWhirProof<Val, Challenge, CompactMmcs<S>>| {
        let mut vc = CompactChallenger::<S>::new();
        vc.observe(roots[0].clone());
        vc.observe(roots[1].clone());
        verifier.verify_trusted_evaluation(&roots, &[2, 1], &point, p, &mut vc)
    };
    assert_eq!(verify(&proof), Ok(()));
    let mut bad = proof.clone();
    bad.batch_evaluations[0][0] += Challenge::ONE;
    assert!(verify(&bad).is_err());
    let mut bad = proof.clone();
    bad.whir_proof.final_poly[0] += Challenge::ONE;
    assert!(verify(&bad).is_err());
    let mut bad = proof.clone();
    bad.whir_proof.round_query_openings[0].leaves[0].values[0][0] += Val::ONE;
    assert!(verify(&bad).is_err());
    let mut bad = proof.clone();
    bad.whir_proof.round_sumcheck_polys.push(vec![]);
    assert!(verify(&bad).is_err());

    // An adversary can relabel serialized bytes. The other suite must reject.
    let relabeled: StackedWhirProof<Val, Challenge, CompactMmcs<Wrong>> =
        bincode::deserialize(&bincode::serialize(&proof).unwrap()).unwrap();
    let other =
        StackedWhirVerifier::<Val, Challenge, _>::new(compact_mmcs::<Wrong>(), cfg, n as u32);
    let mut vc = CompactChallenger::<Wrong>::new();
    vc.observe(roots[0].clone());
    vc.observe(roots[1].clone());
    assert!(other.verify_trusted_evaluation(&roots, &[2, 1], &point, &relabeled, &mut vc).is_err());
    let mut sample = CompactChallenger::<S>::new();
    for _ in 0..64 {
        let x: Val = sample.sample();
        assert!(x.as_canonical_u32() < 0x7f000001);
    }
}

#[test]
fn keccak_whir_round_trip() {
    round_trip::<Keccak256Suite, Sha256Suite>();
}
#[test]
fn sha256_whir_round_trip() {
    round_trip::<Sha256Suite, Blake3Suite>();
}
#[test]
fn blake3_whir_round_trip() {
    round_trip::<Blake3Suite, Keccak256Suite>();
}

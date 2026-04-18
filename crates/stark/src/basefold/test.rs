//! KoalaBear BaseFold prover↔verifier roundtrip test.
//!
//! Mirrors the SP1 reference test in
//! [`/tmp/sp1/slop/crates/basefold-prover/src/prover.rs:285`](file:///tmp/sp1/slop/crates/basefold-prover/src/prover.rs):
//! commit a small batch of MLEs, evaluate at a random point, then
//! prove + verify using the same challenger seed on both sides.

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_challenger::CanObserve;
use p3_dft::Radix2DitParallel;
use p3_field::{BasedVectorSpace, ExtensionField, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use zkm_primitives::poseidon2_init;

// KoalaBear is a 31-bit prime; clamp to 30 bits to keep modular
// reduction trivial.  Same pattern as
// `crates/stark/src/jagged_late_binding.rs` test helpers.
fn rand_kb<R: Rng>(rng: &mut R) -> InnerVal {
    InnerVal::from_u32(rng.gen::<u32>() & 0x3FFF_FFFF)
}

fn rand_ef<R: Rng>(rng: &mut R) -> InnerChallenge {
    <InnerChallenge as BasedVectorSpace<InnerVal>>::from_basis_coefficients_iter(
        (0..4).map(|_| rand_kb(rng)),
    )
    .unwrap()
}

use crate::kb31_poseidon2::{
    InnerChallenge, InnerChallenger, InnerCompress, InnerHash, InnerPerm, InnerVal,
    InnerValMmcs,
};

use super::{BasefoldProver, BasefoldVerifier, FriConfig, Mle};

fn build_mmcs() -> InnerValMmcs {
    let perm: InnerPerm = poseidon2_init();
    let hash = InnerHash::new(perm.clone());
    let compress = InnerCompress::new(perm);
    InnerValMmcs::new(hash, compress, 0)
}

fn build_challenger() -> InnerChallenger {
    let perm: InnerPerm = poseidon2_init();
    InnerChallenger::new(perm)
}

#[test]
fn test_basefold_roundtrip_single_round() {
    type F = InnerVal;
    type EF = InnerChallenge;

    let num_variables = 4usize; // 16 hypercube points
    let num_polys = 3usize;
    let mut rng = StdRng::seed_from_u64(0xBA5E_F01D);

    // Build one Mle with `num_polys` polynomials over the hypercube.
    let mut values = Vec::with_capacity((1 << num_variables) * num_polys);
    for _ in 0..(1 << num_variables) * num_polys {
        values.push(rand_kb(&mut rng));
    }
    let mle = Arc::new(Mle::new(RowMajorMatrix::new(values, num_polys)));

    let fri_config = FriConfig::<F>::test_fri_config();
    let mmcs = build_mmcs();
    let dft = Arc::new(Radix2DitParallel::<F>::default());

    let prover = BasefoldProver::<F, EF, _, _>::new(
        fri_config.clone(),
        dft,
        mmcs.clone(),
        1, // num_expected_commitments
    );
    let verifier = BasefoldVerifier::<F, EF, _>::new(fri_config, mmcs, 1);

    // ── Commit (prover side, observed by both transcripts) ───────────
    let mut p_chal = build_challenger();
    let (commitment, prover_data) = prover.commit_mles(vec![mle.clone()]);
    p_chal.observe(commitment.clone());

    // ── Evaluation claims at a random extension-field point ──────────
    let eval_point: Vec<EF> = (0..num_variables).map(|_| rand_ef(&mut rng)).collect();
    let eval_claims_one_round: Vec<EF> = mle.eval_at::<EF>(&eval_point);
    assert_eq!(eval_claims_one_round.len(), num_polys);

    let proof = prover.prove_trusted_mle_evaluations(
        eval_point.clone(),
        vec![vec![mle.clone()]],
        vec![eval_claims_one_round.clone()],
        vec![prover_data],
        &mut p_chal,
    );

    // ── Verify with a fresh challenger that observes the same digest ─
    let mut v_chal = build_challenger();
    v_chal.observe(commitment.clone());
    verifier
        .verify_mle_evaluations(
            &[commitment],
            eval_point,
            &[eval_claims_one_round],
            &proof,
            &mut v_chal,
        )
        .expect("basefold verifier should accept honest proof");
}

#[test]
fn test_basefold_roundtrip_two_rounds() {
    type F = InnerVal;
    type EF = InnerChallenge;

    let num_variables = 5usize;
    let mut rng = StdRng::seed_from_u64(0x52A1_FACE);

    let make_mle = |num_polys: usize, rng: &mut StdRng| -> Arc<Mle<F>> {
        let n = (1 << num_variables) * num_polys;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(rand_kb(rng));
        }
        Arc::new(Mle::new(RowMajorMatrix::new(v, num_polys)))
    };

    let mle_round_0 = vec![make_mle(2, &mut rng), make_mle(3, &mut rng)];
    let mle_round_1 = vec![make_mle(1, &mut rng)];

    let fri_config = FriConfig::<F>::test_fri_config();
    let mmcs = build_mmcs();
    let dft = Arc::new(Radix2DitParallel::<F>::default());

    let prover = BasefoldProver::<F, EF, _, _>::new(
        fri_config.clone(),
        dft,
        mmcs.clone(),
        2,
    );
    let verifier = BasefoldVerifier::<F, EF, _>::new(fri_config, mmcs, 2);

    let mut p_chal = build_challenger();
    let (commit_0, data_0) = prover.commit_mles(mle_round_0.clone());
    p_chal.observe(commit_0.clone());
    let (commit_1, data_1) = prover.commit_mles(mle_round_1.clone());
    p_chal.observe(commit_1.clone());

    let eval_point: Vec<EF> = (0..num_variables).map(|_| rand_ef(&mut rng)).collect();

    let claims_0: Vec<EF> = mle_round_0
        .iter()
        .flat_map(|m| m.eval_at::<EF>(&eval_point))
        .collect();
    let claims_1: Vec<EF> = mle_round_1
        .iter()
        .flat_map(|m| m.eval_at::<EF>(&eval_point))
        .collect();

    let proof = prover.prove_trusted_mle_evaluations(
        eval_point.clone(),
        vec![mle_round_0, mle_round_1],
        vec![claims_0.clone(), claims_1.clone()],
        vec![data_0, data_1],
        &mut p_chal,
    );

    let mut v_chal = build_challenger();
    v_chal.observe(commit_0.clone());
    v_chal.observe(commit_1.clone());
    verifier
        .verify_mle_evaluations(
            &[commit_0, commit_1],
            eval_point,
            &[claims_0, claims_1],
            &proof,
            &mut v_chal,
        )
        .expect("basefold verifier should accept honest 2-round proof");
}

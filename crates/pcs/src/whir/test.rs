//! Phase-1 validation: the OOD commitment.
//!
//! Uses the same KoalaBear + Poseidon2-Merkle harness as the BaseFold tests.

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_dft::Radix2DitParallel;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use zkm_primitives::poseidon2_init;

use crate::basefold::mle::Mle;
use crate::kb31_poseidon2::{
    InnerChallenge, InnerChallenger, InnerCompress, InnerHash, InnerPerm, InnerVal, InnerValMmcs,
};
use crate::whir::config::WhirConfig;
use crate::whir::prover::WhirProver;

fn rand_kb<R: Rng>(rng: &mut R) -> InnerVal {
    InnerVal::from_u32(rng.gen::<u32>() & 0x3FFF_FFFF)
}
fn build_mmcs() -> InnerValMmcs {
    let perm: InnerPerm = poseidon2_init();
    InnerValMmcs::new(InnerHash::new(perm.clone()), InnerCompress::new(perm), 0)
}
fn build_challenger() -> InnerChallenger {
    InnerChallenger::new(poseidon2_init())
}

/// Commit an MLE and check the prover's OOD answers equal the committed
/// polynomial evaluated at the transcript-drawn OOD points.
#[test]
fn commit_ood_answers_are_correct() {
    type F = InnerVal;
    type EF = InnerChallenge;

    let num_variables = 6usize;
    let mut rng = StdRng::seed_from_u64(0x0D_0D_0D);
    let values: Vec<F> = (0..(1usize << num_variables)).map(|_| rand_kb(&mut rng)).collect();
    let mle = Arc::new(Mle::from_row_major(RowMajorMatrix::new(values, 1)));

    let dft = Arc::new(Radix2DitParallel::<F>::default());
    let mmcs = build_mmcs();
    let mut challenger = build_challenger();

    let mut config = WhirConfig::default_whir_config();
    config.starting_ood_samples = 3;

    let prover = WhirProver::<F, EF, _, _>::new(dft, mmcs, config);
    let commit = prover.commit_with_ood(&mut challenger, Arc::clone(&mle));

    assert_eq!(commit.parsed.ood_points.len(), 3);
    assert_eq!(commit.parsed.ood_answers.len(), 3);
    for (point, answer) in commit.parsed.ood_points.iter().zip(&commit.parsed.ood_answers) {
        assert_eq!(point.len(), num_variables, "OOD point is a full evaluation point");
        let expected = mle.eval_at::<EF>(point)[0];
        assert_eq!(*answer, expected, "OOD answer must equal the committed MLE at the OOD point");
    }
}

/// Phase 2: the folding sumcheck reduces the (batched) claim to
/// `weight(r) · f(r)` at the folding challenge point — its soundness identity.
#[test]
fn folds_reduce_the_claim() {
    use crate::whir::sumcheck::prove_fold;

    type F = InnerVal;
    type EF = InnerChallenge;

    let n = 8usize;
    let mut rng = StdRng::seed_from_u64(0xF01D);
    let values: Vec<F> = (0..(1usize << n)).map(|_| rand_kb(&mut rng)).collect();
    let mle = Mle::from_row_major(RowMajorMatrix::new(values, 1));

    // A random evaluation point and two OOD points, with their true answers.
    let rand_pt = |rng: &mut StdRng| -> Vec<EF> {
        (0..n)
            .map(|_| {
                use p3_field::BasedVectorSpace;
                <EF as BasedVectorSpace<F>>::from_basis_coefficients_iter(
                    (0..4).map(|_| rand_kb(rng)),
                )
                .unwrap()
            })
            .collect()
    };
    let query_point = rand_pt(&mut rng);
    let ood_points: Vec<Vec<EF>> = (0..2).map(|_| rand_pt(&mut rng)).collect();
    let claim = mle.eval_at::<EF>(&query_point)[0];
    let ood_answers: Vec<EF> = ood_points.iter().map(|p| mle.eval_at::<EF>(p)[0]).collect();

    let mut challenger = build_challenger();
    let out = prove_fold(&mle, &query_point, &ood_points, &ood_answers, claim, &mut challenger);

    // The reduced claim must equal weight(r)·f(r) at the folding point.
    assert_eq!(
        out.final_claim,
        out.folded_weight * out.folded_f,
        "sumcheck must reduce the claim to weight(r)·f(r)"
    );
    // And f folded to a point equals f evaluated there (fold ≡ partial eval).
    assert_eq!(
        out.folded_f,
        mle.eval_at::<EF>(&out.folding_randomness)[0],
        "the folded polynomial value must equal f at the folding point"
    );
    assert_eq!(out.round_polys.len(), n);
}

// ---------------------------------------------------------------------------
// Phase 2b: the folding tower.
// ---------------------------------------------------------------------------

/// A small, internally-consistent tower config: `n` variables folded `ff` at a
/// time over `num_rounds` rounds, leaving a `final_poly_log_degree`-variable
/// final polynomial.  PoW bits are zero so the tests run fast.
fn tower_config(n: usize, ff: usize, num_rounds: usize) -> WhirConfig {
    use crate::whir::config::RoundConfig;
    let mut config = WhirConfig::default_whir_config();
    config.starting_ood_samples = 2;
    config.starting_log_inv_rate = 1;
    config.round_parameters = (0..num_rounds)
        .map(|_| RoundConfig {
            folding_factor: ff,
            evaluation_domain_log_size: 0,
            queries_pow_bits: 0,
            pow_bits: alloc::vec![0usize; ff],
            num_queries: 1,
            ood_samples: 1,
            log_inv_rate: 1,
        })
        .collect();
    config.final_poly_log_degree = n - ff * num_rounds;
    config
}

/// Fold the base MLE by a prefix of the folding randomness, reproducing the
/// prover's folded polynomial at a round boundary (LSB-first, one variable per
/// challenge — the same convention `fold_variables` uses).
fn fold_prefix(mle: &Mle<InnerVal>, randomness: &[InnerChallenge]) -> Mle<InnerChallenge> {
    let mut folded = mle.fix_last_variable::<InnerChallenge>(randomness[0]);
    for &r in &randomness[1..] {
        folded = folded.fix_last_variable::<InnerChallenge>(r);
    }
    folded
}

fn run_tower(
    n: usize,
    ff: usize,
    num_rounds: usize,
    seed: u64,
) -> (
    Mle<InnerVal>,
    crate::whir::round_prover::RoundedProof<InnerVal, InnerChallenge, InnerValMmcs>,
) {
    type F = InnerVal;
    type EF = InnerChallenge;

    let mut rng = StdRng::seed_from_u64(seed);
    let values: Vec<F> = (0..(1usize << n)).map(|_| rand_kb(&mut rng)).collect();
    let mle = Arc::new(Mle::from_row_major(RowMajorMatrix::new(values, 1)));

    let rand_pt = |rng: &mut StdRng| -> Vec<EF> {
        (0..n)
            .map(|_| {
                use p3_field::BasedVectorSpace;
                <EF as BasedVectorSpace<F>>::from_basis_coefficients_iter((0..4).map(|_| rand_kb(rng)))
                    .unwrap()
            })
            .collect()
    };
    let point = rand_pt(&mut rng);
    let eval = mle.eval_at::<EF>(&point)[0];

    let base_dft = Arc::new(Radix2DitParallel::<F>::default());
    let ef_dft = Arc::new(Radix2DitParallel::<EF>::default());
    let mmcs = build_mmcs();
    let mut challenger = build_challenger();

    let prover = WhirProver::<F, EF, _, _>::new(base_dft, mmcs, tower_config(n, ff, num_rounds));
    let proof =
        prover.prove_rounds(ef_dft, &mut challenger, Arc::clone(&mle), point, eval);
    (Arc::try_unwrap(mle).ok().unwrap(), proof)
}

/// The tower's reduced claim must equal `Σ_x weight[x]·f_final[x]` — the master
/// identity that threads through every fold and every re-batch.
#[test]
fn tower_claim_invariant() {
    let (_mle, proof) = run_tower(8, 2, 3, 0xA1);
    let dot: InnerChallenge = proof
        .final_weight
        .iter()
        .zip(&proof.final_poly)
        .map(|(&w, &f)| w * f)
        .sum();
    assert_eq!(proof.final_claim, dot, "claim must equal Σ weight·f over the final polynomial");
}

/// The tower folds the ORIGINAL polynomial: the revealed final polynomial,
/// evaluated at any point, equals `f` evaluated at `[folding_randomness, point]`.
/// Re-batching changes the claim and weight, never `f`.
#[test]
fn tower_folds_original_poly() {
    type F = InnerVal;
    type EF = InnerChallenge;
    let (mle, proof) = run_tower(8, 2, 3, 0xB2);

    let final_vars = proof.final_poly.len().trailing_zeros() as usize;
    let final_mle = Mle::from_row_major(RowMajorMatrix::new(proof.final_poly.clone(), 1));

    let mut rng = StdRng::seed_from_u64(0xB2_B2);
    let q: Vec<EF> = (0..final_vars)
        .map(|_| {
            use p3_field::BasedVectorSpace;
            <EF as BasedVectorSpace<F>>::from_basis_coefficients_iter((0..4).map(|_| rand_kb(&mut rng)))
                .unwrap()
        })
        .collect();

    let full_point: Vec<EF> = proof.folding_randomness.iter().copied().chain(q.iter().copied()).collect();
    assert_eq!(full_point.len(), mle.num_variables() as usize);
    assert_eq!(
        final_mle.eval_at::<EF>(&q)[0],
        mle.eval_at::<EF>(&full_point)[0],
        "final poly at q must equal f at [folding_randomness, q]"
    );
}

/// Each committed round's OOD answer must equal the round's folded polynomial
/// (the base MLE folded by the challenges consumed up to that commit) evaluated
/// at the round's OOD point — validating the OOD wiring across the tower.
#[test]
fn tower_round_ood_correct() {
    type EF = InnerChallenge;
    let (mle, proof) = run_tower(9, 3, 3, 0xC3);

    let ff = 3usize;
    for (r, round) in proof.rounds.iter().enumerate() {
        // Round r is committed AFTER folding `(r+1)*ff` variables.
        let prefix = &proof.folding_randomness[..(r + 1) * ff];
        let folded = fold_prefix(&mle, prefix);
        for (pt, &ans) in round.parsed.ood_points.iter().zip(&round.parsed.ood_answers) {
            assert_eq!(pt.len(), folded.num_variables() as usize, "OOD point over remaining vars");
            assert_eq!(ans, folded.eval_at::<EF>(pt)[0], "round OOD answer must match folded f");
        }
    }
    // A 3-round tower commits its two intermediate rounds; the last is revealed.
    assert_eq!(proof.rounds.len(), 2);
}

// ---------------------------------------------------------------------------
// Performance: WHIR prover vs BaseFold prover, identical inputs.
// ---------------------------------------------------------------------------

/// Build a WHIR config for `n` variables, uniform folding factor `ff`, a
/// per-round query schedule, and OOD samples — folding down to a
/// `final`-variable polynomial.
fn whir_config_for(n: usize, ff: usize, queries: &[usize], ood: usize, rate: usize, pow: usize) -> WhirConfig {
    use crate::whir::config::RoundConfig;
    let final_log = n - ff * queries.len();
    let mut config = WhirConfig::default_whir_config();
    config.starting_ood_samples = ood;
    config.starting_log_inv_rate = rate;
    config.round_parameters = queries
        .iter()
        .map(|&nq| RoundConfig {
            folding_factor: ff,
            evaluation_domain_log_size: 0,
            queries_pow_bits: pow,
            pow_bits: alloc::vec![0usize; ff],
            num_queries: nq,
            ood_samples: ood,
            log_inv_rate: rate,
        })
        .collect();
    config.final_poly_log_degree = final_log;
    config.final_queries = *queries.last().unwrap();
    config.final_pow_bits = pow;
    config
}

/// Median wall time of `iters` runs of `f`, in milliseconds.
fn median_ms(iters: usize, mut f: impl FnMut()) -> f64 {
    use std::time::Instant;
    let mut ts: Vec<f64> = (0..iters)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_secs_f64() * 1e3
        })
        .collect();
    ts.sort_by(|a, b| a.partial_cmp(b).unwrap());
    ts[ts.len() / 2]
}

#[test]
#[ignore = "perf benchmark; run with --ignored --nocapture"]
fn bench_whir_vs_basefold() {
    use crate::basefold::{BasefoldProver, FriConfig};

    type F = InnerVal;
    type EF = InnerChallenge;

    let iters = 5usize;
    for &n in &[18usize, 20] {
        let ff = 4usize;
        // Fold n down to a 2-var final poly: (n-2)/ff rounds.
        let n_rounds = (n - 2) / ff;
        let queries: Vec<usize> = (0..n_rounds)
            .map(|i| 124usize >> i) // 124, 62, 31, ... : BaseFold's budget, halving as the codeword shrinks
            .collect();

        let mut rng = StdRng::seed_from_u64(0x5EED ^ n as u64);
        let values: Vec<F> = (0..(1usize << n)).map(|_| rand_kb(&mut rng)).collect();
        let mle = Arc::new(Mle::from_row_major(RowMajorMatrix::new(values, 1)));
        let point: Vec<EF> = (0..n)
            .map(|_| {
                use p3_field::BasedVectorSpace;
                <EF as BasedVectorSpace<F>>::from_basis_coefficients_iter((0..4).map(|_| rand_kb(&mut rng)))
                    .unwrap()
            })
            .collect();
        let eval = mle.eval_at::<EF>(&point)[0];

        // ---- BaseFold prover (its designed params: blowup 2, 124 queries). ----
        let bf_cfg = FriConfig::<F>::default_fri_config();
        let bf_mmcs = build_mmcs();
        let bf_dft = Arc::new(Radix2DitParallel::<F>::default());
        let bf_prover = BasefoldProver::<F, EF, _, _>::new(bf_cfg, bf_dft, bf_mmcs, 1);
        // Time commit+prove TOTAL — WHIR's `prove` includes the starting
        // encode+commit, so BaseFold must include `commit_mles` for parity.
        let bf_ms = median_ms(iters, || {
            let mut ch = build_challenger();
            let (_bc, bf_data) = bf_prover.commit_mles(vec![Arc::clone(&mle)]);
            let _ = bf_prover.prove_trusted_mle_evaluations(
                point.clone(),
                vec![vec![Arc::clone(&mle)]],
                vec![vec![eval]],
                &[&bf_data],
                &mut ch,
            );
        });

        // ---- WHIR prover (its designed params: OOD + fewer queries). ----
        let whir_cfg = whir_config_for(n, ff, &queries, 2, 2, 16); // rate 2 + pow 16, matched to BaseFold
        let whir_mmcs = build_mmcs();
        let base_dft = Arc::new(Radix2DitParallel::<F>::default());
        let ef_dft = Arc::new(Radix2DitParallel::<EF>::default());
        let whir_prover = WhirProver::<F, EF, _, _>::new(base_dft, whir_mmcs, whir_cfg);
        let whir_ms = median_ms(iters, || {
            let mut ch = build_challenger();
            let _ = whir_prover.prove(
                Arc::clone(&ef_dft),
                &mut ch,
                Arc::clone(&mle),
                point.clone(),
                eval,
            );
        });

        println!(
            "n={n:2} ({} pts): BaseFold {bf_ms:8.2} ms  |  WHIR {whir_ms:8.2} ms  |  ratio {:.3}x  ({} WHIR rounds, queries {:?})",
            1usize << n,
            whir_ms / bf_ms,
            n_rounds,
            queries,
        );
    }
}

// ---------------------------------------------------------------------------
// Phase 3: the tower verifier (sumcheck + OOD + terminal identity).
// ---------------------------------------------------------------------------

/// Prove with one challenger, verify with a fresh one replaying the transcript;
/// the honest proof must verify, and tampering must be rejected.
#[test]
fn tower_roundtrip_verifies() {
    use crate::whir::verifier::{WhirVerifier, WhirVerifierError};

    type F = InnerVal;
    type EF = InnerChallenge;

    let (n, ff, num_rounds) = (9usize, 3usize, 3usize);
    let mut rng = StdRng::seed_from_u64(0x2E57);
    let values: Vec<F> = (0..(1usize << n)).map(|_| rand_kb(&mut rng)).collect();
    let mle = Arc::new(Mle::from_row_major(RowMajorMatrix::new(values, 1)));
    let point: Vec<EF> = (0..n)
        .map(|_| {
            use p3_field::BasedVectorSpace;
            <EF as BasedVectorSpace<F>>::from_basis_coefficients_iter((0..4).map(|_| rand_kb(&mut rng)))
                .unwrap()
        })
        .collect();
    let eval = mle.eval_at::<EF>(&point)[0];

    let base_dft = Arc::new(Radix2DitParallel::<F>::default());
    let ef_dft = Arc::new(Radix2DitParallel::<EF>::default());
    let cfg = tower_config(n, ff, num_rounds);

    let prover = WhirProver::<F, EF, _, _>::new(base_dft, build_mmcs(), cfg.clone());
    let mut p_chal = build_challenger();
    let proof =
        prover.prove_rounds(Arc::clone(&ef_dft), &mut p_chal, Arc::clone(&mle), point.clone(), eval);

    let verifier = WhirVerifier::<F, EF, _>::new(build_mmcs(), cfg);

    // Honest proof verifies.
    let mut v_chal = build_challenger();
    assert_eq!(verifier.verify_rounds(&mut v_chal, &point, eval, &proof), Ok(()));

    // Wrong evaluation claim is rejected — it changes the initial claim, so
    // the very first sumcheck message g(0)+g(1)==claim already fails.
    let mut v_chal = build_challenger();
    assert!(verifier.verify_rounds(&mut v_chal, &point, eval + EF::ONE, &proof).is_err());

    // Tampering with the final polynomial is rejected.
    let mut bad = proof;
    bad.final_poly[0] += EF::ONE;
    let mut v_chal = build_challenger();
    assert_eq!(
        verifier.verify_rounds(&mut v_chal, &point, eval, &bad),
        Err(WhirVerifierError::TerminalMismatch),
    );
}

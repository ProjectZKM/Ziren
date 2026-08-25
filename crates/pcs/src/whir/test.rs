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

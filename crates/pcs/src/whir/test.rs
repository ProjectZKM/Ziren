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

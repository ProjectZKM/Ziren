use alloc::vec;
use core::borrow::Borrow;
use core::marker::PhantomData;
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_circle::CirclePcs;
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_field::{FieldAlgebra, PrimeField64};
use p3_fri::FriConfig;
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_mersenne_31::Mersenne31;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};

use tracing_forest::util::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

/// For testing the public values feature
pub struct FibonacciAir {}

impl<F> BaseAir<F> for FibonacciAir {
    fn width(&self) -> usize {
        NUM_FIBONACCI_COLS
    }
}

impl<AB: AirBuilderWithPublicValues> Air<AB> for FibonacciAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let pis = builder.public_values();

        let a = pis[0];
        let b = pis[1];
        let x = pis[2];

        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &FibonacciRow<AB::Var> = (*local).borrow();
        let next: &FibonacciRow<AB::Var> = (*next).borrow();

        let mut when_first_row = builder.when_first_row();

        when_first_row.assert_eq(local.left, a);
        when_first_row.assert_eq(local.right, b);

        let mut when_transition = builder.when_transition();

        // a' <- b
        when_transition.assert_eq(local.right, next.left);

        // b' <- a + b
        when_transition.assert_eq(local.left + local.right, next.right);

        builder.when_last_row().assert_eq(local.right, x);
    }
}

pub fn generate_trace_rows<F: PrimeField64>(a: u64, b: u64, n: usize) -> RowMajorMatrix<F> {
    assert!(n.is_power_of_two());

    let mut trace = RowMajorMatrix::new(F::zero_vec(n * NUM_FIBONACCI_COLS), NUM_FIBONACCI_COLS);

    let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<FibonacciRow<F>>() };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), n);

    rows[0] = FibonacciRow::new(F::from_canonical_u64(a), F::from_canonical_u64(b));

    for i in 1..n {
        rows[i].left = rows[i - 1].right;
        rows[i].right = rows[i - 1].left + rows[i - 1].right;
    }

    trace
}

const NUM_FIBONACCI_COLS: usize = size_of::<FibonacciRow<u8>>();

pub struct FibonacciRow<F> {
    pub left: F,
    pub right: F,
}

impl<F> FibonacciRow<F> {
    const fn new(left: F, right: F) -> FibonacciRow<F> {
        FibonacciRow { left, right }
    }
}

impl<F> Borrow<FibonacciRow<F>> for [F] {
    fn borrow(&self) -> &FibonacciRow<F> {
        debug_assert_eq!(self.len(), NUM_FIBONACCI_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<FibonacciRow<F>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

type Val = Mersenne31;
type Challenge = BinomialExtensionField<Val, 3>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type ByteHash = Keccak256Hash;
type FieldHash = SerializingHasher32<ByteHash>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
type Pcs = CirclePcs<Val, ValMmcs, ChallengeMmcs>;

/// n-th Fibonacci number expected to be x
fn test_public_value_impl(n: usize, x: u64) {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .try_from_env()
        .unwrap_or_default();

    let _ = Registry::default().with(env_filter).with(ForestLayer::default()).try_init();

    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(byte_hash);
    let compress = MyCompress::new(byte_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let trace = generate_trace_rows::<Val>(0, 1, n);
    let fri_config =
        FriConfig { log_blowup: 1, num_queries: 8, proof_of_work_bits: 8, mmcs: challenge_mmcs };
    let pcs = Pcs { mmcs: val_mmcs, fri_config, _phantom: PhantomData };
    let config = p3_uni_stark::StarkConfig::new(pcs);
    let mut challenger = Challenger::from_hasher(vec![], byte_hash);
    let pis = vec![
        Mersenne31::from_canonical_u64(0),
        Mersenne31::from_canonical_u64(1),
        Mersenne31::from_canonical_u64(x),
    ];
    let proof = p3_uni_stark::prove(&config, &FibonacciAir {}, &mut challenger, trace, &pis);
    let mut challenger = Challenger::from_hasher(vec![], byte_hash);
    p3_uni_stark::verify(&config, &FibonacciAir {}, &mut challenger, &proof, &pis)
        .expect("verification failed");
}

#[test]
fn test_one_row_trace() {
    test_public_value_impl(4, 3);
}

#[test]
fn test_public_value() {
    test_public_value_impl(1 << 3, 21);
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "assertion `left == right` failed: constraints had nonzero value")]
fn test_incorrect_public_value() {
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(byte_hash);
    let compress = MyCompress::new(byte_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_config =
        FriConfig { log_blowup: 2, num_queries: 28, proof_of_work_bits: 8, mmcs: challenge_mmcs };
    let trace = generate_trace_rows::<Val>(0, 1, 1 << 3);

    let pcs = Pcs { mmcs: val_mmcs, fri_config, _phantom: PhantomData };
    let config = p3_uni_stark::StarkConfig::new(pcs);
    let mut challenger = Challenger::from_hasher(vec![], byte_hash);
    let pis = vec![
        Mersenne31::from_canonical_u64(0),
        Mersenne31::from_canonical_u64(1),
        Mersenne31::from_canonical_u64(123_123), // incorrect result
    ];
    p3_uni_stark::prove(&config, &FibonacciAir {}, &mut challenger, trace, &pis);
}

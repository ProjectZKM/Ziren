pub mod alu_base;
pub mod alu_ext;
pub mod batch_fri;
pub mod exp_reverse_bits;
pub mod fri_fold;
pub mod mem;
pub mod poseidon2_skinny;
pub mod poseidon2_wide;
pub mod public_values;
pub mod select;

pub mod test_fixtures {
    use std::{array, borrow::Borrow};

    use p3_field::{Field, FieldAlgebra, PrimeField32};
    use p3_koala_bear::KoalaBear;
    use p3_symmetric::Permutation;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use zkm_stark::inner_perm;

    use crate::*;

    const SEED: u64 = 12345;
    pub const MIN_TEST_CASES: usize = 1000;
    const MAX_TEST_CASES: usize = 10000;

    pub fn shard() -> ExecutionRecord<KoalaBear> {
        ExecutionRecord {
            base_alu_events: base_alu_events(),
            ext_alu_events: ext_alu_events(),
            batch_fri_events: batch_fri_events(),
            exp_reverse_bits_len_events: exp_reverse_bits_events(),
            fri_fold_events: fri_fold_events(),
            commit_pv_hash_events: public_values_events(),
            select_events: select_events(),
            poseidon2_events: poseidon2_events(),
            ..Default::default()
        }
    }

    pub fn default_execution_record() -> ExecutionRecord<KoalaBear> {
        ExecutionRecord::<KoalaBear>::default()
    }

    fn initialize() -> (StdRng, usize) {
        let mut rng = StdRng::seed_from_u64(SEED);
        let num_test_cases = rng.gen_range(MIN_TEST_CASES..=MAX_TEST_CASES);
        (rng, num_test_cases)
    }

    fn base_alu_events() -> Vec<BaseAluIo<KoalaBear>> {
        let (mut rng, num_test_cases) = initialize();
        let mut events = Vec::with_capacity(num_test_cases);
        for _ in 0..num_test_cases {
            let in1 = KoalaBear::from_wrapped_u32(rng.gen());
            let in2 = KoalaBear::from_wrapped_u32(rng.gen());
            let out = match rng.gen_range(0..4) {
                0 => in1 + in2, // Add
                1 => in1 - in2, // Sub
                2 => in1 * in2, // Mul
                _ => {
                    let in2 = if in2.is_zero() { KoalaBear::one() } else { in2 };
                    in1 / in2
                }
            };
            events.push(BaseAluIo { out, in1, in2 });
        }
        events
    }

    fn ext_alu_events() -> Vec<ExtAluIo<Block<KoalaBear>>> {
        let (_, num_test_cases) = initialize();
        let mut events = Vec::with_capacity(num_test_cases);
        for _ in 0..num_test_cases {
            events.push(ExtAluIo {
                out: KoalaBear::one().into(),
                in1: KoalaBear::one().into(),
                in2: KoalaBear::one().into(),
            });
        }
        events
    }

    fn batch_fri_events() -> Vec<BatchFRIEvent<KoalaBear>> {
        let (_, num_test_cases) = initialize();
        let mut events = Vec::with_capacity(num_test_cases);
        for _ in 0..num_test_cases {
            events.push(BatchFRIEvent {
                ext_single: BatchFRIExtSingleIo { acc: Block::default() },
                ext_vec: BatchFRIExtVecIo { alpha_pow: Block::default(), p_at_z: Block::default() },
                base_vec: BatchFRIBaseVecIo { p_at_x: KoalaBear::one() },
            });
        }
        events
    }

    fn exp_reverse_bits_events() -> Vec<ExpReverseBitsEvent<KoalaBear>> {
        let (mut rng, num_test_cases) = initialize();
        let mut events = Vec::with_capacity(num_test_cases);
        for _ in 0..num_test_cases {
            let base = KoalaBear::from_wrapped_u32(rng.gen());
            let len = rng.gen_range(1..8); // Random length between 1 and 7 bits
            let exp: Vec<KoalaBear> =
                (0..len).map(|_| KoalaBear::from_canonical_u32(rng.gen_range(0..2))).collect();
            let exp_num = exp
                .iter()
                .enumerate()
                .fold(0u32, |acc, (i, &bit)| acc + (bit.as_canonical_u32() << i));
            let result = base.exp_u64(exp_num as u64);

            events.push(ExpReverseBitsEvent { base, exp, result });
        }
        events
    }

    fn fri_fold_events() -> Vec<FriFoldEvent<KoalaBear>> {
        let (mut rng, num_test_cases) = initialize();
        let mut events = Vec::with_capacity(num_test_cases);
        let random_block =
            |rng: &mut StdRng| Block::from([KoalaBear::from_wrapped_u32(rng.gen()); 4]);
        for _ in 0..num_test_cases {
            events.push(FriFoldEvent {
                base_single: FriFoldBaseIo { x: KoalaBear::from_wrapped_u32(rng.gen()) },
                ext_single: FriFoldExtSingleIo {
                    z: random_block(&mut rng),
                    alpha: random_block(&mut rng),
                },
                ext_vec: FriFoldExtVecIo {
                    mat_opening: random_block(&mut rng),
                    ps_at_z: random_block(&mut rng),
                    alpha_pow_input: random_block(&mut rng),
                    ro_input: random_block(&mut rng),
                    alpha_pow_output: random_block(&mut rng),
                    ro_output: random_block(&mut rng),
                },
            });
        }
        events
    }

    fn public_values_events() -> Vec<CommitPublicValuesEvent<KoalaBear>> {
        let (mut rng, num_test_cases) = initialize();
        let mut events = Vec::with_capacity(num_test_cases);
        for _ in 0..num_test_cases {
            let random_felts: [KoalaBear; air::RECURSIVE_PROOF_NUM_PV_ELTS] =
                array::from_fn(|_| KoalaBear::from_wrapped_u32(rng.gen()));
            events
                .push(CommitPublicValuesEvent { public_values: *random_felts.as_slice().borrow() });
        }
        events
    }

    fn select_events() -> Vec<SelectIo<KoalaBear>> {
        let (mut rng, num_test_cases) = initialize();
        let mut events = Vec::with_capacity(num_test_cases);
        for _ in 0..num_test_cases {
            let bit = if rng.gen_bool(0.5) { KoalaBear::one() } else { KoalaBear::zero() };
            let in1 = KoalaBear::from_wrapped_u32(rng.gen());
            let in2 = KoalaBear::from_wrapped_u32(rng.gen());
            let (out1, out2) = if bit == KoalaBear::one() { (in1, in2) } else { (in2, in1) };
            events.push(SelectIo { bit, out1, out2, in1, in2 });
        }
        events
    }

    fn poseidon2_events() -> Vec<Poseidon2Event<KoalaBear>> {
        let (mut rng, num_test_cases) = initialize();
        let mut events = Vec::with_capacity(num_test_cases);
        for _ in 0..num_test_cases {
            let input = array::from_fn(|_| KoalaBear::from_wrapped_u32(rng.gen()));
            let permuter = inner_perm();
            let output = permuter.permute(input);

            events.push(Poseidon2Event { input, output });
        }
        events
    }
}

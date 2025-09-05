// use p3_bn254_fr::Bn254Fr;
use p3_sect_fr::SectFr;
use p3_field::{FieldAlgebra, PrimeField32};
use p3_koala_bear::KoalaBear;

use zkm_recursion_compiler::ir::{Builder, Config, Felt, Var};
use zkm_recursion_core::DIGEST_SIZE;

use zkm_stark::Word;

/// Convert 8 KoalaBear words into a Bn254Fr field element by shifting by 31 bits each time. The last
/// word becomes the least significant bits.
#[allow(dead_code)]
pub fn koalabears_to_bn254(digest: &[KoalaBear; 8]) -> SectFr {
    let mut result = SectFr::ZERO;
    for (idx, word) in digest.iter().enumerate() {
        result *= SectFr::from_canonical_u64(1 << 32);
        let masked_val_u32 = if idx == 0 { 0 } else { word.as_canonical_u32() };
        result += SectFr::from_canonical_u32(masked_val_u32);
    }
    result
}

/// Convert 32 KoalaBear bytes into a Bn254Fr field element. The first byte's most significant 3 bits
/// (which would become the 3 most significant bits) are truncated.
#[allow(dead_code)]
pub fn koalabear_bytes_to_bn254(bytes: &[KoalaBear; 32]) -> SectFr {
    let mut result = SectFr::ZERO;
    for (idx, byte) in bytes.iter().enumerate() {
        result *= SectFr::from_canonical_u32(256); // shift by 7 bits
        let masked = if idx < 4 { 0 } else { byte.as_canonical_u32() };
        result += SectFr::from_canonical_u32(masked); // add 7-bit
    }
    result
}

#[allow(dead_code)]
pub fn felts_to_bn254_var<C: Config>(
    builder: &mut Builder<C>,
    digest: &[Felt<C::F>; DIGEST_SIZE],
) -> Var<C::N> {
    let var_2_32: Var<_> = builder.constant(C::N::from_canonical_u64(1 << 32));
    let result = builder.constant(C::N::ZERO);
    let zero_var: Var<_> = builder.constant(C::N::ZERO);

    for (i, word) in digest.iter().enumerate() {
        let all_bits: Vec<Var<C::N>> = builder.num2bits_f_circuit(*word);
        let word_var = if i == 0 { zero_var } else { builder.bits2num_v_circuit(&all_bits) };
        if i == 0 {
            builder.assign(result, word_var);
        } else {
            builder.assign(result, result * var_2_32 + word_var);
        }
    }
    result
}

#[allow(dead_code)]
pub fn felt_bytes_to_bn254_var<C: Config>(
    builder: &mut Builder<C>,
    bytes: &[Felt<C::F>; 32],
) -> Var<C::N> {
    let var_256: Var<_> = builder.constant(C::N::from_canonical_u32(256));
    let zero_var: Var<_> = builder.constant(C::N::ZERO);
    let result = builder.constant(C::N::ZERO);
    for (i, byte) in bytes.iter().enumerate() {
        let byte_bits = builder.num2bits_f_circuit(*byte);
        let byte_var = if i < 4 { zero_var } else { builder.bits2num_v_circuit(&byte_bits) };
        if i == 0 {
            builder.assign(result, byte_var);
        } else {
            builder.assign(result, result * var_256 + byte_var);
        }
    }
    result
}

#[allow(dead_code)]
pub fn words_to_bytes<T: Copy>(words: &[Word<T>]) -> Vec<T> {
    words.iter().flat_map(|w| w.0).collect::<Vec<_>>()
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use zkm_core_machine::utils::{run_test_machine_with_prover, setup_logger};
    use zkm_recursion_compiler::{circuit::AsmCompiler, circuit::AsmConfig, ir::DslIr};

    use zkm_recursion_compiler::ir::TracedVec;
    use zkm_recursion_core::{machine::RecursionAir, Runtime};
    use zkm_stark::{
        koala_bear_poseidon2::KoalaBearPoseidon2, CpuProver, InnerChallenge, InnerVal,
        MachineProver,
    };

    use crate::witness::WitnessBlock;

    type SC = KoalaBearPoseidon2;
    type F = InnerVal;
    type EF = InnerChallenge;

    /// A simplified version of some code from `recursion/core/src/stark/mod.rs`.
    /// Takes in a program and runs it with the given witness and generates a proof with a variety
    /// of machines depending on the provided test_config.
    pub(crate) fn run_test_recursion_with_prover<P: MachineProver<SC, RecursionAir<F, 3>>>(
        operations: TracedVec<DslIr<AsmConfig<F, EF>>>,
        witness_stream: impl IntoIterator<Item = WitnessBlock<AsmConfig<F, EF>>>,
    ) {
        setup_logger();

        let compile_span = tracing::debug_span!("compile").entered();
        let mut compiler = AsmCompiler::<AsmConfig<F, EF>>::default();
        let program = Arc::new(compiler.compile(operations));
        compile_span.exit();

        let config = SC::default();

        let run_span = tracing::debug_span!("run the recursive program").entered();
        let mut runtime = Runtime::<F, EF, _>::new(program.clone(), config.perm.clone());
        runtime.witness_stream.extend(witness_stream);
        tracing::debug_span!("run").in_scope(|| runtime.run().unwrap());
        assert!(runtime.witness_stream.is_empty());
        run_span.exit();

        let records = vec![runtime.record];

        // Run with the poseidon2 wide chip.
        let proof_wide_span = tracing::debug_span!("Run test with wide machine").entered();
        let wide_machine = RecursionAir::<_, 3>::compress_machine(SC::default());
        let (pk, vk) = wide_machine.setup(&program);
        let prover = P::new(wide_machine);
        let pk = prover.pk_to_device(&pk);
        let result = run_test_machine_with_prover::<_, _, P>(&prover, records.clone(), pk, vk);
        proof_wide_span.exit();

        if let Err(e) = result {
            panic!("Verification failed: {e:?}");
        }
    }

    #[allow(dead_code)]
    pub(crate) fn run_test_recursion(
        operations: TracedVec<DslIr<AsmConfig<F, EF>>>,
        witness_stream: impl IntoIterator<Item = WitnessBlock<AsmConfig<F, EF>>>,
    ) {
        run_test_recursion_with_prover::<CpuProver<_, _>>(operations, witness_stream)
    }
}

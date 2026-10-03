//! Blake3 in the recursion circuit, over 16-bit limbs.
//!
//! The Blake3 ring commits KoalaBear traces under Blake3 Merkle trees whose
//! leaves hash each element as the four little-endian bytes of its
//! canonical value, and runs a Blake3 transcript over the same bytes.  A
//! 32-bit word does not fit a field element, so the circuit carries every
//! word as two 16-bit limbs, low limb first: a digest is sixteen limbs, a
//! block thirty-two, and an element becomes its two limbs through a
//! canonical bit decomposition.  One [`CircuitV2Builder::blake3_compress_v2`]
//! runs one compression; a hash of at most one chunk is a run of them over
//! the input's blocks, which is every hash the verifier of this ring needs.

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use zkm_pcs::kb31_blake3::{Blake3Digest, ROOT_WORD_BITS};
use zkm_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Felt, SymbolicFelt},
};
use zkm_recursion_core::runtime::blake3::{
    BLOCK_LEN, BLOCK_WORDS, CHUNK_END, CHUNK_LEN, CHUNK_START, IV, ROOT,
};
use zkm_recursion_core::{BLAKE3_BLOCK_LIMBS, BLAKE3_CV_LIMBS, BLAKE3_OUT_LIMBS};

use crate::CircuitConfig;

/// Bits of a limb.
pub const LIMB_BITS: usize = 16;

/// Limbs of a digest.
pub const DIGEST_LIMBS: usize = BLAKE3_OUT_LIMBS;

/// Limbs a run of compressions hashes at most: one chunk.
pub const CHUNK_LIMBS: usize = CHUNK_LEN / 2;

/// A digest in the circuit.
pub type DigestLimbs<F> = [Felt<F>; DIGEST_LIMBS];

/// The limbs of a digest's bytes, on the host.
pub fn digest_limbs(digest: &Blake3Digest) -> [KoalaBear; DIGEST_LIMBS] {
    core::array::from_fn(|i| {
        KoalaBear::from_u16(u16::from_le_bytes([digest[2 * i], digest[2 * i + 1]]))
    })
}

/// The bytes of a digest's limbs, on the host.
pub fn limbs_digest(limbs: &[KoalaBear; DIGEST_LIMBS]) -> Blake3Digest {
    let mut out = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        let value = limb.as_canonical_u32();
        assert!(value < 1 << LIMB_BITS, "a digest limb is sixteen bits");
        out[2 * i..2 * i + 2].copy_from_slice(&(value as u16).to_le_bytes());
    }
    out
}

/// The limbs of a word.
pub fn word_limbs(word: u32) -> [KoalaBear; 2] {
    [KoalaBear::from_u32(word & 0xFFFF), KoalaBear::from_u32(word >> LIMB_BITS)]
}

/// The Blake3 digest of elements on the host, each as its canonical bytes:
/// what [`hash_felts`] computes in the circuit.
pub fn hash_felts_host(values: &[KoalaBear]) -> [KoalaBear; DIGEST_LIMBS] {
    use p3_symmetric::CryptographicHasher;
    let bytes = values.iter().flat_map(|v| v.as_canonical_u32().to_le_bytes());
    let digest: Blake3Digest = p3_blake3::Blake3.hash_iter(bytes);
    digest_limbs(&digest)
}

/// The digest of a verifying key of the Blake3 ring, as the circuit's
/// [`crate::VerifyingKeyVariable::hash`] computes it: the root's limbs,
/// the start pc and the initial global cumulative sum.
pub fn vk_digest(
    vk: &zkm_pcs::StarkVerifyingKey<zkm_pcs::KoalaBearBlake3>,
) -> [KoalaBear; DIGEST_LIMBS] {
    let roots = vk.commit.roots();
    assert_eq!(roots.len(), 1, "a Blake3 commitment is one root");
    let mut inputs: Vec<KoalaBear> = digest_limbs(&roots[0]).to_vec();
    inputs.push(vk.pc_start);
    inputs.extend(vk.initial_global_cumulative_sum.0.x.0);
    inputs.extend(vk.initial_global_cumulative_sum.0.y.0);
    hash_felts_host(&inputs)
}

/// The two limbs of an element's canonical value, bound by the binary
/// machine's limb table to the element's bits, so the bytes the host hashes
/// are the ones the circuit hashes.
pub fn felt_limbs<C: CircuitConfig<F = KoalaBear>>(
    builder: &mut Builder<C>,
    value: Felt<KoalaBear>,
) -> [Felt<KoalaBear>; 2] {
    builder.felt_limbs_v2(value)
}

/// The limbs of a slice of elements, in order.
pub fn felts_limbs<C: CircuitConfig<F = KoalaBear>>(
    builder: &mut Builder<C>,
    values: &[Felt<KoalaBear>],
) -> Vec<Felt<KoalaBear>> {
    values.iter().flat_map(|&v| felt_limbs(builder, v)).collect()
}

/// The IV as limbs.
fn iv_limbs<C: CircuitConfig<F = KoalaBear>>(
    builder: &mut Builder<C>,
) -> [Felt<KoalaBear>; BLAKE3_CV_LIMBS] {
    core::array::from_fn(|i| builder.constant(word_limbs(IV[i / 2])[i % 2]))
}

/// The Blake3 digest of at most one chunk of limbs: the run of
/// compressions of [`zkm_recursion_core::runtime::blake3::chunk_schedule`].
pub fn hash_limbs<C: CircuitConfig<F = KoalaBear>>(
    builder: &mut Builder<C>,
    limbs: &[Felt<KoalaBear>],
) -> DigestLimbs<KoalaBear> {
    assert!(limbs.len() <= CHUNK_LIMBS, "a run of compressions hashes at most one chunk");
    let blocks: Vec<&[Felt<KoalaBear>]> =
        if limbs.is_empty() { vec![&[][..]] } else { limbs.chunks(BLOCK_WORDS * 2).collect() };
    let last = blocks.len() - 1;
    let zero: Felt<KoalaBear> = builder.constant(KoalaBear::ZERO);
    let mut chaining_value = iv_limbs(builder);
    for (i, block) in blocks.iter().enumerate() {
        let mut flags = 0;
        if i == 0 {
            flags |= CHUNK_START;
        }
        if i == last {
            flags |= CHUNK_END | ROOT;
        }
        let padded: [Felt<KoalaBear>; BLAKE3_BLOCK_LIMBS] =
            core::array::from_fn(|j| block.get(j).copied().unwrap_or(zero));
        let block_len = (2 * block.len()) as u32;
        debug_assert!(block_len as usize <= BLOCK_LEN);
        chaining_value = builder.blake3_compress_v2(chaining_value, padded, block_len, flags);
    }
    chaining_value
}

/// The Blake3 digest of elements, each hashed as its canonical bytes.
pub fn hash_felts<C: CircuitConfig<F = KoalaBear>>(
    builder: &mut Builder<C>,
    values: &[Felt<KoalaBear>],
) -> DigestLimbs<KoalaBear> {
    let limbs = felts_limbs(builder, values);
    hash_limbs(builder, &limbs)
}

/// The Merkle node of two digests: the Blake3 hash of their sixty-four
/// bytes, one compression.
pub fn compress_digests<C: CircuitConfig<F = KoalaBear>>(
    builder: &mut Builder<C>,
    input: [DigestLimbs<KoalaBear>; 2],
) -> DigestLimbs<KoalaBear> {
    let block: [Felt<KoalaBear>; BLAKE3_BLOCK_LIMBS] = core::array::from_fn(|j| {
        if j < DIGEST_LIMBS {
            input[0][j]
        } else {
            input[1][j - DIGEST_LIMBS]
        }
    });
    let chaining_value = iv_limbs(builder);
    builder.blake3_compress_v2(
        chaining_value,
        block,
        BLOCK_LEN as u32,
        CHUNK_START | CHUNK_END | ROOT,
    )
}

/// A root as the eight elements the transcript observes: the low thirty
/// bits of each word, the circuit twin of
/// [`zkm_pcs::kb31_blake3::root_felts`].  The high limb of each word is
/// decomposed so its top two bits can be dropped; a digest limb is sixteen
/// bits, so the decomposition is unique.
pub fn root_felts<C: CircuitConfig<F = KoalaBear>>(
    builder: &mut Builder<C>,
    digest: &DigestLimbs<KoalaBear>,
) -> [Felt<KoalaBear>; 8] {
    let kept_high_bits = ROOT_WORD_BITS as usize - LIMB_BITS;
    core::array::from_fn(|i| {
        let low = digest[2 * i];
        let high_bits = builder.num2bits_v2_f(digest[2 * i + 1], LIMB_BITS);
        let high_kept: SymbolicFelt<KoalaBear> = high_bits[..kept_high_bits]
            .iter()
            .enumerate()
            .map(|(k, &bit)| SymbolicFelt::from(bit) * KoalaBear::from_u32(1 << k))
            .sum();
        builder.eval(SymbolicFelt::from(low) + high_kept * KoalaBear::from_u32(1 << LIMB_BITS))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Limbs and bytes round-trip.
    #[test]
    fn limbs_round_trip() {
        let digest: Blake3Digest = core::array::from_fn(|i| (i * 37 % 251) as u8);
        assert_eq!(limbs_digest(&digest_limbs(&digest)), digest);
        assert_eq!(
            word_limbs(0x1234_ABCD),
            [KoalaBear::from_u32(0xABCD), KoalaBear::from_u32(0x1234)]
        );
    }
}

#[cfg(test)]
mod execution_tests {
    use p3_challenger::{CanObserve, CanSample, CanSampleBits, GrindingChallenger};
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;
    use zkm_pcs::kb31_blake3::{blake3_challenger, ABSORB_CAP_BYTES};
    use zkm_pcs::{InnerChallenge, InnerVal};
    use zkm_recursion_compiler::circuit::AsmCompiler;
    use zkm_recursion_compiler::config::InnerConfig;
    use zkm_recursion_compiler::ir::{Builder, Felt};
    use zkm_recursion_core::Runtime;

    use super::*;
    use crate::challenger::{
        Blake3ChallengerVariable, CanObserveVariable, CanSampleBitsVariable, CanSampleVariable,
        FieldChallengerVariable,
    };

    /// Compile and run `builder`'s program in the interpreter; a failed
    /// assertion is a runtime error.
    fn execute(builder: Builder<InnerConfig>) {
        let mut compiler = AsmCompiler::<InnerConfig>::default();
        let program = std::sync::Arc::new(compiler.compile(builder.into_operations()));
        let config = zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2::default();
        let mut runtime = Runtime::<InnerVal, InnerChallenge, _>::new(program, config.perm.clone());
        runtime.run().expect("every assertion holds");
    }

    fn elements(n: usize, seed: u64) -> Vec<KoalaBear> {
        let mut state = seed;
        (0..n)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                KoalaBear::from_u64(state >> 33)
            })
            .collect()
    }

    fn assert_digest(
        builder: &mut Builder<InnerConfig>,
        computed: DigestLimbs<KoalaBear>,
        expected: [KoalaBear; DIGEST_LIMBS],
    ) {
        for (c, e) in computed.into_iter().zip(expected) {
            builder.assert_felt_eq(c, e);
        }
    }

    /// The circuit's hash of elements, and the node of two digests, are
    /// the host's, at every length up to a chunk's worth of elements.
    #[test]
    fn hash_and_compress_match_the_host() {
        let mut builder = Builder::<InnerConfig>::default();
        for len in [0usize, 1, 2, 15, 16, 17, 100, 248] {
            let values = elements(len, len as u64 + 1);
            let felts: Vec<Felt<KoalaBear>> = values.iter().map(|v| builder.constant(*v)).collect();
            let computed = hash_felts(&mut builder, &felts);
            assert_digest(&mut builder, computed, hash_felts_host(&values));
        }
        let a = hash_felts_host(&elements(3, 7));
        let b = hash_felts_host(&elements(5, 9));
        let a_var = core::array::from_fn(|i| builder.constant(a[i]));
        let b_var = core::array::from_fn(|i| builder.constant(b[i]));
        let node = compress_digests(&mut builder, [a_var, b_var]);
        assert_digest(
            &mut builder,
            node,
            <zkm_pcs::KoalaBearBlake3 as crate::hash::FieldHasher<KoalaBear>>::constant_compress([
                a, b,
            ]),
        );
        let root = elements(1, 3)[0];
        let digest = hash_felts_host(&[root]);
        let digest_var = core::array::from_fn(|i| builder.constant(digest[i]));
        let felts = root_felts(&mut builder, &digest_var);
        let expected = zkm_pcs::kb31_blake3::root_felts(&limbs_digest(&digest));
        for (c, e) in felts.into_iter().zip(expected) {
            builder.assert_felt_eq(c, e);
        }
        execute(builder);
    }

    /// A Merkle path of the ring's commitment scheme verifies in the
    /// circuit from the hashed leaf: the leaf and node hashes are the
    /// host's.
    #[test]
    fn merkle_path_matches_the_host() {
        use p3_commit::Mmcs;
        use p3_matrix::dense::RowMajorMatrix;
        let mmcs = zkm_pcs::kb31_blake3::blake3_mmcs();
        let (width, log_height) = (5usize, 4usize);
        let values = elements(width << log_height, 11);
        let (commitment, data) = mmcs.commit(vec![RowMajorMatrix::new(values.clone(), width)]);
        let root = digest_limbs(&commitment.roots()[0]);
        let mut builder = Builder::<InnerConfig>::default();
        for index in [0usize, 5, 15] {
            let opening = mmcs.open_batch(index, &data);
            let row: Vec<Felt<KoalaBear>> =
                opening.opened_values[0].iter().map(|v| builder.constant(*v)).collect();
            assert_eq!(opening.opened_values[0], values[index * width..(index + 1) * width]);
            let mut digest = hash_felts(&mut builder, &row);
            for (level, sibling) in opening.opening_proof.iter().enumerate() {
                let sibling: DigestLimbs<KoalaBear> = {
                    let limbs = digest_limbs(sibling);
                    core::array::from_fn(|i| builder.constant(limbs[i]))
                };
                let pair =
                    if (index >> level) & 1 == 1 { [sibling, digest] } else { [digest, sibling] };
                digest = compress_digests(&mut builder, pair);
            }
            assert_digest(&mut builder, digest, root);
        }
        execute(builder);
    }

    /// The circuit's transcript samples what the host's does through
    /// observations of elements and digests, samples, bits, a grind and a
    /// fold at the cap.
    #[test]
    fn challenger_matches_the_host() {
        let mut builder = Builder::<InnerConfig>::default();
        let mut host = blake3_challenger();
        let mut circuit = Blake3ChallengerVariable::<InnerConfig>::new(&mut builder);
        let values = elements(ABSORB_CAP_BYTES / 4 + 10, 42);
        for (i, v) in values.iter().enumerate() {
            host.observe(*v);
            let felt: Felt<KoalaBear> = builder.constant(*v);
            CanObserveVariable::<InnerConfig, Felt<KoalaBear>>::observe(
                &mut circuit,
                &mut builder,
                felt,
            );
            if i % 97 == 5 {
                let x: KoalaBear = host.sample();
                let y = circuit.sample(&mut builder);
                builder.assert_felt_eq(y, x);
                let e: InnerChallenge = host.sample();
                let f = circuit.sample_ext(&mut builder);
                builder.assert_ext_eq(f, e);
                let bits = host.sample_bits(23);
                let bit_vars = circuit.sample_bits(&mut builder, 23);
                for (k, bit) in bit_vars.into_iter().enumerate() {
                    builder.assert_felt_eq(bit, KoalaBear::from_u32(((bits >> k) & 1) as u32));
                }
            }
        }
        let digest = hash_felts_host(&values[..3]);
        let cap: p3_symmetric::MerkleCap<KoalaBear, Blake3Digest> =
            p3_symmetric::MerkleCap::new(vec![limbs_digest(&digest)]);
        host.observe(cap);
        let digest_var: DigestLimbs<KoalaBear> =
            core::array::from_fn(|i| builder.constant(digest[i]));
        CanObserveVariable::<InnerConfig, DigestLimbs<KoalaBear>>::observe(
            &mut circuit,
            &mut builder,
            digest_var,
        );
        let witness = host.grind(10);
        let witness_var = builder.constant(witness);
        circuit.check_witness(&mut builder, 10, witness_var);
        let x: KoalaBear = host.sample();
        let y = circuit.sample(&mut builder);
        builder.assert_felt_eq(y, x);
        execute(builder);
    }
}

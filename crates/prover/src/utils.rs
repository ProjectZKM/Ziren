use std::{
    borrow::Borrow,
    fs::{self, File},
    io::Read,
    iter::{Skip, Take},
};

use itertools::Itertools;
use p3_bn254_fr::Bn254Fr;
use p3_field::{FieldAlgebra, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_symmetric::CryptographicHasher;
use zkm_core_executor::{Executor, Program};
use zkm_core_machine::{io::ZKMStdin, reduce::ZKMReduceProof};
use zkm_recursion_circuit::machine::RootPublicValues;
use zkm_recursion_core::{
    air::{RecursionPublicValues, NUM_PV_ELMS_TO_HASH},
    stark::KoalaBearPoseidon2Outer,
};
use zkm_stark::{koala_bear_poseidon2::MyHash as InnerHash, Word, ZKMCoreOpts};

use crate::{InnerSC, ZKMCoreProofData};

/// Get the Ziren vkey KoalaBear Poseidon2 digest this reduce proof is representing.
pub fn zkm_vkey_digest_koalabear(
    proof: &ZKMReduceProof<KoalaBearPoseidon2Outer>,
) -> [KoalaBear; 8] {
    let proof = &proof.proof;
    let pv: &RecursionPublicValues<KoalaBear> = proof.public_values.as_slice().borrow();
    pv.zkm_vk_digest
}

/// Get the Ziren vkey Bn Poseidon2 digest this reduce proof is representing.
pub fn zkm_vkey_digest_bn254(proof: &ZKMReduceProof<KoalaBearPoseidon2Outer>) -> Bn254Fr {
    koalabears_to_bn254(&zkm_vkey_digest_koalabear(proof))
}

/// Compute the digest of the public values.
pub fn recursion_public_values_digest(
    config: &InnerSC,
    public_values: &RecursionPublicValues<KoalaBear>,
) -> [KoalaBear; 8] {
    let hash = InnerHash::new(config.perm.clone());
    let pv_array = public_values.as_array();
    hash.hash_slice(&pv_array[0..NUM_PV_ELMS_TO_HASH])
}

pub fn root_public_values_digest(
    config: &InnerSC,
    public_values: &RootPublicValues<KoalaBear>,
) -> [KoalaBear; 8] {
    let hash = InnerHash::new(config.perm.clone());
    let input = (*public_values.zkm_vk_digest())
        .into_iter()
        .chain(
            (*public_values.committed_value_digest())
                .into_iter()
                .flat_map(|word| word.0.into_iter()),
        )
        .collect::<Vec<_>>();
    hash.hash_slice(&input)
}

pub fn is_root_public_values_valid(
    config: &InnerSC,
    public_values: &RootPublicValues<KoalaBear>,
) -> bool {
    let expected_digest = root_public_values_digest(config, public_values);
    for (value, expected) in public_values.digest().iter().copied().zip_eq(expected_digest) {
        if value != expected {
            return false;
        }
    }
    true
}

/// Check if the digest of the public values is correct.
pub fn is_recursion_public_values_valid(
    config: &InnerSC,
    public_values: &RecursionPublicValues<KoalaBear>,
) -> bool {
    let expected_digest = recursion_public_values_digest(config, public_values);
    for (value, expected) in public_values.digest.iter().copied().zip_eq(expected_digest) {
        if value != expected {
            return false;
        }
    }
    true
}

/// Get the committed values Bn Poseidon2 digest this reduce proof is representing.
pub fn zkm_committed_values_digest_bn254(
    proof: &ZKMReduceProof<KoalaBearPoseidon2Outer>,
) -> Bn254Fr {
    let proof = &proof.proof;
    let pv: &RecursionPublicValues<KoalaBear> = proof.public_values.as_slice().borrow();
    let committed_values_digest_bytes: [KoalaBear; 32] =
        words_to_bytes(&pv.committed_value_digest).try_into().unwrap();
    koalabear_bytes_to_bn254(&committed_values_digest_bytes)
}

impl ZKMCoreProofData {
    pub fn save(&self, path: &str) -> Result<(), std::io::Error> {
        let data = serde_json::to_string(self).unwrap();
        fs::write(path, data).unwrap();
        Ok(())
    }
}

/// Get the number of cycles for a given program.
pub fn get_cycles(elf: &[u8], stdin: &ZKMStdin) -> u64 {
    let program = Program::from(elf).unwrap();
    let mut runtime = Executor::new(program, ZKMCoreOpts::default());
    runtime.write_vecs(&stdin.buffer);
    runtime.run_fast().unwrap();
    runtime.state.global_clk
}

/// Load an ELF file from a given path.
pub fn load_elf(path: &str) -> Result<Vec<u8>, std::io::Error> {
    let mut elf_code = Vec::new();
    File::open(path)?.read_to_end(&mut elf_code)?;
    Ok(elf_code)
}

pub fn words_to_bytes<T: Copy>(words: &[Word<T>]) -> Vec<T> {
    words.iter().flat_map(|word| word.0).collect()
}

/// Convert 8 KoalaBear words into a Bn254Fr field element by shifting by 31 bits each time. The last
/// word becomes the least significant bits.
pub fn koalabears_to_bn254(digest: &[KoalaBear; 8]) -> Bn254Fr {
    let mut result = Bn254Fr::ZERO;
    for word in digest.iter() {
        // Since KoalaBear prime is less than 2^31, we can shift by 31 bits each time and still be
        // within the Bn254Fr field, so we don't have to truncate the top 3 bits.
        result *= Bn254Fr::from_canonical_u64(1 << 31);
        result += Bn254Fr::from_canonical_u32(word.as_canonical_u32());
    }
    result
}

/// Convert 32 KoalaBear bytes into a Bn254Fr field element. The first byte's most significant 3 bits
/// (which would become the 3 most significant bits) are truncated.
pub fn koalabear_bytes_to_bn254(bytes: &[KoalaBear; 32]) -> Bn254Fr {
    let mut result = Bn254Fr::ZERO;
    for (i, byte) in bytes.iter().enumerate() {
        debug_assert!(byte < &KoalaBear::from_canonical_u32(256));
        if i == 0 {
            // 32 bytes is more than Bn254 prime, so we need to truncate the top 3 bits.
            result = Bn254Fr::from_canonical_u32(byte.as_canonical_u32() & 0x1f);
        } else {
            result *= Bn254Fr::from_canonical_u32(256);
            result += Bn254Fr::from_canonical_u32(byte.as_canonical_u32());
        }
    }
    result
}

/// Utility method for converting u32 words to bytes in big endian.
pub fn words_to_bytes_be(words: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        let word_bytes = words[i].to_be_bytes();
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word_bytes);
    }
    bytes
}

pub trait MaybeTakeIterator<I: Iterator>: Iterator<Item = I::Item> {
    fn maybe_skip(self, bound: Option<usize>) -> RangedIterator<Self>
    where
        Self: Sized,
    {
        match bound {
            Some(bound) => RangedIterator::Skip(self.skip(bound)),
            None => RangedIterator::Unbounded(self),
        }
    }

    fn maybe_take(self, bound: Option<usize>) -> RangedIterator<Self>
    where
        Self: Sized,
    {
        match bound {
            Some(bound) => RangedIterator::Take(self.take(bound)),
            None => RangedIterator::Unbounded(self),
        }
    }
}

impl<I: Iterator> MaybeTakeIterator<I> for I {}

pub enum RangedIterator<I> {
    Unbounded(I),
    Skip(Skip<I>),
    Take(Take<I>),
    Range(Take<Skip<I>>),
}

impl<I: Iterator> Iterator for RangedIterator<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            RangedIterator::Unbounded(unbounded) => unbounded.next(),
            RangedIterator::Skip(skip) => skip.next(),
            RangedIterator::Take(take) => take.next(),
            RangedIterator::Range(range) => range.next(),
        }
    }
}

//! The Blake3 ring: KoalaBear traces committed under Blake3 Merkle trees and
//! a Blake3 transcript, opened under jagged WHIR at a low rate.
//!
//! The shrink program is proved under this ring so that the proof the binary
//! stage verifies carries no Poseidon2: its Merkle paths and its transcript
//! are Blake3, which over bits is a few thousand columns per compression
//! against half a million per Poseidon2 permutation.  The field and the
//! extension are the inner ring's, so every generic jagged core runs over it
//! unchanged; only the commitment family and the challenger differ, as for
//! the wrap ring.
//!
//! A Blake3 root is thirty-two bytes.  The shard transcript observes a
//! commitment as eight field elements, so the root is read as eight
//! little-endian words with the top two bits of each dropped: a binding of
//! 240 bits, which the circuit that verifies this ring reproduces from the
//! limbs it hashes.

use alloc::vec;
use alloc::vec::Vec;

use p3_blake3::Blake3;
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32, PrimeField64};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher, Hash, MerkleCap};
use serde::{Deserialize, Serialize};

use crate::config::{BasefoldRing, PrepCommitRoot, StarkGenericConfig, ZeroCommitment};
use crate::jagged_pcs::jagged::{PrecomputedJaggedCommitGeneric, WhirDenseOpen};
use crate::jagged_pcs::{JaggedDft, JaggedVal};
use crate::Com;

/// Bytes of a Blake3 digest.
pub const BLAKE3_DIGEST_BYTES: usize = 32;

/// Field elements a Blake3 root is observed as.
pub const BLAKE3_DIGEST_FELTS: usize = 8;

pub type Val = KoalaBear;
pub type Challenge = BinomialExtensionField<Val, 4>;
pub type Blake3Digest = [u8; BLAKE3_DIGEST_BYTES];
pub type Blake3Hash = CanonicalBlake3;
pub type Blake3Compress = CompressionFunctionFromHasher<Blake3, 2, BLAKE3_DIGEST_BYTES>;
pub type Blake3Mmcs = MerkleTreeMmcs<Val, u8, Blake3Hash, Blake3Compress, 2, BLAKE3_DIGEST_BYTES>;
pub type Blake3ChallengeMmcs = ExtensionMmcs<Val, Challenge, Blake3Mmcs>;
pub type Blake3Dft = Radix2DitParallel<Val>;
pub type Blake3Pcs = TwoAdicFriPcs<Val, Blake3Dft, Blake3Mmcs, Blake3ChallengeMmcs>;

/// Blake3 over the canonical bytes of field elements, four little-endian
/// bytes each: the bytes the transcript observes and the circuit hashes.
/// The field's serializing hasher writes the Montgomery form instead,
/// which no circuit over the canonical value reproduces.
#[derive(Clone, Copy, Debug, Default)]
pub struct CanonicalBlake3;

impl CryptographicHasher<Val, Blake3Digest> for CanonicalBlake3 {
    fn hash_iter<I: IntoIterator<Item = Val>>(&self, input: I) -> Blake3Digest {
        Blake3.hash_iter(input.into_iter().flat_map(|v| v.as_canonical_u32().to_le_bytes()))
    }
}

/// The ring's Merkle commitment scheme.
#[must_use]
pub fn blake3_mmcs() -> Blake3Mmcs {
    Blake3Mmcs::new(CanonicalBlake3, CompressionFunctionFromHasher::new(Blake3), 0)
}

/// The ring's transcript, empty.
#[must_use]
pub fn blake3_challenger() -> Blake3Challenger {
    Blake3Challenger::new()
}

/// Words a squeeze yields.
const SQUEEZE_WORDS: usize = BLAKE3_DIGEST_BYTES / 4;

/// Whether every fold of the transcript is logged, for comparing a host
/// transcript with a circuit's (`ZIREN_TRACE_BLAKE3_TRANSCRIPT`).
pub fn transcript_trace_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("ZIREN_TRACE_BLAKE3_TRANSCRIPT").is_some())
}

/// Bytes the transcript buffers before folding them into its state, so
/// that every hash it computes covers at most one Blake3 chunk: the
/// thirty-two bytes of state and this much input.
pub const ABSORB_CAP_BYTES: usize = 1024 - BLAKE3_DIGEST_BYTES;

/// The ring's transcript: a byte sponge over Blake3 of a fixed shape, so
/// that the circuit verifying this ring replays it compression for
/// compression.
///
/// The state is a digest, zero at the start, and a buffer of observed
/// bytes.  Folding hashes the state followed by the buffer into the next
/// state and empties the buffer; it happens when the buffer reaches
/// [`ABSORB_CAP_BYTES`] and at every squeeze, whose digest is the new state.
/// Samples read the state's eight little-endian words in order, and an
/// observation after a sample discards the words still unread.  A field
/// element is observed as the four little-endian bytes of its canonical
/// value and sampled as two words reduced into the field,
/// `w0 + 2^32 w1 mod p`, a bias below `2^-33`; `bits` bits are the low bits
/// of one word.  The field's serializing challenger samples by rejection
/// instead, which has no fixed shape, and hashes unbounded input, which
/// needs Blake3's tree mode.
#[derive(Clone, Debug)]
pub struct Blake3Challenger {
    state: Blake3Digest,
    buffer: Vec<u8>,
    words_left: usize,
}

impl Default for Blake3Challenger {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake3Challenger {
    #[must_use]
    pub fn new() -> Self {
        Self { state: [0; BLAKE3_DIGEST_BYTES], buffer: Vec::new(), words_left: 0 }
    }

    fn absorb(&mut self, bytes: &[u8]) {
        self.words_left = 0;
        for byte in bytes {
            self.buffer.push(*byte);
            if self.buffer.len() == ABSORB_CAP_BYTES {
                self.fold();
            }
        }
    }

    fn fold(&mut self) {
        let digest: Blake3Digest =
            Blake3.hash_iter(self.state.iter().copied().chain(self.buffer.iter().copied()));
        if transcript_trace_enabled() {
            tracing::info!(
                "B3HOST fold buffered={} state={}",
                self.buffer.len(),
                digest.iter().map(|b| alloc::format!("{b:02x}")).collect::<alloc::string::String>()
            );
        }
        self.buffer.clear();
        self.state = digest;
    }

    fn squeeze(&mut self) {
        self.fold();
        self.words_left = SQUEEZE_WORDS;
    }

    /// The next word of the transcript, squeezing when none is left.
    pub fn next_word(&mut self) -> u32 {
        if self.words_left == 0 {
            self.squeeze();
        }
        let at = 4 * (SQUEEZE_WORDS - self.words_left);
        self.words_left -= 1;
        u32::from_le_bytes([
            self.state[at],
            self.state[at + 1],
            self.state[at + 2],
            self.state[at + 3],
        ])
    }

    /// The bytes waiting to be folded into the state.
    #[must_use]
    pub fn pending_input(&self) -> &[u8] {
        &self.buffer
    }

    /// The state digest.
    #[must_use]
    pub fn state(&self) -> &Blake3Digest {
        &self.state
    }
}

impl CanObserve<Val> for Blake3Challenger {
    fn observe(&mut self, value: Val) {
        self.absorb(&value.as_canonical_u32().to_le_bytes());
    }
}

impl CanObserve<Hash<Val, u8, BLAKE3_DIGEST_BYTES>> for Blake3Challenger {
    fn observe(&mut self, value: Hash<Val, u8, BLAKE3_DIGEST_BYTES>) {
        let bytes: Blake3Digest = value.into();
        self.absorb(&bytes);
    }
}

impl CanObserve<&MerkleCap<Val, Blake3Digest>> for Blake3Challenger {
    fn observe(&mut self, cap: &MerkleCap<Val, Blake3Digest>) {
        for root in cap.roots() {
            self.absorb(root);
        }
    }
}

impl CanObserve<MerkleCap<Val, Blake3Digest>> for Blake3Challenger {
    fn observe(&mut self, cap: MerkleCap<Val, Blake3Digest>) {
        self.observe(&cap);
    }
}

impl CanSample<Val> for Blake3Challenger {
    fn sample(&mut self) -> Val {
        let low = u64::from(self.next_word());
        let high = u64::from(self.next_word());
        Val::from_u64(low | (high << 32))
    }
}

impl CanSample<Challenge> for Blake3Challenger {
    fn sample(&mut self) -> Challenge {
        Challenge::from_basis_coefficients_fn(|_| CanSample::<Val>::sample(self))
    }
}

impl CanSampleBits<usize> for Blake3Challenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        assert!(bits <= 32, "a word carries at most 32 bits");
        let word = self.next_word() as usize;
        word & ((1usize << bits) - 1)
    }
}

impl GrindingChallenger for Blake3Challenger {
    type Witness = Val;

    fn grind(&mut self, bits: usize) -> Val {
        if bits == 0 {
            return Val::ZERO;
        }
        let witness = (0u64..Val::ORDER_U64)
            .map(Val::from_u64)
            .find(|&candidate| self.clone().check_witness(bits, candidate))
            .expect("a witness below the field order");
        assert!(self.check_witness(bits, witness));
        witness
    }

    fn check_witness(&mut self, bits: usize, witness: Val) -> bool {
        if bits == 0 {
            return true;
        }
        self.observe(witness);
        self.sample_bits(bits) == 0
    }
}

impl FieldChallenger<Val> for Blake3Challenger {}

/// Bits of each root word a field element carries.
pub const ROOT_WORD_BITS: u32 = 30;

/// A Blake3 root as the eight field elements a transcript observes: the
/// low thirty bits of each little-endian word of the digest.  Thirty bits
/// fit below the field order, so the map is injective on what it keeps,
/// and dropping sixteen bits of a Blake3 digest leaves a 240-bit binding.
#[must_use]
pub fn root_felts(root: &Blake3Digest) -> [Val; BLAKE3_DIGEST_FELTS] {
    core::array::from_fn(|i| {
        let word =
            u32::from_le_bytes([root[4 * i], root[4 * i + 1], root[4 * i + 2], root[4 * i + 3]]);
        Val::from_u32(word & ((1 << ROOT_WORD_BITS) - 1))
    })
}

/// The FRI parameters of the two-adic PCS the config carries; the ring
/// commits and opens under jagged WHIR, so these are never exercised.
fn blake3_fri_params() -> FriParameters<Blake3ChallengeMmcs> {
    FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 100,
        commit_proof_of_work_bits: 0,
        batch_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: Blake3ChallengeMmcs::new(blake3_mmcs()),
    }
}

/// The Blake3 ring.
#[derive(Deserialize)]
#[serde(from = "core::marker::PhantomData<KoalaBearBlake3>")]
pub struct KoalaBearBlake3 {
    pcs: Blake3Pcs,
    fri_config: FriParameters<Blake3ChallengeMmcs>,
}

impl KoalaBearBlake3 {
    #[must_use]
    pub fn new() -> Self {
        let fri_config = blake3_fri_params();
        let pcs = Blake3Pcs::new(Blake3Dft::default(), blake3_mmcs(), fri_config.clone());
        Self { pcs, fri_config }
    }

    /// The two-adic PCS's FRI parameters.
    #[must_use]
    pub fn get_fri_config(&self) -> &FriParameters<Blake3ChallengeMmcs> {
        &self.fri_config
    }
}

impl Default for KoalaBearBlake3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for KoalaBearBlake3 {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl Serialize for KoalaBearBlake3 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        core::marker::PhantomData::<KoalaBearBlake3>.serialize(serializer)
    }
}

impl From<core::marker::PhantomData<KoalaBearBlake3>> for KoalaBearBlake3 {
    fn from(_: core::marker::PhantomData<KoalaBearBlake3>) -> Self {
        Self::new()
    }
}

impl StarkGenericConfig for KoalaBearBlake3 {
    type Val = Val;
    type Domain = <Blake3Pcs as p3_commit::Pcs<Challenge, Blake3Challenger>>::Domain;
    type Pcs = Blake3Pcs;
    type Challenge = Challenge;
    type Challenger = Blake3Challenger;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn challenger(&self) -> Self::Challenger {
        blake3_challenger()
    }

    fn prep_commit(
        named_preprocessed_traces: &[(alloc::string::String, RowMajorMatrix<JaggedVal>)],
        pin: Option<crate::jagged::AreaPin>,
    ) -> Com<Self> {
        <Self::PrepPrecomputed as PrepCommitRoot<Self>>::commit_root(&Self::prep_precompute(
            named_preprocessed_traces,
            pin,
        ))
    }

    type PrepPrecomputed = PrecomputedJaggedCommitGeneric<Blake3Mmcs>;

    fn prep_precompute(
        named_preprocessed_traces: &[(alloc::string::String, RowMajorMatrix<JaggedVal>)],
        pin: Option<crate::jagged::AreaPin>,
    ) -> Self::PrepPrecomputed {
        let views =
            crate::jagged_pcs::jagged::views_over_traces(named_preprocessed_traces.to_vec());
        <Self as BasefoldRing>::commit_multilinears(&views, pin)
    }
}

/// The raw root, as the wrap ring's: the verifier binds the preprocessed
/// round's root to the key by equality, and derives the round's geometry from
/// the key's chip heights.
impl PrepCommitRoot<KoalaBearBlake3> for PrecomputedJaggedCommitGeneric<Blake3Mmcs> {
    fn commit_root(&self) -> Com<KoalaBearBlake3> {
        self.commit.original_commitment.clone()
    }
}

impl ZeroCommitment<KoalaBearBlake3> for Blake3Pcs {
    fn zero_commitment(&self) -> Com<KoalaBearBlake3> {
        MerkleCap::new(vec![[0u8; BLAKE3_DIGEST_BYTES]])
    }
}

impl BasefoldRing for KoalaBearBlake3 {
    const WHIR_INNER_PCS: bool = true;

    const WHIR_PROFILE: crate::whir::jagged::WhirProfile = crate::whir::jagged::WhirProfile::Blake3;

    fn prep_open_data(
        prep: &Self::PrepPrecomputed,
    ) -> &PrecomputedJaggedCommitGeneric<Self::BfMmcs> {
        prep
    }

    type BfMmcs = Blake3Mmcs;

    fn bf_mmcs() -> Self::BfMmcs {
        blake3_mmcs()
    }

    fn vk_commit_is_preceding_root(
        vk_commit: &Com<Self>,
        raw: &<Self::BfMmcs as p3_commit::Mmcs<JaggedVal>>::Commitment,
    ) -> Option<bool> {
        Some(vk_commit == raw)
    }

    fn digest_felts(
        commit: &<Self::BfMmcs as p3_commit::Mmcs<JaggedVal>>::Commitment,
    ) -> [JaggedVal; BLAKE3_DIGEST_FELTS] {
        let roots = commit.roots();
        assert!(!roots.is_empty(), "a Blake3 commitment carries a root");
        root_felts(&roots[0])
    }

    fn whir_committed_bf_prover_data(
        commit: &<Self::BfMmcs as p3_commit::Mmcs<JaggedVal>>::Commitment,
    ) -> Option<<Self::BfMmcs as p3_commit::Mmcs<JaggedVal>>::ProverData<RowMajorMatrix<JaggedVal>>>
    {
        let root = commit.roots()[0];
        Some(p3_merkle_tree::MerkleTree::from_parts(Vec::new(), vec![vec![root]], Vec::new()))
    }

    fn prove_jagged_open(
        z_row: &[crate::InnerChallenge],
        rounds: Vec<crate::jagged_pcs::jagged::JaggedOpenRound<'_, Self::BfMmcs>>,
        challenger: &mut Self::Challenger,
    ) -> crate::shard_level::shard_proof::EvaluationProof {
        let bundle = crate::jagged_pcs::jagged::prove_jagged_rounds_generic::<
            Self::Challenger,
            Self::BfMmcs,
            JaggedDft,
            WhirDenseOpen,
        >(
            &rounds,
            z_row,
            challenger,
            Self::bf_mmcs(),
            alloc::sync::Arc::new(JaggedDft::default()),
            Self::fri_config(),
            Self::WHIR_PROFILE,
        );
        crate::shard_level::shard_proof::EvaluationProof::Bytes(bundle.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use p3_challenger::{CanObserve, FieldChallenger};

    use super::*;
    use crate::jagged_pcs::jagged::{
        build_jagged_verify_inputs, verify_jagged_inner_generic_with_profile, JaggedOpenRound,
    };
    use crate::jagged_pcs::JaggedChallenge;

    fn matrix(width: usize, height: usize, seed: u64) -> RowMajorMatrix<JaggedVal> {
        let values = (0..width * height)
            .map(|i| {
                JaggedVal::from_u32(
                    (((i as u64).wrapping_mul(2_654_435_761).wrapping_add(seed)) % 1_000_003)
                        as u32,
                )
            })
            .collect();
        RowMajorMatrix::new(values, width)
    }

    fn views(
        traces: &[(alloc::string::String, RowMajorMatrix<JaggedVal>)],
    ) -> Vec<crate::jagged_pcs::jagged::ChipTraceView> {
        crate::jagged_pcs::jagged::views_over_traces(traces.to_vec())
    }

    /// A leaf hashes the canonical bytes of its elements, not the
    /// Montgomery form.
    #[test]
    fn leaves_hash_canonical_bytes() {
        let values = [Val::from_u32(3), Val::from_u32(0x7eff_ffff), Val::ONE];
        let digest: Blake3Digest = CanonicalBlake3.hash_iter(values);
        let bytes: Vec<u8> =
            values.iter().flat_map(|v| v.as_canonical_u32().to_le_bytes()).collect();
        assert_eq!(digest, Blake3.hash_iter(bytes));
    }

    /// The root's field elements are the low thirty bits of its words: a
    /// change to a kept byte moves them, and a change to a dropped bit does
    /// not.
    #[test]
    fn root_felts_read_the_words() {
        let mut root = [0u8; BLAKE3_DIGEST_BYTES];
        root[0] = 1;
        root[31] = 0xff;
        let felts = root_felts(&root);
        assert_eq!(felts[0], Val::ONE);
        assert_eq!(felts[7], Val::from_u32(0x3f00_0000));
        let mut other = root;
        other[5] ^= 1;
        assert_ne!(root_felts(&other), felts);
        let mut dropped = root;
        dropped[3] ^= 0x80;
        assert_eq!(root_felts(&dropped), felts);
    }

    /// The transcript is deterministic, an observation discards unread
    /// words, samples lie in the field, and a grind's witness is accepted
    /// while its neighbour is not.
    #[test]
    fn transcript_has_a_fixed_shape() {
        let mut a = blake3_challenger();
        let mut b = blake3_challenger();
        for word in [1u32, 2, 3] {
            a.observe(Val::from_u32(word));
            b.observe(Val::from_u32(word));
        }
        let x: Val = a.sample();
        let y: Val = b.sample();
        assert_eq!(x, y);
        assert_eq!(a.words_left, SQUEEZE_WORDS - 2);
        a.observe(Val::ONE);
        assert_eq!(a.words_left, 0, "an observation discards the unread words");
        let z: Val = a.sample();
        assert_ne!(z, y);
        let bits = a.sample_bits(14);
        assert!(bits < 1 << 14);
        let e: Challenge = a.sample();
        assert_ne!(e, Challenge::ZERO);
        let mut long = blake3_challenger();
        for i in 0..(ABSORB_CAP_BYTES / 4 + 5) as u32 {
            long.observe(Val::from_u32(i));
        }
        assert_eq!(long.pending_input().len(), 20, "the buffer folds at the cap");
        assert_ne!(*long.state(), [0u8; BLAKE3_DIGEST_BYTES]);
        let _: Val = long.sample();
        assert!(long.pending_input().is_empty());

        let mut prover = blake3_challenger();
        prover.observe(Val::from_u32(7));
        let witness = prover.grind(10);
        let mut verifier = blake3_challenger();
        verifier.observe(Val::from_u32(7));
        assert!(verifier.check_witness(10, witness));
        assert_eq!(
            CanSample::<Val>::sample(&mut prover),
            CanSample::<Val>::sample(&mut verifier),
            "prover and verifier agree after the grind"
        );
        let mut other = blake3_challenger();
        other.observe(Val::from_u32(7));
        assert!(!other.check_witness(10, witness + Val::ONE));
    }

    /// Two rounds (a preprocessed one and a main one) commit, open under the
    /// Blake3 schedule and verify over the ring's own transcript; a changed
    /// opened value is rejected.
    #[test]
    fn jagged_whir_round_trip_over_blake3() {
        let prep_traces =
            [("PrepA".to_string(), matrix(4, 16, 11)), ("PrepB".to_string(), matrix(2, 8, 13))];
        let main_traces = [("MainA".to_string(), matrix(3, 32, 17))];
        let prep_views = views(&prep_traces);
        let main_views = views(&main_traces);

        let prep = <KoalaBearBlake3 as BasefoldRing>::commit_multilinears(&prep_views, None);
        let main = <KoalaBearBlake3 as BasefoldRing>::commit_multilinears(&main_views, None);
        let prep_root = prep.commit.original_commitment.clone();
        let main_root = main.commit.original_commitment.clone();
        assert_ne!(prep_root, main_root);

        let mut point_challenger = blake3_challenger();
        let z_row: Vec<JaggedChallenge> = (0..crate::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT
            as usize)
            .map(|_| point_challenger.sample_algebra_element())
            .collect();
        let r_row = |traces: &[(alloc::string::String, RowMajorMatrix<JaggedVal>)]| {
            traces
                .iter()
                .map(|(_, t)| {
                    let height = t.values.len() / t.width.max(1);
                    let log_height = height.next_power_of_two().trailing_zeros() as usize;
                    z_row[z_row.len() - log_height..].to_vec()
                })
                .collect::<Vec<_>>()
        };
        let claims = |traces: &[(alloc::string::String, RowMajorMatrix<JaggedVal>)]| {
            let z_row_rev: Vec<JaggedChallenge> = z_row.iter().rev().copied().collect();
            let eq = crate::zerocheck_prover::eq_mle_table::<JaggedChallenge>(&z_row_rev);
            traces
                .iter()
                .map(|(_, t)| {
                    let width = t.width;
                    let height = t.values.len() / width;
                    (0..width)
                        .map(|col| {
                            (0..height).fold(JaggedChallenge::ZERO, |acc, row| {
                                acc + eq[row] * JaggedChallenge::from(t.values[row * width + col])
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        };
        let prep_r_row = r_row(&prep_traces);
        let main_r_row = r_row(&main_traces);

        let mut prover_challenger = blake3_challenger();
        prover_challenger.observe(prep_root.clone());
        prover_challenger.observe(main_root.clone());
        let rounds = vec![
            JaggedOpenRound {
                chip_traces: &prep_views,
                r_row_per_chip: &prep_r_row,
                claims: claims(&prep_traces),
                precomputed: &prep,
            },
            JaggedOpenRound {
                chip_traces: &main_views,
                r_row_per_chip: &main_r_row,
                claims: claims(&main_traces),
                precomputed: &main,
            },
        ];
        let proof = <KoalaBearBlake3 as BasefoldRing>::prove_jagged_open(
            &z_row,
            rounds,
            &mut prover_challenger,
        );
        let bytes = match proof {
            crate::shard_level::shard_proof::EvaluationProof::Bytes(bytes) => bytes,
            _ => panic!("the Blake3 ring opens to bytes"),
        };
        let bundle =
            crate::jagged_pcs::jagged::JaggedPcsProofGeneric::<Blake3Mmcs>::from_bytes(&bytes)
                .expect("the bundle decodes");
        assert!(bundle.whir_proof.is_some(), "the Blake3 ring opens under WHIR");

        let chip_widths: Vec<usize> =
            prep_traces.iter().chain(main_traces.iter()).map(|(_, t)| t.width).collect();
        let (chip_infos, r_row_v, z_row_v) =
            build_jagged_verify_inputs(&bundle.packing, &chip_widths, &z_row);
        let verify = |opened: &[Vec<JaggedChallenge>]| {
            let mut challenger = blake3_challenger();
            challenger.observe(prep_root.clone());
            challenger.observe(main_root.clone());
            verify_jagged_inner_generic_with_profile::<Blake3Challenger, Blake3Mmcs>(
                &chip_infos,
                &r_row_v,
                &z_row_v,
                &bundle,
                &mut challenger,
                blake3_mmcs(),
                true,
                <KoalaBearBlake3 as BasefoldRing>::fri_config(),
                &[(prep_root.clone(), prep.prover_data.area)],
                opened,
                crate::whir::jagged::WhirProfile::Blake3,
            )
        };
        let honest = bundle.y_per_chip.clone();
        assert!(verify(&honest), "the honest two-round Blake3 bundle verifies");
        let mut tampered = honest;
        tampered[0][0] += JaggedChallenge::ONE;
        assert!(!verify(&tampered), "a changed opened value is rejected");
    }
}

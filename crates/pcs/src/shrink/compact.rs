//! Shared KoalaBear compact shrink proof configuration.
//! Hash suites define commitments, transcript conventions and key identity.
//! Consumer adapters and export formats are independent of this module.
use super::suites::{HashSuite, SuiteHasher};
use crate::config::{BasefoldRing, PrepCommitRoot, StarkGenericConfig, ZeroCommitment};
use crate::jagged_pcs::jagged::{PrecomputedJaggedCommitGeneric, WhirDenseOpen};
use crate::jagged_pcs::{JaggedDft, JaggedVal};
use crate::Com;
use alloc::{vec, vec::Vec};
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
pub const DIGEST_BYTES: usize = 32;
pub const DIGEST_FELTS: usize = 8;
pub type Val = KoalaBear;
pub type Challenge = BinomialExtensionField<Val, 4>;
pub type Digest = [u8; DIGEST_BYTES];
pub type CompactCompress<S> = CompressionFunctionFromHasher<SuiteHasher<S>, 2, DIGEST_BYTES>;
pub type CompactMmcs<S> =
    MerkleTreeMmcs<Val, u8, CanonicalHash<S>, CompactCompress<S>, 2, DIGEST_BYTES>;
pub type CompactChallengeMmcs<S> = ExtensionMmcs<Val, Challenge, CompactMmcs<S>>;
pub type CompactDft = Radix2DitParallel<Val>;
pub type CompactPcs<S> = TwoAdicFriPcs<Val, CompactDft, CompactMmcs<S>, CompactChallengeMmcs<S>>;
const SQUEEZE_WORDS: usize = DIGEST_BYTES / 4;
/// Keccak over the canonical bytes of field elements, four little-endian
/// bytes each: the bytes the transcript observes and an EVM verifier hashes.
/// The field's serializing hasher writes the Montgomery form instead,
/// which no circuit over the canonical value reproduces.
#[derive(Clone, Copy, Debug, Default)]
pub struct CanonicalHash<S: HashSuite>(core::marker::PhantomData<S>);

impl<S: HashSuite> CryptographicHasher<Val, Digest> for CanonicalHash<S> {
    fn hash_iter<I: IntoIterator<Item = Val>>(&self, input: I) -> Digest {
        S::hash(
            &input.into_iter().flat_map(|v| v.as_canonical_u32().to_le_bytes()).collect::<Vec<_>>(),
        )
    }
}

/// The suite's Merkle commitment scheme.
#[must_use]
pub fn compact_mmcs<S: HashSuite>() -> CompactMmcs<S> {
    CompactMmcs::<S>::new(
        CanonicalHash::<S>::default(),
        CompressionFunctionFromHasher::new(SuiteHasher::<S>::default()),
        0,
    )
}

/// A suite-defined hash-chain transcript with canonical LE32 field observations.
/// Digest words are consumed little-endian, in order. Base-field challenges
/// use 31-bit rejection sampling for an exactly uniform KoalaBear element;
/// extension challenges sample four independent coefficients. Bit challenges
/// consume one full word, masking to the requested width. An observation
/// invalidates unread output. The protocol is specific to this terminal.
#[derive(Clone, Debug)]
pub struct CompactChallenger<S: HashSuite> {
    suite: core::marker::PhantomData<S>,
    state: Digest,
    buffer: Vec<u8>,
    words_left: usize,
}

impl<S: HashSuite> Default for CompactChallenger<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: HashSuite> CompactChallenger<S> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            suite: core::marker::PhantomData,
            state: S::hash(S::TRANSCRIPT_DOMAIN),
            buffer: Vec::new(),
            words_left: 0,
        }
    }

    fn absorb(&mut self, bytes: &[u8]) {
        self.words_left = 0;
        for byte in bytes {
            self.buffer.push(*byte);
            if self.buffer.len() == S::ABSORB_CAP_BYTES {
                self.fold();
            }
        }
    }

    fn fold(&mut self) {
        let digest: Digest = S::hash(
            &self.state.iter().copied().chain(self.buffer.iter().copied()).collect::<Vec<_>>(),
        );
        if std::env::var_os("ZIREN_TRACE_SHRINK_TRANSCRIPT").is_some() {
            tracing::info!(
                "KECCAKHOST fold buffered={} state={}",
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
    pub fn state(&self) -> &Digest {
        &self.state
    }
}

impl<S: HashSuite> CanObserve<Val> for CompactChallenger<S> {
    fn observe(&mut self, value: Val) {
        self.absorb(&value.as_canonical_u32().to_le_bytes());
    }
}

impl<S: HashSuite> CanObserve<Hash<Val, u8, DIGEST_BYTES>> for CompactChallenger<S> {
    fn observe(&mut self, value: Hash<Val, u8, DIGEST_BYTES>) {
        let bytes: Digest = value.into();
        self.absorb(&bytes);
    }
}

impl<S: HashSuite> CanObserve<&MerkleCap<Val, Digest>> for CompactChallenger<S> {
    fn observe(&mut self, cap: &MerkleCap<Val, Digest>) {
        for root in cap.roots() {
            self.absorb(root);
        }
    }
}

impl<S: HashSuite> CanObserve<MerkleCap<Val, Digest>> for CompactChallenger<S> {
    fn observe(&mut self, cap: MerkleCap<Val, Digest>) {
        self.observe(&cap);
    }
}

impl<S: HashSuite> CanSample<Val> for CompactChallenger<S> {
    fn sample(&mut self) -> Val {
        loop {
            let word = self.next_word() & 0x7fff_ffff;
            if u64::from(word) < Val::ORDER_U64 {
                return Val::from_u32(word);
            }
        }
    }
}

impl<S: HashSuite> CanSample<Challenge> for CompactChallenger<S> {
    fn sample(&mut self) -> Challenge {
        Challenge::from_basis_coefficients_fn(|_| CanSample::<Val>::sample(self))
    }
}

impl<S: HashSuite> CanSampleBits<usize> for CompactChallenger<S> {
    fn sample_bits(&mut self, bits: usize) -> usize {
        assert!(bits <= 32, "a word carries at most 32 bits");
        let word = u64::from(self.next_word());
        (word & ((1u64 << bits) - 1)) as usize
    }
}

impl<S: HashSuite> GrindingChallenger for CompactChallenger<S> {
    type Witness = Val;

    fn grind(&mut self, bits: usize) -> Val {
        if bits == 0 {
            return Val::ZERO;
        }
        use p3_maybe_rayon::prelude::*;
        let witness = (0u64..Val::ORDER_U64)
            .into_par_iter()
            .map(Val::from_u64)
            .find_any(|&candidate| self.clone().check_witness(bits, candidate))
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

impl<S: HashSuite> FieldChallenger<Val> for CompactChallenger<S> {}

/// Domain-separated compression of the full 256-bit root into the shard's
/// eight-felt seed. No raw-root bits are silently discarded. The seed has the
/// native eight-felt capacity; the Merkle proof still authenticates full roots.
#[must_use]
pub fn root_felts<S: HashSuite>(root: &Digest) -> [Val; DIGEST_FELTS] {
    let digest = S::hash(&S::ROOT_DOMAIN.iter().chain(root).copied().collect::<Vec<_>>());
    core::array::from_fn(|i| {
        Val::from_u64(u64::from(u32::from_le_bytes(digest[4 * i..4 * i + 4].try_into().unwrap())))
    })
}

/// The FRI parameters of the two-adic PCS the config carries; the ring
/// commits and opens under jagged WHIR, so these are never exercised.
fn compact_fri_params<S: HashSuite>() -> FriParameters<CompactChallengeMmcs<S>> {
    FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 100,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: CompactChallengeMmcs::<S>::new(compact_mmcs::<S>()),
    }
}

/// Compact shrink configuration over KoalaBear with a selected hash suite.
#[derive(Deserialize)]
#[serde(bound = "")]
#[serde(from = "core::marker::PhantomData<CompactShrink<S>>")]
pub struct CompactShrink<S: HashSuite> {
    pcs: CompactPcs<S>,
    fri_config: FriParameters<CompactChallengeMmcs<S>>,
}

impl<S: HashSuite> CompactShrink<S> {
    #[must_use]
    pub fn new() -> Self {
        let fri_config = compact_fri_params::<S>();
        let pcs =
            CompactPcs::<S>::new(CompactDft::default(), compact_mmcs::<S>(), fri_config.clone());
        Self { pcs, fri_config }
    }

    /// The unused two-adic PCS's FRI parameters.
    #[must_use]
    pub fn get_fri_config(&self) -> &FriParameters<CompactChallengeMmcs<S>> {
        &self.fri_config
    }
}

impl<S: HashSuite> Default for CompactShrink<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: HashSuite> Clone for CompactShrink<S> {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<S: HashSuite> Serialize for CompactShrink<S> {
    fn serialize<T>(&self, serializer: T) -> Result<T::Ok, T::Error>
    where
        T: serde::Serializer,
    {
        core::marker::PhantomData::<CompactShrink<S>>.serialize(serializer)
    }
}

impl<S: HashSuite> From<core::marker::PhantomData<CompactShrink<S>>> for CompactShrink<S> {
    fn from(_: core::marker::PhantomData<CompactShrink<S>>) -> Self {
        Self::new()
    }
}

impl<S: HashSuite> StarkGenericConfig for CompactShrink<S> {
    type Val = Val;
    type Domain = <CompactPcs<S> as p3_commit::Pcs<Challenge, CompactChallenger<S>>>::Domain;
    type Pcs = CompactPcs<S>;
    type Challenge = Challenge;
    type Challenger = CompactChallenger<S>;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn challenger(&self) -> Self::Challenger {
        CompactChallenger::<S>::new()
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

    type PrepPrecomputed = PrecomputedJaggedCommitGeneric<CompactMmcs<S>>;

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
impl<S: HashSuite> PrepCommitRoot<CompactShrink<S>>
    for PrecomputedJaggedCommitGeneric<CompactMmcs<S>>
{
    fn commit_root(&self) -> Com<CompactShrink<S>> {
        self.commit.original_commitment.clone()
    }
}

impl<S: HashSuite> ZeroCommitment<CompactShrink<S>> for CompactPcs<S> {
    fn zero_commitment(&self) -> Com<CompactShrink<S>> {
        MerkleCap::new(vec![[0u8; DIGEST_BYTES]])
    }
}

impl<S: HashSuite> BasefoldRing for CompactShrink<S> {
    const WHIR_INNER_PCS: bool = true;

    const WHIR_PROFILE: crate::whir::jagged::WhirProfile =
        crate::whir::jagged::WhirProfile::CompactShrink;

    fn prep_open_data(
        prep: &Self::PrepPrecomputed,
    ) -> &PrecomputedJaggedCommitGeneric<Self::BfMmcs> {
        prep
    }

    type BfMmcs = CompactMmcs<S>;

    fn bf_mmcs() -> Self::BfMmcs {
        compact_mmcs::<S>()
    }

    fn vk_commit_is_preceding_root(
        vk_commit: &Com<Self>,
        raw: &<Self::BfMmcs as p3_commit::Mmcs<JaggedVal>>::Commitment,
    ) -> Option<bool> {
        Some(vk_commit == raw)
    }

    fn digest_felts(
        commit: &<Self::BfMmcs as p3_commit::Mmcs<JaggedVal>>::Commitment,
    ) -> [JaggedVal; DIGEST_FELTS] {
        let roots = commit.roots();
        assert_eq!(roots.len(), 1, "the compact shrinker uses a single-root cap");
        root_felts::<S>(&roots[0])
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

/// Stable fingerprint of the compact shrink key and the resolved verifier parameters.
/// HashMap iteration order and Montgomery serialization never enter this codec.
/// Applications must obtain this ID from trusted setup, not from a proof.
#[must_use]
pub fn shrink_key_digest<S: HashSuite>(
    vk: &crate::StarkVerifyingKey<CompactShrink<S>>,
) -> [u8; 32] {
    fn integer(bytes: &mut Vec<u8>, value: usize) {
        bytes.extend(u64::try_from(value).expect("key integer fits u64").to_le_bytes());
    }
    fn name(bytes: &mut Vec<u8>, value: &str) {
        integer(bytes, value.len());
        bytes.extend(value.as_bytes());
    }
    // The descriptor codec binds every suite convention as well as the key.
    // Domain bytes of the proof transcript remain unchanged by API naming.
    let mut bytes = b"ziren-compact-shrink-key-v3".to_vec();
    name(&mut bytes, S::ID);
    integer(&mut bytes, S::ABSORB_CAP_BYTES);
    integer(&mut bytes, S::KEY_DOMAIN.len());
    bytes.extend(S::KEY_DOMAIN);
    integer(&mut bytes, S::ROOT_DOMAIN.len());
    bytes.extend(S::ROOT_DOMAIN);
    integer(&mut bytes, S::TRANSCRIPT_DOMAIN.len());
    bytes.extend(S::TRANSCRIPT_DOMAIN);
    for value in crate::profile::transcript_profile_digest() {
        bytes.extend(value.as_canonical_u32().to_le_bytes());
    }
    let profile = crate::profile::transcript_profile();
    integer(&mut bytes, profile.len());
    for (entry, value) in profile {
        name(&mut bytes, entry);
        bytes.extend(value.to_le_bytes());
    }
    integer(&mut bytes, crate::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize);
    integer(&mut bytes, crate::logup_gkr::gkr_grinding_bits());
    let config = crate::whir::jagged::whir_config_for_profile(
        <CompactShrink<S> as BasefoldRing>::WHIR_PROFILE,
        crate::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize,
    );
    // This structure consists only of integers/vectors of integers. Bincode's
    // fixed little-endian u64 length/usize codec is part of version 1.
    let config = bincode::serialize(&config).expect("WHIR parameters serialize");
    integer(&mut bytes, config.len());
    bytes.extend(config);
    integer(&mut bytes, vk.commit.roots().len());
    for root in vk.commit.roots() {
        bytes.extend(root);
    }
    bytes.extend(vk.pc_start.as_canonical_u32().to_le_bytes());
    for value in
        vk.initial_global_cumulative_sum.0.x.0.iter().chain(&vk.initial_global_cumulative_sum.0.y.0)
    {
        bytes.extend(value.as_canonical_u32().to_le_bytes());
    }
    integer(&mut bytes, vk.chip_information.len());
    for (chip, domain, (width, height)) in &vk.chip_information {
        name(&mut bytes, chip);
        bytes.extend(domain.shift.as_canonical_u32().to_le_bytes());
        integer(&mut bytes, domain.log_size);
        integer(&mut bytes, *width);
        integer(&mut bytes, *height);
    }
    let mut ordering: Vec<_> = vk.chip_ordering.iter().collect();
    ordering.sort_by(|a, b| a.0.cmp(b.0));
    integer(&mut bytes, ordering.len());
    for (chip, index) in ordering {
        name(&mut bytes, chip);
        integer(&mut bytes, *index);
    }
    S::hash(&bytes)
}

#[cfg(test)]
mod tests {
    use p3_challenger::{CanObserve, FieldChallenger};

    use super::*;
    use crate::shrink::suites::Keccak256Suite;
    use p3_keccak::Keccak256Hash;
    type KoalaBearKeccak = CompactShrink<Keccak256Suite>;
    type KeccakChallenger = CompactChallenger<Keccak256Suite>;
    type KeccakMmcs = CompactMmcs<Keccak256Suite>;
    const KECCAK_DIGEST_BYTES: usize = DIGEST_BYTES;
    const ABSORB_CAP_BYTES: usize = Keccak256Suite::ABSORB_CAP_BYTES;
    fn keccak_challenger() -> KeccakChallenger {
        KeccakChallenger::new()
    }
    fn keccak_mmcs() -> KeccakMmcs {
        compact_mmcs::<Keccak256Suite>()
    }
    fn terminal_key_digest(vk: &crate::StarkVerifyingKey<KoalaBearKeccak>) -> Digest {
        shrink_key_digest(vk)
    }
    fn root_felts(root: &Digest) -> [Val; 8] {
        super::root_felts::<Keccak256Suite>(root)
    }

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
        let digest: Digest = CanonicalHash::<Keccak256Suite>::default().hash_iter(values);
        let bytes: Vec<u8> =
            values.iter().flat_map(|v| v.as_canonical_u32().to_le_bytes()).collect();
        assert_eq!(digest, Keccak256Hash.hash_iter(bytes));
    }

    #[test]
    fn every_root_bit_affects_the_seed() {
        let root = [0u8; KECCAK_DIGEST_BYTES];
        let seed = root_felts(&root);
        for i in 0..256 {
            let mut changed = root;
            changed[i / 8] ^= 1 << (i % 8);
            assert_ne!(root_felts(&changed), seed);
        }
    }

    /// The transcript is deterministic, an observation discards unread
    /// words, samples lie in the field, and a grind advances both parties
    /// to the same transcript state.
    #[test]
    fn transcript_has_a_fixed_shape() {
        let mut a = keccak_challenger();
        let mut b = keccak_challenger();
        for word in [1u32, 2, 3] {
            a.observe(Val::from_u32(word));
            b.observe(Val::from_u32(word));
        }
        let x: Val = a.sample();
        let y: Val = b.sample();
        assert_eq!(x, y);
        assert!(a.words_left < SQUEEZE_WORDS);
        a.observe(Val::ONE);
        assert_eq!(a.words_left, 0, "an observation discards the unread words");
        let z: Val = a.sample();
        assert_ne!(z, y);
        let bits = a.sample_bits(14);
        assert!(bits < 1 << 14);
        let e: Challenge = a.sample();
        assert_ne!(e, Challenge::ZERO);
        let mut long = keccak_challenger();
        for i in 0..(ABSORB_CAP_BYTES / 4 + 5) as u32 {
            long.observe(Val::from_u32(i));
        }
        assert_eq!(long.pending_input().len(), 20, "the buffer folds at the cap");
        assert_ne!(*long.state(), [0u8; KECCAK_DIGEST_BYTES]);
        let _: Val = long.sample();
        assert!(long.pending_input().is_empty());

        let mut prover = keccak_challenger();
        prover.observe(Val::from_u32(7));
        let witness = prover.grind(10);
        let mut verifier = keccak_challenger();
        verifier.observe(Val::from_u32(7));
        assert!(verifier.check_witness(10, witness));
        assert_eq!(
            CanSample::<Val>::sample(&mut prover),
            CanSample::<Val>::sample(&mut verifier),
            "prover and verifier agree after the grind"
        );
    }

    /// Independent Keccak-256 vectors generated with Foundry's `cast keccak`.
    /// These fix the domain, byte order, padding, root projection and rejection
    /// sampling for a later Solidity implementation.
    #[test]
    fn evm_keccak_known_answers() {
        let digest = |bytes: [u8; 32]| {
            bytes.iter().map(|byte| alloc::format!("{byte:02x}")).collect::<alloc::string::String>()
        };
        let mut challenger = keccak_challenger();
        assert_eq!(
            digest(*challenger.state()),
            "aab045590d8f17d8b08601933d4a2e2c8bea0d11d115b9fd7d283c13135070ad"
        );
        for word in [1, 2, 3] {
            challenger.observe(Val::from_u32(word));
        }
        let sampled: Val = challenger.sample();
        assert_eq!(sampled.as_canonical_u32(), 350_653_189);
        assert_eq!(
            digest(*challenger.state()),
            "058be614afe273fd0a6e7c85b158e16245deb4f0777e4fb163ede641b35f9145"
        );
        // Force the exact rejection boundary: p is rejected, p-1 accepted.
        let mut rejection = keccak_challenger();
        let p = Val::ORDER_U64 as u32;
        rejection.state[..4].copy_from_slice(&p.to_le_bytes());
        rejection.state[4..8].copy_from_slice(&(p - 1).to_le_bytes());
        rejection.words_left = 8;
        let sampled: Val = rejection.sample();
        assert_eq!(sampled.as_canonical_u32(), p - 1);
        assert_eq!(rejection.words_left, 6);
        let mut long = keccak_challenger();
        for word in 0..30 {
            long.observe(Val::from_u32(word));
        }
        assert_eq!(
            digest(*long.state()),
            "00432bbc58274573115bbe3be1b2e703daa3591cae3bfdf3ad3459a885be9808"
        );
        let _: Val = long.sample();
        assert_eq!(
            digest(*long.state()),
            "99e3c77bf268e09f4881b038e1cb3d630aa5dc6b0460b7dc6dcbae4b9c0c727f"
        );
        assert_eq!(
            digest(CanonicalHash::<Keccak256Suite>::default().hash_iter([
                Val::from_u32(3),
                Val::from_u32(0x7eff_ffff),
                Val::ONE
            ])),
            "20d27074fd75c0d50d2ea6605b127dd68bb525bef6d46fcd376d480c99a3c052"
        );
        let projected = root_felts(&[0; 32]).map(|v| v.as_canonical_u32());
        let raw = [
            0x5e2da935u32,
            0xe2549893,
            0xbd95d6b5,
            0x7eccc3fe,
            0x086a7f34,
            0x87a9762f,
            0x211bcd60,
            0xc817f709,
        ];
        assert_eq!(projected, raw.map(|word| (u64::from(word) % Val::ORDER_U64) as u32));
    }

    #[test]
    fn terminal_key_id_is_canonical_and_binds_metadata() {
        let key = crate::StarkVerifyingKey::<KoalaBearKeccak> {
            commit: MerkleCap::new(vec![[7; 32]]),
            pc_start: Val::ONE,
            initial_global_cumulative_sum: Default::default(),
            chip_information: vec![
                ("A".into(), crate::machine::SerializableDomain::new(Val::ONE, 4), (16, 3)),
                ("B".into(), crate::machine::SerializableDomain::new(Val::ONE, 5), (32, 2)),
            ],
            chip_ordering: [("A".into(), 0), ("B".into(), 1)].into_iter().collect(),
        };
        let id = terminal_key_digest(&key);
        let decoded = bincode::deserialize(&bincode::serialize(&key).unwrap()).unwrap();
        assert_eq!(id, terminal_key_digest(&decoded));
        let mut reordered = key.clone();
        reordered.chip_ordering = [("B".into(), 1), ("A".into(), 0)].into_iter().collect();
        assert_eq!(id, terminal_key_digest(&reordered));
        let mut changed = key.clone();
        changed.commit = MerkleCap::new(vec![[6; 32]]);
        assert_ne!(id, terminal_key_digest(&changed));
        let mut changed = key.clone();
        changed.pc_start += Val::ONE;
        assert_ne!(id, terminal_key_digest(&changed));
        let mut changed = key.clone();
        changed.chip_information[0].2 .1 += 1;
        assert_ne!(id, terminal_key_digest(&changed));
        let mut changed = key.clone();
        changed.chip_ordering.insert("B".into(), 0);
        assert_ne!(id, terminal_key_digest(&changed));
        let mut changed = key;
        changed.initial_global_cumulative_sum.0.x.0[0] += Val::ONE;
        assert_ne!(id, terminal_key_digest(&changed));
    }

    /// Two rounds (a preprocessed one and a main one) commit, open under the
    /// Keccak schedule and verify over the ring's own transcript; a changed
    /// opened value is rejected.
    #[test]
    #[ignore = "production WHIR grinding; run explicitly in release mode"]
    fn jagged_whir_round_trip_over_keccak() {
        let prep_traces =
            [("PrepA".to_string(), matrix(4, 16, 11)), ("PrepB".to_string(), matrix(2, 8, 13))];
        let main_traces = [("MainA".to_string(), matrix(3, 32, 17))];
        let prep_views = views(&prep_traces);
        let main_views = views(&main_traces);

        let prep = <KoalaBearKeccak as BasefoldRing>::commit_multilinears(&prep_views, None);
        let main = <KoalaBearKeccak as BasefoldRing>::commit_multilinears(&main_views, None);
        let prep_root = prep.commit.original_commitment.clone();
        let main_root = main.commit.original_commitment.clone();
        assert_ne!(prep_root, main_root);

        let mut point_challenger = keccak_challenger();
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

        let mut prover_challenger = keccak_challenger();
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
        let proof = <KoalaBearKeccak as BasefoldRing>::prove_jagged_open(
            &z_row,
            rounds,
            &mut prover_challenger,
        );
        let bytes = match proof {
            crate::shard_level::shard_proof::EvaluationProof::Bytes(bytes) => bytes,
            _ => panic!("the Keccak ring opens to bytes"),
        };
        let bundle =
            crate::jagged_pcs::jagged::JaggedPcsProofGeneric::<KeccakMmcs>::from_bytes(&bytes)
                .expect("the bundle decodes");
        assert!(bundle.whir_proof.is_some(), "the Keccak ring opens under WHIR");

        let chip_widths: Vec<usize> =
            prep_traces.iter().chain(main_traces.iter()).map(|(_, t)| t.width).collect();
        let (chip_infos, r_row_v, z_row_v) =
            build_jagged_verify_inputs(&bundle.packing, &chip_widths, &z_row);
        let verify = |opened: &[Vec<JaggedChallenge>]| {
            let mut challenger = keccak_challenger();
            challenger.observe(prep_root.clone());
            challenger.observe(main_root.clone());
            verify_jagged_inner_generic_with_profile::<KeccakChallenger, KeccakMmcs>(
                &chip_infos,
                &r_row_v,
                &z_row_v,
                &bundle,
                &mut challenger,
                keccak_mmcs(),
                true,
                <KoalaBearKeccak as BasefoldRing>::fri_config(),
                &[(prep_root.clone(), prep.prover_data.area)],
                opened,
                Some(crate::whir::jagged::WhirProfile::CompactShrink),
            )
        };
        let honest = bundle.y_per_chip.clone();
        assert!(verify(&honest), "the honest two-round Keccak bundle verifies");
        let mut tampered = honest;
        tampered[0][0] += JaggedChallenge::ONE;
        assert!(!verify(&tampered), "a changed opened value is rejected");
    }
}

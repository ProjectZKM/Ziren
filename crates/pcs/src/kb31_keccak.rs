//! A final KoalaBear/Keccak-256 ring for the existing shrink computation.
//! Merkle leaves use canonical little-endian field words, the transcript is
//! domain separated, and WHIR uses a terminal-specific immutable schedule.
//! Keccak runs on the host; no Keccak AIR or binary-field stage is introduced.
//! This ring is terminal: existing recursive circuits do not verify it.

use alloc::vec;
use alloc::vec::Vec;

use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32, PrimeField64};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher, Hash, MerkleCap};
use serde::{Deserialize, Serialize};

use crate::config::{BasefoldRing, PrepCommitRoot, StarkGenericConfig, ZeroCommitment};
use crate::jagged_pcs::jagged::{PrecomputedJaggedCommitGeneric, WhirDenseOpen};
use crate::jagged_pcs::{JaggedDft, JaggedVal};
use crate::Com;

/// Bytes of a Keccak digest.
pub const KECCAK_DIGEST_BYTES: usize = 32;

/// Field elements a Keccak root is observed as.
pub const KECCAK_DIGEST_FELTS: usize = 8;

pub type Val = KoalaBear;
pub type Challenge = BinomialExtensionField<Val, 4>;
pub type KeccakDigest = [u8; KECCAK_DIGEST_BYTES];
pub type KeccakHash = CanonicalKeccak;
pub type KeccakCompress = CompressionFunctionFromHasher<Keccak256Hash, 2, KECCAK_DIGEST_BYTES>;
pub type KeccakMmcs = MerkleTreeMmcs<Val, u8, KeccakHash, KeccakCompress, 2, KECCAK_DIGEST_BYTES>;
pub type KeccakChallengeMmcs = ExtensionMmcs<Val, Challenge, KeccakMmcs>;
pub type KeccakDft = Radix2DitParallel<Val>;
pub type KeccakPcs = TwoAdicFriPcs<Val, KeccakDft, KeccakMmcs, KeccakChallengeMmcs>;

/// Keccak over the canonical bytes of field elements, four little-endian
/// bytes each: the bytes the transcript observes and an EVM verifier hashes.
/// The field's serializing hasher writes the Montgomery form instead,
/// which no circuit over the canonical value reproduces.
#[derive(Clone, Copy, Debug, Default)]
pub struct CanonicalKeccak;

impl CryptographicHasher<Val, KeccakDigest> for CanonicalKeccak {
    fn hash_iter<I: IntoIterator<Item = Val>>(&self, input: I) -> KeccakDigest {
        Keccak256Hash.hash_iter(input.into_iter().flat_map(|v| v.as_canonical_u32().to_le_bytes()))
    }
}

/// The ring's Merkle commitment scheme.
#[must_use]
pub fn keccak_mmcs() -> KeccakMmcs {
    KeccakMmcs::new(CanonicalKeccak, CompressionFunctionFromHasher::new(Keccak256Hash), 0)
}

/// The ring's transcript, empty.
#[must_use]
pub fn keccak_challenger() -> KeccakChallenger {
    KeccakChallenger::new()
}

/// Words a squeeze yields.
const SQUEEZE_WORDS: usize = KECCAK_DIGEST_BYTES / 4;

/// Whether every fold of the transcript is logged for verifier parity checks
/// (`ZIREN_TRACE_KECCAK_TRANSCRIPT`).
pub fn transcript_trace_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("ZIREN_TRACE_KECCAK_TRANSCRIPT").is_some())
}

/// Maximum buffered payload: a 32-byte state plus 100 bytes and Keccak
/// padding fit in one 136-byte rate block.
pub const ABSORB_CAP_BYTES: usize = 100;

/// Versioned Fiat–Shamir domain for this terminal.
pub const TRANSCRIPT_DOMAIN: &[u8] = b"ziren-koalabear-keccak-terminal-v1";

/// A Keccak hash-chain transcript with canonical LE32 field observations.
/// Digest words are consumed little-endian, in order. Base-field challenges
/// use 31-bit rejection sampling for an exactly uniform KoalaBear element;
/// extension challenges sample four independent coefficients. Bit challenges
/// consume one full word, masking to the requested width. An observation
/// invalidates unread output. The protocol is specific to this terminal.
#[derive(Clone, Debug)]
pub struct KeccakChallenger {
    state: KeccakDigest,
    buffer: Vec<u8>,
    words_left: usize,
}

impl Default for KeccakChallenger {
    fn default() -> Self {
        Self::new()
    }
}

impl KeccakChallenger {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Keccak256Hash.hash_iter(TRANSCRIPT_DOMAIN.iter().copied()),
            buffer: Vec::new(),
            words_left: 0,
        }
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
        let digest: KeccakDigest =
            Keccak256Hash.hash_iter(self.state.iter().copied().chain(self.buffer.iter().copied()));
        if transcript_trace_enabled() {
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
    pub fn state(&self) -> &KeccakDigest {
        &self.state
    }
}

impl CanObserve<Val> for KeccakChallenger {
    fn observe(&mut self, value: Val) {
        self.absorb(&value.as_canonical_u32().to_le_bytes());
    }
}

impl CanObserve<Hash<Val, u8, KECCAK_DIGEST_BYTES>> for KeccakChallenger {
    fn observe(&mut self, value: Hash<Val, u8, KECCAK_DIGEST_BYTES>) {
        let bytes: KeccakDigest = value.into();
        self.absorb(&bytes);
    }
}

impl CanObserve<&MerkleCap<Val, KeccakDigest>> for KeccakChallenger {
    fn observe(&mut self, cap: &MerkleCap<Val, KeccakDigest>) {
        for root in cap.roots() {
            self.absorb(root);
        }
    }
}

impl CanObserve<MerkleCap<Val, KeccakDigest>> for KeccakChallenger {
    fn observe(&mut self, cap: MerkleCap<Val, KeccakDigest>) {
        self.observe(&cap);
    }
}

impl CanSample<Val> for KeccakChallenger {
    fn sample(&mut self) -> Val {
        loop {
            let word = self.next_word() & 0x7fff_ffff;
            if u64::from(word) < Val::ORDER_U64 {
                return Val::from_u32(word);
            }
        }
    }
}

impl CanSample<Challenge> for KeccakChallenger {
    fn sample(&mut self) -> Challenge {
        Challenge::from_basis_coefficients_fn(|_| CanSample::<Val>::sample(self))
    }
}

impl CanSampleBits<usize> for KeccakChallenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        assert!(bits <= 32, "a word carries at most 32 bits");
        let word = u64::from(self.next_word());
        (word & ((1u64 << bits) - 1)) as usize
    }
}

impl GrindingChallenger for KeccakChallenger {
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

impl FieldChallenger<Val> for KeccakChallenger {}

/// Domain-separated compression of the full 256-bit root into the shard's
/// eight-felt seed. No raw-root bits are silently discarded. The seed has the
/// native eight-felt capacity; the Merkle proof still authenticates full roots.
#[must_use]
pub fn root_felts(root: &KeccakDigest) -> [Val; KECCAK_DIGEST_FELTS] {
    let digest = Keccak256Hash.hash_iter(b"ziren-keccak-root-felts-v1".iter().chain(root).copied());
    core::array::from_fn(|i| {
        Val::from_u64(u64::from(u32::from_le_bytes(digest[4 * i..4 * i + 4].try_into().unwrap())))
    })
}

/// The FRI parameters of the two-adic PCS the config carries; the ring
/// commits and opens under jagged WHIR, so these are never exercised.
fn keccak_fri_params() -> FriParameters<KeccakChallengeMmcs> {
    FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 100,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: KeccakChallengeMmcs::new(keccak_mmcs()),
    }
}

/// The Keccak ring.
#[derive(Deserialize)]
#[serde(from = "core::marker::PhantomData<KoalaBearKeccak>")]
pub struct KoalaBearKeccak {
    pcs: KeccakPcs,
    fri_config: FriParameters<KeccakChallengeMmcs>,
}

impl KoalaBearKeccak {
    #[must_use]
    pub fn new() -> Self {
        let fri_config = keccak_fri_params();
        let pcs = KeccakPcs::new(KeccakDft::default(), keccak_mmcs(), fri_config.clone());
        Self { pcs, fri_config }
    }

    /// The unused two-adic PCS's FRI parameters.
    #[must_use]
    pub fn get_fri_config(&self) -> &FriParameters<KeccakChallengeMmcs> {
        &self.fri_config
    }
}

impl Default for KoalaBearKeccak {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for KoalaBearKeccak {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl Serialize for KoalaBearKeccak {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        core::marker::PhantomData::<KoalaBearKeccak>.serialize(serializer)
    }
}

impl From<core::marker::PhantomData<KoalaBearKeccak>> for KoalaBearKeccak {
    fn from(_: core::marker::PhantomData<KoalaBearKeccak>) -> Self {
        Self::new()
    }
}

impl StarkGenericConfig for KoalaBearKeccak {
    type Val = Val;
    type Domain = <KeccakPcs as p3_commit::Pcs<Challenge, KeccakChallenger>>::Domain;
    type Pcs = KeccakPcs;
    type Challenge = Challenge;
    type Challenger = KeccakChallenger;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn challenger(&self) -> Self::Challenger {
        keccak_challenger()
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

    type PrepPrecomputed = PrecomputedJaggedCommitGeneric<KeccakMmcs>;

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
impl PrepCommitRoot<KoalaBearKeccak> for PrecomputedJaggedCommitGeneric<KeccakMmcs> {
    fn commit_root(&self) -> Com<KoalaBearKeccak> {
        self.commit.original_commitment.clone()
    }
}

impl ZeroCommitment<KoalaBearKeccak> for KeccakPcs {
    fn zero_commitment(&self) -> Com<KoalaBearKeccak> {
        MerkleCap::new(vec![[0u8; KECCAK_DIGEST_BYTES]])
    }
}

impl BasefoldRing for KoalaBearKeccak {
    const WHIR_INNER_PCS: bool = true;

    const WHIR_PROFILE: crate::whir::jagged::WhirProfile = crate::whir::jagged::WhirProfile::Keccak;

    fn prep_open_data(
        prep: &Self::PrepPrecomputed,
    ) -> &PrecomputedJaggedCommitGeneric<Self::BfMmcs> {
        prep
    }

    type BfMmcs = KeccakMmcs;

    fn bf_mmcs() -> Self::BfMmcs {
        keccak_mmcs()
    }

    fn vk_commit_is_preceding_root(
        vk_commit: &Com<Self>,
        raw: &<Self::BfMmcs as p3_commit::Mmcs<JaggedVal>>::Commitment,
    ) -> Option<bool> {
        Some(vk_commit == raw)
    }

    fn digest_felts(
        commit: &<Self::BfMmcs as p3_commit::Mmcs<JaggedVal>>::Commitment,
    ) -> [JaggedVal; KECCAK_DIGEST_FELTS] {
        let roots = commit.roots();
        assert_eq!(roots.len(), 1, "the terminal uses a single-root cap");
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

/// Stable fingerprint of the terminal key and the resolved verifier parameters.
/// HashMap iteration order and Montgomery serialization never enter this codec.
/// Applications must obtain this ID from trusted setup, not from a proof.
#[must_use]
pub fn terminal_key_digest(vk: &crate::StarkVerifyingKey<KoalaBearKeccak>) -> [u8; 32] {
    fn integer(bytes: &mut Vec<u8>, value: usize) {
        bytes.extend(u64::try_from(value).expect("key integer fits u64").to_le_bytes());
    }
    fn name(bytes: &mut Vec<u8>, value: &str) {
        integer(bytes, value.len());
        bytes.extend(value.as_bytes());
    }
    // Version two distinguishes the current-main port from the historical
    // staging fixture and binds the complete child transcript profile too.
    let mut bytes = b"ziren-keccak-terminal-key-v2".to_vec();
    integer(&mut bytes, TRANSCRIPT_DOMAIN.len());
    bytes.extend(TRANSCRIPT_DOMAIN);
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
        <KoalaBearKeccak as BasefoldRing>::WHIR_PROFILE,
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
    Keccak256Hash.hash_iter(bytes)
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
        let digest: KeccakDigest = CanonicalKeccak.hash_iter(values);
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
            digest(CanonicalKeccak.hash_iter([
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
                Some(crate::whir::jagged::WhirProfile::Keccak),
            )
        };
        let honest = bundle.y_per_chip.clone();
        assert!(verify(&honest), "the honest two-round Keccak bundle verifies");
        let mut tampered = honest;
        tampered[0][0] += JaggedChallenge::ONE;
        assert!(!verify(&tampered), "a changed opened value is rejected");
    }
}

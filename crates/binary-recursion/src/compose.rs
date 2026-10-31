//! A compose node over bits: the program that verifies two or more binary
//! proofs of consecutive parts of an execution and commits to their union.
//!
//! It is the field machine's compose program, recorded over `GF(2^128)`.
//! Each child's public values are inputs of the program, bound to the
//! digest its proof commits to by recomputing that digest: the Blake3 hash
//! of their canonical little-endian bytes, the low 30 bits of each word, as
//! the ring's `hash_public_felts` computes it.  The checks between children
//! are the field machine's, element for element: equalities are equalities
//! of the elements' encodings, and the arithmetic on elements runs on the
//! tape's KoalaBear operations, the global cumulative sums being points of
//! a curve over the septic extension.  The node's own digest is the
//! program's public values, its first eight inputs.
//!
//! A child's verifying key is no constant of the program: its preprocessed
//! commitment is read as inputs, hashed with the shapes the program fixes
//! into the child's key digest, and that digest is shown a leaf of the key
//! tree whose root the children's public values carry, as the field
//! machine shows its children's keys.  One program then verifies any
//! child the tree allows, and the tree can hold the program's own key.

use core::borrow::{Borrow, BorrowMut};

use p3_binary_field::TowerLevel;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use zkm_pcs::septic_curve::SepticCurve;
use zkm_pcs::septic_digest::SepticDigest;
use zkm_pcs::septic_extension::SepticExtension;
use zkm_recursion_core::air::{
    RecursionPublicValues, NUM_PV_ELMS_TO_HASH, RECURSIVE_PROOF_NUM_PV_ELTS,
};
use zkm_recursion_core::DIGEST_SIZE;

use p3_multi_stark::{verify, VerifierInstance, VerifierInstances};
use zkm_binary_stark::config::MachineProof;
use zkm_binary_stark::machine::RecursionMachine;
use zkm_binary_stark::{BinarySchedule, TRANSCRIPT_DOMAIN};

use p3_word::Word64;
use p3_word_backend::{Deferred, WiringQuery, WordProofKey};

use crate::bytes::{blake3, byte_bits, digest_bytes, merkle_node, to_bytes, Piece};
use crate::tape::digest_elements;
use crate::word::{verify_word_routed, DeferredClaim};
use crate::challenger::TracedChallenger;
use crate::config::{reread, TracedConfig, TracedProof};
use crate::machine::{TapeAir, TapeMachine};
use crate::mmcs::{TracedCap, TracedDigest};
use crate::tape::{as_kb, kb_value, record, KbOp, Tape};
use crate::Traced;

/// The recorded verification of a child's proof against the digest its
/// public values hash to, which the proof commits to as its public values,
/// returning the child's key digest and the claims it deferred.
pub type ChildVerifier<'a> =
    Box<dyn Fn(&[Traced; DIGEST_SIZE]) -> Result<Verified, String> + Send + Sync + 'a>;

/// A child's key digest alone, for a child whose verification defers no
/// claims: what the recording that only learns a node's digest reads in
/// place of the verification.
pub type ChildKey<'a> = Box<dyn Fn() -> [Traced; 2] + Send + Sync + 'a>;

/// What a child's recorded verification leaves: its key digest, and, for a
/// word proof, the claims its verification deferred to the root.
pub struct Verified {
    pub key: [Traced; 2],
    pub claims: Option<Vec<DeferredClaim>>,
}

/// A child of a compose node.
pub struct Child<'a> {
    /// Its public values, as canonical elements.
    pub public_values: Vec<u32>,
    /// The verification of its proof.
    pub verify: ChildVerifier<'a>,
    /// Its key digest without the verification, when that defers no claims.
    pub key: Option<ChildKey<'a>>,
    /// Where its key digest sits in the key tree.
    pub membership: VkMembership,
}

/// A key digest's place in the key tree: its index and the siblings from
/// the leaf up, as the field machine's `MerkleTree::open` gives them.
#[derive(Clone, Debug)]
pub struct VkMembership {
    pub index: usize,
    pub path: Vec<[u8; 32]>,
}

/// What kind of machine a key belongs to, which its digest names.
#[derive(Clone, Copy, Debug)]
pub enum KeyKind {
    /// The binary machine of a normalize program.
    Leaf = 1,
    /// The tape machine of a compose node.
    Node = 2,
}

/// The key digest of a binary machine of `kind` with these shapes and
/// preprocessed commitment roots: the Blake3 hash of a tag, the kind, the
/// shapes and the roots.  Outside a recording the digest is a constant.
fn key_digest(
    kind: KeyKind,
    main: &[p3_sumcheck::TableShape],
    preprocessed: &[p3_sumcheck::TableShape],
    roots: &[[Traced; 2]],
) -> [Traced; 2] {
    let mut header: Vec<u8> = b"ziren binary key".to_vec();
    header.push(kind as u8);
    for shapes in [main, preprocessed] {
        header.extend((shapes.len() as u32).to_le_bytes());
        for shape in shapes {
            header.extend((shape.num_variables() as u32).to_le_bytes());
            header.extend((shape.width() as u32).to_le_bytes());
        }
    }
    let pieces: Vec<Piece> = header
        .into_iter()
        .map(|byte| Piece::Byte(Traced::constant(kb_value(u32::from(byte)))))
        .chain(roots.iter().flat_map(|root| root.map(Piece::Element)))
        .collect();
    blake3(&pieces)
}

/// The key digest of `vk` for a machine of `kind` with these shapes, as
/// the key tree holds it.
///
/// # Panics
/// Panics if called during a recording.
#[must_use]
pub fn binary_key_digest(
    kind: KeyKind,
    main: &[p3_sumcheck::TableShape],
    preprocessed: &[p3_sumcheck::TableShape],
    vk: &p3_multi_stark::VerifyingKey<zkm_binary_stark::config::MachineConfig>,
) -> [u8; 32] {
    assert!(!crate::tape::recording(), "the digest is taken outside a recording");
    let mut roots = Vec::new();
    let _ = vk.lift::<TracedConfig>(|commitment| {
        let cap: TracedCap = reread(commitment);
        roots = cap.roots();
        cap
    });
    let digest = key_digest(kind, main, preprocessed, &roots);
    let [lo, hi] = digest.map(|half| half.value().to_repr().to_le_bytes());
    core::array::from_fn(|i| if i < 16 { lo[i] } else { hi[i - 16] })
}

/// `vk` lifted inside a recording, its commitment read as inputs, with the
/// commitment's roots.
fn lift_as_inputs(
    vk: &p3_multi_stark::VerifyingKey<zkm_binary_stark::config::MachineConfig>,
) -> (p3_multi_stark::VerifyingKey<TracedConfig>, Vec<[Traced; 2]>) {
    let mut roots = Vec::new();
    let lifted = vk.lift::<TracedConfig>(|commitment| {
        let cap: TracedCap = reread(commitment);
        roots = cap.roots();
        cap
    });
    (lifted, roots)
}

/// Show `digest` a leaf of the key tree whose root `vk_root` carries: the
/// path from it, under the bit order of the field machine's
/// `MerkleTree::verify`, reaches a root whose words are `vk_root`.
fn check_membership(
    digest: [Traced; 2],
    membership: &VkMembership,
    vk_root: &[Traced; DIGEST_SIZE],
) {
    let height = membership.path.len();
    let index = (0..height)
        .fold(0usize, |reversed, k| reversed | (((membership.index >> k) & 1) << (height - 1 - k)));
    let mut current = digest;
    for (k, sibling) in membership.path.iter().enumerate() {
        let bit = Traced::input(if (index >> k) & 1 == 1 {
            crate::tape::F::ONE
        } else {
            crate::tape::F::ZERO
        });
        current = merkle_node(bit, current, TracedDigest::read(*sibling).0);
    }
    let root = digest_bytes(current);
    for (w, &word) in vk_root.iter().enumerate() {
        assert_digest_word(word, &root, w);
    }
}

impl<'a> Child<'a> {
    /// A leaf: a binary proof of a normalize program, whose public values
    /// are its digest.
    ///
    /// # Panics
    /// Panics if called during a recording, or if the traced configuration
    /// cannot be built for the machine's shapes.
    #[must_use]
    pub fn leaf(
        machine: &'a RecursionMachine,
        proof: &'a MachineProof,
        public_values: Vec<u32>,
        membership: VkMembership,
        schedule: &BinarySchedule,
    ) -> Self {
        let (main, preprocessed) = machine.shapes();
        let config = TracedConfig::new(&main, &preprocessed, schedule).expect("traced config");
        let (key_main, key_preprocessed) = (main.clone(), preprocessed.clone());
        Self {
            public_values,
            membership,
            key: Some(Box::new(move || {
                let (_, roots) = lift_as_inputs(machine.verifying_key());
                key_digest(KeyKind::Leaf, &key_main, &key_preprocessed, &roots)
            })),
            verify: Box::new(move |public: &[Traced; DIGEST_SIZE]| {
                let (vk, roots) = lift_as_inputs(machine.verifying_key());
                let digest = key_digest(KeyKind::Leaf, &main, &preprocessed, &roots);
                let proof: TracedProof = reread(proof);
                let instances = machine.verifier_instances(&vk, public);
                let mut challenger = TracedChallenger::new(TRANSCRIPT_DOMAIN);
                let verdict = verify(&config, instances, &proof, 0, &mut challenger)
                    .map_err(|e| format!("{e:?}"));
                crate::queries::take();
                verdict.map(|()| Verified { key: digest, claims: None })
            }),
        }
    }

    /// A compose node: a proof of the tape machine, whose public values
    /// are its digest.
    ///
    /// # Panics
    /// Panics if called during a recording, or if the traced configuration
    /// cannot be built for the machine's shapes.
    #[must_use]
    pub fn node(
        machine: &'a TapeMachine,
        proof: &'a MachineProof,
        public_values: Vec<u32>,
        membership: VkMembership,
        schedule: &BinarySchedule,
    ) -> Self {
        let (main, preprocessed) = machine.shapes();
        let config = TracedConfig::new(&main, &preprocessed, schedule).expect("traced config");
        let (key_main, key_preprocessed) = (main.clone(), preprocessed.clone());
        Self {
            public_values,
            membership,
            key: Some(Box::new(move || {
                let (_, roots) = lift_as_inputs(machine.verifying_key());
                key_digest(KeyKind::Node, &key_main, &key_preprocessed, &roots)
            })),
            verify: Box::new(move |public: &[Traced; DIGEST_SIZE]| {
                let (vk, roots) = lift_as_inputs(machine.verifying_key());
                let digest = key_digest(KeyKind::Node, &main, &preprocessed, &roots);
                let proof: TracedProof = reread(proof);
                let instances = VerifierInstances::new(
                    machine
                        .airs()
                        .iter()
                        .map(|air| {
                            let public_values: &[Traced] = match air {
                                TapeAir::Public(_) => public,
                                _ => &[],
                            };
                            VerifierInstance::new(air, &vk, air.log_height(), public_values)
                        })
                        .collect(),
                );
                let mut challenger = TracedChallenger::new(TRANSCRIPT_DOMAIN);
                let verdict = verify(&config, instances, &proof, 0, &mut challenger)
                    .map_err(|e| format!("{e:?}"));
                crate::queries::take();
                verdict.map(|()| Verified { key: digest, claims: None })
            }),
        }
    }
}

impl<'a> Child<'a> {
    /// A leaf proved as a word proof of a normalize program's relations,
    /// whose public input words are its digest; `key_digest` names the key
    /// in the key tree.  The key is a constant of the program, and the
    /// verification's deferred claims, read from `hints` when the prover
    /// supplied them, advance the node's claims chain.
    ///
    /// # Panics
    /// Panics if called during a recording.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn word_leaf(
        key: &'a WordProofKey<Word64>,
        key_digest: [u8; 32],
        public: &'a [Word64],
        commitment: &'a crate::word::Commitment,
        proof: &'a crate::word::Proof,
        public_values: Vec<u32>,
        membership: VkMembership,
        schedule: &BinarySchedule,
        hints: Option<&'a crate::word::Hints>,
        routing: Option<&crate::word::Commitment>,
    ) -> Self {
        assert!(!crate::tape::recording(), "a child is made outside a recording");
        let schedule = *schedule;
        let routing = routing.map(crate::word::lift_routing);
        Self {
            public_values,
            membership,
            key: None,
            verify: Box::new(move |digest: &[Traced; DIGEST_SIZE]| {
                let claims = verify_word_routed(
                    key,
                    &schedule,
                    commitment,
                    routing.as_ref(),
                    public,
                    digest,
                    proof,
                    hints,
                )?;
                let key = digest_elements(key_digest).map(Traced::constant);
                Ok(Verified { key, claims: Some(claims) })
            }),
        }
    }
}

/// The claims chain advanced by a word proof's deferred claims under the key
/// `key`: the low 30 bits of each word of the Blake3 hash of a tag, the
/// chain's words, the key and each claim.  A claim is its kind, the number
/// of its query's values, those values and its value.
fn advance_claims(chain: &[Traced], key: [Traced; 2], claims: &[DeferredClaim]) -> Vec<Traced> {
    let mut pieces: Vec<Piece> =
        CLAIMS_TAG.iter().map(|&b| Piece::Byte(crate::bytes::constant_byte(b))).collect();
    pieces.extend(chain.iter().flat_map(|&word| element_bytes(word).map(Piece::Byte)));
    pieces.extend(key.map(Piece::Element));
    for claim in claims {
        let values: Vec<Traced> = claim.query.values().copied().collect();
        pieces.push(Piece::Byte(crate::bytes::constant_byte(claim_kind(claim.kind))));
        pieces.extend(
            (values.len() as u32).to_le_bytes().map(|b| Piece::Byte(crate::bytes::constant_byte(b))),
        );
        pieces.extend(values.into_iter().chain([claim.value]).map(Piece::Element));
    }
    let digest = digest_bytes(blake3(&pieces));
    (0..DIGEST_SIZE)
        .map(|w| {
            let word = Traced::input(kb_value(digest_word(&digest, w)));
            assert_digest_word(word, &digest, w);
            word
        })
        .collect()
}

/// The tag the claims chain hashes first.
const CLAIMS_TAG: &[u8] = b"ziren word claims";

fn claim_kind(kind: Deferred) -> u8 {
    match kind {
        Deferred::Inputs => 0,
        Deferred::Constants => 1,
        Deferred::Wiring => 2,
    }
}

/// [`advance_claims`] outside a recording: the chain's words after a word
/// proof's claims under the key `key`.
#[must_use]
pub fn advance_claims_native(
    chain: [u32; DIGEST_SIZE],
    key: [u8; 32],
    claims: &[NativeClaim],
) -> [u32; DIGEST_SIZE] {
    let mut message: Vec<u8> = CLAIMS_TAG.to_vec();
    message.extend(chain.iter().flat_map(|word| word.to_le_bytes()));
    message.extend(key);
    for claim in claims {
        let values: Vec<crate::tape::F> = claim.query.values().copied().collect();
        message.push(claim_kind(claim.kind));
        message.extend((values.len() as u32).to_le_bytes());
        for value in values.into_iter().chain([claim.value]) {
            message.extend(value.to_repr().to_le_bytes());
        }
    }
    let hash = ::blake3::hash(&message);
    let bytes = hash.as_bytes();
    core::array::from_fn(|w| {
        u32::from_le_bytes(core::array::from_fn(|k| bytes[4 * w + k])) & ((1 << 30) - 1)
    })
}

/// A deferred claim outside a recording.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NativeClaim {
    pub kind: Deferred,
    pub query: WiringQuery<crate::tape::F>,
    pub value: crate::tape::F,
}

impl From<&DeferredClaim> for NativeClaim {
    fn from(claim: &DeferredClaim) -> Self {
        Self { kind: claim.kind, query: claim.query.map(Traced::value), value: claim.value.value() }
    }
}

/// A compose node: its children in execution order, and whether it closes
/// the execution.
pub struct Compose<'a> {
    pub children: Vec<Child<'a>>,
    pub is_complete: bool,
    /// Shard numbers are below `2^max_log_shards`.
    pub max_log_shards: usize,
    /// Whether each child's key is shown a leaf of the key tree.  Off only
    /// to measure a tree whose keys are not all known before its leaves.
    pub check_keys: bool,
    /// The claims chain the node continues when its first child is a word
    /// proof, read as inputs: the chain the nodes before it in execution
    /// order end with.  Zero for the first node.
    pub claims_start: [u32; DIGEST_SIZE],
}

/// What a compose node commits to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Composed {
    pub public_values: Vec<u32>,
    pub digest: [u32; DIGEST_SIZE],
    /// The key digest and claims of each word-proof child, in order.
    pub claims: Vec<([u8; 32], Vec<NativeClaim>)>,
}

/// The node's verification, recorded: the public values it commits to, and
/// the tape, whose first eight inputs are the digest of those values.
///
/// The recording runs twice: the first run finds the digest, which the
/// second takes as its public inputs and checks.
///
/// # Errors
/// Returns why the children do not compose: a child's proof that does not
/// verify, or public values that do not chain.
pub fn record_compose(node: &Compose<'_>) -> (Result<Composed, String>, Tape) {
    let (first, _) = record(|| compose(node, None));
    let composed = match first {
        Ok(composed) => composed,
        Err(error) => return (Err(error), Tape::default()),
    };
    let digest = composed.digest;
    let profiling = std::env::var_os("ZIREN_TAPE_PROFILE").is_some();
    let (composed, tape) = record(|| {
        if profiling {
            crate::tape::profile(97);
        }
        let composed = compose(node, Some(digest));
        if let Some(profile) = crate::tape::take_profile() {
            for (signature, muls, bytes) in profile.by_signature(6).into_iter().take(24) {
                tracing::info!(
                    "node profile: mul ~{muls:>9} hashed {bytes:>8} B  {}",
                    &signature[..signature.len().min(260)]
                );
            }
        }
        composed
    });
    if profiling {
        let census: Vec<String> = Tape::KINDS
            .iter()
            .zip(tape.census())
            .filter(|(_, count)| *count > 0)
            .map(|(kind, count)| format!("{kind} {count}"))
            .collect();
        tracing::info!("node census: {} ops: {}", tape.ops.len(), census.join(", "));
    }
    (composed, tape)
}

fn constant(value: u32) -> Traced {
    Traced::constant(kb_value(value))
}

fn add(a: Traced, b: Traced) -> Traced {
    if a.is_constant() && a.value() == kb_value(0) {
        return b;
    }
    if b.is_constant() && b.value() == kb_value(0) {
        return a;
    }
    a.kb(KbOp::Add, b)
}

fn sub(a: Traced, b: Traced) -> Traced {
    if b.is_constant() && b.value() == kb_value(0) {
        return a;
    }
    a.kb(KbOp::Sub, b)
}

fn mul(a: Traced, b: Traced) -> Traced {
    a.kb(KbOp::Mul, b)
}

fn assert_zero(x: Traced) {
    x.assert_eq(&constant(0));
}

/// The four low bytes of an element, its upper twelve zero.
fn element_bytes(x: Traced) -> [Traced; 4] {
    let bytes = to_bytes(x);
    for byte in &bytes[4..] {
        byte.assert_eq(&Traced::ZERO);
    }
    [bytes[0], bytes[1], bytes[2], bytes[3]]
}

/// The 32 Blake3 digest bytes of the hashed prefix of public values.
fn hashed(values: &[Traced]) -> [Traced; 32] {
    let pieces: Vec<Piece> = values[..NUM_PV_ELMS_TO_HASH]
        .iter()
        .flat_map(|&x| element_bytes(x).map(Piece::Byte))
        .collect();
    digest_bytes(blake3(&pieces))
}

/// The digest a node's public values hash to, computed outside a recording
/// as the recorded verification computes it: the Blake3 hash of the hashed
/// prefix's little-endian bytes, each word cut to its low 30 bits.
#[must_use]
pub fn public_values_digest(values: &[u32]) -> [u32; DIGEST_SIZE] {
    let bytes: Vec<u8> =
        values[..NUM_PV_ELMS_TO_HASH].iter().flat_map(|value| value.to_le_bytes()).collect();
    let hash = ::blake3::hash(&bytes);
    let hash = hash.as_bytes();
    core::array::from_fn(|w| {
        u32::from_le_bytes([hash[4 * w], hash[4 * w + 1], hash[4 * w + 2], hash[4 * w + 3]])
            & ((1 << 30) - 1)
    })
}

/// Word `w` of a digest, its low 30 bits, as an element.
fn digest_word(digest: &[Traced; 32], w: usize) -> u32 {
    let bytes: [u8; 4] =
        core::array::from_fn(|k| as_kb(digest[4 * w + k].value()).expect("a digest byte") as u8);
    u32::from_le_bytes(bytes) & ((1 << 30) - 1)
}

/// `word` holds the low 30 bits of word `w` of `digest`.
fn assert_digest_word(word: Traced, digest: &[Traced; 32], w: usize) {
    let bytes = element_bytes(word);
    for k in 0..3 {
        bytes[k].assert_eq(&digest[4 * w + k]);
    }
    let (top, expected) = (byte_bits(bytes[3]), byte_bits(digest[4 * w + 3]));
    for i in 0..6 {
        top[i].assert_eq(&expected[i]);
    }
    for bit in &top[6..] {
        bit.assert_eq(&Traced::ZERO);
    }
}

/// `x < 2^bits`.
fn range_check(x: Traced, bits: usize) {
    for (k, byte) in element_bytes(x).into_iter().enumerate() {
        for (i, bit) in byte_bits(byte).into_iter().enumerate() {
            if 8 * k + i >= bits {
                bit.assert_eq(&Traced::ZERO);
            }
        }
    }
}

/// An element of the septic extension `F_p[z] / (z^7 + 2z - 8)`.
type Septic = [Traced; 7];

fn septic_constant(x: SepticExtension<KoalaBear>) -> Septic {
    core::array::from_fn(|i| constant(x.0[i].as_canonical_u32()))
}

fn septic_add(a: &Septic, b: &Septic) -> Septic {
    core::array::from_fn(|i| add(a[i], b[i]))
}

fn septic_sub(a: &Septic, b: &Septic) -> Septic {
    core::array::from_fn(|i| sub(a[i], b[i]))
}

/// The schoolbook product, folded by `z^7 = 8 - 2z`.
fn septic_mul(a: &Septic, b: &Septic) -> Septic {
    let mut product: [Traced; 13] = core::array::from_fn(|_| constant(0));
    for i in 0..7 {
        for j in 0..7 {
            product[i + j] = add(product[i + j], mul(a[i], b[j]));
        }
    }
    let mut folded: Septic = core::array::from_fn(|i| product[i]);
    for i in 7..13 {
        folded[i - 7] = add(folded[i - 7], mul(product[i], constant(8)));
        folded[i - 6] = sub(folded[i - 6], mul(product[i], constant(2)));
    }
    folded
}

fn assert_septic_zero(x: &Septic) {
    for &limb in x {
        assert_zero(limb);
    }
}

/// A point of the curve `y^2 = x^3 + 3z x - 3` over the septic extension.
#[derive(Clone, Copy)]
struct Point {
    x: Septic,
    y: Septic,
}

impl Point {
    fn constant(point: SepticCurve<KoalaBear>) -> Self {
        Self { x: septic_constant(point.x), y: septic_constant(point.y) }
    }

    fn host(&self) -> SepticCurve<KoalaBear> {
        let element = |x: &Septic| {
            SepticExtension(core::array::from_fn(|i| {
                KoalaBear::from_u32(as_kb(x[i].value()).expect("a canonical coordinate"))
            }))
        };
        SepticCurve { x: element(&self.x), y: element(&self.y) }
    }

    /// The sum of two points, hinted and checked as the field machine's
    /// `add_curve_v2` checks it: both sum checkers vanish and the sum is on
    /// the curve.
    fn add(&self, other: &Self) -> Self {
        let sum = self.host().add_incomplete(other.host());
        let input = |x: SepticExtension<KoalaBear>| -> Septic {
            core::array::from_fn(|i| Traced::input(kb_value(x.0[i].as_canonical_u32())))
        };
        let sum = Self { x: input(sum.x), y: input(sum.y) };
        let dx = septic_sub(&other.x, &self.x);
        let dy = septic_sub(&other.y, &self.y);
        let xs = septic_add(&septic_add(&self.x, &other.x), &sum.x);
        assert_septic_zero(&septic_sub(
            &septic_mul(&xs, &septic_mul(&dx, &dx)),
            &septic_mul(&dy, &dy),
        ));
        assert_septic_zero(&septic_sub(
            &septic_mul(&septic_add(&self.y, &sum.y), &dx),
            &septic_mul(&dy, &septic_sub(&self.x, &sum.x)),
        ));
        let mut three_z = [constant(0); 7];
        three_z[1] = constant(3);
        let mut three = [constant(0); 7];
        three[0] = constant(3);
        let cube = septic_mul(&septic_mul(&sum.x, &sum.x), &sum.x);
        let formula = septic_sub(&septic_add(&cube, &septic_mul(&sum.x, &three_z)), &three);
        assert_septic_zero(&septic_sub(&septic_mul(&sum.y, &sum.y), &formula));
        sum
    }

    fn values(&self) -> [Traced; 14] {
        core::array::from_fn(|i| if i < 7 { self.x[i] } else { self.y[i - 7] })
    }
}

/// The digests summed as the field machine's `sum_digest_v2` sums them:
/// from the starting digest, each digest added and the zero digest taken
/// away between them, the starting digest taken away at the end.
fn sum_digests(digests: &[Point]) -> Point {
    let start = SepticDigest::<KoalaBear>::starting_digest().0;
    let zero = SepticDigest::<KoalaBear>::zero().0;
    if digests.is_empty() {
        return Point::constant(zero);
    }
    let neg_zero = Point::constant(zero.neg());
    let mut sum = Point::constant(start);
    for (i, digest) in digests.iter().enumerate() {
        sum = sum.add(digest);
        if i + 1 != digests.len() {
            sum = sum.add(&neg_zero);
        }
    }
    sum.add(&Point::constant(start.neg()))
}

/// One run of the node's program; `public` is the digest it checks its
/// public inputs against, or `None` on the run that finds it.
fn compose(node: &Compose<'_>, public: Option<[u32; DIGEST_SIZE]>) -> Result<Composed, String> {
    assert!(!node.children.is_empty(), "a compose node has children");
    let digest_inputs: [Traced; DIGEST_SIZE] =
        core::array::from_fn(|w| Traced::input(kb_value(public.map_or(0, |p| p[w]))));

    let mut out = vec![constant(0); RECURSIVE_PROOF_NUM_PV_ELTS];
    let mut sums: Vec<Point> = Vec::with_capacity(node.children.len());
    let mut vk_root: [Traced; DIGEST_SIZE] = [constant(0); DIGEST_SIZE];
    let mut exit_code = constant(0);
    let mut pc = constant(0);
    let mut shard = constant(0);
    let mut execution_shard = constant(0);
    let mut contains_execution_shard = constant(0);
    let mut start_execution_shard = constant(0);
    let mut init_addr_bits = [constant(0); 32];
    let mut finalize_addr_bits = [constant(0); 32];
    let mut committed_value_digest: Vec<Traced> = Vec::new();
    let mut deferred_proofs_digest: Vec<Traced> = Vec::new();
    let mut reconstruct_deferred_digest: Vec<Traced> = Vec::new();
    let mut zkm_vk_digest: Vec<Traced> = Vec::new();
    let mut composed_claims: Vec<([u8; 32], Vec<NativeClaim>)> = Vec::new();

    for (i, child) in node.children.iter().enumerate() {
        if child.public_values.len() != RECURSIVE_PROOF_NUM_PV_ELTS {
            return Err(format!("child {i} has {} public values", child.public_values.len()));
        }
        let values: Vec<Traced> =
            child.public_values.iter().map(|&v| Traced::input(kb_value(v))).collect();
        let current: &RecursionPublicValues<Traced> = values.as_slice().borrow();

        let digest = hashed(&values);
        for (w, &word) in current.digest.iter().enumerate() {
            assert_digest_word(word, &digest, w);
        }
        let verified = match (public, &child.key) {
            (None, Some(key)) => Verified { key: key(), claims: None },
            _ => (child.verify)(&current.digest).map_err(|e| format!("child {i}: {e}"))?,
        };
        if node.check_keys {
            check_membership(verified.key, &child.membership, &current.vk_root);
        }

        if i == 0 {
            vk_root = current.vk_root;
            reconstruct_deferred_digest = if verified.claims.is_some() {
                node.claims_start.iter().map(|&w| Traced::input(kb_value(w))).collect()
            } else {
                current.start_reconstruct_deferred_digest.to_vec()
            };
            zkm_vk_digest = current.zkm_vk_digest.to_vec();
            pc = current.start_pc;
            shard = current.start_shard;
            start_execution_shard = current.start_execution_shard;
            execution_shard = current.start_execution_shard;
            init_addr_bits = current.previous_init_addr_bits;
            finalize_addr_bits = current.previous_finalize_addr_bits;
            committed_value_digest =
                current.committed_value_digest.iter().flat_map(|word| word.0).collect();
            deferred_proofs_digest = current.deferred_proofs_digest.to_vec();
            let parent: &mut RecursionPublicValues<Traced> = out.as_mut_slice().borrow_mut();
            parent.start_reconstruct_deferred_digest =
                core::array::from_fn(|k| reconstruct_deferred_digest[k]);
            parent.start_pc = current.start_pc;
            parent.start_shard = current.start_shard;
            parent.previous_init_addr_bits = current.previous_init_addr_bits;
            parent.previous_finalize_addr_bits = current.previous_finalize_addr_bits;
        }

        for (expected, actual) in vk_root.iter().zip(&current.vk_root) {
            expected.assert_eq(actual);
        }
        exit_code = current.exit_code;
        let end_reconstruct = match &verified.claims {
            Some(claims) => {
                for (start, end) in current
                    .start_reconstruct_deferred_digest
                    .iter()
                    .zip(&current.end_reconstruct_deferred_digest)
                {
                    start.assert_eq(end);
                }
                let [lo, hi] = verified.key.map(|half| half.value().to_repr().to_le_bytes());
                let key: [u8; 32] =
                    core::array::from_fn(|k| if k < 16 { lo[k] } else { hi[k - 16] });
                composed_claims.push((key, claims.iter().map(NativeClaim::from).collect()));
                advance_claims(&reconstruct_deferred_digest, verified.key, claims)
            }
            None => {
                for (digest, current) in reconstruct_deferred_digest
                    .iter()
                    .zip(&current.start_reconstruct_deferred_digest)
                {
                    digest.assert_eq(current);
                }
                current.end_reconstruct_deferred_digest.to_vec()
            }
        };
        for (digest, current) in zkm_vk_digest.iter().zip(&current.zkm_vk_digest) {
            digest.assert_eq(current);
        }
        pc.assert_eq(&current.start_pc);
        shard.assert_eq(&current.start_shard);
        range_check(current.start_shard, node.max_log_shards);
        range_check(current.next_shard, node.max_log_shards);

        let contains = current.contains_execution_shard;
        assert_zero(mul(contains, sub(constant(1), contains)));
        let first_seen = mul(contains, sub(constant(1), contains_execution_shard));
        let not_first_seen = sub(constant(1), first_seen);
        start_execution_shard = add(
            mul(current.start_execution_shard, first_seen),
            mul(start_execution_shard, not_first_seen),
        );
        execution_shard = add(
            mul(current.start_execution_shard, first_seen),
            mul(execution_shard, not_first_seen),
        );
        assert_zero(mul(contains, sub(execution_shard, current.start_execution_shard)));

        for (bit, current) in init_addr_bits.iter().zip(&current.previous_init_addr_bits) {
            bit.assert_eq(current);
        }
        for (bit, current) in finalize_addr_bits.iter().zip(&current.previous_finalize_addr_bits) {
            bit.assert_eq(current);
        }

        let current_committed: Vec<Traced> =
            current.committed_value_digest.iter().flat_map(|word| word.0).collect();
        for &is_non_zero in &committed_value_digest {
            for (&accumulated, &public) in committed_value_digest.iter().zip(&current_committed) {
                assert_zero(mul(is_non_zero, sub(accumulated, public)));
            }
        }
        committed_value_digest = current_committed;
        for &is_non_zero in &deferred_proofs_digest {
            for (&accumulated, &public) in
                deferred_proofs_digest.iter().zip(&current.deferred_proofs_digest)
            {
                assert_zero(mul(is_non_zero, sub(accumulated, public)));
            }
        }
        deferred_proofs_digest = current.deferred_proofs_digest.to_vec();

        contains_execution_shard = add(
            contains_execution_shard,
            mul(contains, sub(constant(1), contains_execution_shard)),
        );
        execution_shard = add(
            mul(current.next_execution_shard, contains),
            mul(execution_shard, sub(constant(1), contains)),
        );
        reconstruct_deferred_digest = end_reconstruct;
        pc = current.next_pc;
        shard = current.next_shard;
        init_addr_bits = current.last_init_addr_bits;
        finalize_addr_bits = current.last_finalize_addr_bits;
        sums.push(Point {
            x: current.global_cumulative_sum.0.x.0,
            y: current.global_cumulative_sum.0.y.0,
        });
    }
    let sum = sum_digests(&sums);

    {
        let parent: &mut RecursionPublicValues<Traced> = out.as_mut_slice().borrow_mut();
        parent.start_execution_shard = start_execution_shard;
        parent.zkm_vk_digest = core::array::from_fn(|k| zkm_vk_digest[k]);
        parent.next_pc = pc;
        parent.next_shard = shard;
        parent.next_execution_shard = execution_shard;
        parent.last_init_addr_bits = init_addr_bits;
        parent.last_finalize_addr_bits = finalize_addr_bits;
        parent.end_reconstruct_deferred_digest =
            core::array::from_fn(|k| reconstruct_deferred_digest[k]);
        parent.deferred_proofs_digest = core::array::from_fn(|k| deferred_proofs_digest[k]);
        for (w, word) in parent.committed_value_digest.iter_mut().enumerate() {
            word.0 = core::array::from_fn(|b| committed_value_digest[4 * w + b]);
        }
        let values = sum.values();
        parent.global_cumulative_sum.0.x.0 = core::array::from_fn(|k| values[k]);
        parent.global_cumulative_sum.0.y.0 = core::array::from_fn(|k| values[7 + k]);
        parent.is_complete = constant(u32::from(node.is_complete));
        parent.contains_execution_shard = contains_execution_shard;
        parent.exit_code = exit_code;
        parent.vk_root = vk_root;
    }
    if node.is_complete {
        assert_complete(&out);
    }

    let digest = hashed(&out);
    let words: [u32; DIGEST_SIZE] = core::array::from_fn(|w| digest_word(&digest, w));
    {
        let parent: &mut RecursionPublicValues<Traced> = out.as_mut_slice().borrow_mut();
        parent.digest = core::array::from_fn(|w| constant(words[w]));
    }
    if public.is_some() {
        for (w, word) in digest_inputs.iter().enumerate() {
            assert_digest_word(*word, &digest, w);
        }
    }
    let public_values = out
        .iter()
        .map(|x| as_kb(x.value()).expect("a public value is a canonical element"))
        .collect();
    Ok(Composed { public_values, digest: words, claims: composed_claims })
}

/// The boundary conditions of a proof of the whole execution, as the field
/// machine's `assert_complete` checks them.
fn assert_complete(values: &[Traced]) {
    let pv: &RecursionPublicValues<Traced> = values.borrow();
    assert_zero(pv.next_pc);
    pv.start_shard.assert_eq(&constant(1));
    sub(pv.next_shard, constant(1)).assert_nonzero();
    pv.contains_execution_shard.assert_eq(&constant(1));
    pv.start_execution_shard.assert_eq(&constant(1));
    for &word in &pv.start_reconstruct_deferred_digest {
        assert_zero(word);
    }
    for &word in &pv.deferred_proofs_digest {
        assert_zero(word);
    }
    let zero = SepticDigest::<KoalaBear>::zero().0;
    let expected = Point::constant(zero).values();
    let actual = [pv.global_cumulative_sum.0.x.0, pv.global_cumulative_sum.0.y.0].concat();
    for (actual, expected) in actual.iter().zip(expected) {
        actual.assert_eq(&expected);
    }
}

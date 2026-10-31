//! The verifier of a word proof, recorded.
//!
//! A word proof commits its bits under the binary stage's Boolean WHIR and
//! Blake3 transcript, so the word backend's own verifier runs over traced
//! values exactly as the stage's machine verifier does, and records the
//! program a node runs to verify a word proof.
//!
//! The statement's first public words are its inputs, the values a node
//! reads from the proved program, and the rest are the key's constants.  The
//! inputs are the program's: their bytes in the transcript's seeds and
//! their share of the shift reduction are recorded from them.  Two steps
//! whose cost grows with the statement are not recorded: the constants'
//! share and the shift reduction's wiring factor, functions of the key and
//! the transcript alone.  The recording reads each as a value of the proof
//! and returns where it was asked for; a verifier of the program checks
//! those claims against the key natively.

use core::cell::RefCell;

use p3_binary_pcs::BooleanBackend;
use p3_binary_field::TowerLevel;
use p3_field::PrimeCharacteristicRing;
use p3_word::{Word, Word64};
use p3_word_backend::{Deferred, WiringQuery, WordProof, WordProofKey};
use zkm_binary_stark::config::BitPcs;
use zkm_binary_stark::{BinarySchedule, F, TRANSCRIPT_DOMAIN};

use crate::bytes::{byte_bits, byte_field, constant_byte, select, to_bytes};
use crate::challenger::TracedChallenger;
use crate::config::{bit_commitment, reread, TracedBitPcs};
use crate::tape::{record, Tape};
use crate::traced::Traced;

/// The commitment of a word proof.
pub type Commitment = <BitPcs as BooleanBackend<F>>::Commitment;

/// A word proof.
pub type Proof = WordProof<F, F, <BitPcs as BooleanBackend<F>>::Proof>;

/// The deferred values as the word prover knows them.
pub type Hints = p3_word_backend::ShiftHints<F>;

/// A word proof, over traced values.
pub type TracedProof = WordProof<Traced, Traced, <TracedBitPcs as BooleanBackend<Traced>>::Proof>;

/// A value the recorded verifier relied on that is a function of the key and
/// the transcript alone: the key's `kind` at `query` must be `value`.
#[derive(Clone, Debug)]
pub struct DeferredClaim {
    pub kind: Deferred,
    pub query: WiringQuery<Traced>,
    pub value: Traced,
}

impl DeferredClaim {
    /// Whether the claim holds for `key` on the public words `public`, of
    /// which those from `inputs` on are the key's, in the run that recorded
    /// it.
    #[must_use]
    pub fn holds(&self, key: &WordProofKey<Word64>, public: &[Word64], inputs: usize) -> bool {
        key.deferred(self.kind, public, inputs, &self.query.map(Traced::value)) == self.value.value()
    }
}

/// The public words of the word proof being verified: how many there are,
/// the input words, each as its eight little-endian bytes, and how many
/// seeds took them.
struct SeedWords {
    count: usize,
    inputs: Vec<[Traced; 8]>,
    substituted: usize,
}

std::thread_local! {
    static SEED_WORDS: RefCell<Option<SeedWords>> = const { RefCell::new(None) };
}

/// Each byte of a transcript seed, with the input words' bytes the
/// program's, if the seed is a word proof's that ends with its public
/// words; `None` for any other seed.
///
/// A word proof's seed ends with the statement's public words, each as a
/// four-byte big-endian length and eight little-endian bytes, then one tag
/// byte.
pub(crate) fn seed_inputs(bytes: &[u8]) -> Option<Vec<Traced>> {
    SEED_WORDS.with(|cell| {
        let mut cell = cell.borrow_mut();
        let words = cell.as_mut()?;
        if words.inputs.is_empty() {
            return None;
        }
        let start = bytes.len().checked_sub(12 * words.count + 1)?;
        let positions = (0..words.inputs.len()).map(|i| start + 12 * i);
        let matches = positions.clone().zip(&words.inputs).all(|(at, word)| {
            bytes[at..at + 4] == 8u32.to_be_bytes()
                && word.iter().zip(&bytes[at + 4..at + 12]).all(|(t, &b)| t.value() == byte_field(b))
        });
        if !matches {
            return None;
        }
        let mut pieces: Vec<Traced> = bytes.iter().map(|&b| constant_byte(b)).collect();
        for (at, word) in positions.zip(&words.inputs) {
            pieces[at + 4..at + 12].copy_from_slice(word);
        }
        words.substituted += 1;
        Some(pieces)
    })
}

/// The eight little-endian bytes of a word held in an element's low bits;
/// the element's other bytes are zero.
fn word_bytes(x: Traced) -> [Traced; 8] {
    let bytes = to_bytes(x);
    for byte in &bytes[8..] {
        byte.assert_eq(&Traced::ZERO);
    }
    core::array::from_fn(|i| bytes[i])
}

/// Verifies `proof` of `key`'s relations, inside a recording: the statement's
/// public words are `public`, of which the first are `inputs`, the program's
/// values each holding its word in its low bits.  Returns the claims it
/// deferred, whose values are read from `hints` when the prover supplied
/// them, and evaluated from the key otherwise.
///
/// # Errors
/// Returns why the proof does not verify.
///
/// # Panics
/// Panics if the commitment cannot be built for the key, or if a
/// transcript does not take the input words where a word proof's does.
pub fn verify_word(
    key: &WordProofKey<Word64>,
    schedule: &BinarySchedule,
    commitment: &Commitment,
    public: &[Word64],
    inputs: &[Traced],
    proof: &Proof,
    hints: Option<&Hints>,
) -> Result<Vec<DeferredClaim>, String> {
    verify_word_routed(key, schedule, commitment, None, public, inputs, proof, hints)
}

/// The commitment to a key's routing words, over traced values: a constant of the program
/// when lifted with [`lift_routing`].
pub type TracedCommitment = <TracedBitPcs as BooleanBackend<Traced>>::Commitment;

/// `routing`, the commitment to a routed key's routing words, as constants of the program.
///
/// # Panics
/// Panics if called during a recording, where it would read as proof inputs.
#[must_use]
pub fn lift_routing(routing: &Commitment) -> TracedCommitment {
    assert!(!crate::tape::recording(), "the routing is lifted before the recording");
    reread(routing)
}

/// [`verify_word`] of a key that routes its ports when `routing`, the lifted commitment to
/// its routing words, is given.
///
/// # Errors
/// Returns why the proof does not verify.
///
/// # Panics
/// As [`verify_word`].
#[allow(clippy::too_many_arguments)]
pub fn verify_word_routed(
    key: &WordProofKey<Word64>,
    schedule: &BinarySchedule,
    commitment: &Commitment,
    routing: Option<&TracedCommitment>,
    public: &[Word64],
    inputs: &[Traced],
    proof: &Proof,
    hints: Option<&Hints>,
) -> Result<Vec<DeferredClaim>, String> {
    let count = inputs.len();
    assert!(count <= public.len(), "more inputs than public words");
    let input_bytes: Vec<[Traced; 8]> = inputs.iter().map(|&x| word_bytes(x)).collect();
    let pcs = tracing::info_span!("word traced pcs")
        .in_scope(|| bit_commitment(key.trace_variables(), schedule).expect("the traced commitment"));
    let commitment: TracedCommitment = reread(commitment);
    let proof: TracedProof = tracing::info_span!("word reread").in_scope(|| reread(proof));
    let mut challenger = TracedChallenger::new(TRANSCRIPT_DOMAIN);
    let mut deferred = Vec::new();
    SEED_WORDS.with(|cell| {
        *cell.borrow_mut() =
            Some(SeedWords { count: public.len(), inputs: input_bytes.clone(), substituted: 0 });
    });
    let _span = tracing::info_span!("word traced verify").entered();
    let mut answer = |kind, query: &WiringQuery<Traced>| match kind {
            Deferred::Inputs => {
                let weights = tracing::info_span!("word input weights")
                    .in_scope(|| key.input_bit_weights(count, query));
                let mut share = Traced::ZERO;
                for (bytes, weights) in input_bytes.iter().zip(&weights) {
                    let bits = bytes.iter().flat_map(|&b| byte_bits(b));
                    for (bit, &weight) in bits.zip(weights).take(Word64::BITS as usize) {
                        share += select(bit, Traced::ZERO, weight);
                    }
                }
                share
            }
            _ => {
                let native = tracing::info_span!("word deferred", ?kind).in_scope(|| {
                    let evaluate = |kind| key.deferred(kind, public, count, &query.map(Traced::value));
                    match (hints, kind) {
                        (Some(hints), Deferred::Wiring) => hints.wiring,
                        (Some(hints), _) => hints.public - evaluate(Deferred::Inputs),
                        (None, _) => evaluate(kind),
                    }
                });
                let value = Traced::input(native);
                deferred.push(DeferredClaim { kind, query: query.clone(), value });
                value
            }
    };
    let verdict = match routing {
        Some(routing) => key.verify_routed_with::<Traced, Traced, _, _>(
            &pcs,
            &commitment,
            routing,
            public,
            &proof,
            &mut challenger,
            &mut answer,
        ),
        None => key.verify_with::<Traced, Traced, _, _>(
            &pcs,
            &commitment,
            public,
            &proof,
            &mut challenger,
            &mut answer,
        ),
    };
    let substituted =
        SEED_WORDS.with(|cell| cell.borrow_mut().take().map_or(0, |words| words.substituted));
    crate::queries::take();
    verdict.map_err(|error| format!("{error:?}"))?;
    assert!(
        count == 0 || substituted == 2,
        "the input words entered {substituted} transcript seeds, not the word proof's two"
    );
    Ok(deferred)
}

/// The verification of `proof` of `key`'s relations on the public words
/// `public`, of which the first `inputs` are the program's and the rest the
/// key's constants, committed under `schedule`, recorded: whether it
/// accepted, the claims it deferred, and the tape.  The input words are the
/// tape's first inputs, then the commitment and the proof's values in the
/// order the proof is written, each deferred value read where the verifier
/// asks for it.
pub fn record_word_verification(
    key: &WordProofKey<Word64>,
    schedule: &BinarySchedule,
    commitment: &Commitment,
    public: &[Word64],
    inputs: usize,
    proof: &Proof,
    hints: Option<&Hints>,
) -> (Result<Vec<DeferredClaim>, String>, Tape) {
    let profiling = std::env::var_os("ZIREN_TAPE_PROFILE").is_some();
    record(|| {
        if profiling {
            crate::tape::profile(97);
        }
        let traced: Vec<Traced> = public[..inputs]
            .iter()
            .map(|word| Traced::input(F::from_repr(u128::from(word.to_u64()))))
            .collect();
        let verdict = verify_word(key, schedule, commitment, public, &traced, proof, hints);
        if let Some(profile) = crate::tape::take_profile() {
            for (signature, muls, bytes) in profile.by_signature(6).into_iter().take(16) {
                println!(
                    "    mul ~{muls:>9} hashed {bytes:>8} B  {}",
                    &signature[..signature.len().min(220)]
                );
            }
        }
        verdict
    })
}

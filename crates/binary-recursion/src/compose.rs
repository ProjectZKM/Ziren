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

use core::borrow::{Borrow, BorrowMut};

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

use crate::bytes::{blake3, byte_bits, digest_bytes, to_bytes, Piece};
use crate::challenger::TracedChallenger;
use crate::config::{lift_key, reread, TracedConfig, TracedProof};
use crate::machine::{TapeAir, TapeMachine};
use crate::tape::{as_kb, kb_value, record, KbOp, Tape};
use crate::Traced;

/// The recorded verification of a child's proof against the digest its
/// public values hash to, which the proof commits to as its public values.
pub type ChildVerifier<'a> =
    Box<dyn Fn(&[Traced; DIGEST_SIZE]) -> Result<(), String> + Send + Sync + 'a>;

/// A child of a compose node.
pub struct Child<'a> {
    /// Its public values, as canonical elements.
    pub public_values: Vec<u32>,
    /// The verification of its proof.
    pub verify: ChildVerifier<'a>,
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
        schedule: &BinarySchedule,
    ) -> Self {
        let (main, preprocessed) = machine.shapes();
        let config = TracedConfig::new(&main, &preprocessed, schedule).expect("traced config");
        let vk = lift_key(machine.verifying_key());
        Self {
            public_values,
            verify: Box::new(move |public: &[Traced; DIGEST_SIZE]| {
                let proof: TracedProof = reread(proof);
                let instances = machine.verifier_instances(&vk, public);
                let mut challenger = TracedChallenger::new(TRANSCRIPT_DOMAIN);
                let verdict = verify(&config, instances, &proof, 0, &mut challenger)
                    .map_err(|e| format!("{e:?}"));
                crate::queries::take();
                verdict
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
        schedule: &BinarySchedule,
    ) -> Self {
        let (main, preprocessed) = machine.shapes();
        let config = TracedConfig::new(&main, &preprocessed, schedule).expect("traced config");
        let vk = lift_key(machine.verifying_key());
        Self {
            public_values,
            verify: Box::new(move |public: &[Traced; DIGEST_SIZE]| {
                let proof: TracedProof = reread(proof);
                let instances = VerifierInstances::new(
                    machine
                        .airs()
                        .iter()
                        .map(|air| {
                            let public_values: &[Traced] = match air {
                                TapeAir::Ledger(_) => public,
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
                verdict
            }),
        }
    }
}

/// A compose node: its children in execution order, and whether it closes
/// the execution.
pub struct Compose<'a> {
    pub children: Vec<Child<'a>>,
    pub is_complete: bool,
    /// Shard numbers are below `2^max_log_shards`.
    pub max_log_shards: usize,
}

/// What a compose node commits to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Composed {
    pub public_values: Vec<u32>,
    pub digest: [u32; DIGEST_SIZE],
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
    record(|| compose(node, Some(digest)))
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
        (child.verify)(&current.digest).map_err(|e| format!("child {i}: {e}"))?;

        if i == 0 {
            vk_root = current.vk_root;
            reconstruct_deferred_digest = current.start_reconstruct_deferred_digest.to_vec();
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
            parent.start_reconstruct_deferred_digest = current.start_reconstruct_deferred_digest;
            parent.start_pc = current.start_pc;
            parent.start_shard = current.start_shard;
            parent.previous_init_addr_bits = current.previous_init_addr_bits;
            parent.previous_finalize_addr_bits = current.previous_finalize_addr_bits;
        }

        for (expected, actual) in vk_root.iter().zip(&current.vk_root) {
            expected.assert_eq(actual);
        }
        exit_code = current.exit_code;
        for (digest, current) in
            reconstruct_deferred_digest.iter().zip(&current.start_reconstruct_deferred_digest)
        {
            digest.assert_eq(current);
        }
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
        reconstruct_deferred_digest = current.end_reconstruct_deferred_digest.to_vec();
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
    Ok(Composed { public_values, digest: words })
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
    for (end, deferred) in pv.end_reconstruct_deferred_digest.iter().zip(&pv.deferred_proofs_digest)
    {
        end.assert_eq(deferred);
    }
    let zero = SepticDigest::<KoalaBear>::zero().0;
    let expected = Point::constant(zero).values();
    let actual = [pv.global_cumulative_sum.0.x.0, pv.global_cumulative_sum.0.y.0].concat();
    for (actual, expected) in actual.iter().zip(expected) {
        actual.assert_eq(&expected);
    }
}

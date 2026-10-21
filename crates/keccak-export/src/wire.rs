//! Profile-bound transport for the complete KoalaBear/Keccak terminal proof.
//!
//! This is a representation change, not a proof-system change. Decode restores
//! the native messages, including omitted sumcheck coefficients, before the
//! existing full verifier is called. A profile MUST come from an independently
//! trusted key and a verified reference proof, never from a submission.

use std::collections::{BTreeMap, BTreeSet};

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32, PrimeField64};
use p3_keccak::Keccak256Hash;
use p3_symmetric::{CryptographicHasher, MerkleCap};
use serde::{Deserialize, Serialize};

use zkm_pcs::jagged_pcs::jagged::JaggedPcsProofGeneric;
use zkm_pcs::kb31_keccak::{
    root_felts, terminal_key_digest, Challenge as E, KeccakMmcs as M, KoalaBearKeccak as SC,
    Val as F,
};
use zkm_pcs::shard_level::shard_proof::{EvaluationProof, FoldOrientation, JaggedShardProof};
use zkm_pcs::shard_level::types::PartialSumcheckProof;
use zkm_pcs::{ShardProof, StarkVerifyingKey};

const MAGIC: &[u8; 4] = b"ZKET";
const HEADER: usize = 38; // magic, version, mode, profile ID
type Digest = [u8; 32];
type Bundle = JaggedPcsProofGeneric<M>;
pub type Result<T> = core::result::Result<T, WireError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError(pub &'static str);
impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for WireError {}
fn ensure(ok: bool, message: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(WireError(message))
    }
}

/// Raw hashes, a shared hash table, or a shared authentication-node DAG.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Mode {
    Raw = 0,
    Shared = 1,
    Dag = 2,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeafRange {
    pub field_start: usize,
    pub field_count: usize,
    pub path_start: usize,
    pub path_len: usize,
}

/// Native storage of an approved schema; it is not transmitted with proofs.
/// The on-chain equivalent pins `id()`, counts, leaf ranges and the verifier's
/// complete schema/constants. These fields cannot be selected by a submitter.
#[derive(Clone, Serialize, Deserialize)]
pub struct Profile {
    pub vk: StarkVerifyingKey<SC>,
    template: ShardProof<SC>,
    bundle: Bundle,
    metadata: Vec<u8>,
    pub field_count: usize,
    pub digest_references: usize,
    pub leaves: Vec<LeafRange>,
    pub mode: Mode,
    pub derived_sumchecks: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PacketStats {
    pub bytes: usize,
    pub zero_bytes: usize,
    pub nonzero_bytes: usize,
    pub standard_calldata_gas: usize,
    pub transaction_floor_gas: usize,
}
pub fn packet_stats(packet: &[u8]) -> PacketStats {
    let zero_bytes = packet.iter().filter(|&&b| b == 0).count();
    let nonzero_bytes = packet.len() - zero_bytes;
    let tokens = zero_bytes + 4 * nonzero_bytes;
    PacketStats {
        bytes: packet.len(),
        zero_bytes,
        nonzero_bytes,
        standard_calldata_gas: 4 * tokens,
        transaction_floor_gas: 21_000 + 10 * tokens,
    }
}

impl Profile {
    /// Call only after verifying the reference proof with independently pinned
    /// application/key/root parameters. Geometry is intentionally profile-bound.
    pub fn from_trusted_proof(
        vk: &StarkVerifyingKey<SC>,
        proof: &ShardProof<SC>,
        mode: Mode,
        derived_sumchecks: bool,
    ) -> Result<Self> {
        let (mut template, mut bundle) = split(proof)?;
        let mut tape = Tape::writer(true, derived_sumchecks);
        visit_parts(&mut template, &mut bundle, &mut tape)?;
        ensure(
            tape.digests.len() < 65_536 && tape.leaves.len() < 65_536,
            "profile exceeds u16 dictionary bounds",
        )?;
        Ok(Self {
            vk: vk.clone(),
            template,
            bundle,
            metadata: tape.metadata,
            field_count: tape.fields.len(),
            digest_references: tape.digests.len(),
            leaves: tape.leaves,
            mode,
            derived_sumchecks,
        })
    }

    pub fn id(&self) -> Digest {
        let mut bytes = b"ziren-keccak-wire-profile-v1".to_vec();
        bytes.extend(terminal_key_digest(&self.vk));
        bytes.extend([self.mode as u8, self.derived_sumchecks as u8]);
        bytes.extend(&self.metadata);
        Keccak256Hash.hash_iter(bytes)
    }

    /// Flat canonical stream digest, useful for Rust/Solidity decoder parity.
    /// It is NOT a proof-verification result or a replacement Fiat–Shamir hash.
    pub fn witness_digest(&self, proof: &ShardProof<SC>) -> Result<Digest> {
        let tape = self.tape(proof)?;
        Ok(Keccak256Hash.hash_iter(
            field_bytes(&tape.fields).into_iter().chain(tape.digests.into_iter().flatten()),
        ))
    }

    fn tape(&self, proof: &ShardProof<SC>) -> Result<Tape> {
        let (mut proof, mut bundle) = split(proof)?;
        let mut tape = Tape::writer(false, self.derived_sumchecks);
        visit_parts(&mut proof, &mut bundle, &mut tape)?;
        ensure(
            tape.metadata == self.metadata && tape.leaves == self.leaves,
            "proof does not match approved profile geometry",
        )?;
        ensure(
            tape.fields.len() == self.field_count && tape.digests.len() == self.digest_references,
            "profile stream counts",
        )?;
        Ok(tape)
    }

    pub fn encode(&self, proof: &ShardProof<SC>) -> Result<Vec<u8>> {
        let tape = self.tape(proof)?;
        let mut bytes = MAGIC.to_vec();
        bytes.extend([1, self.mode as u8]);
        bytes.extend(self.id());
        bytes.extend(field_bytes(&tape.fields));
        if self.mode == Mode::Raw {
            bytes.extend(tape.digests.iter().flatten());
        } else {
            let graph = Graph::build(&tape, self.mode == Mode::Dag)?;
            put_u16(&mut bytes, graph.nodes.len())?;
            for node in &graph.nodes {
                match node {
                    Node::Raw(hash) => {
                        if self.mode == Mode::Dag {
                            bytes.push(0);
                        }
                        bytes.extend(hash);
                    }
                    Node::Leaf(leaf) => {
                        bytes.push(1);
                        put_u16(&mut bytes, *leaf)?;
                    }
                    Node::Branch(left, right) => {
                        bytes.push(2);
                        put_u16(&mut bytes, *left)?;
                        put_u16(&mut bytes, *right)?;
                    }
                }
            }
            for index in graph.references {
                put_u16(&mut bytes, index)?;
            }
        }
        Ok(bytes)
    }

    /// Strict canonical decode. Bounds come exclusively from the trusted
    /// profile. Re-encoding rejects unused nodes, alternative dictionaries,
    /// aliases, trailing bytes and alternate DAG representations.
    pub fn decode(&self, packet: &[u8]) -> Result<ShardProof<SC>> {
        let maximum = HEADER
            + 4 * self.field_count
            + 40 * (self.digest_references + self.leaves.len())
            + 2 * self.digest_references
            + 2;
        ensure(packet.len() <= maximum, "packet exceeds profile maximum")?;
        let mut r = Reader { bytes: packet, at: 0 };
        ensure(
            r.take(4)? == MAGIC && r.u8()? == 1 && r.u8()? == self.mode as u8,
            "wire header/version/mode",
        )?;
        ensure(r.take(32)? == self.id(), "wire profile mismatch")?;
        let mut fields = Vec::with_capacity(self.field_count);
        for _ in 0..self.field_count {
            let value = u32::from_le_bytes(r.take(4)?.try_into().unwrap());
            ensure(u64::from(value) < F::ORDER_U64, "noncanonical KoalaBear word")?;
            fields.push(value);
        }
        let mut digests = Vec::with_capacity(self.digest_references);
        if self.mode == Mode::Raw {
            for _ in 0..self.digest_references {
                digests.push(r.take(32)?.try_into().unwrap());
            }
        } else {
            let count = r.u16()?;
            ensure(
                count <= self.digest_references + self.leaves.len(),
                "dictionary count exceeds profile",
            )?;
            let mut nodes: Vec<Digest> = Vec::with_capacity(count);
            let words = field_bytes(&fields);
            for _ in 0..count {
                let tag = if self.mode == Mode::Dag { r.u8()? } else { 0 };
                let hash = match tag {
                    0 => r.take(32)?.try_into().unwrap(),
                    1 => {
                        let range =
                            self.leaves.get(r.u16()?).ok_or(WireError("leaf range reference"))?;
                        Keccak256Hash.hash_iter(
                            words[4 * range.field_start
                                ..4 * (range.field_start + range.field_count)]
                                .iter()
                                .copied(),
                        )
                    }
                    2 => {
                        let left =
                            nodes.get(r.u16()?).ok_or(WireError("forward/invalid DAG child"))?;
                        let right =
                            nodes.get(r.u16()?).ok_or(WireError("forward/invalid DAG child"))?;
                        hash_pair(left, right)
                    }
                    _ => return Err(WireError("unknown DAG opcode")),
                };
                nodes.push(hash);
            }
            for _ in 0..self.digest_references {
                digests.push(*nodes.get(r.u16()?).ok_or(WireError("invalid digest reference"))?);
            }
        }
        ensure(r.at == packet.len(), "trailing proof bytes")?;
        let mut tape = Tape {
            fields,
            digests,
            decoding: true,
            zero: false,
            derived: self.derived_sumchecks,
            ..Default::default()
        };
        let mut proof = self.template.clone();
        let mut bundle = self.bundle.clone();
        visit_parts(&mut proof, &mut bundle, &mut tape)?;
        ensure(
            tape.f_at == tape.fields.len()
                && tape.d_at == tape.digests.len()
                && tape.metadata == self.metadata,
            "decoder schema mismatch",
        )?;
        proof.jagged_shard_proof.public_values = proof.public_values.clone();
        proof.jagged_shard_proof.main_commitment =
            root_felts(&bundle.commit.original_commitment.roots()[0]);
        proof.jagged_shard_proof.evaluation_proof = EvaluationProof::Bytes(bundle.to_bytes());
        ensure(self.encode(&proof)? == packet, "noncanonical proof encoding")?;
        Ok(proof)
    }
}

fn split(proof: &ShardProof<SC>) -> Result<(ShardProof<SC>, Bundle)> {
    let mut proof = proof.clone();
    let shard = &mut proof.jagged_shard_proof;
    ensure(shard.public_values == proof.public_values, "public-value copies differ")?;
    let bytes = match &shard.evaluation_proof {
        EvaluationProof::Bytes(bytes) => bytes,
        _ => return Err(WireError("terminal requires Bytes WHIR")),
    };
    let bundle = Bundle::from_bytes_for_verification(bytes)
        .ok_or(WireError("invalid native WHIR encoding"))?;
    ensure(
        bundle.whir_proof.is_some() && bundle.commit.original_commitment.roots().len() == 1,
        "terminal WHIR/root shape",
    )?;
    ensure(
        shard.main_commitment == root_felts(&bundle.commit.original_commitment.roots()[0]),
        "main commitment seed mismatch",
    )?;
    shard.public_values.clear(); // exact alias of outer public values
    shard.main_commitment = [F::ZERO; 8]; // derived from full root after decode
    shard.evaluation_proof = EvaluationProof::Empty;
    Ok((proof, bundle))
}

fn field_bytes(fields: &[u32]) -> Vec<u8> {
    fields.iter().flat_map(|v| v.to_le_bytes()).collect()
}
fn put_u16(bytes: &mut Vec<u8>, value: usize) -> Result<()> {
    bytes.extend(u16::try_from(value).map_err(|_| WireError("u16 overflow"))?.to_le_bytes());
    Ok(())
}
fn hash_pair(left: &Digest, right: &Digest) -> Digest {
    Keccak256Hash.hash_iter(left.iter().chain(right).copied())
}
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(count).ok_or(WireError("length overflow"))?;
        let bytes = self.bytes.get(self.at..end).ok_or(WireError("truncated proof"))?;
        self.at = end;
        Ok(bytes)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<usize> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as usize)
    }
}

#[derive(Default)]
struct Tape {
    fields: Vec<u32>,
    digests: Vec<Digest>,
    metadata: Vec<u8>,
    leaves: Vec<LeafRange>,
    f_at: usize,
    d_at: usize,
    decoding: bool,
    zero: bool,
    derived: bool,
}
impl Tape {
    fn writer(zero: bool, derived: bool) -> Self {
        Self { zero, derived, ..Default::default() }
    }
    fn label(&mut self, label: &str) {
        self.metadata.extend((label.len() as u64).to_le_bytes());
        self.metadata.extend(label.as_bytes());
    }
    fn integer(&mut self, value: usize) {
        self.metadata.extend((value as u64).to_le_bytes());
    }
    fn field_position(&self) -> usize {
        if self.decoding {
            self.f_at
        } else {
            self.fields.len()
        }
    }
    fn digest_position(&self) -> usize {
        if self.decoding {
            self.d_at
        } else {
            self.digests.len()
        }
    }
}
trait Visit {
    fn visit(&mut self, tape: &mut Tape) -> Result<()>;
}
impl Visit for F {
    fn visit(&mut self, t: &mut Tape) -> Result<()> {
        t.label("F");
        if t.decoding {
            *self = F::from_u32(*t.fields.get(t.f_at).ok_or(WireError("field stream exhausted"))?);
            t.f_at += 1;
        } else {
            t.fields.push(self.as_canonical_u32());
            if t.zero {
                *self = F::ZERO;
            }
        }
        Ok(())
    }
}
impl Visit for E {
    fn visit(&mut self, t: &mut Tape) -> Result<()> {
        t.label("E4");
        let mut coefficients: [F; 4] = self.as_basis_coefficients_slice().try_into().unwrap();
        coefficients.visit(t)?;
        *self = E::from_basis_coefficients_fn(|i| coefficients[i]);
        Ok(())
    }
}
impl Visit for Digest {
    fn visit(&mut self, t: &mut Tape) -> Result<()> {
        t.label("H32");
        if t.decoding {
            *self = *t.digests.get(t.d_at).ok_or(WireError("digest stream exhausted"))?;
            t.d_at += 1;
        } else {
            t.digests.push(*self);
            if t.zero {
                *self = [0; 32];
            }
        }
        Ok(())
    }
}
impl<T: Visit> Visit for Vec<T> {
    fn visit(&mut self, t: &mut Tape) -> Result<()> {
        t.label("Vec");
        t.integer(self.len());
        for value in self {
            value.visit(t)?;
        }
        Ok(())
    }
}
impl<T: Visit> Visit for Option<T> {
    fn visit(&mut self, t: &mut Tape) -> Result<()> {
        t.label("Option");
        t.integer(self.is_some() as usize);
        if let Some(value) = self {
            value.visit(t)?;
        }
        Ok(())
    }
}
impl<T: Visit> Visit for Box<T> {
    fn visit(&mut self, t: &mut Tape) -> Result<()> {
        self.as_mut().visit(t)
    }
}
impl<A: Visit, B: Visit> Visit for (A, B) {
    fn visit(&mut self, t: &mut Tape) -> Result<()> {
        t.label("Pair");
        self.0.visit(t)?;
        self.1.visit(t)
    }
}
impl<T: Visit> Visit for BTreeMap<String, T> {
    fn visit(&mut self, t: &mut Tape) -> Result<()> {
        t.label("Map");
        t.integer(self.len());
        for (key, value) in self {
            t.label(key);
            value.visit(t)?;
        }
        Ok(())
    }
}
macro_rules! constant { ($($ty:ty),*) => { $(impl Visit for $ty { fn visit(&mut self, t: &mut Tape) -> Result<()> { t.label(stringify!($ty)); t.integer(*self as usize); Ok(()) } })* }; }
constant!(usize, u32, u8);
macro_rules! array {
    ($ty:ty) => {
        impl<const N: usize> Visit for [$ty; N] {
            fn visit(&mut self, t: &mut Tape) -> Result<()> {
                t.label("Array");
                t.integer(N);
                for x in self {
                    x.visit(t)?;
                }
                Ok(())
            }
        }
    };
}
array!(F);
array!(E);
impl Visit for MerkleCap<F, Digest> {
    fn visit(&mut self, t: &mut Tape) -> Result<()> {
        let mut roots = self.roots().to_vec();
        roots.visit(t)?;
        *self = Self::new(roots);
        Ok(())
    }
}
impl Visit for FoldOrientation {
    fn visit(&mut self, t: &mut Tape) -> Result<()> {
        ensure(*self == FoldOrientation::Msb, "only canonical MSB folding is supported")?;
        t.label("MSB");
        Ok(())
    }
}
macro_rules! structure { ($ty:ty {$($field:ident),* $(,)?}) => { impl Visit for $ty { fn visit(&mut self, t: &mut Tape) -> Result<()> { t.label(stringify!($ty)); $(t.label(stringify!($field)); self.$field.visit(t)?;)* Ok(()) } } }; }
impl Visit for zkm_pcs::septic_extension::SepticExtension<F> {
    fn visit(&mut self, t: &mut Tape) -> Result<()> {
        self.0.visit(t)
    }
}
impl Visit for zkm_pcs::septic_digest::SepticDigest<F> {
    fn visit(&mut self, t: &mut Tape) -> Result<()> {
        self.0.visit(t)
    }
}
structure!(zkm_pcs::septic_curve::SepticCurve<F> { x, y });
structure!(zkm_pcs::AirOpenedValues<E> { local, next });
structure!(zkm_pcs::ChipOpenedValues<F, E> { preprocessed, main, permutation, quotient, global_cumulative_sum, local_cumulative_sum, log_degree });
structure!(zkm_pcs::ShardOpenedValues < F, E > { chips });
structure!(zkm_pcs::shard_level::shard_proof::ChipCumulativeSums<F, E> { local, global });
structure!(zkm_pcs::shard_level::types::LogUpGkrOutput<E> { numerator, denominator });
structure!(zkm_pcs::shard_level::types::LogupGkrRoundProof<E> { numerator_0, numerator_1, denominator_0, denominator_1, sumcheck_proof });
structure!(zkm_pcs::shard_level::types::ChipEvaluation<E> { log_degree, main_trace_evaluations_full, preprocessed_trace_evaluations_full });
structure!(zkm_pcs::shard_level::types::LogUpEvaluations<E> { point, chip_openings });
structure!(zkm_pcs::shard_level::types::LogupGkrProof<F, E> { circuit_output, round_proofs, logup_evaluations, witness });
structure!(zkm_pcs::shard_level::types::UnivariatePolynomial<E> { coefficients });
structure!(zkm_pcs::jagged_sumcheck::JaggedReductionRound<E> { evals });
structure!(zkm_pcs::jagged_sumcheck::JaggedReductionProof<E> { rounds, eval_point, q_at_z });
structure!(zkm_pcs::jagged_eval_sumcheck::JaggedSumcheckEvalProof<E> { partial_sumcheck_proof });
structure!(zkm_pcs::jagged_pcs::jagged::PackingMeta {
    offsets,
    total_values,
    log_dense_size,
    column_counts,
    round_counts,
    padding_heights
});
structure!(zkm_pcs::jagged_pcs::JaggedCommitGeneric<M> { original_commitment, chip_dims, area, log_stacking_height });
structure!(zkm_pcs::basefold::proof::MerkleOpening < F, M > { leaves });
structure!(zkm_pcs::basefold::proof::BasefoldProof<F, E, M> { univariate_messages, fri_commitments, component_polynomials_query_openings_and_proofs, query_phase_openings_and_proofs, final_poly, pow_witness, batch_grinding_witness });
structure!(zkm_pcs::basefold::stacked::StackedBasefoldProof<F, E, M> { basefold_proof, batch_evaluations });
structure!(zkm_pcs::whir::proof::WhirProof<F, E, M> { round_sumcheck_polys, round_ood_answers, round_commitments, round_query_openings, final_poly, final_sumcheck_polys, folding_pow, final_pow });
structure!(zkm_pcs::whir::stacked::StackedWhirProof<F, E, M> { whir_proof, batch_evaluations, batch_grinding_witness });
structure!(Bundle {
    reduction,
    basefold_proof,
    whir_proof,
    y_per_chip,
    commit,
    packing,
    jagged_eval,
    preceding_commits,
    extra_reduction,
    extra_basefold_proof,
    extra_commit,
    extra_packing,
    extra_jagged_eval,
    groups
});
impl Visit for zkm_pcs::whir::proof::SumcheckPoly<E> {
    fn visit(&mut self, t: &mut Tape) -> Result<()> {
        self.0.visit(t)
    }
}
impl Visit for zkm_pcs::whir::proof::ProofOfWork<F> {
    fn visit(&mut self, t: &mut Tape) -> Result<()> {
        self.0.visit(t)
    }
}

impl Visit for zkm_pcs::basefold::proof::LeafOpening<F, M> {
    fn visit(&mut self, t: &mut Tape) -> Result<()> {
        t.label("Leaf");
        let start = t.field_position();
        self.values.visit(t)?;
        let count = t.field_position() - start;
        let path_start = t.digest_position();
        self.proof.visit(t)?;
        t.leaves.push(LeafRange {
            field_start: start,
            field_count: count,
            path_start,
            path_len: self.proof.len(),
        });
        Ok(())
    }
}

impl Visit for PartialSumcheckProof<E> {
    fn visit(&mut self, t: &mut Tape) -> Result<()> {
        t.label("PartialSumcheck");
        if !t.derived {
            self.univariate_polys.visit(t)?;
            self.claimed_sum.visit(t)?;
            return self.point_and_eval.visit(t);
        }
        t.label("derived-c1-and-final-eval/MSB");
        ensure(
            self.point_and_eval.0.len() == self.univariate_polys.len(),
            "sumcheck point/round count",
        )?;
        let original_claim = self.claimed_sum;
        let original_point = self.point_and_eval.0.clone();
        self.claimed_sum.visit(t)?;
        self.point_and_eval.0.visit(t)?;
        let mut claim = if t.decoding { self.claimed_sum } else { original_claim };
        let point = if t.decoding { self.point_and_eval.0.clone() } else { original_point };
        t.integer(self.univariate_polys.len());
        for (round, poly) in self.univariate_polys.iter_mut().enumerate() {
            let original = poly.coefficients.clone();
            let n = original.len();
            ensure(n >= 2, "unsupported constant/empty sumcheck polynomial")?;
            t.integer(n);
            for (i, coefficient) in poly.coefficients.iter_mut().enumerate() {
                if i != 1 {
                    coefficient.visit(t)?;
                }
            }
            let mut coefficients = if t.decoding { poly.coefficients.clone() } else { original };
            let c1 =
                claim - coefficients[0].double() - coefficients.iter().skip(2).copied().sum::<E>();
            if t.decoding {
                poly.coefficients[1] = c1;
            } else {
                ensure(coefficients[1] == c1, "sumcheck endpoint identity")?;
                if t.zero {
                    poly.coefficients[1] = E::ZERO;
                }
            }
            coefficients[1] = c1;
            // The production verifier stores MSB-fold challenges in reverse
            // round order (insert(0, alpha)), including GKR and jagged eval.
            let alpha = point[point.len() - 1 - round];
            claim = coefficients.iter().rev().fold(E::ZERO, |sum, &c| sum * alpha + c);
        }
        if t.decoding {
            self.point_and_eval.1 = claim;
        } else {
            ensure(self.point_and_eval.1 == claim, "sumcheck final evaluation")?;
            if t.zero {
                self.point_and_eval.1 = E::ZERO;
            }
        }
        Ok(())
    }
}

fn visit_parts(proof: &mut ShardProof<SC>, bundle: &mut Bundle, t: &mut Tape) -> Result<()> {
    t.label("KeccakTerminal/v1");
    proof.public_values.visit(t)?;
    let s: &mut JaggedShardProof<F, E> = &mut proof.jagged_shard_proof;
    // The split() precondition binds both aliases, and decode restores them.
    t.label("inner-PV-alias/derived-main-seed");
    s.logup_gkr_proof.visit(t)?;
    s.zerocheck_proof.visit(t)?;
    s.opened_values.visit(t)?;
    s.chip_heights.visit(t)?;
    s.chip_cumulative_sums.visit(t)?;
    s.fold_orientation.visit(t)?;
    s.row_counts.visit(t)?;
    s.padding_column_counts.visit(t)?;
    s.jagged_original_commitment.visit(t)?;
    s.preprocessed_original_commitment.visit(t)?;
    s.preprocessed_row_counts.visit(t)?;
    s.padding_row_heights.visit(t)?;
    bundle.visit(t)
}

enum Node {
    Raw(Digest),
    Leaf(usize),
    Branch(usize, usize),
}
struct Graph {
    nodes: Vec<Node>,
    references: Vec<usize>,
}
impl Graph {
    fn build(tape: &Tape, dag: bool) -> Result<Self> {
        let original: BTreeSet<Digest> = tape.digests.iter().copied().collect();
        if !dag {
            let hashes: Vec<_> = original.into_iter().collect();
            let ids: BTreeMap<_, _> =
                hashes.iter().enumerate().map(|(i, &hash)| (hash, i)).collect();
            return Ok(Self {
                nodes: hashes.into_iter().map(Node::Raw).collect(),
                references: tape.digests.iter().map(|h| ids[h]).collect(),
            });
        }
        let words = field_bytes(&tape.fields);
        let mut heights: BTreeMap<Digest, usize> =
            original.iter().map(|&hash| (hash, usize::MAX)).collect();
        let mut leaf_ids = BTreeMap::new();
        let mut maximum = 0;
        for (i, leaf) in tape.leaves.iter().enumerate() {
            let hash = Keccak256Hash.hash_iter(
                words[4 * leaf.field_start..4 * (leaf.field_start + leaf.field_count)]
                    .iter()
                    .copied(),
            );
            heights.insert(hash, 0);
            leaf_ids.entry(hash).or_insert(i);
            for (level, &hash) in
                tape.digests[leaf.path_start..leaf.path_start + leaf.path_len].iter().enumerate()
            {
                heights.entry(hash).and_modify(|h| *h = (*h).min(level)).or_insert(level);
            }
            maximum = maximum.max(leaf.path_len);
        }
        let mut recipes: BTreeMap<Digest, (Digest, Digest)> = BTreeMap::new();
        // Discover only exact Keccak identities among already authenticated
        // nodes. No transcript/query-index guessing or hash truncation occurs.
        // Decoder/EVM execution follows explicit backward references, O(nodes).
        for level in 0..=maximum {
            let children: Vec<_> =
                heights.iter().filter(|(_, h)| **h == level).map(|(&h, _)| h).collect();
            for left in &children {
                for right in &children {
                    let parent = hash_pair(left, right);
                    if original.contains(&parent) && heights[&parent] > level {
                        heights.insert(parent, level + 1);
                        recipes
                            .entry(parent)
                            .and_modify(|pair| *pair = (*pair).min((*left, *right)))
                            .or_insert((*left, *right));
                    }
                }
            }
        }
        // Include leaf hashes only if an exact parent recipe needs them.
        let mut needed = original.clone();
        for (parent, (left, right)) in &recipes {
            if heights[parent] > heights[left].max(heights[right]) {
                needed.insert(*left);
                needed.insert(*right);
            }
        }
        ensure(needed.len() < 65_536, "DAG exceeds u16 bounds")?;
        let mut hashes: Vec<_> = needed.into_iter().collect();
        hashes.sort_by_key(|hash| (heights[hash], *hash));
        let ids: BTreeMap<_, _> = hashes.iter().enumerate().map(|(i, &hash)| (hash, i)).collect();
        let mut nodes = Vec::with_capacity(hashes.len());
        for (id, hash) in hashes.iter().enumerate() {
            let node = if let Some(&leaf) = leaf_ids.get(hash) {
                Node::Leaf(leaf)
            } else if let Some((left, right)) = recipes.get(hash) {
                match (ids.get(left), ids.get(right)) {
                    (Some(&l), Some(&r)) if l < id && r < id => Node::Branch(l, r),
                    _ => Node::Raw(*hash),
                }
            } else {
                Node::Raw(*hash)
            };
            nodes.push(node);
        }
        Ok(Self { nodes, references: tape.digests.iter().map(|hash| ids[hash]).collect() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_authentication_dag_reconstructs_hashes() {
        let a = [1; 32];
        let b = [2; 32];
        let ab = hash_pair(&a, &b);
        let c = [3; 32];
        let cd = hash_pair(&c, &[4; 32]);
        let root = hash_pair(&ab, &cd);
        let tape = Tape {
            fields: vec![],
            digests: vec![a, ab, c, cd, root, a, ab, c],
            leaves: vec![
                LeafRange { field_start: 0, field_count: 0, path_start: 0, path_len: 2 },
                LeafRange { field_start: 0, field_count: 0, path_start: 2, path_len: 2 },
            ],
            ..Default::default()
        };
        let graph = Graph::build(&tape, true).unwrap();
        assert!(graph.nodes.iter().any(|n| matches!(n, Node::Branch(_, _))));
        let mut nodes = Vec::new();
        for node in graph.nodes {
            nodes.push(match node {
                Node::Raw(h) => h,
                Node::Leaf(_) => Keccak256Hash.hash_iter([]),
                Node::Branch(a, b) => hash_pair(&nodes[a], &nodes[b]),
            });
        }
        assert_eq!(graph.references.iter().map(|&i| nodes[i]).collect::<Vec<_>>(), tape.digests);
    }
    #[test]
    fn derived_sumcheck_restores_exact_coefficients() {
        let mut proof = PartialSumcheckProof {
            univariate_polys: vec![
                zkm_pcs::shard_level::types::UnivariatePolynomial {
                    coefficients: vec![E::from_u32(3), E::from_u32(5), E::from_u32(7)],
                },
                zkm_pcs::shard_level::types::UnivariatePolynomial {
                    coefficients: vec![E::from_u32(10), E::from_u32(15), E::from_u32(6)],
                },
            ],
            claimed_sum: E::from_u32(18),
            point_and_eval: (vec![E::from_u32(3), E::from_u32(2)], E::from_u32(109)),
        };
        let bytes = bincode::serialize(&proof).unwrap();
        let mut tape = Tape::writer(true, true);
        proof.visit(&mut tape).unwrap();
        assert_eq!(tape.fields.len(), 28); // claim + two points + four coefficients
        tape.decoding = true;
        tape.zero = false;
        tape.metadata.clear();
        proof.visit(&mut tape).unwrap();
        assert_eq!(bincode::serialize(&proof).unwrap(), bytes);
        proof.univariate_polys[0].coefficients[1] += E::ONE;
        assert!(proof.visit(&mut Tape::writer(false, true)).is_err());
    }
}

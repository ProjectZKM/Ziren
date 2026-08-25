//! WHIR proof types, mirroring `slop_whir::WhirProof` / `ParsedCommitment` on
//! Ziren's field types.
//!
//! The shape a shard proof would carry once WHIR replaces BaseFold as the core
//! PCS.  Phase 1 populates only `ParsedCommitment` (the OOD commit); the
//! per-round sumcheck / query fields are filled by the folding prover (phase
//! 2).

use p3_commit::Mmcs;
use p3_field::{ExtensionField, Field};
use serde::{Deserialize, Serialize};

use crate::basefold::proof::MerkleOpening;

/// A degree-`d` univariate polynomial's coefficients — one sumcheck round
/// message.  Mirrors `slop_whir::SumcheckPoly`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SumcheckPoly<EF>(pub Vec<EF>);

/// A proof-of-work witness for one grinding step.  Mirrors
/// `slop_whir::ProofOfWork`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofOfWork<F>(pub F);

/// The parsed commitment: the Merkle root(s) plus the OOD points and the
/// prover-supplied answers at them.  Mirrors `slop_whir::ParsedCommitment`.
///
/// This is the WHIR-specific commit output — BaseFold's commit is just the
/// root.  The OOD answers are drawn into the transcript and later constrained
/// by the folding sumcheck, which is how WHIR trades in-domain queries for OOD
/// evaluations.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "EF: Serialize, C: Serialize",
    deserialize = "EF: Deserialize<'de>, C: Deserialize<'de>"
))]
pub struct ParsedCommitment<F, EF, C> {
    /// One Merkle root per committed round.
    pub commitment: Vec<C>,
    /// The OOD sample points (each a full evaluation point in `EF`).
    pub ood_points: Vec<Vec<EF>>,
    /// The claimed MLE evaluations at `ood_points`.
    pub ood_answers: Vec<EF>,
    #[serde(skip)]
    pub _f: core::marker::PhantomData<F>,
}

/// The full WHIR opening proof.  Mirrors `slop_whir::WhirProof`.
///
/// Phase-1 status: the type is complete for parity with the upstream `WhirProof`; the folding
/// prover (phase 2) populates `round_sumcheck_polys` / `round_commitments` /
/// query openings, and the verifier (phase 3) consumes them.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct WhirProof<F: Field, EF: ExtensionField<F>, MT: Mmcs<F>> {
    /// Per-round folding-sumcheck messages (outer = round, inner = the
    /// `folding_factor` univariate messages of that round).
    pub round_sumcheck_polys: Vec<Vec<SumcheckPoly<EF>>>,
    /// Per-round OOD answers for the newly committed folded polynomial.
    pub round_ood_answers: Vec<Vec<EF>>,
    /// Per-round Merkle roots of the folded codewords.
    pub round_commitments: Vec<MT::Commitment>,
    /// Per-round openings of the previous round's codeword at the query
    /// indices (the `component_polynomials` analogue).
    pub round_query_openings: Vec<MerkleOpening<F, MT>>,
    /// The final small polynomial, sent in the clear.
    pub final_poly: Vec<EF>,
    /// The final folding-sumcheck messages.
    pub final_sumcheck_polys: Vec<SumcheckPoly<EF>>,
    /// Grinding witnesses: per-round folding PoW then the final query PoW.
    pub folding_pow: Vec<ProofOfWork<F>>,
    /// Out-of-domain (OOD) + query proof-of-work for the last round.
    pub final_pow: ProofOfWork<F>,
}

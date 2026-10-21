//! The binary stage's WHIR domain, with query points from traced bits.
//!
//! The additive domain's point at an index is the sum of the Cantor basis
//! vectors the index's bits select, and WHIR's query point is the subspace
//! polynomials at that point.  Both are linear in the index's bits, so the
//! point is computed from the bits the transcript drew, not from the
//! integer: the program evaluates every proof's own query points.

use p3_binary_dft::subspace_polynomial;
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_binary_pcs::whir::{BinaryWhirAlphabet, BooleanWhirDomain};
use p3_commit::Encoder;
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::point::Point;
use p3_whir::parameters::SecurityAssumption;
use p3_whir::{WhirDomain, WhirQueryPoint};

use crate::queries::{self, User};
use crate::traced::Traced;

/// The binary stage's WHIR domain over traced values.
#[derive(Clone, Copy, Debug, Default)]
pub struct TracedDomain;

impl Encoder<Traced> for TracedDomain {
    fn encode_batch(
        &self,
        _message: RowMajorMatrix<Traced>,
        _log_inv_rate: usize,
    ) -> RowMajorMatrix<Traced> {
        panic!("the recorded verifier does not encode")
    }
}

impl WhirDomain<Traced, Traced> for TracedDomain {
    fn protocol_id(&self) -> &'static [u8] {
        <BinaryField128 as BinaryWhirAlphabet>::DOMAIN_ID
    }

    fn supports_security_assumption(&self, assumption: SecurityAssumption) -> bool {
        <BooleanWhirDomain as WhirDomain<BinaryField128, BinaryField128>>::supports_security_assumption(
            &BooleanWhirDomain::default(),
            assumption,
        )
    }

    fn stratified_queries(&self) -> bool {
        <BooleanWhirDomain as WhirDomain<BinaryField128, BinaryField128>>::stratified_queries(
            &BooleanWhirDomain::default(),
        )
    }

    fn max_log_domain_size(&self) -> usize {
        <BooleanWhirDomain as WhirDomain<BinaryField128, BinaryField128>>::max_log_domain_size(
            &BooleanWhirDomain::default(),
        )
    }

    fn encode_extension_batch_padded(
        &self,
        _message: RowMajorMatrix<Traced>,
        _log_inv_rate: usize,
    ) -> RowMajorMatrix<Traced> {
        panic!("the recorded verifier does not encode")
    }

    /// The subspace polynomials at the domain point the drawn bits select.
    fn query_point(
        &self,
        log_domain_size: usize,
        num_variables: usize,
        index: usize,
    ) -> WhirQueryPoint<Traced> {
        let bits = queries::take_for(User::Point, index, log_domain_size);
        let point = bits
            .iter()
            .enumerate()
            .map(|(r, &bit)| bit * Traced::cantor_basis(r))
            .fold(Traced::default(), |acc, term| acc + term);
        WhirQueryPoint::Multilinear(Point::new(
            (0..num_variables).rev().map(|j| subspace_polynomial(j, point)).collect(),
        ))
    }
}

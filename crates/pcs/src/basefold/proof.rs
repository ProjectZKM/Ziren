//! BaseFold proof structure.
//!
//! Per-round shape (much simpler than WHIR):
//!   * `univariate_messages[i]` holds the two end-point evaluations
//!     `[g(...,0), g(...,1)]` of the i-th sumcheck round
//!   * `fri_commitments[i]` is the single Merkle digest committing
//!     to the folded codeword after round i
//!   * `component_polynomials_query_openings_and_proofs[r]` opens the
//!     original (round-r) commitment at every query index
//!   * `query_phase_openings_and_proofs[i]` opens the i-th round
//!     commitment at the (now bit-shifted) query indices
//!   * `final_poly` is the constant remaining after the commit phase
//!   * `pow_witness` / `batch_grinding_witness` are PoW grinding
//!     witnesses

use alloc::vec::Vec;

use p3_commit::Mmcs;
use p3_field::{ExtensionField, Field};
use serde::{Deserialize, Serialize};

/// Opening of a single Merkle leaf at one query index.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct LeafOpening<F: Field, MT: Mmcs<F>> {
    /// Opened leaf values for each matrix in the committed batch.
    /// For component-poly commits this is `Vec<Vec<F>>` with one
    /// inner vec per Mle (each of width `EF::DIMENSION`); for the
    /// commit-phase rounds it's a single matrix with width
    /// `2 * EF::DIMENSION`.  Encoded by [`uniform_rows`].
    #[serde(with = "uniform_rows")]
    pub values: Vec<Vec<F>>,
    pub proof: MT::Proof,
}

/// The encoding of a leaf's opened rows, one row per committed matrix.
///
/// Every matrix of a first-round WHIR leaf is one stripe of the same width
/// `2^k0`, so the nested form spends a length per stripe, as many bytes as
/// the values of a narrow stripe.  A leaf whose rows share a non-zero width
/// `w` is written as `Uniform { w, values }` with the `S · w` values flat,
/// one length for the whole leaf; any other leaf keeps the nested form.
/// Decoding a uniform leaf requires `w > 0` and `w | |values|`, so a
/// malformed proof is a decode error, never a panic.
pub mod uniform_rows {
    use alloc::vec::Vec;

    use serde::{
        de::Error as _, ser::SerializeSeq, Deserialize, Deserializer, Serialize, Serializer,
    };

    #[derive(Deserialize)]
    #[serde(bound = "F: Deserialize<'de>")]
    enum Rows<F> {
        Uniform { width: u32, values: Vec<F> },
        Ragged(Vec<Vec<F>>),
    }

    #[derive(Serialize)]
    #[serde(bound = "F: Serialize")]
    enum RowsRef<'a, F> {
        Uniform { width: u32, values: Flat<'a, F> },
        Ragged(&'a [Vec<F>]),
    }

    struct Flat<'a, F>(&'a [Vec<F>]);

    impl<F: Serialize> Serialize for Flat<'_, F> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut seq = s.serialize_seq(Some(self.0.iter().map(Vec::len).sum()))?;
            for v in self.0.iter().flatten() {
                seq.serialize_element(v)?;
            }
            seq.end()
        }
    }

    pub fn serialize<F: Serialize, S: Serializer>(
        rows: &[Vec<F>],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let width = rows.first().map_or(0, Vec::len);
        let uniform =
            width > 0 && u32::try_from(width).is_ok() && rows.iter().all(|r| r.len() == width);
        if uniform {
            RowsRef::Uniform { width: width as u32, values: Flat(rows) }.serialize(s)
        } else {
            RowsRef::Ragged(rows).serialize(s)
        }
    }

    pub fn deserialize<'de, F: Deserialize<'de> + Clone, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Vec<Vec<F>>, D::Error> {
        match Rows::<F>::deserialize(d)? {
            Rows::Ragged(rows) => Ok(rows),
            Rows::Uniform { width, values } => {
                let w = width as usize;
                if w == 0 || values.len() % w != 0 {
                    return Err(D::Error::custom("leaf rows: width does not divide the values"));
                }
                Ok(values.chunks_exact(w).map(<[F]>::to_vec).collect())
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use alloc::vec;
        use alloc::vec::Vec;

        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Leaf(#[serde(with = "super")] Vec<Vec<u32>>);

        fn round_trip(rows: Vec<Vec<u32>>) -> usize {
            let bytes = bincode::serialize(&Leaf(rows.clone())).unwrap();
            let back: Leaf = bincode::deserialize(&bytes).unwrap();
            assert_eq!(back.0, rows);
            bytes.len()
        }

        /// Uniform, ragged and empty leaves decode to what was encoded, and a
        /// uniform leaf of `S` rows of width `w` costs one length instead of
        /// `S`: 64 stripes of width 4 shrink from 1,544 to 1,040 bytes.
        #[test]
        fn uniform_rows_round_trip() {
            let uniform: Vec<Vec<u32>> = (0..64).map(|i| vec![i, i + 1, i + 2, i + 3]).collect();
            let nested = bincode::serialize(&uniform).unwrap().len();
            let flat = round_trip(uniform);
            assert_eq!((nested, flat), (1544, 1040));
            round_trip(vec![vec![1, 2], vec![3]]);
            round_trip(vec![]);
            round_trip(vec![vec![], vec![]]);
            round_trip(vec![vec![7; 256]]);
        }

        /// A uniform leaf whose width is zero or does not divide its values is
        /// a decode error, not a panic.
        #[test]
        fn uniform_rows_rejects_a_malformed_width() {
            for (width, n) in [(0u32, 0usize), (0, 4), (3, 4)] {
                let mut bytes = 0u32.to_le_bytes().to_vec();
                bytes.extend(width.to_le_bytes());
                bytes.extend((n as u64).to_le_bytes());
                for i in 0..n as u32 {
                    bytes.extend(i.to_le_bytes());
                }
                assert!(bincode::deserialize::<Leaf>(&bytes).is_err(), "width {width}, {n} values");
            }
        }
    }
}

/// All openings for one commitment, one entry per query index.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MerkleOpening<F: Field, MT: Mmcs<F>> {
    pub leaves: Vec<LeafOpening<F, MT>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct BasefoldProof<F: Field, EF: ExtensionField<F>, MT: Mmcs<F>> {
    pub univariate_messages: Vec<[EF; 2]>,
    pub fri_commitments: Vec<MT::Commitment>,
    /// Opens each round's original commitment at the query indices.
    pub component_polynomials_query_openings_and_proofs: Vec<MerkleOpening<F, MT>>,
    /// Opens each commit-phase round's Merkle tree at the (shifted)
    /// query indices.
    pub query_phase_openings_and_proofs: Vec<MerkleOpening<F, MT>>,
    pub final_poly: EF,
    pub pow_witness: F,
    pub batch_grinding_witness: F,
}

//! A shard's main traces, keyed by chip name.

use p3_matrix::dense::RowMajorMatrix;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};

/// A collection of traces.
///
/// The same shape as SP1's `hypercube::prover::Traces`: a newtype over
/// `BTreeMap<String, _>` with the field named `named_traces`, `Deref`,
/// `DerefMut` and `IntoIterator`, and no other API — callers build it with the
/// struct literal.
///
/// It is a type rather than a `Vec<(String, RowMajorMatrix<F>)>` because the
/// commit path depends on two properties the `Vec` left to convention:
///
///  * **Order.** The chip set is committed and observed in alphabetical order,
///    and the recursion verifier's compile-time `column_counts` /
///    `opened_values` are in that same order. A `BTreeMap` *is* that order.
///
///  * **Uniqueness.** `commit_traces` zips the chip slice and the trace views
///    positionally, so a repeated name shifts every later pair and commits
///    traces against the wrong AIRs.
///
/// One difference from SP1 that is deliberate: SP1 stores an already-padded
/// `PaddedMle`, because its trace generator pads (and copies to the backend) at
/// generation time. Ziren pads later, in `commit`, where the device path also
/// supplies baked heights for width-0 chips, so the element here is the raw
/// `RowMajorMatrix` and `named_padded_traces` does the wrap.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(bound(serialize = "F: Serialize", deserialize = "F: Deserialize<'de>"))]
pub struct Traces<F> {
    /// The traces for each chip.
    pub named_traces: BTreeMap<String, RowMajorMatrix<F>>,
}

impl<F> IntoIterator for Traces<F> {
    type Item = (String, RowMajorMatrix<F>);
    type IntoIter = <BTreeMap<String, RowMajorMatrix<F>> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.named_traces.into_iter()
    }
}

impl<F> Deref for Traces<F> {
    type Target = BTreeMap<String, RowMajorMatrix<F>>;

    fn deref(&self) -> &Self::Target {
        &self.named_traces
    }
}

impl<F> DerefMut for Traces<F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.named_traces
    }
}

#[cfg(test)]
mod tests {
    use super::Traces;
    use p3_matrix::dense::RowMajorMatrix;

    /// Traces are the largest thing the prover moves — a shard's main traces
    /// run to hundreds of millions of cells — so building a `Traces` must MOVE
    /// each matrix, never copy its cells.
    ///
    /// `RowMajorMatrix` owns a `Vec`, so a move relocates the 3-word handle and
    /// leaves the allocation alone. This pins that: the backing pointer a
    /// matrix had before it went into the map is the pointer it still has
    /// coming out. If anyone turns one of these steps into a `clone`, the
    /// allocation changes and this fails.
    #[test]
    fn building_traces_moves_cells_rather_than_copying_them() {
        let cells: Vec<u32> = (0..4096).collect();
        let before = cells.as_ptr();
        let m = RowMajorMatrix::new(cells, 16);

        let traces =
            Traces { named_traces: [("Cpu".to_string(), m)].into_iter().collect() };
        assert_eq!(traces.len(), 1);

        let out: Vec<RowMajorMatrix<u32>> = traces.into_iter().map(|(_, mat)| mat).collect();
        assert_eq!(out[0].values.as_ptr(), before, "the trace was copied, not moved");
    }

    #[test]
    fn a_repeated_chip_name_cannot_survive() {
        // The property the `Vec` form could not express: `commit_traces` zips
        // chips and traces positionally, so two entries under one name would
        // shift every later pair.
        let t = Traces {
            named_traces: [
                ("Cpu".to_string(), RowMajorMatrix::new(vec![1u32; 8], 4)),
                ("Cpu".to_string(), RowMajorMatrix::new(vec![2u32; 8], 4)),
            ]
            .into_iter()
            .collect(),
        };
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn iteration_is_name_ordered() {
        // The commit order the recursion verifier's compile-time `column_counts`
        // assume, with no sort at the call site.
        let t = Traces {
            named_traces: [
                ("ShiftLeft".to_string(), RowMajorMatrix::new(vec![0u32; 4], 4)),
                ("AddSub".to_string(), RowMajorMatrix::new(vec![0u32; 4], 4)),
                ("Memory".to_string(), RowMajorMatrix::new(vec![0u32; 4], 4)),
            ]
            .into_iter()
            .collect(),
        };
        let names: Vec<&str> = t.keys().map(String::as_str).collect();
        assert_eq!(names, ["AddSub", "Memory", "ShiftLeft"]);
    }
}

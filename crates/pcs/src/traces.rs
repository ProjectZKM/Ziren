//! A shard's main traces, keyed by chip name.

use p3_matrix::dense::RowMajorMatrix;
use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};

/// The main traces of one shard, keyed by chip name.
///
/// This is the shape SP1 uses (`hypercube::prover::Traces`), and it is a type
/// rather than a `Vec<(String, RowMajorMatrix<F>)>` for two reasons that the
/// commit path depends on:
///
///  * **Order.** The chip set is committed and observed in alphabetical order,
///    and the recursion verifier's compile-time `column_counts` /
///    `opened_values` are in that same order. A `BTreeMap` *is* that order, so
///    the commit cannot forget to establish it. As a `Vec` it was a convention
///    re-imposed by a `sort_by` -- and a second, dead sort by height had
///    accumulated in front of it.
///
///  * **Uniqueness.** `commit_traces` zips the chip slice and the trace views
///    positionally. A repeated name shifts every later pair and commits traces
///    against the wrong AIRs. A map makes that unrepresentable instead of
///    leaving it to an assert.
///
/// Deref gives the whole `BTreeMap` API, so call sites read as they did.
#[derive(Debug, Clone, Default)]
pub struct Traces<F> {
    /// The trace for each chip, by name.
    pub named_traces: BTreeMap<String, RowMajorMatrix<F>>,
}

impl<F> Traces<F> {
    #[must_use]
    pub fn new() -> Self
    where
        F: Clone,
    {
        Self { named_traces: BTreeMap::new() }
    }

    /// Insert a chip's trace.
    ///
    /// Returns the previous trace for `name`, which is always `None` for a
    /// well-formed shard: a chip generates one trace. A `Some` here is the
    /// duplicate this type exists to make visible.
    pub fn insert(&mut self, name: String, trace: RowMajorMatrix<F>) -> Option<RowMajorMatrix<F>> {
        self.named_traces.insert(name, trace)
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

impl<F> IntoIterator for Traces<F> {
    type Item = (String, RowMajorMatrix<F>);
    type IntoIter = <BTreeMap<String, RowMajorMatrix<F>> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.named_traces.into_iter()
    }
}

/// Collecting from name/trace pairs is how the per-chip generators hand their
/// output over; a duplicate name collapses here, which is why
/// [`Traces::insert`] exists for callers that need to see it.
impl<F> FromIterator<(String, RowMajorMatrix<F>)> for Traces<F> {
    fn from_iter<I: IntoIterator<Item = (String, RowMajorMatrix<F>)>>(iter: I) -> Self {
        Self { named_traces: iter.into_iter().collect() }
    }
}

impl<F> From<Vec<(String, RowMajorMatrix<F>)>> for Traces<F> {
    fn from(v: Vec<(String, RowMajorMatrix<F>)>) -> Self {
        v.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Traces;
    use p3_matrix::dense::RowMajorMatrix;

    /// Traces are the largest thing the prover moves -- a shard's main traces
    /// run to hundreds of millions of cells -- so building a `Traces` must MOVE
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

        // Vec<(name, matrix)> -> Traces, the path `generate_traces` takes.
        let traces: Traces<u32> = vec![("Cpu".to_string(), m)].into();
        assert_eq!(traces.len(), 1);

        // ...and back out, the path `commit` takes into `named_padded_traces`.
        let out: Vec<RowMajorMatrix<u32>> =
            traces.into_iter().map(|(_, mat)| mat).collect();
        assert_eq!(out[0].values.as_ptr(), before, "the trace was copied, not moved");
    }

    #[test]
    fn a_repeated_chip_name_cannot_survive() {
        // The property the Vec form could not express: `commit_traces` zips
        // chips and traces positionally, so two entries under one name would
        // shift every later pair.
        let t: Traces<u32> = vec![
            ("Cpu".to_string(), RowMajorMatrix::new(vec![1u32; 8], 4)),
            ("Cpu".to_string(), RowMajorMatrix::new(vec![2u32; 8], 4)),
        ]
        .into();
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn iteration_is_name_ordered() {
        // The commit order the recursion verifier's compile-time column_counts
        // assume, with no sort at the call site.
        let t: Traces<u32> = vec![
            ("ShiftLeft".to_string(), RowMajorMatrix::new(vec![0u32; 4], 4)),
            ("AddSub".to_string(), RowMajorMatrix::new(vec![0u32; 4], 4)),
            ("Memory".to_string(), RowMajorMatrix::new(vec![0u32; 4], 4)),
        ]
        .into();
        let names: Vec<&str> = t.keys().map(String::as_str).collect();
        assert_eq!(names, ["AddSub", "Memory", "ShiftLeft"]);
    }
}

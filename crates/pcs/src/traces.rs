//! A shard's main traces, keyed by chip name.

use crate::multilinear::PaddedMle;
use crate::tensor::{Backend, CpuBackend};
use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};

/// A collection of traces.
///
/// A newtype over
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
///  * **Uniqueness.** One trace per chip name is what makes the name a usable
///    key at all: `commit_traces` reads the name off the key and
///    `prove_shard_with_data` looks each chip's trace up by it, so a duplicate
///    would mean two traces claiming one AIR. (This is also why `commit_traces`
///    takes a `Traces` rather than the `(&[&Chip], &[PaddedMle])` pair it used
///    to: the pair was zipped positionally, and `zip` truncates, so a length
///    mismatch committed traces against the wrong AIRs instead of failing. A map
///    cannot express that state.)
///
/// The element is a [`PaddedMle`]: the trace is wrapped once, at generation, and carries its own cube from then on. The wrap is zero-copy —
/// `Mle::from_row_major` MOVES the matrix's `Vec` — and the cube is the fixed
/// `CORE_MAX_LOG_ROW_COUNT` every stage proves at, so it is known at generation
/// and never floated per proof. Holding the raw `RowMajorMatrix` instead would
/// mean re-wrapping at each consumer and carrying the cube separately.
/// Backend-parameterised: `PaddedMle` already carries a backend (`CudaBackend` implements `Backend` in ziren-gpu), so a
/// device-resident trace map is representable. `CpuBackend` is the default, so
/// `Traces<F>` reads as before.
///
/// (`Serialize`/`Deserialize` would be needed only to cross a process
/// boundary.  `PaddedMle` is not serializable and nothing here serializes a
/// `Traces`, so those derives are omitted rather than
/// forced onto the MLE.)
#[derive(Debug, Clone, Default)]
pub struct Traces<F, A: Backend = CpuBackend> {
    /// The traces for each chip.
    pub named_traces: BTreeMap<String, PaddedMle<F, A>>,
}

impl<F, A: Backend> IntoIterator for Traces<F, A> {
    type Item = (String, PaddedMle<F, A>);
    type IntoIter = <BTreeMap<String, PaddedMle<F, A>> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.named_traces.into_iter()
    }
}

impl<F, A: Backend> Deref for Traces<F, A> {
    type Target = BTreeMap<String, PaddedMle<F, A>>;

    fn deref(&self) -> &Self::Target {
        &self.named_traces
    }
}

impl<F, A: Backend> DerefMut for Traces<F, A> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.named_traces
    }
}

#[cfg(test)]
mod tests {
    use super::Traces;
    use crate::basefold::Mle;
    use crate::multilinear::PaddedMle;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use std::sync::Arc;

    const CUBE: u32 = 5;

    fn wrap(values: Vec<KoalaBear>, width: usize) -> (PaddedMle<KoalaBear>, *const KoalaBear) {
        let m = RowMajorMatrix::new(values, width);
        let ptr = m.values.as_ptr();
        (PaddedMle::padded_with_zeros(Arc::new(Mle::from_row_major(m)), CUBE), ptr)
    }

    /// Traces are the largest thing the prover moves — a shard's main traces
    /// run to hundreds of millions of cells — so building a `Traces` must MOVE
    /// each trace, never copy its cells.
    ///
    /// `Mle::from_row_major` takes the matrix's `Vec` by value and `PaddedMle`
    /// holds it behind an `Arc`, so nothing is copied. This pins it by pointer
    /// identity: if any step in the path becomes a `clone`, the allocation
    /// changes and this fails.
    #[test]
    fn building_traces_moves_cells_rather_than_copying_them() {
        use p3_field::PrimeCharacteristicRing;
        let (pm, before) = wrap(vec![KoalaBear::ONE; 32], 8);
        let traces = Traces { named_traces: [("Cpu".to_string(), pm)].into_iter().collect() };
        assert_eq!(traces.len(), 1);

        let out: Vec<PaddedMle<KoalaBear>> = traces.into_iter().map(|(_, mle)| mle).collect();
        let after = out[0].real_trace_ref().expect("a real trace").values.as_ptr();
        assert_eq!(after, before, "the trace was copied, not moved");
    }

    #[test]
    fn a_repeated_chip_name_cannot_survive() {
        use p3_field::PrimeCharacteristicRing;
        let (a, _) = wrap(vec![KoalaBear::ONE; 8], 4);
        let (b, _) = wrap(vec![KoalaBear::TWO; 8], 4);
        let t = Traces {
            named_traces: [("Cpu".to_string(), a), ("Cpu".to_string(), b)].into_iter().collect(),
        };
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn iteration_is_name_ordered() {
        use p3_field::PrimeCharacteristicRing;
        let names = ["ShiftLeft", "AddSub", "Memory"];
        let t = Traces {
            named_traces: names
                .iter()
                .map(|n| ((*n).to_string(), wrap(vec![KoalaBear::ZERO; 4], 4).0))
                .collect(),
        };
        let got: Vec<&str> = t.keys().map(String::as_str).collect();
        assert_eq!(got, ["AddSub", "Memory", "ShiftLeft"]);
    }
}

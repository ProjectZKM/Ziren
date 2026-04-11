//! Instrumented prover that measures FRI PCS time separately and
//! runs Jagged+WHIR on the same traces for comparison.
//!
//! This gives real end-to-end numbers for FRI vs Jagged+WHIR.
//!
//! Usage: Call `prove_with_pcs_timing()` instead of the standard
//! `CpuProver::prove()` to get per-phase timing breakdown.

#[cfg(feature = "whir")]
pub mod bench {
    use std::time::Instant;

    use p3_field::extension::BinomialExtensionField;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::Matrix;

    use crate::jagged_whir_prover::prove_jagged_whir;
    use crate::whir_config::WhirVal;

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;

    /// Result of a timing comparison between FRI and Jagged+WHIR.
    #[derive(Debug, Clone)]
    pub struct PcsTimingComparison {
        /// Total FRI prove time (includes everything).
        pub fri_total_ms: u128,
        /// Time for trace generation only.
        pub trace_gen_ms: u128,
        /// Time for FRI commit (PCS-specific).
        pub fri_commit_ms: u128,
        /// Time for FRI open (includes constraint eval + PCS open).
        pub fri_open_ms: u128,
        /// Jagged+WHIR PCS time (commit + open only).
        pub whir_pcs_ms: u128,
        /// Estimated total with Jagged+WHIR replacing FRI PCS.
        pub whir_estimated_total_ms: u128,
        /// Number of chips.
        pub num_chips: usize,
        /// Total trace cells.
        pub total_cells: usize,
    }

    impl PcsTimingComparison {
        pub fn print(&self) {
            println!("\n=== FRI vs Jagged+WHIR E2E Comparison ===");
            println!("Chips: {}, Cells: {}", self.num_chips, self.total_cells);
            println!();
            println!("FRI breakdown:");
            println!("  trace gen:  {}ms", self.trace_gen_ms);
            println!("  commit:     {}ms", self.fri_commit_ms);
            println!("  open:       {}ms", self.fri_open_ms);
            println!("  total:      {}ms", self.fri_total_ms);
            println!();
            println!("Jagged+WHIR PCS: {}ms", self.whir_pcs_ms);
            println!();
            let fri_pcs = self.fri_commit_ms + self.fri_open_ms;
            let non_pcs = self.fri_total_ms.saturating_sub(fri_pcs);
            let whir_total = non_pcs + self.whir_pcs_ms;
            println!("Estimated Jagged+WHIR total: {}ms", whir_total);
            println!("  (non-PCS: {}ms + WHIR PCS: {}ms)", non_pcs, self.whir_pcs_ms);
            println!();
            let speedup = self.fri_total_ms as f64 / whir_total.max(1) as f64;
            println!("Speedup: {:.2}x", speedup);
        }
    }

    /// Run Jagged+WHIR PCS benchmark on given traces.
    ///
    /// Takes real chip traces (from generate_traces()) and measures
    /// the Jagged+WHIR batch commit+open time.
    pub fn benchmark_whir_on_traces(
        named_traces: &[(String, RowMajorMatrix<F>)],
    ) -> u128 {
        let traces_owned: Vec<(String, RowMajorMatrix<F>)> = named_traces
            .iter()
            .map(|(name, trace)| (name.clone(), trace.clone()))
            .collect();

        let timings = prove_jagged_whir::<EF>(traces_owned, 100, 1);
        timings.total_ms
    }
}

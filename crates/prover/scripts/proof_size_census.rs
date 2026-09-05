//! Byte census of a compressed proof: which parts of the ~858 KB the
//! eth-proofs client submits are PCS (WHIR openings), which are the
//! sumchecks (zerocheck, LogUp-GKR layers, jagged), and which are opened
//! values and metadata.  `soundcalc` only estimates the PCS part, so this
//! is what decides where proof-size work should go.
//!
//! Input: the bytes `reth-processor` writes with `ZIREN_COMPRESS_PROOF_OUT`
//! (bincode of the SDK's `ZKMProof`, whose `Compressed` variant is index 1
//! followed by a `ZKMReduceProof<InnerSC>`), or a bare
//! `ZKMReduceProof<InnerSC>` (`--bare`).
//!
//! Run:
//!   cargo run --release -p zkm-prover --bin proof_size_census -- <file> [--bare]

use std::collections::BTreeMap;

use serde::Serialize;
use zkm_core_executor::reduce::ZKMReduceProof;
use zkm_pcs::shard_level::shard_proof::EvaluationProof;
use zkm_prover::InnerSC;

fn sz<T: Serialize>(t: &T) -> usize {
    bincode::serialize(t).map(|b| b.len()).unwrap_or(0)
}

struct Report {
    total: usize,
    rows: Vec<(String, usize)>,
}

impl Report {
    fn row(&mut self, name: &str, bytes: usize) {
        self.rows.push((name.to_string(), bytes));
    }
    fn print(&self) {
        println!("{:<56} {:>10} {:>7}", "component", "bytes", "share");
        for (name, bytes) in &self.rows {
            println!(
                "{:<56} {:>10} {:>6.1}%",
                name,
                bytes,
                100.0 * *bytes as f64 / self.total as f64
            );
        }
        println!("{:<56} {:>10}", "TOTAL (file)", self.total);
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: proof_size_census <proof.bin> [--bare]");
    let bare = args.any(|a| a == "--bare");
    let bytes = std::fs::read(&path).expect("read proof file");
    let body: &[u8] = if bare {
        &bytes
    } else {
        let tag = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        assert_eq!(tag, 1, "expected ZKMProof::Compressed (variant 1), got variant {tag}");
        &bytes[4..]
    };
    let reduce: ZKMReduceProof<InnerSC> =
        bincode::deserialize(body).expect("deserialize ZKMReduceProof<InnerSC>");

    let mut r = Report { total: bytes.len(), rows: Vec::new() };
    r.row("vk (StarkVerifyingKey)", sz(&reduce.vk));
    r.row("proof.public_values", sz(&reduce.proof.public_values));
    let bsp = reduce.proof.basefold_shard_proof.as_ref().expect("basefold_shard_proof");
    r.row("basefold_shard_proof (all)", sz(bsp));
    r.row("  public_values", sz(&bsp.public_values));
    r.row("  main_commitment", sz(&bsp.main_commitment));
    r.row("  logup_gkr_proof", sz(&bsp.logup_gkr_proof));
    r.row("    circuit_output", sz(&bsp.logup_gkr_proof.circuit_output));
    r.row(
        &format!("    round_proofs (x{})", bsp.logup_gkr_proof.round_proofs.len()),
        sz(&bsp.logup_gkr_proof.round_proofs),
    );
    r.row("    logup_evaluations", sz(&bsp.logup_gkr_proof.logup_evaluations));
    r.row(
        &format!("  zerocheck_proof ({} rounds)", bsp.zerocheck_proof.univariate_polys.len()),
        sz(&bsp.zerocheck_proof),
    );
    r.row(
        &format!("  opened_values ({} chips)", bsp.opened_values.chips.len()),
        sz(&bsp.opened_values),
    );
    let mut ov: BTreeMap<&str, usize> = BTreeMap::new();
    for c in &bsp.opened_values.chips {
        *ov.entry("preprocessed").or_default() += sz(&c.preprocessed);
        *ov.entry("main").or_default() += sz(&c.main);
        *ov.entry("permutation").or_default() += sz(&c.permutation);
        *ov.entry("quotient").or_default() += sz(&c.quotient);
    }
    for (k, v) in ov {
        r.row(&format!("    {k}"), v);
    }
    r.row("  chip_heights", sz(&bsp.chip_heights));
    r.row("  chip_cumulative_sums", sz(&bsp.chip_cumulative_sums));
    r.row("  row_counts + padding_column_counts", sz(&bsp.row_counts) + sz(&bsp.padding_column_counts));
    match &bsp.evaluation_proof {
        EvaluationProof::Empty => r.row("  evaluation_proof (Empty)", 0),
        EvaluationProof::Bytes(b) => r.row("  evaluation_proof (Bytes)", b.len()),
        EvaluationProof::Bundle(b) => {
            r.row("  evaluation_proof (jagged bundle)", sz(b));
            r.row("    reduction (jagged sumcheck)", sz(&b.reduction));
            r.row("    jagged_eval (eval sumcheck)", sz(&b.jagged_eval));
            r.row("    basefold_proof (inner BaseFold, unused w/ WHIR)", sz(&b.basefold_proof));
            r.row("    y_per_chip", sz(&b.y_per_chip));
            r.row("    commit", sz(&b.commit));
            r.row("    packing", sz(&b.packing));
            if let Some(w) = &b.whir_proof {
                r.row("    whir_proof (stacked)", sz(w));
                r.row("      batch_evaluations", sz(&w.batch_evaluations));
                let p = &w.whir_proof;
                r.row(
                    &format!("      round_query_openings (x{} rounds)", p.round_query_openings.len()),
                    sz(&p.round_query_openings),
                );
                for (i, o) in p.round_query_openings.iter().enumerate() {
                    r.row(&format!("        round {i} ({} leaves)", o.leaves.len()), sz(o));
                    if let Some(l) = o.leaves.first() {
                        r.row(
                            &format!(
                                "          first leaf: {} matrices, {} opened felts, {} path nodes",
                                l.values.len(),
                                l.values.iter().map(|v| v.len()).sum::<usize>(),
                                l.proof.len()
                            ),
                            sz(l),
                        );
                        r.row("            values", sz(&l.values));
                        r.row("            path", sz(&l.proof));
                    }
                }
                r.row("      round_sumcheck_polys", sz(&p.round_sumcheck_polys));
                r.row("      final_sumcheck_polys", sz(&p.final_sumcheck_polys));
                r.row("      round_ood_answers", sz(&p.round_ood_answers));
                r.row("      round_commitments", sz(&p.round_commitments));
                r.row("      final_poly", sz(&p.final_poly));
                r.row("      pow", sz(&p.folding_pow) + sz(&p.final_pow));
            }
        }
    }
    r.print();
}

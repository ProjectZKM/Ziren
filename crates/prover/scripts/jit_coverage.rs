//! What a recursion JIT phase would actually cover.
//!
//! Builds real recursion programs from enumerated shapes — no proving, no
//! GPU — analyzes each one exactly as `Runtime::run` does, and reports the
//! instruction mix plus what `zkm_recursion_jit::plan` can emit.  The point
//! is to size an emitter phase BEFORE writing it: a phase that goes native
//! on a small share of a real program cannot beat the interpreter no matter
//! how good its code is.
//!
//! Run:
//!   cargo run --release --bin jit_coverage

use std::collections::BTreeMap;

use zkm_prover::components::DefaultProverComponents;
use zkm_prover::shapes::{ZKMCompressProgramShape, ZKMProofShape};
use zkm_prover::{ZKMProver, REDUCE_BATCH_SIZE, VK_MERKLE_TREE_HEIGHT};
use zkm_recursion_jit::Plan;

fn main() {
    std::panic::set_hook(Box::new(|_| {}));

    let prover = ZKMProver::<DefaultProverComponents>::new();
    let core_cfg = &zkm_core_machine::shape::CoreShapeConfig::default();
    let rec_cfg = prover.compress_shape_config.as_ref().unwrap();

    let all: Vec<ZKMProofShape> =
        ZKMProofShape::generate(core_cfg, rec_cfg, REDUCE_BATCH_SIZE).collect();
    eprintln!("[JIT-COV] {} shapes enumerated", all.len());

    // One program per category is enough to characterise the mix; the
    // categories differ in what they verify, not in the instruction set.
    let mut seen: BTreeMap<&'static str, ()> = BTreeMap::new();
    let mut totals = Plan::default();

    for shape in all {
        let cat = match &shape {
            ZKMProofShape::Recursion(_) => "Recursion",
            ZKMProofShape::Compress(_) => "Compress",
            ZKMProofShape::Deferred(_) => "Deferred",
            ZKMProofShape::Shrink(_) => "Shrink",
        };
        if seen.contains_key(cat) {
            continue;
        }
        let prog_shape = ZKMCompressProgramShape::from_proof_shape(shape, VK_MERKLE_TREE_HEIGHT);
        let Ok(program) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prover.program_from_shape_basefold(prog_shape)
        })) else {
            continue;
        };
        seen.insert(cat, ());

        // Same preparation the runtime does before its walk.
        let (analyzed, _counts) = program.seq_blocks.clone().analyze();
        let plan = zkm_recursion_jit::plan(&analyzed);

        println!("\n== {cat}: {} instructions ==", plan.total());
        let mut rows: Vec<(usize, &'static str)> = Plan::VARIANTS
            .iter()
            .enumerate()
            .map(|(i, n)| (plan.mix[i], *n))
            .filter(|(n, _)| *n > 0)
            .collect();
        rows.sort_unstable_by(|a, b| b.0.cmp(&a.0));
        for (n, name) in rows {
            println!("  {name:<20} {n:>10}  {:>6.2}%", 100.0 * n as f64 / plan.total() as f64);
        }
        let opnames = ["Add", "Sub", "Mul", "Div"];
        let b: usize = plan.base_ops.iter().sum();
        let e: usize = plan.ext_ops.iter().sum();
        if b > 0 {
            let cols: Vec<String> = (0..4)
                .map(|i| {
                    format!("{}={:.1}%", opnames[i], 100.0 * plan.base_ops[i] as f64 / b as f64)
                })
                .collect();
            println!("  BaseAlu opcodes: {}", cols.join("  "));
        }
        if e > 0 {
            let cols: Vec<String> = (0..4)
                .map(|i| {
                    format!("{}={:.1}%", opnames[i], 100.0 * plan.ext_ops[i] as f64 / e as f64)
                })
                .collect();
            println!("  ExtAlu opcodes:  {}", cols.join("  "));
        }
        println!(
            "  -> native {:.2}%, call-out {:.2}%, fallback {:.2}%",
            100.0 * plan.native as f64 / plan.total() as f64,
            100.0 * plan.call_out as f64 / plan.total() as f64,
            100.0 * plan.fallback as f64 / plan.total() as f64,
        );

        for i in 0..12 {
            totals.mix[i] += plan.mix[i];
        }
        totals.native += plan.native;
        totals.call_out += plan.call_out;
        totals.fallback += plan.fallback;
    }

    println!("\n== all categories: {} instructions ==", totals.total());
    let mut rows: Vec<(usize, &'static str)> = Plan::VARIANTS
        .iter()
        .enumerate()
        .map(|(i, n)| (totals.mix[i], *n))
        .filter(|(n, _)| *n > 0)
        .collect();
    rows.sort_unstable_by(|a, b| b.0.cmp(&a.0));
    for (n, name) in rows {
        println!("  {name:<20} {n:>10}  {:>6.2}%", 100.0 * n as f64 / totals.total() as f64);
    }
}

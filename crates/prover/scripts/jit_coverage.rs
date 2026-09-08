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

        // No preparation needed: a program is analyzed when it is built.
        let analyzed = &program.seq_blocks;
        let plan = zkm_recursion_jit::plan(analyzed);

        // What `run()` used to pay on EVERY call, now paid once at program
        // construction.  Timed on the real program, because the 25.2 ms
        // measured earlier came from a 7,040-instruction node and small
        // programs are dominated by fixed costs rather than by the pass.
        {
            let raw = zkm_recursion_core::runtime::RawProgram {
                seq_blocks: vec![zkm_recursion_core::runtime::SeqBlock::Basic(
                    zkm_recursion_core::runtime::BasicBlock {
                        instrs: program.iter_instructions().cloned().collect(),
                    },
                )],
            };
            let t = std::time::Instant::now();
            let (_a, _c) = raw.clone().analyze();
            let with_clone = t.elapsed();
            let t2 = std::time::Instant::now();
            let (_a2, _c2) = raw.analyze();
            let without_clone = t2.elapsed();
            println!(
                "  analyze: {:.1} ms with the clone run() used to make, {:.1} ms without \
                 ({:.0} ns/instr) -- was paid once per NODE, now once per program",
                with_clone.as_secs_f64() * 1e3,
                without_clone.as_secs_f64() * 1e3,
                without_clone.as_nanos() as f64 / plan.total().max(1) as f64,
            );
        }

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
        // Block structure: a 1:1 unroll emits ~100 B per instruction, so the
        // only way a JIT is viable at 4.3 M instructions is if the program is
        // built from REPEATED sub-programs that can be compiled once and
        // called.  This counts how many distinct opcode sequences the blocks
        // have and what share of instructions the repeats cover.
        {
            use std::collections::HashMap;
            let mut shapes: HashMap<Vec<u8>, (usize, usize)> = HashMap::new();
            let mut n_basic = 0usize;
            let mut n_par = 0usize;
            fn walk(
                blocks: &[zkm_recursion_core::runtime::SeqBlock<
                    zkm_recursion_core::runtime::AnalyzedInstruction<p3_koala_bear::KoalaBear>,
                >],
                shapes: &mut HashMap<Vec<u8>, (usize, usize)>,
                n_basic: &mut usize,
                n_par: &mut usize,
            ) {
                use zkm_recursion_core::runtime::{Instruction, SeqBlock};
                for b in blocks {
                    match b {
                        SeqBlock::Basic(bb) => {
                            *n_basic += 1;
                            let key: Vec<u8> = bb
                                .instrs
                                .iter()
                                .map(|ai| match ai.inner() {
                                    Instruction::BaseAlu(i) => 0 + i.opcode as u8 * 16,
                                    Instruction::ExtAlu(i) => 1 + i.opcode as u8 * 16,
                                    Instruction::Mem(_) => 2,
                                    Instruction::Poseidon2(_) => 3,
                                    Instruction::Select(_) => 4,
                                    Instruction::HintBits(_) => 5,
                                    Instruction::HintAddCurve(_) => 6,
                                    Instruction::Print(_) => 7,
                                    Instruction::HintExt2Felts(_) => 8,
                                    Instruction::Ext2Felts(_) => 9,
                                    Instruction::CommitPublicValues(_) => 10,
                                    Instruction::Hint(_) => 11,
                                })
                                .collect();
                            let n = key.len();
                            let e = shapes.entry(key).or_insert((0, n));
                            e.0 += 1;
                        }
                        SeqBlock::Parallel(subs) => {
                            *n_par += 1;
                            for sub in subs {
                                walk(&sub.seq_blocks, shapes, n_basic, n_par);
                            }
                        }
                    }
                }
            }
            walk(&analyzed.seq_blocks, &mut shapes, &mut n_basic, &mut n_par);
            let distinct = shapes.len();
            let repeated_instrs: usize =
                shapes.values().filter(|(c, _)| *c > 1).map(|(c, n)| c * n).sum();
            // The number that decides whether a template JIT is viable: code
            // is emitted once per DISTINCT sequence, so this is what actually
            // gets compiled, against the 4.3 M a 1:1 unroll would emit.
            let distinct_instrs: usize = shapes.values().map(|(_, n)| *n).sum();
            let biggest = shapes.values().map(|(c, n)| (*c, *n)).max_by_key(|(c, _)| *c);
            println!(
                "  distinct sequence instrs: {distinct_instrs} of {}                  ({:.2}%) -> ~{:.1} MB of code at 100 B/instr",
                plan.total(),
                100.0 * distinct_instrs as f64 / plan.total().max(1) as f64,
                distinct_instrs as f64 * 100.0 / 1e6,
            );
            println!(
                "  blocks: {n_basic} basic, {n_par} parallel groups; {distinct} distinct \
                 opcode sequences; {:.1}% of instructions in a repeated sequence{}",
                100.0 * repeated_instrs as f64 / plan.total().max(1) as f64,
                biggest.map_or(String::new(), |(c, n)| format!(
                    "; most repeated sequence x{c} of {n} instrs"
                ))
            );
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

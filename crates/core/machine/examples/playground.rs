//! Generic experiment harness for the MIPS core machine.
//!
//! One reusable entry point for the questions that keep coming up when a proof
//! misbehaves, so an investigation does not need its own throwaway binary:
//!
//!   * `execute` — run a program and report shards, cycles and syscall usage.
//!   * `buses`   — per-`LookupKind` send/receive balance, the diagnostic that
//!                 localizes a `LogUp-GKR: public-values balance failed`.
//!   * `prove`   — full prove + verify.
//!
//! Reproducibility: every run prints a header naming the program, the commit,
//! and the environment variables that are known to change proof bytes, so a
//! result can be reproduced exactly.  `SHAPE_CHECK_FREQUENCY` in particular is
//! byte-moving and is therefore always reported.
//!
//! ```text
//! cargo run --release -p zkm-core-machine --example playground -- buses fibonacci
//! cargo run --release -p zkm-core-machine --example playground -- prove   /path/to/guest.elf
//! ```
//!
//! Reading a `buses` report: a bus is healthy when it prints BALANCED.  The
//! public-values boundary buses (`State`, `GlobalAccumulation`,
//! `MemoryGlobalInitControl`, `MemoryGlobalFinalizeControl`) are the exception —
//! they are closed by the public-values AIR, which this tool does not evaluate,
//! so each should show exactly TWO unmatched keys (the initial endpoint at `-1`
//! and the final endpoint at `+1`).  More than two means the chip chain failed
//! to telescope, and the extra pair names the row where it broke.

use p3_koala_bear::KoalaBear;
use zkm_core_executor::{Executor, Program};
use zkm_pcs::air::MachineAir;
use zkm_core_machine::{
    mips::MipsAir,
    utils::{run_test, setup_logger},
};
use zkm_pcs::{
    debug_lookups_with_all_chips, koala_bear_poseidon2::KoalaBearPoseidon2, CpuProver, LookupKind,
    LookupScope, StarkMachine, ZKMCoreOpts,
};

/// Every bus the core machine carries.  Sweeping the whole list matters: the
/// public-values boundary buses are 9..=13, and an investigation that only
/// looks at the familiar 1..=8 will see nothing but architectural noise.
const ALL_KINDS: &[LookupKind] = &[
    LookupKind::Memory,
    LookupKind::Program,
    LookupKind::Instruction,
    LookupKind::Byte,
    LookupKind::Range,
    LookupKind::Syscall,
    LookupKind::Global,
    LookupKind::SyscallResult,
    LookupKind::State,
    LookupKind::GlobalAccumulation,
    LookupKind::MemoryGlobalInitControl,
    LookupKind::MemoryGlobalFinalizeControl,
    LookupKind::PrecompileChain,
];

/// Environment variables that change what gets proven or how it is shaped.
/// Printed on every run so a reported result carries the config that produced
/// it -- `SHAPE_CHECK_FREQUENCY` alone flips the proof digest.
const REPRO_ENV: &[&str] = &[
    "SHAPE_CHECK_FREQUENCY",
    "SHARD_SIZE",
    "SHARD_BATCH_SIZE",
    "TRACE_GEN_WORKERS",
    "RAYON_NUM_THREADS",
    "ZKM_SKIP_PROGRAM_BUILD",
];

/// Accepts a built-in fixture name or a path to any guest ELF, so the same
/// harness works for a one-line repro and for a real workload.
fn resolve(name: &str) -> Program {
    let builtin: Option<&[u8]> = match name {
        "fibonacci" => Some(test_artifacts::FIBONACCI_ELF),
        "hello-world" => Some(test_artifacts::HELLO_WORLD_ELF),
        "sha3-chain" => Some(test_artifacts::SHA3_CHAIN_ELF),
        "keccak-sponge" => Some(test_artifacts::KECCAK_SPONGE_ELF),
        "unconstrained" => Some(test_artifacts::UNCONSTRAINED_ELF),
        _ => None,
    };
    if let Some(elf) = builtin {
        return Program::from(elf).expect("built-in fixture must parse");
    }
    let elf = std::fs::read(name)
        .unwrap_or_else(|e| panic!("not a known fixture and not a readable ELF: {name}: {e}"));
    Program::from(&elf).unwrap_or_else(|e| panic!("failed to parse ELF {name}: {e:?}"))
}

fn banner(cmd: &str, program: &str) {
    eprintln!("=== playground: {cmd} {program} ===");
    for k in REPRO_ENV {
        eprintln!("    {k}={}", std::env::var(k).unwrap_or_else(|_| "<unset>".into()));
    }
}

fn main() {
    setup_logger();
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "buses".into());
    let name = args.next().unwrap_or_else(|| "fibonacci".into());
    banner(&cmd, &name);
    let program = resolve(&name);

    match cmd.as_str() {
        "execute" => {
            let mut rt = Executor::new(program, ZKMCoreOpts::default());
            rt.run().expect("execution failed");
            eprintln!("shards       = {}", rt.records.len());
            eprintln!("global_clk   = {}", rt.state.global_clk);
            eprintln!("exited       = {}", rt.state.exited);
        }
        "buses" => {
            let program_clone = program.clone();
            let mut rt = Executor::new(program, ZKMCoreOpts::default());
            rt.run().expect("execution failed");
            let machine: StarkMachine<KoalaBearPoseidon2, MipsAir<KoalaBear>> =
                MipsAir::machine(KoalaBearPoseidon2::new());
            let (pkey, _) = machine.setup(&program_clone);
            let opts = ZKMCoreOpts::default();
            machine.generate_dependencies(&mut rt.records, &opts, None).expect("dependencies");
            let shards = rt.records;

            for kind in ALL_KINDS {
                for (i, shard) in shards.iter().enumerate() {
                    eprintln!("--- shard {i} LOCAL {kind:?}");
                    debug_lookups_with_all_chips::<KoalaBearPoseidon2, MipsAir<KoalaBear>>(
                        &machine,
                        &pkey,
                        std::slice::from_ref(shard),
                        vec![*kind],
                        LookupScope::Local,
                    );
                }
                eprintln!("--- GLOBAL {kind:?}");
                debug_lookups_with_all_chips::<KoalaBearPoseidon2, MipsAir<KoalaBear>>(
                    &machine,
                    &pkey,
                    &shards,
                    vec![*kind],
                    LookupScope::Global,
                );
            }
        }
        "prove" => {
            run_test::<CpuProver<_, _>>(program).expect("prove + verify failed");
            eprintln!("prove + verify OK");
        }
        "widths" => {
            // Per-chip main-trace WIDTH census.  "Where does the trace area go"
            // is the recurring question behind every density comparison against
            // SP1, and answering it otherwise means re-deriving column counts by
            // hand from the `*Cols` struct definitions.  Width is static, so this
            // needs no execution; multiply by the per-chip row count for area.
            let machine: StarkMachine<KoalaBearPoseidon2, MipsAir<KoalaBear>> =
                MipsAir::machine(KoalaBearPoseidon2::new());
            let mut rows: Vec<(String, usize, usize)> = machine
                .chips()
                .iter()
                .map(|c| {
                    (
                        MachineAir::<KoalaBear>::name(c),
                        p3_air::BaseAir::<KoalaBear>::width(c).max(1),
                        MachineAir::<KoalaBear>::preprocessed_width(c),
                    )
                })
                .collect();
            rows.sort_by(|a, b| b.1.cmp(&a.1));
            let total: usize = rows.iter().map(|r| r.1).sum();
            eprintln!("{:<28} {:>7} {:>7}  {:>6}", "chip", "main_w", "prep_w", "%main");
            for (name, w, pw) in &rows {
                eprintln!(
                    "{:<28} {:>7} {:>7}  {:>5.1}%",
                    name,
                    w,
                    pw,
                    100.0 * *w as f64 / total as f64
                );
            }
            eprintln!("{:<28} {:>7}", "TOTAL main width", total);
        }
        other => {
            panic!("unknown command {other:?}; expected execute | buses | prove | widths")
        }
    }
}

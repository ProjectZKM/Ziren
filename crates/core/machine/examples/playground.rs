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
use zkm_core_machine::{
    io::ZKMStdin,
    mips::MipsAir,
    utils::{run_test, run_test_io, setup_logger},
};
use zkm_pcs::air::MachineAir;
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
    // `all` (optional subset list) and `dump` (output dir) don't take a
    // fixture/ELF — resolve lazily.
    let program = if cmd == "all" || cmd == "dump" { None } else { Some(resolve(&name)) };
    let program = move || program.expect("mode needs a fixture");

    match cmd.as_str() {
        "execute" => {
            let mut rt = Executor::new(program(), ZKMCoreOpts::default());
            rt.run().expect("execution failed");
            eprintln!("shards       = {}", rt.records.len());
            eprintln!("global_clk   = {}", rt.state.global_clk);
            eprintln!("exited       = {}", rt.state.exited);
        }
        "buses" => {
            let program = program();
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
            run_test::<CpuProver<_, _>>(program()).expect("prove + verify failed");
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
        "rows" => {
            // Per-chip ROW census.  Every row is a REAL instruction now: the
            // Instruction bus and its synthetic dependency rows are gone
            // (DivRem/CloClz/Misc prove their sub-operations in-row).
            let mut rt = Executor::new(program(), ZKMCoreOpts::default());
            rt.run().expect("execution failed");
            let mut cpu = 0usize;
            let mut tot = 0usize;
            eprintln!("{:<22} {:>10}", "alu chip", "rows");
            for rec in &rt.records {
                cpu += rec.cpu_events.len();
            }
            let mut report = |name: &str, rows: usize| {
                tot += rows;
                eprintln!("{name:<22} {rows:>10}");
            };
            macro_rules! census {
                ($field:ident, $label:literal) => {{
                    let mut r = 0usize;
                    for rec in &rt.records {
                        r += rec.$field.len();
                    }
                    report($label, r);
                }};
            }
            census!(add_sub_events, "AddSub");
            census!(bitwise_events, "Bitwise");
            census!(shift_left_events, "ShiftLeft");
            census!(shift_right_events, "ShiftRight");
            census!(lt_events, "Lt");
            census!(cloclz_events, "CloClz");
            census!(mul_events, "Mul");
            census!(divrem_events, "DivRem");
            eprintln!("{:<22} {:>10}", "ALU TOTAL", tot);
            eprintln!("cpu_events (one per executed instruction) = {cpu}");
            eprintln!("shards = {}", rt.records.len());
        }
        "dump" => {
            // Write <out>/<name>/{program.bin,stdin.bin} for every test
            // artifact, in the format `find_maximal_shapes --list` consumes —
            // the shape-artifact regeneration sweep runs the SAME corpus the
            // all-mode proves.
            let out = std::env::args().nth(2).expect("dump needs an output dir");
            let artifacts: &[(&str, &[u8])] = &[
                ("sha2-rust", test_artifacts::SHA2_RUST_ELF),
                ("fibonacci", test_artifacts::FIBONACCI_ELF),
                ("hello-world", test_artifacts::HELLO_WORLD_ELF),
                ("poseidon2-permute", test_artifacts::POSEIDON2_PERMUTE_ELF),
                ("sha2", test_artifacts::SHA2_ELF),
                ("sha-extend", test_artifacts::SHA_EXTEND_ELF),
                ("sha-compress", test_artifacts::SHA_COMPRESS_ELF),
                ("keccak-sponge", test_artifacts::KECCAK_SPONGE_ELF),
                ("ed25519", test_artifacts::ED25519_ELF),
                ("cycle-tracker", test_artifacts::CYCLE_TRACKER_ELF),
                ("ed-add", test_artifacts::ED_ADD_ELF),
                ("ed-decompress", test_artifacts::ED_DECOMPRESS_ELF),
                ("secp256k1-add", test_artifacts::SECP256K1_ADD_ELF),
                ("secp256k1-decompress", test_artifacts::SECP256K1_DECOMPRESS_ELF),
                ("secp256k1-double", test_artifacts::SECP256K1_DOUBLE_ELF),
                ("secp256r1-add", test_artifacts::SECP256R1_ADD_ELF),
                ("secp256r1-decompress", test_artifacts::SECP256R1_DECOMPRESS_ELF),
                ("secp256r1-double", test_artifacts::SECP256R1_DOUBLE_ELF),
                ("bn254-add", test_artifacts::BN254_ADD_ELF),
                ("bn254-double", test_artifacts::BN254_DOUBLE_ELF),
                ("bn254-mul", test_artifacts::BN254_MUL_ELF),
                ("secp256k1-mul", test_artifacts::SECP256K1_MUL_ELF),
                ("bls12381-add", test_artifacts::BLS12381_ADD_ELF),
                ("bls12381-double", test_artifacts::BLS12381_DOUBLE_ELF),
                ("bls12381-mul", test_artifacts::BLS12381_MUL_ELF),
                ("uint256-mul", test_artifacts::UINT256_MUL_ELF),
                ("bls12381-decompress", test_artifacts::BLS12381_DECOMPRESS_ELF),
                ("bls12381-fp", test_artifacts::BLS12381_FP_ELF),
                ("bls12381-fp2-mul", test_artifacts::BLS12381_FP2_MUL_ELF),
                ("bls12381-fp2-addsub", test_artifacts::BLS12381_FP2_ADDSUB_ELF),
                ("bn254-fp", test_artifacts::BN254_FP_ELF),
                ("bn254-fp2-addsub", test_artifacts::BN254_FP2_ADDSUB_ELF),
                ("bn254-fp2-mul", test_artifacts::BN254_FP2_MUL_ELF),
                ("u256xu2048-mul", test_artifacts::U256XU2048_MUL_ELF),
                ("unconstrained", test_artifacts::UNCONSTRAINED_ELF),
                // sha3-chain exercises KeccakSponge at a chained density no
                // other artifact reaches (test_sha3_chain_prove_simple was
                // shape-stale before it joined the corpus).  No stdin: the
                // guest hardcodes its input.
                ("sha3-chain", test_artifacts::SHA3_CHAIN_ELF),
            ];
            fn hexb2(s: &str) -> Vec<u8> {
                (0..s.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                    .collect()
            }
            for (name, elf) in artifacts {
                let dir = std::path::Path::new(&out).join(name);
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(dir.join("program.bin"), elf).unwrap();
                let stdin = match *name {
                    "sha2-rust" => {
                        let input = b"hello world".to_vec();
                        let expected = hexb2(
                            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                        );
                        let mut s = ZKMStdin::new();
                        s.write(&expected);
                        s.write(&input);
                        s
                    }
                    "secp256k1-decompress" => ZKMStdin::from(
                        hexb2("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                            .as_slice(),
                    ),
                    "secp256r1-decompress" => ZKMStdin::from(
                        hexb2("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
                            .as_slice(),
                    ),
                    "bls12381-decompress" => ZKMStdin::from(
                        hexb2("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb")
                            .as_slice(),
                    ),
                    _ => ZKMStdin::new(),
                };
                std::fs::write(dir.join("stdin.bin"), bincode::serialize(&stdin).unwrap()).unwrap();
                eprintln!("dumped {name}");
            }
        }
        "all" => {
            // Prove + verify EVERY test-artifact guest.  This is the gate an
            // architecture-level change must pass before anything downstream
            // (goldens, vk generation): the four ad-hoc fixtures cover the
            // integer core, but only the full set exercises every precompile
            // chip, every syscall path, and the panic/unconstrained edges.
            let artifacts: &[(&str, &[u8])] = &[
                ("sha2-rust", test_artifacts::SHA2_RUST_ELF),
                ("fibonacci", test_artifacts::FIBONACCI_ELF),
                ("hello-world", test_artifacts::HELLO_WORLD_ELF),
                ("poseidon2-permute", test_artifacts::POSEIDON2_PERMUTE_ELF),
                ("sha2", test_artifacts::SHA2_ELF),
                ("sha-extend", test_artifacts::SHA_EXTEND_ELF),
                ("sha-compress", test_artifacts::SHA_COMPRESS_ELF),
                ("keccak-sponge", test_artifacts::KECCAK_SPONGE_ELF),
                ("ed25519", test_artifacts::ED25519_ELF),
                ("cycle-tracker", test_artifacts::CYCLE_TRACKER_ELF),
                ("ed-add", test_artifacts::ED_ADD_ELF),
                ("ed-decompress", test_artifacts::ED_DECOMPRESS_ELF),
                ("secp256k1-add", test_artifacts::SECP256K1_ADD_ELF),
                ("secp256k1-decompress", test_artifacts::SECP256K1_DECOMPRESS_ELF),
                ("secp256k1-double", test_artifacts::SECP256K1_DOUBLE_ELF),
                ("secp256r1-add", test_artifacts::SECP256R1_ADD_ELF),
                ("secp256r1-decompress", test_artifacts::SECP256R1_DECOMPRESS_ELF),
                ("secp256r1-double", test_artifacts::SECP256R1_DOUBLE_ELF),
                ("bn254-add", test_artifacts::BN254_ADD_ELF),
                ("bn254-double", test_artifacts::BN254_DOUBLE_ELF),
                ("bn254-mul", test_artifacts::BN254_MUL_ELF),
                ("secp256k1-mul", test_artifacts::SECP256K1_MUL_ELF),
                ("bls12381-add", test_artifacts::BLS12381_ADD_ELF),
                ("bls12381-double", test_artifacts::BLS12381_DOUBLE_ELF),
                ("bls12381-mul", test_artifacts::BLS12381_MUL_ELF),
                ("uint256-mul", test_artifacts::UINT256_MUL_ELF),
                ("bls12381-decompress", test_artifacts::BLS12381_DECOMPRESS_ELF),
                ("bls12381-fp", test_artifacts::BLS12381_FP_ELF),
                ("bls12381-fp2-mul", test_artifacts::BLS12381_FP2_MUL_ELF),
                ("bls12381-fp2-addsub", test_artifacts::BLS12381_FP2_ADDSUB_ELF),
                ("bn254-fp", test_artifacts::BN254_FP_ELF),
                ("bn254-fp2-addsub", test_artifacts::BN254_FP2_ADDSUB_ELF),
                ("bn254-fp2-mul", test_artifacts::BN254_FP2_MUL_ELF),
                ("u256xu2048-mul", test_artifacts::U256XU2048_MUL_ELF),
                ("unconstrained", test_artifacts::UNCONSTRAINED_ELF),
                ("sha3-chain", test_artifacts::SHA3_CHAIN_ELF),
            ];
            // Fixtures that READ STDIN get their canonical inputs; an empty
            // stream hits the executor's "insufficient input data" error.
            fn hexb(s: &str) -> Vec<u8> {
                (0..s.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                    .collect()
            }
            fn artifact_stdin(name: &str) -> ZKMStdin {
                match name {
                    "sha2-rust" => {
                        // The guest reads (expected_hash, input) via io::read.
                        let input = b"hello world".to_vec();
                        let expected =
                            hexb("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
                        let mut stdin = ZKMStdin::new();
                        stdin.write(&expected);
                        stdin.write(&input);
                        stdin
                    }
                    // The curve generators, SEC1-compressed.
                    "secp256k1-decompress" => ZKMStdin::from(
                        hexb("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                            .as_slice(),
                    ),
                    "secp256r1-decompress" => ZKMStdin::from(
                        hexb("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
                            .as_slice(),
                    ),
                    "bls12381-decompress" => ZKMStdin::from(
                        hexb("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb")
                            .as_slice(),
                    ),
                    _ => ZKMStdin::new(),
                }
            }

            // Optional comma-separated subset: `playground all a,b,c`.
            let filter: Option<Vec<String>> =
                std::env::args().nth(2).map(|f| f.split(',').map(str::to_string).collect());

            let mut failed: Vec<&str> = vec![];
            for (name, elf) in artifacts {
                if let Some(f) = &filter {
                    if !f.iter().any(|x| x == name) {
                        continue;
                    }
                }
                eprint!("{name:<24} ");
                let program = Program::from(elf).expect("artifact must parse");
                let stdin = artifact_stdin(name);
                match std::panic::catch_unwind(|| {
                    run_test_io::<CpuProver<_, _>>(program, stdin).map(|_| ())
                }) {
                    Ok(Ok(_)) => eprintln!("PASS"),
                    Ok(Err(e)) => {
                        eprintln!("FAIL: {e:?}");
                        failed.push(name);
                    }
                    Err(_) => {
                        eprintln!("PANIC");
                        failed.push(name);
                    }
                }
            }
            if failed.is_empty() {
                eprintln!("ALL {} ARTIFACTS PASS", artifacts.len());
            } else {
                panic!("{} artifacts FAILED: {failed:?}", failed.len());
            }
        }
        other => {
            panic!(
                "unknown command {other:?}; expected execute | buses | prove | widths | rows | all"
            )
        }
    }
}

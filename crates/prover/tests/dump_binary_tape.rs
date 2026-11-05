//! Dump the recorded verifier tapes the garbled verifier (`whir-gc`) reads.
//!
//! One ignored test, `dump`, in one of three modes picked by the environment:
//!
//! - **Level 1** (no `ZIREN_RECURSE_FROM`): prove a Fibonacci program through
//!   core, compress, the Blake3 shrink and the binary stage, and record the
//!   binary stage's verifier on that proof. `ZIREN_BINARY_WITNESS_DUMP` names
//!   a saved shrink proof: read when it exists, written after proving when it
//!   does not. Writes `binary_tape.bin`.
//! - **Recurse** (`ZIREN_RECURSE_FROM=<tape>`, `ZIREN_RECURSE_TO=<name>`):
//!   prove the run of a saved tape on the tape machine under
//!   `ZIREN_B_SCHEDULE` and record the tape machine's verifier on that proof.
//!   Writes the proof as `<name>` with `_tape` replaced by `_proof`, then the
//!   tape as `<name>`.
//! - **Re-record** (also `ZIREN_RERECORD_PROOF=<proof>`): record the verifier
//!   again on a saved proof, with the opened values the verifier knows
//!   (forms over constant preprocessed columns, main padding) as constants,
//!   and the preprocessed tree read `ZIREN_DEEP_PREP_CAP` layers deep.
//!
//! Every file goes to `ZIREN_TAPE_OUT` (default `target/ziren-tapes`); a
//! relative `ZIREN_RECURSE_FROM` or `ZIREN_RERECORD_PROOF` is read from there.
//! `ZIREN_B_SCHEDULE=regime,rate,folding` (as `johnson,10,5`) and
//! `ZIREN_B_MAX_GRIND` set the narrow schedule. `ZIREN_B_FOLDS` and
//! `ZIREN_B_FIRST_ROUND` are read by the stage itself and reach every
//! machine, the binary stage's included, so leave them unset for level 1.
//! `ZIREN_NUM_PUBLIC` (default 0) is how many of a tape's first inputs the
//! narrow machine binds as public values.
//!
//! The tape is written as `whir-gc` parses it (`ZTAP`, version 2): the
//! operations with their kind index as tag, then the inputs, then the values,
//! every element as its 128-bit representation, little-endian.
//!
//! ```sh
//! cargo test --release -p zkm-prover --test dump_binary_tape -- --ignored --nocapture
//! ```

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use p3_air::BaseAir;
use p3_binary_field::TowerLevel;
use p3_field::PrimeCharacteristicRing;
use zkm_binary_recursion::config::{lift_key, reread, Instance, TracedConfig, TracedProof};
use zkm_binary_recursion::machine::program::Program;
use zkm_binary_recursion::machine::{TapeAir, TapeMachine};
use zkm_binary_recursion::tape::kind_index;
use zkm_binary_recursion::{Op, Operand, Tape, Traced};
use zkm_binary_stark::config::MachineProof;
use zkm_binary_stark::machine::RecursionMachine;
use zkm_binary_stark::{BinarySchedule, TRANSCRIPT_DOMAIN};

type Fb = zkm_binary_stark::F;

const MAGIC: &[u8; 4] = b"ZTAP";
const VERSION: u32 = 2;

fn out_dir() -> PathBuf {
    let dir = std::env::var_os("ZIREN_TAPE_OUT").map_or_else(
        || PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/ziren-tapes")),
        PathBuf::from,
    );
    std::fs::create_dir_all(&dir).expect("the output directory");
    dir
}

/// `name` as given if it exists, else under the output directory.
fn resolve(name: &str, out: &Path) -> PathBuf {
    let path = PathBuf::from(name);
    if path.exists() {
        path
    } else {
        out.join(name)
    }
}

/// The narrow machine's schedule, from `ZIREN_B_SCHEDULE` and
/// `ZIREN_B_MAX_GRIND`, and its label (`johnson-10-5`).
fn narrow_schedule() -> (BinarySchedule, String) {
    let spec = std::env::var("ZIREN_B_SCHEDULE").unwrap_or_else(|_| "unique,5,4".into());
    let parts: Vec<&str> = spec.split(',').map(str::trim).collect();
    assert_eq!(parts.len(), 3, "ZIREN_B_SCHEDULE=regime,rate,folding, as johnson,10,5");
    let regime = match parts[0] {
        "johnson" => p3_examples::binary::WhirRegime::Johnson,
        "unique" => p3_examples::binary::WhirRegime::UniqueDecoding,
        other => panic!("regime {other}: johnson or unique"),
    };
    let mut schedule = BinarySchedule {
        regime,
        log_inv_rate: parts[1].parse().expect("a rate"),
        folding: parts[2].parse().expect("a folding factor"),
        ..BinarySchedule::default()
    };
    schedule.budget.max_grinding_bits = std::env::var("ZIREN_B_MAX_GRIND")
        .ok()
        .map_or(40, |v| v.parse().expect("ZIREN_B_MAX_GRIND in bits"));
    (schedule, parts.join("-"))
}

fn census(label: &str, tape: &Tape) {
    let counts: Vec<String> = Tape::KINDS
        .iter()
        .zip(tape.census())
        .filter(|(_, n)| *n > 0)
        .map(|(kind, n)| format!("{kind} {n}"))
        .collect();
    eprintln!(
        "{label}: {} ops, {} variables, {} inputs, {} hashed bytes; {}\n  garbled: {}",
        tape.ops.len(),
        tape.values.len(),
        tape.inputs.len(),
        tape.hashed_bytes(),
        counts.join(", "),
        tape.and_gates()
    );
}

#[test]
#[ignore]
fn dump() {
    zkm_core_machine::utils::setup_logger();
    let out = out_dir();
    match std::env::var("ZIREN_RECURSE_FROM") {
        Err(_) => level_one(&out),
        Ok(from) => {
            let to = std::env::var("ZIREN_RECURSE_TO").expect("ZIREN_RECURSE_TO, the tape to write");
            let started = Instant::now();
            let tape = read_tape(&resolve(&from, &out));
            eprintln!("read {from} in {:.1} s", started.elapsed().as_secs_f64());
            census("source tape", &tape);
            match std::env::var("ZIREN_RERECORD_PROOF") {
                Ok(saved) => rerecord(&tape, &resolve(&saved, &out), &out, &to),
                Err(_) => recurse(&tape, &out, &to),
            }
        }
    }
}

/// Level 1: the binary stage's verifier on a proof of Fibonacci.
fn level_one(out: &Path) {
    use zkm_core_executor::ZKMContext;
    use zkm_core_machine::io::ZKMStdin;
    use zkm_core_machine::reduce::ZKMReduceProof;
    use zkm_pcs::ZKMProverOpts;
    use zkm_prover::components::DefaultProverComponents;
    use zkm_prover::{ShrinkBlake3SC, ZKMProver};

    let prover = ZKMProver::<DefaultProverComponents>::new();
    let dump = std::env::var_os("ZIREN_BINARY_WITNESS_DUMP").map(PathBuf::from);
    let shrink_proof: ZKMReduceProof<ShrinkBlake3SC> = match &dump {
        Some(path) if path.exists() => {
            eprintln!("shrink proof read from {}", path.display());
            bincode::deserialize(&std::fs::read(path).unwrap()).expect("a saved shrink proof")
        }
        _ => {
            let opts = ZKMProverOpts::default();
            let (_, pk_d, program, vk) = prover.setup(test_artifacts::FIBONACCI_ELF);
            let mut stdin = ZKMStdin::new();
            stdin.write(&10u32);
            let core = prover
                .prove_core(&pk_d, program, &stdin, opts, ZKMContext::default())
                .expect("the core proof");
            let compressed = prover.compress(&vk, core, vec![], opts).expect("the compressed proof");
            let shrink = prover.shrink_blake3(compressed, opts).expect("the Blake3 shrink proof");
            if let Some(path) = &dump {
                std::fs::write(path, bincode::serialize(&shrink).unwrap()).unwrap();
                eprintln!("shrink proof written to {}", path.display());
            }
            shrink
        }
    };
    prover.verify_shrink_blake3(&shrink_proof).expect("the shrink proof verifies");

    let started = Instant::now();
    let binary = prover.shrink_binary(shrink_proof).expect("the binary stage proves");
    eprintln!(
        "binary stage proof: {} bytes in {:.1} s",
        postcard::to_allocvec(&binary.proof).unwrap().len(),
        started.elapsed().as_secs_f64()
    );
    prover.verify_shrink_binary(&binary).expect("the binary stage proof verifies");

    let schedule = BinarySchedule::default();
    let machine = RecursionMachine::new(&binary.program, &schedule).expect("the binary machine");
    let public = RecursionMachine::public_values(&binary.digest);
    let (main, preprocessed) = machine.shapes();
    let instances: Vec<Instance<'_, _>> = machine
        .airs()
        .iter()
        .map(|air| Instance {
            air,
            log_height: air.log_height(),
            public_values: match air {
                zkm_binary_stark::machine::RecursionAir::PublicValues(_) => &public,
                _ => &[],
            },
        })
        .collect();
    let started = Instant::now();
    let (verdict, tape) = zkm_binary_recursion::config::record_verification(
        &instances,
        &main,
        &preprocessed,
        &schedule,
        machine.verifying_key(),
        &binary.proof,
    );
    verdict.expect("the recorded verifier accepts the binary stage proof");
    eprintln!("recorded in {:.1} s", started.elapsed().as_secs_f64());
    check_and_write(&tape, &out.join("binary_tape.bin"), "level 1 (the binary stage's verifier)");
}

/// The tape machine of `tape`'s program under the narrow schedule.
fn tape_machine(tape: &Tape) -> TapeMachine {
    let num_public = std::env::var("ZIREN_NUM_PUBLIC")
        .ok()
        .map_or(0, |v| v.parse().expect("ZIREN_NUM_PUBLIC, a count"));
    let started = Instant::now();
    let program = Program::new(tape, num_public);
    eprintln!("  {}", program.census());
    let (schedule, label) = narrow_schedule();
    eprintln!("narrow schedule {label}: {schedule:?}");
    let machine = TapeMachine::new(program, &schedule).expect("the tape machine");
    for air in machine.airs() {
        eprintln!(
            "  {:>7}: 2^{} rows x {} + {} prep",
            air.name(),
            air.log_height(),
            BaseAir::<Fb>::width(air),
            BaseAir::<Fb>::preprocessed_width(air)
        );
    }
    eprintln!("tape machine set up in {:.1} s", started.elapsed().as_secs_f64());
    machine
}

/// The proof file of a tape name: `_tape` replaced by `_proof`.
fn proof_name(to: &str) -> String {
    if to.contains("_tape") {
        to.replacen("_tape", "_proof", 1)
    } else {
        format!("{to}.proof")
    }
}

/// Prove `tape`'s run on the tape machine and record the machine's verifier.
fn recurse(tape: &Tape, out: &Path, to: &str) {
    let machine = tape_machine(tape);
    let public = machine.public_values(&tape.inputs);
    let started = Instant::now();
    let proof = machine.prove(tape, &tape.inputs).expect("the tape machine proves the run");
    let bytes = postcard::to_allocvec(&proof).expect("the proof serializes");
    eprintln!("narrow proof: {} bytes in {:.1} s", bytes.len(), started.elapsed().as_secs_f64());
    for (part, size) in zkm_binary_stark::config::proof_breakdown(&proof) {
        eprintln!("    {part:<55} {size:>9} B");
    }
    let path = out.join(proof_name(to));
    std::fs::write(&path, &bytes).unwrap();
    eprintln!("narrow proof written to {}", path.display());
    machine.verify(&proof, &public).expect("the narrow proof verifies");
    let own = record(&machine, &public, &proof, &[], &[]);
    check_and_write(&own, &out.join(to), "next level (the narrow proof's verifier)");
}

/// Record the tape machine's verifier on a saved proof of `tape`'s run, the
/// opened values it knows read as constants, and write the tape to `out/to`.
fn rerecord(tape: &Tape, saved: &Path, out: &Path, to: &str) {
    let machine = tape_machine(tape);
    let proof: MachineProof =
        postcard::from_bytes(&std::fs::read(saved).unwrap()).expect("a saved narrow proof");
    let public = machine.public_values(&tape.inputs);
    machine.verify(&proof, &public).expect("the saved narrow proof verifies");
    // whir-gc experiment: read the preprocessed commitment down to its nodes at
    // ZIREN_DEEP_PREP_CAP layers below the root, as constants.
    if let Some(level) =
        std::env::var("ZIREN_DEEP_PREP_CAP").ok().map(|v| v.parse::<usize>().expect("a level"))
    {
        let nodes = machine
            .preprocessed_tree_layer(level)
            .expect("the preprocessed tree reaches the level");
        zkm_binary_recursion::mmcs::set_deep_cap(level, nodes);
        eprintln!("deep preprocessed cap: {} constant nodes at level {level}", 1usize << level);
    }
    let (main_known, prep_known) = known_columns(&machine);
    let prep_values = &proof.preprocessed_opening.as_ref().expect("a preprocessed opening").values;
    for &(i, v) in &main_known {
        assert_eq!(proof.opening.values[i], v, "main value {i} is not the padding's zero");
    }
    for &(i, v) in &prep_known {
        assert_eq!(prep_values[i], v, "preprocessed value {i} is not its known constant");
    }
    eprintln!(
        "known opened values: {} of {} main, {} of {} preprocessed",
        main_known.len(),
        proof.opening.values.len(),
        prep_known.len(),
        prep_values.len()
    );
    let own = record(&machine, &public, &proof, &main_known, &prep_known);
    check_and_write(&own, &out.join(to), "re-recorded (known values as constants)");
}

/// The tape machine's verifier on `proof`, recorded, with the opened values
/// in `main_known` and `prep_known` (index, value) read as constants.
fn record(
    machine: &TapeMachine,
    public: &[Fb; zkm_binary_recursion::machine::ledger::MAX_PUBLIC],
    proof: &MachineProof,
    main_known: &[(usize, Fb)],
    prep_known: &[(usize, Fb)],
) -> Tape {
    let (schedule, _) = narrow_schedule();
    let (main, preprocessed) = machine.shapes();
    let config = TracedConfig::new(&main, &preprocessed, &schedule).expect("the traced configuration");
    let vk = lift_key(machine.verifying_key());
    let started = Instant::now();
    let (verdict, tape) = zkm_binary_recursion::record(|| {
        let public: [Traced; zkm_binary_recursion::machine::ledger::MAX_PUBLIC] =
            public.map(Traced::input);
        let mut proof: TracedProof = reread(proof);
        for &(i, v) in main_known {
            proof.opening.values[i] = Traced::constant(v);
        }
        if let Some(opening) = proof.preprocessed_opening.as_mut() {
            for &(i, v) in prep_known {
                opening.values[i] = Traced::constant(v);
            }
        }
        let instances = machine.verifier_instances(&vk, &public);
        let mut challenger = zkm_binary_recursion::challenger::TracedChallenger::new(TRANSCRIPT_DOMAIN);
        let verdict = p3_multi_stark::verify(&config, instances, &proof, 0, &mut challenger)
            .map_err(|e| format!("{e:?}"));
        zkm_binary_recursion::queries::take();
        verdict
    });
    verdict.expect("the recorded verifier accepts the narrow proof");
    eprintln!("recorded in {:.1} s", started.elapsed().as_secs_f64());
    tape
}

/// The opened values a verifier of `machine` knows: main padding columns of
/// tables sending columns (zero), and preprocessed forms or columns over
/// constant preprocessed columns only, as (index, value) in each opening.
fn known_columns(machine: &TapeMachine) -> (Vec<(usize, Fb)>, Vec<(usize, Fb)>) {
    use core::borrow::Borrow;
    use zkm_binary_recursion::machine::arith::{ArithCols, NUM_ARITH_COLS};
    use zkm_binary_recursion::machine::rounds::{RoundsCols, NUM_ROUNDS_COLS};

    let (mut main, mut prep) = (Vec::new(), Vec::new());
    let (mut main_offset, mut prep_offset) = (0usize, 0usize);
    for air in machine.airs() {
        let width = BaseAir::<Fb>::width(air);
        // A table sending forms reads no padding; one sending columns knows its padding is zero.
        if let Some(forms) = BaseAir::<Fb>::main_linear_forms(air) {
            main_offset += forms.forms.len();
        } else {
            let pads: Vec<usize> = match air {
                TapeAir::Arith(_) => {
                    let index: Vec<usize> = (0..NUM_ARITH_COLS).collect();
                    let cols: &ArithCols<usize> = index.as_slice().borrow();
                    cols.pad.to_vec()
                }
                TapeAir::Rounds(_) => {
                    let index: Vec<usize> = (0..NUM_ROUNDS_COLS).collect();
                    let cols: &RoundsCols<usize> = index.as_slice().borrow();
                    cols.pad.to_vec()
                }
                _ => Vec::new(),
            };
            main.extend(pads.into_iter().map(|i| (main_offset + i, Fb::ZERO)));
            main_offset += width;
        }
        if let Some(trace) = BaseAir::<Fb>::preprocessed_trace(air) {
            let width = trace.width;
            let rows = trace.values.len() / width;
            let constant: Vec<Option<Fb>> = (0..width)
                .map(|c| {
                    let first = trace.values[c];
                    (1..rows).all(|r| trace.values[r * width + c] == first).then_some(first)
                })
                .collect();
            // A form reading only constant columns is known; so is a constant column sent alone.
            if let Some(forms) = BaseAir::<Fb>::preprocessed_linear_forms(air) {
                for (j, form) in forms.forms.iter().enumerate() {
                    let value: Option<Fb> =
                        form.iter().map(|&(c, x)| constant[c].map(|v| Fb::from_repr(x) * v)).sum();
                    if let Some(value) = value {
                        prep.push((prep_offset + j, value));
                    }
                }
                prep_offset += forms.forms.len();
            } else {
                for (c, v) in constant.iter().enumerate() {
                    if let Some(v) = v {
                        prep.push((prep_offset + c, *v));
                    }
                }
                prep_offset += width;
            }
        }
    }
    (main, prep)
}

/// Check the tape accepts its own inputs, reproducing its values, then
/// write it.
fn check_and_write(tape: &Tape, path: &Path, label: &str) {
    census(label, tape);
    let started = Instant::now();
    let values = tape.run(&tape.inputs).expect("the tape accepts its own inputs");
    assert!(values == tape.values, "the run reproduces the recorded values");
    eprintln!("tape re-run in {:.1} s", started.elapsed().as_secs_f64());
    write_tape(tape, path);
}

fn put_operand(w: &mut Vec<u8>, operand: &Operand) {
    match operand {
        Operand::Var(v) => {
            w.push(0);
            w.extend_from_slice(&v.to_le_bytes());
        }
        Operand::Const(c) => {
            w.push(1);
            w.extend_from_slice(&c.to_repr().to_le_bytes());
        }
    }
}

fn put_operands(w: &mut Vec<u8>, operands: &[Operand]) {
    w.extend_from_slice(&u32::try_from(operands.len()).unwrap().to_le_bytes());
    for operand in operands {
        put_operand(w, operand);
    }
}

fn write_tape(tape: &Tape, path: &Path) {
    let mut w: Vec<u8> = Vec::with_capacity(16 * (tape.values.len() + tape.inputs.len()) + 32 * tape.ops.len());
    w.extend_from_slice(MAGIC);
    w.extend_from_slice(&VERSION.to_le_bytes());
    w.extend_from_slice(&(tape.ops.len() as u64).to_le_bytes());
    for op in &tape.ops {
        w.push(u8::try_from(kind_index(op)).unwrap());
        match op {
            Op::Input(n) => w.extend_from_slice(&(*n as u64).to_le_bytes()),
            Op::Add(a, b) | Op::Mul(a, b) | Op::AssertEq(a, b) => {
                put_operand(&mut w, a);
                put_operand(&mut w, b);
            }
            Op::Square(a) | Op::Inv(a) | Op::AssertNonZero(a) | Op::ToBytes(a) | Op::ByteBits(a) => {
                put_operand(&mut w, a);
            }
            Op::FromBytes(v) | Op::Transpose(v) => put_operands(&mut w, v),
            Op::Blake3 { slots, len } => {
                put_operands(&mut w, slots);
                w.extend_from_slice(&(*len as u64).to_le_bytes());
            }
            Op::Select(s, a, b) => {
                put_operand(&mut w, s);
                put_operand(&mut w, a);
                put_operand(&mut w, b);
            }
            Op::MerkleNode { bit, cur, sib } => {
                for operand in [bit, &cur[0], &cur[1], &sib[0], &sib[1]] {
                    put_operand(&mut w, operand);
                }
            }
        }
    }
    for list in [&tape.inputs, &tape.values] {
        w.extend_from_slice(&(list.len() as u64).to_le_bytes());
        for x in list.iter() {
            w.extend_from_slice(&x.to_repr().to_le_bytes());
        }
    }
    let mut f = std::fs::File::create(path).expect("the tape file");
    f.write_all(&w).unwrap();
    eprintln!("tape written to {}: {} bytes", path.display(), w.len());
}

struct Reader<'a> {
    d: &'a [u8],
    o: usize,
}

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let bytes = self.d[self.o..self.o + N].try_into().unwrap();
        self.o += N;
        bytes
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take())
    }
    fn u64(&mut self) -> usize {
        usize::try_from(u64::from_le_bytes(self.take())).unwrap()
    }
    fn element(&mut self) -> Fb {
        Fb::from_repr(u128::from_le_bytes(self.take()))
    }
    fn operand(&mut self) -> Operand {
        match self.take::<1>()[0] {
            0 => Operand::Var(self.u32()),
            1 => Operand::Const(self.element()),
            t => panic!("operand tag {t}"),
        }
    }
    fn operands(&mut self) -> Vec<Operand> {
        let n = self.u32() as usize;
        (0..n).map(|_| self.operand()).collect()
    }
}

/// A tape [`write_tape`] wrote.
fn read_tape(path: &Path) -> Tape {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    assert_eq!(&bytes[..4], MAGIC, "not a tape");
    let mut r = Reader { d: &bytes, o: 4 };
    assert_eq!(r.u32(), VERSION, "tape version");
    let n = r.u64();
    let mut tape = Tape { ops: Vec::with_capacity(n), defined: Vec::with_capacity(n), ..Tape::default() };
    let mut next = 0u32;
    for _ in 0..n {
        let tag = r.take::<1>()[0];
        let op = match tag {
            0 => Op::Input(r.u64()),
            1 => Op::Add(r.operand(), r.operand()),
            2 => Op::Mul(r.operand(), r.operand()),
            3 => Op::Inv(r.operand()),
            4 => Op::AssertEq(r.operand(), r.operand()),
            5 => Op::AssertNonZero(r.operand()),
            6 => Op::ToBytes(r.operand()),
            7 => Op::FromBytes(r.operands()),
            8 => Op::ByteBits(r.operand()),
            9 => {
                let slots = r.operands();
                Op::Blake3 { slots, len: r.u64() }
            }
            10 => Op::Transpose(r.operands()),
            11 => Op::Select(r.operand(), r.operand(), r.operand()),
            12 => {
                let bit = r.operand();
                let cur = [r.operand(), r.operand()];
                let sib = [r.operand(), r.operand()];
                Op::MerkleNode { bit, cur, sib }
            }
            13 => Op::Square(r.operand()),
            t => panic!("op tag {t}"),
        };
        assert_eq!(kind_index(&op), usize::from(tag), "tags are kind indices");
        let defines = op.defines() as u32;
        tape.defined.push((defines > 0).then_some(next));
        next += defines;
        tape.ops.push(op);
    }
    let ni = r.u64();
    tape.inputs = (0..ni).map(|_| r.element()).collect();
    let nv = r.u64();
    tape.values = (0..nv).map(|_| r.element()).collect();
    assert_eq!(r.o, bytes.len(), "trailing bytes in the tape");
    assert_eq!(next as usize, tape.values.len(), "one value per variable");
    tape
}

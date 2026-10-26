//! A compose node over real binary leaves, read from the comma-separated
//! paths in `ZIREN_BINARY_LEAVES` as the prover's
//! `test_e2e_leaf_binary_fibonacci` writes them: the node's program is
//! recorded and run, it refuses children whose public values do not chain
//! or do not hash to their digest, and with `ZIREN_COMPOSE_PROVE` the tape
//! machine proves it.

use p3_binary_field::TowerLevel;
use p3_field::PrimeCharacteristicRing;
use zkm_binary_recursion::compose::{record_compose, Child, Compose};
use zkm_binary_recursion::machine::program::Program;
use zkm_binary_recursion::machine::TapeMachine;
use zkm_binary_recursion::{Tape, F};
use zkm_binary_stark::machine::{ProvedProgram, RecursionMachine};
use zkm_binary_stark::BinarySchedule;
use zkm_recursion_core::air::RECURSION_PUBLIC_VALUES_COL_MAP;
use zkm_recursion_core::DIGEST_SIZE;

const MAX_LOG_SHARDS: usize = 16;

fn census(label: &str, tape: &Tape) {
    let counts: Vec<String> = Tape::KINDS
        .iter()
        .zip(tape.census())
        .filter(|(_, n)| *n > 0)
        .map(|(kind, n)| format!("{kind} {n}"))
        .collect();
    println!(
        "{label}: {} ops, {} inputs, {} hashed bytes; {}",
        tape.ops.len(),
        tape.inputs.len(),
        tape.hashed_bytes(),
        counts.join(", ")
    );
}

#[test]
#[ignore]
fn composes_leaves() {
    let paths = std::env::var("ZIREN_BINARY_LEAVES").expect("ZIREN_BINARY_LEAVES names leaves");
    let leaves: Vec<ProvedProgram> = paths
        .split(',')
        .map(|path| {
            ProvedProgram::from_bytes(&std::fs::read(path).expect("the leaf reads"))
                .expect("the leaf deserializes")
        })
        .collect();
    let schedule = BinarySchedule::default();
    let machines: Vec<RecursionMachine> = leaves
        .iter()
        .map(|leaf| RecursionMachine::new(&leaf.program, &schedule).expect("the leaf machine"))
        .collect();
    let children = |values: &dyn Fn(usize) -> Vec<u32>| -> Vec<Child<'_>> {
        leaves
            .iter()
            .zip(&machines)
            .enumerate()
            .map(|(i, (leaf, machine))| Child::leaf(machine, &leaf.proof, values(i), &schedule))
            .collect()
    };
    let honest = |i: usize| leaves[i].public_values.clone();
    let node =
        Compose { children: children(&honest), is_complete: false, max_log_shards: MAX_LOG_SHARDS };

    let started = std::time::Instant::now();
    let (composed, tape) = record_compose(&node);
    let composed = composed.expect("the leaves compose");
    census(&format!("compose of {} leaves", leaves.len()), &tape);
    println!("recorded in {:.1} s; digest {:?}", started.elapsed().as_secs_f64(), composed.digest);
    let values = tape.run(&tape.inputs).expect("the program accepts its own run");
    assert!(values == tape.values, "the run reproduces the recorded values");
    let public: Vec<u32> = tape.inputs[..DIGEST_SIZE].iter().map(|x| x.to_repr() as u32).collect();
    assert_eq!(public, composed.digest.to_vec(), "the public inputs are the node's digest");

    let map = &RECURSION_PUBLIC_VALUES_COL_MAP;
    let last = leaves.len() - 1;
    for (label, child, column) in [
        ("a start pc", last, map.start_pc),
        ("a next shard", 0, map.next_shard),
        ("an exit code", last, map.exit_code),
        ("a digest word", 0, map.digest[3]),
    ] {
        let broken = |i: usize| {
            let mut values = leaves[i].public_values.clone();
            if i == child {
                values[column] = (values[column] + 1) % 0x7f00_0001;
            }
            values
        };
        let node = Compose {
            children: children(&broken),
            is_complete: false,
            max_log_shards: MAX_LOG_SHARDS,
        };
        let refused = match record_compose(&node) {
            (Err(_), _) => true,
            (Ok(_), tape) => tape.run(&tape.inputs).is_err(),
        };
        assert!(refused, "changing {label} of child {child} must be refused");
    }

    let program = Program::new(&tape, DIGEST_SIZE);
    println!("  {}", program.census());
    if std::env::var_os("ZIREN_COMPOSE_PROVE").is_none() {
        return;
    }
    let started = std::time::Instant::now();
    let machine = TapeMachine::new(program, &schedule).expect("the tape machine");
    println!("tape machine set up in {:.1} s", started.elapsed().as_secs_f64());
    for air in machine.airs() {
        println!(
            "  {:>7}: 2^{} rows x {} + {} prep",
            air.name(),
            air.log_height(),
            p3_air::BaseAir::<F>::width(air),
            p3_air::BaseAir::<F>::preprocessed_width(air)
        );
    }
    let public = machine.public_values(&tape.inputs);
    let started = std::time::Instant::now();
    let proof = machine.prove(&tape, &tape.inputs).expect("the node proves");
    println!(
        "compose proof: {} bytes in {:.1} s",
        postcard::to_allocvec(&proof).expect("serializes").len(),
        started.elapsed().as_secs_f64()
    );
    machine.verify(&proof, &public).expect("the node verifies");
    let mut wrong = public;
    wrong[0] += F::ONE;
    assert!(machine.verify(&proof, &wrong).is_err(), "another digest is refused");
}

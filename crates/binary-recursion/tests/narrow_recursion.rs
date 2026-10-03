//! The narrow recursion end to end on a small proof of the binary stage:
//! its verifier recorded, the recording proved by the tape machine, and
//! the tape machine's own verifier recorded, which is what a garbled
//! verifier of the narrow recursion evaluates.

mod common;

use common::{prove_probes, Probe};
use zkm_binary_recursion::config::{record_verification, Instance};
use zkm_binary_recursion::machine::program::Program;
use zkm_binary_recursion::machine::{TapeAir, TapeMachine};
use zkm_binary_recursion::Tape;
use zkm_binary_stark::BinarySchedule;

fn census(label: &str, tape: &Tape) {
    let counts: Vec<String> = Tape::KINDS
        .iter()
        .zip(tape.census())
        .filter(|(_, n)| *n > 0)
        .map(|(kind, n)| format!("{kind} {n}"))
        .collect();
    println!(
        "{label}: {} ops, {} hashed bytes; {}\n  garbled: {}",
        tape.ops.len(),
        tape.hashed_bytes(),
        counts.join(", "),
        tape.and_gates()
    );
}

/// The schedule of the narrow proof: the stage's default, or the regime,
/// rate and folding `ZIREN_B_SCHEDULE` names, as `johnson,8,4`.
fn narrow_schedule() -> BinarySchedule {
    let Ok(spec) = std::env::var("ZIREN_B_SCHEDULE") else { return BinarySchedule::default() };
    let parts: Vec<&str> = spec.split(',').collect();
    let regime = match parts[0] {
        "johnson" => p3_examples::binary::WhirRegime::Johnson,
        _ => p3_examples::binary::WhirRegime::UniqueDecoding,
    };
    let mut schedule = BinarySchedule {
        regime,
        log_inv_rate: parts[1].parse().expect("a rate"),
        folding: parts[2].parse().expect("a folding factor"),
        ..BinarySchedule::default()
    };
    schedule.budget.max_grinding_bits = 40;
    schedule
}

#[test]
fn proves_a_recorded_verification_and_records_its_own() {
    let schedule = BinarySchedule::default();
    let narrow_schedule = narrow_schedule();
    println!("narrow schedule: {narrow_schedule:?}");
    let probes = [Probe { groups: 16, log_height: 10 }];
    let (_, vk, proof) = prove_probes(&probes);
    let shapes: Vec<_> = probes.iter().map(Probe::shape).collect();
    let instances: Vec<Instance<'_, Probe>> = probes
        .iter()
        .map(|p| Instance { air: p, log_height: p.log_height, public_values: &[] })
        .collect();
    for (part, bytes) in zkm_binary_stark::config::proof_breakdown(&proof) {
        println!("    {part:<55} {bytes:>9} B");
    }
    let (verdict, tape) = record_verification(&instances, &shapes, &[], &schedule, &vk, &proof);
    verdict.expect("the recorded verifier accepts the binary proof");
    census("level 1 (the binary proof's verifier)", &tape);

    let program = Program::new(&tape, 0);
    println!("  {}", program.census());
    let machine = TapeMachine::new(program, &narrow_schedule).expect("the tape machine");
    for air in machine.airs() {
        println!(
            "  {:>7}: 2^{} rows x {} + {} prep",
            air.name(),
            air.log_height(),
            p3_air::BaseAir::<zkm_binary_stark::F>::width(air),
            p3_air::BaseAir::<zkm_binary_stark::F>::preprocessed_width(air)
        );
    }
    let public = machine.public_values(&tape.inputs);
    let started = std::time::Instant::now();
    let narrow = machine.prove(&tape, &tape.inputs).expect("the tape machine proves the run");
    println!(
        "  narrow proof: {} bytes in {:.1} s",
        postcard::to_allocvec(&narrow).expect("serializes").len(),
        started.elapsed().as_secs_f64()
    );
    machine.verify(&narrow, &public).expect("the narrow proof verifies");
    for (part, bytes) in zkm_binary_stark::config::proof_breakdown(&narrow) {
        println!("    {part:<55} {bytes:>9} B");
    }

    let (main, preprocessed) = machine.shapes();
    let instances: Vec<Instance<'_, TapeAir>> = machine
        .airs()
        .iter()
        .map(|air| Instance {
            air,
            log_height: air.log_height(),
            public_values: match air {
                TapeAir::Ledger(_) => &public,
                _ => &[],
            },
        })
        .collect();
    let (verdict, own) = record_verification(
        &instances,
        &main,
        &preprocessed,
        &narrow_schedule,
        machine.verifying_key(),
        &narrow,
    );
    verdict.expect("the recorded verifier accepts the narrow proof");
    census("level 2 (the narrow proof's verifier)", &own);
}

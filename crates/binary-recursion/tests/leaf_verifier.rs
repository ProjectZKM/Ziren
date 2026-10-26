//! The verifier of a real leaf's binary proof, recorded and proved by the
//! tape machine: a compose node of arity one, without the public-value
//! checks.  The leaf is read from `ZIREN_BINARY_LEAF`, as the prover's
//! `test_e2e_leaf_binary_fibonacci` writes it.

use p3_multi_stark::verify;
use zkm_binary_recursion::challenger::TracedChallenger;
use zkm_binary_recursion::config::{
    lift_key, record_verification, reread, Instance, TracedConfig, TracedProof,
};
use zkm_binary_recursion::machine::program::Program;
use zkm_binary_recursion::machine::{TapeAir, TapeMachine};
use zkm_binary_recursion::{record, Tape, Traced};
use zkm_binary_stark::machine::{ProvedProgram, RecursionMachine};
use zkm_binary_stark::{BinarySchedule, TRANSCRIPT_DOMAIN};
use zkm_recursion_core::DIGEST_SIZE;

#[test]
#[ignore]
fn proves_the_verifier_of_a_leaf() {
    let path = std::env::var_os("ZIREN_BINARY_LEAF").expect("ZIREN_BINARY_LEAF names a leaf");
    let leaf = ProvedProgram::from_bytes(&std::fs::read(path).expect("the leaf reads"))
        .expect("the leaf deserializes");
    let schedule = BinarySchedule::default();
    let started = std::time::Instant::now();
    let machine = RecursionMachine::verifier(&leaf.program, &schedule).expect("the leaf machine");
    println!("leaf machine set up in {:.1} s", started.elapsed().as_secs_f64());
    machine.verify(&leaf.proof, &leaf.digest).expect("the leaf verifies natively");

    let (main, preprocessed) = machine.shapes();
    let config = TracedConfig::new(&main, &preprocessed, &schedule).expect("traced config");
    let vk = lift_key(machine.verifying_key());
    let started = std::time::Instant::now();
    let profiling = std::env::var_os("ZIREN_TAPE_PROFILE").is_some();
    let ((verdict, profile), tape) = record(|| {
        if profiling {
            zkm_binary_recursion::tape::profile(97);
        }
        let public: [Traced; DIGEST_SIZE] =
            RecursionMachine::public_values(&leaf.digest).map(Traced::input);
        let proof: TracedProof = reread(&leaf.proof);
        let instances = machine.verifier_instances(&vk, &public);
        let mut challenger = TracedChallenger::new(TRANSCRIPT_DOMAIN);
        let verdict =
            verify(&config, instances, &proof, 0, &mut challenger).map_err(|e| format!("{e:?}"));
        (verdict, zkm_binary_recursion::tape::take_profile())
    });
    verdict.expect("the traced verifier accepts the leaf");
    if let Some(profile) = profile {
        for depth in [2, 4, 6] {
            println!("profile at depth {depth}:");
            for (signature, muls, bytes) in profile.by_signature(depth).into_iter().take(20) {
                println!(
                    "    mul ~{muls:>8} hashed {bytes:>9} B  {}",
                    &signature[..signature.len().min(160)]
                );
            }
        }
    }
    let counts: Vec<String> = Tape::KINDS
        .iter()
        .zip(tape.census())
        .filter(|(_, n)| *n > 0)
        .map(|(kind, n)| format!("{kind} {n}"))
        .collect();
    println!(
        "leaf verifier recorded in {:.1} s: {} ops, {} variables, {} inputs, {} hashed bytes; {}",
        started.elapsed().as_secs_f64(),
        tape.ops.len(),
        tape.values.len(),
        tape.inputs.len(),
        tape.hashed_bytes(),
        counts.join(", ")
    );

    if std::env::var_os("ZIREN_RECORD_ONLY").is_some() {
        return;
    }
    let program = Program::new(&tape, 0);
    println!("  {}", program.census());
    let started = std::time::Instant::now();
    let tape_machine = TapeMachine::new(program, &schedule).expect("the tape machine");
    println!("tape machine set up in {:.1} s", started.elapsed().as_secs_f64());
    for air in tape_machine.airs() {
        println!(
            "  {:>7}: 2^{} rows x {} + {} prep",
            air.name(),
            air.log_height(),
            p3_air::BaseAir::<zkm_binary_stark::F>::width(air),
            p3_air::BaseAir::<zkm_binary_stark::F>::preprocessed_width(air)
        );
    }
    let public = tape_machine.public_values(&tape.inputs);
    let started = std::time::Instant::now();
    let proof = tape_machine.prove(&tape, &tape.inputs).expect("the tape machine proves");
    println!(
        "compose proof: {} bytes in {:.1} s",
        postcard::to_allocvec(&proof).expect("serializes").len(),
        started.elapsed().as_secs_f64()
    );
    let started = std::time::Instant::now();
    tape_machine.verify(&proof, &public).expect("the compose proof verifies");
    println!("compose proof verified in {:.1} s", started.elapsed().as_secs_f64());
    for (part, bytes) in zkm_binary_stark::config::proof_breakdown(&proof) {
        println!("    {part:<55} {bytes:>9} B");
    }

    let (main, preprocessed) = tape_machine.shapes();
    let instances: Vec<Instance<'_, TapeAir>> = tape_machine
        .airs()
        .iter()
        .map(|air| Instance {
            air,
            log_height: air.log_height(),
            public_values: match air {
                TapeAir::Public(_) => &public,
                _ => &[],
            },
        })
        .collect();
    let (verdict, own) = record_verification(
        &instances,
        &main,
        &preprocessed,
        &schedule,
        tape_machine.verifying_key(),
        &proof,
    );
    verdict.expect("the recorded verifier accepts the compose proof");
    let counts: Vec<String> = Tape::KINDS
        .iter()
        .zip(own.census())
        .filter(|(_, n)| *n > 0)
        .map(|(kind, n)| format!("{kind} {n}"))
        .collect();
    println!(
        "compose verifier: {} ops, {} hashed bytes; {}",
        own.ops.len(),
        own.hashed_bytes(),
        counts.join(", ")
    );
    println!("  {}", Program::new(&own, 0).census());
}

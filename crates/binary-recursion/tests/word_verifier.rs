//! The word backend's verifier, run over traced values on a real word proof,
//! accepts it and records the verification as a program.

use rand::{rngs::StdRng, Rng, SeedableRng};
use zkm_binary_recursion::word::record_word_verification;
use p3_field::PrimeCharacteristicRing;
use zkm_binary_recursion::{Tape, F};
use zkm_recursion_r1cs::builder::{Built, Builder};
use zkm_recursion_r1cs::kb::P;
use zkm_recursion_r1cs::prove::{schedule, WordKey};

/// `n` KoalaBear multiply-adds of hinted values, its output public.
fn built(n: usize, seed: u64) -> Built {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut builder = Builder::new(1);
    let mut acc = builder.hint(1);
    for _ in 0..n {
        let x = builder.hint(rng.gen_range(0..P));
        let y = builder.hint(rng.gen_range(0..P));
        let sum = builder.add(acc, x);
        acc = builder.mul(sum, y);
    }
    let output = builder.output(0, acc.value);
    builder.assert_zero(acc.terms().chain([output]));
    builder.build().unwrap()
}

fn report(label: &str, tape: &Tape) {
    let census = tape.census();
    let kinds: Vec<String> = Tape::KINDS
        .iter()
        .zip(census)
        .filter(|(_, count)| *count > 0)
        .map(|(kind, count)| format!("{kind} {count}"))
        .collect();
    println!("{label}: {} ops, {} inputs: {}", tape.ops.len(), tape.inputs.len(), kinds.join(", "));
    println!("{label}: {}, {} bytes hashed", tape.and_gates(), tape.hashed_bytes());
}

#[test]
fn the_traced_verifier_accepts_a_word_proof() {
    let built = built(64, 4);
    let key = WordKey::new(&built, &schedule()).unwrap();
    let (commitment, proof, hints) = key.prove(&built).unwrap();
    let (verdict, tape) = record_word_verification(
        &key.key,
        &schedule(),
        &commitment,
        &built.public,
        1,
        &proof,
        Some(&hints),
    );
    let deferred = verdict.unwrap();
    assert_eq!(deferred.len(), 2);
    assert!(deferred.iter().all(|claim| claim.holds(&key.key, &built.public, 1)));
    let (native, _) =
        record_word_verification(&key.key, &schedule(), &commitment, &built.public, 1, &proof, None);
    let native = native.unwrap();
    assert!(native.iter().zip(&deferred).all(|(n, h)| n.value.value() == h.value.value()));
    report("64 products", &tape);
    let values = tape.run(&tape.inputs).expect("the tape replays its own run");
    assert_eq!(values, tape.values);
    let mut wrong = tape.inputs.clone();
    wrong[0] += F::ONE;
    assert!(tape.run(&wrong).is_err(), "a different public input is rejected");
}

/// The recorded verifier's size as the relation system grows.  Run with
/// `--ignored --nocapture`.
#[test]
#[ignore]
fn word_verifier_cost() {
    let sizes: Vec<usize> = std::env::var("ZIREN_WORD_SIZES")
        .map_or_else(|_| vec![1 << 8, 1 << 12, 1 << 16], |s| {
            s.split(',').map(|n| n.parse().unwrap()).collect()
        });
    for n in sizes {
        let built = built(n, 7);
        let key = WordKey::new(&built, &schedule()).unwrap();
        let (commitment, proof, hints) = key.prove(&built).unwrap();
        let (verdict, tape) = record_word_verification(
            &key.key,
            &schedule(),
            &commitment,
            &built.public,
            1,
            &proof,
            Some(&hints),
        );
        assert!(verdict.unwrap().iter().all(|claim| claim.holds(&key.key, &built.public, 1)));
        report(
            &format!("{n} products, {} words, {} vars", built.witness.len(), key.key.trace_variables()),
            &tape,
        );
    }
}

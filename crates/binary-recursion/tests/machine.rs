//! The machine proves a tape that exercises every operation, and refuses a
//! run whose values break the program.

use p3_binary_field::TowerLevel;
use p3_field::{Field, PrimeCharacteristicRing};
use zkm_binary_recursion::bytes::{
    blake3, byte_bits, digest_bytes, from_bytes, merkle_node, select, to_bytes, transpose, Piece,
};
use zkm_binary_recursion::machine::program::Program;
use zkm_binary_recursion::machine::TapeMachine;
use zkm_binary_recursion::{record, Op, Tape, Traced, F};
use zkm_binary_stark::BinarySchedule;

/// A tape of every operation the machine has a table for, its first two
/// inputs public.
fn exercise() -> Tape {
    let ((), tape) = record(|| {
        let element =
            |i: u128| F::from_repr(i.wrapping_mul(0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c835));
        let public = [Traced::input(element(1)), Traced::input(element(2))];
        let x = Traced::input(element(3));
        let y = Traced::input(element(4));
        let sum = x + y + public[0];
        let product = sum * y * public[1];
        let inverse = product.inverse();
        (inverse * product).assert_eq(&Traced::ONE);
        product.assert_nonzero();
        let bytes = to_bytes(product);
        let bits = byte_bits(bytes[3]);
        let chosen = select(bits[1], x, y);
        let back = from_bytes(&bytes);
        back.assert_eq(&product);
        let rows: Vec<Traced> =
            (0..128).map(|i| chosen * Traced::constant(element(i + 9)) + x).collect();
        let columns = transpose(&rows);
        let single = transpose(&[sum]);
        let short = blake3(&[Piece::Element(columns[5]), Piece::Element(single[7] + y)]);
        let misaligned = blake3(&[Piece::Byte(bytes[0]), Piece::Element(x), Piece::Element(y)]);
        let long_pieces: Vec<Piece> =
            (0..80).map(|i| Piece::Element(columns[i % 128] + rows[i])).collect();
        let long = blake3(&long_pieces);
        let node = merkle_node(bits[2], short, misaligned);
        let node = merkle_node(bits[0], node, long);
        let digest = digest_bytes(node);
        let last = byte_bits(digest[31]);
        (last[0] + digest[0] + chosen).assert_nonzero();
    });
    tape
}

fn machine(tape: &Tape) -> TapeMachine {
    let program = Program::new(tape, 2);
    println!("{}", program.census());
    let machine = TapeMachine::new(program, &BinarySchedule::default()).expect("machine");
    for air in machine.airs() {
        println!(
            "  {:>7}: 2^{} rows x {} + {} prep",
            air.name(),
            air.log_height(),
            p3_air::BaseAir::<F>::width(air),
            p3_air::BaseAir::<F>::preprocessed_width(air)
        );
    }
    machine
}

#[test]
fn proves_every_operation_and_refuses_broken_runs() {
    let tape = exercise();
    for (kind, count) in Tape::KINDS.iter().zip(tape.census()) {
        if count > 0 {
            println!("  {kind}: {count}");
        }
    }
    let machine = machine(&tape);
    let public = machine.public_values(&tape.inputs);
    let started = std::time::Instant::now();
    let values = tape.run(&tape.inputs).expect("the run");
    let report = machine.unbalanced(&values, &public);
    if report.contains("unmatched") {
        println!("UNBALANCED:\n{}", &report[..report.len().min(6000)]);
    }
    let proof = machine.prove(&tape, &tape.inputs).expect("the run proves");
    println!(
        "proof {} bytes in {:.1} s",
        postcard::to_allocvec(&proof).expect("serializes").len(),
        started.elapsed().as_secs_f64()
    );
    machine.verify(&proof, &public).expect("the run verifies");

    let mut wrong_public = public;
    wrong_public[1] += F::ONE;
    assert!(machine.verify(&proof, &wrong_public).is_err(), "another public value is refused");

    let defined_by = |kind: fn(&Op) -> bool| -> usize {
        let i = tape.ops.iter().position(kind).expect("the tape has the operation");
        tape.defined[i].expect("the operation defines a value") as usize
    };
    for (label, var) in [
        ("a product", defined_by(|op| matches!(op, Op::Mul(..)))),
        (
            "a transposed column",
            defined_by(|op| matches!(op, Op::Transpose(rows) if rows.len() == 128)) + 5,
        ),
        ("a byte", defined_by(|op| matches!(op, Op::ToBytes(_))) + 3),
        ("a digest", defined_by(|op| matches!(op, Op::Blake3 { .. }))),
        ("a Merkle node", defined_by(|op| matches!(op, Op::MerkleNode { .. })) + 1),
        ("an input", defined_by(|op| matches!(op, Op::Input(2)))),
    ] {
        let mut broken = values.clone();
        broken[var] += F::from_repr(1 << 7);
        let refused = match machine.prove_values(&broken, &public) {
            Err(_) => true,
            Ok(proof) => machine.verify(&proof, &public).is_err(),
        };
        assert!(refused, "changing {label} must be refused");
    }
}

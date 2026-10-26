//! A compose node over real binary leaves, read from the comma-separated
//! paths in `ZIREN_BINARY_LEAVES` as the prover's
//! `test_e2e_leaf_binary_fibonacci` writes them: the node's program is
//! recorded and run, it refuses children whose public values do not chain
//! or do not hash to their digest, and with `ZIREN_COMPOSE_PROVE` the tape
//! machine proves it.

use p3_binary_field::TowerLevel;
use p3_field::PrimeCharacteristicRing;
use zkm_binary_recursion::compose::{
    binary_key_digest, record_compose, Child, Compose, Composed, KeyKind, VkMembership,
};
use zkm_binary_recursion::machine::program::Program;
use zkm_binary_recursion::machine::{TapeMachine, NODE_FLOOR, UPPER_NODE_FLOOR};
use zkm_binary_recursion::{Tape, F};
use zkm_binary_stark::machine::{leaf_floor, ProvedProgram, RecursionMachine};
use zkm_binary_stark::BinarySchedule;
use zkm_recursion_core::air::RECURSION_PUBLIC_VALUES_COL_MAP;
use zkm_recursion_core::DIGEST_SIZE;

const MAX_LOG_SHARDS: usize = 16;

/// Height of the key tree.
const KEY_TREE_HEIGHT: usize = zkm_recursion_core::VK_MERKLE_TREE_HEIGHT;

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> [u8; 32] {
    core::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
}

/// The place of `digest` in the key tree, from the proofs in
/// `ZIREN_BINARY_VK_PROOFS` as the prover's leaf test writes them; without
/// them, a place in no tree, which records the same program and fails its
/// run.
fn membership(digest: &[u8; 32]) -> VkMembership {
    let Some(path) = std::env::var_os("ZIREN_BINARY_VK_PROOFS") else {
        return VkMembership { index: 0, path: vec![[0; 32]; KEY_TREE_HEIGHT] };
    };
    let text = std::fs::read_to_string(path).expect("the proofs read");
    let line = text
        .lines()
        .find(|line| line.starts_with(&hex(digest)))
        .unwrap_or_else(|| panic!("key {} is in the tree", hex(digest)));
    let mut fields = line.split(' ');
    let _ = fields.next();
    let index = fields.next().expect("an index").parse().expect("an index");
    let path = fields.next().expect("a path").split(',').map(unhex).collect();
    VkMembership { index, path }
}

/// A leaf child, with its key's place in the tree.
fn leaf_child<'a>(
    machine: &'a RecursionMachine,
    leaf: &'a ProvedProgram,
    public_values: Vec<u32>,
    schedule: &BinarySchedule,
) -> Child<'a> {
    let (main, preprocessed) = machine.shapes();
    let digest = binary_key_digest(KeyKind::Leaf, &main, &preprocessed, machine.verifying_key());
    Child::leaf(machine, &leaf.proof, public_values, membership(&digest), schedule)
}

/// A node child, with its key's place in the tree.
fn node_child<'a>(
    machine: &'a TapeMachine,
    proof: &'a zkm_binary_stark::config::MachineProof,
    public_values: Vec<u32>,
    schedule: &BinarySchedule,
) -> Child<'a> {
    let (main, preprocessed) = machine.shapes();
    let digest = binary_key_digest(KeyKind::Node, &main, &preprocessed, machine.verifying_key());
    Child::node(machine, proof, public_values, membership(&digest), schedule)
}

/// With `ZIREN_PHASES`, print `label` with the wall clock, which a memory
/// sampler's log lines up against, and the prover's phases as they close.
fn mark(label: &str) {
    if std::env::var_os("ZIREN_PHASES").is_some() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock is past the epoch");
        println!("MARK {:.3} {label}", now.as_secs_f64());
    }
}

fn trace_phases() {
    if std::env::var_os("ZIREN_PHASES").is_some() {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("p3_multi_stark=info"))
            .with_span_events(
                tracing_subscriber::fmt::format::FmtSpan::NEW
                    | tracing_subscriber::fmt::format::FmtSpan::CLOSE,
            )
            .with_ansi(false)
            .init();
    }
}

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
    trace_phases();
    mark("start");
    let paths = std::env::var("ZIREN_BINARY_LEAVES").expect("ZIREN_BINARY_LEAVES names leaves");
    let leaves: Vec<ProvedProgram> = paths
        .split(',')
        .map(|path| {
            ProvedProgram::from_bytes(&std::fs::read(path).expect("the leaf reads"))
                .expect("the leaf deserializes")
        })
        .collect();
    mark("leaves read");
    let schedule = BinarySchedule::default();
    let machines: Vec<RecursionMachine> = leaves
        .iter()
        .map(|leaf| {
            RecursionMachine::verifier_with_floor(
                &leaf.program,
                &schedule,
                leaf_floor(&leaf.program).expect("a leaf class"),
            )
            .expect("the leaf machine")
        })
        .collect();
    let children = |values: &dyn Fn(usize) -> Vec<u32>| -> Vec<Child<'_>> {
        leaves
            .iter()
            .zip(&machines)
            .enumerate()
            .map(|(i, (leaf, machine))| leaf_child(machine, leaf, values(i), &schedule))
            .collect()
    };
    mark("leaf machines built");
    let honest = |i: usize| leaves[i].public_values.clone();
    let node =
        Compose { children: children(&honest), is_complete: false, max_log_shards: MAX_LOG_SHARDS };

    mark("children built");
    let started = std::time::Instant::now();
    let (composed, tape) = record_compose(&node);
    mark("recorded");
    let composed = composed.expect("the leaves compose");
    census(&format!("compose of {} leaves", leaves.len()), &tape);
    println!("recorded in {:.1} s; digest {:?}", started.elapsed().as_secs_f64(), composed.digest);
    let values = tape.run(&tape.inputs).expect("the program accepts its own run");
    assert!(values == tape.values, "the run reproduces the recorded values");
    let public: Vec<u32> = tape.inputs[..DIGEST_SIZE].iter().map(|x| x.to_repr() as u32).collect();
    assert_eq!(public, composed.digest.to_vec(), "the public inputs are the node's digest");

    mark("run checked");
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

    mark("tampers refused");
    let program = Program::new(&tape, DIGEST_SIZE);
    mark("program laid out");
    println!("  {}", program.census());
    if std::env::var_os("ZIREN_COMPOSE_PROVE").is_none() {
        return;
    }
    let started = std::time::Instant::now();
    let node_schedule = std::env::var("ZIREN_NODE_LOG_INV_RATE").map_or(schedule, |rate| {
        BinarySchedule { log_inv_rate: rate.parse().expect("a rate"), ..schedule }
    });
    println!("node commits at rate 2^-{}", node_schedule.log_inv_rate);
    let machine =
        TapeMachine::new_with_floor(program, &node_schedule, NODE_FLOOR).expect("the tape machine");
    println!("tape machine set up in {:.1} s", started.elapsed().as_secs_f64());
    mark("tape machine set up");
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
    mark("prove start");
    let proof = machine.prove(&tape, &tape.inputs).expect("the node proves");
    mark("prove end");
    println!(
        "compose proof: {} bytes in {:.1} s",
        postcard::to_allocvec(&proof).expect("serializes").len(),
        started.elapsed().as_secs_f64()
    );
    machine.verify(&proof, &public).expect("the node verifies");
    mark("verified");
    let mut wrong = public;
    wrong[0] += F::ONE;
    assert!(machine.verify(&proof, &wrong).is_err(), "another digest is refused");
}

/// Record, lay out and prove a compose node over `children`, returning its
/// machine, kept to verify, its proof and what it commits to.
fn prove_node(
    label: &str,
    children: Vec<Child<'_>>,
    schedule: &BinarySchedule,
) -> (TapeMachine, zkm_binary_stark::config::MachineProof, Composed) {
    let node = Compose { children, is_complete: false, max_log_shards: MAX_LOG_SHARDS };
    let (composed, tape) = record_compose(&node);
    let composed = composed.expect("the children compose");
    census(label, &tape);
    let program = Program::new(&tape, DIGEST_SIZE);
    println!("  {}", program.census());
    let mut machine =
        TapeMachine::new_with_floor(program, schedule, NODE_FLOOR).expect("the tape machine");
    let started = std::time::Instant::now();
    let proof = machine.prove(&tape, &tape.inputs).expect("the node proves");
    println!(
        "{label} proof: {} bytes in {:.1} s",
        postcard::to_allocvec(&proof).expect("serializes").len(),
        started.elapsed().as_secs_f64()
    );
    let public = machine.public_values(&tape.inputs);
    machine.verify(&proof, &public).expect("the node verifies");
    machine.drop_proving_key();
    (machine, proof, composed)
}

/// A node over two nodes over two leaves each, from the four comma-separated
/// leaves in `ZIREN_BINARY_LEAVES`: its program is recorded and run, it
/// refuses a child node whose public values do not chain, and with
/// `ZIREN_COMPOSE_PROVE` it is proved.
#[test]
#[ignore]
fn composes_nodes() {
    trace_phases();
    let paths = std::env::var("ZIREN_BINARY_LEAVES").expect("ZIREN_BINARY_LEAVES names leaves");
    let leaves: Vec<ProvedProgram> = paths
        .split(',')
        .map(|path| {
            ProvedProgram::from_bytes(&std::fs::read(path).expect("the leaf reads"))
                .expect("the leaf deserializes")
        })
        .collect();
    assert_eq!(leaves.len(), 4, "four leaves make two nodes of two");
    let schedule = BinarySchedule::default();
    let machines: Vec<RecursionMachine> = leaves
        .iter()
        .map(|leaf| {
            RecursionMachine::verifier_with_floor(
                &leaf.program,
                &schedule,
                leaf_floor(&leaf.program).expect("a leaf class"),
            )
            .expect("the leaf machine")
        })
        .collect();
    let leaf_children = |range: core::ops::Range<usize>| -> Vec<Child<'_>> {
        range
            .map(|i| {
                leaf_child(&machines[i], &leaves[i], leaves[i].public_values.clone(), &schedule)
            })
            .collect()
    };
    mark("leaf machines built");
    let left = prove_node("node 0..2", leaf_children(0..2), &schedule);
    mark("left node proved");
    let right = prove_node("node 2..4", leaf_children(2..4), &schedule);
    mark("right node proved");

    let nodes = [&left, &right];
    let children = |values: &dyn Fn(usize) -> Vec<u32>| -> Vec<Child<'_>> {
        nodes
            .iter()
            .enumerate()
            .map(|(i, (machine, proof, _))| node_child(machine, proof, values(i), &schedule))
            .collect()
    };
    let honest = |i: usize| nodes[i].2.public_values.clone();
    let node =
        Compose { children: children(&honest), is_complete: false, max_log_shards: MAX_LOG_SHARDS };
    let started = std::time::Instant::now();
    let (composed, tape) = record_compose(&node);
    let composed = composed.expect("the nodes compose");
    census("compose of 2 nodes", &tape);
    let own = TapeMachine::table_shapes(&Program::new(&tape, DIGEST_SIZE));
    println!(
        "level-two own shape: {:.2} Gbit, heights {:?}",
        own.iter().map(|&(_, h, w)| (w as u64) << h).sum::<u64>() as f64 / f64::from(1u32 << 30),
        own.iter().map(|(name, h, _)| format!("{name}:{h}")).collect::<Vec<_>>()
    );
    println!("recorded in {:.1} s; digest {:?}", started.elapsed().as_secs_f64(), composed.digest);
    let values = tape.run(&tape.inputs).expect("the program accepts its own run");
    assert!(values == tape.values, "the run reproduces the recorded values");

    let map = &RECURSION_PUBLIC_VALUES_COL_MAP;
    let broken = |i: usize| {
        let mut values = nodes[i].2.public_values.clone();
        if i == 1 {
            values[map.start_pc] = (values[map.start_pc] + 1) % 0x7f00_0001;
        }
        values
    };
    let refused = match record_compose(&Compose {
        children: children(&broken),
        is_complete: false,
        max_log_shards: MAX_LOG_SHARDS,
    }) {
        (Err(_), _) => true,
        (Ok(_), tape) => tape.run(&tape.inputs).is_err(),
    };
    assert!(refused, "a child node that does not chain must be refused");

    let misplaced: Vec<Child<'_>> = nodes
        .iter()
        .enumerate()
        .map(|(i, (machine, proof, composed))| {
            let (main, preprocessed) = machine.shapes();
            let digest =
                binary_key_digest(KeyKind::Node, &main, &preprocessed, machine.verifying_key());
            let mut place = membership(&digest);
            if i == 1 {
                place.index ^= 1;
            }
            Child::node(machine, proof, composed.public_values.clone(), place, &schedule)
        })
        .collect();
    let refused = match record_compose(&Compose {
        children: misplaced,
        is_complete: false,
        max_log_shards: MAX_LOG_SHARDS,
    }) {
        (Err(_), _) => true,
        (Ok(_), tape) => tape.run(&tape.inputs).is_err(),
    };
    assert!(refused, "a child key at the wrong place in the tree must be refused");
    mark("tampers refused");

    let program = Program::new(&tape, DIGEST_SIZE);
    println!("  {}", program.census());
    if std::env::var_os("ZIREN_COMPOSE_PROVE").is_none() {
        return;
    }
    let machine = TapeMachine::new_with_floor(program, &schedule, UPPER_NODE_FLOOR)
        .expect("the tape machine");
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
    mark("prove start");
    let started = std::time::Instant::now();
    let proof = machine.prove(&tape, &tape.inputs).expect("the level-two node proves");
    println!(
        "level-two proof: {} bytes in {:.1} s",
        postcard::to_allocvec(&proof).expect("serializes").len(),
        started.elapsed().as_secs_f64()
    );
    mark("prove end");
    machine.verify(&proof, &public).expect("the level-two node verifies");
    let mut wrong = public;
    wrong[0] += F::ONE;
    assert!(machine.verify(&proof, &wrong).is_err(), "another digest is refused");

    let unplaced = || VkMembership { index: 0, path: vec![[0; 32]; KEY_TREE_HEIGHT] };
    let upper: Vec<Child<'_>> = (0..2)
        .map(|_| {
            Child::node(&machine, &proof, composed.public_values.clone(), unplaced(), &schedule)
        })
        .collect();
    let (_, tape) = record_compose(&Compose {
        children: upper,
        is_complete: false,
        max_log_shards: MAX_LOG_SHARDS,
    });
    let own = TapeMachine::table_shapes(&Program::new(&tape, DIGEST_SIZE));
    println!(
        "level-three own shape: {} ops, {:.2} Gbit, heights {:?}",
        tape.ops.len(),
        own.iter().map(|&(_, h, w)| (w as u64) << h).sum::<u64>() as f64 / f64::from(1u32 << 30),
        own.iter().map(|(name, h, _)| format!("{name}:{h}")).collect::<Vec<_>>()
    );
    let fits = own.iter().all(|&(name, height, _)| {
        UPPER_NODE_FLOOR.iter().any(|&(known, most)| known == name && height <= most)
    });
    assert!(fits, "a node over two upper nodes fits the upper floor");
}

/// The key digests the tree must hold for nodes over the leaves in
/// `ZIREN_BINARY_LEAVES`, written to `ZIREN_BINARY_VK_OUT` a line each: each
/// leaf's, and the key of the node over each pair of them.  The programs
/// read their keys as inputs, so leaves under any tree give the same keys.
#[test]
#[ignore]
fn binary_key_digests() {
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
        .map(|leaf| {
            RecursionMachine::verifier_with_floor(
                &leaf.program,
                &schedule,
                leaf_floor(&leaf.program).expect("a leaf class"),
            )
            .expect("the leaf machine")
        })
        .collect();
    let mut digests: Vec<[u8; 32]> = machines
        .iter()
        .map(|machine| {
            let (main, preprocessed) = machine.shapes();
            binary_key_digest(KeyKind::Leaf, &main, &preprocessed, machine.verifying_key())
        })
        .collect();
    for pair in (0..leaves.len()).collect::<Vec<_>>().chunks(2).filter(|pair| pair.len() == 2) {
        let children = pair
            .iter()
            .map(|&i| {
                leaf_child(&machines[i], &leaves[i], leaves[i].public_values.clone(), &schedule)
            })
            .collect();
        let node = Compose { children, is_complete: false, max_log_shards: MAX_LOG_SHARDS };
        let (_, tape) = record_compose(&node);
        let machine = TapeMachine::verifier_with_floor(
            Program::new(&tape, DIGEST_SIZE),
            &schedule,
            NODE_FLOOR,
        )
        .expect("the tape machine");
        let (main, preprocessed) = machine.shapes();
        digests.push(binary_key_digest(
            KeyKind::Node,
            &main,
            &preprocessed,
            machine.verifying_key(),
        ));
    }
    digests.sort_unstable();
    digests.dedup();
    let text: String = digests.iter().map(|digest| format!("{}\n", hex(digest))).collect();
    print!("{text}");
    let out = std::env::var("ZIREN_BINARY_VK_OUT").expect("ZIREN_BINARY_VK_OUT names the output");
    std::fs::write(out, text).expect("the digests write");
}

/// The table heights of a node over each ordered pair of the leaves in
/// `ZIREN_BINARY_LEAVES`, and the floor that covers them all: what one node
/// shape needs.
#[test]
#[ignore]
fn node_shape_census() {
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
        .map(|leaf| {
            RecursionMachine::verifier_with_floor(
                &leaf.program,
                &schedule,
                leaf_floor(&leaf.program).expect("a leaf class"),
            )
            .expect("the leaf machine")
        })
        .collect();
    let mut floor: Vec<(&'static str, usize)> = Vec::new();
    for i in 0..leaves.len() {
        for j in 0..leaves.len() {
            let children = [i, j]
                .map(|k| {
                    leaf_child(&machines[k], &leaves[k], leaves[k].public_values.clone(), &schedule)
                })
                .into_iter()
                .collect();
            let node = Compose { children, is_complete: false, max_log_shards: MAX_LOG_SHARDS };
            let (_, tape) = record_compose(&node);
            let program = Program::new(&tape, DIGEST_SIZE);
            let tables = TapeMachine::table_shapes(&program);
            let bits: u64 = tables.iter().map(|&(_, h, w)| (w as u64) << h).sum();
            println!(
                "node over leaves {i},{j}: {} ops, {:.2} Gbit, heights {:?}",
                tape.ops.len(),
                bits as f64 / f64::from(1u32 << 30),
                tables.iter().map(|(name, h, _)| format!("{name}:{h}")).collect::<Vec<_>>()
            );
            for (name, log_height, _) in tables {
                match floor.iter_mut().find(|(known, _)| *known == name) {
                    Some((_, most)) => *most = (*most).max(log_height),
                    None => floor.push((name, log_height)),
                }
            }
        }
    }
    println!("node floor: {floor:?}");
}

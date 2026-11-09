//! The compress of a core proof over word proofs: a leaf per core shard,
//! its normalize program compiled to word relations and proved by the word
//! backend, then a tree of compose nodes proved by the tape machine, two
//! children to a node, whose root closes the execution.
//!
//! A first-level node verifies its word leaves in its program except for
//! the steps whose cost grows with a leaf's relations, which it defers: each
//! deferred claim joins the claims chain the nodes' public values carry, and
//! the root's verifier checks every claim against its key natively.
//!
//! The leaves' keys are many (one per normalize program's relations), so
//! the nodes are not yet uniform enough for their keys to be in a key tree
//! before the leaves are proved; until they are, the nodes are built without
//! checking their children's keys, which [`WordCompressedProof::keys_checked`]
//! records.

use std::borrow::Borrow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_word::Word64;
use serde::{Deserialize, Serialize};
use zkm_binary_recursion::compose::{advance_claims_native, Child, NativeClaim, VkMembership};
use zkm_binary_recursion::machine::{LeafWitness, TapeBackend};
use zkm_binary_recursion::node::{record_node_with, BinaryRootProof, ProvedNode};
use zkm_binary_stark::BinarySchedule;
use zkm_recursion_core::air::RecursionPublicValues;
use zkm_recursion_core::{DIGEST_SIZE, VK_MERKLE_TREE_HEIGHT};
use zkm_recursion_r1cs::prove::{
    proof_size, relations_digest, schedule as leaf_schedule, Commitment, Hints, KeyMaker, Proof,
    WordKey, WordKeys,
};

use crate::binary_tree::{plan, root_schedule};
use crate::components::ZKMProverComponents;
use crate::{CoreSC, ZKMCoreProof, ZKMProver, ZKMRecursionProverError, ZKMVerifyingKey};
use rayon::prelude::*;
use zkm_recursion_circuit::machine::core_jagged::ZKMCoreWitnessValues;
use zkm_recursion_core::RecursionProgram;

/// A core proof compressed over word proofs: the root of the tree and the
/// claims its leaves' verifications deferred, each with its key's digest,
/// in leaf order.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WordCompressedProof {
    pub root: BinaryRootProof,
    pub claims: Vec<([u8; 32], Vec<NativeClaim>)>,
    /// Whether the nodes checked their children's keys against the key tree.
    pub keys_checked: bool,
}

/// A proved word leaf: its key's index, its public words, the public values
/// its digest is of, the proof and the prover's deferred values.
struct WordLeaf {
    key: Arc<WordKey>,
    public: Vec<p3_word::Word64>,
    public_values: Vec<u32>,
    commitment: Commitment,
    proof: Proof,
    hints: Hints,
}

/// A place in the key tree for a node that does not check keys.
fn unplaced() -> VkMembership {
    VkMembership { index: 0, path: vec![[0; 32]; VK_MERKLE_TREE_HEIGHT] }
}

/// That the program's cached `tape` is the one `lowered` recorded, when it recorded one, and
/// that `public` and `witness`, computed by the tape, are `lowered`'s words.
fn check_tape(
    shard: usize,
    tape: &zkm_recursion_r1cs::tape::Tape,
    lowered: &zkm_recursion_r1cs::Lowered,
    public: &[u64],
    witness: &[u64],
) -> Result<(), ZKMRecursionProverError> {
    let recorded = &lowered.tape;
    if !recorded.is_empty()
        && (recorded.ops != tape.ops
            || recorded.imms != tape.imms
            || recorded.first_operand != tape.first_operand
            || recorded.operand_starts != tape.operand_starts
            || recorded.terms != tape.terms
            || recorded.outputs != tape.outputs)
    {
        return Err(stage(format!("leaf {shard}: the program's tape differs from its lowering")));
    }
    let built = &lowered.built;
    if public.len() != built.public.len()
        || public.iter().zip(&built.public).any(|(a, b)| *a != b.get())
    {
        return Err(stage(format!("leaf {shard}: the tape's public words differ")));
    }
    if witness.len() != built.witness.len() {
        return Err(stage(format!("leaf {shard}: the tape computes {} words", witness.len())));
    }
    let expected: Vec<u64> = built.witness.iter().map(|w| w.get()).collect();
    let wrong = (0..witness.len()).filter(|&i| witness[i] != expected[i]).count();
    if let Some(&word) = tape.order.iter().find(|&&i| witness[i as usize] != expected[i as usize]) {
        let word = word as usize;
        let first = tape.first_operand[word] as usize;
        let arity = zkm_recursion_r1cs::tape::Op::ALL[tape.ops[word] as usize].arity();
        let operands: Vec<String> = (first..first + arity)
            .map(|o| {
                let terms = &tape.terms
                    [tape.operand_starts[o] as usize..tape.operand_starts[o + 1] as usize];
                let terms: Vec<String> = terms
                    .iter()
                    .map(|&t| {
                        format!(
                            "{t:#x}={:#x}/{:#x}",
                            zkm_recursion_r1cs::tape::term_value(t, public, &expected),
                            zkm_recursion_r1cs::tape::term_value(t, public, witness)
                        )
                    })
                    .collect();
                terms.join(" ^ ")
            })
            .collect();
        return Err(stage(format!(
            "leaf {shard}: {wrong} tape words wrong; the first by level, word {word} (op {}, imm \
             {:#x}), computes {:#x}, the witness has {:#x}; operands (term=lowered/tape) [{}]",
            tape.ops[word],
            tape.imms[word],
            witness[word],
            expected[word],
            operands.join("; ")
        )));
    }
    tracing::info!(
        "word compress: leaf {shard}: the tape computes its {} words, {} levels",
        witness.len(),
        tape.level_starts.len().saturating_sub(1)
    );
    Ok(())
}

fn stage(error: impl std::fmt::Display) -> ZKMRecursionProverError {
    ZKMRecursionProverError::BinaryStage(error.to_string())
}

/// A leaf whose program ran, with what proving it reads.
struct ReadyLeaf {
    shard: usize,
    index: usize,
    key: Arc<WordKey>,
    tape: Arc<zkm_recursion_r1cs::tape::Tape>,
    lowered: Option<zkm_recursion_r1cs::Lowered>,
    new: bool,
    memory: Vec<u32>,
    public_values: Vec<u32>,
    ran: f64,
    keyed: f64,
}

/// A new program's key and scheduled tape, with the leaf it was lowered from, run.
struct MadeKey {
    key: WordKey,
    tape: Arc<zkm_recursion_r1cs::tape::Tape>,
    lowered: Option<zkm_recursion_r1cs::Lowered>,
    memory: Vec<u32>,
    public_values: Vec<u32>,
    ran: f64,
    keyed: f64,
}

/// How many new leaf programs are lowered and keyed at once: `ZIREN_WORD_KEY_BUILDS`, else 2.
/// Each holds its program's lowered relations and key in host memory while it works.
fn key_builders() -> usize {
    std::env::var("ZIREN_WORD_KEY_BUILDS").ok().and_then(|v| v.parse().ok()).unwrap_or(2).max(1)
}

/// The memory blocks of a leaf's run, as canonical words.
fn block_words(blocks: &[zkm_recursion_core::air::Block<KoalaBear>]) -> Vec<u32> {
    blocks.iter().flat_map(|block| block.0.map(|x| x.as_canonical_u32())).collect()
}

/// Whether leaves are proved as routed compositions of their gadgets' templates:
/// `ZIREN_WORD_COMPOSED`.
fn composed_leaves() -> bool {
    std::env::var_os("ZIREN_WORD_COMPOSED").is_some()
}

/// The most consecutive core shards of one structure a leaf verifies,
/// `ZIREN_WORD_LEAF_SHARDS` (one).
fn leaf_shards() -> usize {
    std::env::var("ZIREN_WORD_LEAF_SHARDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&shards| shards > 0)
        .unwrap_or(1)
}

/// The schedule a word tree's nodes are proved under.  A node's parent records its verifier
/// from the node's proof itself, so nothing pins the nodes to the default schedule the fixed
/// binary tree's verifiers are built for, and they trade queries for grinding under the
/// Johnson bound as the root does: half the queries, so half the opening a parent verifies.
fn node_schedule() -> BinarySchedule {
    root_schedule()
}

/// Whether a device readies the next leaf's tape while it proves the one before,
/// `ZIREN_WORD_TAPE_PREFETCH` (on).
fn tape_prefetch() -> bool {
    std::env::var("ZIREN_WORD_TAPE_PREFETCH").map_or(true, |value| value != "0")
}

/// `program`'s relations, lowered over the memory its run left, as a composition when leaves
/// are composed.
fn lower_leaf(
    program: &zkm_recursion_core::RecursionProgram<KoalaBear>,
    blocks: &[zkm_recursion_core::air::Block<KoalaBear>],
) -> Result<zkm_recursion_r1cs::Lowered, ZKMRecursionProverError> {
    tracing::info_span!("leaf lower")
        .in_scope(|| {
            if composed_leaves() {
                zkm_recursion_r1cs::lower_composed(program, Some(blocks))
            } else {
                zkm_recursion_r1cs::lower(program, Some(blocks))
            }
        })
        .map_err(stage)
}

/// The word proof of `leaf` on `backend`.
fn prove_leaf(
    leaf: ReadyLeaf,
    backend: &dyn TapeBackend,
    check: bool,
) -> Result<WordLeaf, ZKMRecursionProverError> {
    let begun = std::time::Instant::now();
    let ReadyLeaf { shard, index, key, tape, lowered, new, memory, public_values, ran, keyed } =
        leaf;
    let constants: Vec<u64> = key.tape_constants().iter().map(|w| w.get()).collect();
    let public =
        tape.public(&constants, &|addr, coefficient| u64::from(memory[4 * addr + coefficient]));
    let devices = backend.word_devices(key.cap_height());
    let held = devices.is_some() && key.routing().is_some();
    let witness = backend.witness(&tape, &public, &memory, held);
    if let (true, Some(lowered)) = (check, &lowered) {
        let words = match &witness {
            LeafWitness::Host(words) => words.clone(),
            LeafWitness::Held(_) => tape
                .evaluate(&public, &|addr, coefficient| u64::from(memory[4 * addr + coefficient])),
        };
        check_tape(shard, &tape, lowered, &public, &words)?;
    }
    drop(lowered);
    let public: Vec<Word64> = public.into_iter().map(Word64::new).collect();
    let evaluated = begun.elapsed().as_secs_f64();
    let statement = key.statement_public(&public);
    let devices = devices.as_ref().map(|d| (d.words, &*d.opening));
    let (words, (commitment, proof, hints)) = match witness {
        LeafWitness::Held(len) => {
            let devices = devices.expect("held words are proved on their device");
            (len, key.prove_held(&public, len, devices, &mut backend.challenger()).map_err(stage)?)
        }
        LeafWitness::Host(witness) => {
            let witness: Vec<Word64> = witness.into_iter().map(Word64::new).collect();
            let proved = key
                .prove_words(&public, &witness, devices, &mut backend.challenger())
                .map_err(stage)?;
            (witness.len(), proved)
        }
    };
    tracing::info!(
        "word compress: leaf {shard}: {} words, key {index}{}, run {ran:.1} s, lower and key \
         {keyed:.1} s, witness {evaluated:.2} s, prove {:.2} s, {} bytes (openings {:?} \
         and ports)",
        words,
        if new { " (new program)" } else { "" },
        begun.elapsed().as_secs_f64() - evaluated,
        proof_size(&proof),
        zkm_recursion_r1cs::prove::proof_parts(&proof)
    );
    Ok(WordLeaf { key, public: statement, public_values, commitment, proof, hints })
}

/// `consume` of every item `produce` makes, `count` of them made in order on this thread and
/// each consumed on a thread of its own per backend, bound to its device; the results in
/// order.  Production stops at the first failure.
fn pipeline<P: Send, T: Send>(
    backends: &[&(dyn TapeBackend + Sync)],
    count: usize,
    mut produce: impl FnMut(usize) -> Result<P, ZKMRecursionProverError>,
    consume: impl Fn(&dyn TapeBackend, P) -> Result<T, ZKMRecursionProverError> + Sync,
) -> Result<Vec<T>, ZKMRecursionProverError> {
    pipeline_unordered(
        backends,
        count,
        |send| {
            for index in 0..count {
                if !send(index, produce(index)?) {
                    break;
                }
            }
            Ok(())
        },
        |_, _| {},
        consume,
    )
}

/// [`pipeline`] with `produce` handing over each of the `count` items with its index, in any
/// order, through the sender it is given, which answers false once an item failed and
/// production should stop; each backend runs `prepare` on its next item, on a thread of its
/// own bound to the device, while it consumes the one before.
fn pipeline_unordered<P: Send, T: Send>(
    backends: &[&(dyn TapeBackend + Sync)],
    count: usize,
    produce: impl FnOnce(&dyn Fn(usize, P) -> bool) -> Result<(), ZKMRecursionProverError>,
    prepare: impl Fn(&dyn TapeBackend, &P) + Sync,
    consume: impl Fn(&dyn TapeBackend, P) -> Result<T, ZKMRecursionProverError> + Sync,
) -> Result<Vec<T>, ZKMRecursionProverError> {
    let failed = AtomicBool::new(false);
    let results: Vec<Mutex<Option<Result<T, ZKMRecursionProverError>>>> =
        (0..count).map(|_| Mutex::new(None)).collect();
    let (sender, receiver) = std::sync::mpsc::channel::<(usize, P)>();
    let receiver = Mutex::new(receiver);
    let produced = std::thread::scope(|scope| {
        for &backend in backends {
            let (receiver, results, failed) = (&receiver, &results, &failed);
            let (prepare, consume) = (&prepare, &consume);
            let (prepared_tx, prepared_rx) = std::sync::mpsc::sync_channel::<(usize, P)>(0);
            scope.spawn(move || {
                backend.bind();
                loop {
                    let next = receiver.lock().expect("the work queue").recv();
                    let Ok((index, item)) = next else { break };
                    prepare(backend, &item);
                    if prepared_tx.send((index, item)).is_err() {
                        break;
                    }
                }
            });
            scope.spawn(move || {
                backend.bind();
                for (index, item) in prepared_rx {
                    let result = consume(backend, item);
                    if result.is_err() {
                        failed.store(true, Ordering::Relaxed);
                    }
                    *results[index].lock().expect("a result slot") = Some(result);
                }
            });
        }
        let produced = {
            let send = |index: usize, item: P| {
                if failed.load(Ordering::Relaxed) {
                    return false;
                }
                sender.send((index, item)).expect("a device thread takes the work");
                true
            };
            produce(&send)
        };
        drop(sender);
        produced
    });
    let mut out = Vec::with_capacity(count);
    for slot in results {
        match slot.into_inner().expect("a result slot") {
            Some(result) => out.push(result?),
            None => return Err(produced.err().unwrap_or_else(|| stage("an item was not proved"))),
        }
    }
    Ok(out)
}

impl<C: ZKMProverComponents> ZKMProver<C> {
    /// Compress `proof` over word proofs; `keys` holds the leaf keys made or
    /// read so far and gains any new one; the nodes are proved on `backend`.
    /// The root and its claims chain are checked; the deferred claims, which
    /// the prover computed from the keys, are evaluated again against the keys
    /// only under `ZIREN_WORD_SELF_CHECK`, a cost of one wiring evaluation per
    /// leaf.
    ///
    /// # Errors
    /// Returns an error if the execution verified deferred proofs, or a leaf
    /// or node fails to prove.
    pub fn compress_word(
        &self,
        vk: &ZKMVerifyingKey,
        proof: &ZKMCoreProof,
        keys: &mut WordKeys,
        backend: &(dyn TapeBackend + Sync),
    ) -> Result<WordCompressedProof, ZKMRecursionProverError> {
        self.compress_word_on(vk, proof, keys, &[backend])
    }

    /// [`Self::compress_word`] with the leaves and the nodes of each level shared among
    /// `backends`, each proving on a thread of its own bound to its device, while this thread
    /// runs the leaves' programs and records the nodes in order.
    ///
    /// # Errors
    /// As [`Self::compress_word`], and an error if there is no backend.
    pub fn compress_word_on(
        &self,
        vk: &ZKMVerifyingKey,
        proof: &ZKMCoreProof,
        keys: &mut WordKeys,
        backends: &[&(dyn TapeBackend + Sync)],
    ) -> Result<WordCompressedProof, ZKMRecursionProverError> {
        if backends.is_empty() {
            return Err(stage("no device to prove on"));
        }
        let last = proof.proof.0.last().ok_or_else(|| stage("the core proof has no shards"))?;
        let last: &zkm_pcs::air::PublicValues<zkm_pcs::Word<KoalaBear>, _> =
            last.public_values.as_slice().borrow();
        if last.deferred_proofs_digest.iter().any(|x| x.as_canonical_u32() != 0) {
            return Err(stage("deferred proofs are not supported by the word compress"));
        }
        let started = std::time::Instant::now();
        let inputs = self.get_recursion_core_inputs(&vk.vk, &proof.proof.0, leaf_shards(), false);
        tracing::info!(
            "word compress: {} leaves over {} shards on {} devices",
            inputs.len(),
            proof.proof.0.len(),
            backends.len()
        );
        let check = std::env::var_os("ZIREN_WORD_TAPE_CHECK").is_some();
        let prefetch = tape_prefetch();
        let leaves = pipeline_unordered(
            backends,
            inputs.len(),
            |send| self.leaves_word_ready(&inputs, keys, check, send),
            |backend, leaf| {
                if prefetch {
                    backend.prefetch(&leaf.tape);
                }
            },
            |backend, leaf| prove_leaf(leaf, backend, check),
        )?;

        let check_keys = false;
        let levels = plan(leaves.len());
        let top = levels.len();
        let mut below: Vec<ProvedNode> = Vec::new();
        let mut claims = Vec::new();
        let mut chain = [0u32; DIGEST_SIZE];
        for (depth, groups) in levels.iter().enumerate() {
            let complete = depth + 1 == top;
            let schedule = if complete { root_schedule() } else { node_schedule() };
            let level = pipeline(
                backends,
                groups.len(),
                |index| {
                    let range = groups[index].clone();
                    let children: Vec<Child<'_>> = if depth == 0 {
                        leaves[range]
                            .iter()
                            .map(|leaf| {
                                Child::word_leaf(
                                    &leaf.key.key,
                                    leaf.key.digest,
                                    &leaf.public,
                                    &leaf.commitment,
                                    &leaf.proof,
                                    leaf.public_values.clone(),
                                    unplaced(),
                                    &leaf_schedule(),
                                    Some(&leaf.hints),
                                    leaf.key.routing(),
                                )
                            })
                            .collect()
                    } else {
                        let child_schedule = node_schedule();
                        below[range]
                            .iter()
                            .map(|node| node.child(unplaced(), &child_schedule))
                            .collect()
                    };
                    let node =
                        record_node_with(children, complete, check_keys, chain).map_err(stage)?;
                    if depth == 0 {
                        for (key, deferred) in &node.composed.claims {
                            chain = advance_claims_native(chain, *key, deferred);
                        }
                        claims.extend(node.composed.claims.iter().cloned());
                    }
                    Ok((index, node))
                },
                |backend, (index, node)| {
                    let begun = std::time::Instant::now();
                    let node = node.prove(&[], &schedule, backend).map_err(stage)?;
                    tracing::info!(
                        "word compress: node at depth {depth} over {:?} in {:.1} s, {} bytes",
                        groups[index],
                        begun.elapsed().as_secs_f64(),
                        node.to_root().proof.len()
                    );
                    Ok(node)
                },
            )?;
            below = level;
        }
        let root = below.pop().ok_or_else(|| stage("the tree has no root"))?;
        let compressed =
            WordCompressedProof { root: root.to_root(), claims, keys_checked: check_keys };
        if std::env::var_os("ZIREN_WORD_SELF_CHECK").is_some() {
            Self::verify_word_compressed(&compressed, keys.as_slice())?;
        } else {
            Self::verify_word_root(&compressed)?;
        }
        tracing::info!(
            "word compress: {} leaves to a root in {:.1} s",
            leaves.len(),
            started.elapsed().as_secs_f64()
        );
        Ok(compressed)
    }

    /// Every leaf of `inputs` run and handed to `send` with its key and tape: first those whose
    /// program has a key in `keys`, in order, then each new program's leaves once its key is
    /// made.  The new programs are lowered and keyed [`key_builders`] at a time, the largest
    /// first, while the known leaves are proved.
    fn leaves_word_ready(
        &self,
        inputs: &[ZKMCoreWitnessValues<CoreSC>],
        keys: &mut WordKeys,
        check: bool,
        send: &dyn Fn(usize, ReadyLeaf) -> bool,
    ) -> Result<(), ZKMRecursionProverError> {
        let mut shapes = std::collections::HashMap::new();
        for (shard, input) in inputs.iter().enumerate() {
            shapes.entry(input.shape_key()).or_insert(shard);
        }
        let firsts: Vec<usize> = shapes.into_values().collect();
        tracing::info_span!("leaf programs", shapes = firsts.len()).in_scope(|| {
            firsts.par_iter().for_each(|&shard| {
                self.recursion_program(&inputs[shard]);
            })
        });
        let programs: Vec<_> = inputs.iter().map(|input| self.recursion_program(input)).collect();

        let mut groups: Vec<([u8; 32], Vec<usize>)> = Vec::new();
        for (shard, (_, digest)) in programs.iter().enumerate() {
            match groups.iter_mut().find(|(d, _)| d == digest) {
                Some((_, shards)) => shards.push(shard),
                None => groups.push((*digest, vec![shard])),
            }
        }
        let (known, mut new): (Vec<_>, Vec<_>) =
            groups.into_iter().partition(|(digest, _)| keys.program(digest).is_some());
        new.sort_by_key(|(_, shards)| std::cmp::Reverse(programs[shards[0]].0.total_memory));
        let mut known: Vec<usize> = known.into_iter().flat_map(|(_, shards)| shards).collect();
        known.sort_by_key(|&shard| (keys.program(&programs[shard].1).map(|(key, _)| key), shard));

        let maker = keys.maker();
        let builders = key_builders().min(new.len());
        let queue = Mutex::new(new.into_iter().collect::<std::collections::VecDeque<_>>());
        let stop = AtomicBool::new(false);
        let (made_tx, made_rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            for _ in 0..builders {
                let (queue, stop, made_tx, maker, programs) =
                    (&queue, &stop, made_tx.clone(), &maker, &programs);
                scope.spawn(move || loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let Some((digest, shards)) = queue.lock().expect("the key queue").pop_front()
                    else {
                        break;
                    };
                    let made = self.leaf_word_key(
                        &inputs[shards[0]],
                        &programs[shards[0]].0,
                        maker,
                        check,
                    );
                    if made_tx.send((digest, shards, made)).is_err() {
                        break;
                    }
                });
            }
            drop(made_tx);
            let result = (|| {
                for &shard in &known {
                    let (key, tape) = keys.program(&programs[shard].1).expect("a known program");
                    let leaf = self.leaf_word_known(
                        shard,
                        &inputs[shard],
                        &programs[shard].0,
                        key,
                        tape,
                        keys,
                        check,
                    )?;
                    if !send(shard, leaf) {
                        return Ok(());
                    }
                }
                for (digest, shards, made) in made_rx.iter() {
                    let made = made?;
                    let key = keys.insert(made.key);
                    keys.insert_tape(digest, key, made.tape.clone());
                    let first = ReadyLeaf {
                        shard: shards[0],
                        index: key,
                        key: keys.as_slice()[key].clone(),
                        tape: made.tape.clone(),
                        lowered: made.lowered,
                        new: true,
                        memory: made.memory,
                        public_values: made.public_values,
                        ran: made.ran,
                        keyed: made.keyed,
                    };
                    if !send(shards[0], first) {
                        return Ok(());
                    }
                    for &shard in &shards[1..] {
                        let leaf = self.leaf_word_known(
                            shard,
                            &inputs[shard],
                            &programs[shard].0,
                            key,
                            made.tape.clone(),
                            keys,
                            check,
                        )?;
                        if !send(shard, leaf) {
                            return Ok(());
                        }
                    }
                }
                Ok(())
            })();
            stop.store(true, Ordering::Relaxed);
            result
        })
    }

    /// The leaf `shard` of `program`, whose key is at `key` in `keys` and whose witness `tape`
    /// computes, run on `input`.
    #[allow(clippy::too_many_arguments)]
    fn leaf_word_known(
        &self,
        shard: usize,
        input: &ZKMCoreWitnessValues<CoreSC>,
        program: &Arc<RecursionProgram<KoalaBear>>,
        key: usize,
        tape: Arc<zkm_recursion_r1cs::tape::Tape>,
        keys: &WordKeys,
        check: bool,
    ) -> Result<ReadyLeaf, ZKMRecursionProverError> {
        let begun = std::time::Instant::now();
        let (blocks, public_values) = self.leaf_word_execute(program, input)?;
        let ran = begun.elapsed().as_secs_f64();
        let lowered = if check { Some(lower_leaf(program, &blocks)?) } else { None };
        Ok(ReadyLeaf {
            shard,
            index: key,
            key: keys.as_slice()[key].clone(),
            tape,
            lowered,
            new: false,
            memory: block_words(&blocks),
            public_values,
            ran,
            keyed: begun.elapsed().as_secs_f64() - ran,
        })
    }

    /// The key and scheduled tape of `program`, lowered from its run on `input`, which is
    /// kept as that leaf's.
    fn leaf_word_key(
        &self,
        input: &ZKMCoreWitnessValues<CoreSC>,
        program: &Arc<RecursionProgram<KoalaBear>>,
        maker: &KeyMaker,
        check: bool,
    ) -> Result<MadeKey, ZKMRecursionProverError> {
        let begun = std::time::Instant::now();
        let (blocks, public_values) = self.leaf_word_execute(program, input)?;
        let ran = begun.elapsed().as_secs_f64();
        let mut lowered = lower_leaf(program, &blocks)?;
        let key = if lowered.composed.is_some() {
            WordKey::composed(&mut lowered, &leaf_schedule())
        } else if check {
            maker.make(
                &lowered.built,
                relations_digest(&lowered.built, DIGEST_SIZE),
                &leaf_schedule(),
            )
        } else {
            let digest = relations_digest(&lowered.built, DIGEST_SIZE);
            maker.make_taking(&mut lowered.built, digest, &leaf_schedule())
        }
        .map_err(stage)?;
        let mut tape = std::mem::take(&mut lowered.tape);
        tracing::info_span!("schedule tape").in_scope(|| tape.schedule());
        Ok(MadeKey {
            key,
            tape: Arc::new(tape),
            lowered: check.then_some(lowered),
            memory: block_words(&blocks),
            public_values,
            ran,
            keyed: begun.elapsed().as_secs_f64() - ran,
        })
    }

    /// [`Self::verify_word_root`] for `vk`'s program: the root's public values
    /// must also close a complete execution of that program.  The claims are
    /// not checked: that takes the leaves' keys ([`Self::verify_word_compressed`]).
    ///
    /// # Errors
    /// Returns why the proof does not verify.
    pub fn verify_word_program(
        proof: &WordCompressedProof,
        vk: &ZKMVerifyingKey,
    ) -> Result<(), ZKMRecursionProverError> {
        let values = &proof.root.public_values;
        if values.len() < zkm_recursion_core::air::RECURSIVE_PROOF_NUM_PV_ELTS {
            return Err(stage("the root's public values are short"));
        }
        let public_values: &RecursionPublicValues<u32> = values.as_slice().borrow();
        if public_values.is_complete != 1 {
            return Err(stage("the execution is not complete"));
        }
        let vk_digest = <crate::CoreSC as crate::types::RingDigests>::vk_public_digest(&vk.vk)
            .map(|x| x.as_canonical_u32());
        if public_values.zkm_vk_digest != vk_digest {
            return Err(stage("the proof is of another program"));
        }
        Self::verify_word_root(proof)
    }

    /// Verify a core proof compressed over word proofs: the root's proof,
    /// that the claims chain its public values end with is the chain of
    /// `proof`'s claims, and every claim against the key it names.
    ///
    /// # Errors
    /// Returns why the proof does not verify.
    pub fn verify_word_compressed(
        proof: &WordCompressedProof,
        keys: &[Arc<WordKey>],
    ) -> Result<(), ZKMRecursionProverError> {
        Self::verify_word_root(proof)?;
        for (digest, claims) in &proof.claims {
            let key = keys
                .iter()
                .find(|key| &key.digest == digest)
                .ok_or_else(|| stage("a claim names a key that is not known"))?;
            let public = key.public(&[p3_word::Word64::new(0); DIGEST_SIZE]);
            for claim in claims {
                let value = key.key.deferred(claim.kind, &public, key.outputs, &claim.query);
                if value != claim.value {
                    return Err(stage(format!("a deferred {:?} claim does not hold", claim.kind)));
                }
            }
        }
        Ok(())
    }

    /// Verify the root of a word-compressed proof: its proof, and that the
    /// claims chain its public values end with is the chain of the claims.
    ///
    /// # Errors
    /// Returns why the proof does not verify.
    pub fn verify_word_root(proof: &WordCompressedProof) -> Result<(), ZKMRecursionProverError> {
        proof.root.verify(&root_schedule()).map_err(stage)?;
        if proof.root.public_values.len() < zkm_recursion_core::air::RECURSIVE_PROOF_NUM_PV_ELTS {
            return Err(stage("the root's public values are short"));
        }
        let elements: Vec<KoalaBear> =
            proof.root.public_values.iter().map(|&v| KoalaBear::from_u32(v)).collect();
        let public_values: &RecursionPublicValues<KoalaBear> = elements.as_slice().borrow();
        let mut chain = [0u32; DIGEST_SIZE];
        for (key, claims) in &proof.claims {
            chain = advance_claims_native(chain, *key, claims);
        }
        let end = public_values.end_reconstruct_deferred_digest.map(|x| x.as_canonical_u32());
        if end != chain {
            return Err(stage("the root's claims chain is not the claims' chain"));
        }
        Ok(())
    }
}

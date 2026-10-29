//! The compress of a core proof over bits: a leaf per core shard, proved by
//! the recursion machine over `GF(2^128)`, then a tree of compose nodes
//! proved by the tape machine, two children to a node, whose root closes
//! the execution.
//!
//! A node checks each child's key against the key tree its children carry,
//! so every key the tree uses is in the tree before the first leaf is
//! proved.  A leaf's key is its program's machine at its class's floor; a
//! node's key is the program of its level, which depends only on its
//! children's shapes, so it is recorded over sample proofs of those shapes.
//! Keys and samples are kept in a [`BinaryKeyStore`]; the key tree here is
//! the recursion key tree with every stored binary key added, a development
//! tree until the binary keys join the published one.

use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::path::PathBuf;

use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;
use serde::{Deserialize, Serialize};
use zkm_binary_recursion::compose::{Child, VkMembership};
use zkm_binary_recursion::machine::{TapeMachine, NODE_FLOOR, UPPER_NODE_FLOOR};
use zkm_binary_recursion::node::{
    leaf_key_digest, node_key, prove_node, BinaryRootProof, ProvedNode,
};
use zkm_binary_stark::machine::{leaf_class, ProvedProgram, RecursionMachine, LEAF_CLASSES};
use zkm_binary_stark::BinarySchedule;
use zkm_recursion_circuit::blake3_circuit::{digest_limbs, limbs_digest};
use zkm_recursion_circuit::hash::FieldHasher;
use zkm_recursion_circuit::machine::ZKMCoreBasefoldWitnessValues;
use zkm_recursion_circuit::merkle_tree::MerkleTree;
use zkm_recursion_core::air::RecursionPublicValues;
use zkm_recursion_core::VK_MERKLE_TREE_HEIGHT;

use crate::components::ZKMProverComponents;
use crate::types::RingDigests;
use crate::{
    BinaryLeafProof, CoreSC, InnerSC, VkDigest, ZKMCoreProof, ZKMProver, ZKMRecursionProverError,
    ZKMVerifyingKey,
};

/// A core proof compressed over bits: the root of the tree, and the place of
/// its key in the key tree its public values name.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BinaryCompressedProof {
    pub root: BinaryRootProof,
    pub membership_index: usize,
    pub membership_path: Vec<[u8; 32]>,
}

/// The schedule the root of a tree is proved under.  No node verifies the
/// root, so it alone trades queries for grinding under the Johnson bound,
/// which keeps its proof under 300 KiB; the nodes below stay on the default
/// schedule their parents' verifiers are built for.
#[must_use]
pub fn root_schedule() -> BinarySchedule {
    BinarySchedule {
        regime: zkm_binary_stark::WhirRegime::Johnson,
        log_inv_rate: 2,
        folding: 3,
        ..BinarySchedule::default()
    }
}

/// The level of a compose node, which fixes what its children are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Level {
    /// Over leaves, at [`NODE_FLOOR`].
    First,
    /// Over first-level nodes, at [`UPPER_NODE_FLOOR`].
    Second,
    /// Over second-level or higher nodes, at [`UPPER_NODE_FLOOR`].
    Upper,
}

impl Level {
    fn of(depth: usize) -> Self {
        match depth {
            1 => Self::First,
            2 => Self::Second,
            _ => Self::Upper,
        }
    }

    const fn floor(self) -> &'static [(&'static str, usize)] {
        match self {
            Self::First => NODE_FLOOR,
            Self::Second | Self::Upper => UPPER_NODE_FLOOR,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::First => "first",
            Self::Second => "second",
            Self::Upper => "upper",
        }
    }
}

/// What fixes a node's program: its level, its children's leaf classes for
/// a first-level node, and whether it closes the execution.  The number of
/// children is the length of `classes`, or `arity` above the first level.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Family {
    level: usize,
    arity: usize,
    classes: Vec<usize>,
    complete: bool,
}

impl Family {
    fn level(&self) -> Level {
        Level::of(self.level)
    }

    /// The schedule the family's nodes are proved under.
    fn schedule(&self) -> BinarySchedule {
        if self.complete {
            root_schedule()
        } else {
            BinarySchedule::default()
        }
    }

    fn name(&self) -> String {
        let classes: Vec<String> = self.classes.iter().map(usize::to_string).collect();
        format!(
            "{}-{}-{}-{}",
            self.level().name(),
            self.arity,
            if classes.is_empty() { "any".to_string() } else { classes.join(".") },
            if self.complete { "root" } else { "open" }
        )
    }
}

/// The tree over `n` leaves: each level pairs the one below in order, an
/// odd last one alone, until one node is left, which closes the execution.
/// Each level lists its nodes as ranges of the level below.
pub(crate) fn plan(n: usize) -> Vec<Vec<std::ops::Range<usize>>> {
    let mut levels = Vec::new();
    let mut width = n;
    loop {
        let groups: Vec<_> = (0..width).step_by(2).map(|i| i..(i + 2).min(width)).collect();
        width = groups.len();
        levels.push(groups);
        if width == 1 {
            return levels;
        }
    }
}

/// The families of the nodes of the tree over leaves of `classes`, level by
/// level, in the order of [`plan`].
fn families(classes: &[usize]) -> Vec<Vec<Family>> {
    let levels = plan(classes.len());
    let top = levels.len();
    levels
        .iter()
        .enumerate()
        .map(|(depth, groups)| {
            groups
                .iter()
                .map(|range| Family {
                    level: (depth + 1).min(3),
                    arity: range.len(),
                    classes: if depth == 0 { classes[range.clone()].to_vec() } else { Vec::new() },
                    complete: depth + 1 == top,
                })
                .collect()
        })
        .collect()
}

/// Binary keys and the sample proofs node keys are recorded over, kept on
/// disk: `leaf/<program digest>` and `node/<family>` hold key digests in
/// hex, `samples/` the proofs.
pub struct BinaryKeyStore {
    dir: PathBuf,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<[u8; 32]> {
    let text = text.trim();
    (text.len() == 64).then_some(())?;
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

impl BinaryKeyStore {
    /// The store at `ZIREN_BINARY_KEY_DIR`, or under the home directory.
    #[must_use]
    pub fn from_env() -> Self {
        let dir = std::env::var_os("ZIREN_BINARY_KEY_DIR").map_or_else(
            || {
                let home = std::env::var_os("HOME").unwrap_or_default();
                PathBuf::from(home).join(".zkm").join("binary-keys")
            },
            PathBuf::from,
        );
        Self { dir }
    }

    #[must_use]
    pub const fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn key(&self, kind: &str, name: &str) -> Option<[u8; 32]> {
        std::fs::read_to_string(self.dir.join(kind).join(name)).ok().and_then(|t| unhex(&t))
    }

    fn put_key(&self, kind: &str, name: &str, digest: &[u8; 32]) -> std::io::Result<()> {
        std::fs::create_dir_all(self.dir.join(kind))?;
        std::fs::write(self.dir.join(kind).join(name), hex(digest))
    }

    /// Every stored key digest.
    fn all_keys(&self) -> Vec<[u8; 32]> {
        let mut keys = Vec::new();
        for kind in ["leaf", "node"] {
            let Ok(entries) = std::fs::read_dir(self.dir.join(kind)) else { continue };
            for entry in entries.flatten() {
                if let Some(digest) =
                    std::fs::read_to_string(entry.path()).ok().and_then(|t| unhex(&t))
                {
                    keys.push(digest);
                }
            }
        }
        keys.sort_unstable();
        keys.dedup();
        keys
    }

    fn sample_path(&self, name: &str) -> PathBuf {
        self.dir.join("samples").join(name)
    }

    fn leaf_sample(&self, class: usize) -> Option<ProvedProgram> {
        let bytes = std::fs::read(self.sample_path(&format!("leaf-{class}"))).ok()?;
        ProvedProgram::from_bytes(&bytes).ok()
    }

    fn put_leaf_sample(&self, class: usize, leaf: BinaryLeafProof) -> std::io::Result<()> {
        let sample = ProvedProgram {
            program: (*leaf.program).clone(),
            digest: leaf.digest,
            public_values: leaf.public_values,
            proof: leaf.proof,
        };
        std::fs::create_dir_all(self.dir.join("samples"))?;
        let bytes = sample.to_bytes().map_err(std::io::Error::other)?;
        std::fs::write(self.sample_path(&format!("leaf-{class}")), bytes)
    }

    fn node_sample(&self, level: Level) -> Option<BinaryRootProof> {
        let bytes = std::fs::read(self.sample_path(&format!("node-{}", level.name()))).ok()?;
        bincode::deserialize(&bytes).ok()
    }

    fn put_node_sample(&self, level: Level, node: &ProvedNode) -> std::io::Result<()> {
        let sample = node.to_root();
        std::fs::create_dir_all(self.dir.join("samples"))?;
        let bytes = bincode::serialize(&sample).map_err(std::io::Error::other)?;
        std::fs::write(self.sample_path(&format!("node-{}", level.name())), bytes)
    }
}

/// The key tree: the recursion keys and the binary keys, each at its index.
struct KeyTree {
    map: BTreeMap<VkDigest, usize>,
    tree: MerkleTree<KoalaBear, InnerSC>,
    root: VkDigest,
}

impl KeyTree {
    fn new(recursion: &BTreeMap<VkDigest, usize>, binary: &[[u8; 32]]) -> Self {
        let mut keys: Vec<VkDigest> = recursion.keys().copied().collect();
        keys.extend(binary.iter().map(digest_limbs));
        keys.sort();
        keys.dedup();
        assert!(keys.len() <= 1 << VK_MERKLE_TREE_HEIGHT, "the key tree holds every key");
        let map = keys.iter().enumerate().map(|(i, &k)| (k, i)).collect();
        let mut leaves = keys;
        leaves.resize(1 << VK_MERKLE_TREE_HEIGHT, VkDigest::default());
        let (root, tree) = MerkleTree::commit(leaves);
        Self { map, tree, root }
    }

    /// The place of `digest`, if the tree holds it.
    fn membership(&self, digest: &[u8; 32]) -> Option<VkMembership> {
        let index = *self.map.get(&digest_limbs(digest))?;
        let (_, proof) = MerkleTree::open(&self.tree, index);
        Some(VkMembership {
            index: proof.index,
            path: proof.path.iter().map(limbs_digest).collect(),
        })
    }

    fn root_felts(&self) -> [KoalaBear; zkm_recursion_core::DIGEST_SIZE] {
        <InnerSC as RingDigests>::public_felts(self.root)
    }
}

/// A placeholder place in the key tree, for a program recorded but not run.
fn unplaced() -> VkMembership {
    VkMembership { index: 0, path: vec![[0; 32]; VK_MERKLE_TREE_HEIGHT] }
}

fn stage(error: impl std::fmt::Display) -> ZKMRecursionProverError {
    ZKMRecursionProverError::BinaryStage(error.to_string())
}

/// A distinct leaf program of the run: its class, its key, and the machine
/// that proves and verifies its leaves, whose proving key is dropped after
/// its last leaf.
struct LeafProgram {
    program: std::sync::Arc<zkm_recursion_core::RecursionProgram<KoalaBear>>,
    class: usize,
    key: [u8; 32],
    machine: Option<RecursionMachine>,
    last: usize,
}

/// A proved leaf and the program it is of.
struct ProvedLeaf {
    program: [u8; 32],
    proof: BinaryLeafProof,
}

impl ProvedLeaf {
    fn child<'a>(
        &'a self,
        programs: &'a BTreeMap<[u8; 32], LeafProgram>,
        keys: &KeyTree,
        schedule: &BinarySchedule,
    ) -> Child<'a> {
        let program = &programs[&self.program];
        Child::leaf(
            program.machine.as_ref().expect("a proved leaf's machine is kept"),
            &self.proof.proof,
            self.proof.public_values.clone(),
            keys.membership(&program.key).unwrap_or_else(unplaced),
            schedule,
        )
    }
}

impl<C: ZKMProverComponents> ZKMProver<C> {
    /// Compress `proof` over bits, with keys and samples from `store`.
    ///
    /// # Errors
    /// Returns an error if the execution verified deferred proofs, a shard's
    /// program has no leaf class, a key cannot be had, or a leaf or node fails
    /// to prove.
    pub fn compress_binary(
        &self,
        vk: &ZKMVerifyingKey,
        proof: &ZKMCoreProof,
        store: &BinaryKeyStore,
    ) -> Result<BinaryCompressedProof, ZKMRecursionProverError> {
        let last = proof.proof.0.last().ok_or_else(|| stage("the core proof has no shards"))?;
        let last: &zkm_pcs::air::PublicValues<zkm_pcs::Word<KoalaBear>, KoalaBear> =
            last.public_values.as_slice().borrow();
        if last.deferred_proofs_digest.iter().any(|x| x.as_canonical_u32() != 0) {
            return Err(stage("deferred proofs are not supported by the binary compress"));
        }
        let schedule = BinarySchedule::default();
        let mut inputs = self.get_recursion_core_inputs_basefold(&vk.vk, &proof.proof.0, 1, false);
        let started = std::time::Instant::now();
        let mut programs: BTreeMap<[u8; 32], LeafProgram> = BTreeMap::new();
        let mut of_shard = Vec::with_capacity(inputs.len());
        for (shard, input) in inputs.iter().enumerate() {
            let (program, digest) = self.recursion_program_basefold(input);
            if let Some(known) = programs.get_mut(&digest) {
                known.last = shard;
            } else {
                let class = leaf_class(&program).map_err(stage)?.ok_or_else(|| {
                    stage(format!("no leaf class covers the program of shard {shard}"))
                })?;
                let (key, machine) = match store.key("leaf", &hex(&digest)) {
                    Some(key) => (key, None),
                    None => {
                        let machine = self.binary_machine(&program, LEAF_CLASSES[class])?;
                        let key = leaf_key_digest(&machine);
                        store.put_key("leaf", &hex(&digest), &key).map_err(stage)?;
                        (key, Some(machine))
                    }
                };
                programs.insert(digest, LeafProgram { program, class, key, machine, last: shard });
            }
            of_shard.push(digest);
        }
        let classes: Vec<usize> = of_shard.iter().map(|digest| programs[digest].class).collect();
        tracing::info!(
            "binary compress: {} leaves of {} programs, classes {:?}, keys in {:.1} s",
            inputs.len(),
            programs.len(),
            classes.iter().fold([0usize; 3], |mut n, &c| {
                n[c] += 1;
                n
            }),
            started.elapsed().as_secs_f64()
        );

        let families = families(&classes);
        self.binary_samples(store, &mut inputs, &classes, &families)?;
        for family in families.iter().flatten() {
            self.binary_node_key(store, family, &schedule)?;
        }

        let keys = KeyTree::new(&self.recursion_vk_map, &store.all_keys());
        for input in &mut inputs {
            input.vk_root = keys.root_felts();
        }
        let mut order: Vec<usize> = (0..inputs.len()).collect();
        order.sort_by_key(|&shard| (of_shard[shard], shard));
        let mut proved: Vec<Option<ProvedLeaf>> = (0..inputs.len()).map(|_| None).collect();
        for shard in order {
            let (input, digest) = (&inputs[shard], &of_shard[shard]);
            let started = std::time::Instant::now();
            let entry = programs.get_mut(digest).expect("every shard's program is known");
            if entry.machine.is_none() {
                entry.machine =
                    Some(self.binary_machine(&entry.program, LEAF_CLASSES[entry.class])?);
            }
            let machine = entry.machine.as_mut().expect("the machine was just set up");
            let proof = self.leaf_binary_on(machine, entry.program.clone(), input)?;
            if entry.last == shard {
                machine.drop_proving_key();
            }
            tracing::info!(
                "binary compress: leaf {shard} of class {} in {:.1} s",
                entry.class,
                started.elapsed().as_secs_f64()
            );
            proved[shard] = Some(ProvedLeaf { program: *digest, proof });
        }
        let leaves: Vec<ProvedLeaf> =
            proved.into_iter().map(|leaf| leaf.expect("every shard is proved")).collect();

        let root = self.binary_levels(&leaves, &programs, &families, &keys, &schedule)?;
        let digest = root.key_digest();
        let membership = keys
            .membership(&digest)
            .ok_or_else(|| stage("the root's key is not in the key tree"))?;
        let compressed = BinaryCompressedProof {
            root: root.to_root(),
            membership_index: membership.index,
            membership_path: membership.path,
        };
        self.verify_binary_compressed(&compressed, vk, Some(keys.root))?;
        tracing::info!(
            "binary compress: {} leaves to a root in {:.1} s",
            leaves.len(),
            started.elapsed().as_secs_f64()
        );
        Ok(compressed)
    }

    /// Prove the node levels over `leaves`, returning the root.
    fn binary_levels(
        &self,
        leaves: &[ProvedLeaf],
        programs: &BTreeMap<[u8; 32], LeafProgram>,
        families: &[Vec<Family>],
        keys: &KeyTree,
        schedule: &BinarySchedule,
    ) -> Result<ProvedNode, ZKMRecursionProverError> {
        let levels = plan(leaves.len());
        let mut below: Vec<ProvedNode> = Vec::new();
        for (depth, groups) in levels.iter().enumerate() {
            let mut level = Vec::with_capacity(groups.len());
            for (range, family) in groups.iter().zip(&families[depth]) {
                let started = std::time::Instant::now();
                let children: Vec<Child<'_>> = if depth == 0 {
                    leaves[range.clone()]
                        .iter()
                        .map(|leaf| leaf.child(programs, keys, schedule))
                        .collect()
                } else {
                    below[range.clone()]
                        .iter()
                        .map(|node| {
                            node.child(
                                keys.membership(&node.key_digest()).unwrap_or_else(unplaced),
                                schedule,
                            )
                        })
                        .collect()
                };
                let node = prove_node(
                    children,
                    family.complete,
                    family.level().floor(),
                    &family.schedule(),
                )
                .map_err(stage)?;
                tracing::info!(
                    "binary compress: node {} over {:?} in {:.1} s",
                    family.name(),
                    range,
                    started.elapsed().as_secs_f64()
                );
                level.push(node);
            }
            below = level;
        }
        below.pop().ok_or_else(|| stage("the tree has no root"))
    }

    /// The key of the nodes of `family`, recorded over samples when the
    /// store does not hold it.
    fn binary_node_key(
        &self,
        store: &BinaryKeyStore,
        family: &Family,
        schedule: &BinarySchedule,
    ) -> Result<[u8; 32], ZKMRecursionProverError> {
        if let Some(key) = store.key("node", &family.name()) {
            return Ok(key);
        }
        let started = std::time::Instant::now();
        let key = match family.level() {
            Level::First => {
                let samples = family
                    .classes
                    .iter()
                    .map(|&class| {
                        let sample = store
                            .leaf_sample(class)
                            .ok_or_else(|| stage(format!("no sample leaf of class {class}")))?;
                        let machine = RecursionMachine::verifier_with_floor(
                            &sample.program,
                            schedule,
                            LEAF_CLASSES[class],
                        )
                        .map_err(stage)?;
                        Ok((machine, sample))
                    })
                    .collect::<Result<Vec<_>, ZKMRecursionProverError>>()?;
                let children = samples
                    .iter()
                    .map(|(machine, sample)| {
                        Child::leaf(
                            machine,
                            &sample.proof,
                            sample.public_values.clone(),
                            unplaced(),
                            schedule,
                        )
                    })
                    .collect();
                node_key(children, family.complete, NODE_FLOOR, &family.schedule())
                    .map_err(stage)?
            }
            level => {
                let below = if level == Level::Second { Level::First } else { Level::Upper };
                let sample = store
                    .node_sample(below)
                    .ok_or_else(|| stage(format!("no sample {} node", below.name())))?;
                let machine = TapeMachine::from_key(&sample.key, schedule)
                    .map_err(|e| stage(format!("{e:?}")))?;
                let proof = sample.machine_proof().map_err(stage)?;
                let children = (0..family.arity)
                    .map(|_| {
                        Child::node(
                            &machine,
                            &proof,
                            sample.public_values.clone(),
                            unplaced(),
                            schedule,
                        )
                    })
                    .collect();
                node_key(children, family.complete, UPPER_NODE_FLOOR, &family.schedule())
                    .map_err(stage)?
            }
        };
        store.put_key("node", &family.name(), &key).map_err(stage)?;
        tracing::info!(
            "binary compress: key of {} recorded in {:.1} s",
            family.name(),
            started.elapsed().as_secs_f64()
        );
        Ok(key)
    }

    /// Make the samples the tree's node keys are recorded over, when the
    /// store lacks them: a leaf of each class the first level reads, and a
    /// node of each level the levels above read.  A sample is any valid
    /// proof of its shape; a sample node's children are proved under a key
    /// tree that holds their keys, so the node's run succeeds.
    fn binary_samples(
        &self,
        store: &BinaryKeyStore,
        inputs: &mut [ZKMCoreBasefoldWitnessValues<CoreSC>],
        classes: &[usize],
        families: &[Vec<Family>],
    ) -> Result<(), ZKMRecursionProverError> {
        let schedule = BinarySchedule::default();
        let needed: std::collections::BTreeSet<usize> =
            families[0].iter().flat_map(|family| family.classes.iter().copied()).collect();
        for class in needed {
            if store.leaf_sample(class).is_some() {
                continue;
            }
            let shard = classes.iter().position(|&c| c == class).expect("a leaf of the class");
            let started = std::time::Instant::now();
            let leaf = self.leaf_binary(&inputs[shard])?;
            store.put_leaf_sample(class, leaf).map_err(stage)?;
            tracing::info!(
                "binary compress: sample leaf of class {class} in {:.1} s",
                started.elapsed().as_secs_f64()
            );
        }
        let wants_first = families.len() >= 2 && store.node_sample(Level::First).is_none();
        let wants_upper = families.len() >= 3 && store.node_sample(Level::Upper).is_none();
        if !wants_first && !wants_upper {
            return Ok(());
        }
        let count = if wants_upper { 4 } else { 2 };
        let chain: Vec<usize> = (0..count).collect();
        let first_families: Vec<Family> = chain
            .chunks(2)
            .map(|pair| Family {
                level: 1,
                arity: 2,
                classes: pair.iter().map(|&i| classes[i]).collect(),
                complete: false,
            })
            .collect();
        for family in &first_families {
            self.binary_node_key(store, family, &schedule)?;
        }
        let keys = KeyTree::new(&self.recursion_vk_map, &store.all_keys());
        let leaves = chain
            .iter()
            .map(|&i| {
                let mut input = inputs[i].clone();
                input.vk_root = keys.root_felts();
                let (machine, proof) = self.leaf_binary_with_machine(&input)?;
                let key = leaf_key_digest(&machine);
                Ok((machine, proof, key))
            })
            .collect::<Result<Vec<_>, ZKMRecursionProverError>>()?;
        let firsts = leaves
            .chunks(2)
            .map(|pair| {
                let children = pair
                    .iter()
                    .map(|(machine, proof, key)| {
                        Child::leaf(
                            machine,
                            &proof.proof,
                            proof.public_values.clone(),
                            keys.membership(key).unwrap_or_else(unplaced),
                            &schedule,
                        )
                    })
                    .collect();
                prove_node(children, false, NODE_FLOOR, &schedule).map_err(stage)
            })
            .collect::<Result<Vec<_>, ZKMRecursionProverError>>()?;
        store.put_node_sample(Level::First, &firsts[0]).map_err(stage)?;
        if wants_upper {
            let children = firsts
                .iter()
                .map(|node| {
                    node.child(
                        keys.membership(&node.key_digest()).unwrap_or_else(unplaced),
                        &schedule,
                    )
                })
                .collect();
            let upper = prove_node(children, false, UPPER_NODE_FLOOR, &schedule).map_err(stage)?;
            store.put_node_sample(Level::Upper, &upper).map_err(stage)?;
        }
        tracing::info!("binary compress: sample nodes proved");
        Ok(())
    }

    /// Verify a core proof compressed over bits: the root's proof against the
    /// machine its key rebuilds, its key's place in the key tree its public
    /// values name, and those values: a complete execution of `vk`'s program
    /// under `expected_root` when one is given.
    ///
    /// # Errors
    /// Returns why the proof does not verify.
    pub fn verify_binary_compressed(
        &self,
        proof: &BinaryCompressedProof,
        vk: &ZKMVerifyingKey,
        expected_root: Option<VkDigest>,
    ) -> Result<(), ZKMRecursionProverError> {
        let digest = proof.root.verify(&root_schedule()).map_err(stage)?;
        let values = &proof.root.public_values;
        if values.len() < zkm_recursion_core::air::RECURSIVE_PROOF_NUM_PV_ELTS {
            return Err(stage("the root's public values are short"));
        }
        let public_values: &RecursionPublicValues<u32> = values.as_slice().borrow();
        let height = proof.membership_path.len();
        let mut index = (0..height).fold(0usize, |reversed, k| {
            reversed | (((proof.membership_index >> k) & 1) << (height - 1 - k))
        });
        let mut current = digest_limbs(&digest);
        for sibling in &proof.membership_path {
            let sibling = digest_limbs(sibling);
            let pair = if index % 2 == 0 { [current, sibling] } else { [sibling, current] };
            current = <InnerSC as FieldHasher<KoalaBear>>::constant_compress(pair);
            index >>= 1;
        }
        let named_root =
            <InnerSC as RingDigests>::public_felts(current).map(|x| x.as_canonical_u32());
        if public_values.vk_root != named_root {
            return Err(stage("the root's key is not in the key tree its public values name"));
        }
        if let Some(expected) = expected_root {
            let expected =
                <InnerSC as RingDigests>::public_felts(expected).map(|x| x.as_canonical_u32());
            if public_values.vk_root != expected {
                return Err(stage("the key tree is not the expected one"));
            }
        }
        if public_values.is_complete != 1 {
            return Err(stage("the execution is not complete"));
        }
        let vk_digest =
            <CoreSC as RingDigests>::vk_public_digest(&vk.vk).map(|x| x.as_canonical_u32());
        if public_values.zkm_vk_digest != vk_digest {
            return Err(stage("the proof is of another program"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_pair_each_level() {
        assert_eq!(plan(1), vec![vec![0..1]]);
        assert_eq!(plan(2), vec![vec![0..2]]);
        assert_eq!(plan(5), vec![vec![0..2, 2..4, 4..5], vec![0..2, 2..3], vec![0..2]]);
        let families = families(&[0, 1, 0, 0, 2]);
        assert_eq!(families.len(), 3);
        assert_eq!(families[0][2].classes, vec![2]);
        assert!(families[2][0].complete && !families[1][0].complete);
        assert_eq!(families[2][0].name(), "upper-2-any-root");
        assert_eq!(families[1][1].name(), "second-1-any-open");
    }
}

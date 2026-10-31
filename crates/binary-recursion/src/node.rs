//! Compose nodes proved, and the proof a tree's root leaves.
//!
//! A node records its verification of its children, lays the tape out for
//! the tape machine at the floor of its level, and proves the run.  The
//! root of a tree is a node that closes the execution; its proof carries
//! the parts of its key a verifier rebuilds the machine from, so the proof
//! stands alone given the key tree.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, LazyLock, Mutex};

use p3_field::PrimeCharacteristicRing;
use p3_multi_stark::HostProver;
use serde::{Deserialize, Serialize};
use zkm_binary_stark::config::MachineProof;
use zkm_binary_stark::machine::RecursionMachine;
use zkm_binary_stark::BinarySchedule;
use zkm_recursion_core::DIGEST_SIZE;

use crate::compose::{binary_key_digest, record_compose, Child, Compose, Composed, KeyKind};
use crate::machine::ledger::MAX_PUBLIC;
use crate::machine::program::Program;
use crate::machine::TapeBackend;
use crate::machine::{NodeKey, TapeMachine};
use crate::tape::{kb_value, Tape, F};

/// Shard numbers of an execution are below `2^MAX_LOG_SHARDS`.
pub const MAX_LOG_SHARDS: usize = 16;

/// A proved compose node: the machine that verifies it, its proof, and
/// what it commits to.
pub struct ProvedNode {
    pub machine: Arc<TapeMachine>,
    pub proof: MachineProof,
    pub composed: Composed,
}

impl ProvedNode {
    /// The node as a child of the next node up, its key at `membership`.
    #[must_use]
    pub fn child<'a>(
        &'a self,
        membership: crate::compose::VkMembership,
        schedule: &BinarySchedule,
    ) -> Child<'a> {
        Child::node(
            &self.machine,
            &self.proof,
            self.composed.public_values.clone(),
            membership,
            schedule,
        )
    }

    /// The node's key digest, as the key tree holds it.
    #[must_use]
    pub fn key_digest(&self) -> [u8; 32] {
        node_key_digest(&self.machine)
    }

    /// The proof a verifier checks alone: the key's parts, the proof and
    /// the public values.
    ///
    /// # Panics
    /// Panics if the proof does not serialize.
    #[must_use]
    pub fn to_root(&self) -> BinaryRootProof {
        BinaryRootProof {
            key: self.machine.key(),
            proof: postcard::to_allocvec(&self.proof).expect("a proof serializes"),
            public_values: self.composed.public_values.clone(),
        }
    }
}

/// The key digest of a leaf machine.
#[must_use]
pub fn leaf_key_digest(machine: &RecursionMachine) -> [u8; 32] {
    let (main, preprocessed) = machine.shapes();
    binary_key_digest(KeyKind::Leaf, &main, &preprocessed, machine.verifying_key())
}

/// The key digest of a node machine.
#[must_use]
pub fn node_key_digest(machine: &TapeMachine) -> [u8; 32] {
    let (main, preprocessed) = machine.shapes();
    binary_key_digest(KeyKind::Node, &main, &preprocessed, machine.verifying_key())
}

/// The program of the node over `children`, recorded but not proved: the
/// tape machine of its level has a key that depends only on this program
/// and the floor, so a key is had without a proof.
///
/// # Errors
/// Returns why the children do not compose.
pub fn record_node(children: Vec<Child<'_>>, is_complete: bool) -> Result<Program, String> {
    let node = Compose {
        children,
        is_complete,
        max_log_shards: MAX_LOG_SHARDS,
        check_keys: true,
        claims_start: [0; DIGEST_SIZE],
    };
    let (composed, tape) = record_compose(&node);
    if tape.ops.is_empty() {
        return Err(composed.err().unwrap_or_else(|| "the node records nothing".into()));
    }
    Ok(Program::new(&tape, DIGEST_SIZE))
}

/// The key digest of the node machine over `children` at `floor`: the
/// machine is set up, which commits its program, and nothing is proved.
///
/// # Errors
/// Returns why the children do not compose or the machine cannot be built.
pub fn node_key(
    children: Vec<Child<'_>>,
    is_complete: bool,
    floor: &[(&str, usize)],
    schedule: &BinarySchedule,
) -> Result<[u8; 32], String> {
    let program = record_node(children, is_complete)?;
    let machine =
        TapeMachine::verifier_with_floor(program, schedule, floor).map_err(|e| format!("{e:?}"))?;
    Ok(node_key_digest(&machine))
}

/// Prove the node over `children`, its tables at least as tall as `floor`.
///
/// # Errors
/// Returns why the children do not compose, or why the node cannot be
/// proved or does not verify.
pub fn prove_node(
    children: Vec<Child<'_>>,
    is_complete: bool,
    floor: &[(&str, usize)],
    schedule: &BinarySchedule,
) -> Result<ProvedNode, String> {
    prove_node_with(children, is_complete, floor, schedule, true, [0; DIGEST_SIZE], &HostProver)
}

/// [`prove_node`], the children's keys shown in the key tree only if
/// `check_keys`, the claims chain continued from `claims_start` when the
/// children are word proofs, and the proof computed on `backend`.
///
/// # Errors
/// As [`prove_node`].
pub fn prove_node_with(
    children: Vec<Child<'_>>,
    is_complete: bool,
    floor: &[(&str, usize)],
    schedule: &BinarySchedule,
    check_keys: bool,
    claims_start: [u32; DIGEST_SIZE],
    backend: &dyn TapeBackend,
) -> Result<ProvedNode, String> {
    record_node_with(children, is_complete, check_keys, claims_start)?.prove(floor, schedule, backend)
}

/// A node's verification of its children, recorded: what it composes, and the tape a
/// [`RecordedNode::prove`] proves, which no longer borrows the children.
pub struct RecordedNode {
    pub composed: Composed,
    tape: Tape,
}

/// The recording [`prove_node_with`] proves.
///
/// # Errors
/// Returns why the children do not compose.
pub fn record_node_with(
    children: Vec<Child<'_>>,
    is_complete: bool,
    check_keys: bool,
    claims_start: [u32; DIGEST_SIZE],
) -> Result<RecordedNode, String> {
    let node =
        Compose { children, is_complete, max_log_shards: MAX_LOG_SHARDS, check_keys, claims_start };
    let (composed, tape) = tracing::info_span!("node record").in_scope(|| record_compose(&node));
    Ok(RecordedNode { composed: composed?, tape })
}

impl RecordedNode {
    /// The node's proof on `backend`, its tables at least as tall as `floor`.
    ///
    /// # Errors
    /// Returns why the node cannot be proved or does not verify.
    pub fn prove(
        self,
        floor: &[(&str, usize)],
        schedule: &BinarySchedule,
        backend: &dyn TapeBackend,
    ) -> Result<ProvedNode, String> {
        let Self { composed, tape } = self;
        let machine = node_machine(&tape, schedule, floor)?;
        let public = machine.public_values(&tape.inputs);
        if std::env::var_os("ZIREN_WORD_SELF_CHECK").is_some()
            && tape.run(&tape.inputs).map_err(|e| format!("{e:?}"))? != tape.values
        {
            return Err("the recorded values are not the tape's run".into());
        }
        let proof = tracing::info_span!("node prove")
            .in_scope(|| machine.prove_values_on(&tape.values, &public, backend))
            .map_err(|e| format!("{e:?}"))?;
        if public != digest_public(&composed.digest)
            || crate::compose::public_values_digest(&composed.public_values) != composed.digest
        {
            return Err("the node's public inputs are not its digest".into());
        }
        if std::env::var_os("ZIREN_WORD_SELF_CHECK").is_some() {
            tracing::info_span!("node verify")
                .in_scope(|| machine.verify(&proof, &public))
                .map_err(|e| format!("{e:?}"))?;
        }
        Ok(ProvedNode { machine, proof, composed })
    }
}

/// The machines of the node programs proved so far, by [`program_fingerprint`]: the nodes of
/// a level run one program, so its layout and preprocessed commitment are made once.
static MACHINES: LazyLock<Mutex<HashMap<u64, Arc<TapeMachine>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The most machines [`MACHINES`] keeps: a tree has a program or two per level.
const MAX_MACHINES: usize = 16;

/// The machine of `tape`'s program under `schedule` at `floor`, set up once per program.
fn node_machine(
    tape: &Tape,
    schedule: &BinarySchedule,
    floor: &[(&str, usize)],
) -> Result<Arc<TapeMachine>, String> {
    let fingerprint = program_fingerprint(tape, schedule, floor);
    if let Some(machine) = MACHINES.lock().expect("the machine cache").get(&fingerprint) {
        return Ok(machine.clone());
    }
    let program = tracing::info_span!("node program").in_scope(|| Program::new(tape, DIGEST_SIZE));
    tracing::debug!(
        "node program over {} tape ops and {} values: {}",
        tape.ops.len(),
        tape.values.len(),
        program.census()
    );
    let machine = tracing::info_span!("node setup")
        .in_scope(|| TapeMachine::new_with_floor(program, schedule, floor))
        .map_err(|e| format!("{e:?}"))?;
    let machine = Arc::new(machine);
    let mut machines = MACHINES.lock().expect("the machine cache");
    if machines.len() == MAX_MACHINES {
        machines.clear();
    }
    machines.insert(fingerprint, machine.clone());
    Ok(machine)
}

/// What a node's program and machine are a function of: the tape's operations, constants
/// included, which variables they define, the schedule and the floor.  Values are not in it.
fn program_fingerprint(tape: &Tape, schedule: &BinarySchedule, floor: &[(&str, usize)]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    tape.ops.hash(&mut hasher);
    tape.defined.hash(&mut hasher);
    format!("{schedule:?}").hash(&mut hasher);
    floor.hash(&mut hasher);
    hasher.finish()
}

/// The public values of a tape machine whose run commits to `digest`.
fn digest_public(digest: &[u32; DIGEST_SIZE]) -> [F; MAX_PUBLIC] {
    core::array::from_fn(|i| if i < DIGEST_SIZE { kb_value(digest[i]) } else { F::ZERO })
}

/// The proof the root of a tree leaves: the parts of its key, its proof,
/// serialized, and the public values it commits to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BinaryRootProof {
    pub key: NodeKey,
    pub proof: Vec<u8>,
    pub public_values: Vec<u32>,
}

impl BinaryRootProof {
    /// The machine proof the bytes hold.
    ///
    /// # Errors
    /// Returns why the bytes are not a proof.
    pub fn machine_proof(&self) -> Result<MachineProof, String> {
        postcard::from_bytes(&self.proof).map_err(|e| e.to_string())
    }

    /// Verify the proof against the machine its key's parts rebuild, and
    /// return the key's digest, which the caller finds in its key tree.
    ///
    /// # Errors
    /// Returns why the machine cannot be rebuilt or the proof does not
    /// verify against the digest of the public values.
    pub fn verify(&self, schedule: &BinarySchedule) -> Result<[u8; 32], String> {
        let machine = TapeMachine::from_key(&self.key, schedule).map_err(|e| format!("{e:?}"))?;
        let proof = self.machine_proof()?;
        let digest = crate::compose::public_values_digest(&self.public_values);
        machine.verify(&proof, &digest_public(&digest)).map_err(|e| format!("{e:?}"))?;
        Ok(node_key_digest(&machine))
    }
}

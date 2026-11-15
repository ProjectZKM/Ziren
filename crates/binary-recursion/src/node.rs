//! Compose nodes proved, and the proof a tree's root leaves.
//!
//! A node records its verification of its children, lays the tape out for
//! the tape machine at the floor of its level, and proves the run.  The
//! root of a tree is a node that closes the execution; its proof carries
//! the parts of its key a verifier rebuilds the machine from, so the proof
//! stands alone given the key tree.

use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
use zkm_binary_stark::config::MachineProof;
use zkm_binary_stark::machine::RecursionMachine;
use zkm_binary_stark::BinarySchedule;
use zkm_recursion_core::DIGEST_SIZE;

use crate::compose::{binary_key_digest, record_compose, Child, Compose, Composed, KeyKind};
use crate::machine::ledger::MAX_PUBLIC;
use crate::machine::program::Program;
use crate::machine::{NodeKey, TapeMachine};
use crate::tape::{kb_value, F};

/// Shard numbers of an execution are below `2^MAX_LOG_SHARDS`.
pub const MAX_LOG_SHARDS: usize = 16;

/// A proved compose node: the machine that verifies it, its proof, and
/// what it commits to.
pub struct ProvedNode {
    pub machine: TapeMachine,
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
    prove_node_with(children, is_complete, floor, schedule, true, [0; DIGEST_SIZE])
}

/// [`prove_node`], the children's keys shown in the key tree only if
/// `check_keys`, and the claims chain continued from `claims_start` when
/// the children are word proofs.
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
) -> Result<ProvedNode, String> {
    let node =
        Compose { children, is_complete, max_log_shards: MAX_LOG_SHARDS, check_keys, claims_start };
    let (composed, tape) = tracing::info_span!("node record").in_scope(|| record_compose(&node));
    let composed = composed?;
    let program = tracing::info_span!("node program").in_scope(|| Program::new(&tape, DIGEST_SIZE));
    let mut machine = tracing::info_span!("node setup")
        .in_scope(|| TapeMachine::new_with_floor(program, schedule, floor))
        .map_err(|e| format!("{e:?}"))?;
    let proof = tracing::info_span!("node prove")
        .in_scope(|| machine.prove(&tape, &tape.inputs))
        .map_err(|e| format!("{e:?}"))?;
    let public = machine.public_values(&tape.inputs);
    if public != digest_public(&composed.digest)
        || crate::compose::public_values_digest(&composed.public_values) != composed.digest
    {
        return Err("the node's public inputs are not its digest".into());
    }
    tracing::info_span!("node verify")
        .in_scope(|| machine.verify(&proof, &public))
        .map_err(|e| format!("{e:?}"))?;
    machine.drop_proving_key();
    Ok(ProvedNode { machine, proof, composed })
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

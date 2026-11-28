//! An end-to-end-prover implementation for the Ziren zkVM.
//!
//! Separates the proof generation process into multiple stages:
//!
//! 1. Generate shard proofs which split up and prove the valid execution of a MIPS program.
//! 2. Compress shard proofs into a single shard proof.
//! 3. Wrap the shard proof into a SNARK-friendly field.
//! 4. Wrap the last shard proof, proven over the SNARK-friendly field, into a PLONK proof.

#![allow(clippy::too_many_arguments)]
#![allow(clippy::new_without_default)]
#![allow(clippy::collapsible_else_if)]

pub mod build;
pub mod components;
pub mod compress;
pub mod compress_tree;
pub mod pk_cache;
pub mod prewarm;
pub mod program_cache;
pub mod shapes;
pub mod types;
pub mod utils;
pub mod verify;
pub mod vk_allowlist;
pub mod wrap;

pub use pk_cache::RecursionPkCache;
pub use program_cache::RecursionProgramCache;
pub use vk_allowlist::vk_collect_record;

use rayon::prelude::*;
use std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet},
    env,
    path::Path,
    sync::{mpsc::sync_channel, Arc, Mutex, OnceLock},
    thread,
};

use p3_field::{PrimeCharacteristicRing, PrimeField, PrimeField32};
use p3_koala_bear::KoalaBear;
use tracing::instrument;
use zkm_core_executor::{ExecutionError, ExecutionReport, Executor, Program, ZKMContext};
use zkm_core_machine::{
    io::ZKMStdin, mips::MipsAir, reduce::ZKMReduceProof, utils::ZKMCoreProverError,
};
use zkm_pcs::MachineProvingKey;
use zkm_pcs::{
    air::PublicValues,
    koala_bear_poseidon2::{
        KoalaBearPoseidon2, KoalaBearPoseidon2Compress, KoalaBearPoseidon2Shrink,
    },
    Challenge, MachineProver, ShardProof, StarkGenericConfig, StarkProvingKey, StarkVerifyingKey,
    Val, Word, ZKMCoreOpts, ZKMProverOpts, DIGEST_SIZE,
};
// Used only by the shape-cardinality count in the `tests` module; the
// non-test build has no reader, which is why it needs the gate.
#[cfg(test)]
use zkm_pcs::shape::OrderedShape;
use zkm_primitives::{hash_deferred_proof, io::ZKMPublicValues, types::RecursionProgramType};
use zkm_recursion_circuit::{
    hash::FieldHasher,
    machine::{
        compress_jagged::ZKMCompressWitnessValues,
        core_jagged::ZKMCoreWitnessValues,
        deferred_jagged::ZKMDeferredWitnessValues,
        programs::{
            build_compose_program, build_deferred_program, build_normalize_program,
            build_wrap_program,
        },
        wrap::ZKMWrapWitnessValues,
        PublicValuesOutputDigest, ZKMCompressShape, ZKMCompressWithVkeyShape,
        ZKMMerkleProofWitnessValues,
    },
    merkle_tree::MerkleTree,
    witness::Witnessable,
    WrapConfig,
};
use zkm_recursion_compiler::{
    circuit::AsmCompiler,
    config::{InnerConfig, OuterConfig},
    ir::{Builder, Witness},
};
use zkm_recursion_core::{
    air::RecursionPublicValues,
    hash_vkey_with_part_vk,
    machine::RecursionAir,
    runtime::ExecutionRecord,
    shape::{RecursionShape, RecursionShapeConfig},
    stark::KoalaBearPoseidon2Outer,
    RecursionProgram, Runtime as RecursionRuntime,
};
pub use zkm_recursion_gnark_ffi::proof::{DvSnarkBn254Proof, Groth16Bn254Proof, PlonkBn254Proof};
use zkm_recursion_gnark_ffi::{
    groth16_bn254::Groth16Bn254Prover, plonk_bn254::PlonkBn254Prover, DvSnarkBn254Prover,
};

pub use types::*;
use utils::{
    words_to_bytes, zkm_committed_values_digest_bn254, zkm_vk_root_bn254, zkm_vkey_digest_bn254,
};

use components::{DefaultProverComponents, ZKMProverComponents};

pub use zkm_core_machine::ZKM_CIRCUIT_VERSION;

/// The configuration for the core prover (KoalaBear with its quintic
/// extension, 128-bit security).
pub type CoreSC = KoalaBearPoseidon2;

/// The configuration for the inner prover: every
/// recursion node below the root (leaves, interior composes, deferred nodes),
/// under the core WHIR schedule, tuned for prover time.
pub type InnerSC = KoalaBearPoseidon2;

/// The configuration of the shrink: the same field, hash and transcript as
/// [`InnerSC`] under the core schedule at its former starting rate `2^-2`
/// ([`zkm_pcs::whir::jagged::WhirProfile::Shrink`]).  The wrap program
/// verifies the shrink proof, so this ring fixes the wrap's geometry and the
/// circuit behind it independently of the core schedule's rate.
pub type ShrinkSC = KoalaBearPoseidon2Shrink;

/// The configuration of the ROOT, the closing compose whose proof is the
/// published compressed proof: the same field, hash and transcript as
/// [`InnerSC`] under the compress WHIR schedule
/// ([`zkm_pcs::whir::jagged::WhirProfile::Compress`]), tuned for proof size.
/// Every consumer of a compressed proof (the shrink, a deferred proof,
/// `verify_compressed`) verifies it under this ring.
pub type CompressedSC = KoalaBearPoseidon2Compress;

/// The configuration for the outer prover, the wrap over BN254 Merkle trees.
pub type OuterSC = KoalaBearPoseidon2Outer;

pub type DeviceProvingKey<C> = <<C as ZKMProverComponents>::CoreProver as MachineProver<
    KoalaBearPoseidon2,
    MipsAir<KoalaBear>,
>>::DeviceProvingKey;

/// The wrap prover's proving and verifying keys, held by [`ZKMProver::wrap_keys_cache`].
pub type WrapKeys<C> = (
    <<C as ZKMProverComponents>::WrapProver as MachineProver<
        OuterSC,
        WrapAir<KoalaBear>,
    >>::DeviceProvingKey,
    StarkVerifyingKey<OuterSC>,
);

/// Fixed height of the allowed-vk Merkle tree (capacity 2^19 = 524,288 vks).
///
/// BOTH the shape enumeration (`ZKMCompressProgramShape::from_proof_shape`,
/// which bakes `merkle_tree_height` into every compose/deferred/shrink
/// program) AND the runtime tree commit (`ZKMProver::new`) use this
/// constant.  If each side instead derived a height from its own
/// cardinality (enumerated-shape count vs vk_map size), the two
/// derivations could diverge and the witnessed merkle paths would desync
/// from the program shape.  A fixed ceiling kills that circularity.
///
/// It has to contain the whole MAP, which is two sources, not one.
///
/// The enumeration is now only the compose/deferred/shrink tail — 29 shapes —
/// because those key on pin classes, which the machine fixes. Normalize keys
/// are COLLECTED from real proofs instead (`ZIREN_VK_COLLECT`): a normalize
/// program is selected by its core shard's chip NAME SET, and which chips a
/// shard carries is a property of the block it executed, so no enumeration over
/// the machine's chips can predict them. Enumerating them produced 7,834 keys
/// that covered 9 of the 57 a real block needed.
///
/// So the occupancy that matters is 29 plus however many distinct normalize
/// keys production has been seen to produce, and it GROWS with traffic rather
/// than being a fixed count. A height that cannot hold them is not "a smaller
/// map" — it is a map that rejects real proofs, which is what 2^11 (2048) did.
/// The enumerated normalize classes (one per chip cluster and preprocessed,
/// global and main round bucket) number about 393k, so the tree holds 2^19.
/// The height is baked into every compose program, so raising it is itself a
/// vk-changing event.
///
/// `tests::enumeration_size_probe` asserts the enumerated tail fits; it cannot
/// bound the collected half, which is why the headroom is deliberate.
pub use zkm_recursion_core::VK_MERKLE_TREE_HEIGHT;

const COMPRESS_DEGREE: usize = 3;
const SHRINK_DEGREE: usize = 3;
const WRAP_DEGREE: usize = 9;

/// Tree-reduce arity for the compress stage. The reduction merges adjacent
/// shard ranges and emits a run the moment it reaches this size, or when the
/// run covers the whole chain with nothing left in flight, so any arity ≥ 2
/// reaches the root cleanly. Larger arity → fewer compress invocations
/// (`(N-1)/(k-1)` total) and amortizes per-shard fixed overhead
/// (Merkle binding, witness assembly, program build).
pub const REDUCE_BATCH_SIZE: usize = 3;

pub use zkm_pcs::logup_gkr::{global_round_groups, global_round_leaf_cells, GLOBAL_LEAF_CELLS};

pub type CompressAir<F> = RecursionAir<F, COMPRESS_DEGREE>;
pub type ShrinkAir<F> = RecursionAir<F, SHRINK_DEGREE>;
pub type WrapAir<F> = RecursionAir<F, WRAP_DEGREE>;

/// An end-to-end prover implementation for the Ziren zkVM.
pub struct ZKMProver<C: ZKMProverComponents = DefaultProverComponents> {
    /// The machine used for proving the core step.
    pub core_prover: C::CoreProver,

    /// The machine used for proving the recursive and reduction steps.
    pub compress_prover: C::CompressProver,

    /// The machine used for proving the shrink step.
    pub shrink_prover: C::ShrinkProver,

    /// The machine used for proving the wrapping step.
    pub wrap_prover: C::WrapProver,

    /// The machine used for proving the root: the compress machine under
    /// [`CompressedSC`].
    pub root_prover: C::RootProver,

    /// The root of the allowed recursion verification keys.
    pub recursion_vk_root: <InnerSC as FieldHasher<KoalaBear>>::Digest,

    /// The allowed VKs and their corresponding indices.
    pub recursion_vk_map: BTreeMap<<InnerSC as FieldHasher<KoalaBear>>::Digest, usize>,

    /// The Merkle tree for the allowed VKs.
    pub recursion_vk_tree: MerkleTree<KoalaBear, InnerSC>,

    /// The recursion shape configuration.
    pub compress_shape_config: Option<RecursionShapeConfig<KoalaBear, CompressAir<KoalaBear>>>,

    /// The verifying key for wrapping.
    pub wrap_vk: OnceLock<StarkVerifyingKey<OuterSC>>,

    /// The wrap's `(pk, vk)`, with the setup digest of the program they were
    /// built from.
    ///
    /// The outer circuit pins the wrap verifying key, so every wrap builds
    /// the same program and one entry serves the whole process: a long-lived
    /// prover (the server, a multi-block run) pays the wrap setup once rather
    /// than per proof.  A program with another digest replaces the entry.
    pub wrap_keys_cache: Mutex<Option<([u8; 32], Arc<WrapKeys<C>>)>>,

    /// Cache for the wrap program, keyed by
    /// [`ZKMWrapWitnessValues::shape_key`].  The shrink proof's shape
    /// is frozen, so a process reaches one entry.
    pub wrap_programs_cache: Mutex<RecursionProgramCache>,

    /// Whether to verify verification keys.
    pub vk_verification: bool,

    /// Recursion proving keys, keyed by the identity of the program they
    /// were built from ([`zkm_recursion_core::setup_digest`]).
    ///
    /// A recursion tree proves one node per core shard plus one per compose
    /// batch — hundreds of nodes — and the programs behind them repeat: every
    /// node of a layer is the same circuit over different values.  `setup` is
    /// a pure function of the program (a per-chip preprocessed trace walk plus
    /// the preprocessed WHIR commit), and it is the single most expensive
    /// thing in the stage, so keying it by program identity turns "once per
    /// node" into "once per distinct program".
    ///
    /// The key is the digest, not the arity: arity does not determine the
    /// program, because per-input shapes vary across nodes of equal arity and
    /// a key built for one shape does not open the other's traces.
    ///
    /// Bounded — an entry holds the preprocessed traces AND the retained
    /// WHIR prover data for a 2^27-cell commit, so an unbounded map would
    /// grow with the number of distinct shapes a workload happens to produce.
    /// Insertion order is recorded alongside so the oldest entry is the one
    /// dropped.
    pub recursion_pks_cache: Mutex<RecursionPkCache>,
    /// Signalled when a key under construction lands in
    /// `recursion_pks_cache` (see [`Self::recursion_pk_cached`]).
    pub recursion_pk_cache_ready: std::sync::Condvar,

    /// Per-shape cache for the Normalize recursion program — the
    /// leaf stage, one node per core shard.
    ///
    /// **Key**: [`ZKMCoreWitnessValues::shape_key`].
    pub normalize_programs_cache: Mutex<RecursionProgramCache>,

    /// Per-shape cache for the global-round programs. A block uses a few of
    /// them, each for many nodes, so they are kept apart from the normalize
    /// programs, whose shapes would push them out between two uses.
    ///
    /// **Key**: `ZKMGlobalRoundWitnessValues::shape_key`.
    pub global_programs_cache: Mutex<RecursionProgramCache>,

    /// Per-shape cache for the Compose recursion program — every
    /// interior node of the recursion tree.
    ///
    /// **Key**: [`ZKMCompressWitnessValues::shape_key`].
    ///
    /// Both caches rest on one invariant, which their key documents and
    /// `ZIREN_VERIFY_PROGRAM_CACHE=1` checks byte-exactly on every hit:
    ///
    /// ```text
    /// shape_key(a) == shape_key(b)  ⟹  program(a) == program(b)
    /// ```
    ///
    /// The converse is not needed: two keys mapping to one program cost a
    /// duplicate build, which `recursion_pks_cache` (keyed by program
    /// identity) absorbs downstream.  Keying on `arity` alone would break the
    /// invariant — per-input shapes vary widely across nodes of equal arity,
    /// and reusing a program built for shape A against shape B's witness
    /// stream trips `RuntimeError::EmptyWitnessStream`.
    pub compose_programs_cache: Mutex<RecursionProgramCache>,
}

impl<C: ZKMProverComponents> ZKMProver<C> {
    /// Initializes a new [ZKMProver].
    #[instrument(name = "initialize prover", level = "debug", skip_all)]
    pub fn new() -> Self {
        let prover = Self::uninitialized();
        prover.prewarm_compose_programs();
        prover
    }

    /// [`Self::new`] with the child-vk membership check fixed by the caller
    /// (`Some`) instead of read from `VERIFY_VK`.  The setting must be final
    /// before construction: every compose program is pre-warmed here, and a
    /// program built under one setting is a different program from the same
    /// shape built under the other.
    pub fn new_with_vk_verification(vk_verification: Option<bool>) -> Self {
        let prover = Self::uninitialized_with(vk_verification);
        prover.prewarm_compose_programs();
        prover
    }

    /// Creates a new [ZKMProver] with lazily initialized components: a compose
    /// program is built on first use rather than pre-warmed, which suits a
    /// client that proves elsewhere and only verifies and wraps locally.
    pub fn uninitialized() -> Self {
        Self::uninitialized_with(None)
    }

    /// [`Self::uninitialized`] with the child-vk membership check fixed by
    /// the caller (`Some`) instead of read from `VERIFY_VK`.
    pub fn uninitialized_with(vk_verification: Option<bool>) -> Self {
        let core_machine = MipsAir::machine(CoreSC::default());
        let core_prover = C::CoreProver::new(core_machine);

        let compress_machine = CompressAir::compress_machine(InnerSC::default());
        let compress_prover = C::CompressProver::new(compress_machine);

        let shrink_machine = ShrinkAir::shrink_machine(ShrinkSC::compressed());
        let shrink_prover = C::ShrinkProver::new(shrink_machine);

        let wrap_machine = WrapAir::wrap_machine(OuterSC::default());
        let wrap_prover = C::WrapProver::new(wrap_machine);

        let root_machine = CompressAir::compress_machine(CompressedSC::default());
        let root_prover = C::RootProver::new(root_machine);

        let recursion_shape_config = env::var("FIX_RECURSION_SHAPES")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(true)
            .then_some(RecursionShapeConfig::default());

        let vk_verification = vk_verification.unwrap_or_else(|| {
            env::var("VERIFY_VK").map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(true)
        });

        tracing::debug!("vk verification: {}", vk_verification);

        let allowed_vk_map: BTreeMap<[KoalaBear; DIGEST_SIZE], usize> = if vk_verification {
            let map_profile = include_str!("../vk_map_profile.txt").trim();
            if let Err(mismatch) = zkm_pcs::profile::check_peer_profile(map_profile) {
                panic!(
                    "vk_map.bin was generated for a different protocol.\n  \
                     this build: {}\n  the map:    {}\n\
                     Every recursion verifying key moves with the transcript, so no \
                     key in the map can match a proof this build produces. Regenerate \
                     the map (build_compress_vks + merge_vk_maps + write_vk_root) and \
                     record the new digest in crates/prover/vk_map_profile.txt, or set \
                     VERIFY_VK=false to run without membership.",
                    mismatch.ours, mismatch.theirs,
                );
            }
            bincode::deserialize(include_bytes!("../vk_map.bin")).unwrap()
        } else {
            let full: BTreeMap<[KoalaBear; DIGEST_SIZE], usize> =
                bincode::deserialize(include_bytes!("../dummy_vk_map.bin")).unwrap();
            full.into_iter().take(1 << VK_MERKLE_TREE_HEIGHT).collect()
        };

        assert!(
            allowed_vk_map.len() <= (1 << VK_MERKLE_TREE_HEIGHT),
            "vk_map ({}) exceeds fixed merkle capacity 2^{}",
            allowed_vk_map.len(),
            VK_MERKLE_TREE_HEIGHT
        );
        let mut leaves: Vec<[KoalaBear; DIGEST_SIZE]> = allowed_vk_map.keys().copied().collect();
        leaves.resize(1 << VK_MERKLE_TREE_HEIGHT, [KoalaBear::ZERO; DIGEST_SIZE]);
        let (root, merkle_tree) = MerkleTree::commit(leaves);

        Self {
            core_prover,
            compress_prover,
            shrink_prover,
            wrap_prover,
            root_prover,
            recursion_vk_root: root,
            recursion_vk_tree: merkle_tree,
            recursion_vk_map: allowed_vk_map,
            compress_shape_config: recursion_shape_config,
            vk_verification,
            wrap_vk: OnceLock::new(),
            wrap_keys_cache: Mutex::new(None),
            wrap_programs_cache: Mutex::new(RecursionProgramCache::default()),
            normalize_programs_cache: Mutex::new(RecursionProgramCache::default()),
            global_programs_cache: Mutex::new(RecursionProgramCache::default()),
            compose_programs_cache: Mutex::new(RecursionProgramCache::default()),
            recursion_pks_cache: Mutex::new(RecursionPkCache::default()),
            recursion_pk_cache_ready: std::sync::Condvar::new(),
        }
    }

    /// Creates a proving key and a verifying key for a given MIPS ELF.
    #[instrument(name = "setup", level = "debug", skip_all)]
    pub fn setup(
        &self,
        elf: &[u8],
    ) -> (ZKMProvingKey, DeviceProvingKey<C>, Program, ZKMVerifyingKey) {
        let program = self.get_program(elf).unwrap();
        let (pk, vk) = self.core_prover.setup(&program);
        let vk = ZKMVerifyingKey { vk };
        let pk = ZKMProvingKey {
            pk: self.core_prover.pk_to_host(&pk),
            elf: elf.to_vec(),
            vk: vk.clone(),
        };
        let pk_d = self.core_prover.pk_to_device(&pk.pk);
        (pk, pk_d, program, vk)
    }

    /// Get a program with an allowed preprocessed shape.
    pub fn get_program(&self, elf: &[u8]) -> eyre::Result<Program> {
        let program = Program::from(elf).unwrap();
        Ok(program)
    }

    /// Generate a proof of a Ziren program with the specified inputs.
    #[instrument(name = "execute", level = "info", skip_all)]
    pub fn execute<'a>(
        &'a self,
        elf: &[u8],
        stdin: &ZKMStdin,
        mut context: ZKMContext<'a>,
    ) -> Result<(ZKMPublicValues, ExecutionReport), ExecutionError> {
        context.subproof_verifier = Some(self);
        let program = self.get_program(elf).unwrap();
        let opts = ZKMCoreOpts::default();
        let mut runtime = Executor::with_context(program, opts, context);
        runtime.write_vecs(&stdin.buffer);
        for (proof, vkey) in stdin.proofs.iter() {
            runtime.write_proof(proof.clone(), vkey.clone());
        }
        runtime.run_fast()?;
        Ok((ZKMPublicValues::from(&runtime.state.public_values_stream), runtime.report))
    }

    /// Generate shard proofs which split up and prove the valid execution of a MIPS program with
    /// the core prover. Uses the provided context.
    #[instrument(name = "prove_core", level = "info", skip_all)]
    pub fn prove_core<'a>(
        &'a self,
        pk_d: &<<C as ZKMProverComponents>::CoreProver as MachineProver<
            KoalaBearPoseidon2,
            MipsAir<KoalaBear>,
        >>::DeviceProvingKey,
        program: Program,
        stdin: &ZKMStdin,
        opts: ZKMProverOpts,
        mut context: ZKMContext<'a>,
    ) -> Result<ZKMCoreProof, ZKMCoreProverError> {
        context.subproof_verifier = Some(self);
        let pk = pk_d;
        let (proof, public_values_stream, cycles) =
            zkm_core_machine::utils::prove_with_context::<_, C::CoreProver>(
                &self.core_prover,
                pk,
                program,
                stdin,
                opts.core_opts,
                context,
            )?;
        Self::check_for_high_cycles(cycles);
        let public_values = ZKMPublicValues::from(&public_values_stream);
        Ok(ZKMCoreProof {
            proof: ZKMCoreProofData(proof.shard_proofs, proof.global_proofs),
            stdin: stdin.clone(),
            public_values,
            cycles,
        })
    }

    fn check_for_high_cycles(cycles: u64) {
        if cycles > 100_000_000 {
            tracing::warn!(
                "high cycle count, consider using the prover network for proof generation"
            );
        }
    }
}

#[cfg(test)]
pub mod tests;

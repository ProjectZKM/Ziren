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

pub mod binary_tree;
pub mod build;
pub mod components;
pub mod program_cache;
pub mod shapes;
pub mod types;
pub mod utils;
pub mod verify;

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    num::NonZeroUsize,
    path::Path,
    sync::{Arc, Mutex, OnceLock},
};

use p3_field::PrimeField;
use p3_koala_bear::KoalaBear;
use tracing::instrument;
use zkm_binary_stark::machine::public_values::PublicValuesAir;
use zkm_binary_stark::machine::RecursionMachine;
use zkm_binary_stark::BinarySchedule;
use zkm_core_executor::{ExecutionError, ExecutionReport, Executor, Program, ZKMContext};
use zkm_core_machine::{
    io::ZKMStdin, mips::MipsAir, reduce::ZKMReduceProof, utils::ZKMCoreProverError,
};
use zkm_pcs::{
    koala_bear_poseidon2::KoalaBearPoseidon2Shrink, Challenge, MachineProver, ShardProof,
    StarkVerifyingKey, Val, ZKMCoreOpts, ZKMProverOpts, DIGEST_SIZE,
};
use zkm_primitives::{io::ZKMPublicValues, types::RecursionProgramType};
use zkm_recursion_circuit::{
    hash::FieldHasher,
    machine::{
        basefold_programs::build_normalize_basefold_program,
        core_basefold::ZKMCoreBasefoldWitnessValues, wrap_basefold::ZKMWrapBasefoldWitnessValues,
        PublicValuesOutputDigest, ZKMMerkleProofWitnessValues,
    },
    merkle_tree::MerkleTree,
    witness::Witnessable,
    WrapConfig,
};
use zkm_recursion_compiler::{
    circuit::AsmCompiler,
    config::InnerConfig,
    ir::{Builder, Witness},
};
use zkm_recursion_core::Instruction;
use zkm_recursion_core::{
    hash_vkey_with_part_vk, machine::RecursionAir, shape::RecursionShapeConfig,
    stark::KoalaBearPoseidon2Outer, RecursionProgram, Runtime as RecursionRuntime,
};
pub use zkm_recursion_gnark_ffi::proof::{DvSnarkBn254Proof, Groth16Bn254Proof, PlonkBn254Proof};
use zkm_recursion_gnark_ffi::{
    groth16_bn254::Groth16Bn254Prover, plonk_bn254::PlonkBn254Prover, DvSnarkBn254Prover,
};

pub use types::*;
use utils::{zkm_committed_values_digest_bn254, zkm_vk_root_bn254, zkm_vkey_digest_bn254};

use components::{DefaultProverComponents, ZKMProverComponents};

pub use zkm_core_machine::ZKM_CIRCUIT_VERSION;

/// The configuration for the core prover: KoalaBear traces committed under
/// Blake3, opened under jagged WHIR, with a Blake3 transcript.
pub type CoreSC = zkm_pcs::KoalaBearBlake3;

/// The configuration for the inner prover: every recursion node below the
/// root (leaves, interior composes, deferred nodes), under the same ring as
/// the core.
pub type InnerSC = zkm_pcs::KoalaBearBlake3;

/// The configuration of the shrink: the Blake3 ring, whose proof the binary
/// stage verifies.
pub type ShrinkSC = zkm_pcs::KoalaBearBlake3;

/// The Poseidon2 shrink ring the BN254 wrap circuit verifies.  The Blake3
/// chain produces no proof under it: the wrap cannot verify a Blake3 proof,
/// so the BN254 wrap is unreachable on this chain and its circuit is kept
/// only so that it builds.
pub type Poseidon2ShrinkSC = KoalaBearPoseidon2Shrink;

/// The configuration of the ROOT, the closing compose whose proof is the
/// compressed proof: the same ring as [`InnerSC`].  The Blake3 ring has one
/// WHIR schedule, so the root is not tuned for proof size separately.  Every
/// consumer of a compressed proof (the shrink, a deferred proof,
/// `verify_compressed`) verifies it under this ring.
pub type CompressedSC = zkm_pcs::KoalaBearBlake3;

/// The configuration for the outer prover (D=4, 100-bit security).
pub type OuterSC = KoalaBearPoseidon2Outer;

/// The ring of the shrink proof the binary stage verifies: the shrink's.
pub type ShrinkBlake3SC = ShrinkSC;

/// The digest a recursion verifying key is known by: the inner ring's.
pub type VkDigest = <InnerSC as FieldHasher<KoalaBear>>::Digest;

pub type DeviceProvingKey<C> = <<C as ZKMProverComponents>::CoreProver as MachineProver<
    CoreSC,
    MipsAir<KoalaBear>,
>>::DeviceProvingKey;

/// Fixed height of the allowed-vk Merkle tree (capacity 2^14 = 16,384 vks).
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
/// than being a fixed census. A height that cannot hold them is not "a smaller
/// map" — it is a map that rejects real proofs, which is what 2^11 (2048) did.
/// 2^14 also leaves room because the height is baked into every compose
/// program, so raising it is itself a vk-changing event. Pay for the headroom
/// once.
///
/// `tests::enumeration_size_probe` asserts the enumerated tail fits; it cannot
/// bound the collected half, which is why the headroom is deliberate.
pub use zkm_recursion_core::VK_MERKLE_TREE_HEIGHT;

/// Digest sink for `ZIREN_VK_COLLECT=<path>`.
///
/// The backfill for an enumeration that did not cover its own key space.  With
/// this set, every recursion VK the prover actually touches is recorded and the
/// path is rewritten in `vk_map.bin` wire format, so ONE workload run yields
/// the keys the map is missing.  Merge the result into
/// `crates/prover/vk_map.bin` with the `merge_vk_maps` bin.
///
/// WHY the map was ever short (Sep 2026): the normalize key is a function of
/// `(chip set, prep blocks, main blocks, prep pad columns, main pad columns)`,
/// but `generate` keyed only on the first three and emitted ONE representative
/// per class.  `shape_at_class` packs its fillers up to the class ceiling, so
/// that representative always landed on the FEWEST pad columns; a real shard
/// that only just crossed into the class commits more of them, which is a
/// different program and so a different vk.  MEASURED by
/// `tests::normalize_vk_padding_column_probe`: one chip set, `main_blocks=8`,
/// 1 pad column vs 2 -> the vks differ.  The pad counts are in the key now.
///
/// Collection should therefore be a DIAGNOSTIC, not a dependency: a key that
/// shows up here and is not in an enumerated map is a coverage bug in
/// `generate`, and the fix belongs there.  Keep it until a full enumerated
/// regen has run against production traffic with nothing new collected.
///
/// Collection is independent of `vk_verification`: the digests are identical
/// either way (only the leaf-index lookup differs), so the capture run is a
/// normal `VERIFY_VK=false` prove.
static VK_COLLECT: std::sync::OnceLock<Option<VkCollectSink>> = std::sync::OnceLock::new();

struct VkCollectSink {
    path: std::path::PathBuf,
    seen: std::sync::Mutex<BTreeSet<VkDigest>>,
}

/// Record one recursion VK digest if `ZIREN_VK_COLLECT` is set. Rewrites the
/// file only when the digest is new, so the cost is per distinct key, not per
/// compose node.
pub fn vk_collect_record(digest: &VkDigest) {
    let sink = VK_COLLECT.get_or_init(|| {
        env::var("ZIREN_VK_COLLECT").ok().map(|path| {
            let path: std::path::PathBuf = path.into();
            let seed: BTreeSet<VkDigest> = std::fs::File::open(&path)
                .ok()
                .and_then(|f| bincode::deserialize_from::<_, BTreeMap<VkDigest, usize>>(f).ok())
                .map(|m| m.into_keys().collect())
                .unwrap_or_default();
            tracing::info!("[VK-COLLECT] seeded {} keys from {:?}", seed.len(), path);
            VkCollectSink { path, seen: std::sync::Mutex::new(seed) }
        })
    });
    let Some(sink) = sink.as_ref() else { return };
    let mut seen = sink.seen.lock().unwrap();
    if !seen.insert(*digest) {
        return;
    }
    let map: BTreeMap<VkDigest, usize> =
        seen.iter().copied().enumerate().map(|(i, d)| (d, i)).collect();
    match std::fs::File::create(&sink.path).map(|mut f| bincode::serialize_into(&mut f, &map)) {
        Ok(Ok(())) => tracing::info!("[VK-COLLECT] {} keys -> {:?}", seen.len(), sink.path),
        Ok(Err(e)) => tracing::warn!("[VK-COLLECT] serialize {:?}: {e}", sink.path),
        Err(e) => tracing::warn!("[VK-COLLECT] create {:?}: {e}", sink.path),
    }
}

const COMPRESS_DEGREE: usize = 3;
const SHRINK_DEGREE: usize = 3;
const WRAP_DEGREE: usize = 9;

const CORE_CACHE_SIZE: usize = 5;

pub type CompressAir<F> = RecursionAir<F, COMPRESS_DEGREE>;
pub type ShrinkAir<F> = RecursionAir<F, SHRINK_DEGREE>;
pub type WrapAir<F> = RecursionAir<F, WRAP_DEGREE>;

/// An end-to-end prover implementation for the Ziren zkVM.
pub struct ZKMProver<C: ZKMProverComponents = DefaultProverComponents> {
    /// The machine used for proving the core step.
    pub core_prover: C::CoreProver,

    /// The machine used for proving the wrapping step.
    pub wrap_prover: C::WrapProver,

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

    /// Whether to verify verification keys.
    pub vk_verification: bool,

    /// Per-shape cache for the basefold Normalize recursion program — the
    /// leaf stage, one node per core shard.
    ///
    /// **Key**: [`ZKMCoreBasefoldWitnessValues::shape_key`].
    pub normalize_programs_basefold_cache: Mutex<RecursionProgramCache>,

    /// Built-but-unsnapped Normalize programs, keyed by input shape.
    pub normalize_programs_unsnapped_cache: Mutex<UnsnappedProgramCache>,
}

/// Built-but-unsnapped recursion programs, keyed by input shape.
///
/// A program's INSTRUCTIONS do not depend on which band it is snapped onto —
/// `fix_shape` only sets `program.shape`.  So the expensive half (the build)
/// can be shared across bands, and choosing a band later costs a clone rather
/// than a rebuild.  That is what lets a node's band be decided by its SIBLINGS,
/// which is knowable only after the program exists.
///
/// No `setup_digest` here: it describes the bytes of a SHAPED program, and
/// hashing one is ~291 ms.
#[derive(Default)]
pub struct UnsnappedProgramCache {
    entries: BTreeMap<u64, Arc<RecursionProgram<KoalaBear>>>,
    order: std::collections::VecDeque<u64>,
}

impl UnsnappedProgramCache {
    fn capacity() -> usize {
        16
    }

    fn get(&self, key: u64) -> Option<Arc<RecursionProgram<KoalaBear>>> {
        self.entries.get(&key).map(Arc::clone)
    }

    fn insert(
        &mut self,
        key: u64,
        program: Arc<RecursionProgram<KoalaBear>>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        if let Some(v) = self.entries.get(&key) {
            return Arc::clone(v);
        }
        self.entries.insert(key, Arc::clone(&program));
        self.order.push_back(key);
        while self.order.len() > Self::capacity() {
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
            }
        }
        program
    }
}

#[derive(Default)]
pub struct RecursionProgramCache {
    /// The cached program AND its `setup_digest`.  Hashing a program is not
    /// cheap -- SHA-256 over the whole serialized instruction stream, ~291 ms
    /// for a 7.1M-instruction node, 73.7 s summed over a reth compress tree --
    /// and the digest is a pure function of the bytes, so a cache HIT already
    /// knows it.  Computed once at insert, beside the `Arc` it describes.
    entries: BTreeMap<u64, (Arc<RecursionProgram<KoalaBear>>, [u8; 32])>,
    order: std::collections::VecDeque<u64>,
    pub hits: u64,
    pub misses: u64,
    /// Builds thrown away because another thread finished the SAME shape first.
    ///
    /// `cached_program` releases the cache lock before calling `build()`, so
    /// concurrent nodes of one shape each construct a full program and all but
    /// one discard it in [`Self::insert`].  That is pure waste, and its size
    /// decides whether a single-flight gate is worth the nested-blocking risk
    /// of holding a lock across the build — so count it before building one.
    pub dup_builds: u64,
}

impl RecursionProgramCache {
    /// How many distinct programs to retain.  A layer contributes a handful
    /// of distinct shapes, so a small cap still holds a whole layer; set it
    /// to 0 to hold nothing, which recovers the build-per-node behaviour for
    /// measurement.
    ///
    /// Default 128 (`ZIREN_RECURSION_PROGRAM_CACHE_SIZE` overrides).  The pk
    /// cache is sized separately, to a block's working set (see
    /// [`RecursionPkCache::capacity`]).  A cache cannot change what is proven:
    /// the cached program is the one a rebuild would produce.
    ///
    /// Eviction is insertion-ordered, not LRU: a tree walks its layers in
    /// order, so the access pattern is cyclic over more distinct shapes than
    /// the cache holds, and for a cyclic pattern LRU evicts exactly the entry
    /// wanted next.  (The pk cache is LRU because its cap exceeds the
    /// per-block working set.)
    fn capacity() -> usize {
        std::env::var("ZIREN_RECURSION_PROGRAM_CACHE_SIZE")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(128)
    }

    fn get(&mut self, key: u64) -> Option<(Arc<RecursionProgram<KoalaBear>>, [u8; 32])> {
        match self.entries.get(&key) {
            Some((v, d)) => {
                self.hits += 1;
                Some((Arc::clone(v), *d))
            }
            None => {
                self.misses += 1;
                None
            }
        }
    }

    /// First writer wins: a racing builder for the same shape discards its
    /// own copy rather than replacing one other nodes already hold.
    fn insert(
        &mut self,
        key: u64,
        program: Arc<RecursionProgram<KoalaBear>>,
    ) -> (Arc<RecursionProgram<KoalaBear>>, [u8; 32]) {
        if let Some((v, d)) = self.entries.get(&key) {
            self.dup_builds += 1;
            return (Arc::clone(v), *d);
        }
        let digest = zkm_recursion_core::setup_digest(&*program);
        self.entries.insert(key, (Arc::clone(&program), digest));
        self.order.push_back(key);
        while self.order.len() > Self::capacity() {
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
            }
        }
        (program, digest)
    }
}

impl<C: ZKMProverComponents> ZKMProver<C> {
    /// Initializes a new [ZKMProver].
    #[instrument(name = "initialize prover", level = "debug", skip_all)]
    pub fn new() -> Self {
        Self::uninitialized()
    }

    /// [`Self::new`] with the child-vk membership check fixed by the caller
    /// (`Some`) instead of read from `VERIFY_VK`.
    pub fn new_with_vk_verification(vk_verification: Option<bool>) -> Self {
        Self::uninitialized_with(vk_verification)
    }

    /// Creates a new [ZKMProver].  Programs are built on first use.
    pub fn uninitialized() -> Self {
        Self::uninitialized_with(None)
    }

    /// [`Self::uninitialized`] with the child-vk membership check fixed by
    /// the caller (`Some`) instead of read from `VERIFY_VK`.
    pub fn uninitialized_with(vk_verification: Option<bool>) -> Self {
        let core_machine = MipsAir::machine(CoreSC::default());
        let core_prover = C::CoreProver::new(core_machine);

        let wrap_machine = WrapAir::wrap_machine(OuterSC::default());
        let wrap_prover = C::WrapProver::new(wrap_machine);

        let core_cache_size = NonZeroUsize::new(
            env::var("PROVER_CORE_CACHE_SIZE")
                .unwrap_or_else(|_| CORE_CACHE_SIZE.to_string())
                .parse()
                .unwrap_or(CORE_CACHE_SIZE),
        )
        .expect("PROVER_CORE_CACHE_SIZE must be a non-zero usize");

        let recursion_shape_config = env::var("FIX_RECURSION_SHAPES")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(true)
            .then_some(RecursionShapeConfig::default());

        let vk_verification = vk_verification.unwrap_or_else(|| {
            env::var("VERIFY_VK").map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(true)
        });

        tracing::debug!("vk verification: {}", vk_verification);

        let allowed_vk_map: BTreeMap<VkDigest, usize> = if vk_verification {
            let map_profile = include_str!("../vk_map_profile.txt").trim();
            if let Err(mismatch) = zkm_pcs::profile::check_peer_profile(map_profile) {
                panic!(
                    "vk_map.bin was generated for a different protocol.\n  \
                     this build: {}\n  the map:    {}\n\
                     Every recursion verifying key moves with the transcript, so no \
                     key in the map can match a program this build produces. Regenerate \
                     the map and record the new digest in crates/prover/vk_map_profile.txt, \
                     or set VERIFY_VK=false.",
                    mismatch.ours, mismatch.theirs,
                );
            }
            bincode::deserialize(include_bytes!("../vk_map.bin"))
                .expect("vk_map.bin does not decode as a map of this ring's key digests")
        } else {
            let dummy = crate::shapes::ZKMProofShape::dummy_vk_map(core_prover.machine());
            dummy.into_iter().take(1 << VK_MERKLE_TREE_HEIGHT).collect()
        };

        assert!(
            allowed_vk_map.len() <= (1 << VK_MERKLE_TREE_HEIGHT),
            "vk_map ({}) exceeds fixed merkle capacity 2^{}",
            allowed_vk_map.len(),
            VK_MERKLE_TREE_HEIGHT
        );
        let mut leaves: Vec<VkDigest> = allowed_vk_map.keys().copied().collect();
        leaves.resize(1 << VK_MERKLE_TREE_HEIGHT, VkDigest::default());
        let (root, merkle_tree) = MerkleTree::commit(leaves);

        let _ = core_cache_size;

        Self {
            core_prover,
            wrap_prover,
            recursion_vk_root: root,
            recursion_vk_tree: merkle_tree,
            recursion_vk_map: allowed_vk_map,
            compress_shape_config: recursion_shape_config,
            vk_verification,
            wrap_vk: OnceLock::new(),
            normalize_programs_basefold_cache: Mutex::new(RecursionProgramCache::default()),
            normalize_programs_unsnapped_cache: Mutex::new(UnsnappedProgramCache::default()),
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
            CoreSC,
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
                None,
            )?;
        Self::check_for_high_cycles(cycles);
        let public_values = ZKMPublicValues::from(&public_values_stream);
        Ok(ZKMCoreProof {
            proof: ZKMCoreProofData(proof.shard_proofs),
            stdin: stdin.clone(),
            public_values,
            cycles,
        })
    }

    /// The FIXED zerocheck cube (= `JaggedShardVerifier`
    /// production default `max_log_row_count`, 22).  EVERY stage builds,
    /// proves, and verifies at this one constant; nothing floats it up
    /// from an input proof's zerocheck dim.  The in-circuit checks bind
    /// the cube against the input proof (`verify_zerocheck` `point.dim ==
    /// pcs_max_log_row_count`; `verify_logup_gkr`
    /// `round_proofs.len()+1 == max_log_row_count`), so a proof produced
    /// at any other cube fails to verify.  Over-tall chip heights cannot
    /// occur: the core executor's `height_split` closes a shard before
    /// any chip reaches `2^cube` rows, and every recursion band is
    /// asserted `<= cube` at shape construction.
    fn pcs_max_log_row_count() -> usize {
        zkm_pcs::shard_level::verifier::JaggedShardVerifier::production_default().max_log_row_count
    }

    /// Settle a recursion program's rows and pin class — see
    /// [`RecursionShapeConfig::fix_shape_kind`].  A no-op without a shape
    /// config (`FIX_RECURSION_SHAPES=false`), which gives up vk enumerability.
    fn fix_recursion_shape_kind(&self, program: &mut RecursionProgram<KoalaBear>, kind: &str) {
        if let Some(config) = self.compress_shape_config.as_ref() {
            config.fix_shape_kind(program, kind);
        }
    }

    /// Build the Normalize (basefold) recursion program and its
    /// `setup_digest` (the proving-key cache key).
    ///
    /// The program is snapped through [`Self::fix_recursion_shape`], which
    /// keeps its verifying key inside `ZKMProofShape::generate`'s enumerated
    /// space.  Programs are cached by shape (see
    /// [`Self::normalize_programs_basefold_cache`]): many core shards share
    /// one program.  The digest is cached with it, since hashing a
    /// multi-million-instruction program is expensive.
    pub fn recursion_program_basefold(
        &self,
        input: &ZKMCoreBasefoldWitnessValues<CoreSC>,
    ) -> (Arc<RecursionProgram<KoalaBear>>, [u8; 32]) {
        self.recursion_program_basefold_at(input, None)
    }

    /// [`Self::recursion_program_basefold`], snapped onto a CALLER-CHOSEN band.
    ///
    /// `None` keeps the program's own choice (the cheapest band it fits).
    /// `Some(i)` overrides it, which is how a node is made to agree with its
    /// siblings: a compose program is traced over its children's proof shapes,
    /// so its verifying key is enumerable only when those shapes agree, and a
    /// child cannot know what its siblings need.
    pub fn recursion_program_basefold_at(
        &self,
        input: &ZKMCoreBasefoldWitnessValues<CoreSC>,
        band: Option<usize>,
    ) -> (Arc<RecursionProgram<KoalaBear>>, [u8; 32]) {
        if normalize_key_census_enabled() {
            let mut names: Vec<&str> = input
                .shard_proofs
                .iter()
                .flat_map(|sp| sp.chip_heights.keys().map(String::as_str))
                .collect();
            names.sort_unstable();
            names.dedup();
            let heights: Vec<String> = input
                .shard_proofs
                .iter()
                .flat_map(|sp| sp.chip_heights.iter().map(|(n, h)| format!("{n}:{h}")))
                .collect();
            let packing: Vec<String> = input
                .shard_proofs
                .iter()
                .map(|sp| match &sp.evaluation_proof {
                    zkm_pcs::shard_level::shard_proof::EvaluationProof::Bundle(b) => format!(
                        "L={} noff={} cc={:?}",
                        b.packing.log_dense_size,
                        b.packing.offsets.len(),
                        b.packing.column_counts,
                    ),
                    other => (if matches!(
                        other,
                        zkm_pcs::shard_level::shard_proof::EvaluationProof::Empty
                    ) {
                        "empty"
                    } else {
                        "bytes"
                    })
                    .to_string(),
                })
                .collect();
            let rounds: Vec<String> = input
                .shard_proofs
                .iter()
                .map(|sp| match &sp.evaluation_proof {
                    zkm_pcs::shard_level::shard_proof::EvaluationProof::Bundle(b) => {
                        format!(
                            "stripes={:?}",
                            b.basefold_proof
                                .batch_evaluations
                                .iter()
                                .map(|r| r.len())
                                .collect::<Vec<_>>(),
                        )
                    }
                    _ => "nobundle".to_string(),
                })
                .collect();
            let dims: Vec<String> = input
                .shard_proofs
                .iter()
                .map(|sp| {
                    zkm_recursion_circuit::machine::shape_signature::describe_shard_proof_structure(
                        sp,
                    )
                    .into_iter()
                    .filter(|(n, _)| !n.starts_with("cc") && !n.starts_with("h."))
                    .map(|(n, v)| format!("{n}={v}"))
                    .collect::<Vec<_>>()
                    .join(" ")
                })
                .collect();
            tracing::warn!(
                "NORMALIZE_KEY shape_key={:016x} band={:?} first={} nchips={} chips={} \
                 PACK[{}] STRIPES[{}] DIMS[{}] heights={}",
                input.shape_key(),
                band,
                input.is_first_shard,
                names.len(),
                names.join(","),
                packing.join(" | "),
                rounds.join(" | "),
                dims.join(" | "),
                heights.join(","),
            );
        }
        self.cached_program(
            &self.normalize_programs_basefold_cache,
            self.band_keyed(input.shape_key(), band),
            "normalize",
            || {
                let program = self.normalize_program_unsnapped(input);
                self.snapped(
                    &program,
                    band,
                    if input.is_complete { "normalize-root" } else { "normalize" },
                )
            },
        )
    }

    /// A cache key that separates the same program snapped onto different
    /// bands, since they are different programs downstream, and built with
    /// the child-vk membership check on or off: `vk_verification` selects the
    /// instructions the program emits (`value_assertions`), so a program built
    /// under one setting is a different program — and a different verifying
    /// key — from the same shape built under the other.
    fn band_keyed(&self, shape_key: u64, band: Option<usize>) -> u64 {
        let shape_key = self.verification_keyed(shape_key);
        match band {
            None => shape_key,
            Some(b) => {
                shape_key.rotate_left(17) ^ (0x9E37_79B9_7F4A_7C15_u64.wrapping_mul(b as u64 + 1))
            }
        }
    }

    /// `shape_key` with the prover's `vk_verification` folded in, the key
    /// every program cache (snapped, unsnapped and on disk) is addressed by.
    fn verification_keyed(&self, shape_key: u64) -> u64 {
        if self.vk_verification {
            shape_key ^ 0x5851_F42D_4C95_7F2D
        } else {
            shape_key
        }
    }

    /// Clone an unsnapped program and fix its shape.
    fn snapped(
        &self,
        program: &Arc<RecursionProgram<KoalaBear>>,
        band: Option<usize>,
        kind: &str,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        let mut owned = (**program).clone();
        let _ = band;
        self.fix_recursion_shape_kind(&mut owned, kind);
        Arc::new(owned)
    }

    fn normalize_program_unsnapped(
        &self,
        input: &ZKMCoreBasefoldWitnessValues<CoreSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        let key = self.verification_keyed(input.shape_key());
        if let Some(p) = self.normalize_programs_unsnapped_cache.lock().unwrap().get(key) {
            return p;
        }
        let max_log_row_count = Self::pcs_max_log_row_count();
        let program = Arc::new(build_normalize_basefold_program(
            self.core_prover.machine(),
            input,
            max_log_row_count,
        ));
        self.normalize_programs_unsnapped_cache.lock().unwrap().insert(key, program)
    }

    /// Uncached body of [`Self::recursion_program_basefold`] — separate so the
    /// cache audit can rebuild and assert byte-equality.
    #[cfg(test)]
    fn build_normalize_program_basefold_uncached(
        &self,
        input: &ZKMCoreBasefoldWitnessValues<CoreSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        let max_log_row_count = Self::pcs_max_log_row_count();
        let mut program =
            build_normalize_basefold_program(self.core_prover.machine(), input, max_log_row_count);
        self.fix_recursion_shape_kind(
            &mut program,
            if input.is_complete { "normalize-root" } else { "normalize" },
        );
        Arc::new(program)
    }

    /// Shared cache wrapper for the shape-keyed recursion program caches.
    ///
    /// Sound exactly when `shape_key` is injective on program bytes; under
    /// `ZIREN_VERIFY_PROGRAM_CACHE=1` every hit rebuilds and bincode
    /// byte-compares, which turns that condition into a checked assertion.
    fn cached_program(
        &self,
        cache: &Mutex<RecursionProgramCache>,
        cache_key: u64,
        stage: &'static str,
        build: impl Fn() -> Arc<RecursionProgram<KoalaBear>>,
    ) -> (Arc<RecursionProgram<KoalaBear>>, [u8; 32]) {
        let audit = crate::program_cache::program_cache_audit_enabled();
        let cached = cache.lock().unwrap().get(cache_key);
        if let Some((cached, digest)) = cached {
            if audit {
                let fresh = build();
                let cached_bytes =
                    bincode::serialize(&*cached).expect("program cache: serialize cached");
                let fresh_bytes =
                    bincode::serialize(&*fresh).expect("program cache: serialize fresh");
                assert_eq!(
                    cached_bytes, fresh_bytes,
                    "{stage} program cache divergence at shape_key={cache_key:#018x}: two \
                     inputs collided in shape_key but produced different programs — extend \
                     shape_key to cover the diverging field",
                );
            }
            return (cached, digest);
        }
        if let Some(program) = crate::program_cache::disk_load::<KoalaBear>(stage, cache_key) {
            let program = Arc::new(program);
            if audit {
                let fresh = build();
                assert_eq!(
                    bincode::serialize(&*program).expect("serialize disk-loaded"),
                    bincode::serialize(&*fresh).expect("serialize fresh"),
                    "{stage} DISK cache divergence at shape_key={cache_key:#018x}: a cached                      file does not match a fresh build — the binary fingerprint should have                      prevented this",
                );
            }
            return cache.lock().unwrap().insert(cache_key, program);
        }
        let program = build();
        crate::program_cache::disk_store(stage, cache_key, &*program);
        cache.lock().unwrap().insert(cache_key, program)
    }

    /// `(disk_hits, disk_stores)` for the cross-process program cache.
    pub fn recursion_program_disk_counts(&self) -> (u64, u64) {
        use std::sync::atomic::Ordering;
        (
            crate::program_cache::DISK_HITS.load(Ordering::Relaxed),
            crate::program_cache::DISK_STORES.load(Ordering::Relaxed),
        )
    }

    /// Build the bn254-Wrap (basefold) recursion program.
    ///
    /// Compiles with [`WrapConfig`] so the resulting [`RecursionProgram`] is
    /// provable on the OuterSC (BN254-friendly) ring via [`Self::wrap_prover`],
    /// and verifies a proof of the Poseidon2 shrink machine.
    ///
    /// The `verify_wrap_basefold` body is generic over `C: CircuitConfig`
    /// with `F=InnerVal` / `EF=InnerChallenge` / `Bit=Felt<KoalaBear>`,
    /// and `WrapConfig` satisfies these bounds (its `CircuitConfig` impl in
    /// `zkm_recursion_circuit`), so the same verifier function works
    /// unchanged here.
    ///
    /// Not cached: the program is built fresh per call from the real input shape (cumulative-sum
    /// maps, chip names, column counts).  `wrap_bn254` is invoked once
    /// per end-to-end proof, so the per-call build cost is acceptable.
    pub fn wrap_bn254_program_basefold(
        &self,
        input: &ZKMWrapBasefoldWitnessValues<Poseidon2ShrinkSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        use zkm_pcs::air::MachineAir;
        use zkm_recursion_circuit::machine::wrap_basefold::verify_wrap_basefold;

        let max_log_row_count = Self::pcs_max_log_row_count();
        let shrink_machine = ShrinkAir::shrink_machine(Poseidon2ShrinkSC::compressed());

        let builder_span = tracing::debug_span!("build wrap-bn254-basefold program").entered();
        let mut builder = Builder::<WrapConfig>::new(RecursionProgramType::Wrap);
        let input_var = input.read(&mut builder);

        verify_wrap_basefold::<WrapConfig, Poseidon2ShrinkSC, _>(
            &mut builder,
            input_var,
            &shrink_machine,
            self.vk_verification,
            max_log_row_count,
            PublicValuesOutputDigest::ReduceToRoot,
        );
        let operations = builder.into_operations();
        builder_span.exit();

        let compiler_span = tracing::debug_span!("compile wrap-bn254-basefold program").entered();
        let mut compiler = AsmCompiler::<WrapConfig>::default();
        let mut program = compiler.compile(operations);
        compiler_span.exit();

        // Preserve the wrap tables used by the published SNARK circuit. Other
        // unshaped recursion programs can use the tighter multiple-of-32 padding.
        let rows = WrapAir::<KoalaBear>::heights(&program)
            .into_iter()
            .filter(|(name, _)| {
                self.wrap_prover.machine().chips().iter().any(|c| c.name() == *name)
            })
            .map(|(name, rows)| {
                let rows = zkm_core_machine::utils::next_power_of_two(rows, None, &name);
                (name, rows)
            })
            .collect::<BTreeMap<_, _>>();
        *program.shape_mut() = Some(rows.into());
        Arc::new(program)
    }

    /// Wrap each batch of `ShardProof`s into a
    /// `ZKMCoreBasefoldWitnessValues`, taking the `JaggedShardProof` each
    /// one carries.
    pub fn get_recursion_core_inputs_basefold(
        &self,
        vk: &StarkVerifyingKey<CoreSC>,
        shard_proofs: &[ShardProof<CoreSC>],
        batch_size: usize,
        is_complete: bool,
    ) -> Vec<ZKMCoreBasefoldWitnessValues<CoreSC>> {
        let mut core_inputs = Vec::new();
        for (batch_idx, batch) in shard_proofs.chunks(batch_size).enumerate() {
            assert_eq!(
                batch.len(),
                1,
                "normalize is single-shard: get_recursion_core_inputs_basefold \
                 must be called with batch_size=1 (one core shard per normalize); \
                 got a batch of {} shards",
                batch.len()
            );
            let bf_proofs =
                batch.iter().map(|sp| (*sp.jagged_shard_proof).clone()).collect::<Vec<_>>();
            core_inputs.push(ZKMCoreBasefoldWitnessValues {
                vk: vk.clone(),
                shard_proofs: bf_proofs,
                is_complete,
                is_first_shard: batch_idx == 0,
                vk_root: self.vk_root_felts(),
            });
        }

        core_inputs
    }

    /// Prove a leaf over bits: the normalize program that verifies `input`'s
    /// core shard, proven by the recursion machine over `GF(2^128)`.
    #[instrument(name = "leaf_binary", level = "info", skip_all)]
    pub fn leaf_binary(
        &self,
        input: &ZKMCoreBasefoldWitnessValues<CoreSC>,
    ) -> Result<BinaryLeafProof, ZKMRecursionProverError> {
        self.leaf_binary_with_machine(input).map(|(_, proof)| proof)
    }

    /// [`Self::leaf_binary`], with the machine that verifies the leaf.
    pub fn leaf_binary_with_machine(
        &self,
        input: &ZKMCoreBasefoldWitnessValues<CoreSC>,
    ) -> Result<(RecursionMachine, BinaryLeafProof), ZKMRecursionProverError> {
        let program = self.recursion_program_basefold(input).0;
        let floor = zkm_binary_stark::machine::leaf_floor(&program)
            .map_err(|e| ZKMRecursionProverError::BinaryStage(e.to_string()))?;
        let mut machine = self.binary_machine(&program, floor)?;
        let proof = self.leaf_binary_on(&machine, program, input)?;
        machine.drop_proving_key();
        Ok((machine, proof))
    }

    /// Prove a leaf of `program`, the normalize program of `input`, with a
    /// machine already set up for it at its class's floor.
    pub fn leaf_binary_on(
        &self,
        machine: &RecursionMachine,
        program: Arc<RecursionProgram<KoalaBear>>,
        input: &ZKMCoreBasefoldWitnessValues<CoreSC>,
    ) -> Result<BinaryLeafProof, ZKMRecursionProverError> {
        let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            program.clone(),
            zkm_pcs::inner_perm(),
        );
        let mut witness_stream = Vec::new();
        Witnessable::<InnerConfig>::write(input, &mut witness_stream);
        runtime.witness_stream = witness_stream.into();
        runtime.run().map_err(|e| ZKMRecursionProverError::RuntimeError(e.to_string()))?;
        let record = runtime.record;
        let digest = PublicValuesAir::digest(&record);
        let public_values = PublicValuesAir::public_values(&record);
        let proof = tracing::debug_span!("binary machine prove")
            .in_scope(|| machine.prove(&record))
            .map_err(|e| ZKMRecursionProverError::BinaryStage(e.to_string()))?;
        Ok(BinaryLeafProof { program, digest, public_values, proof })
    }

    /// The leaf of `input` compiled to word relations: its normalize program
    /// run, then lowered with the runtime's memory, which fills the witness
    /// and checks every value the relations compute.
    pub fn leaf_word(
        &self,
        input: &ZKMCoreBasefoldWitnessValues<CoreSC>,
    ) -> Result<zkm_recursion_r1cs::Lowered, ZKMRecursionProverError> {
        let program = self.recursion_program_basefold(input).0;
        let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            program.clone(),
            zkm_pcs::inner_perm(),
        );
        let mut witness_stream = Vec::new();
        Witnessable::<InnerConfig>::write(input, &mut witness_stream);
        runtime.witness_stream = witness_stream.into();
        runtime.run().map_err(|e| ZKMRecursionProverError::RuntimeError(e.to_string()))?;
        let memory: Vec<_> = (0..program.total_memory)
            .map(|addr| {
                runtime
                    .memory
                    .mr(zkm_recursion_core::Address(
                        <KoalaBear as p3_field::PrimeCharacteristicRing>::from_usize(addr),
                    ))
                    .val
            })
            .collect();
        zkm_recursion_r1cs::lower(&program, Some(&memory))
            .map_err(|e| ZKMRecursionProverError::BinaryStage(e.to_string()))
    }

    /// The binary machine of `program`, every table at least as tall as
    /// `floor` names, with its tables' shapes and the program's instruction
    /// mix reported.
    pub fn binary_machine(
        &self,
        program: &Arc<RecursionProgram<KoalaBear>>,
        floor: &[(&str, usize)],
    ) -> Result<RecursionMachine, ZKMRecursionProverError> {
        let mut mix = std::collections::BTreeMap::new();
        for instruction in program.iter_instructions() {
            let kind = match instruction {
                Instruction::BaseAlu(_) => "BaseAlu",
                Instruction::ExtAlu(_) => "ExtAlu",
                Instruction::Mem(_) => "Mem",
                Instruction::Poseidon2(_) => "Poseidon2",
                Instruction::Select(_) => "Select",
                Instruction::HintBits(_) => "HintBits",
                Instruction::HintAddCurve(_) => "HintAddCurve",
                Instruction::Print(_) => "Print",
                Instruction::HintExt2Felts(_) => "HintExt2Felts",
                Instruction::Ext2Felts(_) => "Ext2Felts",
                Instruction::CommitPublicValues(_) => "CommitPublicValues",
                Instruction::Hint(_) => "Hint",
                Instruction::Blake3Compress(_) => "Blake3Compress",
                Instruction::FeltLimbs(_) => "FeltLimbs",
                Instruction::PrefixSumChecks(_) => "PrefixSumChecks",
            };
            *mix.entry(kind).or_insert(0usize) += 1;
        }
        tracing::info!("binary stage program mix: {mix:?}");
        let machine = tracing::debug_span!("binary machine setup")
            .in_scope(|| {
                RecursionMachine::new_with_floor(program, &BinarySchedule::default(), floor)
            })
            .map_err(|e| ZKMRecursionProverError::BinaryStage(e.to_string()))?;
        for air in machine.airs() {
            tracing::info!(
                "binary stage table {}: 2^{} rows x {} bits",
                air.name(),
                air.log_height(),
                p3_air::BaseAir::<zkm_binary_stark::F>::width(air)
            );
        }
        Ok(machine)
    }

    /// Verify a leaf over bits against the program it names, its tables at
    /// its class's floor.
    pub fn verify_leaf_binary(
        &self,
        proof: &BinaryLeafProof,
    ) -> Result<(), ZKMRecursionProverError> {
        let floor = zkm_binary_stark::machine::leaf_floor(&proof.program)
            .map_err(|e| ZKMRecursionProverError::BinaryStage(e.to_string()))?;
        let machine = RecursionMachine::verifier_with_floor(
            &proof.program,
            &BinarySchedule::default(),
            floor,
        )
        .map_err(|e| ZKMRecursionProverError::BinaryStage(e.to_string()))?;
        machine
            .verify(&proof.proof, &proof.digest)
            .map_err(|e| ZKMRecursionProverError::BinaryStage(e.to_string()))
    }

    /// Wrap a reduce proof into a STARK proven over a SNARK-friendly field.
    #[instrument(name = "wrap_bn254", level = "info", skip_all)]
    pub fn wrap_bn254(
        &self,
        _shrink_proof: ZKMReduceProof<ShrinkSC>,
        _opts: ZKMProverOpts,
    ) -> Result<ZKMReduceProof<OuterSC>, ZKMRecursionProverError> {
        Err(ZKMRecursionProverError::RuntimeError(
            "the BN254 wrap over the binary compress root is not built yet".to_string(),
        ))
    }

    /// Wrap the STARK proven over a SNARK-friendly field into a PLONK proof.
    #[instrument(name = "wrap_plonk_bn254", level = "info", skip_all)]
    pub fn wrap_plonk_bn254(
        &self,
        proof: ZKMReduceProof<OuterSC>,
        build_dir: &Path,
    ) -> PlonkBn254Proof {
        let basefold_proof = (*proof.proof.jagged_shard_proof).clone();
        let vk_merkle_data = ZKMMerkleProofWitnessValues::<OuterSC>::dummy(1, 1);
        let input = ZKMWrapBasefoldWitnessValues {
            vks_and_proofs: vec![(proof.vk.clone(), basefold_proof)],
            vk_merkle_data,
        };
        let vkey_hash = zkm_vkey_digest_bn254(&proof);
        let committed_values_digest = zkm_committed_values_digest_bn254(&proof);

        let mut witness = Witness::default();
        input.write(&mut witness);
        witness.write_committed_values_digest(committed_values_digest);
        witness.write_vkey_hash(vkey_hash);
        let vk_root = zkm_vk_root_bn254(&proof);
        witness.write_vk_root(vk_root);

        let prover = PlonkBn254Prover::new();
        let proof = prover.prove(witness, build_dir.to_path_buf());

        prover
            .verify(
                &proof,
                &vkey_hash.as_canonical_biguint(),
                &committed_values_digest.as_canonical_biguint(),
                &vk_root.as_canonical_biguint(),
                build_dir,
            )
            .unwrap();

        proof
    }

    /// Wrap the STARK proven over a SNARK-friendly field into a Groth16 proof.
    #[instrument(name = "wrap_groth16_bn254", level = "info", skip_all)]
    pub fn wrap_groth16_bn254(
        &self,
        proof: ZKMReduceProof<OuterSC>,
        build_dir: &Path,
    ) -> Groth16Bn254Proof {
        let basefold_proof = (*proof.proof.jagged_shard_proof).clone();
        let vk_merkle_data = ZKMMerkleProofWitnessValues::<OuterSC>::dummy(1, 1);
        let input = ZKMWrapBasefoldWitnessValues {
            vks_and_proofs: vec![(proof.vk.clone(), basefold_proof)],
            vk_merkle_data,
        };
        let mut vkey_hash = zkm_vkey_digest_bn254(&proof);

        if crate::build::zkm_imm_wrap_vk_mode() {
            vkey_hash = hash_vkey_with_part_vk(&proof.vk.part_vk(), vkey_hash);
        }

        let committed_values_digest = zkm_committed_values_digest_bn254(&proof);

        let mut witness = Witness::default();
        input.write(&mut witness);
        witness.write_committed_values_digest(committed_values_digest);
        witness.write_vkey_hash(vkey_hash);
        let vk_root = zkm_vk_root_bn254(&proof);
        witness.write_vk_root(vk_root);

        let prover = Groth16Bn254Prover::new();
        let proof = prover.prove(witness, build_dir.to_path_buf());

        prover
            .verify(
                &proof,
                &vkey_hash.as_canonical_biguint(),
                &committed_values_digest.as_canonical_biguint(),
                &vk_root.as_canonical_biguint(),
                build_dir,
            )
            .unwrap();

        proof
    }

    /// Wrap the STARK proven over a SNARK-friendly field into a DV-SNARK proof.
    #[instrument(name = "wrap_dvsnark_bn254", level = "info", skip_all)]
    pub fn wrap_dvsnark_bn254(
        &self,
        proof: ZKMReduceProof<OuterSC>,
        build_dir: &Path,
        store_dir: &Path,
    ) -> DvSnarkBn254Proof {
        let basefold_proof = (*proof.proof.jagged_shard_proof).clone();
        let vk_merkle_data = ZKMMerkleProofWitnessValues::<OuterSC>::dummy(1, 1);
        let input = ZKMWrapBasefoldWitnessValues {
            vks_and_proofs: vec![(proof.vk.clone(), basefold_proof)],
            vk_merkle_data,
        };
        let vkey_hash = zkm_vkey_digest_bn254(&proof);
        let committed_values_digest = zkm_committed_values_digest_bn254(&proof);

        let mut witness = Witness::default();
        input.write(&mut witness);
        witness.write_committed_values_digest(committed_values_digest);
        witness.write_vkey_hash(vkey_hash);
        let vk_root = zkm_vk_root_bn254(&proof);
        witness.write_vk_root(vk_root);

        let prover = DvSnarkBn254Prover::new();
        prover.prove(witness, build_dir.to_path_buf(), store_dir.to_path_buf())
    }

    /// The key tree's root as the eight elements the public values carry.
    pub fn vk_root_felts(&self) -> [KoalaBear; DIGEST_SIZE] {
        <InnerSC as crate::types::RingDigests>::public_felts(self.recursion_vk_root)
    }

    fn check_for_high_cycles(cycles: u64) {
        if cycles > 100_000_000 {
            tracing::warn!(
                "high cycle count, consider using the prover network for proof generation"
            );
        }
    }
}

/// Whether to log one `NORMALIZE_KEY` line per normalize program request.
/// Read once; off unless `ZIREN_NORMALIZE_KEY_CENSUS` is `1`/`true`.
fn normalize_key_census_enabled() -> bool {
    static FLAG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *FLAG.get_or_init(|| {
        matches!(
            std::env::var("ZIREN_NORMALIZE_KEY_CENSUS").ok().as_deref(),
            Some("1") | Some("true")
        )
    })
}

#[cfg(test)]
pub mod tests {

    /// The recorded profile must be THIS build's, so the mismatch is caught in
    /// CI rather than at a prover's startup.
    ///
    /// A failure here means one of two things. Either the transcript moved, in
    /// which case `vk_map.bin` is stale and regenerating it is the fix and this
    /// file records the new digest afterwards. Or only the profile's own
    /// representation changed, in which case the map is still valid and this
    /// file is simply restated. The two are not distinguishable from here,
    /// which is why updating this file is a deliberate act and not a default.
    #[test]
    fn vk_map_profile_matches_this_build() {
        let recorded = include_str!("../vk_map_profile.txt").trim();
        let ours = zkm_pcs::profile::transcript_profile_digest_hex();
        assert_eq!(
            recorded, ours,
            "crates/prover/vk_map_profile.txt records {recorded}, but this build's \
             protocol profile is {ours}; see this test's documentation",
        );
    }

    use super::*;

    use anyhow::Result;
    use p3_field::PrimeCharacteristicRing;
    use zkm_pcs::{air::PublicValues, StarkGenericConfig, Word};

    #[cfg(test)]
    use serial_test::serial;
    #[cfg(test)]
    use zkm_core_machine::utils::setup_logger;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Test {
        Core,
        Compress,
    }

    pub fn test_e2e_prover<C: ZKMProverComponents>(
        prover: &ZKMProver<C>,
        elf: &[u8],
        stdin: ZKMStdin,
        opts: ZKMProverOpts,
        test_kind: Test,
    ) -> Result<()> {
        run_e2e_prover_with_options(prover, elf, stdin, opts, test_kind, true)
    }

    /// The NORMALIZE program-cache key
    /// (`ZKMCoreBasefoldWitnessValues::shape_key`) carries the same single
    /// invariant as the compose one — **equal `shape_key` implies a
    /// byte-identical normalize program** — since
    /// `recursion_program_basefold` hands back the cached program on a hit.
    ///
    /// The leaf layer is where this matters most: one node per core shard, and
    /// core shards differ from one another only in their per-chip heights,
    /// which the normalize circuit is deliberately agnostic to (heights are
    /// Horner-recomposed from the WITNESSED per-chip `degree`, a fixed
    /// `max_log_row_count + 1` felts wide).  So bands must NOT split the key
    /// while the chip SET must.
    #[test]
    #[serial]
    fn normalize_program_cache_key_implies_identical_program() {
        use zkm_core_machine::shape::CoreShapeConfig;
        use zkm_pcs::shape::OrderedShape;
        use zkm_recursion_circuit::machine::ZKMCoreBasefoldWitnessValues;

        let prover = ZKMProver::<DefaultProverComponents>::new();
        let machine = prover.core_prover.machine();

        let prog_bytes = |w: &ZKMCoreBasefoldWitnessValues<CoreSC>| -> Vec<u8> {
            bincode::serialize(&*prover.build_normalize_program_basefold_uncached(w))
                .expect("serialize normalize program")
        };

        let core_shape_config = CoreShapeConfig::<KoalaBear>::default();
        let base_os = core_shape_config
            .maximal_core_shapes(21)
            .into_iter()
            .next()
            .map(|core_shape| OrderedShape {
                inner: core_shape.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
            })
            .expect("the shape config admits at least one maximal core shape");
        let base: Vec<(String, usize)> = base_os.inner.clone();

        let witness_of = |hs: &[(String, usize)]| -> ZKMCoreBasefoldWitnessValues<CoreSC> {
            let os = OrderedShape { inner: hs.to_vec() };
            let shape = zkm_recursion_circuit::machine::ZKMRecursionShape {
                proof_shapes: vec![os],
                is_complete: false,
            };
            ZKMCoreBasefoldWitnessValues::dummy(machine, &shape)
        };

        let shrink_one = |idx: usize| -> Vec<(String, usize)> {
            let mut v = base.clone();
            v[idx].1 = v[idx].1.saturating_sub(1).max(1);
            v
        };
        let candidates: Vec<Vec<(String, usize)>> =
            std::iter::once(base.clone()).chain((0..base.len().min(4)).map(shrink_one)).collect();

        let mut by_key: std::collections::BTreeMap<u64, Vec<(usize, Vec<u8>)>> =
            std::collections::BTreeMap::new();
        for (n, hs) in candidates.iter().enumerate() {
            let w = witness_of(hs);
            by_key.entry(w.shape_key()).or_default().push((n, prog_bytes(&w)));
        }
        let collided: Vec<_> = by_key.iter().filter(|(_, v)| v.len() > 1).collect();
        assert!(
            !collided.is_empty(),
            "expected at least one shape_key collision across single-chip \
             height variants — without one the normalize cache can never hit",
        );
        for (k, members) in collided {
            let (first_idx, first) = &members[0];
            for (idx, bytes) in members.iter().skip(1) {
                assert_eq!(
                    first.len(),
                    bytes.len(),
                    "NORMALIZE CACHE-KEY UNSOUND: variants {first_idx} and {idx} \
                     share shape_key {k:#018x} but build normalize programs of \
                     different LENGTH; extend shape_key to cover whichever \
                     field diverged",
                );
                assert!(
                    first == bytes,
                    "NORMALIZE CACHE-KEY UNSOUND: variants {first_idx} and {idx} \
                     share shape_key {k:#018x} and length but different BYTES",
                );
            }
        }

        let mut fewer = base.clone();
        fewer.pop();
        assert_ne!(
            witness_of(&fewer).shape_key(),
            witness_of(&base).shape_key(),
            "NORMALIZE CACHE-KEY UNSOUND: dropping a chip left the key \
             unchanged, so a shard missing that chip would be served the \
             wrong cached program",
        );
    }

    /// The normalize dummy core VK is faithful in its `chip_information`.
    ///
    /// `StarkMachine::setup` records one entry per chip with a preprocessed
    /// trace, in name order; the dummy (`dummy_basefold_vk_and_shard_proof`)
    /// records the chips OF THE SHAPE that have one.  The two agree on every
    /// reachable shape because every preprocessed chip of the core machine is
    /// included in every shard, so its name is in every shard's chip set.
    /// Both halves are asserted: unconditional inclusion, and equality on a
    /// representative shape.
    #[test]
    #[serial]
    fn normalize_dummy_core_vk_chip_information_is_faithful() {
        use zkm_core_executor::ExecutionRecord;
        use zkm_core_machine::mips::MipsAir;
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::shape::OrderedShape;

        let prover = ZKMProver::<DefaultProverComponents>::new();
        let core_machine = prover.core_prover.machine();

        let empty = ExecutionRecord::default();
        let prep_chips: Vec<_> = core_machine
            .chips()
            .iter()
            .filter(|c| <_ as MachineAir<KoalaBear>>::preprocessed_width(*c) > 0)
            .collect();
        assert!(!prep_chips.is_empty(), "the core machine has no preprocessed chip");
        for chip in &prep_chips {
            assert!(
                <_ as MachineAir<KoalaBear>>::included(*chip, &empty),
                "preprocessed chip {} is not in every shard, so a shape without it gives \
                 the dummy VK fewer chip_information entries than the real one",
                <_ as MachineAir<KoalaBear>>::name(*chip)
            );
        }
        let expected: BTreeSet<String> =
            prep_chips.iter().map(|c| <_ as MachineAir<KoalaBear>>::name(*c)).collect();

        let mut inner: Vec<(String, usize)> =
            expected.iter().map(|name| (name.clone(), 16usize)).collect();
        inner.push(("AddSub".to_string(), 18));
        inner.push(("Branch".to_string(), 18));
        let shape = OrderedShape::from_log2_heights(&inner);
        let (dummy_vk, _proof) = zkm_recursion_circuit::stark::dummy_basefold_vk_and_shard_proof::<
            _,
            MipsAir<KoalaBear>,
        >(core_machine, &shape);
        let dummy_prep: BTreeSet<String> =
            dummy_vk.chip_information.iter().map(|(n, _, _)| n.clone()).collect();
        assert_eq!(
            dummy_prep, expected,
            "dummy core VK chip_information diverges from the machine's preprocessed set"
        );
    }

    pub fn bench_e2e_prover<C: ZKMProverComponents>(
        prover: &ZKMProver<C>,
        elf: &[u8],
        stdin: ZKMStdin,
        opts: ZKMProverOpts,
        test_kind: Test,
    ) -> Result<()> {
        run_e2e_prover_with_options(prover, elf, stdin, opts, test_kind, false)
    }

    pub fn run_e2e_prover_with_options<C: ZKMProverComponents>(
        prover: &ZKMProver<C>,
        elf: &[u8],
        stdin: ZKMStdin,
        opts: ZKMProverOpts,
        test_kind: Test,
        verify: bool,
    ) -> Result<()> {
        tracing::info!("initializing prover");
        let context = ZKMContext::default();

        tracing::info!("setup elf");
        let (_, pk_d, program, vk) = prover.setup(elf);

        tracing::info!("prove core");
        let core_proof = prover.prove_core(&pk_d, program, &stdin, opts, context)?;

        if verify {
            tracing::info!("verify core");
            prover.verify(&core_proof.proof, &vk)?;
        }

        if test_kind == Test::Core {
            return Ok(());
        }

        tracing::info!("compress over bits");
        let store = crate::binary_tree::BinaryKeyStore::from_env();
        let compressed = prover.compress_binary(&vk, &core_proof, &store)?;
        tracing::info!(
            "compressed proof size: {} bytes",
            bincode::serialize(&compressed).unwrap().len()
        );
        if verify {
            tracing::info!("verify compressed");
            prover.verify_binary_compressed(&compressed, &vk, None)?;
        }
        Ok(())
    }

    /// The fibonacci test guest reads its `n` from standard input (as
    /// `examples/fibonacci` does), so every caller has to supply one. Ten keeps
    /// the cycle count the tests were tuned against.
    fn fib_stdin(n: u32) -> ZKMStdin {
        let mut stdin = ZKMStdin::new();
        stdin.write(&n);
        stdin
    }

    /// Core + recursion + compress only.
    #[test]
    #[serial]
    #[ignore]
    fn test_e2e_compress_fibonacci() -> Result<()> {
        let elf = test_artifacts::FIBONACCI_ELF;
        setup_logger();
        let opts = ZKMProverOpts::default();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        test_e2e_prover::<DefaultProverComponents>(
            &prover,
            elf,
            fib_stdin(10),
            opts,
            Test::Compress,
        )
    }

    /// Add the binary key digests in `hex`, one per line, to the prover's key
    /// tree, which every leaf then carries the root of, and write each one's
    /// index and path to `ZIREN_BINARY_VK_PROOFS`, a line each: the digest,
    /// the index and the siblings, in hex.
    fn add_binary_keys(prover: &mut ZKMProver<DefaultProverComponents>, hex: &str) {
        use zkm_recursion_circuit::blake3_circuit::{digest_limbs, limbs_digest};
        let parse = |line: &str| -> [u8; 32] {
            core::array::from_fn(|i| u8::from_str_radix(&line[2 * i..2 * i + 2], 16).unwrap())
        };
        let encode = |bytes: [u8; 32]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let extra: Vec<VkDigest> = hex
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| digest_limbs(&parse(l.trim())))
            .collect();
        let mut keys: Vec<VkDigest> = prover.recursion_vk_map.keys().copied().collect();
        keys.extend(extra.iter().copied());
        keys.sort();
        keys.dedup();
        assert!(keys.len() <= 1 << VK_MERKLE_TREE_HEIGHT, "the key tree holds every key");
        prover.recursion_vk_map = keys.iter().enumerate().map(|(i, &k)| (k, i)).collect();
        let mut leaves = keys.clone();
        leaves.resize(1 << VK_MERKLE_TREE_HEIGHT, VkDigest::default());
        let (root, tree) = MerkleTree::commit(leaves);
        prover.recursion_vk_root = root;
        prover.recursion_vk_tree = tree;
        let mut lines = String::new();
        for digest in &extra {
            let index = prover.recursion_vk_map[digest];
            let (value, proof) = MerkleTree::open(&prover.recursion_vk_tree, index);
            assert_eq!(&value, digest, "the tree opens the digest at its index");
            let path: Vec<String> =
                proof.path.iter().map(|sibling| encode(limbs_digest(sibling))).collect();
            lines.push_str(&format!(
                "{} {} {}\n",
                encode(limbs_digest(digest)),
                proof.index,
                path.join(",")
            ));
        }
        if let Some(out) = std::env::var_os("ZIREN_BINARY_VK_PROOFS") {
            std::fs::write(out, lines).expect("the proofs write");
        }
        tracing::info!("binary keys: {} added, tree of {} keys", extra.len(), keys.len());
    }

    /// The least log height of each binary table over every normalize program
    /// of the recursion shape set: the leaf floor, printed as the constant
    /// `zkm_binary_stark::machine::LEAF_CLASSES` holds.
    #[test]
    #[ignore]
    fn binary_leaf_floor() {
        use crate::shapes::{ZKMCompressProgramShape, ZKMProofShape};
        setup_logger();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let mut floor: Vec<(&'static str, usize)> = Vec::new();
        let mut programs = 0usize;
        for shape in ZKMProofShape::generate_normalize(prover.core_prover.machine()) {
            let shape = ZKMCompressProgramShape::from_proof_shape(shape);
            let program = prover.program_from_shape(shape);
            let heights = RecursionMachine::table_heights(&program).expect("a binary machine");
            for (name, log_height) in heights {
                match floor.iter_mut().find(|(known, _)| *known == name) {
                    Some((_, most)) => *most = (*most).max(log_height),
                    None => floor.push((name, log_height)),
                }
            }
            programs += 1;
        }
        let entries: Vec<String> =
            floor.iter().map(|(name, log_height)| format!("(\"{name}\", {log_height})")).collect();
        tracing::info!(
            "binary leaf floor over {programs} normalize programs: &[{}]",
            entries.join(", ")
        );
    }

    /// The binary table heights of every core shard's normalize program of a
    /// cached block: the guest at `ZIREN_BLOCK_ELF` on the input at
    /// `ZIREN_BLOCK_INPUT`, its core proved on the host, each shard's program
    /// built and measured, and no leaf proved.
    #[test]
    #[serial]
    #[ignore]
    fn binary_block_heights() -> Result<()> {
        setup_logger();
        let elf = std::fs::read(std::env::var("ZIREN_BLOCK_ELF")?)?;
        let input = std::fs::read(std::env::var("ZIREN_BLOCK_INPUT")?)?;
        let mut stdin = ZKMStdin::new();
        stdin.write_vec(input);
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let (_, pk_d, program, vk) = prover.setup(&elf);
        let started = std::time::Instant::now();
        let core_proof = prover.prove_core(
            &pk_d,
            program,
            &stdin,
            ZKMProverOpts::default(),
            ZKMContext::default(),
        )?;
        tracing::info!(
            "block core: {} shards proved on the host in {:.1} s",
            core_proof.proof.0.len(),
            started.elapsed().as_secs_f64()
        );
        let inputs =
            prover.get_recursion_core_inputs_basefold(&vk.vk, &core_proof.proof.0, 1, false);
        let mut floor: Vec<(&'static str, usize)> = Vec::new();
        let mut shapes: BTreeMap<Vec<usize>, usize> = BTreeMap::new();
        for (i, input) in inputs.iter().enumerate() {
            let program = prover.recursion_program_basefold(input).0;
            let heights = RecursionMachine::table_heights(&program).expect("a binary machine");
            tracing::info!(
                "shard {i}: {} instructions, heights {:?}",
                program.iter_instructions().count(),
                heights.iter().map(|(name, h)| format!("{name}:{h}")).collect::<Vec<_>>()
            );
            *shapes.entry(heights.iter().map(|&(_, h)| h).collect()).or_default() += 1;
            for (name, log_height) in heights {
                match floor.iter_mut().find(|(known, _)| *known == name) {
                    Some((_, most)) => *most = (*most).max(log_height),
                    None => floor.push((name, log_height)),
                }
            }
        }
        let entries: Vec<String> =
            floor.iter().map(|(name, log_height)| format!("(\"{name}\", {log_height})")).collect();
        tracing::info!(
            "binary block floor over {} shards, {} shapes: &[{}]",
            inputs.len(),
            shapes.len(),
            entries.join(", ")
        );
        Ok(())
    }

    /// Execute a cached block and write every core shard's chip heights to
    /// `ZIREN_CORE_SHAPE_DUMP`, proving none: run with
    /// `ZIREN_CORE_SHARD_LIMIT=0`.
    #[test]
    #[serial]
    #[ignore]
    fn dump_block_shapes() -> Result<()> {
        setup_logger();
        let elf = std::fs::read(std::env::var("ZIREN_BLOCK_ELF")?)?;
        let input = std::fs::read(std::env::var("ZIREN_BLOCK_INPUT")?)?;
        let mut stdin = ZKMStdin::new();
        stdin.write_vec(input);
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let (_, pk_d, program, _) = prover.setup(&elf);
        let started = std::time::Instant::now();
        let core_proof = prover.prove_core(
            &pk_d,
            program,
            &stdin,
            ZKMProverOpts::default(),
            ZKMContext::default(),
        )?;
        tracing::info!(
            "block shapes written in {:.1} s, {} shards proved",
            started.elapsed().as_secs_f64(),
            core_proof.proof.0.len()
        );
        Ok(())
    }

    /// The binary leaf classes of the shard shapes in `ZIREN_CORE_SHAPES`,
    /// lines as `dump_block_shapes` writes them: each distinct shape's
    /// normalize program is built from a dummy proof of that shape, and its
    /// binary tables' heights, widths and total bits are reported.
    #[test]
    #[ignore]
    fn binary_shape_census() -> Result<()> {
        setup_logger();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let text = std::fs::read_to_string(std::env::var("ZIREN_CORE_SHAPES")?)?;
        let mut counts: BTreeMap<(bool, String), usize> = BTreeMap::new();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let (shard, shape) = line.split_once(' ').unwrap_or(("0", ""));
            *counts.entry((shard == "1", shape.to_string())).or_default() += 1;
        }
        let shapes: Vec<(&(bool, String), &usize)> = counts.iter().collect();
        let classes = std::sync::Mutex::new(BTreeMap::<u32, usize>::new());
        let failed = std::sync::atomic::AtomicUsize::new(0);
        let next = std::sync::atomic::AtomicUsize::new(0);
        let workers: usize =
            std::env::var("ZIREN_CENSUS_THREADS").map_or(6, |n| n.parse().expect("a count"));
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| loop {
                    let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(&((first, shape), &count)) = shapes.get(index) else { break };
                    let rows: Vec<(String, usize)> = shape
                        .split(',')
                        .filter_map(|entry| entry.split_once(':'))
                        .map(|(name, rows)| (name.to_string(), rows.parse().expect("a row count")))
                        .collect();
                    let built = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let mut input = ZKMCoreBasefoldWitnessValues::dummy_rows(
                            prover.core_prover.machine(),
                            &rows,
                            false,
                        );
                        input.is_first_shard = *first;
                        prover.recursion_program_basefold(&input).0
                    }));
                    let Ok(program) = built else {
                        failed.fetch_add(count, std::sync::atomic::Ordering::Relaxed);
                        tracing::warn!("shape x{count} failed to build: {shape}");
                        continue;
                    };
                    let tables =
                        RecursionMachine::table_shapes(&program).expect("a binary machine");
                    let bits: u64 = tables.iter().map(|&(_, h, w)| (w as u64) << h).sum();
                    let class = 64 - (bits - 1).leading_zeros();
                    *classes.lock().unwrap().entry(class).or_default() += count;
                    tracing::info!(
                        "shape x{count}: {} instructions, {:.3} Gbit, 2^{class}, heights {:?}",
                        program.iter_instructions().count(),
                        bits as f64 / f64::from(1u32 << 30),
                        tables.iter().map(|(name, h, _)| format!("{name}:{h}")).collect::<Vec<_>>()
                    );
                });
            }
        });
        let classes = classes.into_inner().unwrap();
        let failed = failed.into_inner();
        tracing::info!(
            "binary leaf classes over {} shards, {failed} failed to build: {classes:?}",
            counts.values().sum::<usize>()
        );
        Ok(())
    }

    /// The leaves of a cached block's first core shards proved over bits: the
    /// guest at `ZIREN_BLOCK_ELF` on the input at `ZIREN_BLOCK_INPUT`, its
    /// core proved on the host up to `ZIREN_CORE_SHARD_LIMIT` shards, and a
    /// leaf for each of `ZIREN_BINARY_LEAVES` shards from
    /// `ZIREN_BINARY_LEAF_FROM`, dumped as the fibonacci test dumps them.
    #[test]
    #[serial]
    #[ignore]
    fn test_e2e_leaf_binary_block() -> Result<()> {
        setup_logger();
        let elf = std::fs::read(std::env::var("ZIREN_BLOCK_ELF")?)?;
        let input = std::fs::read(std::env::var("ZIREN_BLOCK_INPUT")?)?;
        let mut stdin = ZKMStdin::new();
        stdin.write_vec(input);
        let mut prover = ZKMProver::<DefaultProverComponents>::new();
        if let Some(path) = std::env::var_os("ZIREN_BINARY_VK_EXTRA") {
            add_binary_keys(&mut prover, &std::fs::read_to_string(path)?);
        }
        let (_, pk_d, program, vk) = prover.setup(&elf);
        let started = std::time::Instant::now();
        let core_proof = prover.prove_core(
            &pk_d,
            program,
            &stdin,
            ZKMProverOpts::default(),
            ZKMContext::default(),
        )?;
        tracing::info!(
            "block core: {} shards proved on the host in {:.1} s",
            core_proof.proof.0.len(),
            started.elapsed().as_secs_f64()
        );
        let inputs =
            prover.get_recursion_core_inputs_basefold(&vk.vk, &core_proof.proof.0, 1, false);
        let count: usize = std::env::var("ZIREN_BINARY_LEAVES")
            .map_or(1, |n| n.parse().expect("ZIREN_BINARY_LEAVES is a count"));
        let from: usize = std::env::var("ZIREN_BINARY_LEAF_FROM")
            .map_or(0, |n| n.parse().expect("ZIREN_BINARY_LEAF_FROM is an index"));
        for (i, input) in inputs.iter().enumerate().skip(from).take(count) {
            let started = std::time::Instant::now();
            let leaf_proof = prover.leaf_binary(input)?;
            tracing::info!(
                "binary block leaf {i}: {} bytes, {:.1} s, {} instructions",
                bincode::serialize(&leaf_proof.proof).unwrap().len(),
                started.elapsed().as_secs_f64(),
                leaf_proof.program.iter_instructions().count()
            );
            for (label, bytes) in zkm_binary_stark::config::proof_breakdown(&leaf_proof.proof) {
                tracing::info!("binary block leaf {i} part {label}: {bytes} bytes");
            }
            let started = std::time::Instant::now();
            prover.verify_leaf_binary(&leaf_proof)?;
            tracing::info!(
                "binary block leaf {i} verified in {:.3} s",
                started.elapsed().as_secs_f64()
            );
            if let Some(path) = std::env::var_os("ZIREN_BINARY_LEAF_DUMP") {
                let path = format!("{}.{i}", path.to_string_lossy());
                let dump = zkm_binary_stark::machine::ProvedProgram {
                    program: (*leaf_proof.program).clone(),
                    digest: leaf_proof.digest,
                    public_values: leaf_proof.public_values,
                    proof: leaf_proof.proof,
                };
                std::fs::write(&path, dump.to_bytes().expect("the leaf serializes"))?;
                tracing::info!("binary block leaf written to {path}");
            }
        }
        Ok(())
    }

    /// The leaf of a fibonacci proof's first core shard compiled to word
    /// relations, the relations checked on the host and their cost reported
    /// per instruction kind.
    #[test]
    #[serial]
    #[ignore]
    fn test_e2e_leaf_word_fibonacci() -> Result<()> {
        let elf = test_artifacts::FIBONACCI_ELF;
        setup_logger();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let (_, pk_d, program, vk) = prover.setup(elf);
        let core_proof = prover.prove_core(
            &pk_d,
            program,
            &fib_stdin(10),
            ZKMProverOpts::default(),
            ZKMContext::default(),
        )?;
        let inputs =
            prover.get_recursion_core_inputs_basefold(&vk.vk, &core_proof.proof.0, 1, false);
        let started = std::time::Instant::now();
        let lowered = prover.leaf_word(&inputs[0])?;
        tracing::info!("word leaf lowered in {:.1} s", started.elapsed().as_secs_f64());
        let mut total = zkm_recursion_r1cs::Cost::default();
        for (kind, (count, cost)) in &lowered.census {
            tracing::info!("word leaf {kind}: {count} instructions, {cost:?}");
            total += *cost;
        }
        tracing::info!(
            "word leaf total: {total:?}, {} public words, digest {:?}",
            lowered.built.public.len(),
            lowered.digest
        );
        let started = std::time::Instant::now();
        let built = &lowered.built;
        built.system.verify(&built.public, &built.witness).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        tracing::info!(
            "word leaf relations hold, checked in {:.1} s",
            started.elapsed().as_secs_f64()
        );
        if std::env::var_os("ZIREN_WORD_PROVE").is_some() {
            let started = std::time::Instant::now();
            let key = zkm_recursion_r1cs::prove::WordKey::new(
                built,
                &zkm_binary_stark::BinarySchedule::default(),
            )
            .map_err(|e| anyhow::anyhow!(e))?;
            tracing::info!(
                "word leaf key: {} trace variables, {:.1} s",
                key.key.trace_variables(),
                started.elapsed().as_secs_f64()
            );
            let started = std::time::Instant::now();
            let (commitment, proof) = key.prove(built).map_err(|e| anyhow::anyhow!(e))?;
            tracing::info!(
                "word leaf proved in {:.1} s, {} bytes",
                started.elapsed().as_secs_f64(),
                zkm_recursion_r1cs::prove::proof_size(&proof)
            );
            let started = std::time::Instant::now();
            key.verify(&commitment, &built.public, &proof).map_err(|e| anyhow::anyhow!(e))?;
            tracing::info!("word leaf verified in {:.2} s", started.elapsed().as_secs_f64());
        }
        Ok(())
    }

    /// The leaf of a fibonacci proof's first core shard proved over bits,
    /// then verified on the host.
    #[test]
    #[serial]
    #[ignore]
    fn test_e2e_leaf_binary_fibonacci() -> Result<()> {
        let elf = test_artifacts::FIBONACCI_ELF;
        setup_logger();
        let opts = ZKMProverOpts::default();
        let mut prover = ZKMProver::<DefaultProverComponents>::new();
        if let Some(path) = std::env::var_os("ZIREN_BINARY_VK_EXTRA") {
            add_binary_keys(&mut prover, &std::fs::read_to_string(path)?);
        }
        let (_, pk_d, program, vk) = prover.setup(elf);
        let core_proof =
            prover.prove_core(&pk_d, program, &fib_stdin(10), opts, ZKMContext::default())?;
        let inputs =
            prover.get_recursion_core_inputs_basefold(&vk.vk, &core_proof.proof.0, 1, false);
        let count: usize = std::env::var("ZIREN_BINARY_LEAVES")
            .map_or(1, |n| n.parse().expect("ZIREN_BINARY_LEAVES is a count"));
        let all = count > 1;
        tracing::info!("binary leaves: {} core shards, proving {count}", inputs.len());
        for (i, input) in inputs.iter().enumerate().take(count) {
            let started = std::time::Instant::now();
            let leaf_proof = prover.leaf_binary(input)?;
            tracing::info!(
                "binary leaf proof: {} bytes, {:.1} s",
                bincode::serialize(&leaf_proof.proof).unwrap().len(),
                started.elapsed().as_secs_f64()
            );
            for (label, bytes) in zkm_binary_stark::config::proof_breakdown(&leaf_proof.proof) {
                tracing::info!("binary leaf proof part {label}: {bytes} bytes");
            }
            tracing::info!(
                "binary leaf program: {} instructions",
                leaf_proof.program.iter_instructions().count()
            );
            let started = std::time::Instant::now();
            prover.verify_leaf_binary(&leaf_proof)?;
            tracing::info!("binary leaf verified in {:.3} s", started.elapsed().as_secs_f64());
            if let Some(path) = std::env::var_os("ZIREN_BINARY_LEAF_DUMP") {
                let path = if all {
                    format!("{}.{i}", path.to_string_lossy())
                } else {
                    path.to_string_lossy().into_owned()
                };
                let dump = zkm_binary_stark::machine::ProvedProgram {
                    program: (*leaf_proof.program).clone(),
                    digest: leaf_proof.digest,
                    public_values: leaf_proof.public_values,
                    proof: leaf_proof.proof,
                };
                std::fs::write(&path, dump.to_bytes().expect("the leaf serializes"))?;
                tracing::info!("binary leaf written to {path}");
            }
        }
        Ok(())
    }

    /// A prover runs the program on an initial memory other than its image
    /// and proves against the image's verifying key: it sets up on the
    /// altered image, puts the honest image's initial global sum into the
    /// proving key so the transcript matches the honest key, and moves the
    /// difference between the two initial sums into the Global chip's
    /// declared global sum (`chip_cumulative_sums`) of one shard.  Nothing
    /// constrains the declared sum (the shard prover has no permutation trace,
    /// so `eval_permutation_constraints` returns before its last-row check),
    /// so a verifier summing those would cancel the difference.  Returns the
    /// forged core proof and the honest image's verifying key.
    fn forge_core_proof_over_altered_image(
        prover: &ZKMProver<DefaultProverComponents>,
        opts: ZKMProverOpts,
    ) -> Result<(ZKMCoreProof, ZKMVerifyingKey)> {
        use zkm_pcs::septic_curve::SepticCurveComplete;
        use zkm_pcs::septic_digest::SepticDigest;

        let elf = test_artifacts::FIBONACCI_ELF;
        let (_, _, program, vk) = prover.setup(elf);

        let text = program.pc_base..program.pc_base + 4 * program.instructions.len() as u32;
        let (&addr, &word) = program
            .image
            .iter()
            .rev()
            .find(|(addr, _)| !text.contains(addr))
            .expect("an image word outside the text segment");
        let mut altered = program.clone();
        altered.image.insert(addr, word ^ 1);

        let (altered_pk_d, altered_vk) = prover.core_prover.setup(&altered);
        let honest_initial = vk.vk.initial_global_cumulative_sum;
        let altered_initial = altered_vk.initial_global_cumulative_sum;
        assert_ne!(honest_initial, altered_initial, "the altered word must move the initial sum");
        let mut pk = prover.core_prover.pk_to_host(&altered_pk_d);
        pk.initial_global_cumulative_sum = honest_initial;
        let pk_d = prover.core_prover.pk_to_device(&pk);

        let mut core =
            prover.prove_core(&pk_d, altered, &fib_stdin(10), opts, ZKMContext::default())?;

        let shift = |d: SepticDigest<KoalaBear>| {
            SepticDigest(
                (SepticCurveComplete::Affine(d.0)
                    + SepticCurveComplete::Affine(altered_initial.0)
                    + SepticCurveComplete::Affine(honest_initial.0.neg()))
                .point(),
            )
        };
        let shard = core
            .proof
            .0
            .iter()
            .position(|sp| {
                sp.jagged_shard_proof.chip_cumulative_sums.values().any(|s| !s.global.is_zero())
            })
            .expect("a shard with global interactions");
        for sums in core.proof.0[shard]
            .jagged_shard_proof
            .chip_cumulative_sums
            .values_mut()
            .filter(|s| !s.global.is_zero())
        {
            sums.global = shift(sums.global);
        }
        tracing::info!(
            "altered image word {addr:#x}: {word:#x} -> {:#x}; shifted shard {shard}",
            word ^ 1
        );
        Ok((core, vk))
    }

    /// The host verifier sums the shard public values rather than the declared
    /// per-chip sums, so the core machine's verifier rejects the proof of
    /// [`forge_core_proof_over_altered_image`] on its own, without recursion and
    /// without any check outside `StarkMachine::verify`.
    ///
    /// `cargo test -r -p zkm-prover core_verify_rejects_a_proof_over_a_different_initial_memory -- --ignored --nocapture`
    #[test]
    #[serial]
    #[ignore]
    fn core_verify_rejects_a_proof_over_a_different_initial_memory() -> Result<()> {
        use zkm_pcs::{air::LookupScope, MachineProof, MachineVerificationError};

        setup_logger();
        let opts = ZKMProverOpts::default();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let (core, vk) = forge_core_proof_over_altered_image(&prover, opts)?;

        let machine = prover.core_prover.machine();
        let mut challenger = machine.config().challenger();
        let machine_proof = MachineProof { shard_proofs: core.proof.0.clone() };
        let machine_result = machine.verify(&vk.vk, &machine_proof, &mut challenger);
        tracing::info!("StarkMachine::verify: {machine_result:?}");
        assert!(
            matches!(
                machine_result,
                Err(MachineVerificationError::NonZeroCumulativeSum(LookupScope::Global, 0))
            ),
            "the core machine verifier must reject a proof over an altered initial memory; got {machine_result:?}"
        );

        let prover_result = prover.verify(&core.proof, &vk);
        assert!(
            matches!(
                prover_result,
                Err(MachineVerificationError::NonZeroCumulativeSum(LookupScope::Global, 0))
            ),
            "ZKMProver::verify must reject a proof over an altered initial memory; got {prover_result:?}"
        );
        Ok(())
    }

    /// Compress a keccak (precompile + multi-shard) workload with unpadded
    /// core shapes: exercises non-core chips (KeccakPermute/precompile/memory)
    /// and the multi-shard global cumulative-sum chain through the recursion
    /// `assert_complete`, beyond single-shard pure-core fibonacci.
    #[test]
    #[serial]
    #[ignore]
    fn test_e2e_compress_keccak() -> Result<()> {
        let elf = test_artifacts::KECCAK_SPONGE_ELF;
        setup_logger();
        let opts = ZKMProverOpts::default();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        test_e2e_prover::<DefaultProverComponents>(
            &prover,
            elf,
            ZKMStdin::default(),
            opts,
            Test::Compress,
        )
    }

    /// The MIPS 2-pc state `(pc, next_pc)` rides the State bus, and the bus's
    /// entry endpoint is the public-value pair `(start_pc, start_next_pc)`.
    /// `start_pc` is chained across shards; `start_next_pc` must be pinned too,
    /// or row 0 continues wherever the prover says.  No shard boundary falls
    /// inside a delay slot, so an execution shard enters and exits with the
    /// sequential lookahead `pc + 4`, the halting row included -- which the
    /// honest proof here exercises as the positive control.
    #[test]
    #[serial]
    fn two_pc_lookahead_is_pinned_per_shard() -> Result<()> {
        use std::borrow::BorrowMut;
        use std::panic::{catch_unwind, AssertUnwindSafe};
        setup_logger();
        let elf = test_artifacts::FIBONACCI_ELF;
        let opts = ZKMProverOpts::default();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let (_, pk_d, program, vk) = prover.setup(elf);
        let core =
            prover.prove_core(&pk_d, program, &fib_stdin(10), opts, ZKMContext::default())?;
        let n = core.proof.0.len();

        prover.verify(&core.proof, &vk)?;

        let forge = |idx: usize, f: &dyn Fn(&mut PublicValues<Word<KoalaBear>, KoalaBear>)| {
            let mut p = core.proof.clone();
            let outer: &mut PublicValues<Word<KoalaBear>, KoalaBear> =
                p.0[idx].public_values.as_mut_slice().borrow_mut();
            f(outer);
            let inner: &mut PublicValues<Word<KoalaBear>, KoalaBear> =
                p.0[idx].jagged_shard_proof.public_values.as_mut_slice().borrow_mut();
            f(inner);
            p
        };
        let eight = KoalaBear::from_u32(8);

        let entry = forge(0, &|pv| pv.start_next_pc = pv.start_pc + eight);
        assert!(
            prover.verify(&entry, &vk).is_err(),
            "host verifier accepted a forged start_next_pc"
        );
        let exit = forge(n - 1, &|pv| pv.next_next_pc = pv.next_pc + eight);
        assert!(prover.verify(&exit, &vk).is_err(), "host verifier accepted a forged next_next_pc");

        let outer_only = {
            let mut p = core.proof.clone();
            let pv: &mut PublicValues<Word<KoalaBear>, KoalaBear> =
                p.0[0].public_values.as_mut_slice().borrow_mut();
            pv.initial_timestamp += KoalaBear::ONE;
            p
        };
        let err =
            prover.verify(&outer_only, &vk).expect_err("divergent public-value copies accepted");
        assert!(
            format!("{err:?}").contains("public values mismatch"),
            "rejected for another reason: {err:?}"
        );

        let accepts = |proof: &ZKMCoreProofData| -> bool {
            let input = prover
                .get_recursion_core_inputs_basefold(&vk.vk, &proof.0[..1], 1, n == 1)
                .into_iter()
                .next()
                .unwrap();
            let (program, _) = prover.recursion_program_basefold(&input);
            let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
                program,
                zkm_pcs::inner_perm(),
            );
            let mut ws = Vec::new();
            Witnessable::<InnerConfig>::write(&input, &mut ws);
            runtime.witness_stream = ws.into();
            matches!(catch_unwind(AssertUnwindSafe(|| runtime.run())), Ok(Ok(())))
        };
        assert!(accepts(&core.proof), "the normalize program rejected the honest first shard");
        assert!(!accepts(&entry), "the normalize program accepted a forged start_next_pc");
        Ok(())
    }

    /// Perf-comparison fixture: prove_core only (Test::Core) on
    /// keccak-sponge ELF.  Multi-shard sha-cluster workload — exercises
    /// the jagged shard prover in `prove_shard_with_data` without invoking
    /// the compose tree.
    /// Use to capture per-shard basefold prove perf for keccak vs fib-1k.
    #[test]
    #[serial]
    #[ignore]
    fn test_e2e_core_keccak() -> Result<()> {
        let elf = test_artifacts::KECCAK_SPONGE_ELF;
        setup_logger();
        let opts = ZKMProverOpts::default();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        test_e2e_prover::<DefaultProverComponents>(
            &prover,
            elf,
            ZKMStdin::default(),
            opts,
            Test::Core,
        )
    }

    /// Fast Test::Core fib (prove_core + host verify) — runs the host
    /// verify (verify_jagged_inner) on the fib core shape without
    /// the 40-min compress.
    #[test]
    #[serial]
    #[ignore]
    fn test_e2e_core_fib() -> Result<()> {
        let elf = test_artifacts::FIBONACCI_ELF;
        setup_logger();
        let opts = ZKMProverOpts::default();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        test_e2e_prover::<DefaultProverComponents>(&prover, elf, fib_stdin(10), opts, Test::Core)
    }

    /// PROBE: how large is the shape space `fix_shape` can actually snap a core
    /// record onto?  That set is what the enumeration has to cover, and the vk
    /// merkle tree has a FIXED capacity, so its size decides whether a full
    /// enumeration is even representable.
    #[test]
    #[serial]
    #[ignore]
    fn core_shape_space_size_probe() {
        use zkm_core_machine::shape::CoreShapeConfig;
        setup_logger();
        let cfg = CoreShapeConfig::<KoalaBear>::default();
        let t = std::time::Instant::now();
        let mut n = 0usize;
        const CAP: usize = 5_000_000;
        for _ in cfg.all_shapes() {
            n += 1;
            if n >= CAP {
                break;
            }
        }
        tracing::info!(
            "[SHAPESPACE] all_shapes count={n}{} in {:?} (vk merkle capacity = 2^{} = {})",
            if n >= CAP { " (CAPPED)" } else { "" },
            t.elapsed(),
            VK_MERKLE_TREE_HEIGHT,
            1usize << VK_MERKLE_TREE_HEIGHT,
        );
        tracing::info!(
            "[SHAPESPACE] canonical cluster shapes = {}",
            cfg.enumerate_canonical_cluster_shapes().len(),
        );
    }

    // SHA2_RUST_ELF requires stdin input (ZKMStdin::default() → "insufficient
    // input data" syscall error).  Removed; fib + keccak already
    // characterize the per-cycle vs per-MLE-size cost.

    /// Perf-comparison fixture: prove_core only on
    /// sha2-test ELF (hashes "hello world" literal — needs no stdin).
    /// Third workload to triangulate per-MLE-size cost.
    #[test]
    #[serial]
    #[ignore]
    fn test_e2e_core_sha2_lit() -> Result<()> {
        let elf = test_artifacts::SHA2_ELF;
        setup_logger();
        let opts = ZKMProverOpts::default();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        test_e2e_prover::<DefaultProverComponents>(
            &prover,
            elf,
            ZKMStdin::default(),
            opts,
            Test::Core,
        )
    }
}

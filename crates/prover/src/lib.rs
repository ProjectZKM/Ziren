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
pub mod program_cache;
pub mod shapes;
pub mod types;
pub mod utils;
pub mod verify;

use std::{
    borrow::Borrow,
    collections::BTreeMap,
    env,
    num::NonZeroUsize,
    path::Path,
    sync::{mpsc::sync_channel, Arc, Mutex, OnceLock},
    thread,
};

use p3_field::{PrimeCharacteristicRing, PrimeField, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use tracing::instrument;
use zkm_core_executor::{ExecutionError, ExecutionReport, Executor, Program, ZKMContext};
use zkm_core_machine::{
    io::ZKMStdin, mips::MipsAir, reduce::ZKMReduceProof, utils::ZKMCoreProverError,
};
use zkm_pcs::{
    air::PublicValues, koala_bear_poseidon2::KoalaBearPoseidon2, Challenge, MachineProver,
    ShardProof, StarkGenericConfig, StarkProvingKey, StarkVerifyingKey, Val, Word, ZKMCoreOpts,
    ZKMProverOpts, DIGEST_SIZE,
};
use zkm_pcs::{shape::OrderedShape, MachineProvingKey};
use zkm_primitives::{hash_deferred_proof, io::ZKMPublicValues};
use zkm_recursion_circuit::{
    hash::FieldHasher,
    machine::{
        basefold_programs::{build_normalize_basefold_program, build_wrap_basefold_program},
        build_compose_basefold_recursion_program, build_deferred_basefold_recursion_program,
        compress_basefold::ZKMCompressBasefoldWitnessValues,
        core_basefold::ZKMCoreBasefoldWitnessValues,
        deferred_basefold::ZKMDeferredBasefoldWitnessValues,
        wrap_basefold::ZKMWrapBasefoldWitnessValues,
        PublicValuesOutputDigest, ZKMCompressShape, ZKMCompressWithVkeyShape,
        ZKMMerkleProofWitnessValues,
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
use zkm_recursion_core::{
    air::RecursionPublicValues, hash_vkey_with_part_vk, machine::RecursionAir,
    runtime::ExecutionRecord, shape::RecursionShapeConfig, stark::KoalaBearPoseidon2Outer,
    RecursionProgram, Runtime as RecursionRuntime,
};
pub use zkm_recursion_gnark_ffi::proof::{DvSnarkBn254Proof, Groth16Bn254Proof, PlonkBn254Proof};
use zkm_recursion_gnark_ffi::{
    groth16_bn254::Groth16Bn254Prover, plonk_bn254::PlonkBn254Prover, DvSnarkBn254Prover,
};

pub use types::*;
use utils::{words_to_bytes, zkm_committed_values_digest_bn254, zkm_vkey_digest_bn254};

use components::{DefaultProverComponents, ZKMProverComponents};

pub use zkm_core_machine::ZKM_CIRCUIT_VERSION;

/// The configuration for the core prover (D=4, 100-bit security).
pub type CoreSC = KoalaBearPoseidon2;

/// The configuration for the inner prover (D=4, 100-bit security).
pub type InnerSC = KoalaBearPoseidon2;

/// The configuration for the outer prover (D=4, 100-bit security).
pub type OuterSC = KoalaBearPoseidon2Outer;

pub type DeviceProvingKey<C> = <<C as ZKMProverComponents>::CoreProver as MachineProver<
    KoalaBearPoseidon2,
    MipsAir<KoalaBear>,
>>::DeviceProvingKey;

/// Fixed height of the allowed-vk Merkle tree (capacity 2^12 = 4096 vks).
///
/// BOTH the shape enumeration (`ZKMCompressProgramShape::from_proof_shape`,
/// which bakes `merkle_tree_height` into every compose/deferred/shrink
/// program) AND the runtime tree commit (`ZKMProver::new`) use this
/// constant.  If each side instead derived a height from its own
/// cardinality (enumerated-shape count vs vk_map size), the two
/// derivations could diverge and the witnessed merkle paths would desync
/// from the program shape.  A fixed ceiling kills that circularity.
///
/// It has to CONTAIN the enumeration, which is not a tuning knob: a normalize
/// key is a function of `(chip set, preprocessed block count, main block
/// count)`, and the reachable main block counts run up to the prover's own
/// per-shard area cap (`ELEMENT_THRESHOLD` = 120 stacking blocks).  That is
/// 2707 keys today.  A height that cannot hold them is not "a smaller map" —
/// it is a map that rejects real proofs, which is what 2^11 (2048) did.
/// `tests::enumeration_size_probe` asserts the fit.
pub const VK_MERKLE_TREE_HEIGHT: usize = 12;

const COMPRESS_DEGREE: usize = 3;
const SHRINK_DEGREE: usize = 3;
const WRAP_DEGREE: usize = 9;

const CORE_CACHE_SIZE: usize = 5;
/// Tree-reduce arity for the compress stage. The tree-reduce worker pre-computes
/// `layer_sizes` and emits partial batches when the source layer is
/// exhausted, so any arity ≥ 2 reaches the root cleanly. Larger
/// arity → fewer compress invocations
/// (`(N-1)/(k-1)` total) and amortizes per-shard fixed overhead
/// (Merkle binding, witness assembly, program build).
pub const REDUCE_BATCH_SIZE: usize = 4;

// TODO: FIX
//
// const SHAPES_URL_PREFIX: &str = "https://zkm-circuits.s3.us-east-2.amazonaws.com/shapes";
// const SHAPES_VERSION: &str = "146079e0e";
// lazy_static! {
//     static ref SHAPES_INIT: Once = Once::new();
// }

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

    /// Recursion proving keys, keyed by the identity of the program they
    /// were built from ([`zkm_recursion_core::setup_digest`]).
    ///
    /// A recursion tree proves one node per core shard plus one per compose
    /// batch — hundreds of nodes — and the programs behind them repeat: every
    /// node of a layer is the same circuit over different values.  `setup` is
    /// a pure function of the program (a per-chip preprocessed trace walk plus
    /// the preprocessed BaseFold commit), and it is the single most expensive
    /// thing in the stage, so keying it by program identity turns "once per
    /// node" into "once per distinct program".
    ///
    /// The key is the digest, not the arity: arity does not determine the
    /// program, because per-input shapes vary across nodes of equal arity and
    /// a key built for one shape does not open the other's traces.
    ///
    /// Bounded — an entry holds the preprocessed traces AND the retained
    /// BaseFold prover data for a 2^27-cell commit, so an unbounded map would
    /// grow with the number of distinct shapes a workload happens to produce.
    /// Insertion order is recorded alongside so the oldest entry is the one
    /// dropped.
    pub recursion_pks_basefold_cache: Mutex<RecursionPkCache>,

    /// Per-shape cache for the basefold Normalize recursion program — the
    /// leaf stage, one node per core shard.
    ///
    /// **Key**: [`ZKMCoreBasefoldWitnessValues::shape_key`].
    pub normalize_programs_basefold_cache: Mutex<RecursionProgramCache>,

    /// Per-shape cache for the basefold Compose recursion program — every
    /// interior node of the recursion tree.
    ///
    /// **Key**: [`ZKMCompressBasefoldWitnessValues::shape_key`].
    ///
    /// Both caches rest on one invariant, which their key documents and
    /// `ZIREN_VERIFY_PROGRAM_CACHE=1` checks byte-exactly on every hit:
    ///
    /// ```text
    /// shape_key(a) == shape_key(b)  ⟹  program(a) == program(b)
    /// ```
    ///
    /// The converse is not needed: two keys mapping to one program cost a
    /// duplicate build, which `recursion_pks_basefold_cache` (keyed by program
    /// identity) absorbs downstream.  Keying on `arity` alone would break the
    /// invariant — per-input shapes vary widely across nodes of equal arity,
    /// and reusing a program built for shape A against shape B's witness
    /// stream trips `RuntimeError::EmptyWitnessStream`.
    pub compose_programs_basefold_cache: Mutex<RecursionProgramCache>,
}

/// Program-identity-keyed recursion proving keys, capped so the retained
/// BaseFold data cannot grow without bound.
///
/// The eviction order is insertion order: a recursion tree walks its layers in
/// order and never returns to an earlier one, so the oldest key is also the one
/// least likely to be asked for again.
#[derive(Default)]
pub struct RecursionPkCache {
    entries: BTreeMap<[u8; 32], Arc<(StarkProvingKey<InnerSC>, StarkVerifyingKey<InnerSC>)>>,
    order: std::collections::VecDeque<[u8; 32]>,
    pub hits: u64,
    pub misses: u64,
}

impl RecursionPkCache {
    /// How many distinct programs' keys to retain.  Every layer of the tree
    /// contributes at most a handful of distinct programs, so a small cap
    /// still holds a whole layer's worth; raise it for workloads with an
    /// unusually wide shape spread, and set it to 0 to hold nothing (which
    /// recovers the build-a-key-per-node behaviour, for measurement).
    fn capacity() -> usize {
        std::env::var("ZIREN_RECURSION_PK_CACHE_SIZE")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(24)
    }

    fn get(&mut self, key: &[u8; 32]) -> Option<Arc<(StarkProvingKey<InnerSC>, StarkVerifyingKey<InnerSC>)>> {
        match self.entries.get(key) {
            Some(v) => {
                self.hits += 1;
                Some(Arc::clone(v))
            }
            None => {
                self.misses += 1;
                None
            }
        }
    }

    fn insert(
        &mut self,
        key: [u8; 32],
        pk: StarkProvingKey<InnerSC>,
        vk: StarkVerifyingKey<InnerSC>,
    ) -> Arc<(StarkProvingKey<InnerSC>, StarkVerifyingKey<InnerSC>)> {
        // First writer wins: a racing inserter for the same program discards
        // its own key rather than replacing a copy other shards may hold.
        if let Some(v) = self.entries.get(&key) {
            return Arc::clone(v);
        }
        let value = Arc::new((pk, vk));
        self.entries.insert(key, Arc::clone(&value));
        self.order.push_back(key);
        while self.order.len() > Self::capacity() {
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
            }
        }
        value
    }
}

/// Shape-keyed recursion programs, capped so a workload with a wide shape
/// spread cannot grow the map without bound.
///
/// A recursion tree walks its layers in order and never returns to an
/// earlier one, so insertion order is also least-likely-to-be-asked-again
/// order and is what the eviction uses.
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
}

impl RecursionProgramCache {
    /// How many distinct programs to retain.  A layer contributes a handful
    /// of distinct shapes, so a small cap still holds a whole layer; set it
    /// to 0 to hold nothing, which recovers the build-per-node behaviour for
    /// measurement.
    ///
    /// Holding EVERY shape is not the answer: a reth block reaches ~77 distinct
    /// programs, and raising the cap to 128 cut program builds only 91 -> 80
    /// (compress wall 213.8 -> 207.4 s) while peak RSS rose 128.0 -> 156.0 GB.
    /// A program is large enough that this cap is really a host-memory budget.
    ///
    /// Eviction stays INSERTION-ordered.  Renewing an entry on a hit (LRU) was
    /// measured WORSE — builds 91 -> 104, compress wall 213.8 -> 239.9 s —
    /// because the access pattern is cyclic rather than reuse-driven: a tree
    /// walks its layers in order, cycling through more distinct shapes than the
    /// cache holds, and that is the pattern for which LRU evicts exactly the
    /// entry wanted next.  The way out is fewer distinct shapes, not a
    /// different eviction order.
    fn capacity() -> usize {
        std::env::var("ZIREN_RECURSION_PROGRAM_CACHE_SIZE")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(16)
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
            return (Arc::clone(v), *d);
        }
        // The program is already shape-fixed here (the uncached builder runs
        // `fix_recursion_shape` BEFORE wrapping in the `Arc`), so the digest
        // describes exactly the bytes every later hit hands out.
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

    /// Creates a new [ZKMProver] with lazily initialized components.
    pub fn uninitialized() -> Self {
        // Initialize the provers.
        let core_machine = MipsAir::machine(CoreSC::default());
        let core_prover = C::CoreProver::new(core_machine);

        let compress_machine = CompressAir::compress_machine(InnerSC::default());
        let compress_prover = C::CompressProver::new(compress_machine);

        // TODO: Put the correct shrink and wrap machines here.
        let shrink_machine = ShrinkAir::shrink_machine(InnerSC::compressed());
        let shrink_prover = C::ShrinkProver::new(shrink_machine);

        let wrap_machine = WrapAir::wrap_machine(OuterSC::default());
        let wrap_prover = C::WrapProver::new(wrap_machine);

        let core_cache_size = NonZeroUsize::new(
            env::var("PROVER_CORE_CACHE_SIZE")
                .unwrap_or_else(|_| CORE_CACHE_SIZE.to_string())
                .parse()
                .unwrap_or(CORE_CACHE_SIZE),
        )
        .expect("PROVER_CORE_CACHE_SIZE must be a non-zero usize");

        // FIX-off (height-agnostic natural-commit) is the production DEFAULT.
        // Unset / not "true" => `None` => core shards prove at their NATURAL
        // per-shard heights (no band padding), the faster height-agnostic path
        // that the recursion area-pin + count-hash-bind make enumerable +
        // VERIFY_VK=true-verifying (240-key vk_map).  FIX-on stays SELECTABLE as
        // a fallback: `FIX_CORE_SHAPES=true` => `Some(..)` => the band-padded
        // core shapes.
        let recursion_shape_config = env::var("FIX_RECURSION_SHAPES")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(true)
            .then_some(RecursionShapeConfig::default());

        let vk_verification =
            env::var("VERIFY_VK").map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(true);

        tracing::debug!("vk verification: {}", vk_verification);

        // Read the shapes from the shapes directory and deserialize them into memory.
        let allowed_vk_map: BTreeMap<[KoalaBear; DIGEST_SIZE], usize> = if vk_verification {
            // Regenerate the vk_map.bin when the Ziren circuit is updated.
            // ```
            // cd Ziren
            // cargo run -r --bin build_compress_vks -- --num-compiler-workers 32 --count-setup-workers 32 --build-dir crates/prover
            // ```
            // It takes several days.
            bincode::deserialize(include_bytes!("../vk_map.bin")).unwrap()
        } else {
            // VERIFY_VK=false: the dummy map is a placeholder (membership is
            // never enforced).  Truncate to the FIXED tree capacity so the
            // legacy 10k-entry dummy_vk_map.bin doesn't trip the capacity
            // assert below (the real vk_map is bounded by regen policy).
            let full: BTreeMap<[KoalaBear; DIGEST_SIZE], usize> =
                bincode::deserialize(include_bytes!("../dummy_vk_map.bin")).unwrap();
            full.into_iter().take(1 << VK_MERKLE_TREE_HEIGHT).collect()
        };

        // Pad the leaf set to the FIXED tree capacity (see
        // VK_MERKLE_TREE_HEIGHT) with the all-zero digest — no known vk
        // hashes to it, and the real keys keep their indices.  This makes
        // the runtime tree height match the merkle_tree_height baked into
        // the enumerated recursion programs regardless of map cardinality.
        assert!(
            allowed_vk_map.len() <= (1 << VK_MERKLE_TREE_HEIGHT),
            "vk_map ({}) exceeds fixed merkle capacity 2^{}",
            allowed_vk_map.len(),
            VK_MERKLE_TREE_HEIGHT
        );
        let mut leaves: Vec<[KoalaBear; DIGEST_SIZE]> = allowed_vk_map.keys().copied().collect();
        leaves.resize(1 << VK_MERKLE_TREE_HEIGHT, [KoalaBear::ZERO; DIGEST_SIZE]);
        let (root, merkle_tree) = MerkleTree::commit(leaves);

        // Compose / deferred / shrink / wrap programs are all built lazily per
        // witness via the `*_basefold` builders (the basefold path is the only
        // path).  An upfront FRI build would be 4 ^ REDUCE_BATCH_SIZE programs
        // (256 at arity-4) at >5 min/program with vk_verification.
        let _ = core_cache_size;

        let prover = Self {
            core_prover,
            compress_prover,
            shrink_prover,
            wrap_prover,
            recursion_vk_root: root,
            recursion_vk_tree: merkle_tree,
            recursion_vk_map: allowed_vk_map,
            compress_shape_config: recursion_shape_config,
            vk_verification,
            wrap_vk: OnceLock::new(),
            normalize_programs_basefold_cache: Mutex::new(RecursionProgramCache::default()),
            compose_programs_basefold_cache: Mutex::new(RecursionProgramCache::default()),
            recursion_pks_basefold_cache: Mutex::new(RecursionPkCache::default()),
        };

        // Compose-program pre-warm: for each arity in `1..=REDUCE_BATCH_SIZE`,
        // synthesize a dummy compose witness and build its compose program at
        // process startup rather than inside the first user `compress()`.
        // Each built program lands in the compose cache under its own shape
        // key, and the walk also warms the compiler's internal tables (block
        // layout, codegen, shape fixing) that survive across builds.
        //
        // The dummy shard proof is a struct-only stub rather than a real
        // `prove_shard_with_data` per arity slot, which keeps the whole walk
        // at ~2.0 s.
        prover.prewarm_compose_programs();

        prover
    }

    /// Compose-program pre-warm helper.  See call-site comment in
    /// [`Self::uninitialized`] for the rationale.  Walks
    /// `arity in 1..=REDUCE_BATCH_SIZE`, building one dummy compose program
    /// per arity to amortize first-compile cost.  Unconditional: ~2.0 s of
    /// startup work against ~2.4 s that the first `compress()` would
    /// otherwise pay.
    ///
    /// ⚠ WHAT IT DOES NOT DO IS SEED THE CACHE.  Measured on a reth compress
    /// (`ZIREN_COMPOSE_CHILD_DIAG=1`): of the keys this builds, **none** match
    /// any key a real node presents — `compose_hits` is 40 with the pre-warm
    /// and 40 without, and the proving path still builds all 23 of its own
    /// programs.  Extending it across every band (24 dummies instead of 4)
    /// changes nothing except the 20 extra builds: still zero overlap.
    ///
    /// Two independent reasons, both upstream of this function:
    ///   * the dummy child is built at the CLAMPED area `Some(RECURSION_LOG_
    ///     TRACE_AREA)` while a real child takes `max(natural, pin)` — a
    ///     FLOOR — so every child whose natural area passes the pin has a
    ///     geometry no dummy here reproduces;
    ///   * 27 of 63 real compose nodes are built over children of DIFFERENT
    ///     shapes (25 at arity 4 with two, one with three), which no
    ///     `vec![shape; arity]` dummy can express at all.
    ///
    /// The second is also a vk-enumerability gap: `ZKMProofShape::generate`
    /// emits compose children as `vec![band; arity]`, so those 27 nodes'
    /// verifying keys are outside the enumerated space.  Making a node's
    /// children share a band is the fix for both, and is what would let
    /// compose programs be built once at construction, keyed by (band, arity).
    ///
    /// Bails when:
    ///   - `compress_shape_config` is None
    ///     (`FIX_RECURSION_SHAPES=false` — no allowed shape to drive
    ///     `fix_shape`, would panic or build a non-canonical program),
    ///   - the recursion shape config has no allowed shapes
    ///     (defensive — should not happen with the default config).
    fn prewarm_compose_programs(&self) {
        let Some(recursion_shape_config) = self.compress_shape_config.as_ref() else {
            tracing::debug!(
                "compose pre-warm skipped: compress_shape_config is None \
                 (FIX_RECURSION_SHAPES=false)"
            );
            return;
        };

        // Pull the first allowed recursion shape — replicated across
        // `arity` slots, this is a valid `ZKMCompressShape` that
        // survives `fix_shape`.
        let Some(first_shape_map) = recursion_shape_config.first() else {
            tracing::debug!(
                "compose pre-warm skipped: recursion_shape_config has no allowed shapes"
            );
            return;
        };

        let proof_shape: OrderedShape =
            first_shape_map.iter().map(|(k, v)| (k.clone(), *v)).collect();

        // Use the production merkle tree height — this is what real
        // compose witnesses see at runtime, so the pre-warmed shape
        // matches the JIT path that user calls will hit.
        let merkle_tree_height = self.recursion_vk_tree.height;

        let prewarm_start = std::time::Instant::now();
        for arity in 1..=REDUCE_BATCH_SIZE {
            let compress_shape = ZKMCompressShape::from(vec![proof_shape.clone(); arity]);
            let shape = ZKMCompressWithVkeyShape { compress_shape, merkle_tree_height };
            let witness = ZKMCompressBasefoldWitnessValues::<InnerSC>::dummy(
                self.compress_prover.machine(),
                &shape,
            );
            let per_arity_start = std::time::Instant::now();
            // Retained by `compose_programs_basefold_cache` under this
            // witness's shape key; a real node of the same shape then hits.
            let _program = self.compose_program_basefold(&witness);
            tracing::debug!(
                "compose pre-warm: arity={arity} built in {:?}",
                per_arity_start.elapsed()
            );
        }
        tracing::debug!(
            "compose pre-warm: arity 1..={} done in {:?}",
            REDUCE_BATCH_SIZE,
            prewarm_start.elapsed()
        );
    }

    /// Returns true when the host-side compose-pk cache is enabled.
    /// The key for `program`, as the recursion pk cache sees it.
    pub fn recursion_pk_cache_key(program: &RecursionProgram<KoalaBear>) -> [u8; 32] {
        zkm_recursion_core::setup_digest(program)
    }

    /// The cached `(pk, vk)` for a program, if its key has been built before.
    /// The returned `Arc` is cheap to clone and the GPU dispatch path holds it
    /// for one node.
    pub fn recursion_pk_cache_get(
        &self,
        key: &[u8; 32],
    ) -> Option<Arc<(StarkProvingKey<InnerSC>, StarkVerifyingKey<InnerSC>)>> {
        self.recursion_pks_basefold_cache.lock().unwrap().get(key)
    }

    /// Publish a freshly built key.  Returns the `Arc` that is actually in the
    /// cache, so a caller that lost a race uses the canonical key rather than
    /// its own copy.
    pub fn recursion_pk_cache_insert(
        &self,
        key: [u8; 32],
        pk: StarkProvingKey<InnerSC>,
        vk: StarkVerifyingKey<InnerSC>,
    ) -> Arc<(StarkProvingKey<InnerSC>, StarkVerifyingKey<InnerSC>)> {
        self.recursion_pks_basefold_cache.lock().unwrap().insert(key, pk, vk)
    }

    /// Hits and misses since the process started, for the stage report.
    pub fn recursion_pk_cache_counts(&self) -> (u64, u64) {
        let g = self.recursion_pks_basefold_cache.lock().unwrap();
        (g.hits, g.misses)
    }

    /// Fully initializes the programs, proving keys, and verifying keys that are normally
    /// lazily initialized. TODO: remove this.
    pub fn initialize(&mut self) {}

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

    /// The FIXED zerocheck cube (= `BasefoldShardVerifier`
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
        zkm_pcs::shard_level::verifier::BasefoldShardVerifier::production_default()
            .max_log_row_count
    }

    /// Snap a basefold recursion program onto one of the allowed recursion
    /// shapes before proving a recursion shard.
    ///
    /// This is what makes the produced verifying keys ENUMERABLE.  A program
    /// left at its organic heights produces a proof whose per-chip heights are
    /// whatever execution happened to yield, so the parent compose program —
    /// which is built from its children's shapes — is a function of those
    /// organic heights and can never coincide with a program built from
    /// `ZKMProofShape::generate`'s band-snapped shapes.  That is why
    /// `VERIFY_VK=true` rejected at compress with the vk absent from a FRESHLY
    /// regenerated map: the map was not stale, the produced key was simply
    /// outside the enumerated space.
    ///
    /// `None` (`FIX_RECURSION_SHAPES=false`) leaves the program at its organic
    /// heights and gives up vk enumerability with it.
    fn fix_recursion_shape(&self, program: &mut RecursionProgram<KoalaBear>) {
        if let Some(config) = self.compress_shape_config.as_ref() {
            config.fix_shape(program);
        }
    }

    /// Build the Normalize (basefold) recursion program. Cluster-parametrized
    /// analog of [`Self::recursion_program`].
    ///
    /// Band-snapped through [`Self::fix_recursion_shape`] before proving —
    /// that is what keeps the produced
    /// verifying key inside `ZKMProofShape::generate`'s enumerated space.
    ///
    /// Shape-keyed: the leaf layer builds one node per core shard, and those
    /// nodes collapse onto far fewer distinct programs than there are shards.
    /// See [`Self::normalize_programs_basefold_cache`].
    /// Returns the program AND its `setup_digest` -- the proving-key cache
    /// key.  Hashing a multi-million-instruction program is ~291 ms, so a
    /// caller that re-derived it per node paid for one every time, including
    /// on a cache hit where the digest was already known.
    pub fn recursion_program_basefold(
        &self,
        input: &ZKMCoreBasefoldWitnessValues<InnerSC>,
    ) -> (Arc<RecursionProgram<KoalaBear>>, [u8; 32]) {
        self.cached_program(
            &self.normalize_programs_basefold_cache,
            input.shape_key(),
            "normalize",
            || self.build_normalize_program_basefold_uncached(input),
        )
    }

    /// Uncached body of [`Self::recursion_program_basefold`] — separate so the
    /// cache audit can rebuild and assert byte-equality.
    fn build_normalize_program_basefold_uncached(
        &self,
        input: &ZKMCoreBasefoldWitnessValues<InnerSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        // The normalize circuit verifies its input core-shard proofs at the
        // fixed `max_log_row_count`.
        let max_log_row_count = Self::pcs_max_log_row_count();
        let mut program =
            build_normalize_basefold_program(self.core_prover.machine(), input, max_log_row_count);
        self.fix_recursion_shape(&mut program);
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
        let program = build();
        cache.lock().unwrap().insert(cache_key, program)
    }

    /// Hits and misses of both shape-keyed program caches, for the stage
    /// report: `(normalize_hits, normalize_misses, compose_hits, compose_misses)`.
    pub fn recursion_program_cache_counts(&self) -> (u64, u64, u64, u64) {
        let n = self.normalize_programs_basefold_cache.lock().unwrap();
        let c = self.compose_programs_basefold_cache.lock().unwrap();
        (n.hits, n.misses, c.hits, c.misses)
    }

    /// Build the Compose (basefold) recursion program. Cluster-parametrized
    /// analog of [`Self::compress_program`].
    ///
    /// Shape-keyed — see [`Self::compose_programs_basefold_cache`].
    /// Returns the program AND its `setup_digest` -- the proving-key cache
    /// key.  Hashing a multi-million-instruction program is ~291 ms, so a
    /// caller that re-derived it per node paid for one every time, including
    /// on a cache hit where the digest was already known.
    pub fn compose_program_basefold(
        &self,
        input: &ZKMCompressBasefoldWitnessValues<InnerSC>,
    ) -> (Arc<RecursionProgram<KoalaBear>>, [u8; 32]) {
        // `ZIREN_COMPOSE_CHILD_DIAG=1`: how many DISTINCT child proof
        // structures each compose node is built over.  The vk enumeration
        // emits compose children as `vec![band; arity]` — all children alike —
        // so any node reporting more than one child shape is a node whose vk
        // no enumerated shape can match.
        if std::env::var_os("ZIREN_COMPOSE_CHILD_DIAG").is_some() {
            use std::hash::Hasher;
            let per_child: Vec<u64> = input
                .vks_and_proofs
                .iter()
                .map(|(_vk, sp)| {
                    let mut h = std::collections::hash_map::DefaultHasher::new();
                    zkm_recursion_circuit::machine::shape_signature::hash_shard_proof_structure(
                        sp, &mut h,
                    );
                    h.finish()
                })
                .collect();
            let mut distinct = per_child.clone();
            distinct.sort_unstable();
            distinct.dedup();
            eprintln!(
                "COMPOSE_CHILD_DIAG arity={} distinct_child_shapes={} key={:#018x} children={:?}",
                per_child.len(),
                distinct.len(),
                input.shape_key(),
                per_child,
            );
        }
        self.cached_program(
            &self.compose_programs_basefold_cache,
            input.shape_key(),
            "compose",
            || self.build_compose_program_basefold_uncached(input),
        )
    }

    /// Uncached body of [`Self::compose_program_basefold`] — exposed so the
    /// cache wrapper can rebuild under the cache audit to
    /// assert byte-equality.
    fn build_compose_program_basefold_uncached(
        &self,
        input: &ZKMCompressBasefoldWitnessValues<InnerSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        let max_log_row_count = Self::pcs_max_log_row_count();
        // The `_recursion` variant is the sole production path for
        // basefold-for-recursion.
        let mut program = build_compose_basefold_recursion_program(
            self.compress_prover.machine(),
            input,
            max_log_row_count,
            self.vk_verification,
            PublicValuesOutputDigest::Reduce,
        );
        self.fix_recursion_shape(&mut program);
        Arc::new(program)
    }

    /// Build the Deferred (basefold) recursion program. Cluster-parametrized
    /// analog of [`Self::deferred_program`].
    pub fn deferred_program_basefold(
        &self,
        input: &ZKMDeferredBasefoldWitnessValues<InnerSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        let max_log_row_count = Self::pcs_max_log_row_count();
        // basefold-for-recursion, mirroring
        // `build_compose_program_basefold_uncached`.
        let mut program = build_deferred_basefold_recursion_program(
            self.compress_prover.machine(),
            input,
            max_log_row_count,
            self.vk_verification,
        );
        self.fix_recursion_shape(&mut program);
        Arc::new(program)
    }

    /// Build the Wrap (basefold) recursion program. Cluster-parametrized
    /// analog of [`Self::shrink_program`] / [`Self::wrap_program`].
    /// Band-snapped through [`Self::fix_recursion_shape`], like every other
    /// recursion stage whose verifying key the allowlist has to contain.
    pub fn shrink_program_basefold(
        &self,
        input: &ZKMWrapBasefoldWitnessValues<InnerSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        let max_log_row_count = Self::pcs_max_log_row_count();
        let mut program = build_wrap_basefold_program(
            self.compress_prover.machine(),
            input,
            max_log_row_count,
            self.vk_verification,
        );
        self.fix_recursion_shape(&mut program);
        Arc::new(program)
    }

    /// Build the bn254-Wrap (basefold) recursion program — terminal
    /// stage analog of [`Self::wrap_program`] for the basefold pipeline.
    ///
    /// Differs from [`Self::shrink_program_basefold`] in two ways:
    /// 1. Compiles with [`WrapConfig`] (instead of [`InnerConfig`]) so
    ///    the resulting [`RecursionProgram`] is provable on the OuterSC
    ///    (BN254-friendly) ring via [`Self::wrap_prover`], not the
    ///    KoalaBear-side [`Self::shrink_prover`].
    /// 2. Verifies the input proof against
    ///    [`Self::shrink_prover`]`.machine()` (the machine that produced
    ///    the shrink-basefold output we are wrapping).
    ///
    /// The `verify_wrap_basefold` body is generic over `C: CircuitConfig`
    /// with `F=InnerVal` / `EF=InnerChallenge` / `Bit=Felt<KoalaBear>`,
    /// and `WrapConfig` satisfies these bounds (see
    /// `recursion/circuit/src/lib.rs:327`), so the same verifier function
    /// works unchanged here.
    ///
    /// Not cached — like [`Self::shrink_program_basefold`], the program
    /// is built fresh per call from the real input shape (cumulative-sum
    /// maps, chip names, column counts).  `wrap_bn254` is invoked once
    /// per end-to-end proof, so the per-call build cost is acceptable.
    pub fn wrap_bn254_program_basefold(
        &self,
        input: &ZKMWrapBasefoldWitnessValues<InnerSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        use zkm_recursion_circuit::machine::wrap_basefold::verify_wrap_basefold;

        let max_log_row_count = Self::pcs_max_log_row_count();

        let builder_span = tracing::debug_span!("build wrap-bn254-basefold program").entered();
        let mut builder = Builder::<WrapConfig>::default();
        let input_var = input.read(&mut builder);
        verify_wrap_basefold::<WrapConfig, InnerSC, _>(
            &mut builder,
            input_var,
            self.shrink_prover.machine(),
            self.vk_verification,
            max_log_row_count,
            // The BN254 wrap is the recursion-tree root: emit the ROOT digest
            // so the committed PV digest matches `verify_wrap_bn254`'s
            // `is_root_public_values_valid` (host) and the in-circuit root check.
            PublicValuesOutputDigest::Root,
        );
        let operations = builder.into_operations();
        builder_span.exit();

        let compiler_span = tracing::debug_span!("compile wrap-bn254-basefold program").entered();
        let mut compiler = AsmCompiler::<WrapConfig>::default();
        let program = compiler.compile(operations);
        compiler_span.exit();
        Arc::new(program)
    }

    /// Extract `BasefoldShardProof`s from a batch of `ShardProof`s
    /// (the `basefold_shard_proof` payload populated by
    /// the prover's `open()`) and wrap each batch
    /// into a `ZKMCoreBasefoldWitnessValues`.
    ///
    /// Returns `None` if any proof in the batch lacks the basefold side
    /// channel — every live producer populates it, so the caller treats
    /// `None` as a hard error.
    pub fn get_recursion_core_inputs_basefold(
        &self,
        vk: &StarkVerifyingKey<CoreSC>,
        shard_proofs: &[ShardProof<CoreSC>],
        batch_size: usize,
        is_complete: bool,
    ) -> Option<Vec<ZKMCoreBasefoldWitnessValues<InnerSC>>> {
        // Verify every shard carries a basefold side-channel before
        // producing any witnesses.
        if shard_proofs.iter().any(|p| p.basefold_shard_proof.is_none()) {
            return None;
        }

        let mut core_inputs = Vec::new();
        for (batch_idx, batch) in shard_proofs.chunks(batch_size).enumerate() {
            // SINGLE-SHARD NORMALIZE: the production normalize path is
            // arity-1 (`compress` calls `get_first_layer_inputs` with
            // `first_layer_batch_size = 1` → this function is reached with
            // `batch_size = 1`, one shard per `ZKMCoreBasefoldWitnessValues`).
            // A multi-shard normalize VK is a PHANTOM (only the enumerator
            // would emit arity≥2 Recursion shapes), so an in-circuit
            // aggregate loop + multi-shard dummy would be dead weight on a
            // forbidden path.
            // Hard-assert the single-shard invariant so any caller that batches
            // core shards into the normalize stage (a regression) is caught at
            // input construction rather than silently building a normalize proof
            // whose VK the enumerator does not cover.
            assert_eq!(
                batch.len(),
                1,
                "normalize is single-shard: get_recursion_core_inputs_basefold \
                 must be called with batch_size=1 (one core shard per normalize); \
                 got a batch of {} shards",
                batch.len()
            );
            let bf_proofs = batch
                .iter()
                .map(|sp| *sp.basefold_shard_proof.as_ref().unwrap().clone())
                .collect::<Vec<_>>();
            core_inputs.push(ZKMCoreBasefoldWitnessValues {
                vk: vk.clone(),
                shard_proofs: bf_proofs,
                is_complete,
                is_first_shard: batch_idx == 0,
                vk_root: self.recursion_vk_root,
            });
        }

        Some(core_inputs)
    }

    /// Constructs `ZKMDeferredBasefoldWitnessValues` from each batch
    /// by extracting the `basefold_shard_proof` side channel from
    /// each input proof. Returns `None` when any deferred proof is
    /// missing the side channel (the caller treats that as a hard error).
    ///
    /// Mirrors the layout of
    /// `get_recursion_core_inputs_basefold` — same `if all_have_bf
    /// { Some } else { None }` pattern.
    pub fn get_recursion_deferred_inputs_basefold<'a>(
        &'a self,
        vk: &'a StarkVerifyingKey<CoreSC>,
        last_proof_pv: &PublicValues<Word<KoalaBear>, KoalaBear>,
        deferred_proofs: &[ZKMReduceProof<InnerSC>],
        batch_size: usize,
    ) -> Option<Vec<ZKMDeferredBasefoldWitnessValues<InnerSC>>> {
        // All deferred proofs must carry a basefold side channel.
        if !deferred_proofs.iter().all(|p| p.proof.basefold_shard_proof.is_some()) {
            return None;
        }
        let mut deferred_digest = [Val::<InnerSC>::ZERO; DIGEST_SIZE];
        let mut deferred_inputs = Vec::new();
        for batch in deferred_proofs.chunks(batch_size) {
            let vks_and_proofs: Vec<_> = batch
                .iter()
                .cloned()
                .map(|proof| {
                    let bf = *proof.proof.basefold_shard_proof.unwrap();
                    (proof.vk, bf)
                })
                .collect();

            // The merkle witness only depends on vks, not the proof body —
            // the basefold pipeline uses the SAME vk-merkle indirection
            // here (unlike shrink, where ZKMWrapBasefoldWitnessValues has
            // no merkle field).
            let vks: Vec<StarkVerifyingKey<InnerSC>> =
                vks_and_proofs.iter().map(|(vk, _)| vk.clone()).collect();
            let merkle = self.make_basefold_merkle_proofs(&vks);

            deferred_inputs.push(ZKMDeferredBasefoldWitnessValues {
                vks_and_proofs,
                vk_merkle_data: merkle,
                start_reconstruct_deferred_digest: deferred_digest,
                is_complete: false,
                zkm_vk_digest: vk.hash_koalabear(),
                end_pc: Val::<InnerSC>::ZERO,
                end_shard: last_proof_pv.shard + KoalaBear::ONE,
                end_execution_shard: last_proof_pv.execution_shard,
                init_addr_bits: last_proof_pv.last_init_addr_bits,
                finalize_addr_bits: last_proof_pv.last_finalize_addr_bits,
                committed_value_digest: last_proof_pv.committed_value_digest,
                deferred_proofs_digest: last_proof_pv.deferred_proofs_digest,
            });
            deferred_digest = Self::hash_deferred_proofs(deferred_digest, batch);
        }
        Some(deferred_inputs)
    }

    /// Generate the inputs for the first layer of recursive proofs.
    ///
    /// Every shard carries a `basefold_shard_proof` side channel, so this
    /// emits `ZKMCircuitWitness::CoreBasefold` witnesses that dispatch to
    /// the cluster-parametrized basefold Normalize program. Deferred
    /// proofs follow the same dispatch. A missing side channel is a
    /// producer bug and panics.
    #[allow(clippy::type_complexity)]
    pub fn get_first_layer_inputs<'a>(
        &'a self,
        vk: &'a ZKMVerifyingKey,
        shard_proofs: &[ShardProof<InnerSC>],
        deferred_proofs: &[ZKMReduceProof<InnerSC>],
        batch_size: usize,
    ) -> Vec<ZKMCircuitWitness> {
        let is_complete = shard_proofs.len() == 1 && deferred_proofs.is_empty();

        let mut inputs = Vec::new();

        let bf_inputs = self
            .get_recursion_core_inputs_basefold(&vk.vk, shard_proofs, batch_size, is_complete)
            .expect("core shard proof missing basefold_shard_proof side channel");
        tracing::debug!("emitting {} CoreBasefold witness(es)", bf_inputs.len());
        inputs.extend(bf_inputs.into_iter().map(ZKMCircuitWitness::CoreBasefold));

        let last_proof_pv = shard_proofs.last().unwrap().public_values.as_slice().borrow();
        let bf_deferred = self
            .get_recursion_deferred_inputs_basefold(
                &vk.vk,
                last_proof_pv,
                deferred_proofs,
                batch_size,
            )
            .expect("deferred proof missing basefold_shard_proof side channel");
        inputs.extend(bf_deferred.into_iter().map(ZKMCircuitWitness::DeferredBasefold));
        inputs
    }

    /// Reduce shard proofs to a single shard proof using the recursion prover.
    #[instrument(name = "compress", level = "info", skip_all)]
    // NOTE: the vk_map was last regenerated for the jagged-lift
    // column-count formula (cc[len-2]+1 zero-column padding).
    pub fn compress(
        &self,
        vk: &ZKMVerifyingKey,
        proof: ZKMCoreProof,
        deferred_proofs: Vec<ZKMReduceProof<InnerSC>>,
        opts: ZKMProverOpts,
    ) -> Result<ZKMReduceProof<InnerSC>, ZKMRecursionProverError> {
        // The batch size for reducing two layers of recursion.
        let batch_size = REDUCE_BATCH_SIZE;
        // The batch size for reducing the first layer of recursion.
        let first_layer_batch_size = 1;

        let shard_proofs = &proof.proof.0;

        let first_layer_inputs =
            self.get_first_layer_inputs(vk, shard_proofs, &deferred_proofs, first_layer_batch_size);

        // Pre-compute the input count at each height of the tree so the
        // next-layer worker can flush a partial batch when its layer is
        // exhausted (otherwise an arity > 2 tree with leftovers wedges
        // waiting for items that will never arrive). `layer_sizes[h]` is
        // the number of inputs the worker will receive at height `h`;
        // height 0 is the first-layer input count, and the deepest entry
        // is the final layer that still needs reduction (≤ batch_size).
        let num_first_layer_inputs = first_layer_inputs.len();
        let mut layer_sizes: Vec<usize> = vec![num_first_layer_inputs];
        while *layer_sizes.last().unwrap() > batch_size {
            let last = *layer_sizes.last().unwrap();
            layer_sizes.push(last.div_ceil(batch_size));
        }
        // Tree height = number of reductions to produce the root.
        // With one first-layer input, height = 0 (passthrough); otherwise
        // every layer in `layer_sizes` needs one reduction step (the last
        // one a partial batch if `last < batch_size`).
        let expected_height = if num_first_layer_inputs == 1 { 0 } else { layer_sizes.len() };

        // Generate the proofs.
        let span = tracing::Span::current().clone();
        let (vk, proof) = thread::scope(|s| {
            let _span = span.enter();

            // Spawn a worker that sends the first layer inputs to a bounded channel.
            //
            // No turn-based sync here: the per-height pending lists in the
            // next-layer worker (see `pending: Vec<Vec<Item>>` below) are
            // arrival-order tolerant, so workers can race to drain `input_rx`
            // without preserving first-layer index order.
            let (input_tx, input_rx) = sync_channel::<(usize, usize, ZKMCircuitWitness)>(
                opts.recursion_opts.checkpoints_channel_capacity,
            );
            let input_tx = Arc::new(Mutex::new(input_tx));
            {
                let input_tx = Arc::clone(&input_tx);
                s.spawn(move || {
                    for (index, input) in first_layer_inputs.into_iter().enumerate() {
                        input_tx.lock().unwrap().send((index, 0, input)).unwrap();
                    }
                });
            }

            // Spawn workers who generate the records and traces.
            let (record_and_trace_tx, record_and_trace_rx) =
                sync_channel::<(
                    usize,
                    usize,
                    Arc<RecursionProgram<KoalaBear>>,
                    ExecutionRecord<KoalaBear>,
                    Vec<(String, RowMajorMatrix<KoalaBear>)>,
                )>(opts.recursion_opts.records_and_traces_channel_capacity);
            let record_and_trace_tx = Arc::new(Mutex::new(record_and_trace_tx));
            let record_and_trace_rx = Arc::new(Mutex::new(record_and_trace_rx));
            let input_rx = Arc::new(Mutex::new(input_rx));
            for _ in 0..opts.recursion_opts.trace_gen_workers {
                let record_and_trace_tx = Arc::clone(&record_and_trace_tx);
                let input_rx = Arc::clone(&input_rx);
                let span = tracing::debug_span!("generate records and traces");
                s.spawn(move || {
                    let _span = span.enter();
                    loop {
                        let received = { input_rx.lock().unwrap().recv() };
                        if let Ok((index, height, input)) = received {
                            // Get the program and witness stream.
                            let (program, witness_stream) = tracing::debug_span!(
                                "get program and witness stream"
                            )
                            .in_scope(|| match input {
                                ZKMCircuitWitness::CoreBasefold(input) => {
                                    let mut witness_stream = Vec::new();
                                    Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
                                    (self.recursion_program_basefold(&input).0, witness_stream)
                                }
                                ZKMCircuitWitness::ComposeBasefold(input) => {
                                    let mut witness_stream = Vec::new();
                                    Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
                                    (
                                        self.compose_program_basefold(&input).0,
                                        witness_stream,
                                    )
                                }
                                ZKMCircuitWitness::DeferredBasefold(input) => {
                                    let mut witness_stream = Vec::new();
                                    Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
                                    (
                                        self.deferred_program_basefold(&input),
                                        witness_stream,
                                    )
                                }
                            });

                            // Execute the runtime.
                            //
                            // Instrumentation: info-level span recording the
                            // program's total instruction count.  Bounds the
                            // potential SeqBlock parallelism win before
                            // committing to that refactor — if per-call wall
                            // is small or the instruction count is small, the
                            // win ceiling is correspondingly bounded.  The
                            // per-compose-call span lets `cargo run … 2>&1 |
                            // grep "execute runtime"` extract the per-call
                            // wall histogram for any production run.
                            let n_instructions = program.instruction_count();
                            let _t_run = std::time::Instant::now();
                            let record = tracing::info_span!(
                                "execute_runtime",
                                instructions = n_instructions,
                            ).in_scope(|| {
                                let mut runtime =
                                    RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
                                        program.clone(),
                                        self.compress_prover.machine().config().perm.clone(),
                                    );
                                runtime.witness_stream = witness_stream.into();
                                runtime
                                    .run()
                                    .map_err(|e| {
                                        ZKMRecursionProverError::RuntimeError(e.to_string())
                                    })
                                    .unwrap();
                                runtime.record
                            });
                            // Instrumentation: emit per-compose-call wall
                            // after the span exits.  Use to bound the
                            // potential SeqBlock parallelism win — if this is
                            // routinely <100ms, the win ceiling is small and
                            // the parallelism refactor is not worthwhile.
                            tracing::info!(
                                event = "execute_runtime_done",
                                elapsed_ms = _t_run.elapsed().as_millis() as u64,
                                instructions = n_instructions,
                                "compose-call runtime wall"
                            );

                            // Generate the dependencies.
                            let mut records = vec![record];
                            tracing::debug_span!("generate dependencies").in_scope(|| -> Result<(), ZKMRecursionProverError> {
                                match self.compress_prover.machine().generate_dependencies(
                                    &mut records,
                                    &opts.recursion_opts,
                                    None,
                                ) {
                                    Ok(_) => Ok(()),
                                    Err(e) => {
                                        tracing::error!(
                                            "Failed to generate dependencies for recursion proof: {}",
                                            e
                                        );
                                        Err(ZKMRecursionProverError::DependenciesGenerationError)
                                    }
                                }
                            })?;

                            // Generate the traces.
                            let record = records.into_iter().next().unwrap();
                            let traces = tracing::debug_span!("generate traces")
                                .in_scope(|| self.compress_prover.generate_traces(&record));
                            let traces = match traces {
                                Ok(traces) => traces,
                                Err(e) => {
                                    tracing::error!(
                                        "Failed to generate traces for recursion proof: {}",
                                        e
                                    );
                                    return Err(ZKMRecursionProverError::TracesGenerationError);
                                }
                            };

                            // Send the record and traces to the worker.
                            // Mpsc channel is order-preserving in send order;
                            // arrival order in the prove pool is fine because
                            // the next-layer worker buckets by `height` and
                            // drains FIFO within the bucket.
                            record_and_trace_tx
                                .lock()
                                .unwrap()
                                .send((index, height, program, record, traces))
                                .unwrap();
                        } else {
                            break Ok(());
                        }
                    }
                });
            }

            // Spawn workers who generate the compress proofs.
            let (proofs_tx, proofs_rx) =
                sync_channel::<(usize, usize, StarkVerifyingKey<InnerSC>, ShardProof<InnerSC>)>(
                    num_first_layer_inputs * 2,
                );
            let proofs_tx = Arc::new(Mutex::new(proofs_tx));
            let proofs_rx = Arc::new(Mutex::new(proofs_rx));
            let mut prover_handles = Vec::new();
            for _ in 0..opts.recursion_opts.shard_batch_size {
                let record_and_trace_rx = Arc::clone(&record_and_trace_rx);
                let proofs_tx = Arc::clone(&proofs_tx);
                let span = tracing::debug_span!("prove");
                let handle = s.spawn(move || {
                    let _span = span.enter();
                    loop {
                        let received = { record_and_trace_rx.lock().unwrap().recv() };
                        if let Ok((index, height, program, record, traces)) = received {
                            tracing::debug_span!("batch").in_scope(|| {
                                // The recursion-layer area pin is sourced from
                                // `machine().pins_recursion_area()` inside
                                // `commit()` — nothing to thread here.

                                // Get the keys.
                                let (pk, vk) = tracing::debug_span!("Setup compress program")
                                    .in_scope(|| self.compress_prover.setup(&program));

                                // Observe the proving key.
                                let mut challenger =
                                    self.compress_prover.machine().config().challenger();
                                tracing::debug_span!("observe proving key").in_scope(|| {
                                    pk.observe_into(&mut challenger);
                                });

                                #[cfg(feature = "debug")]
                                self.compress_prover.machine().debug_constraints(
                                    &self.compress_prover.pk_to_host(&pk),
                                    vec![record.clone()],
                                    &mut challenger.clone(),
                                );

                                // Commit to the record and traces.
                                let data = tracing::debug_span!("commit").in_scope(|| {
                                    // recursion (compress): own-chip-set commit (no
                                    // canonical-cluster missing-chip injection);
                                    // recursion AREA PIN threaded explicitly.
                                    self.compress_prover.commit(&record, traces, None)
                                });

                                // Generate the proof.
                                let proof = tracing::debug_span!("open").in_scope(|| {
                                    self.compress_prover.open(&pk, data, &mut challenger).unwrap()
                                });

                                // Verify the proof.
                                #[cfg(feature = "debug")]
                                self.compress_prover
                                    .machine()
                                    .verify(
                                        &vk,
                                        &zkm_pcs::MachineProof {
                                            shard_proofs: vec![proof.clone()],
                                        },
                                        &mut self.compress_prover.machine().config().challenger(),
                                    )
                                    .unwrap();

                                // Send the proof. Order in proofs_rx is whatever
                                // the prove pool finishes in; the next-layer
                                // worker buckets by `height` so arrival order
                                // does not affect tree-reduce correctness.
                                proofs_tx.lock().unwrap().send((index, height, vk, proof)).unwrap();
                            });
                        } else {
                            break;
                        }
                    }
                });
                prover_handles.push(handle);
            }

            // Spawn a worker that generates inputs for the next layer.
            //
            // The worker buckets incoming proofs by height and emits a
            // ComposeBasefold reduction whenever a height bucket has
            // either accumulated `batch_size` items or its source layer
            // has delivered everything it will. Per-height bucketing
            // means cross-layer arrivals (e.g. a height-1 prove output
            // landing while we're still collecting height-0 items) don't
            // wedge the bucket they don't belong in, which the previous
            // single-`batch` design did at any arity > 2.
            let layer_sizes_worker = layer_sizes.clone();
            let handle = {
                let input_tx = Arc::clone(&input_tx);
                let proofs_rx = Arc::clone(&proofs_rx);
                let span = tracing::debug_span!("generate next layer inputs");
                s.spawn(move || {
                    let _span = span.enter();
                    let mut count = num_first_layer_inputs;
                    type Item = (usize, usize, StarkVerifyingKey<InnerSC>, ShardProof<InnerSC>);
                    // PRESERVE CHAIN ORDER. The compose program's
                    // shard-chain continuity asserts
                    // (compress_basefold.rs: input_{k+1}.start_{pc,
                    // shard} == input_k.next_{pc,shard}) require every batch
                    // to be a CONTIGUOUS, IN-ORDER segment of the proof
                    // chain.  Proofs arrive on `proofs_rx` in prove-pool
                    // completion order, so each height keeps a REORDER
                    // BUFFER (`pending[h]`, keyed by index) plus the layer's
                    // expected index order (`expected_order[h]`): items move
                    // to `ready[h]` only in chain order, and chunks are cut
                    // from `ready`.  (A plain arrival-order `Vec` is
                    // "tolerant" only while the chain asserts are vacuous
                    // DivFs — armed, an out-of-order batch like [s1,s3,s2]
                    // honestly trips the runtime at the continuity assert.)
                    let mut pending: Vec<std::collections::BTreeMap<usize, Item>> =
                        (0..layer_sizes_worker.len()).map(|_| Default::default()).collect();
                    let mut expected_order: Vec<std::collections::VecDeque<usize>> =
                        (0..layer_sizes_worker.len()).map(|_| Default::default()).collect();
                    if !layer_sizes_worker.is_empty() {
                        expected_order[0].extend(0..layer_sizes_worker[0]);
                    }
                    let mut ready: Vec<Vec<Item>> =
                        (0..layer_sizes_worker.len()).map(|_| Vec::new()).collect();
                    let mut received_at_height: Vec<usize> = vec![0usize; layer_sizes_worker.len()];
                    let mut done = false;
                    loop {
                        if expected_height == 0 || done {
                            break;
                        }
                        let received = { proofs_rx.lock().unwrap().recv() };
                        let (index, height, vk, proof) = match received {
                            Ok(v) => v,
                            Err(_) => break,
                        };
                        // Items at `expected_height` are the root produced
                        // by the final reduction; the main thread reads
                        // those off `proofs_rx` directly. Anything beyond
                        // is unexpected — drop it on the floor (drains the
                        // channel so the prove pool can shut down cleanly).
                        if height >= layer_sizes_worker.len() {
                            continue;
                        }
                        pending[height].insert(index, (index, height, vk, proof));
                        received_at_height[height] += 1;

                        // Move the in-order prefix from the reorder buffer
                        // into the ready queue.
                        while let Some(&next_idx) = expected_order[height].front() {
                            if let Some(item) = pending[height].remove(&next_idx) {
                                ready[height].push(item);
                                expected_order[height].pop_front();
                            } else {
                                break;
                            }
                        }

                        let layer_exhausted =
                            received_at_height[height] >= layer_sizes_worker[height];

                        // Drain ready[height] in chunks of up to
                        // `batch_size`. Once the source layer is exhausted
                        // we also flush the final partial chunk.
                        while !ready[height].is_empty()
                            && (ready[height].len() >= batch_size || layer_exhausted)
                        {
                            let take = ready[height].len().min(batch_size);
                            let chunk: Vec<Item> = ready[height].drain(..take).collect();
                            let next_input_height = height + 1;
                            // is_complete iff this emission produces the
                            // root and there's nothing else queued at this
                            // height (covers both N-power-of-arity and
                            // partial-final-chunk cases).
                            let is_complete = next_input_height == expected_height
                                && ready[height].is_empty()
                                && pending[height].is_empty();
                            // Register this emission's index in the next
                            // layer's expected chain order (the reorder
                            // buffer drains in this order).
                            if next_input_height < expected_order.len() {
                                expected_order[next_input_height].push_back(count);
                            }

                            // Basefold is the only path; every input must
                            // carry a basefold side-channel. Missing
                            // side-channel is an upstream bug, not a
                            // fall-through condition.
                            let bf_vks_and_proofs: Vec<_> = chunk
                                .into_iter()
                                .map(|(_, _, vk, proof)| {
                                    let bf = *proof
                                        .basefold_shard_proof
                                        .as_ref()
                                        .expect(
                                            "compress next-layer worker: input proof missing \
                                             basefold side-channel — legacy FRI path removed",
                                        )
                                        .clone();
                                    (vk, bf)
                                })
                                .collect();
                            // Bundle the vk-merkle witness so the compose
                            // program can read vk_root from input rather than
                            // baking it as a compile-time constant.
                            let vks_only: Vec<StarkVerifyingKey<InnerSC>> =
                                bf_vks_and_proofs.iter().map(|(vk, _)| vk.clone()).collect();
                            let vk_merkle_data = self.make_basefold_merkle_proofs(&vks_only);
                            let compose_values = ZKMCompressBasefoldWitnessValues {
                                vks_and_proofs: bf_vks_and_proofs,
                                vk_merkle_data,
                                is_complete,
                            };
                            let input = ZKMCircuitWitness::ComposeBasefold(compose_values);

                            input_tx
                                .lock()
                                .unwrap()
                                .send((count, next_input_height, input))
                                .unwrap();
                            count += 1;

                            if is_complete {
                                done = true;
                                break;
                            }
                        }
                    }
                })
            };

            // Wait for all the provers to finish.
            drop(input_tx);
            drop(record_and_trace_tx);
            drop(proofs_tx);
            for handle in prover_handles {
                handle.join().unwrap();
            }
            handle.join().unwrap();

            let (_, _, vk, proof) = proofs_rx.lock().unwrap().recv().unwrap();
            (vk, proof)
        });

        Ok(ZKMReduceProof { vk, proof })
    }

    /// Wrap a reduce proof into a STARK proven over a SNARK-friendly field.
    #[instrument(name = "shrink", level = "info", skip_all)]
    pub fn shrink(
        &self,
        reduced_proof: ZKMReduceProof<InnerSC>,
        opts: ZKMProverOpts,
    ) -> Result<ZKMReduceProof<InnerSC>, ZKMRecursionProverError> {
        // Make the compress proof.
        let ZKMReduceProof { vk: compressed_vk, proof: compressed_proof } = reduced_proof;
        let basefold_proof = *compressed_proof
            .basefold_shard_proof
            .clone()
            .expect("shrink: input compressed proof missing basefold side-channel — legacy FRI shrink removed");
        // Bundle vk_merkle_data so verify_wrap_basefold
        // can bind the input VK against the canonical vk_root.
        let vk_merkle_data = self.make_basefold_merkle_proofs(&[compressed_vk.clone()]);
        let input = ZKMWrapBasefoldWitnessValues {
            vks_and_proofs: vec![(compressed_vk, basefold_proof)],
            vk_merkle_data,
        };
        let program = self.shrink_program_basefold(&input);

        let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            program.clone(),
            self.shrink_prover.machine().config().perm.clone(),
        );
        let mut witness_stream = Vec::new();
        Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
        runtime.witness_stream = witness_stream.into();
        runtime.run().map_err(|e| ZKMRecursionProverError::RuntimeError(e.to_string()))?;
        runtime.print_stats();
        tracing::debug!("Shrink basefold program executed successfully");

        let (shrink_pk, shrink_vk) = tracing::debug_span!("setup shrink basefold")
            .in_scope(|| self.shrink_prover.setup(&program));
        let mut challenger = self.shrink_prover.machine().config().challenger();

        // Capture the execution record before it is moved into `prove`
        // so the BaseFold side-channel attach below (GPU host-fallback
        // path) can re-run generate_traces + commit on a fresh clone.
        let rec = runtime.record;
        let mut compress_proof = self
            .shrink_prover
            .prove(&shrink_pk, vec![rec.clone()], &mut challenger, opts.recursion_opts)
            .unwrap();
        let mut proof = compress_proof.shard_proofs.pop().unwrap();

        // ── BaseFold side-channel attach (GPU shrink) ──────────────────
        //
        // Byte-exact no-op on the CPU prover (`CpuProver::open` already
        // populated `basefold_shard_proof` inline via
        // `prove_shard_with_data_boxed`); a `StarkGpuProver` OVERRIDES
        // `attach_shard_basefold_side_channel` and drives the device-native
        // BaseFold producer over its own in-crate `DeviceShardTraces`
        // (its GPU `open()` returns `basefold_shard_proof: None`, and
        // `wrap_bn254` `.expect()`s that side channel).  `fn shrink` stays
        // backend-agnostic — no device-shaped provider on the host prover
        // surface.
        self.shrink_prover.attach_shard_basefold_side_channel(
            &mut proof,
            &shrink_pk,
            &rec,
            &opts.recursion_opts,
        );

        Ok(ZKMReduceProof { vk: shrink_vk, proof })
    }

    /// Wrap a reduce proof into a STARK proven over a SNARK-friendly field.
    #[instrument(name = "wrap_bn254", level = "info", skip_all)]
    pub fn wrap_bn254(
        &self,
        compressed_proof: ZKMReduceProof<InnerSC>,
        opts: ZKMProverOpts,
    ) -> Result<ZKMReduceProof<OuterSC>, ZKMRecursionProverError> {
        // BaseFold-over-BN254 wrap port: the wrap STARK (CpuProver<OuterSC>)
        // proves + host-verifies over OuterValMmcs/OuterChallenger. The outer
        // jagged BaseFold open/verify paths are static generic calls; the
        // PREPROCESSED-commit is resolved statically via
        // `KoalaBearPoseidon2Outer::prep_commit`.
        let ZKMReduceProof { vk: compressed_vk, proof: compressed_proof } = compressed_proof;
        let basefold_proof = *compressed_proof
            .basefold_shard_proof
            .clone()
            .expect("wrap_bn254: input shrink proof missing basefold side-channel — legacy FRI wrap removed");
        // Bundle vk_merkle_data so verify_wrap_basefold
        // can bind the input VK against the canonical vk_root.
        let vk_merkle_data = self.make_basefold_merkle_proofs(&[compressed_vk.clone()]);
        let input = ZKMWrapBasefoldWitnessValues {
            vks_and_proofs: vec![(compressed_vk, basefold_proof)],
            vk_merkle_data,
        };
        let program = self.wrap_bn254_program_basefold(&input);

        let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            program.clone(),
            self.shrink_prover.machine().config().perm.clone(),
        );
        let mut witness_stream = Vec::new();
        Witnessable::<WrapConfig>::write(&input, &mut witness_stream);
        runtime.witness_stream = witness_stream.into();
        runtime.run().map_err(|e| ZKMRecursionProverError::RuntimeError(e.to_string()))?;
        runtime.print_stats();
        tracing::debug!("wrap_bn254 basefold program executed successfully");

        let (wrap_pk, wrap_vk) = tracing::debug_span!("setup wrap_bn254 basefold")
            .in_scope(|| self.wrap_prover.setup(&program));
        if self.wrap_vk.set(wrap_vk.clone()).is_ok() {
            tracing::debug!("wrap verifier key set (basefold)");
        }

        let mut wrap_challenger = self.wrap_prover.machine().config().challenger();
        let time = std::time::Instant::now();
        let mut wrap_proof = self
            .wrap_prover
            .prove(&wrap_pk, vec![runtime.record], &mut wrap_challenger, opts.recursion_opts)
            .unwrap();
        let elapsed = time.elapsed();
        tracing::debug!("wrap_bn254 basefold proving time: {:?}", elapsed);
        let mut wrap_challenger = self.wrap_prover.machine().config().challenger();
        self.wrap_prover.machine().verify(&wrap_vk, &wrap_proof, &mut wrap_challenger).unwrap();
        tracing::info!("wrapping (basefold) successful");

        Ok(ZKMReduceProof { vk: wrap_vk, proof: wrap_proof.shard_proofs.pop().unwrap() })
    }

    /// Wrap the STARK proven over a SNARK-friendly field into a PLONK proof.
    #[instrument(name = "wrap_plonk_bn254", level = "info", skip_all)]
    pub fn wrap_plonk_bn254(
        &self,
        proof: ZKMReduceProof<OuterSC>,
        build_dir: &Path,
    ) -> PlonkBn254Proof {
        // Mirror `build_constraints_and_witness` (build.rs): the gnark wrap circuit
        // verifies the BaseFold shard proof, so the witness MUST be built from the
        // wrap-basefold witness type — any other layout emits a flat witness
        // incompatible with the circuit (e.g. 523-flat vs the 15208-flat circuit).
        let basefold_proof = *proof.proof.basefold_shard_proof.clone().expect(
            "wrap_plonk_bn254: wrap proof missing basefold_shard_proof \
                 (the outer ring must be a BaseFold config)",
        );
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

        let prover = PlonkBn254Prover::new();
        let proof = prover.prove(witness, build_dir.to_path_buf());

        // Verify the proof.
        prover
            .verify(
                &proof,
                &vkey_hash.as_canonical_biguint(),
                &committed_values_digest.as_canonical_biguint(),
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
        // Mirror `build_constraints_and_witness` (build.rs): the gnark wrap circuit
        // verifies the BaseFold shard proof, so the witness MUST be built from the
        // wrap-basefold witness type — any other layout emits a flat witness
        // incompatible with the circuit (e.g. 523-flat vs the 15208-flat circuit).
        let basefold_proof = *proof.proof.basefold_shard_proof.clone().expect(
            "wrap_groth16_bn254: wrap proof missing basefold_shard_proof \
                 (the outer ring must be a BaseFold config)",
        );
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

        let prover = Groth16Bn254Prover::new();
        let proof = prover.prove(witness, build_dir.to_path_buf());

        // Verify the proof.
        prover
            .verify(
                &proof,
                &vkey_hash.as_canonical_biguint(),
                &committed_values_digest.as_canonical_biguint(),
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
        // Mirror `build_constraints_and_witness` (build.rs): the gnark wrap circuit
        // verifies the BaseFold shard proof, so the witness MUST be built from the
        // wrap-basefold witness type.
        let basefold_proof = *proof.proof.basefold_shard_proof.clone().expect(
            "wrap_dvsnark_bn254: wrap proof missing basefold_shard_proof \
                 (the outer ring must be a BaseFold config)",
        );
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

        let prover = DvSnarkBn254Prover::new();
        prover.prove(witness, build_dir.to_path_buf(), store_dir.to_path_buf())
    }

    /// Accumulate deferred proofs into a single digest.
    pub fn hash_deferred_proofs(
        prev_digest: [Val<CoreSC>; DIGEST_SIZE],
        deferred_proofs: &[ZKMReduceProof<InnerSC>],
    ) -> [Val<CoreSC>; 8] {
        let mut digest = prev_digest;
        for proof in deferred_proofs.iter() {
            let pv: &RecursionPublicValues<Val<CoreSC>> =
                proof.proof.public_values.as_slice().borrow();
            let committed_values_digest = words_to_bytes(&pv.committed_value_digest);
            digest = hash_deferred_proof(
                &digest,
                &pv.zkm_vk_digest,
                &committed_values_digest.try_into().unwrap(),
            );
        }
        digest
    }

    /// Build a merkle witness for a slice of VKs.
    /// Used by basefold compose/wrap/deferred to bundle vk_merkle_data
    /// into the witness that the recursion program reads.
    pub fn make_basefold_merkle_proofs(
        &self,
        vks: &[StarkVerifyingKey<InnerSC>],
    ) -> ZKMMerkleProofWitnessValues<InnerSC> {
        let num_vks = self.recursion_vk_map.len();
        let vk_indices: Vec<usize> = if self.vk_verification {
            vks.iter()
                .map(|vk| {
                    let vk_digest = vk.hash_koalabear();
                    *self.recursion_vk_map.get(&vk_digest).unwrap_or_else(|| {
                        panic!(
                            "vk not allowed: {:?} (map_size={})",
                            vk_digest.map(|x| {
                                use p3_field::PrimeField32;
                                x.as_canonical_u32()
                            }),
                            self.recursion_vk_map.len()
                        )
                    })
                })
                .collect()
        } else {
            vks.iter()
                .map(|vk| {
                    let vk_digest = vk.hash_koalabear();
                    (vk_digest[0].as_canonical_u32() as usize) % num_vks
                })
                .collect()
        };

        // VK-binding soundness: the witnessed `value` MUST be the ACTUAL
        // leaf at the opened index — the in-circuit `merkle_tree::verify`
        // walks the path from `value` to the root UNCONDITIONALLY (only the
        // value==vk_digest binding is gated on vk_verification), and a
        // fabricated leaf can never re-derive the real root.
        // `MerkleTree::open`'s (value, proof) is returned verbatim; under
        // vk_verification=true the leaf IS the vk digest.
        let (values, proofs): (Vec<_>, Vec<_>) = vk_indices
            .iter()
            .map(|index| MerkleTree::open(&self.recursion_vk_tree, *index))
            .unzip();

        ZKMMerkleProofWitnessValues {
            root: self.recursion_vk_root,
            values,
            vk_merkle_proofs: proofs,
        }
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
pub mod tests {
    use std::{
        collections::BTreeSet,
        fs::File,
        io::{Read, Write},
    };

    use super::*;

    use crate::build::try_build_plonk_bn254_artifacts_dev;
    use anyhow::Result;
    use build::{build_constraints_and_witness, try_build_groth16_bn254_artifacts_dev};
    use p3_field::PrimeField32;

    use zkm_core_machine::shape::CoreShapeConfig;
    use zkm_recursion_circuit::machine::ZKMRecursionShape;
    use zkm_recursion_core::air::RecursionPublicValues;

    #[cfg(test)]
    use serial_test::serial;
    use utils::zkm_vkey_digest_koalabear;
    #[cfg(test)]
    use zkm_core_machine::utils::setup_logger;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Test {
        Core,
        Compress,
        Shrink,
        Wrap,
        CircuitTest,
        All,
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

    /// The COMPOSE program-cache key
    /// (`ZKMCompressBasefoldWitnessValues::shape_key`) must satisfy exactly one
    /// invariant — **equal `shape_key` implies a byte-identical compose
    /// program** — because `compose_program_basefold` hands back the cached
    /// program on a key hit.  This test pins both directions of that
    /// invariant.
    ///
    ///   * Height bands do NOT split the key: the compose program is
    ///     height-agnostic — (1) the recursion-layer AREA PIN
    ///     (`RECURSION_LOG_TRACE_AREA` = 27) fixes every child bundle's
    ///     `log_dense_size` for any child whose natural area is under the
    ///     floor, so all bands commit at L=27 with identical stripe/round
    ///     counts; and (2) `chip_height_bits_from_opened_degrees`
    ///     DERIVES per-chip heights
    ///     from witnessed values instead of baking `builder.constant()`s.
    ///     MEASURED at bands 3/8/12/16: one shape_key, one 173,774,597-byte
    ///     program, byte-identical.
    ///
    ///   * `log_dense_size` MUST split the key: the area
    ///     pin is a FLOOR (`max(natural, 27)`), not a clamp, so a recursion
    ///     child
    ///     whose NATURAL jagged area exceeds 2^27 carries L > 27 (the
    ///     soundness compose band used by tendermint and goat lands at natural
    ///     **L=29**; the FIX-off maxima at **L=31**), and
    ///     L=27/28/29 build DIFFERENT programs
    ///     (measured 173.8 MB / 178.0 MB /
    ///     185.3 MB), so a key that collided across L would serve the wrong
    ///     cached program.
    #[test]
    #[serial]
    fn compose_program_cache_key_implies_identical_program() {
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::shape::OrderedShape;
        use zkm_recursion_circuit::machine::{
            ZKMCompressBasefoldWitnessValues, ZKMCompressShape, ZKMCompressWithVkeyShape,
            ZKMMerkleProofWitnessValues,
        };

        let prover = ZKMProver::<DefaultProverComponents>::new();
        let compress_machine = prover.compress_prover.machine();

        let chip_names: Vec<String> = compress_machine
            .chips()
            .iter()
            .map(|c| <_ as MachineAir<KoalaBear>>::name(c))
            .collect();

        let arity = 4usize;
        // Deliberately the UNCACHED builder: routing through
        // `compose_program_basefold` would satisfy the byte-equality assertion
        // from the cache itself rather than from the compiler.
        let prog_bytes = |w: &ZKMCompressBasefoldWitnessValues<InnerSC>| -> Vec<u8> {
            bincode::serialize(&*prover.build_compose_program_basefold_uncached(w))
                .expect("serialize compose program")
        };

        // ── (a) SAFE COLLISION: different per-child height bands ───────────
        // Both bands sit under the area-pin floor, so both children commit at
        // L=27.  Equal key AND equal program bytes — the invariant holding.
        let shape_at_band = |log_h: usize| -> ZKMCompressWithVkeyShape {
            let proof_shape = || {
                OrderedShape::from_log2_heights(
                    &chip_names
                        .iter()
                        .map(|n: &String| (n.clone(), log_h))
                        .collect::<Vec<(String, usize)>>(),
                )
            };
            let compress_shape =
                ZKMCompressShape::from((0..arity).map(|_| proof_shape()).collect::<Vec<_>>());
            ZKMCompressWithVkeyShape { compress_shape, merkle_tree_height: VK_MERKLE_TREE_HEIGHT }
        };

        let witness_low = ZKMCompressBasefoldWitnessValues::<InnerSC>::dummy::<
            CompressAir<KoalaBear>,
        >(compress_machine, &shape_at_band(3));
        let witness_high = ZKMCompressBasefoldWitnessValues::<InnerSC>::dummy::<
            CompressAir<KoalaBear>,
        >(compress_machine, &shape_at_band(8));

        let sk_low = witness_low.shape_key();
        let sk_high = witness_high.shape_key();
        assert_eq!(
            sk_low, sk_high,
            "[STEP-2] expected shape_key to be band-INDEPENDENT (both bands sit \
             under the RECURSION_LOG_TRACE_AREA floor, so both commit at L=27)",
        );
        let bytes_low = prog_bytes(&witness_low);
        let bytes_high = prog_bytes(&witness_high);
        assert_eq!(
            bytes_low.len(),
            bytes_high.len(),
            "[STEP-2] CACHE-KEY UNSOUND: equal shape_key ({sk_low:#018x}) but \
             different compose program LENGTH across bands — the compose \
             program stopped being height-agnostic; extend shape_key to cover \
             whichever field diverged",
        );
        assert!(
            bytes_low == bytes_high,
            "[STEP-2] CACHE-KEY UNSOUND: equal shape_key ({sk_low:#018x}) and \
             equal length but different compose program BYTES across bands",
        );

        // ── (b) THE REGRESSION: children whose bundle L differs ────────────
        // `ZKMCompressBasefoldWitnessValues::dummy` hardcodes the production
        // pin, so build the witness directly with an explicit area pin — which
        // is exactly what a real child with natural area > 2^27 produces.
        let proof_shape = OrderedShape::from_log2_heights(
            &chip_names
                .iter()
                .map(|n: &String| (n.clone(), 8usize))
                .collect::<Vec<(String, usize)>>(),
        );
        let at_pin = |pin: usize| -> ZKMCompressBasefoldWitnessValues<InnerSC> {
            let vks_and_proofs: Vec<_> = (0..arity)
                .map(|_| {
                    zkm_recursion_circuit::stark::dummy_basefold_vk_and_shard_proof::<
                        CompressAir<KoalaBear>,
                    >(compress_machine, &proof_shape, Some(pin))
                })
                .collect();
            let vk_merkle_data =
                ZKMMerkleProofWitnessValues::dummy(vks_and_proofs.len(), VK_MERKLE_TREE_HEIGHT);
            ZKMCompressBasefoldWitnessValues { vks_and_proofs, vk_merkle_data, is_complete: false }
        };

        let mut seen: std::collections::BTreeMap<u64, (usize, Vec<u8>)> =
            std::collections::BTreeMap::new();
        for pin in [
            zkm_pcs::jagged_pcs::RECURSION_LOG_TRACE_AREA,
            zkm_pcs::jagged_pcs::RECURSION_LOG_TRACE_AREA + 1,
            zkm_pcs::jagged_pcs::RECURSION_LOG_TRACE_AREA + 2,
        ] {
            let w = at_pin(pin);
            let sk = w.shape_key();
            let bytes = prog_bytes(&w);
            if let Some((prev_pin, prev_bytes)) = seen.get(&sk) {
                assert!(
                    *prev_bytes == bytes,
                    "[STEP-2] CACHE-KEY UNSOUND: bundle L={prev_pin} and L={pin} \
                     share shape_key {sk:#018x} but build DIFFERENT compose \
                     programs ({} vs {} bytes).  `compose_program_basefold` \
                     would return the wrong cached program for one of them. \
                     shape_key must hash the evaluation_proof bundle's \
                     log_dense_size and the lengths it drives.",
                    prev_bytes.len(),
                    bytes.len(),
                );
            }
            seen.insert(sk, (pin, bytes));
        }
        assert_eq!(
            seen.len(),
            3,
            "[STEP-2] expected three DISTINCT shape_keys for bundle L=27/28/29 \
             (each builds a differently sized compose program); got {} — the \
             key no longer separates log_dense_size",
            seen.len(),
        );
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
        use crate::shapes::ZKMProofShape;
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::shape::OrderedShape;
        use zkm_recursion_circuit::machine::ZKMCoreBasefoldWitnessValues;

        let prover = ZKMProver::<DefaultProverComponents>::new();
        let machine = prover.core_prover.machine();

        // Deliberately the UNCACHED builder: routing through
        // `recursion_program_basefold` would satisfy the byte-equality
        // assertion from the cache itself rather than from the compiler.
        let prog_bytes = |w: &ZKMCoreBasefoldWitnessValues<InnerSC>| -> Vec<u8> {
            bincode::serialize(&*prover.build_normalize_program_basefold_uncached(w))
                .expect("serialize normalize program")
        };

        // Start from an ENUMERATED normalize shape, which is by construction
        // one `fix_shape` accepts.  Variants only SHRINK a chip, so they stay
        // inside the same band.
        let core_shape_config = CoreShapeConfig::default();
        let recursion_shape_config =
            RecursionShapeConfig::<KoalaBear, CompressAir<KoalaBear>>::default();
        let base_os =
            ZKMProofShape::generate(&core_shape_config, &recursion_shape_config, REDUCE_BATCH_SIZE)
                .find_map(|s| match s {
                    ZKMProofShape::Recursion(batch) => batch.into_iter().next(),
                    _ => None,
                })
                .expect("the enumeration emits normalize shapes");
        let base: Vec<(String, usize)> = base_os.inner.clone();

        let witness_of = |hs: &[(String, usize)]| -> ZKMCoreBasefoldWitnessValues<InnerSC> {
            let os = OrderedShape { inner: hs.to_vec() };
            let shape = ZKMRecursionShape { proof_shapes: vec![os], is_complete: false };
            ZKMCoreBasefoldWitnessValues::dummy(machine, &shape)
        };

        // ── (a) The key must COLLIDE, and every collision must be safe ─────
        // Core shards carry no area pin, so a wide height sweep does split the
        // key on `log_dense_size`.  What the cache needs is the other
        // direction: shapes differing only in a dimension the circuit cannot
        // see must land on ONE key, and that key must imply one program.
        // Shrinking a single chip moves the per-chip heights (and with them
        // the packing offsets) without moving `log_dense_size`.
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

        // ── (b) THE SPLIT THAT MUST HAPPEN: a different chip SET ───────────
        // Dropping a chip changes `column_counts_by_round`, which the verifier
        // BAKES, so the two programs differ and the keys must too.
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

    /// Faithful-dummy diagnostic: verify the
    /// NORMALIZE dummy reproduces the REAL core VK's `vk.hash` structural
    /// region.  The normalize recursion program hashes the verified CORE vk
    /// (`vk_legacy.hash(builder)` at core_basefold.rs:759); that hash reads
    /// ONE `[log_n,2^log_n,shift,g]` block per `chip_information` entry
    /// (= per CORE preprocessed chip).  If the dummy core VK's
    /// `chip_information.len()` differs from the real one, the dummy normalize
    /// program reads a different number of witness slots ⇒ different program
    /// ⇒ different VK ⇒ the enumerated vk_map misses the real normalize VK.
    ///
    /// FINDING this test pins: the CORE machine has EXACTLY 2 preprocessed
    /// chips — `Program` and `Byte` (mips/mod.rs:484 `preprocessed_heights`
    /// returns `[(Program,..),(Byte,1<<16)]`) — INDEPENDENT of which
    /// precompiles a shard uses.  And EVERY enumerated normalize cluster
    /// carries `Program`+`Byte` (enumerate.rs `build_mips_machine_shape`:
    /// every cluster is built atop `preprocessed_chips() = ["Program","Byte"]`).
    /// So the dummy core VK's `chip_information` is ALWAYS the same 2 entries
    /// the real core VK carries — the dummy IS faithful for the `vk.hash`
    /// region.  ⇒ the multi-shard "vk not allowed" gap is NOT a dummy
    /// chip_information/ordering-threading bug; it is an enumeration COVERAGE
    /// gap (a reachable (cluster, arity) shape absent from the merged map).
    #[test]
    #[serial]
    fn normalize_dummy_core_vk_chip_information_is_faithful() {
        use zkm_core_machine::mips::MipsAir;
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::shape::OrderedShape;

        let prover = ZKMProver::<DefaultProverComponents>::new();
        let core_machine = prover.core_prover.machine();

        // (a) The CORE machine's preprocessed chip set is exactly {Program,
        //     Byte} — fixed, precompile-independent.
        let prep_chip_names: BTreeSet<String> = core_machine
            .chips()
            .iter()
            .filter(|c| <_ as MachineAir<KoalaBear>>::preprocessed_width(*c) > 0)
            .map(|c| <_ as MachineAir<KoalaBear>>::name(c))
            .collect();
        let expected: BTreeSet<String> =
            ["Byte".to_string(), "Program".to_string()].into_iter().collect();
        assert_eq!(
            prep_chip_names, expected,
            "[STEP-3] core preprocessed chip set drifted from {{Program, Byte}} \
             — the dummy core VK chip_information assumption (always 2 entries) \
             would no longer hold; re-derive the faithful-dummy argument",
        );

        // (b) Build a normalize dummy core VK from a representative core
        //     recursion shape that carries Program+Byte plus a few main
        //     chips, and assert its chip_information == {Program, Byte}.
        //     This is exactly what `dummy_basefold_vk_and_shard_proof`
        //     produces inside `ZKMCoreBasefoldWitnessValues::dummy`.
        let inner = vec![
            ("Program".to_string(), 18usize),
            ("Byte".to_string(), 16usize),
            ("Cpu".to_string(), 18usize),
            ("AddSub".to_string(), 18usize),
        ];
        let shape = OrderedShape::from_log2_heights(&inner);
        let (dummy_vk, _proof) = zkm_recursion_circuit::stark::dummy_basefold_vk_and_shard_proof::<
            MipsAir<KoalaBear>,
        >(core_machine, &shape, None);
        let dummy_prep: BTreeSet<String> =
            dummy_vk.chip_information.iter().map(|(n, _, _)| n.clone()).collect();
        assert_eq!(
            dummy_prep, expected,
            "[STEP-3] dummy core VK chip_information ({:?}) != real core \
             preprocessed set {{Program, Byte}} — dummy is NOT faithful for \
             the vk.hash region (count mismatch ⇒ divergent normalize program)",
            dummy_prep,
        );
        eprintln!(
            "[STEP-3] PASS — dummy core VK chip_information == {{Program, Byte}} \
             (2 entries), matching the real core VK. Dummy is faithful for the \
             vk.hash region; the multi-shard gap is an enumeration COVERAGE \
             gap, not a dummy chip_information bug.",
        );
    }

    #[test]
    #[serial]
    fn compose_basefold_program_emits_seqblock_parallel() {
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::shape::OrderedShape;
        use zkm_recursion_circuit::machine::basefold_programs::build_compose_basefold_program;
        use zkm_recursion_circuit::machine::{
            PublicValuesOutputDigest, ZKMCompressBasefoldWitnessValues, ZKMCompressShape,
            ZKMCompressWithVkeyShape,
        };

        // Build the production compress machine (RecursionAir, COMPRESS_DEGREE).
        let compress_machine = CompressAir::compress_machine(InnerSC::default());

        // Construct a 4-input compress shape using minimal recursion-chip
        // names. Real chip names from RecursionAir; the exact heights
        // don't matter for the program emission check (the dummy
        // generator silently skips unknown chips, so use only ones that
        // exist in the recursion machine).
        // Use the chip names from the recursion machine itself.
        let chip_names: Vec<String> = compress_machine
            .chips()
            .iter()
            .take(2)
            .map(|c| <_ as MachineAir<KoalaBear>>::name(c))
            .collect();
        let proof_shape = || {
            OrderedShape::from_log2_heights(
                &chip_names
                    .iter()
                    .map(|n: &String| (n.clone(), 3usize))
                    .collect::<Vec<(String, usize)>>(),
            )
        };
        let n_inputs = 4;
        let compress_shape =
            ZKMCompressShape::from((0..n_inputs).map(|_| proof_shape()).collect::<Vec<_>>());
        let merkle_tree_height = 4;
        let shape = ZKMCompressWithVkeyShape { compress_shape, merkle_tree_height };

        // Generate the dummy witness with N inputs.
        let witness = ZKMCompressBasefoldWitnessValues::<InnerSC>::dummy::<CompressAir<KoalaBear>>(
            &compress_machine,
            &shape,
        );
        assert_eq!(
            witness.vks_and_proofs.len(),
            n_inputs,
            "dummy witness should have {n_inputs} input proofs",
        );

        // Build the compose program (this triggers verify_compress_basefold
        // → ir_par_map_collect → DslIr::Parallel → compile_block →
        // SeqBlock::Parallel).
        let max_log_row_count =
            zkm_pcs::shard_level::verifier::BasefoldShardVerifier::production_default()
                .max_log_row_count;
        let program = build_compose_basefold_program::<CompressAir<KoalaBear>>(
            &compress_machine,
            &witness,
            max_log_row_count,
            /* value_assertions = */ false,
            PublicValuesOutputDigest::Reduce,
        );

        // Validate the unlock chain via parallelism_summary.
        let (n_par, n_subs, n_par_instrs) = program.seq_blocks.parallelism_summary();
        assert!(
            n_par >= 1,
            "compose program with {n_inputs} inputs should have ≥1 SeqBlock::Parallel block, got {n_par}",
        );
        assert_eq!(
            n_subs, n_inputs,
            "Parallel block should hold {n_inputs} sub-programs, got {n_subs}",
        );
        assert!(n_par_instrs > 0, "Parallel sub-programs should hold non-zero instructions",);

        let total_instrs = program.instruction_count();
        let pct = 100.0 * n_par_instrs as f64 / total_instrs as f64;
        eprintln!(
            "[compose_emits_parallel] N={} parallel_blocks={} subs={} parallel_instrs={}/{} ({:.1}%)",
            n_inputs, n_par, n_subs, n_par_instrs, total_instrs, pct,
        );

        // Count witness-consuming instructions (Hint) inside the
        // parallel sub-programs. Non-zero ⇒ par_iter dispatch needs
        // witness-slicing to be sound (otherwise sub-walkers race on
        // the shared witness stream).
        use zkm_recursion_core::runtime::{Instruction, SeqBlock};
        let mut hint_in_par: usize = 0;
        fn walk<F>(block: &SeqBlock<Instruction<F>>, hint: &mut usize, inside: bool) {
            match block {
                SeqBlock::Basic(b) => {
                    if inside {
                        for instr in &b.instrs {
                            if let Instruction::Hint(h) = instr {
                                *hint += h.output_addrs_mults.len();
                            }
                        }
                    }
                }
                SeqBlock::Parallel(subs) => {
                    for sub in subs {
                        for sb in &sub.seq_blocks {
                            walk(sb, hint, true);
                        }
                    }
                }
            }
        }
        for b in &program.seq_blocks.seq_blocks {
            walk(b, &mut hint_in_par, false);
        }
        eprintln!("[compose_emits_parallel] hint_in_par={}", hint_in_par,);
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
        let public_values = core_proof.public_values.clone();

        if verify {
            tracing::info!("verify core");
            prover.verify(&core_proof.proof, &vk)?;
        }

        if test_kind == Test::Core {
            return Ok(());
        }

        let core_bytes = bincode::serialize(&core_proof.proof).unwrap();
        tracing::info!("core proof size: {} bytes", core_bytes.len());
        tracing::info!("compress");
        let compress_span = tracing::debug_span!("compress").entered();
        let compressed_proof = prover.compress(&vk, core_proof, vec![], opts)?;
        compress_span.exit();
        let compressed_bytes = bincode::serialize(&compressed_proof).unwrap();
        tracing::info!("compressed proof size: {} bytes", compressed_bytes.len());

        if verify {
            tracing::info!("verify compressed");
            prover.verify_compressed(&compressed_proof, &vk)?;
        }

        if test_kind == Test::Compress {
            return Ok(());
        }

        tracing::info!("shrink");
        let shrink_proof = prover.shrink(compressed_proof, opts)?;
        tracing::info!(
            "shrink proof size: {} bytes",
            bincode::serialize(&shrink_proof).unwrap().len()
        );

        if verify {
            tracing::info!("verify shrink");
            prover.verify_shrink(&shrink_proof, &vk)?;
        }

        if test_kind == Test::Shrink {
            return Ok(());
        }

        tracing::info!("wrap bn254");
        let wrapped_bn254_proof = prover.wrap_bn254(shrink_proof, opts)?;
        let bytes = bincode::serialize(&wrapped_bn254_proof).unwrap();
        tracing::info!("wrap_bn254 proof size: {} bytes", bytes.len());

        // Save the proof.
        let mut file = File::create("proof-with-pis.bin").unwrap();
        file.write_all(bytes.as_slice()).unwrap();

        // Load the proof.
        let mut file = File::open("proof-with-pis.bin").unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();

        let wrapped_bn254_proof = bincode::deserialize(&bytes).unwrap();

        if verify {
            tracing::info!("verify wrap bn254");
            prover.verify_wrap_bn254(&wrapped_bn254_proof, &vk).unwrap();
        }

        if test_kind == Test::Wrap {
            return Ok(());
        }

        tracing::info!("checking vkey hash koalabear");
        let vk_digest_koalabear = zkm_vkey_digest_koalabear(&wrapped_bn254_proof);
        assert_eq!(vk_digest_koalabear, vk.hash_koalabear());

        tracing::info!("checking vkey hash bn254");
        let vk_digest_bn254 = zkm_vkey_digest_bn254(&wrapped_bn254_proof);
        assert_eq!(vk_digest_bn254, vk.hash_bn254());

        tracing::info!("Test the outer circuit");
        let (constraints, witness) =
            build_constraints_and_witness(&wrapped_bn254_proof.vk, &wrapped_bn254_proof.proof);
        // test
        PlonkBn254Prover::test(constraints.clone(), witness.clone());
        tracing::info!("Circuit PLONK test succeeded");
        Groth16Bn254Prover::test(constraints, witness);
        tracing::info!("Circuit GROTH16 test succeeded");

        if test_kind == Test::CircuitTest {
            return Ok(());
        }

        tracing::info!("generate plonk bn254 proof");
        let artifacts_dir = try_build_plonk_bn254_artifacts_dev(
            &wrapped_bn254_proof.vk,
            &wrapped_bn254_proof.proof,
        );
        let plonk_bn254_proof =
            prover.wrap_plonk_bn254(wrapped_bn254_proof.clone(), &artifacts_dir);
        println!("{plonk_bn254_proof:?}");

        prover.verify_plonk_bn254(&plonk_bn254_proof, &vk, &public_values, &artifacts_dir)?;

        tracing::info!("generate groth16 bn254 proof");
        let artifacts_dir = try_build_groth16_bn254_artifacts_dev(
            &wrapped_bn254_proof.vk,
            &wrapped_bn254_proof.proof,
        );
        let groth16_bn254_proof = prover.wrap_groth16_bn254(wrapped_bn254_proof, &artifacts_dir);
        println!("{groth16_bn254_proof:?}");

        if verify {
            prover.verify_groth16_bn254(
                &groth16_bn254_proof,
                &vk,
                &public_values,
                &artifacts_dir,
            )?;
        }

        Ok(())
    }

    pub fn test_e2e_with_deferred_proofs_prover<C: ZKMProverComponents>(
        opts: ZKMProverOpts,
    ) -> Result<()> {
        // Test program which proves the Keccak-256 hash of various inputs.
        let keccak_elf = test_artifacts::KECCAK_SPONGE_ELF;

        // Test program which verifies proofs of a vkey and a list of committed inputs.
        let verify_elf = test_artifacts::VERIFY_PROOF_ELF;

        tracing::info!("initializing prover");
        let prover = ZKMProver::<C>::new();

        tracing::info!("setup keccak elf");
        let (_, keccak_pk_d, keccak_program, keccak_vk) = prover.setup(keccak_elf);

        tracing::info!("setup verify elf");
        let (_, verify_pk_d, verify_program, verify_vk) = prover.setup(verify_elf);

        tracing::info!("prove subproof 1");
        let mut stdin = ZKMStdin::new();
        stdin.write(&1usize);
        stdin.write(&vec![0u8, 0, 0]);
        let deferred_proof_1 = prover.prove_core(
            &keccak_pk_d,
            keccak_program.clone(),
            &stdin,
            opts,
            Default::default(),
        )?;
        let pv_1 = deferred_proof_1.public_values.as_slice().to_vec().clone();

        // Generate a second proof of keccak of various inputs.
        tracing::info!("prove subproof 2");
        let mut stdin = ZKMStdin::new();
        stdin.write(&3usize);
        stdin.write(&vec![0u8, 1, 2]);
        stdin.write(&vec![2, 3, 4]);
        stdin.write(&vec![5, 6, 7]);
        let deferred_proof_2 =
            prover.prove_core(&keccak_pk_d, keccak_program, &stdin, opts, Default::default())?;
        let pv_2 = deferred_proof_2.public_values.as_slice().to_vec().clone();

        // Generate recursive proof of first subproof.
        tracing::info!("compress subproof 1");
        let deferred_reduce_1 = prover.compress(&keccak_vk, deferred_proof_1, vec![], opts)?;

        // Generate recursive proof of second subproof.
        tracing::info!("compress subproof 2");
        let deferred_reduce_2 = prover.compress(&keccak_vk, deferred_proof_2, vec![], opts)?;

        // Run verify program with keccak vkey, subproofs, and their committed values.
        let mut stdin = ZKMStdin::new();
        let vkey_digest = keccak_vk.hash_koalabear();
        let vkey_digest: [u32; 8] = vkey_digest
            .iter()
            .map(|n| n.as_canonical_u32())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        stdin.write(&vkey_digest);
        stdin.write(&vec![pv_1.clone(), pv_2.clone(), pv_2.clone()]);
        stdin.write_proof(deferred_reduce_1.clone(), keccak_vk.vk.clone());
        stdin.write_proof(deferred_reduce_2.clone(), keccak_vk.vk.clone());
        stdin.write_proof(deferred_reduce_2.clone(), keccak_vk.vk.clone());

        tracing::info!("proving verify program (core)");
        let verify_proof =
            prover.prove_core(&verify_pk_d, verify_program, &stdin, opts, Default::default())?;
        // let public_values = verify_proof.public_values.clone();

        // Generate recursive proof of verify program
        tracing::info!("compress verify program");
        let verify_reduce = prover.compress(
            &verify_vk,
            verify_proof,
            vec![deferred_reduce_1, deferred_reduce_2.clone(), deferred_reduce_2],
            opts,
        )?;
        let reduce_pv: &RecursionPublicValues<_> =
            verify_reduce.proof.public_values.as_slice().borrow();
        println!("deferred_hash: {:?}", reduce_pv.deferred_proofs_digest);
        println!("complete: {:?}", reduce_pv.is_complete);

        tracing::info!("verify verify program");
        prover.verify_compressed(&verify_reduce, &verify_vk)?;

        let shrink_proof = prover.shrink(verify_reduce, opts)?;

        tracing::info!("verify shrink");
        prover.verify_shrink(&shrink_proof, &verify_vk)?;

        tracing::info!("wrap bn254");
        let wrapped_bn254_proof = prover.wrap_bn254(shrink_proof, opts)?;

        tracing::info!("verify wrap bn254");
        println!("verify wrap bn254 {:#?}", wrapped_bn254_proof.vk.commit);
        prover.verify_wrap_bn254(&wrapped_bn254_proof, &verify_vk).unwrap();

        Ok(())
    }

    /// Tests an end-to-end workflow of proving a program across the entire proof generation
    /// pipeline.
    ///
    /// Add `FRI_QUERIES`=1 to your environment for faster execution. Should only take a few minutes
    /// on a Mac M2. Note: This test always re-builds the plonk bn254 artifacts, so setting ZKM_DEV
    /// is not needed.
    #[test]
    #[serial]
    #[ignore]
    fn test_e2e() -> Result<()> {
        let elf = test_artifacts::FIBONACCI_ELF;
        setup_logger();
        let opts = ZKMProverOpts::default();
        // TODO(mattstam): We should Test::Plonk here, but this uses the existing
        // docker image which has a different API than the current. So we need to wait until the
        // next release (v1.2.0+), and then switch it back.
        let prover = ZKMProver::<DefaultProverComponents>::new();
        test_e2e_prover::<DefaultProverComponents>(
            &prover,
            elf,
            ZKMStdin::default(),
            opts,
            Test::All,
        )
    }

    /// Tests an end-to-end workflow of proving a program across the entire proof generation
    /// pipeline.
    ///
    /// Add `FRI_QUERIES`=1 to your environment for faster execution. Should only take a few minutes
    /// on a Mac M2. Note: This test always re-builds the plonk bn254 artifacts, so setting ZKM_DEV
    /// is not needed.
    #[test]
    #[serial]
    #[ignore]
    fn test_e2e_hello_world() -> Result<()> {
        let elf = test_artifacts::HELLO_WORLD_ELF;

        setup_logger();
        let opts = ZKMProverOpts::default();
        // TODO(mattstam): We should Test::Plonk here, but this uses the existing
        // docker image which has a different API than the current. So we need to wait until the
        // next release (v1.2.0+), and then switch it back.
        let prover = ZKMProver::<DefaultProverComponents>::new();
        test_e2e_prover::<DefaultProverComponents>(
            &prover,
            elf,
            ZKMStdin::default(),
            opts,
            Test::All,
        )
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
            ZKMStdin::default(),
            opts,
            Test::Compress,
        )
    }

    /// FIX-off robustness: compress a KECCAK (precompile + multi-shard)
    /// workload, exercising non-core chips (KeccakPermute/precompile/memory)
    /// and the multi-shard global cumulative-sum chain through the recursion
    /// `assert_complete` — the path the raw-`main_traces` cumsum fix targets
    /// beyond single-shard pure-core fibonacci.
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

    /// Validates the wrap path end-to-end: compress + shrink +
    /// wrap_bn254 + verify_wrap_bn254 — without the heavy PLONK
    /// artifact build that follows.
    #[test]
    #[serial]
    #[ignore]
    fn test_e2e_wrap_fibonacci() -> Result<()> {
        let elf = test_artifacts::FIBONACCI_ELF;
        setup_logger();
        let opts = ZKMProverOpts::default();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        test_e2e_prover::<DefaultProverComponents>(
            &prover,
            elf,
            ZKMStdin::default(),
            opts,
            Test::Wrap,
        )
    }

    /// Runs through Test::CircuitTest — wrap_bn254 + the in-circuit
    /// PlonkBn254/Groth16Bn254 checks against gnark, but without the
    /// multi-hour SRS regen + full proof artifact build.  Cheap gate
    /// before committing to the full Test::All run.
    #[test]
    #[serial]
    #[ignore]
    fn test_e2e_circuit_fibonacci() -> Result<()> {
        let elf = test_artifacts::FIBONACCI_ELF;
        setup_logger();
        let opts = ZKMProverOpts::default();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        test_e2e_prover::<DefaultProverComponents>(
            &prover,
            elf,
            ZKMStdin::default(),
            opts,
            Test::CircuitTest,
        )
    }

    /// VALUE-INDEPENDENCE GATE: build the gnark outer circuit (R1CS
    /// constraints) from wrap proof A, then SOLVE it with the witness built
    /// from a DIFFERENT fresh wrap proof B.  If the outer lift BAKED proof-A's
    /// q_at_z / jagged-eval / sumcheck as `builder.constant`, B's witness would
    /// trip `assertIsEqual`.  Those values are WITNESS inputs, so the A-shaped
    /// circuit accepts B's witness — the gnark verifier verifies ANY fresh
    /// proof.
    ///
    /// Reuses the same shrink proof for both wraps (the grind `find_any` nonce
    /// re-rolls per wrap, so the two wrap proofs carry DIFFERENT q_at_z /
    /// sumcheck / basefold values at the SAME shape — exactly the fresh-proof
    /// scenario the on-chain verifier faces).
    #[test]
    #[serial]
    #[ignore]
    fn test_outer_value_independence() -> Result<()> {
        setup_logger();
        let elf = test_artifacts::FIBONACCI_ELF;
        let opts = ZKMProverOpts::default();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let (_, pk_d, program, vk) = prover.setup(elf);

        // Two DISTINCT fib inputs → same compress/shrink/wrap SHAPE but
        // different proof VALUES (wrap_bn254 is deterministic given its input,
        // so re-wrapping the same shrink is vacuous — distinct inputs are what
        // gives two genuinely different fresh proofs of the same shape, exactly
        // the on-chain "any fresh proof" scenario).
        let wrap_for = |n: u32| -> Result<crate::ZKMReduceProof<OuterSC>> {
            let mut stdin = ZKMStdin::new();
            stdin.write(&n);
            let core = prover
                .prove_core(&pk_d, program.clone(), &stdin, opts, ZKMContext::default())
                .unwrap();
            let compressed = prover.compress(&vk, core, vec![], opts)?;
            let shrink = prover.shrink(compressed, opts)?;
            Ok(prover.wrap_bn254(shrink, opts)?)
        };

        tracing::info!("[VI] wrap A (fib n=100): core→compress→shrink→wrap");
        let wrap_a = wrap_for(100)?;
        tracing::info!("[VI] wrap B (fib n=200): core→compress→shrink→wrap");
        let wrap_b = wrap_for(200)?;

        // Sanity: the two wrap proofs MUST carry different proof-specific
        // values (else the test is vacuous).  Compare the serialized
        // basefold shard proof bytes.
        let a_bytes =
            bincode::serialize(wrap_a.proof.basefold_shard_proof.as_ref().expect("A bundle"))
                .unwrap();
        let b_bytes =
            bincode::serialize(wrap_b.proof.basefold_shard_proof.as_ref().expect("B bundle"))
                .unwrap();
        tracing::info!(
            "[VI] wrap A bundle {} bytes, wrap B bundle {} bytes, identical={}",
            a_bytes.len(),
            b_bytes.len(),
            a_bytes == b_bytes
        );
        assert_ne!(
            a_bytes, b_bytes,
            "[VI] wrap A and B carry IDENTICAL proof bytes — test would be vacuous \
             (need two distinct fresh proofs of the same shape)"
        );

        tracing::info!("[VI] build outer circuit (R1CS) from proof A");
        let (constraints_a, _witness_a) = build_constraints_and_witness(&wrap_a.vk, &wrap_a.proof);
        tracing::info!("[VI] built {} constraints from A", constraints_a.len());

        tracing::info!("[VI] build circuit + witness from proof B");
        let (constraints_b, witness_b) = build_constraints_and_witness(&wrap_b.vk, &wrap_b.proof);
        tracing::info!("[VI] built {} constraints from B", constraints_b.len());

        // Value-independence signal #1: the R1CS structure (constraint count)
        // is identical for two DIFFERENT proofs of the same shape.  (A baked
        // proof-specific value can change the const-folded instruction count;
        // a witnessed value cannot.)
        assert_eq!(
            constraints_a.len(),
            constraints_b.len(),
            "[VI] constraint counts differ between two same-shape proofs \
             ({} vs {}) — circuit is NOT value-independent (still baking?)",
            constraints_a.len(),
            constraints_b.len(),
        );

        tracing::info!("[VI] SOLVE circuit_A with witness_B (the value-independence gate)");
        // PlonkBn254Prover::test runs gnark's test.IsSolved — it panics if any
        // constraint (e.g. a baked assertIsEqual) is violated.  Passing proves
        // the A-shaped circuit accepts B's fresh witness ⇒ value-independent.
        PlonkBn254Prover::test(constraints_a, witness_b);
        tracing::info!(
            "[VI] PASS — circuit_A solved by witness_B: outer wrap is VALUE-INDEPENDENT"
        );
        Ok(())
    }

    /// Tests an end-to-end workflow of proving a program across the entire proof generation
    /// pipeline in addition to verifying deferred proofs.
    #[test]
    #[serial]
    #[ignore]
    fn test_e2e_with_deferred_proofs() -> Result<()> {
        setup_logger();
        test_e2e_with_deferred_proofs_prover::<DefaultProverComponents>(ZKMProverOpts::default())
    }

    /// Perf-comparison fixture: prove_core only (Test::Core) on
    /// keccak-sponge ELF.  Multi-shard sha-cluster workload — exercises
    /// the basefold side channel population path in `prove_shard_with_data`
    /// without invoking the compose tree.
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
    /// verify (verify_jagged_basefold_inner) on the fib core shape without
    /// the 40-min compress.
    #[test]
    #[serial]
    #[ignore]
    fn test_e2e_core_fib() -> Result<()> {
        let elf = test_artifacts::FIBONACCI_ELF;
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

    /// ARITY-ENUM DECISIVE (fast, single fib core prove): for a real
    /// core shard, the ENUMERATED REPRESENTATIVE arity-N normalize batch
    /// (uniform `vec![enum_shape; N]` at the shard's (chip_set, log_dense)
    /// class — exactly what `ZKMProofShape::generate` emits) must produce
    /// the SAME VK as a REAL arity-N batch of that shard (replicated N
    /// times).  This proves the enumeration covers the multishard
    /// first-compose-layer normalize VKs WITHOUT needing an 18-shard
    /// workload.  Faithful-dummy (59aa8eb3) makes real==dummy per shard,
    /// so the dummy-built representative VK == the real arity-N VK.
    #[test]
    #[serial]
    #[ignore]
    fn arity_enum_representative_reproduces_real_vk() -> Result<()> {
        use crate::shapes::ZKMProofShape;
        use zkm_pcs::shape::OrderedShape;
        setup_logger();
        let elf = test_artifacts::FIBONACCI_ELF;
        let opts = ZKMProverOpts::default();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let context = ZKMContext::default();
        let (_, pk_d, program, vk) = prover.setup(elf);
        let core_proof = prover.prove_core(&pk_d, program, &ZKMStdin::default(), opts, context)?;
        let machine = prover.core_prover.machine();
        // FIX-off-safe: under FIX_CORE_SHAPES=false /
        // FIX_RECURSION_SHAPES=false the prover's `*_shape_config` are `None`,
        // so fall back to local defaults for the ENUMERATION probe (the enum
        // is config-independent for the normalize re-key: it derives classes
        // from the machine, not the bands).  Mirrors
        // `multishard_normalize_arity_faithful`.
        let core_cfg_owned = CoreShapeConfig::<KoalaBear>::default();
        let rec_cfg_owned = RecursionShapeConfig::<KoalaBear, CompressAir<KoalaBear>>::default();
        let core_cfg = &core_cfg_owned;
        let rec_cfg = prover.compress_shape_config.as_ref().unwrap_or(&rec_cfg_owned);

        // Enumerated per-shard normalize shapes (flattened across batches).
        let enum_norm: std::collections::BTreeSet<OrderedShape> =
            ZKMProofShape::generate(core_cfg, rec_cfg, REDUCE_BATCH_SIZE)
                .filter_map(|s| match s {
                    ZKMProofShape::Recursion(b) => Some(b),
                    _ => None,
                })
                .flatten()
                .collect();
        // Cheap log_dense (matches generate()'s dedup key).
        let chips_by_name: std::collections::BTreeMap<String, _> = {
            use zkm_pcs::air::MachineAir;
            machine.chips().iter().map(|c| (<_ as MachineAir<KoalaBear>>::name(c), c)).collect()
        };
        // The class key.  `log_dense` — the power of two ENCLOSING the committed
        // length — is too coarse: the recursion program is built over the
        // committed length itself, whose stacking-BLOCK count sets
        // `num_stripes`.  Two shapes sharing a `log_dense` can commit different
        // block counts and yield different keys, so match on the block count.
        // A proof commits TWO rounds — preprocessed then main — and each round's
        // committed area is its real cells rounded out to whole stacking
        // blocks.  The block counts are what set the per-round stripe multiples
        // and the reduction dimension, so the class key is the PAIR.
        let blocks_of = |os: &OrderedShape| -> (usize, usize) {
            use zkm_pcs::air::MachineAir;
            let log_stack = zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize;
            let cells = |prep: bool| -> usize {
                os.inner
                    .iter()
                    .map(|(name, log_h)| {
                        let w = chips_by_name
                            .get(name)
                            .map(|c| {
                                if prep {
                                    MachineAir::<KoalaBear>::preprocessed_width(*c)
                                } else {
                                    p3_air::BaseAir::<KoalaBear>::width(*c).max(1)
                                }
                            })
                            .unwrap_or(0);
                        w * (1usize << *log_h)
                    })
                    .sum()
            };
            let blocks = |total: usize| -> usize {
                zkm_pcs::jagged::committed_dense_len(total, log_stack) >> log_stack
            };
            (blocks(cells(true)), blocks(cells(false)))
        };

        // Use the first real core shard.
        let real_sp = &core_proof.proof.0[0];
        let real_os = real_sp.shape();
        let mut real_names: Vec<String> = real_os.inner.iter().map(|(n, _)| n.clone()).collect();
        real_names.sort();
        let real_ld = blocks_of(&real_os);

        // Arity 1 ONLY.  Normalize is single-shard by construction —
        // `verify_core_basefold` asserts `shard_proof_tuples.len() == 1` and the
        // enumerator emits no multi-shard normalize shape — so replicating the
        // shard to arity 2..4 builds a program that cannot exist.  Aggregation
        // across shards lives in COMPRESS.
        let real_bf = *real_sp
            .basefold_shard_proof
            .as_ref()
            .expect("real shard carries basefold side channel")
            .clone();

        // FAITHFULNESS CONTROL.  Build the dummy at the real shard's OWN shape
        // and compare its key against the real one.  That separates the two
        // remaining explanations: if they agree the dummy reproduces a real
        // proof and the only gap is that the enumeration never emits this
        // shape; if they differ the dummy builder itself is unfaithful and no
        // enumeration can close it.
        {
            let dummy_at_real = ZKMCoreBasefoldWitnessValues::dummy(
                machine,
                &ZKMRecursionShape { proof_shapes: vec![real_os.clone()], is_complete: true },
            );
            let vk_dummy_at_real = prover
                .compress_prover
                .setup(&prover.recursion_program_basefold(&dummy_at_real))
                .1
                .hash_koalabear()
                .map(|x| x.as_canonical_u32());
            let real_witness_1 = ZKMCoreBasefoldWitnessValues {
                vk: vk.vk.clone(),
                shard_proofs: vec![real_bf.clone()],
                is_complete: true,
                is_first_shard: true,
                vk_root: prover.recursion_vk_root,
            };
            let vk_real_1 = prover
                .compress_prover
                .setup(&prover.recursion_program_basefold(&real_witness_1))
                .1
                .hash_koalabear()
                .map(|x| x.as_canonical_u32());
            eprintln!(
                "[ARITY-REPR] FAITHFUL? dummy_at_real_shape == real: {} \
                 (dummy={vk_dummy_at_real:?} real={vk_real_1:?})",
                vk_dummy_at_real == vk_real_1,
            );
            assert_eq!(
                vk_dummy_at_real, vk_real_1,
                "[ARITY-REPR] the dummy built at the REAL shard's own shape does not reproduce \
                 the real normalize vk — the dummy shard proof is not shape-faithful, and no \
                 enumeration can close that",
            );

            // Field-by-field LENGTH diff.  Only lengths reach the compiled
            // program (every value is witnessed), so a length that differs
            // between the dummy and a real proof of the same shape is exactly
            // what makes the produced key unenumerable.
            use zkm_pcs::shard_level::shard_proof::EvaluationProof as EP;
            use zkm_pcs::InnerChallenge;
            let describe = |bf: &zkm_pcs::shard_level::shard_proof::BasefoldShardProof<
                KoalaBear,
                InnerChallenge,
            >|
             -> Vec<(String, String)> {
                let mut v: Vec<(String, String)> = Vec::new();
                v.push(("public_values".into(), bf.public_values.len().to_string()));
                v.push(("opened_values.chips".into(), bf.opened_values.chips.len().to_string()));
                v.push(("chip_heights".into(), format!("{:?}", bf.chip_heights)));
                v.push(("chip_cumulative_sums".into(), bf.chip_cumulative_sums.len().to_string()));
                v.push((
                    "row_counts".into(),
                    format!("{:?}", bf.row_counts.iter().map(|r| r.len()).collect::<Vec<_>>()),
                ));
                v.push(("padding_column_counts".into(), format!("{:?}", bf.padding_column_counts)));
                v.push((
                    "preprocessed_row_counts".into(),
                    bf.preprocessed_row_counts.len().to_string(),
                ));
                v.push((
                    "padding_row_heights".into(),
                    format!(
                        "{:?}",
                        bf.padding_row_heights.iter().map(|r| r.len()).collect::<Vec<_>>()
                    ),
                ));
                v.push((
                    "opened per-chip (prep,main)".into(),
                    format!(
                        "{:?}",
                        bf.opened_values
                            .chips
                            .iter()
                            .map(
                                |c| (c.preprocessed.local.len(), c.main.local.len(), c.log_degree,)
                            )
                            .collect::<Vec<_>>()
                    ),
                ));
                if let EP::Bundle(b) = &bf.evaluation_proof {
                    v.push(("packing.offsets".into(), b.packing.offsets.len().to_string()));
                    v.push((
                        "packing.column_counts".into(),
                        b.packing.column_counts.len().to_string(),
                    ));
                    v.push(("packing.total_values".into(), b.packing.total_values.to_string()));
                    v.push(("packing.log_dense_size".into(), b.packing.log_dense_size.to_string()));
                    v.push((
                        "packing.round_counts".into(),
                        format!(
                            "{:?}",
                            b.packing.round_counts.iter().map(|r| r.len()).collect::<Vec<_>>()
                        ),
                    ));
                    v.push((
                        "packing.padding_heights".into(),
                        format!(
                            "{:?}",
                            b.packing.padding_heights.iter().map(|r| r.len()).collect::<Vec<_>>()
                        ),
                    ));
                    v.push(("y_per_chip".into(), b.y_per_chip.len().to_string()));
                    v.push((
                        "y_per_chip inner".into(),
                        format!("{:?}", b.y_per_chip.iter().map(|y| y.len()).collect::<Vec<_>>()),
                    ));
                    v.push((
                        "batch_evaluations".into(),
                        format!(
                            "{:?}",
                            b.basefold_proof
                                .batch_evaluations
                                .iter()
                                .map(|r| r.len())
                                .collect::<Vec<_>>()
                        ),
                    ));
                    v.push((
                        "fri_commitments".into(),
                        b.basefold_proof.basefold_proof.fri_commitments.len().to_string(),
                    ));
                    v.push((
                        "univariate_messages".into(),
                        b.basefold_proof.basefold_proof.univariate_messages.len().to_string(),
                    ));
                    v.push((
                        "query_phase_openings".into(),
                        b.basefold_proof
                            .basefold_proof
                            .query_phase_openings_and_proofs
                            .len()
                            .to_string(),
                    ));
                    v.push(("reduction.rounds".into(), format!("{:?}", b.reduction.rounds.len())));
                    v.push((
                        "reduction.eval_point".into(),
                        format!("{:?}", b.reduction.eval_point.len()),
                    ));
                    v.push(("preceding_commits".into(), b.preceding_commits.len().to_string()));
                    v.push(("commit.chip_dims".into(), format!("{:?}", b.commit.chip_dims)));
                    v.push((
                        "commit.log_stacking_height".into(),
                        b.commit.log_stacking_height.to_string(),
                    ));
                    v.push((
                        "component_openings".into(),
                        format!(
                            "rounds={} leaves={:?} vals={:?} path={:?}",
                            b.basefold_proof
                                .basefold_proof
                                .component_polynomials_query_openings_and_proofs
                                .len(),
                            b.basefold_proof
                                .basefold_proof
                                .component_polynomials_query_openings_and_proofs
                                .iter()
                                .map(|m| m.leaves.len())
                                .collect::<Vec<_>>(),
                            b.basefold_proof
                                .basefold_proof
                                .component_polynomials_query_openings_and_proofs
                                .iter()
                                .map(|m| m
                                    .leaves
                                    .first()
                                    .map(|l| l.values.iter().map(|v| v.len()).collect::<Vec<_>>())
                                    .unwrap_or_default())
                                .collect::<Vec<_>>(),
                            b.basefold_proof
                                .basefold_proof
                                .component_polynomials_query_openings_and_proofs
                                .iter()
                                .map(|m| m.leaves.first().map(|l| l.proof.len()).unwrap_or(0))
                                .collect::<Vec<_>>(),
                        ),
                    ));
                    v.push((
                        "query_openings".into(),
                        format!(
                            "rounds={} leaves={:?} paths={:?}",
                            b.basefold_proof.basefold_proof.query_phase_openings_and_proofs.len(),
                            b.basefold_proof
                                .basefold_proof
                                .query_phase_openings_and_proofs
                                .iter()
                                .map(|m| m.leaves.len())
                                .collect::<Vec<_>>(),
                            b.basefold_proof
                                .basefold_proof
                                .query_phase_openings_and_proofs
                                .iter()
                                .map(|m| m.leaves.first().map(|l| l.proof.len()).unwrap_or(0))
                                .collect::<Vec<_>>(),
                        ),
                    ));
                    v.push((
                        "jagged_eval.univariate_polys".into(),
                        b.jagged_eval.partial_sumcheck_proof.univariate_polys.len().to_string(),
                    ));
                    v.push((
                        "extra_{reduction,bf,commit,packing,eval}".into(),
                        format!(
                            "{} {} {} {} {}",
                            b.extra_reduction.len(),
                            b.extra_basefold_proof.len(),
                            b.extra_commit.len(),
                            b.extra_packing.len(),
                            b.extra_jagged_eval.len(),
                        ),
                    ));
                    v.push((
                        "packing.round_counts detail".into(),
                        format!("{:?}", b.packing.round_counts),
                    ));
                    v.push((
                        "packing.padding_heights detail".into(),
                        format!("{:?}", b.packing.padding_heights),
                    ));
                } else {
                    v.push(("evaluation_proof".into(), "NOT A BUNDLE".into()));
                }
                v
            };
            let dr = describe(&dummy_at_real.shard_proofs[0]);
            let rr = describe(&real_bf);
            for ((k, dv), (_, rv)) in dr.iter().zip(rr.iter()) {
                if dv != rv {
                    eprintln!("[DIFF] {k}:\n    dummy = {dv}\n    real  = {rv}");
                }
            }
            eprintln!("[DIFF] fields compared = {}", dr.len());
        }

        // Find the enumerated per-shard shape of the SAME (chip_set, log_dense) class.
        let enum_os = enum_norm
            .iter()
            .find(|e| {
                let mut en: Vec<String> = e.inner.iter().map(|(n, _)| n.clone()).collect();
                en.sort();
                en == real_names && blocks_of(e) == real_ld
            })
            .cloned();
        let enum_os = match enum_os {
            Some(e) => e,
            None => {
                panic!(
                    "[ARITY-REPR] real shard (chip_set, blocks={real_ld:?}) class NOT enumerated \
                     — enumeration gap"
                );
            }
        };
        eprintln!(
            "[ARITY-REPR] real_blocks={real_ld:?} real_chips={} enum_blocks={:?} enum_matched=true",
            real_names.len(),
            blocks_of(&enum_os),
        );
        // The class matched on (chip_set, log_dense) — but the vk is a function
        // of the PER-CHIP heights, so print both height vectors and the chips
        // where they disagree.  That difference is the whole reason a produced
        // key can fall outside the enumeration.
        {
            let r: std::collections::BTreeMap<&String, &usize> =
                real_os.inner.iter().map(|(n, h)| (n, h)).collect();
            let e: std::collections::BTreeMap<&String, &usize> =
                enum_os.inner.iter().map(|(n, h)| (n, h)).collect();
            eprintln!("[ARITY-REPR] real heights = {r:?}");
            eprintln!("[ARITY-REPR] enum heights = {e:?}");
            let diffs: Vec<String> = r
                .iter()
                .filter_map(|(n, h)| {
                    let eh = e.get(*n).copied();
                    (eh != Some(*h)).then(|| format!("{n}: real={h} enum={eh:?}"))
                })
                .collect();
            eprintln!("[ARITY-REPR] per-chip height MISMATCHES ({}): {diffs:?}", diffs.len());
        }

        for arity in 1..=1 {
            // REAL arity-N witness: replicate the real shard's bundle N times
            // (a real arity-N batch of identical shards).
            let real_witness = ZKMCoreBasefoldWitnessValues {
                vk: vk.vk.clone(),
                shard_proofs: vec![real_bf.clone(); arity],
                is_complete: true,
                is_first_shard: true,
                vk_root: prover.recursion_vk_root,
            };
            let prog_real = prover.recursion_program_basefold(&real_witness);
            let vk_real = prover.compress_prover.setup(&prog_real).1.hash_koalabear();

            // ENUMERATED REPRESENTATIVE: uniform dummy batch at the enum class.
            let enum_shape =
                ZKMRecursionShape { proof_shapes: vec![enum_os.clone(); arity], is_complete: true };
            let enum_dummy = ZKMCoreBasefoldWitnessValues::dummy(machine, &enum_shape);
            let prog_enum = prover.recursion_program_basefold(&enum_dummy);
            let vk_enum = prover.compress_prover.setup(&prog_enum).1.hash_koalabear();

            let eq = vk_real == vk_enum;
            eprintln!(
                "[ARITY-REPR] arity={arity}: enum_repr_reproduces_real={eq} \
                 vk_real={:?} vk_enum={:?}",
                vk_real.map(|x| {
                    use p3_field::PrimeField32;
                    x.as_canonical_u32()
                }),
                vk_enum.map(|x| {
                    use p3_field::PrimeField32;
                    x.as_canonical_u32()
                }),
            );
            assert!(
                eq,
                "[ARITY-REPR] arity={arity}: the enumerated representative normalize VK does NOT \
                 reproduce the real arity-{arity} normalize VK — the arity enumeration is wrong \
                 for this class (the failure mode: wrong-but-different enumerated VK)."
            );
        }
        Ok(())
    }

    /// What does the allowed-vk Merkle tree's HEIGHT cost the recursion
    /// programs?  Every compose / deferred / shrink program verifies a vk
    /// membership path in-circuit, so its length is `VK_MERKLE_TREE_HEIGHT`
    /// Poseidon2 compressions plus the selects around them, per child.  This
    /// reports the compiled instruction count so the cost of a height change is
    /// a measured number rather than an argument.  Deterministic — no wall
    /// clock, so it is immune to box contention.
    #[test]
    #[serial]
    #[ignore]
    fn compose_program_size_probe() {
        use zkm_pcs::shape::OrderedShape;
        use zkm_recursion_circuit::machine::{ZKMCompressShape, ZKMCompressWithVkeyShape};
        setup_logger();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let compress_machine = prover.compress_prover.machine();
        let child: Vec<(String, usize)> = vec![
            ("BaseAlu".into(), 18),
            ("ExtAlu".into(), 18),
            ("MemoryConst".into(), 17),
            ("MemoryVar".into(), 18),
            ("Poseidon2WideDeg3".into(), 18),
            ("PublicValues".into(), 4),
            ("Select".into(), 18),
        ];
        let os = OrderedShape::from_log2_heights(&child);
        for arity in [1usize, REDUCE_BATCH_SIZE] {
            let with_vkey = ZKMCompressWithVkeyShape {
                compress_shape: ZKMCompressShape::from(vec![os.clone(); arity]),
                merkle_tree_height: VK_MERKLE_TREE_HEIGHT,
            };
            let d = ZKMCompressBasefoldWitnessValues::dummy::<CompressAir<KoalaBear>>(
                compress_machine,
                &with_vkey,
            );
            let p = prover.compose_program_basefold(&d);
            eprintln!(
                "[PROGSIZE] merkle_height={} arity={arity} compose_instructions={}",
                VK_MERKLE_TREE_HEIGHT,
                p.instruction_count(),
            );
        }
    }

    /// How many keys does the enumeration emit, and does it fit the vk merkle
    /// tree's FIXED capacity?  The tree height is baked into every enumerated
    /// recursion program, so an over-large map is not a tuning problem — it
    /// does not fit at all.
    ///
    /// Runs by default (~6 s): each recursion band adds exactly six shapes to
    /// the enumeration, and `fix_shape` scores bands by cost rather than list
    /// order, so bands are meant to be added freely — this is the only thing
    /// standing between that and an enumeration too large to build.
    #[test]
    #[serial]
    fn enumeration_size_probe() {
        use crate::shapes::ZKMProofShape;
        use zkm_core_machine::shape::CoreShapeConfig;
        setup_logger();
        let core_cfg = CoreShapeConfig::<KoalaBear>::default();
        let rec_cfg = RecursionShapeConfig::<KoalaBear, CompressAir<KoalaBear>>::default();
        let all: Vec<ZKMProofShape> =
            ZKMProofShape::generate(&core_cfg, &rec_cfg, REDUCE_BATCH_SIZE).collect();
        let normalize = all.iter().filter(|s| matches!(s, ZKMProofShape::Recursion(_))).count();
        eprintln!(
            "[ENUMSIZE] total={} normalize={} other={} capacity=2^{}={}",
            all.len(),
            normalize,
            all.len() - normalize,
            VK_MERKLE_TREE_HEIGHT,
            1usize << VK_MERKLE_TREE_HEIGHT,
        );
        assert!(
            all.len() <= (1usize << VK_MERKLE_TREE_HEIGHT),
            "[ENUMSIZE] the enumeration ({}) exceeds the vk merkle capacity {}",
            all.len(),
            1usize << VK_MERKLE_TREE_HEIGHT,
        );
    }

    /// PROBE: which AGGREGATE does the normalize vk key on?
    ///
    /// `normalize_vk_height_sensitivity` shows the vk survives moving one
    /// chip's height but not bumping them all, so it is not the per-chip vector.
    /// The enumeration dedups on `log_dense` — the power of two ENCLOSING the
    /// committed length — while the prover's BaseFold geometry keys on the
    /// committed length itself: `dense_len` in whole stacking blocks, and
    /// `num_stripes = dense_len >> log_stacking`.  Two shapes can share a
    /// `log_dense` and still differ in block count.  This builds pairs that
    /// isolate the two candidates.
    #[test]
    #[serial]
    #[ignore]
    fn normalize_vk_aggregate_key_probe() {
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::shape::OrderedShape;
        setup_logger();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let machine = prover.core_prover.machine();
        let widths: std::collections::BTreeMap<String, usize> = machine
            .chips()
            .iter()
            .map(|c| {
                (
                    <_ as MachineAir<KoalaBear>>::name(c),
                    p3_air::BaseAir::<KoalaBear>::width(c).max(1),
                )
            })
            .collect();
        let log_stack = zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize;
        let stats = |hs: &[(&str, usize)]| -> (usize, usize, usize, usize) {
            let total: usize =
                hs.iter().map(|(n, h)| widths.get(*n).copied().unwrap_or(1) * (1usize << h)).sum();
            let dense = zkm_pcs::jagged::committed_dense_len(total, log_stack);
            let blocks = dense >> log_stack;
            let log_dense =
                if dense == 0 { 0 } else { dense.next_power_of_two().trailing_zeros() as usize };
            (total, dense, blocks, log_dense)
        };
        let vk_of = |hs: &[(&str, usize)]| -> [u32; 8] {
            let os = OrderedShape::from_log2_heights(
                &hs.iter().map(|(n, h)| (n.to_string(), *h)).collect::<Vec<_>>(),
            );
            let shape = ZKMRecursionShape { proof_shapes: vec![os], is_complete: false };
            let d = ZKMCoreBasefoldWitnessValues::dummy(machine, &shape);
            let p = prover.recursion_program_basefold(&d);
            use p3_field::PrimeField32;
            prover.compress_prover.setup(&p).1.hash_koalabear().map(|x| x.as_canonical_u32())
        };
        let report =
            |tag: &str, hs: &[(&str, usize)]| -> ([u32; 8], (usize, usize, usize, usize)) {
                let st = stats(hs);
                let vk = vk_of(hs);
                eprintln!(
                    "[AGGKEY] {tag}: total={} dense_len={} blocks={} log_dense={} vk={vk:?}",
                    st.0, st.1, st.2, st.3,
                );
                (vk, st)
            };

        // The shape a snapped fib core shard lands on.
        let base: &[(&str, usize)] = &[
            ("AddSub", 13),
            ("Bitwise", 12),
            ("Branch", 11),
            ("Byte", 16),
            ("CloClz", 10),
            ("Cpu", 14),
            ("DivRem", 10),
            ("Global", 9),
            ("Jump", 10),
            ("Lt", 12),
            ("LoadNarrow", 10),
            ("LoadWord", 10),
            ("StoreNarrow", 10),
            ("StoreWord", 10),
            ("MemoryUnaligned", 10),
            ("MemoryLocal", 10),
            ("MiscInstrs", 1),
            ("MovCond", 10),
            ("Mul", 10),
            ("Program", 19),
            ("ShiftLeft", 9),
            ("ShiftRight", 9),
            ("SyscallCore", 10),
            ("SyscallInstrs", 10),
        ];
        let (vk_base, st_base) = report("base       ", base);

        // (a) SAME chip set, area moved around but the BLOCK COUNT held.
        let same_blocks: Vec<(&str, usize)> = base
            .iter()
            .map(|(n, h)| match *n {
                "Global" => (*n, 12),
                "Mul" => (*n, 11),
                _ => (*n, *h),
            })
            .collect();
        let (vk_sb, st_sb) = report("same-blocks", &same_blocks);

        // (b) SAME chip set, block count moved but `log_dense` held.
        let same_logdense: Vec<(&str, usize)> =
            base.iter().map(|(n, h)| if *n == "Cpu" { (*n, 15) } else { (*n, *h) }).collect();
        let (vk_sl, st_sl) = report("more-blocks", &same_logdense);

        eprintln!("[AGGKEY] (a) blocks {}=={} -> vk_eq={}", st_base.2, st_sb.2, vk_base == vk_sb,);
        eprintln!(
            "[AGGKEY] (b) log_dense {}=={} but blocks {} vs {} -> vk_eq={}",
            st_base.3,
            st_sl.3,
            st_base.2,
            st_sl.2,
            vk_base == vk_sl,
        );
        // (c) SAME chip set, SAME main-round geometry, but the PREPROCESSED
        // round's height moved (Program is a preprocessed chip, and post-#192
        // the proof commits preprocessed as its own round).
        let prep_moved: Vec<(&str, usize)> =
            base.iter().map(|(n, h)| if *n == "Program" { (*n, 17) } else { (*n, *h) }).collect();
        let (vk_pm, st_pm) = report("prep-moved ", &prep_moved);
        eprintln!(
            "[AGGKEY] (c) Program 19->17: blocks {} vs {} -> vk_eq={}",
            st_base.2,
            st_pm.2,
            vk_base == vk_pm,
        );

        eprintln!(
            "[AGGKEY] CONCLUSION: the vk keys on the committed BLOCK COUNT, not log_dense: {}",
            (vk_base == vk_sb && st_base.2 == st_sb.2)
                && !(vk_base == vk_sl && st_base.2 != st_sl.2),
        );
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
        eprintln!(
            "[SHAPESPACE] all_shapes count={n}{} in {:?} (vk merkle capacity = 2^{} = {})",
            if n >= CAP { " (CAPPED)" } else { "" },
            t.elapsed(),
            VK_MERKLE_TREE_HEIGHT,
            1usize << VK_MERKLE_TREE_HEIGHT,
        );
        eprintln!(
            "[SHAPESPACE] canonical cluster shapes = {}",
            cfg.enumerate_canonical_cluster_shapes().len(),
        );
    }

    /// PROBE: does a RECURSION proving key carry a PREPROCESSED opening round?
    ///
    /// `prove_shard_with_data` builds the preprocessed round from
    /// `preprocessed_commit_data.packing.chip_infos` and emits a single
    /// (main-only) round when that list is empty, while the enumeration's dummy
    /// child derives its own two-round geometry from the machine's chip set.
    /// If the two disagree the hint streams differ and so does the compose vk.
    /// Setup only — no proving.
    #[test]
    #[serial]
    #[ignore]
    fn recursion_pk_preprocessed_round_probe() {
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::shape::OrderedShape;
        use zkm_recursion_circuit::machine::ZKMCoreBasefoldWitnessValues;
        setup_logger();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let core_machine = prover.core_prover.machine();

        // What the compress machine's chips CLAIM: a chip must generate a
        // preprocessed trace iff `preprocessed_width() > 0` (`machine.rs`
        // asserts it), so this is the round the key ought to commit.
        for c in prover.compress_prover.machine().chips().iter() {
            eprintln!(
                "[PREPROBE] compress chip {} preprocessed_width={}",
                <_ as MachineAir<KoalaBear>>::name(c),
                c.preprocessed_width(),
            );
        }

        // A normalize program over one dummy core child.  The child's shape
        // does not affect whether the recursion KEY has a preprocessed round.
        let cluster: Vec<&str> = vec![
            "AddSub",
            "Bitwise",
            "Branch",
            "Byte",
            "CloClz",
            "Cpu",
            "DivRem",
            "Global",
            "Jump",
            "Lt",
            "MemoryGlobalFinalize",
            "MemoryGlobalInit",
            "LoadNarrow",
            "LoadWord",
            "StoreNarrow",
            "StoreWord",
            "MemoryUnaligned",
            "MemoryLocal",
            "MiscInstrs",
            "MovCond",
            "Mul",
            "Program",
            "ShiftLeft",
            "ShiftRight",
            "SyscallCore",
            "SyscallInstrs",
        ];
        let hs: Vec<(String, usize)> = cluster
            .iter()
            .map(|n| ((*n).to_string(), if *n == "Byte" { 16 } else { 18 }))
            .collect();
        let os = OrderedShape::from_log2_heights(&hs);
        let shape = ZKMRecursionShape { proof_shapes: vec![os], is_complete: true };
        let dummy = ZKMCoreBasefoldWitnessValues::dummy(core_machine, &shape);
        let prog = prover.recursion_program_basefold(&dummy);
        let (pk, _vk) = prover.compress_prover.setup(&prog);
        let infos = &pk.preprocessed_data().packing.chip_infos;
        eprintln!(
            "[PREPROBE] normalize pk: prep_chip_infos={} pk.traces={} chip_ordering={}",
            infos.len(),
            pk.traces.len(),
            pk.chip_ordering.len(),
        );
        for i in infos.iter() {
            eprintln!(
                "[PREPROBE]   committed prep chip {} rows={} cols={}",
                i.name, i.row_count, i.column_count,
            );
        }
        eprintln!(
            "[PREPROBE] CONCLUSION: the recursion prove path opens {} round(s)",
            if infos.is_empty() { 1 } else { 2 },
        );

        // ── The preprocessed round's COLUMN COUNT, real vs. enumerated ──
        //
        // The real round's padding is `area - real` split into columns no
        // taller than the row cube, at least one (`prove_jagged_basefold_rounds`).
        // The dummy child the enumeration builds derives the SAME quantity from
        // the child's MAIN band heights, which is a different number whenever a
        // chip's preprocessed height differs from its main height.
        let packing = &pk.preprocessed_data().packing;
        let cube = 1usize << ZKMProver::<DefaultProverComponents>::pcs_max_log_row_count();
        let real_cells = packing.total_values;
        let real_area = packing.dense_len;
        let real_pads = real_area.saturating_sub(real_cells).div_ceil(cube).max(1);
        eprintln!(
            "[PREPROBE] REAL prep round: cells={real_cells} area={real_area} \
             gap={} cube={cube} pad_columns={real_pads}",
            real_area.saturating_sub(real_cells),
        );

        // What the dummy computes for the same child, from the band's MAIN
        // heights (`round_real(true)` in `dummy/basefold_shard_proof.rs`).
        let band = prog.shape.as_ref().map(|sh| sh.clone_into_hash_map()).unwrap_or_default();
        let mut band_sorted: Vec<_> = band.iter().collect();
        band_sorted.sort();
        eprintln!("[PREPROBE] program band (main heights) = {band_sorted:?}");
        let dummy_cells: usize = prover
            .compress_prover
            .machine()
            .chips()
            .iter()
            .map(|c| {
                let name = <_ as MachineAir<KoalaBear>>::name(c);
                let log_h = band.get(&name).copied().unwrap_or(0);
                c.preprocessed_width() * (1usize << log_h)
            })
            .sum();
        let dummy_area = zkm_pcs::jagged::committed_dense_len(
            dummy_cells,
            zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize,
        );
        let dummy_pads = dummy_area.saturating_sub(dummy_cells).div_ceil(cube).max(1);
        eprintln!(
            "[PREPROBE] DUMMY prep round: cells={dummy_cells} area={dummy_area} \
             gap={} pad_columns={dummy_pads}",
            dummy_area.saturating_sub(dummy_cells),
        );
        eprintln!(
            "[PREPROBE] VERDICT: real_pad_columns={real_pads} dummy_pad_columns={dummy_pads} \
             match={}",
            real_pads == dummy_pads,
        );
    }

    /// Compose VK height-sensitivity: does the COMPOSE vk depend on the
    /// child recursion proof's EXACT per-chip heights, or only the chip-SET /
    /// log_dense?  `generate()`'s `compress_child_classes` emits a UNIFORM
    /// child (all recursion chips at one `h`), but a REAL compose child is the
    /// NON-uniform natural recursion shape (BaseAlu:18, MemoryConst:17,
    /// PublicValues:4, ...).  If the compose vk is height-sensitive, the
    /// uniform enum child != the real compose vk (the compose analog of the
    /// normalize CPU-shard gap).  No proving — dummy compose programs only.
    #[test]
    #[serial]
    #[ignore]
    fn compose_vk_height_sensitivity() {
        use zkm_pcs::shape::OrderedShape;
        use zkm_recursion_circuit::machine::{ZKMCompressShape, ZKMCompressWithVkeyShape};
        setup_logger();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let compress_machine = prover.compress_prover.machine();
        let vk_of = |child: &[(&str, usize)], arity: usize| -> [u32; 8] {
            let os = OrderedShape::from_log2_heights(
                &child.iter().map(|(n, h)| (n.to_string(), *h)).collect::<Vec<_>>(),
            );
            let cshape = ZKMCompressShape::from(vec![os; arity]);
            let with_vkey = ZKMCompressWithVkeyShape {
                compress_shape: cshape,
                merkle_tree_height: VK_MERKLE_TREE_HEIGHT,
            };
            let d = ZKMCompressBasefoldWitnessValues::dummy::<CompressAir<KoalaBear>>(
                compress_machine,
                &with_vkey,
            );
            let p = prover.compose_program_basefold(&d);
            use p3_field::PrimeField32;
            prover.compress_prover.setup(&p).1.hash_koalabear().map(|x| x.as_canonical_u32())
        };
        // The REAL natural compose child (captured from a real FIX-off proof).
        let natural: &[(&str, usize)] = &[
            ("BaseAlu", 18),
            ("ExtAlu", 18),
            ("MemoryConst", 17),
            ("MemoryVar", 18),
            ("Poseidon2WideDeg3", 18),
            ("PublicValues", 4),
            ("Select", 18),
        ];
        // A UNIFORM child of the SAME chip-set (what generate() emits): all at 18.
        let uniform18: Vec<(&str, usize)> = natural.iter().map(|(n, _)| (*n, 18usize)).collect();
        for arity in [1usize, 4] {
            let vn = vk_of(natural, arity);
            let vu = vk_of(&uniform18, arity);
            eprintln!(
                "[CSENS] arity={arity} natural_vk={vn:?} uniform18_vk={vu:?} eq={}",
                vn == vu
            );
        }
        eprintln!(
            "[CSENS] CONCLUSION: a UNIFORM compose child {} reproduce the natural compose vk",
            "see eq= above —"
        );
    }

    /// Normalize VK height-sensitivity: does the NORMALIZE vk depend on the
    /// EXACT per-chip canonical heights, or only the (chip-SET[, log_dense])?
    /// No proving — builds dummy normalize programs from hardcoded shapes and
    /// compares VKs.  Decides whether the enum can use a coarse cluster-cap
    /// representative (O(N)) or must reproduce the per-chip clamped heights.
    #[test]
    #[serial]
    #[ignore]
    fn normalize_vk_height_sensitivity() {
        use zkm_pcs::shape::OrderedShape;
        setup_logger();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let machine = prover.core_prover.machine();
        let vk_of = |inner: &[(&str, usize)]| -> [u32; 8] {
            let os = OrderedShape::from_log2_heights(
                &inner.iter().map(|(n, h)| (n.to_string(), *h)).collect::<Vec<_>>(),
            );
            let shape = ZKMRecursionShape { proof_shapes: vec![os], is_complete: false };
            let d = ZKMCoreBasefoldWitnessValues::dummy(machine, &shape);
            let p = prover.recursion_program_basefold(&d);
            use p3_field::PrimeField32;
            prover.compress_prover.setup(&p).1.hash_koalabear().map(|x| x.as_canonical_u32())
        };
        // The REALCANON the fib-1k CPU shard padded to (MiscInstrs=1, clamped).
        let realcanon: &[(&str, usize)] = &[
            ("AddSub", 13),
            ("Bitwise", 12),
            ("Branch", 11),
            ("Byte", 16),
            ("CloClz", 10),
            ("Cpu", 14),
            ("DivRem", 10),
            ("Global", 9),
            ("Jump", 10),
            ("Lt", 12),
            ("LoadNarrow", 10),
            ("LoadWord", 10),
            ("StoreNarrow", 10),
            ("StoreWord", 10),
            ("MemoryUnaligned", 10),
            ("MemoryLocal", 10),
            ("MiscInstrs", 1),
            ("MovCond", 10),
            ("Mul", 10),
            ("Program", 19),
            ("ShiftLeft", 9),
            ("ShiftRight", 9),
            ("SyscallCore", 10),
            ("SyscallInstrs", 10),
        ];
        // Same chip-SET but MiscInstrs bumped 1 -> 10 (the lossy ordered lift).
        let misc10: Vec<(&str, usize)> = realcanon
            .iter()
            .map(|(n, h)| if *n == "MiscInstrs" { (*n, 10) } else { (*n, *h) })
            .collect();
        // Same chip-SET, ALL non-prep core chips bumped to a uniform 14 cap
        // (a coarse cluster-cap representative).
        let allcap: Vec<(&str, usize)> = realcanon
            .iter()
            .map(|(n, h)| match *n {
                "Byte" | "Program" => (*n, *h),
                _ => (*n, 14),
            })
            .collect();
        let v_real = vk_of(realcanon);
        let v_misc10 = vk_of(&misc10);
        let v_allcap = vk_of(&allcap);
        eprintln!("[HSENS] realcanon   vk={v_real:?}");
        eprintln!("[HSENS] misc1->10   vk={v_misc10:?} eq_real={}", v_misc10 == v_real);
        eprintln!("[HSENS] all-core=14 vk={v_allcap:?} eq_real={}", v_allcap == v_real);
        eprintln!(
            "[HSENS] CONCLUSION: normalize vk is {} to per-chip heights",
            if v_misc10 == v_real && v_allcap == v_real {
                "INSENSITIVE (chip-SET only)"
            } else {
                "SENSITIVE (per-chip heights load-bearing)"
            }
        );
    }

    /// VK-root construction validation: the normalize program is
    /// (chip_set, log_dense)-determined, so ANY valid memory-cluster shape at
    /// log_dense=27 must produce fib's vk.  Find a CONSTRUCTIBLE one (area
    /// concentrated in a byte-lookup-free chip so the VK-setup
    /// `Σ byte_lookups·2^log_degree ≤ |F|` holds) that hits each log_dense
    /// band — the recipe generate() will use.
    #[test]
    #[serial]
    #[ignore]
    fn vkroot_site5_construct() {
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::shape::OrderedShape;
        use zkm_pcs::shard_level::shard_proof::EvaluationProof;
        use zkm_recursion_circuit::machine::ZKMCoreBasefoldWitnessValues;

        let fib_vk = [
            1995641422u32,
            1126409227,
            1338345684,
            1611704093,
            650337242,
            439362553,
            2125947076,
            2022707873,
        ];
        // memory cluster = fib's 22 chips
        let cluster: Vec<&str> = vec![
            "AddSub",
            "Bitwise",
            "Branch",
            "Byte",
            "CloClz",
            "Cpu",
            "DivRem",
            "Global",
            "Jump",
            "Lt",
            "MemoryGlobalFinalize",
            "MemoryGlobalInit",
            "LoadNarrow",
            "LoadWord",
            "StoreNarrow",
            "StoreWord",
            "MemoryUnaligned",
            "MemoryLocal",
            "MiscInstrs",
            "MovCond",
            "Mul",
            "Program",
            "ShiftLeft",
            "ShiftRight",
            "SyscallCore",
            "SyscallInstrs",
        ];
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let machine = prover.core_prover.machine();

        // byte-lookup count per cluster chip (0 = safe filler).
        for c in machine.chips().iter() {
            let cname = <_ as MachineAir<KoalaBear>>::name(c);
            if cluster.contains(&cname.as_str()) {
                eprintln!("[SITE5] {cname}: num_sent_byte_lookups={}", c.num_sent_byte_lookups());
            }
        }

        let build = |hs: &[(&str, usize)]| -> ([u32; 8], usize) {
            let os = OrderedShape::from_log2_heights(
                &hs.iter().map(|(n, h)| (n.to_string(), *h)).collect::<Vec<_>>(),
            );
            let shape = ZKMRecursionShape { proof_shapes: vec![os], is_complete: true };
            let dummy = ZKMCoreBasefoldWitnessValues::dummy(machine, &shape);
            let ld = match &dummy.shard_proofs[0].evaluation_proof {
                EvaluationProof::Bundle(bd) => bd.packing.log_dense_size,
                _ => 0,
            };
            let prog = prover.recursion_program_basefold(&dummy);
            let vk = prover
                .compress_prover
                .setup(&prog)
                .1
                .hash_koalabear()
                .map(|x| x.as_canonical_u32());
            (vk, ld)
        };

        // Construct: spread area across the byte-lookup-FREE fillers at a uniform
        // sweep height (each <= 2^22 max chip height); byte-lookup chips pinned
        // minimal (so Σ byte_lookups·2^h stays tiny); Byte pinned at its table
        // height 16.  Sweep the filler height to cover the log_dense range; the
        // one at log_dense=27 must match fib.
        let fillers = [
            "Program",
            "Jump",
            "SyscallInstrs",
            "MemoryGlobalInit",
            "MemoryGlobalFinalize",
            "MemoryLocal",
            "MovCond",
        ];
        for fh in [4usize, 8, 12, 15, 16, 17, 18, 20] {
            let mut hs: Vec<(&str, usize)> = cluster.iter().map(|n| (*n, 1usize)).collect();
            for e in hs.iter_mut() {
                if e.0 == "Byte" {
                    e.1 = 16;
                }
                if fillers.contains(&e.0) {
                    e.1 = fh;
                }
            }
            let (vk, ld) = build(&hs);
            eprintln!("[SITE5] fillers@{fh}: log_dense={ld} vk_eq_fib={}", vk == fib_vk);
        }
    }

    /// VKROOT fix-validation (FAST, no core run): tests the hypothesis that
    /// the normalize program vk depends only on (chip_set, np2(total_values))
    /// — NOT the per-chip height distribution.  Uses fib's exact shape + real
    /// vk captured from `test_vk_equality_normalize_fib`.  If alternate
    /// same-band distributions reproduce vk_real, the coverage fix is sound:
    /// generate() need only emit one shape per (cluster, log_dense band).
    #[test]
    #[serial]
    #[ignore]
    fn vkroot_normalize_vk_equivalence_class() {
        use zkm_pcs::shape::OrderedShape;
        use zkm_pcs::shard_level::shard_proof::EvaluationProof;
        use zkm_recursion_circuit::machine::ZKMCoreBasefoldWitnessValues;

        // fib's exact real core shape (from test_vk_equality_normalize_fib dump).
        let fib: Vec<(&str, usize)> = vec![
            ("AddSub", 16),
            ("Bitwise", 13),
            ("Branch", 13),
            ("Byte", 16),
            ("CloClz", 5),
            ("Cpu", 17),
            ("DivRem", 11),
            ("Global", 18),
            ("Jump", 11),
            ("Lt", 15),
            ("MemoryGlobalFinalize", 17),
            ("MemoryGlobalInit", 17),
            ("LoadNarrow", 15),
            ("LoadWord", 15),
            ("StoreNarrow", 15),
            ("StoreWord", 15),
            ("MemoryUnaligned", 15),
            ("MemoryLocal", 11),
            ("MiscInstrs", 11),
            ("MovCond", 12),
            ("Mul", 13),
            ("Program", 19),
            ("ShiftLeft", 13),
            ("ShiftRight", 11),
            ("SyscallCore", 11),
            ("SyscallInstrs", 11),
        ];
        let vk_real: [u32; 8] = [
            1115632139, 1688068798, 1650214975, 1858294344, 1237422514, 2047442675, 305119098,
            273862066,
        ];

        let prover = ZKMProver::<DefaultProverComponents>::new();
        let machine = prover.core_prover.machine();

        // Build dummy from shape, read total_values/log_dense from its bundle,
        // build the normalize program, setup -> vk (canonical u32).  Also
        // returns the program so we can byte/instruction-diff divergent ones.
        let build = |hs: &[(&str, usize)]| -> (
            [u32; 8],
            usize,
            usize,
            std::sync::Arc<zkm_recursion_core::RecursionProgram<KoalaBear>>,
        ) {
            let os = OrderedShape::from_log2_heights(
                &hs.iter().map(|(n, h)| (n.to_string(), *h)).collect::<Vec<_>>(),
            );
            let shape = ZKMRecursionShape { proof_shapes: vec![os], is_complete: true };
            let dummy = ZKMCoreBasefoldWitnessValues::dummy(machine, &shape);
            let (tv, ld) = match &dummy.shard_proofs[0].evaluation_proof {
                EvaluationProof::Bundle(bd) => (bd.packing.total_values, bd.packing.log_dense_size),
                _ => (0, 0),
            };
            let prog = prover.recursion_program_basefold(&dummy);
            let vk = prover
                .compress_prover
                .setup(&prog)
                .1
                .hash_koalabear()
                .map(|x| x.as_canonical_u32());
            (vk, tv, ld, prog)
        };

        // Candidate distributions (same chip_set), incl. very different ones.
        let mut alts: Vec<(&str, Vec<(&str, usize)>)> = Vec::new();
        alts.push(("fib_itself", fib.clone()));
        {
            let mut a = fib.clone();
            for e in a.iter_mut() {
                if e.0 == "Program" {
                    e.1 = 18;
                }
            }
            alts.push(("program_19to18", a));
        }
        {
            // Aggressive redistribute: flatten the big chips, raise small ones.
            let mut a = fib.clone();
            for e in a.iter_mut() {
                match e.0 {
                    "Global" => e.1 = 16,
                    "MemoryGlobalFinalize" => e.1 = 16,
                    "MemoryGlobalInit" => e.1 = 16,
                    "Cpu" => e.1 = 18,
                    "Mul" => e.1 = 18,
                    "DivRem" => e.1 = 18,
                    _ => {}
                }
            }
            alts.push(("redistribute", a));
        }

        let mut fib_prog = None;
        let mut fib_vk: Option<[u32; 8]> = None;
        for (tag, hs) in &alts {
            let (vk, tv, ld, prog) = build(hs);
            // With chip_height_bits witnessed the program changes, so vk does
            // not match the OLD baked vk_real; the correct success criterion is
            // chip_set-DETERMINISM: every same-chip_set shape (fib + alts) must
            // produce the SAME vk (== fib's vk this run).  vk_eq_real is kept
            // for reference only.
            eprintln!(
                "[EQUIV] {tag}: total_values={tv} log_dense={ld} vk_eq_real={} vk_eq_fib={} vk={vk:?}",
                vk == vk_real,
                fib_vk.map(|f| f == vk).unwrap_or(true),
            );
            if *tag == "fib_itself" {
                fib_prog = Some(prog);
                fib_vk = Some(vk);
                continue;
            }
            // ENUMERABILITY: with the baked height anchors cut (the
            // `row_count_felt == constant(2^log_h)` pin + `row_counts_usize`
            // threading), every same-chip-set shape MUST produce the SAME
            // normalize VK regardless of per-chip heights, i.e. VK =
            // f(chip-set, arity) = f(cluster, arity) ⇒ enumerable.  Enforce it
            // loudly so a future regression that re-bakes a height fails here.
            assert_eq!(
                Some(vk),
                fib_vk,
                "[GATE1] normalize VK for same chip-set differs across heights \
                 (tag={tag}): VK is still program-length-dependent — a baked \
                 height anchor was reintroduced",
            );
            // Localize ANY residual per-chip-height dependence: diff fib's
            // program vs this alt's (same chip_set, different heights).  This
            // should show NO diff (vk == fib's vk).
            if Some(vk) != fib_vk {
                let fp = fib_prog.as_ref().unwrap();
                let rb = bincode::serialize(&**fp).unwrap();
                let db = bincode::serialize(&*prog).unwrap();
                let first_diff = rb.iter().zip(db.iter()).position(|(a, b)| a != b);
                let ri: Vec<_> = fp.iter_instructions().collect();
                let di: Vec<_> = prog.iter_instructions().collect();
                eprintln!(
                    "[EQUIV-DIFF] {tag} vs fib: prog_bytes fib={} alt={} first_byte_diff={:?} | instrs fib={} alt={} (delta={}) total_mem fib={} alt={}",
                    rb.len(), db.len(), first_diff, ri.len(), di.len(),
                    ri.len() as i64 - di.len() as i64, fp.total_memory, prog.total_memory,
                );
                let n = ri.len().min(di.len());
                let mut shown = 0;
                let mut first_idx = None;
                for k in 0..n {
                    if format!("{:?}", ri[k]) != format!("{:?}", di[k]) {
                        if first_idx.is_none() {
                            first_idx = Some(k);
                        }
                        eprintln!("[EQUIV-DIFF] {tag} diff@{k}: fib={:?} | alt={:?}", ri[k], di[k]);
                        shown += 1;
                        if shown >= 8 {
                            break;
                        }
                    }
                }
                // The divergent instrs are const-block Mem-Writes (no
                // trace).  Find the READER of each divergent const address
                // and backtrace IT — names the verifier line that BAKES the
                // height-derived bit.  (ZKM_DEBUG=1 + package debug symbols.)
                let rtr = &fp.traces;
                if let Some(fd) = first_idx {
                    let mut shown_rdr = 0;
                    for k in fd..ri.len() {
                        let s = format!("{:?}", ri[k]);
                        if !(s.contains("kind: Write")
                            && format!("{:?}", di.get(k)) != format!("{:?}", Some(&ri[k])))
                        {
                            continue;
                        }
                        if let Some(addr) = s
                            .split("inner: Address(")
                            .nth(1)
                            .and_then(|t| t.split(')').next())
                            .and_then(|t| t.parse::<usize>().ok())
                        {
                            let needle = format!("Address({addr})");
                            for j in (k + 1)..ri.len() {
                                let rs = format!("{:?}", ri[j]);
                                if rs.contains(&needle) && !rs.contains("kind: Write") {
                                    let frame = rtr
                                        .get(j)
                                        .and_then(|t| t.as_ref())
                                        .map(|bt| {
                                            let mut b = bt.clone();
                                            b.resolve();
                                            let fs = format!("{:?}", b);
                                            fs.lines()
                                                .find(|l| {
                                                    l.contains("recursion/circuit/src")
                                                        || l.contains("stark/src")
                                                })
                                                .unwrap_or("(no circuit frame)")
                                                .trim()
                                                .to_string()
                                        })
                                        .unwrap_or_else(|| "(reader no trace)".to_string());
                                    eprintln!("[EQUIV-RDR] {tag} const@{addr} (write instr{k}) read by instr{j}: {frame} | {:?}", ri[j]);
                                    // Reader has no trace; scan a window around it
                                    // for the nearest traced instr → names the phase.
                                    let lo = j.saturating_sub(60);
                                    let hi = (j + 60).min(ri.len());
                                    for w in lo..hi {
                                        if let Some(Some(bt)) = rtr.get(w) {
                                            let mut b = bt.clone();
                                            b.resolve();
                                            let fs = format!("{:?}", b);
                                            if let Some(line) = fs.lines().find(|l| {
                                                (l.contains("recursion/circuit/src")
                                                    || l.contains("stark/src"))
                                                    && !l.contains("shard_proof_variable_lift")
                                            }) {
                                                eprintln!("[EQUIV-NEAR] {tag} @{j} nearest-traced@{w}: {}", line.trim());
                                                break;
                                            }
                                        }
                                    }
                                    break;
                                }
                            }
                            shown_rdr += 1;
                            if shown_rdr >= 6 {
                                break;
                            }
                        }
                    }
                }
                eprintln!("[EQUIV-DIFF] {tag}: traces.len()={} (0 = ZKM_DEBUG unset)", rtr.len());
            }
        }
    }

    // SHA2_RUST_ELF requires stdin input (ZKMStdin::default() → "insufficient
    // input data" syscall error).  Removed; fib + keccak already
    // characterize the per-cycle vs per-MLE-size cost.  See
    // `docs/d2_phased_plan.md` Phase 1.5.

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

    /// MEMBERSHIP BASELINE.
    ///
    /// Records the DETERMINISTIC, no-prove baselines for the VK-identity
    /// work:
    ///
    ///   * the CURRENT height-specific recursion `vk_map` size (the
    ///     baseline to collapse once `VK = f(chip-SET)` instead of
    ///     `f(chip-SET, per-chip-heights)`);
    ///   * the enumerated per-shard NORMALIZE shape count and the
    ///     enumerated COMPOSE (Compress) shape count per arity — the
    ///     height-keyed enumeration cardinality;
    ///   * a pointer to the live enum-vs-real VK comparison tests
    ///     (`multishard_normalize_arity_faithful` /
    ///     `arity_enum_representative_reproduces_real_vk`) whose current
    ///     baseline is `dummy_faithful=true` (the dummy built at the
    ///     canonical-cluster lift reproduces the real normalize VK) but
    ///     `enum_repr_eq=false` for normalize (the enumerated UNIFORM
    ///     representative does NOT, because the normalize VK is keyed on
    ///     per-chip heights — the gap the hash change closes).
    ///
    /// CHEAP (no proving): just loads the baked `vk_map.bin` and runs the
    /// shape enumeration.  Run:
    ///   CUDA_VISIBLE_DEVICES="" cargo test --release -p zkm-prover \
    ///     stage0_membership_baseline -- --ignored --nocapture
    #[test]
    #[serial]
    #[ignore = "loads vk_map.bin + enumerates shapes; run with --ignored"]
    fn stage0_membership_baseline() {
        use crate::shapes::ZKMProofShape;
        setup_logger();

        // ── vk_map sizes (the baked baseline). ──
        let real_vk_map: BTreeMap<[KoalaBear; DIGEST_SIZE], usize> =
            bincode::deserialize(include_bytes!("../vk_map.bin")).unwrap();
        let dummy_vk_map: BTreeMap<[KoalaBear; DIGEST_SIZE], usize> =
            bincode::deserialize(include_bytes!("../dummy_vk_map.bin")).unwrap();
        eprintln!(
            "[STAGE0][MEMBERSHIP] CURRENT height-specific vk_map.bin = {} entries \
             (the collapse target for Stage 2); dummy_vk_map.bin = {} entries",
            real_vk_map.len(),
            dummy_vk_map.len()
        );

        // ── Enumerated shape cardinality (height-keyed). ──
        let core_cfg = CoreShapeConfig::<KoalaBear>::default();
        let rec_cfg = RecursionShapeConfig::<KoalaBear, CompressAir<KoalaBear>>::default();
        let all: Vec<ZKMProofShape> =
            ZKMProofShape::generate(&core_cfg, &rec_cfg, REDUCE_BATCH_SIZE).collect();

        let mut norm_shapes: std::collections::BTreeSet<OrderedShape> =
            std::collections::BTreeSet::new();
        let mut compose_by_arity: BTreeMap<usize, usize> = BTreeMap::new();
        let mut deferred = 0usize;
        let mut shrink = 0usize;
        for s in &all {
            match s {
                ZKMProofShape::Recursion(b) => {
                    for os in b {
                        norm_shapes.insert(os.clone());
                    }
                }
                ZKMProofShape::Compress(b) => {
                    *compose_by_arity.entry(b.len()).or_default() += 1;
                }
                ZKMProofShape::Deferred(_) => deferred += 1,
                ZKMProofShape::Shrink(_) => shrink += 1,
            }
        }
        eprintln!(
            "[STAGE0][MEMBERSHIP] enum total shapes = {} | distinct NORMALIZE per-shard shapes = {} \
             | COMPOSE by arity = {:?} | Deferred = {} | Shrink = {}",
            all.len(),
            norm_shapes.len(),
            compose_by_arity,
            deferred,
            shrink
        );
        eprintln!(
            "[STAGE0][MEMBERSHIP] BASELINE (pre-hash-change): normalize enum_repr_eq=FALSE \
             (height-keyed normalize VK; the enumerated uniform representative misses the real \
             canonical-cluster VK) — see tests::multishard_normalize_arity_faithful \
             (dummy_faithful=true, enum_repr_eq=false) and \
             tests::arity_enum_representative_reproduces_real_vk. Stage 2 (heights out of \
             vk.hash) must FLIP normalize enum_repr_eq to TRUE and collapse vk_map ({} entries).",
            real_vk_map.len()
        );

        // Sanity: the baked map must be within the fixed merkle capacity.
        assert!(
            real_vk_map.len() <= (1 << VK_MERKLE_TREE_HEIGHT),
            "vk_map ({}) exceeds 2^{} capacity",
            real_vk_map.len(),
            VK_MERKLE_TREE_HEIGHT
        );
    }
}

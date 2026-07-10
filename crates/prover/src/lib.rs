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
pub mod residency;
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
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::sync_channel,
        Arc, Mutex, OnceLock,
    },
    thread,
};

use lru::LruCache;
use p3_field::{PrimeCharacteristicRing, PrimeField, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use shapes::ZKMProofShape;
use tracing::instrument;
use zkm_core_executor::{ExecutionError, ExecutionReport, Executor, Program, ZKMContext};
use zkm_core_machine::{
    io::ZKMStdin,
    mips::MipsAir,
    reduce::ZKMReduceProof,
    shape::CoreShapeConfig,
    utils::ZKMCoreProverError,
};
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
        PublicValuesOutputDigest, ZKMCompressShape,
        ZKMCompressWithVKeyWitnessValues, ZKMCompressWithVkeyShape,
        ZKMCompressWitnessValues, ZKMDeferredWitnessValues,
        ZKMMerkleProofWitnessValues, ZKMRecursionShape, ZKMRecursionWitnessValues,
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
use zkm_pcs::{
    air::PublicValues, koala_bear_poseidon2::KoalaBearPoseidon2, Challenge, MachineProver,
    ShardProof, StarkGenericConfig, StarkProvingKey, StarkVerifyingKey, Val, Word, ZKMCoreOpts,
    ZKMProverOpts, DIGEST_SIZE,
};
use zkm_pcs::{shape::OrderedShape, MachineProvingKey};

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

/// Fixed height of the allowed-vk Merkle tree (capacity 2^11 = 2048 vks).
///
/// BOTH the shape enumeration (`ZKMCompressProgramShape::from_proof_shape`,
/// which bakes `merkle_tree_height` into every compose/deferred/shrink
/// program) AND the runtime tree commit (`ZKMProver::new`) use this
/// constant.  If each side instead derived a height from its own
/// cardinality (enumerated-shape count vs vk_map size), the two
/// derivations could diverge and the witnessed merkle paths would desync
/// from the program shape.  A fixed ceiling kills that circularity.
pub const VK_MERKLE_TREE_HEIGHT: usize = 11;

const COMPRESS_DEGREE: usize = 3;
const SHRINK_DEGREE: usize = 3;
const WRAP_DEGREE: usize = 9;

const CORE_CACHE_SIZE: usize = 5;
/// Tree-reduce arity for the compress stage. SP1 uses 4
/// (`DEFAULT_ARITY`). Ziren's tree-reduce worker pre-computes
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

    /// The core shape configuration.
    pub core_shape_config: Option<CoreShapeConfig<KoalaBear>>,

    /// The recursion shape configuration.
    pub compress_shape_config: Option<RecursionShapeConfig<KoalaBear, CompressAir<KoalaBear>>>,

    /// The verifying key for wrapping.
    pub wrap_vk: OnceLock<StarkVerifyingKey<OuterSC>>,

    /// Whether to verify verification keys.
    pub vk_verification: bool,

    /// Per-arity cache for the host-side basefold compose proving-key
    /// shell (preprocessed traces + chip_ordering + local_only flags)
    /// paired with the matching verifying key.
    ///
    /// Distinct from `compose_programs_basefold_cache` (which caches the
    /// uncompiled recursion program).  This caches the **post-setup**
    /// host view that the ziren-gpu `RecursionProverWorker::dispatch`
    /// path materializes per-shard via `pk_to_host()` (after a heavy
    /// per-chip `generate_preprocessed_trace_host` walk during
    /// `setup()`).  Reusing it lets dispatch skip both the device
    /// `setup()` and the `pk_to_host()` D2H sync; the vk is paired so
    /// downstream `ProvedShard { vk, .. }` can be filled from the
    /// cache instead of returned from the (skipped) `setup()` call.
    ///
    /// Opt-in via `ZIREN_GPU_RESIDENCY=full` (legacy
    /// `ZIREN_COMPOSE_PK_CACHE=1` still honored with a deprecation
    /// warn).  Default OFF — the cache is only sound when
    /// (program, arity) → (pk, vk) is deterministic, which holds today
    /// because `compose_program_basefold` is keyed only on arity in
    /// the program cache and `setup()` is a pure function of the
    /// program.  Mirrors SP1's `RecursionKeys::Exists(pk, vk)`
    /// (recursion.rs:280-345).
    pub compose_pks_basefold_cache: Mutex<
        BTreeMap<
            usize,
            Arc<(StarkProvingKey<InnerSC>, StarkVerifyingKey<InnerSC>)>,
        >,
    >,

    /// Per-shape cache for the basefold compose recursion program.
    ///
    /// **Key**: `ZKMCompressBasefoldWitnessValues::shape_key()` —
    /// a u64 structural signature that hashes every variable-length
    /// collection in the witness write traversal (arity, per-input
    /// chip counts, sumcheck round counts, etc.).  Two inputs sharing
    /// a cached program iff their shape keys match — which is the
    /// soundness condition for the cache (cached program's `Hint`
    /// instruction count must equal the next input's witness stream
    /// length).
    ///
    /// **Rationale**: keying on `arity` alone (as SP1 does at
    /// `crates/prover/src/worker/prover/recursion.rs:446`) is unsound for
    /// Ziren because per-input shapes vary widely across calls of the same
    /// arity (lift heights span 5K..328K vs SP1's tight clustering).
    /// Re-using a program built for shape A with shape B's witness stream
    /// triggers `RuntimeError::EmptyWitnessStream` panics under
    /// `ZIREN_PROGRAM_CACHE=1` / `ZIREN_GPU_RESIDENCY=full`.
    ///
    /// Opt-in via `ZIREN_GPU_RESIDENCY=full` (legacy
    /// `ZIREN_PROGRAM_CACHE=1` still honored).  With
    /// `ZIREN_VERIFY_PROGRAM_CACHE=1` every cache hit rebuilds and
    /// asserts byte-equality (bincode) — catches the (now-rare)
    /// failure mode where two inputs collide in `shape_key()` but
    /// produce different programs.  The audit flag is orthogonal to
    /// the residency profile (CI/dev tool).
    pub compose_programs_basefold_cache:
        Mutex<BTreeMap<u64, Arc<RecursionProgram<KoalaBear>>>>,
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
        // NOTE: the offline vk_map regen tooling (`build_compress_vks` ->
        // `shapes::{check_shapes,build_vk_map}`) still `.expect()`s a core shape
        // config, so it MUST be run with `FIX_CORE_SHAPES=true` explicitly (the
        // prove path does not require it).
        let core_shape_config = env::var("FIX_CORE_SHAPES")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
            .then_some(CoreShapeConfig::default());

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
        let mut leaves: Vec<[KoalaBear; DIGEST_SIZE]> =
            allowed_vk_map.keys().copied().collect();
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
            core_shape_config,
            compress_shape_config: recursion_shape_config,
            vk_verification,
            wrap_vk: OnceLock::new(),
            compose_programs_basefold_cache: Mutex::new(BTreeMap::new()),
            compose_pks_basefold_cache: Mutex::new(BTreeMap::new()),
        };

        // Compose-program pre-warm.
        //
        // Mirrors SP1's `worker/prover/recursion.rs:461-487` arity walk:
        // for each arity in `1..=REDUCE_BATCH_SIZE`, synthesize a dummy
        // compose witness and build the compose recursion program.  The
        // built program is discarded — the goal is to amortize the
        // first-compose-call JIT/compile cost (DSL → AsmCompiler → shape
        // fixing) at process startup instead of paying it inside the
        // first user `compress()` invocation.
        //
        // INDEPENDENT of program-cache gating (`ZIREN_GPU_RESIDENCY=full`
        // / legacy `ZIREN_PROGRAM_CACHE=1`, opt-in): the cache stores the
        // *built* program; pre-warm instead warms the compiler's
        // internal caches (e.g. SeqBlock layout, plonky3 codegen
        // tables, shape-fix tables) that survive across builds even
        // when each per-arity program object is discarded.
        //
        // Default ON.  After the SP1 dummy_shard_proof port (commit
        // 8728b983), the prewarm cost dropped from ~64.8s to ~2.0s
        // (the dummy basefold shard proof is now a struct-only stub
        // rather than a real `prove_shard_to_basefold` invocation per
        // arity slot), so the universal ~2.4s amortizable
        // compose-compile saving easily justifies the small upfront
        // cost.  This gate is intentionally decoupled from
        // `ZIREN_GPU_RESIDENCY` — that profile still gates broader
        // residency features (program cache, compose-pk cache, audit)
        // which carry their own characterization needs.
        //
        // Kill-switch: `ZIREN_DISABLE_COMPOSE_PREWARM=1` skips prewarm
        // entirely (useful for cold-start timing experiments or when
        // the calling process never reaches `compress()`).
        prover.prewarm_compose_programs();

        prover
    }

    /// Compose-program pre-warm helper.  See call-site comment in
    /// [`Self::uninitialized`] for the rationale.  Walks
    /// `arity in 1..=REDUCE_BATCH_SIZE`, building (and discarding) a
    /// dummy compose program per arity to amortize first-compile cost.
    ///
    /// Default ON.  Post the SP1 dummy_shard_proof port (commit
    /// 8728b983) the prewarm walk costs ~2.0s total and amortizes
    /// ~2.4s of compose-compile work that would otherwise be paid
    /// inside the first user `compress()` invocation, so it is
    /// universally beneficial and runs by default.
    ///
    /// Kill-switch: `ZIREN_DISABLE_COMPOSE_PREWARM=1` (accepts
    /// `"1"` or `"true"`, case-insensitive) skips prewarm.  This
    /// gate is intentionally NOT coupled to the
    /// `ZIREN_GPU_RESIDENCY` profile — that profile gates broader
    /// residency features (program cache, compose-pk cache, audit)
    /// orthogonal to the compose-program pre-warm.
    ///
    /// Also bails when:
    ///   - `compress_shape_config` is None
    ///     (`FIX_RECURSION_SHAPES=false` — no allowed shape to drive
    ///     `fix_shape`, would panic or build a non-canonical program),
    ///   - the recursion shape config has no allowed shapes
    ///     (defensive — should not happen with the default config).
    fn prewarm_compose_programs(&self) {
        let prewarm_disabled = std::env::var("ZIREN_DISABLE_COMPOSE_PREWARM")
            .map(|v| {
                let v = v.trim();
                v == "1" || v.eq_ignore_ascii_case("true")
            })
            .unwrap_or(false);
        if prewarm_disabled {
            tracing::debug!(
                "compose pre-warm skipped: \
                 ZIREN_DISABLE_COMPOSE_PREWARM kill-switch set"
            );
            return;
        }

        let Some(recursion_shape_config) = self.compress_shape_config.as_ref() else {
            tracing::debug!(
                "compose pre-warm skipped: compress_shape_config is None \
                 (FIX_RECURSION_SHAPES=false)"
            );
            return;
        };

        // Pull the first allowed recursion shape — replicated across
        // `arity` slots, this is a valid `ZKMCompressShape` that
        // survives `fix_shape`.  Mirrors SP1's
        // `compress_proof_shape_from_arity(arity)` which also uses a
        // single canonical shape replicated.
        let Some(first_shape_map) = recursion_shape_config.first() else {
            tracing::debug!(
                "compose pre-warm skipped: recursion_shape_config has no allowed shapes"
            );
            return;
        };

        let proof_shape: OrderedShape = first_shape_map
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();

        // Use the production merkle tree height — this is what real
        // compose witnesses see at runtime, so the pre-warmed shape
        // matches the JIT path that user calls will hit.
        let merkle_tree_height = self.recursion_vk_tree.height;

        let prewarm_start = std::time::Instant::now();
        for arity in 1..=REDUCE_BATCH_SIZE {
            let compress_shape =
                ZKMCompressShape::from(vec![proof_shape.clone(); arity]);
            let shape = ZKMCompressWithVkeyShape {
                compress_shape,
                merkle_tree_height,
            };
            let witness = ZKMCompressBasefoldWitnessValues::<InnerSC>::dummy(
                self.compress_prover.machine(),
                &shape,
            );
            let per_arity_start = std::time::Instant::now();
            // Discard the result — we want the JIT/compile-cache
            // side-effects, not the program object.  When
            // program caching is on the program *will* be stored in
            // `compose_programs_basefold_cache`; that's an additional
            // benefit but not the pre-warm goal.
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
    /// ziren-gpu's `RecursionProverWorker::dispatch` consults this
    /// gate before short-circuiting its per-shard `setup()` +
    /// `pk_to_host()` walk in favor of
    /// `compose_pks_basefold_cache.get(&arity)`.
    ///
    /// Resolved via `crate::residency::compose_pk_cache_enabled()` —
    /// `ZIREN_GPU_RESIDENCY=full` opts in, the legacy
    /// `ZIREN_COMPOSE_PK_CACHE=1` still works (with a deprecation
    /// warn).  Default OFF; see field docs for the soundness contract.
    /// Motivating bottleneck: per-shard repeated `setup()` cost on the
    /// recursion-phase GPU dispatch path.
    pub fn compose_pk_cache_enabled() -> bool {
        crate::residency::compose_pk_cache_enabled()
    }

    /// Lookup helper for the compose-pk cache.  Returns the cached
    /// `(pk, vk)` pair for the given arity if one is present.  The
    /// returned `Arc` is cheap to clone; ziren-gpu's dispatch path
    /// holds it for the duration of one shard.
    ///
    /// Does NOT check `compose_pk_cache_enabled()` — callers gate on
    /// the env helper first and only consult this when caching is on,
    /// so disabled callers pay zero mutex cost.
    pub fn compose_pk_cache_get(
        &self,
        arity: usize,
    ) -> Option<Arc<(StarkProvingKey<InnerSC>, StarkVerifyingKey<InnerSC>)>> {
        let guard = self.compose_pks_basefold_cache.lock().unwrap();
        guard.get(&arity).cloned()
    }

    /// Insertion helper for the compose-pk cache.  Uses the BTreeMap
    /// `entry` API so a concurrent inserter for the same arity does
    /// not get clobbered — the first writer wins and subsequent
    /// inserters discard their freshly-built pk.  Returns the Arc
    /// that's actually in the cache (caller's value if first, the
    /// pre-existing value otherwise) so callers can use the canonical
    /// pk/vk for the downstream device upload.
    pub fn compose_pk_cache_insert(
        &self,
        arity: usize,
        pk: StarkProvingKey<InnerSC>,
        vk: StarkVerifyingKey<InnerSC>,
    ) -> Arc<(StarkProvingKey<InnerSC>, StarkVerifyingKey<InnerSC>)> {
        let mut guard = self.compose_pks_basefold_cache.lock().unwrap();
        Arc::clone(guard.entry(arity).or_insert_with(|| Arc::new((pk, vk))))
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
        let mut program = Program::from(elf).unwrap();
        if let Some(core_shape_config) = &self.core_shape_config {
            core_shape_config.fix_preprocessed_shape(&mut program)?;
        }
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
                self.core_shape_config.as_ref(),
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

    /// PER-STAGE zerocheck-cube floor (= `BasefoldShardVerifier`
    /// production default `max_log_row_count`, 22).
    fn perstage_base_cube() -> usize {
        zkm_pcs::shard_level::verifier::BasefoldShardVerifier::production_default()
            .max_log_row_count
    }

    /// PER-STAGE zerocheck cube for a recursion verifier-circuit.
    ///
    /// The cube is PINNED to the FIXED base (22 = SP1's core cap) for EVERY
    /// stage — it is NOT floated up to a FIX-off input proof's zerocheck dim.
    /// The recursion program's cube axis is HEIGHT-INDEPENDENT: the same
    /// cube=BASE program is reused for FIX-on and FIX-off alike, so it stays
    /// BYTE-IDENTICAL and preserves the production vk_map invariant.
    ///
    /// The in-circuit checks still assert the cube against the input proof's
    /// zerocheck dim and LogUp-GKR round count (`verify_zerocheck`
    /// zerocheck.rs:523 `point.dim == pcs_max_log_row_count`;
    /// `verify_logup_gkr` logup_gkr.rs:354 `round_proofs.len()+1 ==
    /// max_log_row_count`).  FIX-off over-tall heights do NOT violate this:
    /// each prover proves its proof AT the fixed cube; over-tall chip heights
    /// are WITNESSED under the full_geq degree mask (logup_gkr.rs:637) and
    /// carried by the degree bit-length at fixed-cube+1
    /// (shard_proof_variable_lift.rs:328/393/461-468) — they are witnessed,
    /// NOT grown into the circuit.
    ///
    /// If an input proof's dim genuinely EXCEEDS the fixed cube, that is a
    /// real over-cap chip (AXIS-1b: SP1 HEIGHT_THRESHOLD shard-splitting) —
    /// the function WARNs (it does NOT grow the circuit), so a real failing
    /// prove surfaces it precisely.
    ///
    /// `stage` labels the diagnostic eprintln.
    fn perstage_cube_from_input_proofs<'a, I>(
        proofs: I,
        base: usize,
        stage: &str,
    ) -> usize
    where
        I: IntoIterator<
            Item = &'a zkm_pcs::shard_level::shard_proof::BasefoldShardProof<
                zkm_pcs::InnerVal,
                zkm_pcs::InnerChallenge,
            >,
        >,
    {
        let in_dim = proofs
            .into_iter()
            .map(|p| p.zerocheck_proof.point_and_eval.0.len())
            .max()
            .unwrap_or(0);
        // PIN the recursion cube to the FIXED base (22 = SP1's core cap).  The
        // cube is NOT floated up to a FIX-off input proof's zerocheck dim — the
        // recursion program's cube axis is HEIGHT-INDEPENDENT.  An over-tall
        // FIX-off chip is WITNESSED under the full_geq degree mask
        // (logup_gkr.rs:637), carried by the degree bit-length at fixed-cube+1
        // (shard_proof_variable_lift.rs:328/393/461-468) — NOT grown into the
        // circuit.  This preserves the cube=BASE program (byte-identical,
        // vk_map-stable) for ALL stages.
        //
        // The diagnostic is a WARN: if an input proof's dim exceeds the fixed
        // cube, that surfaces a genuine over-cap chip (SP1 HEIGHT_THRESHOLD
        // shard-splitting territory) — it must be reported, not silently
        // absorbed by growing the circuit.
        if in_dim > base {
            eprintln!(
                "PERSTAGE-CUBE build[{stage}]: WARN base={base} input_zc_dim={in_dim} \
                 (input proof zerocheck dim EXCEEDS the pinned cube; cube stays \
                 pinned at {base} — over-tall heights are witnessed under the \
                 full_geq mask, NOT grown into the circuit)"
            );
        }
        base
    }

    /// PER-STAGE zerocheck cube for the *terminal* (shrink / wrap_bn254)
    /// stages — convenience wrapper over [`Self::perstage_cube_from_input_proofs`]
    /// for the `(vk, proof)`-shaped wrap witness.
    fn perstage_cube_from_wrap_input(
        input: &ZKMWrapBasefoldWitnessValues<InnerSC>,
        base: usize,
        stage: &str,
    ) -> usize {
        Self::perstage_cube_from_input_proofs(
            input.vks_and_proofs.iter().map(|(_vk, p)| p),
            base,
            stage,
        )
    }

    /// Should the recursion PROVE path band-snap (`fix_shape`) the program, or
    /// build it at its NATURAL per-(cluster,arity) heights?
    ///
    /// HEIGHT-AGNOSTIC default (`ZIREN_HA_NO_FIXSHAPE` unset / ≠ 0): `false` —
    /// `fix_shape` is disabled, the program keeps its organic chip heights.  The
    /// recursion compose/normalize area is height-independent PER (cluster,
    /// arity) (loop counts derive from `num_variables`/the fixed stacking
    /// height, the cube,
    /// the chip-set, and arity — NONE a child height), so the dummy that built
    /// the program (which never `fix_shape`s) and a real proof land on the SAME
    /// program for a fixed (cluster, arity).  The soundness substrate (full_geq
    /// LogUp reconstruction + `*_full` binding) makes the in-circuit verifier
    /// ACCEPT arbitrary witnessed heights — so band-snapping is not needed
    /// for correctness, and dropping it kills the band over-padding.  This is the
    /// height-agnostic PROVE path (VERIFY_VK=false; the enum/vk_map re-key +
    /// regen change the VK band→natural).
    ///
    /// Band-snap (`ZIREN_HA_NO_FIXSHAPE=0`): `true` when a
    /// `compress_shape_config` is installed — kept A/B-able on the same binary
    /// so the natural-vs-band change can be isolated.  Returns `false` whenever
    /// `compress_shape_config` is `None` (`FIX_RECURSION_SHAPES=false`), which
    /// already skips `fix_shape`.
    fn recursion_fix_shape_enabled(&self) -> bool {
        if self.compress_shape_config.is_none() {
            return false;
        }
        let no_fixshape = std::env::var("ZIREN_HA_NO_FIXSHAPE")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        !no_fixshape
    }

    /// Build the Normalize (basefold) recursion program. Cluster-parametrized
    /// analog of [`Self::recursion_program`].
    ///
    /// `fix_shape` band-snapping is disabled on the prove path by default
    /// ([`Self::recursion_fix_shape_enabled`]) — the program is built at its
    /// NATURAL per-(cluster,arity) heights (the height-agnostic prove path), so
    /// a FIX-off program never panics in `fix_shape` ("no shape found") when its
    /// organic heights exceed every band.  Set `ZIREN_HA_NO_FIXSHAPE=0` to
    /// restore the band-snap (A/B control).
    pub fn recursion_program_basefold(
        &self,
        input: &ZKMCoreBasefoldWitnessValues<InnerSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        // PER-STAGE cube PINNED to the fixed base — the normalize circuit
        // verifies its input core-shard proofs at this fixed
        // `max_log_row_count`.  FIX-off over-tall core heights are witnessed
        // under the full_geq mask, not floated into the cube.
        let base = Self::perstage_base_cube();
        let max_log_row_count = Self::perstage_cube_from_input_proofs(
            input.shard_proofs.iter(),
            base,
            "normalize",
        );
        let mut program = build_normalize_basefold_program(
            self.core_prover.machine(),
            input,
            max_log_row_count,
        );
        // Band-snap disabled by default — build at natural
        // per-(cluster,arity) heights (height-agnostic prove path).
        if self.recursion_fix_shape_enabled() {
            if let Some(recursion_shape_config) = &self.compress_shape_config {
                recursion_shape_config.fix_shape(&mut program);
            }
        }
        let program = Arc::new(program);
        program
    }

    /// The `OrderedShape` of a recursion/core child proof from its
    /// `chip_log_heights` (= `log2(main_trace.height)` per chip), matching
    /// `ShardProof::shape()` (chip name -> log_degree).
    fn basefold_proof_ordered_shape(
        sp: &zkm_pcs::shard_level::shard_proof::BasefoldShardProof<KoalaBear, Challenge<InnerSC>>,
    ) -> zkm_pcs::shape::OrderedShape {
        zkm_pcs::shape::OrderedShape {
            inner: sp
                .chip_log_heights
                .iter()
                .map(|(n, h)| (n.clone(), *h as usize))
                .collect(),
        }
    }

    /// Build the Compose (basefold) recursion program. Cluster-parametrized
    /// analog of [`Self::compress_program`].
    ///
    /// SP1-style per-arity cache (`crates/prover/src/worker/prover/recursion.rs:446`):
    /// under `ZIREN_GPU_RESIDENCY=full` (legacy `ZIREN_PROGRAM_CACHE=1`
    /// still honored), the program is built once per arity and reused.
    /// With `ZIREN_VERIFY_PROGRAM_CACHE=1` (orthogonal to the residency
    /// profile), every cache hit rebuilds and asserts bincode
    /// byte-equality — catches the failure mode where real input
    /// shapes vary across calls of the same arity.
    pub fn compose_program_basefold(
        &self,
        input: &ZKMCompressBasefoldWitnessValues<InnerSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        let cache_enabled = crate::residency::program_cache_enabled();
        let verify_cache = crate::residency::program_cache_audit_enabled();
        // The cache key is a structural shape signature covering every
        // variable-length collection in the witness write traversal (not just
        // arity).  This makes the cache sound for Ziren's heterogeneous-shape
        // workloads — see `compose_programs_basefold_cache` field docs and
        // `ZKMCompressBasefoldWitnessValues::shape_key`.
        let arity = input.vks_and_proofs.len();
        let cache_key = input.shape_key();

        let program: Arc<RecursionProgram<KoalaBear>> = 'build: {
            if cache_enabled || verify_cache {
                let cached = {
                    let guard = self.compose_programs_basefold_cache.lock().unwrap();
                    guard.get(&cache_key).cloned()
                };
                if let Some(cached) = cached {
                    if verify_cache {
                        let fresh = self.build_compose_program_basefold_uncached(input);
                        let cached_bytes = bincode::serialize(&*cached)
                            .expect("compose program cache: serialize cached");
                        let fresh_bytes = bincode::serialize(&*fresh)
                            .expect("compose program cache: serialize fresh");
                        assert_eq!(
                            cached_bytes, fresh_bytes,
                            "compose program cache divergence at \
                             shape_key={cache_key:#x} (arity={arity}): two \
                             inputs collided in shape_key but produced \
                             different programs — extend shape_key to cover \
                             the diverging field",
                        );
                    }
                    break 'build cached;
                }
            }

            let program = self.build_compose_program_basefold_uncached(input);

            if cache_enabled || verify_cache {
                let mut guard = self.compose_programs_basefold_cache.lock().unwrap();
                // Use entry API so a concurrent inserter doesn't get clobbered.
                break 'build Arc::clone(guard.entry(cache_key).or_insert(program));
            }

            program
        };

        program
    }

    /// Uncached body of [`Self::compose_program_basefold`] — exposed so the
    /// cache wrapper can rebuild on `ZIREN_VERIFY_PROGRAM_CACHE=1` to
    /// assert byte-equality.
    fn build_compose_program_basefold_uncached(
        &self,
        input: &ZKMCompressBasefoldWitnessValues<InnerSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        // PER-STAGE cube from the INPUT (normalize/compose) proofs' zerocheck
        // dims — the compose circuit verifies these at `max_log_row_count`.
        let base = Self::perstage_base_cube();
        let max_log_row_count = Self::perstage_cube_from_input_proofs(
            input.vks_and_proofs.iter().map(|(_vk, p)| p),
            base,
            "compose",
        );
        // The `_recursion` variant is the sole production path for
        // basefold-for-recursion.
        let mut program = build_compose_basefold_recursion_program(
            self.compress_prover.machine(),
            input,
            max_log_row_count,
            self.vk_verification,
            PublicValuesOutputDigest::Reduce,
        );
        // Band-snap disabled by default — build at natural
        // per-(cluster,arity) heights (height-agnostic prove path).
        if self.recursion_fix_shape_enabled() {
            if let Some(recursion_shape_config) = &self.compress_shape_config {
                recursion_shape_config.fix_shape(&mut program);
            }
        }
        Arc::new(program)
    }

    /// Build the Deferred (basefold) recursion program. Cluster-parametrized
    /// analog of [`Self::deferred_program`].
    pub fn deferred_program_basefold(
        &self,
        input: &ZKMDeferredBasefoldWitnessValues<InnerSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        // PER-STAGE cube from the INPUT (deferred/compress) proofs' dims.
        let base = Self::perstage_base_cube();
        let max_log_row_count = Self::perstage_cube_from_input_proofs(
            input.vks_and_proofs.iter().map(|(_vk, p)| p),
            base,
            "deferred",
        );
        // basefold-for-recursion, mirroring
        // `build_compose_program_basefold_uncached`.
        let mut program = build_deferred_basefold_recursion_program(
            self.compress_prover.machine(),
            input,
            max_log_row_count,
            self.vk_verification,
        );
        // Band-snap disabled by default — build at natural
        // per-(cluster,arity) heights (height-agnostic prove path).
        if self.recursion_fix_shape_enabled() {
            if let Some(recursion_shape_config) = &self.compress_shape_config {
                recursion_shape_config.fix_shape(&mut program);
            }
        }
        Arc::new(program)
    }

    /// Build the Wrap (basefold) recursion program. Cluster-parametrized
    /// analog of [`Self::shrink_program`] / [`Self::wrap_program`].
    /// Skips `fix_shape` for the same reason as `recursion_program_basefold`
    /// — basefold programs are sized differently from the FRI path.
    pub fn shrink_program_basefold(
        &self,
        input: &ZKMWrapBasefoldWitnessValues<InnerSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        // PER-STAGE cube from the INPUT (compose) proof's zerocheck dim —
        // shrink does not fix_shape its own program, so the band-max source
        // is unavailable; use the dim the verifier circuit asserts against.
        let max_log_row_count = Self::perstage_cube_from_wrap_input(
            input,
            Self::perstage_base_cube(),
            "shrink",
        );
        let program = build_wrap_basefold_program(
            self.compress_prover.machine(),
            input,
            max_log_row_count,
            self.vk_verification,
        );
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
    ///    the shrink-basefold output we are wrapping), mirroring how the
    ///    legacy [`Self::wrap_program`] verifies against `shrink_prover`.
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

        // PER-STAGE cube from the INPUT (shrink) proof's zerocheck dim — same
        // reasoning as `shrink_program_basefold`.
        let max_log_row_count = Self::perstage_cube_from_wrap_input(
            input,
            Self::perstage_base_cube(),
            "wrap_bn254",
        );

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

    pub fn get_recursion_core_inputs(
        &self,
        vk: &StarkVerifyingKey<CoreSC>,
        shard_proofs: &[ShardProof<CoreSC>],
        batch_size: usize,
        is_complete: bool,
    ) -> Vec<ZKMRecursionWitnessValues<CoreSC>> {
        let mut core_inputs = Vec::new();

        // Prepare the inputs for the recursion programs.
        for (batch_idx, batch) in shard_proofs.chunks(batch_size).enumerate() {
            let proofs = batch.to_vec();

            core_inputs.push(ZKMRecursionWitnessValues {
                vk: vk.clone(),
                shard_proofs: proofs.clone(),
                is_complete,
                is_first_shard: batch_idx == 0,
                vk_root: self.recursion_vk_root,
            });
        }

        core_inputs
    }

    /// Extract `BasefoldShardProof`s from a batch of legacy `ShardProof`s
    /// (via the side-channel `basefold_shard_proof` field populated by
    /// `StarkMachine::open` for KoalaBear MIPS shards) and wrap each batch
    /// into a `ZKMCoreBasefoldWitnessValues`.
    ///
    /// Returns `None` if any proof in the batch lacks the basefold side
    /// channel (e.g. a non-KoalaBear config) — caller falls back to
    /// legacy `get_recursion_core_inputs`.
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
            // aggregate loop + multi-shard dummy would be dead weight on a path
            // SP1 likewise forbids (core.rs:118 asserts shard_proofs.len()==1).
            // Hard-assert the single-shard invariant so any caller that batches
            // core shards into the normalize stage (a regression) is caught at
            // input construction rather than silently building a normalize proof
            // whose VK the enumerator does not cover.
            assert_eq!(
                batch.len(),
                1,
                "normalize is single-shard (#88/#82): get_recursion_core_inputs_basefold \
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

    /// Basefold companion to [`Self::get_recursion_deferred_inputs`].
    /// Constructs `ZKMDeferredBasefoldWitnessValues` from each batch
    /// by extracting the `basefold_shard_proof` side channel from
    /// each input proof. Returns `None` when any deferred proof is
    /// missing the side channel (caller falls back to the legacy path).
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

            // Reuse legacy make_merkle_proofs for the vk-merkle witness —
            // basefold pipeline uses the SAME vk-merkle indirection here
            // (unlike shrink, where ZKMWrapBasefoldWitnessValues has no
            // merkle field).  The merkle witness only depends on vks, not
            // the proof body, so we synthesize a compress-witness with the
            // legacy proof shape (carrying the basefold side channel) just
            // to drive make_merkle_proofs.
            let legacy_input = ZKMCompressWitnessValues {
                vks_and_proofs: batch
                    .iter()
                    .cloned()
                    .map(|p| (p.vk, p.proof))
                    .collect(),
                is_complete: true,
            };
            let merkle = self.make_merkle_proofs(legacy_input).merkle_val;

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

    pub fn get_recursion_deferred_inputs<'a>(
        &'a self,
        vk: &'a StarkVerifyingKey<CoreSC>,
        last_proof_pv: &PublicValues<Word<KoalaBear>, KoalaBear>,
        deferred_proofs: &[ZKMReduceProof<InnerSC>],
        batch_size: usize,
    ) -> Vec<ZKMDeferredWitnessValues<InnerSC>> {
        // Prepare the inputs for the deferred proofs recursive verification.
        let mut deferred_digest = [Val::<InnerSC>::ZERO; DIGEST_SIZE];
        let mut deferred_inputs = Vec::new();

        for batch in deferred_proofs.chunks(batch_size) {
            let vks_and_proofs =
                batch.iter().cloned().map(|proof| (proof.vk, proof.proof)).collect::<Vec<_>>();

            let input = ZKMCompressWitnessValues { vks_and_proofs, is_complete: true };
            let input = self.make_merkle_proofs(input);
            let ZKMCompressWithVKeyWitnessValues { compress_val, merkle_val } = input;

            deferred_inputs.push(ZKMDeferredWitnessValues {
                vks_and_proofs: compress_val.vks_and_proofs,
                vk_merkle_data: merkle_val,
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
        deferred_inputs
    }

    /// Generate the inputs for the first layer of recursive proofs.
    ///
    /// Every shard carries a `basefold_shard_proof` side channel, so this
    /// emits `ZKMCircuitWitness::CoreBasefold` witnesses that dispatch to
    /// the cluster-parametrized basefold Normalize program. When the
    /// side-channel is unexpectedly missing (e.g. a non-KoalaBear config),
    /// falls back to the legacy per-chip `ZKMCircuitWitness::Core` path.
    /// Deferred proofs follow the same dispatch.
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

        if let Some(bf_inputs) = self.get_recursion_core_inputs_basefold(
            &vk.vk,
            shard_proofs,
            batch_size,
            is_complete,
        ) {
            tracing::debug!("emitting {} CoreBasefold witness(es)", bf_inputs.len());
            inputs.extend(bf_inputs.into_iter().map(ZKMCircuitWitness::CoreBasefold));
        } else {
            tracing::warn!("basefold side-channel missing; falling back to legacy Core");
            let core_inputs =
                self.get_recursion_core_inputs(&vk.vk, shard_proofs, batch_size, is_complete);
            inputs.extend(core_inputs.into_iter().map(ZKMCircuitWitness::Core));
        }

        let last_proof_pv = shard_proofs.last().unwrap().public_values.as_slice().borrow();
        // when all deferred proofs carry a basefold
        // side channel, emit DeferredBasefold witnesses; otherwise fall
        // back to legacy Deferred.
        if let Some(bf_deferred) = self.get_recursion_deferred_inputs_basefold(
            &vk.vk,
            last_proof_pv,
            deferred_proofs,
            batch_size,
        ) {
            inputs.extend(bf_deferred.into_iter().map(ZKMCircuitWitness::DeferredBasefold));
            return inputs;
        }
        // Fall through to legacy deferred path when side channel missing.
        let deferred_inputs =
            self.get_recursion_deferred_inputs(&vk.vk, last_proof_pv, deferred_proofs, batch_size);
        inputs.extend(deferred_inputs.into_iter().map(ZKMCircuitWitness::Deferred));
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
            // without preserving first-layer index order. SP1 dropped the
            // equivalent serialization for the same reason.
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
                            // Diagnostic probe (env-gated): stash the
                            // serialized input so a runtime trap below can
                            // dump it for offline localization (variant +
                            // bincode payload).
                            let trip_dump: Option<(&'static str, Vec<u8>)> =
                                if std::env::var("DUMP_TRIP_INPUT").is_ok() {
                                    match &input {
                                        ZKMCircuitWitness::CoreBasefold(i) => {
                                            Some(("core", bincode::serialize(i).unwrap()))
                                        }
                                        ZKMCircuitWitness::ComposeBasefold(i) => {
                                            Some(("compose", bincode::serialize(i).unwrap()))
                                        }
                                        ZKMCircuitWitness::DeferredBasefold(i) => {
                                            Some(("deferred", bincode::serialize(i).unwrap()))
                                        }
                                        _ => None,
                                    }
                                } else {
                                    None
                                };
                            // s4 diagnostic: dump EVERY input (not just on
                            // trap) when DUMP_TRIP_INPUT_ALL is set — lets the
                            // CPROBE harness inspect a NON-tripping witness at
                            // the trap addresses for value diffing.
                            if std::env::var("DUMP_TRIP_INPUT_ALL").is_ok() {
                                if let Some((variant, bytes)) = trip_dump.as_ref() {
                                    let path = format!("/tmp/allinput_{variant}_{index}.bin");
                                    let _ = std::fs::write(&path, bytes);
                                    eprintln!("[ALLDUMP] wrote {path} ({} bytes)", bytes.len());
                                }
                            }
                            // Get the program and witness stream.
                            let (program, witness_stream) = tracing::debug_span!(
                                "get program and witness stream"
                            )
                            .in_scope(|| match input {
                                ZKMCircuitWitness::Core(_)
                                | ZKMCircuitWitness::Deferred(_)
                                | ZKMCircuitWitness::Compress(_) => {
                                    panic!(
                                        "legacy FRI witness variant reached trace-gen worker; \
                                         basefold side-channel must be populated for every shard"
                                    );
                                }
                                ZKMCircuitWitness::CoreBasefold(input) => {
                                    let mut witness_stream = Vec::new();
                                    Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
                                    (self.recursion_program_basefold(&input), witness_stream)
                                }
                                ZKMCircuitWitness::ComposeBasefold(input) => {
                                    let mut witness_stream = Vec::new();
                                    Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
                                    (
                                        self.compose_program_basefold(&input),
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
                                        self.compress_prover.config().perm.clone(),
                                    );
                                runtime.witness_stream = witness_stream.into();
                                runtime
                                    .run()
                                    .map_err(|e| {
                                        // Diagnostic: dump the failing input
                                        // for offline localization (see
                                        // trip_dump).
                                        if let Some((variant, bytes)) = trip_dump.as_ref() {
                                            let path =
                                                format!("/tmp/trip_{variant}_{index}.bin");
                                            let _ = std::fs::write(&path, bytes);
                                            eprintln!(
                                                "[TRIPDUMP] wrote {path} ({} bytes)",
                                                bytes.len()
                                            );
                                        }
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
                                // RECURSION-LAYER AREA PIN (SP1-faithful, always
                                // on — no env flag), band-cap carrier removal
                                // Phase C: threaded EXPLICITLY as the `commit()`
                                // `recursion_area_pin` param (was the
                                // `RecursionAreaPinGuard` thread-local installed
                                // here).  Pins this recursion proof's (normalize
                                // AND compose) jagged dense commit to a FIXED area
                                // 2^RECURSION_LOG_TRACE_AREA so every recursion
                                // child commits at a uniform num_stripes =
                                // 2^(27-21) = 64 → the compose VK collapses to
                                // f(chip-set, arity).  Recorded on
                                // `PrecomputedJaggedCommit.recursion_area_pin` at
                                // commit time and read back at open (the SAME
                                // worker thread runs commit + open here), so it
                                // covers both.  CORE (RiscvAir) passes `None` →
                                // core commit stays NATURAL.
                                let recursion_area_pin =
                                    Some(zkm_pcs::jagged_pcs::RECURSION_LOG_TRACE_AREA);

                                // Get the keys.
                                let (pk, vk) = tracing::debug_span!("Setup compress program")
                                    .in_scope(|| self.compress_prover.setup(&program));

                                // Observe the proving key.
                                let mut challenger = self.compress_prover.config().challenger();
                                tracing::debug_span!("observe proving key").in_scope(|| {
                                    pk.observe_into(&mut challenger);
                                });

                                #[cfg(feature = "debug")]
                                self.compress_prover.debug_constraints(
                                    &self.compress_prover.pk_to_host(&pk),
                                    vec![record.clone()],
                                    &mut challenger.clone(),
                                );

                                // Commit to the record and traces.
                                let data = tracing::debug_span!("commit").in_scope(|| {
                                    // recursion (compress): own-chip-set commit (no
                                    // canonical-cluster missing-chip injection);
                                    // recursion AREA PIN threaded explicitly
                                    // (band-cap Phase C).
                                    self.compress_prover.commit(&record, traces, None, recursion_area_pin)
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
                                        &mut self.compress_prover.config().challenger(),
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
                    type Item = (
                        usize,
                        usize,
                        StarkVerifyingKey<InnerSC>,
                        ShardProof<InnerSC>,
                    );
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
                    let mut received_at_height: Vec<usize> =
                        vec![0usize; layer_sizes_worker.len()];
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

                        let layer_exhausted = received_at_height[height]
                            >= layer_sizes_worker[height];

                        // Drain ready[height] in chunks of up to
                        // `batch_size`. Once the source layer is exhausted
                        // we also flush the final partial chunk.
                        while !ready[height].is_empty()
                            && (ready[height].len() >= batch_size || layer_exhausted)
                        {
                            let take = ready[height].len().min(batch_size);
                            let chunk: Vec<Item> =
                                ready[height].drain(..take).collect();
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
                            let vk_merkle_data =
                                self.make_basefold_merkle_proofs(&vks_only);
                            let compose_values = ZKMCompressBasefoldWitnessValues {
                                vks_and_proofs: bf_vks_and_proofs,
                                vk_merkle_data,
                                is_complete,
                            };
                            if std::env::var("VKEQ_COMPOSE").is_ok() {
                                let sk = compose_values.shape_key();
                                let arity = compose_values.vks_and_proofs.len();
                                let mpath = compose_values
                                    .vk_merkle_data
                                    .vk_merkle_proofs
                                    .first()
                                    .map(|p| p.path.len())
                                    .unwrap_or(0);
                                let per_proof: Vec<String> = compose_values
                                    .vks_and_proofs
                                    .iter()
                                    .map(|(_, sp)| {
                                        let hs: Vec<String> = sp
                                            .chip_log_heights
                                            .iter()
                                            .map(|(n, h)| format!("{n}={h}"))
                                            .collect();
                                        format!("[{}]", hs.join(","))
                                    })
                                    .collect();
                                eprintln!(
                                    "[VKEQ-COMPOSE] shape_key={sk:#018x} arity={arity} is_complete={is_complete} merkle_path_len={mpath} per_proof={per_proof:?}"
                                );
                            }
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
        // Byte-identity canary (ZIREN_BF_PROOF_DIGEST=1): digest of the
        // INPUT (root compress) basefold proof, to localize divergence
        // between the compress and shrink stages across A/B legs.
        if std::env::var("ZIREN_BF_PROOF_DIGEST").as_deref() == Ok("1") {
            fn fnv(bytes: &[u8]) -> u64 {
                let mut h: u64 = 0xcbf29ce484222325;
                for &b in bytes {
                    h ^= b as u64;
                    h = h.wrapping_mul(0x100000001b3);
                }
                h
            }
            if let Ok(bytes) = bincode::serialize(&basefold_proof) {
                eprintln!(
                    "[bf-digest] shrink-input-compress bytes={} fnv=0x{:016x}",
                    bytes.len(),
                    fnv(&bytes)
                );
            }
        }
        // SP1 alignment: bundle vk_merkle_data so verify_wrap_basefold
        // can bind the input VK against the canonical vk_root.
        let vk_merkle_data =
            self.make_basefold_merkle_proofs(&[compressed_vk.clone()]);
        let input = ZKMWrapBasefoldWitnessValues {
            vks_and_proofs: vec![(compressed_vk, basefold_proof)],
            vk_merkle_data,
        };
        let program = self.shrink_program_basefold(&input);

        let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            program.clone(),
            self.shrink_prover.config().perm.clone(),
        );
        let mut witness_stream = Vec::new();
        Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
        runtime.witness_stream = witness_stream.into();
        runtime
            .run()
            .map_err(|e| ZKMRecursionProverError::RuntimeError(e.to_string()))?;
        runtime.print_stats();
        tracing::debug!("Shrink basefold program executed successfully");

        let (shrink_pk, shrink_vk) = tracing::debug_span!("setup shrink basefold")
            .in_scope(|| self.shrink_prover.setup(&program));
        let mut challenger = self.shrink_prover.config().challenger();

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
        // The CPU `StarkMachine::open` populates `basefold_shard_proof`
        // inline via `try_prove_shard_to_basefold_boxed`
        // (crates/pcs/src/prover.rs:564), so on CPU this guard is a
        // no-op.  Under `StarkGpuProver<InnerSC, ShrinkAir>` with
        // `ZIREN_GPU_DROP_FRI` (default), the GPU `open()` returns
        // `basefold_shard_proof: None`, and `wrap_bn254` `.expect()`s
        // that side channel.  Mirror the GPU compress orchestrator
        // (ziren-gpu/prover/src/compress_multi_gpu.rs:1496-1865) by
        // re-running the pipeline pieces on the shrink machine and
        // driving `prove_shard_to_basefold` here, extracting the 8-felt
        // `main_commitment` from the `MerkleCap` (precomputed_commit =
        // None, since the GPU lacks the precomputed jagged commit the
        // CPU helper expects).  Host `prove_shard_to_basefold` with
        // `device_traces = None` needs no device snapshot.
        if proof.basefold_shard_proof.is_none() {
            use core::any::Any;
            use p3_challenger::CanObserve;
            use p3_symmetric::MerkleCap;
            use zkm_pcs::air::MachineAir;

            // Re-run generate_dependencies + generate_traces on a fresh
            // clone of the record (mirrors the GPU orchestrator + host
            // `prove` preamble), then commit to obtain the MerkleCap
            // main commitment, chip_ordering, and public_values.
            let mut dep_records = vec![rec.clone()];
            self.shrink_prover
                .machine()
                .generate_dependencies(&mut dep_records, &opts.recursion_opts, None)
                .expect("shrink basefold attach: generate_dependencies failed");
            let bf_record = dep_records.into_iter().next().unwrap();
            let traces = self
                .shrink_prover
                .generate_traces(&bf_record)
                .expect("shrink basefold attach: generate_traces failed");
            let host_pk = self.shrink_prover.pk_to_host(&shrink_pk);
            // shrink: own-chip-set commit (no canonical-cluster missing-chip
            // injection); SHRINK never pins the recursion AREA (band-cap Phase C)
            // → None (NATURAL own-area, byte-identical).
            let data = self.shrink_prover.commit(&bf_record, traces.clone(), None, None);

            // Shrink device-resident routing: when the shrink prover keeps the
            // committed main traces device-resident (StarkGpuProver), hand
            // prove_shard_to_basefold the same per-shard DeviceTraceProvider
            // snapshot the GPU compress pipeline uses, and skip the host
            // rehydrate of the device-only RecursionAir chips below — the
            // interaction-eval hook + device-fold zerocheck resolve them from
            // the provider (mirrors ziren-gpu pipeline/prover.rs, the
            // device-resident zerocheck pattern).
            // SP1-static: always on — on the CPU prover
            // `shard_device_trace_provider` returns None and this whole block
            // is a no-op (legacy path, bit-for-bit). Env gate removed
            // (was ZIREN_GPU_SHRINK_DEVICE, default-on).
            let device_provider = self.shrink_prover.shard_device_trace_provider(&data);
            // Pin this thread's GPU-pool TLS to the provider's device so
            // the device-keyed dispatch hooks in try_run_device_path see a
            // worker context, exactly like the pipeline dispatch does before
            // driving the basefold prove.
            let _shrink_gpu_guard = device_provider
                .as_ref()
                .map(|(_, dev)| zkm_pcs::gpu_worker_context::GpuPoolWorkerGuard::new(*dev));
            // Escape hatch: ZIREN_GPU_SHRINK_DEVICE_REHYDRATE=1 keeps the
            // host rehydrate even with a provider attached (provider-
            // preferred paths still fire; host fallbacks stay covered).
            let shrink_force_rehydrate = std::env::var("ZIREN_GPU_SHRINK_DEVICE_REHYDRATE")
                .map(|v| v == "1")
                .unwrap_or(false);

            // Snapshot the challenger at the state the BaseFold verifier
            // sees at entry to `BasefoldShardVerifier::verify_shard`:
            // fresh challenger -> pk.observe_into -> observe pv. Matches
            // the compress orchestrator's snapshot ordering exactly
            // (compress_multi_gpu.rs:1295 pk.observe_into + :1478
            // snap.observe_slice(pv[0..num_pv_elts])) and the CPU
            // helper's snapshot point (prover.rs:369/383).
            let num_pv_elts = self.shrink_prover.machine().num_pv_elts();
            let mut bf_challenger = self.shrink_prover.config().challenger();
            shrink_pk.observe_into(&mut bf_challenger);
            bf_challenger.observe_slice(&data.public_values[0..num_pv_elts]);

            // Rehydrate device-only RecursionAir chips on host: the GPU
            // `generate_traces` (StarkGpuProver) filters out chips whose
            // `generate_trace_host` returns None, so they are absent from
            // `traces`.  Regenerate them via `chip.air.generate_trace`
            // (host-or-device generic).  No-op on CPU (all present).
            // Mirrors compress_multi_gpu.rs:1341-1383.
            let mut trace_by_name: std::collections::BTreeMap<
                String,
                RowMajorMatrix<Val<InnerSC>>,
            > = traces.into_iter().collect();
            // Skipped when the device provider is attached — the
            // device-only chips resolve from the provider, like the GPU
            // compress pipeline's default (ZIREN_GPU_PIPELINE_DEVICE_REHYDRATE).
            if device_provider.is_none() || shrink_force_rehydrate {
                let machine = self.shrink_prover.machine();
                for chip in machine.chips() {
                    let name = chip.name();
                    if trace_by_name.contains_key(&name) {
                        continue;
                    }
                    if !chip.included(&bf_record) {
                        continue;
                    }
                    let mut output =
                        <ShrinkAir<KoalaBear> as MachineAir<KoalaBear>>::Record::default();
                    let trace = chip
                        .air
                        .generate_trace(&bf_record, &mut output)
                        .expect("shrink basefold attach: rehydrate generate_trace failed");
                    trace_by_name.insert(name, trace);
                }
            }

            // Build per-chip preprocessed + main traces aligned with the
            // chips iteration order (shard_chips_ordered). Empty matrix
            // when a chip has no preprocessed / main columns.
            let machine = self.shrink_prover.machine();
            let chips: Vec<&zkm_pcs::Chip<Val<InnerSC>, _>> =
                machine.shard_chips_ordered(&data.chip_ordering).collect();

            let preprocessed_traces: Vec<RowMajorMatrix<Val<InnerSC>>> = chips
                .iter()
                .map(|chip| {
                    host_pk
                        .chip_ordering
                        .get(&chip.name())
                        .map(|&idx| host_pk.traces[idx].clone())
                        .unwrap_or_else(|| RowMajorMatrix::new(vec![], 0))
                })
                .collect();

            let main_traces: Vec<RowMajorMatrix<Val<InnerSC>>> = chips
                .iter()
                .map(|chip| {
                    trace_by_name
                        .remove(&chip.name())
                        .unwrap_or_else(|| RowMajorMatrix::new(vec![], 0))
                })
                .collect();
            drop(trace_by_name);

            // Extract the 8-felt digest from the main commitment. For
            // KoalaBearPoseidon2 the PCS commitment is
            // `MerkleCap<KoalaBear, [KoalaBear; 8]>`; pull the first
            // root. Mirrors compress_multi_gpu.rs:1585-1611.
            let digest: [Val<InnerSC>; 8] = {
                let any_commit: &dyn Any = &data.main_commit;
                let cap = any_commit
                    .downcast_ref::<MerkleCap<KoalaBear, [KoalaBear; 8]>>()
                    .expect(
                        "shrink basefold attach: Com<InnerSC> downcast to \
                         MerkleCap<KoalaBear,[KoalaBear;8]> failed",
                    );
                let roots = cap.roots();
                assert!(!roots.is_empty(), "MerkleCap must have at least one root");
                roots[0]
            };

            // PER-STAGE cube for the SHRINK proof: `cube = BASE.max(band-max
            // shrink-AIR chip log-height)`.  The wrap_bn254 circuit reads this
            // proof's recorded zerocheck dim, so the cube here defines the
            // shrink-proof dim.  NO-OP (== BASE=22) when all shrink traces
            // fit 2^22 (the common case) → byte-identical.  Heights are
            // power-of-2 post-trace-gen so log2 = trailing_zeros.
            let base_cube =
                zkm_pcs::shard_level::verifier::BasefoldShardVerifier::production_default()
                    .max_log_row_count;
            let max_log_row_count = {
                let mut cube = base_cube;
                for t in main_traces.iter() {
                    let w = t.width;
                    if w == 0 {
                        continue;
                    }
                    let h = t.values.len() / w;
                    if h == 0 {
                        continue;
                    }
                    let log_h = (h as u64).trailing_zeros() as usize;
                    if log_h > cube {
                        cube = log_h;
                    }
                }
                cube
            };
            if max_log_row_count != base_cube {
                eprintln!(
                    "PERSTAGE-CUBE prover[shrink]: base={base_cube} -> \
                     cube={max_log_row_count} (FIX-off shrink trace above base)"
                );
            }

            let bf_proof = zkm_pcs::shard_level::prover::prove_shard_to_basefold::<
                InnerSC,
                ShrinkAir<Val<InnerSC>>,
            >(
                &chips,
                &preprocessed_traces,
                &main_traces,
                digest,
                data.public_values.clone(),
                max_log_row_count,
                &mut bf_challenger,
                // Per-shard device traces when the shrink prover is
                // device-resident; None on the CPU prover (legacy host path).
                device_provider
                    .as_ref()
                    .map(|(p, _)| p.as_ref() as &dyn zkm_pcs::shard_level::DeviceTraceProvider),
                // Both the CPU/host prover and the GPU device path emit
                // MSB-folded proofs (resolve_gpu_fold_orientation() default).
                zkm_pcs::shard_level::shard_proof::FoldOrientation::Msb,
                // band-cap carrier removal Phase B: SHRINK is a non-core stage
                // (`core_rev == false`) → LEGACY bitrev orientation, byte-identical
                // to the pre-carrier path (shrink never installed the carrier).
                false,
                // band-cap carrier removal Phase C: SHRINK never installed the
                // recursion AREA PIN → NATURAL own-area (byte-identical to legacy).
                None,
                // GPU lacks the precomputed jagged commit; the digest
                // above is extracted straight from the MerkleCap.
                None,
            );

            // Byte-identity canary (ZIREN_BF_PROOF_DIGEST=1): FNV-1a over
            // the serialized shrink basefold proof — compare device-routed
            // vs host (ZIREN_GPU_SHRINK_DEVICE=0) legs.  Mirrors the
            // ziren-gpu core_multi_gpu canary format.
            if std::env::var("ZIREN_BF_PROOF_DIGEST").as_deref() == Ok("1") {
                fn fnv(bytes: &[u8]) -> u64 {
                    let mut h: u64 = 0xcbf29ce484222325;
                    for &b in bytes {
                        h ^= b as u64;
                        h = h.wrapping_mul(0x100000001b3);
                    }
                    h
                }
                if let Ok(bytes) = bincode::serialize(&bf_proof) {
                    eprintln!(
                        "[bf-digest] shrink bytes={} fnv=0x{:016x}",
                        bytes.len(),
                        fnv(&bytes)
                    );
                }
            }

            proof.basefold_shard_proof = Some(Box::new(bf_proof));
        }

        Ok(ZKMReduceProof { vk: shrink_vk, proof })
    }

    /// Wrap a reduce proof into a STARK proven over a SNARK-friendly field.
    #[instrument(name = "wrap_bn254", level = "info", skip_all)]
    pub fn wrap_bn254(
        &self,
        compressed_proof: ZKMReduceProof<InnerSC>,
        opts: ZKMProverOpts,
    ) -> Result<ZKMReduceProof<OuterSC>, ZKMRecursionProverError> {
        // BaseFold-over-BN254 wrap port: install the outer-ring jagged
        // BaseFold open/verify hooks so the wrap STARK (CpuProver<OuterSC>) can
        // prove + host-verify over OuterValMmcs/OuterChallenger. Idempotent.
        zkm_recursion_core::stark::outer_jagged_hooks::register_outer_jagged_hooks();
        let ZKMReduceProof { vk: compressed_vk, proof: compressed_proof } = compressed_proof;
        let basefold_proof = *compressed_proof
            .basefold_shard_proof
            .clone()
            .expect("wrap_bn254: input shrink proof missing basefold side-channel — legacy FRI wrap removed");
        // SP1 alignment: bundle vk_merkle_data so verify_wrap_basefold
        // can bind the input VK against the canonical vk_root.
        let vk_merkle_data =
            self.make_basefold_merkle_proofs(&[compressed_vk.clone()]);
        let input = ZKMWrapBasefoldWitnessValues {
            vks_and_proofs: vec![(compressed_vk, basefold_proof)],
            vk_merkle_data,
        };
        let program = self.wrap_bn254_program_basefold(&input);

        let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            program.clone(),
            self.shrink_prover.config().perm.clone(),
        );
        let mut witness_stream = Vec::new();
        Witnessable::<WrapConfig>::write(&input, &mut witness_stream);
        runtime.witness_stream = witness_stream.into();
        runtime
            .run()
            .map_err(|e| ZKMRecursionProverError::RuntimeError(e.to_string()))?;
        runtime.print_stats();
        tracing::debug!("wrap_bn254 basefold program executed successfully");

        let (wrap_pk, wrap_vk) = tracing::debug_span!("setup wrap_bn254 basefold")
            .in_scope(|| self.wrap_prover.setup(&program));
        if self.wrap_vk.set(wrap_vk.clone()).is_ok() {
            tracing::debug!("wrap verifier key set (basefold)");
        }

        let mut wrap_challenger = self.wrap_prover.config().challenger();
        let time = std::time::Instant::now();
        let mut wrap_proof = self
            .wrap_prover
            .prove(&wrap_pk, vec![runtime.record], &mut wrap_challenger, opts.recursion_opts)
            .unwrap();
        let elapsed = time.elapsed();
        tracing::debug!("wrap_bn254 basefold proving time: {:?}", elapsed);
        let mut wrap_challenger = self.wrap_prover.config().challenger();
        self.wrap_prover.machine().verify(&wrap_vk, &wrap_proof, &mut wrap_challenger).unwrap();
        tracing::info!("wrapping (basefold) successful");

        Ok(ZKMReduceProof {
            vk: wrap_vk,
            proof: wrap_proof.shard_proofs.pop().unwrap(),
        })
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
        // wrap-basefold witness type (NOT the legacy ZKMCompressWitnessValues, which
        // emits a stale 523-flat witness incompatible with the 15208-flat circuit).
        let basefold_proof = *proof
            .proof
            .basefold_shard_proof
            .clone()
            .expect(
                "wrap_plonk_bn254: wrap proof missing basefold_shard_proof \
                 (KoalaBearPoseidon2Outer::use_basefold() must be true)",
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
        // wrap-basefold witness type (NOT the legacy ZKMCompressWitnessValues, which
        // emits a stale 523-flat witness incompatible with the 15208-flat circuit).
        let basefold_proof = *proof
            .proof
            .basefold_shard_proof
            .clone()
            .expect(
                "wrap_groth16_bn254: wrap proof missing basefold_shard_proof \
                 (KoalaBearPoseidon2Outer::use_basefold() must be true)",
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
        // wrap-basefold witness type (NOT the legacy ZKMCompressWitnessValues).
        let basefold_proof = *proof
            .proof
            .basefold_shard_proof
            .clone()
            .expect(
                "wrap_dvsnark_bn254: wrap proof missing basefold_shard_proof \
                 (KoalaBearPoseidon2Outer::use_basefold() must be true)",
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

    /// Build a merkle witness for a slice of VKs without
    /// going through the legacy `ZKMCompressWitnessValues` shape.
    /// Used by basefold compose/wrap to bundle vk_merkle_data into the
    /// witness that the recursion program reads.  Mirror of the inner
    /// half of [`Self::make_merkle_proofs`].
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
        // value==vk_digest binding is gated on vk_verification).  The old
        // code fabricated `[index; 8]` under VERIFY_VK=false, which can
        // never re-derive the real root; that was masked while the
        // recursion asserts were vacuous.  SP1 parity: RecursionVks::open
        // returns MerkleTree::open's (value, proof) verbatim.  Under
        // vk_verification=true the leaf IS the vk digest, so this is
        // value-identical to the previous behavior there.
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

    pub fn make_merkle_proofs(
        &self,
        input: ZKMCompressWitnessValues<CoreSC>,
    ) -> ZKMCompressWithVKeyWitnessValues<CoreSC> {
        let num_vks = self.recursion_vk_map.len();
        let vk_indices: Vec<usize> = if self.vk_verification {
            input
                .vks_and_proofs
                .iter()
                .map(|(vk, _)| {
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
            input
                .vks_and_proofs
                .iter()
                .map(|(vk, _)| {
                    let vk_digest = vk.hash_koalabear();
                    (vk_digest[0].as_canonical_u32() as usize) % num_vks
                })
                .collect()
        };

        // VK-binding soundness: witness the ACTUAL opened leaf (see
        // make_basefold_merkle_proofs for the full rationale) — the
        // in-circuit merkle walk is unconditional, so a fabricated
        // `[index; 8]` value is honestly unsatisfiable.
        let (values, proofs): (Vec<_>, Vec<_>) = vk_indices
            .iter()
            .map(|index| MerkleTree::open(&self.recursion_vk_tree, *index))
            .unzip();

        let merkle_val = ZKMMerkleProofWitnessValues {
            root: self.recursion_vk_root,
            values,
            vk_merkle_proofs: proofs,
        };

        ZKMCompressWithVKeyWitnessValues { compress_val: input, merkle_val }
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

    use shapes::ZKMProofShape;
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

    /// Parallelism unlock-chain validation: build a synthetic compose
    /// program with N=4 dummy inputs and verify that the resulting
    /// `RecursionProgram` has at least 1 `SeqBlock::Parallel` block,
    /// containing N sub-programs (one per `ir_par_map_collect` element).
    ///
    /// This is the cheapest end-to-end check that the par_iter unlock
    /// chain (ir_par_map_collect → DslIr::Parallel → SeqBlock::Parallel
    /// → runtime walker) survives all stages of program build/compile.
    /// Local prove tests don't exercise compose programs (single-shard
    /// fibonacci doesn't trigger compose; multi-shard tests panic on
    /// pre-existing legacy-FRI removal regression), so this synthetic
    /// path is the only way to validate the chain without the GPU box.
    /// VKROOT localizer: enumerate every Compress shape (the exact set
    /// `build_vk_map` walks), build the dummy compose witness for each
    /// at the production merkle_tree_height, compute its `shape_key()`,
    /// and collect the set.  Then check whether the real fib compose
    /// shape_key(s) (passed via `VKEQ_TARGETS=hex,hex,...`) are members.
    ///
    /// If a target ∈ set but the real compose vk is NOT in vk_map ⇒
    /// value-dependence (the shape_key→program invariant is violated:
    /// two equal-shape_key witnesses produce different programs ⇒ a
    /// baked-value remnant in the compose path).
    /// If a target ∉ set ⇒ shape-coverage gap (the shape was never
    /// enumerated; injecting it converges since heights match).
    #[test]
    #[serial]
    #[ignore]
    fn vkroot_localize_compose_shape_keys() {
        use zkm_recursion_circuit::machine::ZKMCompressBasefoldWitnessValues;
        use crate::shapes::{ZKMProofShape, ZKMCompressProgramShape};
        use std::collections::BTreeSet;

        let prover = ZKMProver::<DefaultProverComponents>::new();
        let core_shape_config = prover.core_shape_config.as_ref().unwrap();
        let recursion_shape_config = prover.compress_shape_config.as_ref().unwrap();
        let compress_machine = prover.compress_prover.machine();

        let all_shapes: BTreeSet<_> = ZKMProofShape::generate(
            core_shape_config,
            recursion_shape_config,
            REDUCE_BATCH_SIZE,
        )
        .collect();
        let num_shapes = all_shapes.len();
        let height = VK_MERKLE_TREE_HEIGHT;
        eprintln!("[VKROOT-LOC] num_shapes={num_shapes} merkle_tree_height={height}");

        // shape_key set, keyed by arity for diagnostics.
        let mut sk_set: BTreeSet<u64> = BTreeSet::new();
        let mut sk_by_arity: std::collections::BTreeMap<usize, BTreeSet<u64>> =
            std::collections::BTreeMap::new();
        let mut n_compress = 0usize;
        for shape in all_shapes.into_iter() {
            if !matches!(shape, ZKMProofShape::Compress(_)) {
                continue;
            }
            n_compress += 1;
            let prog_shape = ZKMCompressProgramShape::from_proof_shape(shape, height);
            let ZKMCompressProgramShape::Compress(vkey_shape) = prog_shape else { unreachable!() };
            let mut dummy = ZKMCompressBasefoldWitnessValues::<InnerSC>::dummy::<CompressAir<KoalaBear>>(
                compress_machine,
                &vkey_shape,
            );
            let arity = dummy.vks_and_proofs.len();
            // is_complete is witnessed (program-independent) but pollutes
            // shape_key — insert both variants so the real final compose
            // (is_complete=true) can match an enumerated (is_complete=false)
            // shape.
            dummy.is_complete = false;
            let sk_f = dummy.shape_key();
            dummy.is_complete = true;
            let sk_t = dummy.shape_key();
            sk_set.insert(sk_f);
            sk_set.insert(sk_t);
            sk_by_arity.entry(arity).or_default().insert(sk_f);
            sk_by_arity.entry(arity).or_default().insert(sk_t);
        }
        eprintln!(
            "[VKROOT-LOC] enumerated {n_compress} Compress shapes -> {} distinct shape_keys",
            sk_set.len()
        );
        for (arity, set) in sk_by_arity.iter() {
            eprintln!("[VKROOT-LOC]   arity={arity}: {} distinct shape_keys", set.len());
        }

        if let Ok(targets) = std::env::var("VKEQ_TARGETS") {
            for t in targets.split(',').filter(|s| !s.is_empty()) {
                let t = t.trim().trim_start_matches("0x");
                let key = u64::from_str_radix(t, 16).expect("hex shape_key");
                let member = sk_set.contains(&key);
                eprintln!(
                    "[VKROOT-LOC] target shape_key={key:#018x} member_of_enumerated={member} {}",
                    if member { "=> VALUE-DEPENDENCE (shape enumerated, vk differs)" }
                    else { "=> COVERAGE GAP (shape never enumerated)" }
                );
            }
        }
    }

    /// STEP-2 (SP1 MachineShape port): prove the COMPOSE recursion program
    /// is **band-INDEPENDENT** — its bytes (and thus its VK) depend only on
    /// (chip-set, arity), NOT on the per-child input heights / size-class
    /// band.  If true, the `multi_cartesian_product` over `allowed_shapes`
    /// bands in `RecursionShapeConfig::get_all_shape_combinations` is pure
    /// over-enumeration for compose: the band a compose node lands in is a
    /// deterministic function of (chip-set, arity), so bands can be collapsed
    /// to one canonical key per (chip-set, arity).
    ///
    /// MECHANISM (traced, this is what the test mechanizes):
    ///   * The compose verifier (`verify_compress_basefold`) does FIXED work
    ///     per chip — it iterates the child shard's `chip_openings` KEYS
    ///     (the chip-SET) and WITNESSES each height from the opened `degree`
    ///     (`chip_height_*_from_opened_degrees`).  Heights are scalar VALUES,
    ///     never structural.
    ///   * The dummy child shard proof sizes its logup-GKR / zerocheck round
    ///     counts from `max_log_row_count` (a global constant), NOT the
    ///     per-chip heights (`dummy/basefold_shard_proof.rs:120,217-223`); the
    ///     height enters only as a fixed-`bit_len` `quotient[0]` degree
    ///     bit-vector and `log_degree` scalar.
    ///   * Therefore two same-(chip-set, arity) dummy witnesses at DIFFERENT
    ///     bands have equal `shape_key()` AND build byte-identical compose
    ///     programs.  `fix_shape` then snaps both to a band.
    ///
    /// MEASURED VERDICT (this test PINS it — the hypothesis was REFUTED):
    /// **BANDS ARE LOAD-BEARING for compose; they CANNOT be collapsed.**
    /// At the SAME chip-set + SAME arity, a low band (children at log_h=3)
    /// and a high band (log_h=8) build compose programs of DIFFERENT byte
    /// length (~74 MB vs ~112 MB) ⇒ DIFFERENT VK.
    ///
    /// ROOT CAUSE (traced): the per-child band sets each child's trace AREA,
    /// hence the child shard-proof's jagged-basefold bundle
    /// `log_dense_size = L` (dummy/basefold_shard_proof.rs:431-449:
    /// `pack_traces_jagged` on `2^log_h`-tall matrices → L grows with the
    /// heights; `batch_evaluations` width = `2^(L - log_stacking)`, BaseFold
    /// rounds / query-path lengths / reduction rounds all key off L).  The
    /// compose program `read()`s that bundle, so a taller band ⇒ a longer
    /// witness stream ⇒ more program instructions ⇒ a different VK.  The band
    /// therefore encodes the children's `log_dense_size` (total trace area) —
    /// a genuine structural dimension, not incidental padding.
    ///
    /// SECONDARY FINDING (latent cache hazard, also PINNED here): assertion
    /// (a) below shows `shape_key()` is EQUAL across the two bands even though
    /// the programs differ.  `shape_key` (compress_basefold.rs:1227) does NOT
    /// hash the shard proof's `evaluation_proof` bundle lengths
    /// (`log_dense_size` / `batch_evaluations.len()`), so two different-band
    /// inputs COLLIDE in the program cache key.  The default
    /// `compose_program_basefold` cache would return the wrong cached program
    /// for a colliding band; only `ZIREN_VERIFY_PROGRAM_CACHE=1` catches it
    /// (byte-equality audit).  Step-4 (height-agnostic recursion) is what
    /// would actually let bands collapse — until then, shape_key SHOULD be
    /// extended to cover the bundle's `log_dense_size` (see the TODO emitted
    /// by this test).
    ///
    /// The two inputs use the SAME recursion chip-set + SAME arity (4) but a
    /// "low band" (log_h=3) vs "high band" (log_h=8).
    #[test]
    #[serial]
    fn compose_program_basefold_band_is_load_bearing() {
        use zkm_recursion_circuit::machine::{
            ZKMCompressBasefoldWitnessValues, ZKMCompressShape, ZKMCompressWithVkeyShape,
        };
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::shape::OrderedShape;

        let prover = ZKMProver::<DefaultProverComponents>::new();
        let compress_machine = prover.compress_prover.machine();

        // Same recursion chip-set for both bands (the production compose
        // children are recursion proofs over this fixed 7-chip machine).
        let chip_names: Vec<String> = compress_machine
            .chips()
            .iter()
            .map(|c| <_ as MachineAir<KoalaBear>>::name(c))
            .collect();

        let arity = 4usize;
        let merkle_tree_height = VK_MERKLE_TREE_HEIGHT;

        // Build a Compress shape with `arity` children, every child chip at
        // a uniform `log_h`.  Distinct `log_h` => distinct size-class band
        // (a different `allowed_shapes` cartesian-product cell).
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
            ZKMCompressWithVkeyShape { compress_shape, merkle_tree_height }
        };

        let shape_low = shape_at_band(3);
        let shape_high = shape_at_band(8);

        let witness_low = ZKMCompressBasefoldWitnessValues::<InnerSC>::dummy::<
            CompressAir<KoalaBear>,
        >(compress_machine, &shape_low);
        let witness_high = ZKMCompressBasefoldWitnessValues::<InnerSC>::dummy::<
            CompressAir<KoalaBear>,
        >(compress_machine, &shape_high);

        assert_eq!(witness_low.vks_and_proofs.len(), arity, "low-band witness arity");
        assert_eq!(witness_high.vks_and_proofs.len(), arity, "high-band witness arity");

        // (a) LATENT CACHE HAZARD: shape_key COLLIDES across bands even though
        //     the programs differ — shape_key omits the bundle's log_dense_size.
        let sk_low = witness_low.shape_key();
        let sk_high = witness_high.shape_key();
        assert_eq!(
            sk_low, sk_high,
            "[STEP-2] expected shape_key to COLLIDE across bands (it omits the \
             bundle log_dense_size); if this now DIFFERS, shape_key was \
             extended to cover the band — update this test",
        );
        eprintln!(
            "[STEP-2] shape_key collides across bands ({sk_low:#018x}) — \
             program-cache hazard: extend shape_key to hash the shard \
             proof's evaluation_proof bundle log_dense_size / \
             batch_evaluations.len() (or rely on ZIREN_VERIFY_PROGRAM_CACHE=1)."
        );

        // (b) The PRODUCTION compose program (via `compose_program_basefold`,
        //     the same path the vk_map uses, incl. fix_shape) has a DIFFERENT
        //     byte length across bands ⇒ DIFFERENT VK ⇒ bands are load-bearing.
        let prog_low = prover.compose_program_basefold(&witness_low);
        let prog_high = prover.compose_program_basefold(&witness_high);

        let len_low =
            bincode::serialize(&*prog_low).expect("serialize low-band compose program").len();
        let len_high =
            bincode::serialize(&*prog_high).expect("serialize high-band compose program").len();

        assert_ne!(
            len_low, len_high,
            "[STEP-2] compose program byte-length is EQUAL across bands \
             ({len_low}) — if the recursion became height-agnostic, bands can \
             now be collapsed; revisit step-4 (this test's premise is stale)",
        );
        assert!(
            len_high > len_low,
            "[STEP-2] expected the TALLER band to build a LARGER program \
             (more jagged bundle witness reads); got low={len_low} high={len_high}",
        );

        eprintln!(
            "[STEP-2] PASS — bands ARE LOAD-BEARING for compose: low(h=3) \
             builds a {len_low}-byte program, high(h=8) builds {len_high} bytes \
             (Δ={} bytes) at the SAME chip-set/arity={arity}. The band encodes \
             the children's log_dense_size (jagged bundle size). Bands CANNOT \
             be collapsed without making the recursion height-agnostic (step-4).",
            len_high - len_low,
        );
    }

    /// STEP-3 (SP1 MachineShape port, faithful-dummy diagnostic): verify the
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
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::shape::OrderedShape;
        use zkm_core_machine::mips::MipsAir;

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
        let (dummy_vk, _proof) =
            zkm_recursion_circuit::stark::dummy_basefold_vk_and_shard_proof::<
                MipsAir<KoalaBear>,
            >(core_machine, &shape);
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
        use zkm_recursion_circuit::machine::basefold_programs::build_compose_basefold_program;
        use zkm_recursion_circuit::machine::{
            ZKMCompressBasefoldWitnessValues, ZKMCompressWithVkeyShape,
            PublicValuesOutputDigest, ZKMCompressShape,
        };
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::shape::OrderedShape;

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
        let compress_shape = ZKMCompressShape::from(
            (0..n_inputs).map(|_| proof_shape()).collect::<Vec<_>>(),
        );
        let merkle_tree_height = 4;
        let shape = ZKMCompressWithVkeyShape { compress_shape, merkle_tree_height };

        // Generate the dummy witness with N inputs.
        let witness =
            ZKMCompressBasefoldWitnessValues::<InnerSC>::dummy::<CompressAir<KoalaBear>>(
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
        let (n_par, n_subs, n_par_instrs) =
            program.seq_blocks.parallelism_summary();
        assert!(
            n_par >= 1,
            "compose program with {n_inputs} inputs should have ≥1 SeqBlock::Parallel block, got {n_par}",
        );
        assert_eq!(
            n_subs, n_inputs,
            "Parallel block should hold {n_inputs} sub-programs, got {n_subs}",
        );
        assert!(
            n_par_instrs > 0,
            "Parallel sub-programs should hold non-zero instructions",
        );

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
        fn walk<F>(
            block: &SeqBlock<Instruction<F>>,
            hint: &mut usize,
            inside: bool,
        ) {
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
        eprintln!(
            "[compose_emits_parallel] hint_in_par={}",
            hint_in_par,
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
        let public_values = core_proof.public_values.clone();

        if env::var("COLLECT_SHAPES").is_ok() {
            let mut shapes = BTreeSet::new();
            for proof in core_proof.proof.0.iter() {
                let shape = ZKMProofShape::Recursion(vec![proof.shape()]);
                tracing::info!("shape: {:?}", shape);
                shapes.insert(shape);
            }

            let mut file = File::create("../shapes.bin").unwrap();
            bincode::serialize_into(&mut file, &shapes).unwrap();
        }

        if verify {
            tracing::info!("verify core");
            prover.verify(&core_proof.proof, &vk)?;
        }

        if test_kind == Test::Core {
            return Ok(());
        }

        let core_bytes = bincode::serialize(&core_proof.proof).unwrap();
        tracing::info!("core proof size: {} bytes", core_bytes.len());
        if let Ok(p) = std::env::var("DUMP_CORE_PROOF") {
            std::fs::write(&p, &core_bytes).unwrap();
            tracing::info!("dumped core proof to {}", p);
        }
        tracing::info!("compress");
        let compress_span = tracing::debug_span!("compress").entered();
        let compressed_proof = prover.compress(&vk, core_proof, vec![], opts)?;
        compress_span.exit();
        let compressed_bytes = bincode::serialize(&compressed_proof).unwrap();
        tracing::info!("compressed proof size: {} bytes", compressed_bytes.len());
        if let Ok(p) = std::env::var("DUMP_COMPRESS_PROOF") {
            std::fs::write(&p, &compressed_bytes).unwrap();
            tracing::info!("dumped compress proof to {}", p);
        }

        if verify {
            tracing::info!("verify compressed");
            prover.verify_compressed(&compressed_proof, &vk)?;
        }

        if test_kind == Test::Compress {
            return Ok(());
        }

        tracing::info!("shrink");
        let shrink_proof = prover.shrink(compressed_proof, opts)?;
        tracing::info!("shrink proof size: {} bytes", bincode::serialize(&shrink_proof).unwrap().len());

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

    /// FIX-off MULTI-SHARD compress PROVE + host VERIFY harness.
    /// Loads the fibonacci-1k corpus (program.bin + bincode ZKMStdin
    /// stdin.bin) from FIXOFF_PROGRAM_DIR (default
    /// /data/stephen/ziren-shape-bin/fibonacci-1k), proves core, compresses,
    /// and host-verifies the compressed proof (`verify_compressed`, the
    /// recursion-shard crypto verify that is sensitive to `StackingMismatch`
    /// for sub-stripe FIX-off commits).
    ///
    /// Set `SHARD_SIZE=<small, e.g. 262144>` to force >=2 core shards.  Run:
    ///   FIX_CORE_SHAPES=false FIX_RECURSION_SHAPES=true VERIFY_VK=false \
    ///   ZIREN_HA_NO_FIXSHAPE=1 ZIREN_PROGRAM_CACHE=0 SHARD_SIZE=262144 \
    ///   cargo test -p zkm-prover --release fixoff_multishard_compress_verify \
    ///     -- --ignored --exact --nocapture
    #[test]
    #[serial]
    #[ignore]
    fn fixoff_multishard_compress_verify() -> Result<()> {
        setup_logger();
        let dir = std::env::var("FIXOFF_PROGRAM_DIR")
            .unwrap_or_else(|_| "/data/stephen/ziren-shape-bin/fibonacci-1k".to_string());
        let elf = std::fs::read(format!("{dir}/program.bin")).expect("read program.bin");
        let stdin_bytes = std::fs::read(format!("{dir}/stdin.bin")).expect("read stdin.bin");
        let stdin: ZKMStdin = match bincode::deserialize::<ZKMStdin>(&stdin_bytes) {
            Ok(s) => {
                eprintln!("[FIXOFF-MS] stdin = bincode ZKMStdin ({} bufs)", s.buffer.len());
                s
            }
            Err(_) => {
                eprintln!("[FIXOFF-MS] stdin = raw {} bytes -> write_vec", stdin_bytes.len());
                let mut s = ZKMStdin::new();
                s.write_vec(stdin_bytes);
                s
            }
        };
        let opts = ZKMProverOpts::default();
        eprintln!(
            "[FIXOFF-MS] shard_size={} REDUCE_BATCH_SIZE={} elf_bytes={}",
            opts.core_opts.shard_size,
            REDUCE_BATCH_SIZE,
            elf.len()
        );
        let prover = ZKMProver::<DefaultProverComponents>::new();
        eprintln!("[FIXOFF-MS] vk_verification={}", prover.vk_verification);
        let context = ZKMContext::default();
        let (_, pk_d, program, vk) = prover.setup(&elf);
        eprintln!("[FIXOFF-MS] prove core ...");
        let core_proof = prover.prove_core(&pk_d, program, &stdin, opts, context)?;
        let n_shards = core_proof.proof.0.len();
        eprintln!("[FIXOFF-MS] core shard count = {n_shards}");
        eprintln!("[FIXOFF-MS] verify core ...");
        prover.verify(&core_proof.proof, &vk)?;
        eprintln!("[FIXOFF-MS] core verify OK; compress ...");
        let compressed_proof = prover.compress(&vk, core_proof, vec![], opts)?;
        eprintln!("[FIXOFF-MS] compress done; verify_compressed (THE MILESTONE) ...");

        // NATURAL-HEIGHT report.
        // fix_shape is disabled on the prove path (the program keeps its
        // organic per-(cluster,arity) heights — no band-snap, no floor-pin).
        // Report the ROOT recursion commit's area-derived axes (log_dense_size,
        // area, num_stripes) at their NATURAL value — there is no fixed
        // floor/band to compare against.  dummy==real per (cluster,arity) is
        // asserted directly in the build path via `ZIREN_VERIFY_PROGRAM_CACHE`;
        // this report shows the actual natural area the height-agnostic prove
        // path produced.
        {
            use zkm_pcs::shard_level::shard_proof::EvaluationProof;
            let root_eval_proof = compressed_proof
                .proof
                .basefold_shard_proof
                .as_ref()
                .map(|bsp| &bsp.evaluation_proof);
            if let Some(EvaluationProof::Bundle(b)) = root_eval_proof {
                let lds = b.packing.log_dense_size;
                let flat_evals: usize = b
                    .basefold_proof
                    .batch_evaluations
                    .iter()
                    .map(|r| r.len())
                    .sum();
                let stack = zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize;
                let area = 1usize << lds;
                let num_stripes = area >> stack;
                eprintln!(
                    "[STAGEC-NATURAL] ROOT bundle (natural heights, fix_shape retired): \
                     log_dense_size={lds} area=2^{lds} num_stripes={num_stripes} \
                     flat_batch_evals={flat_evals}"
                );
            } else {
                eprintln!("[STAGEC-NATURAL] ROOT evaluation_proof is NOT a Bundle (Empty?)");
            }
        }

        prover.verify_compressed(&compressed_proof, &vk)?;
        eprintln!(
            "[FIXOFF-MS] *** verify_compressed ACCEPTED *** (n_shards={n_shards})"
        );
        Ok(())
    }

    /// FIX-off MULTI-SHARD FULL inner chain PROVE + host VERIFY through
    /// compress -> shrink -> wrap_bn254 harness.  Same corpus and env as
    /// `fixoff_multishard_compress_verify`, but continues past compress into
    /// shrink (verifies the compress proof) and wrap_bn254 (verifies the
    /// shrink proof), host-verifying each stage.  This is the inner-chain
    /// soundness gate before the vk_map regen.  Returns BEFORE the heavy
    /// PLONK/Groth16 artifact build.
    ///
    /// Set `SHARD_SIZE=<small, e.g. 262144>` to force >=2 core shards.  Run:
    ///   FIX_CORE_SHAPES=false FIX_RECURSION_SHAPES=true VERIFY_VK=false \
    ///   ZIREN_HA_NO_FIXSHAPE=1 ZIREN_PROGRAM_CACHE=0 SHARD_SIZE=262144 \
    ///   cargo test -p zkm-prover --release tests::fixoff_multishard_wrap_verify \
    ///     -- --ignored --exact --nocapture
    #[test]
    #[serial]
    #[ignore]
    fn fixoff_multishard_wrap_verify() -> Result<()> {
        setup_logger();
        let dir = std::env::var("FIXOFF_PROGRAM_DIR")
            .unwrap_or_else(|_| "/data/stephen/ziren-shape-bin/fibonacci-1k".to_string());
        let elf = std::fs::read(format!("{dir}/program.bin")).expect("read program.bin");
        let stdin_bytes = std::fs::read(format!("{dir}/stdin.bin")).expect("read stdin.bin");
        let stdin: ZKMStdin = match bincode::deserialize::<ZKMStdin>(&stdin_bytes) {
            Ok(s) => {
                eprintln!("[FIXOFF-MSW] stdin = bincode ZKMStdin ({} bufs)", s.buffer.len());
                s
            }
            Err(_) => {
                eprintln!("[FIXOFF-MSW] stdin = raw {} bytes -> write_vec", stdin_bytes.len());
                let mut s = ZKMStdin::new();
                s.write_vec(stdin_bytes);
                s
            }
        };
        let opts = ZKMProverOpts::default();
        eprintln!(
            "[FIXOFF-MSW] shard_size={} REDUCE_BATCH_SIZE={} elf_bytes={}",
            opts.core_opts.shard_size,
            REDUCE_BATCH_SIZE,
            elf.len()
        );
        let prover = ZKMProver::<DefaultProverComponents>::new();
        eprintln!("[FIXOFF-MSW] vk_verification={}", prover.vk_verification);
        let context = ZKMContext::default();
        let (_, pk_d, program, vk) = prover.setup(&elf);
        eprintln!("[FIXOFF-MSW] prove core ...");
        let core_proof = prover.prove_core(&pk_d, program, &stdin, opts, context)?;
        let n_shards = core_proof.proof.0.len();
        eprintln!("[FIXOFF-MSW] core shard count = {n_shards}");
        eprintln!("[FIXOFF-MSW] verify core ...");
        prover.verify(&core_proof.proof, &vk)?;
        eprintln!("[FIXOFF-MSW] core verify OK; compress ...");
        let compressed_proof = prover.compress(&vk, core_proof, vec![], opts)?;
        eprintln!("[FIXOFF-MSW] compress done; verify_compressed ...");
        prover.verify_compressed(&compressed_proof, &vk)?;
        eprintln!("[FIXOFF-MSW] *** verify_compressed ACCEPTED *** (n_shards={n_shards})");

        eprintln!("[FIXOFF-MSW] shrink ...");
        let shrink_proof = prover.shrink(compressed_proof, opts)?;
        eprintln!("[FIXOFF-MSW] shrink done; verify_shrink ...");
        prover.verify_shrink(&shrink_proof, &vk)?;
        eprintln!("[FIXOFF-MSW] *** verify_shrink ACCEPTED ***");

        eprintln!("[FIXOFF-MSW] wrap_bn254 ...");
        let wrapped_bn254_proof = prover.wrap_bn254(shrink_proof, opts)?;
        eprintln!("[FIXOFF-MSW] wrap_bn254 done; verify_wrap_bn254 ...");
        prover.verify_wrap_bn254(&wrapped_bn254_proof, &vk).unwrap();
        eprintln!(
            "[FIXOFF-MSW] *** verify_wrap_bn254 ACCEPTED *** FULL INNER CHAIN GREEN (n_shards={n_shards})"
        );
        Ok(())
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
        let a_bytes = bincode::serialize(
            wrap_a.proof.basefold_shard_proof.as_ref().expect("A bundle"),
        )
        .unwrap();
        let b_bytes = bincode::serialize(
            wrap_b.proof.basefold_shard_proof.as_ref().expect("B bundle"),
        )
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
        let (constraints_a, _witness_a) =
            build_constraints_and_witness(&wrap_a.vk, &wrap_a.proof);
        tracing::info!("[VI] built {} constraints from A", constraints_a.len());

        tracing::info!("[VI] build circuit + witness from proof B");
        let (constraints_b, witness_b) =
            build_constraints_and_witness(&wrap_b.vk, &wrap_b.proof);
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

        tracing::info!(
            "[VI] SOLVE circuit_A with witness_B (the value-independence gate)"
        );
        // PlonkBn254Prover::test runs gnark's test.IsSolved — it panics if any
        // constraint (e.g. a baked assertIsEqual) is violated.  Passing proves
        // the A-shaped circuit accepts B's fresh witness ⇒ value-independent.
        PlonkBn254Prover::test(constraints_a, witness_b);
        tracing::info!(
            "[VI] PASS — circuit_A solved by witness_B: outer wrap is VALUE-INDEPENDENT"
        );
        Ok(())
    }

    #[test]
    #[serial]
    #[ignore]
    fn diag_localize_circuit() -> Result<()> {
        setup_logger();
        let path = std::env::var("LOCALIZE_PROOF")
            .unwrap_or_else(|_| "proof-with-pis.bin".to_string());
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("read cached wrap proof {path}: {e}"));
        let wrapped: ZKMReduceProof<OuterSC> =
            bincode::deserialize(&bytes).expect("deserialize cached ZKMReduceProof<OuterSC>");
        let (constraints, witness) =
            build_constraints_and_witness(&wrapped.vk, &wrapped.proof);
        tracing::info!("built outer circuit: {} constraints", constraints.len());
        PlonkBn254Prover::test(constraints, witness);
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
    /// the basefold side channel population path in `prove_shard_to_basefold`
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
        let core_cfg = prover.core_shape_config.as_ref().unwrap_or(&core_cfg_owned);
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
            machine
                .chips()
                .iter()
                .map(|c| (<_ as MachineAir<KoalaBear>>::name(c), c))
                .collect()
        };
        let log_dense_of = |os: &OrderedShape| -> usize {
            let total: usize = os
                .inner
                .iter()
                .map(|(name, log_h)| {
                    let w = chips_by_name
                        .get(name)
                        .map(|c| p3_air::BaseAir::<KoalaBear>::width(*c).max(1))
                        .unwrap_or(1);
                    w * (1usize << *log_h)
                })
                .sum();
            if total == 0 { 0 } else { total.next_power_of_two().trailing_zeros() as usize }
        };

        // Use the first real core shard.
        let real_sp = &core_proof.proof.0[0];
        let real_os = real_sp.shape();
        let mut real_names: Vec<String> = real_os.inner.iter().map(|(n, _)| n.clone()).collect();
        real_names.sort();
        let real_ld = log_dense_of(&real_os);

        // Find the enumerated per-shard shape of the SAME (chip_set, log_dense) class.
        let enum_os = enum_norm
            .iter()
            .find(|e| {
                let mut en: Vec<String> = e.inner.iter().map(|(n, _)| n.clone()).collect();
                en.sort();
                en == real_names && log_dense_of(e) == real_ld
            })
            .cloned();
        let enum_os = match enum_os {
            Some(e) => e,
            None => {
                panic!(
                    "[ARITY-REPR] real shard (chip_set, log_dense={real_ld}) class NOT enumerated \
                     — enumeration gap"
                );
            }
        };
        eprintln!(
            "[ARITY-REPR] real_ld={real_ld} real_chips={} enum_ld={} enum_matched=true",
            real_names.len(),
            log_dense_of(&enum_os),
        );

        // For each arity 1..=REDUCE_BATCH_SIZE: real-replicated vs enumerated-rep.
        let real_bf = *real_sp
            .basefold_shard_proof
            .as_ref()
            .expect("real shard carries basefold side channel")
            .clone();
        for arity in 1..=REDUCE_BATCH_SIZE {
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
            let enum_shape = ZKMRecursionShape {
                proof_shapes: vec![enum_os.clone(); arity],
                is_complete: true,
            };
            let enum_dummy = ZKMCoreBasefoldWitnessValues::dummy(machine, &enum_shape);
            let prog_enum = prover.recursion_program_basefold(&enum_dummy);
            let vk_enum = prover.compress_prover.setup(&prog_enum).1.hash_koalabear();

            let eq = vk_real == vk_enum;
            eprintln!(
                "[ARITY-REPR] arity={arity}: enum_repr_reproduces_real={eq} \
                 vk_real={:?} vk_enum={:?}",
                vk_real.map(|x| { use p3_field::PrimeField32; x.as_canonical_u32() }),
                vk_enum.map(|x| { use p3_field::PrimeField32; x.as_canonical_u32() }),
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

    /// VK-equality check: does the ENUMERATION dummy normalize program
    /// (built from `dummy(machine, shape)`) reproduce the PROVE-PATH normalize
    /// VK (built from the real fib core proof)?  If equal → the only gap is
    /// that the real shape isn't enumerated (fix = enumerate the right shapes).
    /// If not → the dummy reconstruction diverges from the real program.
    #[test]
    #[serial]
    #[ignore]
    fn test_vk_equality_normalize_fib() -> Result<()> {
        setup_logger();
        let elf = test_artifacts::FIBONACCI_ELF;
        let opts = ZKMProverOpts::default();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let context = ZKMContext::default();
        let (_, pk_d, program, vk) = prover.setup(elf);
        let core_proof = prover.prove_core(&pk_d, program, &ZKMStdin::default(), opts, context)?;
        let inputs = prover
            .get_recursion_core_inputs_basefold(&vk.vk, &core_proof.proof.0, REDUCE_BATCH_SIZE, true)
            .expect("basefold core inputs");
        let machine = prover.core_prover.machine();
        for (i, (input, batch)) in inputs
            .iter()
            .zip(core_proof.proof.0.chunks(REDUCE_BATCH_SIZE))
            .enumerate()
        {
            let prog_real = prover.recursion_program_basefold(input);
            let vk_real = prover.compress_prover.setup(&prog_real).1.hash_koalabear();
            // The real shape, taken from the original core ShardProofs in this batch.
            let shape = ZKMRecursionShape {
                proof_shapes: batch.iter().map(|sp| sp.shape()).collect(),
                is_complete: input.is_complete,
            };
            let mut dummy = ZKMCoreBasefoldWitnessValues::dummy(machine, &shape);
            // [PROBE-BUNDLE] decisive cheap experiment: overwrite the dummy's
            // evaluation_proof with the REAL one. If EQUAL becomes true, then
            // (a) the bundle was the only remaining divergence and (b) whether
            // a zero-bundle can ever match depends on whether the lift bakes
            // bundle VALUES (builder.constant) vs witnesses them. Gated by env
            // so the normal run is unaffected.
            if std::env::var("PROBE_CLONE_BUNDLE").is_ok() {
                let zero_vals = std::env::var("PROBE_ZERO_SCALARS").is_ok();
                for (di, sp_real) in input.shard_proofs.iter().enumerate() {
                    if let Some(d) = dummy.shard_proofs.get_mut(di) {
                        let mut ep = sp_real.evaluation_proof.clone();
                        if zero_vals {
                            use zkm_pcs::shard_level::shard_proof::EvaluationProof;
                            if let EvaluationProof::Bundle(bd) = &mut ep {
                                use p3_field::PrimeCharacteristicRing;
                                type EF = zkm_pcs::InnerChallenge;
                                // Zero every EF/F scalar value in place, keeping
                                // all vec lengths. If the resulting program is
                                // byte-identical to the real-value clone → the
                                // program is value-INDEPENDENT (witnessed) and a
                                // zero dummy bundle will work.
                                for r in bd.reduction.rounds.iter_mut() { r.evals = [EF::ZERO; 3]; }
                                bd.reduction.eval_point.iter_mut().for_each(|x| *x = EF::ZERO);
                                bd.reduction.q_at_z = EF::ZERO;
                                let bf = &mut bd.basefold_proof.basefold_proof;
                                bf.univariate_messages.iter_mut().for_each(|m| *m = [EF::ZERO; 2]);
                                bf.final_poly = EF::ZERO;
                                for mo in bf.component_polynomials_query_openings_and_proofs.iter_mut() {
                                    for l in mo.leaves.iter_mut() {
                                        for v in l.values.iter_mut() { v.iter_mut().for_each(|x| *x = zkm_pcs::InnerVal::ZERO); }
                                    }
                                }
                                for mo in bf.query_phase_openings_and_proofs.iter_mut() {
                                    for l in mo.leaves.iter_mut() {
                                        for v in l.values.iter_mut() { v.iter_mut().for_each(|x| *x = zkm_pcs::InnerVal::ZERO); }
                                    }
                                }
                                for r in bd.basefold_proof.batch_evaluations.iter_mut() { r.iter_mut().for_each(|x| *x = EF::ZERO); }
                                for c in bd.y_per_chip.iter_mut() { c.iter_mut().for_each(|x| *x = EF::ZERO); }
                                let jp = &mut bd.jagged_eval.partial_sumcheck_proof;
                                jp.claimed_sum = EF::ZERO;
                                jp.point_and_eval.1 = EF::ZERO;
                                jp.point_and_eval.0.iter_mut().for_each(|x| *x = EF::ZERO);
                                for up in jp.univariate_polys.iter_mut() { up.coefficients.iter_mut().for_each(|x| *x = EF::ZERO); }
                                bd.packing.offsets.iter_mut().for_each(|x| *x = 0);
                                bd.packing.total_values = 0;
                            }
                        }
                        d.evaluation_proof = ep;
                    }
                }
            }
            let prog_dummy = prover.recursion_program_basefold(&dummy);
            let vk_dummy = prover.compress_prover.setup(&prog_dummy).1.hash_koalabear();
            let rb = bincode::serialize(&*prog_real).unwrap();
            let db = bincode::serialize(&*prog_dummy).unwrap();
            let first_diff = rb.iter().zip(db.iter()).position(|(a, b)| a != b);
            eprintln!(
                "[VKEQ] input {i}: EQUAL={} | prog_bytes real={} dummy={} first_diff_at={:?} | vk_real={:?} vk_dummy={:?}",
                vk_real == vk_dummy, rb.len(), db.len(), first_diff, vk_real, vk_dummy,
            );
            // program-bytes divergence localizer: measure the divergent region
            // via the longest common suffix, and dump the real-only bytes there.
            if let Some(fd) = first_diff {
                let common_suffix =
                    rb.iter().rev().zip(db.iter().rev()).position(|(a, b)| a != b).unwrap_or(0);
                let re = rb.len() - common_suffix;
                let de = db.len() - common_suffix;
                eprintln!(
                    "[VKEQ-DIFF] first_diff={fd} common_suffix={common_suffix} | real_divergent=[{fd}..{re}] ({}B) dummy_divergent=[{fd}..{de}] ({}B)",
                    re.saturating_sub(fd), de.saturating_sub(fd),
                );
                let r_end = re.min(fd + 120);
                let d_end = de.min(fd + 120);
                eprintln!("[VKEQ-DIFF] real[{fd}..{r_end}]={:?}", &rb[fd..r_end]);
                eprintln!("[VKEQ-DIFF] dummy[{fd}..{d_end}]={:?}", &db[fd..d_end]);
            }
            // instruction-level localizer: counts + first differing instr.
            {
                let ri: Vec<_> = prog_real.iter_instructions().collect();
                let di: Vec<_> = prog_dummy.iter_instructions().collect();
                eprintln!(
                    "[VKEQ-INSTR] real_instrs={} dummy_instrs={} (delta={}) total_mem real={} dummy={}",
                    ri.len(), di.len(), ri.len() as i64 - di.len() as i64,
                    prog_real.total_memory, prog_dummy.total_memory,
                );
                let n = ri.len().min(di.len());
                let mut shown = 0;
                let mut first_diff_idx = None;
                for k in 0..n {
                    if format!("{:?}", ri[k]) != format!("{:?}", di[k]) {
                        if first_diff_idx.is_none() {
                            first_diff_idx = Some(k);
                        }
                        eprintln!("[VKEQ-INSTR] diff@{k}: real={:?} | dummy={:?}", ri[k], di[k]);
                        shown += 1;
                        if shown >= 16 {
                            break;
                        }
                    }
                }
                // Show the real-only tail instructions (the 9 extra) — print the
                // last 20 real instrs that the dummy lacks.
                if ri.len() > di.len() {
                    let tail_start = di.len();
                    for k in tail_start..ri.len().min(tail_start + 20) {
                        eprintln!("[VKEQ-INSTR] real-only tail@{k}: {:?}", ri[k]);
                    }
                }
                // ZKM_DEBUG=1: per-instruction backtraces are captured (traces[k]
                // parallel to iter_instructions; None for the leading const
                // block).  Print the backtrace of the first differing instruction
                // that HAS a trace (the first differing COMPUTED instr) — names
                // the exact source line that bakes the divergent value.
                let rtr = &prog_real.traces;
                // ALIGN: real has `delta` extra instructions inserted at the
                // instruction-level first_diff.  Find that fd, verify the shift,
                // and print ONLY the real-only inserted instructions (with
                // resolved backtraces) — the true divergence.
                let delta = ri.len().saturating_sub(di.len());
                let mut ifd = None;
                for k in 0..n {
                    if format!("{:?}", ri[k]) != format!("{:?}", di[k]) {
                        ifd = Some(k);
                        break;
                    }
                }
                if let (Some(fd), true) = (ifd, delta > 0) {
                    let resync = (fd + 10..di.len()).take(50).all(|j| {
                        format!("{:?}", ri[j + delta]) == format!("{:?}", di[j])
                    });
                    eprintln!("[VKEQ-ALIGN] instr_first_diff={fd} delta={delta} resync_shift_ok={resync}");
                    for off in 0..delta.min(12) {
                        let k = fd + off;
                        let frame = rtr.get(k).and_then(|t| t.as_ref()).map(|bt| {
                            let mut b = bt.clone();
                            b.resolve();
                            let s = format!("{:?}", b);
                            s.lines()
                                .find(|l| l.contains("recursion/circuit/src/machine"))
                                .unwrap_or("(no circuit frame)")
                                .trim()
                                .to_string()
                        }).unwrap_or_else(|| "(const, no trace)".to_string());
                        eprintln!("[VKEQ-INS] real-only@{k}: {} | {:?}", frame, ri[k]);
                    }
                    // For each real-only const Mem-Write, find its READER (the
                    // instruction that consumes that address) and backtrace it —
                    // names the verifier line that BAKES the per-chip eval.
                    for off in 0..delta.min(12) {
                        let k = fd + off;
                        let s = format!("{:?}", ri[k]);
                        // extract "inner: Address(N)" of the write
                        if let Some(addr) = s
                            .split("inner: Address(")
                            .nth(1)
                            .and_then(|t| t.split(')').next())
                            .and_then(|t| t.parse::<usize>().ok())
                        {
                            let needle = format!("Address({addr})");
                            for j in k + 1..ri.len() {
                                let rs = format!("{:?}", ri[j]);
                                if rs.contains(&needle) && !rs.contains("kind: Write") {
                                    let frame = rtr.get(j).and_then(|t| t.as_ref()).map(|bt| {
                                        let mut b = bt.clone();
                                        b.resolve();
                                        let fs = format!("{:?}", b);
                                        fs.lines()
                                            .find(|l| l.contains("recursion/circuit/src"))
                                            .unwrap_or("(no circuit frame)")
                                            .trim()
                                            .to_string()
                                    }).unwrap_or_else(|| "(no trace)".to_string());
                                    eprintln!("[VKEQ-RDR] const@{addr} read by instr{j}: {} | {:?}", frame, ri[j]);
                                    break;
                                }
                            }
                        }
                    }
                }
                let mut bt_shown = 0;
                for k in 0..n {
                    if false && format!("{:?}", ri[k]) != format!("{:?}", di[k]) {
                        if let Some(Some(bt)) = rtr.get(k) {
                            let mut bt2 = bt.clone();
                            bt2.resolve();
                            let s = format!("{:?}", bt2);
                            let frame = s
                                .lines()
                                .find(|l| l.contains("recursion/circuit/src/machine"))
                                .unwrap_or("(no circuit frame)");
                            eprintln!("[VKEQ-BT] @instr{k}: {} | {:?}", frame.trim(), ri[k]);
                            bt_shown += 1;
                            if bt_shown >= 10 {
                                break;
                            }
                        }
                    }
                }
                eprintln!("[VKEQ-BT] traces.len()={} (0 = ZKM_DEBUG not set)", rtr.len());
                // Find the const VALUE feeding the differing DivF/SubF denominator
                // (and the in1 operands) — a recognizable constant names the op.
                for k in first_diff_idx.unwrap_or(0).saturating_sub(2)
                    ..ri.len().min(first_diff_idx.unwrap_or(0) + 6)
                {
                    eprintln!("[VKEQ-CTX] real instr@{k}: {:?}", ri[k]);
                }
                // Resolve the value written to each operand/denominator address.
                for target in [73usize, 157623usize] {
                    for k in 0..ri.len() {
                        let s = format!("{:?}", ri[k]);
                        if s.contains(&format!("inner: Address({target}) }}"))
                            && s.contains("Write")
                        {
                            eprintln!("[VKEQ-CTX] value written to Address({target}): {s}");
                            break;
                        }
                    }
                }
            }
            for (tag, sp) in [("REAL", &input.shard_proofs[0]), ("DUMMY", &dummy.shard_proofs[0])] {
                let qd: Vec<(usize, usize, i32)> = sp
                    .opened_values
                    .chips
                    .iter()
                    .map(|c| {
                        (c.quotient.len(), c.quotient.first().map(|q| q.len()).unwrap_or(0), c.log_degree as i32)
                    })
                    .collect();
                eprintln!("[VKEQ-OV] {tag} (quot_outer,quot_inner0,log_deg) per chip={:?}", qd);
            }
            {
                use zkm_pcs::shard_level::shard_proof::EvaluationProof;
                if let (EvaluationProof::Bundle(rbd), EvaluationProof::Bundle(dbd)) = (
                    &input.shard_proofs[0].evaluation_proof,
                    &dummy.shard_proofs[0].evaluation_proof,
                ) {
                    let ro = &rbd.packing.offsets;
                    let dof = &dbd.packing.offsets;
                    let mism: Vec<(usize, usize, usize)> = ro
                        .iter()
                        .zip(dof.iter())
                        .enumerate()
                        .filter(|(_, (a, b))| a != b)
                        .map(|(i, (a, b))| (i, *a, *b))
                        .take(12)
                        .collect();
                    eprintln!(
                        "[VKEQ-OFF] offsets real.len={} dummy.len={} total_real={} total_dummy={} n_mismatch={} first={:?}",
                        ro.len(), dof.len(), rbd.packing.total_values, dbd.packing.total_values,
                        ro.iter().zip(dof.iter()).filter(|(a, b)| a != b).count(), mism,
                    );
                    // y_per_chip dims (real has 22, dummy 0 — check if it's witnessed)
                    eprintln!(
                        "[VKEQ-OFF] y_per_chip real outer={} inner0={} | reduction.q_at_z r={:?}",
                        rbd.y_per_chip.len(),
                        rbd.y_per_chip.first().map(|v| v.len()).unwrap_or(0),
                        rbd.reduction.q_at_z,
                    );
                }
            }
            eprintln!("[VKEQ] input {i} real shape={:?}", shape);
            {
                use zkm_pcs::shard_level::shard_proof::EvaluationProof;
                for (tag, sp) in
                    [("REAL", &input.shard_proofs[0]), ("DUMMY", &dummy.shard_proofs[0])]
                {
                    let ep = match &sp.evaluation_proof {
                        EvaluationProof::Empty => "Empty".to_string(),
                        EvaluationProof::Bytes(b) => format!("Bytes(len={})", b.len()),
                        EvaluationProof::Bundle(bd) => format!(
                            "Bundle(offsets={} total_values={} log_dense={} jagged_pt={})",
                            bd.packing.offsets.len(),
                            bd.packing.total_values,
                            bd.packing.log_dense_size,
                            bd.jagged_eval.partial_sumcheck_proof.point_and_eval.0.len(),
                        ),
                    };
                    eprintln!(
                        "[VKEQ] input {i} {tag} dims: gkr_rounds={} zerocheck_rounds={} opened_chips={} evalproof={}",
                        sp.logup_gkr_proof.round_proofs.len(),
                        sp.zerocheck_proof.univariate_polys.len(),
                        sp.opened_values.chips.len(),
                        ep,
                    );
                    let gkr_dims: Vec<usize> = sp
                        .logup_gkr_proof
                        .round_proofs
                        .iter()
                        .map(|r| r.sumcheck_proof.univariate_polys.len())
                        .collect();
                    eprintln!("[VKEQ] input {i} {tag} gkr per-round sumcheck dims={gkr_dims:?}");
                    // Full BaseFold bundle dim dump (ground truth for the
                    // dummy_jagged_basefold_bundle construction).
                    if let EvaluationProof::Bundle(bd) = &sp.evaluation_proof {
                        let bf = &bd.basefold_proof.basefold_proof;
                        let comp_paths: Vec<usize> = bf
                            .component_polynomials_query_openings_and_proofs
                            .iter()
                            .flat_map(|mo| mo.leaves.iter().map(|l| l.proof.len()))
                            .take(3)
                            .collect();
                        let query_round_lens: Vec<(usize, usize)> = bf
                            .query_phase_openings_and_proofs
                            .iter()
                            .map(|mo| (mo.leaves.len(), mo.leaves.first().map(|l| l.proof.len()).unwrap_or(0)))
                            .collect();
                        let comp_leaf_val_dims: Vec<(usize, usize)> = bf
                            .component_polynomials_query_openings_and_proofs
                            .iter()
                            .map(|mo| (mo.leaves.len(), mo.leaves.first().map(|l| l.values.len()).unwrap_or(0)))
                            .collect();
                        let batch_evals: Vec<usize> = bd.basefold_proof.batch_evaluations.iter().map(|v| v.len()).collect();
                        eprintln!(
                            "[VKEQ-BUNDLE] {tag}: uni_msgs={} fri_commits={} comp_openings_outer={} comp_leaf(len,valdim)={:?} query_rounds={} query_round(leaves,pathlen)={:?} comp_pathlens(first3)={:?} batch_evals={:?} reduction_rounds={} reduction_evalpt={} jagged_uni_polys={} jagged_pt={} cols={} log_stack={} offsets={} chip_dims={} y_per_chip={} red_poly_coeffs={:?} jag_poly_coeffs={:?}",
                            bf.univariate_messages.len(),
                            bf.fri_commitments.len(),
                            bf.component_polynomials_query_openings_and_proofs.len(),
                            comp_leaf_val_dims,
                            bf.query_phase_openings_and_proofs.len(),
                            query_round_lens,
                            comp_paths,
                            batch_evals,
                            bd.reduction.rounds.len(),
                            bd.reduction.eval_point.len(),
                            bd.jagged_eval.partial_sumcheck_proof.univariate_polys.len(),
                            bd.jagged_eval.partial_sumcheck_proof.point_and_eval.0.len(),
                            bd.packing.column_counts.len(),
                            bd.commit.log_stacking_height,
                            bd.packing.offsets.len(),
                            format!("{:?}", bd.commit.chip_dims),
                            bd.y_per_chip.len(),
                            bd.reduction.rounds.first().map(|_| 3),
                            bd.jagged_eval.partial_sumcheck_proof.univariate_polys.first().map(|p| p.coefficients.len()),
                        );
                    }
                }
            }

            // ===== VKROOT decisive check: map membership + shape coverage =====
            // vk_real is the production normalize/compress vk for this batch
            // (for fib arity-1 single shard this IS the final compressed-proof
            // vk that verify_compressed checks at verify.rs:323).
            let in_map = prover.recursion_vk_map.contains_key(&vk_real);
            eprintln!(
                "[VKROOT] input {i}: vk_real in recursion_vk_map = {in_map} (map_size={})",
                prover.recursion_vk_map.len()
            );
            // Is fib's real per-shard core shape among the enumerated Recursion
            // (small) shapes that build_vk_map walks?  If NOT => coverage gap:
            // the normalize program for this shape was never enumerated, so its
            // vk can never be in the map regardless of value-independence.
            {
                use crate::shapes::ZKMProofShape;
                use zkm_pcs::shape::OrderedShape;
                let core_cfg = prover.core_shape_config.as_ref().unwrap();
                let rec_cfg = prover.compress_shape_config.as_ref().unwrap();
                let enum_rec: std::collections::BTreeSet<OrderedShape> =
                    ZKMProofShape::generate(core_cfg, rec_cfg, REDUCE_BATCH_SIZE)
                        .flat_map(|s| match s {
                            // Flatten the per-shard shapes of each arity batch
                            // (per-shard membership semantics for this probe).
                            ZKMProofShape::Recursion(batch) => batch,
                            _ => Vec::new(),
                        })
                        .collect();
                eprintln!("[VKROOT] enumerated Recursion per-shard shapes: {}", enum_rec.len());
                for (j, sp) in batch.iter().enumerate() {
                    let real_shape = sp.shape();
                    let member = enum_rec.contains(&real_shape);
                    eprintln!(
                        "[VKROOT] input {i} shard {j}: real_core_shape member_of_enumerated={member}"
                    );
                    if !member {
                        eprintln!("[VKROOT]   real_core_shape = {real_shape:?}");
                        // Show the closest enumerated shapes (same chip set).
                        let real_names: std::collections::BTreeSet<&String> =
                            real_shape.inner.iter().map(|(n, _)| n).collect();
                        for es in enum_rec.iter() {
                            let es_names: std::collections::BTreeSet<&String> =
                                es.inner.iter().map(|(n, _)| n).collect();
                            if es_names == real_names {
                                eprintln!("[VKROOT]   same-chipset enumerated = {es:?}");
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// MULTISHARD NORMALIZE arity harness.  Proves a small program at a
    /// reduced SHARD_SIZE so it splits into >=2 core shards, then for each
    /// REDUCE_BATCH_SIZE batch:
    ///   (1) builds the REAL normalize VK from the batch's basefold inputs,
    ///   (2) builds the DUMMY normalize VK from `ZKMCoreBasefoldWitnessValues::dummy`
    ///       fed the FULL batch shape (proof_shapes = batch.map(shape)),
    ///   (3) asserts vk_real == vk_dummy (proves the dummy is FAITHFUL at the
    ///       batch's arity — the per-shard bundle reconstruction is correct;
    ///       any gap is purely enumeration coverage of the ARITY dimension).
    /// Also probes whether two arity-N normalize programs with DIFFERENT
    /// per-shard shape mixes collapse to the SAME vk after fix_shape — which
    /// decides whether the enumeration fix needs per-arity combinations or just
    /// one canonical shape per arity.
    ///
    /// Run: SHARD_SIZE=<small> cargo test -p zkm-prover --release \
    ///   multishard_normalize_arity_faithful -- --ignored --nocapture
    #[test]
    #[serial]
    #[ignore]
    fn multishard_normalize_arity_faithful() -> Result<()> {
        use crate::shapes::ZKMProofShape;
        use zkm_pcs::shape::OrderedShape;
        setup_logger();
        // Default: small SHA2_ELF (SHARD_SIZE env forces a split if large enough).
        // Override SHA2_PROGRAM_BIN=<elf> + SHA2_STDIN_BIN=<stdin> to reproduce the
        // real 18-shard sha2-1mb workload (the decisive multishard case).
        let elf_owned: Vec<u8> = match std::env::var("SHA2_PROGRAM_BIN") {
            Ok(p) => std::fs::read(&p).expect("read SHA2_PROGRAM_BIN"),
            Err(_) => test_artifacts::SHA2_ELF.to_vec(),
        };
        let elf: &[u8] = &elf_owned;
        let stdin: ZKMStdin = match std::env::var("SHA2_STDIN_BIN") {
            Ok(p) => {
                let bytes = std::fs::read(&p).expect("read SHA2_STDIN_BIN");
                // Try ZKMStdin bincode first; fall back to a single raw input vec.
                match bincode::deserialize::<ZKMStdin>(&bytes) {
                    Ok(s) => {
                        eprintln!("[MSNORM] loaded stdin as bincode ZKMStdin ({} bufs)", s.buffer.len());
                        s
                    }
                    Err(_) => {
                        eprintln!("[MSNORM] loaded stdin as raw {} bytes -> write_vec", bytes.len());
                        let mut s = ZKMStdin::new();
                        s.write_vec(bytes);
                        s
                    }
                }
            }
            Err(_) => ZKMStdin::default(),
        };
        let opts = ZKMProverOpts::default();
        eprintln!(
            "[MSNORM] shard_size={} REDUCE_BATCH_SIZE={} elf_bytes={}",
            opts.core_opts.shard_size, REDUCE_BATCH_SIZE, elf.len()
        );
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let context = ZKMContext::default();
        let (_, pk_d, program, vk) = prover.setup(elf);
        let core_proof = prover.prove_core(&pk_d, program, &stdin, opts, context)?;
        let n_shards = core_proof.proof.0.len();
        eprintln!("[MSNORM] core shard count = {n_shards}");
        let inputs = prover
            .get_recursion_core_inputs_basefold(&vk.vk, &core_proof.proof.0, REDUCE_BATCH_SIZE, true)
            .expect("basefold core inputs");
        let machine = prover.core_prover.machine();

        // Enumerated normalize shapes (whole batch, so we can inspect
        // arity) — what build_compress_vks walks.  `ZKMProofShape::Recursion`
        // carries Vec<OrderedShape> (the batch); generate() emits arity
        // 1..=REDUCE_BATCH_SIZE.
        // With FIX_CORE_SHAPES=false the prover's `core_shape_config` is None,
        // so build a local default for the enumeration probe AND the band-cap
        // lift.  The band-cap config is the SAME `CoreShapeConfig::default()`
        // the prover uses to pad the real jagged commit, so the dummy built at
        // this band-cap must reproduce the real proof's jagged shape (= the
        // gate).
        let core_cfg_owned = CoreShapeConfig::<KoalaBear>::default();
        let rec_cfg_owned = RecursionShapeConfig::<KoalaBear, CompressAir<KoalaBear>>::default();
        let core_cfg = prover.core_shape_config.as_ref().unwrap_or(&core_cfg_owned);
        let rec_cfg = prover.compress_shape_config.as_ref().unwrap_or(&rec_cfg_owned);
        let band_cap_cfg = CoreShapeConfig::<KoalaBear>::default();
        // HEIGHT-AGNOSTIC RECURSION: lift a raw per-shard
        // `sp.shape()` (= the proof's `opened_values` chip-set, present chips at
        // RAW STARK heights) to the FULL canonical CLUSTER shape the FIX-off
        // jagged COMMIT actually packed — the SAME shape the prover computes via
        // `CoreShapeConfig::find_canonical_cluster_shape` at the band-cap install
        // site (chip-SET + per-chip band-cap heights, incl. the missing
        // event-driven chips).  The dummy bundle is packed from THIS shape, so
        // `vk_dummy == vk_real` (the real proof's normalize VK equals the
        // FIX-on canonical cluster VK).  Falls back to the raw shape if no
        // cluster fits (then dummy_faithful would flag the mismatch, not hide it).
        let lift_to_band_cap = |os: &OrderedShape| -> OrderedShape {
            match band_cap_cfg.find_canonical_cluster_shape_from_ordered(os) {
                Some(shape) => OrderedShape {
                    inner: shape.iter().map(|(id, h)| (id.to_string(), *h)).collect(),
                },
                None => os.clone(),
            }
        };
        let enum_batches: Vec<Vec<OrderedShape>> =
            ZKMProofShape::generate(core_cfg, rec_cfg, REDUCE_BATCH_SIZE)
                .filter_map(|s| match s {
                    ZKMProofShape::Recursion(batch) => Some(batch),
                    _ => None,
                })
                .collect();
        // All per-shard shapes that appear in ANY enumerated batch.
        let enum_norm: std::collections::BTreeSet<OrderedShape> =
            enum_batches.iter().flat_map(|b| b.iter().cloned()).collect();
        // Arities the enumeration covers for normalize (now {1,2,3,4}).
        let enum_arities: std::collections::BTreeSet<usize> =
            enum_batches.iter().map(|b| b.len()).collect();
        eprintln!(
            "[MSNORM] enumerated normalize: {} batches, {} distinct per-shard shapes, arities present={:?}",
            enum_batches.len(),
            enum_norm.len(),
            enum_arities
        );

        // Cheap log_dense (matches generate()'s dedup key) so we can
        // construct the ENUMERATED REPRESENTATIVE batch for a real batch
        // and assert its VK == the real VK.
        let chips_by_name: std::collections::BTreeMap<String, _> = {
            use zkm_pcs::air::MachineAir;
            machine
                .chips()
                .iter()
                .map(|c| (<_ as MachineAir<KoalaBear>>::name(c), c))
                .collect()
        };
        let log_dense_of = |os: &OrderedShape| -> usize {
            let total: usize = os
                .inner
                .iter()
                .map(|(name, log_h)| {
                    let w = chips_by_name
                        .get(name)
                        .map(|c| p3_air::BaseAir::<KoalaBear>::width(*c).max(1))
                        .unwrap_or(1);
                    w * (1usize << *log_h)
                })
                .sum();
            if total == 0 { 0 } else { total.next_power_of_two().trailing_zeros() as usize }
        };
        // Index enumerated batches by their (per-shard (chip_set, log_dense)) key
        // so we can look up the representative for any real batch.
        let batch_class_key = |batch: &[OrderedShape]| -> Vec<(Vec<String>, usize)> {
            batch
                .iter()
                .map(|os| {
                    let mut names: Vec<String> = os.inner.iter().map(|(n, _)| n.clone()).collect();
                    names.sort();
                    (names, log_dense_of(os))
                })
                .collect()
        };
        let enum_class_keys: std::collections::BTreeSet<Vec<(Vec<String>, usize)>> =
            enum_batches.iter().map(|b| batch_class_key(b)).collect();

        let mut all_faithful = true;
        // DECISIVE arity-enum tracking: does the enumerated representative
        // batch reproduce each real batch's normalize VK?  None = the class
        // overflowed (log_dense>30, catch_unwound by build_compress_vks).
        let mut all_enum_repr_eq = true;
        let mut any_multishard_checked = false;
        // Collect (arity -> first vk) to detect arity-N vk collapse across mixes.
        let mut per_arity_vks: std::collections::BTreeMap<usize, Vec<[KoalaBear; 8]>> =
            std::collections::BTreeMap::new();
        for (i, (input, batch)) in inputs
            .iter()
            .zip(core_proof.proof.0.chunks(REDUCE_BATCH_SIZE))
            .enumerate()
        {
            let arity = input.shard_proofs.len();
            let prog_real = prover.recursion_program_basefold(input);
            let vk_real = prover.compress_prover.setup(&prog_real).1.hash_koalabear();

            // The real proof's jagged commit is padded to the per-chip
            // CLUSTER band-cap, so the dummy must be built at the
            // SAME band-cap shape (NOT the raw sp.shape()) for vk_real ==
            // vk_dummy.  This is the unfakeable gate: an own-height/next_pow2
            // dummy (raw sp.shape()) would FAIL under FIX_CORE_SHAPES=false.
            // ANTI-SHORTCUT PROBE: MSNORM_NO_LIFT=1 builds the dummy at the
            // RAW sp.shape() (own-height) instead of the band-cap.  Under
            // FIX_CORE_SHAPES=false this MUST FAIL (real bundle is padded to
            // band-cap, raw dummy is not) — proving the gate detects the pad.
            let no_lift = std::env::var("MSNORM_NO_LIFT").is_ok();
            let real_shape = ZKMRecursionShape {
                proof_shapes: batch
                    .iter()
                    .map(|sp| {
                        if no_lift {
                            sp.shape()
                        } else {
                            lift_to_band_cap(&sp.shape())
                        }
                    })
                    .collect(),
                is_complete: input.is_complete,
            };
            let dummy = ZKMCoreBasefoldWitnessValues::dummy(machine, &real_shape);

            // ── BUNDLE-STRUCTURE COMPARE: real input bundle vs dummy bundle
            //    (per-shard, shard 0).  Prints every length the in-circuit
            //    verifier loops over, to localize the 46872-instr divergence. ──
            {
                use zkm_pcs::shard_level::shard_proof::EvaluationProof;
                let describe = |tag: &str, ep: &EvaluationProof| {
                    if let EvaluationProof::Bundle(b) = ep {
                        let bf = &b.basefold_proof.basefold_proof;
                        let qph: Vec<usize> = bf
                            .query_phase_openings_and_proofs
                            .iter()
                            .map(|mo| mo.leaves.first().map(|l| l.proof.len()).unwrap_or(0))
                            .collect();
                        let qph_leaves: Vec<usize> = bf
                            .query_phase_openings_and_proofs
                            .iter()
                            .map(|mo| mo.leaves.len())
                            .collect();
                        let comp_rounds = bf.component_polynomials_query_openings_and_proofs.len();
                        let comp_paths: Vec<usize> = bf
                            .component_polynomials_query_openings_and_proofs
                            .iter()
                            .map(|mo| mo.leaves.first().map(|l| l.proof.len()).unwrap_or(0))
                            .collect();
                        let comp_vals: Vec<usize> = bf
                            .component_polynomials_query_openings_and_proofs
                            .iter()
                            .map(|mo| mo.leaves.first().map(|l| l.values.first().map(|v| v.len()).unwrap_or(0)).unwrap_or(0))
                            .collect();
                        let batch_ev: Vec<usize> = b.basefold_proof.batch_evaluations.iter().map(|r| r.len()).collect();
                        eprintln!(
                            "[MSNORM-BUNDLE] {tag}: fri_commits={} uni_msgs={} qph_rounds={} qph_pathlens={:?} \
                             qph_leaves={:?} comp_rounds={comp_rounds} comp_pathlens={:?} comp_vallens={:?} \
                             batch_ev={:?} | log_stacking_height={} | reduction.rounds={} eval_point={} \
                             jagged_eval_pt={} | packing.total_values={} log_dense={} offsets={} col_counts.len={}",
                            bf.fri_commitments.len(),
                            bf.univariate_messages.len(),
                            bf.query_phase_openings_and_proofs.len(),
                            qph, qph_leaves, comp_paths, comp_vals, batch_ev,
                            b.commit.log_stacking_height,
                            b.reduction.rounds.len(),
                            b.reduction.eval_point.len(),
                            b.jagged_eval.partial_sumcheck_proof.point_and_eval.0.len(),
                            b.packing.total_values,
                            b.packing.log_dense_size,
                            b.packing.offsets.len(),
                            b.packing.column_counts.len(),
                        );
                    } else {
                        eprintln!("[MSNORM-BUNDLE] {tag}: NOT a Bundle ({:?} variant)", std::mem::discriminant(ep));
                    }
                };
                describe("REAL ", &input.shard_proofs[0].evaluation_proof);
                describe("DUMMY", &dummy.shard_proofs[0].evaluation_proof);
            }

            let prog_dummy = prover.recursion_program_basefold(&dummy);
            let vk_dummy = prover.compress_prover.setup(&prog_dummy).1.hash_koalabear();

            // STAGE1-DIAG: print the recursion VK chip_information (name, width,
            // log_height) for real vs dummy so we can localize what residually
            // makes the recursion VK differ after the height-loop drop.
            if std::env::var("STAGE1_DIAG").is_ok() {
                let vk_real_full = prover.compress_prover.setup(&prog_real).1;
                let vk_dummy_full = prover.compress_prover.setup(&prog_dummy).1;
                let fmt_ci = |vk: &zkm_pcs::StarkVerifyingKey<InnerSC>| -> Vec<(String, usize, usize)> {
                    vk.chip_information
                        .iter()
                        .map(|(n, d, dims)| (n.clone(), dims.0, d.log_size))
                        .collect()
                };
                let cr = fmt_ci(&vk_real_full);
                let cd = fmt_ci(&vk_dummy_full);
                eprintln!("[STAGE1-DIAG] REAL  recursion VK chip_info (name,width,log_h): {:?}", cr);
                eprintln!("[STAGE1-DIAG] DUMMY recursion VK chip_info (name,width,log_h): {:?}", cd);
                eprintln!("[STAGE1-DIAG] same_chipset_names_widths={}", {
                    let nr: Vec<(String,usize)> = cr.iter().map(|(n,w,_)| (n.clone(),*w)).collect();
                    let nd: Vec<(String,usize)> = cd.iter().map(|(n,w,_)| (n.clone(),*w)).collect();
                    nr == nd
                });
                let commit_eq = {
                    let rr: &[[KoalaBear; DIGEST_SIZE]] = vk_real_full.commit.borrow();
                    let dd: &[[KoalaBear; DIGEST_SIZE]] = vk_dummy_full.commit.borrow();
                    rr == dd
                };
                eprintln!("[STAGE1-DIAG] prep_commit_eq={commit_eq} pc_start_eq={}",
                    vk_real_full.pc_start == vk_dummy_full.pc_start);
                // The CORE vk being VERIFIED inside the recursion program — its
                // chip_information feeds the in-circuit vk.hash (name+width fold).
                let fmt_core = |vk: &zkm_pcs::StarkVerifyingKey<CoreSC>| -> Vec<(String, usize, usize)> {
                    vk.chip_information
                        .iter()
                        .map(|(n, d, dims)| (n.clone(), dims.0, d.log_size))
                        .collect()
                };
                let cr_core = fmt_core(&input.vk);
                let cd_core = fmt_core(&dummy.vk);
                eprintln!("[STAGE1-DIAG] REAL  CORE vk chip_info (name,width,log_h): {:?}", cr_core);
                eprintln!("[STAGE1-DIAG] DUMMY CORE vk chip_info (name,width,log_h): {:?}", cd_core);
                let core_names_widths_eq = {
                    let nr: Vec<(String,usize)> = cr_core.iter().map(|(n,w,_)| (n.clone(),*w)).collect();
                    let nd: Vec<(String,usize)> = cd_core.iter().map(|(n,w,_)| (n.clone(),*w)).collect();
                    nr == nd
                };
                let core_full_eq = cr_core == cd_core;
                eprintln!("[STAGE1-DIAG] CORE names+widths_eq={core_names_widths_eq} CORE full(incl heights)_eq={core_full_eq}");
            }

            let eq = vk_real == vk_dummy;
            all_faithful &= eq;
            let in_map = prover.recursion_vk_map.contains_key(&vk_real);
            let arity_enumerated = enum_arities.contains(&arity);

            // ── DECISIVE: reconstruct the ENUMERATED REPRESENTATIVE batch
            //    (the exact uniform batch generate() emits for this real
            //    batch's per-shard (chip_set, log_dense) classes) and assert
            //    its dummy-built normalize VK == the real VK.  This proves
            //    the enumeration PRODUCES the real arity-N normalize VK. ──
            let real_key = batch_class_key(
                &real_shape.proof_shapes,
            );
            let class_in_enum = enum_class_keys.contains(&real_key);
            // Build the enumerated representative: for each real per-shard
            // shape, find an enumerated per-shard shape of the SAME
            // (chip_set, log_dense) class, then form that batch.
            let enum_repr_batch: Option<Vec<OrderedShape>> = real_shape
                .proof_shapes
                .iter()
                .map(|os| {
                    let mut names: Vec<String> = os.inner.iter().map(|(n, _)| n.clone()).collect();
                    names.sort();
                    let ld = log_dense_of(os);
                    enum_norm
                        .iter()
                        .find(|e| {
                            let mut en: Vec<String> = e.inner.iter().map(|(n, _)| n.clone()).collect();
                            en.sort();
                            en == names && log_dense_of(e) == ld
                        })
                        .cloned()
                })
                .collect();
            let (enum_repr_eq, enum_repr_vk_u32) = match &enum_repr_batch {
                Some(b) if b.len() == real_shape.proof_shapes.len() => {
                    let shape = ZKMRecursionShape {
                        proof_shapes: b.clone(),
                        is_complete: input.is_complete,
                    };
                    let built = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let d = ZKMCoreBasefoldWitnessValues::dummy(machine, &shape);
                        let p = prover.recursion_program_basefold(&d);
                        prover.compress_prover.setup(&p).1.hash_koalabear()
                    }));
                    match built {
                        Ok(vk) => {
                            use p3_field::PrimeField32;
                            (Some(vk == vk_real), Some(vk.map(|x| x.as_canonical_u32())))
                        }
                        Err(_) => (None, None),
                    }
                }
                _ => (None, None),
            };

            let vk_real_u32 = vk_real.map(|x| {
                use p3_field::PrimeField32;
                x.as_canonical_u32()
            });
            eprintln!(
                "[MSNORM] batch {i}: arity={arity} dummy_faithful={eq} real_in_map={in_map} \
                 arity_enumerated={arity_enumerated} class_in_enum={class_in_enum} \
                 enum_repr_eq={enum_repr_eq:?} vk_real={vk_real_u32:?} enum_repr_vk={enum_repr_vk_u32:?}"
            );

            // ── DIVERGENCE PROBE (arity-1 only): why does the real-shape dummy
            //    diverge from the synthetic-enumeration dummy (which DID build the
            //    map vk, real_in_map=true)?  Build a dummy from the matching
            //    SYNTHETIC enumerated shape (same chip SET) and diff its program
            //    against the real prover's and the real-shape dummy's. ──
            if arity == 1 && std::env::var("MSNORM_DIAG").is_ok() {
                let real_os = batch[0].shape();
                let real_chipset: std::collections::BTreeSet<String> =
                    real_os.inner.iter().map(|(n, _)| n.clone()).collect();
                let mut real_heights: Vec<(String, usize)> = real_os.inner.iter().cloned().collect();
                real_heights.sort();
                eprintln!("[MSNORM-DIAG] real shard log-heights = {real_heights:?}");

                // Synthetic enumerated shapes with the same chip SET.
                let mut matches_set: Vec<&OrderedShape> = enum_norm
                    .iter()
                    .filter(|os| {
                        let cs: std::collections::BTreeSet<String> =
                            os.inner.iter().map(|(n, _)| n.clone()).collect();
                        cs == real_chipset
                    })
                    .collect();
                eprintln!(
                    "[MSNORM-DIAG] synthetic enumerated shapes with SAME chip-set = {}",
                    matches_set.len()
                );
                let prog_real_bytes = bincode::serialize(&*prog_real).unwrap();
                let prog_realdummy_bytes = bincode::serialize(&*prog_dummy).unwrap();
                matches_set.sort_by_key(|os| os.inner.iter().map(|(_, h)| *h).sum::<usize>());
                let mut found_match = false;
                for os in matches_set.iter() {
                    let syn_shape = ZKMRecursionShape {
                        proof_shapes: vec![(*os).clone()],
                        is_complete: input.is_complete,
                    };
                    // Over-enumeration: some synthetic shapes exceed log_dense>30
                    // and panic num2bits — build_compress_vks catch_unwinds these.
                    let built = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let syn_dummy = ZKMCoreBasefoldWitnessValues::dummy(machine, &syn_shape);
                        let prog_syn = prover.recursion_program_basefold(&syn_dummy);
                        let vk_syn = prover.compress_prover.setup(&prog_syn).1.hash_koalabear();
                        (prog_syn, vk_syn)
                    }));
                    let (prog_syn, vk_syn) = match built {
                        Ok(t) => t,
                        Err(_) => continue,
                    };
                    if vk_syn == vk_real && !found_match {
                        found_match = true;
                        let prog_syn_bytes = bincode::serialize(&*prog_syn).unwrap();
                        let fd_rs = prog_real_bytes.iter().zip(prog_syn_bytes.iter()).position(|(a, b)| a != b);
                        let fd_rd = prog_realdummy_bytes.iter().zip(prog_syn_bytes.iter()).position(|(a, b)| a != b);
                        let mut syn_h: Vec<(String, usize)> = os.inner.iter().cloned().collect();
                        syn_h.sort();
                        eprintln!(
                            "[MSNORM-DIAG] *** SYNTHETIC MATCH heights={syn_h:?} | prog_real_vs_syn first_diff={fd_rs:?} \
                             (real_len={} syn_len={}) | realdummy_vs_syn first_diff={fd_rd:?} (realdummy_len={})",
                            prog_real_bytes.len(), prog_syn_bytes.len(), prog_realdummy_bytes.len(),
                        );
                        // instr-level diff: realdummy (WRONG) vs syn (RIGHT)
                        let di: Vec<_> = prog_dummy.iter_instructions().collect();
                        let si: Vec<_> = prog_syn.iter_instructions().collect();
                        eprintln!(
                            "[MSNORM-DIAG] realdummy_instrs={} syn_instrs={} (delta={})",
                            di.len(), si.len(), di.len() as i64 - si.len() as i64
                        );
                        let n = di.len().min(si.len());
                        let mut shown = 0;
                        for k in 0..n {
                            if format!("{:?}", di[k]) != format!("{:?}", si[k]) {
                                eprintln!("[MSNORM-DIAG] realdummy_vs_syn diff@{k}: realdummy={:?} | syn={:?}", di[k], si[k]);
                                shown += 1;
                                if shown >= 8 { break; }
                            }
                        }
                    }
                }
                if !found_match {
                    eprintln!("[MSNORM-DIAG] no synthetic same-chipset shape produced vk_real (real_in_map={in_map})");
                }

                // ── PRIMARY DIFF: real `input` program vs real-SHAPE dummy program.
                //    SAME shape, real-values vs zero-dummy.  If value-independent +
                //    shape-faithful these MUST match; they don't (dummy_faithful=false),
                //    so the divergence here is the residual structural field. ──
                let ri: Vec<_> = prog_real.iter_instructions().collect();
                let di: Vec<_> = prog_dummy.iter_instructions().collect();
                eprintln!(
                    "[MSNORM-DIAG] PRIMARY real_input_instrs={} realdummy_instrs={} (delta={}) \
                     real_mem={} dummy_mem={}",
                    ri.len(), di.len(), ri.len() as i64 - di.len() as i64,
                    prog_real.total_memory, prog_dummy.total_memory,
                );
                let rb = bincode::serialize(&*prog_real).unwrap();
                let db = bincode::serialize(&*prog_dummy).unwrap();
                let fd = rb.iter().zip(db.iter()).position(|(a, b)| a != b);
                eprintln!("[MSNORM-DIAG] PRIMARY prog bytes real={} dummy={} first_diff={fd:?}", rb.len(), db.len());
                let n = ri.len().min(di.len());
                let mut shown = 0;
                let mut first_idx = None;
                for k in 0..n {
                    if format!("{:?}", ri[k]) != format!("{:?}", di[k]) {
                        if first_idx.is_none() { first_idx = Some(k); }
                        eprintln!("[MSNORM-DIAG] PRIMARY diff@{k}: real={:?} | dummy={:?}", ri[k], di[k]);
                        shown += 1;
                        if shown >= 12 { break; }
                    }
                }
                eprintln!("[MSNORM-DIAG] PRIMARY first_instr_diff_idx={first_idx:?}");
                // tail of the longer program (the extra instrs)
                if ri.len() != di.len() {
                    let (longer, lbl, start) = if ri.len() > di.len() {
                        (&ri, "real", di.len())
                    } else {
                        (&di, "dummy", ri.len())
                    };
                    for k in start..longer.len().min(start + 10) {
                        eprintln!("[MSNORM-DIAG] PRIMARY {lbl}-only tail@{k}: {:?}", longer[k]);
                    }
                }
            }
            if arity >= 2 {
                any_multishard_checked = true;
                // A multishard batch must have its class enumerated AND its
                // representative VK reproduce the real VK.
                if !(class_in_enum && enum_repr_eq == Some(true)) {
                    all_enum_repr_eq = false;
                }
            }
            per_arity_vks.entry(arity).or_default().push(vk_real);
        }

        // Arity-collapse probe: for each arity seen, do all real batches of that
        // arity (different per-shard mixes) share ONE vk?
        for (arity, vks) in per_arity_vks.iter() {
            let distinct: std::collections::BTreeSet<_> = vks.iter().collect();
            eprintln!(
                "[MSNORM] arity={arity}: {} real batches, {} DISTINCT vks (collapse={})",
                vks.len(),
                distinct.len(),
                distinct.len() == 1
            );
        }

        eprintln!(
            "[MSNORM] SUMMARY: all_dummy_faithful={all_faithful} \
             all_multishard_enum_repr_eq={all_enum_repr_eq} multishard_batches_present={any_multishard_checked}"
        );
        if std::env::var("MSNORM_ASSERT").is_ok() {
            assert!(
                all_faithful,
                "[MSNORM] dummy normalize VK diverged from real at some arity — the per-shard \
                 dummy bundle reconstruction is NOT faithful (this is the deep bug). See \
                 per-batch lines above."
            );
            // DECISIVE arity-enum assertion: every multishard (arity>=2)
            // batch's class must be enumerated and its representative VK
            // must reproduce the real VK.  Only fires if the workload
            // actually produced multishard batches.
            if any_multishard_checked {
                assert!(
                    all_enum_repr_eq,
                    "[MSNORM] a multishard (arity>=2) normalize VK is NOT reproduced by the \
                     enumerated representative batch — the arity enumeration does not cover this \
                     real batch's (arity, per-shard (chip_set, log_dense)) class. See per-batch \
                     lines above (class_in_enum / enum_repr_eq)."
                );
            }
        }
        Ok(())
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
        use zkm_recursion_circuit::machine::{ZKMCompressShape, ZKMCompressWithVkeyShape};
        use zkm_pcs::shape::OrderedShape;
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
            ("BaseAlu", 18), ("ExtAlu", 18), ("MemoryConst", 17), ("MemoryVar", 18),
            ("Poseidon2WideDeg3", 18), ("PublicValues", 4), ("Select", 18),
        ];
        // A UNIFORM child of the SAME chip-set (what generate() emits): all at 18.
        let uniform18: Vec<(&str, usize)> =
            natural.iter().map(|(n, _)| (*n, 18usize)).collect();
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
            ("AddSub", 13), ("Bitwise", 12), ("Branch", 11), ("Byte", 16),
            ("CloClz", 10), ("Cpu", 14), ("DivRem", 10), ("Global", 9),
            ("Jump", 10), ("Lt", 12), ("MemoryInstrs", 10), ("MemoryLocal", 10),
            ("MiscInstrs", 1), ("MovCond", 10), ("Mul", 10), ("Program", 19),
            ("ShiftLeft", 9), ("ShiftRight", 9), ("SyscallCore", 10),
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
            if v_misc10 == v_real && v_allcap == v_real { "INSENSITIVE (chip-SET only)" }
            else { "SENSITIVE (per-chip heights load-bearing)" }
        );
    }

    /// Localizer: prove fib-1k core (FIX-off) and, for each shard, print the
    /// REAL canonical-cluster shape ([REALCANON], from prove.rs) next to the
    /// ORDERED reconstruction
    /// (`find_canonical_cluster_shape_from_ordered(chip_log_heights)`) so the
    /// normalize-lift divergence (CPU shard) can be localized chip-by-chip.
    #[test]
    #[serial]
    #[ignore]
    fn vkmap_canon_localize() -> Result<()> {
        use zkm_pcs::shape::OrderedShape;
        setup_logger();
        let dir = std::env::var("FIXOFF_PROGRAM_DIR")
            .unwrap_or_else(|_| "/data/stephen/ziren-shape-bin/fibonacci-1k".to_string());
        let elf = std::fs::read(format!("{dir}/program.bin")).expect("read program.bin");
        let stdin_bytes = std::fs::read(format!("{dir}/stdin.bin")).expect("read stdin.bin");
        let stdin: ZKMStdin = bincode::deserialize::<ZKMStdin>(&stdin_bytes)
            .unwrap_or_else(|_| {
                let mut s = ZKMStdin::new();
                s.write_vec(stdin_bytes);
                s
            });
        let opts = ZKMProverOpts::default();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let context = ZKMContext::default();
        let (_, pk_d, program, vk) = prover.setup(&elf);
        let core_proof = prover.prove_core(&pk_d, program, &stdin, opts, context)?;
        let band_cap_cfg = CoreShapeConfig::<KoalaBear>::default();
        // The full enumerated canonical-cluster shape set (config-driven).
        let canon_set: std::collections::BTreeSet<Vec<(String, usize)>> = band_cap_cfg
            .enumerate_canonical_cluster_shapes()
            .into_iter()
            .map(|s| {
                let mut v: Vec<(String, usize)> =
                    s.iter().map(|(id, h)| (id.to_string(), *h)).collect();
                v.sort();
                v
            })
            .collect();
        eprintln!("[CANONLOC] enumerated canonical-cluster shapes = {}", canon_set.len());
        for (i, sp) in core_proof.proof.0.iter().enumerate() {
            let raw = sp.shape();
            let mut raw_sorted: Vec<(String, usize)> = raw.inner.clone();
            raw_sorted.sort();
            let ordered = match band_cap_cfg.find_canonical_cluster_shape_from_ordered(&raw) {
                Some(shape) => {
                    let mut v: Vec<(String, usize)> =
                        shape.iter().map(|(id, h)| (id.to_string(), *h)).collect();
                    v.sort();
                    v
                }
                None => vec![],
            };
            let ordered_in_set = canon_set.contains(&ordered);
            eprintln!("[CANONLOC] shard={i} RAW={raw_sorted:?}");
            eprintln!("[CANONLOC] shard={i} ORDERED_LIFT={ordered:?} (in_enum_set={ordered_in_set})");
        }
        let _ = vk;
        Ok(())
    }

    /// DISCRIMINATOR harness: prove a real fib CORE proof and run
    /// the HOST `verify_shard` on each shard (a host-VALID / GREEN child).
    /// With `S8J_RLC=1` set, `verify_zerocheck_host` independently recomputes
    /// the in-circuit `rlc_eval` (recursion zerocheck.rs:613) on the host from
    /// the SAME inputs the circuit uses (the trace@z* openings in
    /// `opened_values`, the transcript-sampled alpha/gkr_batch_open/lambda, the
    /// GKR point and the zerocheck-reduced point) and prints it alongside the
    /// proof's `point_and_eval.1`.  EQUAL ⇒ the claimed eval is consistent with
    /// the openings (the host recompute is trustworthy, so the circuit's
    /// formula is what would diverge on a failing child → explanation (a) for
    /// any reject); UNEQUAL on a green child ⇒ the host recompute itself is
    /// untrustworthy (re-derive FS order before drawing a verdict).
    ///
    /// This is the GREEN-child leg of the discriminator: every core shard
    /// host-verifies (so they are all valid), and we read off whether the
    /// host-recomputed rlc_eval matches the claimed eval by construction.
    /// Run with: S8J_RLC=1 [S8J_PERCHIP=1] cargo test -p zkm-prover
    ///   s8j_rlc_eval_discriminator -- --ignored --nocapture
    #[test]
    #[serial]
    #[ignore]
    fn s8j_rlc_eval_discriminator() -> Result<()> {
        setup_logger();
        std::env::set_var("S8J_RLC", "1");
        let elf = test_artifacts::FIBONACCI_ELF;
        let opts = ZKMProverOpts::default();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let context = ZKMContext::default();
        let (_, pk_d, program, vk) = prover.setup(elf);
        let core_proof =
            prover.prove_core(&pk_d, program, &ZKMStdin::default(), opts, context)?;
        eprintln!(
            "[S8J] fib core: {} shard proof(s) — running host verify_shard on each",
            core_proof.proof.0.len()
        );
        // Host-verify exactly as ZKMProver::verify does (verify.rs:291-293):
        // routes each shard through Verifier::verify_shard ->
        // BasefoldShardVerifier::verify_shard -> verify_zerocheck_host ->
        // (S8J_RLC) recompute_and_report_rlc_eval_host.
        let mut challenger = prover.core_prover.config().challenger();
        let machine_proof = zkm_pcs::MachineProof {
            shard_proofs: core_proof.proof.0.to_vec(),
        };
        let res = prover.core_prover.machine().verify(&vk.vk, &machine_proof, &mut challenger);
        match &res {
            Ok(()) => eprintln!(
                "[S8J] host core verify GREEN — all {} shard(s) host-VALID; \
                 the [S8J-RLC] lines above show host rlc_eval vs point_and_eval.1 \
                 per shard (EQUAL on every green child ⇒ host recompute is faithful \
                 and the identity holds by construction).",
                core_proof.proof.0.len()
            ),
            Err(e) => eprintln!("[S8J] host core verify FAILED: {e:?}"),
        }
        res.expect("fib core must host-verify (green children)");
        Ok(())
    }

    /// VKROOT shrink localizer: build the shrink program from the REAL fib
    /// compress proof (cached via DUMP_COMPRESS_PROOF=/tmp/fib_compress.bin)
    /// vs the enumeration's DUMMY witness from the same OrderedShape, and
    /// compare vk hashes + vk_map membership.
    ///   vk_real == vk_dummy, ∉ map  => Shrink shape-coverage gap
    ///   vk_real != vk_dummy         => value-dependence in the shrink
    ///                                  program build (compress-level
    ///                                  dummy-faithfulness / baked heights)
    #[test]
    #[serial]
    #[ignore]
    fn vkroot_shrink_vkeq() {
        use zkm_recursion_circuit::machine::{
            ZKMCompressWithVkeyShape, ZKMWrapBasefoldWitnessValues,
        };
        use zkm_pcs::shape::OrderedShape;
        setup_logger();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let bytes = std::fs::read("/tmp/fib_compress.bin").expect(
            "run test_e2e_compress_fibonacci with DUMP_COMPRESS_PROOF=/tmp/fib_compress.bin first",
        );
        let reduced: ZKMReduceProof<InnerSC> = bincode::deserialize(&bytes).unwrap();
        let ZKMReduceProof { vk: compressed_vk, proof: compressed_proof } = reduced;
        let basefold_proof = *compressed_proof
            .basefold_shard_proof
            .clone()
            .expect("compress proof missing basefold side-channel");

        // Shape of the real compress (normalize) proof.
        let lh: Vec<(String, usize)> = basefold_proof
            .chip_log_heights
            .iter()
            .map(|(k, v)| (k.clone(), *v as usize))
            .collect();
        let os = OrderedShape::from_log2_heights(&lh);
        eprintln!("[SHRINKEQ] compress proof shape: {os:?}");

        // Coverage: is this OrderedShape among the enumerated compress shapes?
        let rsc = prover.compress_shape_config.as_ref().unwrap();
        let in_enum = rsc
            .get_all_shape_combinations(1)
            .any(|combo| combo.first() == Some(&os));
        eprintln!("[SHRINKEQ] shape in recursion_shape_config combos: {in_enum}");

        // REAL: exactly what `shrink()` builds.  If the input compress vk
        // isn't (yet) in the map, substitute dummy merkle data of the same
        // shape — value-independence of the merkle witness is already
        // established, so the program/vk is unaffected.
        let height_for_merkle = VK_MERKLE_TREE_HEIGHT;
        let vk_merkle_data =
            if prover.recursion_vk_map.contains_key(&compressed_vk.hash_koalabear()) {
                prover.make_basefold_merkle_proofs(&[compressed_vk.clone()])
            } else {
                eprintln!("[SHRINKEQ] compress vk not in map — using dummy merkle data");
                zkm_recursion_circuit::machine::ZKMMerkleProofWitnessValues::dummy(
                    1,
                    height_for_merkle,
                )
            };
        let input_real = ZKMWrapBasefoldWitnessValues {
            vks_and_proofs: vec![(compressed_vk, basefold_proof)],
            vk_merkle_data,
        };
        let prog_real = prover.shrink_program_basefold(&input_real);
        let vk_real = prover.shrink_prover.setup(&prog_real).1.hash_koalabear();

        // DUMMY: exactly what the vk_map enumeration builds.
        let height = VK_MERKLE_TREE_HEIGHT;
        let shape = ZKMCompressWithVkeyShape {
            compress_shape: vec![os.clone()].into(),
            merkle_tree_height: height,
        };
        let input_dummy = ZKMWrapBasefoldWitnessValues::dummy(
            prover.compress_prover.machine(),
            &shape,
        );
        let prog_dummy = prover.shrink_program_basefold(&input_dummy);
        let vk_dummy = prover.shrink_prover.setup(&prog_dummy).1.hash_koalabear();

        let eq = vk_real == vk_dummy;
        let real_in = prover.recursion_vk_map.contains_key(&vk_real);
        let dummy_in = prover.recursion_vk_map.contains_key(&vk_dummy);
        eprintln!(
            "[SHRINKEQ] EQUAL={eq} vk_real={:?} in_map={real_in}",
            vk_real.map(|x| x.as_canonical_u32())
        );
        eprintln!(
            "[SHRINKEQ] vk_dummy={:?} in_map={dummy_in} (map_size={}, height={height})",
            vk_dummy.map(|x| x.as_canonical_u32()),
            prover.recursion_vk_map.len()
        );

        // Third leg: the EXACT enumeration path — the allowed-shape combo
        // (which may carry chip names not present in the current machine)
        // whose machine-filtered heights match the real proof.  This is the
        // true map-membership predicate: vk_enum is what `build_compress_vks`
        // would store.
        use zkm_pcs::air::MachineAir;
        let machine_names: std::collections::BTreeSet<String> = prover
            .compress_prover
            .machine()
            .chips()
            .iter()
            .map(|c| <_ as MachineAir<KoalaBear>>::name(c))
            .collect();
        let matching_combo = rsc.get_all_shape_combinations(1).map(|mut v| v.pop().unwrap()).find(|combo| {
            let filtered: Vec<(String, usize)> = combo
                .inner
                .iter()
                .filter(|(n, _)| machine_names.contains(n))
                .cloned()
                .collect();
            OrderedShape::from_log2_heights(&filtered) == os
        });
        match matching_combo {
            Some(combo) => {
                let shape_enum = ZKMCompressWithVkeyShape {
                    compress_shape: vec![combo].into(),
                    merkle_tree_height: height,
                };
                let input_enum = ZKMWrapBasefoldWitnessValues::dummy(
                    prover.compress_prover.machine(),
                    &shape_enum,
                );
                let prog_enum = prover.shrink_program_basefold(&input_enum);
                let vk_enum = prover.shrink_prover.setup(&prog_enum).1.hash_koalabear();
                eprintln!(
                    "[SHRINKEQ] vk_enum(9-name combo)={:?} ==real:{} in_map={}",
                    vk_enum.map(|x| x.as_canonical_u32()),
                    vk_enum == vk_real,
                    prover.recursion_vk_map.contains_key(&vk_enum)
                );
            }
            None => eprintln!(
                "[SHRINKEQ] NO allowed combo's filtered heights match the real shape"
            ),
        }
        if !eq {
            // Localize: compare instruction streams.
            let a = format!("{:?}", prog_real.seq_blocks);
            let b = format!("{:?}", prog_dummy.seq_blocks);
            let n = a.len().min(b.len());
            let fd = a.bytes().zip(b.bytes()).position(|(x, y)| x != y).unwrap_or(n);
            eprintln!(
                "[SHRINKEQ] instr streams: real_len={} dummy_len={} first_diff_at={fd}",
                a.len(),
                b.len()
            );
            let s = fd.saturating_sub(120);
            eprintln!("[SHRINKEQ] real @diff: ...{}", &a[s..(fd + 120).min(a.len())]);
            eprintln!("[SHRINKEQ] dummy@diff: ...{}", &b[s..(fd + 120).min(b.len())]);
        }
    }

    /// VK-enforcement probe: build the fib normalize program with
    /// ZKM_DEBUG=true and print the instructions + nearest backtraces around
    /// a trap pc (env TRAP_PC, default 99368) to name the DSL site of an
    /// enforced DivFAssert trip.  Program is value-independent, so the dummy
    /// build has identical layout to the failing real run.
    #[test]
    #[serial]
    #[ignore]
    fn vkroot_enforce_probe() {
        use zkm_recursion_circuit::machine::ZKMCoreBasefoldWitnessValues;
        use zkm_pcs::shape::OrderedShape;
        std::env::set_var("ZKM_DEBUG", "true");
        let trap_pc: usize = std::env::var("TRAP_PC")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(99368);
        let fib: Vec<(&str, usize)> = vec![
            ("AddSub", 16), ("Bitwise", 13), ("Branch", 13), ("Byte", 16),
            ("CloClz", 5), ("Cpu", 17), ("DivRem", 11), ("Global", 18),
            ("Jump", 11), ("Lt", 15), ("MemoryGlobalFinalize", 17),
            ("MemoryGlobalInit", 17), ("MemoryInstrs", 15), ("MemoryLocal", 11),
            ("MiscInstrs", 11), ("MovCond", 12), ("Mul", 13), ("Program", 19),
            ("ShiftLeft", 13), ("ShiftRight", 11), ("SyscallCore", 11),
            ("SyscallInstrs", 11),
        ];
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let os = OrderedShape::from_log2_heights(
            &fib.iter().map(|(n, h)| (n.to_string(), *h)).collect::<Vec<_>>(),
        );
        let shape = ZKMRecursionShape { proof_shapes: vec![os], is_complete: false };
        let dummy = ZKMCoreBasefoldWitnessValues::dummy(prover.core_prover.machine(), &shape);
        let prog = prover.recursion_program_basefold(&dummy);
        let n = prog.traces.len();
        eprintln!("[PROBE] program instrs={} traces={}", prog.iter_instructions().count(), n);
        let _ = trap_pc;

        // The runtime's pc numbering diverges from flat order on Parallel
        // blocks, but ADDRESSES are deterministic SSA.  Locate the failing
        // DivFAssert by its addresses (env TRAP_IN1, default 2237763) and
        // back-walk the dataflow to name the producing site.
        use zkm_recursion_core::Instruction as RInstr;
        let trap_in1: u32 = std::env::var("TRAP_IN1")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2237763);
        let instrs: Vec<&RInstr<KoalaBear>> = prog.iter_instructions().collect();
        // writer index: address -> flat idx (first writer wins; SSA so unique)
        let fmt = |i: usize| -> String {
            let has_trace = prog.traces.get(i).map(|t| t.is_some()).unwrap_or(false);
            format!("flat={} trace={} {:?}", i, has_trace, instrs[i])
        };
        // find the DivFAssert consuming trap_in1
        let mut found = Vec::new();
        for (i, ins) in instrs.iter().enumerate() {
            let s = format!("{ins:?}");
            if s.contains("DivFAssert") && s.contains(&format!("in1: Address({trap_in1})")) {
                found.push(i);
            }
        }
        eprintln!("[PROBE] DivFAssert consumers of Address({trap_in1}): {:?}", found);
        for &i in found.iter().take(2) {
            eprintln!("[PROBE] consumer {}", fmt(i));
        }
        // back-walk: find writers of a frontier of addresses, 6 levels deep
        let mut frontier: Vec<u32> = vec![trap_in1];
        for level in 0..6 {
            let mut next = Vec::new();
            for &addr in frontier.iter().take(4) {
                let pat = format!("out: Address({addr})");
                let pat2 = format!("Address({addr}), C::F"); // unused, defensive
                let _ = &pat2;
                if let Some((i, ins)) = instrs
                    .iter()
                    .enumerate()
                    .find(|(_, ins)| format!("{ins:?}").contains(&pat))
                {
                    eprintln!("[PROBE] L{level} writer of {addr}: {}", fmt(i));
                    // harvest its input addresses
                    let s = format!("{ins:?}");
                    for cap in s.split("Address(").skip(1) {
                        if let Some(end) = cap.find(')') {
                            if let Ok(a) = cap[..end].parse::<u32>() {
                                if a != addr && !next.contains(&a) {
                                    next.push(a);
                                }
                            }
                        }
                    }
                    // nearest trace at/below this flat index
                    let mut p = i as i64;
                    while p >= 0 {
                        if let Some(Some(t)) = prog.traces.get(p as usize) {
                            let mut t = t.clone();
                            t.resolve();
                            let txt = format!("{t:?}");
                            let lines: Vec<&str> = txt
                                .lines()
                                .filter(|l| l.contains("zkm_") || l.contains("at /"))
                                .take(14)
                                .collect();
                            eprintln!("[PROBE]   nearest-trace flat={}:\n{}", p, lines.join("\n"));
                            break;
                        }
                        p -= 1;
                    }
                } else {
                    eprintln!("[PROBE] L{level} writer of {addr}: NONE (witness/hint?)");
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }

        // Exact window around the failing assert (flat=1863456): print every
        // instruction so the loop body identifies the source site.
        for (i, ins) in instrs.iter().enumerate() {
            if !(1863430..=1863470).contains(&i) { continue; }
            let s = format!("{ins:?}");
            let short: String = s.chars().take(160).collect();
            eprintln!("[PROBE] W flat={i}{} {}", if i == 1863456 { " <==FAIL" } else { "" }, short);
        }

        // With a cached REAL core proof, print the witness-stream values
        // around the trap operand addresses — block index == hint address
        // for the sequential allocation, so the VALUES identify the fields.
        if let Ok(bytes) = std::fs::read("/tmp/fib_core.bin") {
            let data: ZKMCoreProofData = bincode::deserialize(&bytes).unwrap();
            let (_, _, _, vk) = prover.setup(test_artifacts::FIBONACCI_ELF);
            let inputs = prover.get_recursion_core_inputs(
                &vk.vk,
                &data.0,
                REDUCE_BATCH_SIZE,
                true,
            );
            let mut stream = Vec::new();
            Witnessable::<InnerConfig>::write(&inputs[0], &mut stream);
            eprintln!("[PROBE] real witness stream blocks={}", stream.len());
            // Execute the program on the REAL witness; at the trap, dump
            // memory at the compared address ranges.
            {
                let mut rt = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
                    prog.clone(),
                    prover.shrink_prover.config().perm.clone(),
                );
                rt.witness_stream = stream.clone().into();
                let res = rt.run();
                eprintln!("[PROBE] real-run result: {:?}", res.as_ref().err().map(|e| format!("{e}").chars().take(160).collect::<String>()));
                use p3_field::PrimeCharacteristicRing as _;
                for a in [84u32, 85, 86, 87, 88, 116, 117, 118, 119, 120, 170, 171] {
                    let addr = zkm_recursion_core::Address(KoalaBear::from_u32(a));
                    let entry = unsafe { rt.memory.mr_unchecked(addr) };
                    eprintln!("[PROBE] mem[{a}] = {:?}", entry.val);
                }
            }
            // Find all (i, j) with value_i + 1 == value_j (the observed
            // diff = -1) among base-field blocks — names the two fields the
            // failing assert compares.
            use std::collections::HashMap as StdHashMap;
            let vals: Vec<u32> = stream
                .iter()
                .map(|b| {
                    let s = format!("{b:?}");
                    s.trim_start_matches("Block([")
                        .split(',')
                        .next()
                        .and_then(|x| x.trim().parse::<u32>().ok())
                        .unwrap_or(0)
                })
                .collect();
            let mut by_val: StdHashMap<u32, Vec<usize>> = StdHashMap::new();
            for (i, &v) in vals.iter().enumerate() {
                by_val.entry(v).or_default().push(i);
            }
            let mut pairs = 0;
            for (i, &v) in vals.iter().enumerate() {
                if v == 0 || v == 1 {
                    continue; // skip trivially-common small values
                }
                if let Some(js) = by_val.get(&(v + 1)) {
                    for &j in js.iter().take(3) {
                        eprintln!("[PROBE] PAIR v[{i}]={v} + 1 == v[{j}]={}", v + 1);
                        pairs += 1;
                    }
                }
                if pairs > 30 { break; }
            }
            eprintln!("[PROBE] pairs={pairs}");
            // Field-boundary map: write each top-level field separately and
            // print the cumulative block offsets.
            let w = &inputs[0];
            let mut tmp = Vec::new();
            Witnessable::<InnerConfig>::write(&w.vk, &mut tmp);
            eprintln!("[PROBE] after vk: {}", tmp.len());
            Witnessable::<InnerConfig>::write(&w.shard_proofs, &mut tmp);
            eprintln!("[PROBE] after shard_proofs: {}", tmp.len());
            Witnessable::<InnerConfig>::write(&w.is_complete, &mut tmp);
            Witnessable::<InnerConfig>::write(&w.is_first_shard, &mut tmp);
            Witnessable::<InnerConfig>::write(&w.vk_root, &mut tmp);
            eprintln!("[PROBE] total: {}", tmp.len());
            // And proof sub-fields to localize 1131-1157:
            let pr = &w.shard_proofs[0];
            let mut t2 = Vec::new();
            Witnessable::<InnerConfig>::write(&pr.commitment, &mut t2);
            eprintln!("[PROBE] +commitment: {}", t2.len());
            Witnessable::<InnerConfig>::write(&pr.opened_values, &mut t2);
            eprintln!("[PROBE] +opened_values: {}", t2.len());
            Witnessable::<InnerConfig>::write(&pr.public_values, &mut t2);
            eprintln!("[PROBE] +public_values: {}", t2.len());
            eprintln!("[PROBE] context values 1120..1165:");
            for a in 1120..=1165usize {
                if let Some(&v) = vals.get(a) {
                    eprintln!("[PROBE] v[{a}]={v}");
                }
            }
        }
    }

    /// VK-enforcement probe for the SHRINK program: build it from the real
    /// cached compress proof, locate the failing DivFAssert by operand
    /// address (env TRAP_IN1), print the window + dataflow.
    #[test]
    #[serial]
    #[ignore]
    fn vkroot_enforce_probe_shrink() {
        use zkm_recursion_circuit::machine::ZKMWrapBasefoldWitnessValues;
        std::env::set_var("ZKM_DEBUG", "true");
        let trap_in1: u32 = std::env::var("TRAP_IN1")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(95444);
        setup_logger();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let bytes = std::fs::read("/tmp/fib_compress.bin").expect("need fresh compress dump");
        let reduced: ZKMReduceProof<InnerSC> = bincode::deserialize(&bytes).unwrap();
        let ZKMReduceProof { vk: compressed_vk, proof: compressed_proof } = reduced;
        let basefold_proof = *compressed_proof.basefold_shard_proof.clone().unwrap();
        let height = VK_MERKLE_TREE_HEIGHT;
        // Mirror ZKMProver::shrink exactly: make_basefold_merkle_proofs is
        // total under VERIFY_VK=false (hash-derived index); only fall back to
        // the dummy when vk_verification=true AND the vk is missing (where
        // the real call would panic "vk not allowed").
        let vk_merkle_data = if !prover.vk_verification
            || prover.recursion_vk_map.contains_key(&compressed_vk.hash_koalabear())
        {
            prover.make_basefold_merkle_proofs(&[compressed_vk.clone()])
        } else {
            zkm_recursion_circuit::machine::ZKMMerkleProofWitnessValues::dummy(1, height)
        };
        let input = ZKMWrapBasefoldWitnessValues {
            vks_and_proofs: vec![(compressed_vk, basefold_proof)],
            vk_merkle_data,
        };
        let prog = prover.shrink_program_basefold(&input);
        use zkm_recursion_core::Instruction as RInstr;
        let instrs: Vec<&RInstr<KoalaBear>> = prog.iter_instructions().collect();
        eprintln!("[SPROBE] shrink program instrs={}", instrs.len());
        let mut hit = None;
        for (i, ins) in instrs.iter().enumerate() {
            let s = format!("{ins:?}");
            if s.contains("DivFAssert") && s.contains(&format!("in1: Address({trap_in1})")) {
                hit = Some(i);
                eprintln!("[SPROBE] consumer flat={i}: {}", s.chars().take(170).collect::<String>());
            }
        }
        // Run the REAL witness; on trap, print the full error (instr debug
        // carries the in1 Address for the address-matching pass) and dump
        // memory at every address referenced in the trap window.
        let rt = {
            let mut rt = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
                prog.clone(),
                prover.shrink_prover.config().perm.clone(),
            );
            let mut stream = Vec::new();
            Witnessable::<InnerConfig>::write(&input, &mut stream);
            rt.witness_stream = stream.into();
            let res = rt.run();
            match &res {
                Err(e) => eprintln!(
                    "[SPROBE] real-run TRAP: {}",
                    format!("{e}").chars().take(600).collect::<String>()
                ),
                Ok(()) => eprintln!("[SPROBE] real-run OK (no trap)"),
            }
            rt
        };
        if let Some(i) = hit {
            for w in i.saturating_sub(60)..=(i + 18).min(instrs.len() - 1) {
                let s = format!("{:?}", instrs[w]);
                eprintln!(
                    "[SPROBE] W flat={w}{} {}",
                    if w == i { " <==FAIL" } else { "" },
                    s.chars().take(400).collect::<String>()
                );
            }
            // Dump memory at every address in the window.
            use p3_field::PrimeCharacteristicRing as _;
            let mut addrs: Vec<u32> = Vec::new();
            for w in i.saturating_sub(60)..=(i + 18).min(instrs.len() - 1) {
                let s = format!("{:?}", instrs[w]);
                for cap in s.split("Address(").skip(1) {
                    if let Some(end) = cap.find(')') {
                        if let Ok(a) = cap[..end].parse::<u32>() {
                            if !addrs.contains(&a) {
                                addrs.push(a);
                            }
                        }
                    }
                }
            }
            for &a in addrs.iter() {
                let addr = zkm_recursion_core::Address(KoalaBear::from_u32(a));
                let entry = unsafe { rt.memory.mr_unchecked(addr) };
                eprintln!("[SPROBE] mem[{a}] = {:?}", entry.val);
            }
            // nearest trace below
            let mut p = i as i64;
            while p >= 0 {
                if let Some(Some(t)) = prog.traces.get(p as usize) {
                    let mut t = t.clone();
                    t.resolve();
                    let txt = format!("{t:?}");
                    let lines: Vec<&str> = txt
                        .lines()
                        .filter(|l| l.contains("zkm_"))
                        .take(10)
                        .collect();
                    eprintln!("[SPROBE] nearest-trace flat={p}:
{}", lines.join("
"));
                    break;
                }
                p -= 1;
            }
        }
    }

    /// Probe for a TRIPPED compose (ComposeBasefold) witness:
    /// load the input dumped by the pipelined executor's DUMP_TRIP_INPUT
    /// (env TRIP_INPUT, default /tmp/tripinput_compose_h1_i4.bin),
    /// rebuild the compose program WITH ZKM_DEBUG=true (embeds source
    /// backtraces) and run the real witness on the host runtime — the
    /// trap error then carries "nearest pc with backtrace" naming the
    /// failing in-circuit assert.  Context: the residual hook-independent
    /// multi-GPU compress flake (DivEAssert pc 986076) rejects compose
    /// children that ALL host-verify OK individually (layer-verify
    /// localizer) — this names the cross-child / binding assert.
    #[test]
    #[serial]
    #[ignore]
    fn s7b_compose_trip_replay() {
        use zkm_recursion_circuit::machine::ZKMCompressBasefoldWitnessValues;
        std::env::set_var("ZKM_DEBUG", "true");
        setup_logger();
        let path = std::env::var("TRIP_INPUT")
            .unwrap_or_else(|_| "/tmp/tripinput_compose_h1_i4.bin".to_string());
        let bytes = std::fs::read(&path).expect("need DUMP_TRIP_INPUT compose dump");
        let input: ZKMCompressBasefoldWitnessValues<InnerSC> =
            bincode::deserialize(&bytes).unwrap();
        eprintln!(
            "[S7B] loaded {path}: arity={} is_complete={}",
            input.vks_and_proofs.len(),
            input.is_complete
        );
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let program = prover.compose_program_basefold(&input);
        let mut witness_stream = Vec::new();
        Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
        let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            program.clone(),
            prover.compress_prover.config().perm.clone(),
        );
        runtime.witness_stream = witness_stream.into();
        match runtime.run() {
            Ok(()) => eprintln!(
                "[S7B] compose witness REPLAYS GREEN on host — trap was \
                 execution-environment-dependent (NOT witness content)"
            ),
            Err(e) => eprintln!("[S7B] compose witness TRIPS on host replay: {e}"),
        }
    }

    /// VK-enforcement probe for a TRIPPED normalize (CoreBasefold) program:
    /// load the input dumped by DUMP_TRIP_INPUT (env TRIP_INPUT, default
    /// /tmp/trip_core_2.bin), rebuild the program, run the real witness,
    /// and localize the failing Div{F,E}Assert by operand address
    /// (env TRAP_IN1).
    #[test]
    #[serial]
    #[ignore]
    fn vkroot_enforce_probe_core_trip() {
        use zkm_recursion_circuit::machine::ZKMCoreBasefoldWitnessValues;
        std::env::set_var("ZKM_DEBUG", "true");
        let trap_in1: u32 = std::env::var("TRAP_IN1")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(379644);
        setup_logger();
        let path = std::env::var("TRIP_INPUT")
            .unwrap_or_else(|_| "/tmp/trip_core_2.bin".to_string());
        let bytes = std::fs::read(&path).expect("need DUMP_TRIP_INPUT dump");
        let input: ZKMCoreBasefoldWitnessValues<InnerSC> =
            bincode::deserialize(&bytes).unwrap();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        // Host-side structural analysis: compare the circuit's column-claim
        // geometry (name-sorted machine widths + added-zero heuristic)
        // against the host bundle's actual packing.
        {
            use zkm_pcs::air::MachineAir;
            use zkm_pcs::shard_level::shard_proof::EvaluationProof;
            for (si, sp) in input.shard_proofs.iter().enumerate() {
                let names: Vec<String> = sp.chip_log_heights.keys().cloned().collect();
                eprintln!(
                    "[CPROBE] shard {si}: chip_log_heights={:?}",
                    sp.chip_log_heights
                );
                let _ = &names;
                // Per-chip main widths exactly as the circuit's
                // evaluation_claims sees them: opened_values main.local lens.
                let widths: Vec<usize> = sp
                    .opened_values
                    .chips
                    .iter()
                    .map(|c| c.main.local.len())
                    .collect();
                let flat: usize = widths.iter().sum();
                let added = if widths.len() >= 2 { widths[widths.len() - 2] + 1 } else { 1 };
                let padded = (flat + added).next_power_of_two();
                eprintln!(
                    "[CPROBE] shard {si}: circuit widths(name-sorted)={widths:?} flat={flat} added(heuristic)={added} padded={padded} zcol_circ={}",
                    padded.trailing_zeros()
                );
                if let EvaluationProof::Bundle(b) = &sp.evaluation_proof {
                    let host_cols = b.packing.offsets.len().saturating_sub(1);
                    eprintln!(
                        "[CPROBE] shard {si}: host packing.column_counts={:?} offsets.len()-1={} total_values={} log_dense={} zcol_host={}",
                        b.packing.column_counts,
                        host_cols,
                        b.packing.total_values,
                        b.packing.log_dense_size,
                        host_cols.next_power_of_two().trailing_zeros()
                    );
                    eprintln!(
                        "[CPROBE] shard {si}: y_per_chip lens={:?} (Σ={})",
                        b.y_per_chip.iter().map(|y| y.len()).collect::<Vec<_>>(),
                        b.y_per_chip.iter().map(|y| y.len()).sum::<usize>()
                    );
                }
            }
        }
        let prog = prover.recursion_program_basefold(&input);
        use zkm_recursion_core::Instruction as RInstr;
        let instrs: Vec<&RInstr<KoalaBear>> = prog.iter_instructions().collect();
        eprintln!("[CPROBE] program instrs={}", instrs.len());
        let mut hit = None;
        for (i, ins) in instrs.iter().enumerate() {
            let s = format!("{ins:?}");
            if (s.contains("DivFAssert") || s.contains("DivEAssert"))
                && s.contains(&format!("in1: Address({trap_in1})"))
            {
                hit = Some(i);
                eprintln!(
                    "[CPROBE] consumer flat={i}: {}",
                    s.chars().take(170).collect::<String>()
                );
            }
        }
        let rt = {
            let mut rt = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
                prog.clone(),
                prover.compress_prover.config().perm.clone(),
            );
            let mut stream = Vec::new();
            Witnessable::<InnerConfig>::write(&input, &mut stream);
            rt.witness_stream = stream.into();
            let res = rt.run();
            match &res {
                Err(e) => eprintln!(
                    "[CPROBE] real-run TRAP: {}",
                    format!("{e}").chars().take(600).collect::<String>()
                ),
                Ok(()) => eprintln!("[CPROBE] real-run OK (no trap)"),
            }
            rt
        };
        if let Some(i) = hit {
            for w in i.saturating_sub(60)..=(i + 18).min(instrs.len() - 1) {
                let s = format!("{:?}", instrs[w]);
                eprintln!(
                    "[CPROBE] W flat={w}{} {}",
                    if w == i { " <==FAIL" } else { "" },
                    s.chars().take(400).collect::<String>()
                );
            }
            use p3_field::PrimeCharacteristicRing as _;
            let mut addrs: Vec<u32> = Vec::new();
            for w in i.saturating_sub(60)..=(i + 18).min(instrs.len() - 1) {
                let s = format!("{:?}", instrs[w]);
                for cap in s.split("Address(").skip(1) {
                    if let Some(end) = cap.find(')') {
                        if let Ok(a) = cap[..end].parse::<u32>() {
                            if !addrs.contains(&a) {
                                addrs.push(a);
                            }
                        }
                    }
                }
            }
            for &a in addrs.iter() {
                let addr = zkm_recursion_core::Address(KoalaBear::from_u32(a));
                let entry = unsafe { rt.memory.mr_unchecked(addr) };
                eprintln!("[CPROBE] mem[{a}] = {:?}", entry.val);
            }
        }
    }

    /// VK-enforcement probe for a TRIPPED compose (CompressBasefold)
    /// program: load the input dumped by DUMP_TRIP_INPUT (env TRIP_INPUT,
    /// default /tmp/trip_compose_3.bin), rebuild, run the real witness,
    /// localize by operand address (env TRAP_IN1).
    #[test]
    #[serial]
    #[ignore]
    fn vkroot_enforce_probe_compose_trip() {
        use zkm_recursion_circuit::machine::ZKMCompressBasefoldWitnessValues;
        std::env::set_var("ZKM_DEBUG", "true");
        let trap_in1: u32 = std::env::var("TRAP_IN1")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(400965);
        setup_logger();
        let path = std::env::var("TRIP_INPUT")
            .unwrap_or_else(|_| "/tmp/trip_compose_3.bin".to_string());
        let bytes = std::fs::read(&path).expect("need DUMP_TRIP_INPUT dump");
        let input: ZKMCompressBasefoldWitnessValues<InnerSC> =
            bincode::deserialize(&bytes).unwrap();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        eprintln!(
            "[XPROBE] compose arity={} is_complete={:?}",
            input.vks_and_proofs.len(),
            input.is_complete,
        );
        for (pi, (_vk, p)) in input.vks_and_proofs.iter().enumerate() {
            eprintln!(
                "[XPROBE] input {pi}: chip_log_heights={:?} pv[..24]={:?}",
                p.chip_log_heights,
                p.public_values.iter().take(24).collect::<Vec<_>>()
            );
        }
        let prog = prover.compose_program_basefold(&input);
        use zkm_recursion_core::Instruction as RInstr;
        let instrs: Vec<&RInstr<KoalaBear>> = prog.iter_instructions().collect();
        eprintln!("[XPROBE] program instrs={}", instrs.len());
        let mut hit = None;
        for (i, ins) in instrs.iter().enumerate() {
            let s = format!("{ins:?}");
            if (s.contains("DivFAssert") || s.contains("DivEAssert"))
                && s.contains(&format!("in1: Address({trap_in1})"))
            {
                hit = Some(i);
                eprintln!(
                    "[XPROBE] consumer flat={i}: {}",
                    s.chars().take(170).collect::<String>()
                );
            }
        }
        let rt = {
            let mut rt = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
                prog.clone(),
                prover.compress_prover.config().perm.clone(),
            );
            let mut stream = Vec::new();
            Witnessable::<InnerConfig>::write(&input, &mut stream);
            rt.witness_stream = stream.into();
            let res = rt.run();
            match &res {
                Err(e) => eprintln!(
                    "[XPROBE] real-run TRAP: {}",
                    format!("{e}").chars().take(600).collect::<String>()
                ),
                Ok(()) => eprintln!("[XPROBE] real-run OK (no trap)"),
            }
            rt
        };
        if let Some(i) = hit {
            for w in i.saturating_sub(220)..=(i + 40).min(instrs.len() - 1) {
                let s = format!("{:?}", instrs[w]);
                eprintln!(
                    "[XPROBE] W flat={w}{} {}",
                    if w == i { " <==FAIL" } else { "" },
                    s.chars().take(400).collect::<String>()
                );
            }
            use p3_field::PrimeCharacteristicRing as _;
            let mut addrs: Vec<u32> = Vec::new();
            for w in i.saturating_sub(220)..=(i + 40).min(instrs.len() - 1) {
                let s = format!("{:?}", instrs[w]);
                for cap in s.split("Address(").skip(1) {
                    if let Some(end) = cap.find(')') {
                        if let Ok(a) = cap[..end].parse::<u32>() {
                            if !addrs.contains(&a) {
                                addrs.push(a);
                            }
                        }
                    }
                }
            }
            for &a in addrs.iter() {
                let addr = zkm_recursion_core::Address(KoalaBear::from_u32(a));
                let entry = unsafe { rt.memory.mr_unchecked(addr) };
                eprintln!("[XPROBE] mem[{a}] = {:?}", entry.val);
            }
        }
    }

    /// VK-enforcement NEGATIVE test: corrupt one public value (exit_code)
    /// in an otherwise-honest core proof and run the normalize program —
    /// the armed `assert_felt_eq(exit_code, 0)` (core_basefold.rs) must
    /// reject with a runtime error.  Pre-DivFAssert this tampering was
    /// silently ACCEPTED (the assert was vacuous).
    /// Needs /tmp/fib_core.bin (DUMP_CORE_PROOF from a compress run).
    #[test]
    #[serial]
    #[ignore]
    fn vkroot_enforce_negtest() {
        use std::borrow::BorrowMut as _;
        use zkm_pcs::air::PublicValues;
        use zkm_pcs::Word;
        setup_logger();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let bytes = std::fs::read("/tmp/fib_core.bin").expect("need /tmp/fib_core.bin");
        let mut data: ZKMCoreProofData = bincode::deserialize(&bytes).unwrap();
        let (_, _, _, vk) = prover.setup(test_artifacts::FIBONACCI_ELF);

        // Tamper: exit_code 0 -> 1 in the BASEFOLD side-channel public
        // values (what the normalize witness actually carries).
        {
            let bf = data.0[0]
                .basefold_shard_proof
                .as_mut()
                .expect("core proof missing basefold side-channel");
            let pv: &mut PublicValues<Word<KoalaBear>, KoalaBear> =
                bf.public_values.as_mut_slice().borrow_mut();
            pv.exit_code = KoalaBear::ONE;
        }
        let inputs = prover
            .get_recursion_core_inputs_basefold(&vk.vk, &data.0, REDUCE_BATCH_SIZE, true)
            .expect("basefold inputs");
        let program = prover.recursion_program_basefold(&inputs[0]);
        let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            program,
            prover.compress_prover.config().perm.clone(),
        );
        let mut witness_stream = Vec::new();
        Witnessable::<InnerConfig>::write(&inputs[0], &mut witness_stream);
        runtime.witness_stream = witness_stream.into();
        let res = runtime.run();
        match res {
            Err(e) => {
                let msg = format!("{e}");
                eprintln!(
                    "[NEGTEST] REJECTED as expected: {}",
                    msg.chars().take(160).collect::<String>()
                );
                assert!(
                    msg.contains("division"),
                    "expected a DivFAssert trap, got: {msg}"
                );
            }
            Ok(()) => panic!(
                "[NEGTEST] tampered exit_code was ACCEPTED — enforcement is not armed"
            ),
        }
    }

    /// VKROOT: is fib's normalize vk (computed on THIS box) in the (regen'd)
    /// recursion_vk_map?  Decisive check for the VERIFY_VK=true failure after
    /// the regen — distinguishes a coverage/enumeration gap from a cross-box
    /// build mismatch.
    #[test]
    #[serial]
    #[ignore]
    fn vkroot_check_fib_in_map() {
        use zkm_recursion_circuit::machine::ZKMCoreBasefoldWitnessValues;
        use zkm_pcs::shape::OrderedShape;
        let fib: Vec<(&str, usize)> = vec![
            ("AddSub", 16), ("Bitwise", 13), ("Branch", 13), ("Byte", 16),
            ("CloClz", 5), ("Cpu", 17), ("DivRem", 11), ("Global", 18),
            ("Jump", 11), ("Lt", 15), ("MemoryGlobalFinalize", 17),
            ("MemoryGlobalInit", 17), ("MemoryInstrs", 15), ("MemoryLocal", 11),
            ("MiscInstrs", 11), ("MovCond", 12), ("Mul", 13), ("Program", 19),
            ("ShiftLeft", 13), ("ShiftRight", 11), ("SyscallCore", 11),
            ("SyscallInstrs", 11),
        ];
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let machine = prover.core_prover.machine();
        for ic in [true, false] {
            let os = OrderedShape::from_log2_heights(
                &fib.iter().map(|(n, h)| (n.to_string(), *h)).collect::<Vec<_>>(),
            );
            let shape = ZKMRecursionShape { proof_shapes: vec![os], is_complete: ic };
            let dummy = ZKMCoreBasefoldWitnessValues::dummy(machine, &shape);
            let prog = prover.recursion_program_basefold(&dummy);
            let vk = prover.compress_prover.setup(&prog).1.hash_koalabear();
            eprintln!(
                "[MAPCHK] is_complete={ic}: fib normalize vk={:?} in_map={} (map_size={})",
                vk.map(|x| x.as_canonical_u32()),
                prover.recursion_vk_map.contains_key(&vk),
                prover.recursion_vk_map.len(),
            );
            // VKINJECT=1: add fib's normalize vk to crates/prover/vk_map.bin
            // (on-disk) so a recompile embeds it — proves the recursion-circuit
            // fix delivers VERIFY_VK=true for fib (pending the area-enumeration
            // fix that would cover it via the regen).
            if ic && std::env::var("VKINJECT").is_ok() {
                use std::collections::BTreeMap;
                let bytes = std::fs::read("vk_map.bin").expect("read vk_map.bin");
                let mut map: BTreeMap<[KoalaBear; 8], usize> =
                    bincode::deserialize(&bytes).expect("deser vk_map");
                if !map.contains_key(&vk) {
                    let idx = map.len();
                    map.insert(vk, idx);
                    std::fs::write("vk_map.bin", bincode::serialize(&map).unwrap())
                        .expect("write vk_map.bin");
                    eprintln!("[INJECT] added fib normalize vk; map -> {} entries", map.len());
                } else {
                    eprintln!("[INJECT] already present");
                }
            }
        }
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
        use zkm_recursion_circuit::machine::ZKMCoreBasefoldWitnessValues;
        use zkm_pcs::shape::OrderedShape;
        use zkm_pcs::shard_level::shard_proof::EvaluationProof;
        use zkm_pcs::air::MachineAir;

        let fib_vk = [
            1995641422u32, 1126409227, 1338345684, 1611704093, 650337242, 439362553,
            2125947076, 2022707873,
        ];
        // memory cluster = fib's 22 chips
        let cluster: Vec<&str> = vec![
            "AddSub", "Bitwise", "Branch", "Byte", "CloClz", "Cpu", "DivRem", "Global",
            "Jump", "Lt", "MemoryGlobalFinalize", "MemoryGlobalInit", "MemoryInstrs",
            "MemoryLocal", "MiscInstrs", "MovCond", "Mul", "Program", "ShiftLeft",
            "ShiftRight", "SyscallCore", "SyscallInstrs",
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
            let vk = prover.compress_prover.setup(&prog).1.hash_koalabear().map(|x| x.as_canonical_u32());
            (vk, ld)
        };

        // Construct: spread area across the byte-lookup-FREE fillers at a uniform
        // sweep height (each <= 2^22 max chip height); byte-lookup chips pinned
        // minimal (so Σ byte_lookups·2^h stays tiny); Byte pinned at its table
        // height 16.  Sweep the filler height to cover the log_dense range; the
        // one at log_dense=27 must match fib.
        let fillers = [
            "Program", "Jump", "SyscallInstrs", "MemoryGlobalInit",
            "MemoryGlobalFinalize", "MemoryLocal", "MovCond",
        ];
        for fh in [4usize, 8, 12, 15, 16, 17, 18, 20] {
            let mut hs: Vec<(&str, usize)> = cluster.iter().map(|n| (*n, 1usize)).collect();
            for e in hs.iter_mut() {
                if e.0 == "Byte" { e.1 = 16; }
                if fillers.contains(&e.0) { e.1 = fh; }
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
        use zkm_recursion_circuit::machine::ZKMCoreBasefoldWitnessValues;
        use zkm_pcs::shape::OrderedShape;
        use zkm_pcs::shard_level::shard_proof::EvaluationProof;

        // fib's exact real core shape (from test_vk_equality_normalize_fib dump).
        let fib: Vec<(&str, usize)> = vec![
            ("AddSub", 16), ("Bitwise", 13), ("Branch", 13), ("Byte", 16),
            ("CloClz", 5), ("Cpu", 17), ("DivRem", 11), ("Global", 18),
            ("Jump", 11), ("Lt", 15), ("MemoryGlobalFinalize", 17),
            ("MemoryGlobalInit", 17), ("MemoryInstrs", 15), ("MemoryLocal", 11),
            ("MiscInstrs", 11), ("MovCond", 12), ("Mul", 13), ("Program", 19),
            ("ShiftLeft", 13), ("ShiftRight", 11), ("SyscallCore", 11),
            ("SyscallInstrs", 11),
        ];
        let vk_real: [u32; 8] = [
            1115632139, 1688068798, 1650214975, 1858294344, 1237422514,
            2047442675, 305119098, 273862066,
        ];

        let prover = ZKMProver::<DefaultProverComponents>::new();
        let machine = prover.core_prover.machine();

        // Build dummy from shape, read total_values/log_dense from its bundle,
        // build the normalize program, setup -> vk (canonical u32).  Also
        // returns the program so we can byte/instruction-diff divergent ones.
        let build = |hs: &[(&str, usize)]| -> ([u32; 8], usize, usize, std::sync::Arc<zkm_recursion_core::RecursionProgram<KoalaBear>>) {
            let os = OrderedShape::from_log2_heights(
                &hs.iter().map(|(n, h)| (n.to_string(), *h)).collect::<Vec<_>>(),
            );
            let shape = ZKMRecursionShape { proof_shapes: vec![os], is_complete: true };
            let dummy = ZKMCoreBasefoldWitnessValues::dummy(machine, &shape);
            let (tv, ld) = match &dummy.shard_proofs[0].evaluation_proof {
                EvaluationProof::Bundle(bd) => {
                    (bd.packing.total_values, bd.packing.log_dense_size)
                }
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
            for e in a.iter_mut() { if e.0 == "Program" { e.1 = 18; } }
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
                        if first_idx.is_none() { first_idx = Some(k); }
                        eprintln!("[EQUIV-DIFF] {tag} diff@{k}: fib={:?} | alt={:?}", ri[k], di[k]);
                        shown += 1;
                        if shown >= 8 { break; }
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
                        if !(s.contains("kind: Write") && format!("{:?}", di.get(k)) != format!("{:?}", Some(&ri[k]))) {
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
                                    let frame = rtr.get(j).and_then(|t| t.as_ref()).map(|bt| {
                                        let mut b = bt.clone();
                                        b.resolve();
                                        let fs = format!("{:?}", b);
                                        fs.lines()
                                            .find(|l| l.contains("recursion/circuit/src") || l.contains("stark/src"))
                                            .unwrap_or("(no circuit frame)")
                                            .trim()
                                            .to_string()
                                    }).unwrap_or_else(|| "(reader no trace)".to_string());
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
                                                (l.contains("recursion/circuit/src") || l.contains("stark/src"))
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
                            if shown_rdr >= 6 { break; }
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

    /// Diagnostic: probe a saved core proof for corruption.
    /// Walks the bincode byte stream and reports where deserialization fails.
    #[test]
    #[serial]
    #[ignore]
    fn diag_probe_bad_core() -> Result<()> {
        let path = std::env::var("LOAD_CORE_PROOF").expect("set LOAD_CORE_PROOF");
        let bytes = std::fs::read(&path)?;
        eprintln!("[probe] file size: {}", bytes.len());

        // Use a Read cursor so we can track position via bincode_from_reader.
        let mut cursor = std::io::Cursor::new(&bytes[..]);
        let result: bincode::Result<types::ZKMCoreProofData> = bincode::deserialize_from(&mut cursor);
        match result {
            Ok(p) => eprintln!("[probe] proof deserializes successfully, {} shards", p.0.len()),
            Err(e) => {
                eprintln!("[probe] deserialize error: {e:?}");
                eprintln!("[probe] cursor position when failing: {} (file size {})", cursor.position(), bytes.len());
            }
        }
        Ok(())
    }

    /// Diagnostic: run prove_core ONCE, then run compress() N times on the
    /// SAME core proof. If the compress proof bytes vary, the compress
    /// prover is non-deterministic. If they're identical but only sometimes
    /// verify, the compress verifier is buggy. If they're identical and
    /// always verify or never verify, compress is deterministic.
    #[test]
    #[serial]
    #[ignore]
    fn diag_compress_determinism() -> Result<()> {
        let elf = test_artifacts::FIBONACCI_ELF;
        setup_logger();
        let opts = ZKMProverOpts::default();
        let prover = ZKMProver::<DefaultProverComponents>::new();
        let context = ZKMContext::default();
        let stdin = ZKMStdin::default();
        let (_, pk_d, program, vk) = prover.setup(elf);
        let core_proof = if let Ok(p) = std::env::var("LOAD_CORE_PROOF") {
            let bytes = std::fs::read(&p).expect("read core proof");
            let proof_data: types::ZKMCoreProofData = bincode::deserialize(&bytes).expect("decode");
            ZKMCoreProof {
                proof: proof_data,
                stdin: stdin.clone(),
                public_values: ZKMPublicValues::new(),
                cycles: 0,
            }
        } else {
            prover.prove_core(&pk_d, program, &stdin, opts, context)?
        };
        if let Ok(p) = std::env::var("SAVE_CORE_PROOF") {
            let bytes = bincode::serialize(&core_proof.proof).unwrap();
            std::fs::write(&p, &bytes).unwrap();
            eprintln!("[diag] saved core proof to {}", p);
        }
        let core_verify_result = prover.verify(&core_proof.proof, &vk);
        let core_hash = {
            use std::hash::{Hash, Hasher};
            use std::collections::hash_map::DefaultHasher;
            let bytes = bincode::serialize(&core_proof.proof).unwrap();
            let mut h = DefaultHasher::new();
            bytes.hash(&mut h);
            format!("{:x}", h.finish())
        };
        eprintln!("[diag] core proof hash: {} (size: {}) verify={:?}", core_hash, bincode::serialize(&core_proof.proof).unwrap().len(), core_verify_result.is_ok());

        let cp = core_proof.clone();
        let compressed = prover.compress(&vk, cp, vec![], opts)?;
        let bytes = bincode::serialize(&compressed).unwrap();
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let mut h = DefaultHasher::new();
        bytes.hash(&mut h);
        let chash = format!("{:x}", h.finish());
        let verify_result = prover.verify_compressed(&compressed, &vk);
        eprintln!("[diag] compress hash={} size={} verify={:?}", chash, bytes.len(), verify_result.is_ok());

        if !verify_result.is_ok() {
            if let Ok(p) = std::env::var("SAVE_BAD_CORE") {
                let bytes = bincode::serialize(&core_proof.proof).unwrap();
                std::fs::write(&p, &bytes).unwrap();
                eprintln!("[diag] saved BAD core proof to {}", p);
            }
        } else if let Ok(p) = std::env::var("SAVE_GOOD_CORE") {
            let bytes = bincode::serialize(&core_proof.proof).unwrap();
            std::fs::write(&p, &bytes).unwrap();
            eprintln!("[diag] saved GOOD core proof to {}", p);
        }
        Ok(())
    }

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

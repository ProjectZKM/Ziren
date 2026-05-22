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
        ZKMRecursiveVerifier,
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
use zkm_stark::{
    air::PublicValues, koala_bear_poseidon2::KoalaBearPoseidon2, Challenge, MachineProver,
    ShardProof, StarkGenericConfig, StarkProvingKey, StarkVerifyingKey, Val, Word, ZKMCoreOpts,
    ZKMProverOpts, DIGEST_SIZE,
};
use zkm_stark::{shape::OrderedShape, MachineProvingKey};

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

// ── 128-bit security pipeline aliases (D=5) ──────────────────────────────
//
// These use quintic extension for provable 128-bit security.
// Reference: Plonky3-recursion FriRecursionBackendD5

/// Core prover config with D=5 (128-bit security).
pub type CoreSC128 = zkm_stark::KoalaBearPoseidon2D5;

/// Inner prover config with D=5 (128-bit security).
pub type InnerSC128 = zkm_stark::KoalaBearPoseidon2D5;

/// Outer prover config with D=5 (128-bit security).
pub type OuterSC128 = zkm_recursion_core::stark::KoalaBearPoseidon2OuterD5;

pub type DeviceProvingKey<C> = <<C as ZKMProverComponents>::CoreProver as MachineProver<
    KoalaBearPoseidon2,
    MipsAir<KoalaBear>,
>>::DeviceProvingKey;

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
    /// **History**: Before May 21 2026 (`feat/upgrade-plonky3-program-cache-fix`)
    /// the key was just `arity` (mirroring SP1's
    /// `crates/prover/src/worker/prover/recursion.rs:446`).
    /// That was unsound for Ziren because per-input shapes vary
    /// widely across calls of the same arity (lift heights span
    /// 5K..328K vs SP1's tight clustering — see
    /// `project_256_cache_perf_reverted.md` and
    /// `project_tendermint_speedup_proposals.md` §6).  Re-using a
    /// program built for shape A with shape B's witness stream
    /// triggered `RuntimeError::EmptyWitnessStream` panics under
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

        let core_shape_config = env::var("FIX_CORE_SHAPES")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(true)
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
            bincode::deserialize(include_bytes!("../dummy_vk_map.bin")).unwrap()
        };

        let (root, merkle_tree) = MerkleTree::commit(allowed_vk_map.keys().copied().collect());

        // Legacy FRI compress-program registry removed (May 2026): the
        // basefold path is now the only path. Compose / deferred / shrink
        // / wrap programs are all built lazily per witness via the
        // `*_basefold` builders. The upfront FRI build was 4 ^ REDUCE_BATCH_SIZE
        // programs (256 at arity-4) at >5 min/program with vk_verification.
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

    /// Build the Normalize (basefold) recursion program. Cluster-parametrized
    /// analog of [`Self::recursion_program`].
    ///
    /// Intentionally NOT calling `recursion_shape_config.fix_shape(...)` —
    /// the legacy shape config's `allowed_shapes` was generated for the
    /// smaller legacy recursion programs (~10s of K instructions). The
    /// basefold normalize program is ~660K instructions and produces
    /// chip heights that don't fit any legacy shape, panicking with
    /// "no shape found for heights: ...". The basefold path produces
    /// its own VK based on the program's actual structure; shape
    /// fixing only matters once basefold-aware shapes are enumerated.
    pub fn recursion_program_basefold(
        &self,
        input: &ZKMCoreBasefoldWitnessValues<InnerSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        let max_log_row_count =
            zkm_stark::shard_level::verifier::BasefoldShardVerifier::production_default()
                .max_log_row_count;
        let program = build_normalize_basefold_program(
            self.core_prover.machine(),
            input,
            max_log_row_count,
        );
        Arc::new(program)
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
        // May 21 2026 fix: cache key is now a structural shape signature
        // covering every variable-length collection in the witness
        // write traversal (not just arity).  This makes the cache sound
        // for Ziren's heterogeneous-shape workloads — see
        // `compose_programs_basefold_cache` field docs and
        // `ZKMCompressBasefoldWitnessValues::shape_key`.
        let arity = input.vks_and_proofs.len();
        let cache_key = input.shape_key();

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
                return cached;
            }
        }

        let program = self.build_compose_program_basefold_uncached(input);

        if cache_enabled || verify_cache {
            let mut guard = self.compose_programs_basefold_cache.lock().unwrap();
            // Use entry API so a concurrent inserter doesn't get clobbered.
            return Arc::clone(guard.entry(cache_key).or_insert(program));
        }

        program
    }

    /// Uncached body of [`Self::compose_program_basefold`] — exposed so the
    /// cache wrapper can rebuild on `ZIREN_VERIFY_PROGRAM_CACHE=1` to
    /// assert byte-equality.
    fn build_compose_program_basefold_uncached(
        &self,
        input: &ZKMCompressBasefoldWitnessValues<InnerSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        let max_log_row_count =
            zkm_stark::shard_level::verifier::BasefoldShardVerifier::production_default()
                .max_log_row_count;
        // basefold-for-recursion is now the default. The
        // `ZIREN_FORCE_BASEFOLD_FOR_RECURSION` env toggle and the legacy
        // `build_compose_basefold_program` branch have been retired —
        // the `_recursion` variant is the sole production path.
        let mut program = build_compose_basefold_recursion_program(
            self.compress_prover.machine(),
            input,
            max_log_row_count,
            self.vk_verification,
            PublicValuesOutputDigest::Reduce,
        );
        if let Some(recursion_shape_config) = &self.compress_shape_config {
            recursion_shape_config.fix_shape(&mut program);
        }
        Arc::new(program)
    }

    /// Build the Deferred (basefold) recursion program. Cluster-parametrized
    /// analog of [`Self::deferred_program`].
    pub fn deferred_program_basefold(
        &self,
        input: &ZKMDeferredBasefoldWitnessValues<InnerSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        let max_log_row_count =
            zkm_stark::shard_level::verifier::BasefoldShardVerifier::production_default()
                .max_log_row_count;
        // Step 5 Phase 3e (May 19 2026): basefold-for-recursion is now
        // the default. Mirrors the cutover on
        // `build_compose_program_basefold_uncached`.
        let mut program = build_deferred_basefold_recursion_program(
            self.compress_prover.machine(),
            input,
            max_log_row_count,
            self.vk_verification,
        );
        if let Some(recursion_shape_config) = &self.compress_shape_config {
            recursion_shape_config.fix_shape(&mut program);
        }
        Arc::new(program)
    }

    /// Build the Wrap (basefold) recursion program. Cluster-parametrized
    /// analog of [`Self::shrink_program`] / [`Self::wrap_program`].
    /// Skips `fix_shape` for the same reason as `recursion_program_basefold`
    /// — basefold programs are sized differently from legacy.
    pub fn shrink_program_basefold(
        &self,
        input: &ZKMWrapBasefoldWitnessValues<InnerSC>,
    ) -> Arc<RecursionProgram<KoalaBear>> {
        let max_log_row_count =
            zkm_stark::shard_level::verifier::BasefoldShardVerifier::production_default()
                .max_log_row_count;
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

        let max_log_row_count =
            zkm_stark::shard_level::verifier::BasefoldShardVerifier::production_default()
                .max_log_row_count;

        let builder_span = tracing::debug_span!("build wrap-bn254-basefold program").entered();
        let mut builder = Builder::<WrapConfig>::default();
        let input_var = input.read(&mut builder);
        verify_wrap_basefold::<WrapConfig, InnerSC, _>(
            &mut builder,
            input_var,
            self.shrink_prover.machine(),
            self.vk_verification,
            max_log_row_count,
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
    /// Phase 4. Mirrors the layout of
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
        // Phase 4: when all deferred proofs carry a basefold
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
    // META #59 Phase C vk_map regen Apr 24 v14 (jagged lift: cc[len-2]+1 zero-column formula)
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
                            // #259 pre-sprint instrumentation: upgraded
                            // span to info level + recorded the program's
                            // total instruction count.  Bounds the SeqBlock
                            // parallelism win BEFORE committing the 3-5 week
                            // refactor — if per-call wall is small or the
                            // instruction count is small, the win ceiling
                            // is correspondingly bounded.  Per-compose-call
                            // span lets `cargo run … 2>&1 | grep "execute
                            // runtime"` extract the per-call wall histogram
                            // for any production run.
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
                                        ZKMRecursionProverError::RuntimeError(e.to_string())
                                    })
                                    .unwrap();
                                runtime.record
                            });
                            // #259 instrumentation: emit per-compose-call
                            // wall after the span exits.  Use to bound
                            // the SeqBlock parallelism win — if this is
                            // routinely <100ms, the win ceiling is small
                            // and #259 isn't worth the multi-week sprint.
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
                                let data = tracing::debug_span!("commit")
                                    .in_scope(|| self.compress_prover.commit(&record, traces));

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
                                        &zkm_stark::MachineProof {
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
                    let mut pending: Vec<Vec<Item>> =
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
                        pending[height].push((index, height, vk, proof));
                        received_at_height[height] += 1;

                        let layer_exhausted = received_at_height[height]
                            >= layer_sizes_worker[height];

                        // Drain pending[height] in chunks of up to
                        // `batch_size`. Once the source layer is exhausted
                        // we also flush the final partial chunk.
                        while !pending[height].is_empty()
                            && (pending[height].len() >= batch_size || layer_exhausted)
                        {
                            let take = pending[height].len().min(batch_size);
                            let chunk: Vec<Item> =
                                pending[height].drain(..take).collect();
                            let next_input_height = height + 1;
                            // is_complete iff this emission produces the
                            // root and there's nothing else queued at this
                            // height (covers both N-power-of-arity and
                            // partial-final-chunk cases).
                            let is_complete = next_input_height == expected_height
                                && pending[height].is_empty();

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
                            // #261: bundle vk-merkle witness so the compose
                            // program can read vk_root from input rather than
                            // baking it as a compile-time constant.
                            let vks_only: Vec<StarkVerifyingKey<InnerSC>> =
                                bf_vks_and_proofs.iter().map(|(vk, _)| vk.clone()).collect();
                            let vk_merkle_data =
                                self.make_basefold_merkle_proofs(&vks_only);
                            let input = ZKMCircuitWitness::ComposeBasefold(
                                ZKMCompressBasefoldWitnessValues {
                                    vks_and_proofs: bf_vks_and_proofs,
                                    vk_merkle_data,
                                    is_complete,
                                },
                            );

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
        // #261 SP1 alignment: bundle vk_merkle_data so verify_wrap_basefold
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
        let mut compress_proof = self
            .shrink_prover
            .prove(&shrink_pk, vec![runtime.record], &mut challenger, opts.recursion_opts)
            .unwrap();
        Ok(ZKMReduceProof {
            vk: shrink_vk,
            proof: compress_proof.shard_proofs.pop().unwrap(),
        })
    }

    /// Wrap a reduce proof into a STARK proven over a SNARK-friendly field.
    #[instrument(name = "wrap_bn254", level = "info", skip_all)]
    pub fn wrap_bn254(
        &self,
        compressed_proof: ZKMReduceProof<InnerSC>,
        opts: ZKMProverOpts,
    ) -> Result<ZKMReduceProof<OuterSC>, ZKMRecursionProverError> {
        let ZKMReduceProof { vk: compressed_vk, proof: compressed_proof } = compressed_proof;
        let basefold_proof = *compressed_proof
            .basefold_shard_proof
            .clone()
            .expect("wrap_bn254: input shrink proof missing basefold side-channel — legacy FRI wrap removed");
        // #261 SP1 alignment: bundle vk_merkle_data so verify_wrap_basefold
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
        let input = ZKMCompressWitnessValues {
            vks_and_proofs: vec![(proof.vk.clone(), proof.proof.clone())],
            is_complete: true,
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
        let input = ZKMCompressWitnessValues {
            vks_and_proofs: vec![(proof.vk.clone(), proof.proof.clone())],
            is_complete: true,
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
        let input = ZKMCompressWitnessValues {
            vks_and_proofs: vec![(proof.vk.clone(), proof.proof.clone())],
            is_complete: true,
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

    /// #261 helper: build a merkle witness for a slice of VKs without
    /// going through the legacy `ZKMCompressWitnessValues` shape.
    /// Used by basefold compose/wrap to bundle vk_merkle_data into the
    /// witness that the recursion program reads.  Mirror of the inner
    /// half of [`Self::make_merkle_proofs`].
    pub fn make_basefold_merkle_proofs(
        &self,
        vks: &[StarkVerifyingKey<InnerSC>],
    ) -> ZKMMerkleProofWitnessValues<InnerSC> {
        let num_vks = self.recursion_vk_map.len();
        let (vk_indices, vk_digest_values): (Vec<_>, Vec<_>) = if self.vk_verification {
            vks.iter()
                .map(|vk| {
                    let vk_digest = vk.hash_koalabear();
                    let index = self
                        .recursion_vk_map
                        .get(&vk_digest)
                        .expect("vk not allowed");
                    (index, vk_digest)
                })
                .unzip()
        } else {
            vks.iter()
                .map(|vk| {
                    let vk_digest = vk.hash_koalabear();
                    let index = (vk_digest[0].as_canonical_u32() as usize) % num_vks;
                    (index, [KoalaBear::from_usize(index); 8])
                })
                .unzip()
        };

        let proofs = vk_indices
            .iter()
            .map(|index| {
                let (_, proof) = MerkleTree::open(&self.recursion_vk_tree, *index);
                proof
            })
            .collect();

        ZKMMerkleProofWitnessValues {
            root: self.recursion_vk_root,
            values: vk_digest_values,
            vk_merkle_proofs: proofs,
        }
    }

    pub fn make_merkle_proofs(
        &self,
        input: ZKMCompressWitnessValues<CoreSC>,
    ) -> ZKMCompressWithVKeyWitnessValues<CoreSC> {
        let num_vks = self.recursion_vk_map.len();
        let (vk_indices, vk_digest_values): (Vec<_>, Vec<_>) = if self.vk_verification {
            input
                .vks_and_proofs
                .iter()
                .map(|(vk, _)| {
                    let vk_digest = vk.hash_koalabear();
                    let index = self.recursion_vk_map.get(&vk_digest).expect("vk not allowed");
                    (index, vk_digest)
                })
                .unzip()
        } else {
            input
                .vks_and_proofs
                .iter()
                .map(|(vk, _)| {
                    let vk_digest = vk.hash_koalabear();
                    let index = (vk_digest[0].as_canonical_u32() as usize) % num_vks;
                    (index, [KoalaBear::from_usize(index); 8])
                })
                .unzip()
        };

        let proofs = vk_indices
            .iter()
            .map(|index| {
                let (_, proof) = MerkleTree::open(&self.recursion_vk_tree, *index);
                proof
            })
            .collect();

        let merkle_val = ZKMMerkleProofWitnessValues {
            root: self.recursion_vk_root,
            values: vk_digest_values,
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

    /// #259 unlock-chain validation: build a synthetic compose program
    /// with N=4 dummy inputs and verify that the resulting
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
    #[test]
    #[serial]
    fn compose_basefold_program_emits_seqblock_parallel() {
        use zkm_recursion_circuit::machine::basefold_programs::build_compose_basefold_program;
        use zkm_recursion_circuit::machine::{
            ZKMCompressBasefoldWitnessValues, ZKMCompressWithVkeyShape,
            PublicValuesOutputDigest, ZKMCompressShape,
        };
        use zkm_stark::air::MachineAir;
        use zkm_stark::shape::OrderedShape;

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
            zkm_stark::shard_level::verifier::BasefoldShardVerifier::production_default()
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
                let shape = ZKMProofShape::Recursion(proof.shape());
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

    /// Validates the Phase 4 wrap fix end-to-end: compress + shrink +
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

    /// Tests an end-to-end workflow of proving a program across the entire proof generation
    /// pipeline in addition to verifying deferred proofs.
    #[test]
    #[serial]
    #[ignore]
    fn test_e2e_with_deferred_proofs() -> Result<()> {
        setup_logger();
        test_e2e_with_deferred_proofs_prover::<DefaultProverComponents>(ZKMProverOpts::default())
    }

    /// Phase-1-perf-comparison fixture: prove_core only (Test::Core) on
    /// keccak-sponge ELF.  Multi-shard sha-cluster workload — exercises
    /// the basefold side channel population path in `prove_shard_to_basefold`
    /// without invoking the compose tree (which is blocked on #48).
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

    /// Phase-1-perf-comparison fixture: prove_core only on
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

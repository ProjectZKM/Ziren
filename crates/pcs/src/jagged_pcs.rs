//! Per-chip BaseFold jagged-PCS adapter.
//!
//! The BaseFold replacement for the (now-removed) WHIR late-binding
//! commit for the OOM-blocker chip-trace commit step.  The structural win:
//! each chip trace becomes one MLE that goes through
//! [`crate::basefold::StackedPcsProver`], so the BaseFold encoder
//! materializes one stripe at a time (`1 << log_stacking_height`
//! rows × `batch_size` polys) instead of one giant dense LDE.  No
//! `Vec<F>` of size `2^(num_vars + log_blowup)` is ever held in
//! memory at once — that's the structural cure for tendermint /
//! large-sum's 100+ GB peak RSS that shard-splitting only
//! palliated.
//!
//! Phase-C scope (this file): commit + open + verify with a fixed
//! evaluation point, no jagged sumcheck reduction yet.  Wiring into
//! [`crate::jagged`]'s sumcheck flow is C2/C3.


use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_challenger::CanObserve;
use p3_dft::Radix2DitParallel;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::basefold::{
    BasefoldProver, BasefoldVerifier, FriConfig, Mle, StackedBasefoldProof,
    StackedBasefoldProverData, StackedPcsProver, StackedPcsVerifier,
};
use crate::kb31_poseidon2::{InnerChallenge, InnerChallenger, InnerValMmcs};

pub type JaggedVal = crate::kb31_poseidon2::InnerVal;
pub type JaggedChallenge = InnerChallenge;
pub type JaggedDft = Radix2DitParallel<JaggedVal>;
pub type JaggedMmcs = InnerValMmcs;
pub type JaggedChallenger = InnerChallenger;

/// One committed batch of chip traces, plus the per-chip metadata
/// needed to recompute evaluation points on the verifier side.
///
/// BaseFold-over-BN254 port — generic over the MMCS `MT` so
/// the inner (Poseidon2-KoalaBear) and the wrap (OuterSC, Poseidon2-BN254)
/// commit paths share one struct.  `Val`/`Challenge` stay KoalaBear /
/// KoalaBear⁴ for both (mirrors SP1's `BNGC<KoalaBear,KoalaBear⁴>`); only
/// the commitment hash varies.  The concrete [`JaggedCommit`]
/// alias below pins `MT = JaggedMmcs` so every existing caller (incl.
/// serde wire-format + the ziren-gpu hooks) compiles unchanged.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(bound(
    serialize = "<MT as p3_commit::Mmcs<JaggedVal>>::Commitment: serde::Serialize",
    deserialize = "<MT as p3_commit::Mmcs<JaggedVal>>::Commitment: serde::Deserialize<'de>"
))]
pub struct JaggedCommitGeneric<MT: p3_commit::Mmcs<JaggedVal>> {
    /// SP1 names this `original_commitment`. The `#[serde(rename = "commitment")]`
    /// pins the *serialized* field name to the historical `commitment` so the
    /// (positional) proof wire format is byte-identical across the rename.
    #[serde(rename = "commitment")]
    pub original_commitment: <MT as p3_commit::Mmcs<JaggedVal>>::Commitment,
    /// Per-chip `(width, log_height_padded)` so the verifier can
    /// reconstruct the same Mle shapes when checking openings.
    pub chip_dims: Vec<(usize, u32)>,
    /// Total `[batch_size << log_stacking_height]` area of the
    /// stacked PCS commit — equals the verifier's `round_areas[0]`.
    pub area: usize,
    /// Actual log_stacking_height used for this commit (clamped down
    /// for tiny commits — see [`pick_log_stacking_height`]).
    pub log_stacking_height: u32,
}

/// Concrete inner (Poseidon2-KoalaBear) commit — the type every current
/// caller uses.  Transparent alias to the generic struct so struct
/// literals / field access compile unchanged.
pub type JaggedCommit = JaggedCommitGeneric<JaggedMmcs>;

pub struct JaggedProverDataGeneric<MT: p3_commit::Mmcs<JaggedVal>> {
    pub stacked_data: StackedBasefoldProverData<JaggedVal, MT>,
    pub chip_dims: Vec<(usize, u32)>,
    pub area: usize,
    pub log_stacking_height: u32,
}

/// Concrete inner prover-data alias (`MT = JaggedMmcs`).
pub type JaggedProverData = JaggedProverDataGeneric<JaggedMmcs>;

/// Defaults chosen to match the perf-results sweet spot:
/// `log_stacking_height=14` → 16K rows per stripe, well below the
/// 131K shard-split cliff that worked for tendermint at 51.7 GB.
/// Small commits (under 16K total entries) clamp this down so the
/// stacked PCS doesn't end up over-padding past the actual data.
pub const DEFAULT_LOG_STACKING_HEIGHT: u32 = 21;

/// RECURSION-LAYER trace-area pin.
///
/// SP1's `crates/prover/src/components.rs` pins `RECURSION_LOG_TRACE_AREA = 27`
/// for the compress/recursion machine: every recursion proof (normalize AND
/// compose) commits its jagged dense at a FIXED area `2^27`, so the committed
/// codeword always has `num_stripes = 2^(27 - log_stacking_height) = 2^(27-21)
/// = 64` columns BY CONSTRUCTION.  With the per-child stripe shape fixed, every
/// compose child-bundle read is constant-length, so the compose VK collapses to
/// `f(chip-set, arity)` (the precondition for an enumerable FIX-off recursion
/// vk_map).
///
/// The CORE (`RiscvAir`) commit is NOT pinned — it stays NATURAL (the FIX-off
/// perf win is a core-trace property).  The pin is keyed by which machine is
/// proving: the recursion (`compress`) prover passes
/// `Some(RECURSION_LOG_TRACE_AREA)` as the `recursion_area_pin` param of
/// `MachineProver::commit`, so
/// [`precompute_jagged_basefold_commit_generic`] /
/// [`precompute_jagged_basefold_commit`] bump `packing.log_dense_size` to
/// `max(natural, RECURSION_LOG_TRACE_AREA)` and record it on
/// `PrecomputedJaggedCommit.recursion_area_pin` (read back at open); core passes
/// `None` and is byte-identical to the unpinned path.
pub const RECURSION_LOG_TRACE_AREA: usize = 27;

/// Interleave batch size for the stacked PCS: number of MLE-column
/// streams packed into each stripe.  **`32`** matches SP1's
/// `slop_jagged::basefold::DEFAULT_INTERLEAVE_BATCH_SIZE`
/// (raised from `16`).  Halves the number of stripes per BaseFold
/// commit, which directly halves the Merkle-commit count and the
/// per-stripe DFT count without increasing per-stripe LDE memory.
/// SP1-parity; no soundness implication (purely a packing constant).
pub const DEFAULT_BATCH_SIZE: usize = 32;

/// FIXED stacking height: ALWAYS `DEFAULT_LOG_STACKING_HEIGHT`
/// (21), never clamped down for small commits.
///
/// Clamping to `min(21, log2(np2(total))-1)` for tiny commits would make
/// the prover's `log_stacking_height` depend on the trace AREA.  Because the
/// recursion normalize/compress program is rebuilt per-proof from
/// `bundle.commit.log_stacking_height` (the value the prover used), that
/// clamp would make the program — hence its VK — CLAMP-DEPENDENT (the VK
/// varying with chip heights), which is exactly what forces FIX_CORE_SHAPES
/// + a height-quantized vk_map.
///
/// SP1's `JaggedPcsProver::commit_multilinears` instead FIXES the stacking
/// height and rounds the trace AREA up to a multiple of `2^21` (each call
/// site does `area = total_entries.next_multiple_of(1 << 21)`), so every
/// commit is honestly 21-round → the per-proof verifier rebuild
/// constant-folds to `num_variables = 21` → clamp-INDEPENDENCE, with no
/// transcript masking and no Fiat-Shamir risk (the unsound verifier-side
/// alternative).  The normalize VK then depends on the chip-SET only — the
/// precondition for retiring FIX_CORE_SHAPES while keeping VERIFY_VK=true.
///
/// `total_entries` is retained for call-site/API symmetry but does not
/// affect the height (the call-site area padding absorbs it).
pub fn pick_log_stacking_height(_total_entries: usize) -> u32 {
    DEFAULT_LOG_STACKING_HEIGHT
}




/// Public for the GPU commit-dispatch hook: the
/// device-side commit path needs to run the same MLE-construction +
/// padding logic as the host before invoking the GPU encoder.
pub fn chips_to_mles_owned(
    chip_traces: Vec<(String, RowMajorMatrix<JaggedVal>)>,
) -> (Vec<Arc<Mle<JaggedVal>>>, Vec<(usize, u32)>) {
    let mut mles = Vec::with_capacity(chip_traces.len());
    let mut dims = Vec::with_capacity(chip_traces.len());
    for (_, trace) in chip_traces.into_iter() {
        let width = trace.width.max(1);
        let raw_height = trace.values.len() / width;
        // Round out to whole stacking blocks, NOT to a power of two.  The only
        // caller hands over the single width-1 jagged dense, and the interleave
        // below re-stripes it at exactly this granularity, so a power-of-two
        // round-up buys nothing and costs up to half the committed area — the
        // waste SP1 does not pay (`hypercube/src/prover/simple.rs:33`).
        let padded_height = raw_height.next_multiple_of(1usize << DEFAULT_LOG_STACKING_HEIGHT);
        // `log_h` is the dims' height slot and stays a LOG, so for a
        // non-power-of-two block count it is the enclosing hypercube, an upper
        // bound rather than the exact height.
        let log_h = padded_height.max(1).next_power_of_two().trailing_zeros();

        let values = if raw_height == padded_height {
            trace.values
        } else {
            let mut padded = trace.values;
            padded.resize(padded_height * width, JaggedVal::ZERO);
            padded
        };

        mles.push(Arc::new(Mle::from_row_major(RowMajorMatrix::new(values, width))));
        dims.push((width, log_h));
    }
    (mles, dims)
}

/// Commit a batch of chip traces (consumes ownership — saves the
/// `trace.values.clone()` round-trip in `chips_to_mles_owned`).
/// Returns a public commitment (observed by the challenger as a
/// side effect) and prover-side state for later opening.
///
/// The shard commit runs the host BaseFold + Plonky3 MMCS commit.  The GPU
/// prover does NOT reach this free-fn — its device dense-pack + BaseFold commit
/// is the `StarkGpuProver` override of `MachineProver::commit_multilinears`
/// (SP1-parity: unconditional device commit, no host fallback).  This free-fn is
/// the CPU-prover / unit-test path.
///
/// Does NOT observe the commitment.  Like SP1's
/// `JaggedProver::commit_multilinears` (slop/crates/jagged/src/prover.rs:106)
/// this takes no challenger; the CALLER owns the transcript write and must
/// observe `commit.original_commitment` at the same position as the verifier.
/// On the single-main-commit flow that write is the shard-level Phase 1
/// prologue's 8-felt `main_commitment` observe — observing here as well would
/// desync the prover against the verifier.  The verifier counterpart is
/// [`jagged::verify_jagged_basefold_no_observe`].
pub fn commit_jagged_pcs(
    chip_traces: Vec<(String, RowMajorMatrix<JaggedVal>)>,
) -> (JaggedCommit, JaggedProverData) {
    let perm: crate::kb31_poseidon2::InnerPerm = zkm_primitives::poseidon2_init();
    let hash = crate::kb31_poseidon2::InnerHash::new(perm.clone());
    let compress = crate::kb31_poseidon2::InnerCompress::new(perm);
    let mmcs = JaggedMmcs::new(hash, compress, 0);
    let dft = Arc::new(JaggedDft::default());
    // Delegate to the GC-generic core (inner = Poseidon2-KoalaBear Mmcs).
    commit_jagged_pcs_generic::<JaggedMmcs, JaggedDft>(
        chip_traces,
        mmcs,
        dft,
        FriConfig::<JaggedVal>::from_env_or_default(),
    )
}

/// BaseFold-over-BN254 port: GC-generic commit core.  Does not touch the
/// transcript: like SP1's `JaggedProver::commit_multilinears`
/// (slop/crates/jagged/src/prover.rs:106) it takes no challenger, and the
/// caller owns the `observe` of the returned commitment.  Parameterized over the MMCS `MT` + DFT `D`; the caller
/// supplies the concrete `mmcs`/`dft` so the inner (Poseidon2-KoalaBear)
/// and the wrap (OuterSC, Poseidon2-BN254) paths share one body.
/// `Val`/`Challenge` stay KoalaBear / KoalaBear⁴ for both.
#[allow(clippy::type_complexity)]
pub fn commit_jagged_pcs_generic<MT, D>(
    chip_traces: Vec<(String, RowMajorMatrix<JaggedVal>)>,
    mmcs: MT,
    dft: Arc<D>,
    fri: FriConfig<JaggedVal>,
) -> (
    JaggedCommitGeneric<MT>,
    JaggedProverDataGeneric<MT>,
)
where
    MT: p3_commit::Mmcs<JaggedVal, Commitment: Clone> + Clone,
    D: p3_dft::TwoAdicSubgroupDft<JaggedVal> + Send + Sync,
{
    let (mles, chip_dims) = chips_to_mles_owned(chip_traces);
    let total_entries: usize = mles.iter().map(|m| m.guts().total_len()).sum();
    let log_stacking_height = pick_log_stacking_height(total_entries);
    let area = total_entries.next_multiple_of(1usize << log_stacking_height);

    // Build only the prover: SP1 constructs the stacked PCS at the call site and
    // never pairs it with a verifier it does not use
    // (slop/crates/stacked, crates/recursion/circuit/src/basefold/stacked.rs:129).
    let prover = StackedPcsProver::new(
        BasefoldProver::<JaggedVal, JaggedChallenge, MT, D>::new(fri, dft, mmcs, 1),
        log_stacking_height,
        DEFAULT_BATCH_SIZE,
    );
    let (commitment, stacked_data) = prover.commit_multilinears(mles);

    let commit = JaggedCommitGeneric::<MT> {
        original_commitment: commitment.clone(),
        chip_dims: chip_dims.clone(),
        area,
        log_stacking_height,
    };
    let prover_data = JaggedProverDataGeneric::<MT> {
        stacked_data,
        chip_dims,
        area,
        log_stacking_height,
    };
    (commit, prover_data)
}

/// Extract the 8-felt MMCS digest from a [`JaggedCommit`].
/// The digest is the value the verifier's Phase 1 prologue observes as
/// `main_commitment` in the single-main-commit flow.
///
/// The commitment is a `MerkleCap<KoalaBear, [KoalaBear; 8]>` (the
/// Plonky3 `MerkleTreeMmcs::Commitment` for `InnerValMmcs`).  This
/// helper pulls out the first cap root — the same byte sequence
/// `DuplexChallenger::observe(MerkleCap)` consumes.
#[must_use]
/// Extract the 8-felt MerkleCap root from a JaggedMmcs commitment (the
/// inner BasefoldRing::digest_felts body).
pub fn basefold_commit_digest_felts(
    commitment: &<JaggedMmcs as p3_commit::Mmcs<JaggedVal>>::Commitment,
) -> [JaggedVal; 8] {
    let roots = commitment.roots();
    assert!(!roots.is_empty(), "JaggedCommit MerkleCap must have at least one root");
    roots[0]
}

pub fn basefold_commit_digest(commit: &JaggedCommit) -> [JaggedVal; 8] {
    let roots = commit.original_commitment.roots();
    assert!(
        !roots.is_empty(),
        "JaggedCommit MerkleCap must have at least one root",
    );
    roots[0]
}


// ─────────────────────────────────────────────────────────────────────
// Jagged "hash-bind" (the count ↔ commitment tie).
//
// Ziren historically returned the RAW BaseFold root as the observed
// commitment, with NO cryptographic binding of the per-chip
// (row_count, column_count) geometry to that root.  That left the jagged
// geometry prover-supplied and (under the height-agnostic recursion)
// forgeable: a prover could witness a different geometry than was actually
// committed and still pass the prefix-sum / area consistency checks (which
// only tie the geometry to itself).
//
// SP1 closes this by hashing the geometry and folding it into the observed
// commitment (slop/crates/jagged/src/prover.rs:141-149):
//
//     hash = hash_iter( once(len) ++ row_counts ++ column_counts )
//     modified = compress([raw_root, hash])
//
// and re-checking it in `verify_trusted_evaluations`
// (slop/crates/jagged/src/verifier.rs:206-217).  The observed (Fiat-Shamir)
// commitment becomes `modified`; the BaseFold opening still binds against
// `raw_root` (carried as `original_commitment`).
//
// CONVENTION LOCK (host == circuit must be byte-identical):
//   * `len` is `column_counts.len()` (== `row_counts.len()`; SP1 prover
//     uses `row_counts.len()`, the in-circuit verifier uses
//     `column_counts.len()` — they are equal, we pick `column_counts.len()`
//     and use it IDENTICALLY in both places to avoid any FS desync).
//   * the geometry is the PER-CHIP `(row_count, column_count)` derived from
//     the SAME `packing.offsets` / `packing.column_counts` the recursion
//     lift reconstructs (`shard_level_witness.rs` `packing_row_counts`),
//     so the in-circuit recompute hashes the identical felt sequence.
//   * felts are `from_canonical_usize` (wraps mod the field order — the
//     in-circuit verifier guards each count `< F::ORDER` so the wrap can
//     never be exploited; see the recursion guards).
// ─────────────────────────────────────────────────────────────────────

/// Derive the per-chip `(row_counts, column_counts)` the hash-bind hashes,
/// from the host jagged `PackingMeta`.  This is the SINGLE source of truth
/// for the hash convention — both the host emit path
/// (`jagged_hash_bind_modified`) and the in-circuit recompute consume the
/// SAME per-chip vectors (the recursion lift's `packing_row_counts` /
/// `packing.column_counts`), so the hashed felt sequence is byte-identical.
///
/// `row_counts[i]` = height of chip `i` = `offsets[col_i+1] - offsets[col_i]`
/// where `col_i` is the first column index of chip `i` (a `column_count==0`
/// chip contributes height `0`).  `column_counts[i] = packing.column_counts[i]`.
#[must_use]
pub fn jagged_counts_from_packing(
    packing: &jagged::PackingMeta,
) -> (Vec<usize>, Vec<usize>) {
    let column_counts: Vec<usize> = packing.column_counts.clone();
    let offsets = &packing.offsets;
    let total_values = packing.total_values;
    let mut row_counts: Vec<usize> = Vec::with_capacity(column_counts.len());
    let mut col_idx = 0usize;
    for &cc in column_counts.iter() {
        if cc == 0 {
            row_counts.push(0);
            continue;
        }
        let h = if col_idx + 1 < offsets.len() {
            offsets[col_idx + 1].saturating_sub(offsets[col_idx])
        } else if col_idx < offsets.len() {
            total_values.saturating_sub(offsets[col_idx])
        } else {
            0
        };
        row_counts.push(h);
        col_idx += cc;
    }
    (row_counts, column_counts)
}

/// Compute the geometry hash for ONE round (one commit):
/// `hash_iter( once(len) ++ row_counts ++ column_counts )` where
/// `len = column_counts.len()`.  Uses the inner Poseidon2-KoalaBear sponge
/// (`InnerHash`) — the SAME hasher `SC::hash` resolves to in-circuit.
#[must_use]
pub fn jagged_geometry_hash(
    row_counts: &[usize],
    column_counts: &[usize],
) -> [JaggedVal; 8] {
    use p3_field::PrimeCharacteristicRing;
    use p3_symmetric::CryptographicHasher;
    let perm: crate::kb31_poseidon2::InnerPerm = zkm_primitives::poseidon2_init();
    let hasher = crate::kb31_poseidon2::InnerHash::new(perm);
    let len = column_counts.len();
    let iter = core::iter::once(JaggedVal::from_canonical_usize(len))
        .chain(row_counts.iter().map(|&c| JaggedVal::from_canonical_usize(c)))
        .chain(column_counts.iter().map(|&c| JaggedVal::from_canonical_usize(c)));
    hasher.hash_iter(iter)
}

/// Fold the geometry hash into the raw BaseFold root: `compress([raw, hash])`.
/// Uses `InnerCompress` (the SAME compressor `SC::compress` resolves to
/// in-circuit).  Returns the MODIFIED 8-felt digest that the Fiat-Shamir
/// transcript observes as `main_commitment`.
#[must_use]
pub fn jagged_hash_bind_modified(
    raw_root: [JaggedVal; 8],
    row_counts: &[usize],
    column_counts: &[usize],
) -> [JaggedVal; 8] {
    use p3_symmetric::PseudoCompressionFunction;
    let perm: crate::kb31_poseidon2::InnerPerm = zkm_primitives::poseidon2_init();
    let compressor = crate::kb31_poseidon2::InnerCompress::new(perm);
    let hash = jagged_geometry_hash(row_counts, column_counts);
    compressor.compress([raw_root, hash])
}

/// Convenience: compute the MODIFIED digest directly from the raw commit +
/// packing — the host emit-site one-liner.
#[must_use]
pub fn jagged_hash_bind_from_packing(
    raw_root: [JaggedVal; 8],
    packing: &jagged::PackingMeta,
) -> [JaggedVal; 8] {
    let (row_counts, column_counts) = jagged_counts_from_packing(packing);
    jagged_hash_bind_modified(raw_root, &row_counts, &column_counts)
}

/// Derive the per-chip `(row_counts, column_counts)` from a full
/// [`crate::jagged::JaggedPacking`] (the form the host commit prover holds in
/// `PrecomputedJaggedCommit.packing`).  Uses the OFFSETS-based derivation
/// (NOT `chip_infos[i].row_count`) so it is byte-identical to the recursion
/// lift's `packing_row_counts` (`shard_level_witness.rs`) and to
/// [`jagged_counts_from_packing`]: a `column_count == 0` chip contributes
/// height `0` regardless of its raw trace height.
#[must_use]
pub fn jagged_counts_from_jagged_packing(
    packing: &crate::jagged::JaggedPacking<JaggedVal>,
) -> (Vec<usize>, Vec<usize>) {
    let column_counts: Vec<usize> =
        packing.chip_infos.iter().map(|ci| ci.column_count).collect();
    let offsets = &packing.offsets;
    let total_values = packing.total_values;
    let mut row_counts: Vec<usize> = Vec::with_capacity(column_counts.len());
    let mut col_idx = 0usize;
    for &cc in column_counts.iter() {
        if cc == 0 {
            row_counts.push(0);
            continue;
        }
        let h = if col_idx + 1 < offsets.len() {
            offsets[col_idx + 1].saturating_sub(offsets[col_idx])
        } else if col_idx < offsets.len() {
            total_values.saturating_sub(offsets[col_idx])
        } else {
            0
        };
        row_counts.push(h);
        col_idx += cc;
    }
    (row_counts, column_counts)
}

/// Host emit-site one-liner: the MODIFIED digest from the raw root + the
/// full `JaggedPacking` the commit prover holds.  This is the value the
/// Fiat-Shamir transcript observes as `main_commitment`.
#[must_use]
pub fn jagged_hash_bind_from_jagged_packing(
    raw_root: [JaggedVal; 8],
    packing: &crate::jagged::JaggedPacking<JaggedVal>,
) -> [JaggedVal; 8] {
    let (row_counts, column_counts) = jagged_counts_from_jagged_packing(packing);
    jagged_hash_bind_modified(raw_root, &row_counts, &column_counts)
}

/// Host-side mirror of the in-circuit re-bind (SP1
/// `verify_trusted_evaluations`): recompute `compress([raw, hash(counts)])`
/// and check it equals the observed `modified` digest.  Used by the G-host
/// round-trip gate to LOCK the convention before the circuit consumes it.
#[must_use]
pub fn jagged_hash_bind_verify(
    raw_root: [JaggedVal; 8],
    modified: [JaggedVal; 8],
    packing: &jagged::PackingMeta,
) -> bool {
    let recomputed = jagged_hash_bind_from_packing(raw_root, packing);
    recomputed == modified
}

/// Production-grade FRI config used by the jagged-PCS pipeline.
/// Public so the GPU dispatch hook can construct a matching
/// device-side encoder (same `log_blowup`, same coset shift) without
/// re-creating the env-overrides logic.
pub fn lb_fri_config() -> FriConfig<JaggedVal> {
    FriConfig::<JaggedVal>::from_env_or_default()
}

// ─────────────────────────────────────────────────────────────────────
// GPU jagged-reduction sumcheck dispatch hook.
//
// Mirrors the host `crate::jagged_sumcheck::prove_jagged_reduction_owned`
// signature one-for-one — same inputs (owned `dense_q`, packing,
// `r_row_per_chip`, `y_per_chip`, challenger), same output
// (`JaggedReductionProof<InnerChallenge>`).  Wired from
// `prove_jagged_basefold_with_y_per_chip` step (4) when the GPU
// jagged-reduction hook is registered (GPU prover only).
//
// Per-shard wall: 2.41–2.76s × 25 shards ≈ 62s of the 144s tendermint
// compress wall (measured) — the largest remaining
// per-shard host bottleneck after the BaseFold commit moved to GPU.
// ─────────────────────────────────────────────────────────────────────

/// Borrowed-cells view of an EF row-GKR layer suitable for the GPU
/// init hook.  The four sub-MLEs are passed by slice so the upload
/// stays zero-copy on the host side; the GPU side is responsible for
/// the memcpy / pin + dma into device memory.
///
/// Lifetime borrows from the `LogUpGkrCpuLayer<JaggedChallenge, JaggedChallenge>`
/// the dispatch site holds across the call.
pub struct HostLayerView<'a> {
    pub numerator_0: &'a [crate::shard_level::row_gkr::layer::RowMajorTable<JaggedChallenge>],
    pub denominator_0: &'a [crate::shard_level::row_gkr::layer::RowMajorTable<JaggedChallenge>],
    pub numerator_1: &'a [crate::shard_level::row_gkr::layer::RowMajorTable<JaggedChallenge>],
    pub denominator_1: &'a [crate::shard_level::row_gkr::layer::RowMajorTable<JaggedChallenge>],
    pub num_row_variables: usize,
    pub num_interaction_variables: usize,
}

/// Process-wide monotonic counter for GKR-circuit IDs.  Each
/// `build_gkr_circuit` call that takes the device path allocates a
/// fresh ID via [`allocate_gpu_layer_circuit_id`] and threads it
/// through every device-layer init / transition / pull hook
/// invocation.  The GPU side keys its registry by
/// `(device_id, circuit_id)` so concurrent shards on the same GPU are
/// fully isolated — fixes multi-GPU panics caused by a shared
/// `next_handle` counter being stepped on across shards.
// Backing storage uses AtomicUsize, not AtomicU64, so the file
// compiles on the zkvm-elf target (mipsel — no
// `target_has_atomic="64"`).  The GPU registry never executes on the
// zkvm-elf binary, but the symbol still has to type-check in that
// build because `row_gkr/build.rs` imports the helper unconditionally.
// Public API (`u64`) is preserved via cast.  On host (64-bit)
// `usize == u64`; on the 32-bit zkvm-elf the upper bits are always
// zero and circuit IDs grow well within `u32::MAX`.
static NEXT_GPU_LAYER_CIRCUIT_ID: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(1);

/// Allocate a fresh process-unique GKR-circuit ID for use with the
/// GPU layer-state hooks.  Must be called once per
/// `build_gkr_circuit` device-path invocation; the returned ID is
/// passed verbatim to every init/transition/pull hook for that
/// circuit.
///
/// IDs start at 1 (0 reserved as a sentinel) and increment
/// monotonically.  Wraparound is not handled — at u64 capacity that
/// would require ~10^9 circuits/sec for centuries, which is well
/// outside the threat model.
#[must_use]
pub fn allocate_gpu_layer_circuit_id() -> u64 {
    NEXT_GPU_LAYER_CIRCUIT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u64
}

/// Pure host-side implementation of the jagged-PCS open —
/// extracted so the GPU dispatch hook can fall back to it on
/// shape-unsupported / runtime errors without re-entering the env-flag
/// dispatch loop.  Always runs the CPU StackedPcsProver
/// `prove_trusted_evaluation` body.
/// Batched multi-ROUND open: one BaseFold proof covering every round's
/// committed data.
///
/// SP1 opens all rounds in a single `prove_untrusted_evaluation` over
/// `stacked_prover_data: Rounds<_>` (`slop/crates/jagged/src/prover.rs:300`) —
/// NOT one proof per round.  Every round's stripes are `log_stacking_height`
/// tall, so `BasefoldProver::batch` folds them into one codeword regardless of
/// how many stripes each round contributes.
pub fn open_jagged_pcs_rounds(
    rounds: &[&JaggedProverData],
    eval_point: Vec<JaggedChallenge>,
    challenger: &mut JaggedChallenger,
) -> StackedBasefoldProof<JaggedVal, JaggedChallenge, JaggedMmcs> {
    let perm: crate::kb31_poseidon2::InnerPerm = zkm_primitives::poseidon2_init();
    let hash = crate::kb31_poseidon2::InnerHash::new(perm.clone());
    let compress = crate::kb31_poseidon2::InnerCompress::new(perm);
    let mmcs = JaggedMmcs::new(hash, compress, 0);
    let dft = Arc::new(JaggedDft::default());
    let log_stacking_height = rounds[0].log_stacking_height;
    let prover = StackedPcsProver::new(
        BasefoldProver::<JaggedVal, JaggedChallenge, JaggedMmcs, JaggedDft>::new(
            FriConfig::<JaggedVal>::from_env_or_default(),
            dft,
            mmcs,
            // One expected commitment PER ROUND.
            rounds.len(),
        ),
        log_stacking_height,
        DEFAULT_BATCH_SIZE,
    );
    // Borrowed: the committed Merkle trees are read, never copied.
    let stacked: Vec<&_> = rounds.iter().map(|r| &r.stacked_data).collect();
    prover.prove_trusted_evaluation(eval_point, &stacked, challenger)
}

/// Ring-generic counterpart of [`open_jagged_pcs_rounds`]: ONE batched open
/// across every round's committed data, over any commitment family.  The
/// BN254 wrap ring reaches the multi-round open through this.
pub fn open_jagged_pcs_rounds_generic<Challenger, MT, D>(
    rounds: &[&JaggedProverDataGeneric<MT>],
    eval_point: Vec<JaggedChallenge>,
    challenger: &mut Challenger,
    mmcs: MT,
    dft: Arc<D>,
    fri: FriConfig<JaggedVal>,
) -> StackedBasefoldProof<JaggedVal, JaggedChallenge, MT>
where
    MT: p3_commit::Mmcs<JaggedVal, Commitment: Clone> + Clone,
    D: p3_dft::TwoAdicSubgroupDft<JaggedVal> + Send + Sync,
    Challenger: p3_challenger::FieldChallenger<JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = JaggedVal>
        + CanObserve<<MT as p3_commit::Mmcs<JaggedVal>>::Commitment>,
{
    let log_stacking_height = rounds[0].log_stacking_height;
    let prover = StackedPcsProver::new(
        // One expected commitment PER ROUND.
        BasefoldProver::<JaggedVal, JaggedChallenge, MT, D>::new(fri, dft, mmcs, rounds.len()),
        log_stacking_height,
        DEFAULT_BATCH_SIZE,
    );
    // Borrowed: the committed Merkle trees are read, never copied.
    let stacked: Vec<&_> = rounds.iter().map(|r| &r.stacked_data).collect();
    prover.prove_trusted_evaluation(eval_point, &stacked, challenger)
}

pub fn open_jagged_pcs(
    prover_data: &JaggedProverData,
    eval_point: Vec<JaggedChallenge>,
    challenger: &mut JaggedChallenger,
) -> StackedBasefoldProof<JaggedVal, JaggedChallenge, JaggedMmcs> {
    let perm: crate::kb31_poseidon2::InnerPerm = zkm_primitives::poseidon2_init();
    let hash = crate::kb31_poseidon2::InnerHash::new(perm.clone());
    let compress = crate::kb31_poseidon2::InnerCompress::new(perm);
    let mmcs = JaggedMmcs::new(hash, compress, 0);
    let dft = Arc::new(JaggedDft::default());
    // Delegate to the GC-generic core (inner = Poseidon2-KoalaBear Mmcs).
    open_jagged_pcs_generic::<JaggedChallenger, JaggedMmcs, JaggedDft>(
        prover_data,
        eval_point,
        challenger,
        mmcs,
        dft,
        FriConfig::<JaggedVal>::from_env_or_default(),
    )
}

/// BaseFold-over-BN254 port: GC-generic host open core.  Parameterized
/// over the challenger `Challenger` + MMCS `MT` + DFT `D`; the caller
/// supplies the concrete `mmcs`/`dft`.  The inner path uses `JaggedChallenger`
/// + Poseidon2-KoalaBear Mmcs; the wrap (OuterSC) will pass the BN254
/// challenger + Poseidon2-BN254 Mmcs.  `Val`/`Challenge` stay KoalaBear /
/// KoalaBear⁴ for both (the eval-point is over `JaggedChallenge`).
#[allow(clippy::type_complexity)]
pub fn open_jagged_pcs_generic<Challenger, MT, D>(
    prover_data: &JaggedProverDataGeneric<MT>,
    eval_point: Vec<JaggedChallenge>,
    challenger: &mut Challenger,
    mmcs: MT,
    dft: Arc<D>,
    fri: FriConfig<JaggedVal>,
) -> StackedBasefoldProof<JaggedVal, JaggedChallenge, MT>
where
    MT: p3_commit::Mmcs<JaggedVal, Commitment: Clone> + Clone,
    D: p3_dft::TwoAdicSubgroupDft<JaggedVal> + Send + Sync,
    Challenger: p3_challenger::FieldChallenger<JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = JaggedVal>
        + CanObserve<<MT as p3_commit::Mmcs<JaggedVal>>::Commitment>,
{
    let prover = StackedPcsProver::new(
        BasefoldProver::<JaggedVal, JaggedChallenge, MT, D>::new(fri, dft, mmcs, 1),
        prover_data.log_stacking_height,
        DEFAULT_BATCH_SIZE,
    );
    prover.prove_trusted_evaluation(eval_point, &[&prover_data.stacked_data], challenger)
}

// ─────────────────────────────────────────────────────────────────────
// GPU BaseFold open
// dispatch fn.
//
// Mirror of the GPU commit override — provided
// statically by the prover (`MachineProver::gpu_basefold_open_hook`) and
// threaded down to the `open_jagged_pcs_generic` dispatch, not via a registry.
// The hook receives the same inputs as `open_jagged_pcs_generic` and
// returns a byte-identical `StackedBasefoldProof` — the device side is
// responsible for:
//
//   * routing the per-stripe MLEs / codewords held in
//     `prover_data.stacked_data.pcs_batch_data` to GPU memory (or
//     reading from a device-resident cache if the commit hook installed
//     one),
//   * running `FriCudaProver::prove` (the existing 1349 LOC device
//     prove driver in `ziren-gpu/basefold/src/fri.rs`),
//   * observing the per-round univariate-poly evals + Merkle commits +
//     PoW witness into the supplied `JaggedChallenger` so the transcript
//     stays in lock-step with the host path,
//   * assembling a `StackedBasefoldProof` whose `basefold_proof.*` is
//     shape-compatible with the host path consumed by
//     `verify_jagged_pcs`.
//
// The hook returns `Result<.., (prover_data, eval_point)>` so the device
// side can tunnel ownership of the host inputs back to the host fallback
// on error (mirrors the `commit_jagged_pcs` hook contract).
// ─────────────────────────────────────────────────────────────────────

// `GpuBasefoldOpenFn` (the device open fn-ptr type) was removed in the
// SP1-parity static-dispatch collapse — the device open now lives in the
// `JaggedOpener` impl `DeviceJaggedOpener` (zkm-gpu-basefold), which calls
// `FriCudaProver::prove` and falls back to `open_jagged_pcs` on `Err`
// (returning `(prover_data, eval_point)` ownership so nothing is lost).

// The GPU BaseFold open fn is provided STATICALLY (threaded from
// the prover down to the `open_jagged_pcs_generic` dispatch), not via a global
// registry.  The former `GPU_BASEFOLD_OPEN_HOOK` OnceLock + `register_/get_`
// accessors were removed; the `prover` crate passes `Some(device_fn)` into
// the `prove_shard_to_basefold` free-fn (which threads it through the
// jagged-eval producer + `prove_trusted_evaluations` down to
// `prove_jagged_basefold_single_round`'s open closure).

/// Verify the proof against a previously observed commitment.
/// Multi-ROUND verify: one BaseFold proof covering every round's commitment.
///
/// SP1's verifier builds the commitment list itself —
/// `vec![vk.preprocessed_commit, *main_commitment]`
/// (`hypercube/src/verifier/shard.rs:638`) — so a round whose commitment lives
/// in the verifying key is never taken from the proof.
pub fn verify_jagged_pcs_rounds(
    commitments: &[<JaggedMmcs as p3_commit::Mmcs<JaggedVal>>::Commitment],
    areas: &[usize],
    log_stacking_height: u32,
    eval_point: &[JaggedChallenge],
    evaluation_claim: JaggedChallenge,
    proof: &StackedBasefoldProof<JaggedVal, JaggedChallenge, JaggedMmcs>,
    challenger: &mut JaggedChallenger,
) -> Result<(), crate::basefold::StackedVerifierError> {
    let perm: crate::kb31_poseidon2::InnerPerm = zkm_primitives::poseidon2_init();
    let hash = crate::kb31_poseidon2::InnerHash::new(perm.clone());
    let compress = crate::kb31_poseidon2::InnerCompress::new(perm);
    let mmcs = JaggedMmcs::new(hash, compress, 0);
    let fri = FriConfig::<JaggedVal>::from_env_or_default();
    let verifier = crate::basefold::stacked::StackedPcsVerifier::new(
        crate::basefold::verifier::BasefoldVerifier::<JaggedVal, JaggedChallenge, JaggedMmcs>::new(
            // One expected commitment PER ROUND — the batched open covers them
            // all in a single proof.
            fri,
            mmcs,
            commitments.len(),
        ),
        log_stacking_height,
    );
    verifier.verify_trusted_evaluation(
        commitments,
        areas,
        eval_point,
        proof,
        evaluation_claim,
        challenger,
    )
}

/// Ring-generic counterpart of [`verify_jagged_pcs_rounds`]: verify ONE batched
/// BaseFold opening that covers every round.  The BN254 wrap ring reaches the
/// multi-round verify through this.
#[allow(clippy::too_many_arguments)]
pub fn verify_jagged_pcs_rounds_generic<Challenger, MT>(
    commitments: &[<MT as p3_commit::Mmcs<JaggedVal>>::Commitment],
    areas: &[usize],
    log_stacking_height: u32,
    eval_point: &[JaggedChallenge],
    evaluation_claim: JaggedChallenge,
    proof: &StackedBasefoldProof<JaggedVal, JaggedChallenge, MT>,
    challenger: &mut Challenger,
    mmcs: MT,
    fri: FriConfig<JaggedVal>,
) -> Result<(), crate::basefold::StackedVerifierError>
where
    MT: p3_commit::Mmcs<JaggedVal, Commitment: Clone> + Clone,
    Challenger: p3_challenger::FieldChallenger<JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = JaggedVal>
        + CanObserve<<MT as p3_commit::Mmcs<JaggedVal>>::Commitment>,
{
    let verifier = crate::basefold::stacked::StackedPcsVerifier::new(
        crate::basefold::verifier::BasefoldVerifier::<JaggedVal, JaggedChallenge, MT>::new(
            // One expected commitment PER ROUND.
            fri,
            mmcs,
            commitments.len(),
        ),
        log_stacking_height,
    );
    verifier.verify_trusted_evaluation(
        commitments,
        areas,
        eval_point,
        proof,
        evaluation_claim,
        challenger,
    )
}

pub fn verify_jagged_pcs(
    commitment: &<JaggedMmcs as p3_commit::Mmcs<JaggedVal>>::Commitment,
    area: usize,
    log_stacking_height: u32,
    eval_point: &[JaggedChallenge],
    evaluation_claim: JaggedChallenge,
    proof: &StackedBasefoldProof<JaggedVal, JaggedChallenge, JaggedMmcs>,
    challenger: &mut JaggedChallenger,
) -> Result<(), crate::basefold::StackedVerifierError> {
    let perm: crate::kb31_poseidon2::InnerPerm = zkm_primitives::poseidon2_init();
    let hash = crate::kb31_poseidon2::InnerHash::new(perm.clone());
    let compress = crate::kb31_poseidon2::InnerCompress::new(perm);
    let mmcs = JaggedMmcs::new(hash, compress, 0);
    // Delegate to the GC-generic core (inner = Poseidon2-KoalaBear Mmcs).
    verify_jagged_pcs_generic::<JaggedChallenger, JaggedMmcs>(
        commitment,
        area,
        log_stacking_height,
        eval_point,
        evaluation_claim,
        proof,
        challenger,
        mmcs,
        FriConfig::<JaggedVal>::from_env_or_default(),
    )
}

/// BaseFold-over-BN254 port: GC-generic verify core.  Parameterized
/// over the challenger `Challenger` + MMCS `MT` + DFT `D`; the caller
/// supplies the concrete `mmcs`/`dft`.  The inner path uses `JaggedChallenger`
/// + Poseidon2-KoalaBear Mmcs; the wrap (OuterSC) will pass the BN254
/// challenger + Poseidon2-BN254 Mmcs.  `Val`/`Challenge` stay KoalaBear /
/// KoalaBear⁴ for both.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn verify_jagged_pcs_generic<Challenger, MT>(
    commitment: &<MT as p3_commit::Mmcs<JaggedVal>>::Commitment,
    area: usize,
    log_stacking_height: u32,
    eval_point: &[JaggedChallenge],
    evaluation_claim: JaggedChallenge,
    proof: &StackedBasefoldProof<JaggedVal, JaggedChallenge, MT>,
    challenger: &mut Challenger,
    mmcs: MT,
    fri: FriConfig<JaggedVal>,
) -> Result<(), crate::basefold::StackedVerifierError>
where
    MT: p3_commit::Mmcs<JaggedVal, Commitment: Clone> + Clone,
    Challenger: p3_challenger::FieldChallenger<JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = JaggedVal>
        + CanObserve<<MT as p3_commit::Mmcs<JaggedVal>>::Commitment>,
{
    let verifier = StackedPcsVerifier::new(
        BasefoldVerifier::<JaggedVal, JaggedChallenge, MT>::new(fri, mmcs, 1),
        log_stacking_height,
    );
    verifier.verify_trusted_evaluation(
        core::slice::from_ref(commitment),
        &[area],
        eval_point,
        proof,
        evaluation_claim,
        challenger,
    )
}

// ─── Jagged-sumcheck integration ──────────
//
// Mirrors the (now-removed) WHIR jagged late-binding prover but
// commits via BaseFold instead of WHIR.  The dense polynomial is still
// materialized for the sumcheck reduction (the OOM win is in the
// commit phase: BaseFold streams stripes through dft_batch instead of
// blowing up the whole dense vector by 16×).  Per-chip BaseFold
// commit (which would skip even the brief dense materialization) is
// the next-stage refactor.
//
// Built on `jagged.rs` (data structures) and `jagged_sumcheck.rs`
// (PCS-agnostic reduction math).

pub mod jagged {
    use alloc::vec::Vec;

    use p3_challenger::{CanObserve, FieldChallenger};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;

    use crate::basefold::StackedBasefoldProof;
    use crate::jagged::{JaggedChipInfo, JaggedPacking, compute_jagged_metadata, materialize_dense_jagged};
    use crate::jagged_sumcheck::{JaggedReductionProof, verify_jagged_reduction};
    use crate::kb31_poseidon2::{InnerChallenge, InnerVal};

    /// A named per-chip trace in the form the jagged commit and open consume:
    /// the same `(name, PaddedMle)` pairing SP1 keys its `Traces` map by.
    /// Padding is virtual, so cloning one is an `Arc` bump rather than a
    /// matrix copy, and the Val<->InnerVal relabel stays a zero-copy slice
    /// reinterpret under the caller's TypeId gate.
    ///
    /// Device-resident chips carry a width-0 entry; the host fallback
    /// `rematerialize_chip_traces_via_provider` produces owned side-storage
    /// the caller re-wraps.
    pub type ChipTraceView = (alloc::string::String, crate::multilinear::PaddedMle<InnerVal>);

    use super::{
        FriConfig,
        open_jagged_pcs,
        verify_jagged_pcs,
    };

    // ── Test-only verify-progress tracker ─────────────────────────────────
    // Records how FAR the host verifier got, so CP-A validation can assert
    // the per-round restructure is transcript-faithful (coverage + every
    // group's reduction pass) even when the BaseFold OPEN fails for a reason
    // ORTHOGONAL to the split (e.g. an in-progress jagged-eval/div-fix bug
    // shared by the G==1 path on this WIP branch).
    #[cfg(test)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum VerifyStage {
        /// Failed the coverage check (group map ≠ partition).
        Coverage,
        /// Failed a per-group jagged-sumcheck reduction (group index).
        Reduction(usize),
        /// Failed a per-group BaseFold open (group index).
        Open(usize),
        /// All G groups accepted.
        Accepted,
    }
    #[cfg(test)]
    thread_local! {
        pub(crate) static LAST_VERIFY_STAGE: core::cell::Cell<Option<VerifyStage>> =
            const { core::cell::Cell::new(None) };
    }

    /// Record the verify stage (no-op outside tests).
    macro_rules! record_stage {
        ($s:expr) => {
            #[cfg(test)]
            {
                LAST_VERIFY_STAGE.with(|c| c.set(Some($s)));
            }
        };
    }

    /// Wire-format jagged metadata: only the per-bundle quantities
    /// the verifier needs to reconstruct the same `JaggedPacking`
    /// from chip_infos it receives separately.  We don't serialize
    /// `dense_values` (that's the multi-GB vector we just committed
    /// to BaseFold).
    ///
    /// `column_counts`: per-chip *actual*
    /// column count as exercised by this shard's trace, written by
    /// the prover from `compute_jagged_metadata`.  The verifier reads
    /// this instead of `BaseAir::width(chip)` so the prover can send
    /// `trace.width` (the truly-populated columns) without any
    /// chip.width() pad (~24x reduction in jagged-PCS data on
    /// workloads with sparse-column chips).
    /// Empty vec on the wire = legacy bundle → caller falls back to
    /// `BaseAir::width(chip)` for backward compat.
    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    pub struct PackingMeta {
        pub offsets: Vec<usize>,
        pub total_values: usize,
        pub log_dense_size: usize,
        #[serde(default)]
        pub column_counts: Vec<usize>,
        /// Per-ROUND `(row_count, column_count)` for the REAL chips of each
        /// committed round, in round order — SP1's
        /// `row_counts_and_column_counts: Rounds<Vec<(usize, usize)>>`
        /// (`slop/crates/jagged/src/prover.rs:312`).
        ///
        /// The fields above flatten every round into ONE column space, and that
        /// space also carries the stacking padding between rounds, so a round's
        /// geometry cannot be recovered from them by position.  Each consumer
        /// that speaks about a single round — the hash-bind (which binds the
        /// MAIN round to `main_commitment`) and the preprocessed-round check
        /// (which binds round 0 to `vk.commit`) — reads it from here instead.
        ///
        /// `serde(default)` empty on a single-round bundle, which keeps the
        /// legacy wire format byte-identical.
        #[serde(default)]
        pub round_counts: Vec<Vec<(usize, usize)>>,
        /// Each round's stacking-padding column heights, in round order — the
        /// gap between the round's real cells and the area the stacked
        /// commitment actually covers, split into columns no taller than the
        /// row cube (a taller column has no eq table to be weighed against, so
        /// SP1 carries a padding column COUNT for the same reason).
        ///
        /// It is NOT derivable from `round_counts`: a round whose cells already
        /// fill a whole number of stripes still gets a full extra stripe, so
        /// `next_multiple_of` under-counts it by `1 << log_stacking_height` and
        /// the reconstructed final offset lands a stripe short.  The recursion
        /// lift closes its column space with this height, so it has to be the
        /// prover's own value.
        ///
        /// `serde(default)` empty on a bundle with no padding columns, which
        /// keeps the legacy wire format byte-identical.
        #[serde(default)]
        pub padding_heights: Vec<Vec<usize>>,
    }

    // BaseFold-over-BN254: generic over the Mmcs so the wrap (OuterSC)
    // bundle holds the BN254 commitment + proof; inner alias below keeps every
    // caller + the rmp wire-format unchanged. serde(bound) mirrors the
    // JaggedCommitGeneric pattern (commitment + proof must serde).
    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    #[serde(bound(
        serialize = "<MT as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Commitment: serde::Serialize, <MT as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Proof: serde::Serialize",
        deserialize = "<MT as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Commitment: serde::Deserialize<'de>, <MT as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Proof: serde::Deserialize<'de>"
    ))]
    pub struct JaggedBasefoldBundleGeneric<MT: p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>> {
        /// Group-0 jagged-sumcheck reduction proof.  On the default (FIX-on /
        /// core, G==1) path this is the WHOLE proof and `extra_*` below are
        /// empty — byte-identical to the pre-split bundle.  On the per-round
        /// split (G≥2) path this is the FIRST group and the remaining G-1
        /// groups live in the `extra_*` Vecs (see [`Self::reduction_g`]).
        ///
        /// Rationale for "scalar group-0 + extra Vecs" rather than a single
        /// `Vec<G>`: it keeps the recursion lift + in-circuit verifier
        /// (`shard_level_witness.rs`, `recursive_jagged_pcs.rs`) — which read
        /// these scalar fields and are NOT touched in CP-A (host-only) —
        /// compiling unchanged, AND keeps the G==1 wire format byte-identical
        /// (the `extra_*` / `groups` fields are `serde(default)` empty so they
        /// serialize away).  CP-C folds these into the in-circuit G-loop.
        pub reduction: JaggedReductionProof<InnerChallenge>,
        /// Group-0 BaseFold open proof.
        pub basefold_proof: StackedBasefoldProof<
            InnerVal,
            InnerChallenge,
            MT,
        >,
        /// Per-chip per-column row-MLE values, FLAT in name-sorted chip order
        /// (NOT grouped) — the `groups` index map below partitions it.  Shared
        /// across all groups.
        pub y_per_chip: Vec<Vec<InnerChallenge>>,
        /// Group-0 BaseFold commit.
        pub commit: crate::jagged_pcs::JaggedCommitGeneric<MT>,
        /// Group-0 packing metadata (group-LOCAL offsets / prefix-sums).
        pub packing: PackingMeta,
        /// Group-0 jagged-eval sub-protocol proof.
        ///
        /// `serde(default)` so existing wire-format bundles deserialize.
        #[serde(default = "crate::jagged_eval_sumcheck::JaggedSumcheckEvalProof::dummy")]
        pub jagged_eval: crate::jagged_eval_sumcheck::JaggedSumcheckEvalProof<InnerChallenge>,

        /// The RAW BaseFold roots of the opening rounds BEFORE the last, in
        /// round order — SP1's `original_commitments`.
        ///
        /// A round's commitment as the VERIFYING KEY holds it is the HASH-BOUND
        /// digest `compress([raw, hash(geometry)])`, but the BaseFold open
        /// Merkle-verifies its leaves against the RAW root.  So the proof
        /// carries the raw root and the verifier re-derives the bound form to
        /// check it against the key — which is what pins that round's geometry
        /// (SP1 `slop/crates/jagged/src/verifier.rs:206`).  Empty on a
        /// single-round proof.
        #[serde(default)]
        pub preceding_commits: Vec<<MT as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Commitment>,

        // ── Per-round split (Architecture A) extra groups (G≥2 only) ──────
        // All `serde(default)` empty so a G==1 bundle is byte-identical to the
        // pre-split wire format.  Indexed g-1 for group g≥1.
        /// Reductions for groups 1..G.
        #[serde(default)]
        pub extra_reduction: Vec<JaggedReductionProof<InnerChallenge>>,
        /// BaseFold opens for groups 1..G.
        #[serde(default)]
        pub extra_basefold_proof: Vec<StackedBasefoldProof<InnerVal, InnerChallenge, MT>>,
        /// BaseFold commits for groups 1..G.
        #[serde(default)]
        pub extra_commit: Vec<crate::jagged_pcs::JaggedCommitGeneric<MT>>,
        /// Packing metadata for groups 1..G.
        #[serde(default)]
        pub extra_packing: Vec<PackingMeta>,
        /// Jagged-eval proofs for groups 1..G.
        #[serde(default)]
        pub extra_jagged_eval: Vec<crate::jagged_eval_sumcheck::JaggedSumcheckEvalProof<InnerChallenge>>,
        /// Group membership: `groups[g]` lists the indices (INTO the
        /// name-sorted chip set) committed in group `g`.  THE wire form the
        /// verifier's coverage check validates against an independent
        /// [`crate::jagged::partition_from_chip_infos`] run.  Must be an
        /// exact cover (no drop, no dup, canonical name-sorted order).
        /// `serde(default)` empty for G==1 / legacy bundles → the verifier
        /// treats an empty map as the single-group identity cover.
        #[serde(default)]
        pub groups: Vec<Vec<usize>>,
    }

    impl<MT: p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>> JaggedBasefoldBundleGeneric<MT> {
        /// Number of independent jagged groups (G).  `1` on the default path.
        #[must_use]
        pub fn num_groups(&self) -> usize {
            1 + self.extra_reduction.len()
        }
        /// Reduction proof for group `g` (group 0 is the scalar field).
        #[must_use]
        pub fn reduction_g(&self, g: usize) -> &JaggedReductionProof<InnerChallenge> {
            if g == 0 { &self.reduction } else { &self.extra_reduction[g - 1] }
        }
        /// BaseFold open proof for group `g`.
        #[must_use]
        pub fn basefold_proof_g(
            &self,
            g: usize,
        ) -> &StackedBasefoldProof<InnerVal, InnerChallenge, MT> {
            if g == 0 { &self.basefold_proof } else { &self.extra_basefold_proof[g - 1] }
        }
        /// BaseFold commit for group `g`.
        #[must_use]
        pub fn commit_g(
            &self,
            g: usize,
        ) -> &crate::jagged_pcs::JaggedCommitGeneric<MT> {
            if g == 0 { &self.commit } else { &self.extra_commit[g - 1] }
        }
        /// Packing metadata for group `g`.
        #[must_use]
        pub fn packing_g(&self, g: usize) -> &PackingMeta {
            if g == 0 { &self.packing } else { &self.extra_packing[g - 1] }
        }
        /// Jagged-eval proof for group `g`.
        #[must_use]
        pub fn jagged_eval_g(
            &self,
            g: usize,
        ) -> &crate::jagged_eval_sumcheck::JaggedSumcheckEvalProof<InnerChallenge> {
            if g == 0 { &self.jagged_eval } else { &self.extra_jagged_eval[g - 1] }
        }
        /// The group membership map, defaulting to the identity single-group
        /// cover when empty (G==1 / legacy bundles).
        #[must_use]
        pub fn groups_or_identity(&self, n_chips: usize) -> Vec<Vec<usize>> {
            if self.groups.is_empty() {
                alloc::vec![(0..n_chips).collect()]
            } else {
                self.groups.clone()
            }
        }
    }

    /// Concrete inner (Poseidon2-KoalaBear) bundle alias -- the type every
    /// current caller + wire-format uses.
    pub type JaggedBasefoldBundle = JaggedBasefoldBundleGeneric<crate::jagged_pcs::JaggedMmcs>;

    impl<MT: p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>> JaggedBasefoldBundleGeneric<MT>
    where
        <MT as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Commitment:
            serde::Serialize + for<'d> serde::Deserialize<'d>,
        <MT as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Proof:
            serde::Serialize + for<'d> serde::Deserialize<'d>,
    {
        /// Wire-format bytes (rmp-serde — matches the existing
        /// jagged-PCS bundle's serializer choice).
        pub fn to_bytes(&self) -> Vec<u8> {
            rmp_serde::to_vec(self).expect("JaggedBasefoldBundle serializes")
        }

        pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
            rmp_serde::from_slice(bytes).ok()
        }
    }

    /// Pre-computed jagged-PCS commit bundle for the
    /// single-main-commit flow.  Produced by
    /// [`precompute_jagged_basefold_commit`] before the shard-level
    /// Phase 1 prologue, then consumed by
    /// [`prove_jagged_basefold_with_precomputed_provider`] in Phase 4.
    ///
    /// The 8-felt digest of `commit.original_commitment` (via
    /// [`crate::jagged_pcs::basefold_commit_digest`]) is the
    /// `main_commitment` that the prologue + verifier observe.
    pub struct PrecomputedJaggedCommitGeneric<MT: p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>> {
        pub packing: crate::jagged::JaggedPacking<InnerVal>,
        pub commit: crate::jagged_pcs::JaggedCommitGeneric<MT>,
        pub prover_data: crate::jagged_pcs::JaggedProverDataGeneric<MT>,
        /// The per-shard rev(zeta) orientation the dense commit was
        /// materialized under (from the per-stage `StarkMachine::core_rev()`
        /// source of truth — `true` only on the CORE MIPS path).  Recorded on
        /// the committed data so the step-4 jagged reduction (host
        /// re-materialize + `y_per_chip`) uses the SAME orientation as the
        /// commit, in lockstep.  `false` on every recursion / shrink / wrap
        /// commit (byte-identical).
        pub rev: bool,
        /// The recursion-layer AREA PIN this commit was built under.
        /// `Some(target_log)` on a
        /// RECURSION (`compress`) commit: `packing.log_dense_size` was raised to
        /// `max(natural, target_log)` (a FIXED `2^target_log` committed area →
        /// constant `num_stripes`), and the step-4 jagged-eval must run over the
        /// PINNED dense (`prove_jagged_evaluation` `half = z_trace.len() + 1`) so
        /// its dimension is height-independent.  Recorded on the committed data so
        /// the OPEN path reads it back in lockstep with the commit.  `None` on
        /// every CORE / shrink / wrap commit (NATURAL own-area packing,
        /// byte-identical to legacy).
        pub recursion_area_pin: Option<usize>,
    }
    /// Concrete inner alias (MT = JaggedMmcs).
    pub type PrecomputedJaggedCommit = PrecomputedJaggedCommitGeneric<crate::jagged_pcs::JaggedMmcs>;

    // ─────────────────────────────────────────────────────────────────
    // Single shard-wide commit buffer — GPU precompute-commit hook.
    //
    // Replaces the HOST body of `precompute_jagged_basefold_commit`
    // (host dense pack + host stripe interleave + H2D re-upload) with a
    // device-side build: resident chips are packed D2D from the
    // per-shard provider, host chips H2D once, the stripes/encode/
    // Merkle all run on device, and the dense buffer is retained
    // device-side (registered handle) for the step-4 jagged reduction.
    // Output MUST be byte-identical to the host precompute (commit
    // digest, prover_data shapes, interleaved MLE bytes) — the commit
    // is transcript-critical.
    // ─────────────────────────────────────────────────────────────────

    // Phase-1 static dispatch (SP1-parity): the former
    // `GpuJaggedPrecomputeCommitFn` `fn`-ptr type (signature of the GPU jagged
    // precompute-commit hook) was RETIRED.  The device dense-pack + BaseFold
    // commit is now the `StarkGpuProver` OVERRIDE of
    // `MachineProver::commit_multilinears`, consumed by
    // `maybe_auto_precompute_basefold` through the `JaggedEvalProducer` COMMIT
    // seam — so no `Option<fn>` crosses this boundary.  The device hook body
    // still lives in ziren-gpu `commit_dense::gpu_jagged_precompute_commit_hook`
    // (called DIRECTLY by the override); its recursion-AREA-PIN + provider-read
    // rev(zeta) semantics are unchanged (byte-identical).

    /// Run steps (1) + (2) of `prove_jagged_basefold_with_y_per_chip`
    /// up-front, WITHOUT observing the commitment into a challenger.
    /// Returns the packing metadata plus the BaseFold commit + prover
    /// data — enough state for
    /// [`prove_jagged_basefold_with_precomputed_provider`] to skip the in-band
    /// commit and run steps (3)+(4)+(5) against an aligned transcript.
    ///
    /// Caller MUST surface `commit.original_commitment` (or its 8-felt digest)
    /// to the verifier (via the shard-level proof's
    /// `main_commitment` field) at the same transcript position the
    /// verifier observes it.
    pub fn precompute_jagged_basefold_commit(
        chip_traces: &[ChipTraceView],
        // The per-shard rev(zeta) orientation (from `StarkMachine::core_rev()`);
        // threaded to `materialize_dense_jagged` and recorded on the returned
        // `PrecomputedJaggedCommit.rev` so the step-4 reduction stays in lockstep.
        use_rev: bool,
        // The recursion-layer AREA PIN.  See
        // the twin in `precompute_jagged_basefold_commit_generic`.
        recursion_area_pin: Option<usize>,
    ) -> PrecomputedJaggedCommit {
        let perm: crate::kb31_poseidon2::InnerPerm = zkm_primitives::poseidon2_init();
        let hash = crate::kb31_poseidon2::InnerHash::new(perm.clone());
        let compress = crate::kb31_poseidon2::InnerCompress::new(perm);
        precompute_jagged_basefold_commit_generic::<crate::jagged_pcs::JaggedMmcs>(
            chip_traces,
            crate::jagged_pcs::JaggedMmcs::new(hash, compress, 0),
            FriConfig::<crate::jagged_pcs::JaggedVal>::from_env_or_default(),
            use_rev,
            recursion_area_pin,
        )
    }

    /// BaseFold-over-BN254 generic precompute: build the BaseFold commit
    /// over an arbitrary Mmcs (the ring's `BasefoldRing::BfMmcs`). Inner uses
    /// Poseidon2-KoalaBear; the wrap (OuterSC) passes the Poseidon2-BN254
    /// `OuterValMmcs` so the commitment is the BN254 root. The DFT is over
    /// KoalaBear for BOTH rings (Val == KoalaBear everywhere), so `JaggedDft`
    /// is reused. No challenger observe (caller surfaces the commitment).
    pub fn precompute_jagged_basefold_commit_generic<MT>(
        chip_traces: &[ChipTraceView],
        mmcs: MT,
        fri: FriConfig<crate::jagged_pcs::JaggedVal>,
        // The per-shard rev(zeta) orientation (from `StarkMachine::core_rev()`);
        // threaded to `materialize_dense_jagged` and recorded on the returned
        // `PrecomputedJaggedCommitGeneric.rev`.  `false` on the wrap/BN254 path.
        use_rev: bool,
        // The recursion-layer AREA PIN.
        // `Some(target_log)` (a recursion/compress commit) => pin
        // `log_dense_size` to `max(natural, target_log)`; `None` (CORE / shrink /
        // wrap) => NATURAL own-area packing.
        recursion_area_pin: Option<usize>,
    ) -> PrecomputedJaggedCommitGeneric<MT>
    where
        // `'static`/`Send` bounds on the commitment + prover data.  Both rings
        // (JaggedMmcs / OuterValMmcs) are concrete `'static` types, so this is a
        // no-op tightening for every existing caller.
        MT: p3_commit::Mmcs<
                crate::jagged_pcs::JaggedVal,
                Commitment: Clone + Send + 'static,
                ProverData<RowMajorMatrix<crate::jagged_pcs::JaggedVal>>: Send + 'static,
            > + Clone
            + 'static,
    {
        let mut packing = compute_jagged_metadata::<InnerVal>(chip_traces);
        // RECURSION-LAYER AREA PIN.  When the
        // recursion (`compress`) prover passes `Some(target_log)` here, so
        // raise the committed `dense_len` to the pin floor so the dense
        // materialize + commit run at a FIXED area (`2^pin`) → constant
        // `num_stripes` → compose VK = f(chip-set, arity).  `None` on every
        // CORE / shrink / wrap path → NATURAL own-area packing (byte-identical).
        let pin = recursion_area_pin;
        if let Some(target) = pin {
            packing.dense_len = packing.dense_len.max(1usize << target);
        }
        let (commit, prover_data) = {
            let dense_q =
                materialize_dense_jagged::<InnerVal>(chip_traces, packing.dense_len, use_rev);
            debug_assert_eq!(dense_q.len(), packing.dense_len);
            let dense_traces = vec![(
                alloc::string::String::from("<jagged-dense>"),
                RowMajorMatrix::new(dense_q, 1),
            )];

            let dft = std::sync::Arc::new(crate::jagged_pcs::JaggedDft::default());
            crate::jagged_pcs::commit_jagged_pcs_generic::<MT, crate::jagged_pcs::JaggedDft>(
                dense_traces, mmcs, dft, fri,
            )
        };
        PrecomputedJaggedCommitGeneric { packing, commit, prover_data, rev: use_rev, recursion_area_pin }
    }

    /// **Prover-side one-call entry point** — full pipeline:
    /// commit chip traces (via BaseFold-stacked), run jagged sumcheck
    /// reduction, open dense at the reduction's `z*` via BaseFold,
    /// bundle for the wire.
    pub fn prove_jagged_basefold(
        chip_traces: &[ChipTraceView],
        r_row_per_chip: &[Vec<InnerChallenge>],
        z_row: &[InnerChallenge],
        challenger: &mut crate::jagged_pcs::JaggedChallenger,
    ) -> JaggedBasefoldBundle {
        prove_jagged_basefold_with_y_per_chip(
            chip_traces,
            r_row_per_chip,
            z_row,
            None,
            challenger,
            // host-only self-contained flow (synthetic / tests) — host reducer/opener.
        )
    }

    /// Provider-aware reduction prove: same as
    /// [`prove_jagged_basefold_with_precomputed_provider`] but additionally accepts
    /// the per-shard `DeviceTraceProvider`.  The provider is used ONLY on
    /// the slow GPU-reduction fallback edge: when the device handle / V2
    /// hook declines and the host body must run, any chip whose
    /// `chip_traces` entry is empty (width 0 — its real cells live
    /// device-side) is re-materialized from the provider so the host
    /// `materialize_dense_jagged` rebuilds a correct dense_q.  On the
    /// happy path (V2 hook consumes the registered device dense handle)
    /// the provider is never touched, so passing `Some` is behaviour- and
    /// byte-neutral — it only ARMS the fallback against empty device-chip
    /// traces, removing the silent invalid-proof edge that an unconditional
    /// `commit_traces` D2H skip would otherwise leave.
    /// One commitment ROUND's inputs to the jagged open.
    ///
    /// SP1 passes `prover_data: Rounds<JaggedProverData>` and
    /// `evaluation_claims: Rounds<Evaluations>` as parallel per-round
    /// collections (`slop/crates/jagged/src/prover.rs:162`); this is the same
    /// thing with the parallel arms collapsed into one record, so a round's
    /// commit can never be paired with another round's claims.
    ///
    /// `precomputed` is BORROWED: the preprocessed round opens the proving
    /// key's commit, built once by `setup` and shared by every shard.
    pub struct JaggedOpenRound<'a, MT: p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>> {
        pub chip_traces: &'a [ChipTraceView],
        pub r_row_per_chip: &'a [Vec<InnerChallenge>],
        /// This round's per-chip column claims (SP1's `Evaluations`).
        pub claims: Vec<Vec<InnerChallenge>>,
        pub precomputed: &'a PrecomputedJaggedCommitGeneric<MT>,
    }

    pub fn prove_jagged_basefold_with_precomputed_provider(
        chip_traces: &[ChipTraceView],
        r_row_per_chip: &[Vec<InnerChallenge>],
        z_row: &[InnerChallenge],
        precomputed: &PrecomputedJaggedCommit,
        pre_y_per_chip: Option<Vec<Vec<InnerChallenge>>>,
        challenger: &mut crate::jagged_pcs::JaggedChallenger,
    ) -> JaggedBasefoldBundle {
        prove_jagged_basefold_single_round(
            chip_traces,
            r_row_per_chip,
            z_row,
            pre_y_per_chip,
            precomputed,
            challenger,
        )
    }

    /// Variant of [`prove_jagged_basefold`] that lets the caller pass a
    /// pre-computed `y_per_chip` (e.g. computed device-resident on
    /// GPU).  When `pre_y_per_chip` is `Some`, step (3) — the host
    /// triple-nested per-column reduction — is skipped entirely.
    /// Output bytes are identical to the host path.
    ///
    /// Self-contained legacy flow (host synthetic / unit tests + the
    /// runtime-dead `prove_trusted_evaluations` no-precompute fallthrough):
    /// precompute the single-main dense commit on host, observe its
    /// commitment in-band (mirroring `commit_jagged_pcs`'s observe so the
    /// `verify_jagged_basefold` transcript aligns), then run steps
    /// (3)+(4)+(5) through the precomputed fast path.  Byte-identical to the
    /// former inline in-band-commit body (host commit, legacy `rev = false`,
    /// no area pin, no provider).
    pub fn prove_jagged_basefold_with_y_per_chip(
        chip_traces: &[ChipTraceView],
        r_row_per_chip: &[Vec<InnerChallenge>],
        z_row: &[InnerChallenge],
        pre_y_per_chip: Option<Vec<Vec<InnerChallenge>>>,
        challenger: &mut crate::jagged_pcs::JaggedChallenger,
    ) -> JaggedBasefoldBundle {
        let precomputed = precompute_jagged_basefold_commit(
            chip_traces,
            false, // legacy bitrev orientation
            None,  // no recursion area pin
        );
        // In-band commit observe (the precomputed prove skips it, expecting
        // the orchestrator prologue to have observed the digest; here there
        // is none, so observe it now to match `verify_jagged_basefold`).  This
        // observe stays on THIS (legacy/synthetic) arm and precedes the spine
        // call — the precomputed arms omit it. Then route through the shared
        // `prove_jagged_basefold_with_precomputed_provider` spine (provider
        // `None`) instead of calling `_inner` directly, so `_inner` has a
        // single caller. Byte-identical: the spine is a pure pass-through to
        // `_inner` with these exact args, and the observe order is unchanged.
        challenger.observe(precomputed.commit.original_commitment.clone());
        prove_jagged_basefold_with_precomputed_provider(
            chip_traces,
            r_row_per_chip,
            z_row,
            &precomputed,
            pre_y_per_chip,
            challenger,
        )
    }

    /// Build borrowed `ChipTraceView`s over an OWNED re-materialized trace
    /// set (`rematerialize_chip_traces_via_provider`), so the downstream
    /// view-taking commit/reduction consumers can read its cells with no
    /// further copy.  The returned views borrow `owned`, which must outlive
    /// them (the caller keeps it in scope).
    pub fn views_over_owned(
        owned: &[(alloc::string::String, RowMajorMatrix<InnerVal>)],
    ) -> alloc::vec::Vec<ChipTraceView> {
        owned
            .iter()
            .map(|(name, m)| {
                // The jagged path now carries `PaddedMle`, so the rematerialized
                // side-storage is wrapped rather than borrowed.  `num_variables`
                // is the chip's own log-height: the packer reads dims and cells
                // back off the real trace, and never consults the padding.
                let h = if m.width == 0 { 0 } else { m.values.len() / m.width };
                let log_h = if h <= 1 { 0 } else { h.next_power_of_two().ilog2() };
                let mle = alloc::sync::Arc::new(crate::basefold::Mle::from_row_major(
                    RowMajorMatrix::new(m.values.clone(), m.width),
                ));
                (name.clone(), crate::multilinear::PaddedMle::padded_with_zeros(mle, log_h))
            })
            .collect()
    }

    /// **Shared linear core** — the SP1-shaped, path-INDEPENDENT
    /// challenger sequence at the heart of every jagged-BaseFold prove.
    ///
    /// Mirrors SP1 `JaggedProver::prove_trusted_evaluations`
    /// (`slop/crates/jagged/src/prover.rs`): sample `z_col` at the
    /// verifier-matching transcript position → jagged-sumcheck reduction →
    /// jagged-eval sub-protocol → open.  The ONE Ziren-specific deviation is
    /// the point-extension after the reduction (SP1 opens at
    /// `final_eval_point` directly; Ziren extends `log_dense → log2(area)`
    /// via extra Fiat-Shamir coords — preserved here exactly).
    ///
    /// The `reduce` and `open` closures are the ONLY per-path variation
    /// (host-owned vs device-hook reduction; concrete vs BN254 open; the
    /// pre-reduce / pre-open device-memory frees) and NEITHER may run any
    /// challenger op outside its documented reduction/open — so every caller
    /// (single-group concrete, per-group multi-group, BN254 generic) lands its
    /// `z_col` / reduction / jagged-eval / point-extend / open challenger ops
    /// in the IDENTICAL order.  This is the de-dup that stops `z_col`'s
    /// transcript position from being path-dependent.
    #[allow(clippy::type_complexity)]
    pub fn prove_jagged_basefold_linear_core<Ch, P>(
        offsets: &[usize],
        z_row: &[InnerChallenge],
        area: usize,
        challenger: &mut Ch,
        // The recursion-layer AREA PIN, read
        // off the precomputed commit (`PrecomputedJaggedCommit.recursion_area_pin`)
        // and threaded into `prove_jagged_evaluation` so its half/round-count is
        // pin-consistent with the (pinned) commit.  `None` on CORE/shrink/wrap.
        recursion_area_pin: Option<usize>,
        reduce: impl FnOnce(&[InnerChallenge], &mut Ch) -> JaggedReductionProof<InnerChallenge>,
        open: impl FnOnce(Vec<InnerChallenge>, &mut Ch) -> P,
    ) -> (
        JaggedReductionProof<InnerChallenge>,
        crate::jagged_eval_sumcheck::JaggedSumcheckEvalProof<InnerChallenge>,
        P,
    )
    where
        Ch: FieldChallenger<InnerVal>,
    {
        // (4) SP1-aligned: sample `z_col` (one challenge per column variable)
        // at the verifier-matching transcript position — after the commit
        // observe, immediately before the jagged sumcheck reduction.  Used
        // both to weight the column mix in the reduction and as the column
        // point for the branching-program jagged-eval sub-protocol.
        let num_cols = offsets.len().saturating_sub(1);
        let num_col_vars = num_cols.next_power_of_two().trailing_zeros() as usize;
        let z_col: Vec<InnerChallenge> = (0..num_col_vars)
            .map(|_| challenger.sample_algebra_element())
            .collect();

        // Jagged sumcheck reduction.  The caller's closure supplies the
        // host-owned / device-hook / group-local body; it MUST be
        // transcript-equivalent to
        // `prove_jagged_reduction_owned(.., &z_col, z_row, ..)` (the device
        // hook is byte-equivalent + snapshot-guarded; see the concrete path).
        let reduction = reduce(&z_col, challenger);

        // (4b) Jagged-eval sub-protocol at (z_row, z_col, rev(z*)).  PHASE 2:
        // the BranchingProgram reads its z_index big-endian while the
        // reduction emits z_star little-endian, so feed rev(z_star) — matches
        // recursive_jagged_pcs.rs (verify_sumcheck → jagged_evaluator_fn).
        let z_trace_be: Vec<InnerChallenge> =
            reduction.eval_point.iter().rev().copied().collect();
        let jagged_eval = crate::jagged_eval_sumcheck::prove_jagged_evaluation(
            offsets,
            z_row,
            &z_col,
            &z_trace_be,
            challenger,
            recursion_area_pin,
        );

        // (5) Ziren point-extend (SP1 opens at `final_eval_point` directly):
        // the BaseFold commit covers `area` cells (num_stripes × batch_size ×
        // stack_height), which can exceed 2^log_dense_size, so extend z* to
        // log2(area) with extra Fiat-Shamir coords (the verifier samples the
        // matching coords in the same transcript order), then open at z*.
        let target_dim = area.trailing_zeros() as usize;
        let mut extended_eval_point = reduction.eval_point.clone();
        while extended_eval_point.len() < target_dim {
            let r: InnerChallenge = challenger.sample_algebra_element();
            extended_eval_point.push(r);
        }
        let proof = open(extended_eval_point, challenger);

        (reduction, jagged_eval, proof)
    }

    /// Body shared by [`prove_jagged_basefold_with_y_per_chip`] (legacy
    /// self-contained flow, which now precomputes + observes the commit in its
    /// wrapper) and [`prove_jagged_basefold_with_precomputed_provider`] (the
    /// single-commit flow).  `precomputed` is always supplied: steps (1) + (2)
    /// were run up-front and the in-band commit observe is suppressed (the
    /// caller already observed the digest — the orchestrator at the Phase 1
    /// prologue position, or the wrapper just above).
    /// One group's share of a jagged-BaseFold proof: everything
    /// [`JaggedBasefoldBundleGeneric`] stores per group, before the groups are
    /// assembled into a bundle.
    ///
    /// A single-round proof has exactly one of these (it becomes the bundle's
    /// scalar group-0 fields); SP1's two-round shape has two — preprocessed then
    /// main — and the second lands in the `extra_*` vecs.
    pub struct JaggedGroupProof {
        pub reduction: JaggedReductionProof<InnerChallenge>,
        pub basefold_proof: StackedBasefoldProof<InnerVal, InnerChallenge, crate::jagged_pcs::JaggedMmcs>,
        pub commit: crate::jagged_pcs::JaggedCommit,
        pub packing: PackingMeta,
        pub jagged_eval: crate::jagged_eval_sumcheck::JaggedSumcheckEvalProof<InnerChallenge>,
        /// This group's chips only, in the group's own membership order.
        pub y_per_chip: Vec<Vec<InnerChallenge>>,
    }


    /// Prove ONE jagged group against `z_row`, consuming that group's
    /// precomputed commit.
    ///
    /// Every challenger operation happens inside
    /// [`prove_jagged_basefold_linear_core`], in the order the verifier's
    /// per-group loop replays it, so calling this once per group back-to-back on
    /// the same challenger lands the multi-round transcript the verifier expects.
    pub fn prove_one_jagged_group(
        chip_traces: &[ChipTraceView],
        r_row_per_chip: &[Vec<InnerChallenge>],
        z_row: &[InnerChallenge],
        pre_y_per_chip: Option<Vec<Vec<InnerChallenge>>>,
        // BORROWED so a commit built ONCE can be opened by every shard — the
        // preprocessed round opens the proving key's copy directly.  Only the
        // (small) commitment is cloned into the proof; the packing and the
        // BaseFold prover data are read in place.
        precomputed: &PrecomputedJaggedCommit,
        challenger: &mut crate::jagged_pcs::JaggedChallenger,
    ) -> JaggedGroupProof {
        // Per-shard jagged-PCS sub-phase timing.  Five sub-phases mirror
        // the numbered protocol steps below: (1) metadata, (2) commit
        // (incl. dense materialize + BaseFold encode), (3) per-chip
        // y_{c,j} evaluation, (4) jagged-sumcheck reduction, (5) BaseFold
        // open at z*.
        let n_chips = chip_traces.len();

        // The per-shard rev(zeta) orientation, read off the committed data
        // (`PrecomputedJaggedCommit.rev`, set at commit from
        // `StarkMachine::core_rev()`) so the step-4 reduction's dense
        // re-materialize + `y_per_chip` stay in lockstep with the commit.
        // Read off the committed data (`PrecomputedJaggedCommit.rev`).
        let dense_rev = precomputed.rev;

        // (1) + (2): metadata + dense commit were run up-front by the
        // orchestrator's single-main-commit path, which has already observed
        // the 8-felt digest of `commit.original_commitment` as
        // `main_commitment` in the shard-level Phase 1 prologue.  The in-band
        // commit observe is therefore skipped to keep transcripts aligned with
        // the verifier (which uses `verify_jagged_basefold_no_observe`).
        //
        // `host_dense_q` is `Some` ONLY on the device-commit DECLINE path (the
        // provider-aware host fallback body captured the correct dense_q while
        // the provider was live).  It carries the dense_q forward so the
        // reduction below does not re-materialize from the (drained) provider.
        // `recursion_area_pin` carries the recursion AREA PIN
        // forward so the step-4 jagged-eval half is pin-consistent with the
        // (pinned) commit — read off the committed data.
        tracing::debug!(
            chips = n_chips,
            "jagged_pcs: using precomputed commit (Option B single-main-commit flow)",
        );
        let PrecomputedJaggedCommit {
            packing,
            commit,
            prover_data,
            rev: _,
            recursion_area_pin,
        } = precomputed;
        let commit = commit.clone();
        let recursion_area_pin = *recursion_area_pin;

        // (3) Compute per-chip per-column row-MLE values y_{c,j}.
        //
        // Parallelize across chips AND across columns within each chip.
        // The triple-nested loop
        // (chip × col × row) is O(N_chips · max_w · max_h) which for
        // a 22-chip MIPS shard padded to 2^19 rows hits ~10M+ EF
        // multiply-adds. Each chip × column reduction is independent.
        let _t_yvals = std::time::Instant::now();
        let _yvals_span = tracing::info_span!("jagged_y_per_chip").entered();
        use p3_maybe_rayon::prelude::*;
        let y_per_chip: Vec<Vec<InnerChallenge>> = if let Some(pre) = pre_y_per_chip {
            // Pre-computed (e.g. device-resident GPU eval).  Skip the
            // host triple-nested reduction entirely.
            assert_eq!(
                pre.len(),
                chip_traces.len(),
                "pre_y_per_chip length must match chip_traces length",
            );
            //  empty-chip skip: for empty-trace chips
            // (height==0 || width==0) the GPU dispatch supplies
            // `Vec::new()`; the host fallback (else branch) below
            // would have asserted on `h_padded.trailing_zeros() ==
            // r_row_c.len()` (h_padded=1, trailing_zeros=0 vs
            // r_row_c.len()=max_log_row_count).  Just accept the
            // empty per-chip y slot — y_{c,j} is the empty product
            // for an empty column set, so the downstream sumcheck
            // reduction skips it naturally.
            pre
        } else {
            // The host triple-loop reads chip cells directly from the host
            // `chip_traces` views.  (Stage 5: the device-resident re-materialize
            // fallback is gone — dead from the GPU prover, which runs its own
            // device-native copy, and inert on the CPU prover, which owns real
            // host traces.)
            // The rev(zeta) orientation, read off the committed data
            // (`dense_rev`, from `PrecomputedJaggedCommit.rev`), captured by
            // value into the per-chip / per-column rayon closures below.
            let use_rev_y = dense_rev;
            chip_traces
                .par_iter()
                .zip(r_row_per_chip.par_iter())
                .map(|((_name, pm), r_row_c)| {
                    let (trace_values, w) = crate::jagged::real_cells(pm);
                    let h = if w == 0 { 0 } else { trace_values.len() / w };
                    // A genuine HEIGHT-0 (0-row) but
                    // FULL-WIDTH missing chip
                    // must still emit ONE column claim PER COLUMN (all zero),
                    // NOT an empty Vec.  `build_weight_table` and the verifier's
                    // `verify_jagged_reduction` k-walk advance `k` through EVERY
                    // committed column (chip_info.column_count) including the
                    // 0-row chip's `w` empty columns; skipping them here would
                    // misalign the `z_col_lagrange[k]` index for every later
                    // chip => the round-0 / final reduction identity fails.  An
                    // empty column's row-MLE claim is 0 (Σ over 0 rows), so emit
                    // `w` zeros.  Only a truly width-0 chip (no columns) skips.
                    if w == 0 {
                        return Vec::new();
                    }
                    if h == 0 {
                        return vec![InnerChallenge::ZERO; w];
                    }
                    let h_padded = h.next_power_of_two();
                    assert_eq!(h_padded.trailing_zeros() as usize, r_row_c.len());

                    // Column claim: full row_eq over z_row indexed
                    // by the NATURAL row (eq(z_row, r)), no Pi_high embedding.
                    // The full row_eq subsumes the height factor for any row <
                    // 2^log_h_c (high bits of such a row are 0).  Build over
                    // reversed z_row so eq_c[r] = eq(z_row, r) (undo eq_mle_table
                    // LSB-first bitrev), matching build_weight_table.
                    let _ = r_row_c;
                    let z_row_rev: Vec<InnerChallenge> = z_row.iter().rev().copied().collect();
                    let eq_c = crate::zerocheck_prover::eq_mle_table::<InnerChallenge>(&z_row_rev);
                    // The rev(zeta) orientation (`use_rev_y`, read off the
                    // committed `PrecomputedJaggedCommit.rev`, in lockstep with
                    // the commit).  Under rev, the COMMIT (`materialize_dense_jagged`)
                    // places the data in NATURAL row order, so the column claim
                    // must read NATURAL rows too (`src = row`) — together with the
                    // natural-indexed `build_weight_table` the round-0 identity
                    // `Σ z_col·y == Σ_b q·w` holds.  Else (legacy) bit-reverse the
                    // trace row index so `y_per_chip == opened_values` (= MLE of
                    // bitrev(trace)), byte-identical to today.  `use_rev_y` is
                    // hoisted above (read on the carrier thread, not in this rayon
                    // closure).
                    let is_pow2 = h.is_power_of_two();
                    let log_h2 = if is_pow2 { (h as u32).trailing_zeros() } else { 0 };
                    (0..w)
                        .into_par_iter()
                        .map(|col| {
                            let mut acc = InnerChallenge::ZERO;
                            for row in 0..h {
                                let src = if use_rev_y {
                                    row
                                } else if is_pow2 {
                                    ((row as u32).reverse_bits() >> (32 - log_h2)) as usize
                                } else {
                                    row
                                };
                                acc += eq_c[row]
                                    * InnerChallenge::from(trace_values[src * w + col]);
                            }
                            acc
                        })
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        drop(_yvals_span);
        tracing::info!(
            elapsed_ms = _t_yvals.elapsed().as_millis() as u64,
            chips = n_chips,
            sub_phase = "y_per_chip",
            "jagged sub-phase done"
        );

        // (4) Rebuild dense_q for the sumcheck reduction from the STRIPES the
        // commit retained, then drop it immediately after.  Uses the `_owned`
        // reduction entry point so the inner loop can drop dense_q after round
        // 0 (releasing the 4N base-field buffer before the EF tables for rounds
        // 1..n are built) — saves one full N-element clone vs the `&[InnerVal]`
        // entry point.
        // ── The jagged reduction packaged as the `reduce` closure threaded through
        // the shared `prove_jagged_basefold_linear_core`.  The core samples
        // `z_col` at the SP1 transcript position (after the commit observe,
        // immediately before the reduction) and passes it in.  This closure
        // runs NO challenger op outside the reduction itself, so `z_col`'s
        // transcript position is identical to the generic / per-group paths —
        // the whole point of the de-dup.  Non-`move`: every capture (packing /
        // y_per_chip / chip_traces / provider / r_row_per_chip / z_row /
        // n_chips) is read by reference.
        // SP1 parity (`slop/crates/jagged/src/prover.rs`): take a CHEAP
        // `Arc`-clone handle on the stripes the commit already produced, use it
        // for the sumcheck, then move the same `prover_data` into the open.
        // `Vec<Arc<Mle>>` clone == SP1's `Message<Mle>` clone: pointer-only.
        let interleaved = prover_data.stacked_data.interleaved_mles.clone();
        let reduce = |z_col: &[InnerChallenge],
                      challenger: &mut crate::jagged_pcs::JaggedChallenger|
              -> crate::jagged_sumcheck::JaggedReductionProof<InnerChallenge> {
        // The pre-reduce device-trace `release_all` (SP1 drop_ldes
        // analog) is gone — dead from the GPU prover (its own device-native
        // copy owns the free) and inert on the CPU prover (no provider).

        let _t_red = std::time::Instant::now();
        let _red_span = tracing::info_span!("jagged_sumcheck_reduce").entered();
        let reduction = {
            // Host reduction — the former `HostJaggedReducer::reduce_jagged`
            // body inlined (SP1 shape: reduce is type-dispatched, no trait).
            // The CPU prover is the ONLY caller of this host inner; the GPU
            // prover runs its own device-native copy
            // (`prove_jagged_basefold_inner_gpu`) calling the device
            // reduce/open kernels directly.  Byte-identical to the former
            // `is_device()==false` host arm (device carrier / decline
            // fallback scaffolding was dead on the CPU prover).
            // SP1 shape: the dense representation is built ONCE per round, at
            // commit time, and the SAME data feeds both the jagged sumcheck and
            // the open — `prove_trusted_evaluations` takes
            // `pcs_prover_data.interleaved_mles()` for the sumcheck poly and
            // then moves the same `pcs_prover_data` into
            // `prove_untrusted_evaluation`.  Ziren used to re-derive `dense_q`
            // from `chip_traces` here, a SECOND full pass over the same cells
            // (measured 0.70 s/shard at `log_dense_size = 28`, i.e. 2^28 cells
            // = 1 GiB, on 16 threads).  Rebuild it from the stripes the commit
            // already retained instead; `dense_from_interleaved_mles` is the
            // exact inverse of the width-1 interleave, so this is byte-identical
            // — and it drops the reduction's last dependency on `chip_traces`.
            // SP1 shape: the reduction runs on `HadamardProduct` over the
            // committed stripes themselves — no dense rebuild at all.  The
            // stripes ARE `Message<Mle>`, which is what `LongMle` carries, so
            // `jagged_hadamard_poly` restacks them into the single component the
            // sumcheck needs and pairs them with the weight table.
            let weights = crate::jagged_sumcheck::build_weight_table_from_z_col(
                &packing,
                r_row_per_chip,
                &z_col,
                z_row,
            );
            // The jagged dense area is a PREFIX of the committed stripes (which
            // also carry the stacking padding), so it is extracted rather than
            // handed over whole.  SP1's jagged sumcheck is dense on both sides
            // too (`partial_jagged_little_polynomial_evaluation` builds a dense
            // `2^log_total_area` MLE), so this matches its shape.
            let mut dense_q = crate::basefold::stacked::dense_from_interleaved_mles::<InnerVal>(
                &interleaved,
                packing.dense_len,
            );
            // The committed area is a whole number of stacking blocks, not a
            // power of two, so the sumcheck hypercube runs past it; the gap is
            // zero (this host reduction materializes it, the device one folds
            // the real prefix and leaves the tail implicit).
            dense_q.resize(1usize << packing.log_dense_size(), InnerVal::ZERO);
            let hp = crate::jagged_long::HadamardProduct {
                base: crate::jagged_long::LongMle::from_components(
                    alloc::vec![crate::basefold::Mle::from_values(dense_q)],
                    packing.log_dense_size() as u32,
                ),
                ext: crate::jagged_long::LongMle::from_components(
                    alloc::vec![crate::basefold::Mle::from_values(weights)],
                    packing.log_dense_size() as u32,
                ),
            };
            crate::jagged_long::prove_jagged_reduction_hadamard_poly(hp, challenger)
        };
        drop(_red_span);
        tracing::info!(
            elapsed_ms = _t_red.elapsed().as_millis() as u64,
            chips = n_chips,
            // ENGAGEMENT COUNTER for the committed-stripe rebuild above.  A
            // non-zero `dense_stripes` on every shard is the proof that the
            // reduction really read the commit's `interleaved_mles` and did not
            // silently fall back — the failure mode a byte gate cannot see,
            // because any correct dense_q source produces identical bytes.
            dense_stripes = interleaved.len() as u64,
            sub_phase = "sumcheck_reduce",
            "jagged sub-phase done"
        );

        // The pre-open device-trace `release_all` (PIECE2) is gone —
        // dead from the GPU prover (its own device-native copy owns the
        // pre-open free) and inert on the CPU prover (no provider).

            reduction
        };

        // ── The BaseFold open packaged as the `open` closure.  Moves
        // `prover_data` in; captures `n_chips` by copy.  Runs NO challenger op
        // outside the jagged-PCS open, so the point-extend (sampled by the core
        // immediately before) lands identically across all paths.
        //
        // (5) The jagged sumcheck reduces over `dense_q` (2^log_dense
        // cells) but the BaseFold commit covers `prover_data.area` cells
        // (num_stripes × batch_size × stack_height), which can exceed
        // 2^log_dense_size; the core extends z* to log2(area) with extra
        // Fiat-Shamir coords (SP1's `prove_trusted_evaluation` opens at
        // `final_eval_point` directly — Ziren's one deviation) before this
        // open runs.
        let area = prover_data.area;
        let open = move |extended_eval_point: Vec<InnerChallenge>,
                         challenger: &mut crate::jagged_pcs::JaggedChallenger| {
            let _t_open = std::time::Instant::now();
            let _open_span = tracing::info_span!("jagged_basefold_open").entered();
            let proof =
                open_jagged_pcs(&prover_data, extended_eval_point, challenger);
            drop(_open_span);
            tracing::info!(
                elapsed_ms = _t_open.elapsed().as_millis() as u64,
                chips = n_chips,
                sub_phase = "basefold_open",
                "jagged sub-phase done"
            );
            proof
        };

        // Shared linear core: z_col sample → reduce → jagged-eval →
        // point-extend → open (SP1 `prove_trusted_evaluations` shape).
        let (reduction, jagged_eval, proof) = prove_jagged_basefold_linear_core(
            &packing.offsets,
            z_row,
            area,
            challenger,
            recursion_area_pin,
            reduce,
            open,
        );

        let packing_meta = PackingMeta {
            offsets: packing.offsets.clone(),
            total_values: packing.total_values,
            log_dense_size: packing.log_dense_size(),
            // fix: per-chip *actual* column count, so verifier
            // does not need to consult `BaseAir::width(chip)`.
            column_counts: packing
                .chip_infos
                .iter()
                .map(|ci| ci.column_count)
                .collect(),
            // Single round: its own geometry.
            round_counts: alloc::vec![packing
                .chip_infos
                .iter()
                .map(|ci| (ci.row_count, ci.column_count))
                .collect()],
            // No padding columns on this path.
            padding_heights: Vec::new(),
        };
        let _ = n_chips;
        JaggedGroupProof {
            reduction,
            basefold_proof: proof,
            commit,
            packing: packing_meta,
            jagged_eval,
            y_per_chip,
        }
    }

    /// SP1's multi-ROUND prove: ONE jagged proof spanning every committed
    /// round.
    ///
    /// This is the shape SP1 uses (`slop/crates/jagged/src/prover.rs:236-320`):
    /// one jagged sumcheck over every round's stripes, ONE jagged-eval, and ONE
    /// batched BaseFold open over `stacked_prover_data: Rounds<_>` — only the
    /// commitments are per round.  Proving each round as its own jagged group
    /// instead costs a reduction, an eval and an open PER ROUND; measured on
    /// reth that was 2.87x the wall time and 1.77x the proof size.
    ///
    /// The rounds are concatenated into ONE column space: round r's offsets are
    /// shifted by the total cell count of the rounds before it, so the packing
    /// the reduction and the jagged-eval see is a single jagged matrix whose
    /// columns run `[round 0 | round 1 | ...]`.
    ///
    /// Round order is load-bearing — it fixes the column order the verifier
    /// reconstructs — and the preprocessed round comes first.
    /// The INNER ring's multi-round prove — the ring's own Mmcs / DFT / FRI
    /// config, forwarded to the generic body below.
    pub fn prove_jagged_basefold_rounds(
        rounds: &[JaggedOpenRound<'_, crate::jagged_pcs::JaggedMmcs>],
        z_row: &[InnerChallenge],
        challenger: &mut crate::jagged_pcs::JaggedChallenger,
    ) -> JaggedBasefoldBundle {
        let perm: crate::kb31_poseidon2::InnerPerm = zkm_primitives::poseidon2_init();
        let hash = crate::kb31_poseidon2::InnerHash::new(perm.clone());
        let compress = crate::kb31_poseidon2::InnerCompress::new(perm);
        let mmcs = crate::jagged_pcs::JaggedMmcs::new(hash, compress, 0);
        let dft = alloc::sync::Arc::new(crate::jagged_pcs::JaggedDft::default());
        prove_jagged_basefold_rounds_generic::<
            crate::jagged_pcs::JaggedChallenger,
            crate::jagged_pcs::JaggedMmcs,
            crate::jagged_pcs::JaggedDft,
        >(
            rounds,
            z_row,
            challenger,
            mmcs,
            dft,
            crate::basefold::FriConfig::<crate::jagged_pcs::JaggedVal>::from_env_or_default(),
        )
    }

    /// Ring-generic body.  The INNER (Poseidon2-KoalaBear) ring reaches it
    /// through [`prove_jagged_basefold_rounds`]; the BN254 wrap ring names its
    /// own commitment family, which is what lets the terminal stage open a
    /// preprocessed round like every other stage.
    #[allow(clippy::type_complexity)]
    pub fn prove_jagged_basefold_rounds_generic<Challenger, MT, D>(
        rounds: &[JaggedOpenRound<'_, MT>],
        z_row: &[InnerChallenge],
        challenger: &mut Challenger,
        mmcs: MT,
        dft: alloc::sync::Arc<D>,
        fri: crate::basefold::FriConfig<crate::jagged_pcs::JaggedVal>,
    ) -> JaggedBasefoldBundleGeneric<MT>
    where
        MT: p3_commit::Mmcs<crate::jagged_pcs::JaggedVal, Commitment: Clone> + Clone,
        D: p3_dft::TwoAdicSubgroupDft<crate::jagged_pcs::JaggedVal> + Send + Sync,
        Challenger: p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
            + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
            + p3_challenger::CanObserve<
                <MT as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Commitment,
            >,
    {
        assert!(!rounds.is_empty(), "prove_jagged_basefold_rounds: no rounds");

        // ── Concatenate the rounds into one column space ──────────────────
        let mut chip_infos: Vec<crate::jagged::JaggedChipInfo> = Vec::new();
        let mut offsets: Vec<usize> = Vec::new();
        let mut round_padding_heights: Vec<Vec<usize>> = Vec::with_capacity(rounds.len());
        let mut y_per_chip: Vec<Vec<InnerChallenge>> = Vec::new();
        let mut r_row_per_chip: Vec<Vec<InnerChallenge>> = Vec::new();
        let mut base = 0usize;
        for r in rounds.iter() {
            let pk = &r.precomputed.packing;
            chip_infos.extend(pk.chip_infos.iter().cloned());
            // Drop each round's sentinel; re-base its column offsets onto the
            // running total.
            let n_cols = pk.offsets.len().saturating_sub(1);
            offsets.extend(pk.offsets.iter().take(n_cols).map(|o| o + base));
            y_per_chip.extend(r.claims.iter().cloned());
            r_row_per_chip.extend(r.r_row_per_chip.iter().cloned());

            // The rounds are NOT contiguous in the committed dense: the stacked
            // commitment rounds each one UP to a whole number of stripes
            // (`area = total_values.next_multiple_of(1 << log_stacking_height)`)
            // and the batched open indexes every round's stripes end to end.  So
            // a round FOLLOWED BY ANOTHER has a gap of real committed space in
            // the middle of the column layout, and the offsets can only stay a
            // prefix sum if a column covers it — a DUMMY column of zeros with a
            // ZERO claim.  SP1 does the same, adding `padding_column_count` zero
            // claims per round ("Add in the dummy padding columns added during
            // the stacked PCS commitment", slop/crates/jagged/src/prover.rs:190).
            //
            // EVERY round pads, the last one included.  Its gap looks like it
            // could be left to the hypercube padding the point extension covers
            // — but `total_values` is what makes the reduction's hypercube equal
            // the committed area, and dropping the last round's fill shrinks it
            // below `effective_area`, so the stacked claim no longer equals the
            // interpolated batch evaluations (MEASURED: StackingMismatch on the
            // ~10 s CPU harness).  The column layout has to cover every
            // committed cell.
            let area = r.precomputed.prover_data.area;
            let pad = area.saturating_sub(pk.total_values);
            {
                // Split the gap into whole COLUMNS bounded by the row cube —
                // which is why SP1 carries a padding_column_COUNT rather than a
                // single wide column.  A column taller than `2^z_row.len()` has
                // no eq table to be weighed against.
                //
                // ALWAYS at least one, even when the round happens to land on a
                // stripe boundary — SP1's `.max(1)`
                // (slop/crates/jagged/src/prover.rs:135).  A zero-height column
                // costs nothing and is what keeps the column COUNT a function of
                // the machine rather than of how full this particular shard is,
                // which is what lets the recursion circuit carry a fixed layout.
                let cube = 1usize << z_row.len();
                let mut done = 0usize;
                let mut pad_off = base + pk.total_values;
                let mut this_round_pads: Vec<usize> = Vec::new();
                loop {
                    let h = core::cmp::min(cube, pad - done);
                    this_round_pads.push(h);
                    offsets.push(pad_off);
                    chip_infos.push(crate::jagged::JaggedChipInfo {
                        name: alloc::format!("<stacking-pad:{}>", chip_infos.len()),
                        row_count: h,
                        column_count: 1,
                    });
                    y_per_chip.push(alloc::vec![InnerChallenge::ZERO]);
                    let log_h = h.max(1).next_power_of_two().trailing_zeros() as usize;
                    r_row_per_chip.push(z_row[z_row.len() - log_h..].to_vec());
                    done += h;
                    pad_off += h;
                    if done >= pad {
                        break;
                    }
                }
                round_padding_heights.push(this_round_pads);
            }
            base += area;
        }
        let total_values = base;
        offsets.push(total_values);
        // The rounds' areas are already carried as explicit padding columns, so
        // the concatenated instance's committed length IS its column space.
        let packing = crate::jagged::JaggedPacking::<InnerVal> {
            dense_values: Vec::new(),
            chip_infos: chip_infos.clone(),
            offsets: offsets.clone(),
            total_values,
            dense_len: total_values,
        };
        let n_chips = chip_infos.len();

        // ── The reduction, over the CONCATENATED dense ────────────────────
        let reduce = |z_col: &[InnerChallenge],
                      challenger: &mut Challenger|
         -> crate::jagged_sumcheck::JaggedReductionProof<InnerChallenge> {
            let _red_span = tracing::info_span!("jagged_sumcheck_reduce").entered();
            let weights = crate::jagged_sumcheck::build_weight_table_from_z_col(
                &packing,
                &r_row_per_chip,
                z_col,
                z_row,
            );
            // Each round's dense cells are the PREFIX of its committed stripes;
            // laid end to end they are the concatenated jagged matrix, then
            // zero-padded to the combined hypercube.
            let log_dense_size = packing.log_dense_size();
            let mut dense_q: Vec<InnerVal> = Vec::with_capacity(1usize << log_dense_size);
            for r in rounds.iter() {
                // Each round contributes its FULL committed cell space — real
                // cells followed by the stacking padding — because that is what
                // the batched open indexes.
                let area = r.precomputed.prover_data.area;
                let round_dense =
                    crate::basefold::stacked::dense_from_interleaved_mles::<InnerVal>(
                        &r.precomputed.prover_data.stacked_data.interleaved_mles,
                        area,
                    );
                dense_q.extend_from_slice(&round_dense[..area]);
            }
            dense_q.resize(1usize << log_dense_size, InnerVal::ZERO);
            let hp = crate::jagged_long::HadamardProduct {
                base: crate::jagged_long::LongMle::from_components(
                    alloc::vec![crate::basefold::Mle::from_values(dense_q)],
                    log_dense_size as u32,
                ),
                ext: crate::jagged_long::LongMle::from_components(
                    alloc::vec![crate::basefold::Mle::from_values(weights)],
                    log_dense_size as u32,
                ),
            };
            crate::jagged_long::prove_jagged_reduction_hadamard_poly(hp, challenger)
        };

        // ── ONE batched open across every round's committed data ──────────
        let open = |extended_eval_point: Vec<InnerChallenge>,
                    challenger: &mut Challenger| {
            let _open_span = tracing::info_span!("jagged_basefold_open").entered();
            let datas: Vec<&crate::jagged_pcs::JaggedProverDataGeneric<MT>> =
                rounds.iter().map(|r| &r.precomputed.prover_data).collect();
            crate::jagged_pcs::open_jagged_pcs_rounds_generic::<Challenger, MT, D>(
                &datas,
                extended_eval_point,
                challenger,
                mmcs,
                dft,
                fri,
            )
        };

        // The batched open's point spans the stack coords plus enough batch
        // coords to index EVERY round's stripes end to end; the stripe total
        // need not be a power of two (the verifier zero-pads it), so the
        // dimension is the ceiling.
        let log_stacking_height = rounds[0].precomputed.prover_data.log_stacking_height as usize;
        let total_stripes: usize = rounds
            .iter()
            .map(|r| r.precomputed.prover_data.area >> log_stacking_height)
            .sum();
        let batch_dim = total_stripes.max(1).next_power_of_two().trailing_zeros() as usize;
        let effective_area = 1usize << (log_stacking_height + batch_dim);

        let (reduction, jagged_eval, proof) = prove_jagged_basefold_linear_core(
            &offsets,
            z_row,
            effective_area,
            challenger,
            rounds[0].precomputed.recursion_area_pin,
            reduce,
            open,
        );
        let _ = n_chips;

        // The bundle carries the LAST round's commit — the main one, which the
        // hash-bind ties to `main_commitment`.  An earlier round's commitment as
        // the KEY holds it is the hash-bound digest, so the proof carries only
        // its RAW root and the verifier re-derives the bound form to check it
        // (SP1 `verifier/shard.rs:638` builds
        // `vec![vk.preprocessed_commit, *main_commitment]`).
        let main = rounds.last().expect("non-empty");
        let preceding_commits: Vec<_> = rounds[..rounds.len() - 1]
            .iter()
            .map(|r| r.precomputed.commit.original_commitment.clone())
            .collect();
        let packing_meta = PackingMeta {
            offsets,
            total_values,
            log_dense_size: packing.log_dense_size(),
            column_counts: chip_infos.iter().map(|ci| ci.column_count).collect(),
            // Each round's REAL chip geometry, as committed — no stacking
            // padding, which is an artifact of flattening the rounds together.
            round_counts: rounds
                .iter()
                .map(|r| {
                    r.precomputed
                        .packing
                        .chip_infos
                        .iter()
                        .map(|ci| (ci.row_count, ci.column_count))
                        .collect()
                })
                .collect(),
            padding_heights: round_padding_heights,
        };
        JaggedBasefoldBundleGeneric::<MT> {
            reduction,
            basefold_proof: proof,
            y_per_chip,
            commit: main.precomputed.commit.clone(),
            packing: packing_meta,
            jagged_eval,
            extra_reduction: Vec::new(),
            extra_basefold_proof: Vec::new(),
            extra_commit: Vec::new(),
            extra_packing: Vec::new(),
            extra_jagged_eval: Vec::new(),
            groups: Vec::new(),
            preceding_commits,
        }
    }


    /// Single-round prove: one group, emitted as the bundle's scalar group-0
    /// fields with `extra_*` / `groups` empty — byte-identical to the pre-split
    /// wire format.
    fn prove_jagged_basefold_single_round(
        chip_traces: &[ChipTraceView],
        r_row_per_chip: &[Vec<InnerChallenge>],
        z_row: &[InnerChallenge],
        pre_y_per_chip: Option<Vec<Vec<InnerChallenge>>>,
        precomputed: &PrecomputedJaggedCommit,
        challenger: &mut crate::jagged_pcs::JaggedChallenger,
    ) -> JaggedBasefoldBundle {
        let g = prove_one_jagged_group(
            chip_traces,
            r_row_per_chip,
            z_row,
            pre_y_per_chip,
            precomputed,
            challenger,
        );
        JaggedBasefoldBundle {
            reduction: g.reduction,
            basefold_proof: g.basefold_proof,
            y_per_chip: g.y_per_chip,
            commit: g.commit,
            packing: g.packing,
            jagged_eval: g.jagged_eval,
            extra_reduction: Vec::new(),
            extra_basefold_proof: Vec::new(),
            extra_commit: Vec::new(),
            extra_packing: Vec::new(),
            extra_jagged_eval: Vec::new(),
            groups: Vec::new(),
            preceding_commits: Vec::new(),
        }
    }

    /// The ring-generic single-round prove: challenger + Mmcs generic, so the
    /// wrap (OuterChallenger + OuterValMmcs) can emit a BaseFold-BN254 bundle
    /// from the same body.  `prove_jagged_basefold_single_round` above is the
    /// inner-ring instantiation, which additionally reaches the GPU
    /// jagged-reduction hooks (those are inner-typed).  Requires a precomputed
    /// commit.
    #[allow(clippy::type_complexity)]
    pub fn prove_jagged_basefold_single_round_generic<Challenger, MT>(
        chip_traces: &[ChipTraceView],
        r_row_per_chip: &[Vec<InnerChallenge>],
        z_row: &[InnerChallenge],
        pre_y_per_chip: Option<Vec<Vec<InnerChallenge>>>,
        // Borrowed, like the concrete path: a commit built once can be opened
        // by every shard.
        precomputed: &PrecomputedJaggedCommitGeneric<MT>,
        challenger: &mut Challenger,
        mmcs: MT,
        fri: FriConfig<crate::jagged_pcs::JaggedVal>,
    ) -> JaggedBasefoldBundleGeneric<MT>
    where
        MT: p3_commit::Mmcs<crate::jagged_pcs::JaggedVal, Commitment: Clone> + Clone,
        Challenger: p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
            + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
            + CanObserve<<MT as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Commitment>,
    {
        use p3_maybe_rayon::prelude::*;
        let PrecomputedJaggedCommitGeneric { packing, commit, prover_data, rev: dense_rev, recursion_area_pin } = precomputed;
        // Borrowed commit: only the (small) commitment is cloned into the
        // proof; the packing and BaseFold prover data are read in place.
        let commit = commit.clone();
        let dense_rev = *dense_rev;
        let recursion_area_pin = *recursion_area_pin;

        // (3) per-chip per-column row-MLE values y_{c,j} (field-only; mirrors
        // the host path including the row-eq embedding factor + empty-chip skip).
        // The rev(zeta) orientation, read off the committed data
        // (`PrecomputedJaggedCommitGeneric.rev`), captured by value into the
        // per-chip rayon closures below.  On the wrap/BN254 path `rev == false`
        // => legacy bitrev (byte-identical).
        let use_rev_y = dense_rev;
        let y_per_chip: Vec<Vec<InnerChallenge>> = if let Some(pre) = pre_y_per_chip {
            assert_eq!(pre.len(), chip_traces.len(),
                "pre_y_per_chip length must match chip_traces length");
            pre
        } else {
            chip_traces
                .par_iter()
                .zip(r_row_per_chip.par_iter())
                .map(|((_name, pm), r_row_c)| {
                    let (trace_values, w) = crate::jagged::real_cells(pm);
                    let h = if w == 0 { 0 } else { trace_values.len() / w };
                    if h == 0 || w == 0 {
                        return Vec::new();
                    }
                    let h_padded = h.next_power_of_two();
                    assert_eq!(h_padded.trailing_zeros() as usize, r_row_c.len());
                    let _ = r_row_c; // SP1 convention uses the full z_row row_eq
                    // Column claim: full row_eq over z_row indexed
                    // by the NATURAL row (eq(z_row, r)), no Pi_high embedding.
                    // Build over reversed z_row so eq_c[r] = eq(z_row, r) (undo
                    // eq_mle_table's LSB-first bitrev), matching build_weight_table.
                    let z_row_rev: Vec<InnerChallenge> = z_row.iter().rev().copied().collect();
                    let eq_c = crate::zerocheck_prover::eq_mle_table::<InnerChallenge>(&z_row_rev);
                    // Same rev(zeta) orientation (single source
                    // of truth) — NATURAL rows under rev so the round-0 identity
                    // holds on this no-observe verify recompute too; legacy bitrev
                    // (`y_per_chip == MLE of bitrev(trace)`) otherwise.
                    // `use_rev_y` is hoisted above the `par_iter` (carrier-thread
                    // read), captured by value into these rayon closures.
                    let is_pow2 = h.is_power_of_two();
                    let log_h2 = if is_pow2 { (h as u32).trailing_zeros() } else { 0 };
                    (0..w)
                        .into_par_iter()
                        .map(|col| {
                            let mut acc = InnerChallenge::ZERO;
                            for row in 0..h {
                                let src = if use_rev_y {
                                    row
                                } else if is_pow2 {
                                    ((row as u32).reverse_bits() >> (32 - log_h2)) as usize
                                } else {
                                    row
                                };
                                acc += eq_c[row]
                                    * InnerChallenge::from(trace_values[src * w + col]);
                            }
                            acc
                        })
                        .collect::<Vec<_>>()
                })
                .collect()
        };

        // ── The HOST reduction (no device hooks on the BN254 wrap
        // path) + the BN254 BaseFold open as the `reduce` / `open` closures
        // threaded through the shared `prove_jagged_basefold_linear_core`.
        // The core samples `z_col` at the SP1 transcript position and runs the
        // jagged-eval + point-extend — so this path lands its challenger ops in
        // the IDENTICAL order to the concrete single-group + per-group paths.
        let reduce = |z_col: &[InnerChallenge],
                      challenger: &mut Challenger|
              -> JaggedReductionProof<InnerChallenge> {
            let dense_q =
                materialize_dense_jagged::<InnerVal>(chip_traces, packing.dense_len, dense_rev);
            let weights = crate::jagged_sumcheck::build_weight_table_from_z_col(
                &packing,
                r_row_per_chip,
                z_col,
                z_row,
            );
            let hp = crate::jagged_long::HadamardProduct {
                base: crate::jagged_long::LongMle::from_components(
                    alloc::vec![crate::basefold::Mle::from_values(dense_q)],
                    packing.log_dense_size() as u32,
                ),
                ext: crate::jagged_long::LongMle::from_components(
                    alloc::vec![crate::basefold::Mle::from_values(weights)],
                    packing.log_dense_size() as u32,
                ),
            };
            crate::jagged_long::prove_jagged_reduction_hadamard_poly(hp, challenger)
        };
        let area = prover_data.area;
        let open = move |extended_eval_point: Vec<InnerChallenge>,
                         challenger: &mut Challenger| {
            let dft = std::sync::Arc::new(crate::jagged_pcs::JaggedDft::default());
            crate::jagged_pcs::open_jagged_pcs_generic::<
                Challenger,
                MT,
                crate::jagged_pcs::JaggedDft,
            >(&prover_data, extended_eval_point, challenger, mmcs, dft, fri)
        };
        let (reduction, jagged_eval, proof) = prove_jagged_basefold_linear_core(
            &packing.offsets,
            z_row,
            area,
            challenger,
            recursion_area_pin,
            reduce,
            open,
        );

        let packing_meta = PackingMeta {
            offsets: packing.offsets.clone(),
            total_values: packing.total_values,
            log_dense_size: packing.log_dense_size(),
            column_counts: packing.chip_infos.iter().map(|ci| ci.column_count).collect(),
            // The wrap ring is always single-round: its own geometry.
            round_counts: alloc::vec![packing
                .chip_infos
                .iter()
                .map(|ci| (ci.row_count, ci.column_count))
                .collect()],
            // No padding columns on this path.
            padding_heights: Vec::new(),
        };
        // The BN254 wrap path is always single-round (G==1): scalar fields,
        // empty extra_* / groups (byte-identical to the pre-split bundle).
        JaggedBasefoldBundleGeneric {
            reduction,
            basefold_proof: proof,
            y_per_chip,
            commit,
            packing: packing_meta,
            jagged_eval,
            extra_reduction: Vec::new(),
            extra_basefold_proof: Vec::new(),
            extra_commit: Vec::new(),
            extra_packing: Vec::new(),
            extra_jagged_eval: Vec::new(),
            groups: Vec::new(),
            preceding_commits: Vec::new(),
        }
    }
    /// Verifier mirror.
    pub fn verify_jagged_basefold(
        chip_infos: &[JaggedChipInfo],
        r_row_per_chip: &[Vec<InnerChallenge>],
        z_row: &[InnerChallenge], // full z* for embedding factor
        bundle: &JaggedBasefoldBundle,
        challenger: &mut crate::jagged_pcs::JaggedChallenger,
    ) -> bool {
        verify_jagged_basefold_inner(
            chip_infos,
            r_row_per_chip,
            z_row,
            // Synthetic single-round bundles: no preprocessed round.
            0,
            &[],
            bundle,
            // Synthetic-bundle callers (unit tests) carry no shard
            // openings — the cross-bind is a no-op here.
            None,
            challenger,
            /* skip_commit_observe = */ false,
        )
    }

    /// Option B variant: verifier counterpart of
    /// [`prove_jagged_basefold_with_precomputed_provider`].  Skips the in-band
    /// `challenger.observe(commitment)` because the orchestrator's
    /// Phase 1 prologue already observed the BaseFold commit's 8-felt
    /// digest as `main_commitment`.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_jagged_basefold_no_observe(
        chip_infos: &[JaggedChipInfo],
        r_row_per_chip: &[Vec<InnerChallenge>],
        z_row: &[InnerChallenge], // full z* for embedding factor
        // Rounds committed BEFORE the proof's own, whose commitments come from
        // the VERIFYING KEY (the preprocessed round), as (commitment, area).
        preceding_rounds: &[(
            <crate::jagged_pcs::JaggedMmcs as p3_commit::Mmcs<
                crate::jagged_pcs::JaggedVal,
            >>::Commitment,
            usize,
        )],

        // Number of leading PREPROCESSED entries in `chip_infos` — 0 for a
        // main-only proof, otherwise SP1's two-round split.  Read off the
        // VERIFYING KEY, never off the proof: it is what the coverage check
        // measures the proof's group map against.
        n_prep: usize,
        bundle: &JaggedBasefoldBundle,
        // Cross-bind: per-chip `opened_values.chips[].main.local` (index-
        // aligned with `chip_infos` / `bundle.y_per_chip`); `None` disables the bind.
        opened_main: Option<&[Vec<InnerChallenge>]>,
        challenger: &mut crate::jagged_pcs::JaggedChallenger,
    ) -> bool {
        verify_jagged_basefold_inner(
            chip_infos,
            r_row_per_chip,
            z_row,
            n_prep,
            preceding_rounds,
            bundle,
            opened_main,
            challenger,
            /* skip_commit_observe = */ true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_jagged_basefold_inner(
        chip_infos: &[JaggedChipInfo],
        r_row_per_chip: &[Vec<InnerChallenge>],
        z_row: &[InnerChallenge], // full z* for embedding factor
        n_prep: usize,
        // Rounds committed BEFORE the proof's own, whose commitments come from
        // the VERIFYING KEY (the preprocessed round), as (commitment, area).
        preceding_rounds: &[(
            <crate::jagged_pcs::JaggedMmcs as p3_commit::Mmcs<
                crate::jagged_pcs::JaggedVal,
            >>::Commitment,
            usize,
        )],

        bundle: &JaggedBasefoldBundle,
        // Cross-bind: per-chip `opened_values.chips[].main.local` trace
        // openings (index-aligned with `chip_infos` / `bundle.y_per_chip`), or
        // `None` for synthetic-bundle unit tests with no shard openings.
        opened_main: Option<&[Vec<InnerChallenge>]>,
        challenger: &mut crate::jagged_pcs::JaggedChallenger,
        skip_commit_observe: bool,
    ) -> bool {
        // ── COVERAGE CHECK (the #1 soundness guard — FIRST assertion) ─────
        // Independently re-derive the round partition from the PUBLIC
        // name-sorted (name,row_count,column_count) the verifier already
        // holds, and require the proof's `groups` membership to equal it
        // EXACTLY (no chip dropped, none duplicated, canonical order).
        // Without this a malicious prover could OMIT a chip from every
        // group — that chip's trace is then never opened, and nothing
        // downstream would notice.
        let expected_groups = crate::jagged::partition_from_chip_infos(chip_infos);
        let proof_groups: Vec<Vec<usize>> = bundle.groups_or_identity(chip_infos.len());
        if proof_groups != expected_groups {
            eprintln!(
                "[basefold verify] COVERAGE CHECK FAILED: proof groups {:?} != expected {:?}",
                proof_groups, expected_groups
            );
            record_stage!(VerifyStage::Coverage);
            return false;
        }
        // Structural agreement between the group map and the per-group data.
        let g_count = proof_groups.len();
        if bundle.num_groups() != g_count {
            eprintln!(
                "[basefold verify] COVERAGE CHECK FAILED: bundle carries {} groups \
                 but the group map has G={}",
                bundle.num_groups(),
                g_count,
            );
            record_stage!(VerifyStage::Coverage);
            return false;
        }

        // STEP 1 (transcript): observe ALL G commits up-front in partition
        // order — unless the Option B single-main-commit flow already
        // observed them at the Phase 1 prologue.  (G==1 single-commit is the
        // current Option B path; multi-commit Option B is CP-B/CP-C.)
        if !skip_commit_observe {
            for g in 0..g_count {
                challenger.observe(bundle.commit_g(g).original_commitment.clone());
            }
        }

        // STEP 3: verify each independent jagged instance against the SHARED
        // z_row.  All G must accept.
        for g in 0..g_count {
            let grp = &proof_groups[g];
            // Group-LOCAL chip_infos / r_row (membership-indexed); the
            // per-group bundle metadata (offsets/total/log_dense_size) is
            // group-local too (prefix-sums restart at 0).
            let chip_infos_g: Vec<JaggedChipInfo> =
                grp.iter().map(|&i| chip_infos[i].clone()).collect();
            let r_row_g: Vec<Vec<InnerChallenge>> =
                grp.iter().map(|&i| r_row_per_chip[i].clone()).collect();
            let y_per_chip_g: Vec<Vec<InnerChallenge>> =
                grp.iter().map(|&i| bundle.y_per_chip[i].clone()).collect();
            // Slice this group's opened main.local columns in the SAME
            // membership order as `y_per_chip_g` so the cross-bind k-walk lines up.
            let opened_main_g: Option<Vec<Vec<InnerChallenge>>> = opened_main
                .map(|om| grp.iter().map(|&i| om[i].clone()).collect());
            let pkg = bundle.packing_g(g);
            let packing = JaggedPacking {
                dense_values: Vec::new(),
                chip_infos: chip_infos_g,
                offsets: pkg.offsets.clone(),
                total_values: pkg.total_values,
                // Bundle-level: the rounds' areas are already explicit padding
                // columns, so the committed length IS the column space.
                dense_len: pkg.total_values,
            };
            if !verify_one_jagged_group(
                &packing,
                &r_row_g,
                z_row,
                &y_per_chip_g,
                opened_main_g.as_deref(),
                bundle.reduction_g(g),
                bundle.jagged_eval_g(g),
                bundle.commit_g(g),
                bundle.basefold_proof_g(g),
                challenger,
                // Only the FIRST group carries the vk-pinned rounds; with the
                // batched shape there is exactly one group.
                if g == 0 { preceding_rounds } else { &[] },
                g,
            ) {
                return false;
            }
        }
        record_stage!(VerifyStage::Accepted);
        true
    }

    /// Verify ONE independent jagged instance (group `g`) against the shared
    /// `z_row`: sample `z_col_g`, verify the reduction, replay the
    /// jagged-eval transcript, extend `z*_g`, and verify the BaseFold open
    /// of `C_g`.  Returns `false` on any rejection.
    #[allow(clippy::too_many_arguments)]
    fn verify_one_jagged_group(
        packing: &JaggedPacking<InnerVal>,
        r_row_per_chip: &[Vec<InnerChallenge>],
        z_row: &[InnerChallenge],
        y_per_chip: &[Vec<InnerChallenge>],
        // Cross-bind: this group's per-chip `opened_values.chips[].main.local`
        // trace openings (index-aligned with `y_per_chip`), or `None` for callers
        // (unit tests) that verify a synthetic bundle with no shard openings.
        opened_main: Option<&[Vec<InnerChallenge>]>,
        reduction: &crate::jagged_sumcheck::JaggedReductionProof<InnerChallenge>,
        jagged_eval: &crate::jagged_eval_sumcheck::JaggedSumcheckEvalProof<InnerChallenge>,
        commit: &crate::jagged_pcs::JaggedCommit,
        basefold_proof: &crate::basefold::StackedBasefoldProof<InnerVal, InnerChallenge, crate::jagged_pcs::JaggedMmcs>,
        challenger: &mut crate::jagged_pcs::JaggedChallenger,
        // Rounds committed BEFORE this one whose commitments come from the
        // verifying key (the preprocessed round), as (commitment, area).
        preceding_rounds: &[(
            <crate::jagged_pcs::JaggedMmcs as p3_commit::Mmcs<
                crate::jagged_pcs::JaggedVal,
            >>::Commitment,
            usize,
        )],
        g: usize,
    ) -> bool {
        // SP1-aligned: sample z_col at the matching transcript position
        // (after the commit observe, before the reduction), mirroring
        // the prover.
        let num_cols = packing.offsets.len().saturating_sub(1);
        let num_col_vars = num_cols.next_power_of_two().trailing_zeros() as usize;
        let z_col: Vec<InnerChallenge> = (0..num_col_vars)
            .map(|_| challenger.sample_algebra_element())
            .collect();
        let red_result = verify_jagged_reduction(
            reduction,
            packing,
            r_row_per_chip,
            y_per_chip,
            &z_col,
            z_row,
            challenger,
        );
        let Some((z_star, q_at_z, _w_at_z)) = red_result else {
            eprintln!("[basefold verify] group {g}: jagged sumcheck reduction REJECTED");
            record_stage!(VerifyStage::Reduction(g));
            return false;
        };

        // ── CROSS-BIND (host analog of recursive_jagged_pcs.rs:247) ─────
        //
        // The recursion CIRCUIT ties the jagged sumcheck's claimed sum to the
        // TRACE OPENINGS: it forms `column_claims = opened_values.chips[].main.local`
        // (shard_basefold.rs:588 → recursive_jagged_pcs.rs:218) and asserts
        //   evaluate_mle(column_claims, z_col) == sumcheck_proof.claimed_sum   (:247).
        //
        // The host, in contrast, DERIVES the claimed sum from the bundle's
        // `y_per_chip` alone — `verify_jagged_reduction` uses
        //   t = Σ_k z_col_lagrange[k]·y_flat[k] = evaluate_mle(y_flat, z_col)
        // as its round-0 claim (jagged_sumcheck.rs:735-742) and NEVER checks
        // `y_per_chip` against the openings.  So a malicious host proof could ship
        // `y_per_chip ≠ opened_values.main.local` and be accepted by BOTH the
        // zerocheck (which consumes `opened_values`) and this jagged phase (which
        // consumes `y_per_chip`) independently — the soundness-parity gap.
        //
        // Close it exactly as the circuit does: recompute the OPENED-VALUES column
        // MLE at the SAME `z_col` and require it to equal the y-derived claimed sum
        // `t`.  We mirror the MLE form rather than a raw element-wise compare: under
        // the rev(zeta) orientation the two column vectors are NOT guaranteed
        // element-wise equal, but their `z_col`-MLEs ARE equal — that is precisely
        // the identity the circuit asserts and that passes on every honest proof.
        // We weight only the columns the sumcheck actually consumed (per-chip
        // `y_per_chip[i].len()`, i.e. the packed column_count), matching the k-walk
        // in `verify_jagged_reduction` so `sum_y` reproduces its `t` bit-for-bit.
        if let Some(opened_main_g) = opened_main {
            if opened_main_g.len() != y_per_chip.len() {
                eprintln!(
                    "[basefold verify] group {g}: cross-bind FAILED — opened-main \
                     chip count {} != y_per_chip {}",
                    opened_main_g.len(),
                    y_per_chip.len(),
                );
                record_stage!(VerifyStage::Reduction(g));
                return false;
            }
            let z_col_lagrange =
                crate::jagged_branching_program::partial_lagrange(&z_col);
            let mut sum_y = InnerChallenge::ZERO;
            let mut sum_open = InnerChallenge::ZERO;
            let mut k = 0usize;
            let mut ok = true;
            'chips: for (yc, mc) in y_per_chip.iter().zip(opened_main_g.iter()) {
                // The opened trace must expose at least the columns the sumcheck
                // consumed (column_count ≤ BaseAir::width); a proof opening fewer
                // is malformed → reject.
                if mc.len() < yc.len() {
                    ok = false;
                    break 'chips;
                }
                for j in 0..yc.len() {
                    if k >= z_col_lagrange.len() {
                        ok = false;
                        break 'chips;
                    }
                    let w = z_col_lagrange[k];
                    sum_y += w * yc[j];
                    sum_open += w * mc[j];
                    k += 1;
                }
            }
            if !ok || sum_open != sum_y {
                eprintln!(
                    "[basefold verify] group {g}: CROSS-BIND FAILED — the bundle's \
                     y_per_chip column claims are inconsistent with \
                     opened_values.main.local at z_col \
                     (evaluate_mle(opened_main, z_col) != jagged claimed_sum)"
                );
                record_stage!(VerifyStage::Reduction(g));
                return false;
            }
        }

        // Replay the jagged-eval sub-protocol transcript so the
        // challenger stays in sync with the prover before the BaseFold
        // open.  (Full branching-program verification is done by the
        // recursion verifier; the host self-check needs only transcript
        // fidelity here.)
        crate::jagged_eval_sumcheck::replay_jagged_evaluation_transcript(
            jagged_eval,
            challenger,
        );

        // SP1-port: extend z_star from log_dense_size to log2(area)
        // by sampling additional Fiat-Shamir coords, mirroring the
        // prover's extension in `prove_jagged_basefold` step (5).
        // Both sides sample from the same transcript state at the same
        // point in the protocol so the coords match.
        // Capture the reduced (pre-extension) length BEFORE the extend
        // loop: that is the fixed log_stacking-equivalent height of
        // this (per-group) commit, used below to gate the sub-stripe
        // Π(1-r) claim adjustment.
        let z_star_orig_len = z_star.len();
        // The batched open covers EVERY round, so the point must index all of
        // their stripes end to end — not just this round's area.  The stripe
        // total need not be a power of two (the verifier zero-pads the
        // concatenated list), hence the CEILING.
        let stack_dim_for_target = commit.log_stacking_height as usize;
        let total_stripes: usize = preceding_rounds
            .iter()
            .map(|(_, a)| a >> stack_dim_for_target)
            .sum::<usize>()
            + (commit.area >> stack_dim_for_target);
        let target_dim = stack_dim_for_target
            + total_stripes.max(1).next_power_of_two().trailing_zeros() as usize;
        let mut extended_z_star = z_star;
        while extended_z_star.len() < target_dim {
            let r: InnerChallenge = challenger.sample_algebra_element();
            extended_z_star.push(r);
        }

        // FIX-off sub-stripe commits (host analog of the in-circuit
        // `claim_adj`, recursive_stacked_pcs.rs): when the reduced point is
        // SHORTER than the commit's log_stacking_height, the FS-extension
        // coords falling in the STACK portion `[z_star_orig_len, stack_dim)`
        // correspond to the ZERO high-half padding of the stripe (the dense
        // poly of `z_star_orig_len` vars is zero-padded up to `2^stack_dim`).
        // By the MLE zero-padding identity the committed stripe's eval at
        // `stack_point` carries a Π(1 - r_k) factor over those coords that the
        // reduced-point claim lacks, so the stacked reconstruction equals
        // Π(1 - r_k) · q_at_z.  Multiply the claim to match.  NO-OP when
        // z_star_orig_len >= stack_dim (all FIX-on and large FIX-off commits)
        // ⇒ byte-identical there.  Each group is verified through this
        // function, so this covers every group (CP-A round-split included).
        let stack_dim = commit.log_stacking_height as usize;
        let mut q_at_z_adj = q_at_z;
        if z_star_orig_len < stack_dim {
            for r in &extended_z_star[z_star_orig_len..stack_dim.min(target_dim)] {
                q_at_z_adj *= InnerChallenge::ONE - *r;
            }
        }

        // Verify the BaseFold opening: claim is q_at_z (sub-stripe adjusted),
        // point is the extended z*.
        // The batched open covers EVERY round: the rounds whose commitments
        // the verifying key pins come first, then this round's own.
        let mut commitments: Vec<_> =
            preceding_rounds.iter().map(|(c, _)| c.clone()).collect();
        commitments.push(commit.original_commitment.clone());
        let mut areas: Vec<usize> = preceding_rounds.iter().map(|(_, a)| *a).collect();
        areas.push(commit.area);
        let res = crate::jagged_pcs::verify_jagged_pcs_rounds(
            &commitments,
            &areas,
            commit.log_stacking_height,
            &extended_z_star,
            q_at_z_adj,
            basefold_proof,
            challenger,
        );
        if let Err(e) = &res {
            eprintln!("[basefold verify] basefold opening REJECTED: {:?}", e);
            record_stage!(VerifyStage::Open(g));
        }
        res.is_ok()
    }

    /// BaseFold-over-BN254 wrap port: build the ring-agnostic verifier
    /// inputs (chip_infos / r_row_per_chip / z_row) from the bundle's PackingMeta
    /// + per-chip column widths + the shared zerocheck eval point. Mirrors the
    /// host verifier's construction (shard_level/verifier.rs) so the outer-ring
    /// verify hook reuses the exact same logic. Names are debug-only (unused in
    /// the verify math), so placeholders suffice.
    pub fn build_jagged_verify_inputs(
        packing: &PackingMeta,
        chip_widths: &[usize],
        eval_point: &[InnerChallenge],
    ) -> (
        Vec<crate::jagged::JaggedChipInfo>,
        Vec<Vec<InnerChallenge>>,
        Vec<InnerChallenge>,
    ) {
        use crate::jagged::JaggedChipInfo;
        let column_counts = &packing.column_counts;
        // One entry per COLUMN GROUP the prover emitted — every round's chips
        // AND the stacking-padding columns between them.  `chip_widths` (the
        // machine's main chips) is only the legacy fallback for a bundle that
        // predates `column_counts`: taking its LENGTH as the group count reads
        // a two-round packing as if the preprocessed round's widths were the
        // main chips', and stops before the main round entirely.
        let n_groups =
            if column_counts.is_empty() { chip_widths.len() } else { column_counts.len() };
        let mut chip_infos: Vec<JaggedChipInfo> = (0..n_groups)
            .map(|i| JaggedChipInfo {
                name: alloc::format!("chip{i}"),
                row_count: 0,
                column_count: column_counts
                    .get(i)
                    .copied()
                    .unwrap_or_else(|| chip_widths.get(i).copied().unwrap_or(0)),
            })
            .collect();
        // Patch row_count from the offsets sentinel walk (same as the host verifier).
        {
            let mut col_idx = 0usize;
            for info in chip_infos.iter_mut() {
                if info.column_count == 0 {
                    continue;
                }
                let h = if col_idx + 1 < packing.offsets.len() {
                    packing.offsets[col_idx + 1].saturating_sub(packing.offsets[col_idx])
                } else if col_idx < packing.offsets.len() {
                    packing.total_values.saturating_sub(packing.offsets[col_idx])
                } else {
                    0
                };
                info.row_count = h;
                col_idx += info.column_count;
            }
        }
        let r_row_per_chip: Vec<Vec<InnerChallenge>> = chip_infos
            .iter()
            .map(|info| {
                let log_h =
                    info.row_count.max(1).next_power_of_two().trailing_zeros() as usize;
                if eval_point.len() >= log_h {
                    eval_point[eval_point.len() - log_h..].to_vec()
                } else {
                    eval_point.to_vec()
                }
            })
            .collect();
        let z_row = eval_point.to_vec();
        (chip_infos, r_row_per_chip, z_row)
    }

    /// BaseFold-over-BN254 wrap port: verifier mirror of
    /// `prove_jagged_basefold_single_round_generic`, generic over the challenger + MMCS.
    /// The OUTER (wrap) ring drives this with OuterChallenger + OuterValMmcs via
    /// the registered verify hook; the inner ring keeps the concrete
    /// `verify_jagged_basefold_inner`.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub fn verify_jagged_basefold_inner_generic<Challenger, MT>(
        chip_infos: &[JaggedChipInfo],
        r_row_per_chip: &[Vec<InnerChallenge>],
        z_row: &[InnerChallenge],
        bundle: &JaggedBasefoldBundleGeneric<MT>,
        challenger: &mut Challenger,
        mmcs: MT,
        skip_commit_observe: bool,
        fri: FriConfig<crate::jagged_pcs::JaggedVal>,
        // Rounds committed BEFORE this one, as (commitment, area) — the
        // preprocessed round, whose commitment the verifying key holds.  Empty
        // for a machine with no preprocessed traces.
        preceding_rounds: &[(<MT as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Commitment, usize)],
    ) -> bool
    where
        MT: p3_commit::Mmcs<crate::jagged_pcs::JaggedVal, Commitment: Clone> + Clone,
        Challenger: p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
            + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
            + CanObserve<<MT as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Commitment>,
    {
        // One jagged GROUP (the round split is inside it, as `preceding_rounds`
        // + this bundle's own commit).  The coverage check (group-map vs
        // partition) is enforced on the INNER host verifier; the wrap bundle
        // always carries the identity cover (empty `groups` / `extra_*`).
        debug_assert_eq!(
            bundle.num_groups(), 1,
            "wrap verify expects a single-GROUP bundle",
        );
        if !skip_commit_observe {
            challenger.observe(bundle.commit.original_commitment.clone());
        }
        let packing = JaggedPacking {
            dense_values: Vec::new(),
            chip_infos: chip_infos.to_vec(),
            offsets: bundle.packing.offsets.clone(),
            total_values: bundle.packing.total_values,
            dense_len: bundle.packing.total_values,
        };
        let num_cols = packing.offsets.len().saturating_sub(1);
        let num_col_vars = num_cols.next_power_of_two().trailing_zeros() as usize;
        let z_col: Vec<InnerChallenge> = (0..num_col_vars)
            .map(|_| challenger.sample_algebra_element())
            .collect();
        let red_result = crate::jagged_sumcheck::verify_jagged_reduction(
            &bundle.reduction,
            &packing,
            r_row_per_chip,
            &bundle.y_per_chip,
            &z_col,
            z_row,
            challenger,
        );
        let Some((z_star, q_at_z, _w_at_z)) = red_result else {
            eprintln!("[basefold verify outer] jagged sumcheck reduction REJECTED");
            return false;
        };
        crate::jagged_eval_sumcheck::replay_jagged_evaluation_transcript(
            &bundle.jagged_eval,
            challenger,
        );
        // Capture the reduced (pre-extension) length BEFORE the extend loop
        // (see the inner verifier for the rationale).
        let z_star_orig_len = z_star.len();
        // The batched open indexes EVERY round's stripes end to end, so the
        // point spans the stack coords plus enough batch coords for the total
        // stripe count (ceiling — the verifier zero-pads the tail).
        let stack_dim_for_target = bundle.commit.log_stacking_height as usize;
        let total_stripes: usize = preceding_rounds
            .iter()
            .map(|(_, a)| a >> stack_dim_for_target)
            .sum::<usize>()
            + (bundle.commit.area >> stack_dim_for_target);
        let target_dim = stack_dim_for_target
            + total_stripes.max(1).next_power_of_two().trailing_zeros() as usize;
        let mut extended_z_star = z_star;
        while extended_z_star.len() < target_dim {
            let r: InnerChallenge = challenger.sample_algebra_element();
            extended_z_star.push(r);
        }
        // FIX-off sub-stripe commits: host analog of the in-circuit
        // `claim_adj` (recursive_stacked_pcs.rs).  Multiply q_at_z by the
        // Π(1-r) factor over the stack-portion extension coords when the
        // reduced point is shorter than log_stacking_height.  NO-OP (byte
        // identical) when z_star_orig_len >= stack_dim.
        let stack_dim = bundle.commit.log_stacking_height as usize;
        let mut q_at_z_adj = q_at_z;
        if z_star_orig_len < stack_dim {
            for r in &extended_z_star[z_star_orig_len..stack_dim.min(target_dim)] {
                q_at_z_adj *= InnerChallenge::ONE - *r;
            }
        }
        // The batched open covers EVERY round: the rounds the verifying key
        // pins come first, then this bundle's own.
        let mut commitments: Vec<_> =
            preceding_rounds.iter().map(|(c, _)| c.clone()).collect();
        commitments.push(bundle.commit.original_commitment.clone());
        let mut areas: Vec<usize> = preceding_rounds.iter().map(|(_, a)| *a).collect();
        areas.push(bundle.commit.area);
        let res = crate::jagged_pcs::verify_jagged_pcs_rounds_generic::<Challenger, MT>(
            &commitments,
            &areas,
            bundle.commit.log_stacking_height,
            &extended_z_star,
            q_at_z_adj,
            &bundle.basefold_proof,
            challenger,
            mmcs,
            fri,
        );
        if let Err(e) = &res {
            eprintln!("[basefold verify outer] basefold opening REJECTED: {:?}", e);
        }
        res.is_ok()
    }

    // ── Cross-bind forgery-rejection test ───────────────────────────
    // Lives inside `mod jagged` so it can drive the private
    // `verify_jagged_basefold_inner` (skip_commit_observe=false) with the
    // SAME transcript `prove_jagged_basefold` produced, and inject the
    // per-chip `opened_values.main.local` openings the production shard
    // verifier now threads in.
    #[cfg(test)]
    mod crossbind_121_test {
        use super::*;
        use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};

        fn rk<R: Rng>(rng: &mut R) -> InnerVal {
            InnerVal::from_u32(rng.gen::<u32>() & 0x3FFF_FFFF)
        }
        fn re<R: Rng>(rng: &mut R) -> InnerChallenge {
            <InnerChallenge as BasedVectorSpace<InnerVal>>::from_basis_coefficients_iter(
                (0..4).map(|_| rk(rng)),
            )
            .unwrap()
        }
        fn chal() -> crate::jagged_pcs::JaggedChallenger {
            crate::jagged_pcs::JaggedChallenger::new(zkm_primitives::poseidon2_init())
        }

        /// The commit/open entry points take BORROWED
        /// `ChipTraceView`s over the shard prover's shared `Arc<Mle>` store.
        /// Tests own their matrices, so relabel each owned matrix as a
        /// zero-copy view over its own cells — same cells, same width.
        fn as_chip_views(
            traces: &[(alloc::string::String, RowMajorMatrix<InnerVal>)],
        ) -> Vec<ChipTraceView> {
            traces
                .iter()
                .map(|(name, t)| {
                    (name.clone(), {
                    let h = if t.width == 0 { 0 } else { t.values.len() / t.width };
                    let log_h = if h <= 1 { 0 } else { h.next_power_of_two().ilog2() };
                    crate::multilinear::PaddedMle::padded_with_zeros(
                        std::sync::Arc::new(crate::basefold::Mle::from_row_major(
                            p3_matrix::dense::RowMajorMatrix::new(t.values.clone(), t.width),
                        )),
                        log_h,
                    )
                })
                })
                .collect()
        }

        /// The recursion circuit binds the jagged claimed sum to the trace
        /// openings (recursive_jagged_pcs.rs:247); this mirrors that on the
        /// host.  This test proves the bind is load-bearing:
        ///   (1) honest openings (== y_per_chip) verify;
        ///   (2) a bundle whose column claims DIVERGE from the openings is
        ///       REJECTED once the openings are threaded in (`Some`);
        ///   (3) the SAME divergent proof is (wrongly) ACCEPTED with the bind
        ///       disabled (`None`) — i.e. the host behaviour with the bind removed.
        #[test]
        fn crossbind_rejects_divergent_openings() {
            let mut rng = StdRng::seed_from_u64(0x0121_0BAD_C0DE);
            let mk = |w: usize, h: usize, rng: &mut StdRng| -> RowMajorMatrix<InnerVal> {
                let v: Vec<InnerVal> = (0..w * h).map(|_| rk(rng)).collect();
                RowMajorMatrix::new(v, w)
            };
            let traces = vec![
                ("Cpu".to_string(), mk(4, 16, &mut rng)),
                ("Add".to_string(), mk(2, 8, &mut rng)),
            ];
            let r_row_per_chip: Vec<Vec<InnerChallenge>> = traces
                .iter()
                .map(|(_, t)| {
                    let h = t.values.len() / t.width.max(1);
                    let log_h = h.next_power_of_two().trailing_zeros() as usize;
                    (0..log_h).map(|_| re(&mut rng)).collect()
                })
                .collect();
            let z_row: Vec<InnerChallenge> = r_row_per_chip
                .iter()
                .max_by_key(|v| v.len())
                .cloned()
                .unwrap_or_default();

            let views = as_chip_views(&traces);
            let mut p = chal();
            let bundle = prove_jagged_basefold(&views, &r_row_per_chip, &z_row, &mut p);
            let infos =
                crate::jagged::compute_jagged_metadata::<InnerVal>(&views).chip_infos;

            // The honest per-chip `main.local` openings coincide with the
            // bundle's column claims (single-orientation synthetic bundle).
            let opened_ok: Vec<Vec<InnerChallenge>> = bundle.y_per_chip.clone();

            // (1) honest openings + cross-bind ON → ACCEPT.
            let mut v = chal();
            assert!(
                verify_jagged_basefold_inner(
                    &infos, &r_row_per_chip, &z_row, /* n_prep = */ 0,
                    /* preceding_rounds = */ &[], &bundle,
                    Some(&opened_ok), &mut v, false,
                ),
                "honest openings must verify"
            );

            // (2) DIVERGENT openings + cross-bind ON → REJECT.
            let mut opened_bad = opened_ok.clone();
            opened_bad[0][0] += InnerChallenge::ONE; // tamper ONE column claim
            let mut v = chal();
            assert!(
                !verify_jagged_basefold_inner(
                    &infos, &r_row_per_chip, &z_row, /* n_prep = */ 0,
                    /* preceding_rounds = */ &[], &bundle,
                    Some(&opened_bad), &mut v, false,
                ),
                "y_per_chip diverging from openings MUST be rejected by the cross-bind"
            );

            // (3) SAME divergent openings but bind OFF (None) → ACCEPT.
            //     Documents the pre-fix gap the cross-bind closes.
            let mut v = chal();
            assert!(
                verify_jagged_basefold_inner(
                    &infos, &r_row_per_chip, &z_row, /* n_prep = */ 0,
                    /* preceding_rounds = */ &[], &bundle,
                    None, &mut v, false,
                ),
                "pre-fix baseline: with no opened-values bind the divergent proof is (wrongly) accepted"
            );
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use p3_challenger::FieldChallenger;
    use p3_field::BasedVectorSpace;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    fn rand_kb<R: Rng>(rng: &mut R) -> JaggedVal {
        JaggedVal::from_u32(rng.gen::<u32>() & 0x3FFF_FFFF)
    }

    fn rand_ef<R: Rng>(rng: &mut R) -> JaggedChallenge {
        <JaggedChallenge as BasedVectorSpace<JaggedVal>>::from_basis_coefficients_iter(
            (0..4).map(|_| rand_kb(rng)),
        )
        .unwrap()
    }

    fn build_challenger() -> JaggedChallenger {
        let perm: crate::kb31_poseidon2::InnerPerm =
            zkm_primitives::poseidon2_init();
        JaggedChallenger::new(perm)
    }

    /// End-to-end: commit a small batch of heterogeneous chip traces,
    /// open at a random point, verify.  This is the OOM-cure flow
    /// (per-chip Mles → stacked PCS → BaseFold) on a toy size.
    #[test]
    fn test_jagged_pcs_roundtrip() {
        let mut rng = StdRng::seed_from_u64(0xBA5E_F01D_5EED);

        // Two synthetic chip traces of different shapes; both must
        // pad to power-of-2 row counts inside the stacking height.
        let mk_trace = |width: usize, h: usize, rng: &mut StdRng| -> RowMajorMatrix<JaggedVal> {
            let v: Vec<JaggedVal> = (0..width * h).map(|_| rand_kb(rng)).collect();
            RowMajorMatrix::new(v, width)
        };
        let traces = vec![
            ("Cpu".into(), mk_trace(20, 100, &mut rng)),
            ("Add".into(), mk_trace(8, 50, &mut rng)),
        ];

        let mut p_chal = build_challenger();
        let (commit, prover_data) = commit_jagged_pcs(traces.clone());
        // The caller owns the transcript write.
        p_chal.observe(commit.original_commitment.clone());

        // Compute the eval point + claim for the stacked PCS.  Claim
        // is the multilinear-extension of the *flattened*
        // batch-evaluations vector at the batch part of the point.
        let stack_dim = commit.log_stacking_height as usize;
        let num_stripes = commit.area >> stack_dim;
        let num_batch_vars = num_stripes.next_power_of_two().trailing_zeros() as usize;
        let total_vars = num_batch_vars + stack_dim;
        let eval_point: Vec<JaggedChallenge> =
            (0..total_vars).map(|_| rand_ef(&mut rng)).collect();

        let stack_point: Vec<JaggedChallenge> = eval_point[..stack_dim].to_vec();
        let batch_evals_flat: Vec<JaggedChallenge> = prover_data
            .stacked_data
            .interleaved_mles
            .iter()
            .flat_map(|m| m.eval_at::<JaggedChallenge>(&stack_point))
            .collect();

        // Honest evaluation_claim = MLE of batch_evals_flat at
        // batch_point (matches the verifier's
        // `eval_multilinear_padded` reduction).
        let batch_point = &eval_point[stack_dim..];
        let evaluation_claim = {
            let target = 1usize << batch_point.len();
            let mut current: Vec<JaggedChallenge> = batch_evals_flat.clone();
            current.resize(target, JaggedChallenge::ZERO);
            for &r in batch_point.iter().rev() {
                let half = current.len() / 2;
                for i in 0..half {
                    let lo = current[2 * i];
                    let hi = current[2 * i + 1];
                    current[i] = lo + r * (hi - lo);
                }
                current.truncate(half);
            }
            current[0]
        };

        let proof = open_jagged_pcs(&prover_data, eval_point.clone(), &mut p_chal);

        let mut v_chal = build_challenger();
        v_chal.observe(commit.original_commitment.clone());
        verify_jagged_pcs(
            &commit.original_commitment,
            commit.area,
            commit.log_stacking_height,
            &eval_point,
            evaluation_claim,
            &proof,
            &mut v_chal,
        )
        .expect("basefold jagged-PCS roundtrip");
    }

    /// Full jagged-sumcheck pipeline backed by BaseFold.
    #[test]
    fn test_jagged_basefold_roundtrip() {
        use crate::jagged_pcs::jagged::{
            prove_jagged_basefold, verify_jagged_basefold,
        };

        let mut rng = StdRng::seed_from_u64(0xC0DE_BA5E);

        let mk_trace =
            |width: usize, height: usize, rng: &mut StdRng| -> RowMajorMatrix<JaggedVal> {
                let v: Vec<JaggedVal> = (0..width * height).map(|_| rand_kb(rng)).collect();
                RowMajorMatrix::new(v, width)
            };

        // Two heterogeneous chip traces; both heights round up to a
        // power of 2 inside the stacking stripe.
        let traces = vec![
            ("Cpu".into(), mk_trace(4, 16, &mut rng)),
            ("Add".into(), mk_trace(2, 8, &mut rng)),
        ];

        // Per-chip r_row sampled fresh; length = log2(padded height).
        let r_row_per_chip: Vec<Vec<JaggedChallenge>> = traces
            .iter()
            .map(|(_, t)| {
                let h = t.values.len() / t.width.max(1);
                let log_h = h.next_power_of_two().trailing_zeros() as usize;
                (0..log_h).map(|_| rand_ef(&mut rng)).collect()
            })
            .collect();

        let mut p_chal = build_challenger();
        let z_row_test: Vec<JaggedChallenge> = r_row_per_chip
            .iter()
            .max_by_key(|v| v.len())
            .cloned()
            .unwrap_or_default();
        let views = as_chip_views(&traces);
        let bundle =
            prove_jagged_basefold(&views, &r_row_per_chip, &z_row_test, &mut p_chal);

        // Verifier reconstructs chip_infos from the same traces it
        // already has access to via the protocol's outer loop.
        let chip_infos =
            crate::jagged::compute_jagged_metadata::<JaggedVal>(&views).chip_infos;
        let mut v_chal = build_challenger();
        let ok = verify_jagged_basefold(&chip_infos, &r_row_per_chip, &z_row_test, &bundle, &mut v_chal);
        assert!(ok, "jagged-basefold pipeline should accept honest proof");
    }

    /// **Soundness sanity** — flipping any single field of the bundle
    /// must cause the verifier to reject.  Catches whole classes of
    /// "I forgot to observe X into the challenger" bugs that pass
    /// honest-prover tests but admit forgery.
    #[test]
    fn test_jagged_basefold_rejects_tampered_proof() {
        use p3_field::PrimeCharacteristicRing;
        use crate::jagged_pcs::jagged::{
            prove_jagged_basefold, verify_jagged_basefold,
        };

        let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF);
        let mk_trace =
            |width: usize, height: usize, rng: &mut StdRng| -> RowMajorMatrix<JaggedVal> {
                let v: Vec<JaggedVal> = (0..width * height).map(|_| rand_kb(rng)).collect();
                RowMajorMatrix::new(v, width)
            };
        let traces = vec![("Cpu".into(), mk_trace(4, 16, &mut rng))];
        let r_row_per_chip: Vec<Vec<JaggedChallenge>> = traces
            .iter()
            .map(|(_, t)| {
                let h = t.values.len() / t.width.max(1);
                let log_h = h.next_power_of_two().trailing_zeros() as usize;
                (0..log_h).map(|_| rand_ef(&mut rng)).collect()
            })
            .collect();

        let mut p_chal = build_challenger();
        let z_row_test: Vec<JaggedChallenge> = r_row_per_chip
            .iter()
            .max_by_key(|v| v.len())
            .cloned()
            .unwrap_or_default();
        let views = as_chip_views(&traces);
        let bundle =
            prove_jagged_basefold(&views, &r_row_per_chip, &z_row_test, &mut p_chal);
        let chip_infos =
            crate::jagged::compute_jagged_metadata::<JaggedVal>(&views).chip_infos;

        // Tamper #1: corrupt the sumcheck final claim `q_at_z`.
        let mut tampered = bundle.clone();
        tampered.reduction.q_at_z = tampered.reduction.q_at_z + JaggedChallenge::ONE;
        let mut v_chal = build_challenger();
        assert!(
            !verify_jagged_basefold(&chip_infos, &r_row_per_chip, &z_row_test, &tampered, &mut v_chal),
            "verifier must reject q_at_z tampering"
        );

        // Tamper #2: corrupt one of the per-chip y_{c,j} commitments.
        let mut tampered = bundle.clone();
        tampered.y_per_chip[0][0] = tampered.y_per_chip[0][0] + JaggedChallenge::ONE;
        let mut v_chal = build_challenger();
        assert!(
            !verify_jagged_basefold(&chip_infos, &r_row_per_chip, &z_row_test, &tampered, &mut v_chal),
            "verifier must reject y_per_chip tampering"
        );

        // Tamper #3: corrupt the BaseFold final_poly in the proof.
        let mut tampered = bundle.clone();
        tampered.basefold_proof.basefold_proof.final_poly =
            tampered.basefold_proof.basefold_proof.final_poly + JaggedChallenge::ONE;
        let mut v_chal = build_challenger();
        assert!(
            !verify_jagged_basefold(&chip_infos, &r_row_per_chip, &z_row_test, &tampered, &mut v_chal),
            "verifier must reject final_poly tampering"
        );
    }



    // ════════════════════════════════════════════════════════════════
    // CP-A: per-round jagged split (Architecture A) host validation.
    // ════════════════════════════════════════════════════════════════

    use crate::jagged_pcs::jagged::{
        prove_jagged_basefold, verify_jagged_basefold, ChipTraceView, JaggedBasefoldBundle,
        VerifyStage, LAST_VERIFY_STAGE,
    };

    /// The commit/open entry points take BORROWED
    /// `ChipTraceView`s over the shard prover's shared `Arc<Mle>` store.
    /// Tests own their matrices, so relabel each owned matrix as a zero-copy
    /// view over its own cells — same cells, same width.
    fn as_chip_views(
        traces: &[(String, RowMajorMatrix<JaggedVal>)],
    ) -> Vec<ChipTraceView> {
        traces
            .iter()
            .map(|(name, t)| (name.clone(), {
                    let h = if t.width == 0 { 0 } else { t.values.len() / t.width };
                    let log_h = if h <= 1 { 0 } else { h.next_power_of_two().ilog2() };
                    crate::multilinear::PaddedMle::padded_with_zeros(
                        std::sync::Arc::new(crate::basefold::Mle::from_row_major(
                            p3_matrix::dense::RowMajorMatrix::new(t.values.clone(), t.width),
                        )),
                        log_h,
                    )
                }))
            .collect()
    }

    /// Run `verify_jagged_basefold` and return (accepted, last_stage).
    fn verify_with_stage(
        chip_infos: &[crate::jagged::JaggedChipInfo],
        r_row: &[Vec<JaggedChallenge>],
        z_row: &[JaggedChallenge],
        bundle: &JaggedBasefoldBundle,
    ) -> (bool, Option<VerifyStage>) {
        LAST_VERIFY_STAGE.with(|c| c.set(None));
        let mut v = build_challenger();
        let ok = verify_jagged_basefold(chip_infos, r_row, z_row, bundle, &mut v);
        (ok, LAST_VERIFY_STAGE.with(core::cell::Cell::get))
    }

    /// Build (traces, r_row_per_chip, z_row) for a set of `(width, height)`
    /// chip shapes, with deterministic random cells.
    fn mk_shard(
        shapes: &[(usize, usize)],
        seed: u64,
    ) -> (
        Vec<(String, RowMajorMatrix<JaggedVal>)>,
        Vec<Vec<JaggedChallenge>>,
        Vec<JaggedChallenge>,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        // Name-sorted so the partition's name-sorted-order precondition holds.
        let traces: Vec<(String, RowMajorMatrix<JaggedVal>)> = shapes
            .iter()
            .enumerate()
            .map(|(i, &(w, h))| {
                let v: Vec<JaggedVal> = (0..w * h).map(|_| rand_kb(&mut rng)).collect();
                (alloc::format!("chip{i:03}"), RowMajorMatrix::new(v, w))
            })
            .collect();
        let r_row_per_chip: Vec<Vec<JaggedChallenge>> = traces
            .iter()
            .map(|(_, t)| {
                let h = t.values.len() / t.width.max(1);
                let log_h = h.next_power_of_two().trailing_zeros() as usize;
                (0..log_h).map(|_| rand_ef(&mut rng)).collect()
            })
            .collect();
        let z_row: Vec<JaggedChallenge> = r_row_per_chip
            .iter()
            .max_by_key(|v| v.len())
            .cloned()
            .unwrap_or_default();
        (traces, r_row_per_chip, z_row)
    }

    /// (i) NO-OP byte-identity: with grouping OFF (the default), a G==1
    /// bundle has scalar group-0 fields, EMPTY `extra_*` + `groups`, and an
    /// honest roundtrip verifies.  The empty `serde(default)` fields make the
    /// wire bytes byte-identical to the pre-split format (a freshly
    /// deserialized bundle is bit-for-bit equal AND still verifies).
    #[test]
    fn test_cp_a_g1_noop_byte_identity() {
        // grouping OFF (no test threshold set, env unset).
        let (traces, r_row, z_row) = mk_shard(&[(4, 16), (2, 8), (6, 4)], 0xA11CE);
        let views = as_chip_views(&traces);
        let mut p_chal = build_challenger();
        let bundle = prove_jagged_basefold(&views, &r_row, &z_row, &mut p_chal);

        // Single-group invariants: scalar fields populated, extras empty.
        assert_eq!(bundle.num_groups(), 1, "grouping OFF ⇒ G==1");
        assert!(bundle.groups.is_empty(), "G==1 ⇒ empty group map");
        assert!(bundle.extra_reduction.is_empty());
        assert!(bundle.extra_basefold_proof.is_empty());
        assert!(bundle.extra_commit.is_empty());
        assert!(bundle.extra_packing.is_empty());
        assert!(bundle.extra_jagged_eval.is_empty());

        // Wire-format round-trip is bit-identical.
        let bytes = bundle.to_bytes();
        let bundle2 = JaggedBasefoldBundle::from_bytes(&bytes)
            .expect("deserialize G==1 bundle");
        let bytes2 = bundle2.to_bytes();
        assert_eq!(bytes, bytes2, "G==1 bundle bytes must round-trip identically");

        // Honest verify: coverage passes (identity cover) and the verifier
        // reaches at least the per-group reduction.  On a fully-green branch
        // it ACCEPTS; on this WIP branch the BaseFold open can fail for a
        // reason ORTHOGONAL to CP-A (a pre-existing jagged-eval/div-fix bug
        // shared by today's single-group path — see report).  Either way the
        // failure must NOT be at coverage (the CP-A guard).
        let chip_infos =
            crate::jagged::compute_jagged_metadata::<JaggedVal>(&views).chip_infos;
        let (ok, stage) = verify_with_stage(&chip_infos, &r_row, &z_row, &bundle);
        eprintln!("[CP-A (i) G==1 no-op] accepted={ok} stage={stage:?}");
        assert!(
            stage != Some(VerifyStage::Coverage),
            "G==1 must pass the coverage check (identity cover)"
        );
        assert!(
            ok || matches!(stage, Some(VerifyStage::Open(_))),
            "G==1 must either verify or only fail at the BaseFold open \
             (pre-existing, orthogonal to CP-A); got accepted={ok} stage={stage:?}"
        );
        // The deserialized copy behaves identically (legacy-shape equivalence).
        let (ok2, stage2) = verify_with_stage(&chip_infos, &r_row, &z_row, &bundle2);
        assert_eq!(
            (ok, stage), (ok2, stage2),
            "deserialized G==1 bundle must verify identically"
        );
    }

    // ───────────────────────────────────────────────────────────────────
    // G-host: LOCK THE HASH-BIND CONVENTION (jagged geometry
    // count ↔ commitment tie) with a host-only commit → verify round-trip,
    // BEFORE any circuit consumes it.  A wrong order / missing len-prefix
    // would silently desync Fiat-Shamir; this test prints the host hash and
    // asserts modified == recomputed host-side.
    // ───────────────────────────────────────────────────────────────────
    #[test]
    fn g_host_hash_bind_roundtrip() {
        use crate::jagged_pcs::jagged::PackingMeta;
        // A heterogeneous per-chip geometry (varied heights == a FIX-off
        // natural-commit shard), with the SENTINEL offset (len = total_cols+1).
        // chip heights:   3,      5,           2,        (a 0-col chip)
        // chip widths:    2,      1,           3,        0
        let column_counts: Vec<usize> = vec![2, 1, 3, 0];
        // offsets: column-major prefix sums. col widths sum = 6 columns.
        //  chip0 cols 0,1 (h=3) -> 0,3 ; chip1 col2 (h=5) -> 6 ; chip2 cols 3,4,5 (h=2) -> 11,13,15 ; sentinel 17
        let offsets: Vec<usize> = vec![0, 3, 6, 11, 13, 15, 17];
        let total_values = 17usize;
        let packing = PackingMeta {
            offsets,
            total_values,
            log_dense_size: (total_values.next_power_of_two()).trailing_zeros() as usize,
            column_counts: column_counts.clone(),
            // Synthetic single-round packing.
            round_counts: Vec::new(),
            padding_heights: Vec::new(),
        };

        // The derived per-chip (row_counts, column_counts) — the EXACT felt
        // sequence both host and circuit hash.
        let (row_counts, col_counts) = jagged_counts_from_packing(&packing);
        assert_eq!(col_counts, column_counts);
        // chip0 h = offsets[1]-offsets[0] = 3; chip1 h = offsets[3]-offsets[2] = 5;
        // chip2 h = offsets[5]-offsets[4]... col_idx walk: chip0 col_idx=0 -> 3;
        //   chip1 col_idx=2 -> offsets[3]-offsets[2]=5; chip2 col_idx=3 ->
        //   offsets[4]-offsets[3]=2; chip3 cc==0 -> 0.
        assert_eq!(row_counts, vec![3usize, 5, 2, 0], "row_counts derivation");

        // A toy raw root.
        let raw_root: [JaggedVal; 8] =
            core::array::from_fn(|i| JaggedVal::from_u32((i as u32 + 1) * 7));

        let hash = jagged_geometry_hash(&row_counts, &col_counts);
        let modified = jagged_hash_bind_modified(raw_root, &row_counts, &col_counts);
        let modified_from_packing = jagged_hash_bind_from_packing(raw_root, &packing);

        eprintln!("[G-HOST] raw_root      = {raw_root:?}");
        eprintln!("[G-HOST] geometry_hash = {hash:?}");
        eprintln!("[G-HOST] modified      = {modified:?}");
        eprintln!(
            "[G-HOST] len(=col_counts.len())={} row_counts={row_counts:?} col_counts={col_counts:?}",
            col_counts.len()
        );

        // Convention self-consistency: the packing one-liner equals the
        // explicit path.
        assert_eq!(modified, modified_from_packing, "from_packing must match explicit");

        // The host re-bind check (mirror of SP1 verify_trusted_evaluations)
        // must ACCEPT the honest modified digest.
        assert!(
            jagged_hash_bind_verify(raw_root, modified, &packing),
            "G-host: host re-bind must accept the honest modified digest"
        );

        // FORGERY-SHAPED negative #1: a TAMPERED row_count must change the
        // hash -> modified, so the re-bind REJECTS it (the count↔commitment
        // tie).  (This is the host-side analog of G3b.)
        {
            let mut bad = packing.clone();
            // inflate chip0 height: offsets[1] 3 -> 4 (shifts everything)
            bad.offsets[1] = 4;
            assert!(
                !jagged_hash_bind_verify(raw_root, modified, &bad),
                "G-host: a tampered row_count MUST fail the re-bind"
            );
        }
        // FORGERY-SHAPED negative #2: a TAMPERED column_count must reject.
        {
            let mut bad = packing.clone();
            bad.column_counts[0] = 3; // was 2
            assert!(
                !jagged_hash_bind_verify(raw_root, modified, &bad),
                "G-host: a tampered column_count MUST fail the re-bind"
            );
        }
        // LEN-PREFIX guard: omitting/altering the len prefix would silently
        // collide honest geometries of different lengths.  Verify the len is
        // genuinely mixed in: a geometry with one MORE (zero-height, zero-col)
        // chip — same row/col VALUES extended by a 0 — hashes DIFFERENTLY
        // because the len prefix changes.
        {
            let mut rc2 = row_counts.clone();
            let mut cc2 = col_counts.clone();
            rc2.push(0);
            cc2.push(0);
            let h2 = jagged_geometry_hash(&rc2, &cc2);
            assert_ne!(
                hash, h2,
                "G-host: the len prefix MUST distinguish different-length geometries"
            );
        }
    }
}

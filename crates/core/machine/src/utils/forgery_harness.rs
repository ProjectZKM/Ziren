//! Height-forgery harness.
//!
//! Claim under test: per-chip heights are bound on the shard verify path
//! independently of `vk.hash`, so `VK = f(chip set)` suffices. A forged
//! height must be rejected by at least one of
//!   * the Fiat-Shamir prologue, which observes `chip_heights`;
//!   * the `full_geq(degree, ·)` padding mask in the LogUp-GKR
//!     reconstruction and in the zerocheck;
//!   * the jagged reduction.
//!
//! Proofs here commit every chip at its raw height.
//!
//! Where a height lives in a host shard proof (`JaggedShardProof<F, EF>`):
//!   * `chip_heights[name]`: observed into the transcript prologue.
//!   * `opened_values.chips[c].quotient[0]`: the `degree` bits, the
//!     big-endian (MSB at index 0) boolean decomposition of the real height
//!     `h`; it is the `full_geq` threshold in both the LogUp-GKR
//!     reconstruction and the zerocheck.
//!   * `opened_values.chips[c].log_degree`: `log2 h`.
//!
//! A height lie flips a `degree` bit: an over-claim sets a bit above the top
//! bit of `h`, an under-claim clears the top bit. Either changes the
//! `full_geq` mask, so the reconstructed `(num, den)` differ from the GKR
//! round walk.
//!
//! The rejecting check is read from the `JaggedShardVerifyError` inside
//! `MachineVerificationError::InvalidShardProof`:
//!   * `LogupGkr(_)`: reconstruction under the `full_geq` mask.
//!   * `Zerocheck(_)`: zerocheck identity (also masked by `full_geq`).
//!   * `JaggedPcs(_)`: jagged reduction.
//!
//! Run (CPU, release):
//!   CUDA_VISIBLE_DEVICES="" cargo test --release -p zkm-core-machine \
//!       --features ... forgery_harness -- --nocapture --test-threads=1 --ignored
//!
//! The tests are `#[ignore]`d: each proves a real core proof (seconds).

#![allow(clippy::type_complexity)]

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;

use zkm_core_executor::{Program, ZKMContext};
use zkm_pcs::{
    koala_bear_poseidon2::KoalaBearPoseidon2, CpuProver, MachineProof, MachineProver,
    MachineVerificationError, ShardProof, StarkGenericConfig, StarkMachine, ZKMCoreOpts,
};

use crate::io::ZKMStdin;
use crate::mips::MipsAir;
use crate::programs::tests::{
    fibonacci_program, sha3_chain_program, simple_memory_program, ssz_withdrawals_program,
};
use crate::utils::{prove_with_context, setup_logger};

type SC = KoalaBearPoseidon2;
type Val = KoalaBear;
type Challenge = p3_field::extension::QuinticTrinomialExtensionField<KoalaBear>;

/// The fibonacci guest reads one `u32` from the input stream, so an empty
/// stream fails its first syscall before any trace exists.
fn fib_stdin() -> ZKMStdin {
    let mut stdin = ZKMStdin::new();
    stdin.write(&10u32);
    stdin
}

/// Prove `program` on `stdin` at raw heights.  Returns the `MachineProof` and a
/// freshly-built machine+vk so the caller can verify (and re-verify
/// mutated copies) honestly.
fn prove_raw_heights(
    program: Program,
    stdin: ZKMStdin,
) -> (MachineProof<SC>, StarkMachine<SC, MipsAir<Val>>, zkm_pcs::StarkVerifyingKey<SC>) {
    let config = KoalaBearPoseidon2::new();
    let machine = MipsAir::machine(config);
    let prover = CpuProver::<_, _>::new(machine);

    let (pk, _) = prover.setup(&program);

    let (proof, _output, _cycles) = prove_with_context::<SC, CpuProver<_, _>>(
        &prover,
        &pk,
        program.clone(),
        &stdin,
        ZKMCoreOpts::default(),
        ZKMContext::default(),
    )
    .expect("prove_with_context");

    let config = KoalaBearPoseidon2::new();
    let machine = MipsAir::machine(config);
    let (_pk, vk) = machine.setup(&program);
    (proof, machine, vk)
}

/// Verify a (possibly mutated) `MachineProof` with a fresh challenger.
fn verify(
    machine: &StarkMachine<SC, MipsAir<Val>>,
    vk: &zkm_pcs::StarkVerifyingKey<SC>,
    proof: &MachineProof<SC>,
) -> Result<(), MachineVerificationError<SC>> {
    let mut challenger = machine.config().challenger();
    machine.verify(vk, proof, &mut challenger)
}

/// Map a verify result to a short tag naming WHICH substrate check
/// rejected (so the report can attribute the rejection).
fn reject_tag(res: &Result<(), MachineVerificationError<SC>>) -> String {
    match res {
        Ok(()) => "ACCEPTED".to_string(),
        Err(MachineVerificationError::InvalidShardProof(inner)) => {
            format!("REJECTED::InvalidShardProof[{inner}]")
        }
        Err(other) => format!("REJECTED::{other:?}"),
    }
}

/// Find the first shard whose `jagged_shard_proof` carries an
/// `opened_values` with at least one chip that has a non-trivial
/// `degree` (`quotient[0]`), and return its index + the chip index +
/// the chip name.  Prefers a height-VARIED chip (real height > 2) so the
/// forgery is a meaningful "taller/shorter" lie.
///
/// `opened_values.chips` is name-sorted by the shard prover, so the `ci`-th opening corresponds to
/// the `ci`-th NAME in the name-sorted chip set — NOT the `chip_ordering`
/// HashMap order.  We recover the name from the sorted `chip_ordering`
/// keys so the transcript (`chip_heights[name]`) and the degree
/// (`opened_values.chips[ci]`) refer to the SAME chip.
fn pick_forge_target(proof: &MachineProof<SC>) -> (usize, usize, String, usize) {
    let mut fallback: Option<(usize, usize, String, usize)> = None;
    for (si, sp) in proof.shard_proofs.iter().enumerate() {
        let jagged = sp.jagged_shard_proof.as_ref();
        let sorted_names: Vec<String> = jagged.chip_heights.keys().cloned().collect();
        for (ci, opening) in jagged.opened_values.chips.iter().enumerate() {
            if !opening.quotient.first().map(|q| !q.is_empty()).unwrap_or(false) {
                continue;
            }
            let name = sorted_names.get(ci).cloned().unwrap_or_else(|| format!("chip{ci}"));
            let log_h = opening.log_degree;
            if log_h >= 2 {
                return (si, ci, name, log_h);
            }
            fallback.get_or_insert((si, ci, name, log_h));
        }
    }
    fallback.expect("no shard with a non-empty degree (quotient[0]) found")
}

/// Decode the big-endian degree bits (`quotient[0]`) into the claimed
/// height (the index of the single set bit), or `None` if not a clean
/// power-of-two indicator.
fn degree_bits_to_height(degree: &[Challenge]) -> Option<usize> {
    let bit_len = degree.len();
    let mut set: Option<usize> = None;
    for (i, &b) in degree.iter().enumerate() {
        if b == Challenge::ONE {
            let shift = bit_len - 1 - i;
            if set.is_some() {
                return None;
            }
            set = Some(shift);
        } else if b != Challenge::ZERO {
            return None;
        }
    }
    set.map(|s| 1usize << s)
}

// CONTROL

/// Control: an honest proof verifies.  Proves the harness's
/// verify path is REAL (not trivially rejecting everything), so a later
/// rejection in the forgery tests is meaningful.
#[test]
#[ignore = "proves a real core proof (multi-second); run with --ignored"]
fn control_honest_verifies() {
    setup_logger();
    let (proof, machine, vk) = prove_raw_heights(fibonacci_program(), fib_stdin());
    let res = verify(&machine, &vk, &proof);
    tracing::info!("[control][fibonacci] honest verify = {}", reject_tag(&res));
    assert!(res.is_ok(), "honest proof must verify (control)");
}

// FORGERY

/// Core forgery driver.  Proves a proof, confirms it verifies
/// honestly, then for the chosen target chip applies the supplied
/// `mutate` to the proof copy and re-verifies.  Asserts the outcome
/// matches `expect_reject`.  Returns the reject tag so the caller can
/// log it.
///
/// The degree-masked last-layer reconstruction (the height anchor) is
/// unconditional.
///
/// `expect_reject`: the de-risk assertion — `true` means the forgery
/// MUST be rejected (heights redundantly bound on this path); `false`
/// documents a path where the forgery SURVIVES (records, not a soundness
/// claim).
fn run_forgery(
    label: &str,
    program: Program,
    stdin: ZKMStdin,
    expect_reject: bool,
    mutate: impl Fn(&mut ShardProof<SC>, usize, &str),
) -> String {
    let (proof, machine, vk) = prove_raw_heights(program, stdin);

    let honest = verify(&machine, &vk, &proof);
    assert!(
        honest.is_ok(),
        "[{label}] honest proof must verify before forging (got {})",
        reject_tag(&honest)
    );

    let (si, ci, name, log_h) = pick_forge_target(&proof);
    tracing::info!(
        "[forgery][{label}] target shard={si} chip_idx={ci} chip='{name}' \
         log_height={log_h}"
    );

    let mut forged = proof.clone();
    mutate(&mut forged.shard_proofs[si], ci, &name);

    let res = verify(&machine, &vk, &forged);
    let tag = reject_tag(&res);
    tracing::info!("[forgery][{label}] forged verify = {tag}");

    if expect_reject {
        assert!(
            res.is_err(),
            "[{label}] FORGED HEIGHT SURVIVED — heights are NOT \
             redundantly bound (BLOCKER)"
        );
    } else {
        assert!(res.is_ok(), "[{label}] expected forgery to SURVIVE but it was rejected: {tag}");
    }
    tag
}

/// OVER-CLAIM the degree bits: set a HIGHER bit (claim a taller chip
/// than the real trace).  Mutates `quotient[0]`, `log_degree`, and the
/// transcript `chip_heights` consistently so the lie is a coherent
/// "this chip is 2x taller" claim.
fn overclaim(sp: &mut ShardProof<SC>, ci: usize, name: &str) {
    let jagged = sp.jagged_shard_proof.as_mut();
    let opening = &mut jagged.opened_values.chips[ci];
    let degree = &mut opening.quotient[0];
    let bit_len = degree.len();
    let real_h = degree_bits_to_height(degree);
    let mut top: Option<usize> = None;
    for (i, b) in degree.iter().enumerate() {
        if *b == Challenge::ONE {
            top = Some(bit_len - 1 - i);
        }
    }
    let top_shift = top.unwrap_or(0);
    let new_shift = (top_shift + 1).min(bit_len - 1);
    let new_idx = bit_len - 1 - new_shift;
    let old_idx = bit_len - 1 - top_shift;
    degree[old_idx] = Challenge::ZERO;
    degree[new_idx] = Challenge::ONE;
    opening.log_degree = new_shift;
    jagged.chip_heights.insert(name.to_string(), 1usize << new_shift);
    tracing::info!(
        "[forgery] OVER-claim chip='{name}': real_height={:?} -> claimed 2^{new_shift}",
        real_h
    );
}

/// UNDER-CLAIM the degree bits: clear the real top set bit (claim a
/// SHORTER chip than the real trace).
fn underclaim(sp: &mut ShardProof<SC>, ci: usize, name: &str) {
    let jagged = sp.jagged_shard_proof.as_mut();
    let opening = &mut jagged.opened_values.chips[ci];
    let degree = &mut opening.quotient[0];
    let bit_len = degree.len();
    let real_h = degree_bits_to_height(degree);
    let mut top: Option<usize> = None;
    for (i, b) in degree.iter().enumerate() {
        if *b == Challenge::ONE {
            top = Some(bit_len - 1 - i);
        }
    }
    let top_shift = top.unwrap_or(1).max(1);
    let new_shift = top_shift - 1;
    let old_idx = bit_len - 1 - top_shift;
    let new_idx = bit_len - 1 - new_shift;
    degree[old_idx] = Challenge::ZERO;
    degree[new_idx] = Challenge::ONE;
    opening.log_degree = new_shift;
    jagged.chip_heights.insert(name.to_string(), 1usize << new_shift);
    tracing::info!(
        "[forgery] UNDER-claim chip='{name}': real_height={:?} -> claimed 2^{new_shift}",
        real_h
    );
}

/// Claim one row more than the row cube holds, with the degree bits, the
/// log degree and the transcript height in agreement.
fn overclaim_past_the_cube(sp: &mut ShardProof<SC>, ci: usize, name: &str) {
    let jagged = sp.jagged_shard_proof.as_mut();
    let opening = &mut jagged.opened_values.chips[ci];
    let degree = &mut opening.quotient[0];
    let bit_len = degree.len();
    let height = (1usize << (bit_len - 1)) + 1;
    for (i, bit) in degree.iter_mut().enumerate() {
        *bit = Challenge::from_bool((height >> (bit_len - 1 - i)) & 1 == 1);
    }
    opening.log_degree = bit_len;
    jagged.chip_heights.insert(name.to_string(), height);
}

/// Forge ONLY the `degree` bits (`quotient[0]`) — leave the transcript
/// `chip_heights` and `log_degree` HONEST.  This is the SHARPEST
/// de-risk probe: it isolates the NON-TRANSCRIPT height-binding
/// substrate (the `full_geq` padding mask over the degree bits → the
/// LogUp-GKR reconstruction identity), the exact substrate the
/// VK-identity change relies on once heights leave both `vk.hash` AND the
/// transcript framing.  If THIS rejects, the degree-bit binding is
/// enough on its own to bind the height.  Over-claim: set a higher bit (taller chip).
fn forge_degree_only_overclaim(sp: &mut ShardProof<SC>, ci: usize, name: &str) {
    let jagged = sp.jagged_shard_proof.as_mut();
    let opening = &mut jagged.opened_values.chips[ci];
    let degree = &mut opening.quotient[0];
    let bit_len = degree.len();
    let real_h = degree_bits_to_height(degree);
    let mut top: Option<usize> = None;
    for (i, b) in degree.iter().enumerate() {
        if *b == Challenge::ONE {
            top = Some(bit_len - 1 - i);
        }
    }
    let top_shift = top.unwrap_or(0);
    let new_shift = (top_shift + 1).min(bit_len - 1);
    let new_idx = bit_len - 1 - new_shift;
    let old_idx = bit_len - 1 - top_shift;
    degree[old_idx] = Challenge::ZERO;
    degree[new_idx] = Challenge::ONE;
    tracing::info!(
        "[forgery] DEGREE-only OVER-claim chip='{name}': real_height={:?} -> degree bits claim 2^{new_shift} \
         (transcript log_height LEFT HONEST)",
        real_h
    );
}

/// Degree-only UNDER-claim (clear the real top degree bit; transcript
/// left honest).
fn forge_degree_only_underclaim(sp: &mut ShardProof<SC>, ci: usize, name: &str) {
    let jagged = sp.jagged_shard_proof.as_mut();
    let opening = &mut jagged.opened_values.chips[ci];
    let degree = &mut opening.quotient[0];
    let bit_len = degree.len();
    let real_h = degree_bits_to_height(degree);
    let mut top: Option<usize> = None;
    for (i, b) in degree.iter().enumerate() {
        if *b == Challenge::ONE {
            top = Some(bit_len - 1 - i);
        }
    }
    let top_shift = top.unwrap_or(1).max(1);
    let new_shift = top_shift - 1;
    let old_idx = bit_len - 1 - top_shift;
    let new_idx = bit_len - 1 - new_shift;
    degree[old_idx] = Challenge::ZERO;
    degree[new_idx] = Challenge::ONE;
    tracing::info!(
        "[forgery] DEGREE-only UNDER-claim chip='{name}': real_height={:?} -> degree bits claim 2^{new_shift} \
         (transcript log_height LEFT HONEST)",
        real_h
    );
}

/// Forge ONLY the transcript `chip_heights` (leave the degree bits
/// honest) — isolates whether the transcript observe alone binds height.
fn forge_transcript_only(sp: &mut ShardProof<SC>, _ci: usize, name: &str) {
    let jagged = sp.jagged_shard_proof.as_mut();
    let cur = jagged.chip_heights.get(name).copied().unwrap_or(0);
    let lie = cur.wrapping_add(1);
    jagged.chip_heights.insert(name.to_string(), lie);
    tracing::info!("[forgery] TRANSCRIPT-only chip='{name}': height {cur} -> {lie}");
}

// fibonacci (height-varied MIPS)
//
// Two height-binding mechanisms exist on the host shard-verify path:
//   (A) TRANSCRIPT — `chip_heights` is observed into the Fiat-Shamir
//       prologue.  Any height lie that touches it re-derives different
//       challenges → grinding / consistency rejects.
//   (B) DEGREE-MASKED RECONSTRUCTION — the `degree` bits (`quotient[0]`)
//       feed `full_geq`, the per-chip padding mask; the last-layer
//       reconstruction re-derives num/den from the trace openings masked
//       by `full_geq(degree, ·)` and asserts equality with the GKR round
//       walk.  This binds heights with neither the hash nor the
//       transcript framing.  It always runs.

// (A) Transcript-coupled forgeries: rejected by the transcript bind alone.

#[test]
#[ignore = "proves a real core proof (multi-second); run with --ignored"]
fn forge_overclaim_fibonacci() {
    setup_logger();
    let tag = run_forgery("fibonacci/overclaim", fibonacci_program(), fib_stdin(), true, overclaim);
    tracing::info!("[forgery] fibonacci OVER-claim (transcript+degree) => {tag}");
}

#[test]
#[ignore = "proves a real core proof (multi-second); run with --ignored"]
fn forge_underclaim_fibonacci() {
    setup_logger();
    let tag =
        run_forgery("fibonacci/underclaim", fibonacci_program(), fib_stdin(), true, underclaim);
    tracing::info!("[forgery] fibonacci UNDER-claim (transcript+degree) => {tag}");
}

#[test]
#[ignore = "proves a real core proof (multi-second); run with --ignored"]
fn forge_transcript_only_fibonacci() {
    setup_logger();
    let tag = run_forgery(
        "fibonacci/transcript-only",
        fibonacci_program(),
        fib_stdin(),
        true,
        forge_transcript_only,
    );
    tracing::info!("[forgery] fibonacci TRANSCRIPT-only => {tag}");
}

/// A table taller than the row cube is rejected by the bound on its height,
/// before any other check reads the height.
#[test]
#[ignore = "proves a real core proof (multi-second); run with --ignored"]
fn forge_height_past_the_row_cube_fibonacci() {
    setup_logger();
    let tag = run_forgery(
        "fibonacci/past-the-cube",
        fibonacci_program(),
        fib_stdin(),
        true,
        overclaim_past_the_cube,
    );
    assert!(tag.contains("is above the row cube"), "rejected elsewhere: {tag}");
}

// (B) DEGREE-ONLY forgeries (transcript LEFT HONEST): the degree-bit
//     `full_geq` reconstruction alone binds height.

#[test]
#[ignore = "proves a real core proof (multi-second); run with --ignored"]
fn forge_degree_only_overclaim_fibonacci() {
    setup_logger();
    let tag = run_forgery(
        "fibonacci/degree-only-overclaim",
        fibonacci_program(),
        fib_stdin(),
        true,
        forge_degree_only_overclaim,
    );
    tracing::info!("[forgery] fibonacci DEGREE-only OVER-claim => {tag}");
}

#[test]
#[ignore = "proves a real core proof (multi-second); run with --ignored"]
fn forge_degree_only_underclaim_fibonacci() {
    setup_logger();
    let tag = run_forgery(
        "fibonacci/degree-only-underclaim",
        fibonacci_program(),
        fib_stdin(),
        true,
        forge_degree_only_underclaim,
    );
    tracing::info!("[forgery] fibonacci DEGREE-only UNDER-claim => {tag}");
}

// (B') The degree-masked reconstruction has no switch to disable it: the
//      degree-only over-claim is rejected on the default verify path.

#[test]
#[ignore = "proves a real core proof (multi-second); run with --ignored"]
fn degree_only_overclaim_fibonacci_rejected_unconditionally() {
    setup_logger();
    let tag = run_forgery(
        "fibonacci/degree-only-overclaim-unconditional",
        fibonacci_program(),
        fib_stdin(),
        true,
        forge_degree_only_overclaim,
    );
    tracing::info!(
        "[forgery] fibonacci DEGREE-only OVER-claim is rejected with \
         the reconstruction anchor unconditional => {tag}"
    );
}

#[test]
#[ignore = "proves a real core proof (multi-second); run with --ignored"]
fn degree_only_overclaim_fibonacci_rejected_on_default() {
    setup_logger();
    let (proof, machine, vk) = prove_raw_heights(fibonacci_program(), fib_stdin());
    let honest = verify(&machine, &vk, &proof);
    assert!(
        honest.is_ok(),
        "[degree-only-default] honest proof must verify (got {})",
        reject_tag(&honest)
    );
    let (si, ci, name, log_h) = pick_forge_target(&proof);
    tracing::info!(
        "[forgery][degree-only-default] target shard={si} chip_idx={ci} \
         chip='{name}' log_height={log_h}"
    );
    let mut forged = proof.clone();
    forge_degree_only_overclaim(&mut forged.shard_proofs[si], ci, &name);
    let res = verify(&machine, &vk, &forged);
    let tag = reject_tag(&res);
    tracing::info!("[forgery][degree-only-default] forged verify = {tag}");
    assert!(
        res.is_err(),
        "[degree-only-default] DEGREE-only forgery SURVIVED on the default \
         verify path (BLOCKER): {tag}"
    );
    tracing::warn!(
        "[forgery] fibonacci DEGREE-only OVER-claim REJECTED on the default \
         verify path => {tag}"
    );
}

// keccak / sha3 (precompile-uniform shards)

#[test]
#[ignore = "proves a real keccak core proof (multi-second); run with --ignored"]
fn forge_overclaim_keccak() {
    setup_logger();
    let tag =
        run_forgery("keccak/overclaim", sha3_chain_program(), ZKMStdin::new(), true, overclaim);
    tracing::info!("[forgery] keccak OVER-claim (transcript+degree) => {tag}");
}

#[test]
#[ignore = "proves a real keccak core proof (multi-second); run with --ignored"]
fn forge_underclaim_keccak() {
    setup_logger();
    let tag =
        run_forgery("keccak/underclaim", sha3_chain_program(), ZKMStdin::new(), true, underclaim);
    tracing::info!("[forgery] keccak UNDER-claim (transcript+degree) => {tag}");
}

#[test]
#[ignore = "proves a real keccak core proof (multi-second); run with --ignored"]
fn forge_degree_only_overclaim_keccak() {
    setup_logger();
    let tag = run_forgery(
        "keccak/degree-only-overclaim",
        sha3_chain_program(),
        ZKMStdin::new(),
        true,
        forge_degree_only_overclaim,
    );
    tracing::info!("[forgery] keccak DEGREE-only OVER-claim => {tag}");
}

// Jagged HASH-BIND forgeries.
//
// The hash-bind ties the per-chip (row_count, column_count) geometry to the
// FS-observed commitment via
//   main_commitment = compress([raw_root, hash(once(len) ++ rc ++ cc)]).
// The host shard verifier recomputes this from the bundle's RAW root + packing and asserts it equals
// `main_commitment`.  Tampering with ANY count (row or column) in the bundle's
// packing — WITHOUT being able to forge the corresponding raw root — must make
// the recompute diverge and REJECT (`JaggedPcs(... IncorrectTableSizes)`).
// This is the count↔commitment tie; a raw-root-only digest would let a
// prover witness any geometry.

/// COLUMN-count tamper: bump a chip's `column_count` in the bundle's
/// packing (leaving the committed raw root untouched).  The host re-check
/// recomputes hash(counts) over the tampered count → != observed
/// main_commitment → reject.
fn forge_count_tamper_column(sp: &mut ShardProof<SC>, _ci: usize, _name: &str) {
    use zkm_pcs::shard_level::shard_proof::EvaluationProof;
    let jagged = sp.jagged_shard_proof.as_mut();
    match &mut jagged.evaluation_proof {
        EvaluationProof::Bundle(bundle) => {
            let idx = bundle
                .packing
                .column_counts
                .iter()
                .position(|&c| c > 0)
                .expect("at least one chip with columns");
            let old = bundle.packing.column_counts[idx];
            bundle.packing.column_counts[idx] = old + 1;
            tracing::info!(
                "[forgery] COUNT-tamper column: packing.column_counts[{idx}] {old} -> {}",
                old + 1
            );
        }
        _other => panic!("expected EvaluationProof::Bundle for count-tamper"),
    }
}

/// ROW-count tamper: shift a packing OFFSET so one chip's derived
/// row_count (= offsets[i+1]-offsets[i]) changes.  Same effect: the hash over
/// the (now different) row_counts diverges from the observed main_commitment.
fn forge_count_tamper_row(sp: &mut ShardProof<SC>, _ci: usize, _name: &str) {
    use zkm_pcs::shard_level::shard_proof::EvaluationProof;
    let jagged = sp.jagged_shard_proof.as_mut();
    match &mut jagged.evaluation_proof {
        EvaluationProof::Bundle(bundle) => {
            let n = bundle.packing.offsets.len();
            assert!(n >= 3, "need >=3 offsets to tamper an interior boundary");
            let idx = 1.min(n - 2);
            let old = bundle.packing.offsets[idx];
            bundle.packing.offsets[idx] = old + 1;
            tracing::info!(
                "[forgery] COUNT-tamper row: packing.offsets[{idx}] {old} -> {} \
                 (changes a derived row_count)",
                old + 1
            );
        }
        _other => panic!("expected EvaluationProof::Bundle for row-count tamper"),
    }
}

#[test]
#[ignore = "proves a real core proof (multi-second); run with --ignored"]
fn forge_count_tamper_column_fibonacci() {
    setup_logger();
    let tag = run_forgery(
        "fibonacci/count-tamper-column",
        fibonacci_program(),
        fib_stdin(),
        true,
        forge_count_tamper_column,
    );
    tracing::info!("[forgery] fibonacci COLUMN-count tamper (hash-bind) => {tag}");
}

#[test]
#[ignore = "proves a real core proof (multi-second); run with --ignored"]
fn forge_count_tamper_row_fibonacci() {
    setup_logger();
    let tag = run_forgery(
        "fibonacci/count-tamper-row",
        fibonacci_program(),
        fib_stdin(),
        true,
        forge_count_tamper_row,
    );
    tracing::info!("[forgery] fibonacci ROW-count tamper (hash-bind) => {tag}");
}

/// Cut the zerocheck point below the four skip slots.  The verifier must
/// return an error for it, not index past the end.
fn forge_short_zerocheck_point(sp: &mut ShardProof<SC>, _ci: usize, _name: &str) {
    sp.jagged_shard_proof.as_mut().zerocheck_proof.point_and_eval.0.truncate(2);
}

/// Drop the zerocheck point entirely.
fn forge_empty_zerocheck_point(sp: &mut ShardProof<SC>, _ci: usize, _name: &str) {
    sp.jagged_shard_proof.as_mut().zerocheck_proof.point_and_eval.0.clear();
}

#[test]
#[ignore = "proves a real core proof (multi-second); run with --ignored"]
fn forge_short_zerocheck_point_fibonacci() {
    setup_logger();
    for (label, forge) in [
        ("fibonacci/short-zerocheck-point", forge_short_zerocheck_point as fn(&mut _, _, &_)),
        ("fibonacci/empty-zerocheck-point", forge_empty_zerocheck_point),
    ] {
        let tag = run_forgery(label, fibonacci_program(), fib_stdin(), true, forge);
        assert!(tag.contains("zerocheck point dim"), "[{label}] rejected elsewhere: {tag}");
    }
}

// ZERO-DEGREE MODEL SOUNDNESS.
//
// The missing-chip trace is a GENUINE HEIGHT-0 (0-row, full-width, zero)
// commit: a cluster chip a shard lacks is committed
// with `row_count = 0`, so its `degree` bits (`quotient[0]`) are ALL ZERO
// (=> `full_geq == 1` => identity fraction (0,1) => excluded from the
// LogUp-GKR sum).  These two forgeries PROVE that model is sound — that the
// live degree-mask substrate cannot be fooled into (a) treating a genuinely
// missing (height-0) chip as active, nor (b) treating a real present active
// chip as missing.  Both forge ONLY the `degree` bits (`quotient[0]`) and
// LEAVE the transcript (`log_degree`, `chip_heights`) HONEST, so the
// rejection can only come from the degree-masked substrate (the
// `LogupGkr`/`Zerocheck` reconstruction), NOT the Fiat-Shamir transcript
// bind.

/// Find the first shard+chip committed at genuine HEIGHT 0 — a missing
/// cluster chip: its `degree` bits (`quotient[0]`) are a NON-EMPTY
/// vector of ALL ZEROS (height 0 => every big-endian bit clear; a present
/// height-1 chip instead has the LSB set, and taller chips have a higher bit
/// set).  Returns `(shard_idx, chip_idx, chip_name)`.  Reports every height-0
/// chip it sees (the direct evidence that the commit injects missing cluster
/// chips at h=0/degree=0).  Panics if NONE exist (which would itself mean the
/// injection is not firing — a validation failure).
fn pick_height0_missing_target(proof: &MachineProof<SC>) -> (usize, usize, String) {
    let mut found: Vec<(usize, String)> = Vec::new();
    let mut first: Option<(usize, usize, String)> = None;
    for (si, sp) in proof.shard_proofs.iter().enumerate() {
        let jagged = sp.jagged_shard_proof.as_ref();
        let sorted_names: Vec<String> = jagged.chip_heights.keys().cloned().collect();
        for (ci, opening) in jagged.opened_values.chips.iter().enumerate() {
            let Some(degree) = opening.quotient.first() else { continue };
            if degree.is_empty() {
                continue;
            }
            if degree.iter().all(|b| *b == Challenge::ZERO) {
                let name = sorted_names.get(ci).cloned().unwrap_or_else(|| format!("chip{ci}"));
                found.push((si, name.clone()));
                first.get_or_insert((si, ci, name));
            }
        }
    }
    tracing::warn!(
        "[forgery] HEIGHT-0/degree-0 missing chips in proof: {} -> {:?}",
        found.len(),
        found,
    );
    first.expect(
        "no HEIGHT-0 missing chip in proof — missing-chip injection is NOT firing \
         (the whole zero-degree model is untested)",
    )
}

/// (a) A genuinely-MISSING chip committed at HEIGHT 0 (degree bits all zero)
/// forged to CLAIM ACTIVITY: set a single degree bit non-zero (claim height
/// 2^1).  Transcript LEFT HONEST.
fn forge_height0_claim_active(sp: &mut ShardProof<SC>, ci: usize, name: &str) {
    let jagged = sp.jagged_shard_proof.as_mut();
    let degree = &mut jagged.opened_values.chips[ci].quotient[0];
    let bit_len = degree.len();
    for b in degree.iter_mut() {
        *b = Challenge::ZERO;
    }
    let new_shift = 1usize.min(bit_len.saturating_sub(1));
    let new_idx = bit_len - 1 - new_shift;
    degree[new_idx] = Challenge::ONE;
    tracing::warn!(
        "[forgery] HEIGHT-0 chip='{name}': degree 0 (missing) -> claims 2^{new_shift} \
         ACTIVE (transcript log_height LEFT HONEST)"
    );
}

/// (b) A real PRESENT active chip forged to CLAIM IT IS MISSING: zero ALL its
/// degree bits (claim height 0).  Transcript LEFT HONEST.
fn forge_present_claim_missing(sp: &mut ShardProof<SC>, ci: usize, name: &str) {
    let jagged = sp.jagged_shard_proof.as_mut();
    let degree = &mut jagged.opened_values.chips[ci].quotient[0];
    let real_h = degree_bits_to_height(degree);
    for b in degree.iter_mut() {
        *b = Challenge::ZERO;
    }
    tracing::warn!(
        "[forgery] PRESENT chip='{name}': real_height={real_h:?} -> degree ALL-ZERO \
         (claims missing/height-0, transcript log_height LEFT HONEST)"
    );
}

/// Forgery (a): a genuinely-missing HEIGHT-0 chip forged to claim
/// activity MUST be rejected by the degree-masked substrate.
#[test]
#[ignore = "proves a real core proof (multi-second); run with --ignored"]
fn forge_height0_missing_claims_active_rejected() {
    setup_logger();
    let (proof, machine, vk) = prove_raw_heights(fibonacci_program(), fib_stdin());
    let honest = verify(&machine, &vk, &proof);
    assert!(
        honest.is_ok(),
        "[height0-claims-active] honest proof must verify before forging (got {})",
        reject_tag(&honest)
    );
    let (si, ci, name) = pick_height0_missing_target(&proof);
    tracing::info!(
        "[forgery][height0-claims-active] target shard={si} chip_idx={ci} chip='{name}'"
    );
    let mut forged = proof.clone();
    forge_height0_claim_active(&mut forged.shard_proofs[si], ci, &name);
    let res = verify(&machine, &vk, &forged);
    let tag = reject_tag(&res);
    tracing::info!("[forgery][height0-claims-active] forged verify = {tag}");
    assert!(
        res.is_err(),
        "[height0-claims-active] HEIGHT-0 missing chip forged to ACTIVE SURVIVED — the zero-degree \
         model is UNSOUND (SOUNDNESS HOLE / BLOCKER): {tag}"
    );
    tracing::warn!("[forgery] (a) HEIGHT-0 missing chip claiming activity REJECTED => {tag}");
}

/// Forgery (b): a real present active chip forged to claim it is
/// missing (degree=0) MUST be rejected.  Uses `run_forgery` (which picks a
/// present, height-varied chip).
#[test]
#[ignore = "proves a real core proof (multi-second); run with --ignored"]
fn forge_present_active_claims_missing_rejected() {
    setup_logger();
    let tag = run_forgery(
        "present-claims-missing",
        fibonacci_program(),
        fib_stdin(),
        true,
        forge_present_claim_missing,
    );
    tracing::warn!(
        "[forgery] (b) PRESENT active chip claiming missing (degree=0) REJECTED => {tag}"
    );
}

// PREPROCESSED BINDING PROBE.
//
// Ziren commits preprocessed traces INTO EACH SHARD alongside the main
// traces, and the setup-time `vk.commit` is only OBSERVED into the
// Fiat-Shamir transcript (`machine.rs`'s `vk.observe_into`) -- it is never
// compared, and `preprocessed_commit()` has no callers.  The alternative
// design commits preprocessed ONCE at setup, keeps `preprocessed_data` in
// the proving key, and has the shard verifier check openings against
// `vec![vk.preprocessed_commit, *main_commitment]` -- two rounds, so the
// preprocessed columns are bound to the VK by the opening argument.
//
// Question: does Ziren's transcript observation alone bind them?  Prove
// one program and verify the proof against a DIFFERENT program's vk.  If
// that is accepted, a prover can prove anything and claim it is some other
// program.  If it is rejected, something already binds -- and the tag says
// which check caught it.

#[test]
#[ignore = "proves two real core proofs (multi-second); run with --ignored"]
fn preprocessed_binding_cross_vk_probe() {
    use crate::programs::tests::{fibonacci_program, simple_program};
    setup_logger();

    let (proof_b, machine, vk_b) = prove_raw_heights(simple_program(), ZKMStdin::new());
    let honest = verify(&machine, &vk_b, &proof_b);
    assert!(honest.is_ok(), "anti-confound: program B must verify under its OWN vk");

    let config = KoalaBearPoseidon2::new();
    let machine_a = MipsAir::machine(config);
    let (_pk_a, vk_a) = machine_a.setup(&fibonacci_program());
    assert_ne!(
        format!("{:?}", vk_a.commit),
        format!("{:?}", vk_b.commit),
        "the two programs must have distinct preprocessed commitments for this probe to mean anything"
    );

    let cross = verify(&machine, &vk_a, &proof_b);
    let tag = reject_tag(&cross);
    tracing::info!("[PREP-BIND] program B's proof verified against program A's vk => {tag}");
    assert!(
        cross.is_err(),
        "SOUNDNESS: a proof of one program MUST NOT verify against another \
         program's verifying key; if it does, the preprocessed traces are \
         unbound and `vk.commit` is decorative"
    );
}

/// Control (memory chips): honest proofs of memory-heavy programs verify.
#[test]
#[ignore = "proves three real core proofs; run with --ignored"]
fn control_memory_programs_verify() {
    setup_logger();
    for (name, program) in [
        ("simple_memory", simple_memory_program()),
        ("ssz_withdrawals", ssz_withdrawals_program()),
        ("sha3_chain", sha3_chain_program()),
    ] {
        let (proof, machine, vk) = prove_raw_heights(program, ZKMStdin::new());
        let res = verify(&machine, &vk, &proof);
        tracing::info!(
            "[control][{name}] shards={} honest verify = {}",
            proof.shard_proofs.len(),
            reject_tag(&res)
        );
        assert!(res.is_ok(), "honest proof of {name} must verify");
    }
}

// GLOBAL LOOKUPS.
//
// The shards' cross-shard memory and syscall messages close on the global
// bus under a challenge derived from the hash chain over every shard's
// global round. A prover that deviates from the protocol is modelled by
// `prove_tampered`: it traces the shards as `prove_with_context` does, edits
// the raw traces before anything is committed, binds the edited global
// rounds into the chain, and may prove a shard under a challenge other than
// the chain's. Every deviation must be rejected by the honest verifier.

type RawTraces = std::collections::BTreeMap<String, p3_matrix::dense::RowMajorMatrix<Val>>;
type GlobalChallenge = zkm_pcs::logup_gkr::GlobalChallenge<Val, Challenge>;

/// Proves `program` on `stdin` under `opts` with `prover`, whose machine
/// decides which chips commit in the global round. `tamper` edits every
/// shard's raw chip traces, in shard order, before they are committed;
/// `challenge` picks, per shard, the challenge its global proof is made under
/// from the one the shards' global rounds fix.
fn prove_tampered(
    prover: &CpuProver<SC, MipsAir<Val>>,
    program: &Program,
    stdin: &ZKMStdin,
    opts: ZKMCoreOpts,
    tamper: impl FnOnce(&mut [RawTraces]),
    challenge: impl Fn(usize, &GlobalChallenge) -> GlobalChallenge,
) -> MachineProof<SC> {
    prove_tampered_grouped(prover, program, stdin, opts, tamper, challenge, 1)
}

/// [`prove_tampered`] with each global proof opening up to `rounds_per_proof`
/// consecutive global rounds; `challenge` is asked for the shard of the first
/// round a global proof opens.
fn prove_tampered_grouped(
    prover: &CpuProver<SC, MipsAir<Val>>,
    program: &Program,
    stdin: &ZKMStdin,
    opts: ZKMCoreOpts,
    tamper: impl FnOnce(&mut [RawTraces]),
    challenge: impl Fn(usize, &GlobalChallenge) -> GlobalChallenge,
    rounds_per_proof: usize,
) -> MachineProof<SC> {
    prove_tampered_statement(
        prover,
        program,
        stdin,
        opts,
        |raw, _| tamper(raw),
        challenge,
        rounds_per_proof,
    )
}

/// [`prove_tampered_grouped`] where `tamper` also edits the shards' records
/// once their traces exist, so it can change the public values a shard is
/// proven with: the statement of the shard, where the traces are its witness.
fn prove_tampered_statement(
    prover: &CpuProver<SC, MipsAir<Val>>,
    program: &Program,
    stdin: &ZKMStdin,
    opts: ZKMCoreOpts,
    tamper: impl FnOnce(&mut [RawTraces], &mut [zkm_core_executor::ExecutionRecord]),
    challenge: impl Fn(usize, &GlobalChallenge) -> GlobalChallenge,
    rounds_per_proof: usize,
) -> MachineProof<SC> {
    use zkm_pcs::air::MachineAir;

    let (pk, _) = prover.setup(program);
    let mut records =
        crate::utils::prove::shard_records::<SC, _>(prover, program, stdin, opts).unwrap();

    let mut raw: Vec<RawTraces> = records
        .iter()
        .map(|record| {
            prover
                .machine()
                .shard_chips(record)
                .map(|chip| {
                    let trace = chip
                        .generate_trace(record, &mut zkm_core_executor::ExecutionRecord::default())
                        .unwrap();
                    (chip.name(), trace)
                })
                .collect()
        })
        .collect();
    tamper(&mut raw, &mut records);

    let cube = zkm_pcs::shard_level::verifier::JaggedShardVerifier::production_default()
        .max_log_row_count as u32;
    let traces: Vec<zkm_pcs::Traces<Val>> = raw
        .into_iter()
        .map(|shard| zkm_pcs::Traces {
            named_traces: shard
                .into_iter()
                .map(|(name, trace)| (name, zkm_pcs::into_padded(trace, cube, None)))
                .collect(),
        })
        .collect();

    let mut challenger = prover.machine().config().challenger();
    zkm_pcs::MachineProvingKey::observe_into(&pk, &mut challenger);
    let (mut shard_proofs, tables): (Vec<_>, Vec<_>) = records
        .iter()
        .zip(traces)
        .map(|(record, traces)| {
            let data = prover.commit(record, traces, None);
            let tables = prover.global_round_tables(&data);
            (prover.open(&pk, data, &mut challenger.clone()).unwrap(), tables)
        })
        .unzip();
    prover.machine().assign_global_lanes(&mut shard_proofs);
    let rounds = shard_proofs
        .iter()
        .map(|proof| prover.machine().global_round_binding(proof))
        .collect::<Vec<_>>();
    let global = prover
        .machine()
        .global_challenge(
            &challenger,
            rounds.iter().map(Option::as_ref),
            shard_proofs.iter().map(|proof| proof.global_lane),
        )
        .expect("the core machine has global lookups");

    let (shards, committed): (Vec<_>, Vec<_>) = rounds
        .iter()
        .zip(tables)
        .enumerate()
        .filter_map(|(i, (round, tables))| Some((i, (round.as_ref()?, tables?))))
        .unzip();
    let global_proofs = prover
        .machine()
        .global_proof_groups(committed.iter().map(|(round, _)| *round), rounds_per_proof)
        .into_iter()
        .map(|group| {
            let global = challenge(shards[group.start], &global);
            prover.prove_global_rounds(&pk, &committed[group], &global, &challenger).unwrap()
        })
        .collect();
    MachineProof { shard_proofs, global_proofs }
}

/// The honest machine and the verifying key of `program`.
fn honest_vk(
    program: &Program,
) -> (StarkMachine<SC, MipsAir<Val>>, zkm_pcs::StarkVerifyingKey<SC>) {
    let machine = MipsAir::machine(KoalaBearPoseidon2::new());
    let (_pk, vk) = machine.setup(program);
    (machine, vk)
}

fn honest_prover() -> CpuProver<SC, MipsAir<Val>> {
    CpuProver::new(MipsAir::machine(KoalaBearPoseidon2::new()))
}

fn same_challenge(_: usize, global: &GlobalChallenge) -> GlobalChallenge {
    global.clone()
}

/// Options that cut `fibonacci_program` into several shards.
fn multi_shard_opts() -> ZKMCoreOpts {
    ZKMCoreOpts { shard_size: 1 << 10, ..ZKMCoreOpts::default() }
}

/// Proves `program` with `tamper` and `challenge`, checks the proof has at
/// least `min_shards` shards, and returns the honest verifier's result.
#[allow(clippy::too_many_arguments)]
fn verify_tampered(
    label: &str,
    program: Program,
    stdin: ZKMStdin,
    opts: ZKMCoreOpts,
    min_shards: usize,
    prover: CpuProver<SC, MipsAir<Val>>,
    tamper: impl FnOnce(&mut [RawTraces]),
    challenge: impl Fn(usize, &GlobalChallenge) -> GlobalChallenge,
) -> Result<(), MachineVerificationError<SC>> {
    let proof = prove_tampered(&prover, &program, &stdin, opts, tamper, challenge);
    assert!(
        proof.shard_proofs.len() >= min_shards,
        "[{label}] needs {min_shards} shards, the proof has {}",
        proof.shard_proofs.len()
    );
    let (machine, vk) = honest_vk(&program);
    let res = verify(&machine, &vk, &proof);
    tracing::info!(
        "[global][{label}] shards={} verify = {}",
        proof.shard_proofs.len(),
        reject_tag(&res)
    );
    res
}

/// The honest verifier's result on `fibonacci_program` cut into several
/// shards, each global proof opening up to `rounds_per_proof` consecutive
/// global rounds under the challenge `challenge` picks for the shard of its
/// first round. Checks that a global proof opens as many rounds as the shards
/// allow.
fn verify_grouped(
    label: &str,
    rounds_per_proof: usize,
    challenge: impl Fn(usize, &GlobalChallenge) -> GlobalChallenge,
) -> Result<(), MachineVerificationError<SC>> {
    let program = fibonacci_program();
    let proof = prove_tampered_grouped(
        &honest_prover(),
        &program,
        &fib_stdin(),
        multi_shard_opts(),
        |_| {},
        challenge,
        rounds_per_proof,
    );
    let committed =
        proof.shard_proofs.iter().filter(|p| p.jagged_shard_proof.global_round().is_some()).count();
    let most_rounds = proof
        .global_proofs
        .iter()
        .map(|p| p.jagged_shard_proof.preceding_rounds.len() + 1)
        .max()
        .unwrap_or(0);
    assert!(
        most_rounds >= 3 && most_rounds == rounds_per_proof.min(committed),
        "[{label}] {committed} global rounds, at most {most_rounds} in one global proof",
    );
    let (machine, vk) = honest_vk(&program);
    let res = verify(&machine, &vk, &proof);
    tracing::info!(
        "[global][{label}] shards={} global proofs={} verify = {}",
        proof.shard_proofs.len(),
        proof.global_proofs.len(),
        reject_tag(&res)
    );
    res
}

/// Global proofs that each open several shards' global rounds close the
/// global bus of an honest multi-shard execution.
#[test]
#[ignore = "proves a real multi-shard core proof; run with --ignored"]
fn grouped_global_proofs_verify() {
    setup_logger();
    for rounds_per_proof in [3, zkm_pcs::logup_gkr::MAX_GLOBAL_ROUNDS_PER_PROOF] {
        let res = verify_grouped("grouped", rounds_per_proof, same_challenge);
        assert!(
            res.is_ok(),
            "global proofs of {rounds_per_proof} rounds must verify: {}",
            reject_tag(&res)
        );
    }
}

/// Every global proof but the first opens its shards' global rounds under a
/// challenge derived from a digest other than the chain's `h_star`.
#[test]
#[ignore = "proves a real multi-shard core proof; run with --ignored"]
fn grouped_global_proof_under_another_h_star_rejected() {
    setup_logger();
    let machine = MipsAir::machine(KoalaBearPoseidon2::new());
    let res = verify_grouped("grouped, mixed h_star", 3, |i, global| {
        if i == 0 {
            return global.clone();
        }
        let mut h_star = global.h_star;
        h_star[0] += Val::ONE;
        let mut forged = zkm_pcs::logup_gkr::GlobalChallenge::grind(
            machine.config().challenger(),
            h_star,
            machine.global_beta_seed_dim(),
        );
        forged.pow_witness = global.pow_witness;
        forged
    });
    assert!(
        matches!(res, Err(MachineVerificationError::InvalidGlobalProof(_))),
        "a global proof of several rounds under another h_star must be rejected: {}",
        reject_tag(&res)
    );
}

/// Mutable views of every row of `trace`.
fn rows_mut(trace: &mut p3_matrix::dense::RowMajorMatrix<Val>) -> impl Iterator<Item = &mut [Val]> {
    let width = trace.width;
    trace.values.chunks_mut(width)
}

/// Control: the tampering prover with no tampering proves a multi-shard
/// program that verifies, so a rejection below is the deviation's.
#[test]
#[ignore = "proves a real multi-shard core proof; run with --ignored"]
fn control_untampered_multi_shard_verifies() {
    setup_logger();
    let res = verify_tampered(
        "untampered",
        fibonacci_program(),
        fib_stdin(),
        multi_shard_opts(),
        2,
        honest_prover(),
        |_| {},
        same_challenge,
    );
    assert!(res.is_ok(), "the untampered proof must verify: {}", reject_tag(&res));
}

/// The first shard withholds the program image from the global bus: its
/// MemoryProgram multiplicities are zeroed.
#[test]
#[ignore = "proves a real core proof; run with --ignored"]
fn memory_program_withheld_in_first_shard_rejected() {
    setup_logger();
    let res = verify_tampered(
        "image withheld",
        fibonacci_program(),
        fib_stdin(),
        ZKMCoreOpts::default(),
        1,
        honest_prover(),
        |shards| {
            for row in rows_mut(shards[0].get_mut("MemoryProgram").unwrap()) {
                let cols: &mut crate::memory::MemoryProgramMultCols<Val> =
                    core::borrow::BorrowMut::borrow_mut(row);
                cols.multiplicity = Val::ZERO;
            }
        },
        same_challenge,
    );
    assert!(res.is_err(), "a first shard that withholds the image must be rejected");
}

/// A later shard sends the program image a second time: its MemoryProgram
/// multiplicities are set on every image row.
#[test]
#[ignore = "proves a real multi-shard core proof; run with --ignored"]
fn memory_program_resent_in_later_shard_rejected() {
    setup_logger();
    let program = fibonacci_program();
    let image_len = program.image.len();
    let res = verify_tampered(
        "image resent",
        program,
        fib_stdin(),
        multi_shard_opts(),
        2,
        honest_prover(),
        |shards| {
            for row in rows_mut(shards[1].get_mut("MemoryProgram").unwrap()).take(image_len) {
                let cols: &mut crate::memory::MemoryProgramMultCols<Val> =
                    core::borrow::BorrowMut::borrow_mut(row);
                cols.multiplicity = Val::ONE;
            }
        },
        same_challenge,
    );
    assert!(res.is_err(), "a later shard that sends the image again must be rejected");
}

/// The first shard's proof drops the MemoryProgram table to height 0.
#[test]
#[ignore = "proves a real core proof; run with --ignored"]
fn memory_program_height_zero_in_first_shard_rejected() {
    setup_logger();
    let (mut proof, machine, vk) = prove_raw_heights(fibonacci_program(), fib_stdin());
    proof.shard_proofs[0].jagged_shard_proof.chip_heights.insert("MemoryProgram".to_string(), 0);
    let res = verify(&machine, &vk, &proof);
    tracing::info!("[global][image height 0] verify = {}", reject_tag(&res));
    assert!(res.is_err(), "a first shard without the image table must be rejected");
}

/// A word of the program image differs from the verifying key's: the proof
/// is made with the altered program's proving key, whose commitment is
/// replaced by the honest one so the transcript matches the honest key.
#[test]
#[ignore = "proves a real core proof; run with --ignored"]
fn altered_image_rejected_by_the_honest_vk() {
    setup_logger();
    let program = fibonacci_program();
    let mut altered = program.clone();
    let (&addr, &word) = altered.image.iter().next_back().unwrap();
    altered.image.insert(addr, word ^ 1);

    let (machine, vk) = honest_vk(&program);
    let prover = honest_prover();
    let (mut pk, _) = prover.setup(&altered);
    pk.commit = vk.commit.clone();
    let (proof, _, _) = prove_with_context::<SC, CpuProver<_, _>>(
        &prover,
        &pk,
        altered,
        &fib_stdin(),
        ZKMCoreOpts::default(),
        ZKMContext::default(),
    )
    .unwrap();
    let res = verify(&machine, &vk, &proof);
    tracing::info!("[global][altered image] verify = {}", reject_tag(&res));
    assert!(res.is_err(), "a proof over an altered image must be rejected by the honest key");
}

/// One memory word's final value in a shard's local-memory table is off by
/// one on the global bus.
#[test]
#[ignore = "proves a real multi-shard core proof; run with --ignored"]
fn global_memory_value_off_by_one_rejected() {
    setup_logger();
    let res = verify_tampered(
        "value off by one",
        fibonacci_program(),
        fib_stdin(),
        multi_shard_opts(),
        2,
        honest_prover(),
        |shards| {
            let row = rows_mut(shards[0].get_mut("MemoryLocal").unwrap()).next().unwrap();
            let entry: &mut crate::memory::SingleMemoryLocal<Val> =
                core::borrow::BorrowMut::borrow_mut(
                    &mut row[..core::mem::size_of::<crate::memory::SingleMemoryLocal<u8>>()],
                );
            entry.final_value[0] += Val::ONE;
        },
        same_challenge,
    );
    assert!(res.is_err(), "a global memory value off by one must be rejected");
}

/// Two shards exchange their first local-memory rows. The global bus still
/// balances, since the multiset of global messages is unchanged; each
/// shard's local bus does not.
#[test]
#[ignore = "proves a real multi-shard core proof; run with --ignored"]
fn global_memory_rows_swapped_across_shards_rejected() {
    setup_logger();
    let res = verify_tampered(
        "rows swapped",
        fibonacci_program(),
        fib_stdin(),
        multi_shard_opts(),
        2,
        honest_prover(),
        |shards| {
            let (first, rest) = shards.split_at_mut(1);
            let a = first[0].get_mut("MemoryLocal").unwrap();
            let b = rest[0].get_mut("MemoryLocal").unwrap();
            let width = a.width;
            a.values[..width].swap_with_slice(&mut b.values[..width]);
        },
        same_challenge,
    );
    assert!(res.is_err(), "local-memory rows swapped across shards must be rejected");
}

/// The prover commits MemoryLocal, whose messages are on the global bus, in
/// the main round, after the global challenge is fixed.
#[test]
#[ignore = "proves a real multi-shard core proof; run with --ignored"]
fn global_chip_committed_in_the_main_round_rejected() {
    setup_logger();
    let machine = MipsAir::machine(KoalaBearPoseidon2::new());
    let mut round = machine.global_round().cloned().unwrap();
    assert!(round.remove("MemoryLocal"));
    let prover = CpuProver::new(machine.with_global_round(Some(round)));
    let res = verify_tampered(
        "global chip in main round",
        fibonacci_program(),
        fib_stdin(),
        multi_shard_opts(),
        2,
        prover,
        |_| {},
        same_challenge,
    );
    assert!(res.is_err(), "a global chip committed in the main round must be rejected");
}

/// The last shard is proven under a challenge derived from a digest other
/// than the chain's `h_star`.
#[test]
#[ignore = "proves a real multi-shard core proof; run with --ignored"]
fn shard_proven_under_another_h_star_rejected() {
    setup_logger();
    let program = fibonacci_program();
    let shards = shard_records_count(&program, &fib_stdin(), multi_shard_opts());
    let machine = MipsAir::machine(KoalaBearPoseidon2::new());
    let res = verify_tampered(
        "mixed h_star",
        program,
        fib_stdin(),
        multi_shard_opts(),
        2,
        honest_prover(),
        |_| {},
        |i, global| {
            if i + 1 < shards {
                return global.clone();
            }
            let mut h_star = global.h_star;
            h_star[0] += Val::ONE;
            let mut forged = zkm_pcs::logup_gkr::GlobalChallenge::grind(
                machine.config().challenger(),
                h_star,
                machine.global_beta_seed_dim(),
            );
            forged.pow_witness = global.pow_witness;
            forged
        },
    );
    assert!(res.is_err(), "a shard proven under another h_star must be rejected");
}

/// The number of shards `program` is cut into on `stdin` under `opts`.
fn shard_records_count(program: &Program, stdin: &ZKMStdin, opts: ZKMCoreOpts) -> usize {
    let prover = honest_prover();
    crate::utils::prove::shard_records::<SC, _>(&prover, program, stdin, opts).unwrap().len()
}

// Memory tables
//
// MemoryGlobalInit and MemoryGlobalFinalize list their addresses in strictly
// increasing order, as pairs of 16-bit limbs chained over a control bus. A
// prover that wants an address in a table twice, or a value that is not a
// word of bytes, is modelled by rows it appends after the last honest row of
// each table: one Initialize row and one Finalize row of the same address
// and value, which close on the global bus by themselves. Each row is
// completed the way the constraints ask: the chain columns from the row
// before it, the Byte table multiplicities of the range lookups the table
// holds, and the public values of the last address and of the row count. A
// pair with canonical limbs therefore verifies, and a forged pair breaks the
// rules its test names and no other.

use core::borrow::{Borrow, BorrowMut};

use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use zkm_core_executor::{events::MemoryInitializeFinalizeEvent, ByteOpcode, ExecutionRecord};

use crate::memory::{MemoryChipType, MemoryGlobalChip, MemoryInitCols, TOP_ADDR_HI};

const MEMORY_TABLES: [(&str, MemoryChipType); 2] = [
    ("MemoryGlobalInit", MemoryChipType::Initialize),
    ("MemoryGlobalFinalize", MemoryChipType::Finalize),
];

/// The field's order.
const P: u32 = 0x7F00_0001;

/// Options that put the memory events of `fibonacci_program` in two shards
/// of their own: the Initialize rows and the first Finalize rows in one, the
/// other Finalize rows in the next, which has no Initialize row.
fn multi_memory_shard_opts() -> ZKMCoreOpts {
    let mut opts = ZKMCoreOpts::default();
    opts.split_opts.memory = 1 << 13;
    opts.split_opts.combine_memory_threshold = 0;
    opts
}

fn memory_cols(row: &[Val]) -> &MemoryInitCols<Val> {
    row.borrow()
}

/// The limbs of the integer `addr`, which need not be an address.
fn limbs_of(addr: u32) -> [Val; 2] {
    [Val::from_u32(addr & 0xffff), Val::from_u32(addr >> 16)]
}

/// The rows of a memory table before its padding.
fn real_rows(trace: &RowMajorMatrix<Val>) -> usize {
    trace.values.chunks(trace.width).take_while(|row| memory_cols(row).is_real == Val::ONE).count()
}

/// The shards with rows in the table `name`, in order.
fn shards_with(shards: &[RawTraces], name: &str) -> Vec<usize> {
    (0..shards.len()).filter(|&i| shards[i].contains_key(name)).collect()
}

/// The last address of both memory tables, which end at the same one: the
/// highest address the program touches is outside its image.
fn last_memory_addr(shards: &[RawTraces]) -> u32 {
    let last = MEMORY_TABLES.map(|(name, _)| {
        let trace = &shards[*shards_with(shards, name).last().unwrap()][name];
        let row = real_rows(trace) - 1;
        let cols = memory_cols(&trace.values[row * trace.width..(row + 1) * trace.width]);
        cols.addr[0].as_canonical_u32() + (cols.addr[1].as_canonical_u32() << 16)
    });
    assert_eq!(last[0], last[1], "the two memory tables end at different addresses");
    last[0]
}

/// Adds `count` to the Byte table multiplicities of the range lookups the
/// memory chip of `kind` sends on `row`, for the tuples the table holds.
fn count_range_lookups(
    byte: &mut RowMajorMatrix<Val>,
    kind: MemoryChipType,
    row: &[Val],
    count: Val,
) {
    let chip = zkm_pcs::Chip::<Val, _>::new(MemoryGlobalChip::new(kind));
    for lookup in chip.sends().iter().filter(|lookup| lookup.kind == zkm_pcs::LookupKind::Byte) {
        let multiplicity = lookup.multiplicity.apply::<Val, Val>(&[], row);
        let v: Vec<u32> = lookup
            .values
            .iter()
            .map(|value| value.apply::<Val, Val>(&[], row).as_canonical_u32())
            .collect();
        let table_row = if v[0] == ByteOpcode::U8Range as u32 {
            (v[1] == 0 && v[2] == 0 && v[3] < 256 && v[4] < 256).then_some((v[3] << 8) + v[4])
        } else {
            assert_eq!(v[0], ByteOpcode::U16Range as u32, "a memory row sends range lookups");
            (v[1] < 1 << 16 && v[2..] == [0, 0, 0]).then_some(v[1])
        };
        if let Some(table_row) = table_row {
            let cols: &mut crate::bytes::columns::ByteMultCols<Val> =
                byte.row_mut(table_row as usize).borrow_mut();
            cols.multiplicities[v[0] as usize] += multiplicity * count;
        }
    }
}

/// The 32 public value elements whose two sums are `limbs`: the bits of a
/// limb below `2^16`, and otherwise the limb whole in the lowest element of
/// its half.
fn limb_elements(limbs: [Val; 2]) -> [u32; 32] {
    let mut elements = [0; 32];
    for (half, limb) in elements.chunks_mut(16).zip(limbs) {
        let limb = limb.as_canonical_u32();
        if limb < 1 << 16 {
            for (i, bit) in half.iter_mut().enumerate() {
                *bit = (limb >> i) & 1;
            }
        } else {
            half[0] = limb;
        }
    }
    elements
}

/// Appends a row of address `addr` and value `value` to the memory table
/// `name`, after the last row of the last shard with rows of it. The row is
/// completed as a compared row of the chain, then `forge` edits it. The Byte
/// table counts the range lookups it holds, and the public values name the
/// row's address as the table's last and count the row.
fn append_memory_row(
    shards: &mut [RawTraces],
    records: &mut [ExecutionRecord],
    (name, kind): (&str, MemoryChipType),
    addr: [Val; 2],
    value: [Val; 4],
    forge: &impl Fn(&mut MemoryInitCols<Val>),
) {
    let shard = *shards_with(shards, name).last().unwrap();
    let trace = shards[shard].get_mut(name).unwrap();
    let width = trace.width;
    let rows = real_rows(trace);
    if rows * width == trace.values.len() {
        trace.values.resize((rows + 32) * width, Val::ZERO);
    }
    let last = *memory_cols(&trace.values[(rows - 1) * width..rows * width]);
    let row = &mut trace.values[rows * width..(rows + 1) * width];
    let cols: &mut MemoryInitCols<Val> = row.borrow_mut();
    cols.shard = Val::ZERO;
    cols.timestamp = Val::from_bool(kind == MemoryChipType::Initialize);
    cols.addr = addr;
    cols.top_inv = (Val::from_u32(TOP_ADDR_HI) - addr[1]).try_inverse().unwrap_or(Val::ZERO);
    cols.index = last.index + Val::ONE;
    cols.prev_addr = last.addr;
    cols.prev_valid = last.is_comp;
    cols.hi_differs = Val::from_bool(addr[1] != last.addr[1]);
    cols.gap =
        if addr[1] != last.addr[1] { addr[1] - last.addr[1] } else { addr[0] - last.addr[0] };
    cols.value = value;
    cols.is_real = Val::ONE;
    cols.is_comp = Val::ONE;
    cols.zero_inv = (cols.index + last.addr[0] + last.addr[1]).inverse();
    forge(cols);
    let last_addr = limb_elements(cols.addr);
    let row = row.to_vec();
    count_range_lookups(shards[shard].get_mut("Byte").unwrap(), kind, &row, Val::ONE);

    let counted = MemoryInitializeFinalizeEvent { addr: 0, value: 0, shard: 0, timestamp: 0 };
    for (i, record) in records.iter_mut().enumerate().skip(shard) {
        let pv = &mut record.public_values;
        let (events, previous, last) = match kind {
            MemoryChipType::Initialize => (
                &mut record.global_memory_initialize_events,
                &mut pv.previous_init_addr_bits,
                &mut pv.last_init_addr_bits,
            ),
            MemoryChipType::Finalize => (
                &mut record.global_memory_finalize_events,
                &mut pv.previous_finalize_addr_bits,
                &mut pv.last_finalize_addr_bits,
            ),
        };
        *last = last_addr;
        if i == shard {
            events.push(counted);
        } else {
            *previous = last_addr;
        }
    }
}

/// [`append_memory_row`] to both memory tables.
fn append_memory_pair(
    shards: &mut [RawTraces],
    records: &mut [ExecutionRecord],
    addr: [Val; 2],
    value: [Val; 4],
    forge: impl Fn(&mut MemoryInitCols<Val>),
) {
    for table in MEMORY_TABLES {
        append_memory_row(shards, records, table, addr, value, &forge);
    }
}

fn bytes(value: [u32; 4]) -> [Val; 4] {
    value.map(Val::from_u32)
}

/// The honest verifier's result on `fibonacci_program`, its memory events in
/// two memory shards, proven after `tamper` edited the shards' traces and
/// records.
fn verify_tampered_memory(
    label: &str,
    tamper: impl FnOnce(&mut [RawTraces], &mut [ExecutionRecord]),
) -> Result<(), MachineVerificationError<SC>> {
    let program = fibonacci_program();
    let proof = prove_tampered_statement(
        &honest_prover(),
        &program,
        &fib_stdin(),
        multi_memory_shard_opts(),
        tamper,
        same_challenge,
        1,
    );
    let (machine, vk) = honest_vk(&program);
    let res = verify(&machine, &vk, &proof);
    tracing::info!(
        "[memory][{label}] shards={} verify = {}",
        proof.shard_proofs.len(),
        reject_tag(&res)
    );
    res
}

/// What the verifier's rejection of a row that breaks a constraint names, and
/// of a shard whose lookups do not balance.
const BY_CONSTRAINTS: &str = "zerocheck";
const BY_LOOKUPS: &str = "LogUp-GKR";

/// Asserts that the verifier rejected, at the check `check`.
fn assert_rejected(res: &Result<(), MachineVerificationError<SC>>, check: &str, case: &str) {
    let tag = reject_tag(res);
    assert!(res.is_err() && tag.contains(check), "{case}: expected {check}, got {tag}");
}

/// Control: an appended pair with canonical limbs verifies. The program's
/// last address is one word below the largest address, `0x7F000000`, whose
/// high limb is the top one and whose low limb is zero, so that address is
/// the one a table can still take. The Initialize row is appended in a shard
/// before the last, whose public values pass its address on unchanged.
#[test]
#[ignore = "proves a real multi-shard core proof; run with --ignored"]
fn global_memory_appended_canonical_row_verifies() {
    setup_logger();
    let res = verify_tampered_memory("canonical row", |shards, records| {
        let [init, finalize] = MEMORY_TABLES.map(|(name, _)| shards_with(shards, name));
        assert!(finalize.len() >= 2, "the Finalize rows are in one shard");
        assert!(init.last() < finalize.last(), "every memory shard has Initialize rows");
        assert_eq!(last_memory_addr(shards) + 4, TOP_ADDR_HI << 16);
        append_memory_pair(
            shards,
            records,
            limbs_of(TOP_ADDR_HI << 16),
            bytes([1, 2, 3, 255]),
            |_| {},
        );
    });
    assert!(res.is_ok(), "an appended canonical row must verify: {}", reject_tag(&res));
}

/// A second limb pair for an address a table already holds. The integers the
/// forged limbs spell are above every address, so the rows compare as
/// increasing, and the field element they send to the global bus is the
/// address of an honest row:
///
/// * the address plus the field's order: the high limb is the top one and
///   the low limb is not zero;
/// * the address plus twice the order: the high limb is above the top one;
/// * a high limb of minus one, which names the last honest address: the limb
///   is not a 16-bit integer, and neither is its distance to the limb before.
#[test]
#[ignore = "proves real multi-shard core proofs; run with --ignored"]
fn global_memory_aliased_address_limbs_rejected() {
    setup_logger();
    for case in 0..3 {
        let res = verify_tampered_memory("aliased limbs", |shards, records| {
            let init = &shards[shards_with(shards, "MemoryGlobalInit")[0]]["MemoryGlobalInit"];
            let second = memory_cols(&init.values[init.width..2 * init.width]);
            let held =
                second.addr[0].as_canonical_u32() + (second.addr[1].as_canonical_u32() << 16);
            assert!(held > 0 && held < 1 << 16, "the second address is a register's");
            let last = last_memory_addr(shards);
            let alias = match case {
                0 => limbs_of(held + P),
                1 => limbs_of(held + 2 * P),
                _ => [Val::from_u32((last & 0xffff) - 1), -Val::ONE],
            };
            let named = alias[0] + alias[1] * Val::from_u32(1 << 16);
            assert_eq!(named, Val::from_u32(if case < 2 { held } else { last }));
            append_memory_pair(shards, records, alias, bytes([0; 4]), |_| {});
        });
        let check = if case == 0 { BY_CONSTRAINTS } else { BY_LOOKUPS };
        assert_rejected(&res, check, &format!("limb pair {case} of a held address"));
    }
}

/// An appended pair that does not increase the address: the last address
/// again, the address one word below it, and the address one high limb below
/// it with `hi_differs` set. The gap is zero or wraps below zero, so the gap
/// less one is in no row of the range table.
#[test]
#[ignore = "proves real multi-shard core proofs; run with --ignored"]
fn global_memory_address_not_increasing_rejected() {
    setup_logger();
    for case in 0..3 {
        let res = verify_tampered_memory("not increasing", |shards, records| {
            let last = last_memory_addr(shards);
            assert!(last & 0xffff >= 4 && last >> 16 >= 1);
            let addr = [last, last - 4, last - (1 << 16)][case];
            append_memory_pair(shards, records, limbs_of(addr), bytes([0; 4]), |cols| {
                assert_eq!(cols.hi_differs, Val::from_bool(case == 2));
            });
        });
        assert_rejected(&res, BY_LOOKUPS, &format!("address {case} that does not increase"));
    }
}

/// An appended pair at the largest address whose first value limb is 256.
#[test]
#[ignore = "proves a real multi-shard core proof; run with --ignored"]
fn global_memory_value_limb_past_a_byte_rejected() {
    setup_logger();
    let res = verify_tampered_memory("value limb 256", |shards, records| {
        let top = limbs_of(TOP_ADDR_HI << 16);
        append_memory_pair(shards, records, top, bytes([256, 0, 0, 0]), |_| {});
    });
    assert_rejected(&res, BY_LOOKUPS, "a value limb past a byte");
}

/// An appended pair that does not compare, with a value that is not zero: a
/// row may skip the comparison only at index zero after a zero address, with
/// address and value zero. In the first case the pair repeats the last
/// address and a canonical compared pair at the largest address follows it,
/// so the public values still receive `is_comp = 1` from the last row and the
/// row's constraints alone reject; in the second the forged pair is at the
/// largest address and is the last row, and the control bus does not balance
/// either.
#[test]
#[ignore = "proves real multi-shard core proofs; run with --ignored"]
fn global_memory_row_skipping_the_comparison_rejected() {
    setup_logger();
    for followed in [true, false] {
        let res = verify_tampered_memory("comparison skipped", |shards, records| {
            let top = limbs_of(TOP_ADDR_HI << 16);
            let addr = if followed { limbs_of(last_memory_addr(shards)) } else { top };
            append_memory_pair(shards, records, addr, bytes([9, 0, 0, 0]), |cols| {
                cols.is_comp = Val::ZERO;
                cols.zero_inv = Val::ZERO;
            });
            if followed {
                append_memory_pair(shards, records, top, bytes([0; 4]), |cols| {
                    assert_eq!(cols.prev_valid, Val::ZERO);
                });
            }
        });
        let check = if followed { BY_CONSTRAINTS } else { BY_LOOKUPS };
        assert_rejected(&res, check, &format!("comparison skipped, followed {followed}"));
    }
}

/// The first Finalize row of the second memory shard takes the address one
/// word below the one the public values send it as its previous address,
/// with the rest of the row and the Byte table following. With the shard's
/// public values edited to send that address, the shard verifies: what
/// rejects that statement is the equality of a shard's previous address with
/// the last address of the shard before it, which the verifier of an
/// execution checks over the shards. With the honest public values the
/// control bus of the shard does not balance.
#[test]
#[ignore = "proves real multi-shard core proofs; run with --ignored"]
fn global_memory_chain_broken_across_shards_rejected() {
    setup_logger();
    let (name, kind) = MEMORY_TABLES[1];
    for statement_follows in [true, false] {
        let res = verify_tampered_memory("chain broken", |shards, records| {
            let shard = shards_with(shards, name)[1];
            let trace = shards[shard].get_mut(name).unwrap();
            let width = trace.width;
            let honest = trace.values[..width].to_vec();
            let cols: &mut MemoryInitCols<Val> = trace.values[..width].borrow_mut();
            assert!(cols.is_comp == Val::ONE && cols.index == Val::ZERO);
            assert!(cols.hi_differs == Val::ZERO && cols.prev_addr[0].as_canonical_u32() >= 4);
            cols.prev_addr[0] -= Val::from_u32(4);
            cols.gap += Val::from_u32(4);
            cols.zero_inv = (cols.prev_addr[0] + cols.prev_addr[1]).inverse();
            let previous = limb_elements(cols.prev_addr);
            let forged = trace.values[..width].to_vec();
            let byte = shards[shard].get_mut("Byte").unwrap();
            count_range_lookups(byte, kind, &honest, -Val::ONE);
            count_range_lookups(byte, kind, &forged, Val::ONE);
            if statement_follows {
                records[shard].public_values.previous_finalize_addr_bits = previous;
            }
        });
        if statement_follows {
            assert!(res.is_ok(), "the shards of the edited statement: {}", reject_tag(&res));
        } else {
            assert_rejected(&res, BY_LOOKUPS, "a chain broken under the honest statement");
        }
    }
}

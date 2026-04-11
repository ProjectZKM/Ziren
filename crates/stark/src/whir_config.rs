//! WHIR polynomial commitment scheme configuration for the Ziren STARK prover.
//!
//! WHIR is a multilinear PCS based on Reed-Solomon proximity testing with
//! super-fast verification. It uses folding + sumcheck to reduce polynomial
//! evaluation claims, offering smaller proofs than FRI for equivalent security.
//!
//! # Security Levels
//!
//! The security level is parameterized, not hardcoded. Two extension degrees
//! are supported, following the pattern from
//! [Plonky3-recursion](https://github.com/Plonky3/Plonky3-recursion):
//!
//! | Extension | Field bits | Proven security (JBR) | Notes |
//! |-----------|-----------|----------------------|-------|
//! | D=4 (quartic) | ~124 bits | ~80 bits | Capacity Bound gives ~100 (conjectured) |
//! | D=5 (quintic) | ~155 bits | ~100 bits | Johnson Bound, proven via [BCSS25] |
//!
//! Note: 128-bit JBR is not achievable with KoalaBear^5 (~155-bit field)
//! due to algebraic limits on fold round soundness. Validated via
//! ethereum/soundcalc. A larger extension (D=7+) or base field would be
//! needed for 128-bit proven security at the outermost step.
//!
//! # Usage
//!
//! ```toml
//! zkm-stark = { version = "...", features = ["whir"] }
//! ```
//!
//! ```rust,ignore
//! use zkm_stark::whir_config::*;
//!
//! // 100-bit security with D=4 (default)
//! let params = whir_parameters(100);
//! let pcs = koalabear_whir_pcs::<WhirChallenge>(20, params);
//!
//! // 128-bit security with D=5 (quintic)
//! let params = whir_parameters(128);
//! let pcs = koalabear_whir_pcs::<Whir128Challenge>(20, params);
//! ```

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{ExtensionField, Field};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption, SumcheckStrategy};
use p3_whir::pcs::WhirPcs;

use crate::kb31_poseidon2::DIGEST_SIZE;
use zkm_primitives::poseidon2_init;

// ── Base type aliases (shared across all security levels) ─────────────────

/// KoalaBear base field.
pub type WhirVal = KoalaBear;

/// Poseidon2 permutation for hashing.
pub type WhirPerm = Poseidon2KoalaBear<16>;

/// Padding-free sponge hash.
pub type WhirHash = PaddingFreeSponge<WhirPerm, 16, 8, DIGEST_SIZE>;

/// Truncated permutation for Merkle tree compression.
pub type WhirCompress = TruncatedPermutation<WhirPerm, 2, 8, 16>;

/// Merkle tree MMCS (shared with FRI).
pub type WhirValMmcs = MerkleTreeMmcs<
    <WhirVal as Field>::Packing,
    <WhirVal as Field>::Packing,
    WhirHash,
    WhirCompress,
    2,
    DIGEST_SIZE,
>;

/// Extension MMCS (generic over challenge field).
pub type WhirChallengeMmcs<EF> = ExtensionMmcs<WhirVal, EF, WhirValMmcs>;

/// Duplex challenger for Fiat-Shamir.
pub type WhirChallenger = DuplexChallenger<WhirVal, WhirPerm, 16, 8>;

/// DFT backend for Reed-Solomon encoding.
pub type WhirDft = Radix2DitParallel<WhirVal>;

// ── Challenge field aliases per security level ────────────────────────────

/// Quartic extension (~124 bits) — sufficient for 100-bit security.
pub type WhirChallenge = BinomialExtensionField<WhirVal, 4>;

/// Quintic extension (~155 bits) — sufficient for 128-bit security.
/// Reference: Plonky3-recursion uses D=5 for KoalaBear at 128-bit.
pub type Whir128Challenge = p3_field::extension::QuinticTrinomialExtensionField<WhirVal>;

// ── Generic WHIR PCS type ─────────────────────────────────────────────────

/// WHIR PCS type, generic over the challenge field.
///
/// Use `WhirChallenge` (D=4) for 100-bit or `Whir128Challenge` (D=5) for 128-bit.
pub type KoalaBearWhirPcs<EF> = WhirPcs<
    EF,
    WhirVal,
    WhirValMmcs,
    WhirChallenger,
    WhirDft,
    DIGEST_SIZE,
>;

// ── Parameter constructors ────────────────────────────────────────────────

/// Create WHIR protocol parameters for a given security level.
///
/// Automatically selects the soundness assumption based on the target:
/// - `security_level <= 100`: Capacity Bound (conjectured, most efficient)
/// - `security_level > 100`: Johnson Bound (proven via [BCSS25], requires D=5)
///
/// Reference: Plonky3-recursion targets 124 bits as "conjectured" with D=4,
/// and uses D=5 (quintic) for higher security with proven bounds.
#[must_use]
pub fn whir_parameters(security_level: usize) -> ProtocolParameters<WhirValMmcs> {
    let perm: WhirPerm = poseidon2_init();
    let hash = WhirHash::new(perm.clone());
    let compress = WhirCompress::new(perm);
    let mmcs = WhirValMmcs::new(hash, compress, 0);

    // Use Johnson Bound for >100 bits (proven, requires D=5 extension).
    // Use Capacity Bound for <=100 bits (conjectured, works with D=4).
    let soundness_type = if security_level > 100 {
        SecurityAssumption::JohnsonBound
    } else {
        SecurityAssumption::CapacityBound
    };

    // starting_log_inv_rate=4 (rate 1/16) is required for the proximity gap
    // to support 100-bit JBR security with KoalaBear^5. At rate 1/2
    // (log_inv_rate=1), Shift round soundness is limited to ~48 bits under
    // JBR due to the 155-bit challenge field. Rate 1/16 pushes Shift
    // soundness above 128 bits, making fold rounds the bottleneck at ~100
    // bits — validated via ethereum/soundcalc.
    ProtocolParameters {
        starting_log_inv_rate: 4,
        rs_domain_initial_reduction_factor: 1,
        folding_factor: FoldingFactor::Constant(4),
        soundness_type,
        security_level,
        pow_bits: 16,
        mmcs,
    }
}

/// Create compressed WHIR parameters (smaller proofs, slower proving).
#[must_use]
pub fn whir_parameters_compressed(security_level: usize) -> ProtocolParameters<WhirValMmcs> {
    let mut params = whir_parameters(security_level);
    params.starting_log_inv_rate = 2;
    params.folding_factor = FoldingFactor::Constant(6);
    params
}

/// Create a WHIR PCS instance, generic over the challenge field.
///
/// The challenge field `EF` determines the maximum achievable security:
/// - `WhirChallenge` (D=4, ~124 bits): up to ~100-bit security
/// - `Whir128Challenge` (D=5, ~155 bits): up to ~128-bit security
///
/// # Arguments
///
/// * `num_variables` — log2 of the evaluation domain size
/// * `params` — protocol parameters (from `whir_parameters()`)
#[must_use]
pub fn koalabear_whir_pcs<EF>(
    num_variables: usize,
    params: ProtocolParameters<WhirValMmcs>,
) -> KoalaBearWhirPcs<EF>
where
    EF: ExtensionField<WhirVal> + p3_field::TwoAdicField,
{
    let dft = WhirDft::default();
    WhirPcs::new(num_variables, params, dft, SumcheckStrategy::default())
}

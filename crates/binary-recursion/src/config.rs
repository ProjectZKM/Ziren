//! The binary stage's machine configuration over traced values.
//!
//! [`TracedConfig`] is the stage's `MachineConfig` with every native type
//! replaced by its traced counterpart: the same schedule, the same WHIR
//! parameters, the same Merkle cap height, so Plonky3's verifier walks the
//! same protocol and records it.  A native proof and key are carried over by
//! re-reading them, which makes every value of the proof an input of the
//! recorded program.

use p3_binary_pcs::whir::{
    recommended_cap_height, BooleanWhirPcs, BooleanWhirProver, BooleanWhirTracePcs,
};
use p3_blake3::Blake3;
use p3_multi_stark::config::{Commitment, MultiStarkConfig, ProverData};
use p3_multi_stark::{MultiStarkProof, VerifyingKey};
use p3_sumcheck::layout::{plan_stacked_layout, Table};
use p3_sumcheck::ring_switch::bits::BitRingSwitch;
use p3_sumcheck::TableShape;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use serde::de::DeserializeOwned;
use serde::Serialize;
use zkm_binary_stark::config::{MachineConfig, MachineConfigError, MerkleMmcs};
use zkm_binary_stark::{BinarySchedule, F};

use crate::challenger::TracedChallenger;
use crate::domain::TracedDomain;
use crate::mmcs::TracedMmcs;
use crate::traced::Traced;

/// The stacked Boolean WHIR commitment, over traced values.
pub type TracedPcs =
    BooleanWhirTracePcs<Traced, Traced, TracedDomain, TracedMmcs, TracedChallenger>;

/// The binary stage's machine configuration, over traced values.
pub struct TracedConfig {
    pcs: TracedPcs,
    preprocessed_pcs: TracedPcs,
}

impl TracedConfig {
    /// The configuration `MachineConfig::new` builds for the same shapes.
    pub fn new(
        main: &[TableShape],
        preprocessed: &[TableShape],
        schedule: &BinarySchedule,
    ) -> Result<Self, MachineConfigError> {
        let (arity, _) = plan_stacked_layout(main);
        let pcs = commitment(arity, schedule)?;
        let preprocessed_pcs = if preprocessed.is_empty() {
            commitment(arity, schedule)?
        } else {
            commitment(plan_stacked_layout(preprocessed).0, schedule)?
        };
        Ok(Self { pcs, preprocessed_pcs })
    }
}

/// The commitment `MachineConfig` builds at `arity`, over traced values.
fn commitment(arity: usize, schedule: &BinarySchedule) -> Result<TracedPcs, MachineConfigError> {
    let absorbed = BitRingSwitch::<F>::ABSORBED;
    let packed = arity
        .checked_sub(absorbed)
        .ok_or(MachineConfigError::TooFewVariables { arity, absorbed })?;
    let domain = TracedDomain;
    let profile = BinarySchedule { folding: schedule.folding.min(packed), ..*schedule }.profile();
    let whir_config = profile
        .config::<Traced, Traced, TracedChallenger, _>(packed, &domain)
        .map_err(MachineConfigError::Profile)?;
    let cap_height = recommended_cap_height(&whir_config);
    let merkle = TracedMmcs::new(MerkleMmcs::new(
        SerializingHasher::new(Blake3),
        CompressionFunctionFromHasher::new(Blake3),
        cap_height,
    ));
    let prover = BooleanWhirProver::new(whir_config, domain, merkle);
    let pcs = BooleanWhirPcs::new(prover, arity).map_err(MachineConfigError::Commitment)?;
    Ok(BooleanWhirTracePcs::from_commitment(pcs))
}

impl MultiStarkConfig for TracedConfig {
    type Val = Traced;
    type Challenge = Traced;
    type Challenger = TracedChallenger;
    type Pcs = TracedPcs;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn preprocessed_pcs(&self) -> &Self::Pcs {
        &self.preprocessed_pcs
    }

    fn collision_resistance_bits(&self) -> Option<usize> {
        Some(128)
    }

    fn min_num_variables(&self) -> usize {
        1
    }

    fn build_witness(&self, _tables: Vec<Table<Traced>>) -> Vec<Table<Traced>> {
        panic!("the recorded verifier does not commit")
    }

    fn committed_table<'a>(
        &self,
        _prover_data: &'a ProverData<Self>,
        _table_index: usize,
    ) -> &'a Table<Traced> {
        panic!("the recorded verifier holds no prover data")
    }
}

/// `value` read back as `T`: the native bytes, deserialized into the
/// traced type.  Under [`crate::record`] every proof value becomes an input,
/// in the order the proof is written.
///
/// # Panics
/// Panics if `T` does not read what `value` writes.
#[must_use]
pub fn reread<S: Serialize, T: DeserializeOwned>(value: &S) -> T {
    let bytes = postcard::to_allocvec(value).expect("the native value serializes");
    postcard::from_bytes(&bytes).expect("the traced type reads the native bytes")
}

/// A machine proof, over traced values.
pub type TracedProof = MultiStarkProof<TracedConfig>;

/// The verifying key of a machine, over traced values: its preprocessed
/// commitment is a constant of the program.
///
/// # Panics
/// Panics if called during a recording, where the commitment would read as
/// proof inputs.
#[must_use]
pub fn lift_key(vk: &VerifyingKey<MachineConfig>) -> VerifyingKey<TracedConfig> {
    assert!(!crate::tape::recording(), "the key is lifted before the recording");
    vk.lift(|commitment: &Commitment<MachineConfig>| reread(commitment))
}

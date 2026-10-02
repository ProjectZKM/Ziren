//! The configuration of a machine of several tables under the stage.
//!
//! The harness configuration of `p3_examples` proves one table and refuses
//! every interaction; a machine is several tables, each at its own height,
//! stacked into one Boolean WHIR commitment, with buses between them.  This
//! builds that configuration from the tables' shapes and the schedule.

use p3_binary_pcs::whir::{
    recommended_cap_height, BinaryWhirProfile, BooleanWhirData, BooleanWhirDomain,
    BooleanWhirError, BooleanWhirPcs, BooleanWhirProver, BooleanWhirTracePcs, ProfileError,
};
use p3_binary_pcs::BooleanTraceCommitmentData;
use p3_blake3::Blake3;
use p3_multi_stark::config::MultiStarkConfig;
use p3_sumcheck::layout::{plan_stacked_layout, Table};
use p3_sumcheck::ring_switch::bits::BitRingSwitch;
use p3_sumcheck::TableShape;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};

use crate::{BinarySchedule, Challenger, F};

/// The Blake3 Merkle tree over bytes, arity 2.
pub type MerkleMmcs = p3_merkle_tree::MerkleTreeMmcs<
    F,
    u8,
    SerializingHasher<Blake3>,
    CompressionFunctionFromHasher<Blake3, 2, 32>,
    2,
    32,
>;

/// The stacked Boolean WHIR commitment of every table of a machine.
pub type MachinePcs = BooleanWhirTracePcs<F, F, BooleanWhirDomain, MerkleMmcs, Challenger>;

/// A proof of a machine.
pub type MachineProof = p3_multi_stark::MultiStarkProof<MachineConfig>;

/// Why a machine configuration cannot be built.
#[derive(Debug)]
pub enum MachineConfigError {
    /// The stacked tables are too small for the ring switch to absorb.
    TooFewVariables { arity: usize, absorbed: usize },
    /// The schedule has no WHIR configuration at this size.
    Profile(ProfileError),
    /// The commitment refused the configuration.
    Commitment(BooleanWhirError),
}

impl core::fmt::Display for MachineConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooFewVariables { arity, absorbed } => {
                write!(f, "stacked tables have {arity} variables, below the {absorbed} absorbed")
            }
            Self::Profile(error) => write!(f, "WHIR profile: {error}"),
            Self::Commitment(error) => write!(f, "Boolean WHIR commitment: {error}"),
        }
    }
}

impl std::error::Error for MachineConfigError {}

/// The configuration of one machine: its tables' shapes fix the commitment.
pub struct MachineConfig {
    pcs: MachinePcs,
    /// Variables of the stacked commitment.
    pub arity: usize,
}

impl MachineConfig {
    /// The configuration of the tables at `shapes` under `schedule`.
    pub fn new(
        shapes: &[TableShape],
        schedule: &BinarySchedule,
    ) -> Result<Self, MachineConfigError> {
        let (arity, _) = plan_stacked_layout(shapes);
        let absorbed = BitRingSwitch::<F>::ABSORBED;
        let packed = arity
            .checked_sub(absorbed)
            .ok_or(MachineConfigError::TooFewVariables { arity, absorbed })?;
        let domain = BooleanWhirDomain::default();
        let profile = BinaryWhirProfile::proven_list_decoding(
            schedule.term_security_bits,
            schedule.log_inv_rate,
            schedule.folding,
        );
        let whir_config = profile
            .config::<F, F, Challenger, _>(packed, &domain)
            .map_err(MachineConfigError::Profile)?;
        let cap_height = recommended_cap_height(&whir_config);
        let merkle = MerkleMmcs::new(
            SerializingHasher::new(Blake3),
            CompressionFunctionFromHasher::new(Blake3),
            cap_height,
        );
        let prover = BooleanWhirProver::new(whir_config, domain, merkle);
        let pcs = BooleanWhirPcs::new(prover, arity).map_err(MachineConfigError::Commitment)?;
        Ok(Self { pcs: BooleanWhirTracePcs::from_commitment(pcs), arity })
    }
}

impl MultiStarkConfig for MachineConfig {
    type Val = F;
    type Challenge = F;
    type Challenger = Challenger;
    type Pcs = MachinePcs;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn collision_resistance_bits(&self) -> Option<usize> {
        Some(128)
    }

    fn min_num_variables(&self) -> usize {
        1
    }

    fn build_witness(&self, tables: Vec<Table<F>>) -> Vec<Table<F>> {
        tables
    }

    fn committed_table<'a>(
        &self,
        prover_data: &'a BooleanTraceCommitmentData<F, BooleanWhirData<F, F, MerkleMmcs>>,
        table_index: usize,
    ) -> &'a Table<F> {
        prover_data.table(table_index)
    }
}

#[cfg(test)]
mod tests {
    use core::borrow::Borrow;

    use p3_air::utils::word_view;
    use p3_air::Air;
    use p3_air::{BaseAir, WindowAccess};
    use p3_binary_pcs::coordinate_basis;
    use p3_bus::{BusActivation, BusDirection, BusName};

    use crate::machine_builder::MachineBuilder;
    use p3_binary_field::{BinaryField2, Ghash128};
    use p3_matrix::dense::RowMajorMatrix;
    use p3_multi_stark::{
        prove_with_backend, setup, verify, ProverInstance, ProverInstances, ReprBackend,
        VerifierInstance, VerifierInstances,
    };
    use zkm_derive::AlignedBorrow;

    use super::*;
    use crate::challenger;

    /// One channel: a writer pushes `(address, value)` once per read, and
    /// every reader row pulls one.
    const MEMORY: BusName<'static> = BusName::new("memory");
    const ADDRESS_BITS: usize = 8;
    const VALUE_BITS: usize = 31;

    #[derive(AlignedBorrow, Clone, Copy, Debug)]
    #[repr(C)]
    struct CellCols<T> {
        address: [T; ADDRESS_BITS],
        value: [T; VALUE_BITS],
    }

    const NUM_CELL_COLS: usize = ADDRESS_BITS + VALUE_BITS;

    /// The two tables of the probe, told apart by the side of the channel.
    #[derive(Clone, Copy, Debug)]
    enum ProbeAir {
        Writer,
        Reader,
    }

    impl<AB: MachineBuilder<F = F>> Air<AB> for ProbeAir {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local: &CellCols<AB::Var> = main.current_slice().borrow();
            for bit in local.address.iter().chain(local.value.iter()) {
                builder.assert_bool(*bit);
            }
            let basis = coordinate_basis::<F>();
            let address: AB::Expr = word_view(&local.address, &basis[..ADDRESS_BITS]);
            let value: AB::Expr = word_view(&local.value, &basis[..VALUE_BITS]);
            let direction = match self {
                Self::Writer => BusDirection::Push,
                Self::Reader => BusDirection::Pull,
            };
            builder.declare_bus(MEMORY, direction, vec![address, value], BusActivation::Always);
        }
    }

    impl<X> BaseAir<X> for ProbeAir {
        fn width(&self) -> usize {
            NUM_CELL_COLS
        }
    }

    fn packed(cells: &[(u8, u32)]) -> RowMajorMatrix<u64> {
        let blocks = cells.len().div_ceil(64);
        let mut words = vec![0u64; blocks * NUM_CELL_COLS];
        for (r, &(address, value)) in cells.iter().enumerate() {
            let block = &mut words[(r / 64) * NUM_CELL_COLS..(r / 64 + 1) * NUM_CELL_COLS];
            let (address_words, value_words) = block.split_at_mut(ADDRESS_BITS);
            for (i, word) in address_words.iter_mut().enumerate() {
                *word |= u64::from((address >> i) & 1) << (r % 64);
            }
            for (i, word) in value_words.iter_mut().enumerate() {
                *word |= u64::from((value >> i) & 1) << (r % 64);
            }
        }
        RowMajorMatrix::new(words, NUM_CELL_COLS)
    }

    /// A writer table and a reader table balance one channel under one
    /// stacked Boolean WHIR commitment; a reader that pulls a value never
    /// pushed does not verify.
    #[test]
    fn two_tables_balance_a_bus() {
        let log_height = 7;
        let airs = [ProbeAir::Writer, ProbeAir::Reader];
        let shapes = [TableShape::new(log_height, NUM_CELL_COLS); 2];
        let schedule = BinarySchedule::default();
        let config = MachineConfig::new(&shapes, &schedule).expect("machine config");
        let (pk, vk) = setup(&config, &[&airs[0], &airs[1]], &mut challenger()).expect("keys");

        let cells: Vec<(u8, u32)> = (0..1u32 << log_height)
            .map(|i| ((i % 37) as u8, (i * 2_654_435_761) % crate::word::KB_PRIME))
            .collect();
        let mut reads = cells.clone();
        reads.reverse();
        let public: [F; 0] = [];
        let tables = |reads: &[(u8, u32)]| {
            vec![
                Table::<F>::from_packed_bits(packed(&cells), log_height),
                Table::<F>::from_packed_bits(packed(reads), log_height),
            ]
        };
        let instances = |tables: Vec<Table<F>>| {
            let mut tables = tables.into_iter();
            ProverInstances::new(vec![
                ProverInstance::new(&airs[0], tables.next().unwrap(), &pk, &public),
                ProverInstance::new(&airs[1], tables.next().unwrap(), &pk, &public),
            ])
        };
        let verifier = || {
            VerifierInstances::new(vec![
                VerifierInstance::new(&airs[0], &vk, log_height, &public),
                VerifierInstance::new(&airs[1], &vk, log_height, &public),
            ])
        };
        let proof = prove_with_backend::<_, _, ReprBackend<BinaryField2, Ghash128, true>>(
            &config,
            instances(tables(&reads)),
            0,
            &mut challenger(),
        )
        .expect("balanced tables prove");
        verify(&config, verifier(), &proof, 0, &mut challenger()).expect("balanced tables verify");

        let mut forged = reads;
        forged[3].1 ^= 1;
        let rejected = match prove_with_backend::<_, _, ReprBackend<BinaryField2, Ghash128, true>>(
            &config,
            instances(tables(&forged)),
            0,
            &mut challenger(),
        ) {
            Err(_) => true,
            Ok(proof) => verify(&config, verifier(), &proof, 0, &mut challenger()).is_err(),
        };
        assert!(rejected, "an unbalanced channel must not verify");
    }
}

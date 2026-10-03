//! The machine that proves a tape: the narrow recursion's prover.
//!
//! A recorded verification is a program over `GF(2^128)`; this machine
//! proves a run of it under the binary stage's own configuration, so its
//! proofs are what the next recorded verifier, or a garbled one, checks.
//! Five tables share one memory of cells (see [`program`]):
//!
//! ```text
//!     ledger    one row per read; binds each cell to its source
//!     arith     one row per field operation, assertion, select or copy
//!     rewire    one row per transpose, split into bytes or bits, or assembly
//!     hash      one row per Blake3 compression, with its chaining
//!     rounds    seven rows per compression, the binary stage's round table
//! ```
//!
//! What the verifier of this machine costs grows with its tables and
//! columns far more than with its rows, so the tables are few and their
//! constraints are on packed elements, one per relation.

pub mod arith;
pub mod cells;
pub mod hash;
pub mod ledger;
pub mod program;
pub mod rewire;

use p3_air::symbolic::AirLayout;
use p3_air::{Air, BaseAir};
use p3_binary_field::{BinaryField2, Ghash128};
use p3_bus::BusSymbolicBuilder;
use p3_bus::{BusDebugInstance, BusDebugReport};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_multi_stark::config::{MultiStarkConfig, PcsError, PcsProverError};
use p3_multi_stark::{
    prove_with_backend, setup, verify, ProverInstance, ProverInstances, ProvingError, ProvingKey,
    ReprBackend, SubfieldBackend, VerificationError, VerifierInstance, VerifierInstances,
    VerifyingKey,
};
use p3_sumcheck::layout::Table;
use p3_sumcheck::TableShape;
use zkm_binary_stark::config::{MachineConfig, MachineConfigError, MachineProof};
use zkm_binary_stark::machine::blake3::Blake3RoundAir;
use zkm_binary_stark::machine_builder::MachineBuilder;
use zkm_binary_stark::{challenger, BinaryBase, BinarySchedule};

use self::arith::ArithAir;
use self::hash::HashAir;
use self::ledger::{LedgerAir, MAX_PUBLIC};
use self::program::Program;
use self::rewire::RewireAir;
use crate::tape::{RunError, Tape, F};

/// One table of the machine.
pub enum TapeAir {
    Ledger(LedgerAir),
    Arith(ArithAir),
    Rewire(RewireAir),
    Hash(HashAir),
    Rounds(Blake3RoundAir),
}

impl TapeAir {
    #[must_use]
    pub fn log_height(&self) -> usize {
        match self {
            Self::Ledger(air) => air.log_height(),
            Self::Arith(air) => air.log_height(),
            Self::Rewire(air) => air.log_height(),
            Self::Hash(air) => air.log_height(),
            Self::Rounds(air) => air.log_height(),
        }
    }

    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Ledger(_) => "Ledger",
            Self::Arith(_) => "Arith",
            Self::Rewire(_) => "Rewire",
            Self::Hash(_) => "Hash",
            Self::Rounds(_) => "Rounds",
        }
    }
}

impl<X: Field> BaseAir<X> for TapeAir {
    fn width(&self) -> usize {
        match self {
            Self::Ledger(air) => BaseAir::<X>::width(air),
            Self::Arith(air) => BaseAir::<X>::width(air),
            Self::Rewire(air) => BaseAir::<X>::width(air),
            Self::Hash(air) => BaseAir::<X>::width(air),
            Self::Rounds(air) => BaseAir::<X>::width(air),
        }
    }

    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Ledger(air) => BaseAir::<X>::preprocessed_width(air),
            Self::Arith(air) => BaseAir::<X>::preprocessed_width(air),
            Self::Rewire(air) => BaseAir::<X>::preprocessed_width(air),
            Self::Hash(air) => BaseAir::<X>::preprocessed_width(air),
            Self::Rounds(air) => BaseAir::<X>::preprocessed_width(air),
        }
    }

    fn num_public_values(&self) -> usize {
        match self {
            Self::Ledger(air) => BaseAir::<X>::num_public_values(air),
            _ => 0,
        }
    }

    /// No table reads its next row: a column read there is opened a second
    /// time, and its table's opening carries a successor view.
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        match self {
            Self::Ledger(air) => air.preprocessed_trace(),
            Self::Arith(air) => air.preprocessed_trace(),
            Self::Rewire(air) => air.preprocessed_trace(),
            Self::Hash(air) => air.preprocessed_trace(),
            Self::Rounds(air) => air.preprocessed_trace(),
        }
    }
}

impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for TapeAir {
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Ledger(air) => air.eval(builder),
            Self::Arith(air) => air.eval(builder),
            Self::Rewire(air) => air.eval(builder),
            Self::Hash(air) => air.eval(builder),
            Self::Rounds(air) => air.eval(builder),
        }
    }
}

/// Why a tape cannot be proved or verified.
#[derive(Debug)]
pub enum TapeMachineError {
    Config(MachineConfigError),
    Setup(ProvingError<PcsProverError<MachineConfig>>),
    /// The inputs do not satisfy the program.
    Run(RunError),
    Prove(ProvingError<PcsProverError<MachineConfig>>),
    Verify(VerificationError<PcsError<MachineConfig>>),
}

/// The machine of one tape's program.
pub struct TapeMachine {
    program: Program,
    airs: Vec<TapeAir>,
    config: MachineConfig,
    pk: ProvingKey<MachineConfig>,
    vk: VerifyingKey<MachineConfig>,
}

impl TapeMachine {
    /// The machine of `program` under `schedule`.
    ///
    /// # Errors
    /// Returns an error if the configuration or the keys cannot be built.
    pub fn new(program: Program, schedule: &BinarySchedule) -> Result<Self, TapeMachineError> {
        let airs = vec![
            TapeAir::Ledger(LedgerAir::new(&program)),
            TapeAir::Arith(ArithAir::new(&program)),
            TapeAir::Rewire(RewireAir::new(&program)),
            TapeAir::Hash(HashAir::new(&program)),
            TapeAir::Rounds(Blake3RoundAir::for_count(program.compressions.len())),
        ];
        let (main, preprocessed) = Self::shapes_of(&airs);
        let config =
            MachineConfig::new(&main, &preprocessed, schedule).map_err(TapeMachineError::Config)?;
        let refs: Vec<&TapeAir> = airs.iter().collect();
        let (pk, vk) = setup(&config, &refs, &mut challenger()).map_err(TapeMachineError::Setup)?;
        Ok(Self { program, airs, config, pk, vk })
    }

    fn shapes_of(airs: &[TapeAir]) -> (Vec<TableShape>, Vec<TableShape>) {
        let main = airs
            .iter()
            .map(|air| TableShape::new(air.log_height(), BaseAir::<F>::width(air)))
            .collect();
        let preprocessed = airs
            .iter()
            .filter(|air| BaseAir::<F>::preprocessed_width(*air) > 0)
            .map(|air| TableShape::new(air.log_height(), BaseAir::<F>::preprocessed_width(air)))
            .collect();
        (main, preprocessed)
    }

    /// The shapes of the main and preprocessed tables.
    #[must_use]
    pub fn shapes(&self) -> (Vec<TableShape>, Vec<TableShape>) {
        Self::shapes_of(&self.airs)
    }

    #[must_use]
    pub fn airs(&self) -> &[TapeAir] {
        &self.airs
    }

    #[must_use]
    pub const fn program(&self) -> &Program {
        &self.program
    }

    #[must_use]
    pub const fn verifying_key(&self) -> &VerifyingKey<MachineConfig> {
        &self.vk
    }

    /// The public values of a run on `inputs`: its first public inputs,
    /// padded with zeros to what the ledger binds.
    #[must_use]
    pub fn public_values(&self, inputs: &[F]) -> [F; MAX_PUBLIC] {
        core::array::from_fn(|i| if i < self.program.num_public { inputs[i] } else { F::ZERO })
    }

    /// The verifier's statement under any configuration of the machine.
    #[must_use]
    pub fn verifier_instances<'a, C: MultiStarkConfig>(
        &'a self,
        vk: &'a VerifyingKey<C>,
        public: &'a [C::Val; MAX_PUBLIC],
    ) -> VerifierInstances<'a, C, TapeAir> {
        VerifierInstances::new(
            self.airs
                .iter()
                .map(|air| {
                    let public_values: &[C::Val] = match air {
                        TapeAir::Ledger(_) => public,
                        _ => &[],
                    };
                    VerifierInstance::new(air, vk, air.log_height(), public_values)
                })
                .collect(),
        )
    }

    /// Prove the run of `tape`'s program on `inputs`.
    ///
    /// # Errors
    /// Returns an error if the inputs do not satisfy the program, or if
    /// proving fails.
    pub fn prove(&self, tape: &Tape, inputs: &[F]) -> Result<MachineProof, TapeMachineError> {
        let values = tape.run(inputs).map_err(TapeMachineError::Run)?;
        self.prove_values(&values, &self.public_values(inputs))
    }

    /// Prove that the program runs with these values of its variables and
    /// these public values.
    ///
    /// The values are not checked against the program: a run's values
    /// satisfy it, and anything else must fail to prove or to verify, which
    /// is what this is for besides [`Self::prove`].
    ///
    /// # Errors
    /// Returns an error if proving fails.
    pub fn prove_values(
        &self,
        values: &[F],
        public: &[F; MAX_PUBLIC],
    ) -> Result<MachineProof, TapeMachineError> {
        let owned = self.main_tables(values);
        let instances = ProverInstances::new(
            self.airs
                .iter()
                .zip(owned)
                .map(|(air, table)| {
                    let public_values: &[F] = match air {
                        TapeAir::Ledger(_) => public,
                        _ => &[],
                    };
                    ProverInstance::new(air, table, &self.pk, public_values)
                })
                .collect(),
        );
        let proof = if p3_binary_field::poly_basis::HAS_HARDWARE_CLMUL {
            prove_with_backend::<_, _, ReprBackend<BinaryField2, Ghash128, true>>(
                &self.config,
                instances,
                0,
                &mut challenger(),
            )
        } else {
            prove_with_backend::<_, _, SubfieldBackend<BinaryField2>>(
                &self.config,
                instances,
                0,
                &mut challenger(),
            )
        };
        proof.map_err(TapeMachineError::Prove)
    }

    /// Every table's witness for a run with these values.
    fn main_tables(&self, values: &[F]) -> Vec<Table<F>> {
        let states = self.program.compression_states(values);
        let round_inputs = HashAir::round_inputs(&self.program, &states);
        let (mut rounds_table, finals) = self
            .airs
            .iter()
            .find_map(|air| match air {
                TapeAir::Rounds(rounds) => Some(rounds.table_of(&round_inputs)),
                _ => None,
            })
            .map(|(table, finals)| (Some(table), finals))
            .expect("the machine has a round table");
        self.airs
            .iter()
            .map(|air| match air {
                TapeAir::Ledger(a) => a.main_table(&self.program, values),
                TapeAir::Arith(a) => a.main_table(&self.program, values),
                TapeAir::Rewire(a) => a.main_table(&self.program, values),
                TapeAir::Hash(a) => a.main_table(&self.program, values, &states, &finals),
                TapeAir::Rounds(_) => rounds_table.take().expect("one round table"),
            })
            .collect()
    }

    /// The tuples of a run with these values that no channel balances,
    /// replayed from the tables: what a proof that fails its bus argument
    /// got wrong.
    ///
    /// # Panics
    /// Panics if the tables do not match their declarations.
    #[must_use]
    pub fn unbalanced(&self, values: &[F], public: &[F; MAX_PUBLIC]) -> String {
        let mains = self.main_tables(values);
        let preps: Vec<Option<Table<F>>> = self
            .airs
            .iter()
            .map(|air| BaseAir::<F>::preprocessed_trace(air).map(|m| Table::new(m.transpose())))
            .collect();
        let profiles: Vec<BusSymbolicBuilder<F, F>> = self
            .airs
            .iter()
            .map(|air| BusSymbolicBuilder::<F, F>::from_air(air, AirLayout::from_air::<F>(air)))
            .collect();
        let instances: Vec<BusDebugInstance<'_, F>> = self
            .airs
            .iter()
            .zip(&mains)
            .zip(&preps)
            .zip(&profiles)
            .map(|(((air, main), prep), profile)| {
                let public_values: &[F] = match air {
                    TapeAir::Ledger(_) => public,
                    _ => &[],
                };
                BusDebugInstance::new(main, prep.as_ref(), public_values, profile)
                    .expect("the tables match their declarations")
            })
            .collect();
        let report = BusDebugReport::check(&instances).expect("the replay runs");
        format!("{report}")
    }

    /// Verify `proof` as a proof of a run with these public values.
    ///
    /// # Errors
    /// Returns an error if the proof does not verify.
    pub fn verify(
        &self,
        proof: &MachineProof,
        public: &[F; MAX_PUBLIC],
    ) -> Result<(), TapeMachineError> {
        let instances = self.verifier_instances(&self.vk, public);
        verify(&self.config, instances, proof, 0, &mut challenger())
            .map_err(TapeMachineError::Verify)
    }
}

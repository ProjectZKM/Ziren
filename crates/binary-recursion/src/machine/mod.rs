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
//!     hash      three rows per Blake3 compression: its block, its output
//!     rounds    one row per half quarter-round, 112 per compression
//! ```
//!
//! What the verifier of this machine costs grows with its tables and
//! columns far more than with its rows, so the tables are few and their
//! constraints are on packed elements, one per relation.

pub mod arith;
pub mod cells;
pub mod hash;
pub mod kb;
pub mod ledger;
pub mod program;
pub mod public;
pub mod rewire;
pub mod rounds;
pub mod select;

use p3_air::symbolic::AirLayout;
use p3_air::{Air, BaseAir};
use p3_binary_field::{BinaryField2, Ghash128};
use p3_binary_pcs::BooleanMultilinearPcs;
use p3_bus::BusSymbolicBuilder;
use p3_bus::{BusDebugInstance, BusDebugReport};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_multi_stark::config::{Commitment, MultiStarkConfig, PcsError, PcsProverError};
use p3_multi_stark::{
    prove_on, setup_with_tables, verify, DeviceBackend, HostProver, ProverBackend, ProverInstance,
    ProverInstances, ProvingError, ProvingKey, ReprBackend, SubfieldBackend, VerificationError,
    VerifierInstance, VerifierInstances, VerifyingKey, ZerocheckDevice,
};
use p3_sumcheck::layout::Table;
use p3_sumcheck::TableShape;
use p3_word_backend::WordDevice;
use std::sync::Arc;
use zkm_binary_stark::config::{BitPcs, MachineConfig, MachineConfigError, MachineProof};
use zkm_binary_stark::machine::blake3::STATE_WORDS;
use zkm_binary_stark::machine_builder::MachineBuilder;
use zkm_binary_stark::{challenger, BinaryBase, BinarySchedule, Challenger};

pub use zkm_recursion_r1cs::tape::Tape as WordTape;

use self::arith::ArithAir;
use self::hash::HashAir;
use self::kb::KbAir;
use self::ledger::{LedgerAir, MAX_PUBLIC};
use self::program::Program;
use self::public::PublicAir;
use self::rewire::{RewireAir, NARROW, WIDTH};
use self::rounds::RoundsAir;
use self::select::SelectAir;
use crate::tape::{RunError, Tape, F};

/// The least log height of each table of a compose node, by name: a node
/// over any two leaves of the first two leaf classes, or over two nodes, is
/// a machine of this shape, which one parent program verifies.  The floor is
/// a node's over two leaves of the second class, the tallest of them, and
/// commits `2^33` bits.
pub const NODE_FLOOR: &[(&str, usize)] = &[
    ("Ledger", 23),
    ("Arith", 22),
    ("Rewire", 21),
    ("Gather", 18),
    ("Hash", 19),
    ("Rounds", 20),
    ("Kb", 14),
    ("Select", 16),
    ("Public", 6),
];

/// The least log height of each table of a node over two nodes, by name.
/// Every node over leaves is a machine of [`NODE_FLOOR`]'s shape, so every
/// node over two of them records one program, whose own heights these are;
/// a node over two nodes of this shape verifies smaller machines, so its
/// tables fit too, and from there up every node has one program.  It
/// commits `2^32` bits, half a node over leaves.
pub const UPPER_NODE_FLOOR: &[(&str, usize)] = &[
    ("Ledger", 22),
    ("Arith", 21),
    ("Rewire", 19),
    ("Gather", 16),
    ("Hash", 17),
    ("Rounds", 19),
    ("Kb", 14),
    ("Select", 16),
    ("Public", 6),
];

/// One table of the machine.
pub enum TapeAir {
    Ledger(LedgerAir),
    Arith(ArithAir),
    Rewire(RewireAir<NARROW>),
    Gather(RewireAir<WIDTH>),
    Hash(HashAir),
    Rounds(RoundsAir),
    Kb(KbAir),
    Select(SelectAir),
    Public(PublicAir),
}

impl TapeAir {
    /// The preprocessed columns as the bit table setup commits.
    #[must_use]
    pub fn preprocessed_table(&self) -> Table<F> {
        match self {
            Self::Ledger(air) => air.preprocessed_table(),
            Self::Arith(air) => air.preprocessed_table(),
            Self::Rewire(air) => air.preprocessed_table(),
            Self::Gather(air) => air.preprocessed_table(),
            Self::Hash(air) => air.preprocessed_table(),
            Self::Rounds(air) => air.preprocessed_table(),
            Self::Kb(air) => air.preprocessed_table(),
            Self::Select(air) => air.preprocessed_table(),
            Self::Public(air) => air.preprocessed_table(),
        }
    }

    #[must_use]
    pub fn log_height(&self) -> usize {
        match self {
            Self::Ledger(air) => air.log_height(),
            Self::Arith(air) => air.log_height(),
            Self::Rewire(air) => air.log_height(),
            Self::Gather(air) => air.log_height(),
            Self::Hash(air) => air.log_height(),
            Self::Rounds(air) => air.log_height(),
            Self::Kb(air) => air.log_height(),
            Self::Select(air) => air.log_height(),
            Self::Public(air) => air.log_height(),
        }
    }

    /// The table named `name` at `2^log_height` rows with no program: what a
    /// verifier needs, which reads only the table's shape and constraints.
    fn shell(name: &str, log_height: usize) -> Option<Self> {
        let preprocessed = Vec::new();
        Some(match name {
            "Ledger" => Self::Ledger(LedgerAir { log_height, preprocessed }),
            "Arith" => Self::Arith(ArithAir { log_height, preprocessed }),
            "Rewire" => Self::Rewire(RewireAir { log_height, preprocessed }),
            "Gather" => Self::Gather(RewireAir { log_height, preprocessed }),
            "Hash" => Self::Hash(HashAir { log_height, preprocessed }),
            "Rounds" => Self::Rounds(RoundsAir { log_height, preprocessed }),
            "Kb" => Self::Kb(KbAir { log_height, preprocessed }),
            "Select" => Self::Select(SelectAir { log_height, preprocessed }),
            "Public" => Self::Public(PublicAir { log_height, preprocessed }),
            _ => return None,
        })
    }

    /// Pad the table with zero rows up to `2^log_height`, when it is lower:
    /// a zero row is what every table holds past its program, so the padded
    /// table holds the same program at the height a floor fixes.
    fn raise(&mut self, log_height: usize) {
        let (height, bits) = match self {
            Self::Ledger(air) => (&mut air.log_height, &mut air.preprocessed),
            Self::Arith(air) => (&mut air.log_height, &mut air.preprocessed),
            Self::Rewire(air) => (&mut air.log_height, &mut air.preprocessed),
            Self::Gather(air) => (&mut air.log_height, &mut air.preprocessed),
            Self::Hash(air) => (&mut air.log_height, &mut air.preprocessed),
            Self::Rounds(air) => (&mut air.log_height, &mut air.preprocessed),
            Self::Kb(air) => (&mut air.log_height, &mut air.preprocessed),
            Self::Select(air) => (&mut air.log_height, &mut air.preprocessed),
            Self::Public(air) => (&mut air.log_height, &mut air.preprocessed),
        };
        if log_height <= *height {
            return;
        }
        let width = bits.len() >> *height;
        bits.resize(width << log_height, 0);
        *height = log_height;
    }

    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Ledger(_) => "Ledger",
            Self::Arith(_) => "Arith",
            Self::Rewire(_) => "Rewire",
            Self::Gather(_) => "Gather",
            Self::Hash(_) => "Hash",
            Self::Rounds(_) => "Rounds",
            Self::Kb(_) => "Kb",
            Self::Select(_) => "Select",
            Self::Public(_) => "Public",
        }
    }
}

impl<X: Field> BaseAir<X> for TapeAir {
    fn width(&self) -> usize {
        match self {
            Self::Ledger(air) => BaseAir::<X>::width(air),
            Self::Arith(air) => BaseAir::<X>::width(air),
            Self::Rewire(air) => BaseAir::<X>::width(air),
            Self::Gather(air) => BaseAir::<X>::width(air),
            Self::Hash(air) => BaseAir::<X>::width(air),
            Self::Rounds(air) => BaseAir::<X>::width(air),
            Self::Kb(air) => BaseAir::<X>::width(air),
            Self::Select(air) => BaseAir::<X>::width(air),
            Self::Public(air) => BaseAir::<X>::width(air),
        }
    }

    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Ledger(air) => BaseAir::<X>::preprocessed_width(air),
            Self::Arith(air) => BaseAir::<X>::preprocessed_width(air),
            Self::Rewire(air) => BaseAir::<X>::preprocessed_width(air),
            Self::Gather(air) => BaseAir::<X>::preprocessed_width(air),
            Self::Hash(air) => BaseAir::<X>::preprocessed_width(air),
            Self::Rounds(air) => BaseAir::<X>::preprocessed_width(air),
            Self::Kb(air) => BaseAir::<X>::preprocessed_width(air),
            Self::Select(air) => BaseAir::<X>::preprocessed_width(air),
            Self::Public(air) => BaseAir::<X>::preprocessed_width(air),
        }
    }

    fn num_public_values(&self) -> usize {
        match self {
            Self::Public(air) => BaseAir::<X>::num_public_values(air),
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
            Self::Gather(air) => air.preprocessed_trace(),
            Self::Hash(air) => air.preprocessed_trace(),
            Self::Rounds(air) => air.preprocessed_trace(),
            Self::Kb(air) => air.preprocessed_trace(),
            Self::Select(air) => air.preprocessed_trace(),
            Self::Public(air) => air.preprocessed_trace(),
        }
    }
}

impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for TapeAir {
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Ledger(air) => air.eval(builder),
            Self::Arith(air) => air.eval(builder),
            Self::Rewire(air) => air.eval(builder),
            Self::Gather(air) => air.eval(builder),
            Self::Hash(air) => air.eval(builder),
            Self::Rounds(air) => air.eval(builder),
            Self::Kb(air) => air.eval(builder),
            Self::Select(air) => air.eval(builder),
            Self::Public(air) => air.eval(builder),
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
    /// The machine was built to verify, and holds no proving key.
    NoProvingKey,
    /// A key names a table the machine has none of.
    UnknownTable(String),
}

/// What a verifier rebuilds a tape machine from: its tables' names and log
/// heights, in order, and its preprocessed commitment.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NodeKey {
    pub heights: Vec<(String, usize)>,
    pub commitment: Commitment<MachineConfig>,
}

/// Where a tape machine's proof is computed: the trace commitment and the
/// bus trees through [`ProverBackend`], and the zerocheck's stages on the
/// device the backend names, or on the host's kernels when it names none.
pub trait TapeBackend: ProverBackend<MachineConfig, TapeAir> {
    /// The device that takes the zerocheck's stages, or `None` for the host.
    fn zerocheck_device(&self) -> Option<&dyn ZerocheckDevice<F, F>>;

    /// A fresh transcript for a proof on this backend, its proof-of-work witnesses searched
    /// where the backend searches them.
    fn challenger(&self) -> Challenger;

    /// The devices that prove a word leaf whose commitment's caps are `cap_height` high, or
    /// `None` for the host.
    fn word_devices(&self, cap_height: usize) -> Option<WordDevices<'_>>;

    /// The committed words `tape` computes over the public words `public` and `memory`,
    /// the runtime's memory as four canonical coefficients per address.
    fn witness(&self, tape: &Arc<WordTape>, public: &[u64], memory: &[u32]) -> Vec<u64>;

    /// Makes the backend's device the calling thread's, before the thread proves on it.
    fn bind(&self) {}

    /// The Blake3 round table of `air` over the compressions that start from `inputs`, their
    /// states and blocks, with each compression's final state.
    fn rounds_table(
        &self,
        air: &RoundsAir,
        inputs: &[([u32; STATE_WORDS], [u32; STATE_WORDS])],
    ) -> (Table<F>, Vec<[u32; STATE_WORDS]>);

    /// The table of `air`, `program`'s field operations, over a run with these values.
    fn arith_table(&self, air: &ArithAir, program: &Program, values: &[F]) -> Table<F>;

    /// The table of `air`, `program`'s KoalaBear operations, over a run with these values.
    fn kb_table(&self, air: &KbAir, program: &Program, values: &[F]) -> Table<F>;
}

/// The devices of a word leaf: its trees, relations and shifts, and its commitment's opening.
pub struct WordDevices<'a> {
    pub words: &'a dyn WordDevice,
    pub opening: Box<LeafOpening>,
}

/// Where a word leaf's commitment opens.
pub type LeafOpening = <BitPcs as BooleanMultilinearPcs<F, Challenger>>::OpeningDevice;

impl TapeBackend for HostProver {
    fn zerocheck_device(&self) -> Option<&dyn ZerocheckDevice<F, F>> {
        None
    }

    fn challenger(&self) -> Challenger {
        challenger()
    }

    fn word_devices(&self, _cap_height: usize) -> Option<WordDevices<'_>> {
        None
    }

    fn witness(&self, tape: &Arc<WordTape>, public: &[u64], memory: &[u32]) -> Vec<u64> {
        tape.evaluate(public, &|addr, coefficient| u64::from(memory[4 * addr + coefficient]))
    }

    fn rounds_table(
        &self,
        air: &RoundsAir,
        inputs: &[([u32; STATE_WORDS], [u32; STATE_WORDS])],
    ) -> (Table<F>, Vec<[u32; STATE_WORDS]>) {
        air.table_of(inputs)
    }

    fn arith_table(&self, air: &ArithAir, program: &Program, values: &[F]) -> Table<F> {
        air.main_table(program, values)
    }

    fn kb_table(&self, air: &KbAir, program: &Program, values: &[F]) -> Table<F> {
        air.main_table(program, values)
    }
}

/// The machine of one tape's program.
pub struct TapeMachine {
    program: Program,
    airs: Vec<TapeAir>,
    config: MachineConfig,
    /// The proving key, which holds the preprocessed commitment's prover
    /// data; a machine built to verify drops it.
    pk: Option<ProvingKey<MachineConfig>>,
    vk: VerifyingKey<MachineConfig>,
}

impl TapeMachine {
    /// The machine of `program` under `schedule`.
    ///
    /// # Errors
    /// Returns an error if the configuration or the keys cannot be built.
    pub fn new(program: Program, schedule: &BinarySchedule) -> Result<Self, TapeMachineError> {
        Self::new_with_floor(program, schedule, &[])
    }

    /// The machine of `program` under `schedule`, every table at least as
    /// tall as `floor` names it: nodes of one kind are then machines of one
    /// shape, which one parent program verifies.
    ///
    /// # Errors
    /// Returns an error if the configuration or the keys cannot be built.
    pub fn new_with_floor(
        program: Program,
        schedule: &BinarySchedule,
        floor: &[(&str, usize)],
    ) -> Result<Self, TapeMachineError> {
        let mut airs = tracing::debug_span!("airs").in_scope(|| Self::airs_of(&program));
        for air in &mut airs {
            if let Some(&(_, log_height)) = floor.iter().find(|(name, _)| *name == air.name()) {
                air.raise(log_height);
            }
        }
        let (main, preprocessed) = Self::shapes_of(&airs);
        let config = tracing::debug_span!("config")
            .in_scope(|| MachineConfig::new(&main, &preprocessed, schedule))
            .map_err(TapeMachineError::Config)?;
        let refs: Vec<&TapeAir> = airs.iter().collect();
        let tables = tracing::debug_span!("preprocessed tables").in_scope(|| {
            airs.iter()
                .filter(|air| BaseAir::<F>::preprocessed_width(*air) != 0)
                .map(TapeAir::preprocessed_table)
                .collect()
        });
        let (pk, vk) = tracing::debug_span!("keys")
            .in_scope(|| setup_with_tables(&config, &refs, tables, &mut challenger()))
            .map_err(TapeMachineError::Setup)?;
        Ok(Self { program, airs, config, pk: Some(pk), vk })
    }

    /// The machine a verifier rebuilds from a key's parts: each table's name
    /// and log height, in the machine's order, and the preprocessed
    /// commitment setup made.  It holds no program, so it only verifies.
    ///
    /// # Errors
    /// Returns an error if a table is unknown or the configuration cannot be
    /// built for these shapes.
    pub fn from_key(key: &NodeKey, schedule: &BinarySchedule) -> Result<Self, TapeMachineError> {
        let airs = key
            .heights
            .iter()
            .map(|(name, log_height)| {
                TapeAir::shell(name, *log_height)
                    .ok_or_else(|| TapeMachineError::UnknownTable(name.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (main, preprocessed) = Self::shapes_of(&airs);
        let config =
            MachineConfig::new(&main, &preprocessed, schedule).map_err(TapeMachineError::Config)?;
        let preprocessed_log_heights = preprocessed.iter().map(TableShape::num_variables).collect();
        let refs: Vec<&TapeAir> = airs.iter().collect();
        let vk = VerifyingKey::from_commitment(
            &refs,
            Some(key.commitment.clone()),
            preprocessed_log_heights,
        );
        Ok(Self { program: Program::default(), airs, config, pk: None, vk })
    }

    /// The parts of the machine's key a verifier rebuilds it from.
    ///
    /// # Panics
    /// Panics if the machine has no preprocessed commitment, which every
    /// tape machine has.
    #[must_use]
    pub fn key(&self) -> NodeKey {
        NodeKey {
            heights: self
                .airs
                .iter()
                .map(|air| (air.name().to_string(), air.log_height()))
                .collect(),
            commitment: self
                .vk
                .preprocessed_commitment()
                .expect("a tape machine commits its program")
                .clone(),
        }
    }

    /// The log height and width of each table of `program`'s machine, by
    /// name, with no key built.
    #[must_use]
    pub fn table_shapes(program: &Program) -> Vec<(&'static str, usize, usize)> {
        Self::airs_of(program)
            .iter()
            .map(|air| (air.name(), air.log_height(), BaseAir::<F>::width(air)))
            .collect()
    }

    /// The tables of `program`'s machine.
    fn airs_of(program: &Program) -> Vec<TapeAir> {
        let mut airs = vec![
            TapeAir::Ledger(LedgerAir::new(program)),
            TapeAir::Arith(ArithAir::new(program)),
            TapeAir::Rewire(RewireAir::new(program)),
            TapeAir::Gather(RewireAir::new(program)),
            TapeAir::Hash(HashAir::new(program)),
            TapeAir::Rounds(RoundsAir::new(program.compressions.len())),
        ];
        if !program.kb.is_empty() {
            airs.push(TapeAir::Kb(KbAir::new(program)));
        }
        if select::selects(program).next().is_some() {
            airs.push(TapeAir::Select(SelectAir::new(program)));
        }
        airs.push(TapeAir::Public(PublicAir::new(program)));
        airs
    }

    /// The machine of `program` under `schedule`, keeping only what a
    /// verifier reads.
    ///
    /// # Errors
    /// Returns an error if the configuration or the keys cannot be built.
    pub fn verifier(program: Program, schedule: &BinarySchedule) -> Result<Self, TapeMachineError> {
        Self::verifier_with_floor(program, schedule, &[])
    }

    /// [`Self::verifier`] with every table at least as tall as `floor` names.
    ///
    /// # Errors
    /// Returns an error if the configuration or the keys cannot be built.
    pub fn verifier_with_floor(
        program: Program,
        schedule: &BinarySchedule,
        floor: &[(&str, usize)],
    ) -> Result<Self, TapeMachineError> {
        let mut machine = Self::new_with_floor(program, schedule, floor)?;
        machine.drop_proving_key();
        Ok(machine)
    }

    /// Keep only what a verifier reads, once the machine has proved what it
    /// will: the proving key holds the preprocessed commitment's prover data.
    pub fn drop_proving_key(&mut self) {
        self.pk = None;
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
                        TapeAir::Public(_) => public,
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
        self.prove_on(tape, inputs, &HostProver)
    }

    /// [`Self::prove`] on `backend`.
    ///
    /// # Errors
    /// As [`Self::prove`].
    pub fn prove_on(
        &self,
        tape: &Tape,
        inputs: &[F],
        backend: &dyn TapeBackend,
    ) -> Result<MachineProof, TapeMachineError> {
        let values = tape.run(inputs).map_err(TapeMachineError::Run)?;
        self.prove_values_on(&values, &self.public_values(inputs), backend)
    }

    /// The configuration the machine proves under.
    #[must_use]
    pub const fn config(&self) -> &MachineConfig {
        &self.config
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
        self.prove_values_on(values, public, &HostProver)
    }

    /// [`Self::prove_values`] on `backend`.
    ///
    /// # Errors
    /// As [`Self::prove_values`].
    pub fn prove_values_on(
        &self,
        values: &[F],
        public: &[F; MAX_PUBLIC],
        backend: &dyn TapeBackend,
    ) -> Result<MachineProof, TapeMachineError> {
        let pk = self.pk.as_ref().ok_or(TapeMachineError::NoProvingKey)?;
        let owned =
            tracing::info_span!("main tables").in_scope(|| self.main_tables(values, public, backend));
        let instances = ProverInstances::new(
            self.airs
                .iter()
                .zip(owned)
                .map(|(air, table)| {
                    let public_values: &[F] = match air {
                        TapeAir::Public(_) => public,
                        _ => &[],
                    };
                    ProverInstance::new(air, table, pk, public_values)
                })
                .collect(),
        );
        let proof = if let Some(device) = backend.zerocheck_device() {
            prove_on::<_, _, DeviceBackend<F, F>, _>(
                &self.config,
                instances,
                0,
                &mut backend.challenger(),
                &DeviceBackend(device),
                backend,
            )
        } else if p3_binary_field::poly_basis::HAS_HARDWARE_CLMUL {
            prove_on::<_, _, ReprBackend<BinaryField2, Ghash128, true>, _>(
                &self.config,
                instances,
                0,
                &mut backend.challenger(),
                &ReprBackend::default(),
                backend,
            )
        } else {
            prove_on::<_, _, SubfieldBackend<BinaryField2>, _>(
                &self.config,
                instances,
                0,
                &mut backend.challenger(),
                &SubfieldBackend::default(),
                backend,
            )
        };
        proof.map_err(TapeMachineError::Prove)
    }

    /// Every table's witness for a run with these values.
    fn main_tables(
        &self,
        values: &[F],
        public: &[F; MAX_PUBLIC],
        backend: &dyn TapeBackend,
    ) -> Vec<Table<F>> {
        let states = tracing::info_span!("compression states")
            .in_scope(|| self.program.compression_states(values));
        let round_inputs = HashAir::round_inputs(&self.program, &states);
        let (mut rounds_table, finals) = self
            .airs
            .iter()
            .find_map(|air| match air {
                TapeAir::Rounds(rounds) => Some(
                    tracing::info_span!("main table", air = "rounds")
                        .in_scope(|| backend.rounds_table(rounds, &round_inputs)),
                ),
                _ => None,
            })
            .map(|(table, finals)| (Some(table), finals))
            .expect("the machine has a round table");
        self.airs
            .iter()
            .map(|air| {
                let name = match air {
                    TapeAir::Ledger(_) => "ledger",
                    TapeAir::Arith(_) => "arith",
                    TapeAir::Rewire(_) => "rewire",
                    TapeAir::Gather(_) => "gather",
                    TapeAir::Hash(_) => "hash",
                    TapeAir::Rounds(_) => "rounds taken",
                    TapeAir::Kb(_) => "kb",
                    TapeAir::Select(_) => "select",
                    TapeAir::Public(_) => "public",
                };
                tracing::info_span!("main table", air = name).in_scope(|| match air {
                    TapeAir::Ledger(a) => a.main_table(&self.program, values),
                    TapeAir::Arith(a) => backend.arith_table(a, &self.program, values),
                    TapeAir::Rewire(a) => a.main_table(&self.program, values),
                    TapeAir::Gather(a) => a.main_table(&self.program, values),
                    TapeAir::Hash(a) => a.main_table(&self.program, values, &states, &finals),
                    TapeAir::Rounds(_) => rounds_table.take().expect("one round table"),
                    TapeAir::Kb(a) => backend.kb_table(a, &self.program, values),
                    TapeAir::Select(a) => a.main_table(&self.program, values),
                    TapeAir::Public(a) => a.main_table(public),
                })
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
        let mains = self.main_tables(values, public, &HostProver);
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
                    TapeAir::Public(_) => public,
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

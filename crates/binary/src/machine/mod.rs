//! The recursion machine over bits: the tables that prove one execution of
//! a recursion program, under the stage.
//!
//! The tables are those of the recursion VM re-arithmetised over bits, tied
//! together by two channels: every table that computes a cell pushes it
//! once on [`bits::WRITE`], and every operand read pulls it from
//! [`bits::MEMORY`]; the [`ledger::LedgerAir`] bridges the two, one row per
//! read.  The program fixes every address, flag and multiplicity, so those
//! are preprocessed columns, committed in the verifying key.

pub mod alu_base;
pub mod alu_ext;
pub mod bits;
pub mod ledger;
pub mod memory;
pub mod mul;
pub mod poseidon2;
pub mod public_values;
pub mod select;

use p3_air::{Air, BaseAir};
use p3_binary_field::{BinaryField2, Ghash128};
use p3_field::Field;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_multi_stark::config::{PcsError, PcsProverError};
use p3_multi_stark::{
    prove_with_backend, setup, verify, ProverInstance, ProverInstances, ProvingError, ProvingKey,
    ReprBackend, SubfieldBackend, VerificationError, VerifierInstance, VerifierInstances,
    VerifyingKey,
};
use p3_sumcheck::layout::Table;
use p3_sumcheck::TableShape;
use zkm_recursion_core::{ExecutionRecord, Instruction, RecursionProgram, DIGEST_SIZE};

use self::alu_base::BaseAluAir;
use self::alu_ext::ExtAluAir;
use self::bits::Cell;
use self::ledger::LedgerAir;
use self::memory::{MemoryConstAir, MemoryVarAir};
use self::mul::MulAir;
use self::poseidon2::{Permutations, Poseidon2ExternalAir, Poseidon2InternalAir, Poseidon2IoAir};
use self::public_values::{public_value, PublicValuesAir};
use self::select::SelectAir;
use crate::config::{MachineConfig, MachineConfigError, MachineProof};
use crate::machine_builder::MachineBuilder;
use crate::{challenger, BinarySchedule, F};

/// One table of the machine.
pub enum RecursionAir {
    Ledger(LedgerAir),
    MemoryConst(MemoryConstAir),
    MemoryVar(MemoryVarAir),
    BaseAlu(BaseAluAir),
    ExtAlu(ExtAluAir),
    Select(SelectAir),
    Poseidon2Io(Poseidon2IoAir),
    Poseidon2External(Poseidon2ExternalAir),
    Poseidon2Internal(Poseidon2InternalAir),
    PublicValues(PublicValuesAir),
    Mul(MulAir),
}

impl RecursionAir {
    /// The log height of the table.
    #[must_use]
    pub fn log_height(&self) -> usize {
        match self {
            Self::Ledger(air) => air.log_height(),
            Self::MemoryConst(air) => air.log_height(),
            Self::MemoryVar(air) => air.log_height(),
            Self::BaseAlu(air) => air.log_height(),
            Self::ExtAlu(air) => air.log_height(),
            Self::Select(air) => air.log_height(),
            Self::Poseidon2Io(air) => air.log_height(),
            Self::Poseidon2External(air) => air.log_height(),
            Self::Poseidon2Internal(air) => air.log_height(),
            Self::PublicValues(air) => air.log_height(),
            Self::Mul(air) => air.log_height(),
        }
    }

    /// The name of the table.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ledger(_) => "Ledger",
            Self::MemoryConst(_) => "MemoryConst",
            Self::MemoryVar(_) => "MemoryVar",
            Self::BaseAlu(_) => "BaseAlu",
            Self::ExtAlu(_) => "ExtAlu",
            Self::Select(_) => "Select",
            Self::Poseidon2Io(_) => "Poseidon2Io",
            Self::Poseidon2External(_) => "Poseidon2External",
            Self::Poseidon2Internal(_) => "Poseidon2Internal",
            Self::PublicValues(_) => "PublicValues",
            Self::Mul(_) => "Mul",
        }
    }

    /// The writes `(address, reads)` of the table that are read, in order.
    fn writes(&self) -> Vec<(u32, u32)> {
        match self {
            Self::Ledger(_) => Vec::new(),
            Self::MemoryConst(air) => air.writes().to_vec(),
            Self::MemoryVar(air) => air.writes(),
            Self::BaseAlu(air) => air.writes(),
            Self::ExtAlu(air) => air.writes(),
            Self::Select(air) => air.writes(),
            Self::Poseidon2Io(air) => air.writes(),
            Self::Poseidon2External(_)
            | Self::Poseidon2Internal(_)
            | Self::PublicValues(_)
            | Self::Mul(_) => Vec::new(),
        }
    }

    /// How many products the table asks for, fixed by the program.
    fn mul_request_count(&self) -> usize {
        match self {
            Self::BaseAlu(air) => air.instruction_count(),
            Self::ExtAlu(air) => crate::ext::EXT_MUL_REQUESTS * air.instruction_count(),
            Self::Poseidon2Io(air) => air.mul_request_count(),
            _ => 0,
        }
    }

    /// The products the table asks the multiply table for.
    fn mul_requests(&self, record: &ExecutionRecord<KoalaBear>) -> Vec<(u32, u32)> {
        match self {
            Self::BaseAlu(air) => air.mul_requests(record),
            Self::ExtAlu(air) => air.mul_requests(record),
            Self::Poseidon2Io(air) => air.mul_requests(record),
            _ => Vec::new(),
        }
    }

    /// The values of [`Self::writes`], in order.
    fn written_values(&self, record: &ExecutionRecord<KoalaBear>) -> Vec<Cell> {
        match self {
            Self::Ledger(_) => Vec::new(),
            Self::MemoryConst(air) => air.written_values(),
            Self::MemoryVar(air) => air.written_values(record),
            Self::BaseAlu(air) => air.written_values(record),
            Self::ExtAlu(air) => air.written_values(record),
            Self::Select(air) => air.written_values(record),
            Self::Poseidon2Io(air) => air.written_values(record),
            Self::Poseidon2External(_)
            | Self::Poseidon2Internal(_)
            | Self::PublicValues(_)
            | Self::Mul(_) => Vec::new(),
        }
    }

    /// The witness of the table for `record`, the ledger's being the
    /// written values and the multiply table's the products asked for.
    fn main_table(
        &self,
        record: &ExecutionRecord<KoalaBear>,
        written: &[Cell],
        requests: &[(u32, u32)],
    ) -> Table<F> {
        match self {
            Self::Ledger(air) => air.main_table(written),
            Self::MemoryConst(air) => air.main_table(),
            Self::MemoryVar(air) => air.main_table(record),
            Self::BaseAlu(air) => air.main_table(record),
            Self::ExtAlu(air) => air.main_table(record),
            Self::Select(air) => air.main_table(record),
            Self::Poseidon2Io(air) => air.main_table(record),
            Self::Poseidon2External(air) => air.main_table(record),
            Self::Poseidon2Internal(air) => air.main_table(record),
            Self::PublicValues(air) => air.main_table(record),
            Self::Mul(air) => air.main_table(requests),
        }
    }
}

impl<X: Field> BaseAir<X> for RecursionAir {
    fn width(&self) -> usize {
        match self {
            Self::Ledger(air) => BaseAir::<X>::width(air),
            Self::MemoryConst(air) => BaseAir::<X>::width(air),
            Self::MemoryVar(air) => BaseAir::<X>::width(air),
            Self::BaseAlu(air) => BaseAir::<X>::width(air),
            Self::ExtAlu(air) => BaseAir::<X>::width(air),
            Self::Select(air) => BaseAir::<X>::width(air),
            Self::Poseidon2Io(air) => BaseAir::<X>::width(air),
            Self::Poseidon2External(air) => BaseAir::<X>::width(air),
            Self::Poseidon2Internal(air) => BaseAir::<X>::width(air),
            Self::PublicValues(air) => BaseAir::<X>::width(air),
            Self::Mul(air) => BaseAir::<X>::width(air),
        }
    }

    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Ledger(air) => BaseAir::<X>::preprocessed_width(air),
            Self::MemoryConst(air) => BaseAir::<X>::preprocessed_width(air),
            Self::MemoryVar(air) => BaseAir::<X>::preprocessed_width(air),
            Self::BaseAlu(air) => BaseAir::<X>::preprocessed_width(air),
            Self::ExtAlu(air) => BaseAir::<X>::preprocessed_width(air),
            Self::Select(air) => BaseAir::<X>::preprocessed_width(air),
            Self::Poseidon2Io(air) => BaseAir::<X>::preprocessed_width(air),
            Self::Poseidon2External(air) => BaseAir::<X>::preprocessed_width(air),
            Self::Poseidon2Internal(air) => BaseAir::<X>::preprocessed_width(air),
            Self::PublicValues(air) => BaseAir::<X>::preprocessed_width(air),
            Self::Mul(air) => BaseAir::<X>::preprocessed_width(air),
        }
    }

    fn num_public_values(&self) -> usize {
        match self {
            Self::PublicValues(air) => BaseAir::<X>::num_public_values(air),
            _ => 0,
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        match self {
            Self::Ledger(air) => air.preprocessed_trace(),
            Self::MemoryConst(air) => air.preprocessed_trace(),
            Self::MemoryVar(air) => air.preprocessed_trace(),
            Self::BaseAlu(air) => air.preprocessed_trace(),
            Self::ExtAlu(air) => air.preprocessed_trace(),
            Self::Select(air) => air.preprocessed_trace(),
            Self::Poseidon2Io(air) => air.preprocessed_trace(),
            Self::Poseidon2External(air) => air.preprocessed_trace(),
            Self::Poseidon2Internal(air) => air.preprocessed_trace(),
            Self::PublicValues(air) => air.preprocessed_trace(),
            Self::Mul(air) => air.preprocessed_trace(),
        }
    }
}

impl<AB: MachineBuilder<F = F>> Air<AB> for RecursionAir {
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Ledger(air) => air.eval(builder),
            Self::MemoryConst(air) => air.eval(builder),
            Self::MemoryVar(air) => air.eval(builder),
            Self::BaseAlu(air) => air.eval(builder),
            Self::ExtAlu(air) => air.eval(builder),
            Self::Select(air) => air.eval(builder),
            Self::Poseidon2Io(air) => air.eval(builder),
            Self::Poseidon2External(air) => air.eval(builder),
            Self::Poseidon2Internal(air) => air.eval(builder),
            Self::PublicValues(air) => air.eval(builder),
            Self::Mul(air) => air.eval(builder),
        }
    }
}

/// Why a machine cannot be built or run.
#[derive(Debug)]
pub enum MachineError {
    /// The program uses an instruction the machine has no table for.
    Unsupported(&'static str),
    /// The configuration cannot be built.
    Config(MachineConfigError),
    /// The keys cannot be built.
    Setup(ProvingError<PcsProverError<MachineConfig>>),
    /// Proving failed.
    Prove(ProvingError<PcsProverError<MachineConfig>>),
    /// Verification failed.
    Verify(VerificationError<PcsError<MachineConfig>>),
}

impl core::fmt::Display for MachineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unsupported(what) => write!(f, "the binary machine has no table for {what}"),
            Self::Config(error) => write!(f, "machine configuration: {error}"),
            Self::Setup(error) => write!(f, "machine setup: {error:?}"),
            Self::Prove(error) => write!(f, "machine proving: {error:?}"),
            Self::Verify(error) => write!(f, "machine verification: {error:?}"),
        }
    }
}

impl std::error::Error for MachineError {}

/// The machine of one program: its tables, their configuration and keys.
pub struct RecursionMachine {
    airs: Vec<RecursionAir>,
    config: MachineConfig,
    pk: ProvingKey<MachineConfig>,
    vk: VerifyingKey<MachineConfig>,
}

impl RecursionMachine {
    /// The machine of `program` under `schedule`.
    pub fn new(
        program: &RecursionProgram<KoalaBear>,
        schedule: &BinarySchedule,
    ) -> Result<Self, MachineError> {
        for instruction in program.iter_instructions() {
            let unsupported = match instruction {
                Instruction::BaseAlu(_)
                | Instruction::ExtAlu(_)
                | Instruction::Select(_)
                | Instruction::Poseidon2(_)
                | Instruction::CommitPublicValues(_)
                | Instruction::Mem(_)
                | Instruction::Hint(_)
                | Instruction::HintBits(_)
                | Instruction::HintExt2Felts(_)
                | Instruction::Print(_) => continue,
                Instruction::HintAddCurve(_) => "curve hints",
                Instruction::Ext2Felts(_) => "Ext2Felts",
            };
            return Err(MachineError::Unsupported(unsupported));
        }
        let permutations = std::sync::Arc::new(Permutations::new(program));
        let tables = vec![
            RecursionAir::MemoryConst(MemoryConstAir::new(program)),
            RecursionAir::MemoryVar(MemoryVarAir::new(program)),
            RecursionAir::BaseAlu(BaseAluAir::new(program)),
            RecursionAir::ExtAlu(ExtAluAir::new(program)),
            RecursionAir::Select(SelectAir::new(program)),
            RecursionAir::Poseidon2Io(Poseidon2IoAir::new(permutations.clone())),
            RecursionAir::Poseidon2External(Poseidon2ExternalAir::new(permutations.clone())),
            RecursionAir::Poseidon2Internal(Poseidon2InternalAir::new(permutations)),
            RecursionAir::PublicValues(PublicValuesAir::new(program)),
        ];
        let writes: Vec<(u32, u32)> = tables.iter().flat_map(RecursionAir::writes).collect();
        let products = tables.iter().map(RecursionAir::mul_request_count).sum();
        let mut airs = vec![RecursionAir::Ledger(LedgerAir::new(&writes))];
        airs.extend(tables);
        airs.push(RecursionAir::Mul(MulAir::new(products)));

        let main_shapes: Vec<TableShape> = airs
            .iter()
            .map(|air| TableShape::new(air.log_height(), BaseAir::<F>::width(air)))
            .collect();
        let preprocessed_shapes: Vec<TableShape> = airs
            .iter()
            .filter(|air| BaseAir::<F>::preprocessed_width(*air) > 0)
            .map(|air| TableShape::new(air.log_height(), BaseAir::<F>::preprocessed_width(air)))
            .collect();
        let config = MachineConfig::new(&main_shapes, &preprocessed_shapes, schedule)
            .map_err(MachineError::Config)?;
        let refs: Vec<&RecursionAir> = airs.iter().collect();
        let (pk, vk) = setup(&config, &refs, &mut challenger()).map_err(MachineError::Setup)?;
        Ok(Self { airs, config, pk, vk })
    }

    /// The tables of the machine.
    #[must_use]
    pub fn airs(&self) -> &[RecursionAir] {
        &self.airs
    }

    /// The stage's public values of a program committing `digest`.
    #[must_use]
    pub fn public_values(digest: &[u32; DIGEST_SIZE]) -> [F; DIGEST_SIZE] {
        digest.map(public_value)
    }

    /// The public values of `air` given the program's `public` ones.
    fn public_of<'a>(air: &RecursionAir, public: &'a [F; DIGEST_SIZE]) -> &'a [F] {
        match air {
            RecursionAir::PublicValues(_) => public,
            _ => &[],
        }
    }

    /// Prove `record`, an execution of the machine's program.
    pub fn prove(&self, record: &ExecutionRecord<KoalaBear>) -> Result<MachineProof, MachineError> {
        let written: Vec<Cell> =
            self.airs.iter().flat_map(|air| air.written_values(record)).collect();
        let requests: Vec<(u32, u32)> =
            self.airs.iter().flat_map(|air| air.mul_requests(record)).collect();
        let public = Self::public_values(&PublicValuesAir::digest(record));
        let instances = ProverInstances::new(
            self.airs
                .iter()
                .map(|air| {
                    ProverInstance::new(
                        air,
                        air.main_table(record, &written, &requests),
                        &self.pk,
                        Self::public_of(air, &public),
                    )
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
        proof.map_err(MachineError::Prove)
    }

    /// Verify `proof` as a proof of an execution of the machine's program
    /// committing `digest`.
    pub fn verify(
        &self,
        proof: &MachineProof,
        digest: &[u32; DIGEST_SIZE],
    ) -> Result<(), MachineError> {
        let public = Self::public_values(digest);
        let instances = VerifierInstances::new(
            self.airs
                .iter()
                .map(|air| {
                    VerifierInstance::new(
                        air,
                        &self.vk,
                        air.log_height(),
                        Self::public_of(air, &public),
                    )
                })
                .collect(),
        );
        verify(&self.config, instances, proof, 0, &mut challenger()).map_err(MachineError::Verify)
    }
}

#[cfg(test)]
mod tests {
    use core::array;
    use core::borrow::Borrow;
    use std::sync::Arc;

    use p3_symmetric::Permutation;
    use zkm_recursion_core::air::{RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS};

    use p3_field::extension::BinomialExtensionField;
    use p3_field::BasedVectorSpace;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::Poseidon2InternalLayerKoalaBear;
    use zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2;
    use zkm_pcs::StarkGenericConfig;
    use zkm_recursion_core::runtime::instruction as instr;
    use zkm_recursion_core::{BaseAluOpcode, ExtAluOpcode, MemAccessKind, RawProgram, Runtime};

    use super::*;

    type EF = <KoalaBearPoseidon2 as StarkGenericConfig>::Challenge;
    const _: () = assert!(
        core::mem::size_of::<EF>() == core::mem::size_of::<BinomialExtensionField<KoalaBear, 4>>()
    );

    /// Deterministic elements below `p`.
    fn elements(n: usize) -> Vec<KoalaBear> {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        (0..n)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                KoalaBear::from_u64(state >> 33)
            })
            .collect()
    }

    /// `n` groups of the four operations on constants, each result checked
    /// against the expected constant.
    fn four_ops_program(n: usize) -> RecursionProgram<KoalaBear> {
        let values = elements(2 * n);
        let mut addr = 0u32;
        let instructions = (0..n)
            .flat_map(|i| {
                let in2 =
                    if values[2 * i + 1].is_zero() { KoalaBear::ONE } else { values[2 * i + 1] };
                let quotient = values[2 * i];
                let in1 = in2 * quotient;
                let a: Vec<u32> = (0..6).map(|x| x + addr).collect();
                addr += 6;
                [
                    instr::mem_single(MemAccessKind::Write, 4, a[0], in1),
                    instr::mem_single(MemAccessKind::Write, 4, a[1], in2),
                    instr::base_alu(BaseAluOpcode::AddF, 1, a[2], a[0], a[1]),
                    instr::mem_single(MemAccessKind::Read, 1, a[2], in1 + in2),
                    instr::base_alu(BaseAluOpcode::SubF, 1, a[3], a[0], a[1]),
                    instr::mem_single(MemAccessKind::Read, 1, a[3], in1 - in2),
                    instr::base_alu(BaseAluOpcode::MulF, 1, a[4], a[0], a[1]),
                    instr::mem_single(MemAccessKind::Read, 1, a[4], in1 * in2),
                    instr::base_alu(BaseAluOpcode::DivF, 1, a[5], a[0], a[1]),
                    instr::mem_single(MemAccessKind::Read, 1, a[5], quotient),
                ]
            })
            .collect::<Vec<_>>();
        let mut instructions = instructions;
        instructions.extend(commit(addr, [KoalaBear::ZERO; DIGEST_SIZE]));
        let mut program =
            RecursionProgram::new(RawProgram::from_linear(instructions), 0, Vec::new(), None);
        program.total_memory = program.computed_total_memory();
        program
    }

    /// `n` groups of the four extension operations and a select on each
    /// value of the bit, each result checked against the expected constant.
    fn ext_and_select_program(n: usize) -> RecursionProgram<KoalaBear> {
        let values = elements(8 * n);
        let mut addr = 0u32;
        let instructions = (0..n)
            .flat_map(|i| {
                let coefficients = |offset: usize| -> EF {
                    EF::from_basis_coefficients_fn(|k| values[8 * i + offset + k])
                };
                let quotient = coefficients(0);
                let in2 = {
                    let in2 = coefficients(4);
                    if in2.is_zero() {
                        EF::ONE
                    } else {
                        in2
                    }
                };
                let in1 = in2 * quotient;
                let bit = KoalaBear::from_bool(i % 2 == 1);
                let (f1, f2) = (values[8 * i], values[8 * i + 1]);
                let (o1, o2) = if i % 2 == 1 { (f2, f1) } else { (f1, f2) };
                let a: Vec<u32> = (0..13).map(|x| x + addr).collect();
                addr += 13;
                [
                    instr::mem_ext::<KoalaBear, EF>(MemAccessKind::Write, 4, a[0], in1),
                    instr::mem_ext::<KoalaBear, EF>(MemAccessKind::Write, 4, a[1], in2),
                    instr::ext_alu(ExtAluOpcode::AddE, 1, a[2], a[0], a[1]),
                    instr::mem_ext::<KoalaBear, EF>(MemAccessKind::Read, 1, a[2], in1 + in2),
                    instr::ext_alu(ExtAluOpcode::SubE, 1, a[3], a[0], a[1]),
                    instr::mem_ext::<KoalaBear, EF>(MemAccessKind::Read, 1, a[3], in1 - in2),
                    instr::ext_alu(ExtAluOpcode::MulE, 1, a[4], a[0], a[1]),
                    instr::mem_ext::<KoalaBear, EF>(MemAccessKind::Read, 1, a[4], in1 * in2),
                    instr::ext_alu(ExtAluOpcode::DivE, 1, a[5], a[0], a[1]),
                    instr::mem_ext::<KoalaBear, EF>(MemAccessKind::Read, 1, a[5], quotient),
                    instr::mem_single(MemAccessKind::Write, 1, a[6], bit),
                    instr::mem_single(MemAccessKind::Write, 1, a[7], f1),
                    instr::mem_single(MemAccessKind::Write, 1, a[8], f2),
                    instr::select(1, 1, a[6], a[9], a[10], a[7], a[8]),
                    instr::mem_single(MemAccessKind::Read, 1, a[9], o1),
                    instr::mem_single(MemAccessKind::Read, 1, a[10], o2),
                ]
            })
            .collect::<Vec<_>>();
        let mut instructions = instructions;
        instructions.extend(commit(addr, [KoalaBear::ZERO; DIGEST_SIZE]));
        let mut program =
            RecursionProgram::new(RawProgram::from_linear(instructions), 0, Vec::new(), None);
        program.total_memory = program.computed_total_memory();
        program
    }

    /// The instructions committing public values whose digest is `digest`,
    /// every other public value being zero, from address `base`.
    fn commit(base: u32, digest: [KoalaBear; DIGEST_SIZE]) -> Vec<Instruction<KoalaBear>> {
        let addrs: [u32; RECURSIVE_PROOF_NUM_PV_ELTS] = array::from_fn(|i| base + i as u32);
        let pv_addrs: &RecursionPublicValues<u32> = addrs.as_slice().borrow();
        let digest_addrs = pv_addrs.digest;
        let mut instructions: Vec<Instruction<KoalaBear>> = addrs
            .iter()
            .map(|&addr| {
                let word = digest_addrs.iter().position(|&d| d == addr);
                let value = word.map_or(KoalaBear::ZERO, |w| digest[w]);
                instr::mem_single(MemAccessKind::Write, u32::from(word.is_some()), addr, value)
            })
            .collect();
        instructions.push(instr::commit_public_values(pv_addrs));
        instructions
    }

    /// `n` permutations and a commitment of the last one's first eight
    /// outputs, each output checked against the VM's permutation.
    fn poseidon2_program(n: usize) -> RecursionProgram<KoalaBear> {
        let perm = zkm_pcs::inner_perm();
        let values = elements(16 * n);
        let mut addr = 0u32;
        let mut digest = [KoalaBear::ZERO; DIGEST_SIZE];
        let mut instructions = Vec::new();
        for i in 0..n {
            let input: [KoalaBear; 16] = array::from_fn(|k| values[16 * i + k]);
            let output = perm.permute(input);
            let inputs: [u32; 16] = array::from_fn(|k| addr + k as u32);
            let outputs: [u32; 16] = array::from_fn(|k| addr + 16 + k as u32);
            addr += 32;
            instructions.extend(
                (0..16).map(|k| instr::mem_single(MemAccessKind::Write, 1, inputs[k], input[k])),
            );
            instructions.push(instr::poseidon2([1; 16], outputs, inputs));
            instructions.extend(
                (0..16).map(|k| instr::mem_single(MemAccessKind::Read, 1, outputs[k], output[k])),
            );
            digest = array::from_fn(|k| output[k]);
        }
        instructions.extend(commit(addr, digest));
        let mut program =
            RecursionProgram::new(RawProgram::from_linear(instructions), 0, Vec::new(), None);
        program.total_memory = program.computed_total_memory();
        program
    }

    /// Print span timings when `RUST_LOG` asks for them.
    fn profile() {
        if std::env::var_os("RUST_LOG").is_some() {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
                .with_target(false)
                .try_init();
        }
    }

    fn run(program: &Arc<RecursionProgram<KoalaBear>>) -> ExecutionRecord<KoalaBear> {
        let mut runtime = Runtime::<KoalaBear, EF, Poseidon2InternalLayerKoalaBear<16>>::new(
            program.clone(),
            KoalaBearPoseidon2::new().perm,
        );
        runtime.run().expect("the program runs");
        runtime.record
    }

    /// The four base operations prove through the real runtime, and a
    /// record with one result or one operand changed does not.
    #[test]
    fn four_ops_prove_and_tampering_fails() {
        let program = Arc::new(four_ops_program(40));
        let record = run(&program);
        let machine = RecursionMachine::new(&program, &BinarySchedule::default()).expect("machine");
        for air in machine.airs() {
            println!(
                "{}: 2^{} rows x {} bits",
                air.name(),
                air.log_height(),
                BaseAir::<F>::width(air)
            );
        }
        let started = std::time::Instant::now();
        let proof = machine.prove(&record).expect("the execution proves");
        println!(
            "four ops x40: {} proof bytes, prove {:.1} s",
            postcard::to_allocvec(&proof).expect("a proof serializes").len(),
            started.elapsed().as_secs_f64()
        );
        let digest = PublicValuesAir::digest(&record);
        machine.verify(&proof, &digest).expect("the execution verifies");

        let mut wrong_result = record.clone();
        wrong_result.base_alu_events[0].out += KoalaBear::ONE;
        let rejected = match machine.prove(&wrong_result) {
            Err(_) => true,
            Ok(proof) => machine.verify(&proof, &digest).is_err(),
        };
        assert!(rejected, "a changed result must not verify");

        let mut wrong_operand = record;
        wrong_operand.base_alu_events[1].in1 += KoalaBear::ONE;
        let rejected = match machine.prove(&wrong_operand) {
            Err(_) => true,
            Ok(proof) => machine.verify(&proof, &digest).is_err(),
        };
        assert!(rejected, "a changed operand must not verify");
    }

    /// The extension operations and select prove through the real runtime,
    /// and a record with a swapped select output or a changed extension
    /// result does not.
    #[test]
    fn ext_and_select_prove_and_tampering_fails() {
        let program = Arc::new(ext_and_select_program(8));
        let record = run(&program);
        let machine = RecursionMachine::new(&program, &BinarySchedule::default()).expect("machine");
        for air in machine.airs() {
            println!(
                "{}: 2^{} rows x {} bits",
                air.name(),
                air.log_height(),
                BaseAir::<F>::width(air)
            );
        }
        let started = std::time::Instant::now();
        let proof = machine.prove(&record).expect("the execution proves");
        println!(
            "ext and select x8: {} proof bytes, prove {:.1} s",
            postcard::to_allocvec(&proof).expect("a proof serializes").len(),
            started.elapsed().as_secs_f64()
        );
        let digest = PublicValuesAir::digest(&record);
        machine.verify(&proof, &digest).expect("the execution verifies");

        let mut swapped = record.clone();
        let event = &mut swapped.select_events[0];
        core::mem::swap(&mut event.out1, &mut event.out2);
        let rejected = match machine.prove(&swapped) {
            Err(_) => true,
            Ok(proof) => machine.verify(&proof, &digest).is_err(),
        };
        assert!(rejected, "a swapped select output must not verify");

        let mut wrong_result = record;
        wrong_result.ext_alu_events[2].out.0[1] += KoalaBear::ONE;
        let rejected = match machine.prove(&wrong_result) {
            Err(_) => true,
            Ok(proof) => machine.verify(&proof, &digest).is_err(),
        };
        assert!(rejected, "a changed extension result must not verify");
    }

    /// The extension and select program at the scale `ZIREN_BINARY_SCALE`
    /// groups, for measuring the prover; the proof is verified.
    #[test]
    #[ignore]
    fn scale_ext_and_select() {
        profile();
        let n: usize =
            std::env::var("ZIREN_BINARY_SCALE").ok().and_then(|v| v.parse().ok()).unwrap_or(1024);
        let program = Arc::new(ext_and_select_program(n));
        let record = run(&program);
        let started = std::time::Instant::now();
        let machine = RecursionMachine::new(&program, &BinarySchedule::default()).expect("machine");
        println!("machine setup {:.1} s", started.elapsed().as_secs_f64());
        for air in machine.airs() {
            println!(
                "{}: 2^{} rows x {} bits",
                air.name(),
                air.log_height(),
                BaseAir::<F>::width(air)
            );
        }
        let started = std::time::Instant::now();
        let proof = machine.prove(&record).expect("the execution proves");
        println!(
            "scale {n}: {} proof bytes, prove {:.1} s",
            postcard::to_allocvec(&proof).expect("a proof serializes").len(),
            started.elapsed().as_secs_f64()
        );
        let started = std::time::Instant::now();
        machine.verify(&proof, &PublicValuesAir::digest(&record)).expect("the execution verifies");
        println!("verify {:.3} s", started.elapsed().as_secs_f64());
    }

    /// Permutations and the digest commitment prove through the real
    /// runtime; the proof does not verify against another digest, and a
    /// record with a changed permutation output does not prove.
    #[test]
    fn poseidon2_and_public_values_prove_and_tampering_fails() {
        profile();
        let program = Arc::new(poseidon2_program(3));
        let record = run(&program);
        let machine = RecursionMachine::new(&program, &BinarySchedule::default()).expect("machine");
        for air in machine.airs() {
            println!(
                "{}: 2^{} rows x {} bits",
                air.name(),
                air.log_height(),
                BaseAir::<F>::width(air)
            );
        }
        let started = std::time::Instant::now();
        let proof = machine.prove(&record).expect("the execution proves");
        println!(
            "poseidon2 x3: {} proof bytes, prove {:.1} s",
            postcard::to_allocvec(&proof).expect("a proof serializes").len(),
            started.elapsed().as_secs_f64()
        );
        let digest = PublicValuesAir::digest(&record);
        let started = std::time::Instant::now();
        machine.verify(&proof, &digest).expect("the execution verifies");
        println!("verify {:.3} s", started.elapsed().as_secs_f64());

        let mut other = digest;
        other[3] ^= 1;
        assert!(machine.verify(&proof, &other).is_err(), "another digest must not verify");

        let mut wrong_output = record;
        wrong_output.poseidon2_events[1].output[5] += KoalaBear::ONE;
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            match machine.prove(&wrong_output) {
                Err(_) => true,
                Ok(proof) => machine.verify(&proof, &digest).is_err(),
            }
        }))
        .unwrap_or(true);
        assert!(rejected, "a changed permutation output must not verify");
    }
}

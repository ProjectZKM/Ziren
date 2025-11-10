use crate::{
    global::GlobalChip,
    memory::{MemoryChipType, MemoryLocalChip, NUM_LOCAL_MEMORY_ENTRIES_PER_ROW},
    syscall::precompiles::{
        fptower::{Fp2AddSubAssignChip, Fp2MulAssignChip, FpOpChip},
        poseidon2::Poseidon2PermuteChip,
    },
};
use core::fmt;
use hashbrown::{HashMap, HashSet};
use itertools::Itertools;
pub use mips_chips::*;
use p3_field::PrimeField32;
use strum_macros::{EnumDiscriminants, EnumIter};
use zkm_core_executor::events::PrecompileEvent;
use zkm_core_executor::{
    events::PrecompileLocalMemory, syscalls::SyscallCode, ExecutionRecord, MipsAirId, Program,
};
use zkm_curves::weierstrass::{bls12_381::Bls12381BaseField, bn254::Bn254BaseField};
use zkm_stark::{
    air::{LookupScope, MachineAir, ZKM_PROOF_NUM_PV_ELTS},
    Chip, LookupKind, StarkGenericConfig, StarkMachine,
};

/// A module for importing all the different MIPS chips.
pub(crate) mod mips_chips {
    pub use crate::{
        alu::{
            AddSubChip, BitwiseChip, CloClzChip, DivRemChip, LtChip, MulChip, ShiftLeft,
            ShiftRightChip,
        },
        bytes::ByteChip,
        control_flow::{BranchChip, JumpChip},
        cpu::CpuChip,
        memory::{MemoryGlobalChip, MemoryInstructionsChip},
        misc::{MiscInstrsChip, MovCondChip},
        program::ProgramChip,
        syscall::{
            chip::SyscallChip,
            instructions::SyscallInstrsChip,
            precompiles::{
                edwards::{EdAddAssignChip, EdDecompressChip},
                keccak_sponge::KeccakSpongeChip,
                sha256::{ShaCompressChip, ShaExtendChip},
                sys_linux::SysLinuxChip,
                u256x2048_mul::U256x2048MulChip,
                uint256::Uint256MulChip,
                weierstrass::{
                    WeierstrassAddAssignChip, WeierstrassDecompressChip,
                    WeierstrassDoubleAssignChip,
                },
            },
        },
    };
    pub use zkm_curves::{
        edwards::{ed25519::Ed25519Parameters, EdwardsCurve},
        weierstrass::{
            bls12_381::Bls12381Parameters, bn254::Bn254Parameters, secp256k1::Secp256k1Parameters,
            secp256r1::Secp256r1Parameters, SwCurve,
        },
    };
}

/// The maximum log number of shards in core.
pub const MAX_LOG_NUMBER_OF_SHARDS: usize = 16;

/// The maximum number of shards in core.
pub const MAX_NUMBER_OF_SHARDS: usize = 1 << MAX_LOG_NUMBER_OF_SHARDS;

/// An AIR for encoding MIPS execution.
///
/// This enum contains all the different AIRs that are used in the Ziren IOP. Each variant is
/// a different AIR that is used to encode a different part of the Ziren execution, and the
/// different AIR variants have a joint lookup argument.
#[derive(zkm_derive::MachineAir, EnumDiscriminants)]
#[strum_discriminants(derive(Hash, EnumIter))]
pub enum MipsAir<F: PrimeField32> {
    /// An AIR that contains a preprocessed program table and a lookup for the instructions.
    Program(ProgramChip),
    /// An AIR for the MIPS CPU. Each row represents a cpu cycle.
    Cpu(CpuChip),
    /// An AIR for the MIPS Add and SUB instruction.
    Add(AddSubChip),
    /// An AIR for MIPS Bitwise instructions.
    Bitwise(BitwiseChip),
    /// An AIR for MIPS Mul instruction.
    Mul(MulChip),
    /// An AIR for MIPS Div and Rem instructions.
    DivRem(DivRemChip),
    /// An AIR for MIPS Lt instruction.
    Lt(LtChip),
    /// An AIR for MIPS CLO and CLZ instruction.
    CloClz(CloClzChip),
    /// An AIR for MIPS SLL instruction.
    ShiftLeft(ShiftLeft),
    /// An AIR for MIPS SRL and SRA instruction.
    ShiftRight(ShiftRightChip),
    /// A lookup table for byte operations.
    ByteLookup(ByteChip<F>),
    /// An AIR for MIPS Branch instructions.
    Branch(BranchChip),
    /// An AIR for MIPS Jump instructions.
    Jump(JumpChip),
    /// An AIR for MIPS memory instructions.
    MemoryInstrs(MemoryInstructionsChip),
    /// An AIR for MIPS mov condition instructions.
    MovCond(MovCondChip),
    /// An AIR for MIPS misc instructions.
    MiscInstrs(MiscInstrsChip),
    /// An AIR for MIPS syscall instructions.
    SyscallInstrs(SyscallInstrsChip),
    /// A table for initializing the global memory state.
    MemoryGlobalInit(MemoryGlobalChip),
    /// A table for finalizing the global memory state.
    MemoryGlobalFinal(MemoryGlobalChip),
    /// A table for the local memory state.
    MemoryLocal(MemoryLocalChip),
    /// A table for all the syscall invocations.
    SyscallCore(SyscallChip),
    /// A table for all the precompile invocations.
    SyscallPrecompile(SyscallChip),
    /// A table for all the global lookups.
    Global(GlobalChip),
    /// A precompile for sha256 extend.
    Sha256Extend(ShaExtendChip),
    /// A precompile for sha256 compress.
    Sha256Compress(ShaCompressChip),
    /// A precompile for addition on the Elliptic curve ed25519.
    Ed25519Add(EdAddAssignChip<EdwardsCurve<Ed25519Parameters>>),
    /// A precompile for decompressing a point on the Edwards curve ed25519.
    Ed25519Decompress(EdDecompressChip<Ed25519Parameters>),
    /// A precompile for decompressing a point on the K256 curve.
    K256Decompress(WeierstrassDecompressChip<SwCurve<Secp256k1Parameters>>),
    /// A precompile for decompressing a point on the P256 curve.
    P256Decompress(WeierstrassDecompressChip<SwCurve<Secp256r1Parameters>>),
    /// A precompile for addition on the Elliptic curve secp256k1.
    Secp256k1Add(WeierstrassAddAssignChip<SwCurve<Secp256k1Parameters>>),
    /// A precompile for doubling a point on the Elliptic curve secp256k1.
    Secp256k1Double(WeierstrassDoubleAssignChip<SwCurve<Secp256k1Parameters>>),
    /// A precompile for addition on the Elliptic curve secp256r1.
    Secp256r1Add(WeierstrassAddAssignChip<SwCurve<Secp256r1Parameters>>),
    /// A precompile for doubling a point on the Elliptic curve secp256r1.
    Secp256r1Double(WeierstrassDoubleAssignChip<SwCurve<Secp256r1Parameters>>),
    /// A precompile for the Poseidon2 permutation
    Poseidon2Permute(Poseidon2PermuteChip),
    /// A precompile for the Keccak Sponge
    KeccakSponge(KeccakSpongeChip),
    /// A precompile for addition on the Elliptic curve bn254.
    Bn254Add(WeierstrassAddAssignChip<SwCurve<Bn254Parameters>>),
    /// A precompile for doubling a point on the Elliptic curve bn254.
    Bn254Double(WeierstrassDoubleAssignChip<SwCurve<Bn254Parameters>>),
    /// A precompile for addition on the Elliptic curve bls12_381.
    Bls12381Add(WeierstrassAddAssignChip<SwCurve<Bls12381Parameters>>),
    /// A precompile for doubling a point on the Elliptic curve bls12_381.
    Bls12381Double(WeierstrassDoubleAssignChip<SwCurve<Bls12381Parameters>>),
    /// A precompile for uint256 mul.
    Uint256Mul(Uint256MulChip),
    /// A precompile for u256x2048 mul.
    U256x2048Mul(U256x2048MulChip),
    /// A precompile for decompressing a point on the BLS12-381 curve.
    Bls12381Decompress(WeierstrassDecompressChip<SwCurve<Bls12381Parameters>>),
    /// A precompile for BLS12-381 fp operation.
    Bls12381Fp(FpOpChip<Bls12381BaseField>),
    /// A precompile for BLS12-381 fp2 multiplication.
    Bls12381Fp2Mul(Fp2MulAssignChip<Bls12381BaseField>),
    /// A precompile for BLS12-381 fp2 addition/subtraction.
    Bls12381Fp2AddSub(Fp2AddSubAssignChip<Bls12381BaseField>),
    /// A precompile for BN-254 fp operation.
    Bn254Fp(FpOpChip<Bn254BaseField>),
    /// A precompile for BN-254 fp2 multiplication.
    Bn254Fp2Mul(Fp2MulAssignChip<Bn254BaseField>),
    /// A precompile for BN-254 fp2 addition/subtraction.
    Bn254Fp2AddSub(Fp2AddSubAssignChip<Bn254BaseField>),
    /// A precompile for Linux Syscall.
    SysLinux(SysLinuxChip),
}

impl<F: PrimeField32> MipsAir<F> {
    pub fn machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
        let chips = Self::chips();
        StarkMachine::new(config, chips, ZKM_PROOF_NUM_PV_ELTS)
    }

    /// Get all the different MIPS AIRs.
    pub fn chips() -> Vec<Chip<F, Self>> {
        let (chips, _) = Self::get_chips_and_costs();
        chips
    }

    /// Get all the costs of the different MIPS AIRs.
    pub fn costs() -> HashMap<String, u64> {
        let (_, costs) = Self::get_chips_and_costs();
        costs
    }

    /// Get all the different MIPS AIRs and their costs.
    pub fn get_airs_and_costs() -> (Vec<Self>, HashMap<String, u64>) {
        let (chips, costs) = Self::get_chips_and_costs();
        (chips.into_iter().map(|chip| chip.into_inner()).collect(), costs)
    }

    /// Get all the different MIPS chips and their costs.
    pub fn get_chips_and_costs() -> (Vec<Chip<F, Self>>, HashMap<String, u64>) {
        let mut costs: HashMap<String, u64> = HashMap::new();

        // The order of the chips is used to determine the order of trace generation.
        let mut chips = vec![];
        let cpu = Chip::new(MipsAir::Cpu(CpuChip::default()));
        costs.insert(cpu.name(), cpu.cost());
        chips.push(cpu);

        let program = Chip::new(MipsAir::Program(ProgramChip::default()));
        costs.insert(program.name(), program.cost());
        chips.push(program);

        let sha_extend = Chip::new(MipsAir::Sha256Extend(ShaExtendChip::default()));
        costs.insert(sha_extend.name(), 48 * sha_extend.cost());
        chips.push(sha_extend);

        let sha_compress = Chip::new(MipsAir::Sha256Compress(ShaCompressChip::default()));
        costs.insert(sha_compress.name(), 80 * sha_compress.cost());
        chips.push(sha_compress);

        let ed_add_assign = Chip::new(MipsAir::Ed25519Add(EdAddAssignChip::<
            EdwardsCurve<Ed25519Parameters>,
        >::new()));
        costs.insert(ed_add_assign.name(), ed_add_assign.cost());
        chips.push(ed_add_assign);

        let ed_decompress =
            Chip::new(MipsAir::Ed25519Decompress(EdDecompressChip::<Ed25519Parameters>::default()));
        costs.insert(ed_decompress.name(), ed_decompress.cost());
        chips.push(ed_decompress);

        let k256_decompress = Chip::new(MipsAir::K256Decompress(WeierstrassDecompressChip::<
            SwCurve<Secp256k1Parameters>,
        >::with_lsb_rule()));
        costs.insert(k256_decompress.name(), k256_decompress.cost());
        chips.push(k256_decompress);

        let secp256k1_add_assign = Chip::new(MipsAir::Secp256k1Add(WeierstrassAddAssignChip::<
            SwCurve<Secp256k1Parameters>,
        >::new()));
        costs.insert(secp256k1_add_assign.name(), secp256k1_add_assign.cost());
        chips.push(secp256k1_add_assign);

        let secp256k1_double_assign =
            Chip::new(MipsAir::Secp256k1Double(WeierstrassDoubleAssignChip::<
                SwCurve<Secp256k1Parameters>,
            >::new()));
        costs.insert(secp256k1_double_assign.name(), secp256k1_double_assign.cost());
        chips.push(secp256k1_double_assign);

        let p256_decompress = Chip::new(MipsAir::P256Decompress(WeierstrassDecompressChip::<
            SwCurve<Secp256r1Parameters>,
        >::with_lsb_rule()));
        costs.insert(p256_decompress.name(), p256_decompress.cost());
        chips.push(p256_decompress);

        let secp256r1_add_assign = Chip::new(MipsAir::Secp256r1Add(WeierstrassAddAssignChip::<
            SwCurve<Secp256r1Parameters>,
        >::new()));
        costs.insert(secp256r1_add_assign.name(), secp256r1_add_assign.cost());
        chips.push(secp256r1_add_assign);

        let secp256r1_double_assign =
            Chip::new(MipsAir::Secp256r1Double(WeierstrassDoubleAssignChip::<
                SwCurve<Secp256r1Parameters>,
            >::new()));
        costs.insert(secp256r1_double_assign.name(), secp256r1_double_assign.cost());
        chips.push(secp256r1_double_assign);

        let poseidon2_permute = Chip::new(MipsAir::Poseidon2Permute(Poseidon2PermuteChip::new()));
        costs.insert(poseidon2_permute.name(), poseidon2_permute.cost());
        chips.push(poseidon2_permute);

        let keccak_sponge = Chip::new(MipsAir::KeccakSponge(KeccakSpongeChip::new()));
        costs.insert(keccak_sponge.name(), 24 * keccak_sponge.cost());
        chips.push(keccak_sponge);

        let bn254_add_assign = Chip::new(MipsAir::Bn254Add(WeierstrassAddAssignChip::<
            SwCurve<Bn254Parameters>,
        >::new()));
        costs.insert(bn254_add_assign.name(), bn254_add_assign.cost());
        chips.push(bn254_add_assign);

        let bn254_double_assign = Chip::new(MipsAir::Bn254Double(WeierstrassDoubleAssignChip::<
            SwCurve<Bn254Parameters>,
        >::new()));
        costs.insert(bn254_double_assign.name(), bn254_double_assign.cost());
        chips.push(bn254_double_assign);

        let bls12381_add = Chip::new(MipsAir::Bls12381Add(WeierstrassAddAssignChip::<
            SwCurve<Bls12381Parameters>,
        >::new()));
        costs.insert(bls12381_add.name(), bls12381_add.cost());
        chips.push(bls12381_add);

        let bls12381_double = Chip::new(MipsAir::Bls12381Double(WeierstrassDoubleAssignChip::<
            SwCurve<Bls12381Parameters>,
        >::new()));
        costs.insert(bls12381_double.name(), bls12381_double.cost());
        chips.push(bls12381_double);

        let uint256_mul = Chip::new(MipsAir::Uint256Mul(Uint256MulChip::default()));
        costs.insert(uint256_mul.name(), uint256_mul.cost());
        chips.push(uint256_mul);

        let u256x2048_mul = Chip::new(MipsAir::U256x2048Mul(U256x2048MulChip::default()));
        costs.insert(u256x2048_mul.name(), u256x2048_mul.cost());
        chips.push(u256x2048_mul);

        let bls12381_fp = Chip::new(MipsAir::Bls12381Fp(FpOpChip::<Bls12381BaseField>::new()));
        costs.insert(bls12381_fp.name(), bls12381_fp.cost());
        chips.push(bls12381_fp);

        let bls12381_fp2_addsub =
            Chip::new(MipsAir::Bls12381Fp2AddSub(Fp2AddSubAssignChip::<Bls12381BaseField>::new()));
        costs.insert(bls12381_fp2_addsub.name(), bls12381_fp2_addsub.cost());
        chips.push(bls12381_fp2_addsub);

        let bls12381_fp2_mul =
            Chip::new(MipsAir::Bls12381Fp2Mul(Fp2MulAssignChip::<Bls12381BaseField>::new()));
        costs.insert(bls12381_fp2_mul.name(), bls12381_fp2_mul.cost());
        chips.push(bls12381_fp2_mul);

        let bn254_fp = Chip::new(MipsAir::Bn254Fp(FpOpChip::<Bn254BaseField>::new()));
        costs.insert(bn254_fp.name(), bn254_fp.cost());
        chips.push(bn254_fp);

        let bn254_fp2_addsub =
            Chip::new(MipsAir::Bn254Fp2AddSub(Fp2AddSubAssignChip::<Bn254BaseField>::new()));
        costs.insert(bn254_fp2_addsub.name(), bn254_fp2_addsub.cost());
        chips.push(bn254_fp2_addsub);

        let bn254_fp2_mul =
            Chip::new(MipsAir::Bn254Fp2Mul(Fp2MulAssignChip::<Bn254BaseField>::new()));
        costs.insert(bn254_fp2_mul.name(), bn254_fp2_mul.cost());
        chips.push(bn254_fp2_mul);

        let bls12381_decompress =
            Chip::new(MipsAir::Bls12381Decompress(WeierstrassDecompressChip::<
                SwCurve<Bls12381Parameters>,
            >::with_lexicographic_rule()));
        costs.insert(bls12381_decompress.name(), bls12381_decompress.cost());
        chips.push(bls12381_decompress);

        let syscall_core = Chip::new(MipsAir::SyscallCore(SyscallChip::core()));
        costs.insert(syscall_core.name(), syscall_core.cost());
        chips.push(syscall_core);

        let syscall_precompile = Chip::new(MipsAir::SyscallPrecompile(SyscallChip::precompile()));
        costs.insert(syscall_precompile.name(), syscall_precompile.cost());
        chips.push(syscall_precompile);

        let div_rem = Chip::new(MipsAir::DivRem(DivRemChip::default()));
        costs.insert(div_rem.name(), div_rem.cost());
        chips.push(div_rem);

        let add_sub = Chip::new(MipsAir::Add(AddSubChip::default()));
        costs.insert(add_sub.name(), add_sub.cost());
        chips.push(add_sub);

        let bitwise = Chip::new(MipsAir::Bitwise(BitwiseChip::default()));
        costs.insert(bitwise.name(), bitwise.cost());
        chips.push(bitwise);

        let mul = Chip::new(MipsAir::Mul(MulChip::default()));
        costs.insert(mul.name(), mul.cost());
        chips.push(mul);

        let shift_right = Chip::new(MipsAir::ShiftRight(ShiftRightChip::default()));
        costs.insert(shift_right.name(), shift_right.cost());
        chips.push(shift_right);

        let shift_left = Chip::new(MipsAir::ShiftLeft(ShiftLeft::default()));
        costs.insert(shift_left.name(), shift_left.cost());
        chips.push(shift_left);

        let lt = Chip::new(MipsAir::Lt(LtChip::default()));
        costs.insert(lt.name(), lt.cost());
        chips.push(lt);

        let clo_clz = Chip::new(MipsAir::CloClz(CloClzChip::default()));
        costs.insert(clo_clz.name(), clo_clz.cost());
        chips.push(clo_clz);

        let branch = Chip::new(MipsAir::Branch(BranchChip::default()));
        costs.insert(branch.name(), branch.cost());
        chips.push(branch);

        let jump = Chip::new(MipsAir::Jump(JumpChip::default()));
        costs.insert(jump.name(), jump.cost());
        chips.push(jump);

        let syscall_instrs = Chip::new(MipsAir::SyscallInstrs(SyscallInstrsChip::default()));
        costs.insert(syscall_instrs.name(), syscall_instrs.cost());
        chips.push(syscall_instrs);

        let memory_instructions =
            Chip::new(MipsAir::MemoryInstrs(MemoryInstructionsChip::default()));
        costs.insert(memory_instructions.name(), memory_instructions.cost());
        chips.push(memory_instructions);

        let misc_instrs = Chip::new(MipsAir::MiscInstrs(MiscInstrsChip::default()));
        costs.insert(misc_instrs.name(), misc_instrs.cost());
        chips.push(misc_instrs);

        let memory_global_init =
            Chip::new(MipsAir::MemoryGlobalInit(MemoryGlobalChip::new(MemoryChipType::Initialize)));
        costs.insert(memory_global_init.name(), memory_global_init.cost());
        chips.push(memory_global_init);

        let memory_global_finalize =
            Chip::new(MipsAir::MemoryGlobalFinal(MemoryGlobalChip::new(MemoryChipType::Finalize)));
        costs.insert(memory_global_finalize.name(), memory_global_finalize.cost());
        chips.push(memory_global_finalize);

        let memory_local = Chip::new(MipsAir::MemoryLocal(MemoryLocalChip::new()));
        costs.insert(memory_local.name(), memory_local.cost());
        chips.push(memory_local);

        let global = Chip::new(MipsAir::Global(GlobalChip));
        costs.insert(global.name(), global.cost());
        chips.push(global);

        let byte = Chip::new(MipsAir::ByteLookup(ByteChip::default()));
        costs.insert(byte.name(), byte.cost());
        chips.push(byte);

        let sys_linux = Chip::new(MipsAir::SysLinux(SysLinuxChip::default()));
        costs.insert(sys_linux.name(), sys_linux.cost());
        chips.push(sys_linux);

        let movcond_instrs = Chip::new(MipsAir::MovCond(MovCondChip::default()));
        costs.insert(movcond_instrs.name(), movcond_instrs.cost());
        chips.push(movcond_instrs);

        (chips, costs)
    }

    /// Get the heights of the preprocessed chips for a given program.
    pub(crate) fn preprocessed_heights(program: &Program) -> Vec<(MipsAirId, usize)> {
        vec![(MipsAirId::Program, program.instructions.len()), (MipsAirId::Byte, 1 << 16)]
    }

    /// Get the heights of the chips for a given execution record.
    pub fn core_heights(record: &ExecutionRecord) -> Vec<(MipsAirId, usize)> {
        vec![
            (MipsAirId::Cpu, record.cpu_events.len()),
            (MipsAirId::Branch, record.branch_events.len()),
            (MipsAirId::Jump, record.jump_events.len()),
            (MipsAirId::MovCond, record.movcond_events.len()),
            (MipsAirId::MiscInstrs, record.misc_events.len()),
            (MipsAirId::MemoryInstrs, record.memory_instr_events.len()),
            (MipsAirId::SyscallInstrs, record.syscall_events.len()),
            (MipsAirId::DivRem, record.divrem_events.len()),
            (MipsAirId::AddSub, record.add_sub_events.len()),
            (MipsAirId::Bitwise, record.bitwise_events.len()),
            (MipsAirId::Mul, record.mul_events.len()),
            (MipsAirId::ShiftRight, record.shift_right_events.len()),
            (MipsAirId::ShiftLeft, record.shift_left_events.len()),
            (MipsAirId::Lt, record.lt_events.len()),
            (
                MipsAirId::MemoryLocal,
                record
                    .get_local_mem_events()
                    .chunks(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW)
                    .into_iter()
                    .count(),
            ),
            (MipsAirId::CloClz, record.cloclz_events.len()),
            (
                MipsAirId::Global,
                2 * record.get_local_mem_events().count() + record.syscall_events.len(),
            ),
            (MipsAirId::SyscallCore, record.syscall_events.len()),
        ]
    }

    pub(crate) fn precompile_heights(
        &self,
        record: &ExecutionRecord,
    ) -> Option<(usize, usize, usize)> {
        record
            .precompile_events
            .get_events(self.syscall_code())
            .filter(|events| !events.is_empty())
            .map(|events| {
                let events_len = match self {
                    Self::KeccakSponge(_) => self.keccak_permutation_in_record(record),
                    _ => events.len(),
                };
                let num_rows = events_len * self.rows_per_event();
                (
                    num_rows,
                    events.get_local_mem_events().into_iter().count(),
                    record.global_lookup_events.len(),
                )
            })
    }

    pub(crate) fn memory_heights(record: &ExecutionRecord) -> Vec<(MipsAirId, usize)> {
        vec![
            (MipsAirId::MemoryGlobalInit, record.global_memory_initialize_events.len()),
            (MipsAirId::MemoryGlobalFinalize, record.global_memory_finalize_events.len()),
            (
                MipsAirId::Global,
                record.global_memory_finalize_events.len()
                    + record.global_memory_initialize_events.len(),
            ),
        ]
    }

    pub(crate) fn get_all_core_airs() -> Vec<Self> {
        vec![
            MipsAir::Cpu(CpuChip::default()),
            MipsAir::Add(AddSubChip::default()),
            MipsAir::Bitwise(BitwiseChip::default()),
            MipsAir::Mul(MulChip::default()),
            MipsAir::DivRem(DivRemChip::default()),
            MipsAir::Lt(LtChip::default()),
            MipsAir::CloClz(CloClzChip::default()),
            MipsAir::ShiftLeft(ShiftLeft::default()),
            MipsAir::ShiftRight(ShiftRightChip::default()),
            MipsAir::Branch(BranchChip::default()),
            MipsAir::Jump(JumpChip::default()),
            MipsAir::SyscallInstrs(SyscallInstrsChip::default()),
            MipsAir::MemoryInstrs(MemoryInstructionsChip::default()),
            MipsAir::MovCond(MovCondChip::default()),
            MipsAir::MiscInstrs(MiscInstrsChip::default()),
            MipsAir::MemoryLocal(MemoryLocalChip::new()),
            MipsAir::Global(GlobalChip),
            MipsAir::SyscallCore(SyscallChip::core()),
        ]
    }

    pub(crate) fn memory_init_final_airs() -> Vec<Self> {
        vec![
            MipsAir::MemoryGlobalInit(MemoryGlobalChip::new(MemoryChipType::Initialize)),
            MipsAir::MemoryGlobalFinal(MemoryGlobalChip::new(MemoryChipType::Finalize)),
            MipsAir::Global(GlobalChip),
        ]
    }

    pub(crate) fn precompile_airs_with_memory_events_per_row() -> Vec<(Self, usize)> {
        let mut airs: HashSet<_> = Self::get_airs_and_costs().0.into_iter().collect();

        for core_air in Self::get_all_core_airs() {
            airs.remove(&core_air);
        }

        for memory_air in Self::memory_init_final_airs() {
            airs.remove(&memory_air);
        }

        airs.remove(&Self::SyscallPrecompile(SyscallChip::precompile()));

        // Remove the preprocessed chips.
        airs.remove(&Self::Program(ProgramChip::default()));
        airs.remove(&Self::ByteLookup(ByteChip::default()));

        airs.into_iter()
            .map(|air| {
                let chip = Chip::new(air);
                let local_mem_events: usize = chip
                    .sends()
                    .iter()
                    .chain(chip.receives())
                    .filter(|lookup| {
                        lookup.kind == LookupKind::Memory && lookup.scope == LookupScope::Local
                    })
                    .count();

                (chip.into_inner(), local_mem_events)
            })
            .collect()
    }

    pub(crate) fn rows_per_event(&self) -> usize {
        match self {
            Self::Sha256Compress(_) => 80,
            Self::Sha256Extend(_) => 48,
            Self::KeccakSponge(_) => 24,
            _ => 1,
        }
    }

    fn keccak_permutation_in_record(&self, record: &ExecutionRecord) -> usize {
        record
            .precompile_events
            .get_events(SyscallCode::KECCAK_SPONGE)
            .map(|events| {
                events
                    .iter()
                    .map(|(_, pre_e)| {
                        if let PrecompileEvent::KeccakSponge(event) = pre_e {
                            event.num_blocks()
                        } else {
                            unreachable!()
                        }
                    })
                    .sum::<usize>()
            })
            .unwrap_or(0)
    }

    pub(crate) fn syscall_code(&self) -> SyscallCode {
        match self {
            Self::Bls12381Add(_) => SyscallCode::BLS12381_ADD,
            Self::Bn254Add(_) => SyscallCode::BN254_ADD,
            Self::Bn254Double(_) => SyscallCode::BN254_DOUBLE,
            Self::Bn254Fp(_) => SyscallCode::BN254_FP_ADD,
            Self::Bn254Fp2AddSub(_) => SyscallCode::BN254_FP2_ADD,
            Self::Bn254Fp2Mul(_) => SyscallCode::BN254_FP2_MUL,
            Self::Ed25519Add(_) => SyscallCode::ED_ADD,
            Self::Ed25519Decompress(_) => SyscallCode::ED_DECOMPRESS,
            Self::Secp256k1Add(_) => SyscallCode::SECP256K1_ADD,
            Self::Secp256k1Double(_) => SyscallCode::SECP256K1_DOUBLE,
            Self::Secp256r1Add(_) => SyscallCode::SECP256R1_ADD,
            Self::Secp256r1Double(_) => SyscallCode::SECP256R1_DOUBLE,
            Self::Sha256Compress(_) => SyscallCode::SHA_COMPRESS,
            Self::Sha256Extend(_) => SyscallCode::SHA_EXTEND,
            Self::Uint256Mul(_) => SyscallCode::UINT256_MUL,
            Self::U256x2048Mul(_) => SyscallCode::U256XU2048_MUL,
            Self::Bls12381Decompress(_) => SyscallCode::BLS12381_DECOMPRESS,
            Self::K256Decompress(_) => SyscallCode::SECP256K1_DECOMPRESS,
            Self::P256Decompress(_) => SyscallCode::SECP256R1_DECOMPRESS,
            Self::Bls12381Double(_) => SyscallCode::BLS12381_DOUBLE,
            Self::Bls12381Fp(_) => SyscallCode::BLS12381_FP_ADD,
            Self::Bls12381Fp2Mul(_) => SyscallCode::BLS12381_FP2_MUL,
            Self::Bls12381Fp2AddSub(_) => SyscallCode::BLS12381_FP2_ADD,
            Self::Poseidon2Permute(_) => SyscallCode::POSEIDON2_PERMUTE,
            Self::KeccakSponge(_) => SyscallCode::KECCAK_SPONGE,
            Self::SysLinux(_) => SyscallCode::SYS_LINUX,
            Self::Add(_) => unreachable!("Invalid for core chip"),
            Self::Bitwise(_) => unreachable!("Invalid for core chip"),
            Self::DivRem(_) => unreachable!("Invalid for core chip"),
            Self::Cpu(_) => unreachable!("Invalid for core chip"),
            Self::MemoryGlobalInit(_) => unreachable!("Invalid for memory init/final"),
            Self::MemoryGlobalFinal(_) => unreachable!("Invalid for memory init/final"),
            Self::MemoryLocal(_) => unreachable!("Invalid for memory local"),
            Self::Global(_) => unreachable!("Invalid for global chip"),
            // Self::ProgramMemory(_) => unreachable!("Invalid for memory program"),
            Self::Program(_) => unreachable!("Invalid for core chip"),
            Self::Mul(_) => unreachable!("Invalid for core chip"),
            Self::Lt(_) => unreachable!("Invalid for core chip"),
            Self::CloClz(_) => unreachable!("Invalid for core chip"),
            Self::ShiftRight(_) => unreachable!("Invalid for core chip"),
            Self::ShiftLeft(_) => unreachable!("Invalid for core chip"),
            Self::ByteLookup(_) => unreachable!("Invalid for core chip"),
            Self::SyscallCore(_) => unreachable!("Invalid for core chip"),
            Self::SyscallPrecompile(_) => unreachable!("Invalid for syscall precompile chip"),
            Self::Branch(_) => unreachable!("Invalid for core chip"),
            Self::Jump(_) => unreachable!("Invalid for core chip"),
            Self::SyscallInstrs(_) => unreachable!("Invalid for core chip"),
            Self::MemoryInstrs(_) => unreachable!("Invalid for core chip"),
            Self::MiscInstrs(_) => unreachable!("Invalid for core chip"),
            Self::MovCond(_) => unreachable!("Invalid for core chip"),
        }
    }
}

impl<F: PrimeField32> fmt::Debug for MipsAir<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl<F: PrimeField32> PartialEq for MipsAir<F> {
    fn eq(&self, other: &Self) -> bool {
        self.name() == other.name()
    }
}

impl<F: PrimeField32> Eq for MipsAir<F> {}

impl<F: PrimeField32> core::hash::Hash for MipsAir<F> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.name().hash(state);
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
pub mod tests {
    use crate::programs::tests::other_memory_program;
    use crate::programs::tests::{
        fibonacci_program, hello_world_program, max_memory_program, sha3_chain_program,
        simple_memory_program, simple_program, ssz_withdrawals_program, unconstrained_program,
    };
    use crate::{
        io::ZKMStdin,
        mips::MipsAir,
        utils,
        utils::{prove, run_test, setup_logger},
    };

    use hashbrown::HashMap;
    use itertools::Itertools;
    use p3_koala_bear::KoalaBear;
    use strum::IntoEnumIterator;

    use zkm_core_executor::{Instruction, MipsAirId, Opcode, Program};
    use zkm_stark::air::MachineAir;
    use zkm_stark::{
        koala_bear_poseidon2::KoalaBearPoseidon2, CpuProver, StarkProvingKey, StarkVerifyingKey,
        ZKMCoreOpts,
    };

    #[test]
    fn test_primitives_and_machine_air_names_match() {
        let chips = MipsAir::<KoalaBear>::chips();
        for (a, b) in chips.iter().zip_eq(MipsAirId::iter()) {
            assert_eq!(a.name(), b.to_string());
        }
    }

    #[test]
    fn core_air_cost_consistency() {
        let file = std::fs::File::open("../executor/src/artifacts/mips_costs.json").unwrap();
        let costs: HashMap<String, u64> = serde_json::from_reader(file).unwrap();
        // Compare with costs computed by machine
        let machine_costs = MipsAir::<KoalaBear>::costs();
        log::info!("{machine_costs:?}");
        assert_eq!(costs, machine_costs);
    }

    #[test]
    fn write_core_air_costs() {
        let costs = MipsAir::<KoalaBear>::costs();
        println!("{costs:?}");
        // write to file
        // Create directory if it doesn't exist
        let dir = std::path::Path::new("../executor/src/artifacts");
        if !dir.exists() {
            std::fs::create_dir_all(dir).unwrap();
        }
        let file = std::fs::File::create(dir.join("mips_costs.json")).unwrap();
        serde_json::to_writer_pretty(file, &costs).unwrap();
    }

    #[test]
    fn test_simple_prove() {
        utils::setup_logger();
        let program = simple_program();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_beq_branching_prove() {
        utils::setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 1, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 1, false, true),
            Instruction::new(Opcode::BEQ, 29, 30, 100, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_beq_not_branching_prove() {
        utils::setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 1, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 2, false, true),
            Instruction::new(Opcode::BEQ, 29, 30, 100, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_bne_branching_prove() {
        utils::setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 1, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 2, false, true),
            Instruction::new(Opcode::BNE, 29, 30, 100, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_bne_not_branching_prove() {
        utils::setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 0, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 0, false, true),
            Instruction::new(Opcode::BNE, 29, 30, 100, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_rest_branch_prove() {
        utils::setup_logger();
        let branch_ops = [Opcode::BLTZ, Opcode::BGEZ, Opcode::BLEZ, Opcode::BGTZ];
        let operands = [0, 1, 0xFFFF_FFFF];
        for branch_op in branch_ops.iter() {
            for operand in operands.iter() {
                let instructions = vec![
                    Instruction::new(Opcode::ADD, 29, 0, *operand, false, true),
                    Instruction::new(*branch_op, 29, 0, 100, true, true),
                ];
                let program = Program::new(instructions, 0, 0);
                run_test::<CpuProver<_, _>>(program).unwrap();
            }
        }
    }

    #[test]
    fn test_shift_prove() {
        utils::setup_logger();
        let shift_ops = [Opcode::SRL, Opcode::ROR, Opcode::SRA, Opcode::SLL];
        let operands =
            [(1, 1), (1234, 5678), (0xffff, 0xffff - 1), (u32::MAX - 1, u32::MAX), (u32::MAX, 0)];
        for shift_op in shift_ops.iter() {
            for op in operands.iter() {
                let instructions = vec![
                    Instruction::new(Opcode::ADD, 29, 0, op.0, false, true),
                    Instruction::new(Opcode::ADD, 30, 0, op.1, false, true),
                    Instruction::new(*shift_op, 31, 29, 3, false, false),
                ];
                let program = Program::new(instructions, 0, 0);
                run_test::<CpuProver<_, _>>(program).unwrap();
            }
        }
    }

    #[test]
    fn test_sub_prove() {
        utils::setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
            Instruction::new(Opcode::SUB, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_add_prove() {
        setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_add_overflow_prove() {
        setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 0xEFFF_FFFF, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 2, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_mul_mod_prove() {
        utils::setup_logger();
        let mul_ops = [Opcode::MUL, Opcode::MOD, Opcode::MODU];
        let operands =
            [(1, 1), (1234, 5678), (8765, 4321), (0xffff, 0xffff - 1), (u32::MAX - 1, u32::MAX)];
        for mul_op in mul_ops.iter() {
            for operand in operands.iter() {
                let instructions = vec![
                    Instruction::new(Opcode::ADD, 29, 0, operand.0, false, true),
                    Instruction::new(Opcode::ADD, 30, 0, operand.1, false, true),
                    Instruction::new(*mul_op, 31, 30, 29, false, false),
                ];
                let program = Program::new(instructions, 0, 0);
                run_test::<CpuProver<_, _>>(program).unwrap();
            }
        }
    }

    #[test]
    fn test_mult_div_prove() {
        utils::setup_logger();
        let mul_ops = [Opcode::MULT, Opcode::MULTU, Opcode::DIV, Opcode::DIVU];
        let operands =
            [(1, 1), (1234, 5678), (8765, 4321), (0xffff, 0xffff - 1), (u32::MAX - 1, u32::MAX)];
        for mul_op in mul_ops.iter() {
            for operand in operands.iter() {
                let instructions = vec![
                    Instruction::new(Opcode::ADD, 29, 0, operand.0, false, true),
                    Instruction::new(Opcode::ADD, 30, 0, operand.1, false, true),
                    Instruction::new(*mul_op, 32, 30, 29, false, false),
                ];
                let program = Program::new(instructions, 0, 0);
                run_test::<CpuProver<_, _>>(program).unwrap();
            }
        }
    }

    #[test]
    fn test_lt_prove() {
        setup_logger();
        let less_than = [Opcode::SLT, Opcode::SLTU];
        for lt_op in less_than.iter() {
            let instructions = vec![
                Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
                Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
                Instruction::new(*lt_op, 31, 30, 29, false, false),
            ];
            let program = Program::new(instructions, 0, 0);
            run_test::<CpuProver<_, _>>(program).unwrap();
        }
    }

    #[test]
    fn test_bitwise_prove() {
        setup_logger();
        let bitwise_opcodes = [Opcode::XOR, Opcode::OR, Opcode::AND];

        for bitwise_op in bitwise_opcodes.iter() {
            let instructions = vec![
                Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
                Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
                Instruction::new(*bitwise_op, 31, 30, 29, false, false),
            ];
            let program = Program::new(instructions, 0, 0);
            run_test::<CpuProver<_, _>>(program).unwrap();
        }
    }

    #[test]
    fn test_divrem_prove() {
        setup_logger();
        let div_rem_ops = [Opcode::DIV, Opcode::DIVU];
        let operands = [
            (1, 1),
            (123, 456 * 789),
            (123 * 456, 789),
            (0xffff * (0xffff - 1), 0xffff),
            (u32::MAX - 5, u32::MAX - 7),
        ];
        for div_rem_op in div_rem_ops.iter() {
            for op in operands.iter() {
                let instructions = vec![
                    Instruction::new(Opcode::ADD, 29, 0, op.0, false, true),
                    Instruction::new(Opcode::ADD, 30, 0, op.1, false, true),
                    Instruction::new(*div_rem_op, 32, 29, 30, false, false),
                ];
                let program = Program::new(instructions, 0, 0);
                run_test::<CpuProver<_, _>>(program).unwrap();
            }
        }
    }

    #[test]
    fn test_cloclz_prove() {
        setup_logger();
        let clz_clo_ops = [Opcode::CLZ, Opcode::CLO];
        let operands = [0u32, 0x0a0b0c0d, 0x1000, 0xff7fffff, 0x7fffffff, 0x80000000, 0xffffffff];

        for clo_clz_op in clz_clo_ops.iter() {
            for op in operands.iter() {
                let instructions = vec![
                    Instruction::new(Opcode::ADD, 29, 0, *op, false, true),
                    Instruction::new(*clo_clz_op, 30, 29, 0, false, true),
                ];
                let program = Program::new(instructions, 0, 0);
                run_test::<CpuProver<_, _>>(program).unwrap();
            }
        }
    }

    #[test]
    fn test_j_prove() {
        //   j 100
        //
        // The j instruction performs an unconditional jump to a specified address.
        setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 11, 0, 100, false, true),
            Instruction::new(Opcode::Jumpi, 0, 100, 0, true, true),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_jr_prove() {
        //   addi x11, x11, 100
        //   jr x11
        //
        // The jr instruction jumps to an address stored in a register.
        setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 11, 0, 100, false, true),
            Instruction::new(Opcode::Jump, 0, 11, 0, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_jal_prove() {
        //   addi x11, x11, 100
        //   jal x11
        //
        // The jal instruction jumps to an address and stores the return address in $ra.
        setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 31, 0, 0, false, true),
            Instruction::new(Opcode::Jumpi, 31, 100, 0, true, true),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_jalr_prove() {
        //   addi x11, x11, 100
        //   jalr x11
        //
        // Similar to jal, but jumps to an address stored in a register.
        setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 5, 0, 0, false, true),
            Instruction::new(Opcode::ADD, 11, 11, 100, false, true),
            Instruction::new(Opcode::Jump, 5, 11, 0, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_sc_prove() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 0x12348765, false, true),
            Instruction::new(Opcode::SW, 29, 0, 0x27654320, false, true),
            // LL and SC
            Instruction::new(Opcode::LL, 28, 0, 0x27654320, false, true),
            Instruction::new(Opcode::ADD, 28, 28, 1, false, true),
            Instruction::new(Opcode::SC, 28, 0, 0x27654320, false, true),
            Instruction::new(Opcode::LW, 29, 0, 0x27654320, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_hello_world_prove_simple() {
        setup_logger();
        let program = hello_world_program();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_fibonacci_prove_simple() {
        setup_logger();
        let program = fibonacci_program();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_max_memory_prove_simple() {
        setup_logger();
        let program = max_memory_program();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_sha3_chain_prove_simple() {
        setup_logger();
        let program = sha3_chain_program();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_fibonacci_prove_checkpoints() {
        setup_logger();

        let program = fibonacci_program();
        let stdin = ZKMStdin::new();
        let mut opts = ZKMCoreOpts::default();
        opts.shard_size = 1024;
        opts.shard_batch_size = 2;
        prove::<_, CpuProver<_, _>>(program, &stdin, KoalaBearPoseidon2::new(), opts, None)
            .unwrap();
    }

    #[test]
    fn test_fibonacci_prove_batch() {
        setup_logger();
        let program = fibonacci_program();
        let stdin = ZKMStdin::new();
        prove::<_, CpuProver<_, _>>(
            program,
            &stdin,
            KoalaBearPoseidon2::new(),
            ZKMCoreOpts::default(),
            None,
        )
        .unwrap();
    }

    #[test]
    fn test_simple_memory_program_prove() {
        setup_logger();
        let program = simple_memory_program();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_simple_memory_program_2_prove() {
        setup_logger();
        let program = other_memory_program();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_ssz_withdrawal() {
        setup_logger();
        let program = ssz_withdrawals_program();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_unconstrained() {
        setup_logger();
        let program = unconstrained_program();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_key_serde() {
        let program = ssz_withdrawals_program();
        let config = KoalaBearPoseidon2::new();
        let machine = MipsAir::machine(config);
        let (pk, vk) = machine.setup(&program);

        let serialized_pk = bincode::serialize(&pk).unwrap();
        let deserialized_pk: StarkProvingKey<KoalaBearPoseidon2> =
            bincode::deserialize(&serialized_pk).unwrap();
        assert_eq!(pk.commit, deserialized_pk.commit);
        assert_eq!(pk.pc_start, deserialized_pk.pc_start);
        assert_eq!(pk.traces, deserialized_pk.traces);
        assert_eq!(pk.data.root(), deserialized_pk.data.root());
        assert_eq!(pk.chip_ordering, deserialized_pk.chip_ordering);
        assert_eq!(pk.local_only, deserialized_pk.local_only);

        let serialized_vk = bincode::serialize(&vk).unwrap();
        let deserialized_vk: StarkVerifyingKey<KoalaBearPoseidon2> =
            bincode::deserialize(&serialized_vk).unwrap();
        assert_eq!(vk.commit, deserialized_vk.commit);
        assert_eq!(vk.pc_start, deserialized_vk.pc_start);
        assert_eq!(vk.chip_information.len(), deserialized_vk.chip_information.len());
        for (a, b) in vk.chip_information.iter().zip(deserialized_vk.chip_information.iter()) {
            assert_eq!(a.0, b.0);
            assert_eq!(a.1.log_n, b.1.log_n);
            assert_eq!(a.1.shift, b.1.shift);
            assert_eq!(a.2.height, b.2.height);
            assert_eq!(a.2.width, b.2.width);
        }
        assert_eq!(vk.chip_ordering, deserialized_vk.chip_ordering);
    }
}

use crate::{
    global::GlobalChip,
    memory::{MemoryBumpChip, MemoryChipType, MemoryLocalChip, NUM_LOCAL_MEMORY_ENTRIES_PER_ROW},
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
use zkm_pcs::{
    air::{LookupScope, MachineAir, PicusInfo, ZKM_PROOF_NUM_PV_ELTS},
    Chip, LookupKind, StarkGenericConfig, StarkMachine,
};

/// A module for importing all the different MIPS chips.
pub(crate) mod mips_chips {
    pub use crate::{
        alu::{
            AddSubChip, AddSubImmChip, BitwiseChip, BitwiseImmChip, CloClzChip, DivRemChip, LtChip,
            LtImmChip, MulChip, ShiftLeft, ShiftLeftImm, ShiftRightChip, ShiftRightImmChip,
        },
        bytes::ByteChip,
        control_flow::{BranchChip, JumpChip},
        memory::{
            LoadNarrowChip, LoadWordChip, MemoryGlobalChip, MemoryUnalignedChip, StoreNarrowChip,
            StoreWordChip,
        },
        misc::{MiscInstrsChip, MovCondChip},
        program::ProgramChip,
        range::RangeChip,
        syscall::{
            chip::SyscallChip,
            instructions::SyscallInstrsChip,
            precompiles::{
                edwards::{EdAddAssignChip, EdDecompressChip},
                keccak_sponge::{KeccakSpongeChip, KeccakSpongeControlChip},
                sha256::{
                    ShaCompressChip, ShaCompressControlChip, ShaExtendChip, ShaExtendControlChip,
                },
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
    /// An AIR for the register-form MIPS ADD and SUB instructions.
    Add(AddSubChip),
    /// An AIR for the immediate-form MIPS ADD and SUB instructions.
    AddImm(AddSubImmChip),
    /// An AIR for the register-form MIPS Bitwise instructions.
    Bitwise(BitwiseChip),
    /// An AIR for the immediate-form MIPS Bitwise instructions.
    BitwiseImm(BitwiseImmChip),
    /// An AIR for MIPS Mul instruction.
    Mul(MulChip),
    /// An AIR for MIPS Div and Rem instructions.
    DivRem(DivRemChip),
    /// An AIR for MIPS Lt instruction.
    Lt(LtChip),
    /// An AIR for the immediate-form MIPS compare instructions.
    LtImm(LtImmChip),
    /// An AIR for MIPS CLO and CLZ instruction.
    CloClz(CloClzChip),
    /// An AIR for MIPS SLL instruction.
    ShiftLeft(ShiftLeft),
    /// An AIR for the immediate-form (shamt) MIPS SLL instruction.
    ShiftLeftImm(ShiftLeftImm),
    /// An AIR for MIPS SRL and SRA instruction.
    ShiftRight(ShiftRightChip),
    /// An AIR for the immediate-form (shamt) MIPS shift right instructions.
    ShiftRightImm(ShiftRightImmChip),
    /// A lookup table for byte operations.
    ByteLookup(ByteChip<F>),
    /// The parametric bit-width range table.
    RangeLookup(RangeChip<F>),
    /// An AIR for MIPS Branch instructions.
    Branch(BranchChip),
    /// An AIR for MIPS Jump instructions.
    Jump(JumpChip),
    /// An AIR for the MIPS narrow (sub-word) load instructions.
    LoadNarrow(LoadNarrowChip),
    /// An AIR for the MIPS word-aligned load instructions.
    LoadWord(LoadWordChip),
    /// An AIR for the MIPS narrow (sub-word) store instructions.
    StoreNarrow(StoreNarrowChip),
    /// An AIR for the MIPS word-aligned store instructions.
    StoreWord(StoreWordChip),
    /// An AIR for the MIPS unaligned load/store instructions.
    MemoryUnaligned(MemoryUnalignedChip),
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
    /// A table that bumps each touched register's timestamp into the current shard.
    MemoryBump(MemoryBumpChip),
    /// A table for all the syscall invocations.
    SyscallCore(SyscallChip),
    /// A table for all the precompile invocations.
    SyscallPrecompile(SyscallChip),
    /// A table for all the global lookups.
    Global(GlobalChip),
    /// A precompile for sha256 extend.
    Sha256Extend(ShaExtendChip),
    /// The control chip bookending the sha256-extend `PrecompileChain` state bus.
    Sha256ExtendControl(ShaExtendControlChip),
    /// A precompile for sha256 compress.
    Sha256Compress(ShaCompressChip),
    /// The control chip bookending the sha256-compress `PrecompileChain` state bus.
    Sha256CompressControl(ShaCompressControlChip),
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
    /// The control chip bookending the keccak-sponge `PrecompileChain` state buses.
    KeccakSpongeControl(KeccakSpongeControlChip),
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

        let mut chips = vec![];
        let program = Chip::new(MipsAir::Program(ProgramChip::default()));
        costs.insert(program.name(), program.cost());
        chips.push(program);

        let sha_extend = Chip::new(MipsAir::Sha256Extend(ShaExtendChip::default()));
        costs.insert(sha_extend.name(), 48 * sha_extend.cost());
        chips.push(sha_extend);

        let sha_extend_control =
            Chip::new(MipsAir::Sha256ExtendControl(ShaExtendControlChip::default()));
        costs.insert(sha_extend_control.name(), sha_extend_control.cost());
        chips.push(sha_extend_control);

        let sha_compress = Chip::new(MipsAir::Sha256Compress(ShaCompressChip::default()));
        costs.insert(sha_compress.name(), 80 * sha_compress.cost());
        chips.push(sha_compress);

        let sha_compress_control =
            Chip::new(MipsAir::Sha256CompressControl(ShaCompressControlChip::default()));
        costs.insert(sha_compress_control.name(), sha_compress_control.cost());
        chips.push(sha_compress_control);

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

        let keccak_sponge_control =
            Chip::new(MipsAir::KeccakSpongeControl(KeccakSpongeControlChip::new()));
        costs.insert(keccak_sponge_control.name(), keccak_sponge_control.cost());
        chips.push(keccak_sponge_control);

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

        let add_sub_imm = Chip::new(MipsAir::AddImm(AddSubImmChip::default()));
        costs.insert(add_sub_imm.name(), add_sub_imm.cost());
        chips.push(add_sub_imm);

        let bitwise = Chip::new(MipsAir::Bitwise(BitwiseChip::default()));
        costs.insert(bitwise.name(), bitwise.cost());
        chips.push(bitwise);

        let bitwise_imm = Chip::new(MipsAir::BitwiseImm(BitwiseImmChip::default()));
        costs.insert(bitwise_imm.name(), bitwise_imm.cost());
        chips.push(bitwise_imm);

        let mul = Chip::new(MipsAir::Mul(MulChip::default()));
        costs.insert(mul.name(), mul.cost());
        chips.push(mul);

        let shift_right = Chip::new(MipsAir::ShiftRight(ShiftRightChip::default()));
        costs.insert(shift_right.name(), shift_right.cost());
        chips.push(shift_right);

        let shift_right_imm = Chip::new(MipsAir::ShiftRightImm(ShiftRightImmChip::default()));
        costs.insert(shift_right_imm.name(), shift_right_imm.cost());
        chips.push(shift_right_imm);

        let shift_left = Chip::new(MipsAir::ShiftLeft(ShiftLeft::default()));
        costs.insert(shift_left.name(), shift_left.cost());
        chips.push(shift_left);

        let shift_left_imm = Chip::new(MipsAir::ShiftLeftImm(ShiftLeftImm::default()));
        costs.insert(shift_left_imm.name(), shift_left_imm.cost());
        chips.push(shift_left_imm);

        let lt = Chip::new(MipsAir::Lt(LtChip::default()));
        costs.insert(lt.name(), lt.cost());
        chips.push(lt);

        let lt_imm = Chip::new(MipsAir::LtImm(LtImmChip::default()));
        costs.insert(lt_imm.name(), lt_imm.cost());
        chips.push(lt_imm);

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

        let memory_load_narrow = Chip::new(MipsAir::LoadNarrow(LoadNarrowChip));
        costs.insert(memory_load_narrow.name(), memory_load_narrow.cost());
        chips.push(memory_load_narrow);

        let memory_load_word = Chip::new(MipsAir::LoadWord(LoadWordChip));
        costs.insert(memory_load_word.name(), memory_load_word.cost());
        chips.push(memory_load_word);

        let memory_store_narrow = Chip::new(MipsAir::StoreNarrow(StoreNarrowChip));
        costs.insert(memory_store_narrow.name(), memory_store_narrow.cost());
        chips.push(memory_store_narrow);

        let memory_store_word = Chip::new(MipsAir::StoreWord(StoreWordChip));
        costs.insert(memory_store_word.name(), memory_store_word.cost());
        chips.push(memory_store_word);

        let memory_unaligned = Chip::new(MipsAir::MemoryUnaligned(MemoryUnalignedChip));
        costs.insert(memory_unaligned.name(), memory_unaligned.cost());
        chips.push(memory_unaligned);

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

        let memory_bump = Chip::new(MipsAir::MemoryBump(MemoryBumpChip::new()));
        costs.insert(memory_bump.name(), memory_bump.cost());
        chips.push(memory_bump);

        let global = Chip::new(MipsAir::Global(GlobalChip));
        costs.insert(global.name(), global.cost());
        chips.push(global);

        let byte = Chip::new(MipsAir::ByteLookup(ByteChip::default()));
        costs.insert(byte.name(), byte.cost());
        chips.push(byte);

        let range = Chip::new(MipsAir::RangeLookup(RangeChip::default()));
        costs.insert(range.name(), range.cost());
        chips.push(range);

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
        vec![
            (MipsAirId::Program, program.instructions.len()),
            (MipsAirId::Byte, 1 << 16),
            (MipsAirId::Range, 1 << 10),
        ]
    }

    /// Get the heights of the chips for a given execution record.
    pub fn core_heights(record: &ExecutionRecord) -> Vec<(MipsAirId, usize)> {
        vec![
            (MipsAirId::Branch, record.branch_events.len()),
            (MipsAirId::Jump, record.jump_events.len()),
            (MipsAirId::MovCond, record.movcond_events.len()),
            (MipsAirId::Cpu, record.cpu_events.len()),
            (MipsAirId::MiscInstrs, record.misc_events.len()),
            (MipsAirId::LoadNarrow, record.memory_load_narrow_events.len()),
            (MipsAirId::LoadWord, record.memory_load_word_events.len()),
            (MipsAirId::StoreNarrow, record.memory_store_narrow_events.len()),
            (MipsAirId::StoreWord, record.memory_store_word_events.len()),
            (MipsAirId::MemoryUnaligned, record.memory_unaligned_events.len()),
            (MipsAirId::SyscallInstrs, record.syscall_events.len()),
            (MipsAirId::DivRem, record.divrem_events.len()),
            (MipsAirId::AddSub, record.add_sub_events.len()),
            (MipsAirId::AddSubImm, record.add_sub_imm_events.len()),
            (MipsAirId::Bitwise, record.bitwise_events.len()),
            (MipsAirId::BitwiseImm, record.bitwise_imm_events.len()),
            (MipsAirId::Mul, record.mul_events.len()),
            (MipsAirId::ShiftRight, record.shift_right_events.len()),
            (MipsAirId::ShiftRightImm, record.shift_right_imm_events.len()),
            (MipsAirId::ShiftLeft, record.shift_left_events.len()),
            (MipsAirId::ShiftLeftImm, record.shift_left_imm_events.len()),
            (MipsAirId::Lt, record.lt_events.len()),
            (MipsAirId::LtImm, record.lt_imm_events.len()),
            (
                MipsAirId::MemoryLocal,
                record
                    .get_local_mem_events()
                    .chunks(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW)
                    .into_iter()
                    .count(),
            ),
            (MipsAirId::MemoryBump, record.bump_memory_events.len()),
            (MipsAirId::CloClz, record.cloclz_events.len()),
            (
                MipsAirId::Global,
                2 * record.get_local_mem_events().count() + 2 * record.syscall_events.len(),
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
                let num_local_mem_events = match self {
                    Self::Sha256CompressControl(_) | Self::Sha256ExtendControl(_) => 0,
                    _ => events.get_local_mem_events().into_iter().count(),
                };
                (num_rows, num_local_mem_events, record.global_lookup_events.len())
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
            MipsAir::Add(AddSubChip::default()),
            MipsAir::AddImm(AddSubImmChip::default()),
            MipsAir::Bitwise(BitwiseChip::default()),
            MipsAir::BitwiseImm(BitwiseImmChip::default()),
            MipsAir::Mul(MulChip::default()),
            MipsAir::DivRem(DivRemChip::default()),
            MipsAir::Lt(LtChip::default()),
            MipsAir::LtImm(LtImmChip::default()),
            MipsAir::CloClz(CloClzChip::default()),
            MipsAir::ShiftLeft(ShiftLeft::default()),
            MipsAir::ShiftLeftImm(ShiftLeftImm::default()),
            MipsAir::ShiftRight(ShiftRightChip::default()),
            MipsAir::ShiftRightImm(ShiftRightImmChip::default()),
            MipsAir::Branch(BranchChip::default()),
            MipsAir::Jump(JumpChip::default()),
            MipsAir::SyscallInstrs(SyscallInstrsChip::default()),
            MipsAir::LoadNarrow(LoadNarrowChip),
            MipsAir::LoadWord(LoadWordChip),
            MipsAir::StoreNarrow(StoreNarrowChip),
            MipsAir::StoreWord(StoreWordChip),
            MipsAir::MemoryUnaligned(MemoryUnalignedChip),
            MipsAir::MovCond(MovCondChip::default()),
            MipsAir::MiscInstrs(MiscInstrsChip::default()),
            MipsAir::MemoryLocal(MemoryLocalChip::new()),
            MipsAir::MemoryBump(MemoryBumpChip::new()),
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

        airs.remove(&Self::Program(ProgramChip::default()));
        airs.remove(&Self::ByteLookup(ByteChip::default()));
        airs.remove(&Self::RangeLookup(RangeChip::default()));

        airs.remove(&Self::Sha256CompressControl(ShaCompressControlChip::default()));
        airs.remove(&Self::Sha256ExtendControl(ShaExtendControlChip::default()));
        airs.remove(&Self::KeccakSpongeControl(KeccakSpongeControlChip::default()));

        airs.into_iter()
            .map(|air| {
                let control_air = air.precompile_control_air();
                let rows_per_event = air.rows_per_event();
                let chip = Chip::new(air);
                let mut local_mem_events: usize = chip
                    .sends()
                    .iter()
                    .chain(chip.receives())
                    .filter(|lookup| {
                        lookup.kind == LookupKind::Memory && lookup.scope == LookupScope::Local
                    })
                    .count();
                if let Some(control) = control_air {
                    let control_chip = Chip::new(control);
                    let control_mem: usize = control_chip
                        .sends()
                        .iter()
                        .chain(control_chip.receives())
                        .filter(|lookup| {
                            lookup.kind == LookupKind::Memory && lookup.scope == LookupScope::Local
                        })
                        .count();
                    local_mem_events += control_mem.div_ceil(rows_per_event);
                }

                (chip.into_inner(), local_mem_events)
            })
            .collect()
    }

    /// For a bus-ported precompile **worker** air, returns its paired
    /// `PrecompileChain` **control** air (the chip that seeds/drains the state
    /// bus, 1 row per syscall).  Returns `None` for precompiles that have no
    /// control chip.  Used by `get_precompile_shapes` to size the worker+control
    /// pair together in a single shard shape.
    pub(crate) fn precompile_control_air(&self) -> Option<Self> {
        match self {
            Self::Sha256Compress(_) => {
                Some(Self::Sha256CompressControl(ShaCompressControlChip::default()))
            }
            Self::Sha256Extend(_) => {
                Some(Self::Sha256ExtendControl(ShaExtendControlChip::default()))
            }
            Self::KeccakSponge(_) => {
                Some(Self::KeccakSpongeControl(KeccakSpongeControlChip::default()))
            }
            _ => None,
        }
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
            Self::Sha256CompressControl(_) => SyscallCode::SHA_COMPRESS,
            Self::Sha256Extend(_) => SyscallCode::SHA_EXTEND,
            Self::Sha256ExtendControl(_) => SyscallCode::SHA_EXTEND,
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
            Self::KeccakSpongeControl(_) => SyscallCode::KECCAK_SPONGE,
            Self::SysLinux(_) => SyscallCode::SYS_LINUX,
            Self::Add(_) => unreachable!("Invalid for core chip"),
            Self::AddImm(_) => unreachable!("Invalid for core chip"),
            Self::Bitwise(_) => unreachable!("Invalid for core chip"),
            Self::BitwiseImm(_) => unreachable!("Invalid for core chip"),
            Self::DivRem(_) => unreachable!("Invalid for core chip"),
            Self::MemoryGlobalInit(_) => unreachable!("Invalid for memory init/final"),
            Self::MemoryGlobalFinal(_) => unreachable!("Invalid for memory init/final"),
            Self::MemoryLocal(_) => unreachable!("Invalid for memory local"),
            Self::MemoryBump(_) => unreachable!("Invalid for memory bump"),
            Self::Global(_) => unreachable!("Invalid for global chip"),
            Self::Program(_) => unreachable!("Invalid for core chip"),
            Self::Mul(_) => unreachable!("Invalid for core chip"),
            Self::Lt(_) => unreachable!("Invalid for core chip"),
            Self::LtImm(_) => unreachable!("Invalid for core chip"),
            Self::CloClz(_) => unreachable!("Invalid for core chip"),
            Self::ShiftRight(_) => unreachable!("Invalid for core chip"),
            Self::ShiftRightImm(_) => unreachable!("Invalid for core chip"),
            Self::ShiftLeft(_) => unreachable!("Invalid for core chip"),
            Self::ShiftLeftImm(_) => unreachable!("Invalid for core chip"),
            Self::ByteLookup(_) => unreachable!("Invalid for core chip"),
            Self::RangeLookup(_) => unreachable!("Invalid for core chip"),
            Self::SyscallCore(_) => unreachable!("Invalid for core chip"),
            Self::SyscallPrecompile(_) => unreachable!("Invalid for syscall precompile chip"),
            Self::Branch(_) => unreachable!("Invalid for core chip"),
            Self::Jump(_) => unreachable!("Invalid for core chip"),
            Self::SyscallInstrs(_) => unreachable!("Invalid for core chip"),
            Self::LoadNarrow(_) => unreachable!("Invalid for core chip"),
            Self::LoadWord(_) => unreachable!("Invalid for core chip"),
            Self::StoreNarrow(_) => unreachable!("Invalid for core chip"),
            Self::StoreWord(_) => unreachable!("Invalid for core chip"),
            Self::MemoryUnaligned(_) => unreachable!("Invalid for core chip"),
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
        utils::{prove, run_test, run_test_with_stdin, setup_logger},
    };

    use hashbrown::HashMap;
    use itertools::Itertools;
    use p3_koala_bear::KoalaBear;
    use strum::IntoEnumIterator;

    use zkm_core_executor::{Instruction, MipsAirId, Opcode, Program};
    use zkm_pcs::air::MachineAir;
    use zkm_pcs::{
        koala_bear_poseidon2::KoalaBearPoseidon2, CpuProver, StarkMachine, StarkProvingKey,
        StarkVerifyingKey, ZKMCoreOpts,
    };

    #[test]
    fn test_primitives_and_machine_air_names_match() {
        let chips = MipsAir::<KoalaBear>::chips();
        for (a, b) in chips.iter().zip_eq(MipsAirId::iter().filter(|id| *id != MipsAirId::Cpu)) {
            assert_eq!(a.name(), b.to_string());
        }
    }

    #[test]
    fn core_air_cost_consistency() {
        let file = std::fs::File::open("../executor/src/artifacts/mips_costs.json").unwrap();
        let costs: HashMap<String, u64> = serde_json::from_reader(file).unwrap();
        let machine_costs = MipsAir::<KoalaBear>::costs();
        log::info!("{machine_costs:?}");
        assert_eq!(costs, machine_costs);
    }

    #[test]
    fn write_core_air_costs() {
        let costs = MipsAir::<KoalaBear>::costs();
        println!("{costs:?}");
        let dir = std::path::Path::new("../executor/src/artifacts");
        if !dir.exists() {
            std::fs::create_dir_all(dir).unwrap();
        }
        let file = std::fs::File::create(dir.join("mips_costs.json")).unwrap();
        serde_json::to_writer_pretty(file, &costs).unwrap();
    }

    /// The two-round committed stripe count a core shard can reach against the
    /// verifier, derived from the machine and the verifier's own bound.
    ///
    /// A shard commits TWO rounds, preprocessed then main, and the jagged
    /// lambda batch spans both: `committed_dense_len` rounds each round's raw
    /// cell count up to whole `2^DEFAULT_LOG_STACKING_HEIGHT` stripes, and
    /// above four stripes up to a multiple of eight.  The preprocessed round is
    /// the verifying key's, bounded by the LARGEST admitted Program band.  The
    /// main round is proof-controlled: the verifier admits any area strictly
    /// below `2^MAX_ROUND_LOG_AREA`, so a soundness model of the batch has to
    /// use that bound, not the honest executor's `ELEMENT_THRESHOLD` fence,
    /// which only has to lie inside it.
    #[test]
    fn committed_stripe_bound_over_both_rounds() {
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::jagged::committed_dense_len;
        use zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT;

        let log_stack = DEFAULT_LOG_STACKING_HEIGHT as usize;
        let stripe = 1usize << log_stack;
        let machine =
            MipsAir::machine(zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2::default());

        let width_of = |name: &str| -> usize {
            machine
                .chips()
                .iter()
                .find(|c| <_ as MachineAir<KoalaBear>>::name(*c) == name)
                .map(<_ as MachineAir<KoalaBear>>::preprocessed_width)
                .unwrap_or_else(|| panic!("{name} is not a chip of the core machine"))
        };

        let prog_rows = 1usize << 22;
        let byte_rows = 1usize << 16;
        let range_rows = crate::range::NUM_RANGE_ROWS;
        let prep_cells = prog_rows * width_of("Program")
            + byte_rows * width_of("Byte")
            + range_rows * width_of("Range");

        let prep_stripes = committed_dense_len(prep_cells, log_stack) / stripe;
        let verifier_area = (1usize << zkm_pcs::jagged::MAX_ROUND_LOG_AREA) - 1;
        let main_stripes = committed_dense_len(verifier_area, log_stack) / stripe;

        let batch = prep_stripes + main_stripes;
        tracing::info!(
            "[STRIPES] prep {prep_cells} cells -> {prep_stripes}; \
             main {verifier_area} cells -> {main_stripes}; batch {batch}",
        );
        tracing::info!(
            "[STRIPES] widths Program={} Byte={} Range={}; rows Program=2^22 Byte=2^16 Range={}",
            width_of("Program"),
            width_of("Byte"),
            width_of("Range"),
            range_rows,
        );

        assert_eq!(
            (prep_stripes, main_stripes, batch),
            (32, 512, 544),
            "the committed stripe bound moved; update the soundness model's \
             batch cardinality to {batch} before relying on it",
        );
        assert!(
            zkm_pcs::ELEMENT_THRESHOLD <= verifier_area,
            "the honest area fence must lie inside the verifier's bound",
        );

        let largest =
            zkm_pcs::jagged::RecursionPins::class(zkm_pcs::jagged::RecursionPins::LAST_CLASS);
        let rec_batch = (largest.prep.area >> log_stack) + (largest.main.area >> log_stack);
        tracing::info!(
            "[STRIPES] recursion prep {} + main {} cells -> batch {rec_batch}",
            largest.prep.area,
            largest.main.area,
        );
        assert_eq!(
            rec_batch, 64,
            "the recursion pin classes moved; update the soundness model's \
             compress batch cardinality to {rec_batch}",
        );
    }

    #[test]
    fn test_simple_prove() {
        utils::setup_logger();
        let program = simple_program();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_simple_prove_whir_inner_pcs() {
        utils::setup_logger();
        let program = simple_program();
        let runtime = {
            let mut runtime = zkm_core_executor::Executor::new(program, ZKMCoreOpts::default());
            runtime.run().unwrap();
            runtime
        };
        let result = crate::utils::run_test_core::<CpuProver<_, _>>(runtime, ZKMStdin::new(), None);
        for sp in &result.unwrap().shard_proofs {
            let bsp = sp.jagged_shard_proof.as_ref();
            match &bsp.evaluation_proof {
                zkm_pcs::shard_level::shard_proof::EvaluationProof::Bundle(b) => {
                    assert!(b.whir_proof.is_some(), "shard was proven under BaseFold");
                }
                _ => panic!("expected a Bundle evaluation proof"),
            }
        }
    }

    #[test]
    fn test_beq_branching_prove() {
        utils::setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 1, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 1, false, true),
            Instruction::new(Opcode::BEQ, 29, 30, 100, false, true),
            Instruction::new(Opcode::ADD, 0, 0, 0, false, true),
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
            Instruction::new(Opcode::ADD, 0, 0, 0, false, true),
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
            Instruction::new(Opcode::ADD, 0, 0, 0, false, true),
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
            Instruction::new(Opcode::ADD, 0, 0, 0, false, true),
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
                    Instruction::new(*branch_op, 29, 0, 100, false, true),
                    Instruction::new(Opcode::ADD, 0, 0, 0, false, true),
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
            (5, i32::MIN.unsigned_abs()),
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
        setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 11, 0, 100, false, true),
            Instruction::new(Opcode::Jumpi, 0, 100, 0, true, true),
            Instruction::new(Opcode::ADD, 0, 0, 0, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_jr_prove() {
        setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 11, 0, 100, false, true),
            Instruction::new(Opcode::Jump, 0, 11, 0, false, true),
            Instruction::new(Opcode::ADD, 0, 0, 0, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_jal_prove() {
        setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 31, 0, 0, false, true),
            Instruction::new(Opcode::Jumpi, 31, 100, 0, true, true),
            Instruction::new(Opcode::ADD, 0, 0, 0, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_jalr_prove() {
        setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 5, 0, 0, false, true),
            Instruction::new(Opcode::ADD, 11, 11, 100, false, true),
            Instruction::new(Opcode::Jump, 5, 11, 0, false, true),
            Instruction::new(Opcode::ADD, 0, 0, 0, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_sc_prove() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 0x12348765, false, true),
            Instruction::new(Opcode::SW, 29, 0, 0x27654320, false, true),
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

    /// The input the fibonacci guest reads.
    ///
    /// The guest reads `n: u32` from stdin, so a caller that supplies nothing
    /// fails execution with `InvalidSyscallArgs` before any proving. Ten keeps
    /// the cycle counts these tests were tuned against.
    fn fib_stdin() -> ZKMStdin {
        let mut stdin = ZKMStdin::new();
        stdin.write(&10u32);
        stdin
    }

    #[test]
    fn test_fibonacci_prove_simple() {
        setup_logger();
        let program = fibonacci_program();
        run_test_with_stdin::<CpuProver<_, _>>(program, fib_stdin()).unwrap();
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
        let stdin = fib_stdin();
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
        let stdin = fib_stdin();
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
    fn test_fix_off_core_verify_injected_chips_rollout1b() {
        use zkm_core_executor::Executor;
        setup_logger();
        let program = fibonacci_program();
        let mut opts = ZKMCoreOpts::default();
        opts.shard_size = 262_144;
        let mut runtime = Executor::new(program, opts);
        runtime.write_vecs(&fib_stdin().buffer);
        runtime.run().unwrap();
        utils::run_test_core::<CpuProver<_, _>>(runtime, fib_stdin(), None).unwrap();
    }

    #[test]
    fn test_fix_on_core_verify_control_rollout1b() {
        use crate::shape::CoreShapeConfig;
        use zkm_core_executor::Executor;
        setup_logger();
        let mut program = fibonacci_program();
        let shape_config = CoreShapeConfig::default();
        shape_config.fix_preprocessed_shape(&mut program).unwrap();
        let mut opts = ZKMCoreOpts::default();
        opts.shard_size = 262_144;
        let mut runtime = Executor::new(program, opts);
        runtime.write_vecs(&fib_stdin().buffer);
        runtime.run().unwrap();
        utils::run_test_core::<CpuProver<_, _>>(runtime, fib_stdin(), Some(&shape_config)).unwrap();
    }

    #[test]
    #[ignore]
    fn recon_probe_honest_only() {
        use crate::shape::CoreShapeConfig;
        use zkm_core_executor::Executor;
        use zkm_pcs::{MachineProver, StarkGenericConfig};
        setup_logger();

        let mut program = fibonacci_program();
        let shape_config = CoreShapeConfig::default();
        shape_config.fix_preprocessed_shape(&mut program).unwrap();
        let mut opts = ZKMCoreOpts::default();
        opts.shard_size = 262_144;
        let mut runtime = Executor::new(program, opts);
        runtime.write_vecs(&fib_stdin().buffer);
        runtime.run().unwrap();

        let config = KoalaBearPoseidon2::new();
        let machine = MipsAir::machine(config);
        let prover = CpuProver::new(MipsAir::machine(KoalaBearPoseidon2::new()));
        let (pk, _) = prover.setup(runtime.program.as_ref());
        let (proof, _output, _) = utils::prove_with_context::<_, CpuProver<_, _>>(
            &prover,
            &pk,
            Program::clone(&runtime.program),
            &fib_stdin(),
            ZKMCoreOpts::default(),
            zkm_core_executor::ZKMContext::default(),
            Some(&shape_config),
        )
        .unwrap();
        let (_pk, vk) = machine.setup(runtime.program.as_ref());

        let mut challenger = machine.config().challenger();
        let r = machine.verify(&vk, &proof, &mut challenger);
        tracing::info!("[PROBE] recon-ON honest verify => {:?}", r.map(|_| "OK"));
    }

    #[test]
    fn test_fix_on_height_forgery_red_green_gate_c() {
        use crate::shape::CoreShapeConfig;
        use zkm_core_executor::Executor;
        use zkm_pcs::{MachineProver, StarkGenericConfig};
        setup_logger();

        let mut program = fibonacci_program();
        let shape_config = CoreShapeConfig::default();
        shape_config.fix_preprocessed_shape(&mut program).unwrap();
        let mut opts = ZKMCoreOpts::default();
        opts.shard_size = 262_144;
        let mut runtime = Executor::new(program, opts);
        runtime.write_vecs(&fib_stdin().buffer);
        runtime.run().unwrap();

        let config = KoalaBearPoseidon2::new();
        let machine = MipsAir::machine(config);
        let prover = CpuProver::new(MipsAir::machine(KoalaBearPoseidon2::new()));
        let (pk, _) = prover.setup(runtime.program.as_ref());
        let (proof, _output, _) = utils::prove_with_context::<_, CpuProver<_, _>>(
            &prover,
            &pk,
            Program::clone(&runtime.program),
            &fib_stdin(),
            ZKMCoreOpts::default(),
            zkm_core_executor::ZKMContext::default(),
            Some(&shape_config),
        )
        .unwrap();

        let (_pk, vk) = machine.setup(runtime.program.as_ref());

        let verify = |p: &zkm_pcs::MachineProof<KoalaBearPoseidon2>| -> String {
            let mut challenger = machine.config().challenger();
            match machine.verify(&vk, p, &mut challenger) {
                Ok(()) => "OK".to_string(),
                Err(e) => format!("{e}"),
            }
        };

        let honest = verify(&proof);
        tracing::info!("[GATE-B] honest verify (default) => {honest}");
        assert_eq!(honest, "OK", "honest FIX-on proof must verify (gate-b)");

        let honest_on = verify(&proof);
        tracing::info!("[GATE-B-ON] honest verify (reconstruction ON) => {honest_on}");
        assert_eq!(
            honest_on, "OK",
            "honest FIX-on proof must verify WITH the reconstruction ON (gate-b-on); \
             a reconstruction error here means the leaf-assembly transform is wrong"
        );

        let mut forged = proof.clone();
        let bf = forged.shard_proofs[0].jagged_shard_proof.as_mut();

        let nchips = bf.opened_values.chips.len();
        assert!(nchips >= 2, "need >=2 chips to forge area-preserving heights");

        let bit_len = bf.opened_values.chips[0].quotient[0].len();
        let one = <KoalaBear as p3_field::PrimeCharacteristicRing>::ONE;
        let zero = <KoalaBear as p3_field::PrimeCharacteristicRing>::ZERO;
        let one_ef = p3_field::extension::BinomialExtensionField::<KoalaBear, 4>::from(one);
        let zero_ef = p3_field::extension::BinomialExtensionField::<KoalaBear, 4>::from(zero);

        let mut raise: Option<(usize, usize)> = None;
        let mut lower: Option<(usize, usize)> = None;
        'outer: for bit in (1..bit_len).rev() {
            let mut r = None;
            let mut l = None;
            for c in 0..nchips {
                let v = bf.opened_values.chips[c].quotient[0][bit];
                if v == zero_ef && r.is_none() {
                    r = Some(c);
                } else if v == one_ef && l.is_none() {
                    l = Some(c);
                }
            }
            if let (Some(rc), Some(lc)) = (r, l) {
                if rc != lc {
                    raise = Some((rc, bit));
                    lower = Some((lc, bit));
                    break 'outer;
                }
            }
        }
        let (rc, rb) = raise.expect("found a chip with a settable high degree bit");
        let (lc, lb) = lower.expect("found a chip with a clearable high degree bit");
        tracing::info!(
            "[GATE-C] area-preserving forgery: raise chip[{rc}] bit {rb} (0->1), \
             lower chip[{lc}] bit {lb} (1->0); bit_len={bit_len}"
        );
        bf.opened_values.chips[rc].quotient[0][rb] = one_ef;
        bf.opened_values.chips[lc].quotient[0][lb] = zero_ef;

        let red = verify(&forged);
        tracing::info!("[GATE-C] flag-off forged verify => {red}");
        assert!(
            red.contains("last-layer reconstruction"),
            "the area-preserving height forgery must be rejected at the last-layer \
             reconstruction (it runs unconditionally); got: {red}"
        );

        let green = verify(&forged);
        tracing::info!("[GATE-C] GREEN (reconstruction on) verify => {green}");
        assert!(
            green.contains("last-layer reconstruction"),
            "GREEN: the reconstruction must reject the area-preserving height forgery \
             at the last-layer assert; got: {green}"
        );
    }

    // Height-soundness tests at raw heights (`shape_config = None`, no shape
    // padding, so they are fast): the honest cases verify and the
    // area-preserving height forgeries are rejected.

    #[cfg(test)]
    fn stage0_prove_fixoff(
        program: Program,
        shard_size: usize,
        inputs: ZKMStdin,
    ) -> (
        zkm_pcs::MachineProof<KoalaBearPoseidon2>,
        StarkMachine<KoalaBearPoseidon2, MipsAir<KoalaBear>>,
        StarkVerifyingKey<KoalaBearPoseidon2>,
    ) {
        use zkm_core_executor::Executor;
        use zkm_pcs::MachineProver;

        let mut opts = ZKMCoreOpts::default();
        opts.shard_size = shard_size;
        let mut runtime = Executor::new(program, opts);
        runtime.write_vecs(&inputs.buffer);
        runtime.run().unwrap();

        let config = KoalaBearPoseidon2::new();
        let machine = MipsAir::machine(config);
        let prover = CpuProver::new(MipsAir::machine(KoalaBearPoseidon2::new()));
        let (pk, _) = prover.setup(runtime.program.as_ref());
        let (proof, _output, _) = utils::prove_with_context::<_, CpuProver<_, _>>(
            &prover,
            &pk,
            Program::clone(&runtime.program),
            &inputs,
            opts,
            zkm_core_executor::ZKMContext::default(),
            None,
        )
        .unwrap();
        let (_pk, vk) = machine.setup(runtime.program.as_ref());
        (proof, machine, vk)
    }

    #[cfg(test)]
    fn stage0_verify(
        machine: &StarkMachine<KoalaBearPoseidon2, MipsAir<KoalaBear>>,
        vk: &StarkVerifyingKey<KoalaBearPoseidon2>,
        p: &zkm_pcs::MachineProof<KoalaBearPoseidon2>,
    ) -> String {
        use zkm_pcs::StarkGenericConfig;
        let mut challenger = machine.config().challenger();
        match machine.verify(vk, p, &mut challenger) {
            Ok(()) => "OK".to_string(),
            Err(e) => format!("{e}"),
        }
    }

    #[cfg(test)]
    fn stage0_apply_height_forgery(
        forged: &mut zkm_pcs::MachineProof<KoalaBearPoseidon2>,
    ) -> Option<String> {
        let bf = forged.shard_proofs[0].jagged_shard_proof.as_mut();
        let nchips = bf.opened_values.chips.len();
        if nchips < 2 {
            return None;
        }
        let bit_len = bf.opened_values.chips[0].quotient[0].len();
        let one = <KoalaBear as p3_field::PrimeCharacteristicRing>::ONE;
        let zero = <KoalaBear as p3_field::PrimeCharacteristicRing>::ZERO;
        let one_ef = p3_field::extension::BinomialExtensionField::<KoalaBear, 4>::from(one);
        let zero_ef = p3_field::extension::BinomialExtensionField::<KoalaBear, 4>::from(zero);

        let mut raise: Option<(usize, usize)> = None;
        let mut lower: Option<(usize, usize)> = None;
        'outer: for bit in (1..bit_len).rev() {
            let mut r = None;
            let mut l = None;
            for c in 0..nchips {
                let v = bf.opened_values.chips[c].quotient[0][bit];
                if v == zero_ef && r.is_none() {
                    r = Some(c);
                } else if v == one_ef && l.is_none() {
                    l = Some(c);
                }
            }
            if let (Some(rc), Some(lc)) = (r, l) {
                if rc != lc {
                    raise = Some((rc, bit));
                    lower = Some((lc, bit));
                    break 'outer;
                }
            }
        }
        let (rc, rb) = raise?;
        let (lc, lb) = lower?;
        bf.opened_values.chips[rc].quotient[0][rb] = one_ef;
        bf.opened_values.chips[lc].quotient[0][lb] = zero_ef;
        Some(format!(
            "area-preserving forgery: raise chip[{rc}] bit {rb} (0->1), \
             lower chip[{lc}] bit {lb} (1->0); nchips={nchips} bit_len={bit_len}"
        ))
    }

    #[test]
    fn stage0_tiny_honest_fixoff() {
        setup_logger();
        let (proof, machine, vk) = stage0_prove_fixoff(simple_program(), 262_144, ZKMStdin::new());
        let r = stage0_verify(&machine, &vk, &proof);
        tracing::info!("[STAGE0-TINY-HONEST] FIX-off raw-height verify => {r}");
        assert_eq!(r, "OK", "honest FIX-off tiny proof must verify (stage-0 fast harness)");
    }

    #[test]
    fn stage0_fib_honest_fixoff() {
        setup_logger();
        let (proof, machine, vk) = stage0_prove_fixoff(fibonacci_program(), 262_144, fib_stdin());
        let r = stage0_verify(&machine, &vk, &proof);
        tracing::info!("[STAGE0-FIB-HONEST] FIX-off raw-height verify => {r}");
        assert_eq!(r, "OK", "honest FIX-off fibonacci proof must verify (mixed-height gate)");
    }

    #[test]
    fn stage0_tiny_forgery_baseline_fixoff() {
        setup_logger();
        let (proof, machine, vk) = stage0_prove_fixoff(simple_program(), 262_144, ZKMStdin::new());

        let honest = stage0_verify(&machine, &vk, &proof);
        assert_eq!(honest, "OK", "honest tiny proof must verify before forging");

        let mut forged = proof.clone();
        match stage0_apply_height_forgery(&mut forged) {
            None => {
                tracing::warn!(
                    "[STAGE0-TINY-FORGERY] tiny program cannot host a genuine \
                     area-preserving height forgery (too few chips / no opposite \
                     degree-bit pair); relying on the fibonacci baseline (0.3b)."
                );
            }
            Some(desc) => {
                tracing::info!("[STAGE0-TINY-FORGERY] {desc}");
                let baseline = stage0_verify(&machine, &vk, &forged);
                tracing::info!("[STAGE0-TINY-FORGERY] forged verify (recon off) => {baseline}");
                assert_ne!(
                    baseline, "OK",
                    "FORGERY MUST BE REJECTED (tiny): an area-preserving height \
                     forgery verified with the reconstruction off.  This hole was \
                     closed by the degree-masked height-soundness assert; a pass \
                     here means it has REOPENED."
                );
            }
        }
    }

    #[cfg(test)]
    fn stage3_prove_fixoff_rev(
        program: Program,
        shard_size: usize,
        inputs: ZKMStdin,
    ) -> (
        zkm_pcs::MachineProof<KoalaBearPoseidon2>,
        StarkMachine<KoalaBearPoseidon2, MipsAir<KoalaBear>>,
        StarkVerifyingKey<KoalaBearPoseidon2>,
    ) {
        stage0_prove_fixoff(program, shard_size, inputs)
    }

    #[cfg(test)]
    fn stage3_verify_rev(
        machine: &StarkMachine<KoalaBearPoseidon2, MipsAir<KoalaBear>>,
        vk: &StarkVerifyingKey<KoalaBearPoseidon2>,
        p: &zkm_pcs::MachineProof<KoalaBearPoseidon2>,
    ) -> String {
        use zkm_pcs::StarkGenericConfig;
        let mut challenger = machine.config().challenger();
        match machine.verify(vk, p, &mut challenger) {
            Ok(()) => "OK".to_string(),
            Err(e) => format!("{e}"),
        }
    }

    #[cfg(test)]
    fn stage0_apply_adaptive_full_forgery(
        forged: &mut zkm_pcs::MachineProof<KoalaBearPoseidon2>,
    ) -> Option<String> {
        use p3_field::PrimeCharacteristicRing;
        let desc = {
            let bf = forged.shard_proofs[0].jagged_shard_proof.as_mut();
            let nchips = bf.opened_values.chips.len();
            if nchips < 2 {
                return None;
            }
            let bit_len = bf.opened_values.chips[0].quotient[0].len();
            type EF = p3_field::extension::BinomialExtensionField<KoalaBear, 4>;
            let one_ef = EF::from(KoalaBear::ONE);
            let zero_ef = EF::from(KoalaBear::ZERO);
            let mut raise: Option<(usize, usize)> = None;
            let mut lower: Option<(usize, usize)> = None;
            'outer: for bit in (1..bit_len).rev() {
                let mut r = None;
                let mut l = None;
                for c in 0..nchips {
                    let v = bf.opened_values.chips[c].quotient[0][bit];
                    if v == zero_ef && r.is_none() {
                        r = Some(c);
                    } else if v == one_ef && l.is_none() {
                        l = Some(c);
                    }
                }
                if let (Some(rc), Some(lc)) = (r, l) {
                    if rc != lc {
                        raise = Some((rc, bit));
                        lower = Some((lc, bit));
                        break 'outer;
                    }
                }
            }
            let (rc, rb) = raise?;
            let (lc, lb) = lower?;
            bf.opened_values.chips[rc].quotient[0][rb] = one_ef;
            bf.opened_values.chips[lc].quotient[0][lb] = zero_ef;
            (rc, rb, lc, lb, nchips, bit_len)
        };
        let (rc, rb, lc, lb, nchips, bit_len) = desc;

        let bf = forged.shard_proofs[0].jagged_shard_proof.as_mut();
        type EF = p3_field::extension::BinomialExtensionField<KoalaBear, 4>;
        let scale = EF::from(KoalaBear::from_u32(2));
        let mut touched = 0usize;
        for ce in bf.logup_gkr_proof.logup_evaluations.chip_openings.values_mut() {
            if let Some(mf) = ce.main_trace_evaluations_full.as_mut() {
                for v in mf.iter_mut() {
                    *v *= scale;
                }
                touched += 1;
            }
            if let Some(pf) = ce.preprocessed_trace_evaluations_full.as_mut() {
                for v in pf.iter_mut() {
                    *v *= scale;
                }
            }
        }
        Some(format!(
            "ADAPTIVE forgery: degree raise chip[{rc}] bit {rb} (0->1), lower \
             chip[{lc}] bit {lb} (1->0); + scaled *_full on {touched} chip_openings \
             by 2; nchips={nchips} bit_len={bit_len}"
        ))
    }

    #[test]
    fn stage3_rev_tiny_flip() {
        setup_logger();
        let (proof, machine, vk) =
            stage3_prove_fixoff_rev(simple_program(), 262_144, ZKMStdin::new());

        let honest_on = stage3_verify_rev(&machine, &vk, &proof);
        tracing::info!("[STAGE3-TINY] (a) honest recon-ON under rev => {honest_on}");
        assert_eq!(
            honest_on, "OK",
            "ANTI-CONFOUND: honest tiny FIX-off proof must ACCEPT with the \
             reconstruction ON under rev (else the reconstruction is mis-wired to \
             the rev/natural convention)"
        );

        let mut forged = proof.clone();
        match stage0_apply_height_forgery(&mut forged) {
            None => {
                tracing::warn!(
                    "[STAGE3-TINY] (b) tiny program cannot host an area-preserving \
                     height forgery (too few chips / no opposite-bit pair); the \
                     fibonacci flip (stage3_rev_fib_flip) is the binding gate."
                );
            }
            Some(desc) => {
                tracing::info!("[STAGE3-TINY] (b) {desc}");
                let on = stage3_verify_rev(&machine, &vk, &forged);
                tracing::info!("[STAGE3-TINY] (b) recon-ON forged => {on}");
                assert!(
                    on.contains("last-layer reconstruction"),
                    "THE FLIP (tiny): the degree-only forgery must REJECT at the \
                     last-layer reconstruction with recon ON under rev; got: {on}"
                );
            }
        }
    }

    #[test]
    fn stage3_rev_fib_flip() {
        setup_logger();
        let (proof, machine, vk) =
            stage3_prove_fixoff_rev(fibonacci_program(), 262_144, fib_stdin());

        let honest_on = stage3_verify_rev(&machine, &vk, &proof);
        tracing::info!("[STAGE3-FIB] (a) honest recon-ON under rev => {honest_on}");
        assert_eq!(
            honest_on, "OK",
            "ANTI-CONFOUND: honest fib FIX-off proof must ACCEPT with the \
             reconstruction ON under rev (else the reconstruction is mis-wired to \
             the rev/natural convention)"
        );

        let mut forged = proof.clone();
        let desc = stage0_apply_height_forgery(&mut forged)
            .expect("fibonacci (mixed-height) must host an area-preserving forgery");
        tracing::info!("[STAGE3-FIB] (b) {desc}");
        let on = stage3_verify_rev(&machine, &vk, &forged);
        tracing::info!("[STAGE3-FIB] (b) recon-ON forged => {on}");
        assert!(
            on.contains("last-layer reconstruction"),
            "THE FLIP (fib): the degree-only forgery must REJECT at the last-layer \
             reconstruction with recon ON under rev; got: {on}"
        );
    }

    #[test]
    fn stage3_rev_adaptive_forgery() {
        setup_logger();
        let (proof, machine, vk) =
            stage3_prove_fixoff_rev(fibonacci_program(), 262_144, fib_stdin());

        let h_on = stage3_verify_rev(&machine, &vk, &proof);
        assert_eq!(h_on, "OK", "honest must accept recon-ON under rev before adaptive");

        let mut forged = proof.clone();
        let desc = stage0_apply_adaptive_full_forgery(&mut forged)
            .expect("fib must host the adaptive forgery");
        tracing::info!("[STAGE3-ADAPTIVE] {desc}");

        let on = stage3_verify_rev(&machine, &vk, &forged);
        tracing::info!("[STAGE3-ADAPTIVE] recon-ON FULL verify => {on}");
        assert_ne!(
            on, "OK",
            "SOUNDNESS: the adaptive forgery (degree + tampered *_full) MUST reject \
             under full verify; if it survives, *_full is an unbound free variable \
             and must be collapsed onto the bound opening"
        );

        let mut deg_only = proof.clone();
        let _ =
            stage0_apply_height_forgery(&mut deg_only).expect("fib hosts the degree-only forgery");
        let i_on = stage3_verify_rev(&machine, &vk, &deg_only);
        tracing::info!("[STAGE3-ADAPTIVE] (i) degree-only + honest *_full, recon-ON => {i_on}");
        assert!(
            i_on.contains("last-layer reconstruction"),
            "(i) forged degree with HONEST *_full must REJECT at the reconstruction \
             (so the adversary is forced to change *_full); got: {i_on}"
        );
        tracing::warn!(
            "[STAGE3-ADAPTIVE] CONCLUSION: degree-only forgery is caught by the \
             reconstruction, and any *_full deviation is caught by the claim \
             binding (see stage3_rev_full_binding_probe) ⇒ adaptive forgery \
             rejects; *_full is bound (NOT retired)."
        );
    }

    #[test]
    fn stage3_rev_full_binding_probe() {
        use p3_field::PrimeCharacteristicRing;
        setup_logger();
        let (proof, machine, vk) =
            stage3_prove_fixoff_rev(fibonacci_program(), 262_144, fib_stdin());

        let mut forged = proof.clone();
        type EF = p3_field::extension::BinomialExtensionField<KoalaBear, 4>;
        let scale = EF::from(KoalaBear::from_u32(3));
        let bf = forged.shard_proofs[0].jagged_shard_proof.as_mut();
        let mut touched = 0usize;
        for ce in bf.logup_gkr_proof.logup_evaluations.chip_openings.values_mut() {
            if let Some(mf) = ce.main_trace_evaluations_full.as_mut() {
                if let Some(v) = mf.first_mut() {
                    *v *= scale;
                    touched += 1;
                }
            }
        }
        tracing::info!("[STAGE3-BINDPROBE] perturbed *_full[0] on {touched} chip_openings");

        let off = stage3_verify_rev(&machine, &vk, &forged);
        tracing::info!("[STAGE3-BINDPROBE] FULL verify => {off}");
        assert_ne!(
            off, "OK",
            "BINDING: perturbing *_full alone must reject — proves *_full is \
             bound to the commitment via the rev claim-collapse"
        );
    }

    #[test]
    fn stage3_rev_attributable() {
        use p3_field::PrimeCharacteristicRing;
        setup_logger();
        let (proof, machine, vk) =
            stage3_prove_fixoff_rev(fibonacci_program(), 262_144, fib_stdin());
        type EF = p3_field::extension::BinomialExtensionField<KoalaBear, 4>;
        let one_ef = EF::from(KoalaBear::ONE);
        let zero_ef = EF::from(KoalaBear::ZERO);

        let mut forged = proof.clone();
        let bf = forged.shard_proofs[0].jagged_shard_proof.as_mut();
        let nchips = bf.opened_values.chips.len();
        let bit_len = bf.opened_values.chips[0].quotient[0].len();
        let mut raise: Option<(usize, usize)> = None;
        let mut lower: Option<(usize, usize)> = None;
        'outer: for bit in (1..bit_len).rev() {
            let (mut r, mut l) = (None, None);
            for c in 0..nchips {
                let v = bf.opened_values.chips[c].quotient[0][bit];
                if v == zero_ef && r.is_none() {
                    r = Some(c);
                } else if v == one_ef && l.is_none() {
                    l = Some(c);
                }
            }
            if let (Some(rc), Some(lc)) = (r, l) {
                if rc != lc {
                    raise = Some((rc, bit));
                    lower = Some((lc, bit));
                    break 'outer;
                }
            }
        }
        let (rc, rb) = raise.expect("fib hosts a degree forgery");
        let (lc, lb) = lower.unwrap();
        bf.opened_values.chips[rc].quotient[0][rb] = one_ef;
        bf.opened_values.chips[lc].quotient[0][lb] = zero_ef;
        tracing::info!(
            "[STAGE3-ATTR] forged degree raise chip[{rc}] bit {rb}, lower chip[{lc}] bit {lb}"
        );

        let forged_on = stage3_verify_rev(&machine, &vk, &forged);
        tracing::info!("[STAGE3-ATTR] forged recon-ON => {forged_on}");
        assert!(
            forged_on.contains("last-layer reconstruction"),
            "forged degree must reject at the reconstruction; got: {forged_on}"
        );

        let bf2 = forged.shard_proofs[0].jagged_shard_proof.as_mut();
        bf2.opened_values.chips[rc].quotient[0][rb] = zero_ef;
        bf2.opened_values.chips[lc].quotient[0][lb] = one_ef;
        let reverted_on = stage3_verify_rev(&machine, &vk, &forged);
        tracing::info!("[STAGE3-ATTR] reverted (degree bits only) recon-ON => {reverted_on}");
        assert_eq!(
            reverted_on, "OK",
            "ATTRIBUTABLE: reverting ONLY the degree bits must restore acceptance \
             (proves the reject is caused by the degree tamper, not a side effect)"
        );
    }

    #[test]
    fn stage0_fib_forgery_baseline_fixoff() {
        setup_logger();
        let (proof, machine, vk) = stage0_prove_fixoff(fibonacci_program(), 262_144, fib_stdin());

        let honest = stage0_verify(&machine, &vk, &proof);
        assert_eq!(honest, "OK", "honest fibonacci proof must verify before forging");

        let mut forged = proof.clone();
        let desc = stage0_apply_height_forgery(&mut forged)
            .expect("fibonacci (mixed-height) must host an area-preserving height forgery");
        tracing::info!("[STAGE0-FIB-FORGERY] {desc}");

        let baseline = stage0_verify(&machine, &vk, &forged);
        tracing::info!("[STAGE0-FIB-FORGERY] forged verify (recon off) => {baseline}");
        assert_ne!(
            baseline, "OK",
            "FORGERY MUST BE REJECTED (fib): an area-preserving height forgery \
             verified with the reconstruction off.  This hole was closed by the \
             degree-masked height-soundness assert; a pass here means it has \
             REOPENED."
        );
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

        assert_eq!(pk.chip_ordering, deserialized_pk.chip_ordering);

        let serialized_vk = bincode::serialize(&vk).unwrap();
        let deserialized_vk: StarkVerifyingKey<KoalaBearPoseidon2> =
            bincode::deserialize(&serialized_vk).unwrap();
        assert_eq!(vk.commit, deserialized_vk.commit);
        assert_eq!(vk.pc_start, deserialized_vk.pc_start);
        assert_eq!(vk.chip_information.len(), deserialized_vk.chip_information.len());
        for (a, b) in vk.chip_information.iter().zip(deserialized_vk.chip_information.iter()) {
            assert_eq!(a.0, b.0);
            assert_eq!(a.1.log_size, b.1.log_size);
            assert_eq!(a.1.shift, b.1.shift);
            assert_eq!(a.2 .1, b.2 .1);
            assert_eq!(a.2 .0, b.2 .0);
        }
        assert_eq!(vk.chip_ordering, deserialized_vk.chip_ordering);
    }

    // -----------------------------------------------------------------------
    // Syscall soundness regression tests
    //
    // These tests exercise Go ELF programs that trigger linux syscalls
    // (mmap, clone, brk, fcntl, read, write, exit_group, nop) through the
    // Go runtime initialization. They validate that the bidirectional flag
    // constraints, bytewise heap updates, and other soundness fixes do not
    // reject honest traces.
    //
    // Covered issues:
    //   #1  is_sys_linux bidirectional
    //   #2  SysLinux flag routing bidirectional
    //   #3  is_mmap_a0_0 bidirectional
    //   #4  Reduced arg1/arg2 bound to packed half-words
    //   #5  mmap A3 output zeroed unconditionally
    //   #6  page_offset decomposition + range check + alignment
    //   #7  exit_group result zeroed
    //   #8  fnctl(a1==1) result constrained
    //   #9  is_a0_0/1/2 bidirectional
    //   write: read value = prev_value
    //   mmap: bytewise heap update via AddOperation
    //   is_a1_1/3 bidirectional
    // -----------------------------------------------------------------------

    /// Exercises SYS_WRITE, exit_group, mmap, clone, brk, fcntl, and nop
    /// syscall paths through the Go hello_world runtime.
    #[test]
    fn test_syscall_soundness_hello_world() {
        setup_logger();
        let program = hello_world_program();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    /// Exercises the full Go runtime init: mmap2 with a0=0 (heap allocation),
    /// fcntl with a1=1 and a1=3, clone, brk, read, and exit_group.
    #[test]
    fn test_syscall_soundness_fibonacci() {
        setup_logger();
        let program = fibonacci_program();
        run_test_with_stdin::<CpuProver<_, _>>(program, fib_stdin()).unwrap();
    }
}

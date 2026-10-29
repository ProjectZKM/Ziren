use crate::{
    global::GlobalChip,
    memory::{MemoryBumpChip, MemoryChipType, MemoryLocalChip},
    syscall::precompiles::{
        fptower::{Fp2AddSubAssignChip, Fp2MulAssignChip, FpOpChip},
        poseidon2::Poseidon2PermuteChip,
    },
};
use core::fmt;
use hashbrown::HashMap;
pub use mips_chips::*;
use p3_field::PrimeField32;
use strum_macros::{EnumDiscriminants, EnumIter};
use zkm_curves::weierstrass::{bls12_381::Bls12381BaseField, bn254::Bn254BaseField};
use zkm_pcs::{
    air::{LookupScope, MachineAir, PicusInfo, ZKM_PROOF_NUM_PV_ELTS},
    Chip, StarkGenericConfig, StarkMachine,
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
    /// The shard verifier anchors a shard's public values to the trace iff the
    /// MACHINE has a bus `eval_public_values` closes, whatever chips the shard
    /// names.  The core machine has them; a chip set such as the Byte table
    /// alone has none, so a verifier deciding from the shard's chips would
    /// leave such a shard's public values (its global cumulative sum among
    /// them) bound to nothing.
    #[test]
    fn core_machine_anchors_public_values_for_every_shard() {
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::shard_level::verifier::chips_touch_public_value_buses;

        let machine =
            MipsAir::machine(zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2::default());
        assert!(machine.has_public_value_buses());
        let byte = machine.chips().iter().filter(|chip| chip.name() == "Byte").collect::<Vec<_>>();
        assert_eq!(byte.len(), 1, "the core machine has one Byte chip");
        assert!(!chips_touch_public_value_buses(byte.iter().copied()));
    }

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
                .map(<_ as p3_air::BaseAir<KoalaBear>>::preprocessed_width)
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
            rec_batch, 128,
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
        let result = crate::utils::run_test_core::<CpuProver<_, _>>(runtime, ZKMStdin::new());
        for sp in &result.unwrap().shard_proofs {
            let bsp = sp.jagged_shard_proof.as_ref();
            assert!(
                matches!(
                    &bsp.evaluation_proof,
                    zkm_pcs::shard_level::shard_proof::EvaluationProof::Bundle(_)
                ),
                "expected a Bundle evaluation proof"
            );
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
        prove::<_, CpuProver<_, _>>(program, &stdin, KoalaBearPoseidon2::new(), opts).unwrap();
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
        )
        .unwrap();
    }

    #[test]
    fn test_fibonacci_core_verify_raw_heights() {
        use zkm_core_executor::Executor;
        setup_logger();
        let program = fibonacci_program();
        let mut opts = ZKMCoreOpts::default();
        opts.shard_size = 262_144;
        let mut runtime = Executor::new(program, opts);
        runtime.write_vecs(&fib_stdin().buffer);
        runtime.run().unwrap();
        utils::run_test_core::<CpuProver<_, _>>(runtime, fib_stdin()).unwrap();
    }

    // Height-soundness tests: the honest cases verify and the area-preserving
    // height forgeries are rejected.

    #[cfg(test)]
    fn prove_raw_heights(
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
        )
        .unwrap();
        let (_pk, vk) = machine.setup(runtime.program.as_ref());
        (proof, machine, vk)
    }

    #[cfg(test)]
    fn verify_to_string(
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
    fn apply_height_forgery(
        forged: &mut zkm_pcs::MachineProof<KoalaBearPoseidon2>,
    ) -> Option<String> {
        let jagged = forged.shard_proofs[0].jagged_shard_proof.as_mut();
        let nchips = jagged.opened_values.chips.len();
        if nchips < 2 {
            return None;
        }
        let bit_len = jagged.opened_values.chips[0].quotient[0].len();
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
                let v = jagged.opened_values.chips[c].quotient[0][bit];
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
        jagged.opened_values.chips[rc].quotient[0][rb] = one_ef;
        jagged.opened_values.chips[lc].quotient[0][lb] = zero_ef;
        Some(format!(
            "area-preserving forgery: raise chip[{rc}] bit {rb} (0->1), \
             lower chip[{lc}] bit {lb} (1->0); nchips={nchips} bit_len={bit_len}"
        ))
    }

    #[test]
    fn test_raw_height_simple_verifies() {
        setup_logger();
        let (proof, machine, vk) = prove_raw_heights(simple_program(), 262_144, ZKMStdin::new());
        let r = verify_to_string(&machine, &vk, &proof);
        tracing::info!("simple raw-height verify => {r}");
        assert_eq!(r, "OK", "honest raw-height simple-program proof must verify");
    }

    #[test]
    fn test_raw_height_fibonacci_verifies() {
        setup_logger();
        let (proof, machine, vk) = prove_raw_heights(fibonacci_program(), 262_144, fib_stdin());
        let r = verify_to_string(&machine, &vk, &proof);
        tracing::info!("fibonacci raw-height verify => {r}");
        assert_eq!(r, "OK", "honest raw-height fibonacci proof (mixed heights) must verify");
    }

    #[test]
    fn test_raw_height_forgery_rejected_simple() {
        setup_logger();
        let (proof, machine, vk) = prove_raw_heights(simple_program(), 262_144, ZKMStdin::new());

        let honest = verify_to_string(&machine, &vk, &proof);
        assert_eq!(honest, "OK", "honest tiny proof must verify before forging");

        let mut forged = proof.clone();
        match apply_height_forgery(&mut forged) {
            None => {
                tracing::warn!(
                    "tiny program cannot host a genuine area-preserving height \
                     forgery (too few chips / no opposite degree-bit pair); \
                     test_raw_height_forgery_rejected_fibonacci covers it."
                );
            }
            Some(desc) => {
                tracing::info!("{desc}");
                let baseline = verify_to_string(&machine, &vk, &forged);
                tracing::info!("forged verify => {baseline}");
                assert_ne!(
                    baseline, "OK",
                    "FORGERY MUST BE REJECTED (tiny): an area-preserving height \
                     forgery verified.  The degree-masked height-soundness assert \
                     closes this hole; a pass here means it has REOPENED."
                );
            }
        }
    }

    #[cfg(test)]
    fn apply_adaptive_full_forgery(
        forged: &mut zkm_pcs::MachineProof<KoalaBearPoseidon2>,
    ) -> Option<String> {
        use p3_field::PrimeCharacteristicRing;
        let desc = {
            let jagged = forged.shard_proofs[0].jagged_shard_proof.as_mut();
            let nchips = jagged.opened_values.chips.len();
            if nchips < 2 {
                return None;
            }
            let bit_len = jagged.opened_values.chips[0].quotient[0].len();
            type EF = p3_field::extension::BinomialExtensionField<KoalaBear, 4>;
            let one_ef = EF::from(KoalaBear::ONE);
            let zero_ef = EF::from(KoalaBear::ZERO);
            let mut raise: Option<(usize, usize)> = None;
            let mut lower: Option<(usize, usize)> = None;
            'outer: for bit in (1..bit_len).rev() {
                let mut r = None;
                let mut l = None;
                for c in 0..nchips {
                    let v = jagged.opened_values.chips[c].quotient[0][bit];
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
            jagged.opened_values.chips[rc].quotient[0][rb] = one_ef;
            jagged.opened_values.chips[lc].quotient[0][lb] = zero_ef;
            (rc, rb, lc, lb, nchips, bit_len)
        };
        let (rc, rb, lc, lb, nchips, bit_len) = desc;

        let jagged = forged.shard_proofs[0].jagged_shard_proof.as_mut();
        type EF = p3_field::extension::BinomialExtensionField<KoalaBear, 4>;
        let scale = EF::from(KoalaBear::from_u32(2));
        let mut touched = 0usize;
        for ce in jagged.logup_gkr_proof.logup_evaluations.chip_openings.values_mut() {
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

    /// Whether a verifier verdict is the shard verifier's rejection of opened
    /// degree bits that are not the bits of the chip's observed height.  This
    /// check runs before the LogUp-GKR verification, so a forged degree never
    /// reaches the last-layer reconstruction.
    fn rejected_on_degree_bits(verdict: &str) -> bool {
        verdict.contains("the opened degree bits are not the bits of its observed height")
    }

    #[test]
    fn test_height_forgery_rejected_at_reconstruction_simple() {
        setup_logger();
        let (proof, machine, vk) = prove_raw_heights(simple_program(), 262_144, ZKMStdin::new());

        let honest = verify_to_string(&machine, &vk, &proof);
        tracing::info!("(a) honest verify => {honest}");
        assert_eq!(
            honest, "OK",
            "honest tiny raw-height proof must verify (else the reconstruction is \
             mis-wired to the rev/natural row convention)"
        );

        let mut forged = proof.clone();
        match apply_height_forgery(&mut forged) {
            None => {
                tracing::warn!(
                    "(b) tiny program cannot host an area-preserving height forgery \
                     (too few chips / no opposite-bit pair); \
                     test_height_forgery_rejected_at_reconstruction_fibonacci covers it."
                );
            }
            Some(desc) => {
                tracing::info!("(b) {desc}");
                let on = verify_to_string(&machine, &vk, &forged);
                tracing::info!("(b) forged verify => {on}");
                assert!(
                    rejected_on_degree_bits(&on),
                    "tiny: the degree-only forgery must be rejected on its opened degree \
                     bits; got: {on}"
                );
            }
        }
    }

    #[test]
    fn test_height_forgery_rejected_at_reconstruction_fibonacci() {
        setup_logger();
        let (proof, machine, vk) = prove_raw_heights(fibonacci_program(), 262_144, fib_stdin());

        let honest = verify_to_string(&machine, &vk, &proof);
        tracing::info!("(a) honest verify => {honest}");
        assert_eq!(
            honest, "OK",
            "honest fibonacci raw-height proof must verify (else the reconstruction \
             is mis-wired to the rev/natural row convention)"
        );

        let mut forged = proof.clone();
        let desc = apply_height_forgery(&mut forged)
            .expect("fibonacci (mixed-height) must host an area-preserving forgery");
        tracing::info!("(b) {desc}");
        let on = verify_to_string(&machine, &vk, &forged);
        tracing::info!("(b) forged verify => {on}");
        assert!(
            rejected_on_degree_bits(&on),
            "fibonacci: the degree-only forgery must be rejected on its opened degree \
             bits; got: {on}"
        );
    }

    #[test]
    fn test_adaptive_height_forgery_rejected() {
        setup_logger();
        let (proof, machine, vk) = prove_raw_heights(fibonacci_program(), 262_144, fib_stdin());

        let h_on = verify_to_string(&machine, &vk, &proof);
        assert_eq!(h_on, "OK", "honest proof must verify before the adaptive forgery");

        let mut forged = proof.clone();
        let desc =
            apply_adaptive_full_forgery(&mut forged).expect("fib must host the adaptive forgery");
        tracing::info!("{desc}");

        let on = verify_to_string(&machine, &vk, &forged);
        tracing::info!("adaptive forged verify => {on}");
        assert_ne!(
            on, "OK",
            "SOUNDNESS: the adaptive forgery (degree + tampered *_full) MUST reject \
             under full verify; if it survives, *_full is an unbound free variable \
             and must be collapsed onto the bound opening"
        );

        let mut deg_only = proof.clone();
        let _ = apply_height_forgery(&mut deg_only).expect("fib hosts the degree-only forgery");
        let i_on = verify_to_string(&machine, &vk, &deg_only);
        tracing::info!("(i) degree-only + honest *_full verify => {i_on}");
        assert!(
            rejected_on_degree_bits(&i_on),
            "(i) forged degree with HONEST *_full must REJECT on the opened degree bits \
             (so the adversary is forced to change *_full); got: {i_on}"
        );
    }

    #[test]
    fn test_full_trace_evaluations_bound() {
        use p3_field::PrimeCharacteristicRing;
        setup_logger();
        let (proof, machine, vk) = prove_raw_heights(fibonacci_program(), 262_144, fib_stdin());

        let mut forged = proof.clone();
        type EF = p3_field::extension::BinomialExtensionField<KoalaBear, 4>;
        let scale = EF::from(KoalaBear::from_u32(3));
        let jagged = forged.shard_proofs[0].jagged_shard_proof.as_mut();
        let mut touched = 0usize;
        for ce in jagged.logup_gkr_proof.logup_evaluations.chip_openings.values_mut() {
            if let Some(mf) = ce.main_trace_evaluations_full.as_mut() {
                if let Some(v) = mf.first_mut() {
                    *v *= scale;
                    touched += 1;
                }
            }
        }
        tracing::info!("perturbed *_full[0] on {touched} chip_openings");

        let off = verify_to_string(&machine, &vk, &forged);
        tracing::info!("full verify => {off}");
        assert_ne!(
            off, "OK",
            "BINDING: perturbing *_full alone must reject — proves *_full is \
             bound to the commitment via the rev claim-collapse"
        );
    }

    #[test]
    fn test_height_forgery_rejection_attributable_to_degree_bits() {
        use p3_field::PrimeCharacteristicRing;
        setup_logger();
        let (proof, machine, vk) = prove_raw_heights(fibonacci_program(), 262_144, fib_stdin());
        type EF = p3_field::extension::BinomialExtensionField<KoalaBear, 4>;
        let one_ef = EF::from(KoalaBear::ONE);
        let zero_ef = EF::from(KoalaBear::ZERO);

        let mut forged = proof.clone();
        let jagged = forged.shard_proofs[0].jagged_shard_proof.as_mut();
        let nchips = jagged.opened_values.chips.len();
        let bit_len = jagged.opened_values.chips[0].quotient[0].len();
        let mut raise: Option<(usize, usize)> = None;
        let mut lower: Option<(usize, usize)> = None;
        'outer: for bit in (1..bit_len).rev() {
            let (mut r, mut l) = (None, None);
            for c in 0..nchips {
                let v = jagged.opened_values.chips[c].quotient[0][bit];
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
        jagged.opened_values.chips[rc].quotient[0][rb] = one_ef;
        jagged.opened_values.chips[lc].quotient[0][lb] = zero_ef;
        tracing::info!("forged degree raise chip[{rc}] bit {rb}, lower chip[{lc}] bit {lb}");

        let forged_on = verify_to_string(&machine, &vk, &forged);
        tracing::info!("forged verify => {forged_on}");
        assert!(
            rejected_on_degree_bits(&forged_on),
            "forged degree must reject on the opened degree bits; got: {forged_on}"
        );

        let bf2 = forged.shard_proofs[0].jagged_shard_proof.as_mut();
        bf2.opened_values.chips[rc].quotient[0][rb] = zero_ef;
        bf2.opened_values.chips[lc].quotient[0][lb] = one_ef;
        let reverted_on = verify_to_string(&machine, &vk, &forged);
        tracing::info!("reverted (degree bits only) verify => {reverted_on}");
        assert_eq!(
            reverted_on, "OK",
            "ATTRIBUTABLE: reverting ONLY the degree bits must restore acceptance \
             (proves the reject is caused by the degree tamper, not a side effect)"
        );
    }

    #[test]
    fn test_raw_height_forgery_rejected_fibonacci() {
        setup_logger();
        let (proof, machine, vk) = prove_raw_heights(fibonacci_program(), 262_144, fib_stdin());

        let honest = verify_to_string(&machine, &vk, &proof);
        assert_eq!(honest, "OK", "honest fibonacci proof must verify before forging");

        let mut forged = proof.clone();
        let desc = apply_height_forgery(&mut forged)
            .expect("fibonacci (mixed-height) must host an area-preserving height forgery");
        tracing::info!("{desc}");

        let baseline = verify_to_string(&machine, &vk, &forged);
        tracing::info!("forged verify => {baseline}");
        assert_ne!(
            baseline, "OK",
            "FORGERY MUST BE REJECTED (fib): an area-preserving height forgery \
             verified.  The degree-masked height-soundness assert closes this hole; \
             a pass here means it has REOPENED."
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

use enum_map::Enum;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

/// System Calls.
///
/// A system call is invoked by the `syscall` instruction with a specific value in register V0.
/// The syscall number is a 32-bit integer with the following little-endian layout:
///
/// | Byte 0 | Byte 1 | Byte 2 | Byte 3 |
/// | ------ | ------ | ------ | ------ |
/// |   ID0  |  ID1   | Table  | Cycles |
///
/// where:
/// - Byte 0 and Byte 1: The system call identifier.
/// - Byte 2: Whether the handler of the system call has its own table. This is used in the CPU
///   table to determine whether to lookup the syscall.
/// - Byte 3: The number of additional cycles the syscall uses. This is used to make sure the # of
///   memory accesses is bounded.
#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, EnumIter, Ord, PartialOrd, Serialize, Deserialize, Enum,
)]
#[allow(clippy::enum_clike_unportable_variant)]
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[repr(u32)]
pub enum SyscallCode {
    SYSHINTLEN = 0x00_00_00_F0,
    SYSHINTREAD = 0x00_00_00_F1,
    SYSVERIFY = 0x00_00_00_F2,

    /// Halts the program.
    HALT = 0x00_00_00_00,

    /// Write to the output buffer.
    WRITE = 0x00_00_00_02,

    /// Enter unconstrained block.
    ENTER_UNCONSTRAINED = 0x00_00_00_03,

    /// Exit unconstrained block.
    EXIT_UNCONSTRAINED = 0x00_00_00_04,

    /// Executes the `SHA_EXTEND` precompile.
    SHA_EXTEND = 0x30_01_00_05,

    /// Executes the `SHA_COMPRESS` precompile.
    SHA_COMPRESS = 0x01_01_00_06,

    /// Executes the `ED_ADD` precompile.
    ED_ADD = 0x01_01_00_07,

    /// Executes the `ED_DECOMPRESS` precompile.
    ED_DECOMPRESS = 0x00_01_00_08,

    /// Executes the `KECCAK_SPONGE` precompile.
    KECCAK_SPONGE = 0x01_01_00_09,

    /// Executes the `SECP256K1_ADD` precompile.
    SECP256K1_ADD = 0x01_01_00_0A,

    /// Executes the `SECP256K1_DOUBLE` precompile.
    SECP256K1_DOUBLE = 0x00_01_00_0B,

    /// Executes the `SECP256K1_DECOMPRESS` precompile.
    SECP256K1_DECOMPRESS = 0x00_01_00_0C,

    /// Executes the `BN254_ADD` precompile.
    BN254_ADD = 0x01_01_00_0E,

    /// Executes the `BN254_DOUBLE` precompile.
    BN254_DOUBLE = 0x00_01_00_0F,

    /// Executes the `COMMIT` precompile.
    COMMIT = 0x00_00_00_10,

    /// Executes the `COMMIT_DEFERRED_PROOFS` precompile.
    COMMIT_DEFERRED_PROOFS = 0x00_00_00_1A,

    /// Executes the `VERIFY_ZKM_PROOF` precompile.
    VERIFY_ZKM_PROOF = 0x00_00_00_1B,

    /// Executes the `BLS12381_DECOMPRESS` precompile.
    BLS12381_DECOMPRESS = 0x00_01_00_1C,

    /// Executes the `UINT256_MUL` precompile.
    UINT256_MUL = 0x01_01_00_1D,

    /// Executes the `BLS12381_ADD` precompile.
    BLS12381_ADD = 0x01_01_00_1E,

    /// Executes the `BLS12381_DOUBLE` precompile.
    BLS12381_DOUBLE = 0x00_01_00_1F,

    /// Executes the `BLS12381_FP_ADD` precompile.
    BLS12381_FP_ADD = 0x01_01_00_20,

    /// Executes the `BLS12381_FP_SUB` precompile.
    BLS12381_FP_SUB = 0x01_01_00_21,

    /// Executes the `BLS12381_FP_MUL` precompile.
    BLS12381_FP_MUL = 0x01_01_00_22,

    /// Executes the `BLS12381_FP2_ADD` precompile.
    BLS12381_FP2_ADD = 0x01_01_00_23,

    /// Executes the `BLS12381_FP2_SUB` precompile.
    BLS12381_FP2_SUB = 0x01_01_00_24,

    /// Executes the `BLS12381_FP2_MUL` precompile.
    BLS12381_FP2_MUL = 0x01_01_00_25,

    /// Executes the `BN254_FP_ADD` precompile.
    BN254_FP_ADD = 0x01_01_00_26,

    /// Executes the `BN254_FP_SUB` precompile.
    BN254_FP_SUB = 0x01_01_00_27,

    /// Executes the `BN254_FP_MUL` precompile.
    BN254_FP_MUL = 0x01_01_00_28,

    /// Executes the `BN254_FP2_ADD` precompile.
    BN254_FP2_ADD = 0x01_01_00_29,

    /// Executes the `BN254_FP2_SUB` precompile.
    BN254_FP2_SUB = 0x01_01_00_2A,

    /// Executes the `BN254_FP2_MUL` precompile.
    BN254_FP2_MUL = 0x01_01_00_2B,

    /// Executes the `SECP256R1_ADD` precompile.
    SECP256R1_ADD = 0x01_01_00_2C,

    /// Executes the `SECP256R1_DOUBLE` precompile.
    SECP256R1_DOUBLE = 0x00_01_00_2D,

    /// Executes the `SECP256R1_DECOMPRESS` precompile.
    SECP256R1_DECOMPRESS = 0x00_01_00_2E,

    /// Executes the `U256XU2048_MUL` precompile.
    U256XU2048_MUL = 0x01_01_00_2F,

    /// Mmap
    SYS_MMAP = 4210,
    SYS_MMAP2 = 4090,

    /// Brk
    SYS_BRK = 4045,

    /// Clone
    SYS_CLONE = 4120,

    /// Exit Group
    SYS_EXT_GROUP = 4246,

    /// Read
    SYS_READ = 4003,

    /// Write
    SYS_WRITE = 4004,

    /// Fcntl
    SYS_FCNTL = 4055,

    /// follows are executed as NOP syscalls
    SYS_OPEN = 4005,
    SYS_CLOSE = 4006,
    SYS_MUNMAP = 4091,
    SYS_RT_SIGACTION = 4194,
    SYS_RT_SIGPROCMASK = 4195,
    SYS_SIGALTSTACK = 4206,
    SYS_FSTAT64 = 4215,
    SYS_MADVISE = 4218,
    SYS_GETTID = 4222,
    SYS_SCHED_GETAFFINITY = 4240,
    SYS_CLOCK_GETTIME = 4263,
    SYS_OPENAT = 4288,
    SYS_PRLIMIT64 = 4338,

    /// Executes the `POSEIDON2_PERMUTE` precompile.
    POSEIDON2_PERMUTE = 0x00_01_00_30,

    SYS_LINUX = 4000, // not real syscall, used for represent all linux syscalls

    UNIMPLEMENTED = 0xFF_FF_FF_FF,
}

impl SyscallCode {
    /// Create a [`SyscallCode`] from a u32.
    #[must_use]
    pub fn from_u32(value: u32) -> Self {
        match value {
            0x00_00_00_F0 => SyscallCode::SYSHINTLEN,
            0x00_00_00_F1 => SyscallCode::SYSHINTREAD,
            0x00_00_00_F2 => SyscallCode::SYSVERIFY,

            0x00_00_00_00 => SyscallCode::HALT,
            0x00_00_00_02 => SyscallCode::WRITE,
            0x00_00_00_03 => SyscallCode::ENTER_UNCONSTRAINED,
            0x00_00_00_04 => SyscallCode::EXIT_UNCONSTRAINED,
            0x30_01_00_05 => SyscallCode::SHA_EXTEND,
            0x01_01_00_06 => SyscallCode::SHA_COMPRESS,
            0x01_01_00_07 => SyscallCode::ED_ADD,
            0x00_01_00_08 => SyscallCode::ED_DECOMPRESS,
            0x01_01_00_09 => SyscallCode::KECCAK_SPONGE,
            0x01_01_00_0A => SyscallCode::SECP256K1_ADD,
            0x00_01_00_0B => SyscallCode::SECP256K1_DOUBLE,
            0x00_01_00_0C => SyscallCode::SECP256K1_DECOMPRESS,
            0x01_01_00_0E => SyscallCode::BN254_ADD,
            0x00_01_00_0F => SyscallCode::BN254_DOUBLE,
            0x00_00_00_10 => SyscallCode::COMMIT,
            0x00_00_00_1A => SyscallCode::COMMIT_DEFERRED_PROOFS,
            0x00_00_00_1B => SyscallCode::VERIFY_ZKM_PROOF,
            0x00_01_00_30 => SyscallCode::POSEIDON2_PERMUTE,
            0x00_01_00_1C => SyscallCode::BLS12381_DECOMPRESS,
            0x01_01_00_1D => SyscallCode::UINT256_MUL,
            0x01_01_00_1E => SyscallCode::BLS12381_ADD,
            0x00_01_00_1F => SyscallCode::BLS12381_DOUBLE,
            0x01_01_00_20 => SyscallCode::BLS12381_FP_ADD,
            0x01_01_00_21 => SyscallCode::BLS12381_FP_SUB,
            0x01_01_00_22 => SyscallCode::BLS12381_FP_MUL,
            0x01_01_00_23 => SyscallCode::BLS12381_FP2_ADD,
            0x01_01_00_24 => SyscallCode::BLS12381_FP2_SUB,
            0x01_01_00_25 => SyscallCode::BLS12381_FP2_MUL,
            0x01_01_00_26 => SyscallCode::BN254_FP_ADD,
            0x01_01_00_27 => SyscallCode::BN254_FP_SUB,
            0x01_01_00_28 => SyscallCode::BN254_FP_MUL,
            0x01_01_00_29 => SyscallCode::BN254_FP2_ADD,
            0x01_01_00_2A => SyscallCode::BN254_FP2_SUB,
            0x01_01_00_2B => SyscallCode::BN254_FP2_MUL,
            0x01_01_00_2C => SyscallCode::SECP256R1_ADD,
            0x00_01_00_2D => SyscallCode::SECP256R1_DOUBLE,
            0x00_01_00_2E => SyscallCode::SECP256R1_DECOMPRESS,
            0x01_01_00_2F => SyscallCode::U256XU2048_MUL,
            4000 => SyscallCode::SYS_LINUX,
            4003 => SyscallCode::SYS_READ,
            4004 => SyscallCode::SYS_WRITE,
            4005 => SyscallCode::SYS_OPEN,
            4006 => SyscallCode::SYS_CLOSE,
            4055 => SyscallCode::SYS_FCNTL,
            4045 => SyscallCode::SYS_BRK,
            4090 => SyscallCode::SYS_MMAP2,
            4091 => SyscallCode::SYS_MUNMAP,
            4120 => SyscallCode::SYS_CLONE,
            4194 => SyscallCode::SYS_RT_SIGACTION,
            4195 => SyscallCode::SYS_RT_SIGPROCMASK,
            4206 => SyscallCode::SYS_SIGALTSTACK,
            4210 => SyscallCode::SYS_MMAP,
            4215 => SyscallCode::SYS_FSTAT64,
            4218 => SyscallCode::SYS_MADVISE,
            4222 => SyscallCode::SYS_GETTID,
            4240 => SyscallCode::SYS_SCHED_GETAFFINITY,
            4246 => SyscallCode::SYS_EXT_GROUP,
            4263 => SyscallCode::SYS_CLOCK_GETTIME,
            4288 => SyscallCode::SYS_OPENAT,
            4338 => SyscallCode::SYS_PRLIMIT64,
            _ => SyscallCode::UNIMPLEMENTED,
        }
    }

    /// Get the system call identifier.
    #[must_use]
    pub fn syscall_id(self) -> u32 {
        (self as u32) & 0x0FFFF
    }

    /// Get whether the handler of the system call has its own table.
    #[must_use]
    pub fn should_send(self) -> u32 {
        (self as u32).to_le_bytes()[2].into()
    }

    /// Get upper byte of syscall ID, which is only used by Linux syscall.
    #[must_use]
    pub fn linux_sys(self) -> u32 {
        (self as u32).to_le_bytes()[1].into()
    }

    /// Get the number of additional cycles the syscall uses.
    #[must_use]
    pub fn num_cycles(self) -> u32 {
        (self as u32).to_le_bytes()[3].into()
    }

    /// Map a syscall to another one in order to coalesce their counts.
    #[must_use]
    #[allow(clippy::match_same_arms)]
    pub fn count_map(&self) -> Self {
        match self {
            SyscallCode::BN254_FP_SUB => SyscallCode::BN254_FP_ADD,
            SyscallCode::BN254_FP_MUL => SyscallCode::BN254_FP_ADD,
            SyscallCode::BN254_FP2_SUB => SyscallCode::BN254_FP2_ADD,
            SyscallCode::BLS12381_FP_SUB => SyscallCode::BLS12381_FP_ADD,
            SyscallCode::BLS12381_FP_MUL => SyscallCode::BLS12381_FP_ADD,
            SyscallCode::BLS12381_FP2_SUB => SyscallCode::BLS12381_FP2_ADD,
            SyscallCode::SYS_MMAP2 => SyscallCode::SYS_MMAP,
            _ => *self,
        }
    }
}

impl std::fmt::Display for SyscallCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

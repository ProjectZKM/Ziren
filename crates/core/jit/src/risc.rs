//! MIPS register and operand types used by the lowering API.
//!
//! These mirror the MIPS ABI used in `zkm-core-executor`'s [`Register`]
//! enum and are kept independent so the JIT crate doesn't take a
//! circular dep on the executor.

use serde::{Deserialize, Serialize};

/// MIPS general-purpose register identifier.  R0–R31 (32 GPRs) plus
/// the four ZKM-extension slots (HI, LO, and two reserved).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum MipsRegister {
    /// `$zero` — always reads as 0; writes are silently dropped.
    Zero = 0,
    /// `$at` — assembler temporary.
    At,
    /// `$v0` — function return value, low word.
    V0,
    /// `$v1` — function return value, high word.
    V1,
    /// `$a0` — argument register 0.
    A0,
    /// `$a1` — argument register 1.
    A1,
    /// `$a2` — argument register 2.
    A2,
    /// `$a3` — argument register 3.
    A3,
    /// `$t0` — caller-saved temporary 0.
    T0,
    /// `$t1` — caller-saved temporary 1.
    T1,
    /// `$t2` — caller-saved temporary 2.
    T2,
    /// `$t3` — caller-saved temporary 3.
    T3,
    /// `$t4` — caller-saved temporary 4.
    T4,
    /// `$t5` — caller-saved temporary 5.
    T5,
    /// `$t6` — caller-saved temporary 6.
    T6,
    /// `$t7` — caller-saved temporary 7.
    T7,
    /// `$s0` — callee-saved register 0.
    S0,
    /// `$s1` — callee-saved register 1.
    S1,
    /// `$s2` — callee-saved register 2.
    S2,
    /// `$s3` — callee-saved register 3.
    S3,
    /// `$s4` — callee-saved register 4.
    S4,
    /// `$s5` — callee-saved register 5.
    S5,
    /// `$s6` — callee-saved register 6.
    S6,
    /// `$s7` — callee-saved register 7.
    S7,
    /// `$t8` — caller-saved temporary 8.
    T8,
    /// `$t9` — caller-saved temporary 9.
    T9,
    /// `$k0` — kernel register 0, unused by user code.
    K0,
    /// `$k1` — kernel register 1, unused by user code.
    K1,
    /// Global pointer.
    Gp,
    /// Stack pointer.
    Sp,
    /// Frame pointer.
    Fp,
    /// Return address.
    Ra,
    /// Multiply / divide LO half: `rs * rt` low word, or the quotient
    /// `rs / rt`.  The discriminant is pinned to the executor's
    /// `Register::LO = 32`; the two index encodings must agree, or an
    /// instruction naming register 32 reads LO on one path and HI on the
    /// other.
    Lo,
    /// Multiply / divide HI half: `rs * rt` high word, or the remainder
    /// `rs mod rt`.  Pinned to `Register::HI = 33`.
    Hi,
    /// `brk`/`sbrk` pointer, pinned to `Register::BRK = 34`.  Backed by
    /// `ctx.registers[34]` rather than an XMM lane — the packed lanes are
    /// exhausted by `Lo` and `Hi`.
    Brk,
    /// Heap pointer, pinned to `Register::HEAP = 35`.  Backed by
    /// `ctx.registers[35]`, as for `Brk`.
    Heap,
}

impl MipsRegister {
    /// Convert from the raw register index used by the executor.
    #[inline]
    #[must_use]
    pub const fn from_u8(idx: u8) -> Self {
        // SAFETY: u8 -> 6-bit enum, callers must keep idx < 36.
        // For out-of-range values we saturate at Zero to avoid UB.
        if idx > Self::Heap as u8 {
            Self::Zero
        } else {
            unsafe { std::mem::transmute::<u8, Self>(idx) }
        }
    }

    /// Raw register index.
    #[inline]
    #[must_use]
    pub const fn index(self) -> u8 {
        self as u8
    }
}

/// Operand to a MIPS instruction: either a register or an immediate.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MipsOperand {
    /// Register operand.
    Reg(MipsRegister),
    /// Immediate operand (sign-extended where the opcode requires it).
    Imm(i64),
}

impl From<MipsRegister> for MipsOperand {
    #[inline]
    fn from(r: MipsRegister) -> Self {
        Self::Reg(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_round_trip() {
        for i in 0..36u8 {
            let r = MipsRegister::from_u8(i);
            assert_eq!(r.index(), i);
        }
    }

    #[test]
    fn out_of_range_register_saturates_to_zero() {
        assert_eq!(MipsRegister::from_u8(255), MipsRegister::Zero);
    }
}

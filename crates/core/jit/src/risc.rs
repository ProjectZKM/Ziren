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
    /// Function return values.
    V0, V1,
    /// Function arguments.
    A0, A1, A2, A3,
    /// Caller-saved temporaries.
    T0, T1, T2, T3, T4, T5, T6, T7,
    /// Callee-saved.
    S0, S1, S2, S3, S4, S5, S6, S7,
    /// More temporaries.
    T8, T9,
    /// Kernel registers (unused by user code).
    K0, K1,
    /// Global pointer.
    Gp,
    /// Stack pointer.
    Sp,
    /// Frame pointer.
    Fp,
    /// Return address.
    Ra,
    /// Multiply / divide HI half (R32 in ZKM extension).
    Hi,
    /// Multiply / divide LO half (R33 in ZKM extension).
    Lo,
    /// Reserved (R34).
    Rsv34,
    /// Reserved (R35).
    Rsv35,
}

impl MipsRegister {
    /// Convert from the raw register index used by the executor.
    #[inline]
    #[must_use]
    pub const fn from_u8(idx: u8) -> Self {
        // SAFETY: u8 -> 6-bit enum, callers must keep idx < 36.
        // For out-of-range values we saturate at Zero to avoid UB.
        if idx > Self::Rsv35 as u8 {
            Self::Zero
        } else {
            unsafe { std::mem::transmute(idx) }
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

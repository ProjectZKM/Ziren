use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C)]
pub enum BaseAluOpcode {
    AddF,
    SubF,
    MulF,
    DivF,
    /// `DivF` variant emitted by `base_assert_eq` / `base_assert_ne`
    /// helpers.  Behaves identically to `DivF` at runtime, but the
    /// preprocessed trace sets `is_div_soundness = 1` so the AIR
    /// constraint is enforced UNCONDITIONALLY (not gated on
    /// `mult > 0` like regular `DivF`).  Required because assertion
    /// `out` cells have mult=0 (no real reader) yet must enforce
    /// the soundness invariant.
    DivFAssert,
}

impl BaseAluOpcode {
    /// Returns `true` for any DivF-class opcode (regular or assertion).
    pub fn is_div(self) -> bool {
        matches!(self, BaseAluOpcode::DivF | BaseAluOpcode::DivFAssert)
    }

    /// Returns `true` for assertion-DivF only.
    pub fn is_div_assert(self) -> bool {
        matches!(self, BaseAluOpcode::DivFAssert)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C)]
pub enum ExtAluOpcode {
    AddE,
    SubE,
    MulE,
    DivE,
    /// `DivE` variant emitted by `ext_assert_eq` / `ext_assert_ne`.
    /// Same semantics as `BaseAluOpcode::DivFAssert` for the
    /// extension-field ALU.
    DivEAssert,
}

impl ExtAluOpcode {
    pub fn is_div(self) -> bool {
        matches!(self, ExtAluOpcode::DivE | ExtAluOpcode::DivEAssert)
    }

    pub fn is_div_assert(self) -> bool {
        matches!(self, ExtAluOpcode::DivEAssert)
    }
}

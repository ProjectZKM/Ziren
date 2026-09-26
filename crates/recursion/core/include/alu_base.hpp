#pragma once

#include "prelude.hpp"

namespace zkm_recursion_core_sys::alu_base {
template <class F>
__ZKM_HOSTDEV__ void event_to_row(const BaseAluEvent<F>& event,
                                  BaseAluValueCols<F>& cols) {
  cols.vals = event;
}

template <class F>
__ZKM_HOSTDEV__ void instr_to_row(const BaseAluInstr<F>& instr,
                                  BaseAluAccessCols<F>& access) {
  access.addrs = instr.addrs;
  access.is_add = F(0);
  access.is_sub = F(0);
  access.is_mul = F(0);
  access.is_div = F(0);
  access.mult = instr.mult;

  switch (instr.opcode) {
    case BaseAluOpcode::AddF:
      access.is_add = F(1);
      break;
    case BaseAluOpcode::SubF:
      access.is_sub = F(1);
      break;
    case BaseAluOpcode::MulF:
      access.is_mul = F(1);
      break;
    case BaseAluOpcode::DivF:
      access.is_div = F(1);
      break;
    case BaseAluOpcode::DivFAssert:
      access.is_div = F(1);
      break;
  }

  // `is_div_active = is_div AND mult != 0`.  Regular DivF rows
  // emitted in dead Select branches carry mult=0; gating the
  // constraint on `is_div_active` lets the runtime's mult=0
  // guard skip them without a false-positive AIR obligation.
  const bool is_div_op = (instr.opcode == BaseAluOpcode::DivF ||
                          instr.opcode == BaseAluOpcode::DivFAssert);
  const bool mult_nonzero = !(instr.mult == F(0));
  access.is_div_active = F(is_div_op && mult_nonzero ? 1 : 0);

  // `is_div_soundness = (opcode == DivFAssert)`.  Assertion-DivF
  // rows always enforce the soundness constraint regardless of
  // mult, because their `out` cell has no real reader but must
  // still trip the constraint when the assertion fails.
  access.is_div_soundness =
      F(instr.opcode == BaseAluOpcode::DivFAssert ? 1 : 0);
}
}  // namespace zkm_recursion_core_sys::alu_base

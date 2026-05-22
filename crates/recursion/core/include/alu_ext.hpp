#pragma once

#include "prelude.hpp"

namespace zkm_recursion_core_sys::alu_ext {
template <class F>
__ZKM_HOSTDEV__ void event_to_row(const ExtAluEvent<F>& event,
                                  ExtAluValueCols<F>& cols) {
  cols.vals = event;
}

template <class F>
__ZKM_HOSTDEV__ void instr_to_row(const ExtAluInstr<F>& instr,
                                  ExtAluAccessCols<F>& access) {
  access.addrs = instr.addrs;
  access.is_add = F(0);
  access.is_sub = F(0);
  access.is_mul = F(0);
  access.is_div = F(0);
  access.mult = instr.mult;

  switch (instr.opcode) {
    case ExtAluOpcode::AddE:
      access.is_add = F(1);
      break;
    case ExtAluOpcode::SubE:
      access.is_sub = F(1);
      break;
    case ExtAluOpcode::MulE:
      access.is_mul = F(1);
      break;
    case ExtAluOpcode::DivE:
      access.is_div = F(1);
      break;
    case ExtAluOpcode::DivEAssert:
      access.is_div = F(1);
      break;
  }

  // Mirror of `alu_base::instr_to_row`'s gating: `is_div_active`
  // skips dead-branch DivE rows (mult=0); `is_div_soundness`
  // unconditionally enforces the constraint for assertion-DivEs
  // (`ext_assert_eq` / `ext_assert_ne`).
  const bool is_div_op = (instr.opcode == ExtAluOpcode::DivE ||
                          instr.opcode == ExtAluOpcode::DivEAssert);
  const bool mult_nonzero = !(instr.mult == F(0));
  access.is_div_active = F(is_div_op && mult_nonzero ? 1 : 0);
  access.is_div_soundness =
      F(instr.opcode == ExtAluOpcode::DivEAssert ? 1 : 0);
}
}  // namespace zkm_recursion_core_sys::alu_ext

#pragma once

#include "prelude.hpp"

namespace zkm_recursion_core_sys::select {
template <class F>
__ZKM_HOSTDEV__ void event_to_row(const SelectEvent<F>& event,
                                  SelectCols<F>& cols) {
  cols.vals = event;
}

template <class F>
__ZKM_HOSTDEV__ void instr_to_row(const SelectInstr<F>& instr,
                                  SelectPreprocessedCols<F>& cols) {
  cols.is_real = F::one();
  cols.addrs = instr.addrs;
  cols.mult1 = instr.mult1;
  cols.mult2 = instr.mult2;
}
}  // namespace zkm_recursion_core_sys::select

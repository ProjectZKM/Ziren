#pragma once

#include <cassert>
#include "prelude.hpp"
#include "utils.hpp"

namespace zkm_core_machine_sys::bitwise {
template<class F>
__ZKM_HOSTDEV__ void event_to_row(const AluEvent& event, BitwiseCols<F>& cols) {
    cols.pc = F::from_canonical_u32(event.pc);
    cols.next_pc = F::from_canonical_u32(event.next_pc);

    write_word_from_u32_v2<F>(cols.a, event.a);
    write_word_from_u32_v2<F>(cols.b, event.b);
    write_word_from_u32_v2<F>(cols.c, event.c);

    cols.is_nor = F::from_bool(event.opcode == Opcode::NOR);
    cols.is_xor = F::from_bool(event.opcode == Opcode::XOR);
    cols.is_or = F::from_bool(event.opcode == Opcode::OR);
    cols.is_and = F::from_bool(event.opcode == Opcode::AND);
}
}  // namespace zkm::bitwise

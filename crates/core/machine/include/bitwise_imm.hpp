#pragma once

#include <cassert>
#include "frame.hpp"
#include "prelude.hpp"
#include "utils.hpp"

namespace zkm_core_machine_sys::bitwise_imm {
// Mirrors `BitwiseImmChip::event_to_row`.  Every row is a real
// IMMEDIATE-form instruction owning its I-type frame (the register forms and
// NOR prove in `bitwise.hpp`).
template<class F>
__ZKM_HOSTDEV__ void event_to_row(
    const AluEvent& event,
    BitwiseImmCols<F>& cols,
    const InstructionFfi& instruction,
    const uint32_t shard
) {
    // Every row is a real instruction owning its frame.
    frame::populate_from_alu_imm<AluEvent, F>(cols.frame, event, instruction, shard);

    cols.pc = F::from_canonical_u32(event.pc);
    cols.next_pc = F::from_canonical_u32(event.next_pc);

    cols.is_xor = F::from_bool(event.opcode == Opcode::XOR);
    cols.is_or = F::from_bool(event.opcode == Opcode::OR);
    cols.is_and = F::from_bool(event.opcode == Opcode::AND);

    // No result mirror; see bitwise.hpp.
    cols.lookup_gate = (F::one() - cols.frame.op_a_0)
        * (cols.is_xor + cols.is_or + cols.is_and);
}
}  // namespace zkm_core_machine_sys::bitwise_imm

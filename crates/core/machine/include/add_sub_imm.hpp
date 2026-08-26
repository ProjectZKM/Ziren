#pragma once

#include "add_sub.hpp"
#include "frame.hpp"
#include "prelude.hpp"
#include "utils.hpp"

namespace zkm_core_machine_sys::add_sub_imm {
// Mirrors `AddSubImmChip::event_to_row`.  Every row is a real IMMEDIATE-form
// instruction owning its I-type frame (the register forms prove in
// `add_sub.hpp`); the addition witness itself is shared with the register
// chip.
template<class F>
__ZKM_HOSTDEV__ void event_to_row(
    const AluEvent& event,
    AddSubImmCols<F>& cols,
    const InstructionFfi& instruction,
    const uint32_t shard
) {
    cols.pc = F::from_canonical_u32(event.pc);
    cols.next_pc = F::from_canonical_u32(event.next_pc);

    // Every row is a real instruction owning its frame.
    frame::populate_from_alu_imm<AluEvent, F>(cols.frame, event, instruction, shard);

    bool is_add = event.opcode == Opcode::ADD;
    cols.is_add = F::from_bool(is_add);
    cols.is_sub = F::from_bool(event.opcode == Opcode::SUB);

    auto operand_1 = is_add ? event.b : event.a;
    auto operand_2 = event.c;

    add_sub::populate_carries<F>(cols.carry, operand_1, operand_2);
    const F not_a0 = F::one() - cols.frame.op_a_0;
    cols.add_gate = cols.is_add * not_a0;
    cols.sub_gate = cols.is_sub * not_a0;
}
}  // namespace zkm_core_machine_sys::add_sub_imm

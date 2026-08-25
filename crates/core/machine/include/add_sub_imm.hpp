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
    frame::populate_from_alu_imm<F>(cols.frame, event, instruction, shard);

    bool is_add = event.opcode == Opcode::ADD;
    cols.is_add = F::from_bool(is_add);
    cols.is_sub = F::from_bool(event.opcode == Opcode::SUB);

    auto operand_1 = is_add ? event.b : event.a;
    auto operand_2 = event.c;

    add_sub::populate<F>(cols.add_operation, operand_1, operand_2);
    write_word_from_u32_v2<F>(cols.operand_1, operand_1);
}
}  // namespace zkm_core_machine_sys::add_sub_imm

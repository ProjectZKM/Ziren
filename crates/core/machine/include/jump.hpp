#pragma once

#include <cassert>
#include "frame.hpp"
#include "prelude.hpp"
#include "utils.hpp"

namespace zkm_core_machine_sys::jump {
template<class F>
__ZKM_HOSTDEV__ void event_to_row(
    const JumpEvent& event,
    JumpColumns<F>& cols,
    const InstructionFfi& instruction,
    const uint32_t shard
) {
    const bool is_instruction = event.is_instruction != 0;
    cols.is_instruction = F::from_bool(is_instruction);
    cols.is_dep = F::from_bool(!is_instruction);
    if (is_instruction) {
        frame::populate_from_jump<F>(cols.frame, event, instruction, shard);
    } else {
        frame::populate_dependency<F>(cols.frame);
    }

    cols.pc = F::from_canonical_u32(event.pc);
    cols.is_jump = F::from_bool(event.opcode == Opcode::Jump);
    cols.is_jumpi = F::from_bool(event.opcode == Opcode::Jumpi);
    cols.is_jumpdirect = F::from_bool(event.opcode == Opcode::JumpDirect);

    write_word_from_u32_v2<F>(cols.op_a_value, event.a);
    write_word_from_u32_v2<F>(cols.op_b_value, event.b);
    write_word_from_u32_v2<F>(cols.op_c_value, event.c);
    populate_range_checker(cols.op_a_range_checker, event.a);
    write_word_from_u32_v2<F>(cols.next_pc, event.next_pc);
    populate_range_checker(cols.next_pc_range_checker, event.next_pc);
    write_word_from_u32_v2<F>(cols.next_next_pc, event.next_next_pc);
    populate_range_checker(cols.next_next_pc_range_checker, event.next_next_pc);
}
}  // namespace zkm::jump

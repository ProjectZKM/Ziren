#pragma once

#include <cassert>
#include "frame.hpp"
#include "prelude.hpp"
#include "utils.hpp"

namespace zkm_core_machine_sys::bitwise {
// Mirrors `BitwiseChip::event_to_row`.  `instruction` is only read when the
// event is a REAL instruction.
template<class F>
__ZKM_HOSTDEV__ void event_to_row(
    const AluEvent& event,
    BitwiseCols<F>& cols,
    const InstructionFfi& instruction,
    const uint32_t shard
) {
    const bool is_instruction = event.is_instruction != 0;
    cols.is_instruction = F::from_bool(is_instruction);
    cols.is_dep = F::from_bool(!is_instruction);
    if (is_instruction) {
        frame::populate_from_alu<AluEvent, F>(cols.frame, event, instruction, shard);
    } else {
        frame::populate_dependency<F>(cols.frame);
    }

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
}  // namespace zkm_core_machine_sys::bitwise

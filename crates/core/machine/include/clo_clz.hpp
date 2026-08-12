#pragma once

#include <cassert>
#include "frame.hpp"
#include "prelude.hpp"
#include "utils.hpp"

namespace zkm_core_machine_sys::clo_clz {
template<class F>
__ZKM_HOSTDEV__ void event_to_row(
    const AluEvent& event,
    CloClzCols<F>& cols,
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

    cols.is_real = F::one();
    cols.is_clz = F::from_bool(event.opcode == Opcode::CLZ);

    uint32_t bb = 0xffffffff - event.b;
    if (event.opcode == Opcode::CLZ) {
        bb = event.b;
    }
    write_word_from_u32_v2<F>(cols.bb, bb);

    // if bb == 0, then result is 32.
    cols.is_bb_zero = F::from_bool(bb == 0);
}
}  // namespace zkm::clo_clz

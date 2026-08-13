#pragma once

#include <cassert>
#include "frame.hpp"
#include "prelude.hpp"
#include "shift_right_operation.hpp"
#include "utils.hpp"

namespace zkm_core_machine_sys::clo_clz {
template<class F>
__ZKM_HOSTDEV__ void event_to_row(
    const AluEvent& event,
    CloClzCols<F>& cols,
    const InstructionFfi& instruction,
    const uint32_t shard
) {
    // Every row is a real instruction owning its frame.
    frame::populate_from_alu<AluEvent, F>(cols.frame, event, instruction, shard);

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

    // The inlined shift (the SRL request row): bb >> (31 - a) == 1.
    if (bb != 0) {
        shift_right_operation::populate<F>(cols.srl, Opcode::SRL, bb, 31 - event.a);
    }
}
}  // namespace zkm::clo_clz

#pragma once

#include "frame.hpp"
#include "prelude.hpp"
#include "utils.hpp"

namespace zkm_core_machine_sys::add_sub {
// The carries are recovered in the AIR (no columns); only the value is trace.
template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ uint32_t
populate(AddOperation<F>& op, const uint32_t a_u32, const uint32_t b_u32) {
    uint32_t expected = a_u32 + b_u32;
    write_word_from_u32_v2<F>(op.value, expected);
    return expected;
}

// Mirrors `AddSubChip::event_to_row`.  Every row is a real REGISTER-form
// instruction owning its R-type frame (the immediate forms prove in
// `add_sub_imm.hpp`).
template<class F>
__ZKM_HOSTDEV__ void event_to_row(
    const AluEvent& event,
    AddSubCols<F>& cols,
    const InstructionFfi& instruction,
    const uint32_t shard
) {
    cols.pc = F::from_canonical_u32(event.pc);
    cols.next_pc = F::from_canonical_u32(event.next_pc);

    // Every row is a real instruction owning its frame.
    frame::populate_from_alu_r<AluEvent, F>(cols.frame, event, instruction, shard);

    bool is_add = event.opcode == Opcode::ADD;
    cols.is_add = F::from_bool(is_add);
    cols.is_sub = F::from_bool(event.opcode == Opcode::SUB);

    const F not_a0 = F::one() - cols.frame.op_a_0;
    cols.add_gate = cols.is_add * not_a0;
    cols.sub_gate = cols.is_sub * not_a0;
}
}  // namespace zkm_core_machine_sys::add_sub

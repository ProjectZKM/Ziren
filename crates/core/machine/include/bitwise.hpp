#pragma once

#include <cassert>
#include "frame.hpp"
#include "prelude.hpp"
#include "utils.hpp"

namespace zkm_core_machine_sys::bitwise {
// Mirrors `BitwiseChip::event_to_row`.  Every row is a real REGISTER-form
// instruction owning its R-type frame (the immediate forms prove in
// `bitwise_imm.hpp`).
template<class F>
__ZKM_HOSTDEV__ void event_to_row(
    const AluEvent& event,
    BitwiseCols<F>& cols,
    const InstructionFfi& instruction,
    const uint32_t shard
) {
    // Every row is a real instruction owning its frame.
    frame::populate_from_alu_r<AluEvent, F>(cols.frame, event, instruction, shard);

    cols.pc = F::from_canonical_u32(event.pc);
    cols.next_pc = F::from_canonical_u32(event.next_pc);

    cols.is_nor = F::from_bool(event.opcode == Opcode::NOR);
    cols.is_xor = F::from_bool(event.opcode == Opcode::XOR);
    cols.is_or = F::from_bool(event.opcode == Opcode::OR);
    cols.is_and = F::from_bool(event.opcode == Opcode::AND);

    // No result mirror; the gated byte-lookup multiplicity mirrors
    // alu/bitwise/mod.rs (a discarded register-0 write sends none).
    cols.lookup_gate = (F::one() - cols.frame.op_a_0)
        * (cols.is_xor + cols.is_or + cols.is_and + cols.is_nor);
}
}  // namespace zkm_core_machine_sys::bitwise

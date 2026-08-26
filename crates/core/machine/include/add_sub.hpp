#pragma once

#include "frame.hpp"
#include "prelude.hpp"
#include "utils.hpp"

namespace zkm_core_machine_sys::add_sub {
template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ uint32_t
populate(AddOperation<F>& op, const uint32_t a_u32, const uint32_t b_u32) {
    array_t<uint8_t, 4> a = u32_to_le_bytes(a_u32);
    array_t<uint8_t, 4> b = u32_to_le_bytes(b_u32);
    bool carry = a[0] + b[0] > 0xFF;
    op.carry[0] = F::from_bool(carry).val;
    carry = a[1] + b[1] + carry > 0xFF;
    op.carry[1] = F::from_bool(carry).val;
    carry = a[2] + b[2] + carry > 0xFF;
    op.carry[2] = F::from_bool(carry).val;

    uint32_t expected = a_u32 + b_u32;
    write_word_from_u32_v2<F>(op.value, expected);
    return expected;
}

// The three carry bits of `x + y`, for the chips that verify the addition
// directly against frame words (no AddOperation struct).
template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ void
populate_carries(F (&carry_cols)[3], const uint32_t x, const uint32_t y) {
    array_t<uint8_t, 4> a = u32_to_le_bytes(x);
    array_t<uint8_t, 4> b = u32_to_le_bytes(y);
    bool carry = a[0] + b[0] > 0xFF;
    carry_cols[0] = F::from_bool(carry);
    carry = a[1] + b[1] + carry > 0xFF;
    carry_cols[1] = F::from_bool(carry);
    carry = a[2] + b[2] + carry > 0xFF;
    carry_cols[2] = F::from_bool(carry);
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

    auto operand_1 = is_add ? event.b : event.a;
    auto operand_2 = event.c;

    populate_carries<F>(cols.carry, operand_1, operand_2);
    const F not_a0 = F::one() - cols.frame.op_a_0;
    cols.add_gate = cols.is_add * not_a0;
    cols.sub_gate = cols.is_sub * not_a0;
}
}  // namespace zkm_core_machine_sys::add_sub

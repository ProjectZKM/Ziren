#pragma once

#include "prelude.hpp"
#include "utils.hpp"

// Column mirror of `operations/shift_left_operation.rs`
// (`ShiftLeftOperation`) — the embeddable SLL gadget.  Columns only: the byte
// events come from the host `generate_dependencies` pass.
namespace zkm_core_machine_sys::shift_left_operation {

template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ void populate(
    ShiftLeftOperation<F>& op,
    const uint32_t b_u32,
    const uint32_t c
) {
    const auto b = u32_to_le_bytes(b_u32);
    for (uint32_t i = 0; i < BYTE_SIZE; i += 1) {
        op.c_least_sig_byte[i] = F::from_canonical_u32((c >> i) & 1);
    }

    const uint32_t num_bits_to_shift = c % BYTE_SIZE;
    for (uint32_t i = 0; i < BYTE_SIZE; i++) {
        op.shift_by_n_bits[i] = F::from_bool(num_bits_to_shift == i);
    }

    const uint32_t bit_shift_multiplier = 1u << num_bits_to_shift;
    op.bit_shift_multiplier = F::from_canonical_u32(bit_shift_multiplier);

    uint32_t carry = 0u;
    const uint32_t base = 1u << BYTE_SIZE;
    uint8_t bit_shift_result[WORD_SIZE] = {0u};
    uint8_t bit_shift_result_carry[WORD_SIZE] = {0u};
    for (uint32_t i = 0; i < WORD_SIZE; i++) {
        const uint32_t v = b[i] * bit_shift_multiplier + carry;
        carry = v / base;
        bit_shift_result[i] = v % base;
        bit_shift_result_carry[i] = carry;
    }
    write_word_from_le_bytes_v2<F>(op.bit_shift_result, bit_shift_result);
    write_word_from_le_bytes_v2<F>(op.bit_shift_result_carry, bit_shift_result_carry);

    const uint32_t num_bytes_to_shift = (c & 0b11111u) / BYTE_SIZE;
    for (uint32_t i = 0; i < WORD_SIZE; i++) {
        op.shift_by_n_bytes[i] = F::from_bool(num_bytes_to_shift == i);
    }
}

}  // namespace zkm_core_machine_sys::shift_left_operation

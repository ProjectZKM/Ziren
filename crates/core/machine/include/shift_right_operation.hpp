#pragma once

#include "prelude.hpp"
#include "utils.hpp"

// Column mirror of `operations/shift_right_operation.rs`
// (`ShiftRightOperation`) — the embeddable SRL/SRA/ROR gadget.  Columns only:
// the byte events come from the host `generate_dependencies` pass.
namespace zkm_core_machine_sys::shift_right_operation {

template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ void populate(
    ShiftRightOperation<F>& op,
    const Opcode opcode,
    const uint32_t b,
    const uint32_t c
) {
    op.b_msb = F::from_canonical_u32((b >> 31) & 1);
    for (uint32_t i = 0; i < BYTE_SIZE; i++) {
        op.c_least_sig_byte[i] = F::from_canonical_u32((c >> i) & 1);
    }

    const size_t num_bytes_to_shift = ((size_t)c % 32) / BYTE_SIZE;
    const size_t num_bits_to_shift = (size_t)c % BYTE_SIZE;

    // Byte shifting.
    uint8_t byte_shift_result[LONG_WORD_SIZE] = {0};
    {
        for (size_t i = 0; i < WORD_SIZE; i++) {
            op.shift_by_n_bytes[i] = F::from_bool(num_bytes_to_shift == i);
        }
        array_t<uint8_t, LONG_WORD_SIZE> extended_b;
        if (opcode == Opcode::SRA) {
            extended_b = u64_to_le_bytes((int64_t)((int32_t)b));
        } else if (opcode == Opcode::ROR) {
            extended_b = u64_to_le_bytes((((uint64_t)b) << 32) | ((uint64_t)b));
        } else {
            extended_b = u64_to_le_bytes((uint64_t)b);
        }
        for (uint32_t i = 0; i < LONG_WORD_SIZE; i++) {
            if (i + num_bytes_to_shift < LONG_WORD_SIZE) {
                byte_shift_result[i] = extended_b[i + num_bytes_to_shift];
            }
        }
        write_long_word_from_le_bytes_v2(op.byte_shift_result, byte_shift_result);
    }

    // Bit shifting.
    {
        for (uint32_t i = 0; i < BYTE_SIZE; i++) {
            op.shift_by_n_bits[i] = F::from_bool(num_bits_to_shift == i);
        }
        const uint32_t carry_multiplier = 1 << (8 - num_bits_to_shift);
        uint32_t last_carry = 0u;
        uint8_t bit_shift_result[LONG_WORD_SIZE] = {0u};
        uint8_t shr_carry_output_carry[LONG_WORD_SIZE] = {0u};
        uint8_t shr_carry_output_shifted_byte[LONG_WORD_SIZE] = {0u};
        for (int i = LONG_WORD_SIZE - 1; i >= 0; i--) {
            uint8_t shift, carry;
            std::tie(shift, carry) =
                shr_carry(byte_shift_result[i], (uint8_t)num_bits_to_shift);
            shr_carry_output_carry[i] = carry;
            shr_carry_output_shifted_byte[i] = shift;
            bit_shift_result[i] =
                (uint8_t)(((uint32_t)shift + last_carry * carry_multiplier) & 0xff);
            last_carry = carry;
        }
        write_long_word_from_le_bytes_v2(op.bit_shift_result, bit_shift_result);
        write_long_word_from_le_bytes_v2(op.shr_carry_output_carry, shr_carry_output_carry);
        write_long_word_from_le_bytes_v2(
            op.shr_carry_output_shifted_byte, shr_carry_output_shifted_byte);
    }
}

}  // namespace zkm_core_machine_sys::shift_right_operation

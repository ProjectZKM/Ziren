#pragma once

#include "prelude.hpp"
#include "utils.hpp"
#include "kb31_septic_extension_t.hpp"

namespace zkm_core_machine_sys::shift_right {
    template<class F>
    __ZKM_HOSTDEV__ void event_to_row(const AluEvent& event, ShiftRightCols<F>& cols) {
        // Initialize cols with basic operands and flags derived from the current event.
        {
            cols.pc = F::from_canonical_u32(event.pc);
            cols.next_pc = F::from_canonical_u32(event.next_pc);
            write_word_from_u32_v2<F>(cols.b, event.b);
            write_word_from_u32_v2<F>(cols.c, event.c);

            cols.b_msb = F::from_canonical_u32((event.b >> 31) & 1);

            cols.is_srl = F::from_bool(event.opcode == Opcode::SRL);
            cols.is_sra = F::from_bool(event.opcode == Opcode::SRA);
            cols.is_ror = F::from_bool(event.opcode == Opcode::ROR);

            cols.is_real = F::one();

            for (uint32_t i = 0; i < BYTE_SIZE; i++) {
                cols.c_least_sig_byte[i] = F::from_canonical_u32((event.c >> i) & 1);
            }

            // Insert the MSB lookup event.
            uint32_t most_significant_byte = u32_to_le_bytes(event.b)[WORD_SIZE - 1];
        }

        size_t num_bytes_to_shift = nb_bytes_to_shift(event.c);
        size_t num_bits_to_shift = nb_bits_to_shift(event.c);

        // Byte shifting.
        uint8_t byte_shift_result[LONG_WORD_SIZE] = {0};
        {
            for (size_t i = 0; i < WORD_SIZE; i++) {
                cols.shift_by_n_bytes[i] = F::from_bool(num_bytes_to_shift == i);
            }

            array_t<uint8_t, LONG_WORD_SIZE> sign_extended_b;
            if (event.opcode == Opcode::SRA) {
                // Sign extension is necessary only for arithmetic right shift.
                sign_extended_b = u64_to_le_bytes((int64_t)((int32_t)event.b));
            } else if (event.opcode == Opcode::ROR) {
                sign_extended_b = u64_to_le_bytes((((uint64_t)event.b) << 32) | ((uint64_t)event.b));
            } else {
                sign_extended_b = u64_to_le_bytes((uint64_t)event.b);
            }

            for (uint32_t i = 0; i < LONG_WORD_SIZE; i++) {
                if (i + num_bytes_to_shift < LONG_WORD_SIZE) {
                    byte_shift_result[i] = sign_extended_b[i + num_bytes_to_shift];
                }
            }
            write_long_word_from_le_bytes_v2(cols.byte_shift_result, byte_shift_result);
        }

        // Bit shifting.
        {
            for (uint32_t i = 0; i < BYTE_SIZE; i++) {
                cols.shift_by_n_bits[i] = F::from_bool(num_bits_to_shift == i);
            }
            uint32_t carry_multiplier = 1 << (8 - num_bits_to_shift);
            uint32_t last_carry = 0u;
            uint8_t bit_shift_result[LONG_WORD_SIZE] = {0u};
            uint8_t shr_carry_output_carry[LONG_WORD_SIZE] = {0u};
            uint8_t shr_carry_output_shifted_byte[LONG_WORD_SIZE] = {0u};
            for (int i = LONG_WORD_SIZE - 1; i >= 0; i--) {
                uint8_t shift, carry;
                std::tie(shift, carry) = shr_carry(byte_shift_result[i], (uint8_t)num_bits_to_shift);

                shr_carry_output_carry[i] = carry;
                shr_carry_output_shifted_byte[i] = shift;
                bit_shift_result[i] = (uint8_t)(((uint32_t)shift + last_carry * carry_multiplier) & 0xff);
                last_carry = carry;
            }
            write_long_word_from_le_bytes_v2(cols.bit_shift_result, bit_shift_result);
            write_long_word_from_le_bytes_v2(cols.shr_carry_output_carry, shr_carry_output_carry);
            write_long_word_from_le_bytes_v2(cols.shr_carry_output_shifted_byte, shr_carry_output_shifted_byte);

            Word<F> a;
            write_word_from_u32_v2(a, event.a);
            for (uint32_t i = 0; i < WORD_SIZE; i++) {
                assert(cols.bit_shift_result[i] == a._0[i]);
            }
        }
    }
}  // namespace zkm::shift_right

#pragma once

#include <cstdint>
#include <climits>
#include "add_sub.hpp"
#include "frame.hpp"
#include "lt_operation.hpp"
#include "mul_operation.hpp"
#include "prelude.hpp"
#include "utils.hpp"
#include "kb31_septic_extension_t.hpp"
#include "memory.hpp"

namespace zkm_core_machine_sys::div_rem {
    template<class F>
    __ZKM_HOSTDEV__ void event_to_row(
    const CompAluEvent& event,
    DivRemCols<F>& cols,
    const InstructionFfi& instruction,
    const uint32_t shard
) {
    // Every DivRem row is a real instruction owning its frame.
    frame::populate_from_alu<CompAluEvent, F>(cols.frame, event, instruction, shard);

        assert(
            event.opcode == Opcode::DIVU
                || event.opcode == Opcode::DIV
                || event.opcode == Opcode::MODU
                || event.opcode == Opcode::MOD
        );

        // Initialize cols with basic operands and flags derived from the current event.
        {
            write_word_from_u32_v2<F>(cols.b, event.b);
            write_word_from_u32_v2<F>(cols.c, event.c);
            cols.pc = F::from_canonical_u32(event.pc);
            cols.next_pc = F::from_canonical_u32(event.next_pc);
            cols.is_divu = F::from_bool(event.opcode == Opcode::DIVU);
            cols.is_div = F::from_bool(event.opcode == Opcode::DIV);
            cols.is_modu = F::from_bool(event.opcode == Opcode::MODU);
            cols.is_mod = F::from_bool(event.opcode == Opcode::MOD);
            populate_is_zero_word_operaion(cols.is_c_0, u32_to_word<F>(event.c));

            if (event.opcode == Opcode::DIVU || event.opcode == Opcode::DIV) {
                // DivRem Chip is only used for DIV and DIVU instruction currently.
                memory::populate_read_write_v2<F>(
                    cols.op_hi_access,
                    MemoryRecordEnum {
                        tag: MemoryRecordEnum::Tag::Write,
                        write: MemoryRecordEnum::Write_Body {
                            _0: event.hi_record
                        },
                    }
                );
                cols.shard = F::from_canonical_u32(event.shard);
                cols.clk = F::from_canonical_u32(event.clk);
            }
        }
    
        uint32_t quotient, remainder;
        std::tie(quotient, remainder) = get_quotient_and_remainder(event.b, event.c, event.opcode);
        write_word_from_u32_v2<F>(cols.quotient, quotient);
        write_word_from_u32_v2<F>(cols.remainder, remainder);

        // Calculate flags for sign detection.
        {
            cols.rem_msb = F::from_canonical_u8(get_msb_v2(remainder));
            cols.b_msb = F::from_canonical_u8(get_msb_v2(event.b));
            cols.c_msb = F::from_canonical_u8(get_msb_v2(event.c));
            populate_is_equal_word_operaion(cols.is_overflow_b, event.b, INT32_MIN);
            populate_is_equal_word_operaion(cols.is_overflow_c, event.c, (uint32_t)((int32_t)-1));

            uint32_t abs_remainder = remainder;
            uint32_t abs_c = event.c;
            if (is_signed_operation(event.opcode)) {
                abs_remainder = unsigned_abs((int32_t)remainder);
                abs_c = unsigned_abs((int32_t)event.c);

                cols.rem_neg = cols.rem_msb;
                cols.b_neg = cols.b_msb;
                cols.c_neg = cols.c_msb;
                cols.is_overflow =
                    F::from_bool((int32_t)event.b == INT32_MIN && (int32_t)event.c == -1);
            }
            const uint32_t max_abs_c_or_1 = std::max(1u, abs_c);
            write_word_from_u32_v2<F>(cols.abs_remainder, abs_remainder);
            write_word_from_u32_v2<F>(cols.abs_c, abs_c);
            write_word_from_u32_v2<F>(cols.max_abs_c_or_1, max_abs_c_or_1);

            // The inlined negation checks (the two ADD request rows).
            const bool signed_op = is_signed_operation(event.opcode);
            if (signed_op && get_msb_v2(event.c) == 1) {
                add_sub::populate<F>(cols.neg_c_add, event.c, abs_c);
            }
            if (signed_op && get_msb_v2(remainder) == 1) {
                add_sub::populate<F>(cols.neg_rem_add, remainder, abs_remainder);
            }

            // The inlined abs(remainder) < max(abs(c), 1) (the SLTU request
            // row).
            lt_operation::populate<F>(cols.remainder_check, abs_remainder, max_abs_c_or_1, false);
        }
    
        // Calculate the modified multiplicity
        {
            cols.remainder_check_multiplicity = F::one() - cols.is_c_0.result;
        }

        // Calculate c * quotient + remainder.
        {
            array_t<uint8_t, 8> c_times_quotient = {0};
            if (is_signed_operation(event.opcode)) {
                c_times_quotient = i64_to_le_bytes(((int64_t)((int32_t)quotient)) * ((int64_t)((int32_t)event.c)));
            } else {
                c_times_quotient = u64_to_le_bytes(((uint64_t)quotient) * ((uint64_t)event.c));
            }
            // The inlined multiplication (the MULT/MULTU request row): its
            // 64-bit product equals `c_times_quotient` byte for byte.
            mul_operation::populate<F>(cols.mul, quotient, event.c, is_signed_operation(event.opcode));

            array_t<uint8_t, 8> remainder_bytes = {0};
            if (is_signed_operation(event.opcode)) {
                remainder_bytes = i64_to_le_bytes((int64_t)((int32_t)remainder));
            } else {
                remainder_bytes = u64_to_le_bytes((uint64_t)remainder);
            }

            // Add remainder to product.
            uint32_t carry[8] = {0};
            uint32_t base = 1 << BYTE_SIZE;
            for (uint32_t i = 0; i < LONG_WORD_SIZE; i++) {
                uint32_t x = (uint32_t)c_times_quotient[i] + (uint32_t)remainder_bytes[i];
                if (i > 0) {
                    x += carry[i - 1];
                }
                carry[i] = x / base;
                cols.carry[i] = F::from_canonical_u32(carry[i]);
            }
        }
    }
}  // namespace zkm::div_rem

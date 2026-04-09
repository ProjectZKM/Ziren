#pragma once

#include "prelude.hpp"
#include "utils.hpp"
#include "kb31_septic_extension_t.hpp"
#include "memory.hpp"

namespace zkm_core_machine_sys::mul {
    template<class F>
    __ZKM_HOSTDEV__ void event_to_row(const CompAluEvent& event, MulCols<F>& cols) {
        cols.pc = F::from_canonical_u32(event.pc);
        cols.next_pc = F::from_canonical_u32(event.next_pc);

        cols.hi_record_is_real = F::from_bool(event.hi_record_is_real);
        if (event.hi_record_is_real) {
            // For madd[u]/msub[u] instructions, pass in a dummy byte lookup vector.  This madd[u]/msub[u]
            // instruction chip also has a op_hi_access field that will be populated and that will contribute
            // to the byte lookup dependencies.
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

        auto b = u32_to_le_bytes(event.b);
        auto c = u32_to_le_bytes(event.c);
        std::array<uint8_t, 8> b_signed_extened;
        std::array<uint8_t, 8> c_signed_extened;
        uint8_t b_msb = 0;
        uint8_t c_msb = 0;

        // Handle b and c's signs.
        {
            b_msb = get_msb_v2(event.b);
            cols.b_msb = F::from_canonical_u8(b_msb);
            c_msb = get_msb_v2(event.c);
            cols.c_msb = F::from_canonical_u8(c_msb);

            // If b is signed and it is negative, sign extend b.
            if (event.opcode == Opcode::MULT && b_msb == 1) {
                cols.b_sign_extend = F::one();
                b_signed_extened = signed_extended(b);
            }

            // If c is signed and it is negative, sign extend c.
            if (event.opcode == Opcode::MULT && c_msb == 1) {
                cols.c_sign_extend = F::one();
                c_signed_extened = signed_extended(c);
            }
        }

        uint32_t product[PRODUCT_SIZE] = {0};
        if ((event.opcode == Opcode::MULT && b_msb == 1) && (event.opcode == Opcode::MULT && c_msb == 1)) {
            for (int i = 0; i < b_signed_extened.size(); i++) {
                for (int j = 0; j < c_signed_extened.size(); j++) {
                    if (i + j < PRODUCT_SIZE) {
                        product[i + j] += ((uint32_t)b_signed_extened[i]) * ((uint32_t)c_signed_extened[j]);
                    }
                }
            }
        } else if (event.opcode == Opcode::MULT && b_msb == 1) {
            for (int i = 0; i < b_signed_extened.size(); i++) {
                for (int j = 0; j < c.size(); j++) {
                    if (i + j < PRODUCT_SIZE) {
                        product[i + j] += ((uint32_t)b_signed_extened[i]) * ((uint32_t)c[j]);
                    }
                }
            }
        } else if (event.opcode == Opcode::MULT && c_msb == 1) {
            for (int i = 0; i < b.size(); i++) {
                for (int j = 0; j < c_signed_extened.size(); j++) {
                    if (i + j < PRODUCT_SIZE) {
                        product[i + j] += ((uint32_t)b[i]) * ((uint32_t)c_signed_extened[j]);
                    }
                }
            }
        } else {
            for (int i = 0; i < b.size(); i++) {
                for (int j = 0; j < c.size(); j++) {
                    if (i + j < PRODUCT_SIZE) {
                        product[i + j] += ((uint32_t)b[i]) * ((uint32_t)c[j]);
                    }
                }
            }
        }

        // Calculate the correct product using the `product` array. We store the
        // correct carry value for verification.
        uint32_t base = 1 << BYTE_SIZE;
        uint32_t carry[PRODUCT_SIZE] = {0};
        for (int i = 0; i < PRODUCT_SIZE; i++) {
            carry[i] = product[i] / base;
            product[i] %= base;
            if (i + 1 < PRODUCT_SIZE) {
                product[i + 1] += carry[i];
            }
            cols.carry[i] = F::from_canonical_u32(carry[i]);
        }

        for (int i = 0; i < PRODUCT_SIZE; i++) {
            cols.product[i] = F::from_canonical_u32(product[i]);
        }
        write_word_from_u32_v2<F>(cols.hi, event.hi);
        write_word_from_u32_v2<F>(cols.a, event.a);
        write_word_from_u32_v2<F>(cols.b, event.b);
        write_word_from_u32_v2<F>(cols.c, event.c);
        cols.is_real = F::one();
        cols.is_mul = F::from_bool(event.opcode == Opcode::MUL);
        cols.is_mult = F::from_bool(event.opcode == Opcode::MULT);
        cols.is_multu = F::from_bool(event.opcode == Opcode::MULTU);
    }
}  // namespace zkm::mul

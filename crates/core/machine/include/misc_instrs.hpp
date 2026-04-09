#pragma once

#include <bit>
#include "prelude.hpp"
#include "utils.hpp"
#include "kb31_septic_extension_t.hpp"
#include "memory.hpp"

namespace zkm_core_machine_sys::misc_instrs {
    template<class F>
    __ZKM_HOSTDEV__ __ZKM_INLINE__ void populate_sext(const MiscEvent& event, MiscInstrColumns<F>& cols) {
        if (!(event.opcode == Opcode::SEXT || event.opcode == Opcode::TEQ)) {
            return;
        }

        uint16_t sig_bit = 0;
        uint8_t sig_byte = 0;
        cols.misc_specific_columns.sext.is_seh = F::zero();
        cols.misc_specific_columns.sext.is_seb = F::zero();

        if (event.c > 0) {
            cols.misc_specific_columns.sext.is_seh = F::one();
            sig_bit = (uint16_t)event.b >> 15;
            sig_byte = (uint8_t)(event.b >> 8 & 0xff);
        } else {
            cols.misc_specific_columns.sext.is_seb = F::one();
            sig_bit = (uint16_t)((uint8_t)event.b >> 7);
            sig_byte = (uint8_t)event.b;
        };

        cols.misc_specific_columns.sext.most_sig_bit = F::from_canonical_u16(sig_bit);
        cols.misc_specific_columns.sext.sig_byte = F::from_canonical_u8(sig_byte);
        populate_is_equal_word_operaion(cols.misc_specific_columns.sext.a_eq_b, event.a, event.b);
    }

    template<class F>
    __ZKM_HOSTDEV__ __ZKM_INLINE__ void populate_maddsub(const MiscEvent& event, MiscInstrColumns<F>& cols) {
        if (!(event.opcode == Opcode::MADDU || event.opcode == Opcode::MSUBU || event.opcode == Opcode::MADD || event.opcode == Opcode::MSUB)) {
            return;
        }

        bool is_sign = event.opcode == Opcode::MADD || event.opcode == Opcode::MSUB;
        uint64_t multiply = 0;
        if (is_sign) {
            multiply = ((int64_t)(int32_t)event.b * (int64_t)(int32_t)event.c);
        } else {
            multiply = (uint64_t)event.b * (uint64_t)event.c;
        }
        uint32_t mul_hi = (uint32_t)(multiply >> 32);
        uint32_t mul_lo = (uint32_t)multiply;
        write_word_from_u32_v2<F>(cols.misc_specific_columns.maddsub.mul_hi, mul_hi);
        write_word_from_u32_v2<F>(cols.misc_specific_columns.maddsub.mul_lo, mul_lo);

        bool is_add = event.opcode == Opcode::MADDU || event.opcode == Opcode::MADD;
        uint32_t src2_lo = is_add ? event.prev_a : event.a;
        uint32_t src2_hi = is_add ? event.hi_record.prev_value : event.hi_record.value;
        populate_add_double_operaion(
            cols.misc_specific_columns.maddsub.add_operation,
            multiply,
            ((uint64_t)src2_hi << 32) + (uint64_t)src2_lo
        );
        write_word_from_u32_v2<F>(cols.misc_specific_columns.maddsub.src2_lo, src2_lo);
        write_word_from_u32_v2<F>(cols.misc_specific_columns.maddsub.src2_hi, src2_hi);

        // For maddu/msubu instructions, pass in a dummy byte lookup vector.
        // This maddu/msubu instruction chip also has a op_hi_access field that will be
        // populated and that will contribute to the byte lookup dependencies.
        memory::populate_read_write_v2<F>(
            cols.misc_specific_columns.maddsub.op_hi_access,
            MemoryRecordEnum {
                tag: MemoryRecordEnum::Tag::Write,
                write: MemoryRecordEnum::Write_Body {
                    _0: event.hi_record
                },
            }
        );
    }

    template<class F>
    __ZKM_HOSTDEV__ __ZKM_INLINE__ void populate_ext(const MiscEvent& event, MiscInstrColumns<F>& cols) {
        if (!(event.opcode == Opcode::EXT)) {
            return;
        }
        uint32_t lsb = event.c & 0x1f;
        uint32_t msbd = event.c >> 5;
        uint32_t shift_left = event.b << (31 - lsb - msbd);
        cols.misc_specific_columns.ext.lsb = F::from_canonical_u32(lsb);
        cols.misc_specific_columns.ext.msbd = F::from_canonical_u32(msbd);
        write_word_from_u32_v2<F>(cols.misc_specific_columns.ext.sll_val, shift_left);
    }

    template<class F>
    __ZKM_HOSTDEV__ __ZKM_INLINE__ void populate_ins(const MiscEvent& event, MiscInstrColumns<F>& cols) {
        if (!(event.opcode == Opcode::INS)) {
            return;
        }
        uint32_t lsb = event.c & 0x1f;
        uint32_t msb = event.c >> 5;
        uint32_t ror_val = std::rotr(event.prev_a, lsb);
        uint32_t srl1_val = ror_val >> 1;
        uint32_t srl_val = srl1_val >> (msb - lsb);
        uint32_t sll_val = event.b << (31 - msb + lsb);
        uint32_t add_val = srl_val + sll_val;
        cols.misc_specific_columns.ins.lsb = F::from_canonical_u32(lsb);
        cols.misc_specific_columns.ins.msb = F::from_canonical_u32(msb);
        write_word_from_u32_v2<F>(cols.misc_specific_columns.ins.ror_val, ror_val);
        write_word_from_u32_v2<F>(cols.misc_specific_columns.ins.srl1_val, srl1_val);
        write_word_from_u32_v2<F>(cols.misc_specific_columns.ins.srl_val, srl_val);
        write_word_from_u32_v2<F>(cols.misc_specific_columns.ins.sll_val, sll_val);
        write_word_from_u32_v2<F>(cols.misc_specific_columns.ins.add_val, add_val);
    }

    template<class F>
    __ZKM_HOSTDEV__ void event_to_row(const MiscEvent& event, MiscInstrColumns<F>& cols) {
        cols.pc = F::from_canonical_u32(event.pc);
        cols.next_pc = F::from_canonical_u32(event.next_pc);

        write_word_from_u32_v2<F>(cols.op_a_value, event.a);
        write_word_from_u32_v2<F>(cols.op_b_value, event.b);
        write_word_from_u32_v2<F>(cols.op_c_value, event.c);
        write_word_from_u32_v2<F>(cols.prev_a_value, event.prev_a);
        cols.shard = F::from_canonical_u32(event.shard);
        cols.clk = F::from_canonical_u32(event.clk);

        cols.is_sext = F::from_bool(event.opcode == Opcode::SEXT);
        cols.is_ext = F::from_bool(event.opcode == Opcode::EXT);
        cols.is_ins = F::from_bool(event.opcode == Opcode::INS);
        cols.is_maddu = F::from_bool(event.opcode == Opcode::MADDU);
        cols.is_msubu = F::from_bool(event.opcode == Opcode::MSUBU);
        cols.is_madd = F::from_bool(event.opcode == Opcode::MADD);
        cols.is_msub = F::from_bool(event.opcode == Opcode::MSUB);
        cols.is_teq = F::from_bool(event.opcode == Opcode::TEQ);

        populate_sext(event, cols);
        populate_maddsub(event, cols);
        populate_ext(event, cols);
        populate_ins(event, cols);
    }
}  // namespace zkm::misc_instrs

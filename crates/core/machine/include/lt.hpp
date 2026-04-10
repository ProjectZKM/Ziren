#pragma once

#include <cassert>
#include "prelude.hpp"
#include "utils.hpp"

namespace zkm_core_machine_sys::lt {
template<class F>
__ZKM_HOSTDEV__ void event_to_row(const AluEvent& event, LtCols<F>& cols) {
    cols.pc = F::from_canonical_u32(event.pc);
    cols.next_pc = F::from_canonical_u32(event.next_pc);

    auto a = u32_to_le_bytes(event.a);
    auto b = u32_to_le_bytes(event.b);
    auto c = u32_to_le_bytes(event.c);

    write_word_from_le_bytes<F>(cols.a, a);
    write_word_from_le_bytes<F>(cols.b, b);
    write_word_from_le_bytes<F>(cols.c, c);

    // If this is SLT, mask the MSB of b & c before computing cols.bits.
    uint8_t masked_b = b[3] & 0x7f;
    uint8_t masked_c = c[3] & 0x7f;
    cols.b_masked = F::from_canonical_u8(masked_b);
    cols.c_masked = F::from_canonical_u8(masked_c);

    auto b_comp = b;
    auto c_comp = c;
    if (event.opcode == Opcode::SLT) {
        b_comp[3] = masked_b;
        c_comp[3] = masked_c;
    }
    cols.sltu = F::from_bool(b_comp < c_comp);
    cols.is_comp_eq = F::from_bool(b_comp == c_comp);
    cols.not_eq_inv = F::zero();
    std::fill(std::begin(cols.byte_flags), std::end(cols.byte_flags), F::zero());
    std::fill(std::begin(cols.comparison_bytes), std::end(cols.comparison_bytes), F::zero());

    // Set the byte equality flags.
    for (int idx = 3; idx >= 0; --idx) {
        uint8_t b_byte = b_comp[idx];
        uint8_t c_byte = c_comp[idx];
        
        if (c_byte != b_byte) {
            cols.byte_flags[idx] = F::one();
            cols.sltu = F::from_bool(b_byte < c_byte);

            F b_byte_f = F::from_canonical_u8(b_byte);
            F c_byte_f = F::from_canonical_u8(c_byte);

            cols.not_eq_inv = (b_byte_f - c_byte_f).reciprocal();
            cols.comparison_bytes[0] = b_byte_f;
            cols.comparison_bytes[1] = c_byte_f;
            break;
        }
    }

    cols.msb_b = F::from_canonical_u8((b[3] >> 7) & 1);
    cols.msb_c = F::from_canonical_u8((c[3] >> 7) & 1);
    if (event.opcode == Opcode::SLT) {
        cols.is_sign_eq = F::from_bool((b[3] >> 7) == (c[3] >> 7));
    } else {
        cols.is_sign_eq = F::one();
    };

    cols.is_slt = F::from_bool(event.opcode == Opcode::SLT);
    cols.is_sltu = F::from_bool(event.opcode == Opcode::SLTU);

    cols.bit_b = cols.msb_b * cols.is_slt;
    cols.bit_c = cols.msb_c * cols.is_slt;

    assert(cols.a._0[0] == cols.bit_b * (F::one() - cols.bit_c) + cols.is_sign_eq * cols.sltu);
}
}  // namespace zkm::lt

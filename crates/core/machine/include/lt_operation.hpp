#pragma once

#include "prelude.hpp"
#include "utils.hpp"

// Column mirror of `operations/lt.rs` (`LtOperation`) — the embeddable
// signed/unsigned less-than gadget.  Columns only: the byte events come from
// the host `generate_dependencies` pass.
namespace zkm_core_machine_sys::lt_operation {

template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ void populate(
    LtOperation<F>& op,
    const uint32_t b,
    const uint32_t c,
    const bool is_signed
) {
    const auto b_bytes = u32_to_le_bytes(b);
    const auto c_bytes = u32_to_le_bytes(c);

    const uint8_t masked_b = b_bytes[3] & 0x7f;
    const uint8_t masked_c = c_bytes[3] & 0x7f;
    op.b_masked = F::from_canonical_u8(masked_b);
    op.c_masked = F::from_canonical_u8(masked_c);

    auto b_comp = b_bytes;
    auto c_comp = c_bytes;
    if (is_signed) {
        b_comp[3] = masked_b;
        c_comp[3] = masked_c;
    }
    bool sltu = b_comp < c_comp;
    op.is_comp_eq = F::from_bool(b_comp == c_comp);

    // Most-significant differing byte, mirroring the Rust loop.
    for (int idx = 3; idx >= 0; --idx) {
        const uint8_t b_byte = b_comp[idx];
        const uint8_t c_byte = c_comp[idx];
        if (b_byte != c_byte) {
            op.byte_flags[idx] = F::one();
            sltu = b_byte < c_byte;
            const F b_byte_f = F::from_canonical_u8(b_byte);
            const F c_byte_f = F::from_canonical_u8(c_byte);
            op.not_eq_inv = (b_byte_f - c_byte_f).reciprocal();
            op.comparison_bytes[0] = b_byte_f;
            op.comparison_bytes[1] = c_byte_f;
            break;
        }
    }
    op.sltu = F::from_bool(sltu);

    op.msb_b = F::from_canonical_u8((b_bytes[3] >> 7) & 1);
    op.msb_c = F::from_canonical_u8((c_bytes[3] >> 7) & 1);
    op.is_sign_eq =
        is_signed ? F::from_bool((b_bytes[3] >> 7) == (c_bytes[3] >> 7)) : F::one();
    if (is_signed) {
        op.bit_b = op.msb_b;
        op.bit_c = op.msb_c;
    }
    op.lt = op.bit_b * (F::one() - op.bit_c) + op.is_sign_eq * op.sltu;
}

}  // namespace zkm_core_machine_sys::lt_operation

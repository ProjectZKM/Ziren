#pragma once

#include "prelude.hpp"
#include "utils.hpp"

// Column mirror of `operations/mul_operation.rs` (`MulOperation`) — the
// embeddable 64-bit multiplication gadget.  Columns only: the byte events come
// from the host `generate_dependencies` pass.
namespace zkm_core_machine_sys::mul_operation {

template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ void populate(
    MulOperation<F>& op,
    const uint32_t b,
    const uint32_t c,
    const bool is_signed
) {
    constexpr uintptr_t PRODUCT_SIZE = 8;
    const auto b_word = u32_to_le_bytes(b);
    const auto c_word = u32_to_le_bytes(c);

    const uint8_t b_msb = (b_word[3] >> 7) & 1;
    const uint8_t c_msb = (c_word[3] >> 7) & 1;
    op.b_msb = F::from_canonical_u8(b_msb);
    op.c_msb = F::from_canonical_u8(c_msb);

    const bool b_ext = is_signed && b_msb == 1;
    const bool c_ext = is_signed && c_msb == 1;
    if (b_ext) {
        op.b_sign_extend = F::one();
    }
    if (c_ext) {
        op.c_sign_extend = F::one();
    }

    // Extend to 64 bits (0xff when sign-extended, else zero — zero upper
    // bytes contribute nothing, matching the Rust `Vec::resize` form).
    uint8_t b64[PRODUCT_SIZE];
    uint8_t c64[PRODUCT_SIZE];
    for (uintptr_t i = 0; i < 4; ++i) {
        b64[i] = b_word[i];
        c64[i] = c_word[i];
    }
    for (uintptr_t i = 4; i < PRODUCT_SIZE; ++i) {
        b64[i] = b_ext ? 0xff : 0;
        c64[i] = c_ext ? 0xff : 0;
    }

    uint32_t product[PRODUCT_SIZE] = {0u};
    for (uintptr_t i = 0; i < PRODUCT_SIZE; ++i) {
        for (uintptr_t j = 0; j < PRODUCT_SIZE; ++j) {
            if (i + j < PRODUCT_SIZE) {
                product[i + j] += (uint32_t)b64[i] * (uint32_t)c64[j];
            }
        }
    }

    const uint32_t base = 1u << 8;
    for (uintptr_t i = 0; i < PRODUCT_SIZE; ++i) {
        const uint32_t carry = product[i] / base;
        product[i] %= base;
        if (i + 1 < PRODUCT_SIZE) {
            product[i + 1] += carry;
        }
        op.carry[i] = F::from_canonical_u32(carry);
        op.product[i] = F::from_canonical_u32(product[i]);
    }
}

}  // namespace zkm_core_machine_sys::mul_operation

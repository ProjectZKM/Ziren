#pragma once

#include <cstddef>
#include <tuple>

#include "prelude.hpp"

namespace zkm_core_machine_sys {

// Compiles to a no-op with -O3 and the like.
__ZKM_HOSTDEV__ __ZKM_INLINE__ array_t<uint8_t, 4> u32_to_le_bytes(uint32_t n) {
    return {
        (uint8_t)(n >> 8 * 0),
        (uint8_t)(n >> 8 * 1),
        (uint8_t)(n >> 8 * 2),
        (uint8_t)(n >> 8 * 3),
    };
}

__ZKM_HOSTDEV__ __ZKM_INLINE__ array_t<uint8_t, 8> u64_to_le_bytes(uint64_t n) {
    return {
        (uint8_t)(n >> 8 * 0),
        (uint8_t)(n >> 8 * 1),
        (uint8_t)(n >> 8 * 2),
        (uint8_t)(n >> 8 * 3),
        (uint8_t)(n >> 8 * 4),
        (uint8_t)(n >> 8 * 5),
        (uint8_t)(n >> 8 * 6),
        (uint8_t)(n >> 8 * 7),
    };
}

/// Shifts a byte to the right and returns both the shifted byte and the bits that carried.
__ZKM_HOSTDEV__ __ZKM_INLINE__ std::tuple<uint8_t, uint8_t>
shr_carry(uint8_t input, uint8_t rotation) {
    uint8_t c_mod = rotation & 0x7;
    if (c_mod != 0) {
        uint8_t res = input >> c_mod;
        uint8_t c_mod_comp = 8 - c_mod;
        uint8_t carry = (uint8_t)(input << c_mod_comp) >> c_mod_comp;
        return {res, carry};
    } else {
        return {input, 0};
    }
}

template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ void
write_word_from_u32(Word<decltype(F::val)>& word, const uint32_t value) {
    // Coercion to `uint8_t` truncates the number.
    word._0[0] = F::from_canonical_u8(value).val;
    word._0[1] = F::from_canonical_u8(value >> 8).val;
    word._0[2] = F::from_canonical_u8(value >> 16).val;
    word._0[3] = F::from_canonical_u8(value >> 24).val;
}

template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ void
write_word_from_u32_v2(Word<F>& word, const uint32_t value) {
    word._0[0] = F::from_canonical_u8(value);
    word._0[1] = F::from_canonical_u8(value >> 8);
    word._0[2] = F::from_canonical_u8(value >> 16);
    word._0[3] = F::from_canonical_u8(value >> 24);
}

template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ uint32_t
word_to_u32(const Word<decltype(F::val)>& word) {
    return ((uint8_t)F(word._0[0]).as_canonical_u32())
        + ((uint8_t)F(word._0[1]).as_canonical_u32() << 8)
        + ((uint8_t)F(word._0[1]).as_canonical_u32() << 16)
        + ((uint8_t)F(word._0[1]).as_canonical_u32() << 24);
}

template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ void word_from_le_bytes(
    Word<decltype(F::val)>& word,
    const array_t<uint8_t, 4> bytes
) {
    // Coercion to `uint8_t` truncates the number.
    word._0[0] = F::from_canonical_u8(bytes[0]).val;
    word._0[1] = F::from_canonical_u8(bytes[1]).val;
    word._0[2] = F::from_canonical_u8(bytes[2]).val;
    word._0[3] = F::from_canonical_u8(bytes[3]).val;
}

__ZKM_HOSTDEV__ __ZKM_INLINE__ uint8_t
get_msb(const array_t<uint8_t, WORD_SIZE> a) {
    return (a[WORD_SIZE - 1] >> (BYTE_SIZE - 1)) & 1;
}

namespace opcode_utils {
    __ZKM_HOSTDEV__ __ZKM_INLINE__ bool is_memory(Opcode opcode) {
        switch (opcode) {
            case Opcode::LH:
            case Opcode::LWL:
            case Opcode::LW:
            case Opcode::LBU:
            case Opcode::LHU:
            case Opcode::LWR:
            case Opcode::SB:
            case Opcode::SH:
            case Opcode::SWL:
            case Opcode::SW:
            case Opcode::LL:
            case Opcode::SC:
            case Opcode::LB:
                return true;
            default:
                return false;
        }
    }

    __ZKM_HOSTDEV__ __ZKM_INLINE__ bool is_branch(Opcode opcode) {
        switch (opcode) {
            case Opcode::BEQ:
            case Opcode::BNE:
            case Opcode::BLTZ:
            case Opcode::BGEZ:
            case Opcode::BLEZ:
            case Opcode::BGTZ:
                return true;
            default:
                return false;
        }
    }

    __ZKM_HOSTDEV__ __ZKM_INLINE__ bool is_jump(Opcode opcode) {
        switch (opcode) {
            case Opcode::Jump:
            case Opcode::Jumpi:
            case Opcode::JumpDirect:
                return true;
            default:
                return false;
        }
    }
}  // namespace opcode_utils
}  // namespace zkm_core_machine_sys

#pragma once

#include <cstddef>
#include <tuple>
#include <cstdint>
#include <climits>

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

__ZKM_HOSTDEV__ __ZKM_INLINE__ array_t<uint8_t, 8> i64_to_le_bytes(int64_t n) {
    return {
        static_cast<uint8_t>(n & 0xFF),
        static_cast<uint8_t>((n >> 8) & 0xFF),
        static_cast<uint8_t>((n >> 16) & 0xFF),
        static_cast<uint8_t>((n >> 24) & 0xFF),
        static_cast<uint8_t>((n >> 32) & 0xFF),
        static_cast<uint8_t>((n >> 40) & 0xFF),
        static_cast<uint8_t>((n >> 48) & 0xFF),
        static_cast<uint8_t>((n >> 56) & 0xFF),
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
__ZKM_HOSTDEV__ __ZKM_INLINE__ void
write_word_from_le_bytes(Word<F>& word, const array_t<uint8_t, 4> bytes) {
    word._0[0] = F::from_canonical_u8(bytes[0]);
    word._0[1] = F::from_canonical_u8(bytes[1]);
    word._0[2] = F::from_canonical_u8(bytes[2]);
    word._0[3] = F::from_canonical_u8(bytes[3]);
}

template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ void
write_word_from_le_bytes_v2(F word[WORD_SIZE], const uint8_t bytes[WORD_SIZE]) {
    word[0] = F::from_canonical_u8(bytes[0]);
    word[1] = F::from_canonical_u8(bytes[1]);
    word[2] = F::from_canonical_u8(bytes[2]);
    word[3] = F::from_canonical_u8(bytes[3]);
}

template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ void
write_long_word_from_le_bytes_v2(F word[LONG_WORD_SIZE], const uint8_t bytes[LONG_WORD_SIZE]) {
    word[0] = F::from_canonical_u8(bytes[0]);
    word[1] = F::from_canonical_u8(bytes[1]);
    word[2] = F::from_canonical_u8(bytes[2]);
    word[3] = F::from_canonical_u8(bytes[3]);
    word[4] = F::from_canonical_u8(bytes[4]);
    word[5] = F::from_canonical_u8(bytes[5]);
    word[6] = F::from_canonical_u8(bytes[6]);
    word[7] = F::from_canonical_u8(bytes[7]);
}

template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ uint32_t
word_to_u32(const Word<decltype(F::val)>& word) {
    return ((uint32_t)F(word._0[0]).as_canonical_u32())
        | ((uint32_t)F(word._0[1]).as_canonical_u32() << 8)
        | ((uint32_t)F(word._0[2]).as_canonical_u32() << 16)
        | ((uint32_t)F(word._0[3]).as_canonical_u32() << 24);
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

template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ array_t<F, 4> u32_to_word(uint32_t a) {
    return array_t<F, 4>{
        F::from_canonical_u8((uint8_t)(a >> 8 * 0)),
        F::from_canonical_u8((uint8_t)(a >> 8 * 1)),
        F::from_canonical_u8((uint8_t)(a >> 8 * 2)),
        F::from_canonical_u8((uint8_t)(a >> 8 * 3))
    };
}

/// Calculate the number of bytes to shift by.
///
/// Note that we take the least significant 5 bits per the MIPS spec.
__ZKM_HOSTDEV__ __ZKM_INLINE__ size_t nb_bytes_to_shift(uint32_t shift_amount) {
    size_t n = (size_t)(shift_amount % 32);
    return n / BYTE_SIZE;
}

/// Calculate the number of bits shift by.
///
/// Note that we take the least significant 5 bits per the MIPS spec.
__ZKM_HOSTDEV__ __ZKM_INLINE__ size_t nb_bits_to_shift(uint32_t shift_amount) {
    size_t n = (size_t)(shift_amount % 32);
    return n % BYTE_SIZE;
}

/// Returns `true` if the given opcode is a signed operation.
__ZKM_HOSTDEV__ __ZKM_INLINE__ bool is_signed_operation(Opcode opcode) {
    // todo: add more signed operations
    return (opcode == Opcode::DIV || opcode == Opcode::MOD);
}

/// Calculate the correct `quotient` and `remainder` for the given `b` and `c` per MIPS spec.
__ZKM_HOSTDEV__ __ZKM_INLINE__ std::tuple<uint32_t, uint32_t>
get_quotient_and_remainder(uint32_t b, uint32_t c, Opcode opcode) {
    if (c == 0) {
        // When c is 0, the quotient is 2^32 - 1 and the remainder is b regardless of whether we
        // perform signed or unsigned division.
        return {INT32_MAX, b};
    } else if (is_signed_operation(opcode)) {
        return {(uint32_t)((int32_t)b / (int32_t)c), (uint32_t)((int32_t)b % (int32_t)c)};
    } else {
        return {b / c, b % c};
    }
}

__ZKM_HOSTDEV__ __ZKM_INLINE__ uint8_t
get_msb(const array_t<uint8_t, WORD_SIZE> a) {
    return (a[WORD_SIZE - 1] >> (BYTE_SIZE - 1)) & 1;
}

/// Calculate the most significant bit of the given 32-bit integer `a`, and returns it as a u8.
__ZKM_HOSTDEV__ __ZKM_INLINE__ uint8_t
get_msb_v2(uint32_t a) {
    return (uint8_t)((a >> 31) & 1);
}

__ZKM_HOSTDEV__ __ZKM_INLINE__ uint32_t unsigned_abs(int32_t value) {
    if (value == INT32_MIN) {
        return 0x80000000;
    }

    if (value < 0) {
        return static_cast<uint32_t>(-value);
    }

    return static_cast<uint32_t>(value);
}

template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ void populate_range_checker(KoalaBearWordRangeChecker<F>& self, const uint32_t value) {
    for (size_t i = 0; i < 8; ++i) {
        bool bit = (value & (1u << (i + 24))) != 0;
        self.most_sig_byte_decomp[i] = F::from_bool(bit);
    }
    self.and_most_sig_byte_decomp_0_to_2 =
        self.most_sig_byte_decomp[0] * self.most_sig_byte_decomp[1];
    self.and_most_sig_byte_decomp_0_to_3 =
        self.and_most_sig_byte_decomp_0_to_2 * self.most_sig_byte_decomp[2];
    self.and_most_sig_byte_decomp_0_to_4 =
        self.and_most_sig_byte_decomp_0_to_3 * self.most_sig_byte_decomp[3];
    self.and_most_sig_byte_decomp_0_to_5 =
        self.and_most_sig_byte_decomp_0_to_4 * self.most_sig_byte_decomp[4];
    self.and_most_sig_byte_decomp_0_to_6 =
        self.and_most_sig_byte_decomp_0_to_5 * self.most_sig_byte_decomp[5];
    self.and_most_sig_byte_decomp_0_to_7 =
        self.and_most_sig_byte_decomp_0_to_6 * self.most_sig_byte_decomp[6];
}

template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ uint32_t populate_is_zero_operation(IsZeroOperation<F>& self, const F& a) {
    if (a == F::zero()) {
        self.inverse = F::zero();
        self.result = F::one();
    } else {
        self.inverse = a.reciprocal();
        self.result = F::zero();
    }
    F prod = self.inverse * a;
    assert(prod == F::one() || prod == F::zero());
    return (uint32_t)(a == F::zero());
}

template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ uint32_t
populate_is_zero_word_operaion(IsZeroWordOperation<F>& self, const array_t<F, 4> bytes) {
    bool is_zero = true;
    for (size_t i = 0; i < WORD_SIZE; ++i) {
        is_zero &= populate_is_zero_operation(self.is_zero_byte[i], bytes[i]) == 1;
    }
    self.is_lower_half_zero = self.is_zero_byte[0].result * self.is_zero_byte[1].result;
    self.is_upper_half_zero = self.is_zero_byte[2].result * self.is_zero_byte[3].result;
    self.result = F::from_bool(is_zero);
    return (uint32_t)is_zero;
}

template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ uint32_t
populate_is_equal_word_operaion(IsEqualWordOperation<F>& self, uint32_t a_u32, uint32_t b_u32) {
    array_t<uint8_t, 4> a = u32_to_le_bytes(a_u32);
    array_t<uint8_t, 4> b = u32_to_le_bytes(b_u32);
    array_t<F, 4> diff = {
        F::from_canonical_u8(a[0]) - F::from_canonical_u8(b[0]),
        F::from_canonical_u8(a[1]) - F::from_canonical_u8(b[1]),
        F::from_canonical_u8(a[2]) - F::from_canonical_u8(b[2]),
        F::from_canonical_u8(a[3]) - F::from_canonical_u8(b[3]),
    };
    populate_is_zero_word_operaion(self.is_diff_zero, diff);
    return (uint32_t)(a == b);
}

template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ uint64_t
populate_add_double_operaion(AddDoubleOperation<F>& self, uint64_t a_u64, uint64_t b_u64) {
    uint64_t expected = a_u64 + b_u64;
    write_word_from_u32_v2<F>(self.value, (uint32_t)expected);
    write_word_from_u32_v2<F>(self.value_hi, (uint32_t)(expected >> 32));

    auto a = u64_to_le_bytes(a_u64);
    auto b = u64_to_le_bytes(b_u64);

    uint8_t carry[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    for (int i = 0; i < 7; i++) {
        self.carry[i] = F::zero();
    }

    if ((uint32_t)a[0] + (uint32_t)b[0] > 255) {
        carry[0] = 1;
        self.carry[0] = F::one();
    }
    if ((uint32_t)a[1] + (uint32_t)b[1] + (uint32_t)carry[0] > 255) {
        carry[1] = 1;
        self.carry[1] = F::one();
    }
    if ((uint32_t)a[2] + (uint32_t)b[2] + (uint32_t)carry[1] > 255) {
        carry[2] = 1;
        self.carry[2] = F::one();
    }

    if ((uint32_t)a[3] + (uint32_t)b[3] + (uint32_t)carry[2] > 255) {
        carry[3] = 1;
        self.carry[3] = F::one();
    }

    if ((uint32_t)a[4] + (uint32_t)b[4] + (uint32_t)carry[3] > 255) {
        carry[4] = 1;
        self.carry[4] = F::one();
    }

    if ((uint32_t)a[5] + (uint32_t)b[5] + (uint32_t)carry[4] > 255) {
        carry[5] = 1;
        self.carry[5] = F::one();
    }

    if ((uint32_t)a[6] + (uint32_t)b[6] + (uint32_t)carry[5] > 255) {
        carry[6] = 1;
        self.carry[6] = F::one();
    }

    uint32_t base = 256;
    uint32_t overflow = (uint32_t)a[0] + (uint32_t)b[0] - (uint32_t)u64_to_le_bytes(expected)[0];
    assert(overflow * (overflow - base) == 0);
    return expected;
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

#include <stdio.h>
#include "kb31_t.hpp"
#include "kb31_septic_extension_t.hpp"

namespace zkm_core_machine_sys {

extern "C" void test_mul() {
    const uint32_t i = 0;
    kb31_t t[7] = {
        kb31_t::from_canonical_u32(i + 3),
        kb31_t::from_canonical_u32(2 * i + 6),
        kb31_t::from_canonical_u32(5 * i + 17),
        kb31_t::from_canonical_u32(6 * i + 91),
        kb31_t::from_canonical_u32(8 * i + 37),
        kb31_t::from_canonical_u32(11 * i + 35),
        kb31_t::from_canonical_u32(14 * i + 33),
    };
    const uint32_t i1 = 1;
    kb31_t t1[7] = {
        kb31_t::from_canonical_u32(i1 + 3),
        kb31_t::from_canonical_u32(2 * i1 + 6),
        kb31_t::from_canonical_u32(5 * i1 + 17),
        kb31_t::from_canonical_u32(6 * i1 + 91),
        kb31_t::from_canonical_u32(8 * i1 + 37),
        kb31_t::from_canonical_u32(11 * i1 + 35),
        kb31_t::from_canonical_u32(14 * i1 + 33),
    };

    kb31_septic_extension_t a = kb31_septic_extension_t(t);
    kb31_septic_extension_t b = kb31_septic_extension_t(t1);
    kb31_septic_extension_t c = a * b;

    kb31_t t2[7] = {
        kb31_t(1207801784u),
        kb31_t(1358820143u),
        kb31_t(1241383606u),
        kb31_t(1711239578u),
        kb31_t(452949349u),
        kb31_t(1207938232u),
        kb31_t(167755766u),
    };
    assert(c == kb31_septic_extension_t(t2));
}

extern "C" void test_inv() {
    kb31_septic_extension_t one = kb31_septic_extension_t::one();

    for (int i = 0; i < 256; i++) {
        kb31_t t[7] = {
            kb31_t::from_canonical_u32(i + 3),
            kb31_t::from_canonical_u32(2 * i + 6),
            kb31_t::from_canonical_u32(5 * i + 17),
            kb31_t::from_canonical_u32(6 * i + 91),
            kb31_t::from_canonical_u32(8 * i + 37),
            kb31_t::from_canonical_u32(11 * i + 35),
            kb31_t::from_canonical_u32(14 * i + 33),
        };

        kb31_septic_extension_t a = kb31_septic_extension_t(t);
        kb31_septic_extension_t b = a.reciprocal();
        kb31_septic_extension_t c = a * b;
        assert(c == one);
    }
}

extern "C" void test_sqrt() {
    for (int i = 0; i < 256; i++) {
        kb31_t t[7] = {
            kb31_t::from_canonical_u32(i + 3),
            kb31_t::from_canonical_u32(2 * i + 6),
            kb31_t::from_canonical_u32(5 * i + 17),
            kb31_t::from_canonical_u32(6 * i + 91),
            kb31_t::from_canonical_u32(8 * i + 37),
            kb31_t::from_canonical_u32(11 * i + 35),
            kb31_t::from_canonical_u32(14 * i + 33),
        };

        kb31_septic_extension_t a = kb31_septic_extension_t(t);
        kb31_septic_extension_t b = a * a;

        kb31_t b_pow_r = b.pow_r();
        kb31_t is_square = b_pow_r ^ 1065353216;
        assert(is_square == kb31_t::one());
        kb31_septic_extension_t recovered_a = b.sqrt(b_pow_r);
        assert(recovered_a * recovered_a == b);
    }

    kb31_septic_extension_t b = kb31_septic_extension_t::one();
    kb31_t t[7] = {
        kb31_t::two(),
        kb31_t::one(),
        kb31_t::zero(),
        kb31_t::zero(),
        kb31_t::zero(),
        kb31_t::zero(),
        kb31_t::zero(),
    };
    kb31_septic_extension_t g = kb31_septic_extension_t(t);
    for (int i = 1; i < 256; i++) {
        b *= g;
        kb31_t b_pow_r = b.pow_r();
        kb31_t is_square = b_pow_r ^ 1065353216;
        kb31_septic_extension_t c = b.sqrt(b_pow_r);
        if (i % 2 == 1) {
            assert(is_square != kb31_t::one());
        } else {
            assert(is_square == kb31_t::one());
            assert(c * c == b);
        }
    }
}

extern "C" void test_curve_formula() {
    kb31_t t1[7] = {
        kb31_t::from_canonical_u32(1511106837),
        kb31_t::from_canonical_u32(0),
        kb31_t::from_canonical_u32(0),
        kb31_t::from_canonical_u32(0),
        kb31_t::from_canonical_u32(0),
        kb31_t::from_canonical_u32(0),
        kb31_t::from_canonical_u32(0),
    };
    kb31_t t2[7] = {
        kb31_t(1672765296u),
        kb31_t(1918153453u),
        kb31_t(0),
        kb31_t(0),
        kb31_t(0),
        kb31_t(0),
        kb31_t(0),
    };
    kb31_septic_extension_t x = kb31_septic_extension_t(t1);
    kb31_septic_extension_t y_square = x.curve_formula();
    assert(y_square == kb31_septic_extension_t(t2));

    kb31_t t3[7] = {
        kb31_t::from_canonical_u32(0x2013),
        kb31_t::from_canonical_u32(0x2015),
        kb31_t::from_canonical_u32(0x2016),
        kb31_t::from_canonical_u32(0x2023),
        kb31_t::from_canonical_u32(0x2024),
        kb31_t::from_canonical_u32(0x2016),
        kb31_t::from_canonical_u32(0x2017),
    };
    kb31_t t4[7] = {
        kb31_t(1710435843u),
        kb31_t(137585108u),
        kb31_t(1660143607u),
        kb31_t(1025303300u),
        kb31_t(453379311u),
        kb31_t(578884353u),
        kb31_t(669106462u),
    };

    kb31_septic_extension_t x1 = kb31_septic_extension_t(t3);
    kb31_septic_extension_t y1_square = x1.curve_formula();
    assert(y1_square == kb31_septic_extension_t(t4));
}

}

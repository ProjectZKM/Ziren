// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// Canonical KoalaBear arithmetic. E4 uses four 32-bit lanes, low lane first,
/// in the native basis F[X]/(X^4-3). No Montgomery values enter this API.
library KoalaBear {
    uint256 internal constant P = 0x7f000001;
    error InvalidField();
    error DivisionByZero();

    function canonical(uint256 a) internal pure returns (bool) {
        return a >> 128 == 0 && uint32(a) < P && uint32(a >> 32) < P && uint32(a >> 64) < P && uint32(a >> 96) < P;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256 c) {
        assembly ("memory-safe") {
            let p := 0x7f000001
            let m := 0xffffffff
            c := or(
                or(mod(add(and(a, m), and(b, m)), p), shl(32, mod(add(and(shr(32, a), m), and(shr(32, b), m)), p))),
                or(
                    shl(64, mod(add(and(shr(64, a), m), and(shr(64, b), m)), p)),
                    shl(96, mod(add(and(shr(96, a), m), and(shr(96, b), m)), p))
                )
            )
        }
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256 c) {
        assembly ("memory-safe") {
            let p := 0x7f000001
            let m := 0xffffffff
            c := or(
                or(
                    mod(sub(add(and(a, m), p), and(b, m)), p),
                    shl(32, mod(sub(add(and(shr(32, a), m), p), and(shr(32, b), m)), p))
                ),
                or(
                    shl(64, mod(sub(add(and(shr(64, a), m), p), and(shr(64, b), m)), p)),
                    shl(96, mod(sub(add(and(shr(96, a), m), p), and(shr(96, b), m)), p))
                )
            )
        }
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256 c) {
        assembly ("memory-safe") {
            let p := 0x7f000001
            let m := 0xffffffff
            let a0 := and(a, m)
            let a1 := and(shr(32, a), m)
            let a2 := and(shr(64, a), m)
            let a3 := and(shr(96, a), m)
            let b0 := and(b, m)
            let b1 := and(shr(32, b), m)
            let b2 := and(shr(64, b), m)
            let b3 := and(shr(96, b), m)
            let c0 := mod(add(mul(a0, b0), mul(3, add(add(mul(a1, b3), mul(a2, b2)), mul(a3, b1)))), p)
            let c1 := mod(add(add(mul(a0, b1), mul(a1, b0)), mul(3, add(mul(a2, b3), mul(a3, b2)))), p)
            let c2 := mod(add(add(add(mul(a0, b2), mul(a1, b1)), mul(a2, b0)), mul(3, mul(a3, b3))), p)
            let c3 := mod(add(add(mul(a0, b3), mul(a1, b2)), add(mul(a2, b1), mul(a3, b0))), p)
            c := or(or(c0, shl(32, c1)), or(shl(64, c2), shl(96, c3)))
        }
    }

    /// Multiply an extension by a canonical base-field scalar.
    function scale(uint256 a, uint256 b) internal pure returns (uint256 c) {
        assembly ("memory-safe") {
            let p := 0x7f000001
            let m := 0xffffffff
            c := or(
                or(mod(mul(and(a, m), b), p), shl(32, mod(mul(and(shr(32, a), m), b), p))),
                or(shl(64, mod(mul(and(shr(64, a), m), b), p)), shl(96, mod(mul(and(shr(96, a), m), b), p)))
            )
        }
    }

    function pow(uint256 a, uint256 n) internal pure returns (uint256 r) {
        r = 1;
        while (n != 0) {
            if (n & 1 != 0) r = mul(r, a);
            n >>= 1;
            if (n != 0) a = mul(a, a);
        }
    }

    function inv(uint256 a) internal pure returns (uint256 r) {
        if (a == 0) revert DivisionByZero();
        // Quadratic tower: a=A+X*B, A=a0+a2*u, B=a1+a3*u,
        // u=X^2, u^2=3. Invert the quadratic norm using one base inverse.
        assembly ("memory-safe") {
            let p := 0x7f000001
            let m := 0xffffffff
            let a0 := and(a, m)
            let a1 := and(shr(32, a), m)
            let a2 := and(shr(64, a), m)
            let a3 := and(shr(96, a), m)
            let c0 := mod(sub(add(add(mul(a0, a0), mul(3, mul(a2, a2))), mul(6, mul(p, p))), mul(6, mul(a1, a3))), p)
            let c2 := mod(sub(add(mul(2, mul(a0, a2)), mul(4, mul(p, p))), add(mul(a1, a1), mul(3, mul(a3, a3)))), p)
            let norm := mod(sub(add(mul(c0, c0), mul(3, mul(p, p))), mul(3, mul(c2, c2))), p)
            let inverse := 1
            for { let exponent := sub(p, 2) } exponent { exponent := shr(1, exponent) } {
                if and(exponent, 1) { inverse := mod(mul(inverse, norm), p) }
                norm := mod(mul(norm, norm), p)
            }
            let e0 := mod(mul(mod(sub(add(mul(a0, c0), mul(3, mul(p, p))), mul(3, mul(a2, c2))), p), inverse), p)
            let e1 := mod(mul(mod(sub(add(mul(3, mul(a3, c2)), mul(p, p)), mul(a1, c0)), p), inverse), p)
            let e2 := mod(mul(mod(sub(add(mul(a2, c0), mul(p, p)), mul(a0, c2)), p), inverse), p)
            let e3 := mod(mul(mod(sub(add(mul(a1, c2), mul(p, p)), mul(a3, c0)), p), inverse), p)
            r := or(or(e0, shl(32, e1)), or(shl(64, e2), shl(96, e3)))
        }
    }

    function eq(uint256[] memory a, uint256[] memory b) internal pure returns (uint256 r) {
        require(a.length == b.length, "eq length");
        r = 1;
        for (uint256 i; i < a.length; ++i) {
            r = mul(r, add(mul(a[i], b[i]), mul(sub(1, a[i]), sub(1, b[i]))));
        }
    }

    /// Native Mle::eval_at fixes LSB variables first: adjacent cells are folded.
    function mle(uint256[] memory values, uint256[] memory point) internal pure returns (uint256) {
        require(values.length == 1 << point.length, "MLE shape");
        uint256[] memory row = new uint256[](values.length);
        for (uint256 i; i < values.length; ++i) {
            row[i] = values[i];
        }
        uint256 n = row.length;
        for (uint256 j; j < point.length; ++j) {
            n >>= 1;
            for (uint256 i; i < n; ++i) {
                row[i] = add(row[2 * i], mul(point[j], sub(row[2 * i + 1], row[2 * i])));
            }
        }
        return row[0];
    }

    function mono(uint256[] memory values, uint256[] memory point) internal pure returns (uint256 r) {
        require(values.length == 1 << point.length, "monomial shape");
        uint256[] memory row = new uint256[](values.length);
        for (uint256 i; i < values.length; ++i) {
            row[i] = values[i];
        }
        uint256 n = row.length;
        for (uint256 j; j < point.length; ++j) {
            n >>= 1;
            for (uint256 i; i < n; ++i) {
                row[i] = add(row[2 * i], mul(point[j], row[2 * i + 1]));
            }
        }
        return row[0];
    }

    /// Evaluate E4 coefficients at a base-field x using radix-64 lanes.
    /// Each lane before reduction is <= (p-1)^2+(p-1) < 2^62, so no
    /// carry crosses a 64-bit lane and the four-lane product fits 256 bits.
    function hornerBase(uint256[] memory coefficients, uint256 x) internal pure returns (uint256 out) {
        require(coefficients.length != 0 && x < P, "base polynomial");
        assembly ("memory-safe") {
            let p := 0x7f000001
            let mask := 0xffffffff
            let wideMask := 0xffffffffffffffff
            let start := add(coefficients, 32)
            let src := add(start, mul(mload(coefficients), 32))
            let acc := 0
            for {} gt(src, start) {} {
                src := sub(src, 32)
                let v := mload(src)
                let spread :=
                    or(
                        or(and(v, mask), shl(64, and(shr(32, v), mask))),
                        or(shl(128, and(shr(64, v), mask)), shl(192, and(shr(96, v), mask)))
                    )
                let product := add(mul(acc, x), spread)
                acc := or(
                    or(mod(and(product, wideMask), p), shl(64, mod(and(shr(64, product), wideMask), p))),
                    or(shl(128, mod(and(shr(128, product), wideMask), p)), shl(192, mod(shr(192, product), p)))
                )
            }
            out := or(
                or(and(acc, mask), shl(32, and(shr(64, acc), mask))),
                or(shl(64, and(shr(128, acc), mask)), shl(96, shr(192, acc)))
            )
        }
    }

    /// Add `weight * inputs[i]` to canonical extension accumulators in place.
    /// inputs are canonical base fields; each unreduced lane is below p^2.
    function accumulateBaseRow(uint256[] memory values, uint256[] memory inputs, uint256 weight) internal pure {
        require(values.length == inputs.length, "base row shape");
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff
            let w0 := and(weight, mask)
            let w1 := and(shr(32, weight), mask)
            let w2 := and(shr(64, weight), mask)
            let w3 := and(shr(96, weight), mask)
            let dst := add(values, 32)
            let src := add(inputs, 32)
            let end := add(dst, mul(mload(values), 32))
            for {} lt(dst, end) {
                dst := add(dst, 32)
                src := add(src, 32)
            } {
                let x := mload(src)
                let acc := mload(dst)
                let c0 := mod(add(and(acc, mask), mul(w0, x)), modulus)
                let c1 := mod(add(and(shr(32, acc), mask), mul(w1, x)), modulus)
                let c2 := mod(add(and(shr(64, acc), mask), mul(w2, x)), modulus)
                let c3 := mod(add(shr(96, acc), mul(w3, x)), modulus)
                mstore(dst, or(or(c0, shl(32, c1)), or(shl(64, c2), shl(96, c3))))
            }
        }
    }

    /// Same fused accumulation, reading base words directly from a LE32 view.
    function accumulatePackedBaseRow(uint256[] memory values, bytes memory source, uint256 offset, uint256 weight)
        internal
        pure
    {
        require(offset + 4 * values.length <= source.length, "packed row bounds");
        assembly ("memory-safe") {
            let p := 0x7f000001
            let mask := 0xffffffff
            let w0 := and(weight, mask)
            let w1 := and(shr(32, weight), mask)
            let w2 := and(shr(64, weight), mask)
            let w3 := and(shr(96, weight), mask)
            let dst := add(values, 32)
            let src := add(add(source, 32), offset)
            let end := add(dst, mul(mload(values), 32))
            for {} lt(dst, end) {
                dst := add(dst, 32)
                src := add(src, 4)
            } {
                let word := mload(src)
                let x :=
                    or(or(byte(0, word), shl(8, byte(1, word))), or(shl(16, byte(2, word)), shl(24, byte(3, word))))
                let acc := mload(dst)
                let c0 := mod(add(and(acc, mask), mul(w0, x)), p)
                let c1 := mod(add(and(shr(32, acc), mask), mul(w1, x)), p)
                let c2 := mod(add(and(shr(64, acc), mask), mul(w2, x)), p)
                let c3 := mod(add(shr(96, acc), mul(w3, x)), p)
                mstore(dst, or(or(c0, shl(32, c1)), or(shl(64, c2), shl(96, c3))))
            }
        }
    }

    function packedExtensions(bytes memory source, uint256 offset, uint256 count)
        internal
        pure
        returns (uint256[] memory values)
    {
        require(offset + 16 * count <= source.length, "packed extension bounds");
        values = new uint256[](count);
        assembly ("memory-safe") {
            let dst := add(values, 32)
            let end := add(dst, mul(count, 32))
            let src := add(add(source, 32), offset)
            for {} lt(dst, end) {
                dst := add(dst, 32)
                src := add(src, 16)
            } {
                let w := shr(128, mload(src))
                let v :=
                    or(
                        shl(8, and(w, 0x00ff00ff00ff00ff00ff00ff00ff00ff)),
                        and(shr(8, w), 0x00ff00ff00ff00ff00ff00ff00ff00ff)
                    )
                v := or(
                    shl(16, and(v, 0x0000ffff0000ffff0000ffff0000ffff)),
                    and(shr(16, v), 0x0000ffff0000ffff0000ffff0000ffff)
                )
                v := or(
                    shl(32, and(v, 0x00000000ffffffff00000000ffffffff)),
                    and(shr(32, v), 0x00000000ffffffff00000000ffffffff)
                )
                v := or(shl(64, and(v, 0x0000000000000000ffffffffffffffff)), shr(64, v))
                mstore(dst, v)
            }
        }
    }

    function basePow(uint256 x, uint256 exponent) internal pure returns (uint256 out) {
        require(x < P, "base exponent");
        assembly ("memory-safe") {
            out := 1
            for {} exponent { exponent := shr(1, exponent) } {
                if and(exponent, 1) { out := mulmod(out, x, 0x7f000001) }
                x := mulmod(x, x, 0x7f000001)
            }
        }
    }

    function powers(uint256 x, uint256 n) internal pure returns (uint256[] memory r) {
        r = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            r[i] = x;
            x = mul(x, x);
        }
    }

    function slice(uint256[] memory a, uint256 start, uint256 n) internal pure returns (uint256[] memory b) {
        require(start + n <= a.length, "slice");
        b = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            b[i] = a[start + i];
        }
    }
}

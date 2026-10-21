// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// Execute consecutive arithmetic/equality instructions of an authenticated
/// KVE2 program. Proof inputs and register operands retain bounds checks.
library VerifierArithmetic {
    function run(
        bytes memory program,
        bytes memory packet,
        uint256[] memory regs,
        uint256 at,
        uint256 fields,
        uint256 hashes
    ) internal pure returns (uint256 next) {
        bytes4 badProgram = bytes4(keccak256("InvalidProgram()"));
        bytes4 assertion = bytes4(keccak256("AssertionFailed(uint256,uint256,uint256)"));
        assembly ("memory-safe") {
            function fail(selector) {
                mstore(0, selector)
                revert(0, 4)
            }
            function get(id, packetPtr, registers, nf, nh, err) -> value {
                let index := and(id, 0x0fffffff)
                switch iszero(and(id, 0x80000000))
                case 0 { value := and(id, 0x7fffffff) }
                default {
                    switch iszero(and(id, 0x40000000))
                    case 0 {
                        if iszero(lt(index, nf)) { fail(err) }
                        let w := mload(add(add(packetPtr, 70), mul(4, index)))
                        value := or(or(byte(0, w), shl(8, byte(1, w))), or(shl(16, byte(2, w)), shl(24, byte(3, w))))
                    }
                    default {
                        switch iszero(and(id, 0x20000000))
                        case 0 {
                            if iszero(lt(add(index, 3), nf)) { fail(err) }
                            let w := shr(128, mload(add(add(packetPtr, 70), mul(4, index))))
                            value := or(
                                shl(8, and(w, 0x00ff00ff00ff00ff00ff00ff00ff00ff)),
                                and(shr(8, w), 0x00ff00ff00ff00ff00ff00ff00ff00ff)
                            )
                            value := or(
                                shl(16, and(value, 0x0000ffff0000ffff0000ffff0000ffff)),
                                and(shr(16, value), 0x0000ffff0000ffff0000ffff0000ffff)
                            )
                            value := or(
                                shl(32, and(value, 0x00000000ffffffff00000000ffffffff)),
                                and(shr(32, value), 0x00000000ffffffff00000000ffffffff)
                            )
                            value := or(shl(64, and(value, 0x0000000000000000ffffffffffffffff)), shr(64, value))
                        }
                        default {
                            switch iszero(and(id, 0x10000000))
                            case 0 {
                                if iszero(lt(index, nh)) { fail(err) }
                                value := mload(add(add(add(packetPtr, 70), mul(4, nf)), mul(32, index)))
                            }
                            default {
                                if iszero(lt(id, mload(registers))) { fail(err) }
                                value := mload(add(add(registers, 32), mul(id, 32)))
                            }
                        }
                    }
                }
            }
            function plus(a, b) -> c {
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
            function minus(a, b) -> c {
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
            function times(a, b) -> c {
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
            function scale(a, b) -> c {
                let p := 0x7f000001
                let m := 0xffffffff
                c := or(
                    or(mod(mul(and(a, m), b), p), shl(32, mod(mul(and(shr(32, a), m), b), p))),
                    or(shl(64, mod(mul(and(shr(64, a), m), b), p)), shl(96, mod(mul(and(shr(96, a), m), b), p)))
                )
            }
            let length := mload(program)
            let start := add(program, 32)
            next := at
            for {} lt(next, length) {} {
                let ptr := add(start, next)
                let code := byte(0, mload(ptr))
                if iszero(
                    or(
                        or(eq(code, 4), or(eq(code, 5), eq(code, 6))),
                        or(eq(code, 8), and(iszero(lt(code, 20)), lt(code, 24)))
                    )
                ) { break }
                let size := 13
                if eq(code, 8) { size := 9 }
                if gt(add(next, size), length) { fail(badProgram) }
                let dst := shr(224, mload(add(ptr, 1)))
                let first := 5
                if eq(code, 8) { first := 1 }
                let a := get(shr(224, mload(add(ptr, first))), packet, regs, fields, hashes, badProgram)
                let b := get(shr(224, mload(add(ptr, add(first, 4)))), packet, regs, fields, hashes, badProgram)
                let result := 0
                switch code
                case 4 { result := plus(a, b) }
                case 5 { result := minus(a, b) }
                case 6 { result := times(a, b) }
                case 8 {
                    if iszero(eq(a, b)) {
                        let err := mload(0x40)
                        mstore(err, assertion)
                        mstore(add(err, 4), next)
                        mstore(add(err, 36), a)
                        mstore(add(err, 68), b)
                        revert(err, 100)
                    }
                }
                case 20 { result := addmod(a, b, 0x7f000001) }
                case 21 { result := addmod(a, sub(0x7f000001, b), 0x7f000001) }
                case 22 { result := mulmod(a, b, 0x7f000001) }
                case 23 { result := scale(a, b) }
                if iszero(eq(code, 8)) {
                    if iszero(lt(dst, mload(regs))) { fail(badProgram) }
                    mstore(add(add(regs, 32), mul(dst, 32)), result)
                }
                next := add(next, size)
            }
        }
    }
}

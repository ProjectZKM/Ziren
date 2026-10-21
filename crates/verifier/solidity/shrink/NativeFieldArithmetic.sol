// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// Canonical KoalaBear E4 operands only: four lanes < p, upper 128 bits zero.
/// The approved AOT program's type analysis proves these preconditions; the
/// complete entrypoint checks wire fields before any native kernel executes.
library NativeFieldArithmetic {
    /// Quadratic tower with radix B=2^128. MULMOD modulo B^2-3
    /// computes each pair product (u0+u1*X)(v0+v1*X), X^2=3,
    /// as two exact integer lanes. Canonical coefficients and sums <2p
    /// bound every lane below 2^67, far below B. Neither carries nor a
    /// reduction of the encoded result modulo B^2-3 can mix lanes.
    /// Three such products give AC, BD and AD+BC by Karatsuba; the latter
    /// subtraction is nonnegative in each lane. Only final reductions use p.
    function mul(uint256 left,uint256 right) internal pure returns(uint256 out) {
        assembly("memory-safe") {
            function times(packedLeft,packedRight) -> result {
            let mask:=0xffffffff000000000000000000000000ffffffff
            packedLeft:=or(packedLeft,shl(64,packedLeft))
            packedRight:=or(packedRight,shl(64,packedRight))
            let a:=and(packedLeft,mask)
            let b:=and(shr(32,packedLeft),mask)
            let c:=and(packedRight,mask)
            let d:=and(shr(32,packedRight),mask)
            let modulus:=not(2)
            let ac:=mulmod(a,c,modulus)
            let bd:=mulmod(b,d,modulus)
            let cross:=sub(sub(mulmod(add(a,b),add(c,d),modulus),ac),bd)
            let wide:=0xffffffffffffffffffffffffffffffff
            let p:=0x7f000001
            result:=or(or(mod(add(and(ac,wide),mul(3,shr(128,bd))),p),shl(32,mod(and(cross,wide),p))),or(shl(64,mod(add(shr(128,ac),and(bd,wide)),p)),shl(96,mod(shr(128,cross),p))))
            }
            out:=times(left,right)
        }
    }
    function add(uint256 left,uint256 right) internal pure returns(uint256 out) {
        assembly("memory-safe") {
            function plus(a,b) -> c {
                // Each sum is <2p<2^32: the packed addition has no lane carry.
                let s:=add(a,b)
                // s_i+(2^31-p) < 2^31+p < 2^32, so the biased addition
                // cannot carry. Its high bit is set exactly when s_i >= p.
                let flags:=and(add(s,0x00ffffff00ffffff00ffffff00ffffff),0x80000000800000008000000080000000)
                c:=sub(s,mul(shr(31,flags),0x7f000001))
            }
            out:=plus(left,right)
        }
    }

    function sub(uint256 left,uint256 right) internal pure returns(uint256 out) {
        assembly("memory-safe") {
            function minus(a,b) -> c {
                // a_i+p-b_i is in [1,2p-1], without a carry or a borrow.
                let s:=sub(add(a,0x7f0000017f0000017f0000017f000001),b)
                let flags:=and(add(s,0x00ffffff00ffffff00ffffff00ffffff),0x80000000800000008000000080000000)
                c:=sub(s,mul(shr(31,flags),0x7f000001))
            }
            out:=minus(left,right)
        }
    }

}

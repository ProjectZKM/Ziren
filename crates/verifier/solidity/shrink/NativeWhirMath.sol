// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {KoalaBear as F} from "./KoalaBear.sol";

/// Packed-only kernels for the approved first-fold geometry. Callers retain
/// leaf shape, full canonicality, Merkle and transcript checks before folding.
library NativeWhirMath {
    error InvalidNativeWhirMath();

    /// Consumes a fresh decoded query row. No caller may reuse the row after
    /// this operation; proof coefficients and persistent points stay separate.
    function mleDiscard(uint256[] memory row,uint256[] memory point) internal pure returns(uint256) {
        if(point.length>=256 || row.length!=1<<point.length) revert InvalidNativeWhirMath();
        uint256 n=row.length;
        unchecked {
            for(uint256 j;j<point.length;++j){
                n>>=1;uint256 x=point[j];
                for(uint256 i;i<n;++i){
                    uint256 a;uint256 b;
                    assembly("memory-safe") {
                        let ptr:=add(add(row,32),mul(i,64))
                        a:=mload(ptr) b:=mload(add(ptr,32))
                    }
                    uint256 value=F.add(a,F.mul(x,F.sub(b,a)));
                    assembly("memory-safe"){mstore(add(add(row,32),mul(i,32)),value)}
                }
            }
        }
        return row[0];
    }

    /// Product of 1-y+y*x for base-field x and extension-field y. All
    /// coordinates are canonical, as established when the points are built.
    function monomialFactor(uint256[] memory point,uint256[] memory randomness,uint256 start,uint256 n)
        internal pure returns(uint256 result) {
        if(n>point.length || start>randomness.length || n>randomness.length-start) revert InvalidNativeWhirMath();
        result=1;
        unchecked {
            for(uint256 i;i<n;++i){
                uint256 x=point[i];uint256 y=randomness[start+i];uint256 term;
                assembly("memory-safe") {
                    let p:=0x7f000001
                    // x=0 must use p-1 rather than an unsigned underflow.
                    let scalar:=addmod(x,sub(p,1),p)
                    let mask:=0xffffffff
                    term:=or(or(addmod(mul(and(y,mask),scalar),1,p),shl(32,mulmod(and(shr(32,y),mask),scalar,p))),or(shl(64,mulmod(and(shr(64,y),mask),scalar,p)),shl(96,mulmod(shr(96,y),scalar,p))))
                }
                result=F.mul(result,term);
            }
        }
    }

    function firstWeights(uint256[] memory lambda,uint256 r) internal pure returns(uint256[] memory weights) {
        if(lambda.length>32767) revert InvalidNativeWhirMath();
        weights=new uint256[](4*lambda.length);
        for(uint256 row;row<lambda.length;++row){
            uint256 b=F.mul(lambda[row],r);uint256 a=F.sub(lambda[row],b);
            assembly("memory-safe") {
                let mask:=0xffffffff
                let dst:=add(add(weights,32),mul(row,128))
                mstore(dst,or(and(a,mask),or(shl(80,and(shr(32,a),mask)),shl(160,and(shr(64,a),mask)))))
                mstore(add(dst,32),shr(96,a))
                mstore(add(dst,64),or(and(b,mask),or(shl(80,and(shr(32,b),mask)),shl(160,and(shr(64,b),mask)))))
                mstore(add(dst,96),shr(96,b))
            }
        }
    }

    /// LE32 canonical base inputs and canonical E4 weights prepared above.
    /// At most 65534 terms: each lane sum < 65534*p^2 < 2^78, strictly below
    /// the radix 2^80. The highest packed lane therefore remains below 2^238.
    function firstDot(bytes memory source,uint256 offset,uint256[] memory weights) internal pure returns(uint256 result) {
        uint256 n=weights.length/2;
        if(weights.length%2!=0 || n>65534 || offset>source.length || n>(source.length-offset)/4) revert InvalidNativeWhirMath();
        assembly("memory-safe") {
            let src:=add(add(source,32),offset)
            let ptr:=add(weights,32)
            let end:=add(ptr,mul(n,64))
            let acc:=0
            let last:=0
            let fullEnd:=sub(end,mul(mod(n,4),64))
            for {} lt(ptr,fullEnd) {ptr:=add(ptr,256) src:=add(src,16)} {
                let w:=mload(src)
                let evenBytes:=0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff
                w:=or(shl(8,and(w,evenBytes)),and(shr(8,w),evenBytes))
                let evenPairs:=0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff
                w:=or(shl(16,and(w,evenPairs)),and(shr(16,w),evenPairs))
                {let x:=shr(224,w)
                acc:=add(acc,mul(mload(add(ptr,0)),x))
                last:=add(last,mul(mload(add(ptr,32)),x))}
                {let x:=and(shr(192,w),0xffffffff)
                acc:=add(acc,mul(mload(add(ptr,64)),x))
                last:=add(last,mul(mload(add(ptr,96)),x))}
                {let x:=and(shr(160,w),0xffffffff)
                acc:=add(acc,mul(mload(add(ptr,128)),x))
                last:=add(last,mul(mload(add(ptr,160)),x))}
                {let x:=and(shr(128,w),0xffffffff)
                acc:=add(acc,mul(mload(add(ptr,192)),x))
                last:=add(last,mul(mload(add(ptr,224)),x))}
            }
            for {} lt(ptr,end) {ptr:=add(ptr,64) src:=add(src,4)} {
                let w:=mload(src)
                let x:=or(or(byte(0,w),shl(8,byte(1,w))),or(shl(16,byte(2,w)),shl(24,byte(3,w))))
                acc:=add(acc,mul(mload(ptr),x))
                last:=add(last,mul(mload(add(ptr,32)),x))
            }
            let mask:=0xffffffffffffffffffff
            let p:=0x7f000001
            result:=or(or(mod(and(acc,mask),p),shl(32,mod(and(shr(80,acc),mask),p))),or(shl(64,mod(shr(160,acc),p)),shl(96,mod(last,p))))
        }
    }

    function basePowers(uint256 x,uint256 n) internal pure returns(uint256[] memory result) {
        if(x>=0x7f000001) revert InvalidNativeWhirMath();
        result=new uint256[](n);
        assembly("memory-safe") {
            let at:=add(result,32)
            let end:=add(at,mul(n,32))
            for {} lt(at,end) {at:=add(at,32)} {mstore(at,x) x:=mulmod(x,x,0x7f000001)}
        }
    }
}

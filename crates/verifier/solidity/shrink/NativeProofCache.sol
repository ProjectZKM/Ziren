// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// Private native-call cache, populated from the entry's validated raw proof.
/// Range descriptors are trusted generated constants: BE32 first field, BE16
/// number of consecutive E4 operands (four fields each). Values occupy 16 bytes
/// in native big-endian packed form. The original packet is never overwritten.
library NativeProofCache {
    error InvalidProofCache();

    function populate(bytes memory context,uint256 packetOffset,uint256 fields,bytes memory ranges) internal pure {
        if(packetOffset<32 || packetOffset>context.length || ranges.length%6!=0) revert InvalidProofCache();
        uint256 packetLength;
        assembly("memory-safe"){packetLength:=mload(add(context,packetOffset))}
        if(packetLength>context.length-packetOffset || packetLength<38 || fields>(packetLength-38)/4
            || context.length-packetOffset-packetLength<16) revert InvalidProofCache();
        bytes4 invalidCache=InvalidProofCache.selector;
        assembly("memory-safe") {
            function reversePair(w) -> x {
                // Reverse bytes inside both 128-bit halves independently.
                let mask:=0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff
                x:=or(shl(8,and(w,mask)),and(shr(8,w),mask))
                mask:=0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff
                x:=or(shl(16,and(x,mask)),and(shr(16,x),mask))
                mask:=0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff
                x:=or(shl(32,and(x,mask)),and(shr(32,x),mask))
                mask:=0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff
                x:=or(shl(64,and(x,mask)),and(shr(64,x),mask))
            }
            let proof:=add(add(context,32),packetOffset)
            let dst:=add(proof,packetLength)
            let cacheEnd:=sub(add(add(context,32),mload(context)),16)
            let at:=add(ranges,32)
            let end:=add(at,mload(ranges))
            for {} lt(at,end) {at:=add(at,6)} {
                let descriptor:=mload(at)
                let first:=shr(224,descriptor)
                let count:=and(shr(208,descriptor),0xffff)
                if or(or(iszero(count),gt(first,fields)),gt(count,div(sub(fields,first),4))) {
                    mstore(0,invalidCache) revert(0,4)
                }
                if gt(add(dst,mul(count,16)),cacheEnd) {mstore(0,invalidCache) revert(0,4)}
                let src:=add(add(proof,38),mul(first,4))
                let pairEnd:=add(dst,mul(and(count,not(1)),16))
                let bulkEnd:=add(dst,mul(and(count,not(7)),16))
                for {} lt(dst,bulkEnd) {dst:=add(dst,128) src:=add(src,128)} {
                    mstore(dst,reversePair(mload(src)))
                    mstore(add(dst,32),reversePair(mload(add(src,32))))
                    mstore(add(dst,64),reversePair(mload(add(src,64))))
                    mstore(add(dst,96),reversePair(mload(add(src,96))))
                }
                for {} lt(dst,pairEnd) {dst:=add(dst,32) src:=add(src,32)} {
                    mstore(dst,reversePair(mload(src)))
                }
                if and(count,1) {
                    mstore(dst,and(reversePair(mload(src)),not(0xffffffffffffffffffffffffffffffff)))
                    dst:=add(dst,16)
                }
            }
            if iszero(eq(dst,cacheEnd)) {mstore(0,invalidCache) revert(0,4)}
        }
    }
}

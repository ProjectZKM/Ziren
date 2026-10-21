// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// Canonical little-endian wire fields, independent of extension arithmetic.
library KoalaBearWire {
    error InvalidFieldBuffer();

    /// p=0x7f000001: a field is invalid iff its highest byte exceeds 0x7f,
    /// or that byte is 0x7f and any lower byte is nonzero. Check eight fields
    /// in one EVM word without byte reversal or carries between 32-bit lanes.
    function validateFields(bytes calldata packet,uint256 offset,uint256 count) internal pure {
        if(offset>packet.length || count>(packet.length-offset)/4) revert InvalidFieldBuffer();
        bytes4 invalidField=InvalidFieldBuffer.selector;
        assembly("memory-safe") {
            let ones:=0x0000000100000001000000010000000100000001000000010000000100000001
            let bytesMask:=mul(ones,255)
            let signMask:=shl(7,ones)
            let carryMask:=shl(8,ones)
            let at:=add(packet.offset,offset)
            let bulkEnd:=add(at,mul(and(count,not(7)),4))
            for {} lt(at,bulkEnd) {at:=add(at,32)} {
                let w:=calldataload(at)
                // In a big-endian EVM word each LE32 field's most significant
                // byte is the least significant byte of its 32-bit lane.
                let flagged:=and(or(w,add(and(w,bytesMask),ones)),signMask)
                if flagged {
                    if and(w,signMask) {mstore(0,invalidField) revert(0,4)}
                    // Lower bytes matter only for a highest byte of 0x7f.
                    let low:=and(or(or(shr(8,w),shr(16,w)),shr(24,w)),bytesMask)
                    // low+255 carries into bit 8 iff low!=0, without crossing lanes.
                    let nonzero:=and(add(low,bytesMask),carryMask)
                    if and(shl(1,flagged),nonzero) {mstore(0,invalidField) revert(0,4)}
                }
            }
            let end:=add(at,mul(and(count,7),4))
            for {} lt(at,end) {at:=add(at,4)} {
                let w:=calldataload(at)
                let x:=or(or(byte(0,w),shl(8,byte(1,w))),or(shl(16,byte(2,w)),shl(24,byte(3,w))))
                if iszero(lt(x,0x7f000001)) {mstore(0,invalidField) revert(0,4)}
            }
        }
    }

    /// Memory equivalent used for bounded WHIR leaf views; identical predicate.
    function validateMemoryFields(bytes memory packet,uint256 offset,uint256 count) internal pure {
        if(offset>packet.length || count>(packet.length-offset)/4) revert InvalidFieldBuffer();
        bytes4 invalidField=InvalidFieldBuffer.selector;
        assembly("memory-safe") {
            function checkMemory(at,length,errorSelector) {
            let ones:=0x0000000100000001000000010000000100000001000000010000000100000001
            let bytesMask:=mul(ones,255)
            let signMask:=shl(7,ones)
            let carryMask:=shl(8,ones)
            let bulkEnd:=add(at,mul(and(length,not(7)),4))
            for {} lt(at,bulkEnd) {at:=add(at,32)} {
                let w:=mload(at)
                // In a big-endian EVM word each LE32 field's most significant
                // byte is the least significant byte of its 32-bit lane.
                let flagged:=and(or(w,add(and(w,bytesMask),ones)),signMask)
                if flagged {
                    if and(w,signMask) {mstore(0,errorSelector) revert(0,4)}
                    let low:=and(or(or(shr(8,w),shr(16,w)),shr(24,w)),bytesMask)
                    let nonzero:=and(add(low,bytesMask),carryMask)
                    if and(shl(1,flagged),nonzero) {mstore(0,errorSelector) revert(0,4)}
                }
            }
            let end:=add(at,mul(and(length,7),4))
            for {} lt(at,end) {at:=add(at,4)} {
                let w:=mload(at)
                let x:=or(or(byte(0,w),shl(8,byte(1,w))),or(shl(16,byte(2,w)),shl(24,byte(3,w))))
                if iszero(lt(x,0x7f000001)) {mstore(0,errorSelector) revert(0,4)}
            }
            }
            checkMemory(add(add(packet,32),offset),count,invalidField)
        }
    }
}

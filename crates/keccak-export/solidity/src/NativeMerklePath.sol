// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

library NativeMerklePath {
    /// Caller must validate height, index and the complete height*32-byte memory
    /// range. Every full sibling word is read exactly once; no memory escapes.
    function walk(bytes32 hash,uint256 index,uint256 height,uint256 pathPointer) internal pure returns(bytes32) {
        assembly("memory-safe") {
            let end:=add(pathPointer,mul(height,32))
            for {} lt(pathPointer,end) {pathPointer:=add(pathPointer,32)} {
                let sibling:=mload(pathPointer)
                switch and(index,1)
                case 0 {mstore(0,hash) mstore(32,sibling)}
                default {mstore(0,sibling) mstore(32,hash)}
                hash:=keccak256(0,64)
                index:=shr(1,index)
            }
        }
        return hash;
    }

    /// Same full-word path computation over a caller-bounded calldata range.
    function walkCalldata(bytes32 hash,uint256 index,uint256 height,uint256 pathPointer) internal pure returns(bytes32) {
        assembly("memory-safe") {
            let end:=add(pathPointer,mul(height,32))
            for {} lt(pathPointer,end) {pathPointer:=add(pathPointer,32)} {
                let sibling:=calldataload(pathPointer)
                switch and(index,1)
                case 0 {mstore(0,hash) mstore(32,sibling)}
                default {mstore(0,sibling) mstore(32,hash)}
                hash:=keccak256(0,64)
                index:=shr(1,index)
            }
        }
        return hash;
    }
}

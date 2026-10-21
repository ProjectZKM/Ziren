// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// Lossless transport for the fixed hash section of an approved raw packet.
/// Header/field bytes retain their raw offsets. Mode 2 appends BE16 commands:
/// high bit set: copy the following (command & 32767) literal bytes32 words;
/// high bit clear: copy one previously reconstructed hash at that index.
/// Mode 3 first encodes fields as BE16 runs: high bit set copies count literal
/// LE32 fields; high bit clear emits count zero fields. Hash commands are
/// unchanged. Both transports reconstruct the complete original raw packet.
library HashDictionaryWire {
    error InvalidHashDictionary();

    function decodeInto(bytes calldata encoded, bytes memory context, uint256 packetOffset, uint256 fields, uint256 hashes)
        internal pure
    {
        uint256 prefix = 38 + 4 * fields;
        bool zeroRuns=encoded.length>=38 && encoded[5]==0x03;
        if (hashes > 32768 || encoded.length < (zeroRuns?38:prefix) || packetOffset > context.length
            || prefix + 32 * hashes > context.length - packetOffset) revert InvalidHashDictionary();
        bytes4 dictionaryError = InvalidHashDictionary.selector;
        assembly ("memory-safe") {
            let dst := add(add(context, 32), packetOffset)
            let start := add(dst, prefix)
            let at := add(encoded.offset, prefix)
            let end := add(encoded.offset, encoded.length)
            switch zeroRuns
            case 0 {calldatacopy(dst, encoded.offset, prefix)}
            default {
                calldatacopy(dst,encoded.offset,38)
                at:=add(encoded.offset,38)
                for{let done:=0}lt(done,fields){}{
                    if gt(add(at,2),end){mstore(0,dictionaryError) revert(0,4)}
                    let command:=shr(240,calldataload(at))
                    at:=add(at,2)
                    let count:=and(command,0x7fff)
                    if or(iszero(count),gt(count,sub(fields,done))){mstore(0,dictionaryError) revert(0,4)}
                    let size:=mul(count,4)
                    let target:=add(add(dst,38),mul(done,4))
                    switch and(command,0x8000)
                    case 0 {
                        // Out-of-calldata copies explicitly zero owned memory,
                        // including buffers which held earlier scratch values.
                        calldatacopy(target,calldatasize(),size)
                    }
                    default {
                        if gt(size,sub(end,at)){mstore(0,dictionaryError) revert(0,4)}
                        calldatacopy(target,at,size)
                        at:=add(at,size)
                    }
                    done:=add(done,count)
                }
            }
            mstore8(add(dst, 5), 0) // Restore the original raw-mode header.
            for { let i := 0 } lt(i, hashes) {} {
                if gt(add(at, 2), end) {mstore(0, dictionaryError) revert(0, 4)}
                let command := shr(240, calldataload(at))
                at := add(at, 2)
                switch and(command, 0x8000)
                case 0 {
                    if iszero(lt(command, i)) {mstore(0, dictionaryError) revert(0, 4)}
                    mstore(add(start, mul(i, 32)), mload(add(start, mul(command, 32))))
                    i := add(i, 1)
                }
                default {
                    let count := and(command, 0x7fff)
                    let size := mul(count, 32)
                    if or(or(iszero(count), gt(count, sub(hashes, i))), gt(size, sub(end, at))) {
                        mstore(0, dictionaryError) revert(0, 4)
                    }
                    calldatacopy(add(start, mul(i, 32)), at, size)
                    at := add(at, size)
                    i := add(i, count)
                }
            }
            if iszero(eq(at, end)) {mstore(0, dictionaryError) revert(0, 4)}
        }
    }
}

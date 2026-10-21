// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Transport reader only. Its result is NOT proof verification.
/// @dev Pins a schema supplied by the verifier developer, never by a prover.
/// Expands the transmitted field stream and Merkle-node references and hashes
/// their concatenation for cross-language parity. A full verifier must also
/// reconstruct omitted sumcheck values, run Fiat-Shamir, authenticate queries,
/// check every polynomial identity and bind trusted keys/public inputs.
contract KeccakWireReader {
    error InvalidWire();
    bytes32 public immutable profileId;
    uint256 public immutable fieldCount;
    uint256 public immutable digestReferences;
    uint8 public immutable mode;
    // Each trusted range packs field start in low 32 bits, count in high 32.
    uint64[] private leafRanges;

    constructor(bytes32 id, uint8 encodingMode, uint256 fields, uint256 refs, uint64[] memory ranges) {
        if (encodingMode > 2 || fields > type(uint32).max || refs >= 65536 || ranges.length >= 65536) {
            revert InvalidWire();
        }
        for (uint256 i; i < ranges.length; ++i) {
            if (uint256(uint32(ranges[i])) + uint256(ranges[i] >> 32) > fields) revert InvalidWire();
        }
        profileId = id;
        mode = encodingMode;
        fieldCount = fields;
        digestReferences = refs;
        leafRanges = ranges;
    }

    function _u16(bytes calldata p, uint256 at) private pure returns (uint256) {
        if (at + 2 > p.length) revert InvalidWire();
        return uint8(p[at]) | (uint256(uint8(p[at + 1])) << 8);
    }

    /// @return digest keccak256(canonical field bytes || expanded hash stream).
    /// The native strict decoder additionally enforces the encoder's unique
    /// choice/order of DAG nodes. This reader checks bounded syntax and hashing;
    /// equivalent DAG representations can produce the same stream digest.
    function readWitnessDigest(bytes calldata p) external view returns (bytes32 digest) {
        uint256 fields = fieldCount;
        uint256 refs = digestReferences;
        uint256 fieldBytes = fields * 4;
        uint256 cursor = 38 + fieldBytes;
        uint256 maximum = cursor + 42 * refs + 40 * leafRanges.length + 2;
        if (p.length < cursor || p.length > maximum) revert InvalidWire();
        bytes32 id;
        bytes4 magic;
        assembly ("memory-safe") {
            magic := calldataload(p.offset)
            id := calldataload(add(p.offset, 6))
        }
        if (magic != 0x5a4b4554 || uint8(p[4]) != 1 || uint8(p[5]) != mode || id != profileId) revert InvalidWire();
        // Native LE32 canonicality. An unchecked/noncanonical residue must
        // never enter a field operation or change the transcript encoding.
        bool canonical = true;
        assembly ("memory-safe") {
            let end := add(p.offset, cursor)
            for { let i := add(p.offset, 38) } lt(i, end) { i := add(i, 4) } {
                let word := calldataload(i)
                let x :=
                    or(or(byte(0, word), shl(8, byte(1, word))), or(shl(16, byte(2, word)), shl(24, byte(3, word))))
                if iszero(lt(x, 0x7f000001)) {
                    canonical := 0
                    break
                }
            }
        }
        if (!canonical) revert InvalidWire();
        bytes memory stream = new bytes(fieldBytes + 32 * refs);
        assembly ("memory-safe") { calldatacopy(add(stream, 32), add(p.offset, 38), fieldBytes) }
        if (mode == 0) {
            if (p.length != cursor + 32 * refs) revert InvalidWire();
            assembly ("memory-safe") {
                calldatacopy(add(add(stream, 32), fieldBytes), add(p.offset, cursor), mul(refs, 32))
            }
        } else {
            uint256 count = _u16(p, cursor);
            cursor += 2;
            if (count > refs + leafRanges.length) revert InvalidWire();
            bytes32[] memory nodes = new bytes32[](count);
            for (uint256 i; i < count; ++i) {
                uint256 tag;
                if (mode == 2) {
                    if (cursor == p.length) revert InvalidWire();
                    tag = uint8(p[cursor++]);
                }
                bytes32 node;
                if (tag == 0) {
                    if (cursor + 32 > p.length) revert InvalidWire();
                    assembly ("memory-safe") { node := calldataload(add(p.offset, cursor)) }
                    cursor += 32;
                    if (mode == 1 && i > 0 && node <= nodes[i - 1]) revert InvalidWire();
                } else if (tag == 1) {
                    uint256 leaf = _u16(p, cursor);
                    cursor += 2;
                    if (leaf >= leafRanges.length) revert InvalidWire();
                    uint64 range = leafRanges[leaf];
                    uint256 start = 4 * uint256(uint32(range));
                    uint256 length = 4 * uint256(range >> 32);
                    assembly ("memory-safe") { node := keccak256(add(add(stream, 32), start), length) }
                } else if (tag == 2) {
                    uint256 left = _u16(p, cursor);
                    uint256 right = _u16(p, cursor + 2);
                    cursor += 4;
                    if (left >= i || right >= i) revert InvalidWire();
                    bytes32 a = nodes[left];
                    bytes32 b = nodes[right];
                    assembly ("memory-safe") {
                        mstore(0, a)
                        mstore(32, b)
                        node := keccak256(0, 64)
                    }
                } else {
                    revert InvalidWire();
                }
                nodes[i] = node;
            }
            if (p.length != cursor + 2 * refs) revert InvalidWire();
            bool validReferences = true;
            // The exact stream length was checked above. Bounds-check each
            // index before loading a node; the loop cannot read past calldata.
            assembly ("memory-safe") {
                let at := add(p.offset, cursor)
                let dst := add(add(stream, 32), fieldBytes)
                let end := add(dst, mul(refs, 32))
                let base := add(nodes, 32)
                for {} lt(dst, end) {
                    at := add(at, 2)
                    dst := add(dst, 32)
                } {
                    let w := calldataload(at)
                    let index := or(byte(0, w), shl(8, byte(1, w)))
                    if iszero(lt(index, count)) {
                        validReferences := 0
                        break
                    }
                    mstore(dst, mload(add(base, shl(5, index))))
                }
            }
            if (!validReferences) revert InvalidWire();
        }
        return keccak256(stream);
    }
}

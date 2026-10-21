// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {VerifierArithmetic as Arithmetic} from "./VerifierArithmetic.sol";
import {KoalaBearPoseidon2 as Poseidon2} from "./KoalaBearPoseidon2.sol";
import {KoalaBear as F} from "./KoalaBear.sol";
import {KeccakTranscript as T} from "./KeccakTranscript.sol";
import {StackedWhir as W} from "./StackedWhir.sol";

/// Interpreted reference verifier for a separately approved fixed machine
/// program. Arithmetic/AIR/GKR/jagged checks execute here, followed by full
/// stacked WHIR verification. No off-chain validity result is accepted.
/// A program hash MUST be authenticated independently of submitted proofs.
/// This baseline intentionally permits measuring gas beyond mainnet limits.
contract KeccakTerminalVerifier {
    bytes32 public immutable verifierProgramHash;
    error InvalidProgram();
    error InvalidPacket();
    error AssertionFailed(uint256 pc, uint256 actual, uint256 expected);

    struct Reader {
        bytes data;
        uint256 at;
    }

    struct Env {
        bytes packet;
        uint256 fields;
        uint256 hashes;
        uint256[] regs;
        bytes32 outputDigest;
    }

    constructor(bytes32 approvedProgramHash) {
        verifierProgramHash = approvedProgramHash;
    }

    function n(Reader memory r, uint256 count) private pure returns (uint256 value) {
        bytes4 errorSelector = InvalidProgram.selector;
        assembly ("memory-safe") {
            let data := mload(r)
            let at := mload(add(r, 32))
            let end := add(at, count)
            if or(gt(count, 32), or(lt(end, at), gt(end, mload(data)))) {
                mstore(0, errorSelector)
                revert(0, 4)
            }
            value := shr(mul(sub(32, count), 8), mload(add(add(data, 32), at)))
            mstore(add(r, 32), end)
        }
    }

    function field(Env memory e, uint256 index) private pure returns (uint256 value) {
        bytes4 errorSelector = InvalidProgram.selector;
        assembly ("memory-safe") {
            if iszero(lt(index, mload(add(e, 32)))) {
                mstore(0, errorSelector)
                revert(0, 4)
            }
            let w := mload(add(add(mload(e), 70), mul(4, index)))
            value := or(or(byte(0, w), shl(8, byte(1, w))), or(shl(16, byte(2, w)), shl(24, byte(3, w))))
        }
    }

    function get(Env memory e, uint256 id) private pure returns (uint256 value) {
        bytes4 errorSelector = InvalidProgram.selector;
        assembly ("memory-safe") {
            let index := and(id, 0x0fffffff)
            switch iszero(and(id, 0x80000000))
            case 0 { value := and(id, 0x7fffffff) }
            default {
                switch iszero(and(id, 0x40000000))
                case 0 {
                    if iszero(lt(index, mload(add(e, 32)))) {
                        mstore(0, errorSelector)
                        revert(0, 4)
                    }
                    let w := mload(add(add(mload(e), 70), mul(4, index)))
                    value := or(or(byte(0, w), shl(8, byte(1, w))), or(shl(16, byte(2, w)), shl(24, byte(3, w))))
                }
                default {
                    switch iszero(and(id, 0x20000000))
                    case 0 {
                        if iszero(lt(add(index, 3), mload(add(e, 32)))) {
                            mstore(0, errorSelector)
                            revert(0, 4)
                        }
                        let w := shr(128, mload(add(add(mload(e), 70), mul(4, index))))
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
                            if iszero(lt(index, mload(add(e, 64)))) {
                                mstore(0, errorSelector)
                                revert(0, 4)
                            }
                            value := mload(add(add(add(mload(e), 70), mul(4, mload(add(e, 32)))), mul(32, index)))
                        }
                        default {
                            let regs := mload(add(e, 96))
                            if iszero(lt(id, mload(regs))) {
                                mstore(0, errorSelector)
                                revert(0, 4)
                            }
                            value := mload(add(add(regs, 32), mul(id, 32)))
                        }
                    }
                }
            }
        }
    }

    function arg(Reader memory r, Env memory e) private pure returns (uint256) {
        return get(e, n(r, 4));
    }

    function vector(Reader memory r, Env memory e, uint256 countBytes) private pure returns (uint256[] memory a) {
        uint256 length = n(r, countBytes);
        uint256 kind = n(r, 1);
        a = new uint256[](length);
        if (kind == 0) {
            for (uint256 i; i < length; ++i) {
                a[i] = arg(r, e);
            }
        } else if (kind == 1 || kind == 2) {
            uint256 first = n(r, 4);
            uint256 stride = kind == 1 ? 4 : 16;
            if (first + length * (stride / 4) > e.fields) revert InvalidProgram();
            bytes memory packet = e.packet;
            assembly ("memory-safe") {
                let src := add(add(packet, 70), mul(first, 4))
                let dst := add(a, 32)
                let end := add(dst, mul(length, 32))
                for {} lt(dst, end) {
                    dst := add(dst, 32)
                    src := add(src, stride)
                } {
                    let w := mload(src)
                    switch kind
                    case 1 {
                        mstore(
                            dst,
                            or(or(byte(0, w), shl(8, byte(1, w))), or(shl(16, byte(2, w)), shl(24, byte(3, w))))
                        )
                    }
                    default {
                        w := shr(128, w)
                        let value :=
                            or(
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
                        mstore(dst, value)
                    }
                }
            }
        } else {
            revert InvalidProgram();
        }
    }

    function hashes(Reader memory r, Env memory e) private pure returns (bytes32[] memory a) {
        uint256 length = n(r, 1);
        if (n(r, 1) != 0) revert InvalidProgram();
        a = new bytes32[](length);
        for (uint256 i; i < length; ++i) {
            a[i] = bytes32(arg(r, e));
        }
    }

    function polys(Reader memory r, Env memory e) private pure returns (uint256[][] memory a) {
        uint256 length = n(r, 1);
        a = new uint256[][](length);
        for (uint256 i; i < length; ++i) {
            a[i] = vector(r, e, 1);
        }
    }

    function whir(Reader memory r, Env memory e, T.State memory t) private pure {
        uint256 lengthBytes = n(r, 4);
        uint256 end = r.at + lengthBytes;
        W.Config memory c;
        c.n = n(r, 1);
        c.startingRate = n(r, 1);
        c.batchPow = n(r, 1);
        c.finalQueries = n(r, 2);
        c.finalPow = n(r, 1);
        uint256 length = n(r, 1);
        c.rounds = new W.Round[](length);
        for (uint256 i; i < length; ++i) {
            W.Round memory v;
            v.fold = n(r, 1);
            v.rate = n(r, 1);
            v.queries = n(r, 2);
            v.ood = n(r, 1);
            v.queryPow = n(r, 1);
            uint256 count = n(r, 1);
            v.foldPow = new uint256[](count);
            for (uint256 j; j < count; ++j) {
                v.foldPow[j] = n(r, 1);
            }
            c.rounds[i] = v;
        }
        bytes32[] memory roots = hashes(r, e);
        length = n(r, 1);
        uint256[] memory stripes = new uint256[](length);
        for (uint256 i; i < length; ++i) {
            stripes[i] = n(r, 2);
        }
        uint256[] memory point = vector(r, e, 1);
        W.Proof memory p;
        length = n(r, 1);
        p.batch = new uint256[][](length);
        for (uint256 i; i < length; ++i) {
            p.batch[i] = vector(r, e, 2);
        }
        p.batchPow = arg(r, e);
        length = n(r, 1);
        p.roundPolys = new uint256[][][](length);
        for (uint256 i; i < length; ++i) {
            p.roundPolys[i] = polys(r, e);
        }
        length = n(r, 1);
        p.roundOod = new uint256[][](length);
        for (uint256 i; i < length; ++i) {
            p.roundOod[i] = vector(r, e, 1);
        }
        p.roots = hashes(r, e);
        length = n(r, 1);
        p.openings = new W.Leaf[][](length);
        for (uint256 i; i < length; ++i) {
            uint256 count = n(r, 2);
            p.openings[i] = new W.Leaf[](count);
            for (uint256 j; j < count; ++j) {
                W.Leaf memory leaf;
                leaf.rows = n(r, 2);
                uint256 first;
                for (uint256 row; row < leaf.rows; ++row) {
                    uint256 width = n(r, 2);
                    if (n(r, 1) != 1) revert InvalidProgram();
                    uint256 index = n(r, 4);
                    if (row == 0) {
                        first = index;
                        leaf.width = width;
                    } else if (width != leaf.width || index != first + row * width) {
                        revert InvalidProgram();
                    }
                }
                if (leaf.rows == 0 || first + leaf.rows * leaf.width > e.fields) revert InvalidProgram();
                leaf.source = e.packet;
                leaf.offset = 38 + 4 * first;
                leaf.path = hashes(r, e);
                p.openings[i][j] = leaf;
            }
        }
        p.finalPoly = vector(r, e, 2);
        p.finalPolys = polys(r, e);
        p.foldPow = vector(r, e, 1);
        p.finalPow = arg(r, e);
        if (r.at != end || end != r.data.length) revert InvalidProgram();
        W.verify(p, c, roots, stripes, point, t);
    }

    function verify(bytes calldata approvedProgram, bytes calldata wire, bytes32 expectedOutputDigest)
        external
        view
        returns (bool)
    {
        bytes memory program = approvedProgram;
        if (keccak256(program) != verifierProgramHash) revert InvalidProgram();
        Reader memory r = Reader(program, 0);
        if (n(r, 4) != 0x4b564532) revert InvalidProgram();
        bytes32 profile = bytes32(n(r, 32));
        Env memory e;
        e.packet = wire;
        e.fields = n(r, 4);
        e.hashes = n(r, 4);
        e.regs = new uint256[](n(r, 4));
        e.outputDigest = expectedOutputDigest;
        if (
            wire.length != 38 + 4 * e.fields + 32 * e.hashes || bytes4(wire[:4]) != 0x5a4b4554 || wire[4] != 0x01
                || wire[5] != 0x00 || bytes32(wire[6:38]) != profile
        ) revert InvalidPacket();
        bytes memory packet = e.packet;
        uint256 fieldCount = e.fields;
        bytes4 invalidPacket = InvalidPacket.selector;
        assembly ("memory-safe") {
            let src := add(packet, 70)
            let end := add(src, mul(4, fieldCount))
            for {} lt(src, end) { src := add(src, 4) } {
                let w := mload(src)
                let value := or(or(byte(0, w), shl(8, byte(1, w))), or(shl(16, byte(2, w)), shl(24, byte(3, w))))
                if iszero(lt(value, 0x7f000001)) {
                    mstore(0, invalidPacket)
                    revert(0, 4)
                }
            }
        }
        T.State memory t = T.create();
        while (r.at < r.data.length) {
            uint256 pc = r.at;
            uint256 op = n(r, 1);
            if (op == 255) {
                whir(r, e, t);
                return true;
            }
            if (op == 4 || op == 5 || op == 6 || op == 8 || (op >= 20 && op <= 23)) {
                r.at = Arithmetic.run(program, e.packet, e.regs, pc, e.fields, e.hashes);
                continue;
            }
            uint256 dst;
            if (op == 7 || op == 13 || op == 15 || op == 16 || op == 18) dst = n(r, 4);
            if (op == 7) {
                e.regs[dst] = F.inv(arg(r, e));
            } else if (op == 10) {
                T.observe(t, arg(r, e));
            } else if (op == 11) {
                T.observeE(t, arg(r, e));
            } else if (op == 12) {
                T.observeHash(t, bytes32(arg(r, e)));
            } else if (op == 13) {
                e.regs[dst] = T.sampleE(t);
            } else if (op == 14) {
                uint256 bits = n(r, 1);
                T.grind(t, bits, arg(r, e));
            } else if (op == 15) {
                e.regs[dst] = n(r, 32);
            } else if (op == 16) {
                bytes32 h = keccak256(abi.encodePacked("ziren-keccak-root-felts-v1", bytes32(arg(r, e))));
                for (uint256 i; i < 8; ++i) {
                    uint256 x;
                    uint256 at = 4 * i;
                    assembly ("memory-safe") {
                        x := or(
                            or(byte(at, h), shl(8, byte(add(at, 1), h))),
                            or(shl(16, byte(add(at, 2), h)), shl(24, byte(add(at, 3), h)))
                        )
                    }
                    e.regs[dst + i] = x % F.P;
                }
            } else if (op == 18) {
                uint256 first = n(r, 4);
                uint256 count = n(r, 2);
                uint256[] memory input = new uint256[](count);
                for (uint256 i; i < count; ++i) {
                    input[i] = field(e, first + i);
                }
                uint256[] memory digest = Poseidon2.hash(input, r.data, r.at);
                r.at += 28 * 16 * 4;
                for (uint256 i; i < 8; ++i) {
                    e.regs[dst + i] = digest[i];
                }
            } else if (op == 17) {
                uint256 value = arg(r, e);
                uint256 index = n(r, 1);
                if (index >= 32) revert InvalidProgram();
                if (value != uint8(expectedOutputDigest[index])) {
                    revert AssertionFailed(pc, value, uint8(expectedOutputDigest[index]));
                }
            } else {
                revert InvalidProgram();
            }
        }
        revert InvalidProgram();
    }
}

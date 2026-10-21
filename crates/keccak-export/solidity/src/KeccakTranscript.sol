// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

library KeccakTranscript {
    struct State {
        bytes32 digest;
        bytes payload;
        uint256 pending;
        uint256 wordsLeft;
    }
    error InvalidGrinding();

    function create() internal pure returns (State memory s) {
        s.digest = keccak256("ziren-koalabear-keccak-terminal-v1");
        s.payload = new bytes(164);
    }

    function resume(bytes32 digest, bytes memory buffered, uint256 wordsLeft) internal pure returns (State memory s) {
        require(buffered.length < 100 && wordsLeft <= 8, "transcript shape");
        s.digest = digest;
        s.payload = new bytes(164);
        s.pending = buffered.length;
        s.wordsLeft = wordsLeft;
        for (uint256 i; i < buffered.length; ++i) {
            s.payload[32 + i] = buffered[i];
        }
    }

    function fold(State memory s) private pure {
        bytes memory payload = s.payload;
        bytes32 digest = s.digest;
        uint256 n = s.pending;
        assembly ("memory-safe") {
            mstore(add(payload, 32), digest)
            digest := keccak256(add(payload, 32), add(n, 32))
        }
        s.digest = digest;
        s.pending = 0;
    }

    // The extra 32 bytes in payload reserve space for a whole-word store
    // crossing the logical buffer end. Only [0, pending) is hashed.
    function append(State memory s, uint256 value, uint256 count) private pure {
        s.wordsLeft = 0;
        while (count != 0) {
            uint256 pending = s.pending;
            uint256 take = count < 100 - pending ? count : 100 - pending;
            bytes memory payload = s.payload;
            assembly ("memory-safe") { mstore(add(add(payload, 64), pending), value) }
            s.pending = pending + take;
            if (s.pending == 100) fold(s);
            count -= take;
            value <<= 8 * take;
        }
    }

    function observe(State memory s, uint256 f) internal pure {
        require(f < 0x7f000001, "canonical transcript field");
        uint256 value;
        assembly ("memory-safe") {
            value := or(
                or(shl(248, and(f, 255)), shl(240, and(shr(8, f), 255))),
                or(shl(232, and(shr(16, f), 255)), shl(224, and(shr(24, f), 255)))
            )
        }
        append(s, value, 4);
    }

    function observeE(State memory s, uint256 e) internal pure {
        require(
            uint32(e) < 0x7f000001 && uint32(e >> 32) < 0x7f000001 && uint32(e >> 64) < 0x7f000001
                && uint32(e >> 96) < 0x7f000001,
            "canonical transcript extension"
        );
        uint256 value;
        assembly ("memory-safe") {
            // Byte reversal in the low 128 bits, followed by left alignment.
            value := or(
                shl(8, and(e, 0x00ff00ff00ff00ff00ff00ff00ff00ff)),
                and(shr(8, e), 0x00ff00ff00ff00ff00ff00ff00ff00ff)
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
            value := shl(128, value)
        }
        append(s, value, 16);
    }

    function observeHash(State memory s, bytes32 h) internal pure {
        append(s, uint256(h), 32);
    }

    function word(State memory s) internal pure returns (uint256 r) {
        if (s.wordsLeft == 0) {
            fold(s);
            s.wordsLeft = 8;
        }
        uint256 at = 4 * (8 - s.wordsLeft);
        --s.wordsLeft;
        bytes32 h = s.digest;
        assembly ("memory-safe") {
            r := or(
                or(byte(at, h), shl(8, byte(add(at, 1), h))),
                or(shl(16, byte(add(at, 2), h)), shl(24, byte(add(at, 3), h)))
            )
        }
    }

    function sample(State memory s) internal pure returns (uint256 r) {
        while (true) {
            r = word(s) & 0x7fffffff;
            if (r < 0x7f000001) return r;
        }
    }

    function sampleE(State memory s) internal pure returns (uint256 r) {
        for (uint256 i; i < 4; ++i) {
            r |= sample(s) << (32 * i);
        }
    }

    function bits(State memory s, uint256 n) internal pure returns (uint256) {
        require(n <= 32, "bits");
        return word(s) & ((1 << n) - 1);
    }

    function grind(State memory s, uint256 n, uint256 witness) internal pure {
        if (n == 0) return;
        observe(s, witness);
        if (bits(s, n) != 0) revert InvalidGrinding();
    }
}

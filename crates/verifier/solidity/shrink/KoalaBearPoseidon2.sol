// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// Native recursion-PV checksum: KoalaBear Poseidon2, width16/rate8, x^3,
/// 4 external + 20 internal + 4 external rounds. Constants come from the
/// authenticated verifier program. This is not the Keccak PCS transcript.
library KoalaBearPoseidon2 {
    function hash(uint256[] memory input, bytes memory program, uint256 constantsAt)
        internal
        pure
        returns (uint256[] memory digest)
    {
        require(constantsAt + 28 * 16 * 4 <= program.length, "Poseidon constants");
        digest = new uint256[](8);
        bytes memory diagonal =
            hex"7effffff00000001000000023f80000100000003000000043f8000007efffffe7efffffd7e8100016f2000017effff82007f00000fe0000007f000000000007f";
        assembly ("memory-safe") {
            function linear(state, tmp) {
                let p := 0x7f000001
                for { let i := 0 } lt(i, 512) { i := add(i, 128) } {
                    let a := mload(add(state, i))
                    let b := mload(add(state, add(i, 32)))
                    let c := mload(add(state, add(i, 64)))
                    let d := mload(add(state, add(i, 96)))
                    let t := add(add(a, b), add(c, d))
                    mstore(add(tmp, i), add(add(t, a), mul(2, b)))
                    mstore(add(tmp, add(i, 32)), add(add(t, b), mul(2, c)))
                    mstore(add(tmp, add(i, 64)), add(add(t, c), mul(2, d)))
                    mstore(add(tmp, add(i, 96)), add(add(t, d), mul(2, a)))
                }
                for { let j := 0 } lt(j, 128) { j := add(j, 32) } {
                    let sum :=
                        add(
                            add(mload(add(tmp, j)), mload(add(tmp, add(j, 128)))),
                            add(mload(add(tmp, add(j, 256))), mload(add(tmp, add(j, 384))))
                        )
                    for { let i := j } lt(i, 512) { i := add(i, 128) } {
                        mstore(add(state, i), mod(add(mload(add(tmp, i)), sum), p))
                    }
                }
            }
            function permute(state, tmp, constants, diag) {
                let p := 0x7f000001
                linear(state, tmp)
                for { let r := 0 } lt(r, 28) { r := add(r, 1) } {
                    let rc := add(constants, mul(r, 64))
                    switch or(lt(r, 4), iszero(lt(r, 24)))
                    case 1 {
                        for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                            let slot := add(state, mul(i, 32))
                            let x := add(mload(slot), shr(224, mload(add(rc, mul(i, 4)))))
                            mstore(slot, mod(mul(mod(mul(x, x), p), x), p))
                        }
                        linear(state, tmp)
                    }
                    default {
                        let x := add(mload(state), shr(224, mload(rc)))
                        mstore(state, mod(mul(mod(mul(x, x), p), x), p))
                        let sum := 0
                        for { let i := 0 } lt(i, 512) { i := add(i, 32) } {
                            sum := add(sum, mload(add(state, i)))
                        }
                        for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                            let slot := add(state, mul(i, 32))
                            let d := shr(224, mload(add(diag, mul(i, 4))))
                            mstore(slot, mod(add(sum, mul(mload(slot), d)), p))
                        }
                    }
                }
            }
            let state := mload(0x40)
            let tmp := add(state, 512)
            // State starts zero; reserve and initialize explicitly (memory can be dirty).
            mstore(0x40, add(tmp, 512))
            for { let i := 0 } lt(i, 512) { i := add(i, 32) } { mstore(add(state, i), 0) }
            let length := mload(input)
            for { let at := 0 } lt(at, length) { at := add(at, 8) } {
                let count := sub(length, at)
                if gt(count, 8) { count := 8 }
                // Native sponge overwrites the rate; unused cells in a partial
                // final block retain the previous state (there is no padding).
                for { let i := 0 } lt(i, count) { i := add(i, 1) } {
                    mstore(add(state, mul(i, 32)), mload(add(add(input, 32), mul(add(at, i), 32))))
                }
                permute(state, tmp, add(add(program, 32), constantsAt), add(diagonal, 32))
            }
            mcopy(add(digest, 32), state, 256)
        }
    }
}

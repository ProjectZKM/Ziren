// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {KoalaBear as F} from "../src/KoalaBear.sol";
import {KoalaBearPoseidon2 as Poseidon} from "../src/KoalaBearPoseidon2.sol";
import {KeccakTranscript as T} from "../src/KeccakTranscript.sol";

interface KernelVm {
    function envString(string calldata) external returns (string memory);
    function readFileBinary(string calldata) external view returns (bytes memory);
    function readFile(string calldata) external view returns (string memory);
    function parseJsonUintArray(string calldata, string calldata) external pure returns (uint256[] memory);
    function toString(uint256) external pure returns (string memory);
}

contract OptimizedKernelsTest {
    KernelVm constant vm = KernelVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function testPoseidonAgainstExpandedNativeConstants() public {
        string memory root = string.concat(vm.envString("WIRE_FIXTURE"), "/compiled/");
        bytes memory constants = vm.readFileBinary(string.concat(root, "poseidon-constants.bin"));
        string memory vectors = vm.readFile(string.concat(root, "poseidon-vectors.json"));
        for (uint256 i; i < 8; ++i) {
            string memory path = string.concat("[", vm.toString(i), "]");
            uint256[] memory input = vm.parseJsonUintArray(vectors, string.concat(path, ".input"));
            uint256[] memory expected = vm.parseJsonUintArray(vectors, string.concat(path, ".digest"));
            uint256[] memory actual = Poseidon.hash(input, constants, 0);
            require(keccak256(abi.encode(actual)) == keccak256(abi.encode(expected)), "Poseidon expansion mismatch");
        }
    }

    function testFuzzTowerInverseAndScale(uint128 bits, uint32 scalar) public pure {
        uint256 a;
        for (uint256 i; i < 4; ++i) {
            a |= (uint256(uint32(bits >> (32 * i))) % F.P) << (32 * i);
        }
        if (a == 0) a = 1;
        uint256 inverse = F.inv(a);
        require(inverse == F.pow(a, F.P * F.P * F.P * F.P - 2), "tower/Fermat mismatch");
        require(F.mul(a, inverse) == 1 && F.canonical(inverse), "inverse identity");
        uint256 b = uint256(scalar) % F.P;
        require(F.scale(a, b) == F.mul(a, b), "scalar multiplication mismatch");
    }

    function normal(bytes32 seed) private pure returns (uint256 out) {
        for (uint256 i; i < 4; ++i) {
            out |= (uint256(uint32(uint256(seed) >> (32 * i))) % F.P) << (32 * i);
        }
    }

    function testFuzzBaseHorner(bytes32 seed, uint8 log, uint32 input) public pure {
        uint256 n = uint256(log) % 8;
        uint256[] memory coefficients = new uint256[](1 << n);
        for (uint256 i; i < coefficients.length; ++i) {
            coefficients[i] = normal(keccak256(abi.encode(seed, i)));
        }
        uint256 x = uint256(input) % F.P;
        require(F.hornerBase(coefficients, x) == F.mono(coefficients, F.powers(x, n)), "Horner/monomial mismatch");
        uint256 exponent = uint256(seed) & 0x1fffff;
        require(F.basePow(x, exponent) == F.pow(x, exponent), "base exponent mismatch");
    }

    function testHornerMaximumLanes() public pure {
        uint256[] memory coefficients = new uint256[](128);
        uint256 maximum = uint256(F.P - 1) * 0x1000000010000000100000001;
        for (uint256 i; i < coefficients.length; ++i) {
            coefficients[i] = maximum;
        }
        for (uint256 i; i < 3; ++i) {
            uint256 x = i == 2 ? F.P - 1 : i;
            require(F.hornerBase(coefficients, x) == F.mono(coefficients, F.powers(x, 7)), "Horner carry bound");
        }
    }

    function testFuzzAccumulateBaseRow(bytes32 seed) public pure {
        uint256[] memory row = new uint256[](8);
        uint256[] memory values = new uint256[](8);
        uint256[] memory expected = new uint256[](8);
        uint256 weight = normal(seed);
        for (uint256 i; i < 8; ++i) {
            row[i] = uint256(keccak256(abi.encode(seed, i))) % F.P;
            values[i] = normal(keccak256(abi.encode(seed, i + 10)));
            expected[i] = F.add(values[i], F.mul(weight, row[i]));
        }
        F.accumulateBaseRow(values, row, weight);
        require(keccak256(abi.encode(values)) == keccak256(abi.encode(expected)), "fused row mismatch");
    }

    function testFuzzPackedProofViews(bytes32 seed) public pure {
        uint256[] memory row = new uint256[](8);
        uint256[] memory values = new uint256[](8);
        uint256[] memory expected = new uint256[](8);
        uint256[] memory extensions = new uint256[](8);
        bytes memory packedRow = new bytes(3 + 8 * 4);
        bytes memory packedExt = new bytes(7 + 8 * 16);
        uint256 weight = normal(seed);
        for (uint256 i; i < 8; ++i) {
            row[i] = uint256(keccak256(abi.encode(seed, i))) % F.P;
            values[i] = normal(keccak256(abi.encode(seed, i + 11)));
            extensions[i] = normal(keccak256(abi.encode(seed, i + 22)));
            expected[i] = F.add(values[i], F.mul(weight, row[i]));
            for (uint256 j; j < 4; ++j) {
                packedRow[3 + 4 * i + j] = bytes1(uint8(row[i] >> (8 * j)));
            }
            for (uint256 j; j < 16; ++j) {
                packedExt[7 + 16 * i + j] = bytes1(uint8(extensions[i] >> (8 * j)));
            }
        }
        F.accumulatePackedBaseRow(values, packedRow, 3, weight);
        require(keccak256(abi.encode(values)) == keccak256(abi.encode(expected)), "packed fused row mismatch");
        uint256[] memory decoded = F.packedExtensions(packedExt, 7, 8);
        require(keccak256(abi.encode(decoded)) == keccak256(abi.encode(extensions)), "packed extension endian mismatch");
    }

    struct Reference {
        bytes32 digest;
        bytes buffer;
        uint256 left;
    }

    function fold(Reference memory r) private pure {
        r.digest = keccak256(bytes.concat(r.digest, r.buffer));
        r.buffer = new bytes(0);
    }

    function observe(Reference memory r, bytes memory value) private pure {
        r.left = 0;
        for (uint256 i; i < value.length; ++i) {
            r.buffer = bytes.concat(r.buffer, value[i]);
            if (r.buffer.length == 100) fold(r);
        }
    }

    function word(Reference memory r) private pure returns (uint256 value) {
        if (r.left == 0) {
            fold(r);
            r.left = 8;
        }
        uint256 at = 4 * (8 - r.left--);
        for (uint256 j; j < 4; ++j) {
            value |= uint256(uint8(r.digest[at + j])) << (8 * j);
        }
    }

    function le32(uint256 x) private pure returns (bytes memory) {
        return abi.encodePacked(bytes1(uint8(x)), bytes1(uint8(x >> 8)), bytes1(uint8(x >> 16)), bytes1(uint8(x >> 24)));
    }

    function testFuzzTranscriptAcrossBufferBoundaries(bytes32 seed, uint8 initial, uint8 remaining) public pure {
        uint256 n = uint256(initial) % 100;
        bytes memory buffer = new bytes(n);
        for (uint256 i; i < n; ++i) {
            buffer[i] = seed[i % 32];
        }
        T.State memory fast = T.resume(seed, buffer, uint256(remaining) % 9);
        Reference memory slow = Reference(seed, bytes.concat(buffer), uint256(remaining) % 9);
        // Force field, extension and hash observations over arbitrary offsets,
        // including splitting observations across the 100-byte fold boundary.
        for (uint256 i; i < 12; ++i) {
            seed = keccak256(abi.encode(seed, i));
            uint256 a = uint256(seed) % F.P;
            if (i % 3 == 0) {
                T.observe(fast, a);
                observe(slow, le32(a));
            } else if (i % 3 == 1) {
                uint256 e;
                bytes memory encoded;
                for (uint256 j; j < 4; ++j) {
                    uint256 x = uint256(uint32(uint256(seed) >> (32 * j))) % F.P;
                    e |= x << (32 * j);
                    encoded = bytes.concat(encoded, le32(x));
                }
                T.observeE(fast, e);
                observe(slow, encoded);
            } else {
                T.observeHash(fast, seed);
                observe(slow, abi.encodePacked(seed));
            }
            require(
                fast.digest == slow.digest && fast.pending == slow.buffer.length && fast.wordsLeft == slow.left,
                "transcript state"
            );
            if (i % 2 == 0) {
                require(T.word(fast) == word(slow), "transcript word mismatch");
                require(T.word(fast) == word(slow), "transcript second word mismatch");
            }
        }
        // Exhaust squeeze state; then force a fold of an empty buffer.
        for (uint256 i; i < 20; ++i) {
            require(T.word(fast) == word(slow), "transcript final words");
        }
    }
}

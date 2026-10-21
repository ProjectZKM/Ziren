// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {StackedWhir as W} from "../src/StackedWhir.sol";
import {KoalaBear as F} from "../src/KoalaBear.sol";
import {KeccakTranscript as T} from "../src/KeccakTranscript.sol";

/// Deliberately a component harness. Incoming transcript/claims are supplied by
/// the test; this contract MUST NOT authorize a Ziren statement or settlement.
contract WhirComponentHarness {
    struct Fixture {
        W.Config config;
        W.Proof proof;
        bytes32[] roots;
        uint256[] stripes;
        uint256[] point;
        bytes32 digest;
        bytes buffered;
        uint256 wordsLeft;
    }

    struct Reader {
        bytes data;
        uint256 at;
    }

    function number(Reader memory r, uint256 n) private pure returns (uint256 x) {
        require(n <= 32 && r.at + n <= r.data.length, "truncated component");
        bytes memory data = r.data;
        uint256 at = r.at;
        assembly ("memory-safe") { x := shr(mul(sub(32, n), 8), mload(add(add(data, 32), at))) }
        r.at += n;
    }

    function vector(Reader memory r, uint256 width, uint256 countBytes) private pure returns (uint256[] memory a) {
        uint256 n = number(r, countBytes);
        require(n <= 65536, "component allocation");
        a = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            a[i] = number(r, width);
        }
    }

    function hashes(Reader memory r, uint256 countBytes) private pure returns (bytes32[] memory a) {
        uint256 n = number(r, countBytes);
        require(n <= 65536, "hash allocation");
        a = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            a[i] = bytes32(number(r, 32));
        }
    }

    function polys(Reader memory r) private pure returns (uint256[][] memory a) {
        uint256 n = number(r, 1);
        a = new uint256[][](n);
        for (uint256 i; i < n; ++i) {
            a[i] = vector(r, 16, 1);
        }
    }

    function decode(bytes memory encoded) private pure returns (Fixture memory a) {
        Reader memory r = Reader(encoded, 0);
        require(number(r, 4) == 0x5a4b5750, "component magic");
        a.config.n = number(r, 1);
        a.config.startingRate = number(r, 1);
        a.config.batchPow = number(r, 1);
        a.config.finalQueries = number(r, 2);
        a.config.finalPow = number(r, 1);
        uint256 n = number(r, 1);
        a.config.rounds = new W.Round[](n);
        for (uint256 i; i < n; ++i) {
            W.Round memory v;
            v.fold = number(r, 1);
            v.rate = number(r, 1);
            v.queries = number(r, 2);
            v.ood = number(r, 1);
            v.queryPow = number(r, 1);
            v.foldPow = vector(r, 1, 1);
            a.config.rounds[i] = v;
        }
        a.digest = bytes32(number(r, 32));
        n = number(r, 1);
        a.buffered = new bytes(n);
        for (uint256 i; i < n; ++i) {
            a.buffered[i] = bytes1(uint8(number(r, 1)));
        }
        a.wordsLeft = number(r, 1);
        a.roots = hashes(r, 1);
        a.stripes = vector(r, 2, 1);
        a.point = vector(r, 16, 1);
        n = number(r, 1);
        a.proof.batch = new uint256[][](n);
        for (uint256 i; i < n; ++i) {
            a.proof.batch[i] = vector(r, 16, 2);
        }
        a.proof.batchPow = number(r, 4);
        n = number(r, 1);
        a.proof.roundPolys = new uint256[][][](n);
        for (uint256 i; i < n; ++i) {
            a.proof.roundPolys[i] = polys(r);
        }
        n = number(r, 1);
        a.proof.roundOod = new uint256[][](n);
        for (uint256 i; i < n; ++i) {
            a.proof.roundOod[i] = vector(r, 16, 1);
        }
        a.proof.roots = hashes(r, 1);
        n = number(r, 1);
        a.proof.openings = new W.Leaf[][](n);
        for (uint256 i; i < n; ++i) {
            uint256 k = number(r, 2);
            a.proof.openings[i] = new W.Leaf[](k);
            for (uint256 j; j < k; ++j) {
                W.Leaf memory leaf;
                uint256 rows = number(r, 2);
                leaf.values = new uint256[][](rows);
                for (uint256 row; row < rows; ++row) {
                    leaf.values[row] = vector(r, 4, 2);
                }
                leaf.path = hashes(r, 1);
                a.proof.openings[i][j] = leaf;
            }
        }
        a.proof.finalPoly = vector(r, 16, 2);
        a.proof.finalPolys = polys(r);
        a.proof.foldPow = vector(r, 4, 1);
        a.proof.finalPow = number(r, 4);
        require(r.at == encoded.length, "component EOF");
    }

    function check(bytes memory encoded, uint256 mutation) public pure returns (bool) {
        Fixture memory a = decode(encoded);
        if (mutation == 1) a.proof.roundPolys[0][0][0] = F.add(a.proof.roundPolys[0][0][0], 1);
        if (mutation == 2) a.proof.openings[0][0].values[0][0] = (a.proof.openings[0][0].values[0][0] + 1) % F.P;
        if (mutation == 3) a.digest = bytes32(uint256(a.digest) ^ 1);
        if (mutation >= 4) {
            for (uint256 r; r < a.proof.openings.length; ++r) {
                for (uint256 j; j < a.proof.openings[r].length; ++j) {
                    W.Leaf memory leaf = a.proof.openings[r][j];
                    leaf.rows = leaf.values.length;
                    leaf.width = leaf.values[0].length;
                    leaf.source = new bytes(leaf.rows * leaf.width * 4);
                    for (uint256 row; row < leaf.rows; ++row) {
                        for (uint256 col; col < leaf.width; ++col) {
                            uint256 value = leaf.values[row][col];
                            for (uint256 k; k < 4; ++k) {
                                leaf.source[4 * (row * leaf.width + col) + k] = bytes1(uint8(value >> (8 * k)));
                            }
                        }
                    }
                    leaf.values = new uint256[][](0);
                }
            }
            if (mutation == 5) a.proof.openings[0][0].width += 1;
        }
        T.State memory t = T.resume(a.digest, a.buffered, a.wordsLeft);
        W.verify(a.proof, a.config, a.roots, a.stripes, a.point, t);
        return true;
    }
}

interface WhirVm {
    function envString(string calldata) external returns (string memory);
    function readFileBinary(string calldata) external view returns (bytes memory);
}

contract StackedWhirTest {
    WhirVm constant vm = WhirVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    event ComponentGas(uint256 executionGas, uint256 abiBytes);

    function testSavedFullShrinkWhirComponent() public {
        bytes memory encoded = vm.readFileBinary(string.concat(vm.envString("WIRE_FIXTURE"), "/whir.component.bin"));
        WhirComponentHarness h = new WhirComponentHarness();
        uint256 before = gasleft();
        require(h.check(encoded, 0));
        emit ComponentGas(before - gasleft(), encoded.length);
        for (uint256 i = 1; i <= 3; ++i) {
            (bool ok, bytes memory error) = address(h).staticcall(abi.encodeCall(h.check, (encoded, i)));
            require(!ok && error.length > 0, "altered component accepted or OOG");
        }
    }

    function testSavedPackedWhirComponentParity() public {
        bytes memory encoded = vm.readFileBinary(string.concat(vm.envString("WIRE_FIXTURE"), "/whir.component.bin"));
        WhirComponentHarness h = new WhirComponentHarness();
        require(h.check(encoded, 4), "packed WHIR replay");
        (bool ok, bytes memory error) = address(h).staticcall(abi.encodeCall(h.check, (encoded, uint256(5))));
        require(!ok && error.length > 0, "packed leaf shape accepted or OOG");
    }

    function testExtensionBasisAndInversion() public pure {
        uint256 x = uint256(1) << 32;
        require(F.mul(F.mul(x, x), F.mul(x, x)) == 3);
        uint256 a = uint256(13) | (uint256(2) << 32) | (uint256(11) << 64) | (uint256(7) << 96);
        require(F.mul(a, F.inv(a)) == 1);
        require(F.sub(F.add(a, x), x) == a);
        uint256[] memory v = new uint256[](4);
        for (uint256 i; i < 4; ++i) {
            v[i] = i + 1;
        }
        uint256[] memory p = new uint256[](2);
        p[0] = 5;
        p[1] = 7;
        require(F.mle(v, p) == 20);
        require(F.mono(v, p) == 172);
    }
}

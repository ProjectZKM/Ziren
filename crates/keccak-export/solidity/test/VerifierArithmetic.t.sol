// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {VerifierArithmetic as A} from "../src/VerifierArithmetic.sol";
import {KoalaBear as F} from "../src/KoalaBear.sol";

contract ArithmeticHarness {
    function run(bytes memory program, bytes memory packet, uint256[] memory regs)
        external
        pure
        returns (uint256 next, uint256[] memory result)
    {
        return (A.run(program, packet, regs, 0, 4, 1), regs);
    }
}

contract VerifierArithmeticTest {
    function normal(uint128 x) private pure returns (uint256 out) {
        for (uint256 i; i < 4; ++i) {
            out |= (uint256(uint32(x >> (32 * i))) % F.P) << (32 * i);
        }
    }

    function packet(uint256 a, bytes32 hash) private pure returns (bytes memory out) {
        out = new bytes(38);
        for (uint256 i; i < 16; ++i) {
            out = bytes.concat(out, bytes1(uint8(a >> (8 * i))));
        }
        out = bytes.concat(out, hash);
    }

    function binary(uint8 op, uint32 dst, uint32 a, uint32 b) private pure returns (bytes memory) {
        return abi.encodePacked(op, dst, a, b);
    }

    function testFuzzArithmeticAndRegisterReuse(uint128 aa, uint128 bb, uint32 scalar) public pure {
        uint256 a = normal(aa);
        uint256 b = normal(bb);
        uint32 s = uint32(uint256(scalar) % F.P);
        bytes32 hash = keccak256(abi.encode(a, b));
        uint256[] memory regs = new uint256[](5);
        regs[0] = a;
        regs[1] = b;
        regs[4] = uint256(hash);
        bytes memory program = bytes.concat(
            binary(4, 0, 0, 1),
            binary(5, 2, 0, 0x20000000),
            binary(6, 3, 2, 0x20000000),
            binary(23, 3, 3, 0x80000000 | s),
            binary(20, 0, 0x80000000 | s, 0x40000000),
            binary(21, 0, 0, 0x80000000 | s),
            binary(22, 0, 0, 0x80000000 | s),
            abi.encodePacked(uint8(8), uint32(2), uint32(1)),
            abi.encodePacked(uint8(8), uint32(0x10000000), uint32(4)),
            hex"ff"
        );
        require(A.run(program, packet(a, hash), regs, 0, 4, 1) == program.length - 1, "arithmetic PC");
        require(regs[0] == mulmod(uint32(a), s, F.P) && regs[1] == b && regs[2] == b, "scalar/register mismatch");
        require(regs[3] == F.mul(F.mul(a, b), s), "extension arithmetic mismatch");
    }

    function testRejectInvalidArithmeticOperands() public {
        ArithmeticHarness h = new ArithmeticHarness();
        uint256[] memory regs = new uint256[](5);
        bytes memory data = packet(0, bytes32(0));
        bytes[6] memory bad = [
            binary(4, 0, 0x20000001, 0),
            binary(4, 0, 0x40000004, 0),
            binary(4, 0, 0x10000001, 0),
            binary(4, 0, 5, 0),
            binary(4, 5, 0, 0),
            hex"040000000000000000"
        ];
        for (uint256 i; i < bad.length; ++i) {
            (bool ok, bytes memory error) = address(h).staticcall(abi.encodeCall(h.run, (bad[i], data, regs)));
            require(!ok && error.length == 4, "bad operand accepted or OOG");
        }
        bytes memory wrong = abi.encodePacked(uint8(8), uint32(0x80000000), uint32(0x80000001));
        (bool equalityOk, bytes memory equalityError) =
            address(h).staticcall(abi.encodeCall(h.run, (wrong, data, regs)));
        require(!equalityOk && equalityError.length == 100, "bad equality accepted or OOG");
    }
}

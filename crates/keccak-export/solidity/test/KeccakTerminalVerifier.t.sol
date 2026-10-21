// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {KeccakTerminalVerifier} from "../src/KeccakTerminalVerifier.sol";

interface TerminalVm {
    function envString(string calldata) external returns (string memory);
    function readFileBinary(string calldata) external view returns (bytes memory);
    function readFile(string calldata) external view returns (string memory);
    function parseJsonBytes32(string calldata, string calldata) external pure returns (bytes32);
    function parseJsonUint(string calldata, string calldata) external pure returns (uint256);
}

contract KeccakTerminalVerifierTest {
    TerminalVm constant vm = TerminalVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    event FullVerificationGas(uint256 executionGas, uint256 programBytes, uint256 proofBytes, uint256 runtimeBytes);
    event log_named_uint(string key, uint256 value);

    function testCompleteSavedShrinkVerification() public {
        string memory root = vm.envString("WIRE_FIXTURE");
        bytes memory program = vm.readFileBinary(string.concat(root, "/compiled/program.bin"));
        bytes memory packet = vm.readFileBinary(string.concat(root, "/raw.bin"));
        bytes32 digest =
            vm.parseJsonBytes32(vm.readFile(string.concat(root, "/compiled/statement.json")), ".output_digest");
        KeccakTerminalVerifier verifier = new KeccakTerminalVerifier(keccak256(program));
        uint256 before = gasleft();
        require(verifier.verify(program, packet, digest));
        uint256 gasUsed = before - gasleft();
        emit FullVerificationGas(gasUsed, program.length, packet.length, address(verifier).code.length);
        emit log_named_uint("honest full verification execution gas", gasUsed);
        emit log_named_uint("trusted verifier program bytes", program.length);
        emit log_named_uint("raw proof packet bytes", packet.length);
        emit log_named_uint("verifier runtime bytes", address(verifier).code.length);
        (bool ok, bytes memory error) = address(verifier)
            .staticcall(abi.encodeCall(verifier.verify, (program, packet, bytes32(uint256(digest) ^ 1))));
        require(!ok && error.length > 0, "wrong public output accepted or OOG");
        packet[38] ^= 0x01;
        (ok, error) = address(verifier).staticcall(abi.encodeCall(verifier.verify, (program, packet, digest)));
        require(!ok && error.length > 0, "altered public values accepted or OOG");
        packet[38] ^= 0x01;
        string memory mutations = vm.readFile(string.concat(root, "/compiled/mutations.json"));
        for (uint256 i; i < 2; ++i) {
            uint256 fieldIndex = vm.parseJsonUint(mutations, i == 0 ? ".gkr_field" : ".merkle_field");
            uint256 offset = 38 + 4 * fieldIndex;
            packet[offset] ^= 0x01;
            (ok, error) = address(verifier).staticcall(abi.encodeCall(verifier.verify, (program, packet, digest)));
            require(!ok && error.length > 0, "invalid GKR/Merkle proof accepted or OOG");
            packet[offset] ^= 0x01;
        }
        // The fast canonical scan and raw packet bounds must reject malformed
        // packets before any field arithmetic, including p itself as a word.
        bytes memory malformed = bytes.concat(packet, hex"00");
        (ok, error) = address(verifier).staticcall(abi.encodeCall(verifier.verify, (program, malformed, digest)));
        require(!ok && error.length > 0, "trailing packet byte accepted or OOG");
        malformed = bytes.concat(packet);
        assembly ("memory-safe") { mstore(malformed, sub(mload(malformed), 1)) }
        (ok, error) = address(verifier).staticcall(abi.encodeCall(verifier.verify, (program, malformed, digest)));
        require(!ok && error.length > 0, "truncated packet accepted or OOG");
        malformed = bytes.concat(packet);
        malformed[38] = 0x01;
        malformed[39] = 0x00;
        malformed[40] = 0x00;
        malformed[41] = 0x7f;
        (ok, error) = address(verifier).staticcall(abi.encodeCall(verifier.verify, (program, malformed, digest)));
        require(!ok && error.length > 0, "noncanonical packet field accepted or OOG");
        malformed = bytes.concat(packet);
        malformed[6] ^= 0x01;
        (ok, error) = address(verifier).staticcall(abi.encodeCall(verifier.verify, (program, malformed, digest)));
        require(!ok && error.length > 0, "wrong profile accepted or OOG");
        program[64] ^= 0x01;
        (ok, error) = address(verifier).staticcall(abi.encodeCall(verifier.verify, (program, packet, digest)));
        require(!ok && error.length > 0, "unapproved program accepted or OOG");
    }
}

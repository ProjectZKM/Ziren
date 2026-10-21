// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {KeccakWireReader} from "../src/KeccakWireReader.sol";

interface Vm {
    function envString(string calldata) external returns (string memory);
    function readFile(string calldata) external view returns (string memory);
    function readFileBinary(string calldata) external view returns (bytes memory);
    function parseJsonBytes32(string calldata, string calldata) external pure returns (bytes32);
    function parseJsonUint(string calldata, string calldata) external pure returns (uint256);
    function toString(uint256) external pure returns (string memory);
}

contract KeccakWireReaderTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    event ReaderMeasurement(
        string variant,
        uint256 packetBytes,
        uint256 executionGas,
        uint256 abiTokens,
        uint256 transactionGasIncludingFloor
    );

    function testDagBranchesAndMalformedReferences() public {
        bytes32 id = bytes32(uint256(7));
        KeccakWireReader reader = new KeccakWireReader(id, 2, 0, 3, new uint64[](0));
        bytes32 a = keccak256("a");
        bytes32 b = keccak256("b");
        bytes32 root = keccak256(abi.encodePacked(a, b));
        bytes memory packet =
            abi.encodePacked(hex"5a4b45540102", id, hex"030000", a, hex"00", b, hex"0200000100000001000200");
        require(reader.readWitnessDigest(packet) == keccak256(abi.encodePacked(a, b, root)));
        bytes memory bad = bytes.concat(packet);
        bad[107] = 0x02; // branch refers to itself
        (bool ok,) = address(reader).staticcall(abi.encodeCall(reader.readWitnessDigest, (bad)));
        require(!ok, "forward/self reference accepted");
        bad = bytes.concat(packet);
        bad[40] = 0x03;
        (ok,) = address(reader).staticcall(abi.encodeCall(reader.readWitnessDigest, (bad)));
        require(!ok, "unknown opcode accepted");
        bad = bytes.concat(packet);
        bad[115] = 0xff;
        bad[116] = 0xff;
        (ok,) = address(reader).staticcall(abi.encodeCall(reader.readWitnessDigest, (bad)));
        require(!ok, "out-of-range reference accepted");
    }

    function testDagLeafUsesCanonicalLittleEndianWords() public {
        bytes32 id = bytes32(uint256(8));
        uint64[] memory ranges = new uint64[](1);
        ranges[0] = uint64(2) << 32;
        KeccakWireReader reader = new KeccakWireReader(id, 2, 2, 1, ranges);
        bytes memory fields = hex"0100000002000000";
        bytes memory packet = abi.encodePacked(hex"5a4b45540102", id, fields, hex"01000100000000");
        require(reader.readWitnessDigest(packet) == keccak256(abi.encodePacked(fields, keccak256(fields))));
    }

    function testFuzzCanonicalWords(uint32 x, uint32 y) public {
        bytes32 id = bytes32(uint256(9));
        KeccakWireReader reader = new KeccakWireReader(id, 0, 2, 0, new uint64[](0));
        bytes memory fields = new bytes(8);
        for (uint256 i; i < 4; ++i) {
            fields[i] = bytes1(uint8(x >> (8 * i)));
            fields[i + 4] = bytes1(uint8(y >> (8 * i)));
        }
        bytes memory packet = abi.encodePacked(hex"5a4b45540100", id, fields);
        (bool ok, bytes memory result) = address(reader).staticcall(abi.encodeCall(reader.readWitnessDigest, (packet)));
        require(ok == (x < 0x7f000001 && y < 0x7f000001), "field canonicality mismatch");
        if (ok) require(abi.decode(result, (bytes32)) == keccak256(fields), "little-endian stream mismatch");
    }

    function testSavedProductionProofRustParity() public {
        string[4] memory names = [string("raw"), "shared", "dag", "dag-derived"];
        for (uint256 j; j < names.length; ++j) {
            string memory prefix = string.concat(vm.envString("WIRE_FIXTURE"), "/", names[j]);
            string memory manifest = vm.readFile(string.concat(prefix, ".json"));
            uint256 fields = vm.parseJsonUint(manifest, ".field_count");
            uint256 refs = vm.parseJsonUint(manifest, ".digest_references");
            uint256 mode = vm.parseJsonUint(manifest, ".mode");
            // Count is provided explicitly to keep the test independent of
            // JSON object ordering and avoid importing a test-only dependency.
            uint256 n = vm.parseJsonUint(manifest, ".leaf_count");
            uint64[] memory ranges = new uint64[](n);
            for (uint256 i; i < n; ++i) {
                string memory key = string.concat(".leaves[", vm.toString(i), "]");
                uint256 start = vm.parseJsonUint(manifest, string.concat(key, ".field_start"));
                uint256 count = vm.parseJsonUint(manifest, string.concat(key, ".field_count"));
                require(start <= type(uint32).max && count <= type(uint32).max);
                ranges[i] = uint64(start | (count << 32));
            }
            KeccakWireReader reader =
                new KeccakWireReader(vm.parseJsonBytes32(manifest, ".profile_id"), uint8(mode), fields, refs, ranges);
            bytes memory packet = vm.readFileBinary(string.concat(prefix, ".bin"));
            uint256 before = gasleft();
            bytes32 digest = reader.readWitnessDigest(packet);
            uint256 execution = before - gasleft();
            require(digest == vm.parseJsonBytes32(manifest, ".witness_digest"), "Rust/Solidity stream mismatch");
            bytes memory call = abi.encodeCall(reader.readWitnessDigest, (packet));
            uint256 tokens;
            for (uint256 i; i < call.length; ++i) {
                tokens += call[i] == 0 ? 1 : 4;
            }
            uint256 regular = 4 * tokens + execution;
            uint256 floor = 10 * tokens;
            emit ReaderMeasurement(
                names[j], packet.length, execution, tokens, 21000 + (regular > floor ? regular : floor)
            );
            bytes memory bad = bytes.concat(packet, hex"00");
            (bool success,) = address(reader).staticcall(abi.encodeCall(reader.readWitnessDigest, (bad)));
            require(!success, "trailing bytes accepted");
            packet[38] = 0x01;
            packet[39] = 0x00;
            packet[40] = 0x00;
            packet[41] = 0x7f;
            (success,) = address(reader).staticcall(abi.encodeCall(reader.readWitnessDigest, (packet)));
            require(!success, "noncanonical field accepted");
        }
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// Base for an ahead-of-time compiled, separately approved verifier profile.
/// Generated subclasses pin every module's runtime hash and the original KVE2
/// program hash. Modules exchange private intermediate state, never a validity
/// bit supplied by the caller. All calls execute under STATICCALL.
contract NativeKernelTable {
    constructor(bytes memory runtime) {
        // STOP followed by the approved ordered 20-byte module addresses.
        assembly("memory-safe"){return(add(runtime,32),mload(runtime))}
    }
}

abstract contract NativeTerminalVerifier {
    address public immutable kernelTable;
    uint256 public immutable kernelCount;
    bytes32 public immutable verifierProgramHash;
    error InvalidKernel(uint256 index);
    error InvalidRegisterUpdate(uint256 offset);
    error InvalidPacket();

    constructor(address[] memory modules, bytes32 approvedCommitment, uint256 expectedCount, bytes32 sourceProgramHash) {
        require(modules.length != 0 && modules.length == expectedCount && modules.length <= 1228, "kernel count");
        bytes memory hashes=new bytes(32+32*modules.length);
        assembly("memory-safe"){mstore(add(hashes,32),mload(modules))}
        for (uint256 i; i < modules.length; ++i) {
            if (modules[i].code.length == 0 || modules[i].code.length > 24576) revert InvalidKernel(i);
            bytes32 actual=modules[i].codehash;
            assembly("memory-safe"){mstore(add(add(hashes,64),mul(i,32)),actual)}
        }
        require(keccak256(hashes)==approvedCommitment,"kernel code/order commitment");
        // Reserve a trailing word for unaligned stores, then set the exact
        // runtime length. The leading STOP makes the table non-executable.
        bytes memory runtime=new bytes(1+20*modules.length+32);
        for(uint256 i;i<modules.length;++i){
            address module=modules[i];
            assembly("memory-safe"){mstore(add(add(runtime,33),mul(i,20)),shl(96,module))}
        }
        assembly("memory-safe"){mstore(runtime,add(1,mul(mload(modules),20)))}
        kernelTable=address(new NativeKernelTable(runtime));
        kernelCount=modules.length;
        verifierProgramHash = sourceProgramHash;
    }

    function kernels(uint256 index) external view returns(address module) {
        if(index>=kernelCount) revert InvalidKernel(index);
        address table=kernelTable;
        assembly("memory-safe") {extcodecopy(table,0,add(1,mul(index,20)),20) module:=shr(96,mload(0))}
    }

    function _initialize(bytes calldata wire, bytes32 outputDigest) internal pure virtual returns (bytes memory);
    function _prefixLength() internal pure virtual returns (uint256);
    function _maxReturnLength() internal pure virtual returns (uint256);
    function _finish(bytes memory context) internal view virtual returns (bool);

    function verify(bytes calldata wire, bytes32 outputDigest) external view virtual returns (bool) {
        bytes memory context = _initialize(wire, outputDigest);
        uint256 registers = _prefixLength() - 320;
        bytes memory updates = new bytes(_maxReturnLength());
        bytes memory addresses=new bytes(20*kernelCount);
        address table=kernelTable;
        assembly("memory-safe"){extcodecopy(table,add(addresses,32),1,mload(addresses))}
        bytes4 invalidUpdate = InvalidRegisterUpdate.selector;
        for (uint256 i; i < kernelCount; ++i) {
            address kernel;
            assembly("memory-safe"){kernel:=shr(96,mload(add(add(addresses,32),mul(i,20))))}
            bool ok;
            uint256 returned;
            assembly ("memory-safe") {
                // Pinned kernels return transcript state followed by sparse
                // (register byte offset, value) pairs. Reuse one response
                // buffer; never expose the proof suffix to return-data writes.
                ok := staticcall(gas(), kernel, add(context, 32), mload(context), 0, 0)
                returned := returndatasize()
                if iszero(ok) {
                    let at := mload(0x40)
                    returndatacopy(at, 0, returned)
                    revert(at, returned)
                }
            }
            if (returned < 288 || returned > updates.length || (returned - 288) % 64 != 0) revert InvalidKernel(i);
            assembly ("memory-safe") {
                let result := add(updates, 32)
                let state := add(context, 32)
                returndatacopy(result, 0, returned)
                mcopy(add(state, registers), result, 288)
                for { let at := add(result, 288) } lt(at, add(result, returned)) { at := add(at, 64) } {
                    let offset := mload(at)
                    // These checks also make the proof and expected-output
                    // regions immutable even if a module returns a bad frame.
                    if or(iszero(lt(offset, registers)), and(offset, 31)) {
                        mstore(0, invalidUpdate)
                        mstore(4, offset)
                        revert(0, 36)
                    }
                    mstore(add(state, offset), mload(add(at, 32)))
                }
            }
        }
        return _finish(context);
    }
}

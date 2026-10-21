// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {NativeTerminalVerifier} from "../src/NativeTerminalVerifier.sol";

/// Deliberately malformed, locally pinned kernels exercise the frame boundary.
contract FrameKernel {
    uint256 private immutable mode;
    constructor(uint256 selected) { mode=selected; }
    fallback() external {
        uint256 selected=mode;
        assembly("memory-safe") {
            let result:=mload(0x40)
            calldatacopy(result,64,288)
            mstore(add(result,288),0)
            mstore(add(result,320),33)
            switch selected
            case 1 { return(result,287) }
            case 2 { return(result,353) }
            case 3 { return(result,416) }
            case 4 { mstore(add(result,288),1) }
            case 5 { mstore(add(result,288),64) }
            case 6 { mstore(add(result,288),352) }
            case 7 { mstore(add(result,288),416) }
            case 8 { mstore(add(result,288),not(0)) }
            return(result,352)
        }
    }
}

contract FrameHarness is NativeTerminalVerifier {
    constructor(address[] memory modules) NativeTerminalVerifier(
        modules,keccak256(abi.encode(uint256(1),modules[0].codehash)),1,bytes32(0)
    ) {}
    function _prefixLength() internal pure override returns(uint256){return 384;}
    function _maxReturnLength() internal pure override returns(uint256){return 352;}
    function _initialize(bytes calldata wire,bytes32 output) internal pure override returns(bytes memory context){
        context=new bytes(416+wire.length);
        assembly("memory-safe") {
            let state:=add(context,32)
            mstore(state,11)
            mstore(add(state,32),22)
            mstore(add(state,64),0xabcdef)
            mstore(add(state,352),output)
            mstore(add(state,384),wire.length)
            calldatacopy(add(state,416),wire.offset,wire.length)
        }
    }
    function _finish(bytes memory context) internal pure override returns(bool valid){
        assembly("memory-safe") {
            let state:=add(context,32)
            valid:=and(and(eq(mload(state),33),eq(mload(add(state,32)),22)),
                and(eq(mload(add(state,64)),0xabcdef),
                and(eq(mload(add(state,352)),0x1234),
                and(eq(mload(add(state,384)),3),eq(shr(232,mload(add(state,416))),0xaabbcc)))))
        }
    }
}

contract NativeFramesTest {
    function harness(uint256 mode) private returns(FrameHarness){
        address[] memory modules=new address[](1);
        modules[0]=address(new FrameKernel(mode));
        return new FrameHarness(modules);
    }
    function testSparseUpdatesPreserveUntouchedRegistersAndProof() public {
        require(harness(0).verify(hex"aabbcc",bytes32(uint256(0x1234))),"frame state changed");
    }
    function testMalformedFramesRejected() public {
        for(uint256 mode=1;mode<=8;++mode){
            FrameHarness target=harness(mode);
            (bool ok,bytes memory error)=address(target).staticcall(abi.encodeCall(target.verify,(hex"aabbcc",bytes32(uint256(0x1234)))));
            require(!ok && error.length>0,"malformed frame accepted or OOG");
        }
    }
}

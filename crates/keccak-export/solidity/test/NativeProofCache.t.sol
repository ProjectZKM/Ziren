// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {NativeProofCache as C} from "../src/NativeProofCache.sol";

contract NativeProofCacheTest {
    function fixture(bytes32 seed,uint256 firstCount,uint256 secondCount,uint256 offset)
        private pure returns(bytes memory context,uint256 fields,uint256 original,bytes memory ranges,uint256[] memory values) {
        fields=4*(firstCount+secondCount)+3;
        uint256 packetLength=38+4*fields+64;
        original=offset+packetLength;
        context=new bytes(original+16*(firstCount+secondCount)+16);
        for(uint256 i;i<offset;++i)context[i]=0xa7;
        assembly("memory-safe"){mstore(add(context,offset),packetLength)}
        values=new uint256[](fields);
        for(uint256 i;i<fields;++i){
            uint256 value=uint256(keccak256(abi.encode(seed,i)))%0x7f000001;
            values[i]=value;
            for(uint256 j;j<4;++j)context[offset+38+4*i+j]=bytes1(uint8(value>>(8*j)));
        }
        ranges=abi.encodePacked(uint32(0),uint16(firstCount),uint32(4*firstCount+1),uint16(secondCount));
    }
    function run(bytes memory context,uint256 offset,uint256 fields,bytes memory ranges) external pure returns(bytes memory){
        C.populate(context,offset,fields,ranges);return context;
    }
    function testFuzzCacheMatchesScalarAndPreservesProof(bytes32 seed,uint8 a,uint8 b,uint8 alignment) public pure {
        uint256 n0=1+uint256(a)%65;uint256 n1=1+uint256(b)%65;uint256 offset=96+uint256(alignment)%33;
        (bytes memory context,uint256 fields,uint256 original,bytes memory ranges,uint256[] memory values)=fixture(seed,n0,n1,offset);
        bytes32 beforeHash;bytes32 afterHash;
        assembly("memory-safe"){beforeHash:=keccak256(add(context,32),original)}
        C.populate(context,offset,fields,ranges);
        assembly("memory-safe"){afterHash:=keccak256(add(context,32),original)}
        require(beforeHash==afterHash,"proof or prefix overwritten");
        for(uint256 i;i<n0+n1;++i){
            uint256 first=i<n0?4*i:4*i+1;uint256 expected;uint256 actual;
            for(uint256 j;j<4;++j)expected|=values[first+j]<<(32*j);
            assembly("memory-safe"){actual:=shr(128,mload(add(add(context,32),add(original,mul(i,16)))))}
            require(actual==expected,"cached extension mismatch");
        }
        for(uint256 i=original+16*(n0+n1);i<context.length;++i)require(context[i]==0,"cache guard changed");
    }
    function reject(bytes memory context,uint256 offset,uint256 fields,bytes memory ranges) private view {
        (bool ok,bytes memory error)=address(this).staticcall(abi.encodeCall(this.run,(context,offset,fields,ranges)));
        require(!ok && error.length>0,"invalid cache accepted or OOG");
    }
    function testInvalidRangesAndCacheLengthsRejected() public {
        (bytes memory context,uint256 fields,,bytes memory ranges,)=fixture(bytes32(0),2,3,96);
        reject(context,31,fields,ranges);
        reject(context,context.length+1,fields,ranges);
        reject(context,96,fields,bytes.concat(ranges,hex"01"));
        reject(context,96,fields,abi.encodePacked(uint32(0),uint16(0)));
        reject(context,96,fields,abi.encodePacked(uint32(fields-3),uint16(1)));
        reject(context,96,fields+100,ranges);
        reject(context,96,fields,abi.encodePacked(uint32(0),uint16(6)));
        reject(context,96,fields,abi.encodePacked(uint32(0),uint16(1)));
        bytes memory bad=bytes.concat(context);
        assembly("memory-safe"){mstore(add(bad,96),not(0))}
        reject(bad,96,fields,ranges);
    }
}

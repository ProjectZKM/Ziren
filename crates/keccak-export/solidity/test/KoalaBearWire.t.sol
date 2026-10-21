// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {KoalaBearWire as Wire} from "../src/KoalaBearWire.sol";

contract FieldBufferHarness {
    function validate(bytes calldata data,uint256 offset,uint256 count) external pure returns(bool){
        Wire.validateFields(data,offset,count);return true;
    }
    function validateMemory(bytes memory data,uint256 offset,uint256 count) external pure returns(bool){
        Wire.validateMemoryFields(data,offset,count);return true;
    }
}

contract KoalaBearWireTest {
    uint256 constant P=0x7f000001;
    FieldBufferHarness private immutable target=new FieldBufferHarness();

    function put(bytes memory data,uint256 at,uint256 value) private pure {
        for(uint256 j;j<4;++j)data[at+j]=bytes1(uint8(value>>(8*j)));
    }
    function check(bytes memory data,uint256 offset,uint256 count,bool expected) private view {
        (bool ok,bytes memory result)=address(target).staticcall(abi.encodeCall(target.validate,(data,offset,count)));
        require(ok==expected,"bulk/scalar canonicality mismatch");
        require(expected ? abi.decode(result,(bool)) : result.length==4,"unexpected return/error");
        (ok,result)=address(target).staticcall(abi.encodeCall(target.validateMemory,(data,offset,count)));
        require(ok==expected,"memory/scalar canonicality mismatch");
        require(expected ? abi.decode(result,(bool)) : result.length==4,"unexpected memory return/error");
    }

    function testEveryLaneThresholdAndTrailingHashes() public view {
        uint256[9] memory cases=[uint256(0),1,P-2,P-1,P,P+255,0x7fffffff,0x80000000,0xffffffff];
        for(uint256 count;count<=24;++count){
            bytes memory data=new bytes(38+4*count+32);
            for(uint256 j=38+4*count;j<data.length;++j)data[j]=0xff;
            check(data,38,count,true);
            for(uint256 lane;lane<count;++lane){
                for(uint256 c;c<cases.length;++c){
                    put(data,38+4*lane,cases[c]);check(data,38,count,cases[c]<P);
                }
                put(data,38+4*lane,0);
            }
        }
    }

    function testNeighborLanesDoNotCarry() public view {
        bytes memory data=new bytes(64);
        for(uint256 pattern;pattern<256;++pattern){
            for(uint256 i;i<16;++i)put(data,4*i,(pattern & (1<<(i%8)))==0 ? P-1 : 0x7effffff);
            check(data,0,16,true);
        }
    }

    function testFuzzBulkMatchesScalar(bytes32 seed,uint8 length,uint8 shift) public view {
        uint256 count=uint256(length)%65;
        uint256 offset=uint256(shift)%39;
        bytes memory data=new bytes(offset+4*count+32);
        bool expected=true;
        for(uint256 i;i<count;++i){
            uint256 value=uint32(uint256(keccak256(abi.encode(seed,i))));
            // Exercise valid buffers as well as arbitrary 32-bit invalid data.
            if((uint256(seed)&1)==0)value%=P;
            if(value>=P)expected=false;
            put(data,offset+4*i,value);
        }
        for(uint256 i=offset+4*count;i<data.length;++i)data[i]=0xff;
        check(data,offset,count,expected);
    }

    function testFieldBufferBounds() public view {
        bytes memory data=new bytes(33);
        check(data,1,8,true);
        check(data,2,8,false);
        check(data,34,0,false);
        check(data,0,type(uint256).max,false);
    }
}

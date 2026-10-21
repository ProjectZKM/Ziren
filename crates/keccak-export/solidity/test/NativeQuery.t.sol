// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {NativeQueryEvaluator as Q} from "../src/NativeQueryEvaluator.sol";
import {KoalaBear as F} from "../src/KoalaBear.sol";

contract NativeQueryTest {
    Q evaluator=new Q();
    function field(bytes32 seed,uint256 i) private pure returns(uint256 value){
        uint256 raw=uint256(keccak256(abi.encode(seed,i)));
        for(uint256 j;j<4;++j)value|=(uint256(uint32(raw>>(32*j)))%F.P)<<(32*j);
    }
    function put(bytes memory data,uint256 at,uint256 value,uint256 width) private pure {
        for(uint256 j;j<width;++j)data[at+j]=bytes1(uint8(value>>(8*j)));
    }
    function testFuzzInitialRowsMatchOriginalScalar(bytes32 seed,uint8 roots,uint8 rows,uint8 count) public view {
        uint256 nRoots=1+uint256(roots)%3;uint256 queries=1+uint256(count)%5;uint256 columns;
        uint256[][] memory powers=new uint256[][](nRoots);
        for(uint256 r;r<nRoots;++r){
            uint256 n=1+(uint256(rows)+r)%12;powers[r]=new uint256[](n);columns+=n;
            for(uint256 i;i<n;++i)powers[r][i]=field(seed,100*r+i);
        }
        uint256 point=field(seed,1000);bytes memory packed=new bytes(8*columns*queries);
        uint256[] memory expected=new uint256[](queries);uint256 cursor;
        for(uint256 q;q<queries;++q){
            for(uint256 r;r<nRoots;++r){
                uint256 a;uint256 b;
                for(uint256 i;i<powers[r].length;++i){
                    uint256 x=uint256(keccak256(abi.encode(seed,q,r,i,0)))%F.P;
                    uint256 y=uint256(keccak256(abi.encode(seed,q,r,i,1)))%F.P;
                    put(packed,cursor,x,4);put(packed,cursor+4,y,4);cursor+=8;
                    a=F.add(a,F.scale(powers[r][i],x));b=F.add(b,F.scale(powers[r][i],y));
                }
                expected[q]=F.add(expected[q],F.add(a,F.mul(point,F.sub(b,a))));
            }
        }
        uint256[] memory actual=evaluator.foldInitial(packed,powers,point);
        require(keccak256(abi.encode(actual))==keccak256(abi.encode(expected)),"initial fold mismatch");
    }
    function testFuzzExtensionRowsMatchOriginalMle(bytes32 seed,uint8 size,uint8 count) public view {
        uint256 log=uint256(size)%6;uint256 width=1<<log;uint256 queries=1+uint256(count)%5;
        uint256[] memory point=new uint256[](log);uint256[] memory expected=new uint256[](queries);
        for(uint256 j;j<log;++j)point[j]=field(seed,1000+j);
        bytes memory packed=new bytes(16*width*queries);
        for(uint256 q;q<queries;++q){
            uint256[] memory row=new uint256[](width);
            for(uint256 i;i<width;++i){row[i]=field(seed,q*width+i);put(packed,16*(q*width+i),row[i],16);}
            expected[q]=F.mle(row,point);
        }
        uint256[] memory actual=evaluator.foldRows(packed,point);
        require(keccak256(abi.encode(actual))==keccak256(abi.encode(expected)),"extension fold mismatch");
    }
    function testExtensionMaximumAndBooleanCoordinates() public view {
        uint256 maximum=(F.P-1)*0x1000000010000000100000001;
        uint256[7] memory dimensions=[uint256(0),1,3,4,5,6,8];
        for(uint256 d;d<dimensions.length;++d){
            uint256 log=dimensions[d];uint256 width=1<<log;
            bytes memory packed=new bytes(32*width);
            for(uint256 i;i<width;++i){
                put(packed,16*i,maximum,16);
                put(packed,16*(width+i),i&1==0?0:maximum,16);
            }
            for(uint256 edge;edge<4;++edge){
                uint256[] memory point=new uint256[](log);
                for(uint256 j;j<log;++j)point[j]=edge==0?0:edge==1?1:edge==2?maximum:j&1;
                uint256 expected=log==0?0:F.mul(maximum,point[0]);
                uint256[] memory actual=evaluator.foldRows(packed,point);
                require(actual.length==2 && actual[0]==maximum && actual[1]==expected,"extension maximum/Boolean mismatch");
            }
        }
    }
    function testInitialMaximumAndEmptyQueries() public view {
        uint256[][] memory powers=new uint256[][](2);powers[0]=new uint256[](24);powers[1]=new uint256[](56);
        uint256 maximum=(F.P-1)*0x1000000010000000100000001;uint256 expected;
        for(uint256 r;r<2;++r)for(uint256 i;i<powers[r].length;++i){powers[r][i]=maximum;expected=F.add(expected,F.scale(maximum,F.P-1));}
        bytes memory packed=new bytes(2*80*8);
        for(uint256 i;i<320;++i)put(packed,4*i,F.P-1,4);
        uint256[] memory actual=evaluator.foldInitial(packed,powers,maximum);
        require(actual.length==2 && actual[0]==expected && actual[1]==expected,"maximum initial fold");
        require(evaluator.foldInitial(new bytes(0),powers,1).length==0,"empty initial queries");
        require(evaluator.foldRows(new bytes(0),new uint256[](0)).length==0,"empty extension queries");
    }
    function testInitialEmptyRootsAndZeroOrUnitChallenges() public view {
        uint256[][] memory powers=new uint256[][](3);
        powers[0]=new uint256[](0);powers[1]=new uint256[](1);powers[2]=new uint256[](0);
        powers[1][0]=(F.P-1)*0x1000000010000000100000001;
        bytes memory packed=new bytes(8);put(packed,0,5,4);put(packed,4,7,4);
        for(uint256 point;point<=1;++point){
            uint256[] memory actual=evaluator.foldInitial(packed,powers,point);
            require(actual.length==1 && actual[0]==F.scale(powers[1][0],point==0?5:7),"empty root or edge challenge");
        }
    }
    function rejected(bytes memory data) private view {
        (bool ok,bytes memory error)=address(evaluator).staticcall(data);require(!ok && error.length>0,"malformed query accepted or OOG");
    }
    function testMalformedInputsRejected() public view {
        uint256[][] memory powers=new uint256[][](1);powers[0]=new uint256[](1);powers[0][0]=1;
        rejected(abi.encodeCall(evaluator.foldInitial,(new bytes(7),powers,1)));
        rejected(abi.encodeCall(evaluator.foldInitial,(new bytes(8),new uint256[][](0),1)));
        rejected(abi.encodeCall(evaluator.foldInitial,(new bytes(8),powers,F.P)));
        powers[0][0]=1<<128;rejected(abi.encodeCall(evaluator.foldInitial,(new bytes(8),powers,1)));powers[0][0]=1;
        bytes memory invalid=new bytes(16);put(invalid,0,F.P,4);
        rejected(abi.encodeCall(evaluator.foldInitial,(invalid,powers,1)));
        rejected(abi.encodeCall(evaluator.foldRows,(invalid,new uint256[](0))));
        rejected(abi.encodeCall(evaluator.foldRows,(new bytes(15),new uint256[](0))));
        rejected(abi.encodeCall(evaluator.foldRows,(new bytes(0),new uint256[](25))));
        uint256[] memory point=new uint256[](1);point[0]=F.P;
        rejected(abi.encodeCall(evaluator.foldRows,(new bytes(32),point)));
    }
}

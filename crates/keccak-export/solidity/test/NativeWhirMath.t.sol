// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {NativeWhirMath as N} from "../src/NativeWhirMath.sol";
import {KoalaBear as F} from "../src/KoalaBear.sol";

contract NativeWhirMathTest {
    function normal(uint128 x) private pure returns(uint256 out){
        for(uint256 i;i<4;++i)out|=(uint256(uint32(x>>(32*i)))%F.P)<<(32*i);
    }
    function run(bytes32 seed,uint256 rows,uint256 r,bool edges) private pure {
        uint256 offset=uint256(seed)%33;
        uint256[] memory lambda=new uint256[](rows);bytes memory source=new bytes(offset+rows*8+19);
        uint256 a;uint256 b;
        for(uint256 i;i<rows;++i){
            lambda[i]=edges?(F.P-1)*0x1000000010000000100000001:normal(uint128(uint256(keccak256(abi.encode(seed,i)))));
            uint256 x=edges?F.P-1:uint256(keccak256(abi.encode(seed,i,1)))%F.P;
            uint256 y=edges?F.P-1:uint256(keccak256(abi.encode(seed,i,2)))%F.P;
            for(uint256 j;j<4;++j){source[offset+8*i+j]=bytes1(uint8(x>>(8*j)));source[offset+4+8*i+j]=bytes1(uint8(y>>(8*j)));}
            a=F.add(a,F.scale(lambda[i],x));b=F.add(b,F.scale(lambda[i],y));
        }
        if(edges)for(uint256 i=offset+rows*8;i<source.length;++i)source[i]=0xff;
        uint256 expected=F.add(a,F.mul(r,F.sub(b,a)));
        require(N.firstDot(source,offset,N.firstWeights(lambda,r))==expected,"fused fold mismatch");
    }
    function testFuzzFirstFoldMatchesScalar(bytes32 seed,uint8 rows,uint128 r) public pure {run(seed,1+uint256(rows)%64,normal(r),false);}
    function testFirstFoldMaximalLanes() public pure {run(bytes32(0),56,(F.P-1)*0x1000000010000000100000001,true);}
    function testFirstFoldOddRowsWithPoisonedSuffix() public pure {
        uint256[8] memory rows=[uint256(1),2,3,31,32,56,63,64];
        uint256 maximum=(F.P-1)*0x1000000010000000100000001;
        for(uint256 i;i<rows.length;++i)run(bytes32(uint256(7)),rows[i],maximum,true);
    }
    function testFuzzBasePowerVector(uint32 x,uint8 length) public pure {
        uint256 value=uint256(x)%F.P;uint256 n=uint256(length)%25;
        uint256[] memory expected=F.powers(value,n);uint256[] memory actual=N.basePowers(value,n);
        require(keccak256(abi.encode(expected))==keccak256(abi.encode(actual)),"base power mismatch");
    }
    function testFuzzConsumedMleMatchesReference(bytes32 seed,uint8 logSize) public pure {
        uint256 log=uint256(logSize)%6;
        uint256[] memory row=new uint256[](1<<log);uint256[] memory point=new uint256[](log);
        for(uint256 i;i<row.length;++i)row[i]=normal(uint128(uint256(keccak256(abi.encode(seed,i)))));
        for(uint256 j;j<log;++j)point[j]=normal(uint128(uint256(keccak256(abi.encode(seed,j,1)))));
        uint256 expected=F.mle(row,point);
        require(N.mleDiscard(row,point)==expected,"consumed MLE mismatch");
    }
    function testFuzzMonomialFactorMatchesReference(bytes32 seed,uint8 size,uint8 skip) public pure {
        uint256 n=uint256(size)%25;uint256 start=uint256(skip)%8;
        uint256[] memory point=new uint256[](n);uint256[] memory randomness=new uint256[](n+start);
        uint256 expected=1;
        for(uint256 i;i<n;++i){
            // Include zero and one, where shortcuts often mishandle scalar-1.
            point[i]=i%4==0?0:i%4==1?1:uint256(keccak256(abi.encode(seed,i)))%F.P;
            uint256 y=normal(uint128(uint256(keccak256(abi.encode(seed,i,1)))));
            randomness[start+i]=y;
            expected=F.mul(expected,F.add(F.sub(1,y),F.mul(y,point[i])));
        }
        require(N.monomialFactor(point,randomness,start,n)==expected,"monomial factor mismatch");
    }
}

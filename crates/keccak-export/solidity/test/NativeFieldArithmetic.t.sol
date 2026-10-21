// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {NativeFieldArithmetic as N} from "../src/NativeFieldArithmetic.sol";
import {KoalaBear as F} from "../src/KoalaBear.sol";

contract NativeFieldArithmeticTest {
    uint256 constant P=0x7f000001;
    function normal(uint128 value) private pure returns(uint256 out){
        for(uint256 i;i<4;++i)out|=(uint256(uint32(value>>(32*i)))%P)<<(32*i);
    }
    function check(uint256 a,uint256 b) private pure {
        uint256 sum;uint256 difference;
        for(uint256 i;i<4;++i){
            uint256 ai=uint32(a>>(32*i));uint256 bi=uint32(b>>(32*i));
            sum|=addmod(ai,bi,P)<<(32*i);
            difference|=addmod(ai,P-bi,P)<<(32*i);
        }
        require(N.add(a,b)==sum,"packed sum mismatch");
        require(N.sub(a,b)==difference,"packed difference mismatch");
    }
    function testFuzzPackedArithmetic(uint128 a,uint128 b) public pure {
        check(normal(a),normal(b));
    }
    function referenceMul(uint256 a,uint256 b) private pure returns(uint256 result){
        uint256[4] memory coefficients;
        for(uint256 i;i<4;++i)for(uint256 j;j<4;++j){
            uint256 value=mulmod(uint32(a>>(32*i)),uint32(b>>(32*j)),P);
            if(i+j>=4)value=mulmod(value,3,P);
            uint256 k=(i+j)%4;
            coefficients[k]=addmod(coefficients[k],value,P);
        }
        for(uint256 i;i<4;++i)result|=coefficients[i]<<(32*i);
    }
    function testFuzzTowerMulmodAgainstScalarConvolution(uint128 a,uint128 b) public pure {
        uint256 left=normal(a);uint256 right=normal(b);
        uint256 expected=referenceMul(left,right);
        require(N.mul(left,right)==expected,"tower convolution mismatch");
        require(F.mul(left,right)==expected,"selected field convolution mismatch");
        require(N.mul(left,1)==left && N.mul(1,right)==right,"tower identity mismatch");
        require(N.mul(left,0)==0 && N.mul(0,right)==0,"tower zero mismatch");
    }
    function testTowerMulmodLaneBoundaries() public pure {
        uint256[4] memory edges=[uint256(0),1,P-2,P-1];
        for(uint256 i;i<4;++i)for(uint256 j;j<4;++j){
            uint256 a=edges[i]*0x1000000010000000100000001;
            uint256 b=edges[j]*0x1000000010000000100000001;
            require(N.mul(a,b)==referenceMul(a,b),"tower maximal lanes");
            for(uint256 x;x<4;++x)for(uint256 y;y<4;++y){
                a=edges[i]<<(32*x);b=edges[j]<<(32*y);
                require(N.mul(a,b)==referenceMul(a,b),"tower basis product");
            }
        }
    }
    function testArithmeticLaneBoundaries() public pure {
        uint256[8] memory edges=[uint256(0),1,P/2,P/2+1,0x00ffffff,P-2,P-1,0x01000000];
        for(uint256 i;i<edges.length;++i){
            for(uint256 j;j<edges.length;++j){
                // Replicated and adjacent lanes exercise carry/borrow boundaries.
                check(edges[i]*0x1000000010000000100000001,edges[j]*0x1000000010000000100000001);
                for(uint256 lane;lane<4;++lane)check(edges[i]<<(32*lane),edges[j]<<(32*((lane+1)%4)));
            }
        }
    }
}

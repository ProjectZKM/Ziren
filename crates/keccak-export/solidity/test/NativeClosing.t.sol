// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {NativeClosingEvaluator as C} from "../src/NativeClosingEvaluator.sol";
import {NativeClosingMath as M} from "../src/NativeClosingMath.sol";
import {KoalaBear as F} from "../src/KoalaBear.sol";

contract NativeClosingTest {
    C evaluator=new C();
    function field(bytes32 seed,uint256 i) private pure returns(uint256 value){
        uint256 raw=uint256(keccak256(abi.encode(seed,i)));
        for(uint256 j;j<4;++j)value|=(uint256(uint32(raw>>(32*j)))%F.P)<<(32*j);
    }
    function baselineClosing(uint256[] memory r,uint256[] memory poly,uint256[] memory point,uint256 coeff,bool mono)
        private pure returns(uint256 out){
        uint256 finalLog;for(uint256 size=poly.length;size>1;size>>=1)++finalLog;
        uint256 k=point.length-finalLog;uint256 factor=1;
        for(uint256 j;j<k;++j){
            uint256 y=r[r.length-k+j];
            factor=F.mul(factor,mono?F.add(F.sub(1,y),F.mul(y,point[j]))
                :F.add(F.mul(point[j],y),F.mul(F.sub(1,point[j]),F.sub(1,y))));
        }
        uint256 eval=mono?F.hornerBase(poly,finalLog==0?0:point[k]):F.mle(poly,F.slice(point,k,finalLog));
        out=F.mul(coeff,F.mul(factor,eval));
    }
    function testFuzzPairedFactorMatchesOriginal(bytes32 seed,uint8 size,uint32 base) public pure {
        uint256 n=uint256(size)%25;uint256[] memory r=new uint256[](n);
        for(uint256 i;i<n;++i)r[i]=field(seed,i);
        uint256 x=uint256(base)%F.P;uint256 expected=1;uint256 power=x;
        for(uint256 i;i<n;++i){expected=F.mul(expected,F.add(F.sub(1,r[i]),F.scale(r[i],power)));power=mulmod(power,power,F.P);}
        (uint256 actual,uint256 finalX)=M.evaluate(M.prepare(r,n),n,x);
        require(actual==expected && finalX==power,"paired factor mismatch");
    }
    function testFuzzPreparedPolynomialMatchesOriginal(bytes32 seed,uint8 logSize,uint32 base) public pure {
        uint256[] memory poly=new uint256[](1<<(uint256(logSize)%7));
        for(uint256 i;i<poly.length;++i)poly[i]=field(seed,i);
        uint256 x=uint256(base)%F.P;
        require(M.hornerPrepared(M.preparePolynomial(poly),x)==F.hornerBase(poly,x),"prepared polynomial mismatch");
    }
    function testPreparedPolynomialMaximalLanes() public pure {
        for(uint256 log;log<7;++log){
            uint256[] memory poly=new uint256[](1<<log);
            for(uint256 i;i<poly.length;++i)poly[i]=(F.P-1)*0x1000000010000000100000001;
            uint256[] memory wide=M.preparePolynomial(poly);
            require(M.hornerPrepared(wide,0)==F.hornerBase(poly,0),"zero polynomial argument");
            require(M.hornerPrepared(wide,1)==F.hornerBase(poly,1),"unit polynomial argument");
            require(M.hornerPrepared(wide,F.P-1)==F.hornerBase(poly,F.P-1),"maximal polynomial argument");
        }
        // The math helper also accepts even lengths that are not powers of
        // two, although the complete verifier's final polynomial is dyadic.
        for(uint256 n=2;n<=34;n+=4){
            uint256[] memory poly=new uint256[](n);
            for(uint256 i;i<n;++i)poly[i]=(F.P-1)*0x1000000010000000100000001;
            uint256[] memory wide=M.preparePolynomial(poly);
            require(M.hornerPrepared(wide,0)==F.hornerBase(poly,0),"remainder zero");
            require(M.hornerPrepared(wide,1)==F.hornerBase(poly,1),"remainder one");
            require(M.hornerPrepared(wide,F.P-1)==F.hornerBase(poly,F.P-1),"remainder maximal");
        }
    }
    function testFuzzMixedClosingMatchesOriginal(bytes32 seed,uint8 size,uint8 logSize,uint32 base) public view {
        uint256 finalLog=uint256(logSize)%6;uint256 n=uint256(size)%17;uint256 k=n==0?0:uint256(uint8(seed[0]))%(n+1);
        uint256 vars=k+finalLog;uint256[] memory r=new uint256[](n);uint256[] memory poly=new uint256[](1<<finalLog);
        for(uint256 i;i<n;++i)r[i]=field(seed,i);
        for(uint256 i;i<poly.length;++i)poly[i]=field(seed,100+i);
        uint256[] memory requests=new uint256[](5+vars);uint256 cursor;uint256 expected;
        for(uint256 q;q<4;++q){
            uint256 x=q==0?uint256(base)%F.P:q==1?0:q==2?1:F.P-1;uint256 coeff=field(seed,200+q);
            uint256 queryK=q==1?n:q==2?0:k;uint256 queryVars=queryK+finalLog;
            requests[cursor++]=coeff|(queryVars<<128)|(1<<136)|(x<<160);
            expected=F.add(expected,baselineClosing(r,poly,F.powers(x,queryVars),coeff,true));
        }
        uint256 pointCoeff=field(seed,300);requests[cursor++]=pointCoeff|(vars<<128);
        uint256[] memory point=new uint256[](vars);
        for(uint256 i;i<vars;++i){point[i]=field(seed,400+i);requests[cursor++]=point[i];}
        expected=F.add(expected,baselineClosing(r,poly,point,pointCoeff,false));
        require(evaluator.evaluate(r,poly,requests)==expected,"closing total mismatch");
    }
    function testFuzzAffineClosingSegments(bytes32 seed,uint8 size,uint8 logSize) public view {
        uint256 finalLog=uint256(logSize)%6;uint256 n=uint256(size)%(25-finalLog);
        uint256[] memory r=new uint256[](n);uint256[] memory poly=new uint256[](1<<finalLog);
        uint256 maximal=(F.P-1)*0x1000000010000000100000001;
        for(uint256 i;i<n;++i){
            uint256 mode=(i+uint8(seed[1]))%7;
            r[i]=mode==0?0:mode==1?1:mode==2?maximal:field(seed,i);
        }
        for(uint256 i;i<poly.length;++i)poly[i]=field(seed,100+i);
        uint256[4] memory widths=[uint256(0),n,n/2,uint256(uint8(seed[0]))%(n+1)];
        uint256 length=4+4*finalLog;for(uint256 q;q<4;++q)length+=widths[q];
        uint256[] memory requests=new uint256[](length);uint256 cursor;uint256 expected;
        for(uint256 q;q<4;++q){
            uint256 vars=widths[q]+finalLog;uint256 coeff=q==0?0:field(seed,200+q);
            requests[cursor++]=coeff|(vars<<128);uint256[] memory point=new uint256[](vars);
            for(uint256 j;j<vars;++j){
                point[j]=q==0?0:q==1?1:q==2?maximal:field(seed,300+j);
                requests[cursor++]=point[j];
            }
            expected=F.add(expected,baselineClosing(r,poly,point,coeff,false));
        }
        require(cursor==requests.length && evaluator.evaluate(r,poly,requests)==expected,"affine segment mismatch");
    }
    function reject(uint256[] memory r,uint256[] memory poly,uint256[] memory requests) private view {
        (bool ok,bytes memory error)=address(evaluator).staticcall(abi.encodeCall(evaluator.evaluate,(r,poly,requests)));
        require(!ok && error.length>0,"malformed closing accepted or OOG");
    }
    function testMalformedClosingInputsRejected() public view {
        uint256[] memory r=new uint256[](1);r[0]=1;uint256[] memory poly=new uint256[](2);poly[0]=1;
        uint256[] memory requests=new uint256[](1);requests[0]=1|(uint256(2)<<128)|(uint256(1)<<136)|(uint256(3)<<160);
        require(evaluator.evaluate(r,poly,requests)==3,"honest closing");
        uint256 header=requests[0];
        requests[0]=header|(1<<192);reject(r,poly,requests);
        requests[0]=header|(1<<137);reject(r,poly,requests);
        requests[0]=F.P|(uint256(2)<<128)|(uint256(1)<<136);reject(r,poly,requests);
        requests[0]=1|(uint256(3)<<128)|(uint256(1)<<136);reject(r,poly,requests);
        requests[0]=1|(uint256(1)<<136);reject(r,poly,requests);
        requests[0]=1|(uint256(2)<<128)|(uint256(1)<<136)|(F.P<<160);reject(r,poly,requests);
        requests[0]=1|(uint256(2)<<128);reject(r,poly,requests); // missing coordinates
        requests[0]=header;r[0]=1<<128;reject(r,poly,requests);r[0]=1;
        poly[0]=F.P;reject(r,poly,requests);poly[0]=1;
        reject(r,new uint256[](0),requests);reject(r,new uint256[](3),requests);
        uint256[] memory badPoint=new uint256[](3);badPoint[0]=1|(uint256(2)<<128);badPoint[1]=F.P;
        reject(r,poly,badPoint);
    }
}

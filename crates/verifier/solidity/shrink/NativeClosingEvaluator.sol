// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {KoalaBear as F} from "./KoalaBear.sol";
import {NativeClosingMath as M} from "./NativeClosingMath.sol";
import {INativeClosingEvaluator} from "./INativeClosingEvaluator.sol";

/// Auxiliary deterministic closing arithmetic, not a proof verifier. The full
/// entry computes all requests on chain and the WHIR tail pins this runtime.
contract NativeClosingEvaluator is INativeClosingEvaluator {
    error InvalidClosingInput();

    function evaluate(uint256[] calldata randomness,uint256[] calldata finalPoly,uint256[] calldata requests)
        external pure returns(uint256 total) {
        uint256 length=finalPoly.length;
        if(length==0 || length&(length-1)!=0)revert InvalidClosingInput();
        uint256 finalLog;
        while(length>1){length>>=1;++finalLog;}
        if(finalLog>24 || randomness.length>24-finalLog)revert InvalidClosingInput();
        for(uint256 i;i<randomness.length;++i)if(!F.canonical(randomness[i]))revert InvalidClosingInput();
        for(uint256 i;i<finalPoly.length;++i)if(!F.canonical(finalPoly[i]))revert InvalidClosingInput();
        uint256[] memory r=randomness;uint256[] memory polynomial=finalPoly;
        uint256[] memory widePolynomial=M.preparePolynomial(polynomial);
        uint256[][] memory caches=new uint256[][](r.length+1);uint256 prepared;
        uint256 cursor;
        while(cursor<requests.length){
            uint256 header=requests[cursor++];uint256 coeff=uint128(header);
            uint256 vars=uint8(header>>128);bool monomial=(header>>136)&1!=0;
            uint256 x=uint32(header>>160);
            if(header>>192!=0 || (header>>137)&0x7fffff!=0 || !F.canonical(coeff)
                || vars<finalLog || vars>r.length+finalLog)revert InvalidClosingInput();
            uint256 k=vars-finalLog;uint256 factor;uint256 evaluation;
            if(monomial){
                if(x>=F.P)revert InvalidClosingInput();
                if(prepared&(1<<k)==0){caches[k]=M.prepare(r,k);prepared|=1<<k;}
                uint256 finalX;
                (factor,finalX)=M.evaluate(caches[k],k,x);
                evaluation=M.hornerPrepared(widePolynomial,finalX);
            }else{
                if(x!=0 || vars>requests.length-cursor)revert InvalidClosingInput();
                uint256[] memory point=new uint256[](vars);
                for(uint256 j;j<vars;++j){
                    uint256 value=requests[cursor++];
                    if(!F.canonical(value))revert InvalidClosingInput();
                    point[j]=value;
                }
                factor=1;
                for(uint256 j;j<k;++j){
                    uint256 y=r[r.length-k+j];
                    // eq(point,y) = (1-y) + (2*y-1)*point.
                    factor=F.mul(factor,F.add(F.sub(1,y),F.mul(point[j],F.sub(F.add(y,y),1))));
                }
                evaluation=F.mle(polynomial,F.slice(point,k,finalLog));
            }
            total=F.add(total,F.mul(coeff,F.mul(factor,evaluation)));
        }
    }
}

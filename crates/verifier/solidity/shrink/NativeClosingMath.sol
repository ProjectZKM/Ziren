// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {KoalaBear as F} from "./KoalaBear.sol";

/// Paired monomial factors over the original KoalaBear E4 basis.
library NativeClosingMath {
    function preparePolynomial(uint256[] memory coefficients) internal pure returns(uint256[] memory wide){
        wide=new uint256[](coefficients.length);
        assembly("memory-safe") {
            let src:=add(coefficients,32)
            let dst:=add(wide,32)
            let end:=add(src,mul(mload(coefficients),32))
            let mask:=0xffffffff
            for {} lt(src,end) {src:=add(src,32) dst:=add(dst,32)} {
                let value:=mload(src)
                mstore(dst,or(or(and(value,mask),shl(64,and(shr(32,value),mask))),or(shl(128,and(shr(64,value),mask)),shl(192,shr(96,value)))))
            }
        }
    }

    /// Two Horner steps per reduction. Each radix-64 lane is bounded by
    /// 2*(p-1)^2+(p-1)<2^63, so carries and 256-bit overflow are impossible.
    function hornerPrepared(uint256[] memory wide,uint256 x) internal pure returns(uint256 result){
        require(wide.length>0 && (wide.length==1 || wide.length%2==0) && x<F.P,"closing polynomial");
        assembly("memory-safe") {
            let start:=add(wide,32)
            let at:=add(start,mul(mload(wide),32))
            let acc:=0
            let p:=0x7f000001
            let mask:=0xffffffffffffffff
            let x2:=mulmod(x,x,p)
            switch eq(mload(wide),1)
            case 1 {acc:=mload(start)}
            default {
                for {} gt(at,start) {} {
                    at:=sub(at,64)
                    let product:=add(add(mul(acc,x2),mul(mload(add(at,32)),x)),mload(at))
                    acc:=or(or(mod(and(product,mask),p),shl(64,mod(and(shr(64,product),mask),p))),or(shl(128,mod(and(shr(128,product),mask),p)),shl(192,mod(shr(192,product),p))))
                }
            }
            result:=or(or(and(acc,0xffffffff),shl(32,and(shr(64,acc),0xffffffff))),or(shl(64,and(shr(128,acc),0xffffffff)),shl(96,shr(192,acc))))
        }
    }

    function prepare(uint256[] memory randomness,uint256 k) internal pure returns(uint256[] memory cache){
        require(k<=randomness.length,"closing dimension");
        uint256 pairs=k/2;uint256 start=randomness.length-k;
        cache=new uint256[](4*pairs+1);
        for(uint256 i;i<pairs;++i){
            uint256 r=randomness[start+2*i];uint256 s=randomness[start+2*i+1];
            uint256 rs=F.mul(r,s);
            uint256 a=F.add(F.sub(F.sub(1,r),s),rs);
            uint256 b=F.sub(r,rs);uint256 c=F.sub(s,rs);
            for(uint256 lane;lane<4;++lane){
                cache[4*i+lane]=uint256(uint32(a>>(32*lane)))
                    |(uint256(uint32(b>>(32*lane)))<<64)
                    |(uint256(uint32(c>>(32*lane)))<<128)
                    |(uint256(uint32(rs>>(32*lane)))<<192);
            }
        }
        if(k&1!=0)cache[4*pairs]=randomness[start+k-1];
    }

    /// Each convolution limb is <4*p^2<2^64. Truncating MUL at 256 bits
    /// leaves the complete cubic dot in its highest limb without carries.
    function evaluate(uint256[] memory cache,uint256 k,uint256 x) internal pure returns(uint256 factor,uint256 finalX){
        require(x<F.P && cache.length==4*(k/2)+1,"closing cache");
        uint256 pairs=k/2;factor=1;
        for(uint256 i;i<pairs;++i){
            uint256 pair;
            assembly("memory-safe") {
                let p:=0x7f000001
                let x2:=mulmod(x,x,p)
                let x3:=mulmod(x2,x,p)
                let powers:=or(or(x3,shl(64,x2)),or(shl(128,x),shl(192,1)))
                let at:=add(add(cache,32),mul(i,128))
                pair:=or(or(mod(shr(192,mul(mload(at),powers)),p),shl(32,mod(shr(192,mul(mload(add(at,32)),powers)),p))),or(shl(64,mod(shr(192,mul(mload(add(at,64)),powers)),p)),shl(96,mod(shr(192,mul(mload(add(at,96)),powers)),p))))
                x:=mulmod(x2,x2,p)
            }
            factor=i==0?pair:F.mul(factor,pair);
        }
        if(k&1!=0){
            uint256 r=cache[4*pairs];
            uint256 term=F.add(1,F.scale(r,(x+F.P-1)%F.P));
            factor=pairs==0?term:F.mul(factor,term);
            x=mulmod(x,x,F.P);
        }
        finalX=x;
    }
}

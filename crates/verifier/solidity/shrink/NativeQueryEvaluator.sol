// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {NativeClosingEvaluator} from "./NativeClosingEvaluator.sol";
import {INativeQueryEvaluator} from "./INativeQueryEvaluator.sol";
import {NativeWhirMath as N} from "./NativeWhirMath.sol";
import {KoalaBear as F} from "./KoalaBear.sol";
import {KoalaBearWire as Wire} from "./KoalaBearWire.sol";

/// Deterministic query arithmetic in the same pinned module as closing math.
/// The WHIR tail authenticates all leaves/paths and checks the resulting claims.
contract NativeQueryEvaluator is NativeClosingEvaluator,INativeQueryEvaluator {
    function foldInitial(bytes calldata fields,uint256[][] calldata lambdaPowers,uint256 point)
        external pure returns(uint256[] memory values) {
        if(!F.canonical(point))revert InvalidClosingInput();
        uint256 columns;uint256[][] memory weights=new uint256[][](lambdaPowers.length);
        for(uint256 r;r<lambdaPowers.length;++r){
            if(lambdaPowers[r].length>32767)revert InvalidClosingInput();
            for(uint256 i;i<lambdaPowers[r].length;++i)if(!F.canonical(lambdaPowers[r][i]))revert InvalidClosingInput();
            columns+=lambdaPowers[r].length;
            weights[r]=N.firstWeights(lambdaPowers[r],point);
        }
        uint256 stride=8*columns;
        if(stride==0 || fields.length%stride!=0)revert InvalidClosingInput();
        Wire.validateFields(fields,0,fields.length/4);
        bytes memory packed=fields;values=new uint256[](fields.length/stride);
        for(uint256 q;q<values.length;++q){
            uint256 offset=q*stride;uint256 total;
            for(uint256 r;r<weights.length;++r){
                total=F.add(total,N.firstDot(packed,offset,weights[r]));
                offset+=8*lambdaPowers[r].length;
            }
            values[q]=total;
        }
    }

    function foldRows(bytes calldata fields,uint256[] calldata point)
        external pure returns(uint256[] memory values) {
        if(point.length>24)revert InvalidClosingInput();
        for(uint256 i;i<point.length;++i)if(!F.canonical(point[i]))revert InvalidClosingInput();
        uint256 width=1<<point.length;uint256 stride=16*width;
        if(fields.length%stride!=0)revert InvalidClosingInput();
        Wire.validateFields(fields,0,fields.length/4);
        bytes memory packed=fields;uint256[] memory coordinates=point;
        values=new uint256[](fields.length/stride);
        for(uint256 q;q<values.length;++q){
            values[q]=N.mleDiscard(F.packedExtensions(packed,q*stride,width),coordinates);
        }
    }
}

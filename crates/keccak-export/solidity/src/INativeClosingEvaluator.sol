// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

interface INativeClosingEvaluator {
    function evaluate(uint256[] calldata randomness,uint256[] calldata finalPoly,uint256[] calldata requests)
        external pure returns(uint256 total);
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

interface INativeQueryEvaluator {
    function foldInitial(bytes calldata fields,uint256[][] calldata lambdaPowers,uint256 point)
        external pure returns(uint256[] memory values);
    function foldRows(bytes calldata fields,uint256[] calldata point)
        external pure returns(uint256[] memory values);
}

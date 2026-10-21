// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {NativeMerklePath as M} from "../src/NativeMerklePath.sol";

contract NativeMerklePathHarness {
    error InvalidPathView();
    function packed(bytes32 hash,uint256 index,uint256 height,bytes memory source,uint256 offset) external pure returns(bytes32) {
        if(height>24 || index>=1<<height || offset>source.length || height>(source.length-offset)/32) revert InvalidPathView();
        uint256 pointer;assembly("memory-safe"){pointer:=add(add(source,32),offset)}
        return M.walk(hash,index,height,pointer);
    }
    function materialized(bytes32 hash,uint256 index,bytes32[] memory path) external pure returns(bytes32) {
        if(path.length>24 || index>=1<<path.length) revert InvalidPathView();
        uint256 pointer;assembly("memory-safe"){pointer:=add(path,32)}
        return M.walk(hash,index,path.length,pointer);
    }
}

contract NativeMerklePathTest {
    NativeMerklePathHarness h=new NativeMerklePathHarness();
    function scalarRoot(bytes32 hash,uint256 index,bytes32[] memory path) private pure returns(bytes32) {
        for(uint256 i;i<path.length;++i){
            hash=(index&1)==0?keccak256(abi.encodePacked(hash,path[i])):keccak256(abi.encodePacked(path[i],hash));index>>=1;
        }
        return hash;
    }
    function testFuzzFullWordsAndUnalignedViews(bytes32 seed,uint8 height,uint32 index,uint8 offset) public view {
        height%=25;index=uint32(uint256(index)% (1<<height));offset%=65;
        bytes32[] memory path=new bytes32[](height);
        bytes memory source=new bytes(uint256(offset)+32*uint256(height)+17);
        for(uint256 i;i<height;++i){
            bytes32 value=keccak256(abi.encode(seed,i));path[i]=value;
            assembly("memory-safe"){mstore(add(add(add(source,32),offset),mul(i,32)),value)}
        }
        bytes32 expected=scalarRoot(seed,index,path);
        require(h.packed(seed,index,height,source,offset)==expected,"packed path mismatch");
        require(h.materialized(seed,index,path)==expected,"materialized path mismatch");
    }
    function testRejectsInvalidViewBoundsAndIndex() public view {
        for(uint256 mode;mode<5;++mode){
            (bool ok,bytes memory error)=address(h).staticcall(abi.encodeCall(h.packed,(bytes32(uint256(1)),mode==4?2:0,mode==3?25:1,new bytes(mode==2?31:32),mode==0?33:mode==1?1:0)));
            require(!ok && error.length==4 && bytes4(error)==NativeMerklePathHarness.InvalidPathView.selector,"invalid view accepted or OOG");
        }
    }
}

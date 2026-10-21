// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {HashDictionaryWire as D} from "../src/HashDictionaryWire.sol";

contract DictionaryHarness {
    function decode(bytes calldata encoded,uint256 fields,uint256 hashes) external pure returns(bytes memory result) {
        uint256 length=38+4*fields+32*hashes;
        bytes memory context=new bytes(length+64);
        bytes32 guard=bytes32(type(uint256).max);
        assembly("memory-safe") {
            // The destination deliberately contains old scratch data. Zero
            // runs must actively clear it without touching either guard.
            let end:=add(add(context,64),length)
            for{let at:=add(context,64)}lt(at,end){at:=add(at,32)}{mstore(at,not(0))}
            mstore(add(context,32),guard) mstore(end,guard)
        }
        D.decodeInto(encoded,context,32,fields,hashes);
        assembly("memory-safe") {
            if or(iszero(eq(mload(add(context,32)),guard)),iszero(eq(mload(add(add(context,64),length)),guard))) {revert(0,0)}
        }
        result=new bytes(length);
        assembly("memory-safe") {mcopy(add(result,32),add(context,64),length)}
    }
}

contract HashDictionaryWireTest {
    DictionaryHarness h=new DictionaryHarness();

    function fixture(bytes32 seed,uint256 fields,uint256 hashes) private pure returns(bytes memory encoded,bytes memory raw) {
        bytes memory prefix=new bytes(38+4*fields);
        prefix[0]=0x5a;prefix[1]=0x4b;prefix[2]=0x45;prefix[3]=0x54;prefix[4]=0x01;
        for(uint256 i=6;i<prefix.length;++i) prefix[i]=bytes1(uint8(i));
        raw=bytes.concat(prefix);
        prefix[5]=0x02;
        uint256 count=hashes<7?hashes:7;
        encoded=bytes.concat(prefix);
        if(count!=0) encoded=bytes.concat(encoded,bytes2(uint16(0x8000+count)));
        for(uint256 i;i<count;++i) encoded=bytes.concat(encoded,keccak256(abi.encode(seed,i)));
        for(uint256 i;i<hashes;++i){
            uint256 index=i%count;
            if(i>=count) encoded=bytes.concat(encoded,bytes2(uint16(index)));
            raw=bytes.concat(raw,keccak256(abi.encode(seed,index)));
        }
    }

    function testFuzzLosslessFullDigestAndBounds(bytes32 seed,uint8 fields,uint8 hashes) public view {
        fields%=33;hashes%=65;
        (bytes memory packed,bytes memory raw)=fixture(seed,fields,hashes);
        require(keccak256(h.decode(packed,fields,hashes))==keccak256(raw),"lossless packet/guard mismatch");
    }

    function rejected(bytes memory packet,uint256 fields,uint256 hashes) private view {
        (bool ok,bytes memory error)=address(h).staticcall(abi.encodeCall(h.decode,(packet,fields,hashes)));
        require(!ok && error.length==4 && bytes4(error)==D.InvalidHashDictionary.selector,"accepted malformed dictionary or OOG");
    }

    function testRejectDictionaryLengthCountAndIndex() public view {
        (bytes memory packed,)=fixture(bytes32(uint256(19)),2,13);
        rejected(bytes.concat(packed,hex"00"),2,13);
        bytes memory short=bytes.concat(packed);
        assembly("memory-safe"){mstore(short,sub(mload(short),1))}
        rejected(short,2,13);
        bytes memory bad=bytes.concat(packed);bad[46]=0;bad[47]=0;rejected(bad,2,13);
        bad=bytes.concat(packed);bad[46]=0x80;bad[47]=0x0e;rejected(bad,2,13);
        bad=bytes.concat(packed);bad[46]=0x80;bad[47]=0;rejected(bad,2,13);
        bad=bytes.concat(packed);bad[48+7*32]=0;bad[49+7*32]=0x07;rejected(bad,2,13);
        rejected(hex"0000",2,13);
        rejected(packed,2,32769);
    }

    function testAllDigestBytesSurvive() public view {
        (bytes memory packed,bytes memory raw)=fixture(bytes32(type(uint256).max),0,1);
        for(uint256 i;i<32;++i){packed[40+i]=bytes1(uint8(i*7+1));raw[38+i]=packed[40+i];}
        require(keccak256(h.decode(packed,0,1))==keccak256(raw),"digest truncated");
    }

    function slice(bytes memory data,uint256 at,uint256 count) private pure returns(bytes memory part){
        require(at<=data.length && count<=data.length-at,"test slice");part=new bytes(count);
        assembly("memory-safe"){mcopy(add(part,32),add(add(data,32),at),count)}
    }
    function zeroFixture(bytes32 seed,uint256 fields,uint256 hashes) private pure returns(bytes memory packed,bytes memory raw){
        (bytes memory hashPacket,bytes memory hashRaw)=fixture(seed,0,hashes);
        bytes memory header=slice(hashPacket,0,38);header[5]=0x03;
        packed=header;bytes memory fieldBytes=new bytes(4*fields);
        uint256 done;bool zero=true;
        while(done<fields){
            uint256 count=1+(uint256(keccak256(abi.encode(seed,done)))%12);
            if(count>fields-done)count=fields-done;
            if(zero){packed=bytes.concat(packed,bytes2(uint16(count)));}
            else{
                bytes memory literal=new bytes(4*count);
                for(uint256 i;i<count;++i){
                    uint256 value=uint32(uint256(keccak256(abi.encode(seed,done+i))));
                    for(uint256 b;b<4;++b){bytes1 item=bytes1(uint8(value>>(8*b)));literal[4*i+b]=item;fieldBytes[4*(done+i)+b]=item;}
                }
                packed=bytes.concat(packed,bytes2(uint16(0x8000+count)),literal);
            }
            done+=count;zero=!zero;
        }
        packed=bytes.concat(packed,slice(hashPacket,38,hashPacket.length-38));
        raw=bytes.concat(slice(hashRaw,0,38),fieldBytes,slice(hashRaw,38,hashRaw.length-38));
    }
    function testFuzzFieldZeroRunsPreserveEveryByteAndDirtyMemory(bytes32 seed,uint8 fields,uint8 hashes) public view {
        fields%=65;hashes%=33;
        (bytes memory packed,bytes memory raw)=zeroFixture(seed,fields,hashes);
        require(keccak256(h.decode(packed,fields,hashes))==keccak256(raw),"zero-run packet or memory guard mismatch");
    }
    function testRejectMalformedFieldZeroRuns() public view {
        (bytes memory header,)=fixture(bytes32(0),0,0);header[5]=0x03;
        bytes memory honest=bytes.concat(header,hex"0008");
        bytes memory expected=bytes.concat(slice(header,0,5),hex"00",slice(header,6,32),new bytes(32));
        require(keccak256(h.decode(honest,8,0))==keccak256(expected),"zero-run honest packet");
        for(uint256 i;i<4;++i){
            bytes2 command=i==0?bytes2(0):i==1?bytes2(uint16(9)):i==2?bytes2(uint16(0x8000)):bytes2(uint16(0x8008));
            rejected(bytes.concat(header,command),8,0);
        }
        rejected(bytes.concat(header,hex"00"),8,0);
        rejected(bytes.concat(header,hex"8008",new bytes(31)),8,0);
        rejected(bytes.concat(honest,hex"00"),8,0);
        require(keccak256(h.decode(bytes.concat(header,hex"00030005"),8,0))==keccak256(expected),"split zero run");
    }
}

"""Native-only transcript kernels; original Solidity remains the reference."""

def _replace(source,name,replacement):
    start=source.index('    function '+name+'(');at=source.index('{',start);end=at+1;depth=1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[:start]+replacement+source[end:]


def native_transcript(source):
    original_check='''        require(
            uint32(e) < 0x7f000001 && uint32(e >> 32) < 0x7f000001 && uint32(e >> 64) < 0x7f000001
                && uint32(e >> 96) < 0x7f000001,
            "canonical transcript extension"
        );'''
    assert source.count(original_check)==1
    source=source.replace(original_check,'''        bool valid;
        assembly("memory-safe") {
            // Original API checks only the four low lanes. An existing sign
            // bit rejects immediately; otherwise the biased sum cannot carry
            // between lanes and its sign bit identifies exactly x>=p.
            valid:=iszero(and(or(e,add(and(e,0xffffffffffffffffffffffffffffffff),0x00ffffff00ffffff00ffffff00ffffff)),0x80000000800000008000000080000000))
        }
        require(valid,"canonical transcript extension");''',1)
    resume='''    function resume(bytes32 digest, bytes memory buffered, uint256 wordsLeft) internal pure returns (State memory s) {
        require(buffered.length < 100 && wordsLeft <= 8, "transcript shape");
        s.digest = digest;
        s.payload = new bytes(164);
        s.pending = buffered.length;
        s.wordsLeft = wordsLeft;
        bytes memory payload=s.payload;
        assembly("memory-safe"){mcopy(add(payload,64),add(buffered,32),mload(buffered))}
    }'''
    append='''    function append(State memory s, uint256 value, uint256 count) private pure {
        assembly("memory-safe") {
            mstore(add(s,96),0)
            let payload:=mload(add(s,32))
            for {} count {} {
                let pending:=mload(add(s,64))
                // Match the original checked subtraction on malformed state.
                if gt(pending,100){mstore(0,shl(224,0x4e487b71)) mstore(4,0x11) revert(0,36)}
                let take:=sub(100,pending)
                if lt(count,take){take:=count}
                mstore(add(add(payload,64),pending),value)
                pending:=add(pending,take)
                mstore(add(s,64),pending)
                if eq(pending,100){
                    mstore(add(payload,32),mload(s))
                    mstore(s,keccak256(add(payload,32),132))
                    mstore(add(s,64),0)
                }
                count:=sub(count,take) value:=shl(mul(8,take),value)
            }
        }
    }'''
    word='''    function word(State memory s) internal pure returns (uint256 r) {
        uint256 index = 8 - s.wordsLeft;
        assembly("memory-safe") {
            let left:=sub(8,index)
            if iszero(left){
                let payload:=mload(add(s,32))
                mstore(add(payload,32),mload(s))
                mstore(s,keccak256(add(payload,32),add(mload(add(s,64)),32)))
                mstore(add(s,64),0) left:=8
            }
            let at:=mul(4,sub(8,left))
            mstore(add(s,96),sub(left,1))
            let h:=mload(s)
            r:=or(or(byte(at,h),shl(8,byte(add(at,1),h))),or(shl(16,byte(add(at,2),h)),shl(24,byte(add(at,3),h))))
        }
    }'''
    sample='''    function sampleE(State memory s) internal pure returns (uint256 r) {
        // Separate statements fix draw order; every lane retains rejection.
        r = sample(s);
        r |= sample(s) << 32;
        r |= sample(s) << 64;
        r |= sample(s) << 96;
    }'''
    for name,text in (('resume',resume),('append',append),('word',word),('sampleE',sample)):
        source=_replace(source,name,text)
    return source

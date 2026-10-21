#!/usr/bin/env python3
"""Ahead-of-time compile an independently approved KVE2 profile to native Yul.

No proof values are consumed by code generation. The approved symbolic program
and trusted wire schema determine all native operations, bounds and constants.
Generated source, compiler output and deployment manifests must stay outside the
repository. Each immutable kernel fits EIP-170. The generated Solidity entry
binds kernel code hashes, validates the packet, then verifies full stacked WHIR.
"""
import argparse
import concurrent.futures
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from Crypto.Hash import keccak
from transcript import native_transcript

ROOT = Path(__file__).resolve().parents[1]
P = 0x7f000001
MAX_CODE = 24576


def kh(data):
    return keccak.new(digest_bits=256, data=data).digest()


def block(text, marker):
    start = text.index(marker)
    at = text.index('{', start)
    depth = 1
    end = at + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


def compact_shape_errors(source, error):
    """Preserve every require predicate; replace only diagnostic string data.

    The original reference libraries remain unchanged. Native build copies use
    one custom shape error per library to keep the WHIR tail inside EIP-170.
    """
    pieces=[];at=0
    while True:
        start=source.find('require(',at)
        if start<0:
            pieces.append(source[at:]);break
        pieces.append(source[at:start]);end=start+len('require(');depth=1;quoted=False
        while depth:
            char=source[end]
            if char=='"' and source[end-1]!='\\':quoted=not quoted
            if not quoted:depth+=(char=='(')-(char==')')
            end+=1
        original=source[start:end]
        modified,count=re.subn(r',\s*"[^"\\]*"\s*\)$',','+error+'())',original)
        assert count==1,original
        pieces.append(modified);at=end
    result=''.join(pieces)
    marker=re.search(r'library\s+\w+\s*\{',result)
    assert marker
    return result[:marker.end()]+'\n    error '+error+'();\n'+result[marker.end():]


def packed_poseidon_linear():
    """Exact M4 blocks as radix-64 cyclic convolutions modulo 2^256-1.

    Every input is canonical when linear is called. Block coefficients are
    below 7p and final coefficients below 35p, so packed additions cannot carry.
    Unreduced full-round S-box inputs are below 36p and their cubes below 2^111.
    The first internal round's sum/diagonal products remain below 2^68; it
    reduces every lane normally. Normalize all 16 slots at the permutation end.
    """
    assert 35*P < 1<<64 and 36*P < 1<<37
    assert 35*P*(P-1)+16*35*P < 1<<68
    radix=1<<64
    constant=2+radix+radix**2+3*radix**3
    code=['function linear(state,tmp){']
    for g in range(4):
        k=128*g
        code.append(f'let v{g}:=or(or(mload(add(state,{k})),shl(64,mload(add(state,{k+32})))),or(shl(128,mload(add(state,{k+64}))),shl(192,mload(add(state,{k+96})))))')
        code.append(f'v{g}:=mulmod(v{g},{hex(constant)},not(0))')
    code.append('let total:=add(add(v0,v1),add(v2,v3))')
    for g in range(4):
        code.append('{let value:=add(v'+str(g)+',total)')
        for j in range(4):
            value='and(value,0xffffffffffffffff)' if j==0 else f'and(shr({64*j},value),0xffffffffffffffff)' if j<3 else 'shr(192,value)'
            code.append(f'mstore(add(state,{128*g+32*j}),{value})')
        code.append('}')
    code.append('}')
    return '\n'.join(code)


def specialized_poseidon(data,loop_partial_rounds=False,tracked_partial_sum=False):
    """Unroll the exact authenticated permutation; preserve sponge semantics."""
    encoded=bytes.fromhex(data)
    assert len(encoded)==28*16*4
    constants=[[int.from_bytes(encoded[64*r+4*i:64*r+4*i+4],'big') for i in range(16)] for r in range(28)]
    assert all(0<=x<P for row in constants for x in row)
    assert not tracked_partial_sum or loop_partial_rounds
    source=(ROOT/'src/KoalaBearPoseidon2.sol').read_text()
    diag=bytes.fromhex(re.search(r'hex"([0-9a-f]+)"',source)[1])
    diagonal=[int.from_bytes(diag[4*i:4*i+4],'big') for i in range(16)]
    assert len(diag)==64 and all(0<=x<P for x in diagonal),'noncanonical Poseidon diagonal'
    linear=packed_poseidon_linear().splitlines()
    rounds=['function permute(state,tmp,constants,diag){linear(state,tmp)']
    groups=['add(add(mload(add(state,'+str(at)+')),mload(add(state,'+str(at+32)+'))),add(mload(add(state,'+str(at+64)+')),mload(add(state,'+str(at+96)+'))))' for at in range(0,512,128)]
    state_sum='add(add('+groups[0]+','+groups[1]+'),add('+groups[2]+','+groups[3]+'))'
    for r,row in enumerate(constants):
        if r<4 or r>=24:
            for i,value in enumerate(row):
                rounds.append(f'{{let x:=add(mload(add(state,{32*i})),{value}) mstore(add(state,{32*i}),mod(mul(mul(x,x),x),{P}))}}')
            rounds.append('linear(state,tmp)')
        else:
            if loop_partial_rounds:
                if r!=4:continue
                # The original caller reserves the complete constants region.
                # Reuse 96 owned bytes for the same 20 partial-round keys.
                keys=b''.join(c[0].to_bytes(4,'big') for c in constants[4:24])
                for at in range(0,96,32):
                    chunk=keys[at:at+32].ljust(32,b'\0')
                    rounds.append(f'mstore(add(constants,{at}),0x{chunk.hex()})')
                if tracked_partial_sum:rounds.append('let partialSum:='+state_sum)
                rounds.append('for{let step:=0}lt(step,20){step:=add(step,1)}{')
                key='shr(224,mload(add(constants,mul(step,4))))'
            else:key=str(row[0])
            if tracked_partial_sum:
                # The preceding linear layer leaves each cell below 35*p. The
                # first sum is below 560*p; later partial steps are canonical.
                # Replace the old first cell in that exact integer sum.
                rounds.append(f'{{let oldFirst:=mload(state) let x:=add(oldFirst,{key}) let nextFirst:=mod(mul(mul(x,x),x),{P}) mstore(state,nextFirst) partialSum:=add(sub(partialSum,oldFirst),nextFirst)}}')
                rounds.append('{let total:=partialSum let nextSum:=0')
                for i,d in enumerate(diagonal):rounds.append(f'{{let value:=mod(add(total,mul(mload(add(state,{32*i})),{d})),{P}) mstore(add(state,{32*i}),value) nextSum:=add(nextSum,value)}}')
                rounds.append('partialSum:=nextSum')
            else:
                rounds.append(f'{{let x:=add(mload(state),{key}) mstore(state,mod(mul(mul(x,x),x),{P}))}}')
                rounds.append('{let total:='+state_sum)
                for i,d in enumerate(diagonal):rounds.append(f'mstore(add(state,{32*i}),mod(add(total,mul(mload(add(state,{32*i})),{d})),{P}))')
            rounds.append('}')
            if loop_partial_rounds:rounds.append('}')
    # Preserve the original canonical 16-word permutation interface.
    rounds.extend(f'mstore(add(state,{32*i}),mod(mload(add(state,{32*i})),{P}))' for i in range(16))
    rounds.append('}')
    return '\n'.join(linear+rounds)


def helpers(registers, poseidon,poseidon_data=None,tower_mulmod=False,bulk_observe=False,fast_sample=False,loop_partial_rounds=False,tracked_partial_sum=False):
    arithmetic = (ROOT/'src/VerifierArithmetic.sol').read_text()
    packed = (ROOT/'src/NativeFieldArithmetic.sol').read_text()
    functions = '\n'.join(block(packed, 'function '+name+'(') for name in ('plus','minus'))
    multiplication=block(packed if tower_mulmod else arithmetic,'function times(')
    if tower_mulmod:
        # Cheap runtime identities help native witness arithmetic. Keep the
        # random-heavy WHIR field library on the unconditional tower kernel.
        marker='function times(packedLeft,packedRight) -> result {\n'
        assert multiplication.count(marker)==1
        multiplication=multiplication.replace(marker,marker+'''            // Zero and one are base-field scalars in the packed representation.
            // This product is exact even when the other operand is full E4.
            if or(lt(packedLeft,2),lt(packedRight,2)) {result:=mul(packedLeft,packedRight) leave}
''',1)
    functions += '\n'+multiplication+'\n'+block(arithmetic,'function scale(')
    inverse = block((ROOT/'src/KoalaBear.sol').read_text(), 'function inv(')
    body = block(inverse, 'assembly ("memory-safe")')[len('assembly ("memory-safe") {'):-1]
    functions += '\nfunction invertE(a) -> r { if iszero(a) { fail(0x'+kh(b'DivisionByZero()')[:4].hex()+') }'+body+'}\n'
    t = 256 + registers*32
    # Identical transcript state layout across every kernel: digest, pending,
    # wordsLeft, 192 bytes of payload (digest prefix + buffered bytes + guard).
    functions += f'''
    function fail(selector) {{mstore(0,shl(224,selector)) revert(0,4)}}
    function eqCheck(position, a, b) {{
      if iszero(eq(a,b)) {{
        mstore(0, shl(224, 0x{kh(b'AssertionFailed(uint256,uint256,uint256)')[:4].hex()}))
        mstore(4,position) mstore(36,a) mstore(68,b) revert(0,100)
      }}
    }}
    function le32(w) -> x {{
      x := or(or(byte(0,w),shl(8,byte(1,w))),or(shl(16,byte(2,w)),shl(24,byte(3,w))))
    }}
    function reverse128(w) -> x {{
      x := or(shl(8,and(w,0x00ff00ff00ff00ff00ff00ff00ff00ff)),and(shr(8,w),0x00ff00ff00ff00ff00ff00ff00ff00ff))
      x := or(shl(16,and(x,0x0000ffff0000ffff0000ffff0000ffff)),and(shr(16,x),0x0000ffff0000ffff0000ffff0000ffff))
      x := or(shl(32,and(x,0x00000000ffffffff00000000ffffffff)),and(shr(32,x),0x00000000ffffffff00000000ffffffff))
      x := or(shl(64,and(x,0x0000000000000000ffffffffffffffff)),shr(64,x))
    }}
    function fold() {{
      mstore({t+96},mload({t}))
      mstore({t},keccak256({t+96},add(mload({t+32}),32)))
      mstore({t+32},0)
    }}
    function append(value,count) {{
      mstore({t+64},0)
      for {{ }} count {{ }} {{
        let pending := mload({t+32})
        let take := sub(100,pending)
        if lt(count,take) {{ take := count }}
        mstore(add({t+128},pending),value)
        pending := add(pending,take) mstore({t+32},pending)
        if eq(pending,100) {{ fold() }}
        count := sub(count,take) value := shl(mul(8,take),value)
      }}
    }}
    function observeF(value) {{
      if iszero(lt(value,{P})) {{ fail(0x{kh(b'InvalidField()')[:4].hex()}) }}
      let x := or(or(shl(248,and(value,255)),shl(240,and(shr(8,value),255))),or(shl(232,and(shr(16,value),255)),shl(224,and(shr(24,value),255))))
      append(x,4)
    }}
    function observeE(value) {{
      for {{ let i := 0 }} lt(i,128) {{ i := add(i,32) }} {{
        if iszero(lt(and(shr(i,value),0xffffffff),{P})) {{ fail(0x{kh(b'InvalidField()')[:4].hex()}) }}
      }}
      append(shl(128,reverse128(value)),16)
    }}
    function word() -> value {{
      let left := mload({t+64})
      if iszero(left) {{ fold() left := 8 }}
      value := le32(shl(mul(sub(8,left),32),mload({t})))
      mstore({t+64},sub(left,1))
    }}
    function sampleE() -> value {{
      for {{ let i := 0 }} lt(i,128) {{ i := add(i,32) }} {{
        let x := and(word(),0x7fffffff)
        for {{ }} iszero(lt(x,{P})) {{ }} {{ x := and(word(),0x7fffffff) }}
        value := or(value,shl(i,x))
      }}
    }}
    function grind(bits,value) {{
      if bits {{ observeF(value) if and(word(),sub(shl(bits,1),1)) {{ fail(0x{kh(b'InvalidGrinding()')[:4].hex()}) }} }}
    }}
    '''
    if fast_sample:
        original=block(functions,'function sampleE(')
        replacement=f'''function sampleE() -> value {{
            let written:=0
            for {{}} lt(written,128) {{}} {{
                let left:=mload({t+64})
                if iszero(left) {{fold() left:=8 mstore({t+64},left)}}
                let take:=div(sub(128,written),32)
                if gt(take,left) {{take:=left}}
                let candidates:=and(reverse128(shr(128,shl(mul(sub(8,left),32),mload({t})))),0x7fffffff7fffffff7fffffff7fffffff)
                candidates:=and(candidates,sub(shl(mul(take,32),1),1))
                switch iszero(and(add(candidates,0x00ffffff00ffffff00ffffff00ffffff),0x80000000800000008000000080000000))
                case 1 {{
                    mstore({t+64},sub(left,take))
                    value:=or(value,shl(written,candidates))
                    written:=add(written,mul(take,32))
                }}
                default {{
                    let candidate:=and(candidates,0xffffffff)
                    mstore({t+64},sub(left,1))
                    if lt(candidate,{P}) {{value:=or(value,shl(written,candidate)) written:=add(written,32)}}
                }}
            }}
        }}'''
        functions=functions.replace(original,replacement,1)
    if bulk_observe:
        functions+=f'''
        function appendProof(offset,count) {{
            mstore({t+64},0)
            for {{}} count {{}} {{
                let pending:=mload({t+32})
                let take:=sub(100,pending)
                if lt(count,take) {{take:=count}}
                calldatacopy(add({t+128},pending),offset,take)
                pending:=add(pending,take)
                mstore({t+32},pending)
                if eq(pending,100) {{fold()}}
                offset:=add(offset,take) count:=sub(count,take)
            }}
        }}
        '''
    if poseidon:
        if poseidon_data is not None:functions+='\n'+specialized_poseidon(poseidon_data,loop_partial_rounds,tracked_partial_sum)
        else:
            source = (ROOT/'src/KoalaBearPoseidon2.sol').read_text()
            functions += '\n'+block(source, 'function linear(')+'\n'+block(source, 'function permute(')
    return functions


def native_field_library(source,tower_mulmod=False):
    """Replace selected arithmetic in generated copies; retain the reference."""
    packed=(ROOT/'src/NativeFieldArithmetic.sol').read_text()
    for name in (('add','sub','mul') if tower_mulmod else ('add','sub')):
        original=block(source,'function '+name+'(')
        assert source.count(original)==1
        source=source.replace(original,block(packed,'function '+name+'('))
    return source


def packed_canonical_library(source):
    """The original four lane bounds and upper-half bound, checked together.

    With all sign bits clear, adding 2^31-p cannot carry between 32-bit
    lanes. A flagged input sign bit already proves invalidity otherwise.
    """
    original=block(source,'function canonical(')
    expected='''function canonical(uint256 a) internal pure returns (bool) {
        return a >> 128 == 0 && uint32(a) < P && uint32(a >> 32) < P && uint32(a >> 64) < P && uint32(a >> 96) < P;
    }'''
    assert original==expected,'original canonical predicate changed'
    replacement='''function canonical(uint256 a) internal pure returns (bool valid) {
        assembly("memory-safe") {
            let flags:=and(or(a,add(a,0x00ffffff00ffffff00ffffff00ffffff)),0x80000000800000008000000080000000)
            valid:=iszero(or(shr(128,a),flags))
        }
    }'''
    return source.replace(original,replacement,1)


def assembly_mle_library(source):
    """Retain the original shape predicate and copy; fold owned row in place."""
    original=block(source,'function mle(')
    arithmetic=(ROOT/'src/NativeFieldArithmetic.sol').read_text()
    helpers='\n'.join(block(arithmetic,'function '+name+'(') for name in ('plus','minus','times'))
    replacement='''function mle(uint256[] memory values,uint256[] memory point) internal pure returns(uint256 folded) {
        require(values.length == 1 << point.length, "MLE shape");
        uint256[] memory row=new uint256[](values.length);
        assembly("memory-safe") {
            ARITHMETIC
            let data:=add(row,32)
            let n:=mload(values)
            mcopy(data,add(values,32),mul(n,32))
            let end:=add(add(point,32),mul(mload(point),32))
            for {let at:=add(point,32)} lt(at,end) {at:=add(at,32)} {
                n:=shr(1,n)
                let x:=mload(at)
                let rowEnd:=add(data,mul(n,32))
                for {let dst:=data let src:=data} lt(dst,rowEnd) {dst:=add(dst,32) src:=add(src,64)} {
                    let a:=mload(src)
                    mstore(dst,plus(a,times(x,minus(mload(add(src,32)),a))))
                }
            }
        }
        folded=row[0];
    }'''.replace('ARITHMETIC',helpers)
    return source.replace(original,replacement,1)


def assembly_closing_math(source):
    """Same paired factors, canonical guard, cache shape and exponent schedule."""
    original=block(source,'function evaluate(')
    arithmetic=(ROOT/'src/NativeFieldArithmetic.sol').read_text()
    helpers='\n'.join(block(arithmetic,'function '+name+'(') for name in ('plus','times'))
    helpers+='\n'+block((ROOT/'src/VerifierArithmetic.sol').read_text(),'function scale(')
    pair_body=block(original,'assembly("memory-safe")')
    pair_body=pair_body[pair_body.index('{')+1:-1]
    pair_body=pair_body.replace('let at:=add(add(cache,32),mul(i,128))','')
    pair_body=pair_body.replace('pair:=','let pair:=',1)
    replacement='''function evaluate(uint256[] memory cache,uint256 k,uint256 x) internal pure returns(uint256 factor,uint256 finalX) {
        require(x<F.P && cache.length==4*(k/2)+1,"closing cache");
        assembly("memory-safe") {
            ARITHMETIC
            factor:=1
            let start:=add(cache,32)
            let end:=add(start,mul(div(k,2),128))
            for {let at:=start} lt(at,end) {at:=add(at,128)} {
                PAIR
                switch eq(at,start)
                case 1 {factor:=pair}
                default {factor:=times(factor,pair)}
            }
            if and(k,1) {
                let term:=plus(1,scale(mload(end),addmod(x,0x7f000000,0x7f000001)))
                switch eq(start,end)
                case 1 {factor:=term}
                default {factor:=times(factor,term)}
                x:=mulmod(x,x,0x7f000001)
            }
            finalX:=x
        }
    }'''.replace('ARITHMETIC',helpers).replace('PAIR',pair_body)
    return source.replace(original,replacement,1)


def wide_dot_helpers():
    """Unreduced tower products; at most 1024 terms keep all lanes <2^128."""
    original=block((ROOT/'src/NativeFieldArithmetic.sol').read_text(),'function times(')
    split=original.index('            let wide:=')
    product=original[:split].replace('function times(packedLeft,packedRight) -> result {',
        'function wideTimes(packedLeft,packedRight) -> ac,bd,cross {',1)
    for name in ('ac','bd','cross'):
        assert product.count('let '+name+':=')==1
        product=product.replace('let '+name+':=',name+':=',1)
    marker='function wideTimes(packedLeft,packedRight) -> ac,bd,cross {\n'
    product=product.replace(marker,marker+'''            if or(lt(packedLeft,2),lt(packedRight,2)) {
                let value:=mul(packedLeft,packedRight)
                let spread:=or(value,shl(64,value))
                let mask:=0xffffffff000000000000000000000000ffffffff
                ac:=and(spread,mask) cross:=and(shr(32,spread),mask)
                leave
            }
''',1)+'\n}'
    reduce='function reduceWide(ac,bd,cross) -> result {\n'+original[split:]
    return '\n'+product+'\n'+reduce+'\n'


def matrix_helpers(left_only=False):
    source=(Path(__file__).parent/'matrix.yul.in').read_text()
    if left_only:
        before='''    let q:=mload(add(at,128))
    if or(lt(a,2),lt(q,2)){result:=mul(a,q) leave}'''
        assert source.count(before)==1
        source=source.replace(before,'    if lt(a,2){result:=mul(a,mload(add(at,128))) leave}',1)
    return source


def branchless_product_helpers(source):
    """The complete tower/matrix formulas also cover canonical zero and one."""
    for name in ('times','wideTimes','matrixTimes'):
        marker='function '+name+'('
        if marker not in source:continue
        original=block(source,marker)
        updated=original
        for condition in ('if or(lt(packedLeft,2)','if lt(a,2)','if or(lt(a,2)'):
            if condition in updated:updated=updated.replace(block(updated,condition),'',1)
        source=source.replace(original,updated,1)
    return source


def transposed_initial_math(source):
    """Use four-term scalar dots; keep the original initial-fold equation."""
    assert 4*(P-1)**2 < 1<<64
    assert 65536*(P-1)**2 < 1<<78
    template=(Path(__file__).parent/'initial-transpose.sol.in').read_text()
    for name in ('firstWeights','firstDot'):
        original=block(source,'function '+name+'(')
        source=source.replace(original,block(template,'function '+name+'('),1)
    return source


def assembly_initial_query_evaluator(source,transposed=False):
    """Use pointer loops around the original checked initial dot product.

    Public shape/canonicality checks and weight construction remain unchanged.
    The local dot helper retains the original internal length/offset predicate
    and verbatim arithmetic body. All output memory is freshly allocated.
    """
    original=block(source,'for(uint256 q;q<values.length;++q){')
    math=(ROOT/'src/NativeWhirMath.sol').read_text()
    if transposed:math=transposed_initial_math(math)
    dot=block(math,'function firstDot(')
    body=block(dot,'assembly("memory-safe")')[len('assembly("memory-safe")'):]
    body=body[body.index('{')+1:-1]
    invalid='0x'+kh(b'InvalidNativeWhirMath()')[:4].hex()
    helper='''function firstDot(source,offset,weights) -> result {
                let n:=div(mload(weights),2)
                if or(or(mod(mload(weights),2),gt(n,65534)),or(gt(offset,mload(source)),gt(n,div(sub(mload(source),offset),4)))) {
                    mstore(0,shl(224,INVALID)) revert(0,4)
                }
                BODY
            }'''.replace('INVALID',invalid).replace('BODY',body)
    if transposed:
        helper='''function firstDot(source,offset,weights) -> result {
                if iszero(mload(weights)){mstore(0,shl(224,INVALID)) revert(0,4)}
                let n:=mload(add(weights,32))
                if or(or(gt(n,65534),iszero(eq(mload(weights),add(1,mul(4,div(add(n,3),4)))))),or(gt(offset,mload(source)),gt(n,div(sub(mload(source),offset),4)))){
                    mstore(0,shl(224,INVALID)) revert(0,4)
                }
                BODY
            }'''.replace('INVALID',invalid).replace('BODY',body)
    # A Yul function parameter may not shadow the parent Solidity local.
    helper=re.sub(r'\bweights\b','dotWeights',helper)
    plus=block((ROOT/'src/NativeFieldArithmetic.sol').read_text(),'function plus(')
    replacement='''assembly("memory-safe") {
            DOT
            PLUS
            let output:=add(values,32)
            let outputEnd:=add(output,mul(mload(values),32))
            let roots:=add(weights,32)
            let rootsEnd:=add(roots,mul(mload(weights),32))
            for {let queryOffset:=0} lt(output,outputEnd) {output:=add(output,32) queryOffset:=add(queryOffset,stride)} {
                let offset:=queryOffset
                let total:=0
                for {let at:=roots} lt(at,rootsEnd) {at:=add(at,32)} {
                    let rootWeights:=mload(at)
                    total:=plus(total,firstDot(packed,offset,rootWeights))
                    offset:=add(offset,mul(mload(rootWeights),2))
                }
                mstore(output,total)
            }
        }'''.replace('DOT',helper).replace('PLUS',plus)
    if transposed:replacement=replacement.replace('offset:=add(offset,mul(mload(rootWeights),2))','offset:=add(offset,mul(mload(add(rootWeights,32)),4))')
    return source.replace(original,replacement,1)


def canonical_query_evaluator(source):
    """Add explicit globally-validated variants; retain checked public methods.

    Only the duplicate field-byte scan is omitted. Shape, point, lambda and dot
    bounds are identical. The complete entry has already checked these exact
    immutable packet field ranges; direct calls are auxiliary arithmetic only.
    """
    methods=[]
    for name in ('foldInitial','foldRows'):
        original=block(source,'function '+name+'(')
        scan='Wire.validateFields(fields,0,fields.length/4);'
        assert original.count(scan)==1
        method=original.replace('function '+name+'(','function '+name+'Canonical(',1)
        method=method.replace(scan,'// Requires the complete entry\'s global validation of these exact field bytes.',1)
        methods.append(method)
    end=source.rfind('}')
    return source[:end]+'\n    '+'\n\n    '.join(methods)+'\n'+source[end:]


def derived_query_inputs(source):
    """The pinned WHIR caller derives these parameters from canonical samples.

    Original checked public methods stay byte-for-byte unchanged. The native
    Canonical variants additionally require canonical point/lambda parameters.
    """
    predicates={
        'foldInitialCanonical':['if(!F.canonical(point))revert InvalidClosingInput();',
            'for(uint256 i;i<lambdaPowers[r].length;++i)if(!F.canonical(lambdaPowers[r][i]))revert InvalidClosingInput();'],
        'foldRowsCanonical':['for(uint256 i;i<point.length;++i)if(!F.canonical(point[i]))revert InvalidClosingInput();']}
    for name,checks in predicates.items():
        original=block(source,'function '+name+'(');updated=original
        for check in checks:
            assert updated.count(check)==1,'query parameter predicate changed'
            updated=updated.replace(check,'',1)
        at=updated.index('{')+1
        updated=updated[:at]+'\n        // Requires canonical parameters derived by the pinned WHIR caller.'+updated[at:]
        source=source.replace(original,updated,1)
    return source


def check_query_parameter_derivations(source):
    """Fail if the canonical-sample/multiplication/slice derivations change."""
    verify=block(source,'function verify(')
    expected=[
        'uint256 lambda = t.sampleE();','uint256 lp = 1;',
        'w.lambdaPowers[r][j] = lp;','lp = F.mul(lp, lambda);',
        'uint256 x = t.sampleE();','w.randomness[w.folded++] = x;',
        'uint256[] memory foldPoint = F.slice(w.randomness, start, rc.fold);',
        'uint256[] memory lastPoint = F.slice(w.randomness, w.randomness.length - lastFold, lastFold);']
    for statement in expected:assert verify.count(statement)==1,'query canonical derivation changed'
    assert re.findall(r'w\.randomness\[[^;]+?\]\s*=\s*[^;]+;',verify)==['w.randomness[w.folded++] = x;']
    assert re.findall(r'w\.lambdaPowers\[[^;]+?\]\s*=\s*[^;]+;',verify)==['w.lambdaPowers[r] = new uint256[](p.batch[r].length);','w.lambdaPowers[r][j] = lp;']
    assert not re.search(r'\b(?:foldPoint|lastPoint)\s*\[[^;\n]+\]\s*=',verify),'query point overwritten'
    for name in ('lambda','lp','foldPoint','lastPoint'):
        assignments=re.findall(r'\b'+name+r'\s*=\s*[^;]+;',verify)
        expected_count=2 if name=='lp' else 1
        assert len(assignments)==expected_count,'query canonical value overwritten'


def canonical_query_interface(source):
    methods=[]
    for name in ('foldInitial','foldRows'):
        original=re.search(r'function '+name+r'\([^;]+;',source)[0]
        methods.append(original.replace('function '+name+'(','function '+name+'Canonical(',1))
    end=source.rfind('}')
    return source[:end]+'\n    '+'\n    '.join(methods)+'\n'+source[end:]


def canonical_query_whir(source):
    for name,count in (('foldInitial',1),('foldRows',2)):
        before='Q(closingModule).'+name+'('
        assert source.count(before)==count
        source=source.replace(before,'Q(closingModule).'+name+'Canonical(')
    return source


def domain_power_tables(compiler,bits):
    """Exact generator windows from approved geometry, never witness values."""
    assert bits in (4,6)
    from wire import parse
    cfg=parse(compiler.tail)[0]
    original=block((ROOT/'src/StackedWhir.sol').read_text(),'function generator(')
    generators=[int(value,16) for value in re.findall(r'0x[0-9a-f]+',original)]
    assert len(generators)==25
    domain=cfg['n']-cfg['rounds'][0]['fold']+cfg['startingRate'];folded=0;logs=[]
    for r,rc in enumerate(cfg['rounds']):
        assert 0<domain<=24
        logs.append(domain);folded+=rc['fold']
        if r+1<len(cfg['rounds']):domain=cfg['n']-folded-cfg['rounds'][r+1]['fold']+rc['rate']
    result={}
    for log in sorted(set(logs)):
        g=generators[log];assert g==pow(3,(P-1)>>log,P)
        values=[pow(g,j<<(bits*k),P) for k in range((log+bits-1)//bits) for j in range(1<<min(bits,log-bits*k))]
        # The final unaligned MLOAD owns its otherwise unused trailing bytes.
        result[log]=b''.join(value.to_bytes(4,'big') for value in values)+bytes(32)
    return result


def windowed_query_powers(source,compiler,bits,shared=False):
    tables=domain_power_tables(compiler,bits)
    choices=[]
    for log,table in tables.items():
        choices.append(('if' if not choices else 'else if')+f'(log=={log}){{table=hex"{table.hex()}";windows={(log+bits-1)//bits};}}')
    method='''
    /// Exact fixed-domain generator powers, with no caller-supplied table.
    function domainPowers(uint256 log,uint256[] calldata indices) external pure returns(uint256[] memory values){
        bytes memory table;uint256 windows;
        CHOICES
        else {revert InvalidClosingInput();}
        values=new uint256[](indices.length);
        bytes4 invalidPower=InvalidClosingInput.selector;
        assembly("memory-safe") {
            let data:=add(table,32)
            let dst:=add(values,32)
            let end:=add(indices.offset,mul(indices.length,32))
            let limit:=shl(log,1)
            for {let at:=indices.offset} lt(at,end) {at:=add(at,32) dst:=add(dst,32)} {
                let index:=calldataload(at)
                if iszero(lt(index,limit)){mstore(0,invalidPower) revert(0,4)}
                let value:=shr(224,mload(add(data,mul(and(index,MASK),4))))
                index:=shr(BITS,index)
                for {let k:=1} lt(k,windows) {k:=add(k,1)} {
                    let factor:=shr(224,mload(add(add(data,mul(k,STRIDE)),mul(and(index,MASK),4))))
                    value:=mulmod(value,factor,0x7f000001)
                    index:=shr(BITS,index)
                }
                mstore(dst,value)
            }
        }
    }
'''.replace('CHOICES','\n        '.join(choices)).replace('MASK',str((1<<bits)-1)).replace('BITS',str(bits)).replace('STRIDE',str(4<<bits))
    if shared:
        maximum=max(tables)
        # g_log = g_max^(2^(max-log)). The checked index shift is <2^max,
        # so it cannot overflow and uses exactly the same table values.
        g=pow(3,(P-1)>>maximum,P)
        assert all(pow(g,1<<(maximum-log),P)==pow(3,(P-1)>>log,P) for log in tables)
        before='bytes memory table;uint256 windows;\n        '+'\n        '.join(choices)+'\n        else {revert InvalidClosingInput();}'
        guard=' && '.join(f'log!={log}' for log in tables)
        after=f'if({guard})revert InvalidClosingInput();\n        bytes memory table=hex"{tables[maximum].hex()}";uint256 windows={(maximum+bits-1)//bits};'
        assert method.count(before)==1
        method=method.replace(before,after,1)
        before='if iszero(lt(index,limit)){mstore(0,invalidPower) revert(0,4)}'
        method=method.replace(before,before+f'\n                index:=shl(sub({maximum},log),index)',1)
    end=source.rfind('}')
    return source[:end]+method+source[end:]


def windowed_power_interface(source):
    end=source.rfind('}')
    return source[:end]+'''    function domainPowers(uint256 log,uint256[] calldata indices) external pure returns(uint256[] memory values);
'''+source[end:]


def windowed_whir_points(source):
    replacements={
        '            uint256 g = generator(w.domainLog);':'''            uint256[] memory bases=Q(closingModule).domainPowers(w.domainLog,indices);
            require(bases.length==rc.queries,"base power count");''',
        'stirPoints[q][0] = F.basePow(g, indices[q]);':'stirPoints[q][0] = bases[q];',
        '''        uint256 gf = generator(w.domainLog);
        uint256[] memory finalBases=new uint256[](c.finalQueries);''':'''        uint256[] memory finalIndices=new uint256[](c.finalQueries);''',
        '            finalBases[q]=F.basePow(gf,index);':'            finalIndices[q]=index;',
        '        uint256[] memory finalFolded=':'''        uint256[] memory finalBases=Q(closingModule).domainPowers(w.domainLog,finalIndices);
        require(finalBases.length==c.finalQueries,"final base power count");
        uint256[] memory finalFolded='''}
    for before,after in replacements.items():
        assert source.count(before)==1,'WHIR base-point layout changed'
        source=source.replace(before,after,1)
    return source


def proof_cache_module_source(c):
    """Native conversion of immutable approved ranges; no validity result."""
    assert c.proof_cache_ranges and c.proof_cache_indices
    reverse=block((ROOT/'src/NativeProofCache.sol').read_text(),'function reversePair(')
    ranges=c.proof_cache_ranges;total=0
    for at in range(0,len(ranges),6):
        first=int.from_bytes(ranges[at:at+4],'big');count=int.from_bytes(ranges[at+4:at+6],'big')
        assert count>0 and first+4*count<=c.meta['field_count']
        total+=count
    assert total==len(c.proof_cache_indices)
    size=16*total+16;range_at=(size+63)&~31
    return f'''object "ProofCacheModule" {{
      code {{datacopy(0,dataoffset("Runtime"),datasize("Runtime")) return(0,datasize("Runtime"))}}
      object "Runtime" {{code {{
        {reverse}
        if iszero(eq(calldatasize(),{4*c.meta['field_count']})){{revert(0,0)}}

        let dst:=0 let at:={range_at} let end:=add(at,{len(ranges)})
        datacopy(at,dataoffset("Ranges"),{len(ranges)})
        for {{}} lt(at,end) {{at:=add(at,6)}} {{
            let descriptor:=mload(at)
            let count:=and(shr(208,descriptor),0xffff)
            let src:=mul(shr(224,descriptor),4)
            let bulkEnd:=add(dst,mul(and(count,not(7)),16))
            let pairEnd:=add(dst,mul(and(count,not(1)),16))
            for {{}} lt(dst,bulkEnd) {{dst:=add(dst,128) src:=add(src,128)}} {{
                mstore(dst,reversePair(calldataload(src)))
                mstore(add(dst,32),reversePair(calldataload(add(src,32))))
                mstore(add(dst,64),reversePair(calldataload(add(src,64))))
                mstore(add(dst,96),reversePair(calldataload(add(src,96))))
            }}
            for {{}} lt(dst,pairEnd) {{dst:=add(dst,32) src:=add(src,32)}} {{mstore(dst,reversePair(calldataload(src)))}}
            if and(count,1) {{
                mstore(dst,and(reversePair(calldataload(src)),not(0xffffffffffffffffffffffffffffffff)))
                dst:=add(dst,16)
            }}
        }}
        // The owned read guard is disjoint from the immutable descriptor table.
        mstore({16*total},0)
        return(0,{size})
      }} data "Ranges" hex"{ranges.hex()}"}}
    }}'''


def vectorize_proof_cache(source):
    """Transpose eight independent words stage by stage; keep exact scalar tails.

    The memory guard covers the complete owned output and immutable descriptor
    table. Compiler spill slots therefore cannot alias either region.
    """
    first='mstore(dst,reversePair(calldataload(src)))'
    start=source.index(first)
    last='mstore(add(dst,96),reversePair(calldataload(add(src,96))))'
    end=source.index(last,start)+len(last)
    rows=['{']+[f'let w{i}:=calldataload(add(src,{32*i}))' for i in range(8)]
    masks=[int('00ff'*16,16),int('0000ffff'*8,16),int('00000000ffffffff'*4,16),int('0000000000000000ffffffffffffffff'*2,16)]
    for shift,mask in zip((8,16,32,64),masks):
        rows.append('{let mask:='+hex(mask))
        rows.extend(f'w{i}:=or(shl({shift},and(w{i},mask)),and(shr({shift},w{i}),mask))' for i in range(8))
        rows.append('}')
    rows.extend(f'mstore(add(dst,{32*i}),w{i})' for i in range(8))
    rows.append('}')
    source=source[:start]+'\n'.join(rows)+source[end:]
    source=source.replace('and(count,not(7))','and(count,not(15))',1)
    source=source.replace('dst:=add(dst,128) src:=add(src,128)','dst:=add(dst,256) src:=add(src,256)',1)
    # The trusted generator places its descriptor table beyond the output.
    at=int(re.search(r'let at:=(\d+)',source)[1])
    ranges=re.search(r'data "Ranges" hex"([0-9a-f]+)"',source)[1]
    guard=(at+len(bytes.fromhex(ranges))+31)&~31
    assert source.count('let dst:=0')==1
    return source.replace('let dst:=0',f'pop(memoryguard({guard})) let dst:=0',1)


def offload_cache_entry(source,c,cache_module):
    """Stage LE fields in owned future packet space; receive native cache in place.

    Creation code is embedded in the approved entry constructor. It creates
    and pins one immutable arithmetic module; no extra transaction is needed.
    """
    before='internal pure override returns(bytes memory context)'
    assert source.count(before)==1
    source=source.replace(before,'internal view override returns(bytes memory context)',1)
    original=f'NativeProofCache.populate(context,{c.packet},{c.meta["field_count"]},hex"{c.proof_cache_ranges.hex()}");'
    assert source.count(original)==1
    source=source.replace(original,'',1)
    needle='   if(wire[5]==0x02) Dictionary.decodeInto'
    assert source.count(needle)==1
    nf=c.meta['field_count'];size=16*len(c.proof_cache_indices)+16
    assert c.context_bytes==c.packet+c.wire_bytes+size
    call=f'''   address cacheTarget=proofCacheModule;
   assembly("memory-safe") {{
     let at:=add(add(context,32),{c.packet+38})
     calldatacopy(at,add(wire.offset,38),{4*nf})
     let ok:=staticcall(gas(),cacheTarget,at,{4*nf},add(add(context,32),{c.packet+c.wire_bytes}),{size})
     if iszero(ok){{let dst:=mload(0x40) returndatacopy(dst,0,returndatasize()) revert(dst,returndatasize())}}
     if iszero(eq(returndatasize(),{size})){{revert(0,0)}}
   }}
'''
    if getattr(c,'zero_run_fields',False):
        before=f'calldatacopy(at,add(wire.offset,38),{4*nf})'
        assert call.count(before)==1
        call=call.replace(before,'if iszero(eq(byte(5,calldataload(wire.offset)),3)) {'+before+'}',1)
    source=source.replace(needle,call+needle,1)
    before=' CompiledWhirVerifier private immutable tail;'
    assert source.count(before)==1
    source=source.replace(before,before+'\n address public immutable proofCacheModule;',1)
    before='closingModule=closing;'
    assert source.count(before)==1
    runtime_hash='0x'+kh(bytes.fromhex(cache_module['runtime'])).hex()
    create=f'''
   bytes memory cacheCreation=hex"{cache_module['bytecode']}";
   address createdCache;
   assembly("memory-safe"){{createdCache:=create(0,add(cacheCreation,32),mload(cacheCreation))}}
   require(createdCache!=address(0) && createdCache.codehash=={runtime_hash},"cache code hash");
   proofCacheModule=createdCache;
'''
    return source.replace(before,before+create,1)


def direct_register_updates(source):
    """Apply bounded return frames using only the EVM's owned 64-byte scratch.

    The original frame size/alignment and register offset predicates remain.
    No response array is allocated beyond the large persistent proof context.
    """
    before='bytes memory updates = new bytes(_maxReturnLength());'
    assert source.count(before)==1
    source=source.replace(before,'uint256 maxReturnLength = _maxReturnLength();',1)
    assert source.count('returned > updates.length')==1
    source=source.replace('returned > updates.length','returned > maxReturnLength',1)
    before='''                let result := add(updates, 32)
                let state := add(context, 32)
                returndatacopy(result, 0, returned)
                mcopy(add(state, registers), result, 288)
                for { let at := add(result, 288) } lt(at, add(result, returned)) { at := add(at, 64) } {
                    let offset := mload(at)'''
    after='''                let state := add(context, 32)
                returndatacopy(add(state, registers), 0, 288)
                for { let at := 288 } lt(at, returned) { at := add(at, 64) } {
                    // Only the reserved 0..63 scratch region is overwritten.
                    returndatacopy(0, at, 64)
                    let offset := mload(0)'''
    assert source.count(before)==1
    source=source.replace(before,after,1)
    before='mstore(add(state, offset), mload(add(at, 32)))'
    assert source.count(before)==1
    return source.replace(before,'mstore(add(state, offset), mload(32))',1)


def isolate_monomial_closing(source):
    """Combine paired factors and Horner over a reused, owned self-call buffer.

    The child endpoint reads prepared arrays from calldata without expanding
    them to memory. Arithmetic and guards are copied from the original helpers;
    the parent's header/coordinate/nonce checks and weighted sum remain intact.
    """
    signature='external pure returns(uint256 total)'
    assert source.count(signature)==1
    source=source.replace(signature,'external view returns(uint256 total)',1)
    before='uint256[][] memory caches=new uint256[][](r.length+1);uint256 prepared;'
    assert source.count(before)==1
    source=source.replace(before,'bytes[] memory monomialRequests=new bytes[](r.length+1);',1)
    before='''if(prepared&(1<<k)==0){caches[k]=M.prepare(r,k);prepared|=1<<k;}
                uint256 finalX;
                (factor,finalX)=M.evaluate(caches[k],k,x);
                evaluation=M.hornerPrepared(widePolynomial,finalX);'''
    after='''if(monomialRequests[k].length==0){
                    monomialRequests[k]=prepareMonomialRequest(M.prepare(r,k),k,widePolynomial);
                }
                bytes memory request=monomialRequests[k];
                assembly("memory-safe") {
                    let at:=add(request,32)
                    mstore(add(at,68),x)
                    let result:=mload(0x40)
                    let ok:=staticcall(gas(),address(),at,mload(request),result,64)
                    if iszero(ok){returndatacopy(result,0,returndatasize()) revert(result,returndatasize())}
                    if iszero(eq(returndatasize(),64)){revert(0,0)}
                    factor:=mload(result) evaluation:=mload(add(result,32))
                }'''
    assert source.count(before)==1
    source=source.replace(before,after,1)
    math=(ROOT/'src/NativeClosingMath.sol').read_text()
    factor=block(assembly_closing_math(math),'function evaluate(')
    factor=factor.replace('function evaluate(','function factorCalldata(',1).replace('uint256[] memory cache','uint256[] calldata cache',1).replace('internal pure','private pure',1)
    factor=factor.replace('let start:=add(cache,32)','let start:=cache.offset',1).replace('mload(','calldataload(')
    horner=block(math,'function hornerPrepared(')
    horner=horner.replace('function hornerPrepared(','function hornerCalldata(',1).replace('uint256[] memory wide','uint256[] calldata wide',1).replace('internal pure','private pure',1)
    horner=horner.replace('let start:=add(wide,32)','let start:=wide.offset',1).replace('mload(wide)','wide.length').replace('mload(','calldataload(')
    selector='0x'+kh(b'monomialPrepared(uint256[],uint256,uint256,uint256[])')[:4].hex()
    extra='''
    function prepareMonomialRequest(uint256[] memory cache,uint256 k,uint256[] memory wide) private pure returns(bytes memory request){
        request=new bytes(196+32*(cache.length+wide.length));
        assembly("memory-safe") {
            let at:=add(request,32)
            let cacheBytes:=mul(mload(cache),32)
            mstore(at,shl(224,SELECTOR))
            mstore(add(at,4),128) mstore(add(at,36),k) mstore(add(at,68),0)
            mstore(add(at,100),add(160,cacheBytes))
            mstore(add(at,132),mload(cache))
            mcopy(add(at,164),add(cache,32),cacheBytes)
            mstore(add(add(at,164),cacheBytes),mload(wide))
            mcopy(add(add(at,196),cacheBytes),add(wide,32),mul(mload(wide),32))
        }
    }
    /// Prepared canonical cache/polynomial; this endpoint returns arithmetic only.
    function monomialPrepared(uint256[] calldata cache,uint256 k,uint256 x,uint256[] calldata wide)
        external pure returns(uint256 factor,uint256 evaluation){
        uint256 finalX;
        (factor,finalX)=factorCalldata(cache,k,x);
        evaluation=hornerCalldata(wide,finalX);
    }
    FACTOR
    HORNER
'''.replace('SELECTOR',selector).replace('FACTOR',factor).replace('HORNER',horner)
    end=source.rfind('}')
    return source[:end]+extra+source[end:]


def monomial_yul_core(source,horner_steps=2):
    """Run the same guarded calldata arithmetic in one small assembly scope."""
    factor=block(source,'function factorCalldata(')
    horner=block(source,'function hornerCalldata(')
    factor_body=block(factor,'assembly("memory-safe")');factor_body=factor_body[factor_body.index('{')+1:-1]
    factor_body=factor_body.replace('cache.offset','cacheStart')
    for old,new in (('factor','foldFactor'),('finalX','foldX'),('k','foldK'),('x','baseX'),('wide','limbMask')):
        factor_body=re.sub(r'\b'+old+r'\b',new,factor_body)
    horner_body=block(horner,'assembly("memory-safe")');horner_body=horner_body[horner_body.index('{')+1:-1]
    horner_body=horner_body.replace('wide.offset','coefficientStart').replace('wide.length','coefficientCount')
    for old,new in (('result','polynomialValue'),('x','basePoint')):
        horner_body=re.sub(r'\b'+old+r'\b',new,horner_body)
    assert horner_steps in (2,4)
    if horner_steps==4:
        assert 4*(P-1)**2+(P-1)<1<<64
        reduce='acc:=or(or(mod(and(product,mask),p),shl(64,mod(and(shr(64,product),mask),p))),or(shl(128,mod(and(shr(128,product),mask),p)),shl(192,mod(shr(192,product),p))))'
        horner_body='''
                let start:=coefficientStart
                let at:=add(start,mul(coefficientCount,32))
                let acc:=0 let p:=0x7f000001 let mask:=0xffffffffffffffff
                switch eq(coefficientCount,1)
                case 1 {acc:=calldataload(start)}
                default {
                    let x2:=mulmod(basePoint,basePoint,p)
                    let x3:=mulmod(x2,basePoint,p)
                    let x4:=mulmod(x2,x2,p)
                    if mod(coefficientCount,4) {
                        at:=sub(at,64)
                        let product:=add(mul(calldataload(add(at,32)),basePoint),calldataload(at))
                        REDUCE
                    }
                    for {} gt(at,start) {} {
                        at:=sub(at,128)
                        let product:=add(add(mul(acc,x4),mul(calldataload(add(at,96)),x3)),add(add(mul(calldataload(add(at,64)),x2),mul(calldataload(add(at,32)),basePoint)),calldataload(at)))
                        REDUCE
                    }
                }
                polynomialValue:=or(or(and(acc,0xffffffff),shl(32,and(shr(64,acc),0xffffffff))),or(shl(64,and(shr(128,acc),0xffffffff)),shl(96,shr(192,acc))))
        '''.replace('REDUCE',reduce)
    original=block(source,'function monomialPrepared(')
    replacement='''function monomialPrepared(uint256[] calldata cache,uint256 k,uint256 x,uint256[] calldata wide)
        external pure returns(uint256 factor,uint256 evaluation){
        require(x<F.P && cache.length==4*(k/2)+1,"closing cache");
        require(wide.length>0 && (wide.length==1 || wide.length%2==0),"closing polynomial");
        assembly("memory-safe") {
            function factorCore(cacheStart,foldK,baseX) -> foldFactor,foldX {FACTOR}
            function hornerCore(coefficientStart,coefficientCount,basePoint) -> polynomialValue {HORNER}
            let preparedFactor,finalPoint:=factorCore(cache.offset,k,x)
            // factorCore returns x^(2^k) modulo p (or the checked x if k=0).
            // Its base point is therefore canonical for every allowed input.
            mstore(0,preparedFactor)
            evaluation:=hornerCore(wide.offset,wide.length,finalPoint)
            factor:=mload(0)
        }
    }'''.replace('FACTOR',factor_body).replace('HORNER',horner_body)
    source=source.replace(original,replacement,1).replace(factor,'',1).replace(horner,'',1)
    return source


def unroll_closing_horner(source):
    """Fast path for 32 coefficients; every other supported size uses the original.

    Each four-term lane is still bounded by 4*(p-1)^2+(p-1)<2^64.
    Coefficients and evaluation points remain dynamic, canonical field values.
    """
    assert 4*(P-1)**2+(P-1)<1<<64
    reduce='acc:=or(or(mod(and(product,mask),p),shl(64,mod(and(shr(64,product),mask),p))),or(shl(128,mod(and(shr(128,product),mask),p)),shl(192,mod(shr(192,product),p))))'
    rows=['if eq(coefficientCount,32){let acc:=0 let p:=0x7f000001 let mask:=0xffffffffffffffff let x2:=mulmod(basePoint,basePoint,p) let x3:=mulmod(x2,basePoint,p) let x4:=mulmod(x2,x2,p)']
    for i,offset in enumerate(reversed(range(0,1024,128))):
        term=f'add(mul(mload(add(coefficientStart,{offset+96})),x3),add(add(mul(mload(add(coefficientStart,{offset+64})),x2),mul(mload(add(coefficientStart,{offset+32})),basePoint)),mload(add(coefficientStart,{offset}))))'
        if i:term='add(mul(acc,x4),'+term+')'
        rows.extend(['{let product:='+term,reduce,'}'])
    rows.extend(['polynomialValue:=or(or(and(acc,0xffffffff),shl(32,and(shr(64,acc),0xffffffff))),or(shl(64,and(shr(128,acc),0xffffffff)),shl(96,shr(192,acc))))','leave}'])
    assert source.count('let start:=coefficientStart')==1
    return source.replace('let start:=coefficientStart','\n'.join(rows)+'\nlet start:=coefficientStart',1)


def native_closing_source(source):
    """Reuse the checked paired-factor/Horner cores with an owned native driver."""
    mono=block(source,'function monomialPrepared(')
    factor=block(mono,'function factorCore(').replace('calldataload(','mload(')
    horner=block(mono,'function hornerCore(').replace('calldataload(','mload(')
    horner=unroll_closing_horner(horner)
    field=(ROOT/'src/NativeFieldArithmetic.sol').read_text()
    arithmetic='\n'.join(block(field,'function '+name+'(') for name in ('plus','minus','times'))
    for old,new in [('plus','driverPlus'),('minus','driverMinus'),('times','driverTimes')]:
        arithmetic=re.sub(r'\b'+old+r'\b',new,arithmetic)
    template=(ROOT/'native/NativeClosingDriver.yul.in').read_text()
    replacements={'DRIVER_ARITHMETIC':arithmetic,'FACTOR_CORE':factor,'HORNER_CORE':horner,
                  'EVALUATE_SELECTOR':'0x'+kh(b'evaluate(uint256[],uint256[],uint256[])')[:4].hex(),
                  'INVALID_CLOSING':'0x'+kh(b'InvalidClosingInput()')[:4].hex()}
    for key,value in replacements.items():
        assert template.count(key)==1,key
        template=template.replace(key,value,1)
    return template


def native_closing_wrapper(source,module):
    """Constructor-create exact code; authenticate it on every arithmetic call.

    The child address is stored rather than embedded so the parent's reusable
    runtime hash is deployment-independent. Its constant child-code hash check
    makes the storage value incapable of selecting a different computation.
    """
    child_hash='0x'+kh(bytes.fromhex(module['runtime'])).hex()
    method='''function evaluate(uint256[] calldata randomness,uint256[] calldata finalPoly,uint256[] calldata requests)
        external view returns(uint256 total){
        address target=closingDriver;
        require(target.codehash==DRIVER_HASH,"closing driver code hash");
        bytes memory frame=abi.encodeWithSelector(INativeClosingEvaluator.evaluate.selector,randomness,finalPoly,requests);
        assembly("memory-safe") {
            let result:=mload(0x40)
            let ok:=staticcall(gas(),target,add(frame,32),mload(frame),result,32)
            if iszero(ok){returndatacopy(result,0,returndatasize()) revert(result,returndatasize())}
            if iszero(eq(returndatasize(),32)){revert(0,0)}
            total:=mload(result)
        }
    }'''.replace('DRIVER_HASH',child_hash)
    source=source.replace(block(source,'function evaluate('),method,1)
    constructor='''
    address public closingDriver;
    constructor(){
        bytes memory creation=hex"DRIVER_CREATION";
        address created;
        assembly("memory-safe"){created:=create(0,add(creation,32),mload(creation))}
        require(created!=address(0) && created.codehash==DRIVER_HASH,"closing driver creation");
        closingDriver=created;
    }
'''.replace('DRIVER_CREATION',module['bytecode']).replace('DRIVER_HASH',child_hash)
    assert source.count('error InvalidClosingInput();')==1
    return source.replace('error InvalidClosingInput();','error InvalidClosingInput();'+constructor,1)


def stack_register_code(code,slots,resident):
    """Promote only registers never accessed through a dynamic loop pointer.

    Each promoted local starts at the same zero value as fresh EVM memory.
    Dynamic loop operands retain their exact original memory slots. Helpers,
    transcript, matrices, proof/cache calldata and response memory are untouched.
    """
    names={256+32*slot:'stackReg_'+str(slot) for reg,slot in slots.items() if reg not in resident}
    if not names:return code
    def transform(source):
        source=re.sub(r'\bmload\((\d+)\)',lambda match:names.get(int(match[1]),match[0]),source)
        result=[];at=0
        for match in re.finditer(r'\bmstore\((\d+),',source):
            address=int(match[1])
            if address not in names:continue
            assert match.start()>=at,'nested local-register stores are unsupported'
            result.append(source[at:match.start()])
            end=match.end();depth=1
            while depth:
                depth+=(source[end]=='(')-(source[end]==')');end+=1
            result.append(names[address]+':='+source[match.end():end-1])
            at=end
        result.append(source[at:])
        return ''.join(result)
    result=[transform(part) for part in code]
    # Keep the memory guard/context validation first. The compiler can reserve
    # spill memory above that guard, disjoint from every original local slot.
    result.insert(1,'\n'.join('let '+name+':=0' for name in names.values()))
    return result


def matrix_query_evaluator(source):
    """Prepare each public fold coordinate once; consume only fresh row memory.

    The external module retains all shape/canonicality checks. Its private
    matrices are derived from checked coordinates, never supplied by a caller.
    Each scalar dot is bounded by 4*p^2 < 2^64, as in the native prefix.
    """
    before='bytes memory packed=fields;uint256[] memory coordinates=point;'
    assert source.count(before)==1
    source=source.replace(before,'bytes memory packed=fields;uint256[] memory matrices=prepareCoordinates(point);',1)
    before='N.mleDiscard(F.packedExtensions(packed,q*stride,width),coordinates)'
    assert source.count(before)==1
    source=source.replace(before,'foldPrepared(F.packedExtensions(packed,q*stride,width),matrices)',1)
    packed=(ROOT/'src/NativeFieldArithmetic.sol').read_text()
    helpers='\n'.join(block(packed,'function '+name+'(') for name in ('plus','minus'))
    extra='''
    function prepareCoordinates(uint256[] calldata point) private pure returns(uint256[] memory matrices){
        matrices=new uint256[](5*point.length);
        assembly("memory-safe"){
            PREPARE
            let end:=add(point.offset,mul(point.length,32))
            let dst:=add(matrices,32)
            for{let src:=point.offset}lt(src,end){src:=add(src,32) dst:=add(dst,160)}{
                prepareMatrix(calldataload(src),dst)
            }
        }
    }
    function foldPrepared(uint256[] memory row,uint256[] memory matrices) private pure returns(uint256 folded){
        assembly("memory-safe"){
            MATRIX
            ARITHMETIC
            let end:=add(add(matrices,32),mul(mload(matrices),32))
            let data:=add(row,32)
            let n:=mload(row)
            for{let at:=add(matrices,32)}lt(at,end){at:=add(at,160)}{
                n:=shr(1,n)
                let rowEnd:=add(data,mul(n,32))
                for{let dst:=data let src:=data}lt(dst,rowEnd){dst:=add(dst,32) src:=add(src,64)}{
                    let a:=mload(src)
                    mstore(dst,plus(a,matrixTimes(minus(mload(add(src,32)),a),at)))
                }
            }
            folded:=mload(data)
        }
    }
'''.replace('PREPARE',block(matrix_helpers(True),'function prepareMatrix(')).replace('MATRIX',block(matrix_helpers(True),'function matrixTimes(')).replace('ARITHMETIC',helpers)
    end=source.rfind('}')
    return source[:end]+extra+source[end:]


def tensor_query_evaluator(source):
    """Prepare the exact MLE basis once; defer the four dot reductions.

    For canonical E4 inputs, each radix-64 scalar convolution is below 4*p^2.
    The preserved point-length bound gives at most 2^24 terms, so each scalar
    accumulator is below 2^88. The paired decoder consumes exactly two 16-byte
    E4 values per word; width=1 uses only the checked first half-word.
    """
    assert 4*(P-1)**2 < 1<<64
    assert (1<<24)*4*(P-1)**2 < 1<<88
    before='uint256[] memory matrices=prepareCoordinates(point);uint256[] memory row=new uint256[](width>>1);'
    assert source.count(before)==1,'stream query setup changed'
    source=source.replace(before,'uint256[] memory basis=prepareBasis(point);',1)
    before='foldStream(fields,q*stride,width,matrices,row)'
    assert source.count(before)==1,'stream query call changed'
    source=source.replace(before,'foldBasis(fields,q*stride,width,basis)',1)
    source=source.replace(block(source,'function prepareCoordinates('),'',1)
    source=source.replace(block(source,'function foldStream('),'',1)
    extra=(Path(__file__).parent/'tensor-query.sol.in').read_text()
    end=source.rfind('}')
    return source[:end]+extra+source[end:]


def stream_query_evaluator(source):
    """Fold the first adjacent pairs directly from checked packed calldata.

    The outer module validates every field and fixes width/query bounds. One
    owned half-row is completely overwritten per query, then consumed in place.
    No proof, coordinate or matrix memory is modified.
    """
    before='bytes memory packed=fields;uint256[] memory matrices=prepareCoordinates(point);'
    assert source.count(before)==1
    source=source.replace(before,'uint256[] memory matrices=prepareCoordinates(point);uint256[] memory row=new uint256[](width>>1);',1)
    before='foldPrepared(F.packedExtensions(packed,q*stride,width),matrices)'
    assert source.count(before)==1
    source=source.replace(before,'foldStream(fields,q*stride,width,matrices,row)',1)
    arithmetic=(ROOT/'src/NativeFieldArithmetic.sol').read_text()
    helpers='\n'.join(block(arithmetic,'function '+name+'(') for name in ('plus','minus'))
    replacement='''function foldStream(bytes calldata fields,uint256 offset,uint256 width,uint256[] memory matrices,uint256[] memory row)
        private pure returns(uint256 folded){
        assembly("memory-safe"){
            REVERSE
            MATRIX
            ARITHMETIC
            let source:=add(fields.offset,offset)
            switch eq(width,1)
            case 1 {folded:=shr(128,reversePair(calldataload(source)))}
            default {
                let at:=add(matrices,32)
                let data:=add(row,32)
                let n:=shr(1,width)
                let firstEnd:=add(data,mul(n,32))
                for{let dst:=data}lt(dst,firstEnd){dst:=add(dst,32) source:=add(source,32)}{
                    let pair:=reversePair(calldataload(source))
                    let a:=shr(128,pair)
                    let b:=and(pair,0xffffffffffffffffffffffffffffffff)
                    mstore(dst,plus(a,matrixTimes(minus(b,a),at)))
                }
                let end:=add(at,mul(mload(matrices),32))
                for{at:=add(at,160)}lt(at,end){at:=add(at,160)}{
                    n:=shr(1,n)
                    let rowEnd:=add(data,mul(n,32))
                    for{let dst:=data let src:=data}lt(dst,rowEnd){dst:=add(dst,32) src:=add(src,64)}{
                        let a:=mload(src)
                        mstore(dst,plus(a,matrixTimes(minus(mload(add(src,32)),a),at)))
                    }
                }
                folded:=mload(data)
            }
        }
    }'''.replace('REVERSE',block((ROOT/'src/NativeProofCache.sol').read_text(),'function reversePair(')).replace('MATRIX',block(matrix_helpers(True),'function matrixTimes(')).replace('ARITHMETIC',helpers)
    return source.replace(block(source,'function foldPrepared('),replacement,1)


def recycle_whir_scratch(source):
    """Recycle only scalar-returning query/evaluation temporaries.

    Proof, constraints, transcript and persistent point arrays predate each
    marker. In the first query loop, persistent stir points are allocated only
    after resetting the marker. No returned memory pointer escapes a region.
    """
    query='                stir[q] = F.mle(virtualLeaf(p, roots, stripes, w, r, q, indices[q], rc.fold), foldPoint);'
    final='            uint256 folded = F.mle(virtualLeaf(p, roots, stripes, w, finalRound, q, index, lastFold), lastPoint);'
    assertion='            if (folded != F.hornerBase(p.finalPoly, F.basePow(gf, index))) revert InvalidWhir(4);'
    identity='            Constraint memory a = w.constraints[i];'
    total='            total = F.add(total, F.mul(a.coeff, F.mul(factor, eval)));'
    replacements={
        query:'                uint256 queryScratch;\n                assembly("memory-safe"){queryScratch:=mload(0x40)}\n'+query+'\n                assembly("memory-safe"){mstore(0x40,queryScratch)}',
        final:'            uint256 finalQueryScratch;\n            assembly("memory-safe"){finalQueryScratch:=mload(0x40)}\n'+final,
        assertion:assertion+'\n            assembly("memory-safe"){mstore(0x40,finalQueryScratch)}',
        identity:'            uint256 identityScratch;\n            assembly("memory-safe"){identityScratch:=mload(0x40)}\n'+identity,
        total:total+'\n            assembly("memory-safe"){mstore(0x40,identityScratch)}'}
    for before,after in replacements.items():
        assert source.count(before)==1,'WHIR scratch boundary changed'
        source=source.replace(before,after)
    return source


def native_whir_library(source):
    """Retain leaf canonicality and bounds, checking eight memory fields/word."""
    marker='assembly ("memory-safe") {\n                let start := add(add(source, 32), offset)'
    original=block(source,marker)
    checker=block((ROOT/'src/KoalaBearWire.sol').read_text(),'function checkMemory(')
    replacement='assembly ("memory-safe") {\n'+checker+'''
                let start := add(add(source, 32), offset)
                checkMemory(start,div(byteCount,4),invalidField)
                h := keccak256(start,byteCount)
            }'''
    assert source.count(original)==1
    return source.replace(original,replacement)


def validated_leaf_fields(source):
    """Use the complete entry's global field check for fixed decoded leaves.

    Only the duplicated packed-leaf field scan is removed. The trusted decoder
    builds every leaf from a checked, contiguous base-field range in that same
    immutable packet; all sizes, offsets, Merkle hashes and paths remain.
    The auxiliary WHIR endpoint alone is not a complete proof verifier.
    """
    original=block(source,'function checkMerkle(')
    before='checkMemory(start,div(byteCount,4),invalidField)'
    assert original.count(before)==1
    after=original.replace(before,'// Fields were validated by the complete entry before any kernel call.',1)
    return source.replace(original,after,1)


def check_fixed_whir_geometry(cfg,roots,stripes,point,p):
    """Mirror fixed decoder/WHIR shape predicates without witness values."""
    rounds=cfg['rounds'];count=len(rounds)
    assert 0<count<=24 and cfg['n']<=24,'WHIR config'
    folds=sum(r['fold'] for r in rounds)
    assert all(len(r['foldPow'])==r['fold'] for r in rounds),'fold difficulty count'
    assert folds<=cfg['n'] and len(point)==cfg['n'],'stack dimension'
    final_log=cfg['n']-folds
    assert len(p['finalPoly'])==1<<final_log and len(p['finalPolys'])==rounds[-1]['fold'],'final shape'
    assert len(p['roots'])==len(p['roundOod'])==len(p['roundPolys'])==count-1 and len(p['openings'])==count,'round shape'
    assert len(p['foldPow'])==folds+count-1 and len(p['batch'])==len(stripes)==len(roots),'batch shape'
    assert all(len(row)==stripe for row,stripe in zip(p['batch'],stripes)),'stripe count'
    assert all(len(polys)==rc['fold'] and len(ood)==rc['ood'] for polys,ood,rc in zip(p['roundPolys'],p['roundOod'],rounds)),'round data shape'
    assert all(len(poly)==3 for group in p['roundPolys'] for poly in group),'degree two'
    assert all(len(poly)==3 for poly in p['finalPolys']),'final degree two'
    domain=cfg['n']-rounds[0]['fold']+cfg['startingRate'];folded=0
    for r,(rc,leaves) in enumerate(zip(rounds,p['openings'])):
        assert 0<=domain<=24,'Merkle height'
        queries=cfg['finalQueries'] if r==count-1 else rc['queries']
        period=len(roots) if r==0 else 1
        assert len(leaves)==queries*period,'query leaf count'
        for i,leaf in enumerate(leaves):
            rows=stripes[i%period] if r==0 else 1
            width=1<<rc['fold'] if r==0 else 4<<rc['fold']
            assert len(leaf['values'])==rows and all(len(row)==width for row in leaf['values']),'packed Merkle shape'
            assert len(leaf['path'])==domain,'path view height'
            path=leaf['path']
            assert path and path[0]&0xf0000000==0x10000000 and path==list(range(path[0],path[0]+len(path))),'path hash range'
            flat=[ref for row in leaf['values'] for ref in row]
            assert flat and flat[0]&0xf0000000==0x40000000 and flat==list(range(flat[0],flat[0]+len(flat))),'leaf field range'
        folded+=rc['fold']
        if r+1<count:domain=cfg['n']-folded-rounds[r+1]['fold']+rc['rate']
    return final_log


def fixed_whir_profile(source,compiler):
    """Discharge immutable geometry at build time; retain all proof equations.

    The complete entry binds the approved program and packet and checks every
    field. Its typed kernels produce canonical point coordinates. Only that
    entry establishes these preconditions; direct tail calls are auxiliary.
    """
    from wire import parse
    cfg,roots,stripes,point,p=parse(compiler.tail)
    final_log=check_fixed_whir_geometry(cfg,roots,stripes,point,p)
    def fields(value):
        if isinstance(value,int):yield value
        else:
            for item in value:yield from fields(item)
    values=[point,p['batch'],p['roundPolys'],p['roundOod'],p['finalPoly'],p['finalPolys']]
    assert all(compiler.field_kind(ref) in ('F','E') for ref in fields(values)),'noncanonical fixed-profile operand type'
    assert all(compiler.field_kind(ref)=='F' for ref in [p['batchPow'],p['finalPow'],*p['foldPow']]),'non-base grinding nonce'
    # ref() also proves every generated absolute field/hash offset is inside
    # the exact packet length checked by the complete entry and tail.
    for group in p['openings']:
        for leaf in group:
            for ref in [*fields(leaf['values']),*leaf['path']]:compiler.ref(ref)
    original=block(source,'function validate(')
    signature=original[:original.index('{')]
    source=source.replace(original,signature+'{return '+str(final_log)+';}',1)
    before=block(source,'function checkMerkle(')
    after=before
    predicates=[f'require(index<1<<height && leaf.pathView>>32==height && {compiler.wire_bytes}!=0,"Merkle shape");',
                'require(leaf.rows==rows && leaf.width==width,"packed Merkle shape");',
                f'require(leaf.offset+byteCount<={compiler.wire_bytes},"packed Merkle bounds");',
                f'require(pathOffset<={compiler.wire_bytes} && height<=({compiler.wire_bytes}-pathOffset)/32,"path bounds");']
    for predicate in predicates:
        assert before.count(predicate)==1,'fixed-profile Merkle predicate changed'
        after=after.replace(predicate,'',1)
    needle=after.index('{')+1
    after=after[:needle]+'\n        require(index<1<<height,"Merkle index");'+after[needle:]
    return source.replace(before,after,1)


def unroll_merkle_paths(source,factor):
    """Read every full sibling in order; amortize loop bookkeeping only."""
    assert factor in (4,8)
    for name,load in (('walk','mload'),('walkCalldata','calldataload')):
        original=block(source,'function '+name+'(')
        expected='''{
        assembly("memory-safe") {
            let end:=add(pathPointer,mul(height,32))
            for {} lt(pathPointer,end) {pathPointer:=add(pathPointer,32)} {
                let sibling:=LOAD(pathPointer)
                switch and(index,1)
                case 0 {mstore(0,hash) mstore(32,sibling)}
                default {mstore(0,sibling) mstore(32,hash)}
                hash:=keccak256(0,64)
                index:=shr(1,index)
            }
        }
        return hash;
    }'''.replace('LOAD',load)
        normalize=lambda text:re.sub(r'\s+','',text)
        assert normalize(original[original.index('{'):])==normalize(expected),'native Merkle walker changed'
        def step(offset):
            address='pathPointer' if offset==0 else f'add(pathPointer,{offset})'
            return '''{
                let sibling:=LOAD(ADDRESS)
                let side:=shl(5,and(index,1))
                mstore(side,hash) mstore(xor(side,32),sibling)
                hash:=keccak256(0,64) index:=shr(1,index)
            }'''.replace('LOAD',load).replace('ADDRESS',address)
        signature=original[:original.index('{')]
        replacement=signature+'''{
        assembly("memory-safe") {
            let end:=add(pathPointer,mul(height,32))
            let bulkEnd:=sub(end,mul(mod(height,FACTOR),32))
            for {} lt(pathPointer,bulkEnd) {pathPointer:=add(pathPointer,STRIDE)} {
                STEPS
            }
            for {} lt(pathPointer,end) {pathPointer:=add(pathPointer,32)} {
                TAIL
            }
        }
        return hash;
    }'''.replace('FACTOR',str(factor)).replace('STRIDE',str(factor*32)).replace('STEPS','\n'.join(step(32*i) for i in range(factor))).replace('TAIL',step(0))
        source=source.replace(original,replacement,1)
    return source


def native_merkle_path_views(source):
    """Use approved bounded path views; retain the independent array fallback."""
    source=source.replace('import {KoalaBear as F}', 'import {NativeMerklePath} from "./NativeMerklePath.sol";\nimport {KoalaBear as F}',1)
    before='        uint256 width;\n    }'
    assert source.count(before)==1
    source=source.replace(before,'        uint256 width;\n        uint256 pathView;\n    }')
    before='        require(leaf.path.length == height && index < 1 << height, "Merkle shape");'
    assert source.count(before)==1
    source=source.replace(before,'''        require(index < 1 << height, "Merkle index");
        uint256 pathPointer;
        if(leaf.pathView!=0){
            uint256 pathOffset=leaf.pathView&0xffffffff;
            require(leaf.path.length==0 && leaf.pathView>>32==height && leaf.source.length!=0, "path view shape");
            require(pathOffset<=leaf.source.length && height<=(leaf.source.length-pathOffset)/32, "path view bounds");
            bytes memory pathSource=leaf.source;
            assembly("memory-safe"){pathPointer:=add(add(pathSource,32),pathOffset)}
        } else {
            require(leaf.path.length==height, "Merkle shape");
            bytes32[] memory path=leaf.path;
            assembly("memory-safe"){pathPointer:=add(path,32)}
        }''')
    before=block(source,'for (uint256 i; i < height; ++i)')
    assert 'h := keccak256(0, 64)' in before
    return source.replace(before,'h = NativeMerklePath.walk(h,index,height,pathPointer);',1)


def specialize_whir_generators(source, config):
    """Keep only domain generators reached by this approved fixed schedule."""
    original=block(source,'function generator(')
    values=[int(value,16) for value in re.findall(r'0x[0-9a-f]+',original)]
    assert len(values)==25
    heights=[];folded=0
    domain=config['n']-config['rounds'][0]['fold']+config['startingRate']
    for r,round in enumerate(config['rounds']):
        assert 0<=domain<=24
        heights.append(domain);folded+=round['fold']
        if r+1<len(config['rounds']):
            domain=config['n']-folded-config['rounds'][r+1]['fold']+round['rate']
    cases='\n'.join(f'        if(log=={height}) return {values[height]};' for height in sorted(set(heights)))
    replacement='function generator(uint256 log) internal pure returns(uint256){\n'+cases+'\n        revert InvalidWhir(1);\n    }'
    return source.replace(original,replacement,1)


def fused_base_whir(source, config):
    """Packed-only first-fold fusion, guarded by the approved fixed decoder."""
    assert len(config['rounds'])>1 and config['rounds'][0]['fold']==1
    source=source.replace('import {KoalaBear as F}', 'import {NativeWhirMath as N} from "./NativeWhirMath.sol";\nimport {KoalaBear as F}',1)
    leaf=block(source,'struct Leaf {')
    source=source.replace(leaf,'''struct Leaf {
        bytes source;
        uint256 offset;
        uint256 rows;
        uint256 width;
        uint256 pathView;
    }''',1)
    original=block(source,'function checkMerkle(')
    # Keep the tested canonical memory checker and original full leaf hashing.
    canonical=block(original,'assembly ("memory-safe") {\nfunction checkMemory(')
    new='''function checkMerkle(Leaf memory leaf,bytes32 root,uint256 index,uint256 height,uint256 rows,uint256 width) private pure {
        require(index<1<<height && leaf.pathView>>32==height && leaf.source.length!=0,"Merkle shape");
        require(leaf.rows==rows && leaf.width==width,"packed Merkle shape");
        uint256 byteCount=4*rows*width;
        require(leaf.offset+byteCount<=leaf.source.length,"packed Merkle bounds");
        uint256 pathOffset=leaf.pathView&0xffffffff;
        require(pathOffset<=leaf.source.length && height<=(leaf.source.length-pathOffset)/32,"path bounds");
        bytes memory source=leaf.source;uint256 offset=leaf.offset;
        bytes4 invalidField=F.InvalidField.selector;bytes32 h;
        '''+canonical+'''
        uint256 pathPointer;assembly("memory-safe"){pathPointer:=add(add(source,32),pathOffset)}
        h=NativeMerklePath.walk(h,index,height,pathPointer);
        if(h!=root) revert InvalidWhir(2);
    }'''
    source=source.replace(original,new,1)
    original=block(source,'function virtualLeaf(')
    new='''function virtualLeaf(Proof memory p,bytes32[] memory roots,uint256[] memory stripes,Work memory w,uint256 r,uint256 q,uint256 index,uint256 fold)
        private pure returns(uint256[] memory values) {
        require(r>0,"packed continuation round");
        Leaf memory leaf=p.openings[r][q];
        checkMerkle(leaf,p.roots[r-1],index,w.domainLog,1,4<<fold);
        return F.packedExtensions(leaf.source,leaf.offset,1<<fold);
    }

    function firstFold(Proof memory p,bytes32[] memory roots,uint256[] memory stripes,Work memory w,uint256 q,uint256 index,uint256[][] memory weights)
        private pure returns(uint256 result) {
        for(uint256 ri;ri<roots.length;++ri){
            Leaf memory leaf=p.openings[0][q*roots.length+ri];
            checkMerkle(leaf,roots[ri],index,w.domainLog,stripes[ri],2);
            result=F.add(result,N.firstDot(leaf.source,leaf.offset,weights[ri]));
        }
    }'''
    source=source.replace(original,new,1)
    marker='            uint256 g = generator(w.domainLog);'
    assert source.count(marker)==1
    source=source.replace(marker,marker+'''
            uint256[][] memory firstWeights;
            if(r==0){
                firstWeights=new uint256[][](roots.length);
                for(uint256 ri;ri<roots.length;++ri)firstWeights[ri]=N.firstWeights(w.lambdaPowers[ri],foldPoint[0]);
            }''',1)
    before='stir[q] = F.mle(virtualLeaf(p, roots, stripes, w, r, q, indices[q], rc.fold), foldPoint);'
    assert source.count(before)==1
    source=source.replace(before,'stir[q] = r==0 ? firstFold(p,roots,stripes,w,q,indices[q],firstWeights) : F.mle(virtualLeaf(p,roots,stripes,w,r,q,indices[q],rc.fold),foldPoint);')
    source=source.replace('F.powers(F.basePow(g, indices[q]), rem)','N.basePowers(F.basePow(g, indices[q]), rem)')
    source=source.replace('F.mul(y, a.point[j])','F.scale(y, a.point[j])')
    # Only virtualLeaf creates these query arrays; consume them in place.
    source=source.replace('F.mle(virtualLeaf(', 'N.mleDiscard(virtualLeaf(')
    before='''            uint256 factor = 1;
            for (uint256 j; j < k; ++j) {'''
    assert source.count(before)==1
    source=source.replace(before,'''            uint256 factor = a.monomial ? N.monomialFactor(a.point,w.randomness,c.n-a.vars,k) : 1;
            for (uint256 j; !a.monomial && j < k; ++j) {''',1)
    return source


def closing_module_whir(source):
    """Keep all closing identities, evaluating them in one pinned static call."""
    source=source.replace('import {KoalaBear as F}', 'import {INativeClosingEvaluator} from "./INativeClosingEvaluator.sol";\nimport {KoalaBear as F}',1)
    signature='        T.State memory t\n    ) internal pure {'
    assert source.count(signature)==1
    source=source.replace(signature,'        T.State memory t, address closingModule\n    ) internal view {',1)
    powers='                stirPoints[q] = N.basePowers(F.basePow(g, indices[q]), rem);'
    assert source.count(powers)==1
    source=source.replace(powers,'                stirPoints[q] = new uint256[](1);\n                stirPoints[q][0] = F.basePow(g, indices[q]);',1)
    start=source.index('        uint256 total;',source.index('    function verify('))
    marker='        if (total != w.claim) revert InvalidWhir(5);'
    end=source.index(marker,start)
    replacement='''        uint256 words;
        for(uint256 i;i<w.count;++i)words+=w.constraints[i].monomial?1:1+w.constraints[i].vars;
        uint256[] memory requests=new uint256[](words);uint256 cursor;
        for(uint256 i;i<w.count;++i){
            Constraint memory a=w.constraints[i];
            uint256 header=a.coeff|(a.vars<<128);
            if(a.monomial){requests[cursor++]=header|(1<<136)|(a.point[0]<<160);}
            else{
                require(a.point.length==a.vars,"closing point shape");
                requests[cursor++]=header;
                for(uint256 j;j<a.vars;++j)requests[cursor++]=a.point[j];
            }
        }
        uint256 total=INativeClosingEvaluator(closingModule).evaluate(w.randomness,p.finalPoly,requests);
'''
    return source[:start]+replacement+source[end:]


def calldata_whir(source,packet_bytes):
    """Retain all checks while reading immutable proof views from calldata."""
    assert isinstance(packet_bytes,int) and packet_bytes>0
    replacements={
        '        bytes source;\n        uint256 offset;':'        uint256 sourceOffset;\n        uint256 offset;',
        'leaf.source.length':str(packet_bytes),
        'bytes memory source=leaf.source;uint256 offset=leaf.offset;':'bytes calldata source=leafSource(leaf);uint256 offset=leaf.offset;',
        'let start := add(add(source, 32), offset)\n                checkMemory':'let start := mload(0x40)\n                calldatacopy(start,add(source.offset,offset),byteCount)\n                checkMemory',
        'pathPointer:=add(add(source,32),pathOffset)':'pathPointer:=add(source.offset,pathOffset)',
        'NativeMerklePath.walk(h,index,height,pathPointer)':'NativeMerklePath.walkCalldata(h,index,height,pathPointer)',
        'F.packedExtensions(leaf.source,leaf.offset,1<<fold)':'N.packedExtensionsCalldata(leafSource(leaf),leaf.offset,1<<fold)',
        'N.firstDot(leaf.source,leaf.offset,weights[ri])':'N.firstDotCalldata(leafSource(leaf),leaf.offset,weights[ri])',
    }
    for before,after in replacements.items():
        assert before in source,before
        source=source.replace(before,after)
    helper='''    function leafSource(Leaf memory leaf) private pure returns(bytes calldata source){
        // Only the fixed decoder constructs this offset, from its bounded
        // packet slice. verifyContext checks the exact enclosing length.
        assembly("memory-safe"){
            source.offset:=mload(leaf) source.length:=PACKET_BYTES
        }
    }

'''.replace('PACKET_BYTES',str(packet_bytes))
    marker='    function checkMerkle('
    assert source.count(marker)==1
    return source.replace(marker,helper+marker,1)


def calldata_whir_math(source):
    first=block(source,'function firstDot(')
    first=first.replace('function firstDot(','function firstDotCalldata(',1).replace('bytes memory source','bytes calldata source',1)
    first=first.replace('let src:=add(add(source,32),offset)','let src:=add(source.offset,offset)',1).replace('mload(src)','calldataload(src)')
    packed=block((ROOT/'src/KoalaBear.sol').read_text(),'function packedExtensions(')
    packed=packed.replace('function packedExtensions(','function packedExtensionsCalldata(',1).replace('bytes memory source','bytes calldata source',1)
    packed=packed.replace('let src := add(add(source, 32), offset)','let src := add(source.offset, offset)',1).replace('mload(src)','calldataload(src)')
    end=source.rfind('}')
    return source[:end]+first+'\n'+packed+'\n'+source[end:]


def offload_query_whir(source):
    """Keep leaf authentication in WHIR; batch deterministic folds on chain."""
    source=source.replace('import {NativeWhirMath as N} from "./NativeWhirMath.sol";',
        'import {INativeQueryEvaluator as Q} from "./INativeQueryEvaluator.sol";',1)
    source=source.replace('struct Proof {','struct Proof {\n        uint256[] dataViews;',1)
    for name in ('virtualLeaf','firstFold'):source=source.replace(block(source,'function '+name+'('),'',1)
    weights='            uint256[][] memory firstWeights;\n'+block(source,'            if(r==0){')
    source=source.replace(weights,'',1)
    before='''            for (uint256 q; q < rc.queries; ++q) {
                uint256 queryScratch;
                assembly("memory-safe"){queryScratch:=mload(0x40)}
                stir[q] = r==0 ? firstFold(p,roots,stripes,w,q,indices[q],firstWeights) : N.mleDiscard(virtualLeaf(p,roots,stripes,w,r,q,indices[q],rc.fold),foldPoint);
                assembly("memory-safe"){mstore(0x40,queryScratch)}
                stirPoints[q] = new uint256[](1);
                stirPoints[q][0] = F.basePow(g, indices[q]);
            }'''
    after='''            for (uint256 q; q < rc.queries; ++q) {
                if(r==0){
                    for(uint256 ri;ri<roots.length;++ri){
                        checkMerkle(p.openings[0][q*roots.length+ri],roots[ri],indices[q],w.domainLog,stripes[ri],2);
                    }
                }else{checkContinuation(p,w,r,q,indices[q],rc.fold);}
                stirPoints[q] = new uint256[](1);
                stirPoints[q][0] = F.basePow(g, indices[q]);
            }
            stir=r==0 ? Q(closingModule).foldInitial(querySource(p,r),w.lambdaPowers,foldPoint[0])
                : Q(closingModule).foldRows(querySource(p,r),foldPoint);
            require(stir.length==rc.queries,"folded query count");'''
    assert source.count(before)==1
    source=source.replace(before,after,1).replace('uint256[] memory stir = new uint256[](rc.queries);','uint256[] memory stir;',1)
    before='''        for (uint256 q; q < c.finalQueries; ++q) {
            uint256 index = t.bits(w.domainLog);
            uint256 finalQueryScratch;
            assembly("memory-safe"){finalQueryScratch:=mload(0x40)}
            uint256 folded = N.mleDiscard(virtualLeaf(p, roots, stripes, w, finalRound, q, index, lastFold), lastPoint);
            if (folded != F.hornerBase(p.finalPoly, F.basePow(gf, index))) revert InvalidWhir(4);
            assembly("memory-safe"){mstore(0x40,finalQueryScratch)}
        }'''
    after='''        uint256[] memory finalBases=new uint256[](c.finalQueries);
        for (uint256 q; q < c.finalQueries; ++q) {
            uint256 index = t.bits(w.domainLog);
            checkContinuation(p,w,finalRound,q,index,lastFold);
            finalBases[q]=F.basePow(gf,index);
        }
        uint256[] memory finalFolded=Q(closingModule).foldRows(querySource(p,finalRound),lastPoint);
        require(finalFolded.length==c.finalQueries,"final folded count");
        for(uint256 q;q<c.finalQueries;++q){
            if(finalFolded[q]!=F.hornerBase(p.finalPoly,finalBases[q]))revert InvalidWhir(4);
        }'''
    assert source.count(before)==1
    source=source.replace(before,after,1)
    helpers='''    function querySource(Proof memory p,uint256 r) private pure returns(bytes calldata source){
        uint256 start=p.dataViews[2*r];uint256 length=p.dataViews[2*r+1];
        assembly("memory-safe"){
            if or(gt(start,calldatasize()),gt(length,sub(calldatasize(),start))){revert(0,0)}
            source.offset:=start source.length:=length
        }
    }
    function checkContinuation(Proof memory p,Work memory w,uint256 r,uint256 q,uint256 index,uint256 fold) private pure {
        require(r>0,"continuation round");
        checkMerkle(p.openings[r][q],p.roots[r-1],index,w.domainLog,1,4<<fold);
    }

'''
    assert 'N.' not in source
    return source.replace('    function verify(',helpers+'    function verify(',1)


def compile_contract_artifact(solc, source_dir,unit,contract,runs=1):
    """Compile one independent unit; pin each unit's optimizer settings."""
    sources={}
    def collect(name):
        if name in sources:return
        content=(source_dir.parent/name).read_text()
        sources[name]={'content':content}
        for relative in re.findall(r'import\s+(?:[^;]*?from\s+)?[\"\']([^\"\']+)[\"\']\s*;',content):
            dependency=(Path(name).parent/relative).as_posix()
            # Normalize ./ without permitting imports outside this local build.
            dependency=Path(dependency).as_posix()
            assert '..' not in Path(dependency).parts
            collect(dependency)
    collect(unit)
    request={'language':'Solidity','sources':sources,'settings':{
        'optimizer':{'enabled':True,'runs':runs},'viaIR':True,'evmVersion':'prague',
        'outputSelection':{unit:{contract:['evm.bytecode.object','evm.deployedBytecode.object']}}}}
    result=subprocess.run([solc,'--standard-json'],input=json.dumps(request),text=True,capture_output=True,timeout=180,check=True)
    output=json.loads(result.stdout)
    errors=[item['formattedMessage'] for item in output.get('errors',[]) if item['severity']=='error']
    if errors:raise RuntimeError('\n'.join(errors))
    artifact=output['contracts'][unit][contract]['evm']
    runtime=bytes.fromhex(artifact['deployedBytecode']['object'])
    assert len(runtime)<=MAX_CODE,f'{contract} runtime exceeds EIP-170: {len(runtime)} bytes'
    return artifact


def compile_contract_runtime(solc,source_dir,unit,contract):
    return bytes.fromhex(compile_contract_artifact(solc,source_dir,unit,contract)['deployedBytecode']['object'])


def compile_whir_runtime(solc,source_dir):
    return compile_contract_runtime(solc,source_dir,'src/CompiledWhirVerifier.sol','CompiledWhirVerifier')


class Compiler:
    def __init__(self, manifest, source_program):
        self.manifest = manifest
        self.meta = manifest['metadata']
        self.ops = manifest['ops']
        self.registers = manifest['registers']
        assert self.registers>0 and 256+32*self.registers+320<=0xa000,'native workspace overlaps Poseidon scratch'
        self.prefix = self.registers*32+288+32
        self.packet = self.prefix+32
        self.wire_bytes = 38+4*self.meta['field_count']+32*self.meta['hash_count']
        self.program_hash = kh(source_program)
        self.pcs = []
        pc = 48
        sizes = {4:13,5:13,6:13,7:9,8:9,10:5,11:5,12:5,13:5,14:6,15:37,16:9,17:6,18:1803,20:13,21:13,22:13,23:13}
        for op in self.ops:
            assert source_program[pc] == op[0], ('opcode mismatch',pc,op[0])
            self.pcs.append(pc)
            pc += sizes[op[0]]
        assert source_program[pc] == 255
        size=int.from_bytes(source_program[pc+1:pc+5],'big')
        self.tail=source_program[pc+5:]
        assert len(self.tail)==size
        # Bind every operand and header byte, not just the opcode sequence.
        import importlib.util
        spec=importlib.util.spec_from_file_location('reference_compiler',ROOT/'compile-machine.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        assert module.binary_program(self.ops,self.registers,self.meta,self.tail)==source_program
        self.check_arithmetic_types()

    def specialize_assertions(self):
        """Use only dominating checked equalities and exact base constants.

        Keep every original assertion and transcript instruction verbatim.
        Proof cells are immutable under the entry's frame bounds; register
        knowledge is invalidated on each overwrite. No witness is consulted.
        Operation count/positions remain unchanged for independent checkpoints.
        """
        assert not hasattr(self,'assertion_history'),'assertion pass already applied'
        original=self.ops
        fields={};registers={i:0 for i in range(self.registers)}
        history={'fields':{},'registers':{i:[(-1,0)] for i in registers}}
        statistics={'proof_bindings':0,'constant_results':0,'replaced_operands':0}
        def record(group,index,value,at):
            table=fields if group=='fields' else registers
            if table.get(index)==value:return
            if value is None:table.pop(index,None)
            else:table[index]=value
            history[group].setdefault(index,[]).append((at,value))
        def value(ref):
            if ref&0x80000000:return ref&0x7fffffff
            index=ref&0x0fffffff
            if ref&0x40000000:return fields.get(index)
            if ref&0x20000000:
                limbs=[fields.get(index+j) for j in range(4)]
                return limbs[0] if limbs[0] is not None and limbs[1:]==[0,0,0] else None
            if ref&0x10000000:return None
            return registers.get(ref)
        def bind(ref,known,at):
            if known is None or ref&0x80000000:return
            index=ref&0x0fffffff
            if ref&0x40000000:
                record('fields',index,known,at);statistics['proof_bindings']+=1
            elif ref&0x20000000:
                for j in range(4):record('fields',index+j,known if j==0 else 0,at)
                statistics['proof_bindings']+=1
            elif not ref&0x10000000:record('registers',ref,known,at)
        optimized=[]
        for at,instruction in enumerate(original):
            op,dst,*args=instruction
            emitted=list(instruction)
            if op==8:
                # Learn facts only after this unmodified equality executes.
                a,b=map(value,args)
                bind(args[0],b,at);bind(args[1],a,at)
            elif op in (4,5,6,7,20,21,22,23):
                known=[value(ref) for ref in args]
                resolved=[ref if x is None else 0x80000000|x for ref,x in zip(args,known)]
                statistics['replaced_operands']+=sum(a!=b for a,b in zip(args,resolved))
                emitted=[op,dst,*resolved]
                result=None
                if op==7:
                    if known[0]:result=pow(known[0],P-2,P)
                else:
                    a,b=known
                    if a is not None and b is not None:
                        result=((a+b) if op in (4,20) else (a-b) if op in (5,21) else a*b)%P
                    elif op in (6,22,23) and (a==0 or b==0):result=0
                    elif op in (5,21) and resolved[0]==resolved[1]:result=0
                if result is not None:
                    emitted=[4,dst,0x80000000|result,0x80000000]
                    statistics['constant_results']+=1
                # Other identities may copy a known scalar; resolve their
                # source against the pre-write register version.
                identity=self.identity_source(emitted)
                scalar=value(identity) if identity is not None else result
                record('registers',dst,scalar,at)
            elif op in (13,15):record('registers',dst,None,at)
            elif op in (16,18):
                for j in range(8):record('registers',dst+j,None,at)
            optimized.append(emitted)
        assert len(optimized)==len(original)
        assert [x for x in optimized if x[0]==8]==[x for x in original if x[0]==8]
        for before,after in zip(original,optimized):
            if before[0] not in (4,5,6,7,20,21,22,23):assert list(before)==after
        self.approved_ops=original
        self.ops=optimized
        self.assertion_history=history
        self.assertion_statistics=statistics
        self.check_arithmetic_types()

    def constant_preconditions(self,start):
        """Facts established before a standalone auxiliary checkpoint call."""
        import bisect
        result={}
        for group,histories in self.assertion_history.items():
            known={}
            for index,events in histories.items():
                position=bisect.bisect_left([at for at,_ in events],start)-1
                if position>=0 and events[position][1] is not None:known[index]=events[position][1]
            result[group]=known
        return result

    def prepare_proof_cache(self):
        """Cache only E4 operands actually read by native arithmetic/checks."""
        refs=set()
        for at,instruction in enumerate(self.ops):
            if at in getattr(self,'dead_ops',()):continue
            op,dst,*args=instruction
            identity=self.identity_source(instruction)
            if identity==dst:continue
            if identity is not None:args=[identity]
            elif op not in (4,5,6,7,8,20,21,22,23):continue
            for value in args:
                self.ref(value)
                if value&0xf0000000==0x20000000:refs.add(value&0x0fffffff)
        indices=sorted(refs)
        self.proof_cache_indices=indices
        start=self.packet+self.wire_bytes
        self.proof_cache_offsets={index:start+16*i for i,index in enumerate(indices)}
        self.context_bytes=start+16*len(indices)+16  # last overlapping store guard
        ranges=[]
        for index in indices:
            if ranges and ranges[-1][0]+4*ranges[-1][1]==index and ranges[-1][1]<65535:
                ranges[-1][1]+=1
            else:ranges.append([index,1])
        self.proof_cache_ranges=b''.join(first.to_bytes(4,'big')+count.to_bytes(2,'big') for first,count in ranges)

    def eliminate_dead_arithmetic(self,terminal_registers=None):
        """Remove only total pure computations with no observable consumer.

        Assertions, inverse guards, all transcript operations and RNG draws are
        always retained. Liveness follows physical register overwrites backwards
        from every WHIR input, assertion and observation. Masks describe the
        original register versions that remain semantically needed at a boundary.
        """
        if terminal_registers is None:
            from wire import parse
            _,roots,_,point,proof=parse(self.tail)
            def flatten(value):
                if isinstance(value,int):yield value
                elif isinstance(value,list):
                    for item in value:yield from flatten(item)
                elif isinstance(value,dict):
                    for item in value.values():yield from flatten(item)
            terminal_registers={x for x in flatten([roots,point,proof]) if x<0x10000000}
        assert all(0<=value<self.registers for value in terminal_registers)
        live=sum(1<<value for value in set(terminal_registers))
        masks=[0]*(len(self.ops)+1);masks[-1]=live;dead=set()
        for at in range(len(self.ops)-1,-1,-1):
            op,dst,*args=self.ops[at]
            count=8 if op in (16,18) else 1 if op in (4,5,6,7,13,15,20,21,22,23) else 0
            writes=((1<<count)-1)<<dst if count else 0
            pure=op in (4,5,6,15,16,18,20,21,22,23)
            if pure and not live&writes:dead.add(at)
            else:
                live&=~writes
                if op in (15,18):args=[]
                if op==14:args=args[1:]
                if op==17:args=args[:1]
                for value in args:
                    if value&0xf0000000==0:live|=1<<value
            masks[at]=live
        self.dead_ops=dead;self.live_masks=masks

    def live_registers(self,at):
        mask=self.live_masks[at]
        return [i for i in range(self.registers) if mask>>i&1]

    def check_arithmetic_types(self):
        """Prove packed arithmetic preconditions for every possible packet.

        The entrypoint canonicalizes all wire fields. Hashes remain unrestricted
        256-bit values and cannot flow into field arithmetic. Physical register
        types follow every overwrite, with sources checked before destinations.
        """
        kinds=['F']*self.registers  # entrypoint initializes all registers to zero
        def kind(value):
            self.ref(value)  # includes proof, constant and register bounds
            if value&0x80000000:return 'F'
            if value&0x40000000:return 'F'
            if value&0x20000000:return 'E'
            if value&0x10000000:return 'H'
            return kinds[value]
        for op,dst,*args in self.ops:
            if op not in (8,10,11,12,14,17):assert 0 <= dst < self.registers
            if op in (4,5,6,20,21,22,23):
                a,b=map(kind,args)
                assert a in ('F','E') and b in ('F','E'),'noncanonical arithmetic operand'
                if op in (20,21,22):assert a==b=='F','base arithmetic requires base fields'
                if op==23:assert b=='F','scalar multiplication requires a base scalar'
                kinds[dst]='E' if 'E' in (a,b) else 'F'
            elif op==7:
                a=kind(args[0]);assert a in ('F','E'),'noncanonical inverse operand'
                kinds[dst]=a
            elif op in (10,11,14,17):
                a=kind(args[1] if op==14 else args[0])
                assert a in (('F','E') if op==11 else ('F',)),'noncanonical transcript/public operand'
            elif op==8:
                for value in args:kind(value)
            elif op==12:
                kind(args[0])
            elif op==13:kinds[dst]='E'
            elif op==15:
                assert 0 <= args[0] < 1<<256
                kinds[dst]='H'
            elif op in (16,18):
                assert dst+7<self.registers
                if op==16:kind(args[0])
                kinds[dst:dst+8]=['F']*8
            else:raise ValueError(('unsupported typed opcode',op))
        self.final_register_kinds=kinds

    def field_kind(self,value):
        """Canonical kind at the handoff to the authenticated WHIR tail."""
        self.ref(value)
        if value&0x80000000:return 'F'
        if value&0x40000000:return 'F'
        if value&0x20000000:return 'E'
        if value&0x10000000:return 'H'
        return self.final_register_kinds[value]

    def ref(self, value, slots=None):
        if value & 0x80000000:
            n = value & 0x7fffffff
            assert n < P
            return hex(n)
        index = value & 0x0fffffff
        if value & 0x40000000:
            assert index < self.meta['field_count']
            return f'le32(calldataload({self.packet+38+4*index}))'
        if value & 0x20000000:
            assert index+3 < self.meta['field_count']
            cached=getattr(self,'proof_cache_offsets',{}).get(index)
            if cached is not None:return f'shr(128,calldataload({cached}))'
            # Four LE32 lanes reverse as one 128-bit little-endian integer.
            return f'reverse128(shr(128,calldataload({self.packet+38+4*index})))'
        if value & 0x10000000:
            assert index < self.meta['hash_count']
            return f'calldataload({self.packet+38+4*self.meta["field_count"]+32*index})'
        assert value < self.registers
        return f'mload({256+32*(value if slots is None else slots[value])})'

    @staticmethod
    def identity_source(instruction):
        """Literal identities, valid after the canonical field type analysis."""
        op,_,*args=instruction
        zero,one=0x80000000,0x80000001
        if op in (4,20):
            if args[0]==zero:return args[1]
            if args[1]==zero:return args[0]
        if op in (5,21) and args[1]==zero:return args[0]
        if op in (6,22,23):
            if zero in args:return zero
            if args[1]==one:return args[0]
            if args[0]==one and op!=23:return args[1]
        return None

    def operand_location(self,value,slots):
        """Class and address of one statically validated field operand."""
        self.ref(value,slots)
        if value&0x80000000:return 'constant',value&0x7fffffff
        index=value&0x0fffffff
        if value&0x40000000:return 'base',self.packet+38+4*index
        if value&0x20000000:
            cached=getattr(self,'proof_cache_offsets',{}).get(index)
            return ('cached',cached) if cached is not None else ('extension',self.packet+38+4*index)
        if value&0x10000000:return 'hash',self.packet+38+4*self.meta['field_count']+32*index
        return 'register',256+32*slots[value]

    def affine_prefix(self,values,slots):
        """Longest exact address progression; no submitted pointer or stride."""
        locations=[self.operand_location(value,slots) for value in values]
        if len(locations)<2:return 1
        kind,first=locations[0];step=locations[1][1]-first
        if kind=='constant' and step:return 1
        for i,location in enumerate(locations):
            if location!=(kind,first+i*step):return i
        return len(locations)

    def indexed_ref(self,first,second,slots):
        kind,at=self.operand_location(first,slots)
        _,after=self.operand_location(second,slots);step=after-at
        pointer=str(at)
        if step>0:pointer=f'add({at},mul(j,{step}))'
        if step<0:pointer=f'sub({at},mul(j,{-step}))'
        return {'constant':str(at),'register':f'mload({pointer})',
                'base':f'le32(calldataload({pointer}))',
                'extension':f'reverse128(shr(128,calldataload({pointer})))',
                'cached':f'shr(128,calldataload({pointer}))',
                'hash':f'calldataload({pointer})'}[kind]

    def arithmetic_loop(self,start,end,slots):
        """Compress repeated mul/add pairs to an identical native loop body.

        Every original operand is checked, and both memory-address sequences
        must be affine after local register allocation. Neither field arithmetic
        nor reduction order changes; every final register write is retained.
        """
        if start+7>=end:return None
        product,addition=self.ops[start:start+2]
        if product[0]!=6 or addition[0]!=4:return None
        temp,acc=product[1],addition[1]
        if temp==acc:return None
        expected=sorted([temp,acc]);operands=[]
        for at in range(start,end-1,2):
            if at in getattr(self,'dead_ops',()) or at+1 in getattr(self,'dead_ops',()):break
            p,a=self.ops[at:at+2]
            if p[0]!=6 or p[1]!=temp or a[0]!=4 or a[1]!=acc or sorted(a[2:])!=expected:break
            if self.identity_source(p) is not None:break
            operands.append(p[2:])
        if len(operands)<4:return None
        n=min(self.affine_prefix([a for a,_ in operands],slots),
              self.affine_prefix([b for _,b in operands],slots))
        if n<4:return None
        left=self.indexed_ref(operands[0][0],operands[1][0],slots)
        right=self.indexed_ref(operands[0][1],operands[1][1],slots)
        target=256+32*slots[temp];total=256+32*slots[acc]
        # Delaying reductions is valid only for independent dot terms. In
        # particular an affine address sequence may still read temp or acc.
        independent=all(value not in (temp,acc) for pair in operands[:n] for value in pair)
        if getattr(self,'fused_dot',False) and independent and n<=1024:
            final_temp=not hasattr(self,'live_masks') or bool(self.live_masks[start+2*n]>>temp&1)
            keep=f'if eq(j,{n-1}) {{mstore({target},reduceWide(ac,bd,cross))}}' if final_temp else ''
            return n,f'''{{ // native batch dot terms: {n}
                let acSum:=0 let bdSum:=0 let crossSum:=0
                for {{let j:=0}} lt(j,{n}) {{j:=add(j,1)}} {{
                    let ac,bd,cross:=wideTimes({left},{right})
                    acSum:=add(acSum,ac) bdSum:=add(bdSum,bd) crossSum:=add(crossSum,cross)
                    {keep}
                }}
                mstore({total},plus(mload({total}),reduceWide(acSum,bdSum,crossSum)))
            }}'''
        return n,f'''for {{let j:=0}} lt(j,{n}) {{j:=add(j,1)}} {{
          mstore({target},times({left},{right}))
          mstore({total},plus(mload({total}),mload({target})))
        }}'''

    def observation_run(self,start,end):
        """Coalesce only adjacent, contiguous, already validated proof bytes."""
        first=None;next_field=None;count=0
        for op,_,*args in self.ops[start:end]:
            if (op,args[0]&0xf0000000 if args else 0) not in ((10,0x40000000),(11,0x20000000)):break
            self.ref(args[0])
            index=args[0]&0x0fffffff
            if next_field is not None and index!=next_field:break
            if first is None:first=index
            next_field=index+(1 if op==10 else 4);count+=1
        if count<2:return None
        return count,f'appendProof({self.packet+38+4*first},{4*(next_field-first)})'

    def matrix_plan(self,start,end,slots):
        """Cache hot multiplicands by exact immutable reference/register version.

        This never shares a cache across an overwrite, even when physical
        register numbers are reused. Existing arithmetic loops stay intact.
        """
        if not getattr(self,'matrix_cache',False):return {},[]
        skipped=set();at=start
        while at<end:
            if at in getattr(self,'dead_ops',()):at+=1;continue
            loop=self.arithmetic_loop(at,end,slots)
            if loop:
                skipped.update(range(at,at+2*loop[0]));at+=2*loop[0]
            else:at+=1
        from collections import defaultdict
        versions={v:-1 for v in slots};positions=defaultdict(set);eligible={}
        for at in range(start,end):
            op,dst,*args=self.ops[at]
            if op==6 and at not in skipped and at not in getattr(self,'dead_ops',()) and self.identity_source(self.ops[at]) is None:
                keys=[('reference',v) if v&0xf0000000 else ('register',v,versions[v]) for v in args]
                eligible[at]=keys
                for key in set(keys):positions[key].add(at)
            count=8 if op in (16,18) else 1 if op in (4,5,6,7,13,15,20,21,22,23) else 0
            for v in range(dst,dst+count):versions[v]=at
        covered=set();plan={};factors=[]
        for _ in range(32):
            if not positions:break
            # Stable tie-breaking keeps generated bytecode reproducible.
            key=max(positions,key=lambda x:(len(positions[x]-covered),x))
            uses=positions.pop(key)-covered
            if len(uses)<getattr(self,'matrix_min_uses',8):break
            index=len(factors);first=min(uses);factors.append((key,first,len(uses)))
            for at in uses:plan[at]=(index,eligible[at].index(key),at==first)
            covered.update(uses)
        return plan,factors

    def register_access(self, start, end):
        """Exact reads-before-writes and final writes, including aliased slots.

        Register allocation reuses physical slots. Read each instruction's
        sources before recording its destinations; root seeding and Poseidon
        each write eight consecutive slots, rather than just their first slot.
        """
        inputs, written, used = set(), set(), set()
        for at,(op, dst, *args) in enumerate(self.ops[start:end],start):
            if at in getattr(self,'dead_ops',()):continue
            identity=self.identity_source([op,dst,*args])
            if identity==dst:continue  # no state change or unchecked side effect
            refs = [identity] if identity is not None else args
            if op == 14: refs = args[1:]
            if op in (15,18): refs = []
            if op == 17: refs = args[:1]
            for value in refs:
                if value & 0xf0000000 == 0:
                    assert 0 <= value < self.registers
                    used.add(value)
                    if value not in written: inputs.add(value)
            if op not in (8,10,11,12,14,17):
                destinations = set(range(dst,dst+(8 if op in (16,18) else 1)))
                assert all(0 <= value < self.registers for value in destinations)
                written.update(destinations)
                used.update(destinations)
        if hasattr(self,'live_masks'):
            written={value for value in written if self.live_masks[end]>>value&1}
        return sorted(inputs), sorted(written), sorted(used)

    def kernel(self, start, end, name):
        ops = self.ops[start:end]
        poseidons = [x for at,x in enumerate(ops,start) if x[0] == 18 and at not in getattr(self,'dead_ops',())]
        assert len(poseidons) <= 1
        inputs, written, used = self.register_access(start,end)
        slots = {value:i for i,value in enumerate(used)}
        lazy_spans=getattr(self,'lazy_linear_spans',None)
        lazy_mode=getattr(self,'lazy_linear_products',False) and (lazy_spans is None or any(lo<=start and end<=hi for lo,hi in lazy_spans))
        identity_spans=getattr(self,'identity_branch_spans',None) or []
        branchless=getattr(self,'branchless_products',False) and not any(lo<=start and end<=hi for lo,hi in identity_spans)
        if lazy_mode:assert getattr(self,'tower_mulmod',False) and branchless,'lazy linear products require the complete tower formula'
        lazy=set()
        raw_ref=lambda value:self.ref(value,slots)
        ref=lambda value:('reducePacked('+raw_ref(value)+')') if value&0xf0000000==0 and value in lazy else raw_ref(value)
        t = 256+32*len(used)
        dense=getattr(self,'contiguous_results',False)
        returned = 288+(32 if dense else 64)*len(written)
        # Fixed workspace stays below the guard. Consume its returned free
        # pointer for the response, so solc can retain the guard and reserve
        # stack-spill memory between the workspace and that response. An unused
        # free pointer gets optimized away and disables stack-to-memory moves.
        guard = max(t+288,0xab40 if poseidons else 256)
        inverse_ops=[(i,op[2]) for i,op in enumerate(self.ops[start:end],start)
                     if op[0]==7 and op[2]&0xf0000000==0x20000000]
        if not getattr(self,'batch_inverse',False) or len(inverse_ops)<4:inverse_ops=[]
        batch_start=guard
        batch_count=len(inverse_ops)
        batch_map={index:batch_start+64*batch_count+32*j for j,(index,_) in enumerate(inverse_ops)}
        guard+=96*batch_count
        matrix_plan,matrix_factors=self.matrix_plan(start,end,slots)
        matrix_start=guard;guard+=160*len(matrix_factors)
        fast_poseidon=getattr(self,'fast_poseidon',False)
        functions = helpers(len(used), bool(poseidons),poseidons[0][-1] if poseidons and fast_poseidon else None,getattr(self,'tower_mulmod',False),getattr(self,'bulk_observe',False),getattr(self,'fast_sample',False),getattr(self,'loop_partial_rounds',False),getattr(self,'tracked_partial_sum',False))
        context_bytes=getattr(self,'context_bytes',self.packet+self.wire_bytes)
        code = [f'mstore(0x40,memoryguard({guard}))\nif iszero(eq(calldatasize(),{context_bytes})) {{ revert(0,0) }}\ncalldatacopy({t},{32*self.registers},288)']
        code += [f'mstore({256+32*slots[value]},calldataload({32*value}))' for value in inputs]
        if inverse_ops:
            for j,(_,value) in enumerate(inverse_ops):code.append(f'mstore({batch_start+32*j},{ref(value)})')
            code.append(f'''{{let product:=1
              for {{let j:=0}} lt(j,{batch_count}) {{j:=add(j,1)}} {{
                mstore(add({batch_start+32*batch_count},mul(j,32)),product)
                product:=times(product,mload(add({batch_start},mul(j,32))))
              }}
              let reciprocal:=invertE(product)
              for {{let j:={batch_count}}} j {{}} {{
                j:=sub(j,1)
                mstore(add({batch_start+64*batch_count},mul(j,32)),times(reciprocal,mload(add({batch_start+32*batch_count},mul(j,32)))))
                reciprocal:=times(reciprocal,mload(add({batch_start},mul(j,32))))
              }}
            }}''')
        skipped_until=start
        for i, (op, dst, *args) in enumerate(ops, start):
            if i<skipped_until:continue
            if i in getattr(self,'dead_ops',()):continue
            observation=self.observation_run(i,end) if getattr(self,'bulk_observe',False) else None
            if observation:
                count,source=observation;code.append(source);skipped_until=i+count
                continue
            loop=self.arithmetic_loop(i,end,slots)
            if loop:
                count,source=loop
                accumulator=self.ops[i+1][1];temporary=self.ops[i][1]
                if accumulator in lazy:
                    code.append(f'mstore({256+32*slots[accumulator]},{ref(accumulator)})')
                code.append(source);skipped_until=i+2*count
                lazy.difference_update((accumulator,temporary))
                continue
            identity=self.identity_source([op,dst,*args])
            if identity==dst:continue
            if op not in (8,10,11,12,14,17):
                assert dst < self.registers
            dest = 256+32*slots[dst] if op not in (8,10,11,12,14,17) else None
            if identity is not None:
                code.append(f'mstore({dest},{ref(identity)})')
                lazy.discard(dst)
                continue
            if op in (4,5,6,20,21,22,23):
                a,b = map(ref,args)
                if lazy_mode and op==6 and i not in matrix_plan:a,b=map(raw_ref,args)
                if lazy_mode and op==23:a=raw_ref(args[0])
                expr = {4:f'plus({a},{b})',5:f'minus({a},{b})',6:f'times({a},{b})',
                        20:f'addmod({a},{b},{P})',21:f'addmod({a},sub({P},{b}),{P})',
                        22:f'mulmod({a},{b},{P})',23:f'scale({a},{b})'}[op]
                if lazy_mode and op in (4,5):
                    expr=f'add({a},{b})' if op==4 else f'sub(add({a},0x7f0000017f0000017f0000017f000001),{b})'
                if i in matrix_plan:
                    index,side,first=matrix_plan[i];at=matrix_start+160*index
                    if first:code.append(f'prepareMatrix({ref(args[side])},{at})')
                    expr=f'matrixTimes({ref(args[1-side])},{at})'
                code.append(f'mstore({dest},{expr})')
                if lazy_mode and op in (4,5):lazy.add(dst)
                else:lazy.discard(dst)
            elif op == 7:
                value=f'mload({batch_map[i]})' if i in batch_map else f'invertE({ref(args[0])})'
                code.append(f'mstore({dest},{value})')
                lazy.discard(dst)
            elif op == 8:
                code.append(f'eqCheck({self.pcs[i]},{ref(args[0])},{ref(args[1])})')
            elif op in (10,11,12):
                v = ref(args[0])
                tag=args[0]&0xf0000000
                if (op,tag) in ((10,0x40000000),(11,0x20000000)):
                    # The complete entrypoint has validated every wire field.
                    # Observe its existing canonical LE bytes directly; avoid
                    # decode/re-encode and repeated canonicality checks. `ref`
                    # above still validates all approved offsets at build time.
                    at=self.packet+38+4*(args[0]&0x0fffffff)
                    code.append(f'append(calldataload({at}),{4 if op==10 else 16})')
                else:
                    code.append({10:f'observeF({v})',11:f'observeE({v})',12:f'append({v},32)'}[op])
            elif op == 13:
                code.append(f'mstore({dest},sampleE())')
                lazy.discard(dst)
            elif op == 14:
                assert 0 <= args[0] <= 32
                code.append(f'grind({args[0]},{ref(args[1])})')
            elif op == 15:
                assert 0 <= args[0] < 1 << 256
                code.append(f'mstore({dest},{hex(args[0])})')
                lazy.discard(dst)
            elif op == 16:
                assert dst+7 < self.registers
                domain = b'ziren-keccak-root-felts-v1'
                code += [f'mstore(0,{hex(int.from_bytes(domain.ljust(32,bytes(1)),"big"))})',
                         f'mstore({len(domain)},{ref(args[0])})',f'mstore(0,keccak256(0,{len(domain)+32}))']
                for j in range(8):
                    code.append(f'mstore({256+32*slots[dst+j]},mod(le32(mload({4*j})),{P}))')
                lazy.difference_update(range(dst,dst+8))
            elif op == 17:
                assert 0 <= args[1] < 32
                output_at = self.registers*32+288
                code.append(f'eqCheck({self.pcs[i]},{ref(args[0])},byte({args[1]},calldataload({output_at})))')
            elif op == 18:
                first,count,_ = args
                assert first+count <= self.meta['field_count'] and dst+7 < self.registers
                diag = re.search(r'hex"([0-9a-f]+)"', (ROOT/'src/KoalaBearPoseidon2.sol').read_text())[1]
                if not fast_poseidon:
                    code += ['codecopy(0xa400,dataoffset("poseidon"),1792)',f'mstore(0xab00,0x{diag[:64]})',f'mstore(0xab20,0x{diag[64:]})']
                code += ['for { let j := 0 } lt(j,512) { j := add(j,32) } { mstore(add(0xa000,j),0) }',
                         f'''for {{ let at := 0 }} lt(at,{count}) {{ at := add(at,8) }} {{
                           let n := sub({count},at) if gt(n,8) {{ n := 8 }}
                           for {{ let j := 0 }} lt(j,n) {{ j := add(j,1) }} {{
                             mstore(add(0xa000,mul(j,32)),le32(calldataload(add({self.packet+38+4*first},mul(add(at,j),4)))))
                           }}
                           permute(0xa000,0xa200,0xa400,0xab00)
                         }}''']
                code += [f'mstore({256+32*slots[dst+j]},mload({0xa000+32*j}))' for j in range(8)]
                lazy.difference_update(range(dst,dst+8))
            else:
                raise ValueError(('unsupported opcode',op))
        # Return semantic transcript state and only final register writes. The
        # root retains every other register, the expected digest and raw proof.
        code.append(f'let response := mload(0x40)\nmcopy(response,{t},288)')
        for j,value in enumerate(written):
            canonical=ref(value)
            if dense:
                code.append(f'mstore(add(response,{288+32*j}),{canonical})')
            else:
                code += [f'mstore(add(response,{288+64*j}),{32*value})',
                         f'mstore(add(response,{320+64*j}),{canonical})']
        code.append(f'return(response,{returned})')
        if any('reducePacked(' in line for line in code):
            assert lazy_mode
            assert 2*P-1+((1<<31)-P)<1<<32
            assert 64*P*P*1024<1<<128
            functions+='''\nfunction reducePacked(value)->out {
                let flags:=and(add(value,0x00ffffff00ffffff00ffffff00ffffff),0x80000000800000008000000080000000)
                out:=sub(value,mul(shr(31,flags),0x7f000001))
            }\n'''
        spans=getattr(self,'stack_register_spans',None)
        if getattr(self,'stack_registers',False) and (spans is None or any(lo<=start and end<=hi for lo,hi in spans)):
            resident=set();at=start
            while at<end:
                if at in getattr(self,'dead_ops',()):at+=1;continue
                loop=self.arithmetic_loop(at,end,slots)
                if loop:
                    for op in self.ops[at:at+2*loop[0]:2]:
                        resident.update(value for value in op[2:] if value&0xf0000000==0)
                    at+=2*loop[0]
                else:at+=1
            code=stack_register_code(code,slots,resident)
        if any('wideTimes(' in line for line in code):functions+=wide_dot_helpers()
        if matrix_factors:functions+='\n'+matrix_helpers(getattr(self,'matrix_left_only',False))+'\n'
        if branchless:functions=branchless_product_helpers(functions)
        data = f'data "poseidon" hex"{poseidons[0][-1]}"' if poseidons and not fast_poseidon else ''
        return f'''object "{name}" {{
          code {{ datacopy(0,dataoffset("Runtime"),datasize("Runtime")) return(0,datasize("Runtime")) }}
          object "Runtime" {{ code {{ {functions}\n{chr(10).join(code)} }} {data} }}
        }}'''


def compiler_input(source,name,optimizer,runs=1):
    inp = {'language':'Yul','sources':{name+'.yul':{'content':source}},
           'settings':{'optimizer':{'enabled':True,'runs':runs,'details':{'yulDetails':{'optimizerSteps':'u','stackAllocation':True}}},'evmVersion':'prague',
                       'outputSelection':{'*':{'*':['evm.bytecode.object','evm.deployedBytecode.object']}}}}
    if optimizer=='full':
        inp['settings']['optimizer'].pop('details')
    elif optimizer=='compact':
        # Documented solc 0.8.30 sequence, retaining function boundaries.
        # https://docs.soliditylang.org/en/v0.8.30/internals/optimizer.html#selecting-optimizations
        inp['settings']['optimizer']['details']['yulDetails']['optimizerSteps']='dhfoD[xarrscLMcCTU]uljmul:fDnTOcmu'
    return json.dumps(inp)


def compile_yul(solc, source, name, cache, optimizer='minimal', timeout=8, fresh=False,runs=1):
    encoded=compiler_input(source,name,optimizer,runs)
    cached=cache/(hashlib.sha256((solc+encoded).encode()).hexdigest()+'.json')
    if cached.exists() and not fresh:
        built=json.loads(cached.read_text());built['optimizer']=optimizer;built['optimizer_runs']=runs
        return built
    result = subprocess.run([solc,'--standard-json'],input=encoded,text=True,capture_output=True,timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stdout+'\n'+result.stderr)
    out = json.loads(result.stdout)
    errors = [e for e in out.get('errors',[]) if e['severity']=='error']
    if errors:
        raise RuntimeError('\n'.join(e['formattedMessage'] for e in errors))
    evm = out['contracts'][name+'.yul'][name]['evm']
    built={'name':name,'source':source,'bytecode':evm['bytecode']['object'],
           'runtime':evm['deployedBytecode']['object'],'optimizer':optimizer,'optimizer_runs':runs}
    cached.write_text(json.dumps(built))
    return built


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--fixtures',type=Path,required=True)
    ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--solc',required=True)
    ap.add_argument('--chunk-ops',type=int,default=1024)
    ap.add_argument('--jobs',type=int,default=4)
    ap.add_argument('--compile-timeout',type=int,help='per-kernel compiler timeout in seconds; does not affect verifier code or gas')
    ap.add_argument('--optimizer',choices=['minimal','full'],default='full')
    ap.add_argument('--runs',type=int,default=1,help='Yul expected execution count, pinned per kernel (default: 1)')
    ap.add_argument('--poseidon-optimizer',choices=['minimal','full','compact'],help='override only kernels containing the public-value Poseidon hash')
    ap.add_argument('--poseidon-runs',type=int,help='independent optimizer runs for kernels containing the public-value Poseidon hash')
    ap.add_argument('--reuse-kernels',action='store_true',help='reuse this trusted local build after checking source and runtime hashes')
    ap.add_argument('--plan',type=Path,help='rebuild exact boundaries/settings from a saved native.json; no adaptive changes')
    ap.add_argument('--fresh',action='store_true',help='bypass compiler cache when checking a frozen plan')
    ap.add_argument('--path-views',action=argparse.BooleanOptionalAction,default=None,
                    help='use bounded full-hash path views; default on for new builds, inherited for saved plans')
    ap.add_argument('--fused-base',action='store_true',help='packed-only first-fold fusion and base-point specialization')
    ap.add_argument('--fast-poseidon',action='store_true',help='unroll the exact authenticated Poseidon permutation')
    ap.add_argument('--loop-partial-rounds',action='store_true',help='retain unrolled external rounds but loop the same 20 scalar partial rounds')
    ap.add_argument('--tracked-partial-sum',action='store_true',help='maintain the exact integer state sum across the original 20 partial rounds')
    ap.add_argument('--stack-registers',action='store_true',help='promote scalar-only local register slots to Yul variables; retain dynamically addressed loop operands')
    ap.add_argument('--stack-register-spans',type=Path,help='trusted JSON instruction intervals selecting register promotion; inherited from a frozen/reused plan when omitted')
    ap.add_argument('--isolate-public-hash',action='store_true',help='put the original public-value hash instruction in its own code-pinned kernel')
    ap.add_argument('--compact-public-bindings',action='store_true',help='use minimal optimization for isolated non-arithmetic binding kernels')
    ap.add_argument('--tower-mulmod',action='store_true',help='exact radix-128 quadratic-tower multiplication using EVM MULMOD')
    ap.add_argument('--batch-inverse',action='store_true',help='batch independent proof-input inversions inside each kernel')
    ap.add_argument('--assertion-facts',action='store_true',help='specialize arithmetic using prior checked equalities; keep every assertion')
    ap.add_argument('--proof-cache',action='store_true',help='decode reusable E4 wire operands once in a private entrypoint cache')
    ap.add_argument('--bulk-observe',action='store_true',help='absorb contiguous proof observations together; preserve 100-byte sponge folds')
    ap.add_argument('--dead-arithmetic',action='store_true',help='omit pure computations that feed no remaining assertion, transcript or WHIR input')
    ap.add_argument('--closing-module',action='store_true',help='evaluate the complete closing identity in one code-pinned auxiliary math contract')
    ap.add_argument('--fast-sample',action='store_true',help='sample E4 limbs in rejection-safe chunks with exact original word consumption')
    ap.add_argument('--inplace-tail',action='store_true',help='reserve private ABI headroom and call the pinned WHIR tail without copying the context')
    ap.add_argument('--entry-runs',type=int,default=1,help='independent entrypoint optimizer runs (default 1)')
    ap.add_argument('--whir-runs',type=int,default=1,help='independent WHIR optimizer runs; exact runtime must fit EIP-170')
    ap.add_argument('--closing-runs',type=int,default=1,help='independent closing-math optimizer runs')
    ap.add_argument('--calldata-tail',action='store_true',help='decode the WHIR context directly from calldata, retaining bounded full leaf/path checks')
    ap.add_argument('--fused-dot',action='store_true',help='delay field reductions across independent affine E4 dot terms')
    ap.add_argument('--matrix-cache',action='store_true',help='cache scalar multiplication matrices for hot E4 multiplicand versions')
    ap.add_argument('--matrix-min-uses',type=int,default=8,help='minimum per-kernel reuse for a prepared E4 matrix (default 8)')
    ap.add_argument('--matrix-left-only',action='store_true',help='use the matrix for every right factor, retaining only the left zero/one shortcut')
    ap.add_argument('--fast-whir-transcript',action='store_true',help='use compact exact WHIR transcript kernels; keep an independent original reference')
    ap.add_argument('--offload-queries',action='store_true',help='batch authenticated query arithmetic in the pinned on-chain math module')
    ap.add_argument('--matrix-query-folds',action='store_true',help='reuse checked coordinate multiplication matrices across query folds')
    ap.add_argument('--stream-query-folds',action='store_true',help='fold checked query calldata directly into one reusable half-row')
    ap.add_argument('--tensor-query-folds',action='store_true',help='reuse exact multilinear basis and accumulate checked query dots with paired direct decoding')
    ap.add_argument('--assembly-initial',action='store_true',help='use checked pointer loops around the original initial query dot product')
    ap.add_argument('--transpose-initial-fold',action='store_true',help='transpose initial weights into bounded four-term scalar dots with explicit term counts')
    ap.add_argument('--assembly-closing',action='store_true',help='use pointer loops for paired closing factors and owned MLE rows')
    ap.add_argument('--validated-leaf-fields',action='store_true',help='use global entry canonicality for approved fixed packet leaf ranges')
    ap.add_argument('--canonical-query-inputs',action='store_true',help='use explicit query variants for packet bytes already validated by the complete entry')
    ap.add_argument('--fixed-whir-profile',action='store_true',help='prove immutable WHIR shapes in the approved decoder at build time; retain all dynamic proof equations')
    ap.add_argument('--merkle-unroll',type=int,choices=(1,4,8),default=1,help='full sibling steps per native path loop, with the exact scalar tail (default 1)')
    ap.add_argument('--base-power-window',type=int,choices=(0,4,6),default=0,help='batch exact fixed-generator exponentiation in the pinned math module (default disabled)')
    ap.add_argument('--shared-power-table',action='store_true',help='reuse the largest approved domain table with bounded exponent shifts for all smaller domains')
    ap.add_argument('--zero-run-fields',action='store_true',help='accept lossless mode-3 field zero runs followed by the unchanged full-hash dictionary')
    ap.add_argument('--lazy-linear-spans',type=Path,help='trusted JSON operation intervals eligible for bounded linear deferral; inherited from a plan when omitted')
    ap.add_argument('--lazy-linear-products',action='store_true',help='keep one bounded unreduced linear layer in private registers and canonicalize strict uses/returns')
    ap.add_argument('--derived-query-inputs',action='store_true',help='reuse canonicality of query parameters derived by the pinned WHIR transcript and arithmetic')
    ap.add_argument('--packed-canonical',action='store_true',help='check the exact four packed extension lane bounds and upper-half bound in parallel')
    ap.add_argument('--offload-proof-cache',action='store_true',help='prepare approved cache ranges in a constructor-created pinned native module using staged owned packet space')
    ap.add_argument('--direct-updates',action='store_true',help='apply bounded kernel return frames directly from returndata without a response array')
    ap.add_argument('--contiguous-results',action='store_true',help='return dense register values and copy approved contiguous runs into fixed root destinations')
    ap.add_argument('--calldata-closing',action='store_true',help='reuse same-contract prepared closing requests and evaluate four bounded Horner steps per reduction')
    ap.add_argument('--native-closing-driver',action='store_true',help='constructor-create a code-pinned native closing driver with canonical ABI and a 32-coefficient Horner fast path')
    ap.add_argument('--vector-proof-cache',action='store_true',help='transpose eight independent cache words together; retain exact bounded scalar tails')
    ap.add_argument('--branchless-products',action='store_true',help='use complete canonical product formulas even for runtime zero and one')
    ap.add_argument('--identity-branch-spans',type=Path,help='trusted operation intervals retaining zero/one product fast paths; cannot select a linear-deferral kernel')
    ap.add_argument('--update-kernels',action='store_true',help='allow longer full-optimizer builds; with reuse-kernels recompile changed sources and retain identical ones')
    a=ap.parse_args()
    if a.stack_register_spans and not a.stack_registers:ap.error('stack-register-spans requires stack-registers')
    if a.lazy_linear_spans and not a.lazy_linear_products:ap.error('lazy-linear-spans requires lazy-linear-products')
    if a.identity_branch_spans and not a.branchless_products:ap.error('identity-branch-spans requires branchless-products elsewhere')
    if a.identity_branch_spans and not a.tower_mulmod:ap.error('identity-branch-spans requires tower-mulmod')
    if a.out.resolve().is_relative_to(ROOT.parents[2]):
        ap.error('generated artifacts must be outside the source repository')
    if not 1 <= a.chunk_ops <= 1024 or not 1 <= a.jobs <= 16:
        ap.error('chunk-ops 1..1024; jobs 1..16')
    if a.compile_timeout is not None and not 1<=a.compile_timeout<=3600:ap.error('compile-timeout 1..3600')
    if not 1 <= a.runs <= 1_000_000:ap.error('runs 1..1000000')
    if a.poseidon_runs is not None and not 1<=a.poseidon_runs<=1_000_000:ap.error('poseidon-runs 1..1000000')
    if (a.poseidon_optimizer is not None or a.poseidon_runs is not None) and not a.fast_poseidon:ap.error('poseidon optimizer overrides require fast-poseidon')
    if not 1 <= a.entry_runs <= 1_000_000:ap.error('entry-runs 1..1000000')
    if not 1 <= a.whir_runs <= 1_000_000:ap.error('whir-runs 1..1000000')
    if not 1 <= a.closing_runs <= 1_000_000:ap.error('closing-runs 1..1000000')
    if not 2 <= a.matrix_min_uses <= 1024:ap.error('matrix-min-uses 2..1024')
    a.out.mkdir(parents=True,exist_ok=True)
    if a.path_views is None:
        saved_plan=a.out/'native.json' if a.reuse_kernels else a.plan
        a.path_views=json.loads(saved_plan.read_text()).get('merkle_path_views',False) if saved_plan else True
    if a.fused_base:assert a.path_views,'fused base requires path views'
    if a.loop_partial_rounds:assert a.fast_poseidon,'partial-round looping requires authenticated Poseidon specialization'
    if a.tracked_partial_sum:assert a.loop_partial_rounds,'tracked partial sum requires the original partial-round loop'
    if a.isolate_public_hash:assert a.fast_poseidon,'public hash isolation requires authenticated Poseidon specialization'
    if a.compact_public_bindings:assert a.isolate_public_hash,'compact public bindings require public hash isolation'
    if a.closing_module:assert a.fused_base,'closing module requires packed native WHIR'
    if a.calldata_tail:assert a.closing_module,'calldata tail requires the packed closing-module path'
    if a.fast_whir_transcript:assert a.fused_base,'fast WHIR transcript requires the independent packed/reference build'
    if a.offload_queries:assert a.calldata_tail,'query offload requires the bounded packed calldata decoder'
    if a.matrix_query_folds:assert a.offload_queries,'matrix query folds require the pinned query module'
    if a.stream_query_folds:assert a.matrix_query_folds,'stream query folds require prepared coordinate matrices'
    if a.tensor_query_folds:assert a.stream_query_folds,'tensor query folds require the checked streaming query path'
    if a.assembly_initial:assert a.offload_queries,'assembly initial fold requires the pinned query module'
    if a.transpose_initial_fold:assert a.assembly_initial,'transposed initial fold requires the checked initial query module'
    if a.assembly_closing:assert a.closing_module and a.tower_mulmod,'assembly closing requires the native closing module and canonical tower arithmetic'
    if a.validated_leaf_fields:assert a.offload_queries and a.calldata_tail,'validated leaf fields require the approved fixed calldata decoder and complete entry'
    if a.canonical_query_inputs:assert a.validated_leaf_fields,'canonical query inputs require global entry validation of the approved leaf ranges'
    if a.fixed_whir_profile:assert a.canonical_query_inputs,'fixed WHIR profile requires the complete-entry canonicality and fixed decoder path'
    if a.merkle_unroll!=1:assert a.path_views,'Merkle unrolling requires the bounded full-word path walker'
    if a.lazy_linear_products:assert a.tower_mulmod and a.branchless_products,'lazy linear products require the full canonical tower kernel'
    if a.derived_query_inputs:assert a.fixed_whir_profile,'derived query inputs require the approved fixed WHIR caller'
    if a.base_power_window:assert a.fixed_whir_profile,'base power windows require the approved fixed WHIR profile'
    if a.shared_power_table:assert a.base_power_window,'shared power table requires fixed-domain windowed exponentiation'
    if a.offload_proof_cache:assert a.proof_cache and a.closing_module and a.inplace_tail,'cache offload requires the proof cache, pinned module and owned context'
    if a.calldata_closing:assert a.closing_module and a.assembly_closing,'calldata closing requires the packed pinned closing module'
    if a.native_closing_driver:assert a.calldata_closing,'native closing driver requires the checked paired-factor and Horner cores'
    if a.vector_proof_cache:assert a.offload_proof_cache,'vector proof cache requires the constructor-created cache module'
    if a.contiguous_results:assert a.direct_updates,'contiguous results require direct updates'
    context_abi='dense-register-results-v2' if a.contiguous_results else 'sparse-register-updates-v1'
    cache=a.out/'compiler-cache';cache.mkdir(exist_ok=True)
    m=json.loads((a.fixtures/'compiled/program.json').read_text())
    c=Compiler(m,(a.fixtures/'compiled/program.bin').read_bytes())
    if a.assertion_facts:c.specialize_assertions()
    if a.dead_arithmetic:c.eliminate_dead_arithmetic()
    if a.proof_cache:c.prepare_proof_cache()
    c.fast_poseidon=a.fast_poseidon;c.batch_inverse=a.batch_inverse;c.tower_mulmod=a.tower_mulmod
    c.bulk_observe=a.bulk_observe
    c.fast_sample=a.fast_sample
    c.inplace_tail=a.inplace_tail
    c.calldata_tail=a.calldata_tail
    c.fused_dot=a.fused_dot
    c.matrix_cache=a.matrix_cache;c.matrix_min_uses=a.matrix_min_uses
    c.matrix_left_only=a.matrix_left_only
    c.offload_queries=a.offload_queries
    c.branchless_products=a.branchless_products
    c.lazy_linear_products=a.lazy_linear_products
    c.loop_partial_rounds=a.loop_partial_rounds
    c.tracked_partial_sum=a.tracked_partial_sum
    c.contiguous_results=a.contiguous_results
    c.stack_registers=a.stack_registers
    spans=None
    if a.stack_register_spans:
        spans=json.loads(a.stack_register_spans.read_text())
    elif a.stack_registers and (a.plan or a.reuse_kernels):
        saved=a.plan or a.out/'native.json'
        spans=json.loads(saved.read_text()).get('stack_register_spans')
    if spans is not None:
        assert isinstance(spans,list) and all(isinstance(row,list) and len(row)==2 and all(type(v) is int for v in row) for row in spans),'invalid register-promotion intervals'
        assert all(0<=lo<hi<=len(c.ops) for lo,hi in spans),'register-promotion interval out of range'
        assert all(left[1]<=right[0] for left,right in zip(spans,spans[1:])),'register-promotion intervals overlap or are unordered'
    c.stack_register_spans=spans
    lazy_spans=None
    if a.lazy_linear_spans:lazy_spans=json.loads(a.lazy_linear_spans.read_text())
    elif a.lazy_linear_products and (a.plan or a.reuse_kernels):
        saved=a.plan or a.out/'native.json'
        lazy_spans=json.loads(saved.read_text()).get('lazy_linear_spans')
    if lazy_spans is not None:
        assert isinstance(lazy_spans,list) and all(isinstance(row,list) and len(row)==2 and all(type(v) is int for v in row) for row in lazy_spans),'invalid linear-deferral intervals'
        assert all(0<=lo<hi<=len(c.ops) for lo,hi in lazy_spans),'linear-deferral interval out of range'
        assert all(left[1]<=right[0] for left,right in zip(lazy_spans,lazy_spans[1:])),'linear-deferral intervals overlap or are unordered'
    c.lazy_linear_spans=lazy_spans
    c.zero_run_fields=a.zero_run_fields
    identity_spans=None
    if a.identity_branch_spans:identity_spans=json.loads(a.identity_branch_spans.read_text())
    elif a.plan or a.reuse_kernels:
        identity_spans=json.loads((a.plan or a.out/'native.json').read_text()).get('identity_branch_spans')
    if identity_spans is not None:
        assert isinstance(identity_spans,list) and all(isinstance(row,list) and len(row)==2 and all(type(v) is int for v in row) for row in identity_spans),'invalid identity-branch intervals'
        assert all(0<=lo<hi<=len(c.ops) for lo,hi in identity_spans),'identity-branch interval out of range'
        assert all(left[1]<=right[0] for left,right in zip(identity_spans,identity_spans[1:])),'identity-branch intervals overlap or are unordered'
    c.identity_branch_spans=identity_spans
    version=subprocess.check_output([a.solc,'--version'],text=True).strip()
    assert 'Version: 0.8.30+' in version,'native profile is pinned to solc 0.8.30'
    def build(bounds):
        lo,hi=bounds;name=f'Kernel_{lo:05d}_{hi:05d}'
        hot=a.fast_poseidon and any(op[0]==18 for op in c.ops[lo:hi])
        if a.isolate_public_hash and hot and hi-lo>1:
            at=next(i for i in range(lo,hi) if c.ops[i][0]==18)
            parts=[(lo,at),(at,at+1),(at+1,hi)]
            return [kernel for part in parts if part[0]<part[1] for kernel in build(part)]
        runs=a.poseidon_runs if hot and a.poseidon_runs is not None else a.runs
        try:
            # Default to preserved permutation boundaries. Hot-kernel-only
            # overrides retain the same adaptive code-size/stack safeguards.
            simple=a.compact_public_bindings and all(op[0] in (8,10,11,12,15,17) for op in c.ops[lo:hi])
            mode=(a.poseidon_optimizer or 'minimal') if hot else 'minimal' if simple else a.optimizer
            r=compile_yul(a.solc,c.kernel(lo,hi,name),name,cache,mode,
                          timeout=a.compile_timeout or (180 if a.update_kernels else 8),runs=runs)
        except (subprocess.TimeoutExpired, RuntimeError) as error:
            if not isinstance(error,subprocess.TimeoutExpired) and 'stack' not in str(error).lower():
                raise
            if hi-lo>32:
                mid=(lo+hi)//2
                return build((lo,mid))+build((mid,hi))
            r=compile_yul(a.solc,c.kernel(lo,hi,name),name,cache,'minimal',runs=runs)
        if len(r['runtime'])//2 > MAX_CODE:
            if hi-lo == 1:raise ValueError('single operation exceeds code limit')
            mid=(lo+hi)//2
            return build((lo,mid))+build((mid,hi))
        r.update(start=lo,end=hi,runtime_bytes=len(r['runtime'])//2,
                 code_hash='0x'+kh(bytes.fromhex(r['runtime'])).hex(),
                 read_registers=c.register_access(lo,hi)[0],
                 write_registers=c.register_access(lo,hi)[1])
        print(f'{name}: {r["runtime_bytes"]} runtime bytes',flush=True)
        return [r]
    bounds=[(i,min(i+a.chunk_ops,len(c.ops))) for i in range(0,len(c.ops),a.chunk_ops)]
    if a.reuse_kernels:
        saved=json.loads((a.out/'native.json').read_text())
        assert saved['source_program_hash']=='0x'+c.program_hash.hex()
        assert saved['context_abi'] in ('sparse-register-updates-v1','dense-register-results-v2'),'unknown native context ABI'
        assert saved['context_abi']==context_abi or a.update_kernels,'context ABI migration requires update-kernels'
        kernels=[];changed=[]
        for r in saved['kernels']:
            r.setdefault('optimizer_runs',200)
            old_source=(a.out/(r['name']+'.yul')).read_text()
            if 'source_hash' in r:
                assert r['source_hash']==hashlib.sha256(old_source.encode()).hexdigest(),'saved kernel source/manifest mismatch'
            r['source']=c.kernel(r['start'],r['end'],r['name'])
            hot=a.fast_poseidon and any(op[0]==18 for op in c.ops[r['start']:r['end']])
            override=hot and (a.poseidon_optimizer is not None or a.poseidon_runs is not None)
            changed_settings=override and (r.get('optimizer')!=(a.poseidon_optimizer or 'minimal')
                or r['optimizer_runs']!=(a.poseidon_runs if a.poseidon_runs is not None else a.runs))
            changed_boundaries=a.isolate_public_hash and hot and r['end']-r['start']>1
            bindings_override=a.compact_public_bindings and all(op[0] in (8,10,11,12,15,17) for op in c.ops[r['start']:r['end']])
            changed_settings=changed_settings or (bindings_override and (r.get('optimizer')!='minimal' or r['optimizer_runs']!=a.runs))
            if r['source']!=old_source or changed_settings or changed_boundaries:
                assert a.update_kernels,'kernel source/settings changed; use update-kernels to compile the new implementation'
                changed.append((len(kernels),(r['start'],r['end'])))
                kernels.append(None)
                continue
            assert r['code_hash']=='0x'+kh(bytes.fromhex(r['runtime'])).hex()
            assert r['runtime_bytes']<=MAX_CODE
            if 'optimizer' not in r:
                # Upgrade an older trusted local manifest without recompiling.
                for mode in ('full','minimal'):
                    key=hashlib.sha256((a.solc+compiler_input(r['source'],r['name'],mode,r['optimizer_runs'])).encode()).hexdigest()
                    candidate=cache/(key+'.json')
                    if candidate.exists() and json.loads(candidate.read_text())['runtime']==r['runtime']:
                        r['optimizer']=mode;break
                assert 'optimizer' in r,'compiler settings missing from trusted cache'
            kernels.append(r)
        # Compile independent changed modules together, retaining their order.
        # Adaptive splitting remains local to each original range.
        with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as pool:
            rebuilt=list(pool.map(build,[bounds for _,bounds in changed]))
        replacements={position:group for (position,_),group in zip(changed,rebuilt)}
        kernels=[kernel for i,kernel in enumerate(kernels)
                 for kernel in (replacements[i] if i in replacements else [kernel])]
    elif a.plan:
        plan=json.loads(a.plan.read_text())
        assert plan['source_program_hash']=='0x'+c.program_hash.hex()
        assert plan['context_abi']==context_abi,'incompatible native context ABI'
        def rebuild(r):
            name=r['name'];source=c.kernel(r['start'],r['end'],name)
            runs=r.get('optimizer_runs',200)
            built=compile_yul(a.solc,source,name,cache,r['optimizer'],a.compile_timeout or 60,a.fresh,runs)
            assert built['runtime']==r['runtime'] and built['bytecode']==r['bytecode'],'frozen compiler output differs'
            return dict(r,source=source,optimizer_runs=runs)
        with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as pool:
            kernels=list(pool.map(rebuild,plan['kernels']))
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as pool:
            kernels=[r for group in pool.map(build,bounds) for r in group]
    assert kernels[0]['start']==0 and kernels[-1]['end']==len(c.ops)
    assert all(a['end']==b['start'] for a,b in zip(kernels,kernels[1:]))
    for kernel in kernels:
        inputs,written,_=c.register_access(kernel['start'],kernel['end'])
        assert kernel['read_registers']==inputs and kernel['write_registers']==written,'inconsistent native register frame'
    src=a.out/'src';src.mkdir(exist_ok=True)
    errors={'StackedWhir.sol':'InvalidWhirShape','KoalaBear.sol':'InvalidArithmeticShape','KeccakTranscript.sol':'InvalidTranscriptShape'}
    for p in (ROOT/'src').glob('*.sol'):
        text=p.read_text()
        if p.name=='NativeTerminalVerifier.sol' and a.offload_proof_cache:text=text.replace('internal pure virtual returns (bytes memory);','internal view virtual returns (bytes memory);',1)
        if p.name=='NativeTerminalVerifier.sol' and a.direct_updates:text=direct_register_updates(text)
        if p.name=='KoalaBear.sol':text=native_field_library(text,a.tower_mulmod)
        if p.name=='KoalaBear.sol' and a.packed_canonical:text=packed_canonical_library(text)
        if p.name=='KoalaBear.sol' and a.assembly_closing:text=assembly_mle_library(text)
        if p.name=='NativeClosingMath.sol' and a.assembly_closing:text=assembly_closing_math(text)
        if p.name=='NativeClosingEvaluator.sol' and a.calldata_closing:text=monomial_yul_core(isolate_monomial_closing(text),4)
        if p.name=='NativeClosingEvaluator.sol' and a.native_closing_driver:
            closing_source=native_closing_source(text)
            (a.out/'NativeClosingDriver.yul').write_text(closing_source)
            closing_driver=compile_yul(a.solc,closing_source,'NativeClosingDriver',cache,'minimal',a.compile_timeout,a.fresh,1)
            assert len(bytes.fromhex(closing_driver['runtime']))<=MAX_CODE
            assert len(bytes.fromhex(closing_driver['bytecode']))<=49152
            (a.out/'native-closing-artifact.json').write_text(json.dumps(closing_driver)+'\n')
            (a.out/'native-closing-creation.bin').write_bytes(bytes.fromhex(closing_driver['bytecode']))
            text=native_closing_wrapper(text,closing_driver)
        if p.name=='INativeClosingEvaluator.sol' and a.calldata_closing:
            assert text.count('external pure returns')==1
            text=text.replace('external pure returns','external view returns',1)
        if p.name=='KeccakTranscript.sol' and a.fast_whir_transcript:text=native_transcript(text)
        if p.name=='NativeWhirMath.sol' and a.transpose_initial_fold:text=transposed_initial_math(text)
        if p.name=='NativeWhirMath.sol' and a.calldata_tail:text=calldata_whir_math(text)
        if p.name=='NativeQueryEvaluator.sol' and a.matrix_query_folds:text=matrix_query_evaluator(text)
        if p.name=='NativeQueryEvaluator.sol' and a.stream_query_folds:text=stream_query_evaluator(text)
        if p.name=='NativeQueryEvaluator.sol' and a.tensor_query_folds:text=tensor_query_evaluator(text)
        if p.name=='NativeQueryEvaluator.sol' and a.assembly_initial:text=assembly_initial_query_evaluator(text,a.transpose_initial_fold)
        if p.name=='NativeQueryEvaluator.sol' and a.canonical_query_inputs:text=canonical_query_evaluator(text)
        if p.name=='NativeQueryEvaluator.sol' and a.derived_query_inputs:text=derived_query_inputs(text)
        if p.name=='INativeQueryEvaluator.sol' and a.canonical_query_inputs:text=canonical_query_interface(text)
        if p.name=='NativeQueryEvaluator.sol' and a.base_power_window:text=windowed_query_powers(text,c,a.base_power_window,a.shared_power_table)
        if p.name=='INativeQueryEvaluator.sol' and a.base_power_window:text=windowed_power_interface(text)
        if p.name=='NativeMerklePath.sol' and a.merkle_unroll!=1:text=unroll_merkle_paths(text,a.merkle_unroll)
        if p.name=='StackedWhir.sol':
            text=native_whir_library(recycle_whir_scratch(text))
            if a.path_views:
                from wire import parse
                text=specialize_whir_generators(native_merkle_path_views(text),parse(c.tail)[0])
            if a.fused_base:text=fused_base_whir(text,parse(c.tail)[0])
            if a.closing_module:text=closing_module_whir(text)
            if a.calldata_tail:text=calldata_whir(text,c.wire_bytes)
            if a.offload_queries:text=offload_query_whir(text)
            if a.validated_leaf_fields:text=validated_leaf_fields(text)
            if a.canonical_query_inputs:text=canonical_query_whir(text)
            if a.fixed_whir_profile:text=fixed_whir_profile(text,c)
            if a.base_power_window:text=windowed_whir_points(text)
            if a.derived_query_inputs:check_query_parameter_derivations(text)
        if p.name in errors:text=compact_shape_errors(text,errors[p.name])
        (src/p.name).write_text(text)
    if a.fused_base:
        reference=(ROOT/'src/StackedWhir.sol').read_text().replace('library StackedWhir {','library ReferenceStackedWhir {').replace('{KoalaBear as F} from "./KoalaBear.sol"','{ReferenceKoalaBear as F} from "./ReferenceKoalaBear.sol"')
        if a.fast_whir_transcript:
            (src/'ReferenceKeccakTranscript.sol').write_text((ROOT/'src/KeccakTranscript.sol').read_text().replace('library KeccakTranscript {','library ReferenceKeccakTranscript {'))
            reference=reference.replace('{KeccakTranscript as T} from "./KeccakTranscript.sol"','{ReferenceKeccakTranscript as T} from "./ReferenceKeccakTranscript.sol"')
        (src/'ReferenceStackedWhir.sol').write_text(reference)
        (src/'ReferenceKoalaBear.sol').write_text((ROOT/'src/KoalaBear.sol').read_text().replace('library KoalaBear {','library ReferenceKoalaBear {'))
        reference=(src/'KeccakTerminalVerifier.sol').read_text().replace('{StackedWhir as W} from "./StackedWhir.sol"','{ReferenceStackedWhir as W} from "./ReferenceStackedWhir.sol"')
        if a.fast_whir_transcript:reference=reference.replace('{KeccakTranscript as T} from "./KeccakTranscript.sol"','{ReferenceKeccakTranscript as T} from "./ReferenceKeccakTranscript.sol"')
        (src/'KeccakTerminalVerifier.sol').write_text(reference)
    if a.closing_module:
        closing_name='NativeQueryEvaluator' if a.offload_queries else 'NativeClosingEvaluator'
        closing_artifact=compile_contract_artifact(a.solc,src,'src/'+closing_name+'.sol',closing_name,a.closing_runs)
        closing_runtime=bytes.fromhex(closing_artifact['deployedBytecode']['object'])
        closing_creation=bytes.fromhex(closing_artifact['bytecode']['object'])
        (a.out/'closing-artifact.json').write_text(json.dumps(closing_artifact)+'\n')
        (a.out/'closing-creation.bin').write_bytes(closing_creation)
        c.closing_module_hash='0x'+kh(closing_runtime).hex()
    # Import only at execution: the decoder generator is independent of solc.
    from wire import entry_source,split_sources
    hashes=''.join(r['code_hash'][2:] for r in kernels)
    tail,entry=split_sources(entry_source(c,hashes,max(len(r['write_registers']) for r in kernels),path_views=a.path_views,fused_base=a.fused_base,
                                        result_registers=[r['write_registers'] for r in kernels]))
    if a.offload_proof_cache:
        cache_source=proof_cache_module_source(c)
        if a.vector_proof_cache:cache_source=vectorize_proof_cache(cache_source)
        (a.out/'ProofCacheModule.yul').write_text(cache_source)
        cache_module=compile_yul(a.solc,cache_source,'ProofCacheModule',cache,'minimal',a.compile_timeout,a.fresh,1)
        assert len(bytes.fromhex(cache_module['runtime']))<=MAX_CODE
        (a.out/'proof-cache-artifact.json').write_text(json.dumps(cache_module)+'\n')
        entry=offload_cache_entry(entry,c,cache_module)
    (src/'CompiledWhirVerifier.sol').write_text(tail)
    whir_artifact=compile_contract_artifact(a.solc,src,'src/CompiledWhirVerifier.sol','CompiledWhirVerifier',a.whir_runs)
    runtime=bytes.fromhex(whir_artifact['deployedBytecode']['object'])
    whir_creation=bytes.fromhex(whir_artifact['bytecode']['object'])
    (a.out/'whir-artifact.json').write_text(json.dumps(whir_artifact)+'\n')
    (a.out/'whir-creation.bin').write_bytes(whir_creation)
    tail_hash='0x'+kh(runtime).hex()
    check='keccak256(type(CompiledWhirVerifier).runtimeCode)'
    assert entry.count(check)==1
    (src/'CompiledTerminalVerifier.sol').write_text(entry.replace(check,tail_hash))
    entry_artifact=compile_contract_artifact(a.solc,src,'src/CompiledTerminalVerifier.sol','CompiledTerminalVerifier',a.entry_runs)
    entry_creation=bytes.fromhex(entry_artifact['bytecode']['object'])
    (a.out/'entry-artifact.json').write_text(json.dumps(entry_artifact)+'\n')
    (a.out/'entry-creation.bin').write_bytes(entry_creation)
    # Do not replace a trusted saved kernel's source before PCS compilation
    # succeeds. Bind source files to the manifest for subsequent reuse.
    for r in kernels:
        source=r.pop('source')
        if a.assertion_facts:r['constant_preconditions']=c.constant_preconditions(r['start'])
        else:r.pop('constant_preconditions',None)
        if a.dead_arithmetic:r['live_registers_after']=c.live_registers(r['end'])
        else:r.pop('live_registers_after',None)
        r['source_hash']=hashlib.sha256(source.encode()).hexdigest()
        (a.out/(r['name']+'.yul')).write_text(source)
    report={'source_program_hash':'0x'+c.program_hash.hex(),'registers':c.registers,
            'context_abi':context_abi,'contiguous_results':a.contiguous_results,
            'context_prefix_bytes':c.prefix,'packet_offset':c.packet,'proof_bytes':c.wire_bytes,
            'kernel_count':len(kernels),'solc_version':version,'entry_optimizer_runs':a.entry_runs,
            'entry_creation_hash':'0x'+kh(entry_creation).hex(),
            'whir_optimizer_runs':a.whir_runs,'whir_creation_hash':'0x'+kh(whir_creation).hex(),
            'closing_optimizer_runs':a.closing_runs if a.closing_module else None,
            'closing_creation_hash':'0x'+kh(closing_creation).hex() if a.closing_module else None,
            'approved_whir_runtime_hash':tail_hash,'approved_whir_runtime_bytes':len(runtime),
            'merkle_path_views':a.path_views,
            'fused_base':a.fused_base,
            'fast_poseidon':a.fast_poseidon,'poseidon_linear_backend':'packed-circulant-deferred-v1' if a.fast_poseidon else None,'batch_inverse':a.batch_inverse,'tower_mulmod':a.tower_mulmod,
            'loop_partial_rounds':a.loop_partial_rounds,
            'tracked_partial_sum':a.tracked_partial_sum,
            'stack_registers':a.stack_registers,
            'assertion_facts':c.assertion_statistics if a.assertion_facts else None,
            'proof_cache_indices':getattr(c,'proof_cache_indices',None),
            'context_bytes':getattr(c,'context_bytes',c.packet+c.wire_bytes),
            'bulk_observe':a.bulk_observe,
            'dead_arithmetic_operations':len(c.dead_ops) if a.dead_arithmetic else 0,
            'closing_module_runtime_hash':getattr(c,'closing_module_hash',None),
            'closing_module_runtime_bytes':len(closing_runtime) if a.closing_module else None,
            'fast_sample':a.fast_sample,
            'inplace_tail':a.inplace_tail,
            'calldata_tail':a.calldata_tail,
            'fused_dot':a.fused_dot,
            'matrix_cache':a.matrix_cache,'matrix_min_uses':a.matrix_min_uses if a.matrix_cache else None,
            'matrix_left_only':a.matrix_left_only,
            'fast_whir_transcript':a.fast_whir_transcript,
            'offload_queries':a.offload_queries,
            'matrix_query_folds':a.matrix_query_folds,
            'stream_query_folds':a.stream_query_folds,'tensor_query_folds':a.tensor_query_folds,
            'assembly_initial':a.assembly_initial,'transpose_initial_fold':a.transpose_initial_fold,
            'assembly_closing':a.assembly_closing,
            'validated_leaf_fields':a.validated_leaf_fields,
            'canonical_query_inputs':a.canonical_query_inputs,
            'fixed_whir_profile':a.fixed_whir_profile,
            'merkle_unroll':a.merkle_unroll,
            'base_power_window':a.base_power_window,
            'shared_power_table':a.shared_power_table,
            'zero_run_fields':a.zero_run_fields,
            'calldata_closing':a.calldata_closing,
            'native_closing_driver':a.native_closing_driver,
            'vector_proof_cache':a.vector_proof_cache,
            'direct_updates':a.direct_updates,
            'offload_proof_cache':a.offload_proof_cache,
            'packed_canonical':a.packed_canonical,
            'derived_query_inputs':a.derived_query_inputs,
            'lazy_linear_products':a.lazy_linear_products,
            'branchless_products':a.branchless_products,
            'identity_branch_spans':identity_spans,
            'yul_optimizer_policy':a.optimizer,'kernels':kernels}
    if not a.loop_partial_rounds:report.pop('loop_partial_rounds')
    if not a.tracked_partial_sum:report.pop('tracked_partial_sum')
    if not a.stack_registers:report.pop('stack_registers')
    if spans is not None:report['stack_register_spans']=spans
    if not a.assembly_initial:report.pop('assembly_initial')
    if not a.assembly_closing:report.pop('assembly_closing')
    if not a.validated_leaf_fields:report.pop('validated_leaf_fields')
    if not a.canonical_query_inputs:report.pop('canonical_query_inputs')
    if not a.fixed_whir_profile:report.pop('fixed_whir_profile')
    if a.merkle_unroll==1:report.pop('merkle_unroll')
    if not a.base_power_window:report.pop('base_power_window')
    if not a.shared_power_table:report.pop('shared_power_table')
    if not a.zero_run_fields:report.pop('zero_run_fields')
    if not a.calldata_closing:report.pop('calldata_closing')
    if not a.native_closing_driver:report.pop('native_closing_driver')
    if not a.vector_proof_cache:report.pop('vector_proof_cache')
    if not a.direct_updates:report.pop('direct_updates')
    if not a.offload_proof_cache:report.pop('offload_proof_cache')
    if not a.packed_canonical:report.pop('packed_canonical')
    if not a.derived_query_inputs:report.pop('derived_query_inputs')
    if not a.lazy_linear_products:report.pop('lazy_linear_products')
    if a.lazy_linear_products and lazy_spans is not None:report['lazy_linear_spans']=lazy_spans
    if a.offload_proof_cache:
        report['proof_cache_module']={'runtime_bytes':len(bytes.fromhex(cache_module['runtime'])),'runtime_hash':'0x'+kh(bytes.fromhex(cache_module['runtime'])).hex(),'embedded_creation':True,'optimizer':'minimal','optimizer_runs':1}
    if a.native_closing_driver:
        report['native_closing_module']={'runtime_bytes':len(bytes.fromhex(closing_driver['runtime'])),'runtime_hash':'0x'+kh(bytes.fromhex(closing_driver['runtime'])).hex(),
            'creation_hash':'0x'+kh(bytes.fromhex(closing_driver['bytecode'])).hex(),'embedded_creation':True,'optimizer':'minimal','optimizer_runs':1,
            'abi':'canonical-evaluate-arrays-v1','horner_fast_path_coefficients':32,'maximum_total_dimensions':24}
    (a.out/'native.json').write_text(json.dumps(report,indent=2)+'\n')
    config=(ROOT/'foundry.toml').read_text().replace('optimizer_runs = 200','optimizer_runs = 1').replace('fs_permissions = []',
        'fs_permissions = [{ access = "read", path = '+json.dumps(str(a.fixtures.resolve()))+' }, { access = "read", path = '+json.dumps(str(a.out.resolve()))+' }]')
    (a.out/'foundry.toml').write_text(config)
    summary={k:v for k,v in report.items() if k not in ('kernels','proof_cache_indices')}
    summary['proof_cache_operands']=len(getattr(c,'proof_cache_indices',[]))
    print(json.dumps(summary))


if __name__=='__main__':
    sys.dont_write_bytecode=True
    main()

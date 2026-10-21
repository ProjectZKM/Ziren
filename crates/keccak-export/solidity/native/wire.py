"""Decode the authenticated KVE2 tail at build time; emit a fixed native reader.

All generated offsets come from the approved binary program. No witness values
or sender-provided configuration become code-generation constants.
"""


class Reader:
    def __init__(self, data):
        self.data, self.at = data, 0

    def n(self, size=1):
        assert self.at+size <= len(self.data)
        value = int.from_bytes(self.data[self.at:self.at+size], 'big')
        self.at += size
        return value

    def vec(self, count=1):
        length, kind = self.n(count), self.n()
        if kind == 0:
            return [self.n(4) for _ in range(length)]
        assert kind in (1,2)
        first = self.n(4)
        tag,stride = (0x40000000,1) if kind == 1 else (0x20000000,4)
        return [tag+first+i*stride for i in range(length)]

    def polys(self):
        return [self.vec() for _ in range(self.n())]


def split_sources(combined):
    """Keep the PCS runtime independent of the entry's code-hash literal.

    Separate source units avoid a circular metadata dependency when the entry
    pins the exact compiled PCS hash instead of embedding its entire runtime.
    """
    tail_marker='/// Auxiliary PCS decoder/verifier; only the complete entrypoint is a settlement verifier.'
    entry_marker='/// Complete AOT machine verifier, including the pinned WHIR tail.'
    tail_at=combined.index(tail_marker); entry_at=combined.index(entry_marker)
    prefix='// SPDX-License-Identifier: MIT\npragma solidity ^0.8.30;\n'
    tail=prefix+'''import {StackedWhir as W} from "./StackedWhir.sol";
import {KeccakTranscript as T} from "./KeccakTranscript.sol";
'''+combined[tail_at:entry_at]
    entry=prefix+'''import {NativeTerminalVerifier} from "./NativeTerminalVerifier.sol";
import {CompiledWhirVerifier} from "./CompiledWhirVerifier.sol";
import {KoalaBearWire as Wire} from "./KoalaBearWire.sol";
import {HashDictionaryWire as Dictionary} from "./HashDictionaryWire.sol";
'''+combined[entry_at:]
    if 'NativeProofCache.' in entry:
        entry=entry.replace('import {NativeTerminalVerifier}', 'import {NativeProofCache} from "./NativeProofCache.sol";\nimport {NativeTerminalVerifier}',1)
    return tail,entry


def parse(data):
    r=Reader(data)
    c=dict(n=r.n(),startingRate=r.n(),batchPow=r.n(),finalQueries=r.n(2),finalPow=r.n())
    rounds=[]
    for _ in range(r.n()):
        a=dict(fold=r.n(),rate=r.n(),queries=r.n(2),ood=r.n(),queryPow=r.n())
        a['foldPow']=[r.n() for _ in range(r.n())]
        rounds.append(a)
    c['rounds']=rounds
    roots=r.vec();stripes=[r.n(2) for _ in range(r.n())];point=r.vec()
    p={'batch':[r.vec(2) for _ in range(r.n())],'batchPow':r.n(4)}
    p['roundPolys']=[r.polys() for _ in range(r.n())]
    p['roundOod']=[r.vec() for _ in range(r.n())]
    p['roots']=r.vec()
    groups=[]
    for _ in range(r.n()):
        leaves=[]
        for _ in range(r.n(2)):
            values=[r.vec(2) for _ in range(r.n(2))]
            leaves.append({'values':values,'path':r.vec()})
        groups.append(leaves)
    p['openings']=groups
    p['finalPoly']=r.vec(2);p['finalPolys']=r.polys();p['foldPow']=r.vec();p['finalPow']=r.n(4)
    assert r.at == len(data)
    return c,roots,stripes,point,p


def register_result_runs(registers, count):
    """Trusted dense frame: (destination byte, source byte, length) runs."""
    assert type(count) is int and count > 0, 'invalid register count'
    assert all(type(r) is int and 0 <= r < count for r in registers), 'result register out of bounds'
    assert registers == sorted(set(registers)), 'result registers must be sorted and unique'
    runs=[]
    for i,r in enumerate(registers):
        if runs and runs[-1][0]+runs[-1][2] == 32*r:
            destination, source, length=runs[-1]
            runs[-1]=(destination,source,length+32)
        else:
            runs.append((32*r,288+32*i,32))
    assert sum(length for _,_,length in runs) == 32*len(registers)
    assert all(destination+length <= 32*count and source+length <= 288+32*len(registers)
               for destination,source,length in runs)
    return runs


def dense_driver_source(layouts, registers):
    """Emit an exact-length decoder whose destinations are approved code."""
    from Crypto.Hash import keccak
    invalid='0x'+keccak.new(digest_bits=256,data=b'InvalidKernel(uint256)').digest()[:4].hex()
    assert 0 < len(layouts) <= 1228, 'invalid dense kernel count'
    cases=[]
    for i,writes in enumerate(layouts):
        runs=register_result_runs(writes,registers)
        copies='\n'.join(f'returndatacopy(add(state,{destination}),{source},{length})'
                         for destination,source,length in runs)
        cases.append(f'''case {i} {{
            if iszero(eq(returned,{288+32*len(writes)})) {{ invalidFrame(i) }}
            {copies}
        }}''')
    return f'''function verify(bytes calldata wire, bytes32 outputDigest) external view override returns (bool) {{
        bytes memory context = _initialize(wire, outputDigest);
        bytes memory addresses = new bytes(20*kernelCount);
        address table = kernelTable;
        assembly("memory-safe") {{ extcodecopy(table,add(addresses,32),1,mload(addresses)) }}
        for (uint256 i; i < kernelCount; ++i) {{
            assembly("memory-safe") {{
                function invalidFrame(index) {{ mstore(0,shl(224,{invalid})) mstore(4,index) revert(0,36) }}
                let kernel := shr(96,mload(add(add(addresses,32),mul(i,20))))
                let state := add(context,32)
                let ok := staticcall(gas(),kernel,state,mload(context),0,0)
                let returned := returndatasize()
                if iszero(ok) {{
                    let at := mload(0x40)
                    returndatacopy(at,0,returned)
                    revert(at,returned)
                }}
                switch i
                {chr(10).join(cases)}
                default {{ invalidFrame(i) }}
                returndatacopy(add(state,{32*registers}),0,288)
            }}
        }}
        return _finish(context);
    }}'''


def entry_source(compiler, hashes, max_writes, path_views=False,fused_base=False,result_registers=None):
    c=compiler
    calldata_tail=getattr(c,'calldata_tail',False)
    cache_call=''
    finish_prefix=''
    if hasattr(c,'proof_cache_ranges'):
        cache_call=f'NativeProofCache.populate(context,{c.packet},{c.meta["field_count"]},hex"{c.proof_cache_ranges.hex()}");'
        finish_prefix=f'assembly("memory-safe"){{mstore(context,{c.packet+c.wire_bytes})}}'
    if path_views:assert c.wire_bytes<1<<32,'path-view offsets exceed their 32-bit descriptor'
    cfg,roots,stripes,point,p=parse(c.tail)
    assert stripes==c.manifest['stripes']
    body=[]
    def scalar(ref):
        # Also apply the native prefix compiler's index/range checks.
        c.ref(ref)
        if ref & 0x80000000:return str(ref & 0x7fffffff)
        ix=ref & 0x0fffffff
        if ref & 0x40000000:return f'_f(packet,{ix})'
        if ref & 0x20000000:return f'_e(packet,{ix})'
        if ref & 0x10000000:return f'uint256(_h(packet,{ix}))'
        return f'_word(context,{32*ref})'

    def vector(target,refs,hashes=False):
        n=len(refs)
        for ref in refs:c.ref(ref)
        if hashes:
            if refs and refs==list(range(refs[0],refs[0]+n)) and refs[0]&0xf0000000==0x10000000:
                body.append(f'{target}=_hs(packet,{refs[0]&0x0fffffff},{n});');return
            body.append(f'{target}=new bytes32[]({n});')
            for i,ref in enumerate(refs):body.append(f'{target}[{i}]=bytes32({scalar(ref)});')
            return
        assert all(c.field_kind(ref) in ('F','E') for ref in refs),'noncanonical WHIR field reference'
        for tag,stride,helper in [(0x20000000,4,'_es'),(0x40000000,1,'_fs')]:
            if refs and refs[0]&0xf0000000==tag and refs==list(range(refs[0],refs[0]+n*stride,stride)):
                body.append(f'{target}={helper}(packet,{refs[0]&0x0fffffff},{n});');return
        body.append(f'{target}=new uint256[]({n});')
        for i,ref in enumerate(refs):body.append(f'{target}[{i}]={scalar(ref)};')

    body.append('W.Config memory config;')
    for k,v in cfg.items():
        if k!='rounds':body.append(f'config.{k}={v};')
    body.append(f'config.rounds=new W.Round[]({len(cfg["rounds"])});')
    for i,round in enumerate(cfg['rounds']):
        for k,v in round.items():
            if k!='foldPow':body.append(f'config.rounds[{i}].{k}={v};')
        body.append(f'config.rounds[{i}].foldPow=new uint256[]({len(round["foldPow"])});')
        for j,v in enumerate(round['foldPow']):body.append(f'config.rounds[{i}].foldPow[{j}]={v};')
    body.append('bytes32[] memory roots;');vector('roots',roots,True)
    body.append(f'uint256[] memory stripes=new uint256[]({len(stripes)});')
    for i,v in enumerate(stripes):body.append(f'stripes[{i}]={v};')
    body.append('uint256[] memory point;');vector('point',point)
    body.append('W.Proof memory p;')
    if calldata_tail:body.append('uint256 packetOffset;assembly("memory-safe"){packetOffset:=packet.offset}')
    body.append(f'p.batch=new uint256[][]({len(p["batch"])});')
    for i,row in enumerate(p['batch']):vector(f'p.batch[{i}]',row)
    assert c.field_kind(p['batchPow'])=='F','noncanonical WHIR grinding witness'
    body.append(f'p.batchPow={scalar(p["batchPow"])};')
    body.append(f'p.roundPolys=new uint256[][][]({len(p["roundPolys"])});')
    for i,group in enumerate(p['roundPolys']):
        body.append(f'p.roundPolys[{i}]=new uint256[][]({len(group)});')
        for j,poly in enumerate(group):vector(f'p.roundPolys[{i}][{j}]',poly)
    body.append(f'p.roundOod=new uint256[][]({len(p["roundOod"])});')
    for i,row in enumerate(p['roundOod']):vector(f'p.roundOod[{i}]',row)
    vector('p.roots',p['roots'],True)
    body.append(f'p.openings=new W.Leaf[][]({len(p["openings"])});')
    if getattr(c,'offload_queries',False):body.append(f'p.dataViews=new uint256[]({2*len(p["openings"])});')
    for ri,leaves in enumerate(p['openings']):
        body.append(f'p.openings[{ri}]=new W.Leaf[]({len(leaves)});')
        descriptors=[]
        for leaf in leaves:
            rows=leaf['values'];assert rows and rows[0]
            width=len(rows[0]);flat=[r for row in rows for r in row]
            for ref in flat+leaf['path']:c.ref(ref)
            assert all(len(row)==width for row in rows)
            assert flat[0]&0xf0000000==0x40000000
            assert flat==list(range(flat[0],flat[0]+len(flat)))
            path=leaf['path'];assert path and path[0]&0xf0000000==0x10000000
            assert path==list(range(path[0],path[0]+len(path)))
            descriptors.append((len(rows),width,flat[0]&0x0fffffff,path[0]&0x0fffffff,len(path)))
        if getattr(c,'offload_queries',False):
            contiguous=[value for leaf in leaves for row in leaf['values'] for value in row]
            assert contiguous and contiguous[0]&0xf0000000==0x40000000
            assert contiguous==list(range(contiguous[0],contiguous[0]+len(contiguous))),'query fields must be one approved contiguous range'
            first=contiguous[0]&0x0fffffff
            assert first+len(contiguous)<=c.meta['field_count']
            body.append(f'p.dataViews[{2*ri}]=packetOffset+{38+4*first};p.dataViews[{2*ri+1}]={4*len(contiguous)};')
        period=len(roots) if ri==0 else 1
        assert len(leaves)%period==0
        repetitions=len(leaves)//period
        body.append(f'for(uint256 q;q<{repetitions};++q){{')
        for j in range(period):
            rows,width,field,hash_index,height=descriptors[j]
            fs=descriptors[j+period][2]-field if repetitions>1 else 0
            hs=descriptors[j+period][3]-hash_index if repetitions>1 else 0
            assert fs>=0 and hs>=0
            assert all(descriptors[j+q*period]==(rows,width,field+q*fs,hash_index+q*hs,height) for q in range(repetitions))
            if path_views:
                assert height<=24,'path-view height exceeds native domain bound'
                path=f'new bytes32[](0)'
                extra=f',((38+4*{c.meta["field_count"]}+32*({hash_index}+q*{hs}))|({height}<<32))'
            else:
                path=f'_hs(packet,{hash_index}+q*{hs},{height})';extra=''
            prefix='' if fused_base else f'new uint256[][](0),{path},'
            leaf_source='packetOffset' if calldata_tail else 'packet'
            body.append(f'p.openings[{ri}][q*{period}+{j}]=W.Leaf({prefix}{leaf_source},38+4*({field}+q*{fs}),{rows},{width}{extra});')
        body.append('}')
    vector('p.finalPoly',p['finalPoly'])
    body.append(f'p.finalPolys=new uint256[][]({len(p["finalPolys"])});')
    for i,row in enumerate(p['finalPolys']):vector(f'p.finalPolys[{i}]',row)
    vector('p.foldPow',p['foldPow'])
    assert c.field_kind(p['finalPow'])=='F','noncanonical WHIR grinding witness'
    body.append(f'p.finalPow={scalar(p["finalPow"])};')
    closing=hasattr(c,'closing_module_hash')
    body.append('W.verify(p,config,roots,stripes,point,t'+(',closingModule' if closing else '')+'); return true;')
    nf,nh=c.meta['field_count'],c.meta['hash_count']
    rbytes=c.registers*32
    profile=c.meta['profile_id']
    generated=f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {{NativeTerminalVerifier}} from "./NativeTerminalVerifier.sol";
import {{StackedWhir as W}} from "./StackedWhir.sol";
import {{KeccakTranscript as T}} from "./KeccakTranscript.sol";
import {{KoalaBearWire as Wire}} from "./KoalaBearWire.sol";
import {{HashDictionaryWire as Dictionary}} from "./HashDictionaryWire.sol";
/// Generated from the authenticated symbolic KVE2 profile. No proof values.
contract CompiledTerminalVerifier is NativeTerminalVerifier {{
 constructor(address[] memory modules) NativeTerminalVerifier(modules,hex"{hashes}",0x{c.program_hash.hex()}) {{}}
 function _prefixLength() internal pure override returns(uint256){{return {c.prefix};}}
 function _initialize(bytes calldata wire,bytes32 outputDigest) internal pure override returns(bytes memory context){{
   if(wire.length<38 || bytes4(wire[:4])!=0x5a4b4554 || wire[4]!=0x01 || bytes32(wire[6:38])!={profile}) revert InvalidPacket();
   if(wire[5]!=0x00 && wire[5]!=0x02) revert InvalidPacket();
   if(wire[5]==0x00 && wire.length!={c.wire_bytes}) revert InvalidPacket();
   Wire.validateFields(wire,38,{nf});
   context=new bytes({getattr(c,'context_bytes',c.packet+c.wire_bytes)});
   if(wire[5]==0x02) Dictionary.decodeInto(wire,context,{c.packet},{nf},{nh});
   bytes32 domain=keccak256("ziren-koalabear-keccak-terminal-v1");
   assembly("memory-safe"){{
     let at:=add(context,32)
     mstore(add(at,{rbytes}),domain)
     mstore(add(at,{rbytes+288}),outputDigest)
     mstore(add(at,{c.prefix}),{c.wire_bytes})
     if iszero(byte(5,calldataload(wire.offset))) {{ calldatacopy(add(at,{c.packet}),wire.offset,wire.length) }}
   }}
   {cache_call}
 }}
 function _word(bytes memory data,uint256 at) private pure returns(uint256 value){{
   assembly("memory-safe"){{value:=mload(add(add(data,32),at))}}
 }}
 function _f(bytes memory packet,uint256 index) private pure returns(uint256 value){{
   assembly("memory-safe"){{let w:=mload(add(add(packet,70),mul(index,4))) value:=or(or(byte(0,w),shl(8,byte(1,w))),or(shl(16,byte(2,w)),shl(24,byte(3,w))))}}
 }}
 function _e(bytes memory packet,uint256 index) private pure returns(uint256 value){{
   assembly("memory-safe"){{
     let w:=shr(128,mload(add(add(packet,70),mul(index,4))))
     value:=or(shl(8,and(w,0x00ff00ff00ff00ff00ff00ff00ff00ff)),and(shr(8,w),0x00ff00ff00ff00ff00ff00ff00ff00ff))
     value:=or(shl(16,and(value,0x0000ffff0000ffff0000ffff0000ffff)),and(shr(16,value),0x0000ffff0000ffff0000ffff0000ffff))
     value:=or(shl(32,and(value,0x00000000ffffffff00000000ffffffff)),and(shr(32,value),0x00000000ffffffff00000000ffffffff))
     value:=or(shl(64,and(value,0x0000000000000000ffffffffffffffff)),shr(64,value))
   }}
 }}
 function _h(bytes memory packet,uint256 index) private pure returns(bytes32 value){{
   assembly("memory-safe"){{value:=mload(add(add(packet,{70+4*nf}),mul(index,32)))}}
 }}
 function _fs(bytes memory packet,uint256 first,uint256 count) private pure returns(uint256[] memory a){{
   a=new uint256[](count);for(uint256 i;i<count;++i)a[i]=_f(packet,first+i);
 }}
 function _es(bytes memory packet,uint256 first,uint256 count) private pure returns(uint256[] memory a){{
   a=new uint256[](count);for(uint256 i;i<count;++i)a[i]=_e(packet,first+4*i);
 }}
 function _hs(bytes memory packet,uint256 first,uint256 count) private pure returns(bytes32[] memory a){{
   a=new bytes32[](count);for(uint256 i;i<count;++i)a[i]=_h(packet,first+i);
 }}
 function _finish(bytes memory context) internal pure override returns(bool){{
   bytes memory packet;
   assembly("memory-safe"){{packet:=add(add(context,32),{c.prefix})}}
   uint256 pending=_word(context,{rbytes+32});
   bytes memory buffered=new bytes(pending);
   for(uint256 i;i<pending;++i)buffered[i]=context[{rbytes+128}+i];
   T.State memory t=T.resume(bytes32(_word(context,{rbytes})),buffered,_word(context,{rbytes+64}));
   {chr(10).join(body)}
 }}
}}
'''
    if getattr(c,'zero_run_fields',False):
        before='if(wire[5]!=0x00 && wire[5]!=0x02) revert InvalidPacket();'
        assert generated.count(before)==1
        generated=generated.replace(before,'if(wire[5]!=0x00 && wire[5]!=0x02 && wire[5]!=0x03) revert InvalidPacket();',1)
        before=f'Wire.validateFields(wire,38,{nf});'
        assert generated.count(before)==1
        generated=generated.replace(before,'if(wire[5]!=0x03) '+before,1)
        before='   if(wire[5]==0x02) Dictionary.decodeInto'
        assert generated.count(before)==1
        expanded=f'''   if(wire[5]==0x03) {{
     Dictionary.decodeInto(wire,context,{c.packet},{nf},{nh});
     Wire.validateMemoryFields(context,{c.packet+38},{nf});
   }}
'''
        generated=generated.replace(before,expanded+before,1)
    # Only the small complete entrypoint is an application verifier. The tail
    # receives private intermediate state exclusively from that entrypoint's
    # pinned kernels; calling the tail alone does not verify a machine proof.
    from Crypto.Hash import keccak
    count=len(hashes)//64
    dense_driver=''
    if getattr(c,'contiguous_results',False):
        assert result_registers is not None and len(result_registers)==count, 'missing approved result layouts'
        dense_driver=dense_driver_source(result_registers,c.registers)
    commitment=keccak.new(digest_bits=256,data=count.to_bytes(32,'big')+bytes.fromhex(hashes)).hexdigest()
    init=generated[generated.index(' function _initialize('):generated.index(' function _word(')]
    helpers=generated[generated.index(' function _word('):generated.rfind('}')]
    helpers=helpers.replace('internal pure override returns(bool)','private pure returns(bool)')
    closing_parameter='';closing_call='';closing_check='';closing_declaration='';closing_constructor='';closing_init=''
    if closing:
        helpers=helpers.replace('function _finish(bytes memory context) private pure','function _finish(bytes memory context,address closingModule) private view')
        closing_parameter=',address closingModule';closing_call=',closingModule'
        closing_check=f'require(closingModule.codehash=={c.closing_module_hash},"closing code hash");'
        closing_declaration='address private immutable closingModule;'
        closing_constructor=',address closing'
        closing_init=f'require(closing.code.length<=24576 && closing.codehash=={c.closing_module_hash},"closing code hash"); closingModule=closing;'
    if calldata_tail:
        before=f'''   bytes memory packet;
   assembly("memory-safe"){{packet:=add(add(context,32),{c.prefix})}}'''
        assert helpers.count(before)==1
        helpers=helpers.replace(before,f'   bytes calldata packet=context[{c.packet}:];',1)
        helpers=helpers.replace('bytes memory context','bytes calldata context').replace('bytes memory packet','bytes calldata packet').replace('bytes memory data','bytes calldata data')
        replacements={
            'mload(add(add(data,32),at))':'calldataload(add(data.offset,at))',
            'mload(add(add(packet,70),mul(index,4)))':'calldataload(add(add(packet.offset,38),mul(index,4)))',
            f'mload(add(add(packet,{70+4*nf}),mul(index,32)))':f'calldataload(add(add(packet.offset,{38+4*nf}),mul(index,32)))',
        }
        for before,after in replacements.items():
            assert before in helpers,before
            helpers=helpers.replace(before,after)
    finish_call=f'return tail.verifyContext(context{closing_call});'
    if getattr(c,'inplace_tail',False):
        # The allocation owns its length word and 96 bytes of ABI headroom.
        # The private context begins at +96. Its data, proof and cached fields
        # keep exactly the same relative offsets seen by every pinned kernel.
        length=getattr(c,'context_bytes',c.packet+c.wire_bytes)
        original=f'context=new bytes({length});'
        assert init.count(original)==1
        init=init.replace(original,f'bytes memory allocation=new bytes({length+96});\n   assembly("memory-safe"){{context:=add(allocation,96) mstore(context,{length})}}',1)
        signature=b'verifyContext(bytes,address)' if closing else b'verifyContext(bytes)'
        selector=keccak.new(digest_bits=256,data=signature).hexdigest()[:8]
        before=68 if closing else 36
        extra='mstore(add(at,36),closing)' if closing else ''
        local='address closing=closingModule;' if closing else ''
        finish_call=f'''address target=address(tail);{local}
   bool result;
   assembly("memory-safe"){{
     let at:=sub(context,{before})
     mstore(at,shl(224,0x{selector}))
     mstore(add(at,4),{64 if closing else 32})
     {extra}
     // Only private headroom is changed. The existing context length word
     // already is the ABI dynamic-bytes length; its data is never copied.
     let size:=add({before+32},and(add(mload(context),31),not(31)))
     let ok:=staticcall(gas(),target,at,size,0,32)
     if iszero(ok){{let dst:=mload(0x40) returndatacopy(dst,0,returndatasize()) revert(dst,returndatasize())}}
     if or(lt(returndatasize(),32),gt(mload(0),1)){{revert(0,0)}}
     result:=mload(0)
   }}
   return result;'''
    header=generated[:generated.index('/// Generated')]
    return header+f'''
/// Auxiliary PCS decoder/verifier; only the complete entrypoint is a settlement verifier.
contract CompiledWhirVerifier {{
 function verifyContext(bytes calldata serialized{closing_parameter}) external {'view' if closing else 'pure'} returns(bool){{
   require(serialized.length=={c.packet+c.wire_bytes},"native context length");
   {closing_check}
   bytes {'calldata' if calldata_tail else 'memory'} context=serialized;
   return _finish(context{closing_call});
 }}
 {helpers}
}}
/// Complete AOT machine verifier, including the pinned WHIR tail.
contract CompiledTerminalVerifier is NativeTerminalVerifier {{
 CompiledWhirVerifier private immutable tail;
 {closing_declaration}
 constructor(address[] memory modules,address whir{closing_constructor}) NativeTerminalVerifier(modules,0x{commitment},{count},0x{c.program_hash.hex()}){{
   require(whir.code.length<=24576 && whir.codehash==keccak256(type(CompiledWhirVerifier).runtimeCode),"WHIR code hash");
   tail=CompiledWhirVerifier(whir);
   {closing_init}
 }}
 function _prefixLength() internal pure override returns(uint256){{return {c.prefix};}}
 function _maxReturnLength() internal pure override returns(uint256){{return {288+(32 if dense_driver else 64)*max_writes};}}
 {dense_driver}
 {init}
 function _finish(bytes memory context) internal view override returns(bool){{{finish_prefix}{finish_call}}}
}}
'''

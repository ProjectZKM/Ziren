#!/usr/bin/env python3
"""Compare native WHIR transcript state with original Solidity and Python."""
import argparse,json,random,sys,time,urllib.parse,urllib.request
from pathlib import Path
sys.dont_write_bytecode=True
from compile import ROOT,P,compile_contract_artifact,compact_shape_errors
from transcript import native_transcript
from reference import Transcript

ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('--out',type=Path,required=True)
ap.add_argument('--solc',required=True)
ap.add_argument('--rpc',default='http://127.0.0.1:18600')
a=ap.parse_args()
assert not a.out.resolve().is_relative_to(ROOT.parents[2])
assert urllib.parse.urlparse(a.rpc).hostname in ('127.0.0.1','localhost')
a.out.mkdir(exist_ok=True,parents=True);src=a.out/'src';src.mkdir(exist_ok=True)
original=(ROOT/'src/KeccakTranscript.sol').read_text()
(src/'KeccakTranscript.sol').write_text(compact_shape_errors(native_transcript(original),'InvalidTranscriptShape'))
(src/'ReferenceKeccakTranscript.sol').write_text(original.replace('library KeccakTranscript {','library ReferenceKeccakTranscript {'))
harness='''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {LIBRARY as T} from "./FILE";
contract NAME {
    function snapshot(T.State memory s,bytes memory out,uint256 at,uint256 value) private pure {
        bytes memory payload=s.payload;
        assembly("memory-safe"){
            let dst:=add(add(out,32),at)
            mstore(dst,mload(s)) mstore(add(dst,32),mload(add(s,64)))
            mstore(add(dst,64),mload(add(s,96))) mstore(add(dst,96),value)
            mcopy(add(dst,128),add(payload,64),mload(add(s,64)))
        }
    }
    fallback() external {
        require(msg.data.length>=224 && (msg.data.length-224)%64==0,"shape");
        bytes32 digest;uint256 pending;uint256 left;
        assembly("memory-safe"){digest:=calldataload(0) pending:=calldataload(32) left:=calldataload(64)}
        require(pending<=128,"test allocation");
        bytes memory buffer=new bytes(pending);
        assembly("memory-safe"){calldatacopy(add(buffer,32),96,pending)}
        T.State memory s=T.resume(digest,buffer,left);
        uint256 count=(msg.data.length-224)/64;
        bytes memory out=new bytes(256*(count+1));snapshot(s,out,0,0);
        for(uint256 i;i<count;++i){
            uint256 tag;uint256 value;uint256 result;
            assembly("memory-safe"){let at:=add(224,mul(i,64)) tag:=calldataload(at) value:=calldataload(add(at,32))}
            if(tag==0)T.observe(s,value);
            else if(tag==1)T.observeE(s,value);
            else if(tag==2)T.observeHash(s,bytes32(value));
            else if(tag==3)result=T.word(s);
            else if(tag==4)result=T.sampleE(s);
            else if(tag==5)result=T.bits(s,value);
            else if(tag==6)result=T.sample(s);
            else if(tag==7)T.grind(s,value>>32,uint32(value));
            else if(tag==8)s.wordsLeft=value;
            else if(tag==9)s.pending=value;
            else revert("tag");
            snapshot(s,out,256*(i+1),result);
        }
        assembly("memory-safe"){return(add(out,32),mload(out))}
    }
}'''
def request(payload):
    req=urllib.request.Request(a.rpc,json.dumps(payload).encode(),{'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=60) as response:return json.load(response)
def rpc(method,params):
    r=request({'jsonrpc':'2.0','id':1,'method':method,'params':params});assert 'error' not in r,r;return r['result']
assert int(rpc('eth_chainId',[]),16)==31337
account=rpc('eth_accounts',[])[0];targets=[]
for fast in (False,True):
    name='NativeHarness' if fast else 'OriginalHarness';library='KeccakTranscript' if fast else 'ReferenceKeccakTranscript'
    s=harness.replace('LIBRARY',library).replace('FILE',library+'.sol').replace('NAME',name)
    (src/(name+'.sol')).write_text(s)
    artifact=compile_contract_artifact(a.solc,src,'src/'+name+'.sol',name,100)
    (a.out/(name+'.json')).write_text(json.dumps(artifact))
    tx=rpc('eth_sendTransaction',[{'from':account,'data':'0x'+artifact['bytecode']['object'],'gas':hex(16000000)}])
    for _ in range(200):
        receipt=rpc('eth_getTransactionReceipt',[tx])
        if receipt:break
        time.sleep(.05)
    assert receipt and int(receipt['status'],16)==1;targets.append(receipt['contractAddress'])
word=lambda x:x.to_bytes(32,'big');rng=random.Random(398201)
def field():return sum(rng.randrange(P)<<(32*i) for i in range(4))
def clone(t):
    q=Transcript();q.digest=t.digest;q.buffer=bytearray(t.buffer);q.left=t.left;return q
def snapshot(t,result=0):return t.digest+word(len(t.buffer))+word(t.left)+word(result)+t.buffer+bytes(128-len(t.buffer))
def step(t,tag,value):
    if tag in (0,1,2):
        if tag==1:value&=(1<<128)-1 # The original API ignores upper bits.
        t.observe(value.to_bytes({0:4,1:16,2:32}[tag],'big' if tag==2 else 'little'));return 0
    if tag==3:return t.word()
    if tag==4:return t.extension()
    if tag==5:return t.word()&((1<<value)-1)
    if tag==6:return t.sample()
    bits=value>>32
    if bits:
        t.observe((value&0xffffffff).to_bytes(4,'little'));assert t.word()&((1<<bits)-1)==0
    return 0
def grind(t,bits):
    if bits==0:return 0
    for witness in range(10000):
        q=clone(t);q.observe(witness.to_bytes(4,'little'))
        if q.word()&((1<<bits)-1)==0:return (bits<<32)|witness
    raise AssertionError('grind search')
def encode(digest,buffer,left,ops):return digest+word(len(buffer))+word(left)+buffer+bytes(128-len(buffer))+b''.join(word(tag)+word(value) for tag,value in ops)
vectors=[]
patterns=[[P]*8,[P-1,P,P+1,0xffffffff,0,1,0x80000000,2],[1,2,3,P,0,0,0,P-1],[1,P,2,P,3,P,4,P],[0]*8]
fixed=[(4,0)]*3+[(3,0),(5,0),(5,32),(6,0),(0,P-1),(1,(P-1)*0x1000000010000000100000001),(2,(1<<256)-1),(4,0)]
for pattern in patterns:
    for left in range(9):
        for pending in (0,1,99):
            digest=b''.join(value.to_bytes(4,'little') for value in pattern);buffer=rng.randbytes(pending)
            for first_observe in (False,True):vectors.append((digest,buffer,left,([(0,P-1)] if first_observe else [])+fixed))
for pending in range(100):vectors.append((rng.randbytes(32),rng.randbytes(pending),pending%9,[(1,field())]*9+[(2,rng.getrandbits(256))]*4+[(4,0),(5,0),(3,0)]))
for _ in range(256):
    t=Transcript();t.digest=rng.randbytes(32);t.buffer=bytearray(rng.randbytes(rng.randrange(100)));t.left=rng.randrange(9);initial=clone(t);ops=[]
    for _ in range(32):
        tag=rng.randrange(8);value=rng.randrange(P) if tag==0 else field() if tag==1 else rng.getrandbits(256) if tag==2 else rng.randrange(33) if tag==5 else grind(t,rng.randrange(5)) if tag==7 else 0
        ops.append((tag,value));step(t,tag,value)
    vectors.append((initial.digest,bytes(initial.buffer),initial.left,ops))
for start in range(0,len(vectors),16):
    requests=[];expected={}
    for i,(digest,buffer,left,ops) in enumerate(vectors[start:start+16]):
        t=Transcript();t.digest=digest;t.buffer=bytearray(buffer);t.left=left;out=snapshot(t)
        for tag,value in ops:out+=snapshot(t,step(t,tag,value))
        data='0x'+encode(digest,buffer,left,ops).hex()
        for j,target in enumerate(targets):
            at=2*i+j;expected[at]='0x'+out.hex();requests.append({'jsonrpc':'2.0','id':at,'method':'eth_call','params':[{'to':target,'data':data,'gas':hex(100000000)},'latest']})
    results=request(requests);assert len(results)==len(requests)
    for result in results:assert 'error' not in result and result['result']==expected[result['id']],(start,result)
bad=[];digest=rng.randbytes(32)
for pending,left in ((100,0),(101,8),(0,9),(99,100)):bad.append(encode(digest,bytes(pending),left,[]))
for op in [(0,P),*[(1,P<<(32*i)) for i in range(4)],(5,33),(7,(33<<32)|1)]:bad.append(encode(digest,b'',0,[op]))
for ops in ([(8,9),(3,0)],[(8,9),(4,0)],[(9,101),(0,1)]):bad.append(encode(digest,b'',0,ops))
t=Transcript();t.digest=digest;witness=0
while True:
    q=clone(t);q.observe(witness.to_bytes(4,'little'))
    if q.word()&3:break
    witness+=1
bad.append(encode(digest,b'',0,[(7,(2<<32)|witness)]))
for data in bad:
    for target in targets:
        result=request({'jsonrpc':'2.0','id':1,'method':'eth_call','params':[{'to':target,'data':'0x'+data.hex()},'latest']})
        assert 'error' in result and result['error'].get('data') not in (None,'0x'),result
extensions=[0,1,(P-1)*0x1000000010000000100000001]
extensions += [x<<(32*i) for i in range(4) for x in (P-1,P,P+1,0x7fffffff,0x80000000,0xffffffff)]
extensions += [rng.getrandbits(128) for _ in range(2048)]
extensions += [field() for _ in range(2048)]
for start in range(0,len(extensions),64):
    requests=[];expected={}
    for i,low in enumerate(extensions[start:start+64]):
        value=low|(rng.getrandbits(128)<<128);valid=all((low>>(32*j))&0xffffffff<P for j in range(4))
        t=Transcript();t.digest=digest;t.left=0;out=snapshot(t)
        if valid:out+=snapshot(t,step(t,1,value))
        data='0x'+encode(digest,b'',0,[(1,value)]).hex()
        for j,target in enumerate(targets):
            at=2*i+j;expected[at]='0x'+out.hex() if valid else None
            requests.append({'jsonrpc':'2.0','id':at,'method':'eth_call','params':[{'to':target,'data':data},'latest']})
    results=request(requests);assert len(results)==len(requests)
    for result in results:
        target=expected[result['id']]
        if target is None:assert 'error' in result and result['error'].get('data') not in (None,'0x'),result
        else:assert 'error' not in result and result['result']==target,result
report={'logical_state_sequences':len(vectors),'operations':sum(len(x[3]) for x in vectors),'invalid_input_cases':len(bad),'all_pending_lengths':list(range(100)),'all_cursor_positions':list(range(9)),'matches_original_solidity_and_python':True,'seed':398201}
report['extension_canonicality_and_upper_bit_cases']=len(extensions)
(a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2),flush=True)

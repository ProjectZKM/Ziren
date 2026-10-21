#!/usr/bin/env python3
"""Check chunked rejection sampling against original EVM and Python models."""
import argparse,json,random,sys,time,urllib.parse,urllib.request
from pathlib import Path
sys.dont_write_bytecode=True
from compile import ROOT,P,compile_yul,helpers
from reference import Transcript

ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('--out',type=Path,required=True)
ap.add_argument('--solc',required=True)
ap.add_argument('--rpc',default='http://127.0.0.1:18600')
a=ap.parse_args()
assert not a.out.resolve().is_relative_to(ROOT.parents[2])
assert urllib.parse.urlparse(a.rpc).hostname in ('localhost','127.0.0.1')
a.out.mkdir(parents=True,exist_ok=True);cache=a.out/'cache';cache.mkdir(exist_ok=True)
def rpc(method,params):
    request=urllib.request.Request(a.rpc,json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),{'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=300) as response:r=json.load(response)
    assert 'error' not in r,r
    return r['result']
assert int(rpc('eth_chainId',[]),16)==31337
account=rpc('eth_accounts',[])[0];addresses=[]
for fast in (False,True):
    name='SampleFast' if fast else 'SampleOriginal'
    source='''object "NAME" {code{datacopy(0,dataoffset("R"),datasize("R")) return(0,datasize("R"))}
object "R" {code {HELPERS
mstore(0x40,memoryguard(1024))
if iszero(eq(calldatasize(),320)) {revert(0,0)}
let count:=calldataload(288) if gt(count,64) {revert(0,0)}
calldatacopy(256,0,288)
let response:=mload(0x40)
for{let i:=0} lt(i,count){i:=add(i,1)} {mstore(add(response,mul(i,32)),sampleE())}
mcopy(add(response,mul(count,32)),256,288)
return(response,add(mul(count,32),288))
}}}'''.replace('NAME',name).replace('HELPERS',helpers(0,False,fast_sample=fast))
    (a.out/(name+'.yul')).write_text(source)
    artifact=compile_yul(a.solc,source,name,cache,'full',60,runs=1)
    assert len(artifact['runtime'])//2<=24576
    tx=rpc('eth_sendTransaction',[{'from':account,'data':'0x'+artifact['bytecode'],'gas':hex(5000000)}])
    for _ in range(200):
        receipt=rpc('eth_getTransactionReceipt',[tx])
        if receipt:break
        time.sleep(.05)
    assert receipt and int(receipt['status'],16)==1
    addresses.append(receipt['contractAddress'])
rng=random.Random(192847);word=lambda x:x.to_bytes(32,'big')
patterns=[[P]*8,[P-1,P,P+1,0xffffffff,0,1,0x80000000,2],[1,2,3,P,0,0,0,P-1],[1,P,2,P,3,P,4,P],[0]*8]
cases=[(b''.join(x.to_bytes(4,'little') for x in pattern),left,pending,count)
       for pattern in patterns for left in range(9) for pending in (0,1,99) for count in (1,2,8)]
cases += [(rng.randbytes(32),rng.randrange(9),rng.randrange(100),rng.randrange(17)) for _ in range(128)]
for digest,left,pending,count in cases:
    reference=Transcript();reference.digest=digest;reference.buffer=bytearray(rng.randbytes(pending));reference.left=left
    state=digest+word(pending)+word(left)+bytes(32)+reference.buffer+bytes(160-pending)
    expected=[reference.extension() for _ in range(count)]
    data='0x'+(state+word(count)).hex();results=[]
    for target in addresses:
        results.append(bytes.fromhex(rpc('eth_call',[{'to':target,'data':data,'gas':hex(10000000)},'latest'])[2:]))
    assert results[0]==results[1],(left,pending,count,'original EVM divergence')
    result=results[1];assert len(result)==count*32+288
    assert [int.from_bytes(result[i*32:i*32+32],'big') for i in range(count)]==expected
    tail=result[count*32:]
    assert tail[:32]==reference.digest and int.from_bytes(tail[32:64],'big')==len(reference.buffer)
    assert int.from_bytes(tail[64:96],'big')==reference.left
    assert tail[128:128+len(reference.buffer)]==reference.buffer
report={'cases':len(cases),'seed':192847,'all_cursor_positions':list(range(9)),'adversarial_rejection_patterns':len(patterns),'matches_original_evm_and_independent_python':True}
(a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

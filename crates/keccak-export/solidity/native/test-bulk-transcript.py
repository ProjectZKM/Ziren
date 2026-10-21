#!/usr/bin/env python3
"""Differential EVM checks for the generated bulk-observation sponge helper."""
import argparse
import json
import random
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
sys.dont_write_bytecode=True
from compile import ROOT,compile_yul,helpers
from reference import Transcript

ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('--out',type=Path,required=True)
ap.add_argument('--solc',required=True)
ap.add_argument('--rpc',default='http://127.0.0.1:18600')
a=ap.parse_args()
assert not a.out.resolve().is_relative_to(ROOT.parents[2]),'artifacts must stay outside repository'
assert urllib.parse.urlparse(a.rpc).hostname in ('127.0.0.1','localhost')
a.out.mkdir(parents=True,exist_ok=True);cache=a.out/'cache';cache.mkdir(exist_ok=True)
def rpc(method,params):
    request=urllib.request.Request(a.rpc,json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),{'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=300) as response:result=json.load(response)
    assert 'error' not in result,result
    return result['result']
assert int(rpc('eth_chainId',[]),16)==31337,'local benchmark only'
name='BulkTranscriptProbe'
source='''object "BulkTranscriptProbe" {
code {datacopy(0,dataoffset("R"),datasize("R")) return(0,datasize("R"))}
object "R" {code {HELPERS
mstore(0x40,memoryguard(1024))
if lt(calldatasize(),288) {revert(0,0)}
calldatacopy(256,0,288)
appendProof(288,sub(calldatasize(),288))
return(256,288)
}}}'''.replace('HELPERS',helpers(0,False,bulk_observe=True))
(a.out/(name+'.yul')).write_text(source)
artifact=compile_yul(a.solc,source,name,cache,'full',60,runs=1)
assert len(artifact['runtime'])//2<=24576
account=rpc('eth_accounts',[])[0]
tx=rpc('eth_sendTransaction',[{'from':account,'data':'0x'+artifact['bytecode'],'gas':hex(5000000)}])
for _ in range(200):
    receipt=rpc('eth_getTransactionReceipt',[tx])
    if receipt:break
    time.sleep(.05)
assert receipt and int(receipt['status'],16)==1
address=receipt['contractAddress'];word=lambda x:x.to_bytes(32,'big');rng=random.Random(591820)
cases=[(pending,n) for pending in (0,1,3,4,16,96,99) for n in (0,1,4,16,31,32,33,99,100,101,512,8192)]
cases += [(rng.randrange(100),rng.randrange(4097)) for _ in range(128)]
for pending,n in cases:
    reference=Transcript();reference.digest=rng.randbytes(32);reference.buffer=bytearray(rng.randbytes(pending));reference.left=rng.randrange(9)
    state=reference.digest+word(pending)+word(reference.left)+bytes(32)+reference.buffer+bytes(160-pending)
    assert len(state)==288
    payload=rng.randbytes(n);reference.observe(payload)
    result=bytes.fromhex(rpc('eth_call',[{'to':address,'data':'0x'+(state+payload).hex(),'gas':hex(20000000)},'latest'])[2:])
    assert len(result)==288
    assert result[:32]==reference.digest,(pending,n,'digest')
    assert int.from_bytes(result[32:64],'big')==len(reference.buffer),(pending,n,'pending')
    assert int.from_bytes(result[64:96],'big')==reference.left,(pending,n,'words')
    assert result[128:128+len(reference.buffer)]==reference.buffer,(pending,n,'bytes')
report={'cases':len(cases),'seed':591820,'pending_boundaries':[0,1,3,4,16,96,99],'max_payload_bytes':8192,'digest_pending_bytes_and_cursor_match_independent_model':True}
(a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

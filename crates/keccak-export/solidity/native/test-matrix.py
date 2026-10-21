#!/usr/bin/env python3
"""Test canonical multiplication matrices and cache-versioned native kernels."""
import argparse,copy,json,random,sys,time,urllib.parse,urllib.request
from pathlib import Path
sys.dont_write_bytecode=True
from compile import ROOT,P,Compiler,compile_yul,helpers,matrix_helpers,branchless_product_helpers
from reference import Transcript,kh

ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('--fixtures',type=Path,required=True)
ap.add_argument('--out',type=Path,required=True)
ap.add_argument('--solc',required=True)
ap.add_argument('--rpc',default='http://127.0.0.1:18600')
ap.add_argument('--cases',type=int,default=16384)
ap.add_argument('--left-only',action='store_true')
ap.add_argument('--branchless-products',action='store_true')
a=ap.parse_args()
if a.cases<1:ap.error('--cases must be positive')
assert not a.out.resolve().is_relative_to(ROOT.parents[2])
assert urllib.parse.urlparse(a.rpc).hostname in ('127.0.0.1','localhost')
a.out.mkdir(exist_ok=True,parents=True);cache=a.out/'cache';cache.mkdir(exist_ok=True)
def request(payload):
    req=urllib.request.Request(a.rpc,json.dumps(payload).encode(),{'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=60) as response:return json.load(response)
def rpc(method,params):
    r=request({'jsonrpc':'2.0','id':1,'method':method,'params':params});assert 'error' not in r,r;return r['result']
assert int(rpc('eth_chainId',[]),16)==31337
account=rpc('eth_accounts',[])[0]
def deploy(built):
    assert len(built['runtime'])//2<=24576
    tx=rpc('eth_sendTransaction',[{'from':account,'data':'0x'+built['bytecode'],'gas':hex(16000000)}])
    for _ in range(200):
        r=rpc('eth_getTransactionReceipt',[tx])
        if r:break
        time.sleep(.05)
    assert r and int(r['status'],16)==1
    return r['contractAddress']
def call(target,data):return bytes.fromhex(rpc('eth_call',[{'to':target,'data':'0x'+data.hex(),'gas':hex(100000000)},'latest'])[2:])
word=lambda x:x.to_bytes(32,'big')
def product(left,right):
    result=[0]*4
    for i in range(4):
        for j in range(4):result[(i+j)%4]+=(3 if i+j>=4 else 1)*((left>>(32*i))&0xffffffff)*((right>>(32*j))&0xffffffff)
    return sum((x%P)<<(32*i) for i,x in enumerate(result))
def plus(left,right):return sum(((((left>>(32*i))&0xffffffff)+((right>>(32*i))&0xffffffff))%P)<<(32*i) for i in range(4))
rng=random.Random(462191);maximal=(P-1)*0x1000000010000000100000001
def field():return sum(rng.randrange(P)<<(32*i) for i in range(4))
addresses=[]
for fast in (False,True):
    name='MatrixProduct' if fast else 'OriginalProduct'
    h=matrix_helpers(a.left_only) if fast else helpers(0,False,tower_mulmod=True)
    if fast and a.branchless_products:h=branchless_product_helpers(h)
    body='mstore(0x40,memoryguard(512)) PREP let value:=EXPR mstore(0,value) return(0,32)'
    body=body.replace('PREP','prepareMatrix(calldataload(32),256)' if fast else '').replace('EXPR','matrixTimes(calldataload(0),256)' if fast else 'times(calldataload(0),calldataload(32))')
    source='object "'+name+'" {code{datacopy(0,dataoffset("R"),datasize("R")) return(0,datasize("R"))} object "R" {code{'+h+'\n'+body+'}}}'
    (a.out/(name+'.yul')).write_text(source)
    addresses.append(deploy(compile_yul(a.solc,source,name,cache,'full',60,runs=1)))
edges=[0,1,P-1,maximal]+[(P-1)<<(32*i) for i in range(4)]
vectors=[(x,y) for x in edges for y in edges]+[(field(),field()) for _ in range(a.cases)]
for start in range(0,len(vectors),128):
    batch=vectors[start:start+128];requests=[];expected={}
    for i,(left,right) in enumerate(batch):
        data='0x'+(word(left)+word(right)).hex();result='0x'+word(product(left,right)).hex()
        for j,target in enumerate(addresses):
            at=2*i+j;expected[at]=result
            requests.append({'jsonrpc':'2.0','id':at,'method':'eth_call','params':[{'to':target,'data':data},'latest']})
    results=request(requests);assert len(results)==len(requests)
    for result in results:assert 'error' not in result and result['result']==expected[result['id']],(start,result)
print(len(vectors),'scalar/original-EVM matrix product cases pass',flush=True)

approved=json.loads((a.fixtures/'compiled/program.json').read_text());original=Compiler(approved,(a.fixtures/'compiled/program.bin').read_bytes());rows=[];kernel_cases=0
for mode in ('register','copy-overwrite','result-overwrite','rng-overwrite','seed-overwrite','proof'):
    c=copy.copy(original);c.tower_mulmod=True;c.fast_sample=True;c.matrix_min_uses=8
    c.matrix_left_only=a.left_only
    c.branchless_products=a.branchless_products
    factor=5 if mode=='seed-overwrite' else 2
    reference=0x20000000 if mode=='proof' else factor
    first=[[6,100+i,reference,10+i] for i in range(8)]
    second=[[6,108+i,18+i,reference] for i in range(8)]
    middle=[]
    if mode=='copy-overwrite':middle=[[4,factor,3,0x80000000]]
    if mode=='result-overwrite':first[-1]=[6,factor,factor,17]
    if mode=='rng-overwrite':middle=[[13,factor]]
    if mode=='seed-overwrite':middle=[[16,2,0x10000000]]
    c.ops=first+middle+second;_,_,used=c.register_access(0,len(c.ops));slots={v:i for i,v in enumerate(used)}
    c.matrix_cache=True;plan,factors=c.matrix_plan(0,len(c.ops),slots)
    assert len(factors)==(1 if mode in ('register','proof') else 2),(mode,factors)
    assert len(plan)==16,(mode,plan)
    targets=[]
    for fast in (False,True):
        c.matrix_cache=fast;name='MatrixKernel_'+mode.replace('-','_')+'_'+str(int(fast));source=c.kernel(0,len(c.ops),name)
        (a.out/(name+'.yul')).write_text(source)
        targets.append(deploy(compile_yul(a.solc,source,name,cache,'full',60,runs=1)))
    for pattern in range(35):
        initial=lambda:0 if pattern==0 else 1 if pattern==1 else maximal if pattern==2 else field()
        registers={v:initial() for v in used};q=initial();root_hash=rng.randbytes(32)
        t=Transcript();t.digest=rng.randbytes(32);t.left=8
        if pattern==0:t.digest=P.to_bytes(4,'little')+t.digest[4:]
        context=bytearray(c.packet+c.wire_bytes)
        for v,value in registers.items():context[32*v:32*v+32]=word(value)
        frame=t.digest+word(0)+word(t.left)+bytes(192)
        assert len(frame)==288
        context[32*c.registers:32*c.registers+288]=frame;context[c.prefix:c.packet]=word(c.wire_bytes)
        context[c.packet+38:c.packet+54]=q.to_bytes(16,'little')
        at=c.packet+38+4*c.meta['field_count'];context[at:at+32]=root_hash
        def source(ref):
            if ref&0x80000000:return ref&0x7fffffff
            if ref==0x20000000:return q
            return registers[ref]
        for op,dst,*args in c.ops:
            if op in (4,6):registers[dst]=(product if op==6 else plus)(source(args[0]),source(args[1]))
            elif op==13:registers[dst]=t.extension()
            elif op==16:
                digest=kh(b'ziren-keccak-root-felts-v1'+root_hash)
                for j in range(8):registers[dst+j]=int.from_bytes(digest[4*j:4*j+4],'little')%P
            else:raise AssertionError(op)
        results=[call(target,context) for target in targets];assert results[0]==results[1],(mode,pattern,'original EVM mismatch')
        result=results[1];assert result[:32]==t.digest
        assert int.from_bytes(result[32:64],'big')==len(t.buffer) and int.from_bytes(result[64:96],'big')==t.left
        assert result[128:128+len(t.buffer)]==t.buffer
        seen=set()
        for at in range(288,len(result),64):
            offset=int.from_bytes(result[at:at+32],'big');assert offset%32==0
            reg=offset//32;assert reg not in seen;seen.add(reg)
            assert int.from_bytes(result[at+32:at+64],'big')==registers[reg],(mode,pattern,reg)
        assert seen==set(c.register_access(0,len(c.ops))[1]);kernel_cases+=1
    rows.append({'mode':mode,'factors':len(factors),'products':len(plan)})
    print(mode,'versioned kernel cases pass',flush=True)
report={'primitive_scalar_and_original_evm_cases':len(vectors),'kernel_differential_cases':kernel_cases,'kernel_configurations':rows,'matches_original_evm_and_scalar_model':True,'seed':462191}
report['matrix_left_only']=a.left_only
(a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2),flush=True)

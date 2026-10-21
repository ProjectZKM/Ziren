#!/usr/bin/env python3
"""Compare delayed native dots with original EVM kernels and scalar E4 math.

Standalone synthetic kernels test arithmetic, not machine-proof validity. All
artifacts stay outside the repository and all calls use a local test chain.
"""
import argparse,copy,importlib.util,json,random,sys,time,urllib.parse,urllib.request
from pathlib import Path
sys.dont_write_bytecode=True
from compile import ROOT,P,Compiler,compile_yul

ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('--fixtures',type=Path,required=True)
ap.add_argument('--out',type=Path,required=True)
ap.add_argument('--solc',required=True)
ap.add_argument('--rpc',default='http://127.0.0.1:18600')
ap.add_argument('--branchless-products',action='store_true')
a=ap.parse_args()
assert not a.out.resolve().is_relative_to(ROOT.parents[2])
assert urllib.parse.urlparse(a.rpc).hostname in ('127.0.0.1','localhost')
a.out.mkdir(parents=True,exist_ok=True);cache=a.out/'cache';cache.mkdir(exist_ok=True)
def rpc(method,params):
    request=urllib.request.Request(a.rpc,json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),{'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=60) as response:r=json.load(response)
    assert 'error' not in r,r
    return r['result']
assert int(rpc('eth_chainId',[]),16)==31337
account=rpc('eth_accounts',[])[0]
def deploy(bytecode):
    tx=rpc('eth_sendTransaction',[{'from':account,'data':'0x'+bytecode,'gas':hex(16000000)}])
    for _ in range(200):
        receipt=rpc('eth_getTransactionReceipt',[tx])
        if receipt:break
        time.sleep(.05)
    assert receipt and int(receipt['status'],16)==1
    return receipt['contractAddress']
def call(address,packet):
    return bytes.fromhex(rpc('eth_call',[{'to':address,'data':'0x'+packet.hex(),'gas':hex(100000000)},'latest'])[2:])
word=lambda value:value.to_bytes(32,'big')
def mul(left,right):
    result=[0]*4
    for i in range(4):
        for j in range(4):
            result[(i+j)%4]+=(3 if i+j>=4 else 1)*((left>>(32*i))&0xffffffff)*((right>>(32*j))&0xffffffff)
    return sum((x%P)<<(32*i) for i,x in enumerate(result))
def add(left,right):return sum(((((left>>(32*i))&0xffffffff)+((right>>(32*i))&0xffffffff))%P)<<(32*i) for i in range(4))
approved=json.loads((a.fixtures/'compiled/program.json').read_text())
original=Compiler(approved,(a.fixtures/'compiled/program.bin').read_bytes())
rng=random.Random(684391);maximal=(P-1)*0x1000000010000000100000001
def value(pattern,index):
    if pattern==0:return maximal
    if pattern==1:return (0,1,maximal,1,0)[index%5]
    return sum(rng.randrange(P)<<(32*i) for i in range(4))

configurations=[(n,'independent',False) for n in (4,5,16,64,127,412,1024)]
configurations += [(n,'independent',True) for n in (5,17,128)]
configurations += [(8,'accumulator',False),(8,'temporary',False),(9,'late-alias',False),(17,'reverse',False)]
cases=0;fused_configurations=0;rows=[]
for n,mode,partial in configurations:
    c=copy.copy(original);c.tower_mulmod=True;c.branchless_products=a.branchless_products
    left=[10+i for i in range(n)]
    if mode=='accumulator':left=[0]*n
    if mode=='temporary':left=[1]*n
    if mode=='late-alias':left=list(range(n-1,-1,-1))
    if mode=='reverse':left=list(range(10+n-1,9,-1))
    right=[0x20000000+4*(n-1-i if mode=='reverse' else i) for i in range(n)]
    c.ops=[op for x,y in zip(left,right) for op in ([6,1,x,y],[4,0,0,1])]
    end=len(c.ops)-int(partial)
    _,_,used=c.register_access(0,end);slots={v:i for i,v in enumerate(used)}
    c.fused_dot=True;loop=c.arithmetic_loop(0,end,slots)
    should_fuse=mode in ('independent','reverse')
    assert bool(loop and 'wideTimes(' in loop[1])==should_fuse,(n,mode,partial)
    fused_configurations+=int(should_fuse)
    addresses=[];sizes=[]
    for fused in (False,True):
        c.fused_dot=fused;name=f'Dot{n}_{mode.replace("-", "_")}_{int(partial)}_{int(fused)}'
        source=c.kernel(0,end,name);(a.out/(name+'.yul')).write_text(source)
        built=compile_yul(a.solc,source,name,cache,'full',60,runs=1)
        assert len(built['runtime'])//2<=24576
        addresses.append(deploy(built['bytecode']));sizes.append(len(built['runtime'])//2)
    for pattern in [0,1]+[2]*32:
        context=bytearray(c.packet+c.wire_bytes);registers={v:value(pattern,v) for v in used}
        for v,x in registers.items():context[32*v:32*v+32]=word(x)
        frame=rng.randbytes(288);context[32*c.registers:32*c.registers+288]=frame
        context[c.prefix:c.packet]=word(c.wire_bytes)
        fields={i:value(pattern,i+19) for i in range(n)}
        for i,x in fields.items():context[c.packet+38+16*i:c.packet+54+16*i]=x.to_bytes(16,'little')
        for op,dst,x,y in c.ops[:end]:
            source=lambda ref:fields[(ref&0x0fffffff)//4] if ref&0x20000000 else registers[ref]
            registers[dst]=(mul if op==6 else add)(source(x),source(y))
        results=[call(address,context) for address in addresses]
        assert results[0]==results[1],(n,mode,partial,pattern,'EVM divergence')
        result=results[1];assert result[:288]==frame
        seen=set()
        for at in range(288,len(result),64):
            slot=int.from_bytes(result[at:at+32],'big');assert slot%32==0
            reg=slot//32;assert reg not in seen;seen.add(reg)
            assert int.from_bytes(result[at+32:at+64],'big')==registers[reg],(n,mode,partial,pattern,reg)
        assert seen==set(c.register_access(0,end)[1])
        cases+=1
    rows.append({'terms':n,'mode':mode,'partial_final_product':partial,'fused':should_fuse,'runtime_bytes':sizes})
    print(json.dumps(rows[-1]),flush=True)
report={'cases':cases,'configurations':rows,'fused_configurations':fused_configurations,'matches_original_evm_and_independent_scalar_convolution':True,'seed':684391}
(a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print('all',cases,'dot differential cases pass',flush=True)

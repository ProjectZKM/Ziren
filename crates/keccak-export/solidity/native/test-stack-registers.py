#!/usr/bin/env python3
"""Differential EVM/Python tests for scalar-register promotion.

Synthetic programs exercise aliases, dynamic forward/reverse loops, batched
inversions, hashing and transcript changes. These are compiler tests, not proofs.
Generated harnesses stay outside the repository. Only local chain 31337 is used.
"""
import argparse,copy,importlib.util,json,random,sys,time,urllib.request,urllib.parse
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('native_compiler',HERE/'compile.py')
g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
from reference import Reference,pack


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--fixtures',type=Path,required=True)
    ap.add_argument('--build',type=Path,required=True)
    ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--solc',required=True)
    ap.add_argument('--rpc',default='http://127.0.0.1:18600')
    ap.add_argument('--lazy-linear-products',action='store_true')
    a=ap.parse_args()
    assert not a.out.resolve().is_relative_to(HERE.parents[3])
    assert urllib.parse.urlparse(a.rpc).hostname in ('localhost','127.0.0.1')
    def rpc(method,params):
        req=urllib.request.Request(a.rpc,json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),{'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=300) as response:r=json.load(response)
        if 'error' in r:raise RuntimeError(r['error'])
        return r['result']
    assert int(rpc('eth_chainId',[]),16)==31337
    account=rpc('eth_accounts',[])[0]
    def deploy(code):
        h=rpc('eth_sendTransaction',[{'from':account,'data':'0x'+code,'gas':hex(10_000_000)}])
        for _ in range(1200):
            receipt=rpc('eth_getTransactionReceipt',[h])
            if receipt:break
            time.sleep(.05)
        assert receipt,('deployment receipt timeout',h)
        assert int(receipt['status'],16)==1,('deployment reverted',h,receipt)
        return receipt['contractAddress']
    def call(address,context):
        return bytes.fromhex(rpc('eth_call',[{'to':address,'data':'0x'+context.hex(),'gas':hex(100_000_000)},'latest'])[2:])
    approved=json.loads((a.fixtures/'compiled/program.json').read_text())
    raw=(a.fixtures/'raw.bin').read_bytes()
    selected=json.loads((a.build/'native.json').read_text())
    original=g.Compiler(approved,(a.fixtures/'compiled/program.bin').read_bytes())
    flags=('fast_poseidon','batch_inverse','tower_mulmod','bulk_observe','fast_sample','inplace_tail','calldata_tail','fused_dot','matrix_cache','matrix_min_uses','matrix_left_only','offload_queries','branchless_products','loop_partial_rounds','tracked_partial_sum')
    for key in flags:setattr(original,key,selected.get(key,False))
    rng=random.Random(631429)
    programs=[]
    forward=[op for i in range(12) for op in ([6,65,i,16+i],[4,64,64,65])]
    programs.append(forward+[[4,0,64,0x80000001],[6,1,0,64]])
    programs.append([op for i in range(12) for op in ([6,65,11-i,27-i],[4,64,64,65])]+[[4,3,64,3]])
    programs.append([op for i in range(8) for op in ([6,65,64,i],[4,64,64,65])]+[[6,64,64,64]])
    ops=[[rng.choice((4,5,6)),rng.randrange(48),rng.randrange(48),rng.randrange(48)] for _ in range(200)]
    ops+= [[16,64,0],[10,0,64],[11,0,30],[13,82],[6,83,82,3],[8,0,83,83]]
    programs.append(ops)
    fields=[int.from_bytes(raw[38+4*i:42+4*i],'little') for i in range(approved['metadata']['field_count'])]
    nonzero=[i for i in range(0,len(fields)-3,4) if any(fields[i:i+4])][:6]
    programs.append([[7,64+i,0x20000000+ix] for i,ix in enumerate(nonzero)]+[[6,70,64,65],[11,0,70],[13,71],[6,72,71,70]])
    # Unrestricted 256-bit values must survive promotion and sparse returns;
    # only the root-to-field instruction reduces its eight output words.
    programs.append([[15,84,(1<<256)-17],[12,0,84],[16,64,84],[10,0,64],[13,82],[6,83,82,3],[8,0,84,84]])
    if a.lazy_linear_products:
        programs.append([[4,0,1,2],[4,3,4,5],[6,6,0,3],[5,7,0,1],[23,8,7,0x80000002],[11,0,8],[13,10],[8,0,8,8]])
        programs.append([[4,0,1,2]]+[[4,16+i,i,32+i] for i in range(12)]+[[6,64+i,0,16+i] for i in range(12)])
    a.out.mkdir(parents=True,exist_ok=True);cache=a.out/'cache';cache.mkdir(exist_ok=True)
    word=lambda x:x.to_bytes(32,'big')
    successes=failures=0;rows=[]
    for number,ops in enumerate(programs):
        c=copy.copy(original);c.ops=ops;c.pcs=list(range(len(ops)))
        assert not hasattr(c,'live_masks') and not hasattr(c,'proof_cache_offsets')
        meta=copy.deepcopy(approved);meta['ops']=ops
        targets=[]
        modes=[(False,False),(False,True),(True,True)] if a.lazy_linear_products else [(False,False),(True,False)]
        for enabled,defer in modes:
            c.stack_registers=enabled;c.lazy_linear_products=defer
            name=f'StackTest_{number}_{int(enabled)}_{int(defer)}';source=c.kernel(0,len(ops),name)
            (a.out/(name+'.yul')).write_text(source)
            artifact=g.compile_yul(a.solc,source,name,cache,'full',300,runs=1)
            assert len(artifact['runtime'])//2<=24576 and len(artifact['bytecode'])//2<=49152
            targets.append(deploy(artifact['bytecode']))
        _,written,_=c.register_access(0,len(ops));cases=0
        for test in range(68):
            ref=Reference(meta,raw,bytes(32))
            for i in range(90):ref.regs[i]=pack([test if test<2 else g.P-1 if test==2 else rng.randrange(g.P) for _ in range(4)])
            if a.lazy_linear_products and test==3:
                for i in range(90):ref.regs[i]=pack([g.P-1 if (i+j)%2==0 else 0 for j in range(4)])
            context=bytearray(c.packet+c.wire_bytes)
            for i,v in enumerate(ref.regs):context[32*i:32*i+32]=word(v)
            reg_bytes=c.registers*32
            context[reg_bytes:reg_bytes+32]=ref.t.digest
            context[c.prefix:c.prefix+32]=word(len(raw));context[c.packet:]=raw
            ref.run(0,len(ops))
            results=[call(address,context) for address in targets]
            assert all(result==results[0] for result in results),(number,test,'original/lazy/stack mismatch')
            result=results[1];assert len(result)==288+64*len(written)
            context[reg_bytes:reg_bytes+288]=result[:288]
            for j,register in enumerate(written):
                at=288+64*j;assert int.from_bytes(result[at:at+32],'big')==32*register
                context[32*register:32*register+32]=result[at+32:at+64]
            ref.check(context[:c.prefix],written);cases+=1;successes+=1
        if number==4:
            at=c.packet+38+4*nonzero[2];context[at:at+16]=bytes(16)
            for address in targets:
                try:call(address,context)
                except RuntimeError as error:assert 'revert' in str(error);failures+=1
                else:raise AssertionError('zero inverse accepted')
        rows.append({'program':number,'instructions':len(ops),'equivalent_evm_python_cases':cases})
    if a.lazy_linear_products:
        c=copy.copy(original);c.ops=[[5,0,1,1],[7,0,0]];c.pcs=[0,1]
        context=bytearray(c.packet+c.wire_bytes)
        context[32:64]=word(pack([g.P-1]*4))
        for enabled,defer in [(False,False),(False,True),(True,True)]:
            c.stack_registers=enabled;c.lazy_linear_products=defer
            name=f'LazyZeroInverse_{int(enabled)}_{int(defer)}';source=c.kernel(0,2,name)
            (a.out/(name+'.yul')).write_text(source)
            artifact=g.compile_yul(a.solc,source,name,cache,'full',300,runs=1)
            address=deploy(artifact['bytecode'])
            try:call(address,context)
            except RuntimeError as error:assert 'revert' in str(error);failures+=1
            else:raise AssertionError('unreduced zero inverse accepted')
    report={'programs':rows,'cases':successes,'zero_inverse_rejections':failures,'seed':631429,'scope':'synthetic compiler equivalence; complete proof checkpoints are checked separately'}
    (a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))


if __name__=='__main__':main()

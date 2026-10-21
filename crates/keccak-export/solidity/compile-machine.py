#!/usr/bin/env python3
"""Compile a trusted, fixed Ziren verifier profile to an EVM reference program.

All runtime arithmetic, transcript samples, assertions and PCS checks must run
on chain. No off-chain acceptance bit is embedded. Input markers identify wire
slots; only independently approved geometry/key/AIR data become constants.
"""
import argparse
import json
import heapq
from pathlib import Path
from functools import reduce

P=0x7f000001
CONST=0x80000000
def integer(x):return int(x,0) if isinstance(x,str) else x
def logceil(n):return (max(1,n)-1).bit_length()
def canonical(m):return m*pow(1<<32,-1,P)%P

class Ref:
    def __init__(self,c,i):self.c=c;self.i=i
    def __add__(self,b):return self.c.binary(4,self,b)
    __radd__=__add__
    def __sub__(self,b):return self.c.binary(5,self,b)
    def __rsub__(self,b):return self.c.binary(5,b,self)
    def __mul__(self,b):return self.c.binary(6,self,b)
    __rmul__=__mul__
    def __neg__(self):return 0-self
    def __truediv__(self,b):return self*self.c.inverse(b)
    def __bool__(self):raise TypeError("witness-dependent host branching is forbidden")

class Compiler:
    def __init__(self):self.ops=[];self.regs=0;self.memo={};self.phases=[];self.base=set()
    def ref(self,x):return x if isinstance(x,Ref) else Ref(self,CONST | (x%P))
    def emit(self,op,*args,count=1):
        out=self.regs;self.regs+=count;self.ops.append((op,out,*args))
        if op in (16,18,20,21,22):self.base.update(range(out,out+count))
        return Ref(self,out)
    def cached(self,op,*args):
        k=(op,*args)
        if k not in self.memo:self.memo[k]=self.emit(op,*args)
        return self.memo[k]
    def binary(self,op,a,b):
        a=self.ref(a);b=self.ref(b)
        if a.i&CONST and b.i&CONST:
            x=a.i&~CONST;y=b.i&~CONST;return self.ref({4:lambda:x+y,5:lambda:x-y,6:lambda:x*y}[op]())
        if op in (4,6) and a.i>b.i:a,b=b,a
        if op==4 and a.i==CONST:return b
        if op==5 and b.i==CONST:return a
        if op==5 and a.i==b.i:return self.ref(0)
        if op==6:
            if a.i==CONST or b.i==CONST:return self.ref(0)
            if a.i==CONST|1:return b
            if b.i==CONST|1:return a
        def base(x):return bool(x.i&CONST or x.i&0x40000000 or x.i in self.base)
        ab,bb=base(a),base(b)
        if ab and bb:op={4:20,5:21,6:22}[op]
        elif op==6 and (ab or bb):
            op=23
            if ab:a,b=b,a
        return self.cached(op,a.i,b.i)
    def inverse(self,a):
        a=self.ref(a)
        if a.i&CONST:return self.ref(pow(a.i&~CONST,-1,P))
        return self.cached(7,a.i)
    def equal(self,a,b):
        a=self.ref(a);b=self.ref(b)
        if a.i!=b.i:self.emit(8,a.i,b.i,count=0)
    def observe(self,a,kind=10):self.emit(kind,self.ref(a).i,count=0)
    def sample(self):return self.emit(13)
    def grind(self,bits,witness):self.emit(14,bits,self.ref(witness).i,count=0)
    def phase(self,name):self.phases.append((name,len(self.ops)))
    def field(self,x):assert isinstance(x,dict) and 'f' in x;return Ref(self,0x40000000|x['f'])
    def ext(self,x):
        x=x['value'] if isinstance(x,dict) and 'value' in x else x
        assert len(x)==4 and [v['f'] for v in x]==list(range(x[0]['f'],x[0]['f']+4))
        return Ref(self,0x20000000|x[0]['f'])
    def exts(self,x):return [self.ext(v) for v in x]
    def hash(self,x):
        # A MerkleCap serializes as {roots:[hash],_phantom:null}.
        if isinstance(x,dict) and 'cap' in x:x=x['cap'][0]
        assert isinstance(x,dict) and 'h' in x,x
        return Ref(self,0x10000000|x['h'])
    def constant_hash(self,x):return self.cached(15,integer(x))
    def seed(self,h):
        out=self.emit(16,h.i,count=8);return [Ref(self,out.i+i) for i in range(8)]
    def emit_air(self,desc,main,prep,pv,alpha):
        values=main+prep+pv
        def arg(i):return self.ref(i&~CONST) if i&CONST else values[i]
        for op,a,b in desc['air_ops']:values.append(self.binary([4,5,6][op],arg(a),arg(b)))
        return reduce(lambda acc,i:acc*alpha+arg(i),desc['air_roots'],self.ref(0))

def layout(a,b):
    if isinstance(a,list):
        if len(a)==32 and all(isinstance(v,int) and 0<=v<256 for v in a) and bytes(a[:8])==b'EVMDIGST':
            assert a==b;return {'h':int.from_bytes(bytes(a[8:12]),'little')}
        assert len(a)==len(b);return [layout(x,y) for x,y in zip(a,b)]
    if isinstance(a,dict):
        if 'Uniform' in a:
            ua=a['Uniform'];ub=b['Uniform'];assert ua['width']==ub['width'];width=ua['width']
            fields=layout(ua['values'],ub['values']);assert width>0 and len(fields)%width==0
            return [fields[i:i+width] for i in range(0,len(fields),width)]
        assert a.keys()==b.keys();return {k:layout(v,b[k]) for k,v in a.items()}
    if a!=b:
        assert isinstance(a,int) and canonical(b)-canonical(a)==1_000_000
        return {'f':canonical(a)-1}
    return a

def eq(a,b):
    assert len(a)==len(b)
    return reduce(lambda acc,p:acc*((1-p[0])*(1-p[1])+p[0]*p[1]),zip(a,b),1)
def table(point):
    v=[1]
    for r in point:v=[x*(1-r) for x in v]+[x*r for x in v]
    return v
def mle(values,point):
    assert len(values)==1<<len(point);v=list(values)
    for r in point:v=[v[2*i]+r*(v[2*i+1]-v[2*i]) for i in range(len(v)//2)]
    return v[0]
def horner(a,x):return reduce(lambda v,c:v*x+c,reversed(a),0)
def geq(threshold,point):
    assert len(threshold)==len(point);v=1
    for x,y in zip(reversed(threshold),reversed(point)):v=((1-y)*(1-x)+y*x)*v+y*(1-x)
    return v
def sumcheck(c,p,degree):
    polys=[c.exts(poly['coefficients']) for poly in p['univariate_polys']]
    point=c.exts(p['point_and_eval'][0]);claim=c.ext(p['claimed_sum'])
    assert len(polys)==len(point) and len(polys)>0
    for i,poly in enumerate(polys):
        assert len(poly)==degree+1;c.equal(poly[0]+sum(poly),claim)
        for v in poly:c.observe(v,11)
        x=c.sample();c.equal(x,point[len(point)-1-i]);claim=horner(poly,x)
    c.equal(claim,c.ext(p['point_and_eval'][1]));return point,claim
def affine(c,a,main,prep):
    return sum((c.ref(weight)*(main if kind==0 else prep)[index] for kind,index,weight in a['weights']),c.ref(a['constant']))
def lookup(c,a,main,prep,alpha,betas):
    return affine(c,a['multiplicity'],main,prep), alpha+betas[0]*a['kind']+sum((b*affine(c,v,main,prep) for b,v in zip(betas[1:],a['values'])),c.ref(0))
def observe_openings(c,groups):
    c.observe(len(groups))
    for prep,main in groups:
        for a in [prep,main]:
            c.observe(len(a))
            for v in a:c.observe(v,11)

def gkr_and_zero(c,meta,s,pv):
    c.phase('GKR');p=s['logup_gkr_proof'];desc=meta['chips'];opening=s['opened_values']['chips']
    names=[d['name'] for d in desc];assert names==sorted(names)
    gkr=p['logup_evaluations'];gkr_open=gkr['chip_openings']
    n=c.exts(p['circuit_output']['numerator']);d=c.exts(p['circuit_output']['denominator'])
    assert len(n)==len(d) and len(n)==1<<logceil(len(n));initial=logceil(len(n))
    c.grind(meta['gkr_grinding_bits'],c.field(p['witness']));alpha=c.sample()
    arity=max(len(l['values'])+1 for chip in desc for l in chip['lookups'])
    betas=table([c.sample() for _ in range(logceil(arity))])
    # Production recursion AIRs have no State/GlobalAccumulation/control buses.
    assert not any(l['kind'] in (9,10,11,12) for chip in desc for l in chip['lookups'])
    c.equal(sum((a/b for a,b in zip(n,d)),c.ref(0)),0)
    for a in n+d:c.observe(a,11)
    point=[c.sample() for _ in range(initial)];ne=mle(n,point);de=mle(d,point)
    assert len(p['round_proofs'])==21
    for i,r in enumerate(p['round_proofs']):
        lam=c.sample();c.equal(c.ext(r['sumcheck_proof']['claimed_sum']),lam*ne+de)
        q,val=sumcheck(c,r['sumcheck_proof'],3);assert len(q)==i+initial
        n0,n1,d0,d1=[c.ext(r[k]) for k in ['numerator_0','numerator_1','denominator_0','denominator_1']]
        c.equal(val,eq(q,point)*(lam*(n0*d1+n1*d0)+d0*d1))
        for a in [n0,n1,d0,d1]:c.observe(a,11)
        line=c.sample();point=q[:initial-1]+[line]+q[initial-1:]
        ne=n0+(n1-n0)*line;de=d0+(d1-d0)*line
    interaction=point[:initial-1];trace=point[initial-1:];assert len(trace)==22
    for a,b in zip(trace,c.exts(gkr['point'])):c.equal(a,b)
    nums=[];dens=[];groups=[]
    for chip,o in zip(desc,opening):
        m=c.exts(gkr_open[chip['name']]['main_trace_evaluations_full'] or [])
        pp=c.exts(gkr_open[chip['name']]['preprocessed_trace_evaluations_full'] or [])
        mask=geq(c.exts(o['quotient'][0]),[0]+list(reversed(trace)))
        for l in chip['lookups']:
            rn,rd=lookup(c,l,m,pp,alpha,betas);pn,pd=lookup(c,l,[0]*len(m),[0]*len(pp),alpha,betas)
            num=rn-pn*mask;nums.append(num if l['send'] else -num);dens.append(rd+(1-pd)*mask)
        groups.append((pp,m))
    width=1<<len(interaction);assert len(nums)<=width
    c.equal(ne,mle(nums+[0]*(width-len(nums)),interaction));c.equal(de,mle(dens+[1]*(width-len(dens)),interaction))
    observe_openings(c,groups)
    c.phase('zerocheck');a=c.sample();batch=c.sample();lam=c.sample();zero=s['zerocheck_proof'];z=c.exts(zero['point_and_eval'][0]);assert len(z)==22
    batch_powers=[];v=1
    for _ in range(max(chip['main_width']+chip['prep_width'] for chip in desc)):v=v*batch;batch_powers.append(v)
    expected=0
    for pp,m in groups:expected=expected*lam+sum((o*b for o,b in zip(m+pp,batch_powers)),c.ref(0))
    c.equal(c.ext(zero['claimed_sum']),expected)
    rlc=0;eqval=eq(list(reversed(trace)),z);opened=[]
    for chip,o in zip(desc,opening):
        m=c.exts(o['main']['local']);pp=c.exts(o['preprocessed']['local']);assert len(m)==chip['main_width'] and len(pp)==chip['prep_width']
        ce=c.emit_air(chip,m,pp,pv,a);pra=c.emit_air(chip,[c.ref(0)]*len(m),[c.ref(0)]*len(pp),pv,a)
        mask=geq(c.exts(o['quotient'][0]),[0]+z)
        ob=sum((o*b for o,b in zip(m+pp,batch_powers)),c.ref(0));rlc=rlc*lam+eqval*(ce-pra*mask+ob)
        opened.append((pp,m))
    c.equal(rlc,c.ext(zero['point_and_eval'][1]));sumcheck(c,zero,4);observe_openings(c,opened)
    return z,opened

def poseidon(c,values,constants):
    def linear(s):
        out=[]
        for i in range(0,16,4):
            a,b,d,e=s[i:i+4];t=a+b+d+e;out += [t+b+a+b,t+b+2*d,t+e+d+e,t+e+2*a]
        sums=[sum(out[j::4],c.ref(0)) for j in range(4)];return [x+sums[i%4] for i,x in enumerate(out)]
    diag=[-2,1,2,pow(2,-1,P),3,4,-pow(2,-1,P),-3,-4,pow(256,-1,P),pow(8,-1,P),pow(1<<24,-1,P),-pow(256,-1,P),-pow(8,-1,P),-pow(16,-1,P),-pow(1<<24,-1,P)]
    def perm(s):
        s=linear(s)
        for r in range(28):
            if r<4 or r>=24:
                s=[(x+constants[r][i])*(x+constants[r][i])*(x+constants[r][i]) for i,x in enumerate(s)];s=linear(s)
            else:
                x=s[0]+constants[r][0];s[0]=x*x*x;total=sum(s,c.ref(0));s=[total+x*d for x,d in zip(s,diag)]
        return s
    s=[c.ref(0)]*16
    for i in range(0,len(values),8):s[:len(values[i:i+8])]=values[i:i+8];s=perm(s)
    return s[:8]

def public_bindings(c,meta,pv):
    c.phase('public bindings');b=meta['public_binding']
    for key,off in [('application','application_offset'),('recursion_root','root_offset')]:
        for i,x in enumerate(b[key]):c.equal(pv[b[off]+i],x)
    c.equal(pv[b['complete_offset']],1);c.equal(pv[b['execution_offset']],1);c.equal(pv[b['exit_offset']],0)
    for i in range(32):c.emit(17,pv[b['committed_offset']+i].i,i,count=0)
    inputs=pv[:b['hash_inputs']]
    assert [x.i for x in inputs]==list(range(inputs[0].i,inputs[0].i+len(inputs))) and inputs[0].i&0x40000000
    constants=''.join(int(x).to_bytes(4,'big').hex() for row in meta['poseidon_constants'][:28] for x in row)
    digest=c.emit(18,inputs[0].i&0x0fffffff,len(inputs),constants,count=8)
    for i in range(8):c.equal(Ref(c,digest.i+i),pv[b['digest_offset']+i])

def global_balance(c,meta,s):
    # Supported terminal has only local lookup buses. Requiring the native
    # identity digest on every chip is stronger than checking their sum, and
    # establishes the same final global-balance result without curve arithmetic.
    identity=[637514027,1595065213,1998064738,72333738,1211544370,822986770,1518535784,
              1604177449,90440090,259343427,140470264,1162099742,941559812,1064053343]
    assert meta['vk']['global']==identity
    for sums in s['chip_cumulative_sums'].values():
        g=sums['global']
        for x,v in zip(g['x']+g['y'],identity):c.equal(c.field(x),v)
    for chip,o in zip(meta['chips'],s['opened_values']['chips']):
        height=s['chip_heights'][chip['name']];degree=c.exts(o['quotient'][0]);assert len(degree)==23
        for i,x in enumerate(degree):c.equal(x,(height>>(22-i))&1)

def branching(c,start,end,zrow,zindex):
    # For an aligned 2^k interval, row+start has no carry in its low k bits.
    # Its MLE factors into low-bit equality, zero high row bits and fixed high
    # index bits. Keep the general four-state automaton for all other intervals.
    height=end-start;k=logceil(height)
    if height==1<<k and start%height==0 and k<=len(zrow) and k<=len(zindex) and end<=1<<len(zindex):
        low=eq(zrow[len(zrow)-k:] if k else [],zindex[len(zindex)-k:] if k else [])
        high=reduce(lambda a,r:a*(1-r),zrow[:len(zrow)-k],c.ref(1))
        for bit in range(k,len(zindex)):
            x=zindex[-1-bit];high=high*(x if start>>bit&1 else 1-x)
        return low*high
    n=max(len(zrow),len(zindex));v=[c.ref(0),c.ref(0),c.ref(1),c.ref(0)]
    for layer in range(n,-1,-1):
        r=zrow[-1-layer] if layer<len(zrow) else 0;x=zindex[-1-layer] if layer<len(zindex) else 0
        cb=(start>>layer)&1;nb=(end>>layer)&1;out=[]
        for state in range(4):
            acc=0
            for row in range(2):
                total=row+(state&1)+cb;ix=total&1;cmp=(state>>1) if ix==nb else nb;target=(total>>1)|(cmp<<1)
                weight=(r if row else 1-r)*(x if ix else 1-x);acc=acc+weight*v[target]
            out.append(acc)
        v=out
    return v[0]

def jagged(c,meta,s,b,z,opened):
    c.phase('jagged PCS');packing=b['packing'];offsets=packing['offsets'];widths=packing['column_counts'];assert sum(widths)==len(offsets)-1
    groups=[];names={d['name']:i for i,d in enumerate(meta['chips'])};areas=[]
    rounds=packing['round_counts'];pads=packing['padding_heights'];assert len(rounds)==2 and len(pads)==2
    for ri,round in enumerate(rounds):
        if ri==0:
            assert len(round)==len(meta['vk']['prep'])
            for (height,width),(name,vkw,vkh) in zip(round,meta['vk']['prep']):
                assert (height,width)==(vkh,vkw);groups.append(opened[names[name]][0])
        else:
            for (height,width),desc,opening in zip(round,meta['chips'],opened):
                assert height==s['chip_heights'][desc['name']] and width==desc['main_width'];groups.append(opening[1])
        groups.extend([[c.ref(0)] for _ in pads[ri]])
        areas.append(sum(h*w for h,w in round)+sum(pads[ri]))
    assert len(groups)==len(widths)
    assert len(b['preceding_commits'])==1;c.equal(c.hash(b['preceding_commits'][0]),c.constant_hash(meta['vk']['root']))
    for ri,area in enumerate(areas):assert area%(1<<21)==0
    assert b['commit']['area']==areas[-1] and b['commit']['log_stacking_height']==21
    zcol=[c.sample() for _ in range(logceil(len(offsets)-1))];w=table(zcol);y=[c.exts(row) for row in b['y_per_chip']]
    assert [len(g) for g in groups]==widths and [len(g) for g in y]==widths
    sy=sum((a*t for a,t in zip([v for row in y for v in row],w)),c.ref(0));so=sum((a*t for a,t in zip([v for row in groups for v in row],w)),c.ref(0));c.equal(sy,so)
    red=b['reduction'];claim=so;zstar=[];half=pow(2,-1,P)
    assert len(red['rounds'])==logceil(packing['total_values'])
    for r in red['rounds']:
        p0,p1,p2=c.exts(r['evals']);c.observe(p0,11);c.observe(-3*half*p0+2*p1-half*p2,11);c.observe(half*p0-p1+half*p2,11)
        c.equal(p0+p1,claim);x=c.sample();zstar.append(x);claim=p0*(x-1)*(x-2)*half-p1*x*(x-2)+p2*x*(x-1)*half
    for x,yv in zip(zstar,c.exts(red['eval_point'])):c.equal(x,yv)
    weight=sum((wc*branching(c,lo,hi,z,list(reversed(zstar))) for wc,lo,hi in zip(w,offsets,offsets[1:])),c.ref(0))
    q=c.ext(red['q_at_z']);c.equal(claim,q*weight)
    # This is the existing native outer verifier's transcript-only jagged-eval
    # replay; the closing identity above is independently checked in full.
    je=b['jagged_eval']['partial_sumcheck_proof'];c.observe(c.ext(je['claimed_sum']),11)
    for poly in je['univariate_polys']:
        for x in c.exts(poly['coefficients']):c.observe(x,11)
        c.sample()
    target=21+logceil(sum(area>>21 for area in areas));orig=len(zstar)
    while len(zstar)<target:zstar.append(c.sample())
    for x in zstar[orig:min(21,target)]:q=q*(1-x)
    batch=[x for row in b['whir_proof']['batch_evaluations'] for x in c.exts(row)];batch+= [c.ref(0)]*((1<<len(zstar[21:]))-len(batch));c.equal(mle(batch,zstar[21:]),q)
    return zstar[:21],[c.hash(b['preceding_commits'][0]),c.hash(b['commit']['commitment'])],[a>>21 for a in areas]

def whir_refs(c,b,point,roots,stripes,config):
    out=bytearray();references=[]
    def n(v,k=1):out.extend(integer(v).to_bytes(k,'big'))
    def arg(v):
        value=c.ref(v).i;references.append((len(out),value));n(value,4)
    def vec(v,count=1):
        n(len(v),count)
        ids=[c.ref(x).i for x in v]
        for tag,mask,stride in [(1,0x40000000,1),(2,0x20000000,4)]:
            if ids and ids[0]&0xf0000000==mask and ids==list(range(ids[0],ids[0]+len(ids)*stride,stride)):
                n(tag);n(ids[0]&0x0fffffff,4);return
        n(0)
        for x in v:arg(x)
    def polys(v):
        n(len(v))
        for poly in v:vec(c.exts(poly))
    for k in ['n','startingRate','batchPow']:n(config[k])
    n(config['finalQueries'],2);n(config['finalPow']);n(len(config['rounds']))
    for r in config['rounds']:
        n(r['fold']);n(r['rate']);n(r['queries'],2);n(r['ood']);n(r['queryPow']);n(len(r['foldPow']))
        for bits in r['foldPow']:n(bits)
    vec(roots);n(len(stripes))
    for count in stripes:n(count,2)
    vec(point)
    p=b['whir_proof'];w=p['whir_proof']
    n(len(p['batch_evaluations']))
    for row in p['batch_evaluations']:vec(c.exts(row),2)
    arg(c.field(p['batch_grinding_witness']));n(len(w['round_sumcheck_polys']))
    for r in w['round_sumcheck_polys']:polys(r)
    n(len(w['round_ood_answers']))
    for r in w['round_ood_answers']:vec(c.exts(r))
    vec([c.hash(root) for root in w['round_commitments']]);n(len(w['round_query_openings']))
    for r in w['round_query_openings']:
        n(len(r['leaves']),2)
        for leaf in r['leaves']:
            ids=[v['f'] for row in leaf['values'] for v in row]
            assert ids and ids==list(range(ids[0],ids[0]+len(ids))), "packed leaf requires contiguous native fields"
            assert len({len(row) for row in leaf['values']})==1
            n(len(leaf['values']),2)
            for row in leaf['values']:vec([c.field(x) for x in row],2)
            vec([c.hash(x) for x in leaf['proof']])
    vec(c.exts(w['final_poly']),2);polys(w['final_sumcheck_polys']);vec([c.field(x) for x in w['folding_pow']]);arg(c.field(w['final_pow']))
    return out,references

def allocate(c,whir,references):
    def inputs(code,args):
        if code in (4,5,6,8,20,21,22,23):return [0,1]
        if code in (7,10,11,12,16,17):return [0]
        if code==14:return [1]
        return []
    last={}
    for i,(code,dst,*args) in enumerate(c.ops):
        for j in inputs(code,args):
            if args[j]<0x10000000:last[args[j]]=i
    for _,ref in references:
        if ref<0x10000000:last[ref]=len(c.ops)
    mapping={};free=[];peak=0;ops=[]
    def mapped(ref):return mapping[ref] if ref<0x10000000 else ref
    for i,(code,dst,*args) in enumerate(c.ops):
        slots=inputs(code,args);converted=list(args)
        for j in slots:converted[j]=mapped(args[j])
        for ref in set(args[j] for j in slots):
            if ref<0x10000000 and last[ref]==i:heapq.heappush(free,mapping[ref])
        count=8 if code in (16,18) else 1 if code in (4,5,6,7,13,15,20,21,22,23) else 0
        physical=0
        if count==8:
            physical=peak;peak+=8
        elif count:
            if free:physical=heapq.heappop(free)
            else:physical=peak;peak+=1
        for j in range(count):
            mapping[dst+j]=physical+j
            if dst+j not in last:heapq.heappush(free,physical+j)
        ops.append((code,physical,*converted))
    whir=bytearray(whir)
    for at,ref in references:whir[at:at+4]=mapped(ref).to_bytes(4,'big')
    return ops,peak,whir

def binary_program(ops,registers,meta,whir):
    out=bytearray(b'KVE2'+bytes.fromhex(meta['profile_id'][2:]))
    def n(x,k=4):out.extend(x.to_bytes(k,'big'))
    n(meta['field_count']);n(meta['hash_count']);n(registers)
    for op in ops:
        code,dst,*args=op;n(code,1)
        if code in (4,5,6,7,13,15,16,18,20,21,22,23):n(dst)
        if code in (4,5,6,8,20,21,22,23):n(args[0]);n(args[1])
        elif code in (7,10,11,12,16):n(args[0])
        elif code==13:pass
        elif code==14:n(args[0],1);n(args[1])
        elif code==15:n(args[0],32)
        elif code==17:n(args[0]);n(args[1],1)
        elif code==18:n(args[0]);n(args[1],2);out.extend(bytes.fromhex(args[2]))
        else:raise ValueError(op)
    n(255,1);n(len(whir));out.extend(whir)
    return out

def main():
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('out',type=Path);args=p.parse_args();directory=args.directory
    meta=json.loads((directory/'machine.json').read_text());a=json.loads((directory/'marker.json').read_text());b=json.loads((directory/'marker_shift.json').read_text());schema=layout(a,b)
    c=Compiler();proof=schema['proof'];s=proof['jagged_shard_proof'];bundle=schema['bundle'];pv=[c.field(x) for x in proof['public_values']]
    public_bindings(c,meta,pv)
    global_balance(c,meta,s)
    c.phase('transcript prologue');vk=meta['vk'];c.observe(c.constant_hash(vk['root']),12);c.observe(vk['pc_start'])
    for x in vk['global']:c.observe(x)
    c.observe(0)
    for _ in range(2):
        for x in pv:c.observe(x)
    root=c.hash(bundle['commit']['commitment'])
    for x in c.seed(root):c.observe(x)
    c.observe(len(meta['chips']))
    for chip in meta['chips']:
        name=chip['name'];c.observe(s['chip_heights'][name]);c.observe(len(name))
        for char in name.encode():c.observe(char)
    z,opened=gkr_and_zero(c,meta,s,pv);point,roots,stripes=jagged(c,meta,s,bundle,z,opened)
    assert not args.out.resolve().is_relative_to(Path(__file__).resolve().parents[3]), "artifacts must stay outside repository"
    args.out.mkdir(parents=True,exist_ok=True)
    cfg=meta['whir_config'];assert cfg['starting_ood_samples']==0
    config={'n':21,'startingRate':cfg['starting_log_inv_rate'],'batchPow':cfg['batch_pow_bits'],'finalQueries':cfg['final_queries'],'finalPow':cfg['final_pow_bits'],
            'rounds':[dict(fold=r['folding_factor'],rate=r['log_inv_rate'],queries=r['num_queries'],ood=r['ood_samples'],queryPow=r['queries_pow_bits'],foldPow=r['pow_bits']) for r in cfg['round_parameters']]}
    whir,references=whir_refs(c,bundle,point,roots,stripes,config)
    ops,registers,whir=allocate(c,whir,references)
    manifest={'metadata':meta,'schema':schema,'original_registers':c.regs,'registers':registers,'ops':ops,'phases':c.phases,'stripes':stripes}
    (args.out/'program.json').write_text(json.dumps(manifest,separators=(',',':')))
    (args.out/'program.bin').write_bytes(binary_program(ops,registers,meta,whir))
    first_leaf=bundle['whir_proof']['whir_proof']['round_query_openings'][0]['leaves'][0]['values'][0][0]['f']
    first_gkr=s['logup_gkr_proof']['round_proofs'][0]['sumcheck_proof']['univariate_polys'][0]['coefficients'][0]['value'][0]['f']
    (args.out/'mutations.json').write_text(json.dumps({'merkle_field':first_leaf,'gkr_field':first_gkr}))
    print(json.dumps({'original_registers':c.regs,'registers':registers,'operations':len(c.ops),'phases':c.phases}))

if __name__=='__main__':main()

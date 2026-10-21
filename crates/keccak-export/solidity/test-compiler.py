#!/usr/bin/env python3
"""Independent field/automaton checks and Poseidon kernel regression vectors.

Vector artifacts go to the external fixture, never into tracked source files.
"""
import importlib.util
import json
import random
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('compiler',Path(__file__).with_name('compile-machine.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
P=m.P
class E:
    def __init__(self,x):self.v=tuple(v%P for v in x) if isinstance(x,tuple) else (x%P,0,0,0)
    def __add__(self,b):
        b=b if isinstance(b,E) else E(b)
        return E(tuple(a+y for a,y in zip(self.v,b.v)))
    __radd__=__add__
    def __neg__(self):return E(tuple(-x for x in self.v))
    def __sub__(self,b):return self+-as_e(b)
    def __rsub__(self,b):return as_e(b)+-self
    def __mul__(self,b):
        b=as_e(b);out=[0]*4
        for i,a in enumerate(self.v):
            for j,y in enumerate(b.v):out[(i+j)%4]+=a*y*(3 if i+j>=4 else 1)
        return E(tuple(out))
    __rmul__=__mul__
    def __eq__(self,b):return self.v==as_e(b).v

def as_e(x):return x if isinstance(x,E) else E(x)
class Numeric:
    def ref(self,x):return as_e(x)

def reference(start,end,zrow,zindex):
    # Unreduced four-state carry/comparison automaton, independent of shortcut.
    v=[E(0),E(0),E(1),E(0)]
    for layer in range(max(len(zrow),len(zindex)),-1,-1):
        row=zrow[-1-layer] if layer<len(zrow) else E(0)
        ix=zindex[-1-layer] if layer<len(zindex) else E(0)
        nextv=[]
        for state in range(4):
            value=E(0)
            for bit in (0,1):
                s=bit+(state%2)+((start>>layer)&1)
                ib=s%2;endbit=(end>>layer)&1
                cmp=state//2 if ib==endbit else endbit
                value += (row if bit else 1-row)*(ix if ib else 1-ix)*v[s//2+2*cmp]
            nextv.append(value)
        v=nextv
    return v[0]

class CompilerTests(unittest.TestCase):
    def test_aligned_identity_at_extension_points(self):
        rng=random.Random(2981)
        for _ in range(160):
            nr=rng.randrange(1,23);ni=rng.randrange(nr,29);k=rng.randrange(nr+1)
            lo=rng.randrange(1<<(ni-k))<<k
            row=[E(tuple(rng.randrange(P) for _ in range(4))) for _ in range(nr)]
            ix=[E(tuple(rng.randrange(P) for _ in range(4))) for _ in range(ni)]
            self.assertEqual(m.branching(Numeric(),lo,lo+(1<<k),row,ix),reference(lo,lo+(1<<k),row,ix))
    def test_fallback_and_boundary_points(self):
        rng=random.Random(233)
        for nr in (1,3,5):
            for lo,hi in [(0,1),(1,2),(1,5),(3,8),(8,16),(7,31)]:
                for _ in range(4):
                    row=[E(rng.randrange(2)) for _ in range(nr)]
                    ix=[E(rng.randrange(2)) for _ in range(5)]
                    self.assertEqual(m.branching(Numeric(),lo,hi,row,ix),reference(lo,hi,row,ix))
    def test_scalar_instruction_selection(self):
        c=m.Compiler();f=c.field({'f':0});e=c.ext([{'f':i} for i in range(4)])
        a=f*9;b=e*a;d=e*e
        self.assertEqual([x[0] for x in c.ops],[22,23,6])
        self.assertIn(a.i,c.base);self.assertNotIn(b.i,c.base);self.assertNotIn(d.i,c.base)

def vectors(fixture):
    meta=json.loads((fixture/'machine/machine.json').read_text())
    rng=random.Random(13121);out=[]
    for length in (0,1,7,8,9,16,223,224):
        values=[rng.randrange(P) for _ in range(length)]
        answer=m.poseidon(Numeric(),[E(v) for v in values],meta['poseidon_constants'])
        out.append({'input':values,'digest':[x.v[0] for x in answer]})
    (fixture/'compiled/poseidon-vectors.json').write_text(json.dumps(out))
    (fixture/'compiled/poseidon-constants.bin').write_bytes(b''.join(int(v).to_bytes(4,'big') for row in meta['poseidon_constants'][:28] for v in row))

if __name__=='__main__':
    if len(sys.argv)==2:
        vectors(Path(sys.argv.pop()).resolve())
    unittest.main()

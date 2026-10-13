import re, pickle
from poly import *
C = open('conj.txt').read().split('\n')
eqs = {}
defs = {}
for i, c in enumerate(C):
    if '.val' in c: continue
    body = c[:-4] if c.endswith(' = 0') else None
    assert body is not None, c
    p = parse(body)
    m = re.match(r'\(w\.v(\d+) - ', c)
    if m and int(m.group(1)) >= 364:
        r = int(m.group(1))
        e = padd(var(r), p, -1)
        if r not in vars_of(e):
            if r in defs: eqs[defs[r][0]] = padd(var(r), defs[r][1], -1)
            defs[r] = (i, e); continue
    eqs[i] = p
def expand(p):
    while True:
        vs = [v for v in vars_of(p) if v in defs]
        if not vs: return p
        for v in vs: p = subst(p, v, defs[v][1])
full = {i: expand(p) for i, p in eqs.items()}
pickle.dump((defs, full), open('full.pkl', 'wb'))
print(len(defs), 'defs', len(full), 'eqs')
for i, p in full.items(): print(i, len(p), sorted(vars_of(p))[:20])

import pickle
from poly import *
defs, full = pickle.load(open('full.pkl', 'rb'))
def V(base): return [var(base + i) for i in range(7)]
def vadd(a, b, s=1): return [padd(x, y, s) for x, y in zip(a, b)]
def sm(a, b):
    res = [{} for _ in range(13)]
    for i in range(7):
        for j in range(7):
            res[i + j] = padd(res[i + j], pmul(a[i], b[j]))
    ret = res[:7]
    for i in range(7, 13):
        ret[i - 7] = padd(ret[i - 7], pscale(res[i], 8))
        ret[i - 6] = padd(ret[i - 6], pscale(res[i], -2))
    return ret
def cv(x):
    z3 = [const(0), const(3)] + [{}] * 5
    return vadd(vadd(sm(sm(x, x), x), sm(x, z3)), [const(3)] + [{}] * 6, -1)
x2, y2 = V(9), V(16); x1, y1 = V(30), V(37); x3, y3 = V(51), V(58); inv = V(44)
one = [const(1)] + [{}] * 6
T = {}
T['lift'] = vadd(sm(y2, y2), cv(x2), -1)
d = vadd(x2, x1, -1); n = vadd(y2, y1, -1)
T['sx'] = vadd(sm(vadd(vadd(x1, x2), x3), sm(d, d)), sm(n, n), -1)
T['sy'] = vadd(sm(vadd(y1, y3), d), sm(n, vadd(x1, x3, -1)), -1)
T['di'] = vadd(sm(d, inv), one, -1)
match = {}
for name, comps in T.items():
    for k, t in enumerate(comps):
        found = None
        for i, p in full.items():
            if not p or len(p) != len(t): continue
            m0 = next(iter(t));
            if m0 not in p: continue
            a = t[m0] * pow(p[m0], P - 2, P) % P
            if padd(t, pscale(p, a), -1) == {}:
                found = (i, a); break
        match[(name, k)] = found
        print(name, k, found, len(t))
pickle.dump(match, open('match.pkl', 'wb'))

import re
P = 2130706433
def padd(a, b, s=1):
    r = dict(a)
    for m, c in b.items():
        r[m] = (r.get(m, 0) + s * c) % P
        if r[m] == 0: del r[m]
    return r
def pmul(a, b):
    r = {}
    for m1, c1 in a.items():
        for m2, c2 in b.items():
            d = dict(m1)
            for v, e in m2: d[v] = d.get(v, 0) + e
            m = tuple(sorted(d.items()))
            r[m] = (r.get(m, 0) + c1 * c2) % P
    return {m: c for m, c in r.items() if c}
def const(c): return {(): c % P} if c % P else {}
def var(v): return {((v, 1),): 1}
def pscale(a, k): return {m: c * k % P for m, c in a.items() if c * k % P}
TOK = re.compile(r'\s*(\(|\)|\+|-|\*|w\.v\d+|x\d+|\d+|: F)')
def parse(s):
    toks = [t for t in TOK.findall(s)]
    pos = [0]
    def peek(): return toks[pos[0]] if pos[0] < len(toks) else None
    def eat(t=None):
        x = toks[pos[0]]; assert t is None or x == t, (x, t, s[:80]); pos[0] += 1; return x
    def atom():
        t = peek()
        if t == '(':
            eat('(')
            if peek() == '-' :
                eat('-'); n = eat()
                if peek() == ': F': eat(': F'); eat(')'); return const(-int(n))
            e = expr()
            if peek() == ': F': eat(': F'); eat(')'); return e
            eat(')'); return e
        if t.startswith('w.v'): eat(); return var(int(t[3:]))
        if t.startswith('x'): eat(); return var(int(t[1:]))
        if t.isdigit(): eat(); return const(int(t))
        raise Exception((t, s[:100]))
    def term():
        a = atom()
        while peek() == '*': eat(); a = pmul(a, atom())
        return a
    def expr():
        a = term()
        while peek() in ('+', '-'):
            o = eat(); b = term(); a = padd(a, b, 1 if o == '+' else -1)
        return a
    e = expr(); assert pos[0] == len(toks), (toks[pos[0]:pos[0]+5], s[:80]); return e
def subst(a, v, e):
    r = {}
    for m, c in a.items():
        t = const(c)
        for x, k in m:
            f = e if x == v else var(x)
            for _ in range(k): t = pmul(t, f)
        r = padd(r, t)
    return r
def vars_of(a): return {x for m in a for x, _ in m}

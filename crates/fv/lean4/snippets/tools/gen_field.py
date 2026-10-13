"""gen_field.py MODULE_FILE OUT: the gadget proof of a chip built from field operations
without division (`FpOpAssign`, `Fp2AddSubAssign`, `Fp2MulAssign`) for one module, as a snippet
with the generator's placeholders.

Every operation's coefficient rows give an integer identity `F(values) = K·M`, so its result is
a polynomial in its operands modulo `M`; the chain of operations makes every result a function
of the inputs modulo `M`, and the less-than gadget of an output makes it the canonical residue,
whose bytes are then a function of the inputs."""
import itertools, math, random, re, sys
sys.path.insert(0, '.')
from mklemma import subst
from gen_fpop import parse, reified_columns, pyexpr, resolve, raw, back, toint


class Poly(dict):
    """A polynomial with integer coefficients: monomial (sorted tuple of symbols) -> coefficient."""

    @staticmethod
    def const(c):
        return Poly({(): c}) if c else Poly()

    @staticmethod
    def var(s):
        return Poly({(s,): 1})

    def _lift(o):
        return o if isinstance(o, Poly) else Poly.const(o)

    def __add__(self, o):
        r = Poly(self)
        for m, c in Poly._lift(o).items():
            r[m] = r.get(m, 0) + c
            if r[m] == 0:
                del r[m]
        return r
    __radd__ = __add__

    def __neg__(self):
        return Poly({m: -c for m, c in self.items()})

    def __sub__(self, o):
        return self + (-Poly._lift(o))

    def __rsub__(self, o):
        return Poly._lift(o) - self

    def __mul__(self, o):
        r = Poly()
        for m1, c1 in self.items():
            for m2, c2 in Poly._lift(o).items():
                m = tuple(sorted(m1 + m2))
                r[m] = r.get(m, 0) + c1 * c2
                if r[m] == 0:
                    del r[m]
        return r
    __rmul__ = __mul__


def expand(text, zero):
    """The polynomial of a constraint's left side, with the columns of `zero` set to zero."""
    env = {}
    t = re.sub(r'\((-?\d+) : F\)', r'(\1)', text)
    def col(m):
        c = int(m.group(1))
        if c in zero:
            return '(0)'
        env[f'c{c}'] = Poly.var(c)
        return f'c{c}'
    return Poly._lift(eval(re.sub(r'w\.v(\d+)', col, t), {}, env))


def lt_gadgets(cons, reified):
    """Every less-than gadget: flags, result limbs, modulus limbs, rows."""
    eq = []
    for i, c in cons.items():
        m = re.fullmatch(r'\(\((\(*w\.v\d+(?: \+ w\.v\d+\))*) - \(1 : F\)\) \* \(w\.v(\d+) - \((\d+) : F\)\)\) = 0', c)
        m0 = re.fullmatch(r'\(\((\(*w\.v\d+(?: \+ w\.v\d+\))*) - \(1 : F\)\) \* w\.v(\d+)\) = 0', c)
        if m:
            eq.append((i, [int(x) for x in re.findall(r'w\.v(\d+)', m.group(1))], int(m.group(2)), int(m.group(3)), m.group(1)))
        elif m0:
            eq.append((i, [int(x) for x in re.findall(r'w\.v(\d+)', m0.group(1))], int(m0.group(2)), 0, m0.group(1)))
    out = []
    for top in sorted({e[1][0] for e in eq}):
        rows = sorted((e for e in eq if e[1][0] == top), key=lambda e: len(e[1]))
        n = len(rows)
        assert [len(e[1]) for e in rows] == list(range(1, n + 1))
        full = rows[-1][1]
        g = dict(n=n, flags=full[::-1], r=[0] * n, mod=[0] * n, row=[0] * n, sumtext=[''] * n)
        for k, (i, fs, rv, mv, st) in enumerate(rows):
            assert fs == full[:k + 1]
            g['r'][n - 1 - k], g['mod'][n - 1 - k], g['row'][n - 1 - k], g['sumtext'][n - 1 - k] = rv, mv, i, st
        g['total'] = next(i for i, c in cons.items() if c.endswith(' - (1 : F)) = 0') and ' * ' not in c
                          and sorted(int(x) for x in re.findall(r'w\.v(\d+)', c)) == sorted(g['flags']))
        fl, rs = set(g['flags']), set(g['r'])
        rowset = set(g['row'])
        defs, cmp_cols = [], []
        for i, c in cons.items():
            cols = {int(x) for x in re.findall(r'w\.v(\d+)', c)}
            if i in rowset or ' * ' not in c or not (fl & cols) or not c.endswith(' = 0'):
                continue
            rest = [x for x in cols if x not in fl and x not in rs and x not in reified]
            if len(rest) == 1:
                defs.append(i)
                cmp_cols.append(rest[0])
        assert len(defs) == 2, defs
        i, m = next((i, m) for i, c in cons.items()
                    if (m := re.fullmatch(r'\(w\.v(\d+)\)\.val < \(w\.v(\d+)\)\.val', c)) and int(m.group(1)) in cmp_cols)
        g['lt'], g['p'], g['q'] = i, int(m.group(1)), int(m.group(2))
        g['dp'] = defs[cmp_cols.index(g['p'])]
        g['dq'] = defs[cmp_cols.index(g['q'])]
        g['M'] = sum(m * 256 ** i for i, m in enumerate(g['mod']))
        out.append(g)
    return out


def build_raw(cons, idx, L, goal, name, tactic, bound_of):
    """Two lemmas.  `{name}_int` states the constraints `idx` over integer names `n<column>` for
    the columns of `L` (as casts, with their ranges) and proves `goal` by `tactic`; `{name}`
    states them over the chip's own columns and reduces to `{name}_int` by lifting every column
    of `L` in its own small context, so the chip applies it to its constraints directly."""
    used = set()
    for i in idx:
        used |= {int(n) for n in re.findall(r'w\.v(\d+)', cons[i])}
    goalcols = [int(t) for t in dict.fromkeys(re.findall(r'\bn(\d+)\b', goal))]
    used |= set(goalcols)
    cols = sorted(used)
    lifted = [c for c in cols if c in L]
    plain = [c for c in cols if c not in L]
    o = [f"theorem {name}_int"]
    o.append("    (" + " ".join(f"n{c}" for c in lifted) + " : ℤ)")
    if plain:
        o.append("    (" + " ".join(f"x{c}" for c in plain) + " : F)")
    for c in lifted:
        o.append(f"    (hn{c} : 0 ≤ n{c} ∧ n{c} ≤ {L[c][1]})")
    for i in idx:
        o.append(f"    (e{i} : {subst(cons[i], L)})")
    o.append(f"    : {goal} := by")
    o.append(tactic)
    o.append("")
    val = lambda c: f"((x{c}.val : ℕ) : ℤ)"
    stated = re.sub(r'\bn(\d+)\b', lambda m: val(int(m.group(1))), goal)
    o.append(f"theorem {name}")
    o.append("    (" + " ".join(f"x{c}" for c in cols) + " : F)")
    for c in lifted:
        o.append(f"    (b{c} : x{c}.val ≤ {L[c][1]})")
    for i in idx:
        o.append(f"    (e{i} : {raw(cons[i])})")
    o.append(f"    : {stated} := by")
    args = " ".join([f"((x{c}.val : ℕ) : ℤ)" for c in lifted] + [f"x{c}" for c in plain]
                    + [f"⟨by positivity, by exact_mod_cast b{c}⟩" for c in lifted]
                    + [(f"(by simp only [ZirenDet.FieldOp.cast_val]; exact e{i})"
                        if any(int(c) in L for c in re.findall(r'w\.v(\d+)', cons[i])) else f"e{i}") for i in idx])
    o[-1] = o[-1].replace(" := by", " :=")
    o.append(f"  {name}_int {args}")
    app = f"{name} " + " ".join(f"w.v{c}" for c in cols) + " " + " ".join(bound_of(c, L[c][1]) for c in lifted) \
        + " " + " ".join(f"c{i}" for i in idx)
    return "\n".join(o) + "\n", app


def lt_lemma(cons, g, L, name, bound_of, reified):
    n, mod = g['n'], g['mod']
    F = lambda i: f"n{g['flags'][i]}"
    R = lambda i: f"n{g['r'][i]}"
    P, Q = f"n{g['p']}", f"n{g['q']}"
    t1, p1, u1 = resolve(cons, g['dp'], reified)
    t2, p2, u2 = resolve(cons, g['dq'], reified)
    S = lambda i: " + ".join(F(j) for j in range(i, n))
    bits = ' '.join(f'h{F(j)}' for j in range(n))
    o = []
    o.append(f"  have hsum : {S(0)} = 1 := by")
    o.append(f"    have r : {subst(cons[g['total']][:-4], L)} = 0 := by")
    o.append(f"      exact e{g['total']}")
    o.append(f"    clear * - r {bits}")
    o.append("    fieldop_row r")
    o.append(f"  have hp : {P} = {' + '.join(f'{R(i)} * {F(i)}' for i in range(n))} := by")
    o.append(f"    have r : {subst(t1, L)} = 0 := by")
    o.append(f"      linear_combination {p1}")
    o.append(f"    clear * - r h{P} {' '.join(f'h{F(j)} h{R(j)}' for j in range(n))}")
    o.append("    fieldop_row r")
    o.append(f"  have hq : {Q} = {' + '.join(f'{F(i)} * {mod[i]}' for i in range(n))} := by")
    o.append(f"    have r : {subst(t2, L)} = 0 := by")
    o.append(f"      linear_combination {p2}")
    o.append(f"    clear * - r h{Q} {bits}")
    o.append("    fieldop_row r")
    o.append(f"  have hlt : {P} < {Q} := ZirenDet.DivRem.lt_of_val_lt e{g['lt']} (by omega) (by omega)")
    o.append(f"  obtain ⟨S{n}, hS{n}⟩ : ∃ S : ℤ, S = 0 := ⟨_, rfl⟩")
    o.append(f"  obtain ⟨R{n}, hR{n}⟩ : ∃ R : ℤ, R = 0 := ⟨_, rfl⟩")
    for i in range(n - 1, -1, -1):
        o.append(f"  obtain ⟨S{i}, hS{i}⟩ : ∃ S : ℤ, S = {F(i)} + S{i + 1} := ⟨_, rfl⟩")
        o.append(f"  obtain ⟨R{i}, hR{i}⟩ : ∃ R : ℤ, R = {R(i)} + 256 * R{i + 1} := ⟨_, rfl⟩")
    chain = ' '.join(f'hS{j}' for j in range(n + 1))
    for i in range(n):
        o.append(f"  have hb{i} : 0 ≤ S{i} ∧ S{i} ≤ 1 := by")
        o.append(f"    clear * - hsum {chain} {bits}")
        o.append("    omega")
    for i in range(n):
        o.append(f"  have H{i} : S{i} = 0 → {R(i)} = {mod[i]} := by")
        o.append("    intro h0")
        o.append(f"    have h0' : {S(i)} = 0 := by")
        o.append(f"      clear * - h0 {' '.join(f'hS{j}' for j in range(i, n + 1))}")
        o.append("      omega")
        o.append(f"    have hc : ((({S(i)} : ℤ) : F)) = 0 := by rw [h0']; simp")
        o.append(f"    have r : (({R(i)} : ℤ) : F) - ({mod[i]} : F) = 0 := by")
        o.append(f"      have e : {subst(cons[g['row'][i]], L)} := by")
        o.append(f"        exact e{g['row'][i]}")
        o.append("      push_cast at hc")
        o.append(f"      have hne : ({subst(g['sumtext'][i], L)} - (1 : F)) = -1 := by linear_combination hc")
        o.append("      rw [hne] at e")
        o.append("      linear_combination -e")
        o.append(f"    clear * - r h{R(i)}")
        o.append(f"    have r' : (({R(i)} - {mod[i]} : ℤ) : F) = ((0 : ℤ) : F) := by push_cast; linear_combination r")
        o.append("    obtain ⟨m, hm⟩ := ZirenDet.cast_eq_iff_dvd.mp r'")
        o.append("    omega")
    for i in range(n):
        o.append(f"  have G{i} : {F(i)} = 1 → {R(i)} < {mod[i]} := by")
        o.append("    intro h1")
        for j in range(n):
            if j != i:
                o.append(f"    have z{j} : {F(j)} = 0 := by clear * - hsum h1 {bits}; omega")
        o.append(f"    clear * - hp hq hlt h1 {' '.join(f'z{j}' for j in range(n) if j != i)}")
        o.append("    subst_vars")
        o.append("    simp only [mul_zero, mul_one, zero_mul, one_mul, add_zero, zero_add] at hlt")
        o.append("    omega")
    top = lambda i: sum(mod[j] * 256 ** (j - i) for j in range(i, n))
    o.append(f"  have P{n} : (S{n} = 0 ∧ R{n} = 0) ∨ (S{n} = 1 ∧ R{n} < 0) := Or.inl ⟨hS{n}, hR{n}⟩")
    for i in range(n - 1, -1, -1):
        o.append(f"  have P{i} : (S{i} = 0 ∧ R{i} = {top(i)}) ∨ (S{i} = 1 ∧ R{i} < {top(i)}) := by")
        o.append(f"    clear * - P{i + 1} hS{i} hR{i} h{F(i)} h{R(i)} H{i} G{i} hb{i}" + (f" hb{i + 1}" if i + 1 < n else f" hS{n}"))
        o.append("    omega")
    o.append(f"  have hS0 : S0 = 1 := by clear * - hsum {chain}; omega")
    o.append(f"  clear * - P0 hS0 {' '.join(f'hR{j}' for j in range(n + 1))}")
    o.append("  omega")
    goal = f"{' + '.join(f'{256 ** i} * {R(i)}' for i in range(n))} < {g['M']}"
    used = sorted({g['total'], g['lt']} | set(g['row']) | set(u1) | set(u2))
    return build_raw(cons, used, L, goal, name, "\n".join(o), bound_of)


def main():
    src, cons = parse(sys.argv[1])
    reified = reified_columns(src)
    gadgets = lt_gadgets(cons, reified)
    n, M = gadgets[0]['n'], gadgets[0]['M']
    mod = gadgets[0]['mod']
    assert all(g['n'] == n and g['M'] == M for g in gadgets)
    off = next(int(m.group(1)) for c in cons.values()
               if (m := re.search(r'\(w\.v\d+ - \((\d+) : F\)\) \* \(-256 : F\)', c)))
    allrows = [resolve(cons, i, reified) for i, c in cons.items()
               if f'({off} : F)) * (-256 : F)' in c or re.search(rf'- \(w\.v\d+ - \({off} : F\)\)\)+ = 0$', c)]
    key = lambda r: tuple(sorted(int(x) for x in re.findall(rf'w\.v(\d+) - \({off} : F\)', r[0])))
    wit = sorted({c for r in allrows for c in key(r)})
    blocks, cur = [], [wit[0]]
    for c in wit[1:]:
        if c == cur[-1] + 1 and len(cur) < 2 * n - 2:
            cur.append(c)
        else:
            blocks.append(cur)
            cur = [c]
    blocks.append(cur)
    assert all(len(b) == 2 * n - 2 for b in blocks), [len(b) for b in blocks]

    def bound_of(c, bound):
        for i, t in cons.items():
            if t == f"(w.v{c}).val ≤ {bound}":
                return f"c{i}"
        for i, t in cons.items():
            if t == f"(w.v{c} * (w.v{c} - (1 : F))) = 0":
                return f"(ZirenDet.bit_val_le c{i})"
        raise AssertionError(c)

    def has_bound(c, bound):
        return any(t == f"(w.v{c}).val ≤ {bound}" for t in cons.values())

    i0 = next(i for i, l in enumerate(src) if l.startswith('def inputs'))
    inputs = [int(x) for x in re.findall(r'w\.v(\d+)', src[i0 + 1])]
    words = sorted(((int(m.group(1)), [int(x) for x in re.findall(r'w\.v(\d+)', l)])
                    for l in src if (m := re.match(r'def in_mem_read_(\d+)_val ', l))))
    flat = [c for _, w in words for c in w]

    def vector(c):
        """The limbs of the vector whose lowest limb is column `c`."""
        v = flat[flat.index(c):flat.index(c) + n] if c in flat else list(range(c, c + n))
        assert len(v) == n and all(has_bound(x, 255) for x in v), (c, v)
        return v

    L, ops, selectors = {}, [], {}
    for b in blocks:
        rows = sorted((r for r in allrows if set(key(r)) <= set(b)),
                      key=lambda r: 0 if key(r) == (b[0],) else (min(key(r)) - b[0] + 1))
        assert [len(key(r)) for r in rows] == [1] + [2] * (2 * n - 3) + [1]
        carry = []
        for i in range(n):
            ks = re.findall(rf'\(w\.v(\d+) \* \({mod[0]} : F\)\)', rows[i][0])
            carry.append(int(ks[-1]))
        p0 = expand(rows[0][0], set(b) | set(carry))
        syms = sorted({s for m in p0 for s in m})
        sel = [s for s in syms if not has_bound(s, 255)]
        vecs = {s: vector(s) for s in syms if s not in sel}
        for s in sel:
            selectors[s] = None
        ops.append(dict(block=b, rows=rows, carry=carry, p0=p0, vecs=vecs, sel=sel))
        for c in b:
            L[c] = (f'n{c}', 65535)
        for c in carry:
            L[c] = (f'n{c}', 255)
        for v in vecs.values():
            for c in v:
                L[c] = (f'n{c}', 255)
        for s in sel:
            L[s] = (f'n{s}', 1)
    for g in gadgets:
        for c in g['flags']:
            L[c] = (f'n{c}', 1)
        L[g['p']] = (f"n{g['p']}", 255)
        L[g['q']] = (f"n{g['q']}", 255)
        for c in g['r']:
            L[c] = (f'n{c}', 255)
    # selectors: pinned by a constraint of their own, or free bits
    pins = {}
    for s in selectors:
        hit = [(i, v) for i, c in cons.items() for v in (0, 1)
               if set(re.findall(r'w\.v(\d+)', c)) == {str(s)} and '*' not in c and c.endswith(' = 0')
               and eval(pyexpr(c[:-4], lambda _: v)) == 0 and eval(pyexpr(c[:-4], lambda _: 1 - v)) != 0]
        if hit:
            pins[s] = hit[0]
    free = [s for s in selectors if s not in pins]
    # each operation: the orientation of its rows and its template, checked numerically
    env = {c: random.randrange(0, b + 1) for c, (_, b) in L.items()}
    for s, (_, v) in pins.items():
        env[s] = v
    value = lambda v: sum(env[c] * 256 ** i for i, c in enumerate(v))
    lemmas, apps = [], []
    for k, op in enumerate(ops):
        b, rows, carry = op['block'], op['rows'], op['carry']
        wp = lambda i: (env[b[i]] - off) if 0 <= i < len(b) else 0
        # the template: every limb symbol of row 0 stands for its vector's value
        def template(sym_value, const):
            total = 0
            for m, c in op['p0'].items():
                t = c
                for s in m:
                    t = t * sym_value(s)
                total += t if m else const
            return total
        consts = [expand(r[0], set(b) | set(carry)).get((), 0) for r in rows]
        const_val = None
        sign = []
        for i, (text, _, _) in enumerate(rows):
            got = eval(pyexpr(text, lambda c: env[c]))
            sign.append(got)
        # fix the orientation of row 0 by its witness term, then every other row by evaluation
        K = value(carry)
        def limb_poly(i):
            return expand(rows[i][0], set(b) | set(carry))
        tvals = [eval(pyexpr(rows[i][0], lambda c: 0 if c in b or c in carry else env[c])) for i in range(len(rows))]
        sg = []
        for i in range(len(rows)):
            exp = tvals[i] - sum(env[carry[j]] * mod[i - j] for j in range(n) if 0 <= i - j < n)
            # tvals carries the row's own sign: compare against the row with sign +1 on the witness
            w_part = wp(i - 1) - 256 * wp(i)
            full = sign[i]
            cand = [s for s in (1, -1) if s * full == s * (tvals[i] - 0) - 0 or True]
            sg.append(None)
        # orientation: a row is `s * (T - carry*mod - (w' - 256 w''))`; s = -1 exactly when the
        # witness term enters with the opposite sign
        for i in range(len(rows)):
            base = dict(env)
            e1 = dict(env); e0 = dict(env)
            wc = b[i] if i < len(b) else b[i - 1]
            e1[wc] = env[wc] + 1
            d = eval(pyexpr(rows[i][0], lambda c: e1[c])) - eval(pyexpr(rows[i][0], lambda c: e0[c]))
            coef = 256 if i < len(b) else -1
            assert d in (coef, -coef), (k, i, d)
            sg[i] = 1 if d == coef else -1
        T256 = sum(sg[i] * 256 ** i * tvals[i] for i in range(len(rows)))
        total = sum(sg[i] * 256 ** i * sign[i] for i in range(len(rows)))
        assert total == T256 - K * M, (k, 'rows do not telescope')
        full_poly = Poly()
        for i, (text, _, _) in enumerate(rows):
            full_poly = full_poly + expand(text, set(b) | set(carry)) * (sg[i] * 256 ** i)
        colpos = {c: (s_, i) for s_, v in op['vecs'].items() for i, c in enumerate(v)}
        fit = {}
        for m, c in full_poly.items():
            key, weight, groups = [], 0, {}
            for col in m:
                if col in op['sel']:
                    key.append(col)
                else:
                    s_, i = colpos[col]
                    key.append(s_)
                    weight += i
                    groups.setdefault(s_, []).append(i)
            orderings = 1
            for pos in groups.values():
                orderings *= math.factorial(len(pos))
                for q in set(pos):
                    orderings //= math.factorial(pos.count(q))
            assert c % (orderings * 256 ** weight) == 0, (k, m, c)
            fit.setdefault(tuple(sorted(key)), set()).add(c // (orderings * 256 ** weight))
        assert all(len(v) == 1 for v in fit.values()), (k, 'inconsistent template')
        fitted = {m: v.pop() for m, v in fit.items()}
        const_val = fitted.pop((), 0)
        op['p0'] = fitted
        s0 = 1
        F_val = sum(c * eval('*'.join(['1'] + [str(env[s]) if s in op['sel'] else str(value(op['vecs'][s])) for s in m]))
                    for m, c in op['p0'].items() if m) + const_val
        assert F_val == T256, (k, 'template does not match', F_val - T256)
        op['sign'], op['s0'], op['const'] = sg, s0, const_val
        P = lambda v: "(" + " + ".join(f"{256 ** i} * n{c}" for i, c in enumerate(v)) + ")"
        def mono(m, c):
            fs = [f"n{s}" if s in op['sel'] else P(op['vecs'][s]) for s in m]
            return f"({s0 * c}) * " + " * ".join(fs)
        op['F'] = " + ".join([mono(m, c) for m, c in op['p0'].items() if m] + ([f"({const_val})"] if const_val else []))
        o = []
        for s in op['sel']:
            if s in pins:
                i, v = pins[s]
                o.append(f"  have pn{s} : n{s} = {v} := by")
                o.append(f"    have e : {subst(cons[i], L)} := by")
                o.append(f"      exact e{i}")
                o.append(f"    clear * - e hn{s}")
                o.append("    divrem_lift; omega")
        pinned = ' '.join(f"pn{s}" for s in op['sel'] if s in pins)
        for i, (text, proof, _) in enumerate(rows):
            f = subst(text, L)
            keep = " ".join(f"h{L[int(c)][0]}" for c in dict.fromkeys(re.findall(r'w\.v(\d+)', text)))
            o.append(f"  have H{i} : {toint(f)} = 0 := by")
            o.append(f"    have r : {f} = 0 := by")
            o.append(f"      linear_combination {proof}")
            o.append(f"    clear * - r {pinned} {keep}")
            o.append("    subst_vars")
            o.append("    (try simp only [Int.cast_zero, Int.cast_one, mul_zero, zero_mul, mul_one, one_mul, add_zero, sub_zero, zero_add] at r ⊢)")
            o.append("    fieldop_row r")
        o.append(f"  clear * - {pinned} {' '.join(f'H{i}' for i in range(len(rows)))}")
        o.append("  subst_vars")
        o.append("  linear_combination " + " + ".join(f"({sg[i] * 256 ** i}) * H{i}" for i in range(len(rows))))
        goal = f"{op['F']} = {P(carry)} * {M}"
        if pinned:
            goal = re.sub(r'\bn(\d+)\b', lambda m: str(pins[int(m.group(1))][1]) if int(m.group(1)) in pins else m.group(0), goal)
        used = sorted({i for r in rows for i in r[2]} | {pins[s][0] for s in op['sel'] if s in pins})
        text, app = build_raw(cons, used, L, goal, f"op{k}_identity", "\n".join(o), bound_of)
        op['goal'] = goal
        lemmas.append(text)
        apps.append(app)
    for k, g in enumerate(gadgets):
        text, app = lt_lemma(cons, g, L, f"result{k}_lt", bound_of, reified)
        lemmas.append(text)
        g['app'] = app
    import json
    # ---- the chip-level statements
    inset = set(inputs)
    for k, op in enumerate(ops):
        op['res'] = op['carry'][0] - n
        assert op['res'] in op['vecs'], (k, op['res'], list(op['vecs']))
    order, done = [], set()
    while len(order) < len(ops):
        ready = [k for k, op in enumerate(ops) if k not in order
                 and all(x == op['res'] or set(v) <= inset or x in done for x, v in op['vecs'].items())]
        assert ready, "operations do not form a chain"
        inverse = lambda k: [m for m in ops[k]['p0'] if m] == [m for m in ops[k]['p0'] if m and ops[k]['res'] in m] \
            and all(len(m) == 2 for m in ops[k]['p0'] if m)
        ready.sort(key=lambda k: (not inverse(k), k))
        order.append(ready[0])
        done.add(ops[ready[0]]['res'])
    vec_of = {}
    for op in ops:
        vec_of.update(op['vecs'])
    EV = lambda v, w: "(ZirenDet.FieldOp.ev [" + ", ".join(f"(({w}.v{c}.val : ℕ) : ℤ)" for c in v) + "])"
    PS = lambda v, w: " + ".join(f"{256 ** i} * (({w}.v{c}.val : ℕ) : ℤ)" for i, c in enumerate(v))
    SEL = lambda s, w: str(pins[s][1]) if s in pins else f"(({w}.v{s}.val : ℕ) : ℤ)"

    def F_text(op, w):
        def mono(m, c):
            return f"({op['s0'] * c}) * " + " * ".join(SEL(x, w) if x in op['sel'] else EV(op['vecs'][x], w) for x in m)
        return " + ".join([mono(m, c) for m, c in op['p0'].items() if m] + ([f"({op['const']})"] if op['const'] else []))

    ZM = f"ZMod {M}"
    seldef = {}
    for s_ in free:
        if s_ in inset:
            continue
        for i, c in cons.items():
            m = re.fullmatch(rf'\(w\.v(\d+) - \(\(w\.v{s_} \* \((\d+) : F\)\) \+ \(\(\(1 : F\) - w\.v{s_}\) \* \((\d+) : F\)\)\)\) = 0', c)
            if m and int(m.group(1)) in inset and abs(int(m.group(2)) - int(m.group(3))) == 1:
                seldef[s_] = (i, int(m.group(1)), int(m.group(2)), int(m.group(3)))
                break
        assert s_ in seldef, f"selector {s_} is neither an input nor defined from one"
    conj = [f"((({F_text(op, 'w')} : ℤ)) : {ZM}) = 0" for op in ops]
    conj += [f"{EV(g['r'], 'w')} < {M}" for g in gadgets]
    conj += [f"({SEL(s, 'w')} = 0 ∨ {SEL(s, 'w')} = 1)" for s in free]
    conj += [f"w.v{x} = w.v{s_} * {a_} + (1 - w.v{s_}) * {b_}" for s_, (_, x, a_, b_) in seldef.items()]
    proof = ["  %OPEN_HW%"]
    for k, app in enumerate(apps):
        proof.append(f"  have h{k} := {app}")
    for k, g in enumerate(gadgets):
        proof.append(f"  have l{k} := {g['app']}")
    used_vecs = {}
    for op in ops:
        for x, v in op['vecs'].items():
            used_vecs[x] = v
    for g in gadgets:
        used_vecs[g['r'][0]] = g['r']
    for x, v in used_vecs.items():
        proof.append(f"  have ev{x} : {EV(v, 'w')} = {PS(v, 'w')} := by")
        proof.append("    simp only [ZirenDet.FieldOp.ev]; ring")
    proof.append(f"  rw [{', '.join(f'ev{x}' for x in used_vecs)}]")
    proof.append("  refine ⟨" + ", ".join("?_" for _ in conj) + "⟩")
    for k, op in enumerate(ops):
        proof.append(f"  · exact ZirenDet.FieldOp.cast_eq_zero_of_eq_mul (K := {PS(op['carry'], 'w')})")
        proof.append(f"      (by push_cast; linear_combination h{k})")
    for k, g in enumerate(gadgets):
        proof.append(f"  · exact l{k}")
    for s_ in free:
        proof.append(f"  · exact ZirenDet.FieldOp.bit_cases {bound_of(s_, 1)}")
    for s_, (i, _, _, _) in seldef.items():
        proof.append(f"  · linear_combination c{i}")
    outs = [c for g in gadgets for c in g['r']]
    rng = [bound_of(c, 255) for c in outs]
    names = lambda pre, n_, suf="": ", ".join(f"{pre}{i}{suf}" for i in range(n_))
    nf = len(ops)
    pat = lambda suf: "⟨" + ", ".join([f"f{k}{suf}" for k in range(nf)] + [f"l{k}{suf}" for k in range(len(gadgets))]
                                     + [f"s{k}{suf}" for k in range(len(free))]
                                     + [f"d{k}{suf}" for k in range(len(seldef))]) + "⟩"
    incols = sorted({c for op in ops for v in op['vecs'].values() for c in v if c in inset}
                    | {s_ for s_ in free if s_ in inset})
    pos = lambda c: inputs.index(c)
    CAST = lambda v, w: f"(({EV(v, w)} : ℤ) : {ZM})"

    def den_step(k, poly, res, R, dens, term, eq_of, pad):
        """`R·(cr + cX·D) = num` with `D = d·(x₁y₁)(x₂y₂)`: the Edwards denominator, nonzero because
        `num = 0` would make `d` (for `x₁y₂ + x₂y₁`) or `−d` (for `y₁y₂ + x₁x₂`) a square."""
        W1 = "w'"
        assert len(dens) == 1, (k, poly)
        cr, cX = poly.pop((res,)), poly.pop(dens[0])
        D = dens[0][0] if dens[0][1] == res else dens[0][1]
        assert cr in (1, -1) and cX in (1, -1) and all(res not in m for m in poly), (k, poly)
        only = lambda x: next(j for j, op in enumerate(ops) if op['res'] == x)
        mons = lambda j: {m: c for m, c in ops[j]['p0'].items() if m and m != (ops[j]['res'],)}
        kD = only(D)
        (fm, dc), = mons(kD).items()
        kf = only(fm[0])
        (pq, one), = mons(kf).items()
        assert len(pq) == 2
        kP, kQ = only(pq[0]), only(pq[1])
        (P, c1), = mons(kP).items()
        (Q, c2), = mons(kQ).items()
        assert len(P) == 2 and len(Q) == 2
        (N, cn), = poly.items()
        assert len(N) == 1
        kN = only(N[0])
        nm = {tuple(sorted(m)): c for m, c in mons(kN).items()}
        assert set(nm.values()) == {1}
        srt = lambda a, b: tuple(sorted((a, b)))
        case = None
        for x1, y1 in (P, P[::-1]):
            for x2, y2 in (Q, Q[::-1]):
                if set(nm) == {srt(x1, y2), srt(x2, y1)}:
                    case = ('x', x1, y1, x2, y2)
                elif set(nm) == {srt(y1, y2), srt(x1, x2)}:
                    case = ('y', x1, y1, x2, y2)
        assert case, (k, nm)
        which, x1, y1, x2, y2 = case
        e = 1 if which == 'x' else -1
        assert e * cr * cX == 1, "the denominator can vanish"
        side = lambda x, w: W1 if set(vec_of[x]) <= inset else w
        C = lambda x: CAST(vec_of[x], side(x, 'w'))
        lead = lambda j: -ops[j]['p0'][(ops[j]['res'],)]
        dd = lead(kD) * dc * lead(kf) * one * lead(kP) * c1 * lead(kQ) * c2
        num = lambda w: term(N, -cn, w)
        o = [f"{pad}haveI := ZirenDet.Edwards.ed25519_fact",
             f"{pad}have hd{k} : ({cr}) + ({cX}) * {CAST(vec_of[D], 'w')} ≠ 0 := by",
             f"{pad}  intro h0",
             f"{pad}  have hnum : {num('w')} = 0 := by linear_combination {R('w')} * h0 - f{k}",
             f"{pad}  have hD : {CAST(vec_of[D], 'w')} = ({dd}) * ({C(x1)} * {C(y1)}) * ({C(x2)} * {C(y2)}) := by",
             f"{pad}    rw [r{kD}, r{kf}, r{kP}, r{kQ}]; ring",
             f"{pad}  rw [r{kN}] at hnum"]
        if which == 'x':
            o.append(f"{pad}  exact ZirenDet.Edwards.x_den_ne (x1 := {C(x1)}) (y1 := {C(y1)}) (x2 := {C(x2)}) (y2 := {C(y2)}) ZirenDet.Edwards.ed25519_d_nonsq "
                     f"(by linear_combination ({-cn}) * hnum) (by linear_combination ({e * cX}) * h0 + ({-e}) * hD)")
        else:
            o.append(f"{pad}  exact ZirenDet.Edwards.y_den_ne (x1 := {C(x1)}) (y1 := {C(y1)}) (x2 := {C(x2)}) (y2 := {C(y2)}) ZirenDet.Edwards.ed25519_neg_d_nonsq "
                     f"(by linear_combination ({-cn}) * hnum) (by linear_combination ({e * cX}) * h0 + ({-e}) * hD)")
        qs = [eq_of[x] for x in (D, N[0]) if x in eq_of]
        o.append(f"{pad}have fk{k} := f{k}")
        o.append(f"{pad}rw [{', '.join(qs)}] at fk{k}")
        o.append(f"{pad}have hd{k}' : ({cr}) + ({cX}) * {CAST(vec_of[D], W1)} ≠ 0 := by rw [← {eq_of[D]}]; exact hd{k}")
        o.append(f"{pad}have q{k} : {R('w')} = {R(W1)} := ZirenDet.Edwards.quot_unique hd{k}' (a := {num(W1)})")
        o.append(f"{pad}  (by linear_combination fk{k}) (by linear_combination f{k}')")
        eq_of[res] = f"q{k}"
        return o

    def case_body(values, indent):
        pad = " " * indent
        o = []
        facts = " ".join([f"f{k}" for k in range(nf)] + [f"f{k}'" for k in range(nf)])
        if free:
            o.append(f"{pad}simp only [{', '.join(f't{i}' for i in range(len(free)))}] at {facts}")
        o.append(f"{pad}push_cast at {facts}")
        eq_of, inv_of = {}, {}
        W1 = "w'"
        side = lambda x, w: W1 if set(vec_of[x]) <= inset else w
        def term(m, c, w):
            fs = [CAST(vec_of[x], side(x, w)) for x in m]
            return f"({c}) * " + " * ".join(fs) if fs else f"({c})"
        for k in order:
            op = ops[k]
            poly = Poly()
            for m, c in op['p0'].items():
                if not m:
                    continue
                coef, rest = op['s0'] * c, []
                for x in m:
                    if x in op['sel']:
                        coef *= pins[x][1] if x in pins else values[x]
                    else:
                        rest.append(x)
                if coef:
                    key = tuple(sorted(rest))
                    poly[key] = poly.get(key, 0) + coef
                    if poly[key] == 0:
                        del poly[key]
            if op['const']:
                poly[()] = poly.get((), 0) + op['const']
                if poly[()] == 0:
                    del poly[()]
            res = op['res']
            R = lambda w: CAST(vec_of[res], w)
            dens = [m for m in poly if len(m) == 2 and res in m]
            if (res,) in poly and dens:
                o += den_step(k, poly, res, R, dens, term, eq_of, pad)
                continue
            if (res,) in poly:
                cr = poly.pop((res,))
                assert cr in (1, -1) and all(res not in m for m in poly), (k, poly)
                def expr(w):
                    ts = [term(m, -cr * c, w) for m, c in poly.items()]
                    return " + ".join(ts) if ts else "0"
                o.append(f"{pad}have r{k} : {R('w')} = {expr('w')} := by linear_combination ({cr}) * f{k}")
                o.append(f"{pad}have r{k}' : {R(W1)} = {expr(W1)} := by linear_combination ({cr}) * f{k}'")
                prev = [eq_of[x] for m in poly for x in m if x in eq_of]
            else:
                mons = [m for m in poly if res in m]
                assert len(mons) == 1 and len(mons[0]) == 2, (k, poly)
                a = poly.pop(mons[0])
                B = mons[0][0] if mons[0][1] == res else mons[0][1]
                assert a in (1, -1) and all(res not in m for m in poly), (k, poly)
                if all(len(m) == 0 for m in poly):
                    assert poly.get((), 0) == -a, (k, poly)
                    inv_of[B] = (res, k, a)
                    qB = f" - ({R('w')} * {R(W1)}) * {eq_of[B]}" if B in eq_of else ""
                    o.append(f"{pad}have q{k} : {R('w')} = {R(W1)} := by")
                    o.append(f"{pad}  linear_combination ({a} * {R(W1)}) * f{k} - ({a} * {R('w')}) * f{k}'{qB}")
                    eq_of[res] = f"q{k}"
                    continue
                inv, ki, ai = inv_of[B]
                I = lambda w: CAST(vec_of[inv], w)
                def expr(w):
                    ts = [term(m, c, w) for m, c in poly.items()]
                    return f"{I(w)} * ((-({a})) * ({' + '.join(ts)}))"
                o.append(f"{pad}have r{k} : {R('w')} = {expr('w')} := by linear_combination (-({ai}) * {R('w')}) * f{ki} + ({a} * {I('w')}) * f{k}")
                o.append(f"{pad}have r{k}' : {R(W1)} = {expr(W1)} := by linear_combination (-({ai}) * {R(W1)}) * f{ki}' + ({a} * {I(W1)}) * f{k}'")
                prev = [eq_of[inv]] + [eq_of[x] for m in poly for x in m if x in eq_of]
            prev = list(dict.fromkeys(prev))
            o.append(f"{pad}have q{k} : {R('w')} = {R(W1)} := by")
            o.append(f"{pad}  rw [r{k}, r{k}'" + "".join(f", {q}" for q in prev) + "]")
            eq_of[res] = f"q{k}"
        ex = []
        for k, g in enumerate(gadgets):
            q = eq_of[g['r'][0]]
            o.append(f"{pad}have hR{k} : {EV(g['r'], 'w')} = {EV(g['r'], chr(119) + chr(39))} :=")
            o.append(f"{pad}  ZirenDet.FieldOp.eq_of_cast_eq (ZirenDet.FieldOp.ev_nonneg _ hr{k}) (by exact_mod_cast l{k})")
            o.append(f"{pad}    (ZirenDet.FieldOp.ev_nonneg _ hr{k}') (by exact_mod_cast l{k}') {q}")
            o.append(f"{pad}have hl{k} := ZirenDet.FieldOp.ev_inj _ _ (by simp only [List.length_cons, List.length_nil]) hr{k} hr{k}' hR{k}")
            o.append(f"{pad}simp only [List.cons.injEq, and_true] at hl{k}")
            o.append(f"{pad}obtain ⟨{', '.join(f'e{c}' for c in g['r'])}⟩ := hl{k}")
        o.append(f"{pad}exact ⟨{', '.join(f'ZMod.val_injective _ (by exact_mod_cast e{c})' for c in outs)}⟩")
        return o

    def cases(i, values, indent):
        if i == len(free):
            return case_body(values, indent)
        pad = " " * indent
        o = [f"{pad}rcases s{i}' with t{i} | t{i}"]
        for v in (0, 1):
            body = cases(i + 1, {**values, free[i]: v}, indent + 2)
            body[0] = pad + "· " + body[0].lstrip()
            o += body
        return o

    det = []
    det.append(f"  obtain {pat('')} := row_spec w hw")
    det.append(f"  obtain {pat(chr(39))} := row_spec w' hw'")
    det.append(f"  obtain ⟨{', '.join(f'a{c}' for c in outs)}⟩ := row_ranges w hw")
    det.append(f"  obtain ⟨{', '.join(f'a{c}' + chr(39) for c in outs)}⟩ := row_ranges w' hw'")
    det.append("  have hin' := hin")
    det.append("  simp only [inputs, List.cons.injEq, and_true] at hin'")
    det.append(f"  obtain ⟨{', '.join(f'j{k}' for k in range(len(inputs)))}⟩ := hin'")
    for c in incols:
        det.append(f"  have i{c} : w.v{c} = w'.v{c} := j{pos(c)}")
    for k, (s_, (_, x, a_, b_)) in enumerate(seldef.items()):
        det.append(f"  have i{s_} : w.v{s_} = w'.v{s_} := by")
        det.append(f"    have jx := j{pos(x)}")
        det.append(f"    linear_combination ({1 if a_ - b_ == 1 else -1}) * (d{k}' - d{k} + jx)")
        incols.append(s_)
    det.append(f"  simp only [{', '.join(f'i{c}' for c in incols)}] at {' '.join(f'f{k}' for k in range(nf))}")
    for k, g in enumerate(gadgets):
        for suf, w in (("", "w"), ("'", "w'")):
            det.append(f"  have hr{k}{suf} : ∀ x ∈ [{', '.join(f'(({w}.v{c}.val : ℕ) : ℤ)' for c in g['r'])}], 0 ≤ x ∧ x ≤ 255 := by")
            det.append("    intro x hx")
            det.append("    simp only [List.mem_cons, List.mem_nil_iff, or_false] at hx")
            det.append(f"    rcases hx with {' | '.join('rfl' for _ in g['r'])} <;>")
            det.append("      exact ZirenDet.FieldOp.byte_range (by assumption)")
    det += cases(0, {}, 2)
    out = ["section FieldOpGadget", "open ZirenDet", ""] + lemmas
    out.append("/-- Every operation holds modulo the modulus, and every output is below it. -/")
    out.append("theorem row_spec (w : W) (hw : constraints w) :")
    out.append("    " + " ∧\n    ".join(conj) + " := by")
    out += proof
    out.append("")
    out.append("/-- The byte ranges of the outputs. -/")
    out.append("theorem row_ranges (w : W) (hw : constraints w) :")
    out.append("    " + " ∧ ".join(f"w.v{c}.val ≤ 255" for c in outs) + " := by")
    out.append("  %OPEN_HW%")
    out.append(f"  exact ⟨{', '.join(rng)}⟩")
    out.append("")
    out.append("/-- The outputs' bytes are determined by the row's inputs. -/")
    out.append("theorem gadget_det (w w' : W) (hw : constraints w) (hw' : constraints w')")
    out.append("    (hin : inputs w = inputs w') :")
    out.append("    " + " ∧ ".join(f"w.v{c} = w'.v{c}" for c in outs) + " := by")
    out += det
    out.append("")
    out.append("end FieldOpGadget")
    out.append("")
    open(sys.argv[2], 'w').write("\n".join(out))
    print(json.dumps(dict(n=n, ops=len(ops), outs=[g['r'][0] for g in gadgets], free=free,
                          pins={str(s): v for s, (_, v) in pins.items()})), file=sys.stderr)


if __name__ == "__main__":
    main()

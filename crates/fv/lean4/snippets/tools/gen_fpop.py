"""gen_fpop.py MODULE_FILE OUT: the gadget proof of a field-operation chip (`FpOpAssign`) for one
module (a split Lean file), as a snippet with the generator's placeholders.

The module's coefficient rows give `A ∘ B = R + C·M` over the integers, its less-than gadget
gives `R < M`, so `R` is the canonical residue of `A ∘ B` and its bytes are a function of the
operands' bytes."""
import random, re, sys
sys.path.insert(0, '.')
from mklemma import subst



def parse(path):
    src = open(path).read().split('\n')
    start = next(i for i, l in enumerate(src) if l.startswith('def constraints_0'))
    cons, k = {}, 0
    for l in src[start:]:
        if l.startswith('def constraints '):
            break
        if l.startswith('def ') or not l.strip():
            continue
        cons[k] = re.sub(r' ∧$', '', l.strip())
        k += 1
    return src, cons


def reified_columns(src):
    """The columns the extractor introduced for an expression: fields without a column name."""
    out = set()
    for prev, line in zip(src, src[1:]):
        m = re.fullmatch(r'\s*v(\d+) : F', line)
        if m and not prev.strip().startswith('/--'):
            out.add(int(m.group(1)))
    return out


def pyexpr(text, value):
    """The constraint's left side as a Python expression over `value(column)`."""
    t = re.sub(r'\((-?\d+) : F\)', r'(\1)', text)
    return re.sub(r'w\.v(\d+)', lambda m: f"({value(int(m.group(1)))})", t)


def resolve(cons, i, reified):
    """Constraint `i` with its reified columns replaced by their other constraint (`z = 0` or
    `z - D = 0`); returns the text, its proof from the constraints and the constraints used."""
    text, proof, used = cons[i][:-4], f"e{i}", [i]
    while True:
        zs = sorted({int(n) for n in re.findall(r'w\.v(\d+)', text) if int(n) in reified})
        if not zs:
            return text, proof, used
        z = zs[0]
        other = [(j, d) for j, d in cons.items() if j not in used and re.search(rf'w\.v{z}\b', d)]
        assert len(other) == 1, (i, z, other)
        j, d = other[0]
        m = re.fullmatch(rf'\(w\.v{z} - \((.*)\)\) = 0', d)
        assert m or d == f"w.v{z} = 0", d
        val = f"({m.group(1)})" if m else "(0 : F)"
        coef = eval(pyexpr(text, lambda c: 1 if c == z else 7)) - eval(pyexpr(text, lambda c: 0 if c == z else 7))
        text = re.sub(rf'w\.v{z}\b', lambda _: val, text)
        proof += f" - ({coef}) * e{j}"
        used.append(j)


def raw(text):
    return re.sub(r'w\.v(\d+)', r'x\1', text)


def build_raw(cons, idx, L, goal, name, tactic, bound_of):
    """A lemma over the chip's own columns: the constraints `idx` enter as they stand, the
    columns of `L` come with their range, and `goal` (over the integer names of `L`) is stated
    on the columns' values.  The proof lifts the columns to integers without substituting
    them, so the chip applies the lemma to its constraints directly."""
    names = {nm: c for c, (nm, _) in L.items()}
    used = set()
    for i in idx:
        used |= {int(n) for n in re.findall(r'w\.v(\d+)', cons[i])}
    used |= {names[t] for t in re.findall(r'\b[a-z]\d*\b', goal) if t in names}
    cols = sorted(used)
    lifted = [c for c in cols if c in L]
    val = lambda c: f"((x{c}.val : ℕ) : ℤ)"
    stated = re.sub(r'\b[a-z]\d*\b', lambda m: val(names[m.group(0)]) if m.group(0) in names else m.group(0), goal)
    o = [f"theorem {name}", "    (" + " ".join(f"x{c}" for c in cols) + " : F)"]
    for c in lifted:
        o.append(f"    (b{L[c][0]} : x{c}.val ≤ {L[c][1]})")
    for i in idx:
        o.append(f"    (e{i} : {raw(cons[i])})")
    o.append(f"    : {stated} := by")
    for c in lifted:
        nm, bound = L[c]
        o.append(f"  obtain ⟨{nm}, h{nm}a, h{nm}b, x{nm}⟩ := ZirenDet.lift_le x{c} b{nm}")
        o.append(f"  have h{nm} : 0 ≤ {nm} ∧ {nm} ≤ {bound} := ⟨h{nm}a, by exact_mod_cast h{nm}b⟩")
    goalcols = [names[t] for t in dict.fromkeys(re.findall(r'\b[a-z]\d*\b', goal)) if t in names]
    for c in goalcols:
        nm = L[c][0]
        o.append(f"  have v{nm} : {val(c)} = {nm} := by rw [x{nm}, ZirenDet.val_cast]; omega")
    o.append(f"  simp only [{', '.join('v' + L[c][0] for c in goalcols)}]")
    o.append(tactic)
    app = f"{name} " + " ".join(f"w.v{c}" for c in cols) + " " + " ".join(bound_of(c, L[c][1]) for c in lifted) \
        + " " + " ".join(f"c{i}" for i in idx)
    return "\n".join(o) + "\n", app


def back(text, L):
    """The rewrites that turn the casts of `text`'s columns back into the columns."""
    return ", ".join(f"← x{L[int(c)][0]}" for c in dict.fromkeys(re.findall(r'w\.v(\d+)', text)) if int(c) in L)


def toint(t):
    return re.sub(r'\((-?\w+) : F\)', lambda m: m.group(1) if not m.group(1).startswith('-') else f"({m.group(1)})", t)


def lt_gadget(cons):
    """The columns of the less-than gadget: flags, result limbs, modulus limbs, rows."""
    eqrows = []
    for i, c in cons.items():
        m = re.fullmatch(r'\(\((\(*w\.v\d+(?: \+ w\.v\d+\))*) - \(1 : F\)\) \* \(w\.v(\d+) - \((\d+) : F\)\)\) = 0', c)
        if m:
            eqrows.append((i, [int(x) for x in re.findall(r'w\.v(\d+)', m.group(1))], int(m.group(2)), int(m.group(3)), m.group(1)))
    n = len(eqrows)
    assert n and [len(e[1]) for e in eqrows] == list(range(1, n + 1))
    top = eqrows[-1][1]
    g = dict(n=n, flags=top[::-1], r=[0] * n, mod=[0] * n, row=[0] * n, sumtext=[''] * n)
    for k, (i, fs, rv, mv, st) in enumerate(eqrows):
        assert fs == top[:k + 1]
        limb = n - 1 - k
        g['r'][limb], g['mod'][limb], g['row'][limb], g['sumtext'][limb] = rv, mv, i, st
    g['total'] = next(i for i, c in cons.items() if c.endswith(' - (1 : F)) = 0') and ' * ' not in c
                      and sorted(int(x) for x in re.findall(r'w\.v(\d+)', c)) == sorted(g['flags']))
    i, m = next((i, m) for i, c in cons.items() if (m := re.fullmatch(r'\(w\.v(\d+)\)\.val < \(w\.v(\d+)\)\.val', c)))
    g['lt'], g['p'], g['q'] = i, int(m.group(1)), int(m.group(2))
    g['dp'] = next(i for i, c in cons.items() if re.search(rf"w\.v{g['p']}\b", c) and ' * ' in c)
    g['dq'] = next(i for i, c in cons.items() if re.search(rf"w\.v{g['q']}\b", c) and ' * ' in c)
    g['M'] = sum(m * 256 ** i for i, m in enumerate(g['mod']))
    return g


def lt_lemma(cons, g, L, name, bound_of, reified):
    n, mod = g['n'], g['mod']
    t1, p1, u1 = resolve(cons, g['dp'], reified)
    t2, p2, u2 = resolve(cons, g['dq'], reified)
    S = lambda i: " + ".join(f"f{j}" for j in range(i, n))
    bits = ' '.join(f'hf{j}' for j in range(n))
    o = []
    o.append(f"  have hsum : {S(0)} = 1 := by")
    o.append(f"    have r : {subst(cons[g['total']][:-4], L)} = 0 := by")
    o.append(f"      simp only [{back(cons[g['total']], L)}]; exact e{g['total']}")
    o.append(f"    clear * - r {bits}")
    o.append("    fieldop_row r")
    o.append(f"  have hp : p = {' + '.join(f'r{i} * f{i}' for i in range(n))} := by")
    o.append(f"    have r : {subst(t1, L)} = 0 := by")
    o.append(f"      simp only [{back(t1, L)}]; linear_combination {p1}")
    o.append(f"    clear * - r hp {' '.join(f'hf{j} hr{j}' for j in range(n))}")
    o.append("    fieldop_row r")
    o.append(f"  have hq : q = {' + '.join(f'f{i} * {mod[i]}' for i in range(n))} := by")
    o.append(f"    have r : {subst(t2, L)} = 0 := by")
    o.append(f"      simp only [{back(t2, L)}]; linear_combination {p2}")
    o.append(f"    clear * - r hq {bits}")
    o.append("    fieldop_row r")
    o.append(f"  have hlt : p < q := ZirenDet.DivRem.lt_of_val_lt (by rw [← xp, ← xq]; exact e{g['lt']}) (by omega) (by omega)")
    o.append(f"  obtain ⟨S{n}, hS{n}⟩ : ∃ S : ℤ, S = 0 := ⟨_, rfl⟩")
    o.append(f"  obtain ⟨R{n}, hR{n}⟩ : ∃ R : ℤ, R = 0 := ⟨_, rfl⟩")
    for i in range(n - 1, -1, -1):
        o.append(f"  obtain ⟨S{i}, hS{i}⟩ : ∃ S : ℤ, S = f{i} + S{i + 1} := ⟨_, rfl⟩")
        o.append(f"  obtain ⟨R{i}, hR{i}⟩ : ∃ R : ℤ, R = r{i} + 256 * R{i + 1} := ⟨_, rfl⟩")
    chain = ' '.join(f'hS{j}' for j in range(n + 1))
    for i in range(n):
        o.append(f"  have hb{i} : 0 ≤ S{i} ∧ S{i} ≤ 1 := by")
        o.append(f"    clear * - hsum {chain} {bits}")
        o.append("    omega")
    for i in range(n):
        o.append(f"  have H{i} : S{i} = 0 → r{i} = {mod[i]} := by")
        o.append("    intro h0")
        o.append(f"    have h0' : {S(i)} = 0 := by")
        o.append(f"      clear * - h0 {' '.join(f'hS{j}' for j in range(i, n + 1))}")
        o.append("      omega")
        o.append(f"    have hc : ((({S(i)} : ℤ) : F)) = 0 := by rw [h0']; simp")
        o.append(f"    have r : ((r{i} : ℤ) : F) - ({mod[i]} : F) = 0 := by")
        o.append(f"      have e : {subst(cons[g['row'][i]], L)} := by")
        o.append(f"        simp only [{back(cons[g['row'][i]], L)}]; exact e{g['row'][i]}")
        o.append("      push_cast at hc")
        o.append(f"      have hne : ({subst(g['sumtext'][i], L)} - (1 : F)) = -1 := by linear_combination hc")
        o.append("      rw [hne] at e")
        o.append("      linear_combination -e")
        o.append(f"    clear * - r hr{i}")
        o.append(f"    have r' : ((r{i} - {mod[i]} : ℤ) : F) = ((0 : ℤ) : F) := by push_cast; linear_combination r")
        o.append("    obtain ⟨m, hm⟩ := ZirenDet.cast_eq_iff_dvd.mp r'")
        o.append("    omega")
    for i in range(n):
        o.append(f"  have G{i} : f{i} = 1 → r{i} < {mod[i]} := by")
        o.append("    intro h1")
        for j in range(n):
            if j != i:
                o.append(f"    have z{j} : f{j} = 0 := by clear * - hsum h1 {bits}; omega")
        o.append(f"    clear * - hp hq hlt h1 {' '.join(f'z{j}' for j in range(n) if j != i)}")
        o.append("    subst_vars")
        o.append("    simp only [mul_zero, mul_one, zero_mul, one_mul, add_zero, zero_add] at hlt")
        o.append("    omega")
    top = lambda i: sum(mod[j] * 256 ** (j - i) for j in range(i, n))
    o.append(f"  have P{n} : (S{n} = 0 ∧ R{n} = 0) ∨ (S{n} = 1 ∧ R{n} < 0) := Or.inl ⟨hS{n}, hR{n}⟩")
    for i in range(n - 1, -1, -1):
        o.append(f"  have P{i} : (S{i} = 0 ∧ R{i} = {top(i)}) ∨ (S{i} = 1 ∧ R{i} < {top(i)}) := by")
        o.append(f"    clear * - P{i + 1} hS{i} hR{i} hf{i} hr{i} H{i} G{i} hb{i}" + (f" hb{i + 1}" if i + 1 < n else f" hS{n}"))
        o.append("    omega")
    o.append(f"  have hS0 : S0 = 1 := by clear * - hsum {chain}; omega")
    o.append(f"  clear * - P0 hS0 {' '.join(f'hR{j}' for j in range(n + 1))}")
    o.append("  omega")
    goal = f"{' + '.join(f'{256 ** i} * r{i}' for i in range(n))} < {g['M']}"
    used = sorted({g['total'], g['lt']} | set(g['row']) | set(u1) | set(u2))
    return build_raw(cons, used, L, goal, name, "\n".join(o), bound_of)


def op_rows(cons, reified):
    """The coefficient rows, lowest first, the columns of the witness and its offset."""
    off = next(int(m.group(1)) for c in cons.values()
               if (m := re.search(r'\(w\.v\d+ - \((\d+) : F\)\) \* \(-256 : F\)', c)))
    rows = [resolve(cons, i, reified) for i, c in cons.items() if f'({off} : F)) * (-256 : F)' in c or re.search(rf'- \(w\.v\d+ - \({off} : F\)\)\)+ = 0$', c)]
    key = lambda r: tuple(sorted(int(n) for n in re.findall(rf'w\.v(\d+) - \({off} : F\)', r[0])))
    wit = sorted({c for r in rows for c in key(r)})
    rows.sort(key=lambda r: 0 if key(r) == (wit[0],) else (min(key(r)) - wit[0] + 1))
    assert [len(key(r)) for r in rows] == [1] + [2] * (len(rows) - 2) + [1]
    return rows, wit, off


def main():
    src, cons = parse(sys.argv[1])
    reified = reified_columns(src)
    g = lt_gadget(cons)
    n = g['n']
    rows, wit, off = op_rows(cons, reified)
    assert len(rows) == 2 * n - 1 and len(wit) == 2 * n - 2
    vals = lambda name: [int(x) for x in re.findall(r'w\.v(\d+)', next(l for l in src if l.startswith(f'def {name} ')))]
    words = n // 4
    a = sum((vals(f'in_mem_read_{k}_val') for k in range(words, 2 * words)), [])
    b = sum((vals(f'in_mem_read_{k}_val') for k in range(words)), [])
    carry = []
    for i in range(n):
        ks = re.findall(rf'\(w\.v(\d+) \* \({g["mod"][0]} : F\)\)', rows[i][0])
        carry.append(int(ks[-1]))
    L = {}
    for i in range(n):
        L[a[i]] = (f'a{i}', 255)
        L[b[i]] = (f'b{i}', 255)
        L[g['r'][i]] = (f'r{i}', 255)
        L[carry[i]] = (f'k{i}', 255)
        L[g['flags'][i]] = (f'f{i}', 1)
    for i, c in enumerate(wit):
        L[c] = (f'w{i}', 65535)
    L[g['p']] = ('p', 255)
    L[g['q']] = ('q', 255)
    # every other column of the rows is a selector the module pins to a constant
    sel = sorted({int(c) for r in rows for c in re.findall(r'w\.v(\d+)', r[0])} - set(L))
    pins = {}
    for k, s in enumerate(sel):
        L[s] = (f's{k}', 1)
        hit = [(i, v) for i, c in cons.items() for v in (0, 1)
               if set(re.findall(r'w\.v(\d+)', c)) == {str(s)} and '*' not in c and c.endswith(' = 0')
               and eval(pyexpr(c[:-4], lambda _: v)) == 0 and eval(pyexpr(c[:-4], lambda _: 1 - v)) != 0]
        assert hit, s
        pins[s] = hit[0]
    # the operation and the orientation of every row, found numerically
    env = {name: random.randrange(0, bound + 1) for name, bound in L.values()}
    for s, (_, v) in pins.items():
        env[L[s][0]] = v
    col = lambda c: env[L[c][0]]
    lv = lambda p, i: env.get(f'{p}{i}', 0)
    wp = lambda i: (lv('w', i) - off) if 0 <= i < len(wit) else 0
    ops = {
        'mul': lambda i: sum(lv('a', j) * lv('b', i - j) for j in range(n) if 0 <= i - j < n),
        'add': lambda i: lv('a', i) + lv('b', i),
    }
    got = [eval(pyexpr(t, col)) for t, _, _ in rows]
    op, sign = None, None
    for name, f in ops.items():
        exp = [f(i) - lv('r', i) - sum(lv('k', j) * g['mod'][i - j] for j in range(n) if 0 <= i - j < n)
               - (wp(i - 1) - 256 * wp(i)) for i in range(2 * n - 1)]
        if all(x in (e, -e) for x, e in zip(got, exp)):
            op, sign = name, [1 if x == e else -1 for x, e in zip(got, exp)]
    assert op, "operation not recognised"
    P = lambda p: " + ".join(f"{256 ** i} * {p}{i}" for i in range(n))
    sym = {'mul': '*', 'add': '+'}[op]
    o = []
    for s, (i, v) in pins.items():
        nm = L[s][0]
        o.append(f"  have p{nm} : {nm} = {v} := by")
        o.append(f"    have e : {subst(cons[i], L)} := by")
        o.append(f"      simp only [{back(cons[i], L)}]; exact e{i}")
        o.append(f"    clear * - e h{nm}")
        o.append("    divrem_lift; omega")
    pinned = ' '.join(f"p{L[s][0]}" for s in pins)
    for k, (text, proof, _) in enumerate(rows):
        f = subst(text, L)
        keep = " ".join(f"h{v}" for v in sorted({L[int(c)][0] for c in re.findall(r'w\.v(\d+)', text)}))
        o.append(f"  have H{k} : {toint(f)} = 0 := by")
        o.append(f"    have r : {f} = 0 := by")
        o.append(f"      simp only [{back(text, L)}]; linear_combination {proof}")
        o.append(f"    clear * - r {pinned} {keep}")
        o.append("    subst_vars")
        o.append("    (try simp only [Int.cast_zero, Int.cast_one, mul_zero, zero_mul, mul_one, one_mul, add_zero, sub_zero, zero_add] at r ⊢)")
        o.append("    fieldop_row r")
    o.append(f"  clear * - {pinned} {' '.join(f'H{k}' for k in range(len(rows)))}")
    o.append("  subst_vars")
    o.append("  linear_combination " + " + ".join(f"({sg * 256 ** k}) * H{k}" for k, sg in enumerate(sign)))
    goal = f"({P('a')}) {sym} ({P('b')}) = ({P('r')}) + ({P('k')}) * {g['M']}"
    used = sorted({i for r in rows for i in r[2]} | {i for i, _ in pins.values()})
    def bound_of(c, bound):
        for i, t in cons.items():
            if t == f"(w.v{c}).val ≤ {bound}":
                return f"c{i}"
        for i, t in cons.items():
            if t == f"(w.v{c} * (w.v{c} - (1 : F))) = 0":
                return f"(ZirenDet.bit_val_le c{i})"
        raise AssertionError(c)

    id_text, id_app = build_raw(cons, used, L, goal, "op_identity", "\n".join(o), bound_of)
    lt_text, lt_app = lt_lemma(cons, g, L, "result_lt", bound_of, reified)

    val = lambda c: f"((w.v{c}.val : ℕ) : ℤ)"
    ev = lambda cols, w='w': "(ZirenDet.FieldOp.ev [" + ", ".join(f"(({w}.v{c}.val : ℕ) : ℤ)" for c in cols) + "])"
    xval = lambda c: f"((w.v{c}.val : ℕ) : ℤ)"
    hval = lambda cols: "".join(f"{xval(c)} + 256 * (" for c in cols) + "0" + ")" * len(cols)
    pval = lambda cols: " + ".join(f"{256 ** i} * {xval(c)}" for i, c in enumerate(cols))
    i0 = next(i for i, l in enumerate(src) if l.startswith('def inputs'))
    inputs = re.findall(r'w\.v(\d+)', src[i0 + 1])
    pos = lambda c: inputs.index(str(c))
    rng = [bound_of(c, 255) for c in g['r']]
    R = g['r']
    out = ["section FieldOpGadget", "open ZirenDet", "", id_text, lt_text]
    out.append(f"""/-- The result is the canonical residue of the operation on the operands. -/
theorem row_spec (w : W) (hw : constraints w) :
    {ev(R)} < {g['M']} ∧
      {ev(R)} ≡ {ev(a)} {sym} {ev(b)} [ZMOD {g['M']}] := by
  %OPEN_HW%
  have hid := {id_app}
  have hlt := {lt_app}
  simp only [ZirenDet.FieldOp.ev]
  have eA : {hval(a)} = {pval(a)} := by ring
  have eB : {hval(b)} = {pval(b)} := by ring
  have eR : {hval(R)} = {pval(R)} := by ring
  obtain ⟨K, hK⟩ : ∃ K : ℤ, K = {pval(carry)} := ⟨_, rfl⟩
  rw [eA, eB, eR]
  rw [← hK] at hid
  refine ⟨hlt, ?_⟩
  rw [hid]
  exact (Int.modEq_iff_dvd.mpr ⟨K, by ring⟩)

/-- The byte ranges of the result. -/
theorem row_ranges (w : W) (hw : constraints w) :
    {' ∧ '.join(f'w.v{c}.val ≤ 255' for c in R)} := by
  %OPEN_HW%
  exact ⟨{', '.join(rng)}⟩

/-- The result's bytes are determined by the row's inputs. -/
theorem gadget_det (w w' : W) (hw : constraints w) (hw' : constraints w')
    (hin : inputs w = inputs w') :
    {' ∧ '.join(f"w.v{c} = w'.v{c}" for c in R)} := by
  obtain ⟨h1, h2⟩ := row_spec w hw
  obtain ⟨h1', h2'⟩ := row_spec w' hw'
  obtain ⟨{', '.join(f'a{c}' for c in R)}⟩ := row_ranges w hw
  obtain ⟨{', '.join(f"a{c}'" for c in R)}⟩ := row_ranges w' hw'
  have hin' := hin
  simp only [inputs, List.cons.injEq, and_true] at hin'
  obtain ⟨{', '.join(f'j{k}' for k in range(len(inputs)))}⟩ := hin'
{chr(10).join(f"  have i{c} : w.v{c} = w'.v{c} := j{pos(c)}" for c in a + b)}
  simp only [{', '.join(f'i{c}' for c in a + b)}] at h2
  have hr : ∀ x ∈ [{', '.join(val(c) for c in R)}], 0 ≤ x ∧ x ≤ 255 := by
    intro x hx
    simp only [List.mem_cons, List.mem_nil_iff, or_false] at hx
    rcases hx with {' | '.join('rfl' for _ in R)} <;>
      exact ZirenDet.FieldOp.byte_range (by assumption)
  have hr' : ∀ x ∈ [{', '.join(f"((w'.v{c}.val : ℕ) : ℤ)" for c in R)}], 0 ≤ x ∧ x ≤ 255 := by
    intro x hx
    simp only [List.mem_cons, List.mem_nil_iff, or_false] at hx
    rcases hx with {' | '.join('rfl' for _ in R)} <;>
      exact ZirenDet.FieldOp.byte_range (by assumption)
  have hR : {ev(R)} = {ev(R, "w'")} :=
    ZirenDet.FieldOp.residue_unique (X := {ev(a, "w'")} {sym} {ev(b, "w'")}) (M := {g['M']})
      (ZirenDet.FieldOp.ev_nonneg _ hr) h1 (ZirenDet.FieldOp.ev_nonneg _ hr') h1' h2 h2'
  have hl : [{', '.join(val(c) for c in R)}] = [{', '.join(f"((w'.v{c}.val : ℕ) : ℤ)" for c in R)}] :=
    ZirenDet.FieldOp.ev_inj _ _ (by simp only [List.length_cons, List.length_nil]) hr hr' hR
  simp only [List.cons.injEq, and_true] at hl
  obtain ⟨{', '.join(f'e{c}' for c in R)}⟩ := hl
  exact ⟨{', '.join(f'ZMod.val_injective _ (by exact_mod_cast e{c})' for c in R)}⟩

end FieldOpGadget
""")
    open(sys.argv[2], 'w').write("\n".join(out))
    print(op, n, hex(g['M']), 'selectors', {L[s][0]: v for s, (_, v) in pins.items()}, file=sys.stderr)


if __name__ == "__main__":
    main()

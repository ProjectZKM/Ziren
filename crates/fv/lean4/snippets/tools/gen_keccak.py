"""gen_keccak.py MODULE_FILE OUT: the gadget proof of the keccak-f round chip (`KeccakSponge`), as
a snippet with the generator's placeholders.

With `sᵧₓz = xor3(a'ᵧₓz, cₓz, c'ₓz)`, each input limb is `Σ 2ᵏ·s`, so the `s` are the input bits;
θ's column check makes `cₓz` their column parity (`Keccak.column_parity`), `c'` is a function of
`c`, `a'` is `s` with `c`, `c'` undone (`Keccak.xor3F_cancel`), `a''` a function of `a'`, the
`a''[0][0]` bits its binary digits, the round flags the one-hot reading of the index, and
`a'''[0][0]` a function of those bits and flags.  Every output limb is then determined."""
import random, re, sys

HERE = __file__.rsplit('/', 1)[0]
sys.path.insert(0, HERE)
from gen_fpop import parse, reified_columns, pyexpr

KB = 2130706433
ren = lambda proof, h: re.sub(r'\be(\d+)', h + r'\1', proof)
NR = 24
FLAG = lambda i: i
A = lambda y, x, l: 125 + 20 * y + 4 * x + l
C = lambda x, z: 225 + 64 * x + z
CP = lambda x, z: 545 + 64 * x + z
AP = lambda y, x, z: 865 + 320 * y + 64 * x + z
APP = lambda y, x, l: 2465 + 20 * y + 4 * x + l
B00 = lambda z: 2565 + z
APPP = lambda l: 2629 + l


def proj(names, src, tmp):
    """Bind the conjuncts of `src` to `names` by projection: an `obtain` would `cases` each `∧` in
    the gadget's context of thousands of hypotheses, at a cost that grows with the context."""
    n = len(names)
    o = [f"  have {tmp} := {src}"]
    for k, nm in enumerate(names):
        o.append(f"  have {nm} := {tmp}" + ".2" * k + (".1" if k < n - 1 else ""))
    return o


def limb16_lemma():
    s = [f"s{k}" for k in range(16)]
    t = [f"t{k}" for k in range(16)]
    o = ["/-- Sixteen bits read as a 16-bit limb are its binary digits. -/",
         "theorem limb16 {" + " ".join(s + t) + " : F}"]
    o.append("    " + " ".join(f"(h{v} : Keccak.bitF {v})" for v in s + t))
    o.append(f"    (h : {' + '.join(f'({2 ** k} : F) * {s[k]}' for k in range(16))} =")
    o.append(f"      {' + '.join(f'({2 ** k} : F) * {t[k]}' for k in range(16))}) :")
    o.append("    " + " ∧ ".join(f"{s[k]} = {t[k]}" for k in range(16)) + " := by")
    for v in s + t:
        o.append(f"  have v{v} := Keccak.bitF_val h{v}")
        o.append(f"  have c{v} : {v} = ((({v}.val : ℕ) : ℤ) : F) := Keccak.bitF_cast")
    V = lambda v: f"(({v}.val : ℕ) : ℤ)"
    o.append(f"  rw [{', '.join(f'c{v}' for v in s + t)}] at h")
    o.append(f"  have h2 : ((({' + '.join(f'{2 ** k} * {V(s[k])}' for k in range(16))} : ℤ)) : F) =")
    o.append(f"      ((({' + '.join(f'{2 ** k} * {V(t[k])}' for k in range(16))} : ℤ)) : F) := by")
    o.append("    push_cast; exact h")
    o.append("  have h3 := ZirenDet.Gadgets.cast_inj_small h2 (by rw [abs_lt]; constructor <;> omega) (by rw [abs_lt]; constructor <;> omega)")
    o.append(f"  have h4 := Keccak.evb_inj [{', '.join(V(v) for v in s)}] [{', '.join(V(v) for v in t)}] rfl")
    o.append("    (by intro x hx; simp only [List.mem_cons, List.mem_nil_iff, or_false] at hx; rcases hx with "
             + " | ".join("rfl" for _ in s) + " <;> assumption)")
    o.append("    (by intro x hx; simp only [List.mem_cons, List.mem_nil_iff, or_false] at hx; rcases hx with "
             + " | ".join("rfl" for _ in t) + " <;> assumption)")
    o.append("    (by simp only [Keccak.evb]; linarith)")
    o.append("  simp only [List.cons.injEq, and_true] at h4")
    o.append(f"  obtain ⟨{', '.join(f'e{k}' for k in range(16))}⟩ := h4")
    o.append("  exact ⟨" + ", ".join(f"ZMod.val_injective _ (by exact_mod_cast e{k})" for k in range(16)) + "⟩")
    return "\n".join(o) + "\n"


def onehot_lemma():
    f = [f"f{i}" for i in range(NR)]
    g = [f"g{i}" for i in range(NR)]
    o = ["/-- One-hot round flags with the same index agree. -/",
         "theorem onehot {" + " ".join(f + g) + " I : F}"]
    o.append("    " + " ".join(f"(h{v} : Keccak.bitF {v})" for v in f + g))
    o.append(f"    (hs : {' + '.join(f)} = 1) (hi : {' + '.join(f'({i} : F) * {f[i]}' for i in range(NR))} = I)")
    o.append(f"    (hs' : {' + '.join(g)} = 1) (hi' : {' + '.join(f'({i} : F) * {g[i]}' for i in range(NR))} = I) :")
    o.append("    " + " ∧ ".join(f"{f[i]} = {g[i]}" for i in range(NR)) + " := by")
    sums = ("simp only [Fin.sum_univ_succ, Fin.sum_univ_zero, Matrix.cons_val_zero, Matrix.cons_val_succ, "
            "Fin.val_zero, Fin.val_succ, Nat.cast_add, Nat.cast_one, Nat.cast_zero]")
    o.append("  have bit01 : ∀ {x : F}, Keccak.bitF x → x * (x - 1) = 0 := fun h => by rcases h with h | h <;> simp [h]")
    o.append(f"  have key := ZirenDet.OneHot.onehot_lin_det (n := {NR}) (by norm_num [KB]) (fun i => ((i : ℕ) : F))")
    o.append("    (fun i j h => Fin.ext (by")
    o.append("      have hv := congrArg ZMod.val h")
    o.append("      simp only [ZMod.val_natCast] at hv")
    o.append("      rwa [Nat.mod_eq_of_lt (lt_of_lt_of_le i.2 (by norm_num [KB])), "
             "Nat.mod_eq_of_lt (lt_of_lt_of_le j.2 (by norm_num [KB]))] at hv))")
    o.append(f"    ![{', '.join(f)}] ![{', '.join(g)}]")
    o.append("    (by intro i; fin_cases i <;> exact bit01 (by assumption))")
    o.append(f"    (by {sums}; linear_combination hs)")
    o.append("    (by intro i; fin_cases i <;> exact bit01 (by assumption))")
    o.append(f"    (by {sums}; linear_combination hs')")
    o.append(f"    (by {sums}; linear_combination hi - hi')")
    o.append("  exact ⟨" + ", ".join(f"congrFun key {i}" for i in range(NR)) + "⟩")
    return "\n".join(o) + "\n"


def lift(det, typ):
    """Moves every `have NAME : TYPE := by …` step of `det` into a top-level lemma and leaves its
    application in place.  One declaration of thousands of `ring` proofs is elaborated on one
    thread; separate lemmas are elaborated in parallel.  A lemma is stated over plain variables
    `x…` (for `w.v…`) and `y…` (for `w'.v…`), implicit and fixed by its hypotheses, and applied
    without restating its type: elaborating a field access `w.v…` of the chip's structure costs
    time linear in its thousands of fields.  `typ` gives the statement of every hypothesis a step
    may name; a step's own declared type is added to it."""
    ren = lambda t: re.sub(r"\bw'\.v(\d+)", r"y\1", re.sub(r"\bw\.v(\d+)", r"x\1", t))
    var = lambda t: set(re.findall(r"\b([xy]\d+)\b", t))
    key = lambda v: (v[0], int(v[1:]))
    out, lemmas, k = [], [], 0
    tok = re.compile(r"(?<![\w.'])([A-Za-z]+\d+'?|fs'?|fi'?|qflag)(?![\w'])")
    while k < len(det):
        line = det[k]
        m = re.fullmatch(r"  have (\S+) : (.*) := by", line)
        n = k + 1
        while n < len(det) and det[n].startswith("    "):
            n += 1
        if m is None:
            m2 = re.fullmatch(r"  have (\S+) : (.*?) := (.*)", line)
            if m2:
                typ[m2.group(1)] = m2.group(2)
                if not m2.group(3).startswith("by "):
                    line = f"  have {m2.group(1)} := {m2.group(3)}"
            out += [line] + det[k + 1:n]
            k = n
            continue
        name, ty = m.group(1), m.group(2)
        body = det[k + 1:n]
        used = []
        for t in tok.findall(" ".join(body)):
            if t in typ and t not in used:
                used.append(t)
        hyps = [(u, ren(typ[u])) for u in used]
        inferred = set().union(*(var(t) for _, t in hyps)) if hyps else set()
        concl = ren(ty)
        explicit = sorted(var(concl) - inferred, key=key)
        implicit = sorted(inferred, key=key)
        lname = f"ks_step{len(lemmas)}"
        head = f"theorem {lname}" + (f" {{{' '.join(implicit)} : F}}" if implicit else "")
        head += "".join(f" ({v} : F)" for v in explicit)
        lemmas.append(head + "".join(f" ({u} : {t})" for u, t in hyps) + f" :\n    {concl} := by\n"
                      + "\n".join(ren(l[2:]) for l in body) + "\n")
        args = [("w'" if v[0] == "y" else "w") + ".v" + v[1:] for v in explicit] + used
        out.append(f"  have {name} := {lname} {' '.join(args)}")
        typ[name] = ty
        k = n
    det[:] = out
    return lemmas


def segment(det, typ, final, target=2500):
    """Moves runs of consecutive steps of `det` (after the input prologue) into lemmas `gd_segK`.

    A tactic in one declaration pays for every hypothesis in its context, and `gadget_det` holds
    thousands of facts; a segment lemma holds only the facts its steps use (its hypotheses) and the
    ones they prove.  A segment's size counts its steps, the local facts it re-derives and the
    conjuncts it projects.  A segment's conclusion is the facts later steps use, so every one of those
    needs a known statement (`typ`); a fact rewritten in place (`rw … at X`) never crosses a
    boundary.  Segments are chained: each states the gadget's conclusion `final`, takes the
    witnesses, both constraint sets and the facts live at its start, projects the conjuncts it uses
    (`%PROJ_…%`, filled by the generator), and ends by applying the next segment, so no context
    ever holds more than one segment's facts."""
    ren = lambda t: re.sub(r"\bw'\.v(\d+)", r"y\1", re.sub(r"\bw\.v(\d+)", r"x\1", t))
    var = lambda t: set(re.findall(r"\b([xy]\d+)\b", t))
    key = lambda v: (v[0], int(v[1:]))
    tok = re.compile(r"(?<![\w.'])([A-Za-z]+\d+'?|fs'?|fi'?|qflag)(?![\w'])")
    stmts, cur = [], None
    for line in det:
        if line.startswith("  ") and not line.startswith("    "):
            cur = [line]; stmts.append(cur)
        else:
            cur.append(line)
    pro = 0
    while pro < len(stmts) and re.search(r"%OPEN|hin'|jall|^  have j\d+ :=|^  have i\d+ (?:: .* )?:= j\d+$", stmts[pro][0]):
        pro += 1
    tail = len(stmts) - 1
    assert stmts[tail][0].startswith("  exact ⟨")
    defs, rew = [], []
    for s in stmts:
        m = re.match(r"  have (\S+?)(?: :|) ", s[0] + " ")
        defs.append(m.group(1) if m and s[0].startswith("  have ") else None)
        m2 = re.match(r"  rw \[.*\] at (\S+)$", s[0])
        rew.append(m2.group(1) if m2 else None)
    uses = [set(tok.findall(" ".join(s))) for s in stmts]
    conj = re.compile(r"[cd]\d+$")
    pinned = {r for r in rew if r} | (uses[tail] - {None})
    local = {}
    for k in range(pro, tail):
        n = defs[k]
        if n and not rew[k] and n not in pinned and all(conj.match(u) or u in local or u not in typ and u not in defs
                                                         for u in uses[k] - {n}):
            local[n] = k
    keep = [k for k in range(len(stmts)) if not (pro <= k < tail and defs[k] in local and local[defs[k]] == k)]

    def closure(names):
        need, todo = set(), [n for n in names if n in local]
        while todo:
            n = todo.pop()
            if n in need:
                continue
            need.add(n)
            todo += [u for u in full_uses[local[n]] if u in local and u != n]
        return sorted(need, key=lambda n: local[n])

    orig = stmts
    full_uses = uses
    stmts = [stmts[k] for k in keep]
    defs = [defs[k] for k in keep]
    rew = [rew[k] for k in keep]
    tail = len(stmts) - 1
    uses = [set(tok.findall(" ".join(s))) for s in stmts]
    last = {}
    for i, u in enumerate(uses):
        for n in u:
            last[n] = i
    conj_of = lambda names: {u for n in names for u in full_uses[local[n]] if conj.match(u)}
    bounds, i = [pro], pro
    while i < tail:
        j, size, have = i, 0, set()
        while j < tail:
            add = set(closure(uses[j])) - have
            cs = ({u for u in uses[j] if conj.match(u)} | conj_of(add)) - have
            size += len(stmts[j]) + sum(len(orig[local[n]]) for n in add) + len(cs)
            have |= add | cs
            j += 1
            if size < target or j == tail:
                continue
            seg_defs = {defs[k] for k in range(i, j) if defs[k]}
            seg_rew = {rew[k] for k in range(i, j) if rew[k]}
            live = {n for n in seg_defs | seg_rew if last.get(n, -1) >= j}
            if all(n in typ and n not in seg_rew for n in live):
                break
        bounds.append(j)
        i = j
    first = {}
    for k, n in enumerate(defs):
        if n and n not in first:
            first[n] = k

    def live_at(b):
        lv = sorted((n for n, k in first.items() if k < b and last.get(n, -1) >= b), key=lambda n: first[n])
        assert all(n in typ for n in lv), [n for n in lv if n not in typ][:5]
        return lv

    segs = list(zip(bounds[:-1], bounds[1:]))
    lemmas = []
    for idx, (i, j) in enumerate(segs):
        need = closure(set().union(*(uses[k] for k in range(i, j))))
        body = [l for n in need for l in orig[local[n]]] + [l for k in range(i, j) for l in stmts[k]]
        conjs = sorted({u for l in body for u in tok.findall(l) if conj.match(u)}, key=lambda c: (c[0], int(c[1:])))
        proj = [f"  have {c} := %PROJ_{c[0].upper()}{c[1:]}%" for c in conjs]
        if idx + 1 < len(segs):
            close = [f"  exact gd_seg{idx + 1} w w' hw hw' {' '.join(live_at(j))}"]
        else:
            close = stmts[tail]
        head = "theorem gd_seg%d (w w' : W) (hw : constraints w) (hw' : constraints w')" % idx
        head += "".join(f" ({n} : {typ[n]})" for n in live_at(i))
        lemmas.append(head + f" :\n    {final} := by\n" + "\n".join(proj + body + close) + "\n")
    lemmas.reverse()
    out = [l for s in stmts[:pro] for l in s if "%OPEN" not in l]
    out.append(f"  exact gd_seg0 w w' hw hw' {' '.join(live_at(pro))}")
    det[:] = out
    return lemmas


def main():
    path, outp = sys.argv[1], sys.argv[2]
    src, cons = parse(path)
    reified = reified_columns(src)
    defs = {}
    for i, c in cons.items():
        m = re.fullmatch(r'\(w\.v(\d+) - (\(.*\))\) = 0', c)
        if m and int(m.group(1)) in reified:
            defs.setdefault(int(m.group(1)), []).append((i, m.group(2)))
    assert all(len(v) == 1 for v in defs.values()), [u for u, v in defs.items() if len(v) != 1][:5]
    defs = {u: v[0] for u, v in defs.items()}
    def_rows = {i for i, _ in defs.values()}
    roots = {}
    for i, c in cons.items():
        if i in def_rows or not c.endswith(' = 0'):
            continue
        m = re.fullmatch(r'w\.v(\d+) = 0', c)
        roots[i] = c[:-4]
    cols = lambda t: {int(x) for x in re.findall(r'w\.v(\d+)', t)}
    memo_base = {}

    def base(u):
        """Base columns under reified column `u`."""
        if u not in memo_base:
            out = set()
            for c in cols(defs[u][1]):
                out |= base(c) if c in defs else {c}
            memo_base[u] = out
        return memo_base[u]
    rbase = {}
    for i, t in roots.items():
        out = set()
        for c in cols(t):
            out |= base(c) if c in defs else {c}
        rbase[i] = out

    def evaluate(t, env, memo):
        def val(c):
            if c in defs:
                if c not in memo:
                    memo[c] = evaluate(defs[c][1], env, memo)
                return memo[c]
            return env[c]
        return eval(pyexpr(t, val))

    def coef_in(t, u):
        """The constant coefficient of reified `u` in `t` (checked at two points)."""
        vals = set()
        for seed in (1, 2):
            rnd = random.Random(seed)
            env = {c: rnd.randrange(0, 3) for c in cols(t)}
            e1, e0 = dict(env), dict(env)
            e1[u], e0[u] = 1, 0
            vals.add(eval(pyexpr(t, lambda c: e1[c])) - eval(pyexpr(t, lambda c: e0[c])))
        assert len(vals) == 1, (u, vals)
        return vals.pop()

    def proof(i, h):
        """`e_i` minus the reified definitions it rests on, weighted so the reified columns cancel."""
        terms = [f"{h}{i}"]
        work = [(roots[i], 1)]
        while work:
            t, wgt = work.pop()
            for u in sorted(c for c in cols(t) if c in defs):
                g = wgt * coef_in(t, u)
                if g:
                    j, y = defs[u]
                    terms.append(f"({-g}) * {h}{j}")
                    work.append((y, g))
        return " + ".join(terms)

    def orient(i, canon):
        for _ in range(40):
            env = {c: random.randrange(0, 2) for c in rbase[i] | cols(canon)}
            a = evaluate(roots[i], env, {})
            b = eval(pyexpr(canon, lambda c: env[c]))
            if b:
                assert a in (b, -b), (i, a, b)
                return 1 if a == b else -1
        raise AssertionError(("orientation", i))

    def dag(i, h, eqs, target):
        """Equalities of every reified column under root `i`, children first, then `target`."""
        order, seen = [], set()

        def visit(u):
            if u in seen:
                return
            seen.add(u)
            for c in cols(defs[u][1]):
                if c in defs:
                    visit(c)
            order.append(u)
        for c in cols(roots[i]):
            if c in defs:
                visit(c)
        o = []
        for u in order:
            if u in eqs:
                continue
            j, y = defs[u]
            rw = [f"r{c}" if c in defs else f"e{c}" for c in sorted(cols(y)) if (c in defs or c in eqs)]
            o.append(f"  have r{u} : w.v{u} = w'.v{u} := by")
            o.append(f"    have h1 := c{j}")
            o.append(f"    have h2 := d{j}")
            if rw:
                o.append(f"    simp only [{', '.join(rw)}] at h1")
            o.append("    linear_combination h1 - h2")
            eqs.add(u)
        t = roots[i]
        rw = [f"r{c}" if c in defs else f"e{c}" for c in sorted(cols(t)) if c != target and (c in defs or c in eqs)]
        o.append(f"  have e{target} : w.v{target} = w'.v{target} := by")
        o.append(f"    have h1 := c{i}")
        o.append(f"    have h2 := d{i}")
        if rw:
            o.append(f"    simp only [{', '.join(rw)}] at h1")
        o.append(f"    linear_combination ({coef_in(t, target)}) * (h1 - h2)")
        eqs.add(target)
        return o

    bit = {}
    for i, c in cons.items():
        m = re.fullmatch(r'\(w\.v(\d+) \* \(w\.v(\d+) - \(1 : F\)\)\) = 0', c)
        if m and m.group(1) == m.group(2):
            bit[int(m.group(1))] = i
    by_col = {}
    for i, cs in rbase.items():
        for c in cs:
            by_col.setdefault(c, []).append(i)

    def find(pred, key):
        hits = [i for i in by_col.get(key, []) if pred(roots[i], rbase[i])]
        assert len(hits) == 1, (key, hits)
        return hits[0]
    ins = src[next(i for i, l in enumerate(src) if l.startswith('def inputs')) + 1]
    inputs = [int(x) for x in re.findall(r'w\.v(\d+)', ins)]
    FL = {FLAG(i) for i in range(NR)}
    i_sum = find(lambda t, cs: cs == FL and '*' not in t, FLAG(0))
    i_idx = find(lambda t, cs: cs - FL and cs >= FL - {FLAG(0)} and len(cs) == NR, FLAG(1))
    IDX = (rbase[i_idx] - FL).pop()
    assert IDX in inputs
    APSET = {AP(y, x, z) for y in range(5) for x in range(5) for z in range(64)}
    xor2 = lambda a, b: f"({a} + {b} - {a} * ({b} + {b}))"
    xor3 = lambda a, b, c: xor2(a, xor2(b, c))
    W = lambda c, w="w": f"{w}.v{c}"
    lemmas = [limb16_lemma(), onehot_lemma()]
    det = ["  %OPEN_HW%", "  %OPEN_HW'%",
           "  have hin' := hin",
           "  simp only [inputs, List.cons.injEq, and_true] at hin'"]
    det += proj([f"j{k}" for k in range(len(inputs))], "hin'", "jall")
    for y in range(5):
        for x in range(5):
            for l in range(4):
                det.append(f"  have i{A(y, x, l)} : w.v{A(y, x, l)} = w'.v{A(y, x, l)} := j{inputs.index(A(y, x, l))}")
    det.append(f"  have i{IDX} : w.v{IDX} = w'.v{IDX} := j{inputs.index(IDX)}")
    bitcols = [C(x, z) for x in range(5) for z in range(64)] + sorted(APSET) + [B00(z) for z in range(64)] + sorted(FL)
    for c in bitcols:
        det.append(f"  have b{c} := Keccak.bitF_of c{bit[c]}")
        det.append(f"  have b{c}' := Keccak.bitF_of d{bit[c]}")
    s_of = lambda y, x, z, w: f"(Keccak.xor3F {W(AP(y, x, z), w)} {W(C(x, z), w)} {W(CP(x, z), w)})"
    for x in range(5):
        for z in range(64):
            cp = CP(x, z)
            i = find(lambda t, cs, cp=cp: t.startswith(f"(w.v{cp} - ("), cp)
            args = (C(x, z), C((x + 4) % 5, z), C((x + 1) % 5, (z + 63) % 64))
            canon = f"(w.v{cp} - {xor3(*(W(a) for a in args))})"
            sg = orient(i, canon)
            for suf, w, h in (("", "w", "c"), ("'", "w'", "d")):
                det.append(f"  have k{cp}{suf} : {W(cp, w)} = Keccak.xor3F {' '.join(W(a, w) for a in args)} := by")
                det.append(f"    unfold Keccak.xor3F Keccak.xorF; linear_combination ({sg}) * ({proof(i, h)})")
                det.append(f"  have b{cp}{suf} : Keccak.bitF {W(cp, w)} := by")
                det.append(f"    rw [k{cp}{suf}]; exact Keccak.xor3F_bit {' '.join(f'b{a}{suf}' for a in args)}")
    for y in range(5):
        for x in range(5):
            for l in range(4):
                a = A(y, x, l)
                i = find(lambda t, cs: a in cs and AP(y, x, 16 * l) in cs, a)
                canon = f"(w.v{a} - (" + " + ".join(f"{2 ** k} * {xor3(W(AP(y, x, 16 * l + k)), W(C(x, 16 * l + k)), W(CP(x, 16 * l + k)))}" for k in range(16)) + "))"
                sg = orient(i, canon)
                for suf, w, h in (("", "w", "c"), ("'", "w'", "d")):
                    det.append(f"  have la{a}{suf} : {W(a, w)} = " + " + ".join(f"({2 ** k} : F) * {s_of(y, x, 16 * l + k, w)}" for k in range(16)) + " := by")
                    det.append(f"    unfold Keccak.xor3F Keccak.xorF; linear_combination ({sg}) * ({proof(i, h)})")
                bits = [f"(Keccak.xor3F_bit b{AP(y, x, 16 * l + k)} b{C(x, 16 * l + k)} b{CP(x, 16 * l + k)})" for k in range(16)]
                bitsp = [f"(Keccak.xor3F_bit b{AP(y, x, 16 * l + k)}' b{C(x, 16 * l + k)}' b{CP(x, 16 * l + k)}')" for k in range(16)]
                det += proj([f"s{AP(y, x, 16 * l + k)}" for k in range(16)],
                            f"limb16 {' '.join(bits)} {' '.join(bitsp)} ((la{a}.symm.trans i{a}).trans la{a}')", f"q{a}")
    for x in range(5):
        for z in range(64):
            first = AP(0, x, z)
            i = find(lambda t, cs, x=x, z=z: cs == {AP(y, x, z) for y in range(5)} | {CP(x, z)}, first)
            summ = " + ".join(W(AP(y, x, z)) for y in range(5))
            canon = f"(({summ} - w.v{CP(x, z)}) * ({summ} - w.v{CP(x, z)} - 2) * ({summ} - w.v{CP(x, z)} - 4))"
            sg = orient(i, canon)
            for suf, w, h in (("", "w", "c"), ("'", "w'", "d")):
                par = " ".join(f"(Keccak.xor3F {W(AP(y, x, z), w)} {W(C(x, z), w)} {W(CP(x, z), w)})" for y in range(5))
                det.append(f"  have p{C(x, z)}{suf} : {W(C(x, z), w)} = Keccak.par5 {par} := by")
                det.append(f"    exact Keccak.column_parity " + " ".join(f"b{AP(y, x, z)}{suf}" for y in range(5))
                           + f" b{C(x, z)}{suf} b{CP(x, z)}{suf} (by linear_combination ({sg}) * ({proof(i, h)}))")
            det.append(f"  have e{C(x, z)} : w.v{C(x, z)} = w'.v{C(x, z)} := by")
            det.append(f"    rw [p{C(x, z)}, p{C(x, z)}', " + ", ".join(f"s{AP(y, x, z)}" for y in range(5)) + "]")
    for x in range(5):
        for z in range(64):
            args = (C(x, z), C((x + 4) % 5, z), C((x + 1) % 5, (z + 63) % 64))
            det.append(f"  have e{CP(x, z)} : w.v{CP(x, z)} = w'.v{CP(x, z)} := by")
            det.append(f"    rw [k{CP(x, z)}, k{CP(x, z)}', {', '.join(f'e{a}' for a in args)}]")
    eqs = set()
    for y in range(5):
        for x in range(5):
            for z in range(64):
                ap = AP(y, x, z)
                det.append(f"  have e{ap} : w.v{ap} = w'.v{ap} := Keccak.xor3F_cancel b{ap} b{ap}' b{C(x, z)}' b{CP(x, z)}'")
                det.append(f"    (by have h := s{ap}; rw [e{C(x, z)}, e{CP(x, z)}] at h; exact h)")
                eqs.add(ap)
    for y in range(5):
        for x in range(5):
            for l in range(4):
                p = APP(y, x, l)
                i = find(lambda t, cs, p=p: p in cs and (cs - {p}) <= APSET and len(cs) > 1, p)
                det += dag(i, "c", eqs, p)
    for l in range(4):
        p = APP(0, 0, l)
        i = find(lambda t, cs, p=p: p in cs and B00(16 * l) in cs, p)
        canon = f"(w.v{p} - (" + " + ".join(f"{2 ** k} * w.v{B00(16 * l + k)}" for k in range(16)) + "))"
        sg = orient(i, canon)
        for suf, w, h in (("", "w", "c"), ("'", "w'", "d")):
            det.append(f"  have lb{p}{suf} : {W(p, w)} = " + " + ".join(f"({2 ** k} : F) * {W(B00(16 * l + k), w)}" for k in range(16)) + " := by")
            det.append(f"    linear_combination ({sg}) * ({proof(i, h)})")
        det += proj([f"e{B00(16 * l + k)}" for k in range(16)],
                    "limb16 " + " ".join(f"b{B00(16 * l + k)}" for k in range(16)) + " "
                    + " ".join(f"b{B00(16 * l + k)}'" for k in range(16)) + f" ((lb{p}.symm.trans e{p}).trans lb{p}')", f"q{p}")
        eqs |= {B00(16 * l + k) for k in range(16)}
    fs = [FLAG(i) for i in range(NR)]
    for suf, h in (("", "c"), ("'", "d")):
        w = "w" if not suf else "w'"
        det.append(f"  have fs{suf} : {' + '.join(W(f, w) for f in fs)} = 1 := by linear_combination ({orient(i_sum, '(' + ' + '.join(W(f) for f in fs) + ' - 1)')}) * ({proof(i_sum, h)})")
        det.append(f"  have fi{suf} : {' + '.join(f'({i} : F) * {W(fs[i], w)}' for i in range(NR))} = {W(IDX, w)} := by linear_combination ({orient(i_idx, '(' + ' + '.join(f'{i} * w.v{fs[i]}' for i in range(NR)) + f' - w.v{IDX})')}) * ({proof(i_idx, h)})")
    det.append(f"  rw [i{IDX}] at fi")
    det += proj([f"e{f}" for f in fs],
                f"onehot {' '.join(f'b{f}' for f in fs)} {' '.join(f'b{f}' + chr(39) for f in fs)} fs fi fs' fi'", "qflag")
    eqs |= set(fs)
    for l in range(4):
        p = APPP(l)
        i = find(lambda t, cs, p=p: p in cs, p)
        det += dag(i, "c", eqs, p)
    outs = []
    for y in range(5):
        for x in range(5):
            for l in range(4):
                outs.append(APPP(l) if (x, y) == (0, 0) else APP(y, x, l))
    det.append("  exact ⟨" + ", ".join(f"e{c}" for c in outs) + "⟩")
    typ = {}
    for i, t in cons.items():
        typ[f"c{i}"] = t
        typ[f"d{i}"] = re.sub(r"\bw\.v", "w'.v", t)
    for c in bitcols:
        typ[f"b{c}"] = f"Keccak.bitF w.v{c}"
        typ[f"b{c}'"] = f"Keccak.bitF w'.v{c}"
    for y in range(5):
        for x in range(5):
            for z in range(64):
                typ[f"s{AP(y, x, z)}"] = (f"Keccak.xor3F w.v{AP(y, x, z)} w.v{C(x, z)} w.v{CP(x, z)} = "
                                          f"Keccak.xor3F w'.v{AP(y, x, z)} w'.v{C(x, z)} w'.v{CP(x, z)}")
    for c in [B00(z) for z in range(64)] + fs:
        typ[f"e{c}"] = f"w.v{c} = w'.v{c}"
    lemmas += lift(det, typ)
    lemmas += segment(det, typ, " ∧ ".join(f"w.v{c} = w'.v{c}" for c in outs))
    out = ["section FieldOpGadget", "open ZirenDet", ""] + lemmas
    out.append("/-- The round's output limbs are determined by its input limbs and round index. -/")
    out.append("theorem gadget_det (w w' : W) (hw : constraints w) (hw' : constraints w')")
    out.append("    (hin : inputs w = inputs w') :")
    out.append("    " + " ∧ ".join(f"w.v{c} = w'.v{c}" for c in outs) + " := by")
    out += det
    out.append("")
    out.append("end FieldOpGadget")
    out.append("")
    open(outp, 'w').write("\n".join(out))
    print(dict(IDX=IDX, sum=i_sum, idx=i_idx, reified=len(defs), lines=len(out)), file=sys.stderr)


if __name__ == "__main__":
    main()

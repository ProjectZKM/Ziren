"""gen_u256.py MODULE_FILE OUT: the gadget proof of `Uint256MulMod`, as a snippet with the
generator's placeholders.

The chip multiplies modulo `P = m·(1 − z) + 2²⁵⁶·z`, where `z` is the is-zero flag of the modulus
bytes.  Its coefficient rows give `A·B − R − C·m = 0` over the integers when `z = 0` and
`A·B − R − C·2²⁵⁶ = 0` when `z = 1`; the less-than gadget, live when `z = 0`, gives `R < m`, and the
bytes give `R < 2²⁵⁶`.  `z` is a function of the modulus, so in either case `R` is the canonical
residue of `A·B` and its bytes are a function of the operands' bytes."""
import random, re, sys

HERE = __file__.rsplit('/', 1)[0]
sys.path.insert(0, HERE)
import gen_field as gf
from gated_lt import gated_lt
from gen_fpop import parse, reified_columns, pyexpr, resolve, toint
from mklemma import subst

KB = 2130706433
OFF = 16384
SIMP = ("Int.cast_zero, Int.cast_one, mul_zero, zero_mul, mul_one, one_mul, add_zero, sub_zero, "
        "zero_add, sub_self, zero_sub, neg_zero")


def main():
    path, outp = sys.argv[1], sys.argv[2]
    src, cons = parse(path)
    reified = reified_columns(src)
    n = 32
    (i_z0, inv, sumtext, Z), = [(i, int(m.group(1)), m.group(2), int(m.group(3))) for i, c in cons.items()
                                if (m := re.fullmatch(r'\(\(\(1 : F\) - \(w\.v(\d+) \* (\(.*\))\)\) - w\.v(\d+)\) = 0', c))]
    mod = [int(x) for x in re.findall(r'w\.v(\d+)', sumtext)]
    assert len(mod) == n
    i_z2 = next(i for i, c in cons.items() if c == f"(w.v{Z} * {sumtext}) = 0")
    i_zb = next(i for i, c in cons.items() if c == f"(w.v{Z} * (w.v{Z} - (1 : F))) = 0")
    (i_g, G), = [(i, int(m.group(1))) for i, c in cons.items()
                 if (m := re.fullmatch(rf'\(w\.v(\d+) - \(\(1 : F\) - w\.v{Z}\)\) = 0', c))]

    wpat = lambda c: f'({OFF} : F)) * (-256 : F)' in c or re.search(rf'- \(w\.v\d+ - \({OFF} : F\)\)\)+ = 0$', c)
    defs_of = {}
    for i, c in cons.items():
        m = re.fullmatch(r'\(w\.v(\d+) - (\(.*\))\) = 0', c)
        if m and int(m.group(1)) in reified:
            defs_of.setdefault(int(m.group(1)), []).append((i, m.group(2)))
    allrows = []

    def expand(row):
        text, proof, used = row
        while True:
            zs = sorted({int(x) for x in re.findall(r'w\.v(\d+)', text) if int(x) in reified})
            if not zs:
                return text, proof, used
            z = zs[0]
            other = [(j, d) for j, d in cons.items() if j not in used and re.search(rf'w\.v{z}\b', d)]
            assert len(other) == 1, (z, other)
            j, d = other[0]
            m = re.fullmatch(rf'\(w\.v{z} - \((.*)\)\) = 0', d)
            coef = eval(pyexpr(text, lambda c: 1 if c == z else 7)) - eval(pyexpr(text, lambda c: 0 if c == z else 7))
            text = re.sub(rf'w\.v{z}\b', lambda _: f"({m.group(1)})", text)
            proof += f" - ({coef}) * e{j}"
            used = used + [j]
    for i, c in cons.items():
        m = re.match(r'\(w\.v(\d+) - ', c)
        if m and int(m.group(1)) in reified:
            continue
        if wpat(c):
            allrows.append(resolve(cons, i, reified))
        elif (m := re.fullmatch(r'w\.v(\d+) = 0', c)) and int(m.group(1)) in reified and \
                any(wpat(f"{x} = 0") or 'w.v' in x for _, x in defs_of.get(int(m.group(1)), [])):
            t = resolve(cons, i, reified)
            if wpat(t[0] + " = 0") or re.search(rf'\({OFF} : F\)', t[0]):
                allrows.append(t)
    for v, ds in defs_of.items():
        if len(ds) == 2:
            (i1, x1), (i2, x2) = ds
            w1, w2 = bool(re.search(rf'\({OFF} : F\)', x1)), bool(re.search(rf'\({OFF} : F\)', x2))
            assert w1 != w2, (v, ds)
            (ip, xp), (iw, xw) = ((i2, x2), (i1, x1)) if w1 else ((i1, x1), (i2, x2))
            allrows.append(expand((f"({xp} - {xw})", f"e{iw} - e{ip}", [iw, ip])))
    key = lambda r: tuple(sorted(int(x) for x in re.findall(rf'w\.v(\d+) - \({OFF} : F\)', r[0])))
    wit = sorted({c for r in allrows for c in key(r)})
    rows = sorted(allrows, key=lambda r: 0 if key(r) == (wit[0],) else (min(key(r)) - wit[0] + 1))
    assert [len(key(r)) for r in rows] == [1] + [2] * (len(wit) - 1) + [1], [key(r) for r in rows]
    m0 = re.match(r'\(+w\.v(\d+) \* w\.v(\d+)\) - w\.v(\d+)\) - \(w\.v(\d+) \* \(w\.v(\d+) \*', rows[0][0])
    a0, b0, r0, c0, mm0 = (int(m0.group(k)) for k in range(1, 6))
    assert mm0 == mod[0]
    words = sorted(((int(m.group(1)), [int(x) for x in re.findall(r'w\.v(\d+)', l)])
                    for l in src if (m := re.match(r'def in_mem_read_(\d+)_val ', l))))
    flat = [c for _, w in words for c in w]
    wflat = [c for l in src if (m := re.match(r'def (?:in|out)_mem_\w+_val ', l)) for c in re.findall(r'w\.v(\d+)', l)]

    def vector(c):
        for fl in (flat, [int(x) for x in wflat]):
            if c in fl:
                return fl[fl.index(c):fl.index(c) + n]
        return list(range(c, c + n))
    A, B, R, C = vector(a0), vector(b0), list(range(r0, r0 + n)), list(range(c0, c0 + n))
    assert vector(mod[0]) == mod, (vector(mod[0]), mod)

    def bound_of(c, bound):
        for i, t in cons.items():
            if t == f"(w.v{c}).val ≤ {bound}":
                return f"c{i}"
        if bound == 1:
            for i, t in cons.items():
                if t == f"(w.v{c} * (w.v{c} - (1 : F))) = 0":
                    return f"(ZirenDet.bit_val_le c{i})"
            for i, t in cons.items():
                if t == f"(w.v{G} * (w.v{c} * (w.v{c} - (1 : F)))) = 0":
                    return f"(ZirenDet.bit_val_le (by have e := c{i}; rw [hg, one_mul] at e; exact e))"
        if c == G and bound == 1:
            return "(by rw [hg, ZMod.val_one])"
        if bound == KB - 1:
            return f"(Nat.le_of_lt_succ (ZMod.val_lt w.v{c}))"
        raise AssertionError((c, bound))

    L = {}
    for v in (A, B, R, C, mod):
        for c in v:
            L[c] = (f'n{c}', 255)
    for c in wit:
        L[c] = (f'n{c}', 65535)
    L[Z] = (f'n{Z}', 1)
    L[G] = (f'n{G}', 1)
    P = lambda v: "(" + " + ".join(f"{256 ** i} * n{c}" for i, c in enumerate(v)) + ")"
    PV = lambda v, w: "(" + " + ".join(f"{256 ** i} * (({w}.v{c}.val : ℕ) : ℤ)" for i, c in enumerate(v)) + ")"

    sg = []
    for i, (text, _, _) in enumerate(rows):
        wc = wit[i] if i < len(wit) else wit[i - 1]
        e0 = {c: 7 for c in range(0, 5000)}
        e1 = dict(e0)
        e1[wc] += 1
        d = eval(pyexpr(text, lambda c: e1[c])) - eval(pyexpr(text, lambda c: e0[c]))
        coef = 256 if i < len(wit) else -1
        assert d in (coef, -coef), (i, d)
        sg.append(1 if d == coef else -1)
    val = lambda v, env: sum(env[c] * 256 ** i for i, c in enumerate(v))
    for zv in (0, 1):
        for _ in range(3):
            env = {c: random.randrange(0, b + 1) for c, (_, b) in L.items()}
            env[Z], env[G] = zv, 1 - zv
            T = sum(sg[i] * 256 ** i * eval(pyexpr(t, lambda c: env[c])) for i, (t, _, _) in enumerate(rows))
            Pm = val(mod, env) if zv == 0 else 2 ** 256
            assert T == val(A, env) * val(B, env) - val(R, env) - val(C, env) * Pm, (zv, 'rows do not telescope')

    lemmas, apps = [], {}
    for zv in (0, 1):
        pz = 900000 + zv
        cons[pz] = f"w.v{Z} = {zv}" if zv == 0 else f"w.v{Z} = (1 : F)"
        o = [f"  have pz : n{Z} = {zv} := by",
             f"    have e := e{pz}",
             f"    clear * - e hn{Z}",
             "    divrem_lift; omega"]
        for i, (text, proof, _) in enumerate(rows):
            f = subst(text, L)
            keep = " ".join(f"h{L[int(c)][0]}" for c in dict.fromkeys(re.findall(r'w\.v(\d+)', text)) if int(c) in L)
            o.append(f"  have H{i} : {toint(f)} = 0 := by")
            o.append(f"    have r : {f} = 0 := by")
            o.append(f"      linear_combination {proof}")
            o.append(f"    clear * - r pz {keep}")
            o.append("    subst_vars")
            o.append(f"    (try simp only [{SIMP}] at r ⊢)")
            o.append("    fieldop_row r")
        o.append(f"  clear * - pz {' '.join(f'H{i}' for i in range(len(rows)))}")
        o.append("  subst_vars")
        o.append("  linear_combination " + " + ".join(f"({sg[i] * 256 ** i}) * H{i}" for i in range(len(rows))))
        Pm = P(mod) if zv == 0 else str(2 ** 256)
        goal = f"{P(A)} * {P(B)} - {P(R)} - {P(C)} * {Pm} = 0"
        used = sorted({i for r in rows for i in r[2]} | {pz})
        text, app = gf.build_raw(cons, used, L, goal, f"mulmod_z{zv}", "\n".join(o), bound_of)
        lemmas.append(text)
        apps[zv] = app.replace(f"c{pz}", "hz")

    text, app = gated_lt(cons, reified, L, G, R, mod, "mulmod_lt", "hg", 900002, bound_of)
    lemmas.append(text)
    apps['lt'] = app

    Sw = sumtext
    conj = [f"(w.v{Z} = 0 ∨ w.v{Z} = 1)",
            f"({Sw} = 0 → w.v{Z} = 1)",
            f"({Sw} ≠ 0 → w.v{Z} = 0)",
            f"(w.v{Z} = 0 → {PV(A, 'w')} * {PV(B, 'w')} - {PV(R, 'w')} - {PV(C, 'w')} * {PV(mod, 'w')} = 0 ∧ {PV(R, 'w')} < {PV(mod, 'w')})",
            f"(w.v{Z} = 1 → {PV(A, 'w')} * {PV(B, 'w')} - {PV(R, 'w')} - {PV(C, 'w')} * {2 ** 256} = 0)"]
    proof = ["  %OPEN_HW%", "  refine ⟨" + ", ".join("?_" for _ in conj) + "⟩",
             f"  · exact ZirenDet.bit_cases c{i_zb}",
             "  · intro hS",
             f"    have e := c{i_z0}",
             "    rw [hS] at e",
             "    linear_combination -e",
             "  · intro hS",
             f"    exact (mul_eq_zero.mp c{i_z2}).resolve_right hS",
             "  · intro hz",
             f"    have hg : w.v{G} = 1 := by",
             f"      have e := c{i_g}",
             "      rw [hz] at e",
             "      linear_combination e",
             f"    exact ⟨{apps[0]}, {apps['lt']}⟩",
             "  · intro hz",
             f"    exact {apps[1]}"]
    W1 = "w'"
    ins = src[next(i for i, l in enumerate(src) if l.startswith('def inputs')) + 1]
    inputs = [int(x) for x in re.findall(r'w\.v(\d+)', ins)]
    incols = sorted(set(A + B + mod))
    assert set(incols) <= set(inputs)
    det = ["  obtain ⟨hzb, hS1, hS0, h0, h1⟩ := row_spec w hw",
           "  obtain ⟨hzb', hS1', hS0', h0', h1'⟩ := row_spec w' hw'",
           f"  obtain ⟨{', '.join(f'a{c}' for c in R)}⟩ := row_ranges w hw",
           f"  obtain ⟨{', '.join(f'a{c}' + chr(39) for c in R)}⟩ := row_ranges w' hw'",
           "  have hin' := hin",
           "  simp only [inputs, List.cons.injEq, and_true] at hin'",
           f"  obtain ⟨{', '.join(f'j{k}' for k in range(len(inputs)))}⟩ := hin'"]
    for c in incols:
        det.append(f"  have i{c} : w.v{c} = w'.v{c} := j{inputs.index(c)}")
    det.append(f"  simp only [{', '.join(f'i{c}' for c in incols)}] at hS1 hS0 h0 h1")
    for suf, w in (("", "w"), ("'", W1)):
        det.append(f"  have hr{suf} : ∀ x ∈ [{', '.join(f'(({w}.v{c}.val : ℕ) : ℤ)' for c in R)}], 0 ≤ x ∧ x ≤ 255 := by")
        det.append("    intro x hx")
        det.append("    simp only [List.mem_cons, List.mem_nil_iff, or_false] at hx")
        det.append(f"    rcases hx with {' | '.join('rfl' for _ in R)} <;>")
        det.append("      exact ZirenDet.FieldOp.byte_range (by assumption)")
    X = f"({PV(A, W1)} * {PV(B, W1)})"
    det.append(f"  have hR : {PV(R, 'w')} = {PV(R, W1)} := by")
    det.append(f"    by_cases hS : {re.sub(r'w[.]v', W1 + '.v', Sw)} = 0")
    det.append("    · have e := h1 (hS1 hS)")
    det.append("      have e' := h1' (hS1' hS)")
    det.append(f"      exact ZirenDet.FieldOp.residue_unique (M := {2 ** 256}) (X := {X}) (by positivity) (by omega)")
    det.append("        (by positivity) (by omega)")
    det.append(f"        (Int.modEq_iff_dvd.mpr ⟨{PV(C, 'w')}, by linear_combination e⟩)")
    det.append(f"        (Int.modEq_iff_dvd.mpr ⟨{PV(C, W1)}, by linear_combination e'⟩)")
    det.append("    · obtain ⟨e, hl⟩ := h0 (hS0 hS)")
    det.append("      obtain ⟨e', hl'⟩ := h0' (hS0' hS)")
    det.append(f"      exact ZirenDet.FieldOp.residue_unique (M := {PV(mod, W1)}) (X := {X}) (by positivity) hl")
    det.append("        (by positivity) hl'")
    det.append(f"        (Int.modEq_iff_dvd.mpr ⟨{PV(C, 'w')}, by linear_combination e⟩)")
    det.append(f"        (Int.modEq_iff_dvd.mpr ⟨{PV(C, W1)}, by linear_combination e'⟩)")
    det.append("  have hl := ZirenDet.FieldOp.ev_inj _ _ (by simp only [List.length_cons, List.length_nil]) hr hr'")
    det.append("    (by simp only [ZirenDet.FieldOp.ev]; linear_combination hR)")
    det.append("  simp only [List.cons.injEq, and_true] at hl")
    det.append(f"  obtain ⟨{', '.join(f'e{c}' for c in R)}⟩ := hl")
    det.append(f"  exact ⟨{', '.join(f'ZMod.val_injective _ (by exact_mod_cast e{c})' for c in R)}⟩")
    out = ["section FieldOpGadget", "open ZirenDet", ""] + lemmas
    out.append("/-- The is-zero flag of the modulus, and the two product identities with the less-than check. -/")
    out.append("theorem row_spec (w : W) (hw : constraints w) :")
    out.append("    " + " ∧\n    ".join(conj) + " := by")
    out += proof
    out.append("")
    out.append("/-- The byte ranges of the result. -/")
    out.append("theorem row_ranges (w : W) (hw : constraints w) :")
    out.append("    " + " ∧ ".join(f"w.v{c}.val ≤ 255" for c in R) + " := by")
    out.append("  %OPEN_HW%")
    out.append(f"  exact ⟨{', '.join(bound_of(c, 255) for c in R)}⟩")
    out.append("")
    out.append("/-- The result's bytes are determined by the row's inputs. -/")
    out.append("theorem gadget_det (w w' : W) (hw : constraints w) (hw' : constraints w')")
    out.append("    (hin : inputs w = inputs w') :")
    out.append("    " + " ∧ ".join(f"w.v{c} = w'.v{c}" for c in R) + " := by")
    out += det
    out.append("")
    out.append("end FieldOpGadget")
    out.append("")
    open(outp, 'w').write("\n".join(out))
    print(dict(Z=Z, G=G, A=A[:2], B=B[:2], R=R[:2], C=C[:2], mod=mod[:2], rows=len(rows)), file=sys.stderr)


if __name__ == "__main__":
    main()

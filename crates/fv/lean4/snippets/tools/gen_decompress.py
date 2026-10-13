"""gen_decompress.py MODULE_FILE PRIME OUT: the gadget proof of a Weierstrass decompress chip with the
least-significant-bit sign rule, as a snippet with the generator's placeholders.

The field operations give `c ≡ x³ + a·x + b` and `y² ≡ c (mod p)`, the negation gives `n + y ≡ 0`,
the range checks give `y, n < p`, the lookup `y₀ AND 1` gives the parity bit `l` of `y`, and the
written word is `y` when `l` equals the sign bit and `n` otherwise.  Two square roots of one value
modulo the prime `p` are equal or sum to `p` (`sqrt_pair`), and `p` is odd, so both witnesses write
the same word.  `PRIME` names the theorem in `ZirenDet.Primes` that proves `p` prime."""
import re, sys

HERE = __file__.rsplit('/', 1)[0]
field_src = open(f"{HERE}/gen_field.py").read()
head = field_src.split("    # ---- the chip-level statements\n")[0]
prep = head.replace("def main():", "def prepare():") + "    return locals()\n"
ns = {"__name__": "gen_field_prep", "__file__": f"{HERE}/gen_field.py"}
sys.path.insert(0, HERE)
exec(compile(prep, "gen_field_prep", "exec"), ns)


def main():
    path, prime, outp = sys.argv[1], sys.argv[2], sys.argv[3]
    sys.argv = [sys.argv[0], path, "/dev/null"]
    ctx = ns["prepare"]()
    cons, src, L, ops, gadgets = ctx["cons"], ctx["src"], ctx["L"], ctx["ops"], ctx["gadgets"]
    apps, lemmas, pins, free, inputs = ctx["apps"], ctx["lemmas"], ctx["pins"], ctx["free"], ctx["inputs"]
    bound_of, n, M = ctx["bound_of"], ctx["n"], ctx["M"]
    subst = ns["subst"]
    inset = set(inputs)
    for op in ops:
        op['res'] = op['carry'][0] - n
    vec_of = {}
    for op in ops:
        vec_of.update(op['vecs'])
    sq = [op for op in ops if (op['res'], op['res']) in op['p0']]
    assert len(sq) == 1
    sq = sq[0]
    Y = sq['res']
    C = next(m[0] for m in sq['p0'] if len(m) == 1)
    neg = [op for op in ops if op is not sq and Y in op['vecs'] and len(op['vecs']) == 2
           and all(len(m) <= 1 for m in op['p0'])]
    assert len(neg) == 1
    neg = neg[0]
    N = neg['res']
    chain = [op for op in ops if op is not sq and op is not neg]
    gY = next(g for g in gadgets if g['r'][0] == Y)
    gN = next(g for g in gadgets if g['r'][0] == N)
    Yv, Nv = vec_of[Y], vec_of[N]
    and_row = next((i, int(m.group(1)), int(m.group(2))) for i, c in cons.items()
                   if (m := re.fullmatch(rf'\(w\.v{Yv[0]} - \(\(w\.v(\d+) \* \(2 : F\)\) \+ w\.v(\d+)\)\) = 0', c)))
    i_and, H, Lb = and_row
    sel_y, sel_n = {}, {}
    for i, c in cons.items():
        m = re.fullmatch(rf'\(\(w\.v{Lb} - \(\(1 : F\) - w\.v(\d+)\)\) \* \(w\.v(\d+) - w\.v(\d+)\)\) = 0', c)
        if m:
            sel_y[int(m.group(2))] = (i, int(m.group(3)), int(m.group(1)))
        m = re.fullmatch(rf'\(\(w\.v{Lb} - w\.v(\d+)\) \* \(w\.v(\d+) - w\.v(\d+)\)\) = 0', c)
        if m:
            sel_n[int(m.group(2))] = (i, int(m.group(3)), int(m.group(1)))
    assert sorted(sel_y) == sorted(Yv) and sorted(sel_n) == sorted(Nv)
    Sb = sel_y[Yv[0]][2]
    assert Sb in inset
    Ov = [sel_y[c][1] for c in Yv]
    assert Ov == [sel_n[c][1] for c in Nv]
    bit = lambda c: next(i for i, t in cons.items() if t == f"(w.v{c} * (w.v{c} - (1 : F))) = 0")
    ZM = f"ZMod {M}"
    V = lambda c, w: f"(({w}.v{c}.val : ℕ) : ℤ)"
    EV = lambda v, w: "(ZirenDet.FieldOp.ev [" + ", ".join(V(c, w) for c in v) + "])"
    PS = lambda v, w: " + ".join(f"{256 ** i} * {V(c, w)}" for i, c in enumerate(v))
    CAST = lambda v, w: f"(({EV(v, w)} : ℤ) : {ZM})"

    def F_text(op, w):
        def mono(m, c):
            return f"({op['s0'] * c}) * " + " * ".join(EV(op['vecs'][x], w) for x in m)
        return " + ".join([mono(m, c) for m, c in op['p0'].items() if m] + ([f"({op['const']})"] if op['const'] else []))

    assert all(not op['sel'] for op in ops), "selectors in a decompress operation"
    nf = len(ops)
    conj = [f"((({F_text(op, 'w')} : ℤ)) : {ZM}) = 0" for op in ops]
    conj += [f"{EV(g['r'], 'w')} < {M}" for g in gadgets]
    conj.append(f"{EV(Yv, 'w')} % 2 = {V(Lb, 'w')}")
    conj.append(f"({V(Lb, 'w')} = 0 ∨ {V(Lb, 'w')} = 1)")
    conj.append(f"({V(Sb, 'w')} = 0 ∨ {V(Sb, 'w')} = 1)")
    conj.append(f"({V(Lb, 'w')} = {V(Sb, 'w')} → " + " ∧ ".join(f"w.v{o} = w.v{y}" for o, y in zip(Ov, Yv)) + ")")
    conj.append(f"({V(Lb, 'w')} ≠ {V(Sb, 'w')} → " + " ∧ ".join(f"w.v{o} = w.v{x}" for o, x in zip(Ov, Nv)) + ")")
    proof = ["  %OPEN_HW%"]
    for k, app in enumerate(apps):
        proof.append(f"  have h{k} := {app}")
    for k, g in enumerate(gadgets):
        proof.append(f"  have l{k} := {g['app']}")
    used = {}
    for op in ops:
        used.update(op['vecs'])
    for g in gadgets:
        used[g['r'][0]] = g['r']
    for x, v in used.items():
        proof.append(f"  have ev{x} : {EV(v, 'w')} = {PS(v, 'w')} := by")
        proof.append("    simp only [ZirenDet.FieldOp.ev]; ring")
    proof.append(f"  rw [{', '.join(f'ev{x}' for x in used)}]")
    proof.append("  refine ⟨" + ", ".join("?_" for _ in conj) + "⟩")
    for k, op in enumerate(ops):
        proof.append(f"  · exact ZirenDet.FieldOp.cast_eq_zero_of_eq_mul (K := {PS(op['carry'], 'w')})")
        proof.append(f"      (by push_cast; linear_combination h{k})")
    for k, g in enumerate(gadgets):
        proof.append(f"  · exact l{k}")
    ib, iL, iS = bit(Lb), bit(Lb), bit(Sb)
    proof.append("  · have hb := ZirenDet.FieldOp.byte_range (" + bound_of(Yv[0], 255) + ")")
    proof.append(f"    have hh : ((w.v{H}.val : ℕ) : ℤ) ≤ 127 := by exact_mod_cast c{i_and - 1 if cons[i_and - 1] == f'(w.v{H}).val ≤ 127' else next(i for i, t in cons.items() if t == f'(w.v{H}).val ≤ 127')}")
    proof.append(f"    have hl := ZirenDet.bit_val_le c{iL}")
    proof.append(f"    obtain ⟨y0, hy0a, hy0b, ey0⟩ := ZirenDet.lift_le w.v{Yv[0]} ({bound_of(Yv[0], 255)})")
    proof.append(f"    obtain ⟨hv, hva, hvb, ehv⟩ := ZirenDet.lift_le w.v{H} (by exact_mod_cast hh)")
    proof.append(f"    obtain ⟨lv, hla, hlb, elv⟩ := ZirenDet.lift_le w.v{Lb} hl")
    proof.append(f"    have e := c{i_and}")
    proof.append("    rw [ey0, ehv, elv] at e")
    proof.append("    have e' : ((y0 : ℤ) : F) = ((hv * 2 + lv : ℤ) : F) := by push_cast; linear_combination e")
    proof.append("    have hy : y0 = hv * 2 + lv := ZirenDet.Gadgets.cast_inj_small e' (by rw [abs_lt]; constructor <;> omega) (by rw [abs_lt]; constructor <;> omega)")
    proof.append(f"    rw [ey0, elv, ZirenDet.val_cast, ZirenDet.val_cast]")
    rest = " + ".join(f"{256 ** i} * {V(c, 'w')}" for i, c in enumerate(Yv) if i > 0)
    proof.append(f"    have hy0 : (y0 % 2130706433).toNat = y0 := by omega")
    proof.append(f"    have hl0 : (lv % 2130706433).toNat = lv := by omega")
    proof.append(f"    rw [hy0, hl0]")
    proof.append("    omega")
    proof.append(f"  · exact ZirenDet.FieldOp.bit_cases (ZirenDet.bit_val_le c{iL})")
    proof.append(f"  · exact ZirenDet.FieldOp.bit_cases (ZirenDet.bit_val_le c{iS})")

    def sel_case(which):
        rows = sel_y if which == 'y' else sel_n
        vec = Yv if which == 'y' else Nv
        out = ["  · intro hsel"]
        if which == 'y':
            out.append(f"    have hLS : w.v{Lb} = w.v{Sb} := ZirenDet.FieldOp.eq_of_val_cast hsel")
            out.append("    exact ⟨" + ", ".join(f"ZirenDet.FieldOp.sel_same c{iL} hLS c{rows[c][0]}" for c in vec) + "⟩")
        else:
            out.append(f"    have hLS : w.v{Lb} ≠ w.v{Sb} := fun h => hsel (by rw [h])")
            out.append("    exact ⟨" + ", ".join(f"ZirenDet.FieldOp.sel_diff hLS c{rows[c][0]}" for c in vec) + "⟩")
        return out
    proof += sel_case('y')
    proof += sel_case('n')
    lemma_text = "\n".join(lemmas)
    rng = lambda cols: [bound_of(c, 255) for c in cols]
    out = ["section FieldOpGadget", "open ZirenDet", "", lemma_text]
    out.append("/-- The operations modulo the prime, the range checks, the parity bit and the selection. -/")
    out.append("theorem row_spec (w : W) (hw : constraints w) :")
    out.append("    " + " ∧\n    ".join(conj) + " := by")
    out += proof
    out.append("")
    out.append("/-- The byte ranges of the root and its negation. -/")
    out.append("theorem row_ranges (w : W) (hw : constraints w) :")
    out.append("    " + " ∧ ".join(f"w.v{c}.val ≤ 255" for c in Yv + Nv) + " := by")
    out.append("  %OPEN_HW%")
    out.append(f"  exact ⟨{', '.join(rng(Yv + Nv))}⟩")
    out.append("")
    i0 = next(i for i, l in enumerate(src) if l.startswith('def inputs'))
    pos = lambda c: inputs.index(c)
    W1 = "w'"
    side = lambda x, w: W1 if set(vec_of[x]) <= inset else w
    CASTX = lambda x, w: CAST(vec_of[x], side(x, w))
    fnames = [f"f{k}" for k in range(nf)]
    lnames = [f"l{k}" for k in range(len(gadgets))]
    pat = lambda suf: "⟨" + ", ".join([x + suf for x in fnames + lnames]
                                      + [f"hpar{suf}", f"hL{suf}", f"hS{suf}", f"hsy{suf}", f"hsn{suf}"]) + "⟩"
    det = []
    det.append(f"  obtain {pat('')} := row_spec w hw")
    det.append(f"  obtain {pat(chr(39))} := row_spec w' hw'")
    rv = Yv + Nv
    det.append(f"  obtain ⟨{', '.join(f'a{c}' for c in rv)}⟩ := row_ranges w hw")
    det.append(f"  obtain ⟨{', '.join(f'a{c}' + chr(39) for c in rv)}⟩ := row_ranges w' hw'")
    det.append("  have hin' := hin")
    det.append("  simp only [inputs, List.cons.injEq, and_true] at hin'")
    det.append(f"  obtain ⟨{', '.join(f'j{k}' for k in range(len(inputs)))}⟩ := hin'")
    incols = sorted({c for op in ops for v in op['vecs'].values() for c in v if c in inset} | {Sb})
    for c in incols:
        det.append(f"  have i{c} : w.v{c} = w'.v{c} := j{pos(c)}")
    det.append(f"  simp only [{', '.join(f'i{c}' for c in incols)}] at {' '.join(fnames)} hS hsy hsn")
    det.append(f"  push_cast at {' '.join(fnames)} {' '.join(x + chr(39) for x in fnames)}")
    eq_of = {}
    idx = {id(op): k for k, op in enumerate(ops)}
    done = set()
    todo = list(chain)
    while todo:
        op = next(o for o in todo if all(x == o['res'] or set(v) <= inset or x in done for x, v in o['vecs'].items()))
        todo.remove(op)
        k = idx[id(op)]
        res = op['res']
        poly = {}
        for m, c in op['p0'].items():
            if m:
                poly[m] = poly.get(m, 0) + op['s0'] * c
        if op['const']:
            poly[()] = op['const']
        cr = poly.pop((res,))
        assert cr in (1, -1) and all(res not in m for m in poly), (k, poly)
        def expr(w, poly=poly, cr=cr):
            ts = []
            for m, c in poly.items():
                fs = [CASTX(x, w) for x in m]
                ts.append(f"({-cr * c}) * " + " * ".join(fs) if fs else f"({-cr * c})")
            return " + ".join(ts) if ts else "0"
        det.append(f"  have r{k} : {CASTX(res, 'w')} = {expr('w')} := by linear_combination ({cr}) * f{k}")
        det.append(f"  have r{k}' : {CASTX(res, W1)} = {expr(W1)} := by linear_combination ({cr}) * f{k}'")
        prev = list(dict.fromkeys(eq_of[x] for m in poly for x in m if x in eq_of))
        det.append(f"  have q{k} : {CASTX(res, 'w')} = {CASTX(res, W1)} := by")
        det.append(f"    rw [r{k}, r{k}'" + "".join(f", {q}" for q in prev) + "]")
        eq_of[res] = f"q{k}"
        done.add(res)
    ks = idx[id(sq)]
    a = sq['s0'] * sq['p0'][(Y, Y)]
    b = sq['s0'] * sq['p0'][(C,)]
    qC = f" - ({a * b}) * {eq_of[C]}" if C in eq_of else ""
    det.append(f"  have hsq : {CAST(Yv, 'w')} ^ 2 = {CAST(Yv, W1)} ^ 2 := by")
    det.append(f"    linear_combination ({a}) * (f{ks} - f{ks}'){qC}")
    det.append(f"  have hmod : {EV(Yv, 'w')} ^ 2 ≡ {EV(Yv, W1)} ^ 2 [ZMOD (({M} : ℕ) : ℤ)] :=")
    det.append("    (ZMod.intCast_eq_intCast_iff _ _ _).mp (by push_cast; exact hsq)")
    rgs = lambda v, w, suf: f"(∀ x ∈ [{', '.join(V(c, w) for c in v)}], 0 ≤ x ∧ x ≤ 255)"
    for nm, v in (("Y", Yv), ("N", Nv)):
        for suf, w in (("", "w"), ("'", W1)):
            det.append(f"  have hr{nm}{suf} : {rgs(v, w, suf)} := by")
            det.append("    intro x hx")
            det.append("    simp only [List.mem_cons, List.mem_nil_iff, or_false] at hx")
            det.append(f"    rcases hx with {' | '.join('rfl' for _ in v)} <;>")
            det.append("      exact ZirenDet.FieldOp.byte_range (by assumption)")
            det.append(f"  have hn{nm}{suf} := ZirenDet.FieldOp.ev_nonneg _ hr{nm}{suf}")
    kY, kN = gadgets.index(gY), gadgets.index(gN)
    det.append(f"  have hp : Prime ((({M} : ℕ) : ℤ)) := Nat.prime_iff_prime_int.mp ZirenDet.Primes.{prime}")
    det.append(f"  have hpair := ZirenDet.Gadgets.sqrt_pair hp hnY (by push_cast; exact l{kY}) hnY' (by push_cast; exact l{kY}') hmod")
    det.append("  push_cast at hpair")
    kn = idx[id(neg)]
    for suf, w in (("", "w"), ("'", W1)):
        det.append(f"  obtain ⟨kn{suf}, hkn{suf}⟩ := (ZMod.intCast_zmod_eq_zero_iff_dvd ({EV(Nv, w)} + {EV(Yv, w)}) {M}).mp")
        det.append(f"    (by push_cast; linear_combination f{kn}{suf})")
    det.append("  push_cast at hkn hkn'")
    det.append(f"  have hS2 : {V(Sb, 'w')} = {V(Sb, W1)} := by rw [i{Sb}]")
    facts = "hpair hkn hkn' hnY hnY' hnN hnN' hpar hpar' hL hL' hS hS' l{0} l{0}' l{1} l{1}'".format(kY, kN)
    goal = " ∧ ".join(f"w.v{o} = w'.v{o}" for o in Ov)
    det.append(f"  by_cases e1 : {V(Lb, 'w')} = {V(Sb, W1)} <;> by_cases e2 : {V(Lb, W1)} = {V(Sb, W1)}")
    combos = [("Y", "Y", "hsy e1", "hsy' e2"), ("Y", "N", "hsy e1", "hsn' e2"),
              ("N", "Y", "hsn e1", "hsy' e2"), ("N", "N", "hsn e1", "hsn' e2")]
    for A, B, sa, sb in combos:
        va, vb = (Yv if A == "Y" else Nv), (Yv if B == "Y" else Nv)
        det.append("  · have hv : " + f"{EV(va, 'w')} = {EV(vb, W1)} := by omega")
        det.append(f"    have hl := ZirenDet.FieldOp.ev_inj _ _ (by simp only [List.length_cons, List.length_nil]) hr{A} hr{B}' hv")
        det.append("    simp only [List.cons.injEq, and_true] at hl")
        det.append(f"    obtain ⟨{', '.join(f'z{i}' for i in range(len(Ov)))}⟩ := hl")
        det.append(f"    obtain ⟨{', '.join(f'o{i}' for i in range(len(Ov)))}⟩ := {sa}")
        det.append(f"    obtain ⟨{', '.join(f'o{i}' + chr(39) for i in range(len(Ov)))}⟩ := {sb}")
        det.append("    exact ⟨" + ", ".join(
            f"by rw [o{i}, o{i}']; exact ZMod.val_injective _ (by exact_mod_cast z{i})" for i in range(len(Ov))) + "⟩")
    out.append("/-- The written word is determined by the row's inputs. -/")
    out.append("theorem gadget_det (w w' : W) (hw : constraints w) (hw' : constraints w')")
    out.append("    (hin : inputs w = inputs w') :")
    out.append(f"    {goal} := by")
    out += det
    out.append("")
    out.append("end FieldOpGadget")
    open(outp, 'w').write("\n".join(out) + "\n")
    import json
    print(json.dumps(dict(n=n, Y=Y, N=N, C=C, L=Lb, S=Sb, H=H, O=Ov[:3], chain=[op['res'] for op in chain])), file=sys.stderr)


main()

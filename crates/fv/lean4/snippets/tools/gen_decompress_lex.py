"""gen_decompress_lex.py MODULE_FILE PRIME OUT: the gadget proof of a Weierstrass decompress chip
with the lexicographic sign rule (BLS12-381), as a snippet with the generator's placeholders.

The field operations give `c ≡ x³ + a·x + b` and `y² ≡ c (mod p)`, the negation gives `n + y ≡ 0`,
the range checks give `y, n < p`, and the two gated less-than checks give `y < n` under `A` and
`n < y` under `B`, with `A + B = 1`; the choice bit `E` is `B` when the sign bit is set and `A`
otherwise, and the written word is `y` when `E` is set and `n` otherwise.  Two square roots of one
value modulo the prime `p` are equal or sum to `p` (`sqrt_pair`); when they sum to `p` the pair
`(y, n)` of one witness is the pair `(n, y)` of the other, `A` and `B` swap, and both witnesses
write the same word."""
import re, sys

HERE = __file__.rsplit('/', 1)[0]
field_src = open(f"{HERE}/gen_field.py").read()
head = field_src.split("    # ---- the chip-level statements\n")[0]
prep = head.replace("def main():", "def prepare():") + "    return locals()\n"
ns = {"__name__": "gen_field_prep", "__file__": f"{HERE}/gen_field.py"}
sys.path.insert(0, HERE)
from gated_lt import gated_lt
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
    sel_y, sel_n = {}, {}
    for i, c in cons.items():
        m = re.fullmatch(r'\(w\.v(\d+) \* \(w\.v(\d+) - w\.v(\d+)\)\) = 0', c)
        if m and int(m.group(2)) in Yv:
            sel_y[int(m.group(2))] = (i, int(m.group(3)), int(m.group(1)))
        m = re.fullmatch(r'\(\(w\.v(\d+) - \(1 : F\)\) \* \(w\.v(\d+) - w\.v(\d+)\)\) = 0', c)
        if m and int(m.group(2)) in Nv:
            sel_n[int(m.group(2))] = (i, int(m.group(3)), int(m.group(1)))
    assert sorted(sel_y) == sorted(Yv) and sorted(sel_n) == sorted(Nv), (sorted(sel_y), sorted(sel_n))
    Eb = sel_y[Yv[0]][2]
    assert all(v[2] == Eb for v in list(sel_y.values()) + list(sel_n.values()))
    Ov = [sel_y[c][1] for c in Yv]
    assert Ov == [sel_n[c][1] for c in Nv]
    (i_ab, Ab, Bb), = [(i, int(m.group(1)), int(m.group(2))) for i, c in cons.items()
                       if (m := re.fullmatch(r'\(\(w\.v(\d+) \+ w\.v(\d+)\) - \(1 : F\)\) = 0', c))]
    ltA = [i for i, c in cons.items() if re.fullmatch(rf'\(w\.v{Ab} \* \(\(.*\) \* \(w\.v{Yv[-1]} - w\.v{Nv[-1]}\)\)\) = 0', c)]
    if not ltA:
        Ab, Bb = Bb, Ab
    (i_sb, Sb), = [(i, int(m.group(1))) for i, c in cons.items()
                   if (m := re.fullmatch(rf'\(w\.v(\d+) \* \(w\.v{Eb} - w\.v{Bb}\)\) = 0', c))]
    i_sa = next(i for i, c in cons.items() if c == f"((w.v{Sb} - (1 : F)) * (w.v{Eb} - w.v{Ab})) = 0")
    assert Sb in inset
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
    PSV = lambda v, w: "(" + " + ".join(f"{256 ** i} * {V(c, w)}" for i, c in enumerate(v)) + ")"
    conj.append(f"({V(Eb, 'w')} = 0 ∨ {V(Eb, 'w')} = 1)")
    conj.append(f"({V(Ab, 'w')} = 0 ∨ {V(Ab, 'w')} = 1)")
    conj.append(f"{V(Ab, 'w')} + {V(Bb, 'w')} = 1")
    conj.append(f"({V(Sb, 'w')} = 0 ∨ {V(Sb, 'w')} = 1)")
    conj.append(f"({V(Sb, 'w')} = 1 → {V(Eb, 'w')} = {V(Bb, 'w')})")
    conj.append(f"({V(Sb, 'w')} = 0 → {V(Eb, 'w')} = {V(Ab, 'w')})")
    conj.append(f"({V(Ab, 'w')} = 1 → {PSV(Yv, 'w')} < {PSV(Nv, 'w')})")
    conj.append(f"({V(Bb, 'w')} = 1 → {PSV(Nv, 'w')} < {PSV(Yv, 'w')})")
    conj.append(f"({V(Eb, 'w')} = 1 → " + " ∧ ".join(f"w.v{o} = w.v{y}" for o, y in zip(Ov, Yv)) + ")")
    conj.append(f"({V(Eb, 'w')} = 0 → " + " ∧ ".join(f"w.v{o} = w.v{x}" for o, x in zip(Ov, Nv)) + ")")
    oplem = []
    for k, (op, app) in enumerate(zip(ops, apps)):
        oplem.append(f"/-- Field operation {k} modulo the prime. -/")
        oplem.append(f"theorem row_op{k} (w : W) (hw : constraints w) :")
        oplem.append(f"    {conj[k]} := by")
        oplem.append("  %OPEN_HW%")
        oplem.append(f"  have h{k} := {app}")
        for x, v in op['vecs'].items():
            oplem.append(f"  have ev{x} : {EV(v, 'w')} = {PS(v, 'w')} := by")
            oplem.append("    simp only [ZirenDet.FieldOp.ev]; ring")
        oplem.append(f"  rw [{', '.join(f'ev{x}' for x in op['vecs'])}]")
        oplem.append(f"  exact ZirenDet.FieldOp.cast_eq_zero_of_eq_mul (K := {PS(op['carry'], 'w')})")
        oplem.append(f"    (by push_cast; linear_combination h{k})")
        oplem.append("")
    proof = ["  have hw0 := hw", "  %OPEN_HW%"]
    for k, g in enumerate(gadgets):
        proof.append(f"  have l{k} := {g['app']}")
    used = {}
    for g in gadgets:
        used[g['r'][0]] = g['r']
    for x, v in used.items():
        proof.append(f"  have ev{x} : {EV(v, 'w')} = {PS(v, 'w')} := by")
        proof.append("    simp only [ZirenDet.FieldOp.ev]; ring")
    proof.append(f"  rw [{', '.join(f'ev{x}' for x in used)}]")
    proof.append("  refine ⟨" + ", ".join("?_" for _ in conj) + "⟩")
    for k, op in enumerate(ops):
        proof.append(f"  · have r := row_op{k} w hw0")
        proof.append(f"    rwa [{', '.join(f'ev{x}' for x in used if x in op['vecs'])}] at r" if any(x in op['vecs'] for x in used) else "    exact r")
    for k, g in enumerate(gadgets):
        proof.append(f"  · exact l{k}")
    iE, iA, iB, iS = bit(Eb), bit(Ab), bit(Bb), bit(Sb)
    Lx = dict(L)
    for c in Yv + Nv:
        Lx[c] = (f'n{c}', 255)
    txtA, appA = gated_lt(cons, ctx["reified"], Lx, Ab, Yv, Nv, "choice_lt_a", "hg", 900010, bound_of)
    txtB, appB = gated_lt(cons, ctx["reified"], Lx, Bb, Nv, Yv, "choice_lt_b", "hg", 900011, bound_of)
    lemmas += [txtA, txtB]
    proof.append(f"  · exact ZirenDet.FieldOp.bit_cases (ZirenDet.bit_val_le c{iE})")
    proof.append(f"  · exact ZirenDet.FieldOp.bit_cases (ZirenDet.bit_val_le c{iA})")
    proof.append(f"  · exact ZirenDet.FieldOp.sum_bits_one c{iA} c{iB} c{i_ab}")
    proof.append(f"  · exact ZirenDet.FieldOp.bit_cases (ZirenDet.bit_val_le c{iS})")
    proof.append(f"  · intro hsel")
    proof.append(f"    rw [ZirenDet.FieldOp.sel_one (ZirenDet.FieldOp.eq_one_of_val hsel) c{i_sb}]")
    proof.append(f"  · intro hsel")
    proof.append(f"    rw [ZirenDet.FieldOp.sel_zero (ZirenDet.FieldOp.eq_zero_of_val hsel) c{i_sa}]")
    proof.append(f"  · intro hsel")
    proof.append(f"    have hg := ZirenDet.FieldOp.eq_one_of_val hsel")
    proof.append(f"    exact {appA}")
    proof.append(f"  · intro hsel")
    proof.append(f"    have hg := ZirenDet.FieldOp.eq_one_of_val hsel")
    proof.append(f"    exact {appB}")
    proof.append("  · intro hsel")
    proof.append("    have hE1 := ZirenDet.FieldOp.eq_one_of_val hsel")
    proof.append("    exact ⟨" + ", ".join(f"ZirenDet.FieldOp.sel_one hE1 c{sel_y[c][0]}" for c in Yv) + "⟩")
    proof.append("  · intro hsel")
    proof.append("    have hE0 := ZirenDet.FieldOp.eq_zero_of_val hsel")
    proof.append("    exact ⟨" + ", ".join(f"ZirenDet.FieldOp.sel_zero hE0 c{sel_n[c][0]}" for c in Nv) + "⟩")
    lemma_text = "\n".join(lemmas)
    rng = lambda cols: [bound_of(c, 255) for c in cols]
    out = ["section FieldOpGadget", "open ZirenDet", "", lemma_text] + oplem
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
                                      + [f"hE{suf}", f"hA{suf}", f"hAB{suf}", f"hS{suf}", f"hSB{suf}", f"hSA{suf}", f"hltA{suf}", f"hltB{suf}", f"hsy{suf}", f"hsn{suf}"]) + "⟩"
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
    det.append(f"  simp only [{', '.join(f'i{c}' for c in incols)}] at {' '.join(fnames)} hS hSB hSA")
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
    goal = " ∧ ".join(f"w.v{o} = w'.v{o}" for o in Ov)
    for suf, w in (("", "w"), ("'", W1)):
        for nm, v in (("Y", Yv), ("N", Nv)):
            det.append(f"  have hp{nm}{suf} : {PSV(v, w)} = {EV(v, w)} := by simp only [ZirenDet.FieldOp.ev]; ring")
        det.append(f"  have dA{suf} : ({V(Ab, w)} = 1 ∧ {EV(Yv, w)} < {EV(Nv, w)}) ∨ ({V(Ab, w)} = 0 ∧ {V(Bb, w)} = 1 ∧ {EV(Nv, w)} < {EV(Yv, w)}) := by")
        det.append(f"    rcases hA{suf} with a | a")
        det.append(f"    · have hb : {V(Bb, w)} = 1 := by omega")
        det.append(f"      have := hltB{suf} hb")
        det.append(f"      exact Or.inr ⟨a, hb, by omega⟩")
        det.append(f"    · have := hltA{suf} a")
        det.append(f"      exact Or.inl ⟨a, by omega⟩")
        det.append(f"  have dS{suf} : ({V(Sb, W1)} = 1 ∧ {V(Eb, w)} = {V(Bb, w)}) ∨ ({V(Sb, W1)} = 0 ∧ {V(Eb, w)} = {V(Ab, w)}) := by")
        det.append(f"    rcases hS{suf} with s | s")
        det.append(f"    · exact Or.inr ⟨s, hSA{suf} s⟩")
        det.append(f"    · exact Or.inl ⟨s, hSB{suf} s⟩")
    det.append(f"  clear hltA hltA' hltB hltB' hSA hSA' hSB hSB'")
    det.append(f"  rcases hE with e1 | e1 <;> rcases hE' with e2 | e2")
    combos = [("N", "N", "hsn e1", "hsn' e2"), ("N", "Y", "hsn e1", "hsy' e2"),
              ("Y", "N", "hsy e1", "hsn' e2"), ("Y", "Y", "hsy e1", "hsy' e2")]
    choice = []
    for A, B, sa, sb in combos:
        e1, e2 = (1 if A == "Y" else 0), (1 if B == "Y" else 0)
        choice.append(f"/-- The lexicographic choice with `E = {e1}`, `E' = {e2}`: the written values agree. -/")
        choice.append(f"theorem lex_choice_{A}{B} (Y N Y2 N2 k k2 A B E A2 B2 E2 S : ℤ)")
        choice.append(f"    (hY : 0 ≤ Y) (hN : 0 ≤ N) (hY2 : 0 ≤ Y2) (hN2 : 0 ≤ N2)")
        choice.append(f"    (lY : Y < {M}) (lN : N < {M}) (lY2 : Y2 < {M}) (lN2 : N2 < {M})")
        choice.append(f"    (hk : N + Y = {M} * k) (hk2 : N2 + Y2 = {M} * k2) (hpair : Y = Y2 ∨ Y + Y2 = {M})")
        choice.append(f"    (dA : (A = 1 ∧ Y < N) ∨ (A = 0 ∧ B = 1 ∧ N < Y))")
        choice.append(f"    (dA2 : (A2 = 1 ∧ Y2 < N2) ∨ (A2 = 0 ∧ B2 = 1 ∧ N2 < Y2))")
        choice.append(f"    (dS : (S = 1 ∧ E = B) ∨ (S = 0 ∧ E = A)) (dS2 : (S = 1 ∧ E2 = B2) ∨ (S = 0 ∧ E2 = A2))")
        choice.append(f"    (hAB : A + B = 1) (hAB2 : A2 + B2 = 1)")
        choice.append(f"    (hE : E = {e1}) (hE2 : E2 = {e2}) : {A} = {B}2 := by")
        choice.append("  have h1 : k = 0 ∨ k = 1 := by omega")
        choice.append("  have h2 : k2 = 0 ∨ k2 = 1 := by omega")
        choice.append("  rcases h1 with rfl | rfl <;> rcases h2 with rfl | rfl <;> omega")
        choice.append("")
    for A, B, sa, sb in combos:
        va, vb = (Yv if A == "Y" else Nv), (Yv if B == "Y" else Nv)
        args = " ".join([EV(Yv, 'w'), EV(Nv, 'w'), EV(Yv, W1), EV(Nv, W1), "kn", "kn'",
                         V(Ab, 'w'), V(Bb, 'w'), V(Eb, 'w'), V(Ab, W1), V(Bb, W1), V(Eb, W1), V(Sb, W1)])
        facts = f"hnY hnN hnY' hnN' l{kY} l{kN} l{kY}' l{kN}' hkn hkn' hpair dA dA' dS dS' hAB hAB' e1 e2"
        det.append("  · have hv : " + f"{EV(va, 'w')} = {EV(vb, W1)} := lex_choice_{A}{B} {args} {facts}")
        det.append(f"    have hl := ZirenDet.FieldOp.ev_inj _ _ (by simp only [List.length_cons, List.length_nil]) hr{A} hr{B}' hv")
        det.append("    simp only [List.cons.injEq, and_true] at hl")
        det.append(f"    obtain ⟨{', '.join(f'z{i}' for i in range(len(Ov)))}⟩ := hl")
        det.append(f"    obtain ⟨{', '.join(f'o{i}' for i in range(len(Ov)))}⟩ := {sa}")
        det.append(f"    obtain ⟨{', '.join(f'o{i}' + chr(39) for i in range(len(Ov)))}⟩ := {sb}")
        det.append("    exact ⟨" + ", ".join(
            f"by rw [o{i}, o{i}']; exact ZMod.val_injective _ (by exact_mod_cast z{i})" for i in range(len(Ov))) + "⟩")
    out += choice
    out.append("/-- The written word is determined by the row's inputs. -/")
    out.append("theorem gadget_det (w w' : W) (hw : constraints w) (hw' : constraints w')")
    out.append("    (hin : inputs w = inputs w') :")
    out.append(f"    {goal} := by")
    out += det
    out.append("")
    out.append("end FieldOpGadget")
    open(outp, 'w').write("\n".join(out) + "\n")
    import json
    print(json.dumps(dict(n=n, Y=Y, N=N, C=C, E=Eb, A=Ab, B=Bb, S=Sb, O=Ov[:3], chain=[op['res'] for op in chain])), file=sys.stderr)


main()

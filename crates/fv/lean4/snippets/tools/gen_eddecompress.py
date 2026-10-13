"""gen_eddecompress.py MODULE_FILE OUT: the gadget proof of the Ed25519 decompress chip, as a snippet
with the generator's placeholders.

The field operations give `u = y² − 1`, `v = 1 + d·y²`, `q·v = u` and `r² = q (mod p)`, the negation
gives `n + r ≡ 0`, the range checks give `r, n < p`, and the lookup `r₀ AND 1` with the pinned bit
gives `r` even.  `v ≠ 0` because `−d` is not a square, so `q` is determined; two square roots of `q`
are equal or sum to the odd prime `p`, and both are even, so `r` and `n` are determined, and the
written word is `n` when the sign bit is set and `r` otherwise."""
import re, sys

HERE = __file__.rsplit('/', 1)[0]
field_src = open(f"{HERE}/gen_field.py").read()
head = field_src.split("    # ---- the chip-level statements\n")[0]
prep = head.replace("def main():", "def prepare():") + "    return locals()\n"
ns = {"__name__": "gen_field_prep", "__file__": f"{HERE}/gen_field.py"}
sys.path.insert(0, HERE)
exec(compile(prep, "gen_field_prep", "exec"), ns)


def yop_ok(ops, YY):
    op = next(o for o in ops if o['res'] == YY)
    return op['p0'][(YY,)] == -1 and op['s0'] == 1 and not op['const']


def main():
    path, outp = sys.argv[1], sys.argv[2]
    sys.argv = [sys.argv[0], path, "/dev/null"]
    ctx = ns["prepare"]()
    cons, src, ops, gadgets = ctx["cons"], ctx["src"], ctx["ops"], ctx["gadgets"]
    apps, lemmas, inputs = ctx["apps"], ctx["lemmas"], ctx["inputs"]
    bound_of, n, M = ctx["bound_of"], ctx["n"], ctx["M"]
    inset = set(inputs)
    for op in ops:
        op['res'] = op['carry'][0] - n
    vec_of = {}
    for op in ops:
        vec_of.update(op['vecs'])
    mons = lambda op: {m: op['s0'] * c for m, c in op['p0'].items() if m}
    sq = next(op for op in ops if (op['res'], op['res']) in op['p0'])
    R = sq['res']
    Q = next(m[0] for m in sq['p0'] if len(m) == 1)
    div = next(op for op in ops if op['res'] == Q)
    Vm = next(m for m in div['p0'] if len(m) == 2 and Q in m)
    V = Vm[0] if Vm[1] == Q else Vm[1]
    U = next(m[0] for m in div['p0'] if len(m) == 1)
    neg = next(op for op in ops if set(op['p0']) == {(op['res'],), (R,)})
    N = neg['res']
    vop = next(op for op in ops if op['res'] == V)
    DY = next(m[0] for m in vop['p0'] if len(m) == 1 and m[0] != V)
    dop = next(op for op in ops if op['res'] == DY)
    YY = next(m[0] for m in dop['p0'] if len(m) == 1 and m[0] != DY)
    dconst = dop['p0'][(YY,)]
    assert dop['p0'][(DY,)] == -1 and dop['s0'] == 1 and yop_ok(ops, YY)
    yop = next(op for op in ops if op['res'] == YY)
    (Ym,) = [m for m in yop['p0'] if len(m) == 2]
    assert Ym[0] == Ym[1] and set(vec_of[Ym[0]]) <= inset
    Yin = Ym[0]
    assert mons(vop) == {(V,): mons(vop)[(V,)], (DY,): -mons(vop)[(V,)]} and vop['const'] * vop['s0'] == -mons(vop)[(V,)]
    chain = [op for op in ops if op is not sq and op is not neg and op is not div]
    gR = next(g for g in gadgets if g['r'][0] == R)
    gN = next(g for g in gadgets if g['r'][0] == N)
    Rv, Nv = vec_of[R], vec_of[N]
    i_and, H, Lb = next((i, int(m.group(1)), int(m.group(2))) for i, c in cons.items()
                        if (m := re.fullmatch(rf'\(w\.v{Rv[0]} - \(\(w\.v(\d+) \* \(2 : F\)\) \+ w\.v(\d+)\)\) = 0', c)))
    i_lz = next(i for i, c in cons.items() if c == f"w.v{Lb} = 0")
    i_h = next(i for i, t in cons.items() if t == f'(w.v{H}).val ≤ 127')
    sel_n, sel_r = {}, {}
    for i, c in cons.items():
        m = re.fullmatch(r'\(w\.v(\d+) \* \(w\.v(\d+) - w\.v(\d+)\)\) = 0', c)
        if m and int(m.group(2)) in Nv:
            sel_n[int(m.group(2))] = (i, int(m.group(3)), int(m.group(1)))
        m = re.fullmatch(r'\(\(w\.v(\d+) - \(1 : F\)\) \* \(w\.v(\d+) - w\.v(\d+)\)\) = 0', c)
        if m and int(m.group(2)) in Rv:
            sel_r[int(m.group(2))] = (i, int(m.group(3)), int(m.group(1)))
    assert sorted(sel_n) == sorted(Nv) and sorted(sel_r) == sorted(Rv)
    Sb = sel_n[Nv[0]][2]
    assert Sb in inset and all(v[2] == Sb for v in list(sel_n.values()) + list(sel_r.values()))
    Ov = [sel_r[c][1] for c in Rv]
    assert Ov == [sel_n[c][1] for c in Nv]
    iS = next(i for i, t in cons.items() if t == f"(w.v{Sb} * (w.v{Sb} - (1 : F))) = 0")
    ZM = f"ZMod {M}"
    Vt = lambda c, w: f"(({w}.v{c}.val : ℕ) : ℤ)"
    EV = lambda v, w: "(ZirenDet.FieldOp.ev [" + ", ".join(Vt(c, w) for c in v) + "])"
    PS = lambda v, w: " + ".join(f"{256 ** i} * {Vt(c, w)}" for i, c in enumerate(v))
    CAST = lambda v, w: f"(({EV(v, w)} : ℤ) : {ZM})"

    def F_text(op, w):
        def mono(m, c):
            return f"({op['s0'] * c}) * " + " * ".join(EV(op['vecs'][x], w) for x in m)
        return " + ".join([mono(m, c) for m, c in op['p0'].items() if m] + ([f"({op['const']})"] if op['const'] else []))

    assert all(not op['sel'] for op in ops), "selectors in a decompress operation"
    nf = len(ops)
    conj = [f"((({F_text(op, 'w')} : ℤ)) : {ZM}) = 0" for op in ops]
    conj += [f"{EV(g['r'], 'w')} < {M}" for g in gadgets]
    conj.append(f"{EV(Rv, 'w')} % 2 = 0")
    conj.append(f"({Vt(Sb, 'w')} = 0 ∨ {Vt(Sb, 'w')} = 1)")
    conj.append(f"({Vt(Sb, 'w')} = 1 → " + " ∧ ".join(f"w.v{o} = w.v{x}" for o, x in zip(Ov, Nv)) + ")")
    conj.append(f"({Vt(Sb, 'w')} = 0 → " + " ∧ ".join(f"w.v{o} = w.v{y}" for o, y in zip(Ov, Rv)) + ")")
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
    proof.append(f"  · exact root_parity w ({bound_of(Rv[0], 255)}) c{i_h} c{i_and} c{i_lz}")
    par = ["/-- The root's low byte is twice the high half, so the root is even. -/",
           f"theorem root_parity (w : W) (hr : w.v{Rv[0]}.val ≤ 255) (hh0 : {cons[i_h]})",
           f"    (hand : {cons[i_and]}) (hlz : {cons[i_lz]}) :",
           f"    ({PS(Rv, 'w')}) % 2 = 0 := by",
           "  have hb := ZirenDet.FieldOp.byte_range hr",
           f"  have hh : ((w.v{H}.val : ℕ) : ℤ) ≤ 127 := by exact_mod_cast hh0",
           f"  obtain ⟨y0, hy0a, hy0b, ey0⟩ := ZirenDet.lift_le w.v{Rv[0]} hr",
           f"  obtain ⟨hv, hva, hvb, ehv⟩ := ZirenDet.lift_le w.v{H} (by exact_mod_cast hh)",
           "  have e := hand",
           "  rw [hlz, ey0, ehv] at e",
           "  have e' : ((y0 : ℤ) : F) = ((hv * 2 : ℤ) : F) := by push_cast; linear_combination e",
           "  have hy : y0 = hv * 2 := ZirenDet.Gadgets.cast_inj_small e' (by rw [abs_lt]; constructor <;> omega) (by rw [abs_lt]; constructor <;> omega)",
           f"  have h0 : ((w.v{Rv[0]}.val : ℕ) : ℤ) = hv * 2 := by",
           "    rw [ey0, ZirenDet.val_cast_small hy0a (by omega), Int.toNat_of_nonneg hy0a, hy]",
           "  rw [h0]",
           "  exact Int.emod_eq_zero_of_dvd ⟨hv + " + " + ".join(f"{256 ** i // 2} * {Vt(c, 'w')}" for i, c in enumerate(Rv) if i) + ", by ring⟩", ""]
    proof.append(f"  · exact ZirenDet.FieldOp.bit_cases (ZirenDet.bit_val_le c{iS})")
    proof.append("  · intro hsel")
    proof.append(f"    have hS1 := ZirenDet.FieldOp.eq_one_of_val hsel")
    proof.append("    exact ⟨" + ", ".join(f"ZirenDet.FieldOp.sel_one hS1 c{sel_n[c][0]}" for c in Nv) + "⟩")
    proof.append("  · intro hsel")
    proof.append(f"    have hS0 := ZirenDet.FieldOp.eq_zero_of_val hsel")
    proof.append("    exact ⟨" + ", ".join(f"ZirenDet.FieldOp.sel_zero hS0 c{sel_r[c][0]}" for c in Rv) + "⟩")
    lemma_text = "\n".join(lemmas)
    rng = lambda cols: [bound_of(c, 255) for c in cols]
    out = ["section FieldOpGadget", "open ZirenDet", "", lemma_text] + par + oplem
    out.append("/-- The operations modulo the prime, the range checks, the parity of the root and the selection. -/")
    out.append("theorem row_spec (w : W) (hw : constraints w) :")
    out.append("    " + " ∧\n    ".join(conj) + " := by")
    out += proof
    out.append("")
    out.append("/-- The byte ranges of the root and its negation. -/")
    out.append("theorem row_ranges (w : W) (hw : constraints w) :")
    out.append("    " + " ∧ ".join(f"w.v{c}.val ≤ 255" for c in Rv + Nv) + " := by")
    out.append("  %OPEN_HW%")
    out.append(f"  exact ⟨{', '.join(rng(Rv + Nv))}⟩")
    out.append("")
    pos = lambda c: inputs.index(c)
    W1 = "w'"
    side = lambda x, w: W1 if set(vec_of[x]) <= inset else w
    CASTX = lambda x, w: CAST(vec_of[x], side(x, w))
    fnames = [f"f{k}" for k in range(nf)]
    lnames = [f"l{k}" for k in range(len(gadgets))]
    pat = lambda suf: "⟨" + ", ".join([x + suf for x in fnames + lnames]
                                      + [f"hpar{suf}", f"hS{suf}", f"hsn{suf}", f"hsr{suf}"]) + "⟩"
    det = ["  haveI := ZirenDet.Edwards.ed25519_fact"]
    det.append(f"  obtain {pat('')} := row_spec w hw")
    det.append(f"  obtain {pat(chr(39))} := row_spec w' hw'")
    rv = Rv + Nv
    det.append(f"  obtain ⟨{', '.join(f'a{c}' for c in rv)}⟩ := row_ranges w hw")
    det.append(f"  obtain ⟨{', '.join(f'a{c}' + chr(39) for c in rv)}⟩ := row_ranges w' hw'")
    det.append("  have hin' := hin")
    det.append("  simp only [inputs, List.cons.injEq, and_true] at hin'")
    det.append(f"  obtain ⟨{', '.join(f'j{k}' for k in range(len(inputs)))}⟩ := hin'")
    incols = sorted({c for op in ops for v in op['vecs'].values() for c in v if c in inset} | {Sb})
    for c in incols:
        det.append(f"  have i{c} : w.v{c} = w'.v{c} := j{pos(c)}")
    det.append(f"  simp only [{', '.join(f'i{c}' for c in incols)}] at {' '.join(fnames)} hS hsn hsr")
    det.append(f"  push_cast at {' '.join(fnames)} {' '.join(x + chr(39) for x in fnames)}")
    eq_of, r_of = {}, {}
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
            poly[()] = op['s0'] * op['const']
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
        r_of[res] = f"r{k}"
        done.add(res)
    Y = CASTX(Yin, 'w')
    det.append(f"  have hv : {CASTX(V, 'w')} ≠ 0 := by")
    det.append("    intro h0")
    det.append(f"    rw [{r_of[V]}, {r_of[DY]}, {r_of[YY]}] at h0")
    det.append(f"    have e : (-({dconst} : {ZM})) * {Y} ^ 2 = 1 := by linear_combination (-1 : {ZM}) * h0")
    det.append("    exact ZirenDet.Edwards.ed25519_neg_d_nonsq (ZirenDet.Edwards.isSquare_of_mul_sq e)")
    kd = idx[id(div)]
    cq = div['s0'] * div['p0'][Vm]
    det.append(f"  have fk{kd} := f{kd}")
    det.append(f"  rw [{eq_of[V]}, {eq_of[U]}] at fk{kd}")
    det.append(f"  have hv' : {CASTX(V, W1)} ≠ 0 := by rw [← {eq_of[V]}]; exact hv")
    det.append(f"  have q{kd} : {CASTX(Q, 'w')} = {CASTX(Q, W1)} :=")
    det.append(f"    mul_left_cancel₀ hv' (by linear_combination ({cq}) * (fk{kd} - f{kd}'))")
    eq_of[Q] = f"q{kd}"
    ks = idx[id(sq)]
    a = sq['s0'] * sq['p0'][(R, R)]
    b = sq['s0'] * sq['p0'][(Q,)]
    det.append(f"  have hsq : {CAST(Rv, 'w')} ^ 2 = {CAST(Rv, W1)} ^ 2 := by")
    det.append(f"    linear_combination ({a}) * (f{ks} - f{ks}') - ({a * b}) * {eq_of[Q]}")
    det.append(f"  have hmod : {EV(Rv, 'w')} ^ 2 ≡ {EV(Rv, W1)} ^ 2 [ZMOD (({M} : ℕ) : ℤ)] :=")
    det.append("    (ZMod.intCast_eq_intCast_iff _ _ _).mp (by push_cast; exact hsq)")
    rgs = lambda v, w: f"(∀ x ∈ [{', '.join(Vt(c, w) for c in v)}], 0 ≤ x ∧ x ≤ 255)"
    for nm, v in (("R", Rv), ("N", Nv)):
        for suf, w in (("", "w"), ("'", W1)):
            det.append(f"  have hr{nm}{suf} : {rgs(v, w)} := by")
            det.append("    intro x hx")
            det.append("    simp only [List.mem_cons, List.mem_nil_iff, or_false] at hx")
            det.append(f"    rcases hx with {' | '.join('rfl' for _ in v)} <;>")
            det.append("      exact ZirenDet.FieldOp.byte_range (by assumption)")
            det.append(f"  have hn{nm}{suf} := ZirenDet.FieldOp.ev_nonneg _ hr{nm}{suf}")
    kR, kN = gadgets.index(gR), gadgets.index(gN)
    det.append(f"  have hp : Prime ((({M} : ℕ) : ℤ)) := Nat.prime_iff_prime_int.mp ZirenDet.Primes.ed25519_p")
    det.append(f"  have hpair := ZirenDet.Gadgets.sqrt_pair hp hnR (by push_cast; exact l{kR}) hnR' (by push_cast; exact l{kR}') hmod")
    det.append("  push_cast at hpair")
    det.append(f"  have hR : {EV(Rv, 'w')} = {EV(Rv, W1)} := by omega")
    kn = idx[id(neg)]
    det.append(f"  have hRc : {CAST(Rv, 'w')} = {CAST(Rv, W1)} := by rw [hR]")
    det.append(f"  have hNc : {CAST(Nv, 'w')} = {CAST(Nv, W1)} := by linear_combination ({neg['s0']}) * (f{kn} - f{kn}') - hRc")
    det.append(f"  have hN : {EV(Nv, 'w')} = {EV(Nv, W1)} :=")
    det.append(f"    ZirenDet.FieldOp.eq_of_cast_eq hnN (by exact_mod_cast l{kN}) hnN' (by exact_mod_cast l{kN}') hNc")
    L = len(Ov)
    for nm, hv_, v in (("R", "hR", Rv), ("N", "hN", Nv)):
        det.append(f"  have hl{nm} := ZirenDet.FieldOp.ev_inj _ _ (by simp only [List.length_cons, List.length_nil]) hr{nm} hr{nm}' {hv_}")
        det.append(f"  simp only [List.cons.injEq, and_true] at hl{nm}")
        det.append(f"  obtain ⟨{', '.join(f'e{nm}{i}' for i in range(L))}⟩ := hl{nm}")
    for nm, v in (("R", Rv), ("N", Nv)):
        for i, c in enumerate(v):
            det.append(f"  have g{nm}{i} : w.v{c} = w'.v{c} := ZMod.val_injective _ (by exact_mod_cast e{nm}{i})")
    cols = ", ".join([f"gR{i}" for i in range(len(Rv))] + [f"gN{i}" for i in range(len(Nv))])
    det.append("  rcases hS with h1 | h1")
    for nm, hs in (("R", "hsr"), ("N", "hsn")):
        det.append(f"  · obtain ⟨{', '.join(f'o{i}' for i in range(L))}⟩ := {hs} h1")
        det.append(f"    obtain ⟨{', '.join(f'o{i}' + chr(39) for i in range(L))}⟩ := {hs}' h1")
        det.append(f"    exact ⟨{cols}, " + ", ".join(
            f"by rw [o{i}, o{i}']; exact g{nm}{i}" for i in range(L)) + "⟩")
    goal = " ∧ ".join(f"w.v{o} = w'.v{o}" for o in Rv + Nv + Ov)
    out.append("/-- The square root, its negation and the written word are determined by the row's inputs. -/")
    out.append("theorem gadget_det (w w' : W) (hw : constraints w) (hw' : constraints w')")
    out.append("    (hin : inputs w = inputs w') :")
    out.append(f"    {goal} := by")
    out += det
    out.append("")
    out.append("end FieldOpGadget")
    open(outp, 'w').write("\n".join(out) + "\n")
    import json
    print(json.dumps(dict(n=n, R=R, N=N, Q=Q, V=V, U=U, S=Sb, L=Lb, H=H, O=Ov[:3],
                          chain=[op['res'] for op in chain])), file=sys.stderr)


main()

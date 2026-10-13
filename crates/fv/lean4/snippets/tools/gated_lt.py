"""gated_lt.py: the less-than gadget `FieldLtCols` evaluated under a gate `g` against a
variable right-hand side, as a lemma `g = 1 → X < Y` over the limbs of `X` and `Y`."""
import re, sys

HERE = __file__.rsplit('/', 1)[0]
sys.path.insert(0, HERE)
import gen_field as gf
from gen_fpop import resolve
from mklemma import subst

KB = 2130706433


def gated_lt(cons, reified, L, G, R, mod, name, hgname, pin_id, bound_of):
    """The lemma `name` stating `Σ 256ⁱ Rᵢ < Σ 256ⁱ modᵢ` from the gadget's rows under `G = 1`,
    and its application with `hgname : w.vG = 1`."""
    n = len(R)
    L = dict(L)
    reified = {z for z in reified if any(re.fullmatch(rf'\(w\.v{z} - \(.*\)\) = 0', c) or c == f"w.v{z} = 0"
                                         for c in cons.values())}

    def bound(c, b):
        if b == 1:
            for i, t in cons.items():
                if t == f"(w.v{G} * (w.v{c} * (w.v{c} - (1 : F)))) = 0":
                    return f"(ZirenDet.bit_val_le (by have e := c{i}; rw [{hgname}, one_mul] at e; exact e))"
            if c == G:
                return f"(by rw [{hgname}, ZMod.val_one])"
        if b == KB - 1:
            return f"(Nat.le_of_lt_succ (ZMod.val_lt w.v{c}))"
        return bound_of(c, b)

    L[G] = (f'n{G}', 1)
    P = lambda v: "(" + " + ".join(f"{256 ** i} * n{c}" for i, c in enumerate(v)) + ")"
    flagrow = {}
    for i, c in cons.items():
        m = re.fullmatch(rf'\(w\.v{G} \* \(\((\(*w\.v\d+(?: \+ w\.v\d+\))*) - \(1 : F\)\) \* \(w\.v(\d+) - w\.v(\d+)\)\)\) = 0', c)
        if m:
            fl = [int(x) for x in re.findall(r'w\.v(\d+)', m.group(1))]
            flagrow[int(m.group(2))] = (i, fl, int(m.group(3)), m.group(1))
    assert sorted(flagrow) == sorted(R), sorted(flagrow)
    assert all(flagrow[R[i]][2] == mod[i] for i in range(n))
    FL = [None] * n
    for i in range(n):
        fl = flagrow[R[i]][1]
        assert len(fl) == n - i and fl == flagrow[R[n - 1]][1] + [x for x in fl if x not in flagrow[R[n - 1]][1]]
        FL[i] = fl[-1]
    i_tot = next(i for i, c in cons.items() if c.startswith(f"(w.v{G} * (") and c.endswith(" - (1 : F))) = 0")
                 and sorted(int(x) for x in re.findall(r'w\.v(\d+)', c)) == sorted([G] + FL))
    (i_lt, Pc, Qc), = [(i, int(m.group(1)), int(m.group(2))) for i, c in cons.items()
                       if (m := re.fullmatch(rf'\(\(w\.v(\d+) \* w\.v{G}\)\)\.val < \(\(\(w\.v(\d+) \* w\.v{G}\) \+ \(\(1 : F\) - w\.v{G}\)\)\)\.val', c))]
    defs = {}
    for i, c in cons.items():
        m = re.fullmatch(rf'\(w\.v{G} \* w\.v(\d+)\) = 0', c)
        m2 = re.fullmatch(rf'\(w\.v{G} \* \(w\.v({Pc}|{Qc}) - \(.*\)\) = 0', c)
        if (m and int(m.group(1)) in reified) or m2:
            c1 = dict(cons)
            c1[i] = re.sub(rf'w\.v{G}\b', '(1 : F)', cons[i])
            t, p, u = resolve(c1, i, reified)
            inner = re.fullmatch(r'\(\(1 : F\) \* (.*)\)', t).group(1)
            first = int(re.search(r'w\.v(\d+)', inner).group(1))
            defs[first] = (i, t, p, u, inner)
    assert set(defs) == {Pc, Qc}, defs.keys()
    for c in FL:
        L[c] = (f'n{c}', 1)
    L[Pc] = (f'n{Pc}', KB - 1)
    L[Qc] = (f'n{Qc}', KB - 1)
    pg = pin_id
    cons[pg] = f"w.v{G} = (1 : F)"
    Fn = lambda i: f"n{FL[i]}"
    Rn = lambda i: f"n{R[i]}"
    Mn = lambda i: f"n{mod[i]}"
    S = lambda i: " + ".join(Fn(j) for j in range(i, n))
    bits = " ".join(f"h{Fn(j)}" for j in range(n))
    one = lambda t: t.replace(f"(n{G} : F)", "((1 : ℤ) : F)")
    gated = lambda i: re.fullmatch(rf'\(w\.v{G} \* (.*)\) = 0', cons[i]).group(1)
    o = [f"  have pg : n{G} = 1 := by",
         f"    have e := e{pg}",
         f"    clear * - e hn{G}",
         "    divrem_lift; omega",
         "  subst pg"]
    o.append(f"  have hsum : {S(0)} = 1 := by")
    o.append(f"    have r : {subst(gated(i_tot), L)} = 0 := by")
    o.append(f"      have e := e{i_tot}")
    o.append("      simp only [Int.cast_one, one_mul] at e")
    o.append("      exact e")
    o.append(f"    clear * - r {bits}")
    o.append("    fieldop_row r")
    for nm, c, rhs, hs in (("hp", Pc, " + ".join(f"{Rn(i)} * {Fn(i)}" for i in range(n)), f"h{Rn(0)}"),
                           ("hq", Qc, " + ".join(f"{Fn(i)} * {Mn(i)}" for i in range(n)), "")):
        i, t, p, u, inner = defs[c]
        o.append(f"  have {nm} : n{c} = {rhs} := by")
        o.append(f"    have r : {subst(inner, L)} = 0 := by")
        o.append(f"      have e : {one(subst(t, L))} = 0 := by linear_combination {p}")
        o.append("      simp only [Int.cast_one, one_mul] at e")
        o.append("      exact e")
        keep = " ".join(f"h{L[int(x)][0]}" for x in dict.fromkeys(re.findall(r'w\.v(\d+)', inner)) if int(x) in L)
        o.append(f"    clear * - r {keep}")
        o.append("    fieldop_row r")
    o.append(f"  have hlt : n{Pc} < n{Qc} := by")
    o.append(f"    have e := e{i_lt}")
    o.append("    simp only [Int.cast_one, mul_one, sub_self, add_zero] at e")
    o.append(f"    exact ZirenDet.DivRem.lt_of_val_lt e (by omega) (by omega)")
    o.append(f"  obtain ⟨S{n}, hS{n}⟩ : ∃ S : ℤ, S = 0 := ⟨_, rfl⟩")
    o.append(f"  obtain ⟨R{n}, hR{n}⟩ : ∃ R : ℤ, R = 0 := ⟨_, rfl⟩")
    o.append(f"  obtain ⟨T{n}, hT{n}⟩ : ∃ T : ℤ, T = 0 := ⟨_, rfl⟩")
    for i in range(n - 1, -1, -1):
        o.append(f"  obtain ⟨S{i}, hS{i}⟩ : ∃ S : ℤ, S = {Fn(i)} + S{i + 1} := ⟨_, rfl⟩")
        o.append(f"  obtain ⟨R{i}, hR{i}⟩ : ∃ R : ℤ, R = {Rn(i)} + 256 * R{i + 1} := ⟨_, rfl⟩")
        o.append(f"  obtain ⟨T{i}, hT{i}⟩ : ∃ T : ℤ, T = {Mn(i)} + 256 * T{i + 1} := ⟨_, rfl⟩")
    chain = " ".join(f"hS{j}" for j in range(n + 1))
    for i in range(n):
        o.append(f"  have hb{i} : 0 ≤ S{i} ∧ S{i} ≤ 1 := by")
        o.append(f"    clear * - hsum {chain} {bits}")
        o.append("    omega")
    for i in range(n):
        ri, fl, mi, st = flagrow[R[i]]
        o.append(f"  have H{i} : S{i} = 0 → {Rn(i)} = {Mn(i)} := by")
        o.append("    intro h0")
        o.append(f"    have h0' : {S(i)} = 0 := by")
        o.append(f"      clear * - h0 {' '.join(f'hS{j}' for j in range(i, n + 1))}")
        o.append("      omega")
        o.append(f"    have hc : ((({S(i)} : ℤ) : F)) = 0 := by rw [h0']; simp")
        o.append(f"    have r : (({Rn(i)} : ℤ) : F) - (({Mn(i)} : ℤ) : F) = 0 := by")
        o.append(f"      have e : {subst(gated(ri), L)} = 0 := by")
        o.append(f"        have e := e{ri}")
        o.append("        simp only [Int.cast_one, one_mul] at e")
        o.append("        exact e")
        o.append("      push_cast at hc")
        o.append(f"      have hne : ({subst(st, L)} - (1 : F)) = -1 := by linear_combination hc")
        o.append("      rw [hne] at e")
        o.append("      linear_combination -e")
        o.append(f"    clear * - r h{Rn(i)} h{Mn(i)}")
        o.append(f"    have r' : (({Rn(i)} - {Mn(i)} : ℤ) : F) = ((0 : ℤ) : F) := by push_cast; linear_combination r")
        o.append("    obtain ⟨m, hm⟩ := ZirenDet.cast_eq_iff_dvd.mp r'")
        o.append("    omega")
    for i in range(n):
        o.append(f"  have G{i} : {Fn(i)} = 1 → {Rn(i)} < {Mn(i)} := by")
        o.append("    intro h1")
        for j in range(n):
            if j != i:
                o.append(f"    have z{j} : {Fn(j)} = 0 := by clear * - hsum h1 {bits}; omega")
        o.append(f"    clear * - hp hq hlt h1 {' '.join(f'z{j}' for j in range(n) if j != i)}")
        o.append("    subst_vars")
        o.append("    simp only [mul_zero, mul_one, zero_mul, one_mul, add_zero, zero_add] at hlt")
        o.append("    omega")
    o.append(f"  have P{n} : (S{n} = 0 ∧ R{n} = T{n}) ∨ (S{n} = 1 ∧ R{n} < T{n}) := Or.inl ⟨hS{n}, by rw [hR{n}, hT{n}]⟩")
    for i in range(n - 1, -1, -1):
        o.append(f"  have P{i} : (S{i} = 0 ∧ R{i} = T{i}) ∨ (S{i} = 1 ∧ R{i} < T{i}) := by")
        o.append(f"    clear * - P{i + 1} hS{i} hR{i} hT{i} h{Fn(i)} h{Rn(i)} h{Mn(i)} H{i} G{i} hb{i}"
                 + (f" hb{i + 1}" if i + 1 < n else f" hS{n}"))
        o.append("    omega")
    o.append(f"  have hS0 : S0 = 1 := by clear * - hsum {chain}; omega")
    o.append(f"  clear * - P0 hS0 {' '.join(f'hR{j}' for j in range(n + 1))} {' '.join(f'hT{j}' for j in range(n + 1))}")
    o.append("  omega")
    used = sorted({i_tot, i_lt, pg} | {flagrow[c][0] for c in R} | {u for d in defs.values() for u in d[3]})
    goal = f"{P(R)} < {P(mod)}"
    text, app = gf.build_raw(cons, used, L, goal, name, "\n".join(o), bound)
    return text, app.replace(f"c{pg}", hgname)

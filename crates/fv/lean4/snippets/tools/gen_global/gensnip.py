"""Writes snippets/Global.lean: the row's septic facts from the Global chip's constraints and the
determinism of the added point's `y` and the running digest (`ZirenDet/Septic.lean`)."""
import pickle
import sys

defs, full = pickle.load(open("full.pkl", "rb"))
match = pickle.load(open("match.pkl", "rb"))
conj = open("conj.txt").read().split("\n")

Q = "ZirenDet.Septic."
VEC = {"gX": 9, "gY": 16, "gX1": 30, "gY1": 37, "gI": 44, "gX3": 51, "gY3": 58}
DOC = {
    "gX": "The added point's `x`.", "gY": "The added point's `y`.",
    "gX1": "The digest received, `x`.", "gY1": "The digest received, `y`.",
    "gI": "The witnessed inverse of `x − x₁`.",
    "gX3": "The digest sent, `x`.", "gY3": "The digest sent, `y`.",
}


def find(pred):
    hits = [i for i, c in enumerate(conj) if pred(c)]
    assert len(hits) == 1, hits
    return hits[0]


def conj_text(i):
    return conj[i]


flags = [find(lambda c: c.startswith("(w.v27 * (w.v27 - (1 : F)))")),
         find(lambda c: c.startswith("(w.v26 * (w.v26 - (1 : F)))")),
         find(lambda c: c.startswith("((w.v27 + w.v26) - (1 : F))"))]
recv = find(lambda c: c.startswith("(w.v26 * (w.v22 - ((1 : F)"))
send = find(lambda c: c.startswith("(w.v27 * (w.v22 - ((-1056964608 : F)"))
ranges = [find(lambda c: c == "(w.v23).val ≤ 65535"), find(lambda c: c == "(w.v24).val ≤ 255"),
          find(lambda c: c == "(w.v25).val < 63")]
lins = [find(lambda c: c.startswith(f"(w.v{9 + k} - ")) for k in range(7)]
plain = flags + [recv, send] + ranges + lins

out = []
out.append("/-! ### The septic point and its chord addition (`ZirenDet/Septic.lean`) -/\n")
for name, base in VEC.items():
    comps = ", ".join(f"w.v{base + k}" for k in range(7))
    out.append(f"/-- {DOC[name]} -/\ndef {name} (w : W) : {Q}V := ![{comps}]\n")

sm = Q + "sm"
vec_stmts = [
    ("lift", f"{sm} (gY w) (gY w) = {Q}cv (gX w)"),
    ("sx", f"{sm} (gX1 w + gX w + gX3 w) ({sm} (gX w - gX1 w) (gX w - gX1 w)) =\n"
           f"      {sm} (gY w - gY1 w) (gY w - gY1 w)"),
    ("sy", f"{sm} (gY1 w + gY3 w) (gX w - gX1 w) = {sm} (gY w - gY1 w) (gX1 w - gX3 w)"),
    ("di", f"{sm} (gX w - gX1 w) (gI w) = {Q}one"),
]
stmt = " ∧\n    ".join([s for _, s in vec_stmts] + [conj_text(i) for i in plain])
out.append("/-- The row's septic facts: `y² = x³ + 3zx − 3` for the added point, the chord identities of\n"
           "the digest step and the inverse, with the flags, the `y₆` ranges and `x` from the message. -/")
out.append(f"theorem row_spec (w : W) (hw : constraints w) :\n    {stmt} := by")
out.append("  %OPEN_W%")
out.append("  %OPEN_HW%")
out.append("  dsimp only at *")
for r, (i, _) in sorted(defs.items(), key=lambda kv: kv[1][0]):
    out.append(f"  have s{r} := sub_eq_zero.mp c{i}")
    out.append(f"  subst s{r}")
holes = ", ".join(["?_"] * len(vec_stmts) + [f"c{i}" for i in plain])
out.append(f"  refine ⟨{holes}⟩")
simp = (f"simp only [{Q}sm, {Q}cv, {Q}one, gX, gY, gX1, gY1, gI, gX3, gY3, Pi.add_apply, "
        "Pi.sub_apply, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]")
for name, _ in vec_stmts:
    out.append(f"  · refine {Q}V_ext ?_ ?_ ?_ ?_ ?_ ?_ ?_")
    for k in range(7):
        j, a = match[(name, k)]
        assert a == 1
        out.append(f"    · {simp}")
        out.append(f"      linear_combination c{j}")
out.append("")

pairs = [f"w.v{16 + k} = w'.v{16 + k}" for k in range(7)] + \
        [f"w.v{51 + k} = w'.v{51 + k}" for k in range(14)]
out.append("/-- The added point's `y` and the digest sent are determined by the row's inputs. -/")
out.append("theorem gadget_det (w w' : W) (hw : constraints w) (hw' : constraints w')\n"
           "    (hin : inputs w = inputs w') : " + " ∧ ".join(pairs) + " := by")
names = ["L", "SX", "SY", "DI", "B27", "B26", "FS", "R26", "R27", "H23", "H24", "H25"] + \
        [f"E{9 + k}" for k in range(7)]
out.append(f"  obtain ⟨{', '.join(names)}⟩ := row_spec w hw")
out.append(f"  obtain ⟨{', '.join(n + chr(39) for n in names)}⟩ := row_spec w' hw'")
order = [0, 1, 2, 3, 4, 5, 6, 27, 26, 7, 29] + list(range(30, 44)) + [8]
for pos, v in enumerate(order):
    out.append(f"  have i{v} := congrArg (·[{pos}]?) hin")
    out.append(f"  simp only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, "
               f"Option.some.injEq] at i{v}")
cv = "simp only [gX, gX1, gY1, Matrix.cons_val, Matrix.cons_val_zero, Matrix.cons_val_one]"
out.append(f"  have hX : gX w = gX w' := by")
out.append(f"    refine {Q}V_ext ?_ ?_ ?_ ?_ ?_ ?_ ?_ <;> {cv}")
out.append("    · linear_combination E9 - E9' + i0 + 65536 * i7")
for k in range(1, 6):
    out.append(f"    · linear_combination E{9 + k} - E{9 + k}' + i{k}")
out.append("    · linear_combination E15 - E15' + 256 * i6 + i8")
for name, base in (("gX1", 30), ("gY1", 37)):
    out.append(f"  have h{name} : {name} w = {name} w' := by")
    out.append(f"    refine {Q}V_ext ?_ ?_ ?_ ?_ ?_ ?_ ?_ <;> {cv}")
    for k in range(7):
        out.append(f"    · exact i{base + k}")
tail = ["((w.v23 + (w.v24 * (65536 : F))) + (w.v25 * (16777216 : F)))",
        "((w'.v23 + (w'.v24 * (65536 : F))) + (w'.v25 * (16777216 : F)))"]
out.append(f"""  have hsq : {sm} (gY w) (gY w) = {sm} (gY w') (gY w') := by rw [L, L', hX]
  have hY : gY w = gY w' := by
    rcases {Q}sq_unique hsq with h | h
    · exact h
    · exfalso
      have h6 : w.v22 = -w'.v22 := congrFun h 6
      rcases mul_eq_zero.mp B26 with h26 | h26
      · have h26' : w'.v26 = 0 := by rw [← i26]; exact h26
        have h27 : w.v27 = 1 := by linear_combination FS - h26
        have h27' : w'.v27 = 1 := by linear_combination FS' - h26'
        have ha : w.v22 = (-1056964608 : F) + {tail[0]} := by
          rw [h27, one_mul, sub_eq_zero] at R27; exact R27
        have hb : w'.v22 = (-1056964608 : F) + {tail[1]} := by
          rw [h27', one_mul, sub_eq_zero] at R27'; exact R27'
        exact {Q}y6_send ha hb H23 H24 H25 H23' H24' H25' h6
      · have h26 : w.v26 = 1 := sub_eq_zero.mp h26
        have h26' : w'.v26 = 1 := by rw [← i26]; exact h26
        have ha : w.v22 = (1 : F) + {tail[0]} := by
          rw [h26, one_mul, sub_eq_zero] at R26; exact R26
        have hb : w'.v22 = (1 : F) + {tail[1]} := by
          rw [h26', one_mul, sub_eq_zero] at R26'; exact R26'
        exact {Q}y6_recv ha hb H23 H24 H25 H23' H24' H25' h6
  rw [← hX, ← hY, ← hgX1, ← hgY1] at SX'
  rw [← hX, ← hY, ← hgX1, ← hgY1] at SY'
  rw [← hX, ← hgX1] at DI'
  obtain ⟨h3x, h3y⟩ := {Q}chord_unique SX SY DI SX' SY' DI'""")
for nm, base in (("hY", 16), ("h3x", 51), ("h3y", 58)):
    lhs = ", ".join(f"w.v{base + k}" for k in range(7))
    rhs = ", ".join(f"w'.v{base + k}" for k in range(7))
    out.append(f"  have {nm}c : (![{lhs}] : {Q}V) = ![{rhs}] := {nm}")
    out.append(f"  obtain ⟨{', '.join(f'a{base + k}' for k in range(7))}⟩ := {Q}V_components {nm}c")
out.append("  exact ⟨" + ", ".join([f"a{16 + k}" for k in range(7)] + [f"a{51 + k}" for k in range(14)]) + "⟩")
open(sys.argv[1] if len(sys.argv) > 1 else "Global.snippet.lean", "w").write("\n".join(out) + "\n")
print("defs", len(defs), "plain", plain)

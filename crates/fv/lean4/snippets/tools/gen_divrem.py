"""gen_divrem.py MODULE_FILE SIGNED OUT: the hand-written proof of the division chip's gadget
for one module (a split Lean file), as a snippet with the generator's placeholders."""
import os, re, sys
sys.path.insert(0, '.')
from mklemma import build

src = open(sys.argv[1]).read().split('\n')
signed = sys.argv[2] == '1'
start = next(i for i, l in enumerate(src) if l.startswith('def constraints_0'))
actual, k = {}, 0
for l in src[start:]:
    if l.startswith('def constraints '):
        break
    if l.startswith('def ') or not l.strip():
        continue
    actual[k] = re.sub(r' ∧$', '', l.strip())
    k += 1
i0 = next(i for i, l in enumerate(src) if l.startswith('def inputs'))
inputs = re.findall(r'w\.v(\d+)', src[i0 + 1])

# The reference numbering is that of the signed division module: the tactic scripts name
# hypotheses and columns by it.  A module's auxiliary columns (the low parts of the sign
# decompositions) are numbered differently; `ROLES` finds them by the constraint they occur in.
ROLES = {
    560: r'\(w\.v5 - \(\(w\.v38 \* \(128 : F\)\) \+ w\.v(\d+)\)\) = 0',
    561: r'\(w\.v117 - \(\(w\.v39 \* \(128 : F\)\) \+ w\.v(\d+)\)\) = 0',
    562: r'\(w\.v149 \* \(w\.v13 - \(\(w\.v(\d+) \* \(128 : F\)\) \+ w\.v50\)\)\) = 0',
    563: r'\(w\.v149 \* \(w\.v21 - \(\(w\.v(\d+) \* \(128 : F\)\) \+ w\.v51\)\)\) = 0',
    564: r'\(w\.v111 - \(\(w\.v143 \* \(128 : F\)\) \+ w\.v(\d+)\)\) = 0',
    565: r'\(w\.v117 - \(\(w\.v145 \* \(128 : F\)\) \+ w\.v(\d+)\)\) = 0',
    566: r'\(w\.v9 - \(\(w\.v144 \* \(128 : F\)\) \+ w\.v(\d+)\)\) = 0',
}
col_of = {}
for ref, pat in ROLES.items():
    for c in actual.values():
        m = re.fullmatch(pat, c)
        if m:
            col_of[ref] = int(m.group(1))
ref_of = {v: k for k, v in col_of.items()}
to_ref = lambda text: re.sub(r'w\.v(\d+)', lambda m: f"w.v{ref_of.get(int(m.group(1)), int(m.group(1)))}", text)
actual_ref = {i: to_ref(c) for i, c in actual.items()}
reference = {}
for l in open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'divrem_reference.txt')).read().split('\n'):
    m = re.match(r'c(\d+): (.*?)( ∧)?$', l)
    if m:
        reference[int(m.group(1))] = m.group(2)
UNSIGNED = {0: '((0 : F) - w.v146) = 0', 1: '((0 : F) - w.v147) = 0', 2: '((0 : F) - w.v148) = 0',
            3: 'w.v40 = 0', 4: 'w.v41 = 0', 55: 'w.v120 = 0'}
cons, idx_of = {}, {}
for r, text in reference.items():
    want = UNSIGNED[r] if (not signed and r in UNSIGNED) else text
    hits = [i for i, c in actual_ref.items() if c == want]
    if hits:
        cons[r] = want
        idx_of[r] = hits[0]
actual_col = lambda ref: col_of.get(ref, ref)

def find(pattern):
    hits = [i for i, c in actual_ref.items() if c == pattern]
    assert hits, pattern
    return hits[0]

def bound_of(col, bound):
    if bound == 1:
        return find(f"(w.v{col} * (w.v{col} - (1 : F))) = 0"), True
    return find(f"(w.v{col}).val ≤ {bound}"), False

L = {}
for i, v in enumerate(range(2, 6)): L[v] = (f'q{i}', 255)
for i, v in enumerate(range(6, 10)): L[v] = (f'r{i}', 255)
for i, v in enumerate(range(108, 112)): L[v] = (f'b{i}', 255)
for i, v in enumerate(range(114, 118)): L[v] = (f'dv{i}', 255)
for i, v in enumerate(range(30, 38)): L[v] = (f'm{i}', 255)
for i, v in enumerate(range(22, 30)): L[v] = (f'kk{i}', 65535)
for i, v in enumerate(range(67, 75)): L[v] = (f't{i}', 1)
L.update({40: ('sq', 1), 41: ('sx', 1), 147: ('sr', 1), 148: ('sc', 1), 146: ('sb', 1),
          120: ('ov', 1)})
if signed:
    L.update({38: ('msq', 1), 39: ('msc', 1), 144: ('msr', 1), 145: ('msd', 1), 143: ('msb', 1),
              560: ('lq', 127), 561: ('lc', 127), 566: ('lr', 127), 565: ('ld', 127),
              564: ('lb', 127)})
sub = lambda cols: {c: L[c] for c in cols if c in L}
W4 = lambda p: f"w4 {p}0 {p}1 {p}2 {p}3"

lemmas, apps = [], {}
def add(name, idx, lifts, goal, tactic):
    missing = [i for i in idx if i not in cons]
    assert not missing, (name, missing)
    text, app = build(cons, idx, lifts, goal, name, tactic, L,
                      name_c=lambda i: f"c{idx_of[i]}", name_x=lambda n: f"x{actual_col(n)}")
    lemmas.append(text)
    apps[name] = app

rows = list(range(7, 15)) + list(range(56, 72))
qcols = list(range(2, 10)) + list(range(108, 112)) + list(range(114, 118)) + list(range(30, 38)) \
    + list(range(22, 30)) + list(range(67, 75)) + [40, 41, 147, 148, 146, 120, 38, 39, 144, 560, 561, 566]
absidx = [1, 2, 92] + list(range(93, 151)) + list(range(208, 216)) + list(range(220, 242))
if signed:
    add('quotient_eq', [3, 4] + rows + [184, 187], sub(qcols),
        f"({W4('q')} - 4294967296 * sq) * ({W4('dv')} - 4294967296 * sx) + ({W4('r')} - 4294967296 * sr) = {W4('b')} - 4294967296 * (sb * (1 - ov))",
        open('quotient.tac').read())
    add('rem_bound', absidx + [247, 250],
        sub([6, 7, 8, 9, 114, 115, 116, 117, 147, 148, 144, 145, 565, 566]),
        f"({W4('r')} - 4294967296 * sr).natAbs < ({W4('dv')} - 4294967296 * sc).natAbs",
        open('rembound.tac').read())
    add('overflow', [19, 21, 22, 24, 25, 27, 28, 30, 34, 35, 36, 37, 39, 40, 42, 43, 45, 46, 48, 52, 53, 54, 55],
        sub([108, 109, 110, 111, 114, 115, 116, 117, 120]),
        "(ov = 1 ∧ (b0 = 0 ∧ b1 = 0 ∧ b2 = 0 ∧ b3 = 128) ∧ (dv0 = 255 ∧ dv1 = 255 ∧ dv2 = 255 ∧ dv3 = 255)) ∨ (ov = 0 ∧ ¬((b0 = 0 ∧ b1 = 0 ∧ b2 = 0 ∧ b3 = 128) ∧ (dv0 = 255 ∧ dv1 = 255 ∧ dv2 = 255 ∧ dv3 = 255)))",
        open('overflow.tac').read())
    add('msb_bits', [0, 1, 2, 3, 4, 184, 187, 244, 247, 250],
        sub([5, 9, 111, 117, 40, 41, 147, 148, 146, 38, 39, 144, 145, 143, 560, 561, 566, 565, 564]),
        "(sq = msq ∧ q3 = 128 * msq + lq) ∧ (sx = msc ∧ dv3 = 128 * msc + lc) ∧ (sr = msr ∧ r3 = 128 * msr + lr) ∧ (sb = msb ∧ b3 = 128 * msb + lb) ∧ (sc = msd ∧ dv3 = 128 * msd + ld)",
        "  refine ⟨⟨?_, ?_⟩, ⟨?_, ?_⟩, ⟨?_, ?_⟩, ⟨?_, ?_⟩, ⟨?_, ?_⟩⟩ <;> (divrem_lift; omega)\n")
    add('sign_cond', [72, 73], sub([6, 7, 8, 9, 147, 146]),
        "(sr = 1 → sb = 1) ∧ (sb = 1 → sr = 0 → r0 + r1 + r2 + r3 = 0)",
        """  have hs : sr = 0 ∨ sr = 1 := by omega
  have hb : sb = 0 ∨ sb = 1 := by omega
  rcases hs with rfl | rfl <;> rcases hb with rfl | rfl <;>
    simp only [Int.cast_zero, Int.cast_one, sub_zero, sub_self, zero_sub, one_mul, zero_mul,
      mul_zero, mul_one] at * <;>
    (refine ⟨?_, ?_⟩ <;> intro _ <;> (try intro _) <;> first | omega | (divrem_lift; omega))
""")
else:
    add('quotient_eq', [0, 1, 3, 4, 55] + rows, sub(qcols),
        f"{W4('q')} * {W4('dv')} + {W4('r')} = {W4('b')}",
        open('quotient_u.tac').read())
    add('rem_bound', absidx, sub([6, 7, 8, 9, 114, 115, 116, 117, 147, 148]),
        f"({W4('r')}).natAbs < ({W4('dv')}).natAbs",
        open('rembound_u.tac').read())

lift_lines = []
for col in sorted(L):
    name, bound = L[col]
    ci, bit = bound_of(col, bound)
    proof = f"(ZirenDet.bit_val_le c{ci})" if bit else f"c{ci}"
    lift_lines.append(f"  obtain ⟨{name}, h{name}a, h{name}b, rfl⟩ := ZirenDet.lift_le x{actual_col(col)} {proof}")
    lift_lines.append(f"  have h{name} : 0 ≤ {name} ∧ {name} ≤ {bound} := ⟨h{name}a, by exact_mod_cast h{name}b⟩")

val = lambda col: f"((w.v{col}.val : ℕ) : ℤ)"
word = lambda cols: "(ZirenDet.DivRem.w4 " + " ".join(val(c) for c in cols) + ")"
B, C, Q, R = word(range(108, 112)), word(range(114, 118)), word(range(2, 6)), word(range(6, 10))
words = list(range(108, 112)) + list(range(114, 118)) + list(range(2, 10))
vals = "\n".join(
    f"  have v{L[c][0]} : ((ZMod.val ((({L[c][0]} : ℤ) : F)) : ℕ) : ℤ) = {L[c][0]} := by\n"
    f"    rw [ZirenDet.val_cast]; omega"
    for c in words)
vnames = ", ".join(f"v{L[c][0]}" for c in words)
qr = list(range(2, 10))
rng = [find(f"(w.v{c}).val ≤ 255") for c in qr]
pos = lambda col: inputs.index(str(col))
bc = list(range(108, 112)) + list(range(114, 118))
sg = 1 if signed else 0
if signed:
    finish = f"""  have hq := {apps['quotient_eq']}
  have hr := {apps['rem_bound']}
  have ho := {apps['overflow']}
  have hm := {apps['msb_bits']}
  have hs := {apps['sign_cond']}
  obtain ⟨⟨m1, m2⟩, ⟨m3, m4⟩, ⟨m5, m6⟩, ⟨m7, m8⟩, ⟨m9, m10⟩⟩ := hm
  have ex : sx = sc := by omega
  rw [ex] at hq
{vals}
  simp only [{vnames}]
  exact ZirenDet.DivRem.spec_signed hb0 hb1 hb2 hdv0 hdv1 hdv2 hq0 hq1 hq2 hr0 hr1 hr2 hsq hsc hsr hsb hov
    hlq hld hlr hlb (by omega) (by omega) (by omega) (by omega) hq hr ho hs.1 hs.2"""
else:
    finish = f"""  have hq := {apps['quotient_eq']}
  have hr := {apps['rem_bound']}
{vals}
  simp only [{vnames}]
  exact ZirenDet.DivRem.spec_unsigned (ZirenDet.DivRem.w4_range hb0 hb1 hb2 hb3).1
    (ZirenDet.DivRem.w4_range hr0 hr1 hr2 hr3).1 hq hr"""

out = ["section DivRemGadget", "open ZirenDet.DivRem", ""]
out += [l for t in lemmas for l in (t.split('\n') + [''])]
out.append(f"""/-- The row satisfies the division specification on its words. -/
theorem row_spec (w : W) (hw : constraints w) :
    ZirenDet.DivRem.Spec {sg} {B} {C}
      {Q} {R} := by
  %OPEN_W%
  %OPEN_HW%
{chr(10).join(lift_lines)}
{finish}

/-- The byte ranges of quotient and remainder. -/
theorem row_ranges (w : W) (hw : constraints w) :
    {' ∧ '.join(f'w.v{c}.val ≤ 255' for c in qr)} := by
  %OPEN_W%
  %OPEN_HW%
  exact ⟨{', '.join(f'c{i}' for i in rng)}⟩

/-- Quotient and remainder are determined by the row's inputs. -/
theorem gadget_det (w w' : W) (hw : constraints w) (hw' : constraints w')
    (hin : inputs w = inputs w') :
    {' ∧ '.join(f"w.v{c} = w'.v{c}" for c in qr)} := by
  have h := row_spec w hw
  have h' := row_spec w' hw'
  obtain ⟨{', '.join(f'a{c}' for c in qr)}⟩ := row_ranges w hw
  obtain ⟨{', '.join(f"a{c}'" for c in qr)}⟩ := row_ranges w' hw'
{chr(10).join(f"  have i{c} : w.v{c} = w'.v{c} := by{chr(10)}    have t := congrArg (·[{pos(c)}]?) hin{chr(10)}    simpa only [inputs, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] using t" for c in bc)}
  simp only [{', '.join(f'i{c}' for c in bc)}] at h
  have rg : ∀ {{x : F}}, x.val ≤ 255 → 0 ≤ ((x.val : ℕ) : ℤ) ∧ ((x.val : ℕ) : ℤ) ≤ 255 :=
    fun hx => ⟨by positivity, by exact_mod_cast hx⟩
  obtain ⟨hQ, hR⟩ := ZirenDet.DivRem.spec_unique (sg := {sg}) (by decide)
    (ZirenDet.DivRem.w4_range (rg a2) (rg a3) (rg a4) (rg a5))
    (ZirenDet.DivRem.w4_range (rg a6) (rg a7) (rg a8) (rg a9))
    (ZirenDet.DivRem.w4_range (rg a2') (rg a3') (rg a4') (rg a5'))
    (ZirenDet.DivRem.w4_range (rg a6') (rg a7') (rg a8') (rg a9')) h h'
  obtain ⟨e2, e3, e4, e5⟩ := ZirenDet.DivRem.w4_inj (rg a2) (rg a3) (rg a4) (rg a5)
    (rg a2') (rg a3') (rg a4') (rg a5') hQ
  obtain ⟨e6, e7, e8, e9⟩ := ZirenDet.DivRem.w4_inj (rg a6) (rg a7) (rg a8) (rg a9)
    (rg a6') (rg a7') (rg a8') (rg a9') hR
  exact ⟨{', '.join(f'ZMod.val_injective _ (by exact_mod_cast e{c})' for c in qr)}⟩

end DivRemGadget
""")
open(sys.argv[3], 'w').write("\n".join(out))

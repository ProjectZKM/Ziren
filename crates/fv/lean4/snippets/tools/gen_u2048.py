"""gen_u2048.py MODULE_FILE OUT: the gadget proof of `U256XU2048Mul`, as a snippet with the
generator's placeholders.

The chip chains eight multiply-and-carry operations `A·Bᵢ + Cᵢ₋₁ = Rᵢ + Cᵢ·2²⁵⁶` (with `C₋₁ = 0`),
each from its coefficient rows over the integers.  `Rᵢ < 2²⁵⁶` by its bytes, so `Rᵢ` is the
canonical residue of `A·Bᵢ + Cᵢ₋₁` modulo `2²⁵⁶` and `Cᵢ` is the quotient; by induction on `i`
every result and carry is a function of the operands' bytes."""
import random, re, sys

HERE = __file__.rsplit('/', 1)[0]
sys.path.insert(0, HERE)
import gen_field as gf
from gen_fpop import parse, reified_columns, pyexpr, resolve, toint
from mklemma import subst

OFF = 16384
SIMP = ("Int.cast_zero, Int.cast_one, mul_zero, zero_mul, mul_one, one_mul, add_zero, sub_zero, "
        "zero_add, sub_self, zero_sub, neg_zero")
T256 = 2 ** 256


def collect_rows(cons, reified):
    """Every coefficient row, with its reified columns replaced by their definitions."""
    wpat = lambda c: f'({OFF} : F)) * (-256 : F)' in c or re.search(rf'- \(w\.v\d+ - \({OFF} : F\)\)\)+ = 0$', c)
    defs_of = {}
    for i, c in cons.items():
        m = re.fullmatch(r'\(w\.v(\d+) - (\(.*\))\) = 0', c)
        if m and int(m.group(1)) in reified:
            defs_of.setdefault(int(m.group(1)), []).append((i, m.group(2)))

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
    rows = []
    for i, c in cons.items():
        m = re.match(r'\(w\.v(\d+) - ', c)
        if m and int(m.group(1)) in reified:
            continue
        if wpat(c):
            rows.append(resolve(cons, i, reified))
        elif (m := re.fullmatch(r'w\.v(\d+) = 0', c)) and int(m.group(1)) in reified:
            t = resolve(cons, i, reified)
            if re.search(rf'\({OFF} : F\)', t[0]):
                rows.append(t)
    for v, ds in defs_of.items():
        if len(ds) == 2:
            (i1, x1), (i2, x2) = ds
            w1, w2 = bool(re.search(rf'\({OFF} : F\)', x1)), bool(re.search(rf'\({OFF} : F\)', x2))
            if w1 == w2:
                continue
            (ip, xp), (iw, xw) = ((i2, x2), (i1, x1)) if w1 else ((i1, x1), (i2, x2))
            rows.append(expand((f"({xp} - {xw})", f"e{iw} - e{ip}", [iw, ip])))
    return rows


def main():
    path, outp = sys.argv[1], sys.argv[2]
    src, cons = parse(path)
    reified = reified_columns(src)
    n = 32
    allrows = collect_rows(cons, reified)
    key = lambda r: tuple(sorted(int(x) for x in re.findall(rf'w\.v(\d+) - \({OFF} : F\)', r[0])))
    wit = sorted({c for r in allrows for c in key(r)})
    blocks, cur = [], [wit[0]]
    for c in wit[1:]:
        if c == cur[-1] + 1 and len(cur) < 2 * n - 1:
            cur.append(c)
        else:
            blocks.append(cur)
            cur = [c]
    blocks.append(cur)
    assert all(len(b) == 2 * n - 1 for b in blocks), [len(b) for b in blocks]
    words = sorted(((int(m.group(1)), [int(x) for x in re.findall(r'w\.v(\d+)', l)])
                    for l in src if (m := re.match(r'def in_mem_read_(\d+)_val ', l))))
    flat = [c for _, w in words for c in w]

    def vector(c):
        v = flat[flat.index(c):flat.index(c) + n] if c in flat else list(range(c, c + n))
        assert len(v) == n
        return v

    def bound_of(c, bound):
        for i, t in cons.items():
            if t == f"(w.v{c}).val ≤ {bound}":
                return f"c{i}"
        raise AssertionError((c, bound))

    ops = []
    for b in blocks:
        rows = sorted((r for r in allrows if set(key(r)) <= set(b)),
                      key=lambda r: 0 if key(r) == (b[0],) else (min(key(r)) - b[0] + 1))
        assert [len(key(r)) for r in rows] == [1] + [2] * (len(b) - 1) + [1], [key(r) for r in rows]
        m0 = re.match(r'\(+w\.v(\d+) \* w\.v(\d+)\)(?: \+ w\.v(\d+)\))? - w\.v(\d+)\)', rows[0][0])
        a0, b0, cp0, r0 = int(m0.group(1)), int(m0.group(2)), m0.group(3), int(m0.group(4))
        RC = list(range(r0, r0 + 2 * n))
        ops.append(dict(rows=rows, A=vector(a0), B=vector(b0), Cp=list(range(int(cp0), int(cp0) + n)) if cp0 else None,
                        R=RC[:n], C=RC[n:], wit=b))
    ops.sort(key=lambda o: o['R'][0])
    for k, op in enumerate(ops):
        if k == 0:
            assert op['Cp'] is None
        else:
            assert op['Cp'] == ops[k - 1]['C'], (k, op['Cp'][:2], ops[k - 1]['C'][:2])
        assert op['A'] == ops[0]['A']
    L = {}
    for op in ops:
        for v in (op['A'], op['B'], op['R'], op['C']):
            for c in v:
                L[c] = (f'n{c}', 255)
        for c in op['wit']:
            L[c] = (f'n{c}', 65535)
    P = lambda v: "(" + " + ".join(f"{256 ** i} * n{c}" for i, c in enumerate(v)) + ")"
    PV = lambda v, w: "(" + " + ".join(f"{256 ** i} * (({w}.v{c}.val : ℕ) : ℤ)" for i, c in enumerate(v)) + ")"
    val = lambda v, env: sum(env[c] * 256 ** i for i, c in enumerate(v))
    lemmas, apps = [], []
    for k, op in enumerate(ops):
        rows, wt = op['rows'], op['wit']
        sg = []
        for i, (text, _, _) in enumerate(rows):
            wc = wt[i] if i < len(wt) else wt[i - 1]
            e0 = {c: 7 for c in range(0, 10000)}
            e1 = dict(e0)
            e1[wc] += 1
            d = eval(pyexpr(text, lambda c: e1[c])) - eval(pyexpr(text, lambda c: e0[c]))
            coef = 256 if i < len(wt) else -1
            assert d in (coef, -coef), (k, i, d)
            sg.append(1 if d == coef else -1)
        for _ in range(3):
            env = {c: random.randrange(0, bnd + 1) for c, (_, bnd) in L.items()}
            T = sum(sg[i] * 256 ** i * eval(pyexpr(t, lambda c: env[c])) for i, (t, _, _) in enumerate(rows))
            cp = val(op['Cp'], env) if op['Cp'] else 0
            assert T == val(op['A'], env) * val(op['B'], env) + cp - val(op['R'], env) - val(op['C'], env) * T256, (k, 'rows do not telescope')
        o = []
        for i, (text, proof, _) in enumerate(rows):
            f = subst(text, L)
            keep = " ".join(f"h{L[int(c)][0]}" for c in dict.fromkeys(re.findall(r'w\.v(\d+)', text)) if int(c) in L)
            o.append(f"  have H{i} : {toint(f)} = 0 := by")
            o.append(f"    have r : {f} = 0 := by")
            o.append(f"      linear_combination {proof}")
            o.append(f"    clear * - r {keep}")
            o.append(f"    (try simp only [{SIMP}] at r ⊢)")
            o.append("    fieldop_row r")
        o.append(f"  clear * - {' '.join(f'H{i}' for i in range(len(rows)))}")
        o.append("  linear_combination " + " + ".join(f"({sg[i] * 256 ** i}) * H{i}" for i in range(len(rows))))
        cp = f" + {P(op['Cp'])}" if op['Cp'] else ""
        goal = f"{P(op['A'])} * {P(op['B'])}{cp} - {P(op['R'])} - {P(op['C'])} * {T256} = 0"
        used = sorted({i for r in rows for i in r[2]})
        text, app = gf.build_raw(cons, used, L, goal, f"mul_add{k}", "\n".join(o), bound_of)
        lemmas.append(text)
        apps.append(app)
        op['goalv'] = lambda w, op=op: (f"{PV(op['A'], w)} * {PV(op['B'], w)}"
                                        + (f" + {PV(op['Cp'], w)}" if op['Cp'] else "")
                                        + f" - {PV(op['R'], w)} - {PV(op['C'], w)} * {T256} = 0")
    conj = [op['goalv']('w') for op in ops]
    proof = ["  %OPEN_HW%", "  exact ⟨" + ", ".join(apps) + "⟩"]
    outs = [c for op in ops for c in op['R'] + op['C']]
    W1 = "w'"
    ins = src[next(i for i, l in enumerate(src) if l.startswith('def inputs')) + 1]
    inputs = [int(x) for x in re.findall(r'w\.v(\d+)', ins)]
    incols = sorted({c for op in ops for c in op['A'] + op['B']})
    assert set(incols) <= set(inputs)
    fs = [f"f{k}" for k in range(len(ops))]
    # A right-nested conjunction of hundreds of facts is read by projection: an `obtain` with
    # that many names does not finish in hours, `h.2.2….1` costs its depth.
    proj = lambda h, k, n: h + ".2" * k + (".1" if k < n - 1 else "")
    det = [f"  obtain ⟨{', '.join(fs)}⟩ := row_spec w hw",
           f"  obtain ⟨{', '.join(x + chr(39) for x in fs)}⟩ := row_spec w' hw'",
           "  have ra := row_ranges w hw",
           "  have ra' := row_ranges w' hw'"]
    ra, ra1, hin1 = "ra", "ra'", "hin'"
    det += [f"  have a{c} := {proj(ra, k, len(outs))}" for k, c in enumerate(outs)]
    det += [f"  have a{c}' := {proj(ra1, k, len(outs))}" for k, c in enumerate(outs)]
    det += ["  have hin' := hin",
            "  simp only [inputs, List.cons.injEq, and_true] at hin'"]
    for c in incols:
        det.append(f"  have i{c} : w.v{c} = w'.v{c} := {proj(hin1, inputs.index(c), len(inputs))}")
    det.append(f"  simp only [{', '.join(f'i{c}' for c in incols)}] at {' '.join(fs)}")
    rng = lambda v, w: f"∀ x ∈ [{', '.join(f'(({w}.v{c}.val : ℕ) : ℤ)' for c in v)}], 0 ≤ x ∧ x ≤ 255"
    for k, op in enumerate(ops):
        for nm, v in (("R", op['R']), ("C", op['C'])):
            for suf, w in (("", "w"), ("'", W1)):
                acc = "List.forall_mem_nil _"
                for c in reversed(v):
                    acc = f"List.forall_mem_cons.mpr ⟨ZirenDet.FieldOp.byte_range a{c}{suf}, {acc}⟩"
                det.append(f"  have hr{nm}{k}{suf} : {rng(v, w)} := {acc}")
        X = lambda w: f"({PV(op['A'], W1)} * {PV(op['B'], W1)}" + (f" + {PV(op['Cp'], w)})" if op['Cp'] else ")")
        if op['Cp']:
            det.append(f"  rw [hC{k - 1}] at f{k}")
        for suf, w in (("", "w"), ("'", W1)):
            det.append(f"  have bR{k}{suf} := bytes_bound {' '.join(f'{w}.v{c}' for c in op['R'])} {' '.join(f'a{c}{suf}' for c in op['R'])}")
        det.append(f"  obtain ⟨hR{k}, hC{k}⟩ := block_uniq (T := {T256}) (by norm_num) f{k} f{k}' bR{k}.1 bR{k}.2 bR{k}'.1 bR{k}'.2")
    for k, op in enumerate(ops):
        for nm, v in (("R", op['R']), ("C", op['C'])):
            det.append(f"  have hl{nm}{k} := ZirenDet.FieldOp.ev_inj _ _ (by simp only [List.length_cons, List.length_nil]) hr{nm}{k} hr{nm}{k}'")
            det.append(f"    (by simp only [ZirenDet.FieldOp.ev]; linear_combination h{nm}{k})")
            det.append(f"  simp only [List.cons.injEq, and_true] at hl{nm}{k}")
            det.append(f"  obtain ⟨{', '.join(f'e{c}' for c in v)}⟩ := hl{nm}{k}")
    det.append(f"  exact ⟨{', '.join(f'ZMod.val_injective _ (by exact_mod_cast e{c})' for c in outs)}⟩")
    xs = [f"x{i}" for i in range(n)]
    pvx = "(" + " + ".join(f"{256 ** i} * ((x{i}.val : ℕ) : ℤ)" for i in range(n)) + ")"
    bb = ["/-- Bytes read little-endian lie in `[0, 2^(8n))`. -/",
          f"theorem bytes_bound ({' '.join(xs)} : F)",
          "    " + " ".join(f"(h{i} : x{i}.val ≤ 255)" for i in range(n)) + " :",
          f"    0 ≤ {pvx} ∧ {pvx} < {T256} := by",
          "  constructor <;> omega", ""]
    bb += ["/-- A multiply-and-carry row has one residue below `T` and one carry. -/",
           "theorem block_uniq {X R R' C C' T : ℤ} (hT : 0 < T) (h : X - R - C * T = 0)",
           "    (h' : X - R' - C' * T = 0) (h0 : 0 ≤ R) (h1 : R < T) (h0' : 0 ≤ R') (h1' : R' < T) :",
           "    R = R' ∧ C = C' := by",
           "  have hR : R = R' := ZirenDet.FieldOp.residue_unique (M := T) (X := X) h0 h1 h0' h1'",
           "    (Int.modEq_iff_dvd.mpr ⟨C, by linear_combination h⟩) (Int.modEq_iff_dvd.mpr ⟨C', by linear_combination h'⟩)",
           "  refine ⟨hR, ?_⟩",
           "  have h2 : T * (C - C') = 0 := by linear_combination h' - h - hR",
           "  exact sub_eq_zero.mp ((mul_eq_zero.mp h2).resolve_left hT.ne')", ""]
    out = ["section FieldOpGadget", "open ZirenDet", ""] + lemmas + bb
    out.append("/-- The eight multiply-and-carry identities. -/")
    out.append("theorem row_spec (w : W) (hw : constraints w) :")
    out.append("    " + " ∧\n    ".join(conj) + " := by")
    out += proof
    out.append("")
    out.append("/-- The byte ranges of the results and carries. -/")
    out.append("theorem row_ranges (w : W) (hw : constraints w) :")
    out.append("    " + " ∧ ".join(f"w.v{c}.val ≤ 255" for c in outs) + " := by")
    out.append("  %OPEN_HW%")
    out.append(f"  exact ⟨{', '.join(bound_of(c, 255) for c in outs)}⟩")
    out.append("")
    out.append("/-- The results' and carries' bytes are determined by the row's inputs. -/")
    out.append("theorem gadget_det (w w' : W) (hw : constraints w) (hw' : constraints w')")
    out.append("    (hin : inputs w = inputs w') :")
    out.append("    " + " ∧ ".join(f"w.v{c} = w'.v{c}" for c in outs) + " := by")
    out += det
    out.append("")
    out.append("end FieldOpGadget")
    out.append("")
    open(outp, 'w').write("\n".join(out))
    print(dict(ops=len(ops), A=ops[0]['A'][:2], R=[o['R'][0] for o in ops], C=[o['C'][0] for o in ops]), file=sys.stderr)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""flat_det.py ROOT PREFIX DETMOD [per_module]: rewrite a generated `deterministic` without splitting w, w'.

The generated proof splits both witnesses into fields and every constraint set into conjuncts, so
every tactic pays for a context of tens of thousands of entries.  Here `w`, `w'` stay whole: each
step lemma `stK` gets an adapter `stKf` that restates it over the original conjuncts plus the
equalities and fixed values established so far, and `deterministic` applies the adapters to
projections of `hw`, `hw'`.  Bit and one-hot case splits keep their shape.  Projections are
inlined unless the module would exceed 64 MB; then each used conjunct is bound once by name.
"""
import copy
import os
import re
import sys

from leanmod import add_modules, read, write

root, mp, det = sys.argv[1:4]
per = int(sys.argv[4]) if len(sys.argv) > 4 else 150
d = os.path.join(root, mp)
src = read(os.path.join(d, det + ".lean"))
L = src.split("\n")
t0 = next(i for i, l in enumerate(L) if l.startswith("theorem deterministic"))
by = next(i for i in range(t0, len(L)) if L[i].rstrip().endswith(":= by"))
end = next(i for i in range(by + 1, len(L)) if L[i].startswith("end ") or re.match(r"(theorem|lemma) ", L[i]))
body = L[by + 1 : end]
ns_of_det = [l.split()[1] for l in L[:t0] if l.startswith("namespace ")]
P = read(os.path.join(d, "P.lean"))


def ns_section(text, inner):
    """The part of `text` inside `namespace inner` … `end inner` (the chip module of the theorem)."""
    blocks = re.findall(rf"^namespace {re.escape(inner)}\n(.*?)^end {re.escape(inner)}$", text, re.M | re.S)
    return "\n".join(blocks) if blocks else text


PS = ns_section(P, ns_of_det[-1])


def list_def(name):
    m = re.search(rf"^def {name} \(w : W\) : List F :=\n\s*\[(.*?)\]\s*$", PS, re.M | re.S)
    if not m:
        return []
    items, depth, cur = [], 0, ""
    for ch in m.group(1):
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            items.append(cur.strip()); cur = ""
        else:
            cur += ch
    if cur.strip():
        items.append(cur.strip())
    return items


inputs = list_def("inputs")
outputs = list_def("outputs")
out_vars = set(int(v) for v in re.findall(r"\bw\.v(\d+)\b", " ".join(outputs)))
CJ = {int(m.group(1)): m.group(2).split() for m in re.finditer(r"^def cj(\d+) \(([^:]*) : F\) : Prop", PS, re.M)}
CJBODY = {int(m.group(1)): m.group(2).strip() for m in re.finditer(r"^def cj(\d+) \([^:]*: F\) : Prop := (.*)$", PS, re.M)}

chunk_of, lem_text = {}, {}
gd = None
for f in sorted(os.listdir(d)):
    if not re.fullmatch(r"C\d+[a-z0-9]*\.lean", f) or f == det + ".lean":
        continue
    t = read(os.path.join(d, f))
    t = "\n".join(ns_section(t, ns_of_det[-1]) for _ in [0]) if re.search(rf"^namespace {re.escape(ns_of_det[-1])}$", t, re.M) else ""
    for m in re.finditer(r"^theorem (st\d+) ", t, re.M):
        s = m.start(); e = t.find(":= by", s)
        chunk_of[m.group(1)] = f[:-5]; lem_text[m.group(1)] = t[s:e]
    m = re.search(r"^theorem gadget_det \(w w' : W\).*?\(hin : inputs w = inputs w'\) :\s*(.*?) := by", t, re.M | re.S)
    if m and gd is None:
        gd = [tuple(int(x) for x in p) for p in re.findall(r"w\.v(\d+) = w'\.v(\d+)", m.group(1))]

TOK = re.compile(r"\b([xy])(\d+)\b")


def parse_binders(stmt):
    rest = stmt[stmt.index(" ", 8):]
    out, depth, cur, goal, k = [], 0, None, None, 0
    while k < len(rest):
        ch = rest[k]
        if depth == 0 and ch in "({":
            depth = 1; cur = ch; k += 1; continue
        if depth > 0:
            if ch in "({[⟨":
                depth += 1
            elif ch in ")}]⟩":
                depth -= 1
            if depth == 0:
                out.append(cur + ch); cur = None
            else:
                cur += ch
            k += 1; continue
        if ch == ":":
            goal = rest[k + 1 :].strip(); break
        k += 1
    return out, goal


def xy(expr, side):
    return re.sub(r"\bw\.v(\d+)\b", lambda mm: f"{side}{mm.group(1)}", expr)


paths = {}
emit = []
adapters = {}
helpers = []
state = {"sub": {}, "val": {}}
saved, seen_bullet = {}, set()
branch_b = None
zeros = []


def ind(raw):
    return len(raw) - len(raw.lstrip(" "))


def out(depth, text):
    emit.append(" " * depth + text)


NAMED = os.environ.get("FLAT_NAMED") == "1"
INLINE_LIMIT = 64 << 20
named, named_at = [], [None]


def proj(nm):
    if NAMED and not nm.endswith("g"):
        if nm not in named:
            named.append(nm)
        return nm
    return f"({paths[nm]})"


def flush_zeros(depth):
    global zeros
    if not zeros:
        return
    b, hs = branch_b
    os_ = [o for o, _ in zeros]
    group = onehot_group({b, *os_})
    name = f"ohz{len(helpers)}"
    vs = " ".join(f"x{v}" for v in group["vars"])
    bits = " ".join(f"(b{v} : cj{group['bit'][v]} x{v})" for v in group["vars"])
    concl = " ∧ ".join(f"x{o} = 0" for o in os_)
    n = len(group["vars"])
    vec = ", ".join(f"x{v}" for v in group["vars"])
    unf = ", ".join(f"cj{group['bit'][v]}" for v in group["vars"]) + f", cj{group['sum']}"
    idx = {v: i for i, v in enumerate(group["vars"])}
    hk = [f"  have h{v} : x{v} = if ({idx[v]} : Fin {n}) = k then 1 else 0 := hk {idx[v]}" for v in [b] + os_]
    helpers.append("\n".join([
        f"theorem {name} {{{vs} : F}} {bits} (s : cj{group['sum']} {' '.join('x' + str(v) for v in CJ[group['sum']] and [int(p[1:]) for p in CJ[group['sum']]])}) (h : x{b} = 1) :",
        f"    {concl} := by",
        f"  simp only [{unf}] at *",
        f"  obtain ⟨k, hk⟩ := ZirenDet.OneHot.onehot_single (n := {n}) (by norm_num [KB]) ![{vec}]",
        f"    (by intro i; fin_cases i <;> assumption)",
        "    (by simp only [Fin.sum_univ_succ, Fin.sum_univ_zero, Matrix.cons_val_zero, Matrix.cons_val_succ]; linear_combination s)",
    ] + hk + [
        f"  fin_cases k <;> simp (config := {{ decide := true }}) only [ite_true, ite_false] at {' '.join('h' + str(v) for v in [b] + os_)} <;> simp_all",
        "",
    ]))
    args = " ".join(proj(f"c{group['bit'][v]}") for v in group["vars"]) + " " + proj(f"c{group['sum']}") + f" {hs}"
    pat = ", ".join(f"z{o}" for o in os_)
    out(depth, f"obtain ⟨{pat}⟩ := {name} {args}" if len(os_) > 1 else f"have z{os_[0]} := {name} {args}")
    for o in os_:
        state["val"][o] = (f"z{o}", "(0 : F)")
    zeros = []


def onehot_group(need):
    """The flags of the one-hot sum conjunct that mentions every variable in `need`, with the bit
    conjunct of each."""
    for k, ps in CJ.items():
        vs = [int(p[1:]) for p in ps]
        if not need <= set(vs) or len(vs) < 2:
            continue
        body = CJBODY.get(k, "")
        if not re.fullmatch(r"\(*" + r"[\s()+x\d]*" + r"- \(1 : F\)\)* = 0", body):
            continue
        bit = {}
        for v in vs:
            cand = [j for j, qs in CJ.items() if qs == [f"x{v}"] and re.fullmatch(rf"\(x{v} \* \(x{v} - \(1 : F\)\)\) = 0", CJBODY.get(j, ""))]
            if not cand:
                break
            bit[v] = cand[0]
        else:
            return {"vars": vs, "bit": bit, "sum": k}
    raise SystemExit(f"no one-hot sum conjunct over {sorted(need)}")


def adapter_call(st, args, target, depth):
    binders, goal = parse_binders(lem_text[st])
    names = [b[1:-1].split(" : ", 1)[0] for b in binders if not b.startswith("{")]
    assert names == args, (st, names[:5], args[:5])
    orig = []
    for b in binders:
        if b.startswith("{"):
            continue
        nm, ty = b[1:-1].split(" : ", 1)
        mm = re.fullmatch(r"([cd])(\d+)", nm)
        if mm:
            side = "x" if mm.group(1) == "c" else "y"
            ty = f"cj{mm.group(2)}" + "".join(" " + side + p[1:] for p in CJ[int(mm.group(2))])
        elif nm == "hg":
            ty = " ∧ ".join(f"x{a} = y{b}" for a, b in gd)
        elif re.fullmatch(r"hin\d+", nm):
            e = inputs[int(nm[3:])]
            ty = f"{xy(e, 'x')} = {xy(e, 'y')}"
        elif re.fullmatch(r"e\d+", nm) or nm.startswith("h_"):
            pass
        else:
            raise SystemExit(f"{st}: binder {nm} not restatable")
        orig.append(f"({nm} : {ty})")
    sub, val = state["sub"], state["val"]
    present = {(m.group(1), int(m.group(2))) for m in TOK.finditer(" ".join(orig) + " " + goal)}
    gs = sorted({n for a, n in present if n in val})
    fs = sorted({n for a, n in present if a == "y" and n in sub} | {n for n in gs if ("y", n) in present})
    for n in fs:
        assert n in sub, (st, "not identified", n)
    fb = [f"(f{n} : x{n} = y{n})" for n in fs]
    gb = [f"(g{n} : x{n} = {val[n][1]})" for n in gs]
    allty = " ".join(orig + fb + gb) + " " + goal
    vs = sorted({(m.group(1), int(m.group(2))) for m in TOK.finditer(allty)})
    head = " {" + " ".join(f"{a}{n}" for a, n in vs) + " : F}" if vs else ""
    tac = [f"  subst f{n}" for n in fs] + [f"  subst g{n}" for n in gs] + [f"  exact {st} {' '.join(names)}"]
    adapters[st] = f"theorem {st}f{head}\n    {' '.join(orig + fb + gb)} :\n    {goal} := by\n" + "\n".join(tac) + "\n"
    a2 = [proj(nm) if re.fullmatch(r"[cd]\d+", nm) else nm for nm in args]
    a2 += [sub[n] for n in fs] + [val[n][0] for n in gs]
    out(depth, f"have {target} := {st}f {' '.join(a2)}")


def final(depth):
    rules = []
    for n in sorted(out_vars):
        if n in state["sub"]:
            r = state["sub"][n]
            rules.append(f"← {r}" if r.startswith("hin") else f"e{n}")
        if n in state["val"]:
            rules.append(state["val"][n][0])
    out(depth, f"simp only [outputs, List.cons.injEq, and_true{', ' if rules else ''}{', '.join(rules)}]")


keep_pre = []
for raw in body:
    l = raw.strip()
    if not l or l in ("picus_safe (", ")"):
        continue
    depth = 2 + max(0, ind(raw) - 4)
    if zeros and not re.match(r"^(have e\d+ : x\d+ = 0 := by|subst e\d+$)", l):
        flush_zeros(depth)
    if l.startswith("have hg :=") or l.startswith("have hin") or l.startswith("clear hin"):
        out(depth, l); continue
    if re.match(r"obtain ⟨.*⟩ := w'?$", l) or l.startswith("dsimp only"):
        continue
    m = re.match(r"^subst hin(\d+)$", l)
    if m:
        j = int(m.group(1)); vm = re.fullmatch(r"w\.v(\d+)", inputs[j])
        assert vm, ("non-variable input substituted", j)
        state["sub"].setdefault(int(vm.group(1)), f"hin{j}"); continue
    if re.match(r"^obtain ⟨[cd]", l) or re.match(r"^have [cd]\d+g? := And\.", l):
        for part in [p.strip() for p in l.split("; ")]:
            if part.startswith("clear "):
                continue
            mo = re.match(r"^obtain ⟨(.*)⟩ := (hw'?|[cd]\d+g)$", part)
            if mo:
                pats = [x.strip() for x in mo.group(1).split(",")]
                for i, nm in enumerate(pats):
                    if nm in ("-", "_"):
                        continue
                    t = mo.group(2)
                    for _ in range(i):
                        t = f"And.right ({t})"
                    if i + 1 < len(pats):
                        t = f"And.left ({t})"
                    paths[nm] = t
                continue
            mh = re.match(r"^have ([cd]\d+g?) := (.*)$", part)
            assert mh, ("unparsed open", part[:80])
            paths[mh.group(1)] = mh.group(2)
        for g in sorted(k for k in paths if k.endswith("g")):
            if not any(e.endswith(f"have {g} := {paths[g]}") for e in emit):
                out(depth, f"have {g} := {paths[g]}")
        named_at[0] = (len(emit), depth)
        continue
    m = re.match(r"^have e(\d+) : y\1 = x\1 := by first \| exact (st\d+)((?: [\w']+)*) \|", l)
    if m:
        adapter_call(m.group(2), m.group(3).split(), f"e{m.group(1)}", depth); continue
    m = re.match(r"^have k(\d+) : x\1 = (.+?) := by first \| exact (st\d+)((?: [\w']+)*) \|", l)
    if m:
        v = int(m.group(1)); adapter_call(m.group(3), m.group(4).split(), f"k{v}", depth)
        state.setdefault("pending_val", {})[v] = m.group(2); continue
    m = re.match(r"^subst k(\d+)$", l)
    if m:
        v = int(m.group(1)); state["val"][v] = (f"k{v}", state["pending_val"].pop(v)); continue
    m = re.match(r"^replace e(\d+) := e\1\.symm; subst e\1$", l)
    if m:
        state["sub"].setdefault(int(m.group(1)), f"(e{m.group(1)}).symm"); continue
    m = re.match(r"^have (hs\d+) : x(\d+) = 1 ∨ x\2 = 0 := by first \| exact \(ZirenDet\.bit_cases (c\d+)\)\.symm \|", l)
    if m:
        out(depth, f"have {m.group(1)} := (ZirenDet.bit_cases {proj(m.group(3))}).symm")
        state.setdefault("hsvar", {})[m.group(1)] = int(m.group(2)); continue
    m = re.match(r"^have (hs\d+) : x(\d+) = 0 ∨ x\2 = 1 := by first \| \(rcases mul_eq_zero\.mp \(show x\2 \* \(x\2 - 1\) = 0 by have q := (c\d+);", l)
    if m:
        h, b, c = m.group(1), int(m.group(2)), m.group(3)
        if CJBODY.get(int(c[1:])) == f"(x{b} * (x{b} - (1 : F))) = 0":
            out(depth, f"have {h} := ZirenDet.bit_cases {proj(c)}")
        else:
            out(depth, f"have {h} : w.v{b} = 0 ∨ w.v{b} = 1 := by rcases mul_eq_zero.mp (show w.v{b} * (w.v{b} - 1) = 0 by "
                       f"have q := {proj(c)}; (try dsimp only [cj{c[1:]}] at q); linear_combination q) with q | q; "
                       f"exact Or.inl q; exact Or.inr (sub_eq_zero.mp q)")
        state.setdefault("hsvar", {})[h] = b
        state.setdefault("hsbit", set()).add(h); continue
    m = re.match(r"^rcases (hs\d+) with \1 \| \1$", l)
    if m:
        saved[m.group(1)] = copy.deepcopy(state); out(depth, l); continue
    m = re.match(r"^· subst (hs\d+)$", l)
    if m:
        h = m.group(1); b = saved[h]["hsvar"][h]
        bit = h in saved[h].get("hsbit", set())
        state = copy.deepcopy(saved[h])
        if h not in seen_bullet:
            seen_bullet.add(h); state["val"][b] = (h, "(0 : F)" if bit else "(1 : F)")
            if not bit:
                branch_b = (b, h)
        else:
            state["val"][b] = (h, "(1 : F)" if bit else "(0 : F)")
        out(depth, "· skip"); continue
    m = re.match(r"^have e(\d+) : x\1 = 0 := by", l)
    if m:
        zeros.append((int(m.group(1)), l)); continue
    m = re.match(r"^subst e(\d+)$", l)
    if m and zeros:
        continue
    if l.startswith("exfalso"):
        need = {n for n, (nm, c) in state["val"].items() if nm.startswith("hs") and c == "(0 : F)"}
        group = onehot_group(need)
        name = f"ohn{len(helpers)}"
        vs = " ".join(f"x{v}" for v in group["vars"])
        hs_ = " ".join(f"(h{v} : x{v} = 0)" for v in group["vars"])
        helpers.append(f"theorem {name} {{{vs} : F}} (s : cj{group['sum']} {vs}) {hs_} : False := by\n  simp only [cj{group['sum']}] at s\n" + "\n".join(f"  subst h{v}" for v in group["vars"]) + "\n  norm_num at s\n")
        out(depth, f"exact ({name} {proj('c' + str(group['sum']))} " + " ".join(state["val"][v][0] for v in group["vars"]) + ").elim")
        continue
    if l.startswith("first | rfl | (simp only [outputs"):
        final(depth); continue
    raise SystemExit(f"unparsed line: {l[:120]}")

if NAMED and named:
    at, dep = named_at[0]
    emit[at:at] = [" " * dep + f"have {nm} := {paths[nm]}" for nm in sorted(named, key=lambda c: (c[0], int(c[1:])))]

imports = [l for l in L[:t0] if l.startswith("import ")]
header = [l for l in L[:t0] if l.startswith("set_option ")]
nsl = [l for l in L[:t0] if l.startswith("namespace ")]
opens = sorted({l for l in L if l.startswith("open ")})
ends = [l for l in L[end:] if l.startswith("end ")]

mods = []
items = list(adapters.items())
blocks = [(st, txt) for st, txt in items]
groups_ = [blocks[g : g + per] for g in range(0, len(blocks), per)] or [[]]
if helpers:
    groups_[0] = groups_[0] + [("", h) for h in helpers]
for gi, grp in enumerate(groups_):
    mod = f"{det}f{gi:02d}"
    mods.append(mod)
    deps = sorted({chunk_of[st] for st, _ in grp if st})
    txt = [l for l in imports if not l.startswith(f"import {mp}.C")] + [f"import {mp}.{c}" for c in deps]
    txt += [""] + header + [""] + nsl + opens + [""] + [t for _, t in grp] + ends
    write(os.path.join(d, mod + ".lean"), "\n".join(txt) + "\n")

thm = L[t0 : by + 1]
new = imports + [f"import {mp}.{m}" for m in mods] + [""] + header + [""] + nsl + opens + [""] + thm + emit + [""] + ends
if not NAMED and sum(len(x) + 1 for x in new) > INLINE_LIMIT:
    os.execve(sys.executable, [sys.executable] + sys.argv, {**os.environ, "FLAT_NAMED": "1"})
if not os.path.exists(os.path.join(d, det + ".lean.preflat")):
    write(os.path.join(d, det + ".lean.preflat"), src)
write(os.path.join(d, det + ".lean"), "\n".join(new) + "\n")

deps = [f" {mp}/P.olean " + " ".join(f"{mp}/{c}.olean" for c in sorted({chunk_of[st] for st, _ in g if st})) for g in groups_]
add_modules(root, mp, det, mods, deps, once=True)
print(f"{det}: adapters={len(adapters)} helpers={len(helpers)} modules={len(mods)} lines={len(new)} bytes={sum(len(x)+1 for x in new)}")

#!/usr/bin/env python3
"""lift_steps.py ROOT PREFIX CHUNK THEOREM [lemmas_per_chunk]: lift the self-contained top-level
steps of one theorem into lemmas in their own modules.

A step `have X : T := by …` becomes `theorem THEOREM__X (vars) (hyps) : T`, taking the hypotheses
its `clear * - …` keeps or, without one, those its text names (with the range hypotheses of the
variables they mention); the step then calls the lemma.  A final `clear * - …` and the tactics after
it become one more lemma with the goal as statement, unless an earlier tactic may have changed it.
Binder types come from the signature, `obtain … := ⟨_, rfl⟩`, `ZirenDet.lift_le`, earlier `have`
statements and top-level `subst`.
"""
import os
import re
import sys

from leanmod import add_modules, read, theorem_span, write

root, mp, chunk, thm = sys.argv[1:5]
per = int(sys.argv[5]) if len(sys.argv) > 5 else 8
path = os.path.join(root, mp, chunk + ".lean")
lines = read(path).split("\n")
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_']*")

start, by = theorem_span(lines, thm)
end = next((i for i in range(by + 1, len(lines)) if lines[i][:1] not in ("", " ")), len(lines))
stmt = " ".join(l.strip() for l in lines[start:by + 1])
stmt = stmt[len(f"theorem {thm}"):].rstrip()
assert stmt.endswith(":= by")
stmt = stmt[: -len(":= by")].strip()

ctx = {}
i, depth, goal = 0, 0, None
while i < len(stmt):
    c = stmt[i]
    if c in "({" and depth == 0:
        j, d = i, 0
        while True:
            if stmt[j] in "({[⟨":
                d += 1
            elif stmt[j] in ")}]⟩":
                d -= 1
                if d == 0:
                    break
            j += 1
        inner = stmt[i + 1 : j]
        k, d = 0, 0
        while k < len(inner):
            if inner[k] in "({[⟨":
                d += 1
            elif inner[k] in ")}]⟩":
                d -= 1
            elif d == 0 and inner.startswith(" : ", k):
                break
            k += 1
        for n in inner[:k].split():
            ctx[n] = inner[k + 3 :].strip()
        i = j + 1
    elif c == ":" and depth == 0:
        goal = stmt[i + 1 :].strip()
        break
    else:
        i += 1
assert goal is not None

body = lines[by + 1 : end]
stmts = []
for l in body:
    if l.startswith("  ") and not l.startswith("   "):
        stmts.append([l])
    elif stmts:
        stmts[-1].append(l)
    else:
        stmts.append([l])

OBT = re.compile(r"^  obtain ⟨(\S+), (\S+)⟩ : ∃ (\S+) : (.+?), \3 = (.+) := ⟨_, rfl⟩\s*$")
LIFT = re.compile(r"^  obtain ⟨(\S+), (\S+), (\S+), (\S+)⟩ := ZirenDet\.lift_le (\S+) (\S+)\s*$")
HAVE = re.compile(r"^  have (\S+) : (.*) := by\s*(.*)$")
HAVE1 = re.compile(r"^  have (\S+) : (.*?) := (?!by)(.+)$")
SORTS = {"ℤ", "F", "ℕ", "Int", "Nat"}
CLEAR = re.compile(r"^\s*clear \* - ([^;]*?)\s*$")


def lemma(name, keep, typ, tac):
    toks = set(IDENT.findall(typ + " " + " ".join(ctx[h] for h in keep)))
    vs = [v for v in ctx if v in toks and v not in keep]
    bind = " ".join(f"({v} : {ctx[v]})" for v in vs) + " " + " ".join(f"({h} : {ctx[h]})" for h in keep)
    text = f"theorem {name}\n    {bind.strip()} :\n    {typ} := by\n" + "\n".join(tac) + "\n"
    return text, f"{name} {' '.join(vs + keep)}"


SUBST = re.compile(r"^  subst (\S+)\s*$")


def subst(h):
    lhs, rhs = (t.strip() for t in ctx[h].split(" = ", 1))
    v, e = (rhs, lhs) if rhs in ctx and ctx[rhs] in SORTS else (lhs, rhs)
    assert v in ctx and ctx[v] in SORTS, ctx[h]
    rep = f"({e} : {ctx[v]})"
    pat = re.compile(rf"(?<![\w.']){re.escape(v)}(?![\w'])")
    del ctx[v], ctx[h]
    for k in ctx:
        ctx[k] = pat.sub(rep, ctx[k])


out, lemmas, goal_moved = [], [], False
for s in stmts:
    head = s[0]
    m = LIFT.match(head)
    if m and len(s) == 1 and m.group(6) in ctx:
        n, ha, hb, xn, x, b = m.groups()
        c = ctx[b].split(" ≤ ", 1)[1].strip()
        ctx[n], ctx[ha], ctx[hb], ctx[xn] = "ℤ", f"0 ≤ {n}", f"{n} ≤ (({c} : ℕ) : ℤ)", f"{x} = ({n} : F)"
        out.extend(s)
        continue
    m = SUBST.match(head)
    if m and len(s) == 1 and m.group(1) in ctx:
        subst(m.group(1))
        out.extend(s)
        continue
    m = OBT.match(head)
    if m and len(s) == 1:
        a, ha, _, ty, e = m.groups()
        ctx[a], ctx[ha] = ty, f"{a} = {e}"
        out.extend(s)
        continue
    m = HAVE.match(head)
    if m:
        x, ty, rest = m.groups()
        keep, tac = None, []
        if not rest and len(s) > 1:
            cm = CLEAR.match(s[1])
            if cm:
                keep = cm.group(1).split()
                tac = [t[2:] if t.startswith("    ") else t for t in s[2:]]
            else:
                used = set(IDENT.findall("\n".join(s[1:])))
                keep = [h for h in ctx if h in used and ctx[h] not in SORTS]
                toks = set(IDENT.findall(ty + " " + " ".join(ctx[h] for h in keep)))
                keep += [f"h{v}" for v in ctx if v in toks and ctx[v] in SORTS and f"h{v}" in ctx and f"h{v}" not in keep]
                tac = [t[2:] if t.startswith("    ") else t for t in s[1:]]
        elif rest.startswith("clear * - ") and ";" in rest and len(s) == 1:
            keep = rest[len("clear * - "):].split(";", 1)[0].split()
            tac = ["  " + rest.split(";", 1)[1].strip()]
        elif rest and len(s) == 1:
            used = set(IDENT.findall(rest))
            keep = [h for h in ctx if h in used and ctx[h] not in SORTS]
            toks = set(IDENT.findall(ty + " " + " ".join(ctx[h] for h in keep)))
            keep += [f"h{v}" for v in ctx if v in toks and ctx[v] in SORTS and f"h{v}" in ctx and f"h{v}" not in keep]
            tac = ["  " + rest.strip()]
        if keep and tac and all(h in ctx for h in keep):
            name = f"{thm}__{x}".replace("'", "_p")
            text, call = lemma(name, keep, ty, tac)
            lemmas.append(text)
            out.append(f"  have {x} : {ty} := {call}")
            ctx[x] = ty
            continue
        ctx[x] = ty
        out.extend(s)
        continue
    m = HAVE1.match(head)
    if m and len(s) == 1:
        ctx[m.group(1)] = m.group(2)
        out.extend(s)
        continue
    if not re.match(r"  (obtain|clear|subst)\b", head) or re.match(r"  \S+ .* at .*⊢", head):
        goal_moved = True
    out.extend(s)

ci = max((k for k, l in enumerate(out) if l.startswith("  clear * - ") and CLEAR.match(l)), default=-1)
if ci >= 0 and not goal_moved and all(not l.startswith("  have ") and not l.startswith("  obtain ") for l in out[ci + 1 :]):
    keep = CLEAR.match(out[ci]).group(1).split()
    tac = [l for l in out[ci + 1 :] if l.strip()]
    if keep and tac and all(h in ctx for h in keep):
        name = f"{thm}__goal"
        text, call = lemma(name, keep, goal, tac)
        lemmas.append(text)
        out[ci:] = [f"  exact {call}"]

pre = lines[:start]
imports = [l for l in pre if l.startswith("import ")]
header = [l for l in pre if not l.startswith("import ")]
ns_close = [l for l in lines[end:] if l.startswith("end ")]
groups = [lemmas[k : k + per] for k in range(0, len(lemmas), per)]
mods = []
for g, grp in enumerate(groups):
    mod = f"{chunk}s{g:02d}"
    mods.append(mod)
    txt = "\n".join(imports) + "\n" + "\n".join(header) + "\n" + "\n".join(grp) + "\n" + "\n".join(ns_close) + "\n"
    write(os.path.join(root, mp, mod + ".lean"), txt)
new = imports + [f"import {mp}.{m}" for m in mods] + header + lines[start : by + 1] + out + lines[end:]
write(path + ".orig", "\n".join(lines))
write(path, "\n".join(new))
add_modules(root, mp, chunk, mods)
print(f"{chunk}: {len(lemmas)} lemmas in {len(mods)} chunks; theorem body {len(body)} -> {len(out)} lines")

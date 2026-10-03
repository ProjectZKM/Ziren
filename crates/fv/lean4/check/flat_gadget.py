#!/usr/bin/env python3
"""flat_gadget.py IN OUT [THEOREM]: rewrite a snippet theorem (default `gadget_det`) so it never
opens all of its constraint conjuncts.

A snippet opens every constraint conjunct as its own hypothesis, either as `have` lines
(`have c0g := …; have c0 := …`) or as `obtain` patterns (`obtain ⟨c0g, c48g, …⟩ := hw; obtain
⟨c0, c1, …⟩ := c0g; …`), and every later tactic pays for that context.  In the `have` form only
the chunk groups stay hypotheses and each use of a conjunct `cN`/`dN` becomes its projection from
the group.  In the `obtain` form no conjunct is introduced: `hw` stays whole and each use of a
conjunct becomes its projection from `hw` (Secp256k1Decompress's `row_spec`: over 30 min opened,
6 min projected)."""
import re, sys

from leanmod import read, theorem_span, write

src, out = sys.argv[1:3]
thm = sys.argv[3] if len(sys.argv) > 3 else "gadget_det"
L = read(src).split("\n")
t0, by = theorem_span(L, thm)
paths, body, groups = {}, [], []
OPEN = re.compile(r"^have ([cd]\d+g?) := (.*)$")
OBT = re.compile(r"^obtain ⟨([^⟩]*)⟩ := (\S+)$")


def nested(names, e):
    """Projections of `e : n₀ ∧ (n₁ ∧ (… ∧ nₖ))` onto each name of the pattern ⟨n₀, …, nₖ⟩."""
    out = {}
    for i, n in enumerate(names):
        p = e
        for _ in range(i):
            p = f"And.right ({p})"
        out[n] = p if i == len(names) - 1 else f"And.left ({p})"
    return out


rest = []
for i in range(by + 1, len(L)):
    l = L[i]
    if l[:1] not in ("", " "):
        rest = L[i:]
        break
    s = l.strip()
    if re.match(r"^have [cd]\d+g? := And\.", s):
        for part in [p.strip() for p in s.split("; ")]:
            if part.startswith("clear "):
                continue
            m = OPEN.match(part)
            assert m, part[:80]
            nm, ex = m.groups()
            if nm.endswith("g"):
                groups.append(f"  have {nm} := {ex}")
            else:
                paths[nm] = ex
        continue
    if re.match(r"^obtain ⟨[cd]0g?, ", s):
        src_of = {}
        for part in [p.strip() for p in s.split("; ")]:
            m = OBT.match(part)
            assert m, part[:80]
            names, e = [n.strip() for n in m.group(1).split(",")], m.group(2)
            for n, p in nested(names, src_of.get(e, e)).items():
                src_of[n] = f"({p})"
        paths.update({n: p for n, p in src_of.items() if not n.endswith("g")})
        groups.append(None)
        continue
    body.append(l)
TOK = re.compile(r"(?<![\w.'])([cd]\d+)(?![\w'])")
used = sorted({m.group(1) for l in body for m in TOK.finditer(l) if m.group(1) in paths},
              key=lambda c: (c[0], int(c[1:])))
missing = {m.group(1) for l in body for m in TOK.finditer(l) if m.group(1) not in paths}
if None in groups:
    head = []
    new_body = [TOK.sub(lambda m: f"{paths[m.group(1)]}" if m.group(1) in paths else m.group(1), l) for l in body]
else:
    head = groups
    new_body = [TOK.sub(lambda m: f"({paths[m.group(1)]})" if m.group(1) in paths else m.group(1), l) for l in body]
out_l = L[: by + 1] + head + new_body + rest
write(out, "\n".join(out_l))
print(f"{thm}: opened={len(paths)} used={len(used)} body={len(body)} unresolved={sorted(missing)[:10]} "
      f"bytes={sum(len(x) + 1 for x in out_l)}")

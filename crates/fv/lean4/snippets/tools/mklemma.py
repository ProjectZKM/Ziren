"""mklemma.py: state a group of a chip's constraints as a standalone Lean lemma.

`build` turns the constraints `idx` into hypotheses `e<i>` over field variables `x<N>`; the
columns of `lifts` (column -> (name, bound)) enter as integers with `0 ≤ name ≤ bound` and appear
cast in the hypotheses.  It returns the lemma and the term that applies it in a context where
every column of `all_lifts` has been replaced by the cast of its integer and the constraints are
named `c<i>`.
"""
import re

def load(path):
    out = {}
    for l in open(path).read().split('\n'):
        m = re.match(r'c(\d+): (.*?)( ∧)?$', l)
        if m:
            out[int(m.group(1))] = m.group(2)
    return out

def subst(text, lifts):
    def rep(m):
        n = int(m.group(1))
        return f"({lifts[n][0]} : F)" if n in lifts else f"x{n}"
    return re.sub(r'w\.v(\d+)', rep, text)

def build(cons, idx, lifts, goal, name, tactic, all_lifts=None, name_c=None, name_x=None):
    all_lifts = all_lifts or lifts
    name_c = name_c or (lambda i: f"c{i}")
    name_x = name_x or (lambda n: f"x{n}")
    used = set()
    for i in idx:
        used |= {int(n) for n in re.findall(r'w\.v(\d+)', cons[i])}
    fvars = sorted(n for n in used if n not in lifts)
    ints = [lifts[n] for n in sorted(lifts)]
    lines = [f"theorem {name}"]
    if ints:
        lines.append("    (" + " ".join(v for v, _ in ints) + " : ℤ)")
    if fvars:
        lines.append("    (" + " ".join(f"x{n}" for n in fvars) + " : F)")
    for v, b in ints:
        lines.append(f"    (h{v} : 0 ≤ {v} ∧ {v} ≤ {b})")
    for i in idx:
        lines.append(f"    (e{i} : {subst(cons[i], lifts)})")
    lines.append(f"    : {goal} := by")
    lines.append(tactic)
    args = [v for v, _ in ints]
    args += [f"(({all_lifts[n][0]} : ℤ) : F)" if n in all_lifts else name_x(n) for n in fvars]
    args += [f"h{v}" for v, _ in ints]
    args += [name_c(i) for i in idx]
    return "\n".join(lines) + "\n", f"{name} " + " ".join(args)

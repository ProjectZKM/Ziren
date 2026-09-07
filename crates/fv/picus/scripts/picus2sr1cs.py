#!/usr/bin/env python3
"""Convert the modules of a `.picus` file to Picus (Veridise, GitHub) `.sr1cs` files and run
the solver on each one.

The public Picus reads circom / r1cs / sr1cs.  `.sr1cs` is an s-expression R1CS with range
facts (`extra-constraint (< (var i) (int c))`), so every polynomial constraint is flattened into
rank-1 constraints through auxiliary wires.  Two approximations, both reported:

* a `(call [outs] helper [ins])` of an abstract helper (byte table op) has no R1CS form; its
  outputs are declared as extra *inputs*.  That is the same assumption the Lean theorem makes
  (`h_<helper>` : the helper relation is deterministic) when the helper's inputs are module
  inputs; when they are internal wires it over-approximates determinism (can hide a bug, never
  invents one).
* `(<=> ...)` (comparison summaries) has no R1CS form; modules containing one are skipped.

usage: picus2sr1cs.py <picus-file>... [--out DIR] [--run] [--timeout MS] [--jobs N]
"""
import argparse
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

TOOLS = "/data/stephen/tools"
RACKET = f"{TOOLS}/racket/bin/racket"
PICUS = f"{TOOLS}/Picus/picus.rkt"
CVC5DIR = f"{TOOLS}/cvc5gpl/cvc5-Linux-x86_64-static-gpl/bin"


def tokenize(s):
    return re.findall(r"\(|\)|\[|\]|[^\s()\[\]]+", s)


def parse(tokens):
    out = []
    stack = [out]
    for t in tokens:
        if t in "([":
            new = []
            stack[-1].append(new)
            stack.append(new)
        elif t in ")]":
            stack.pop()
        else:
            stack[-1].append(t)
    return out


class Flattener:
    def __init__(self, prime):
        self.p = prime
        self.ids = {}  # x_name -> id (0 is the constant wire)
        self.next_id = 1
        self.constraints = []  # (A, B, C) each a dict id->coeff
        self.extra = []
        self.approx = []
        self.labels = {}

    def var(self, name):
        if name not in self.ids:
            self.ids[name] = self.next_id
            self.labels[self.next_id] = name
            self.next_id += 1
        return self.ids[name]

    def aux(self):
        i = self.next_id
        self.next_id += 1
        return i

    def const(self, c):
        return {0: c % self.p}

    def add(self, a, b, sign=1):
        r = dict(a)
        for k, v in b.items():
            r[k] = (r.get(k, 0) + sign * v) % self.p
        return {k: v for k, v in r.items() if v}

    def scale(self, a, c):
        return {k: (v * c) % self.p for k, v in a.items() if (v * c) % self.p}

    def is_const(self, a):
        return all(k == 0 for k in a)

    def lin(self, e):
        """Linear combination (dict id->coeff) equal to expression `e`, adding aux wires."""
        if isinstance(e, str):
            if e.startswith("x_"):
                return {self.var(e): 1}
            if re.fullmatch(r"-?\d+", e):
                return self.const(int(e))
            raise ValueError(f"atom {e}")
        op = e[0]
        if op == "+":
            r = self.lin(e[1])
            for x in e[2:]:
                r = self.add(r, self.lin(x))
            return r
        if op == "-":
            if len(e) == 2:
                return self.scale(self.lin(e[1]), self.p - 1)
            r = self.lin(e[1])
            for x in e[2:]:
                r = self.add(r, self.lin(x), -1)
            return r
        if op == "*":
            r = self.lin(e[1])
            for x in e[2:]:
                b = self.lin(x)
                if self.is_const(b):
                    r = self.scale(r, b.get(0, 0))
                elif self.is_const(r):
                    r = self.scale(b, r.get(0, 0))
                else:
                    t = self.aux()
                    self.constraints.append((r, b, {t: 1}))
                    r = {t: 1}
            return r
        if op == "/":
            b = self.lin(e[2])
            assert self.is_const(b), "division by a non-constant"
            inv = pow(b.get(0, 0), self.p - 2, self.p)
            return self.scale(self.lin(e[1]), inv)
        if op == "^":
            base = self.lin(e[1])
            k = int(e[2])
            r = self.const(1)
            for _ in range(k):
                r = self.lin(["*", ("__lin__", r), ("__lin__", base)]) if False else self.mul(r, base)
            return r
        raise ValueError(f"op {op}")

    def mul(self, a, b):
        if self.is_const(b):
            return self.scale(a, b.get(0, 0))
        if self.is_const(a):
            return self.scale(b, a.get(0, 0))
        t = self.aux()
        self.constraints.append((a, b, {t: 1}))
        return {t: 1}

    def as_var(self, a):
        """A wire id equal to the linear combination `a`."""
        if len(a) == 1 and 0 not in a and list(a.values())[0] == 1:
            return list(a.keys())[0]
        t = self.aux()
        self.constraints.append((a, {0: 1}, {t: 1}))
        return t

    def eq0(self, e):
        a = self.lin(e)
        self.constraints.append((a, {0: 1}, {}))

    def le(self, e, c, strict):
        """Range fact as a bit decomposition (cvc5's finite-field theory has no order)."""
        v = self.as_var(self.lin(e))
        bound = c if strict else c + 1
        k = max(1, (bound - 1).bit_length())
        if (1 << k) != bound:
            self.approx.append(f"range {bound} widened to {1 << k}")
        acc = {}
        for i in range(k):
            b = self.aux()
            self.constraints.append(({b: 1}, {b: 1}, {b: 1}))
            acc = self.add(acc, {b: (1 << i) % self.p})
        self.constraints.append((acc, {0: 1}, {v: 1}))

    def lt_vars(self, a, b):
        self.approx.append("dropped var<var comparison")


def convert_module(prime, name, forms):
    """Returns (sr1cs text, info) or (None, reason)."""
    f = Flattener(prime)
    inputs, outputs = [], []
    calls = 0
    for fm in forms:
        if fm[0] == "input":
            inputs.append(fm[1])
        elif fm[0] == "output":
            outputs.append(fm[1])
    # declare interface wires first so ids are stable
    for x in inputs + outputs:
        f.var(x)
    for fm in forms:
        head = fm[0]
        if head in ("input", "output", "post-condition", "assume-deterministic"):
            continue
        if head == "call":
            outs, helper, ins = fm[1], fm[2], fm[3]
            for x in outs:
                if x not in inputs:
                    inputs.append(x)
                    f.var(x)
            for i in ins:
                f.lin(i)
            calls += 1
            continue
        if head == "assert":
            c = fm[1]
            op = c[0]
            if op == "=":
                lhs, rhs = c[1], c[2]
                if rhs == "0":
                    f.eq0(lhs)
                else:
                    f.eq0(["-", lhs, rhs])
            elif op == "<=":
                if isinstance(c[2], str) and re.fullmatch(r"-?\d+", c[2]):
                    f.le(c[1], int(c[2]), False)
                else:
                    return None, "non-constant <="
            elif op == "<":
                if isinstance(c[2], str) and re.fullmatch(r"-?\d+", c[2]):
                    f.le(c[1], int(c[2]), True)
                else:
                    f.lt_vars(c[1], c[2])
            elif op in ("<=>", "=>", "||", "&&", "!", "or", "and", "not", "iff"):
                return None, f"logical constraint {op}"
            else:
                return None, f"unknown assert {op}"
        else:
            return None, f"unknown form {head}"
    lines = [f"(prime-number {prime})"]
    for x in inputs:
        lines.append(f"(in {f.ids[x]})")
    for x in outputs:
        lines.append(f"(out {f.ids[x]})")
    for i, lab in f.labels.items():
        lines.append(f"(label {i} {lab})")

    def blk(d):
        return "[" + " ".join(f"({v} {k})" for k, v in d.items()) + " ]"

    for a, b, c in f.constraints:
        lines.append(f"(constraint {blk(a)} {blk(b)} {blk(c)})")
    lines += f.extra
    info = {
        "inputs": len(inputs),
        "outputs": len(outputs),
        "wires": f.next_id,
        "constraints": len(f.constraints),
        "ranges": len(f.extra),
        "helper_calls": calls,
        "approx": sorted(set(f.approx)),
    }
    return "\n".join(lines) + "\n", info


def split_modules(path):
    forms = parse(tokenize(open(path).read()))
    prime = None
    modules = []
    cur = None
    for fm in forms:
        if fm[0] == "prime-number":
            prime = int(fm[1])
        elif fm[0] == "begin-module":
            cur = (fm[1], [])
        elif fm[0] == "end-module":
            modules.append(cur)
            cur = None
        elif cur is not None:
            cur[1].append(fm)
    return prime, modules


def run_picus(sr1cs, timeout_ms):
    env = dict(os.environ)
    env["PATH"] = f"{CVC5DIR}:{TOOLS}/racket/bin:" + env.get("PATH", "")
    env["PLTUSERHOME"] = f"{TOOLS}/plt"
    try:
        r = subprocess.run(
            [RACKET, PICUS, "--solver", "cvc5", "--timeout", str(timeout_ms), "--json", "-", sr1cs],
            capture_output=True, text=True, timeout=timeout_ms / 1000 * 40 + 120, env=env,
        )
    except subprocess.TimeoutExpired:
        return "tool-timeout", ""
    out = r.stdout
    verdict = "unknown"
    detail = ""
    for line in out.splitlines():
        try:
            j = json.loads(line)
        except Exception:
            continue
        if isinstance(j, dict) and j.get("level") in ("INFO", "CRITICAL", "ERROR") or True:
            msg = json.dumps(j)
            if '"safe"' in msg or "is safe" in msg or "safe (" in msg:
                pass
        s = json.dumps(j)
        if "unsafe" in s and "unknown" not in s:
            verdict = "unsafe"
            detail = s[:400]
        elif '"safe' in s or ' safe' in s:
            if verdict != "unsafe":
                verdict = "safe"
    if verdict == "unknown":
        tail = (r.stdout + r.stderr)[-600:]
        detail = tail.replace("\n", " | ")
    return verdict, detail


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--out", default="sr1cs_out")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--timeout", type=int, default=20000)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--report", default=None)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    jobs = []
    report = []
    for path in a.files:
        chip = os.path.basename(path).rsplit(".", 1)[0]
        prime, modules = split_modules(path)
        for name, forms in modules:
            # abstract helpers have no constraints: skip
            if not any(fm[0] == "assert" for fm in forms):
                continue
            if name == "top":
                continue  # selector shape: no inputs, determinism is not the question
            text, info = convert_module(prime, name, forms)
            entry = {"chip": chip, "module": name}
            if text is None:
                entry["verdict"] = "skipped"
                entry["reason"] = info
                report.append(entry)
                continue
            entry.update(info)
            out = os.path.join(a.out, f"{chip}__{name}.sr1cs")
            open(out, "w").write(text)
            entry["sr1cs"] = out
            report.append(entry)
            if a.run:
                jobs.append(entry)
    if a.run:
        def work(entry):
            v, d = run_picus(entry["sr1cs"], a.timeout)
            entry["verdict"] = v
            if d:
                entry["detail"] = d
            print(f"{entry['chip']:28} {entry['module']:36} {v}", flush=True)
        with ThreadPoolExecutor(max_workers=a.jobs) as ex:
            list(ex.map(work, jobs))
    if a.report:
        json.dump(report, open(a.report, "w"), indent=1)
    counts = {}
    for e in report:
        counts[e.get("verdict", "converted")] = counts.get(e.get("verdict", "converted"), 0) + 1
    print("summary:", counts)


if __name__ == "__main__":
    main()

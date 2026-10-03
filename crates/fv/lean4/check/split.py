#!/usr/bin/env python3
"""Split one generated picus Lean file into a prelude module plus theorem chunk modules.

Every top-level declaration keeps its namespace; defs/structures with no theorem among their
(transitive) dependencies go to the prelude, every other declaration is placed by dependency
level (1 + max level of the earlier declarations it names) and bin-packed by size within its
level.  A chunk imports the prelude and exactly the chunks holding its dependencies, so the
chunks of one level elaborate in parallel.  `Check.lean` imports every chunk and prints the
axioms of each `deterministic`, which is the closure test (no `sorryAx`).

usage: split.py FILE OUTROOT MODPREFIX [chunk_bytes]
writes OUTROOT/MODPREFIX/{P,Cnnn,Check}.lean and OUTROOT/Makefile.
"""
import os
import re
import sys

src, root, mp = sys.argv[1], sys.argv[2], sys.argv[3]
CHUNK = int(sys.argv[4]) if len(sys.argv) > 4 else 40_000

DECL = re.compile(
    r"^(?:@\[[^\]]*\]\s*)?(?:(?:noncomputable|protected|private|unsafe|partial)\s+)*"
    r"(theorem|lemma|def|abbrev|structure|instance|inductive|class|opaque|axiom)\b\s*([^\s:({\[]*)"
)
IDENT = re.compile(r"[A-Za-z_Ͱ-Ͽ][A-Za-z0-9_'!?Ͱ-Ͽ₀-₉]*")

lines = open(src, encoding="utf-8").read().split("\n")
imports, options, opens = [], [], []
ns = []
decls = []
cur = None
pending = []
i = 0
anon = 0
while i < len(lines):
    ln = lines[i]
    col0 = ln[:1] not in ("", " ", "\t")
    if not col0:
        if cur is not None:
            cur["text"].append(ln)
        i += 1
        continue
    if ln.startswith("/--"):
        cur = None
        blk = [ln]
        while "-/" not in lines[i][3 if len(blk) == 1 else 0:]:
            i += 1
            blk.append(lines[i])
        pending.extend(blk)
        i += 1
        continue
    if ln.startswith("/-"):
        cur = None
        while "-/" not in lines[i][2 if lines[i] is ln else 0:]:
            i += 1
        i += 1
        continue
    if ln.startswith("--"):
        i += 1
        continue
    m = DECL.match(ln)
    if m:
        name = m.group(2)
        if not name:
            anon += 1
            name = f"_anon{anon}"
        cur = {"kind": m.group(1), "name": name, "ns": tuple(ns), "text": pending + [ln]}
        pending = []
        decls.append(cur)
    elif ln.startswith("@["):
        cur = None
        pending.append(ln)
    elif ln.startswith("import "):
        imports.append(ln)
    elif ln.startswith("set_option ") and " in" not in ln.split("--")[0][-4:]:
        options.append(ln)
        cur = None
    elif ln.startswith("namespace "):
        ns.append(ln.split()[1])
        cur = None
    elif ln.startswith("section"):
        ns.append(None)
        cur = None
    elif ln.startswith("end"):
        ns.pop()
        cur = None
    elif ln.startswith("open "):
        if ln not in opens:
            opens.append(ln)
        cur = None
    elif ln.startswith("#"):
        cur = None
    else:
        if cur is not None:
            cur["text"].append(ln)
    i += 1
assert not ns, f"unbalanced namespaces {ns}"

by_short = {}
for k, d in enumerate(decls):
    d["idx"] = k
    by_short.setdefault(d["name"].split(".")[-1], []).append(k)
    d["size"] = sum(len(t) + 1 for t in d["text"])

for d in decls:
    toks = set()
    body = "\n".join(d["text"][0:])
    for t in IDENT.findall(body):
        toks.add(t)
    for t in re.findall(r"[A-Za-z0-9_'.]+", body):
        for p in t.split("."):
            toks.add(p)
    own = d["name"].split(".")[-1]
    deps = set()
    for t in toks:
        for k in by_short.get(t, ()):
            if k < d["idx"] and not (t == own and decls[k]["ns"] != d["ns"] and False):
                deps.add(k)
    d["deps"] = deps

THM = ("theorem", "lemma")
for d in decls:
    d["thmdep"] = d["kind"] in THM or any(decls[k]["thmdep"] for k in d["deps"])
    d["level"] = 0 if not d["thmdep"] else 1 + max([decls[k]["level"] for k in d["deps"]] + [0])

prelude = [d for d in decls if not d["thmdep"]]
rest = [d for d in decls if d["thmdep"]]
chunks = []
for lvl in sorted({d["level"] for d in rest}):
    items = sorted([d for d in rest if d["level"] == lvl], key=lambda d: -d["size"])
    bins = []
    for d in items:
        if d["size"] >= CHUNK or not bins or bins[-1]["size"] + d["size"] > CHUNK:
            bins.append({"items": [], "size": 0})
        bins[-1]["items"].append(d)
        bins[-1]["size"] += d["size"]
    chunks.extend(bins)
for c, b in enumerate(chunks):
    b["mod"] = f"C{c:03d}"
    b["items"].sort(key=lambda d: d["idx"])
    for d in b["items"]:
        d["chunk"] = c
for d in prelude:
    d["chunk"] = None

os.makedirs(os.path.join(root, mp), exist_ok=True)


def write_if_changed(path, text):
    if os.path.exists(path) and open(path, encoding="utf-8").read() == text:
        return
    open(path, "w", encoding="utf-8").write(text)


def emit(path, extra_imports, items, tail=""):
    out = list(imports) + [f"import {m}" for m in extra_imports] + [""] + options + [""]
    groups = []
    for d in items:
        if groups and groups[-1][0] == d["ns"]:
            groups[-1][1].append(d)
        else:
            groups.append((d["ns"], [d]))
    for nsl, ds in groups:
        real = [n for n in nsl if n is not None]
        for n in real:
            out.append(f"namespace {n}")
        out.extend(opens)
        out.append("")
        for d in ds:
            out.extend(d["text"])
            out.append("")
        for n in reversed(real):
            out.append(f"end {n}")
        out.append("")
    out.append(tail)
    write_if_changed(path, "\n".join(out) + "\n")


emit(os.path.join(root, mp, "P.lean"), [], prelude)
mk = [f"R := {root}", "LEANRUN ?= $(R)/run_mod.sh", "", ".PHONY: all check", "all: check", ""]
mk.append(f"{mp}/P.olean: {mp}/P.lean\n\t$(LEANRUN) {mp} P\n")
for b in chunks:
    need = sorted({decls[k]["chunk"] for d in b["items"] for k in d["deps"]} - {None, b["items"][0]["chunk"]})
    imps = [f"{mp}.P"] + [f"{mp}.{chunks[c]['mod']}" for c in need]
    emit(os.path.join(root, mp, b["mod"] + ".lean"), imps, b["items"])
    deps = " ".join([f"{mp}/P.olean"] + [f"{mp}/{chunks[c]['mod']}.olean" for c in need])
    mk.append(f"{mp}/{b['mod']}.olean: {mp}/{b['mod']}.lean {deps}\n\t$(LEANRUN) {mp} {b['mod']}\n")
dets = [d for d in decls if d["name"] == "deterministic"]
chk = [f"#print axioms {'.'.join([n for n in d['ns'] if n] + ['deterministic'])}" for d in dets]
write_if_changed(os.path.join(root, mp, "Check.lean"),
    "\n".join(imports + [f"import {mp}.{b['mod']}" for b in chunks] + [""] + chk + ['#print "PICUS_FILE_DONE"', ""])
)
alld = " ".join(f"{mp}/{b['mod']}.olean" for b in chunks)
mk.append(f"check: {alld}\n\t$(LEANRUN) {mp} Check\n")
open(os.path.join(root, "Makefile"), "w").write("\n".join(mk))

print(f"decls={len(decls)} prelude={len(prelude)} chunks={len(chunks)} deterministic={len(dets)}")

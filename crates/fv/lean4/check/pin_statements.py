#!/usr/bin/env python3
"""pin_statements.py: pin the determinism statements of the generated chip files.

    pin_statements.py snapshot ZIRENDET_DIR > statements.json
    pin_statements.py compare OLD.json NEW.json|ZIRENDET_DIR [--all-info]

A theorem count says nothing about what each theorem claims.  `snapshot` records, for every
module of every generated chip file, the parts that give its determinism theorem its meaning:
the theorem statements, the helper hypotheses, the `inputs`, `outputs` and `assumed` ports, which
ports share a column, and the interface definitions.  Constraint bodies and the witness layout
change with every AIR edit, so they are recorded for information only.

`compare` classifies every difference per module.  A WEAKENING (a module or a pinned theorem
removed, an input, assumed value or helper hypothesis gained, an output or a postcondition
conjunct lost, a port carried by another column or newly sharing a column with another port, a
statement or interface definition reshaped, a helper relation redefined, an axiom declared)
exits 1; everything else is reported as INFO and exits 0.  Bad arguments or an unreadable tree
exit 2.

Columns are named `base#k`: the column's field name from the generator's doc comment with its
index suffix removed, numbered by order among the columns of that name (`derived` for the
unnamed columns the extractor introduces for expressions).  A port is recorded as
`provenance <- column`: its lookup provenance (`input_origins`, `output_origins`) and the name,
without the number, of the column that carries it.  Renumbering or inserting columns therefore
changes nothing that is pinned.  See ../README.md."""
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

FORMAT = "ziren-fv-statements/1"
PINNED_THEOREMS = ("deterministic", "postconditions")
INTERFACE_DEFS = ("inputs", "outputs", "assumed", "rel", "constraints")
PORT_DEFS = ("inputs", "outputs", "assumed")

CHIP_NS = re.compile(r"^namespace ZirenDet\.Chips\.(\w+)$")
MODULE_TITLE = re.compile(r"^/-! ### Module `([^`]*)` -/$")
DOC_NAME = re.compile(r"^/-- `(.*)` -/$")
FIELD = re.compile(r"^v(\d+) : F$")
VAR = re.compile(r"\b(w'?)\.v(\d+)\b")
DECL = re.compile(
    r"^(?:(?:private|protected|noncomputable|@\[[^\]]*\])\s+)*"
    r"(def|theorem|lemma|abbrev|opaque|axiom|structure|instance|section)\s+([^\s(:{\[]+)")
RANGE_FACT = re.compile(r"\.val (?:≤|<) [0-9]+\s*(?:∧)?\s*$")
HELPER_CALL = re.compile(r"\b([A-Za-z_][\w]*)\.rel \[")
LINE_COMMENT = re.compile(r"\s--.*$")


class Usage(Exception):
    """A bad argument or an input this script cannot read (exit 2)."""


def digest(obj):
    """A short, stable hash of a JSON-serialisable value."""
    text = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def squash(text):
    """Collapse whitespace runs to one space."""
    return " ".join(text.split())


def statement_lines(lines, i):
    """The header of the declaration starting at `lines[i]`, up to its `:=`, comments removed."""
    out = []
    while i < len(lines):
        line = LINE_COMMENT.sub("", lines[i])
        if ":=" in line:
            out.append(line.split(":=", 1)[0])
            return squash(" ".join(out)), i
        out.append(line)
        i += 1
    raise ValueError("declaration without :=")


def split_binders(stmt):
    """Split `name (b1) (b2) ... : concl` into its binder groups and its conclusion."""
    binders = []
    i = stmt.index(" ") + 1 if " " in stmt else len(stmt)
    pairs = {"(": ")", "{": "}", "[": "]", "⦃": "⦄"}
    while i < len(stmt):
        ch = stmt[i]
        if ch == " ":
            i += 1
        elif ch in pairs:
            depth, j = 0, i
            while j < len(stmt):
                if stmt[j] in pairs:
                    depth += 1
                elif stmt[j] in pairs.values():
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            binders.append(stmt[i:j + 1])
            i = j + 1
        elif ch == ":":
            return binders, stmt[i + 1:].strip()
        else:
            raise ValueError(f"unexpected token in statement: {stmt[i:i + 40]!r}")
    return binders, ""


def split_conjuncts(text):
    """Top-level conjuncts of a proposition."""
    parts, depth, cur = [], 0, []
    for tok in re.split(r"(\s∧\s|[()\[\]{}⟨⟩])", text):
        if tok in ("(", "[", "{", "⟨"):
            depth += 1
        elif tok in (")", "]", "}", "⟩"):
            depth -= 1
        if depth == 0 and tok.strip() == "∧":
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(tok)
    parts.append("".join(cur).strip())
    return [p for p in parts if p]


def column_names(fields):
    """`base#k` names for the witness fields, given `(index, doc name or None)` in order."""
    seen = Counter()
    names = {}
    for idx, doc in fields:
        base = "derived"
        if doc is not None:
            m = re.fullmatch(r"(.*)_(\d+)", doc)
            base = m.group(1) if m and int(m.group(2)) == idx else doc
        names[idx] = f"{base}#{seen[base]}"
        seen[base] += 1
    return names


def run_lengths(names):
    """Run-length encoding of the column base names in field order."""
    runs = []
    for name in names:
        b = base(name)
        if runs and runs[-1][0] == b:
            runs[-1][1] += 1
        else:
            runs.append([b, 1])
    return runs


def port_list(text):
    """Field indices of a port list `[w.v3, w.v7]`."""
    body = text.strip()
    if not (body.startswith("[") and body.endswith("]")):
        raise ValueError(f"unexpected port list: {body[:60]!r}")
    items = [x.strip() for x in body[1:-1].split(",") if x.strip()]
    out = []
    for item in items:
        m = re.fullmatch(r"_?w\.v(\d+)", item)
        if not m:
            raise ValueError(f"port is not a column: {item!r}")
        out.append(int(m.group(1)))
    return out


def unique_labels(labels):
    """Disambiguate repeated labels as `label@2`, `label@3`, ..."""
    seen = Counter()
    out = []
    for label in labels:
        seen[label] += 1
        out.append(label if seen[label] == 1 else f"{label}@{seen[label]}")
    return out


class Module:
    """The raw pieces of one module namespace, collected while scanning a file."""

    def __init__(self, chip, namespace, title):
        self.chip, self.namespace, self.title = chip, namespace, title
        self.fields = []
        self.ports = {}
        self.origins = {}
        self.defs = {}
        self.constraint_lines = []
        self.theorems = {}
        self.other = Counter()
        self.sections = []
        self.helper = None


def body_until_blank(lines, i):
    """Lines after a `:=` header up to the next blank or column-0 line."""
    out = []
    while i < len(lines) and lines[i].strip() and lines[i].startswith(" "):
        out.append(lines[i])
        i += 1
    return out, i


def scan_file(path):
    """Parse one generated chip file into its modules and file-level facts."""
    lines = path.read_text().split("\n")
    chip, title, mod = None, None, None
    modules, axioms, header = [], [], []
    i = 0
    while i < len(lines):
        line = lines[i]
        d = DECL.match(line)
        if d and d.group(1) == "axiom":
            axioms.append(squash(LINE_COMMENT.sub("", line)))
        m = CHIP_NS.match(line)
        if m and chip is None:
            chip = m.group(1)
            i += 1
            continue
        if chip is None:
            if line.startswith(("import ", "set_option ")):
                header.append(line.strip())
            i += 1
            continue
        m = MODULE_TITLE.match(line)
        if m:
            title = m.group(1)
            i += 1
            continue
        if mod is None and line.startswith("namespace "):
            mod = Module(chip, line.split()[1], title)
            title = None
            i += 1
            continue
        if mod is not None and line == f"end {mod.namespace}":
            modules.append(mod)
            mod = None
            i += 1
            continue
        if mod is None or not d:
            i += 1
            continue
        kind, name = d.groups()
        if kind == "structure" and name == "W":
            i, doc = i + 1, None
            while i < len(lines) and lines[i].startswith("  "):
                s = lines[i].strip()
                dm, fm = DOC_NAME.match(s), FIELD.match(s)
                if dm:
                    doc = dm.group(1)
                elif fm:
                    mod.fields.append((int(fm.group(1)), doc))
                    doc = None
                else:
                    raise ValueError(f"{path.name}: unexpected witness line {s!r}")
                i += 1
            continue
        if kind == "opaque":
            mod.helper = squash(LINE_COMMENT.sub("", line))
            i += 1
            continue
        if kind == "section":
            mod.sections.append(name)
            i += 1
            continue
        if kind in ("theorem", "lemma"):
            if name in PINNED_THEOREMS:
                stmt, i = statement_lines(lines, i)
                mod.theorems[name] = stmt.split(" ", 1)[1]
            else:
                mod.other[re.sub(r"\d+", "N", name)] += 1
            i += 1
            continue
        if kind == "def" and re.fullmatch(r"constraints_\d+", name):
            body, i = body_until_blank(lines, i + 1)
            mod.constraint_lines.extend(body)
            continue
        if kind == "def" and name in ("input_origins", "output_origins"):
            mod.origins[name] = json.loads(line.split(":=", 1)[1])
            i += 1
            continue
        if kind == "def" and name in INTERFACE_DEFS:
            head, rest = line.split(":=", 1)
            body, j = body_until_blank(lines, i + 1)
            text = squash(" ".join([rest] + body))
            mod.defs[name] = (squash(head).replace("(_w :", "(w :"), text)
            if name in PORT_DEFS:
                mod.ports[name] = port_list(text)
            i = j
            continue
        i += 1
    if chip is None:
        raise ValueError(f"{path.name}: no ZirenDet.Chips namespace")
    return chip, modules, axioms, header


def base(name):
    """The column name without its `#k` number."""
    return name.rsplit("#", 1)[0]


def split_port(entry):
    """`provenance <- column` into its two halves."""
    label, _, column = entry.rpartition(" <- ")
    return label, column


def canonical(text, names):
    """Replace `w.vN` / `w'.vN` by the column's `base#k` name."""
    return VAR.sub(lambda m: f"{m.group(1)}.⟨{names.get(int(m.group(2)), 'v' + m.group(2))}⟩", text)


def summarize(mod):
    """The manifest entry of one module."""
    if not mod.fields:
        decl = mod.helper
        if decl is None and "rel" in mod.defs:
            head, text = mod.defs["rel"]
            decl = f"{head} := {text}"
        entry = {"kind": "helper", "title": mod.title, "decl": decl}
        entry["hashes"] = {"decl": digest(decl)}
        return entry
    names = column_names(mod.fields)
    ordered = [names[idx] for idx, _ in mod.fields]
    col = dict(names)

    def labels(kind):
        idxs = mod.ports.get(kind, [])
        origins = mod.origins.get({"inputs": "input_origins", "outputs": "output_origins"}.get(kind, ""), [])
        if origins and len(origins) == len(idxs):
            raw = list(origins)
        else:
            raw = [f"col {col[i]}" for i in idxs]
        return list(zip(unique_labels(raw), idxs))

    ports = {k: labels(k) for k in ("inputs", "outputs", "assumed")}
    by_col = {}
    for kind, prefix in (("inputs", "in"), ("outputs", "out"), ("assumed", "assumed")):
        for label, idx in ports[kind]:
            by_col.setdefault(idx, []).append(f"{prefix}:{label}")
    aliases = sorted(sorted(g) for g in by_col.values() if len(g) > 1)

    theorems = {}
    for name, stmt in sorted(mod.theorems.items()):
        binders, concl = split_binders(canonical(stmt, col))
        hyps = sorted(re.sub(r"^\(h_\w+ :\s*", "(", b) for b in binders if b.startswith("(h_"))
        shape = [b for b in binders if not b.startswith("(h_")]
        theorems[name] = {
            "statement": canonical(stmt, col),
            "binders": shape,
            "hypotheses": hyps,
            "conclusion": split_conjuncts(concl) if name == "postconditions" else [concl],
        }
    defs = {k: f"{h} := {'[ports]' if k in PORT_DEFS else canonical(t, col)}"
            for k, (h, t) in sorted(mod.defs.items()) if k != "constraints"}
    cons = [squash(canonical(c, col)) for c in mod.constraint_lines]
    helpers = Counter()
    for c in mod.constraint_lines:
        helpers.update(HELPER_CALL.findall(c))
    entry = {
        "kind": "module",
        "title": mod.title,
        "theorems": theorems,
        "inputs": [f"{label} <- {base(col[i])}" for label, i in ports["inputs"]],
        "outputs": [f"{label} <- {base(col[i])}" for label, i in ports["outputs"]],
        "assumed": [f"{label} <- {base(col[i])}" for label, i in ports["assumed"]],
        "aliases": aliases,
        "interface": defs,
        "witness": {"fields": len(ordered), "layout": run_lengths(ordered)},
        "constraints": {
            "definition": squash(" := ".join(mod.defs.get("constraints", ("", "")))),
            "conjuncts": len(cons),
            "range_facts": sum(1 for c in cons if RANGE_FACT.search(c)),
            "helper_calls": dict(sorted(helpers.items())),
        },
        "other_theorems": dict(sorted(mod.other.items())),
        "sections": mod.sections,
    }
    entry["hashes"] = {
        "statement": digest(theorems),
        "hypotheses": digest({k: v["hypotheses"] for k, v in theorems.items()}),
        "inputs": digest(entry["inputs"]),
        "outputs": digest(entry["outputs"]),
        "assumed": digest(entry["assumed"]),
        "aliases": digest(aliases),
        "interface": digest(defs),
        "witness": digest(ordered),
        "constraints": digest(cons),
    }
    return entry


def chips_dir(path):
    """Locate `Chips/*.lean` under a ZirenDet directory, its parent, or the Chips directory."""
    p = Path(path)
    for cand in (p / "Chips", p / "ZirenDet" / "Chips", p):
        if cand.is_dir() and any(cand.glob("*.lean")) and cand.name == "Chips":
            return cand
    raise Usage(f"no Chips/*.lean under {path}")


def snapshot(path):
    """The manifest of every generated chip file under `path`."""
    modules, files = {}, {}
    for f in sorted(chips_dir(path).glob("*.lean")):
        chip, mods, axioms, header = scan_file(f)
        files[chip] = {"header": digest(header), "axioms": axioms, "modules": len(mods)}
        for mod in mods:
            key = f"{chip}/{mod.namespace}"
            if key in modules:
                raise ValueError(f"duplicate module {key}")
            modules[key] = summarize(mod)
    return {"format": FORMAT, "files": files, "modules": modules}


def load(path):
    """A manifest from a JSON file, or a fresh snapshot of a generated tree."""
    p = Path(path)
    if p.is_file():
        data = json.loads(p.read_text())
        if data.get("format") != FORMAT:
            raise Usage(f"{path}: not a {FORMAT} manifest")
        return data
    return snapshot(p)


def multiset_diff(old, new):
    """(gained, lost) between two label lists, as sorted lists."""
    a, b = Counter(old), Counter(new)
    return sorted((b - a).elements()), sorted((a - b).elements())


def fmt(items, limit=12):
    items = list(items)
    more = f" ... (+{len(items) - limit})" if len(items) > limit else ""
    return ", ".join(items[:limit]) + more


def compare_module(old, new):
    """Lists of (weakening, info) messages for one module present on both sides."""
    weak, info = [], []
    if old["kind"] != new["kind"]:
        weak.append(f"kind changed: {old['kind']} -> {new['kind']}")
        return weak, info
    if old["kind"] == "helper":
        if old["decl"] != new["decl"]:
            weak.append(f"helper relation redefined: {old['decl']!r} -> {new['decl']!r}")
        return weak, info
    for name, ot in old["theorems"].items():
        nt = new["theorems"].get(name)
        if nt is None:
            weak.append(f"theorem {name} removed")
            continue
        if ot["binders"] != nt["binders"]:
            weak.append(f"{name}: binders changed: {' '.join(ot['binders'])} -> {' '.join(nt['binders'])}")
        gained, lost = multiset_diff(ot["hypotheses"], nt["hypotheses"])
        for h in gained:
            weak.append(f"{name}: hypothesis added: {h}")
        for h in lost:
            info.append(f"{name}: hypothesis dropped: {h}")
        if name == "postconditions":
            gained, lost = multiset_diff(ot["conclusion"], nt["conclusion"])
            for c in lost:
                weak.append(f"{name}: conjunct lost: {c}")
            for c in gained:
                info.append(f"{name}: conjunct gained: {c}")
        elif ot["conclusion"] != nt["conclusion"]:
            weak.append(f"{name}: conclusion changed: {ot['conclusion'][0]} -> {nt['conclusion'][0]}")
    for name in sorted(set(new["theorems"]) - set(old["theorems"])):
        info.append(f"theorem {name} added")
    renames = rename_map(old["witness"], new["witness"])
    for kind, bad in (("inputs", "gained"), ("outputs", "lost"), ("assumed", "gained")):
        oports = dict(split_port(rename_label(p, renames)) for p in old[kind])
        nports = dict(split_port(p) for p in new[kind])
        gained = sorted(set(nports) - set(oports))
        lost = sorted(set(oports) - set(nports))
        for side, items in (("gained", gained), ("lost", lost)):
            if items:
                msg = f"{kind} {side} {len(items)}: {fmt(items)}"
                (weak if side == bad else info).append(msg)
        for label in sorted(set(oports) & set(nports)):
            if renames.get(oports[label], oports[label]) != nports[label]:
                weak.append(f"{kind[:-1]} {label} is carried by another column: "
                            f"{oports[label]} -> {nports[label]}")
        same = [split_port(rename_label(p, renames))[0] for p in old[kind]]
        if not gained and not lost and same != [split_port(p)[0] for p in new[kind]]:
            info.append(f"{kind} reordered")
    kept = {f"{prefix}:{split_port(rename_label(p, renames))[0]}"
            for kind, prefix in (("inputs", "in"), ("outputs", "out"), ("assumed", "assumed"))
            for p in old[kind]}
    kept &= {f"{prefix}:{split_port(p)[0]}"
             for kind, prefix in (("inputs", "in"), ("outputs", "out"), ("assumed", "assumed"))
             for p in new[kind]}
    old_pairs = {(a, b) for a, b in alias_pairs(
        [[rename_label(x, renames) for x in g] for g in old["aliases"]]) if a in kept and b in kept}
    new_pairs = {(a, b) for a, b in alias_pairs(new["aliases"]) if a in kept and b in kept}
    for a, b in sorted(new_pairs - old_pairs):
        weak.append(f"ports now share one column: {a} = {b}")
    lost_pairs = sorted(old_pairs - new_pairs)
    if lost_pairs:
        pairs = [f"{a} = {b}" for a, b in lost_pairs]
        info.append(f"ports no longer share a column ({len(pairs)}): {fmt(pairs, 6)}")
    for name in sorted(set(old["interface"]) | set(new["interface"])):
        o, n = old["interface"].get(name), new["interface"].get(name)
        if o != n:
            weak.append(f"definition {name} changed: {o!r} -> {n!r}")
    if old["constraints"]["definition"] != new["constraints"]["definition"]:
        info.append("constraints conjunction regrouped")
    info.extend(witness_info(old["witness"], new["witness"]))
    if old["hashes"]["constraints"] != new["hashes"]["constraints"]:
        oc, nc = old["constraints"], new["constraints"]
        parts = [f"conjuncts {oc['conjuncts']} -> {nc['conjuncts']}",
                 f"range facts {oc['range_facts']} -> {nc['range_facts']}"]
        if oc["helper_calls"] != nc["helper_calls"]:
            parts.append(f"helper calls {oc['helper_calls']} -> {nc['helper_calls']}")
        info.append("constraints changed: " + ", ".join(parts))
    if old["other_theorems"] != new["other_theorems"]:
        o, n = sum(old["other_theorems"].values()), sum(new["other_theorems"].values())
        info.append(f"proof lemmas {o} -> {n}")
    if old["sections"] != new["sections"]:
        info.append(f"snippet sections {old['sections']} -> {new['sections']}")
    return weak, info


def alias_pairs(groups):
    """Every unordered pair of ports that share a column, as sorted tuples."""
    return {tuple(sorted((a, b))) for g in groups for i, a in enumerate(g) for b in g[i + 1:]}


def rename_map(old, new):
    """Column renames `old base -> new base` read off two witness layouts of the same shape.

    Two layouts with the same run lengths in the same order describe the same columns; a run
    whose name differs is a rename.  A name that would map to two different names is left out."""
    ol, nl = old["layout"], new["layout"]
    if len(ol) != len(nl) or any(a[1] != b[1] for a, b in zip(ol, nl)):
        return {}
    pairs = {}
    for (a, _), (b, _) in zip(ol, nl):
        pairs.setdefault(a, set()).add(b)
    return {a: next(iter(bs)) for a, bs in pairs.items() if len(bs) == 1 and a not in bs}


def rename_label(entry, renames):
    """Apply column renames to a port entry or alias member (`col base#k`, `... <- base`)."""
    if not renames:
        return entry
    label, sep, column = entry.rpartition(" <- ")
    if not sep:
        label, column = entry, None
    m = re.fullmatch(r"(.*col )([^#]+)(#\d+.*)", label)
    if m and m.group(2) in renames:
        label = m.group(1) + renames[m.group(2)] + m.group(3)
    if column is None:
        return label
    return f"{label} <- {renames.get(column, column)}"


def witness_info(old, new):
    """INFO lines for a changed witness layout, with 1:1 column renames recognised."""
    if old == new:
        return []
    ol, nl = old["layout"], new["layout"]
    if len(ol) == len(nl) and all(a[1] == b[1] for a, b in zip(ol, nl)):
        renames = [f"{a[0]} -> {b[0]}" for a, b in zip(ol, nl) if a[0] != b[0]]
        return [f"witness columns renamed 1:1: {fmt(renames)}"]
    oc, nc = Counter(), Counter()
    for name, n in ol:
        oc[name] += n
    for name, n in nl:
        nc[name] += n
    delta = [f"{k} {'+' if nc[k] > oc[k] else ''}{nc[k] - oc[k]}" for k in sorted(oc | nc) if nc[k] != oc[k]]
    msg = f"witness fields {old['fields']} -> {new['fields']}"
    return [msg + (f" ({fmt(delta)})" if delta else ", reordered")]


def compare(old, new, all_info=False, out=None):
    """Print the classified differences; return the number of weakenings."""
    out = out or sys.stdout
    weak, info = {}, {}
    om, nm = old["modules"], new["modules"]
    added = sorted(set(nm) - set(om))
    for key in sorted(set(om) - set(nm)):
        if om[key]["kind"] == "helper":
            info.setdefault(key, []).append("helper removed")
            continue
        chip = key.split("/", 1)[0]
        same_chip = [k.split("/", 1)[1] for k in added if k.startswith(chip + "/")]
        hint = f"; {chip} gained {', '.join(same_chip)}" if same_chip else ""
        weak.setdefault(key, []).append(
            f"module removed (theorems: {', '.join(om[key]['theorems']) or 'none'}{hint})")
    for key in added:
        info.setdefault(key, []).append(
            "helper added" if nm[key]["kind"] == "helper"
            else f"module added (theorems: {', '.join(nm[key]['theorems']) or 'none'})")
    for key in sorted(set(om) & set(nm)):
        w, i = compare_module(om[key], nm[key])
        if w:
            weak.setdefault(key, []).extend(w)
        if i:
            info.setdefault(key, []).extend(i)
    for chip in sorted(set(old["files"]) | set(new["files"])):
        of, nf = old["files"].get(chip), new["files"].get(chip)
        if of is None or nf is None:
            info.setdefault(chip, []).append("chip file " + ("added" if of is None else "removed"))
            continue
        for ax in sorted(set(nf["axioms"]) - set(of["axioms"])):
            weak.setdefault(chip, []).append(f"axiom declared: {ax}")
        if of["header"] != nf["header"]:
            info.setdefault(chip, []).append("file header (imports, options) changed")
    for key in sorted(weak):
        for msg in weak[key]:
            print(f"WEAKENING  {key}: {msg}", file=out)
    for key in sorted(info):
        msgs = info[key] if all_info else info[key][:4]
        for msg in msgs:
            print(f"INFO       {key}: {msg}", file=out)
        if len(info[key]) > len(msgs):
            print(f"INFO       {key}: ... {len(info[key]) - len(msgs)} more (--all-info)", file=out)
    n_weak = sum(len(v) for v in weak.values())
    stmt = sum(1 for k in set(om) & set(nm) if om[k]["hashes"].get("statement") != nm[k]["hashes"].get("statement")
               or any(om[k]["hashes"].get(p) != nm[k]["hashes"].get(p)
                      for p in ("inputs", "outputs", "assumed", "aliases", "interface", "decl")))
    print(f"{len(om)} -> {len(nm)} modules; {stmt} with a changed pinned part; "
          f"{n_weak} weakening(s) in {len(weak)} module(s); {len(info)} module(s) with info", file=out)
    return n_weak


def main(argv):
    try:
        if argv[:1] == ["snapshot"] and len(argv) == 2:
            manifest = snapshot(argv[1])
            json.dump(manifest, sys.stdout, indent=1, sort_keys=True, ensure_ascii=False)
            sys.stdout.write("\n")
            return 0
        rest = [a for a in argv[1:] if a != "--all-info"]
        if argv[:1] == ["compare"] and len(rest) == 2:
            return 1 if compare(load(rest[0]), load(rest[1]), "--all-info" in argv) else 0
    except (Usage, ValueError, OSError) as err:
        print(f"pin_statements: {err}", file=sys.stderr)
        return 2
    print(__doc__.split("\n\n")[1], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

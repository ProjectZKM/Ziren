"""Plumbing shared by the check passes: Lean module text and the Makefile of a split root.

A split root holds `PREFIX/*.lean` modules and a Makefile with one rule per module,
`PREFIX/M.olean: PREFIX/M.lean <deps>` run by `$(LEANRUN) PREFIX M`.  A pass that moves part of a
module M into new modules adds a rule for each and makes M depend on them (`add_modules`)."""
import os
import re


def read(path):
    return open(path, encoding="utf-8").read()


def write(path, text):
    open(path, "w", encoding="utf-8").write(text)


def theorem_span(lines, name):
    """Indices of the `theorem NAME` line and of the line ending its statement with `:= by`."""
    start = next(i for i, l in enumerate(lines) if re.match(rf"theorem {re.escape(name)}\b", l))
    by = next(i for i in range(start, len(lines)) if lines[i].rstrip().endswith(":= by"))
    return start, by


def add_modules(root, mp, parent, mods, deps=None, once=False):
    """Add a Makefile rule for each new module of `mods` and make `parent` depend on them.

    `deps[k]` is the dependency text of `mods[k]`'s rule; by default each inherits `parent`'s.
    With `once`, nothing is added when the first module already has a rule."""
    path = os.path.join(root, "Makefile")
    mk = read(path)
    rule = re.search(rf"^{mp}/{parent}\.olean: {mp}/{parent}\.lean(.*)$", mk, re.M)
    if deps is None:
        deps = [rule.group(1)] * len(mods)
    if not (once and f"{mp}/{mods[0]}.olean:" in mk):
        mk = mk.replace(rule.group(0), rule.group(0) + " " + " ".join(f"{mp}/{m}.olean" for m in mods))
        mk += "\n" + "\n".join(f"{mp}/{m}.olean: {mp}/{m}.lean{d}\n\t$(LEANRUN) {mp} {m}\n" for m, d in zip(mods, deps))
    write(path, mk)

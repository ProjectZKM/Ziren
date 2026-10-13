"""Generates the computed parts of ZirenDet/Septic.lean: the product `sm`, the quotient of
`φ_sm`, and the certificates that `z⁷ + 2z − 8` has no factor of degree 1, 2 or 3."""
P = 2130706433


def smv(a, b):
    res = [0] * 13
    for i in range(7):
        for j in range(7):
            res[i + j] = (res[i + j] + a[i] * b[j]) % P
    ret = res[:7]
    for i in range(7, 13):
        ret[i - 7] = (ret[i - 7] + 8 * res[i]) % P
        ret[i - 6] = (ret[i - 6] - 2 * res[i]) % P
    return ret


def lit(v):
    return "![" + ", ".join(str(x) for x in v) + "]"


def sm_def():
    comps = []
    for k in range(7):
        terms = []
        for i in range(7):
            j = k - i
            if 0 <= j < 7:
                terms.append(f"a {i} * b {j}")
        hi = [f"a {i} * b {k + 7 - i}" for i in range(7) if 0 <= k + 7 - i < 7]
        mid = [f"a {i} * b {k + 6 - i}" for i in range(7) if 0 <= k + 6 - i < 7] if k >= 1 else []
        e = " + ".join(terms)
        if hi:
            e += " + 8 * (" + " + ".join(hi) + ")"
        if mid:
            e += " - 2 * (" + " + ".join(mid) + ")"
        comps.append(e)
    return "def sm (a b : V) : V :=\n  ![" + ",\n    ".join(comps) + "]\n"


def phi_quot():
    parts = []
    for m in range(7, 13):
        res = " + ".join(f"A{i} * B{m - i}" for i in range(7) if 0 <= m - i < 7)
        parts.append(f"({res}) * r ^ {m - 7}")
    return " + ".join(parts)


def chain(base, base_name, n_final, prefix):
    """Square-and-multiply for `base ^ n_final`, one `have` per step."""
    bits = bin(n_final)[3:]
    lines = []
    acc = base
    n = 1
    lines.append(f"  have {prefix}0 : φ {base_name} = φ {base_name} ^ 1 := (pow_one _).symm")
    k = 0
    for bit in bits:
        nxt = smv(acc, acc)
        n2 = 2 * n
        lines.append(
            f"  have {prefix}{k + 1} : φ {lit(nxt)} = φ {base_name} ^ {n2} :=\n"
            f"    chain_sq {prefix}{k} (by decide +kernel) rfl")
        acc, n, k = nxt, n2, k + 1
        if bit == "1":
            nxt = smv(acc, base)
            lines.append(
                f"  have {prefix}{k + 1} : φ {lit(nxt)} = φ {base_name} ^ {n + 1} :=\n"
                f"    chain_mul {prefix}{k} (by decide +kernel) rfl")
            acc, n, k = nxt, n + 1, k + 1
    assert n == n_final
    return acc, lines, f"{prefix}{k}"


def inverse(a):
    r = [1, 0, 0, 0, 0, 0, 0]
    e = P ** 7 - 2
    b = a
    while e:
        if e & 1:
            r = smv(r, b)
        b = smv(b, b)
        e >>= 1
    assert smv(r, a) == [1, 0, 0, 0, 0, 0, 0]
    return r


if __name__ == "__main__":
    X = [0, 1, 0, 0, 0, 0, 0]
    out = []
    out.append("-- SM_DEF\n" + sm_def())
    out.append("-- PHI_QUOT\n" + phi_quot())
    R = {}
    base, name = X, "Xv"
    for e in (1, 2, 3):
        acc, lines, last = chain(base, name, P, f"k{e}_")
        R[e] = acc
        out.append(f"-- CHAIN {e} last={last} R={lit(acc)}\n" + "\n".join(lines))
        base, name = acc, lit(acc)
        d = [(acc[i] - X[i]) % P for i in range(7)]
        inv = inverse(d)
        out.append(f"-- CERT {e} V={lit(inv)} D={lit(d)}")
    open("genlib.out", "w").write("\n".join(out) + "\n")
    print("ok", {e: R[e] for e in R})


def assemble():
    X = [0, 1, 0, 0, 0, 0, 0]
    quot = phi_quot()
    for i in range(7):
        quot = quot.replace(f"A{i} ", f"ι (a {i}) ").replace(f"B{i})", f"ι (b {i}))").replace(f"B{i} ", f"ι (b {i}) ")
    certs = []
    base, name = X, "Xv"
    prev = None
    for e in (1, 2, 3):
        acc, lines, last = chain(base, name, P, f"k{e}_")
        d = [(acc[i] - X[i]) % P for i in range(7)]
        inv = inverse(d)
        certs.append(f"def R{e} : V := {lit(acc)}\n")
        certs.append(f"def Vc{e} : V := {lit(inv)}\n")
        stmt = "r ^ KB" if e == 1 else f"r ^ KB ^ {e}"
        tail = {1: "  rw [e, φ_X]", 2: "  rw [e, pow1, ← pow_mul, sq]", 3: "  rw [e, pow2, ← pow_mul]\n  congr 1"}[e]
        certs.append(f"theorem pow{e} : φ R{e} = {stmt} := by\n" + "\n".join(lines) +
                     f"\n  have e : φ R{e} = φ {name} ^ KB := {last}\n{tail}\n")
        pre = "rw [pow_one, ← pow1," if e == 1 else f"rw [← pow{e},"
        certs.append(f"theorem cert{e} : φ Vc{e} * (r ^ KB ^ {e} - r) = 1 := by\n"
                     f"  {pre} ← φ_X, ← φ_sub, ← φ_sm,\n"
                     f"    (by decide +kernel : sm Vc{e} (R{e} - Xv) = one), φ_one]\n")
        base, name = acc, f"R{e}"
    t = open("Septic.tmpl").read()
    t = t.replace("%SM_DEF%\n", sm_def()).replace("%PHI_QUOT%", quot).replace("%CERTS%", "\n".join(certs))
    open("Septic.lean", "w").write(t)


if __name__ == "__main__":
    assemble()

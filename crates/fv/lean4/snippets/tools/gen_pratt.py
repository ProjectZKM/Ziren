"""gen_pratt.py NAME P [NAME P ...]: Lean theorems `NAME : Nat.Prime P` by Lucas certificates
(`ZirenDet.Pratt.prime_of_cert`), with the prime factors of `P − 1` proved the same way,
recursively; primes below 2^20 are left to `norm_num`.  Factoring uses PARI/GP."""
import subprocess, sys

SMALL = 1 << 20


def is_probable_prime(n):
    if n < 2:
        return False
    for q in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % q == 0:
            return n == q
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53):
        if a % n == 0:
            continue
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def factor(n, out):
    """Factor `n` with PARI/GP (`gp` on PATH), which runs ECM and MPQS."""
    if n == 1:
        return
    script = f"print(factor({n}));quit;"
    res = subprocess.run(["gp", "-q", "-D", "parisizemax=2000000000"], input=script,
                         capture_output=True, text=True, check=True).stdout
    body = res.strip().splitlines()[-1].strip("[]")
    for part in body.split(";"):
        q, e = part.split(",")
        q, e = int(q), int(e)
        assert is_probable_prime(q), q
        out[q] = out.get(q, 0) + e


done = {}
lines = []


def cert(p):
    if p in done:
        return done[p]
    assert is_probable_prime(p), p
    if p < SMALL:
        done[p] = None
        return None
    fs = {}
    factor(p - 1, fs)
    fs = sorted(fs.items())
    for q, _ in fs:
        cert(q)
    a = 2
    while not (pow(a, p - 1, p) == 1 and all(pow(a, (p - 1) // q, p) != 1 for q, _ in fs)):
        a += 1
    name = f"prime_{p:x}"
    done[p] = name
    fl = ", ".join(f"({q}, {e})" for q, e in fs)
    pats = " | ".join("rfl" for _ in fs)
    cases = "\n".join(f"      · {'exact ' + done[q] if done[q] else 'norm_num'}" for q, _ in fs)
    lines.append(f"""theorem {name} : Nat.Prime {p} :=
  ZirenDet.Pratt.prime_of_cert {p} {a} [{fl}] (by decide +kernel) (by decide +kernel) (by decide +kernel)
    (by
      intro f hf
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hf
      rcases hf with {pats}
{cases})
    (by decide +kernel) (by decide +kernel)
""")
    return name


def main():
    args = sys.argv[1:]
    heads = []
    for name, p in zip(args[::2], args[1::2]):
        p = int(p, 0)
        inner = cert(p)
        heads.append(f"theorem {name} : Nat.Prime {p} := {inner}\n")
    print("import ZirenDet.Pratt\n\nnamespace ZirenDet.Primes\n")
    print("\n".join(lines))
    print("\n".join(heads))
    print("end ZirenDet.Primes")


main()

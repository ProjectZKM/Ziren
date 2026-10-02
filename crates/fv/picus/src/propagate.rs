//! Determinism propagation: a fast, proof-oriented triage of every extracted module.
//!
//! A module is deterministic when its outputs are functions of its inputs.  This pass decides
//! that the way a proof would: it starts from the inputs (and the `assume-deterministic`
//! expressions) as *known* variables, and repeatedly applies one of a few derivation rules, each
//! of which is a small lemma that the Lean emission can later discharge on a handful of
//! hypotheses:
//!
//! - **call**: a helper call whose inputs are known has known outputs (the helper is a
//!   deterministic table);
//! - **linear**: a constraint with one unknown `x`, linear in `x` with a coefficient that is a
//!   nonzero constant, or a known expression the constraint itself forces nonzero
//!   (`a * x = b` with `b` a nonzero constant), determines `x`;
//! - **positional**: a constraint linear in a few unknowns with constant coefficients, each
//!   unknown range-checked, whose image over the box is injective modulo `p`, determines them all
//!   (limb decompositions, byte carries);
//! - **iff-bit**: `(v = 1) <=> (a < b)` with `a`, `b` known and `v` a bit determines `v`.
//!
//! When propagation stalls, it case-splits on facts that are equal in both witnesses: a known
//! bit that gates an unknown (`g * E = 0`), or a known variable used as a coefficient (zero or
//! nonzero).  A module is `Determined` when every branch determines every output.
//!
//! Two preprocessing steps put constraints into the shape the rules read: a range fact on a
//! non-variable expression `e <= c` becomes a fresh range-checked variable `t` with `e - t = 0`,
//! and a bit constraint on an expression, `E * (E - 1) = 0`, becomes a fresh bit `k` with
//! `E - k = 0`.
//!
//! **Gadget summaries.**  A gadget the AIR marks (`MessageBuilder::annotate`) enters as a call
//! tagged with the lemma it stands for, proved once for the gadget rather than per chip.  The
//! field gadgets determine a residue, not a value: `result` is only fixed modulo `m` until a
//! `field_lt` check pins it below `m`.  Each operand `X` read modulo `m` gets a ghost variable
//! `[X]_m`, and the summaries are:
//!
//! - `residue_of_value`: `[X]_m` is a function of `X` and `m`;
//! - `field_op`: `[r]_m` is a function of `[a]_m`, `[b]_m` and the four selectors
//!   (`r ≡ a + b`, `a − b` or `a · b`); `field_op_div` when the division selector can be set,
//!   whose lemma also needs `b ≢ 0 (mod m)`;
//! - `field_mul_add`: `r ≡ a · b + c`;  `field_inner_product`: `r ≡ Σ aᵢ bᵢ`;
//!   `field_den`: `r ≡ a / (1 ± b)`, which also needs `1 ± b ≢ 0`;
//! - `field_lt_canonical`: `L < M` and `[L]_M` determine `L`;
//! - `field_sqrt_unique`: `S² ≡ A`, `S < m` and the parity of `S` determine `S` (`m` an odd prime);
//! - `sqrt_choice_lsb` / `sqrt_choice_lex`: the decompress chips leave the root's parity free and
//!   write the root of `A` of the requested parity, or the smaller / larger of `{s, m − s}` by
//!   the sign bit; either choice is a function of `[A]_m` and the sign (`sqrt_pair`).
//!
//! `PICUS_SKIP_GADGETS=field_lt,…` drops the named marks (a negative control).
//!
//! - `leading_one_unique`: the count of a word and its zero flag, `bb >> (31 − a) = 1` or
//!   `bb = 0, a = 32` (`msb_unique`, `msb_ne_zero`);
//! - `gt_bytes_unique`: `GtColsBytes` flags the first differing byte from the top (a higher flag
//!   sees equal bytes and fails the strict LTU, a lower one fails the equalities above it), so
//!   `result = [a > b]`;
//! - `divrem_unique`: `b = q · c + r`, `|r| < |c|` and `r` of the sign of `b` fix `q` and `r`
//!   (`c ≠ 0` is constrained; the chip must also show the one overflow row, `−2³¹ / −1`, forces
//!   `q = b`, `r = 0`).
//! - `septic_sqrt_sign`: the Global chip's point `(x, y)` on the septic curve: `y² = x³ + 3zx − 3`
//!   in the field `F[z]/(z⁷ + 2z − 8)` leaves `±y`, and the range of `y₆` the send or receive flag
//!   selects holds for one of them (`ZirenDet.Septic.sq_unique`, `y6_recv` / `y6_send`);
//! - `septic_chord`: the running digest `p₃ = p₁ + p₂` from the chord identities
//!   `(x₁ + x₂ + x₃)(x₂ − x₁)² = (y₂ − y₁)²`, `(y₁ + y₃)(x₂ − x₁) = (y₂ − y₁)(x₁ − x₃)` and the
//!   witnessed inverse of `x₂ − x₁` (`ZirenDet.Septic.chord_unique`; no field needed).
//!
//! Every field-gadget lemma rests on the gadget's limb range checks (bytes for `result` and
//! `carry`, `u16` for the witness), which hold on real rows.
//!
//! This pass is triage, not proof: its verdict is only as strong as the Lean emission that will
//! replay each step.  A `Stuck` verdict names the outputs no rule reached; each is either a
//! missing rule or an under-constrained column.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::pcl::{PicusConstraint, PicusExpr, PicusModule};

/// A gadget the AIR marked, specialized like its module: `operands[0]` is what the gadget
/// determines, the rest are what it reads (see `zkm_pcs::air::MessageBuilder::annotate`).
#[derive(Clone, Debug)]
pub struct GadgetMark {
    pub gadget: &'static str,
    /// The expression the gadget's range checks are enforced under: its summary holds where
    /// the gate is `1`.
    pub gate: PicusExpr,
    pub operands: Vec<Vec<PicusExpr>>,
}

/// The gadget marks of every module extracted in this process, by module name.
pub static GADGET_MARKS: std::sync::Mutex<BTreeMap<String, Vec<GadgetMark>>> =
    std::sync::Mutex::new(BTreeMap::new());

/// Ghost variables `[X]_m` for the residues the field gadgets read and determine.
struct Residues {
    ghosts: BTreeMap<String, usize>,
    /// `(X, m, [X]_m)` in creation order.
    entries: Vec<(Vec<PicusExpr>, Vec<PicusExpr>, usize)>,
}

impl Residues {
    /// `[x]_m`, created with its `residue_of_value` summary on first use.
    fn of(
        &mut self,
        x: &[PicusExpr],
        m: &[PicusExpr],
        facts: &mut Vec<Fact>,
        fresh: &mut usize,
    ) -> Option<Poly> {
        let render =
            |v: &[PicusExpr]| v.iter().map(|e| e.to_string()).collect::<Vec<_>>().join(",");
        let key = format!("{}|{}", render(x), render(m));
        if let Some(&g) = self.ghosts.get(&key) {
            return Some(Poly::var(g));
        }
        let mut ins: Vec<Poly> = x.iter().map(to_poly).collect::<Option<_>>()?;
        ins.extend(m.iter().map(to_poly).collect::<Option<Vec<_>>>()?);
        let g = *fresh;
        *fresh += 1;
        self.ghosts.insert(key, g);
        self.entries.push((x.to_vec(), m.to_vec(), g));
        facts.push(Fact::Call {
            outs: vec![Poly::var(g)],
            ins,
            lemma: Some("residue_of_value"),
            guard: vec![],
        });
        Some(Poly::var(g))
    }
}

impl Residues {
    /// Facts relating residues of one operand: `residue_transfer` moves `[X]_{m₁}` to
    /// `[X]_{m₂}` once `m₁ − m₂` vanishes (limbwise, the shorter padded with zeros), and
    /// `canonical_by_width` reads a byte-limbed `X` of `n` limbs off `[X]_m` once `m` is
    /// `2^(8n)` (`canonical_unique` with the bound the bytes give).
    fn links(&self, ub: &BTreeMap<usize, u64>) -> Vec<Fact> {
        let polys = |v: &[PicusExpr]| v.iter().map(to_poly).collect::<Option<Vec<Poly>>>();
        let limbwise = |a: &[Poly], b: &[Poly]| -> Vec<Poly> {
            let zero = Poly::constant(0);
            (0..a.len().max(b.len()))
                .map(|i| {
                    let (x, y) = (a.get(i).unwrap_or(&zero), b.get(i).unwrap_or(&zero));
                    x.add(&y.scale(P - 1))
                })
                .filter(|p| !p.is_zero())
                .collect()
        };
        let mut out = vec![];
        for (i, (x, m1, g1)) in self.entries.iter().enumerate() {
            let Some(p1) = polys(m1) else { continue };
            for (x2, m2, g2) in &self.entries[i + 1..] {
                if x2 != x {
                    continue;
                }
                let Some(p2) = polys(m2) else { continue };
                let guard = limbwise(&p1, &p2);
                for (from, to) in [(g1, g2), (g2, g1)] {
                    out.push(Fact::Call {
                        outs: vec![Poly::var(*to)],
                        ins: vec![Poly::var(*from)],
                        lemma: Some("residue_transfer"),
                        guard: guard.clone(),
                    });
                }
            }
            let Some(xs) = polys(x) else { continue };
            let bytes = xs.iter().all(|p| p.single_var().and_then(|v| ub.get(&v)) == Some(&255));
            if bytes && p1.len() == xs.len() + 1 {
                let mut width = vec![Poly::constant(0); xs.len()];
                width.push(Poly::constant(1));
                out.push(Fact::Call {
                    outs: xs,
                    ins: vec![Poly::var(*g1)],
                    lemma: Some("canonical_by_width"),
                    guard: limbwise(&p1, &width),
                });
            }
        }
        out
    }
}

/// A gadget summary: what it determines, from what, under which lemma.
type Summary = (Vec<Poly>, Vec<Poly>, &'static str);

/// The summary of one gadget mark; `None` for a mark whose operands do not lower to
/// polynomials, or that names no known gadget.
fn gadget_fact(
    mark: &GadgetMark,
    residues: &mut Residues,
    facts: &mut Vec<Fact>,
    fresh: &mut usize,
) -> Option<Summary> {
    let polys = |v: &[PicusExpr]| v.iter().map(to_poly).collect::<Option<Vec<Poly>>>();
    let ops = &mark.operands;
    match mark.gadget {
        "field_op" | "field_mul_add" | "field_inner_product" | "field_den" => {
            let (r, m) = (ops.first()?, ops.get(1)?);
            let out = residues.of(r, m, facts, fresh)?;
            let mut ins = polys(m)?;
            for o in &ops[2..] {
                if o.len() == 1 {
                    ins.extend(polys(o)?);
                } else {
                    ins.push(residues.of(o, m, facts, fresh)?);
                }
            }
            let divides = mark.gadget == "field_op"
                && !matches!(ops.get(7).and_then(|s| s.first()), Some(PicusExpr::Const(0)));
            let lemma = match mark.gadget {
                "field_op" if divides => "field_op_div",
                "field_op" => "field_op",
                "field_mul_add" => "field_mul_add",
                "field_inner_product" => "field_inner_product",
                _ => "field_den",
            };
            Some((vec![out], ins, lemma))
        }
        "field_lt" => {
            let (l, bound) = (ops.first()?, ops.get(1)?);
            let mut ins = vec![residues.of(l, bound, facts, fresh)?];
            ins.extend(polys(bound)?);
            Some((polys(l)?, ins, "field_lt_canonical"))
        }
        "gt_bytes" => {
            let mut ins = polys(ops.get(1)?)?;
            ins.extend(polys(ops.get(2)?)?);
            Some((polys(ops.first()?)?, ins, "gt_bytes_unique"))
        }
        "leading_one" => Some((polys(ops.first()?)?, polys(ops.get(1)?)?, "leading_one_unique")),
        "septic_lift" | "septic_add" => {
            let mut ins = vec![];
            for o in &ops[1..] {
                ins.extend(polys(o)?);
            }
            let lemma = match mark.gadget {
                "septic_lift" => "septic_sqrt_sign",
                _ => "septic_chord",
            };
            Some((polys(ops.first()?)?, ins, lemma))
        }
        "keccak_round" => {
            let mut ins = polys(ops.get(1)?)?;
            ins.extend(polys(ops.get(2)?)?);
            Some((polys(ops.first()?)?, ins, "keccak_round"))
        }
        "divrem" => {
            let mut ins = vec![];
            for o in &ops[1..] {
                ins.extend(polys(o)?);
            }
            Some((polys(ops.first()?)?, ins, "divrem_unique"))
        }
        "field_sqrt" | "sqrt_choice_lsb" | "sqrt_choice_lex" => {
            let (s, m, a, odd) = (ops.first()?, ops.get(1)?, ops.get(2)?, ops.get(3)?);
            let mut ins = vec![residues.of(a, m, facts, fresh)?];
            ins.extend(polys(m)?);
            ins.extend(polys(odd)?);
            let lemma = match mark.gadget {
                "field_sqrt" => "field_sqrt_unique",
                g => g,
            };
            Some((polys(s)?, ins, lemma))
        }
        _ => None,
    }
}

pub(crate) const P: u64 = 0x7f00_0001;
/// Largest number of monomials a constraint may expand to before it is treated as opaque.
const MAX_MONOMIALS: usize = 4096;
/// Largest number of unknowns the positional rule considers in one constraint.
const MAX_POSITIONAL: usize = 10;
/// Wall-clock budget for one module.
const MODULE_BUDGET: std::time::Duration = std::time::Duration::from_secs(60);
/// Largest definition (in monomials) substituted for a determined variable.
const MAX_SUBST_TERMS: usize = 32;
/// Largest domain the small-domain rule enumerates.
const MAX_DOMAIN: u64 = 1 << 16;
/// Largest number of unknown bits probed per stall.
const MAX_PROBES: usize = 64;
/// Largest number of linear facts the elimination rule reduces.
const MAX_ELIM_ROWS: usize = 6000;
/// Branch budget per module.
const MAX_BRANCHES: usize = 4096;

/// The module budget, `PICUS_BUDGET_S` seconds when set.
fn module_budget() -> std::time::Duration {
    std::env::var("PICUS_BUDGET_S")
        .ok()
        .and_then(|s| s.parse().ok())
        .map(std::time::Duration::from_secs)
        .unwrap_or(MODULE_BUDGET)
}

/// The branch budget, `PICUS_MAX_BRANCHES` when set.
fn max_branches() -> usize {
    std::env::var("PICUS_MAX_BRANCHES").ok().and_then(|s| s.parse().ok()).unwrap_or(MAX_BRANCHES)
}

fn mulm(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % P as u128) as u64
}
fn addm(a: u64, b: u64) -> u64 {
    (a + b) % P
}
fn negm(a: u64) -> u64 {
    (P - a % P) % P
}
fn powm(mut b: u64, mut e: u64) -> u64 {
    let mut acc = 1u64;
    b %= P;
    while e > 0 {
        if e & 1 == 1 {
            acc = mulm(acc, b);
        }
        b = mulm(b, b);
        e >>= 1;
    }
    acc
}
fn invm(a: u64) -> u64 {
    powm(a, P - 2)
}
/// Signed representative in `(-p/2, p/2]`.
fn signed(a: u64) -> i128 {
    let a = a % P;
    if a > P / 2 {
        a as i128 - P as i128
    } else {
        a as i128
    }
}

static NAMES: std::sync::Mutex<Option<HashMap<usize, String>>> = std::sync::Mutex::new(None);

/// Column names for the debug dump of a stuck module.
pub fn set_names(names: HashMap<usize, String>) {
    *NAMES.lock().unwrap() = Some(names);
}

fn var_name(v: usize) -> String {
    if v >= 1 << 40 {
        return format!("t{}", v - (1 << 40));
    }
    NAMES
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|n| n.get(&v).cloned())
        .unwrap_or_else(|| format!("x{v}"))
}

/// A readable form of `p = 0`, coefficients as signed integers.
fn show(p: &Poly) -> String {
    let terms: Vec<String> = p
        .0
        .iter()
        .map(|(m, c)| {
            let mono: Vec<String> = m
                .iter()
                .map(|(v, e)| if *e == 1 { var_name(*v) } else { format!("{}^{e}", var_name(*v)) })
                .collect();
            let c = signed(*c);
            if mono.is_empty() {
                format!("{c}")
            } else if c == 1 {
                mono.join("*")
            } else {
                format!("{c}*{}", mono.join("*"))
            }
        })
        .collect();
    format!("{} = 0", terms.join(" + "))
}

/// A monomial: sorted `(variable, exponent)` pairs.
type Mono = Vec<(usize, u32)>;

/// A sparse polynomial over `F_p`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Poly(BTreeMap<Mono, u64>);

impl Poly {
    /// The terms `(monomial, coefficient)`, a monomial as `(variable, exponent)` pairs.
    pub fn terms(&self) -> impl Iterator<Item = (&[(usize, u32)], u64)> {
        self.0.iter().map(|(m, c)| (m.as_slice(), *c))
    }
}

impl Poly {
    fn constant(c: u64) -> Self {
        let mut m = BTreeMap::new();
        if !c.is_multiple_of(P) {
            m.insert(vec![], c % P);
        }
        Poly(m)
    }
    fn var(v: usize) -> Self {
        let mut m = BTreeMap::new();
        m.insert(vec![(v, 1)], 1);
        Poly(m)
    }
    fn is_zero(&self) -> bool {
        self.0.is_empty()
    }
    pub(crate) fn as_constant_pub(&self) -> Option<u64> {
        self.as_constant()
    }
    fn as_constant(&self) -> Option<u64> {
        match self.0.len() {
            0 => Some(0),
            1 => self.0.get(&vec![]).copied(),
            _ => None,
        }
    }
    fn add(&self, o: &Poly) -> Poly {
        let mut r = self.0.clone();
        for (m, c) in &o.0 {
            let e = r.entry(m.clone()).or_insert(0);
            *e = addm(*e, *c);
            if *e == 0 {
                r.remove(m);
            }
        }
        Poly(r)
    }
    pub(crate) fn scale(&self, k: u64) -> Poly {
        if k.is_multiple_of(P) {
            return Poly::default();
        }
        Poly(self.0.iter().map(|(m, c)| (m.clone(), mulm(*c, k))).collect())
    }
    fn mul(&self, o: &Poly) -> Option<Poly> {
        if self.0.len() * o.0.len() > MAX_MONOMIALS * 4 {
            return None;
        }
        let mut r: BTreeMap<Mono, u64> = BTreeMap::new();
        for (m1, c1) in &self.0 {
            for (m2, c2) in &o.0 {
                let m = mono_mul(m1, m2);
                let e = r.entry(m).or_insert(0);
                *e = addm(*e, mulm(*c1, *c2));
            }
        }
        r.retain(|_, c| *c != 0);
        if r.len() > MAX_MONOMIALS {
            return None;
        }
        Some(Poly(r))
    }
    pub(crate) fn vars(&self) -> BTreeSet<usize> {
        self.0.keys().flat_map(|m| m.iter().map(|(v, _)| *v)).collect()
    }
    /// Degree of `v` in the polynomial.
    pub(crate) fn degree_in(&self, v: usize) -> u32 {
        self.0
            .keys()
            .filter_map(|m| m.iter().find(|(x, _)| *x == v).map(|(_, e)| *e))
            .max()
            .unwrap_or(0)
    }
    /// Splits `self = a * v + b` for a polynomial of degree one in `v`.
    pub(crate) fn split_linear(&self, v: usize) -> (Poly, Poly) {
        let mut a = BTreeMap::new();
        let mut b = BTreeMap::new();
        for (m, c) in &self.0 {
            if let Some(pos) = m.iter().position(|(x, _)| *x == v) {
                let mut m2 = m.clone();
                m2.remove(pos);
                a.insert(m2, *c);
            } else {
                b.insert(m.clone(), *c);
            }
        }
        (Poly(a), Poly(b))
    }
    /// Substitutes constants for variables.
    fn subst(&self, env: &BTreeMap<usize, u64>) -> Poly {
        let mut r: BTreeMap<Mono, u64> = BTreeMap::new();
        for (m, c) in &self.0 {
            let mut coef = *c;
            let mut rest = vec![];
            for (v, e) in m {
                if let Some(val) = env.get(v) {
                    coef = mulm(coef, powm(*val, *e as u64));
                } else {
                    rest.push((*v, *e));
                }
            }
            if coef != 0 {
                let e = r.entry(rest).or_insert(0);
                *e = addm(*e, coef);
            }
        }
        r.retain(|_, c| *c != 0);
        Poly(r)
    }
    /// The polynomial scaled so that its first coefficient is one (zero stays zero).
    fn monic(&self) -> Poly {
        match self.0.values().next() {
            Some(c) => self.scale(invm(*c)),
            None => Poly::default(),
        }
    }
    /// Substitutes the polynomial `r` for the variable `v`.
    fn subst_poly(&self, v: usize, r: &Poly) -> Option<Poly> {
        let mut out = Poly::default();
        for (m, c) in &self.0 {
            let mut rest = vec![];
            let mut e = 0;
            for (x, k) in m {
                if *x == v {
                    e = *k;
                } else {
                    rest.push((*x, *k));
                }
            }
            let mut term = Poly(BTreeMap::from([(rest, *c)]));
            for _ in 0..e {
                term = term.mul(r)?;
            }
            out = out.add(&term);
        }
        Some(out)
    }
    /// A variable of degree one with a constant coefficient that occurs in no other monomial,
    /// and the polynomial it equals when `self = 0`.
    fn pivot(&self) -> Option<(usize, Poly)> {
        for v in self.vars() {
            if self.degree_in(v) != 1 {
                continue;
            }
            let (a, b) = self.split_linear(v);
            if let Some(c) = a.as_constant() {
                if c != 0 && !b.vars().contains(&v) {
                    return Some((v, b.scale(negm(invm(c)))));
                }
            }
        }
        None
    }
    /// If the polynomial is `c * v` (one monomial, one variable of degree one), returns `v`.
    fn single_var(&self) -> Option<usize> {
        if self.0.len() != 1 {
            return None;
        }
        let (m, _) = self.0.iter().next().unwrap();
        if m.len() == 1 && m[0].1 == 1 {
            Some(m[0].0)
        } else {
            None
        }
    }
}

fn mono_mul(a: &Mono, b: &Mono) -> Mono {
    let mut r: BTreeMap<usize, u32> = BTreeMap::new();
    for (v, e) in a.iter().chain(b.iter()) {
        *r.entry(*v).or_insert(0) += e;
    }
    r.into_iter().collect()
}

pub(crate) fn to_poly(e: &PicusExpr) -> Option<Poly> {
    Some(match e {
        PicusExpr::Const(c) => Poly::constant(*c),
        PicusExpr::Var(v) => Poly::var(*v),
        PicusExpr::Add(a, b) => to_poly(a)?.add(&to_poly(b)?),
        PicusExpr::Sub(a, b) => to_poly(a)?.add(&to_poly(b)?.scale(P - 1)),
        PicusExpr::Neg(a) => to_poly(a)?.scale(P - 1),
        PicusExpr::Mul(a, b) => to_poly(a)?.mul(&to_poly(b)?)?,
        PicusExpr::Div(a, b) => {
            let d = to_poly(b)?.as_constant()?;
            if d == 0 {
                return None;
            }
            to_poly(a)?.scale(invm(d))
        }
        PicusExpr::Pow(k, a) => {
            let base = to_poly(a)?;
            let mut r = Poly::constant(1);
            for _ in 0..*k {
                r = r.mul(&base)?;
            }
            r
        }
    })
}

/// A normalized constraint the rules read.
#[derive(Clone, Debug)]
enum Fact {
    /// `p = 0`.
    Zero(Poly),
    /// `(v = 1) <=> (a < b)`.
    IffLt { v: usize, a: Poly, b: Poly },
    /// A helper call, or a gadget summary when `lemma` names the lemma it stands for; it fires
    /// once every `guard` polynomial has become the zero polynomial.
    Call { outs: Vec<Poly>, ins: Vec<Poly>, lemma: Option<&'static str>, guard: Vec<Poly> },
    /// Anything the rules do not read (kept for the report).
    Opaque,
}

/// Why a variable became known.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    Input,
    Call,
    Linear,
    LinearInverse,
    Positional,
    IffBit,
    Elimination,
    ZeroSum,
    Probe,
    SmallDomain,
    Bounds,
    OneHot,
    Quadratic,
    IsZero,
    Gadget,
}

/// How a branch of a determined module was determined: its steps in order, then how it ends.
#[derive(Clone, Debug)]
pub struct Derivation {
    /// `(variable, rule, conjuncts used)` in order (see [`INPUT_ORIGIN`] for the encoding).
    pub steps: Vec<(usize, Rule, BTreeSet<u32>)>,
    /// Values learned, as `(steps before it, variable, value, conjuncts used)`.
    pub values: Vec<(usize, usize, u64, BTreeSet<u32>)>,
    pub end: DerivEnd,
}

/// The end of a [`Derivation`] branch.
#[derive(Clone, Debug)]
pub enum DerivEnd {
    /// Every output is known.
    Done,
    /// No witness takes this branch, by the conjuncts `support`.
    Infeasible { support: BTreeSet<u32> },
    /// Some output stayed unknown, or the search ran out of budget.
    Open,
    /// A known bit: `zero` under `var = 0`, `one` under `var = 1`; `support` shows it is a bit.
    Bit { var: usize, support: BTreeSet<u32>, zero: Box<Derivation>, one: Box<Derivation> },
    /// A known one-hot set: branch `k` has `bits[k] = 1` and the others `0`; `support` shows
    /// the bits are bits summing to one.
    OneHot { bits: Vec<usize>, support: BTreeSet<u32>, branches: Vec<Derivation> },
    /// A known polynomial: `zero` holds the zero case (one branch when it is solved for a
    /// pivot, else one branch per variable of its single monomial set to zero), `nonzero` the
    /// nonzero case.
    Coef { poly: Poly, pivot: bool, zero: Vec<Derivation>, nonzero: Box<Derivation> },
}

/// Verdict for one module.
#[derive(Clone, Debug)]
pub enum Verdict {
    Determined {
        branches: usize,
        rules: BTreeMap<Rule, usize>,
        lemmas: BTreeSet<&'static str>,
        derivation: Derivation,
    },
    Stuck {
        branches: usize,
        stuck_outputs: Vec<usize>,
        opaque: usize,
    },
    TooManyBranches,
    Timeout,
}

/// Where a fact came from: conjunct `i` of the module (constraints, then calls), input
/// `INPUT_ORIGIN + j` or assumed value `ASSUMED_ORIGIN + j`.
pub const INPUT_ORIGIN: u32 = 1 << 24;
/// Variables the analyser introduces (bindings, fresh bits) start here; the Lean module has no
/// such variable, so what determined one travels with every fact that uses it.
const FRESH_BASE: usize = 1 << 40;
pub const ASSUMED_ORIGIN: u32 = 1 << 25;

struct Ctx {
    /// The conjuncts each fact came from.
    origins: Vec<BTreeSet<u32>>,
    /// The range conjuncts of each variable.
    ub_origin: BTreeMap<usize, BTreeSet<u32>>,
    facts: Vec<Fact>,
    /// Upper bounds `0 <= v <= ub` from range facts.
    ub: BTreeMap<usize, u64>,
    outputs: Vec<usize>,
    opaque: usize,
    /// Fresh variable counter for preprocessing.
    fresh: usize,
}

fn gather_ranges(c: &PicusConstraint, out: &mut Vec<(PicusExpr, u64)>) -> bool {
    match c {
        PicusConstraint::Leq(e, b) => {
            if let PicusExpr::Const(k) = **b {
                out.push(((**e).clone(), k));
                return true;
            }
            false
        }
        PicusConstraint::Lt(e, b) => {
            if let PicusExpr::Const(k) = **b {
                if k > 0 {
                    out.push(((**e).clone(), k - 1));
                    return true;
                }
            }
            false
        }
        PicusConstraint::And(a, b) => gather_ranges(a, out) & gather_ranges(b, out),
        _ => false,
    }
}

/// Detects `E * (E - 1)` (either order), or a constant multiple of it, and returns `E`.
///
/// A bit constraint on a linear form `L` expands to `L^2 - L`, so `L` is recovered from the
/// degree-one part and accepted when its square minus itself reproduces the polynomial.
fn bit_expr(p: &Poly) -> Option<Poly> {
    let lin: BTreeMap<Mono, u64> =
        p.0.iter()
            .filter(|(m, _)| m.iter().map(|(_, e)| *e).sum::<u32>() <= 1)
            .map(|(m, c)| (m.clone(), negm(*c)))
            .collect();
    if lin.is_empty() {
        return None;
    }
    let l = Poly(lin);
    let sq = l.mul(&l)?;
    let cand = sq.add(&l.scale(P - 1));
    if cand == *p {
        Some(l)
    } else {
        let (m0, c0) = p.0.iter().find(|(m, _)| m.iter().map(|(_, e)| *e).sum::<u32>() == 2)?;
        let _ = m0;
        let k = *c0;
        let lin2: BTreeMap<Mono, u64> =
            p.0.iter()
                .filter(|(m, _)| m.iter().map(|(_, e)| *e).sum::<u32>() <= 1)
                .map(|(m, c)| (m.clone(), negm(mulm(*c, invm(k)))))
                .collect();
        let l2 = Poly(lin2);
        let sq2 = l2.mul(&l2)?;
        if sq2.add(&l2.scale(P - 1)).scale(k) == *p && !l2.is_zero() {
            Some(l2)
        } else {
            None
        }
    }
}

impl Ctx {
    fn new(m: &PicusModule) -> (Self, BTreeSet<usize>) {
        let mut fresh = FRESH_BASE;
        let mut facts = vec![];
        let mut ub: BTreeMap<usize, u64> = BTreeMap::new();
        let mut known = BTreeSet::new();
        let mut opaque = 0;
        let mut outputs = vec![];
        let mut origins: Vec<BTreeSet<u32>> = vec![];
        let mut ub_origin: BTreeMap<usize, BTreeSet<u32>> = BTreeMap::new();
        let tag = |facts: &Vec<Fact>, origins: &mut Vec<BTreeSet<u32>>, o: &[u32]| {
            while origins.len() < facts.len() {
                origins.push(o.iter().copied().collect());
            }
        };

        let bind = |e: &PicusExpr, facts: &mut Vec<Fact>, fresh: &mut usize| -> Option<usize> {
            if let PicusExpr::Var(v) = e {
                return Some(*v);
            }
            let p = to_poly(e)?;
            let t = *fresh;
            *fresh += 1;
            facts.push(Fact::Zero(p.add(&Poly::var(t).scale(P - 1))));
            Some(t)
        };

        let ports = m.inputs.iter().enumerate().map(|(j, e)| (INPUT_ORIGIN + j as u32, e)).chain(
            m.assume_deterministic.iter().enumerate().map(|(j, e)| (ASSUMED_ORIGIN + j as u32, e)),
        );
        for (origin, e) in ports {
            tag(&facts, &mut origins, &[]);
            match to_poly(e) {
                Some(p) if p.single_var().is_some() && matches!(e, PicusExpr::Var(_)) => {
                    known.insert(p.single_var().unwrap());
                }
                Some(p) => {
                    let t = fresh;
                    fresh += 1;
                    known.insert(t);
                    facts.push(Fact::Zero(p.add(&Poly::var(t).scale(P - 1))));
                }
                None => opaque += 1,
            }
            tag(&facts, &mut origins, &[origin]);
        }
        for e in &m.outputs {
            if let Some(v) = bind(e, &mut facts, &mut fresh) {
                outputs.push(v);
            }
        }
        tag(&facts, &mut origins, &[]);
        for (ci, c) in m.constraints.iter().enumerate() {
            let ci = ci as u32;
            tag(&facts, &mut origins, &[]);
            let mut ranges = vec![];
            if gather_ranges(c, &mut ranges) {
                for (e, k) in ranges {
                    match e {
                        PicusExpr::Var(v) => {
                            let cur = ub.entry(v).or_insert(k);
                            *cur = (*cur).min(k);
                            ub_origin.entry(v).or_default().insert(ci);
                        }
                        _ => {
                            if let Some(p) = to_poly(&e) {
                                let t = fresh;
                                fresh += 1;
                                ub.insert(t, k);
                                ub_origin.entry(t).or_default().insert(ci);
                                facts.push(Fact::Zero(p.add(&Poly::var(t).scale(P - 1))));
                            } else {
                                opaque += 1;
                            }
                        }
                    }
                }
                tag(&facts, &mut origins, &[ci]);
                continue;
            }
            match c {
                PicusConstraint::Eq(e) => match to_poly(e) {
                    Some(p) => facts.push(Fact::Zero(p)),
                    None => {
                        opaque += 1;
                        facts.push(Fact::Opaque)
                    }
                },
                PicusConstraint::Iff(l, r) => {
                    if let (PicusConstraint::Eq(le), PicusConstraint::Lt(a, b)) = (&**l, &**r) {
                        if let (Some(lp), Some(ap), Some(bp)) =
                            (to_poly(le), to_poly(a), to_poly(b))
                        {
                            let v = lp.add(&Poly::constant(1)).single_var();
                            if let Some(v) = v {
                                facts.push(Fact::IffLt { v, a: ap, b: bp });
                                tag(&facts, &mut origins, &[ci]);
                                continue;
                            }
                        }
                    }
                    opaque += 1;
                    facts.push(Fact::Opaque);
                }
                _ => {
                    opaque += 1;
                    facts.push(Fact::Opaque);
                }
            }
            tag(&facts, &mut origins, &[ci]);
        }
        let nc = m.constraints.len() as u32;
        for (j, call) in m.calls.iter().enumerate() {
            let outs: Option<Vec<Poly>> = call.outputs.iter().map(to_poly).collect();
            let ins: Option<Vec<Poly>> = call.inputs.iter().map(to_poly).collect();
            match (outs, ins) {
                (Some(outs), Some(ins)) => {
                    facts.push(Fact::Call { outs, ins, lemma: None, guard: vec![] })
                }
                _ => opaque += 1,
            }
            tag(&facts, &mut origins, &[nc + j as u32]);
        }
        let marks = GADGET_MARKS.lock().unwrap().get(&m.name).cloned().unwrap_or_default();
        let skipped = std::env::var("PICUS_SKIP_GADGETS").unwrap_or_default();
        let skipped: BTreeSet<&str> = skipped.split(',').filter(|g| !g.is_empty()).collect();
        let mut residues = Residues { ghosts: BTreeMap::new(), entries: vec![] };
        for mark in marks.iter().filter(|mark| !skipped.contains(mark.gadget)) {
            let gate = to_poly(&mark.gate).map(|g| g.add(&Poly::constant(P - 1)));
            match (gadget_fact(mark, &mut residues, &mut facts, &mut fresh), gate) {
                (Some((outs, ins, lemma)), Some(gate)) => {
                    let guard = if gate.is_zero() { vec![] } else { vec![gate] };
                    facts.push(Fact::Call { outs, ins, lemma: Some(lemma), guard })
                }
                (Some(_), None) => opaque += 1,
                (None, _) => {
                    tracing::debug!("gadget {} not summarized in {}", mark.gadget, m.name)
                }
            }
        }
        facts.extend(residues.links(&ub));
        tag(&facts, &mut origins, &[]);
        for (bytes, flag, why) in canonical_words(&facts, &origins, &ub, &ub_origin) {
            let ghost = fresh;
            fresh += 1;
            let word = bytes
                .iter()
                .enumerate()
                .fold(Poly::default(), |acc, (i, b)| acc.add(&Poly::var(*b).scale(1 << (8 * i))));
            facts.push(Fact::Zero(Poly::var(ghost).add(&word.scale(P - 1))));
            let mut outs: Vec<Poly> = bytes.iter().map(|b| Poly::var(*b)).collect();
            outs.push(Poly::var(flag));
            facts.push(Fact::Call {
                outs,
                ins: vec![Poly::var(ghost)],
                lemma: Some("canonical_word"),
                guard: vec![],
            });
            let why: Vec<u32> = why.into_iter().collect();
            tag(&facts, &mut origins, &why);
        }
        normalize(&mut facts, &origins, &mut ub, &mut ub_origin, &mut fresh);
        (Ctx { origins, ub_origin, facts, ub, outputs, opaque, fresh }, known)
    }
}

/// A word under the field's range checker: bytes `b₀..b₃`, a flag `z` and the constraints
/// `z·(b₃ − 127) = 0`, `z·(b₀ + b₁ + b₂) = 0`, `b₃·(1 − z) < 127`.
type CanonicalWord = ([usize; 4], usize, BTreeSet<u32>);

/// **Canonical words**: the range checker of a word (`KoalaBearWordRangeChecker`) admits
/// exactly the byte strings whose value is below `p = 127·2²⁴ + 1`: either `b₃ < 127`, or
/// `b₃ = 127` and the low bytes vanish.  A value below `p` has one byte string, and the flag
/// says which case holds, so the bytes and the flag are functions of the word's field value.
/// Returns, for every checker found among `facts`, the bytes in order of weight (read off a
/// linear fact that mentions the word), the flag, and the conjuncts the checker consists of.
/// A low byte may be ranged under gates (`b·g ≤ 255`, `b·(1 − g) ≤ 255`): the gates cited
/// are linear in bits and sum to one, so one of them is one and the byte is bounded.
fn canonical_words(
    facts: &[Fact],
    origins: &[BTreeSet<u32>],
    ub: &BTreeMap<usize, u64>,
    ub_origin: &BTreeMap<usize, BTreeSet<u32>>,
) -> Vec<CanonicalWord> {
    let zero = |i: usize| match &facts[i] {
        Fact::Zero(p) => Some(p),
        _ => None,
    };
    let mut out = vec![];
    for i in 0..facts.len() {
        let Some(p) = zero(i) else { continue };
        if p.0.len() != 2 {
            continue;
        }
        let Some((z, top)) = p.0.iter().find_map(|(m, c)| match m.as_slice() {
            [(z, 1)] if *c == P - 127 => p.0.iter().find_map(|(m2, c2)| match m2.as_slice() {
                [(a, 1), (b, 1)] if *c2 == 1 && (a == z || b == z) => {
                    Some((*z, if a == z { *b } else { *a }))
                }
                _ => None,
            }),
            _ => None,
        }) else {
            continue;
        };
        let pair = |v: usize| -> Mono {
            let mut m = vec![(v, 1), (z, 1)];
            m.sort_unstable();
            m
        };
        let low = (0..facts.len()).find_map(|j| {
            let q = zero(j)?;
            if q.0.len() != 3 || q.0.values().any(|c| *c != 1) {
                return None;
            }
            let vars: Vec<usize> =
                q.0.keys()
                    .filter_map(|m| match m.as_slice() {
                        [(a, 1), (b, 1)] if *a == z => Some(*b),
                        [(a, 1), (b, 1)] if *b == z => Some(*a),
                        _ => None,
                    })
                    .collect();
            (vars.len() == 3).then_some((j, vars))
        });
        let Some((j, low)) = low else { continue };
        let bit = |x: usize| -> Option<Option<usize>> {
            if ub.get(&x).is_some_and(|b| *b <= 1) {
                return Some(None);
            }
            (0..facts.len())
                .find(|k| {
                    zero(*k).is_some_and(|q| {
                        q.0.len() == 2
                            && q.0
                                .get(&vec![(x, 2)])
                                .is_some_and(|c| q.0.get(&vec![(x, 1)]) == Some(&((P - *c) % P)))
                    })
                })
                .map(Some)
        };
        let gated_byte = |v: usize| -> Vec<(usize, usize, Poly)> {
            (0..facts.len())
                .filter_map(|k| {
                    let q = zero(k)?;
                    let mut bound = None;
                    let mut gate = Poly::default();
                    for (m, c) in q.0.iter() {
                        match m.as_slice() {
                            [(t, 1)]
                                if *t != v
                                    && *c == P - 1
                                    && bound.is_none()
                                    && ub.get(t).is_some_and(|b| *b <= 255) =>
                            {
                                bound = Some(*t);
                            }
                            _ => {
                                let rest: Mono =
                                    m.iter().copied().filter(|(x, _)| *x != v).collect();
                                let linear = rest.len() <= 1
                                    && rest.iter().all(|(x, e)| *e == 1 && bit(*x).is_some());
                                if !m.contains(&(v, 1)) || !linear {
                                    return None;
                                }
                                gate.0.insert(rest, *c);
                            }
                        }
                    }
                    Some((k, bound?, gate))
                })
                .collect()
        };
        let mut byte_ranges: Vec<(usize, usize)> = vec![];
        let mut gate_bits: Vec<usize> = vec![];
        let mut bit_facts: Vec<usize> = vec![];
        let mut bounded = true;
        for v in &low {
            if ub.get(v).is_some_and(|b| *b <= 255) {
                continue;
            }
            let gated = gated_byte(*v);
            let cover = (0..gated.len()).find_map(|a| {
                (a..gated.len()).find_map(|b| {
                    let sum = if a == b { gated[a].2.clone() } else { gated[a].2.add(&gated[b].2) };
                    (sum.as_constant() == Some(1)).then_some(if a == b {
                        vec![a]
                    } else {
                        vec![a, b]
                    })
                })
            });
            let Some(cover) = cover else {
                bounded = false;
                break;
            };
            for c in cover {
                byte_ranges.push((gated[c].0, gated[c].1));
                for (x, _) in gated[c].2 .0.keys().flatten() {
                    gate_bits.push(*x);
                    if let Some(Some(k)) = bit(*x) {
                        bit_facts.push(k);
                    }
                }
            }
        }
        if !bounded {
            continue;
        }
        let range = (0..facts.len()).find_map(|k| {
            let q = zero(k)?;
            if q.0.len() != 3
                || q.0.get(&vec![(top, 1)]) != Some(&1)
                || q.0.get(&pair(top)) != Some(&(P - 1))
            {
                return None;
            }
            q.0.iter().find_map(|(m, c)| match m.as_slice() {
                [(t, 1)] if *t != top && *c == P - 1 && ub.get(t).is_some_and(|b| *b <= 126) => {
                    Some((k, *t))
                }
                _ => None,
            })
        });
        let Some((k, t)) = range else { continue };
        let order = facts.iter().find_map(|f| {
            let Fact::Zero(w) = f else { return None };
            let c3 = *w.0.get(&vec![(top, 1)])?;
            let unit = mulm(c3, invm(1 << 24));
            let mut bytes = [usize::MAX; 3];
            for v in &low {
                let c = *w.0.get(&vec![(*v, 1)])?;
                let weight = mulm(c, invm(unit));
                let slot = [1u64, 256, 65536].iter().position(|x| *x == weight)?;
                bytes[slot] = *v;
            }
            bytes.iter().all(|b| *b != usize::MAX).then_some(bytes)
        });
        let Some([b0, b1, b2]) = order else { continue };
        let mut why: BTreeSet<u32> = BTreeSet::new();
        for f in [i, j, k].into_iter().chain(byte_ranges.iter().map(|r| r.0)).chain(bit_facts) {
            why.extend(origins.get(f).cloned().unwrap_or_default());
        }
        for v in [b0, b1, b2, top, z, t]
            .into_iter()
            .chain(byte_ranges.iter().map(|r| r.1))
            .chain(gate_bits.iter().copied())
        {
            why.extend(ub_origin.get(&v).cloned().unwrap_or_default());
        }
        out.push(([b0, b1, b2, top], z, why));
    }
    out
}

/// **Quadratic**: `A x² + B x + C = 0` in a single unknown `x ≤ U`, with `A` a nonzero constant
/// and the discriminant `D = B² − 4AC` a constant.  The roots differ by `d` with
/// `d² = D / A²`; when `D = 0` the root is unique, and when no `t ∈ [1, U]` has `t² = D / A²`
/// the roots are more than `U` apart, so at most one lies in `[0, U]`.  Either way `x` is a
/// function of the known variables (a carry bit written as `E(E − 1) = 0` over a byte whose
/// `E` is not linear: `d = ±256`).
fn quadratic_separated(p: &Poly, x: usize, ub: &BTreeMap<usize, u64>) -> bool {
    let Some(&u) = ub.get(&x) else { return false };
    if u > MAX_DOMAIN {
        return false;
    }
    let mut coef = [Poly::default(), Poly::default(), Poly::default()];
    for (m, c) in p.0.iter() {
        let e = m.iter().find(|(v, _)| *v == x).map(|(_, e)| *e).unwrap_or(0) as usize;
        if e > 2 {
            return false;
        }
        let rest: Mono = m.iter().copied().filter(|(v, _)| *v != x).collect();
        coef[e].0.insert(rest, *c);
    }
    let [c0, c1, c2] = coef;
    let Some(a) = c2.as_constant().filter(|a| *a != 0) else { return false };
    let Some(b2) = c1.mul(&c1) else { return false };
    let four_ac = c0.scale(mulm(4, a));
    let Some(disc) = b2.add(&four_ac.scale(P - 1)).as_constant() else { return false };
    if disc == 0 {
        return true;
    }
    let q = mulm(disc, invm(mulm(a, a)));
    !(1..=u).any(|t| mulm(t, t) == q)
}

/// Enumerates a fact whose variables are all range-checked over a domain of at most
/// `MAX_DOMAIN` points.  `Some(None)`: no point satisfies it; `Some(Some(vals))`: exactly one
/// does; `None`: not applicable or several solutions.
#[allow(clippy::option_option)]
fn small_domain(
    p: &Poly,
    vars: &BTreeSet<usize>,
    ub: &BTreeMap<usize, u64>,
) -> Option<Option<Vec<(usize, u64)>>> {
    if vars.is_empty() || vars.len() > 6 {
        return None;
    }
    let vs: Vec<usize> = vars.iter().copied().collect();
    let mut size: u64 = 1;
    for v in &vs {
        size = size.checked_mul(ub.get(v)? + 1)?;
        if size > MAX_DOMAIN {
            return None;
        }
    }
    let mut found: Option<Vec<(usize, u64)>> = None;
    let mut cur = vec![0u64; vs.len()];
    loop {
        let env: BTreeMap<usize, u64> = vs.iter().copied().zip(cur.iter().copied()).collect();
        if p.subst(&env).is_zero() {
            if found.is_some() {
                return None;
            }
            found = Some(env.into_iter().collect());
        }
        let mut i = 0;
        loop {
            if i == vs.len() {
                return Some(found);
            }
            cur[i] += 1;
            if cur[i] > ub[&vs[i]] {
                cur[i] = 0;
                i += 1;
            } else {
                break;
            }
        }
    }
}

/// Positional injectivity: is `sum c_i x_i` injective over `0 <= x_i <= ub_i` modulo `p`?
/// Tries every rescaling that makes one coefficient a power of two.
fn positional_injective(coefs: &[(usize, u64)], ub: &BTreeMap<usize, u64>) -> bool {
    let bounds: Vec<u64> = coefs.iter().map(|(v, _)| ub[v]).collect();
    for &(_, c0) in coefs {
        let inv0 = invm(c0);
        for k in 0..31u32 {
            let s = mulm(inv0, 1u64 << k);
            let mut terms: Vec<(i128, i128)> = coefs
                .iter()
                .zip(&bounds)
                .map(|((_, c), b)| (signed(mulm(*c, s)).abs(), *b as i128))
                .collect();
            let total: i128 = terms.iter().map(|(c, b)| c * b).sum();
            if total >= P as i128 {
                continue;
            }
            terms.sort();
            let mut acc: i128 = 0;
            let mut ok = true;
            for (c, b) in &terms {
                if *c <= acc {
                    ok = false;
                    break;
                }
                acc += c * b;
            }
            if ok {
                return true;
            }
        }
    }
    false
}

/// `c * (x - y)`: two variables of degree one with opposite coefficients and nothing else.
fn var_equality(p: &Poly) -> Option<(usize, usize)> {
    if p.0.len() != 2 {
        return None;
    }
    let mut it = p.0.iter();
    let (m1, c1) = it.next()?;
    let (m2, c2) = it.next()?;
    if m1.len() == 1 && m2.len() == 1 && m1[0].1 == 1 && m2[0].1 == 1 && addm(*c1, *c2) == 0 {
        Some((m1[0].0, m2[0].0))
    } else {
        None
    }
}

/// Bit constraints on variables become range facts; on expressions `E * (E - 1) = 0`, a fresh
/// bit `k` with `E - k = 0`.  Idempotent: a rewritten fact is replaced, not duplicated.
fn normalize(
    facts: &mut [Fact],
    origins: &[BTreeSet<u32>],
    ub: &mut BTreeMap<usize, u64>,
    ub_origin: &mut BTreeMap<usize, BTreeSet<u32>>,
    fresh: &mut usize,
) {
    for (f, o) in facts.iter_mut().zip(origins) {
        normalize_one(f, o, ub, ub_origin, fresh);
    }
}

/// Puts one fact into the shape the rules read; a bound it records (a bit, or a bound copied
/// across `x = y`) is charged to the fact's `origin` in `ub_origin`.
fn normalize_one(
    f: &mut Fact,
    origin: &BTreeSet<u32>,
    ub: &mut BTreeMap<usize, u64>,
    ub_origin: &mut BTreeMap<usize, BTreeSet<u32>>,
    fresh: &mut usize,
) {
    let Fact::Zero(p) = f else { return };
    if let Some((x, y)) = var_equality(p) {
        let bound = match (ub.get(&x), ub.get(&y)) {
            (Some(a), Some(b)) => Some(*a.min(b)),
            (Some(a), None) | (None, Some(a)) => Some(*a),
            (None, None) => None,
        };
        if let Some(b) = bound {
            ub.insert(x, b);
            ub.insert(y, b);
            let mut o = origin.clone();
            o.extend(ub_origin.get(&x).cloned().unwrap_or_default());
            o.extend(ub_origin.get(&y).cloned().unwrap_or_default());
            ub_origin.insert(x, o.clone());
            ub_origin.insert(y, o);
        }
    }
    if p.0.is_empty() || p.0.keys().all(|m| m.is_empty()) {
        return;
    }
    if let Some(l) = bit_expr(p) {
        if let Some(v) = l.single_var() {
            if l.0.values().next() == Some(&1) {
                let cur = ub.entry(v).or_insert(1);
                *cur = (*cur).min(1);
                ub_origin.entry(v).or_default().extend(origin.iter().copied());
                *f = Fact::Opaque;
                return;
            }
        }
        let k = *fresh;
        *fresh += 1;
        ub.insert(k, 1);
        ub_origin.entry(k).or_default().extend(origin.iter().copied());
        *f = Fact::Zero(l.add(&Poly::var(k).scale(P - 1)));
    }
}

/// The variables a fact mentions.
fn fact_vars(f: &Fact) -> BTreeSet<usize> {
    match f {
        Fact::Zero(p) => p.vars(),
        Fact::Call { outs, ins, guard, .. } => {
            outs.iter().chain(ins).chain(guard).flat_map(|p| p.vars()).collect()
        }
        Fact::IffLt { v, a, b } => {
            let mut s = a.vars();
            s.extend(b.vars());
            s.insert(*v);
            s
        }
        Fact::Opaque => BTreeSet::new(),
    }
}

/// Whether a fact mentions the variable.
fn mentions(f: &Fact, v: usize) -> bool {
    let has = |p: &Poly| p.0.keys().any(|m| m.iter().any(|(x, _)| *x == v));
    match f {
        Fact::Zero(p) => has(p),
        Fact::Call { outs, ins, guard, .. } => outs.iter().chain(ins).chain(guard).any(has),
        Fact::IffLt { v: w, a, b } => *w == v || has(a) || has(b),
        Fact::Opaque => false,
    }
}

fn subst_fact(f: &Fact, env: &BTreeMap<usize, u64>) -> Fact {
    match f {
        Fact::Zero(p) => Fact::Zero(p.subst(env)),
        Fact::Call { outs, ins, lemma, guard } => Fact::Call {
            outs: outs.iter().map(|p| p.subst(env)).collect(),
            ins: ins.iter().map(|p| p.subst(env)).collect(),
            lemma: *lemma,
            guard: guard.iter().map(|p| p.subst(env)).collect(),
        },
        Fact::IffLt { v, a, b } => Fact::IffLt { v: *v, a: a.subst(env), b: b.subst(env) },
        Fact::Opaque => Fact::Opaque,
    }
}

/// A case split.
enum Split {
    /// A known bit: both values.
    Bit(usize),
    /// A known polynomial: zero, or nonzero.
    Coef(Poly),
    /// A known one-hot set (`Σ b = 1`, all bits): one branch per member, that member `1` and the
    /// others `0`.
    OneHot(Vec<usize>),
}

/// One branch of the search.
#[derive(Clone)]
struct State {
    facts: Vec<Fact>,
    ub: BTreeMap<usize, u64>,
    known: BTreeSet<usize>,
    /// Known polynomials, monic, established nonzero on this branch.
    nonzero: Vec<Poly>,
    fresh: usize,
    /// Some fact reduced to a nonzero constant: no witness takes this branch.
    infeasible: bool,
    /// Values assigned on this branch (debug dump of a stuck branch's case).
    values: BTreeMap<usize, u64>,
    /// Facts already used as a pivot definition on this branch.
    pivots_used: BTreeSet<usize>,
    /// Variables this branch determined, in order, with the rule and the conjuncts it used.
    log: Vec<(usize, Rule, BTreeSet<u32>)>,
    /// Values this branch learned, as `(steps logged before it, variable, value, conjuncts)`.
    vlog: Vec<(usize, usize, u64, BTreeSet<u32>)>,
    /// The conjuncts each fact depends on (its own, plus those of every value or definition
    /// substituted into it).
    origins: Vec<BTreeSet<u32>>,
    /// The range conjuncts of each variable.
    ub_origin: BTreeMap<usize, BTreeSet<u32>>,
    /// The conjuncts that fixed a variable's value or definition, for those substituted.
    vsupport: BTreeMap<usize, BTreeSet<u32>>,
    /// The conjuncts behind an infeasible branch.
    infeasible_support: BTreeSet<u32>,
}

impl State {
    /// Marks `v` known by `rule` from the conjuncts `support`; returns whether it was new.
    fn learn(&mut self, v: usize, rule: Rule, support: BTreeSet<u32>) -> bool {
        let new = self.known.insert(v);
        if new {
            if v >= FRESH_BASE {
                self.vsupport.insert(v, support.clone());
            }
            self.log.push((v, rule, support));
        }
        new
    }

    /// Assigns `v := val` from the conjuncts `support`, logging `rule` when `v` was not yet
    /// known.
    fn learn_value(&mut self, v: usize, val: u64, rule: Rule, support: BTreeSet<u32>) {
        if !self.known.contains(&v) {
            self.log.push((v, rule, support.clone()));
        }
        self.vlog.push((self.log.len(), v, val, support.clone()));
        self.vsupport.insert(v, support);
        self.assign(v, val);
    }

    /// The conjuncts fact `i` depends on, with the range conjuncts of its variables.
    fn fact_support(&self, i: usize) -> BTreeSet<u32> {
        let mut out = self.origins.get(i).cloned().unwrap_or_default();
        for v in fact_vars(&self.facts[i]) {
            if let Some(r) = self.ub_origin.get(&v) {
                out.extend(r);
            }
            if let Some(r) = self.vsupport.get(&v) {
                out.extend(r);
            }
        }
        out
    }

    /// The conjuncts of every fact mentioning one of `vars` (a rule that reads many facts).
    fn near_support(&self, vars: &[usize]) -> BTreeSet<u32> {
        let mut out = BTreeSet::new();
        for i in 0..self.facts.len() {
            if vars.iter().any(|&v| mentions(&self.facts[i], v)) {
                out.extend(self.fact_support(i));
            }
        }
        for v in vars {
            if let Some(r) = self.ub_origin.get(v) {
                out.extend(r);
            }
            if let Some(r) = self.vsupport.get(v) {
                out.extend(r);
            }
        }
        out
    }

    /// [`Self::near_support`] widened `hops` times through the facts' other unknowns (a rule
    /// that combines facts: probing, elimination).
    fn near_support_hops(&self, vars: &[usize], hops: usize) -> BTreeSet<u32> {
        let mut frontier: BTreeSet<usize> = vars.iter().copied().collect();
        let mut seen = frontier.clone();
        for _ in 1..hops {
            let mut next = BTreeSet::new();
            for f in &self.facts {
                let fv = fact_vars(f);
                if fv.iter().any(|v| frontier.contains(v)) {
                    next.extend(
                        fv.into_iter().filter(|v| !self.known.contains(v) && !seen.contains(v)),
                    );
                }
            }
            seen.extend(next.iter().copied());
            frontier = next;
        }
        let all: Vec<usize> = seen.into_iter().collect();
        self.near_support(&all)
    }

    /// Adds the support of `v`'s value or definition to fact `i`, which it was substituted into.
    fn inherit(&mut self, i: usize, v: usize) {
        if let Some(r) = self.vsupport.get(&v).cloned() {
            self.origins[i].extend(r);
        }
    }

    fn is_known(&self, p: &Poly) -> bool {
        p.vars().iter().all(|v| self.known.contains(v))
    }

    fn is_nonzero(&self, a: &Poly) -> bool {
        match a.as_constant() {
            Some(c) => c != 0,
            None => self.nonzero.contains(&a.monic()),
        }
    }

    /// Substitutes `v := r` everywhere (the zero branch of a split on a known polynomial).
    /// Only facts that mention `v` are rewritten and re-normalized.
    fn assign_poly(&mut self, v: usize, r: &Poly) -> bool {
        let sub = |p: &Poly| p.subst_poly(v, r);
        let mut updates = vec![];
        for (i, f) in self.facts.iter().enumerate() {
            if !mentions(f, v) {
                continue;
            }
            let g = match f {
                Fact::Zero(p) => match sub(p) {
                    Some(q) => Fact::Zero(q),
                    None => return false,
                },
                Fact::Call { outs, ins, lemma, guard } => {
                    let o2: Option<Vec<Poly>> = outs.iter().map(sub).collect();
                    let i2: Option<Vec<Poly>> = ins.iter().map(sub).collect();
                    let g2: Option<Vec<Poly>> = guard.iter().map(sub).collect();
                    match (o2, i2, g2) {
                        (Some(outs), Some(ins), Some(guard)) => {
                            Fact::Call { outs, ins, lemma: *lemma, guard }
                        }
                        _ => return false,
                    }
                }
                Fact::IffLt { v: w, a, b } => match (sub(a), sub(b)) {
                    (Some(a), Some(b)) => Fact::IffLt { v: *w, a, b },
                    _ => return false,
                },
                Fact::Opaque => Fact::Opaque,
            };
            updates.push((i, g));
        }
        for (i, mut g) in updates {
            self.inherit(i, v);
            let o = self.origins.get(i).cloned().unwrap_or_default();
            normalize_one(&mut g, &o, &mut self.ub, &mut self.ub_origin, &mut self.fresh);
            self.facts[i] = g;
        }
        self.nonzero =
            self.nonzero.iter().filter_map(|p| p.subst_poly(v, r)).map(|p| p.monic()).collect();
        true
    }

    /// Substitutes `v := val` everywhere, marks `v` known and re-normalizes the facts that
    /// mentioned `v`.
    fn assign(&mut self, v: usize, val: u64) {
        let env: BTreeMap<usize, u64> = [(v, val)].into_iter().collect();
        self.known.insert(v);
        self.values.insert(v, val);
        if val <= 1 {
            let cur = self.ub.entry(v).or_insert(val);
            *cur = (*cur).min(val);
        }
        for i in 0..self.facts.len() {
            if mentions(&self.facts[i], v) {
                let mut g = subst_fact(&self.facts[i], &env);
                self.inherit(i, v);
                let o = self.origins.get(i).cloned().unwrap_or_default();
                normalize_one(&mut g, &o, &mut self.ub, &mut self.ub_origin, &mut self.fresh);
                self.facts[i] = g;
            }
        }
        self.nonzero = self.nonzero.iter().map(|p| p.subst(&env).monic()).collect();
    }
}

struct Search {
    outputs: Vec<usize>,
    branches: usize,
    rules: BTreeMap<Rule, usize>,
    /// Gadget lemmas a summary fired under.
    lemmas: BTreeSet<&'static str>,
    stuck: BTreeSet<usize>,
    overflow: bool,
    /// A probe's inner propagation: no elimination, no nested probes.
    probing: bool,
    /// Wall-clock deadline for the whole module.
    deadline: std::time::Instant,
    /// Time spent per phase (debug census): pass, tighten, eliminate, probe.
    phase_us: [u128; 4],
}

impl Search {
    fn bump(&mut self, r: Rule) {
        *self.rules.entry(r).or_default() += 1;
    }

    fn propagate(&mut self, st: &mut State) {
        let mut tightened = false;
        loop {
            if std::time::Instant::now() > self.deadline {
                self.overflow = true;
                return;
            }
            let mut progress = false;
            let t_pass = std::time::Instant::now();
            let mut i = 0;
            while i < st.facts.len() {
                if i % 256 == 0 && std::time::Instant::now() > self.deadline {
                    self.overflow = true;
                    return;
                }
                let f = st.facts[i].clone();
                i += 1;
                match f {
                    Fact::Call { outs, ins, lemma, guard } => {
                        if guard.iter().all(|p| p.is_zero()) && ins.iter().all(|p| st.is_known(p)) {
                            for o in outs {
                                if let Some(v) = o.single_var() {
                                    let rule =
                                        if lemma.is_some() { Rule::Gadget } else { Rule::Call };
                                    if st.learn(v, rule, st.fact_support(i - 1)) {
                                        match lemma {
                                            Some(l) => {
                                                self.bump(Rule::Gadget);
                                                self.lemmas.insert(l);
                                            }
                                            None => self.bump(Rule::Call),
                                        }
                                        progress = true;
                                    }
                                }
                            }
                        }
                    }
                    Fact::IffLt { v, a, b } => {
                        if !st.known.contains(&v)
                            && st.ub.get(&v) == Some(&1)
                            && st.is_known(&a)
                            && st.is_known(&b)
                        {
                            st.learn(v, Rule::IffBit, st.fact_support(i - 1));
                            self.bump(Rule::IffBit);
                            progress = true;
                        }
                    }
                    Fact::Zero(p) => {
                        if let Some(c) = p.as_constant() {
                            if c != 0 {
                                st.infeasible_support = st.fact_support(i - 1);
                                st.infeasible = true;
                                return;
                            }
                            continue;
                        }
                        let all = p.vars();
                        if let Some(sol) = small_domain(&p, &all, &st.ub) {
                            match sol {
                                None => {
                                    st.infeasible_support = st.fact_support(i - 1);
                                    st.infeasible = true;
                                    return;
                                }
                                Some(vals) => {
                                    self.bump(Rule::SmallDomain);
                                    let sup = st.fact_support(i - 1);
                                    for (v, x) in vals {
                                        st.learn_value(v, x, Rule::SmallDomain, sup.clone());
                                    }
                                    progress = true;
                                    continue;
                                }
                            }
                        }
                        if all.len() == 1 {
                            let x = *all.iter().next().unwrap();
                            if p.degree_in(x) == 1 {
                                let (a, b) = p.split_linear(x);
                                if let (Some(c), Some(bc)) = (a.as_constant(), b.as_constant()) {
                                    if c != 0 {
                                        if !st.known.contains(&x) {
                                            self.bump(Rule::Linear);
                                        }
                                        st.learn_value(
                                            x,
                                            mulm(negm(bc), invm(c)),
                                            Rule::Linear,
                                            st.fact_support(i - 1),
                                        );
                                        progress = true;
                                        continue;
                                    }
                                }
                            }
                        }
                        let unknown: Vec<usize> =
                            all.into_iter().filter(|v| !st.known.contains(v)).collect();
                        if unknown.len() == 1 {
                            let x = unknown[0];
                            if p.degree_in(x) == 2 && quadratic_separated(&p, x, &st.ub) {
                                st.learn(x, Rule::Quadratic, st.fact_support(i - 1));
                                self.bump(Rule::Quadratic);
                                progress = true;
                                continue;
                            }
                            if p.degree_in(x) != 1 {
                                continue;
                            }
                            let (a, b) = p.split_linear(x);
                            if let Some(c) = a.as_constant() {
                                if c != 0 {
                                    self.bump(Rule::Linear);
                                    progress = true;
                                    if let Some(bc) = b.as_constant() {
                                        st.learn_value(
                                            x,
                                            mulm(negm(bc), invm(c)),
                                            Rule::Linear,
                                            st.fact_support(i - 1),
                                        );
                                    } else {
                                        let sup = st.fact_support(i - 1);
                                        st.learn(x, Rule::Linear, sup.clone());
                                        st.vsupport.insert(x, sup);
                                        if b.0.len() <= MAX_SUBST_TERMS
                                            && b.0.keys().all(|m| {
                                                m.iter().map(|(_, e)| *e).sum::<u32>() <= 1
                                            })
                                        {
                                            let r = b.scale(negm(invm(c)));
                                            st.assign_poly(x, &r);
                                        }
                                    }
                                }
                            } else if b.is_zero() && st.is_nonzero(&a) {
                                self.bump(Rule::LinearInverse);
                                progress = true;
                                st.learn_value(x, 0, Rule::LinearInverse, st.fact_support(i - 1));
                            } else if b.as_constant().map(|c| c != 0).unwrap_or(false)
                                || st.is_nonzero(&a)
                            {
                                st.learn(x, Rule::LinearInverse, st.fact_support(i - 1));
                                self.bump(Rule::LinearInverse);
                                progress = true;
                            }
                        } else if unknown.len() >= 2 && unknown.len() <= MAX_POSITIONAL {
                            if !unknown.iter().all(|v| st.ub.contains_key(v)) {
                                continue;
                            }
                            let mut coefs = vec![];
                            let mut ok = true;
                            for &x in &unknown {
                                if p.degree_in(x) != 1 {
                                    ok = false;
                                    break;
                                }
                                let (a, _) = p.split_linear(x);
                                match a.as_constant() {
                                    Some(c) if c != 0 => coefs.push((x, c)),
                                    _ => {
                                        ok = false;
                                        break;
                                    }
                                }
                            }
                            if ok && positional_injective(&coefs, &st.ub) {
                                for &x in &unknown {
                                    st.learn(x, Rule::Positional, st.fact_support(i - 1));
                                }
                                self.bump(Rule::Positional);
                                progress = true;
                            } else if ok {
                                let rest = p.subst(&unknown.iter().map(|v| (*v, 0)).collect());
                                let same_sign = coefs.iter().all(|(_, c)| signed(*c) > 0)
                                    || coefs.iter().all(|(_, c)| signed(*c) < 0);
                                let total: i128 = coefs
                                    .iter()
                                    .map(|(v, c)| signed(*c).abs() * st.ub[v] as i128)
                                    .sum();
                                if same_sign && total < P as i128 && rest.as_constant() == Some(0) {
                                    for &x in &unknown {
                                        st.learn_value(x, 0, Rule::ZeroSum, st.fact_support(i - 1));
                                    }
                                    self.bump(Rule::ZeroSum);
                                    progress = true;
                                }
                            }
                        }
                    }
                    Fact::Opaque => {}
                }
            }
            if st.infeasible {
                return;
            }
            self.phase_us[0] += t_pass.elapsed().as_micros();
            if progress {
                tightened = false;
                continue;
            }
            if self.one_hot(st)
                || self.one_hot_positional(st)
                || self.is_zero_gadget(st)
                || self.pivot_substitute(st)
            {
                continue;
            }
            let t = std::time::Instant::now();
            let moved = !tightened && self.tighten(st);
            self.phase_us[1] += t.elapsed().as_micros();
            if moved {
                tightened = true;
                continue;
            }
            if self.probing {
                break;
            }
            let t = std::time::Instant::now();
            let eliminated = self.eliminate(st);
            self.phase_us[2] += t.elapsed().as_micros();
            if !eliminated {
                break;
            }
        }
    }

    /// **One-hot**: unknown bits `b_k` with `b_k · (S − c_k) = 0` for one known polynomial `S`
    /// and pairwise distinct constants `c_k`, together with `Σ_k b_k = 1`, are all determined:
    /// `b_k = 1` forces `S = c_k`, which at most one `k` satisfies, so both witnesses select the
    /// same `k` (a byte- or bit-shift selector decoded from a known shift amount).
    ///
    /// **One-hot sum**: for a known one-hot set (`Σ_k b_k = 1`, all `b_k` known bits), an
    /// unknown `m` with a fact `b_k · (α m + β_k) = 0` for *every* `k` (same constant `α ≠ 0`,
    /// `β_k` known) is determined: summing the facts gives `α m + Σ_k b_k β_k = 0` (a shift
    /// multiplier `m = Σ_k b_k 2^k`).  Returns whether anything became known.
    fn one_hot(&mut self, st: &mut State) -> bool {
        let mut selector: BTreeMap<usize, (Poly, u64)> = BTreeMap::new();
        for f in &st.facts {
            let Fact::Zero(p) = f else { continue };
            let unknown: Vec<usize> =
                p.vars().into_iter().filter(|v| !st.known.contains(v)).collect();
            let [b] = unknown.as_slice() else { continue };
            if st.ub.get(b) != Some(&1) || p.degree_in(*b) != 1 {
                continue;
            }
            let (a, rest) = p.split_linear(*b);
            if !rest.is_zero() || a.as_constant().is_some() {
                continue;
            }
            let c = a.0.get(&vec![]).copied().unwrap_or(0);
            let s = a.add(&Poly::constant(negm(c))).monic();
            let scale = {
                let lead = a.add(&Poly::constant(negm(c)));
                let (_, k) = lead.0.iter().next().expect("non-constant");
                *k
            };
            selector.insert(*b, (s, mulm(negm(c), invm(scale))));
        }
        let mut fixed = vec![];
        let one_hot_sets: Vec<Vec<usize>> = st
            .facts
            .iter()
            .filter_map(|f| {
                let Fact::Zero(p) = f else { return None };
                if p.0.get(&vec![]).copied() != Some(P - 1) {
                    return None;
                }
                let bits: Vec<usize> =
                    p.0.iter()
                        .filter(|(m, _)| !m.is_empty())
                        .filter_map(|(m, c)| match m.as_slice() {
                            [(v, 1)] if *c == 1 && st.ub.get(v) == Some(&1) => Some(*v),
                            _ => None,
                        })
                        .collect();
                (bits.len() >= 2 && bits.len() + 1 == p.0.len()).then_some(bits)
            })
            .collect();
        for set in one_hot_sets.iter().filter(|s| s.iter().all(|b| st.known.contains(b))) {
            let members: BTreeSet<usize> = set.iter().copied().collect();
            let mut gated: BTreeMap<usize, (u64, BTreeSet<usize>)> = BTreeMap::new();
            for f in &st.facts {
                let Fact::Zero(p) = f else { continue };
                let unknown: Vec<usize> =
                    p.vars().into_iter().filter(|v| !st.known.contains(v)).collect();
                let [m] = unknown.as_slice() else { continue };
                if p.degree_in(*m) != 1 {
                    continue;
                }
                let (a, _) = p.split_linear(*m);
                let [(mono, alpha)] = a.0.iter().collect::<Vec<_>>()[..] else { continue };
                let [(b, 1)] = mono.as_slice() else { continue };
                if !members.contains(b) {
                    continue;
                }
                let entry = gated.entry(*m).or_insert((*alpha, BTreeSet::new()));
                if entry.0 == *alpha {
                    entry.1.insert(*b);
                }
            }
            for (m, (_, covered)) in gated {
                if covered == members && !st.known.contains(&m) {
                    let mut why = set.clone();
                    why.push(m);
                    fixed.push((m, why));
                }
            }
        }
        if !fixed.is_empty() {
            for (m, why) in fixed {
                if st.learn(m, Rule::OneHot, st.near_support(&why)) {
                    self.bump(Rule::OneHot);
                }
            }
            return true;
        }
        if selector.len() < 2 {
            return false;
        }
        for f in &st.facts {
            let Fact::Zero(p) = f else { continue };
            if p.0.get(&vec![]).copied() != Some(P - 1) {
                continue;
            }
            let bits: Vec<usize> =
                p.0.iter()
                    .filter(|(m, _)| !m.is_empty())
                    .filter_map(|(m, c)| match m.as_slice() {
                        [(v, 1)] if *c == 1 => Some(*v),
                        _ => None,
                    })
                    .collect();
            if bits.len() + 1 != p.0.len() || bits.len() < 2 {
                continue;
            }
            if bits.iter().any(|b| st.known.contains(b)) {
                continue;
            }
            let Some((s0, _)) = selector.get(&bits[0]) else { continue };
            let mut consts = BTreeSet::new();
            let ok = bits.iter().all(|b| match selector.get(b) {
                Some((s, c)) => s == s0 && consts.insert(*c),
                None => false,
            });
            if ok {
                let mut why = bits.clone();
                why.extend(s0.vars());
                fixed.extend(bits.iter().map(|b| (*b, why.clone())));
            }
        }
        if fixed.is_empty() {
            return false;
        }
        for (b, why) in fixed {
            if st.learn(b, Rule::OneHot, st.near_support(&why)) {
                self.bump(Rule::OneHot);
            }
        }
        true
    }

    /// **One-hot positional**: a linear fact whose unknowns are all bits, partitioned into
    /// one-hot groups (`Σ b = 1` over each group), determines every bit of those groups when the
    /// sum `Σ c_v v` takes pairwise distinct values over the choices of one bit per group (at most
    /// `MAX_DOMAIN` choices; a row position `index = Σ i·octet_i + Σ 8j·octet_num_j`).  Returns
    /// whether a bit became known.
    fn one_hot_positional(&mut self, st: &mut State) -> bool {
        let groups: Vec<Vec<usize>> = st
            .facts
            .iter()
            .filter_map(|f| {
                let Fact::Zero(p) = f else { return None };
                if p.0.get(&vec![]).copied() != Some(P - 1) {
                    return None;
                }
                let bits: Vec<usize> =
                    p.0.iter()
                        .filter(|(m, _)| !m.is_empty())
                        .filter_map(|(m, c)| match m.as_slice() {
                            [(v, 1)]
                                if *c == 1 && st.ub.get(v) == Some(&1) && !st.known.contains(v) =>
                            {
                                Some(*v)
                            }
                            _ => None,
                        })
                        .collect();
                (bits.len() >= 2 && bits.len() + 1 == p.0.len()).then_some(bits)
            })
            .collect();
        if groups.is_empty() {
            return false;
        }
        let group_of: BTreeMap<usize, usize> = groups
            .iter()
            .enumerate()
            .flat_map(|(g, bits)| bits.iter().map(move |b| (*b, g)))
            .collect();
        let mut fixed: Vec<(usize, Vec<usize>)> = vec![];
        for f in &st.facts {
            let Fact::Zero(p) = f else { continue };
            if p.0.keys().any(|m| m.iter().map(|(_, e)| *e).sum::<u32>() > 1) {
                continue;
            }
            let unknown: Vec<usize> =
                p.vars().into_iter().filter(|v| !st.known.contains(v)).collect();
            if unknown.len() < 2 || !unknown.iter().all(|v| group_of.contains_key(v)) {
                continue;
            }
            let mut used: Vec<usize> = unknown.iter().map(|v| group_of[v]).collect();
            used.sort_unstable();
            used.dedup();
            let combos: u64 = used.iter().map(|g| groups[*g].len() as u64).product();
            if used.is_empty() || combos > MAX_DOMAIN {
                continue;
            }
            let coef = |v: usize| -> u64 { p.0.get(&vec![(v, 1)]).copied().unwrap_or(0) };
            let mut sums = BTreeSet::new();
            let mut distinct = true;
            let mut idx = vec![0usize; used.len()];
            'enumerate: loop {
                let s = used
                    .iter()
                    .zip(idx.iter())
                    .fold(0u64, |acc, (g, i)| addm(acc, coef(groups[*g][*i])));
                if !sums.insert(s) {
                    distinct = false;
                    break;
                }
                for k in 0..used.len() {
                    idx[k] += 1;
                    if idx[k] < groups[used[k]].len() {
                        continue 'enumerate;
                    }
                    idx[k] = 0;
                }
                break;
            }
            if distinct {
                let why: Vec<usize> =
                    used.iter().flat_map(|g| groups[*g].iter().copied()).collect();
                fixed.extend(why.iter().map(|b| (*b, why.clone())));
            }
        }
        let mut moved = false;
        for (b, why) in fixed {
            if st.learn(b, Rule::OneHot, st.near_support(&why)) {
                self.bump(Rule::OneHot);
                moved = true;
            }
        }
        moved
    }

    /// **Pivot substitution**: a linear fact `c·v + L = 0` with a constant `c ≠ 0` and a few
    /// unknowns defines `v = −L / c`; substituting it into the *nonlinear* facts that mention `v`
    /// (the defining fact is kept) exposes known linear forms hidden in products — a word
    /// `b₀ + 256 b₁ + 65536 b₂ + 2²⁴ b₃` over unconstrained bytes whose 16-bit halves are known.
    /// A substitution is kept only when it cancels: some nonlinear fact ends with strictly fewer
    /// unknowns and none new.  Each defining fact serves once per branch.  Returns whether a
    /// substitution happened.
    fn pivot_substitute(&mut self, st: &mut State) -> bool {
        let nonlinear_in = |p: &Poly, v: usize| -> bool {
            p.0.keys().any(|m| {
                m.iter().any(|(w, _)| *w == v)
                    && m.iter().filter(|(w, _)| !st.known.contains(w)).map(|(_, e)| *e).sum::<u32>()
                        > 1
            })
        };
        for i in 0..st.facts.len() {
            if st.pivots_used.contains(&i) {
                continue;
            }
            let Fact::Zero(p) = &st.facts[i] else { continue };
            if p.0.len() > MAX_SUBST_TERMS
                || p.0.keys().any(|m| m.iter().map(|(_, e)| *e).sum::<u32>() > 1)
            {
                continue;
            }
            let unknown: Vec<usize> =
                p.vars().into_iter().filter(|v| !st.known.contains(v)).collect();
            if unknown.len() < 2 || unknown.len() > 6 {
                continue;
            }
            for &v in &unknown {
                let Some(&c) = p.0.get(&vec![(v, 1)]) else { continue };
                let targets = st
                    .facts
                    .iter()
                    .enumerate()
                    .any(|(j, f)| j != i && matches!(f, Fact::Zero(q) if nonlinear_in(q, v)));
                if !targets {
                    continue;
                }
                let rest = p.add(&Poly::var(v).scale(P - c));
                let r = rest.scale(negm(invm(c)));
                let keep = st.facts[i].clone();
                let mut trial = st.clone();
                trial.vsupport.insert(v, st.fact_support(i));
                if !trial.assign_poly(v, &r) {
                    continue;
                }
                let cancels =
                    st.facts.iter().zip(trial.facts.iter()).enumerate().any(|(j, pair)| {
                        let (Fact::Zero(before), Fact::Zero(after)) = pair else { return false };
                        if j == i || !nonlinear_in(before, v) {
                            return false;
                        }
                        let open = |q: &Poly| -> BTreeSet<usize> {
                            q.vars().into_iter().filter(|w| !st.known.contains(w)).collect()
                        };
                        let (b, a) = (open(before), open(after));
                        a.len() < b.len() && a.is_subset(&b)
                    });
                if !cancels {
                    continue;
                }
                trial.facts[i] = keep;
                trial.pivots_used.insert(i);
                *st = trial;
                self.bump(Rule::Elimination);
                return true;
            }
        }
        false
    }

    /// **IsZero**: `x · r = 0` and `r + x · w − 1 = 0` (up to a constant factor) with `x` known
    /// determine `r = [x = 0]`: `x = 0` forces `r = 1`, `x ≠ 0` forces `r = 0`, whatever the
    /// inverse witness `w`.  Returns whether a flag became known.
    fn is_zero_gadget(&mut self, st: &mut State) -> bool {
        let mut flags: BTreeMap<usize, Poly> = BTreeMap::new();
        for f in &st.facts {
            let Fact::Zero(p) = f else { continue };
            let unknown: Vec<usize> =
                p.vars().into_iter().filter(|v| !st.known.contains(v)).collect();
            let [r] = unknown.as_slice() else { continue };
            if p.degree_in(*r) != 1 {
                continue;
            }
            let (a, rest) = p.split_linear(*r);
            if rest.is_zero() && a.as_constant().is_none() && st.is_known(&a) {
                flags.insert(*r, a.monic());
            }
        }
        if flags.is_empty() {
            return false;
        }
        let mut fixed = vec![];
        for f in &st.facts {
            let Fact::Zero(q) = f else { continue };
            let unknown: Vec<usize> =
                q.vars().into_iter().filter(|v| !st.known.contains(v)).collect();
            if unknown.len() != 2 {
                continue;
            }
            for (r, w) in [(unknown[0], unknown[1]), (unknown[1], unknown[0])] {
                let Some(x) = flags.get(&r) else { continue };
                let Some(&c) = q.0.get(&vec![(r, 1)]) else { continue };
                let qn = q.scale(invm(c));
                let (xw, rest) = qn.split_linear(w);
                if q.degree_in(w) != 1 || rest != Poly::var(r).add(&Poly::constant(P - 1)) {
                    continue;
                }
                if xw.monic() == *x {
                    fixed.push(r);
                }
            }
        }
        let mut moved = false;
        for r in fixed {
            if st.learn(r, Rule::IsZero, st.near_support(&[r])) {
                self.bump(Rule::IsZero);
                moved = true;
            }
        }
        moved
    }

    /// **Bounds**: a linear fact `Σ a_i x_i + k = 0` whose variables are all range-checked is
    /// read as two sums of nonnegative terms, `Σ_{a_i>0} a_i x_i + k⁺ = Σ_{a_i<0} |a_i| x_i + k⁻`
    /// (coefficients and constant as signed representatives).  When the largest value of each
    /// side is below `p`, the equation holds over the integers, so every term is at most the
    /// other side's largest value less its own side's constant:
    /// `x_j ≤ ⌊(max(other side) − k(own side)) / |a_j|⌋`.  Tightened bounds feed the positional
    /// and small-domain rules (a packed immediate `lsb + 32·msbd` with `lsb + msbd ≤ 31` becomes
    /// injective).  A bound of `0` fixes the variable.  A fact with exactly one variable `t`
    /// lacking a bound, of coefficient `±1`, whose other side is a sum of nonnegative bounded
    /// terms below `p`, bounds `t` by that sum's maximum (a carry `c = b₁ + 2b₂ + 3b₃` over
    /// bits is at most `6`).  Returns whether a bound moved.
    fn tighten(&mut self, st: &mut State) -> bool {
        let mut moved = false;
        for _ in 0..8 {
            let mut changed = false;
            for i in 0..st.facts.len() {
                let Fact::Zero(p) = &st.facts[i] else { continue };
                if p.0.len() > 64 || p.0.keys().any(|m| m.iter().map(|(_, e)| *e).sum::<u32>() > 1)
                {
                    continue;
                }
                let mut terms: Vec<(usize, i128, i128)> = vec![];
                let mut k: i128 = 0;
                let mut unbounded: Vec<(usize, i128)> = vec![];
                for (m, c) in p.0.iter() {
                    let c = signed(*c);
                    match m.as_slice() {
                        [] => k = c,
                        [(v, 1)] => match st.ub.get(v) {
                            Some(b) => terms.push((*v, c, *b as i128)),
                            None => unbounded.push((*v, c)),
                        },
                        _ => unreachable!("linear monomials only"),
                    }
                }
                if let [(t, ct)] = unbounded.as_slice() {
                    if ct.abs() == 1 && !terms.is_empty() {
                        let rest: Vec<i128> = terms.iter().map(|x| -x.1 * ct).collect();
                        let r0 = -k * ct;
                        if rest.iter().all(|r| *r >= 0) && r0 >= 0 {
                            let max: i128 =
                                rest.iter().zip(terms.iter()).map(|(r, x)| r * x.2).sum::<i128>()
                                    + r0;
                            if max < P as i128 {
                                let why = st.fact_support(i);
                                st.ub.insert(*t, max as u64);
                                st.ub_origin.entry(*t).or_default().extend(why);
                                changed = true;
                                self.bump(Rule::Bounds);
                            }
                        }
                    }
                    continue;
                }
                if !unbounded.is_empty() || terms.len() < 2 {
                    continue;
                }
                let (kp, kn) = if k >= 0 { (k, 0) } else { (0, -k) };
                let max_p: i128 =
                    terms.iter().filter(|t| t.1 > 0).map(|t| t.1 * t.2).sum::<i128>() + kp;
                let max_n: i128 =
                    terms.iter().filter(|t| t.1 < 0).map(|t| -t.1 * t.2).sum::<i128>() + kn;
                if max_p >= P as i128 || max_n >= P as i128 {
                    continue;
                }
                let mut updates = vec![];
                for &(v, c, b) in &terms {
                    let limit = if c > 0 { max_n - kp } else { max_p - kn };
                    if limit < 0 {
                        st.infeasible_support = st.fact_support(i);
                        st.infeasible = true;
                        return true;
                    }
                    let nb = limit / c.abs();
                    if nb < b {
                        updates.push((v, nb as u64));
                    }
                }
                let why = st.fact_support(i);
                for (v, nb) in updates {
                    st.ub.insert(v, nb);
                    st.ub_origin.entry(v).or_default().extend(why.iter().copied());
                    changed = true;
                    self.bump(Rule::Bounds);
                    if nb == 0 && !st.known.contains(&v) {
                        st.learn_value(v, 0, Rule::Bounds, why.clone());
                    }
                }
            }
            if !changed {
                break;
            }
            moved = true;
        }
        moved
    }

    /// Probes unknown bits: if assuming a value makes the branch infeasible, the bit takes the
    /// other value.  Returns whether a bit was fixed.
    fn probe(&mut self, st: &mut State) -> bool {
        let mut candidates: Vec<usize> = vec![];
        for f in &st.facts {
            if let Fact::Zero(p) = f {
                for v in p.vars() {
                    if !st.known.contains(&v)
                        && st.ub.get(&v) == Some(&1)
                        && !candidates.contains(&v)
                    {
                        candidates.push(v);
                    }
                }
            }
            if candidates.len() >= MAX_PROBES {
                break;
            }
        }
        for v in candidates {
            for val in [1u64, 0] {
                let mut s = st.clone();
                s.assign(v, val);
                let mut inner = Search {
                    outputs: vec![],
                    branches: 0,
                    rules: BTreeMap::new(),
                    lemmas: BTreeSet::new(),
                    stuck: BTreeSet::new(),
                    overflow: false,
                    probing: true,
                    deadline: self.deadline,
                    phase_us: [0; 4],
                };
                inner.propagate(&mut s);
                if s.infeasible {
                    let sup = st.near_support_hops(&[v], 2);
                    st.learn_value(v, 1 - val, Rule::Probe, sup);
                    self.bump(Rule::Probe);
                    return true;
                }
            }
        }
        false
    }

    /// Gaussian elimination over the facts that are linear in the unknowns with constant
    /// coefficients.  A derived row with one unknown determines it; a derived row whose unknowns
    /// are all range-checked determines them when it is positional.  Returns whether anything
    /// became known.
    fn eliminate(&mut self, st: &mut State) -> bool {
        type Row = (BTreeMap<usize, u64>, BTreeSet<usize>);
        let mut rows: Vec<Row> = vec![];
        for (fi, f) in st.facts.iter().enumerate() {
            let Fact::Zero(p) = f else { continue };
            let mut row: BTreeMap<usize, u64> = BTreeMap::new();
            let mut ok = true;
            let mut any = false;
            for (m, c) in &p.0 {
                let unk: Vec<&(usize, u32)> =
                    m.iter().filter(|(v, _)| !st.known.contains(v)).collect();
                match unk.len() {
                    0 => {}
                    1 if m.len() == 1 && unk[0].1 == 1 => {
                        row.insert(unk[0].0, *c);
                        any = true;
                    }
                    _ => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok && any {
                rows.push((row, [fi].into_iter().collect()));
            }
        }
        if rows.len() < 2 || rows.len() > MAX_ELIM_ROWS {
            return false;
        }
        let reduce = |row: &mut Row, pivot: &Row| {
            let (&pv, &pc) = pivot.0.iter().next().unwrap();
            if let Some(&rc) = row.0.get(&pv) {
                let k = mulm(rc, invm(pc));
                for (v, c) in &pivot.0 {
                    let e = row.0.entry(*v).or_insert(0);
                    *e = addm(*e, negm(mulm(k, *c)));
                }
                row.0.retain(|_, c| *c != 0);
                row.1.extend(pivot.1.iter().copied());
            }
        };
        let mut pivots: Vec<Row> = vec![];
        for mut r in rows {
            for pr in &pivots {
                reduce(&mut r, pr);
            }
            if !r.0.is_empty() {
                pivots.push(r);
            }
        }
        for i in (0..pivots.len()).rev() {
            let pr = pivots[i].clone();
            for row in pivots.iter_mut().take(i) {
                reduce(row, &pr);
            }
        }
        let mut progress = false;
        for (r, sources) in &pivots {
            let unknown: Vec<usize> = r.keys().copied().filter(|v| !st.known.contains(v)).collect();
            let support = |st: &State| -> BTreeSet<u32> {
                sources.iter().flat_map(|f| st.fact_support(*f)).collect()
            };
            if unknown.len() == 1 {
                let why = support(st);
                st.learn(unknown[0], Rule::Elimination, why);
                progress = true;
            } else if unknown.len() >= 2
                && unknown.len() <= MAX_POSITIONAL
                && unknown.iter().all(|v| st.ub.contains_key(v))
            {
                let coefs: Vec<(usize, u64)> = unknown.iter().map(|v| (*v, r[v])).collect();
                if positional_injective(&coefs, &st.ub) {
                    let why = support(st);
                    for v in unknown {
                        st.learn(v, Rule::Elimination, why.clone());
                    }
                    progress = true;
                }
            }
        }
        if progress {
            self.bump(Rule::Elimination);
        }
        progress
    }

    /// The known one-hot set (`-1 + Σ b = 0`, every member a known bit) that contains `v`.
    fn one_hot_set_of(&self, st: &State, v: usize) -> Option<Vec<usize>> {
        st.facts.iter().find_map(|f| {
            let Fact::Zero(p) = f else { return None };
            if p.0.get(&vec![]).copied() != Some(P - 1) || !p.vars().contains(&v) {
                return None;
            }
            let bits: Vec<usize> =
                p.0.iter()
                    .filter(|(m, _)| !m.is_empty())
                    .filter_map(|(m, c)| match m.as_slice() {
                        [(b, 1)] if *c == 1 && st.ub.get(b) == Some(&1) && st.known.contains(b) => {
                            Some(*b)
                        }
                        _ => None,
                    })
                    .collect();
            (bits.len() >= 2 && bits.len() + 1 == p.0.len()).then_some(bits)
        })
    }

    /// A case split on a fact equal in both witnesses: a known bit multiplying an unknown, else
    /// a known polynomial that is the coefficient of a single unknown (zero or nonzero).
    fn pick_split(&self, st: &State, missing: &[usize]) -> Option<Split> {
        let mut dist: BTreeMap<usize, usize> = missing.iter().map(|v| (*v, 0)).collect();
        for level in 0..6 {
            let mut grew = false;
            for f in &st.facts {
                let Fact::Zero(p) = f else { continue };
                let unknown: Vec<usize> =
                    p.vars().into_iter().filter(|v| !st.known.contains(v)).collect();
                if !unknown.iter().any(|v| dist.get(v) == Some(&level)) {
                    continue;
                }
                for v in unknown {
                    if let std::collections::btree_map::Entry::Vacant(e) = dist.entry(v) {
                        e.insert(level + 1);
                        grew = true;
                    }
                }
            }
            if !grew {
                break;
            }
        }
        let mut best: Option<(usize, u8, Split)> = None;
        for f in &st.facts {
            let Fact::Zero(p) = f else { continue };
            let unknown: Vec<usize> =
                p.vars().into_iter().filter(|v| !st.known.contains(v)).collect();
            if unknown.is_empty() {
                continue;
            }
            let score =
                unknown.iter().filter_map(|v| dist.get(v)).min().copied().unwrap_or(usize::MAX);
            if best.as_ref().is_some_and(|(s, _, _)| *s < score) {
                continue;
            }
            let mut candidate: Option<(u8, Split)> = None;
            'monos: for m in p.0.keys() {
                if !m.iter().any(|(v, _)| !st.known.contains(v)) {
                    continue;
                }
                for (v, _) in m {
                    if st.known.contains(v) && st.ub.get(v) == Some(&1) {
                        let split = match self.one_hot_set_of(st, *v) {
                            Some(set) => Split::OneHot(set),
                            None => Split::Bit(*v),
                        };
                        candidate = Some((0, split));
                        break 'monos;
                    }
                }
            }
            if candidate.is_none() && unknown.len() == 1 && p.degree_in(unknown[0]) == 1 {
                let (a, _) = p.split_linear(unknown[0]);
                if a.as_constant().is_none() && st.is_known(&a) && !st.is_nonzero(&a) {
                    candidate = Some((1, Split::Coef(a)));
                }
            }
            if let Some((kind, split)) = candidate {
                let better = match &best {
                    None => true,
                    Some((s, k, _)) => score < *s || (score == *s && kind < *k),
                };
                if better {
                    best = Some((score, kind, split));
                }
            }
        }
        best.map(|(_, _, split)| split)
    }

    fn run(&mut self, mut st: State, depth: usize) -> Derivation {
        self.branches += 1;
        if self.branches > max_branches() {
            self.overflow = true;
            return Derivation { steps: vec![], values: vec![], end: DerivEnd::Open };
        }
        loop {
            self.propagate(&mut st);
            if st.infeasible {
                let support = std::mem::take(&mut st.infeasible_support);
                return Derivation {
                    steps: std::mem::take(&mut st.log),
                    values: std::mem::take(&mut st.vlog),
                    end: DerivEnd::Infeasible { support },
                };
            }
            if self.outputs.iter().all(|o| st.known.contains(o)) {
                break;
            }
            let t = std::time::Instant::now();
            let probed = self.probe(&mut st);
            self.phase_us[3] += t.elapsed().as_micros();
            if !probed {
                break;
            }
        }
        let missing: Vec<usize> =
            self.outputs.iter().copied().filter(|o| !st.known.contains(o)).collect();
        let steps = std::mem::take(&mut st.log);
        let values = std::mem::take(&mut st.vlog);
        if missing.is_empty() {
            return Derivation { steps, values, end: DerivEnd::Done };
        }
        if depth < 24 {
            let split = self.pick_split(&st, &missing);
            if depth < 6 && tracing::enabled!(tracing::Level::TRACE) {
                let what = match &split {
                    Some(Split::OneHot(bits)) => format!("one-hot over {} bits", bits.len()),
                    Some(Split::Bit(v)) => format!("bit {}", var_name(*v)),
                    Some(Split::Coef(a)) => format!("coef {}", show(a)),
                    None => "none".into(),
                };
                let missing: Vec<String> = missing.iter().map(|v| var_name(*v)).collect();
                tracing::trace!("split at depth {depth}: {what}; missing {missing:?}");
                if let Ok(watch) = std::env::var("PICUS_WATCH") {
                    for f in &st.facts {
                        if let Fact::Zero(p) = f {
                            if p.vars().iter().any(|v| var_name(*v) == watch) {
                                tracing::trace!("    watch: {}", show(p));
                            }
                        }
                    }
                }
                if let Some(Split::Bit(v)) = &split {
                    for f in &st.facts {
                        if let Fact::Zero(p) = f {
                            if p.vars().contains(v) {
                                let open: Vec<String> = p
                                    .vars()
                                    .iter()
                                    .filter(|w| !st.known.contains(w))
                                    .map(|w| var_name(*w))
                                    .collect();
                                tracing::trace!("    {}   [open: {}]", show(p), open.join(", "));
                            }
                        }
                    }
                }
            }
            match split {
                Some(Split::OneHot(bits)) => {
                    let mut branches = vec![];
                    for &k in &bits {
                        let mut s = st.clone();
                        for &b in &bits {
                            s.assign(b, u64::from(b == k));
                        }
                        branches.push(self.run(s, depth + 1));
                    }
                    let support = st.near_support(&bits);
                    return Derivation {
                        steps,
                        values,
                        end: DerivEnd::OneHot { bits, support, branches },
                    };
                }
                Some(Split::Bit(v)) => {
                    let mut s0 = st.clone();
                    s0.assign(v, 0);
                    let zero = Box::new(self.run(s0, depth + 1));
                    let mut s1 = st.clone();
                    s1.assign(v, 1);
                    let one = Box::new(self.run(s1, depth + 1));
                    let support = st.near_support(&[v]);
                    return Derivation {
                        steps,
                        values,
                        end: DerivEnd::Bit { var: v, support, zero, one },
                    };
                }
                Some(Split::Coef(a)) => {
                    let mut zero = vec![];
                    let pivot = a.pivot();
                    let zero_ok = if let Some((v, r)) = &pivot {
                        let mut z = st.clone();
                        if z.assign_poly(*v, r) {
                            zero.push(self.run(z, depth + 1));
                            true
                        } else {
                            false
                        }
                    } else if a.0.len() == 1 {
                        let m = a.0.keys().next().unwrap().clone();
                        for (v, _) in m {
                            let mut z = st.clone();
                            z.assign(v, 0);
                            zero.push(self.run(z, depth + 1));
                        }
                        true
                    } else {
                        false
                    };
                    if zero_ok {
                        let mut nz = st;
                        nz.nonzero.push(a.monic());
                        let nonzero = Box::new(self.run(nz, depth + 1));
                        return Derivation {
                            steps,
                            values,
                            end: DerivEnd::Coef { poly: a, pivot: pivot.is_some(), zero, nonzero },
                        };
                    }
                }
                None => {}
            }
        }
        if tracing::enabled!(tracing::Level::DEBUG) {
            let names: Vec<String> = missing.iter().map(|v| var_name(*v)).collect();
            tracing::debug!("stuck at depth {depth}: missing {names:?}");
            let case: Vec<String> = st
                .values
                .iter()
                .filter(|(v, _)| {
                    let n = var_name(**v);
                    n.starts_with("is_") || n.starts_with("decode_")
                })
                .map(|(v, x)| format!("{}={x}", var_name(*v)))
                .collect();
            tracing::debug!("  case: {}", case.join(" "));
            let mut frontier: BTreeSet<usize> = missing.iter().copied().collect();
            let mut shown = BTreeSet::new();
            for _ in 0..6 {
                let mut next = BTreeSet::new();
                for (i, f) in st.facts.iter().enumerate() {
                    let Fact::Zero(p) = f else { continue };
                    if shown.contains(&i) || !p.vars().iter().any(|v| frontier.contains(v)) {
                        continue;
                    }
                    shown.insert(i);
                    let open: Vec<String> = p
                        .vars()
                        .iter()
                        .filter(|v| !st.known.contains(v))
                        .map(|v| match st.ub.get(v) {
                            Some(b) => format!("{}<={b}", var_name(*v)),
                            None => var_name(*v),
                        })
                        .collect();
                    tracing::debug!("  {}   [open: {}]", show(p), open.join(", "));
                    next.extend(p.vars().into_iter().filter(|v| !st.known.contains(v)));
                }
                frontier = next;
            }
            for a in &st.nonzero {
                tracing::debug!("  nonzero: {}", show(a));
            }
        }
        self.stuck.extend(missing);
        Derivation { steps, values, end: DerivEnd::Open }
    }
}

/// Analyzes one module.
pub fn analyze(m: &PicusModule) -> Verdict {
    let (ctx, known) = Ctx::new(m);
    let st = State {
        facts: ctx.facts.clone(),
        ub: ctx.ub.clone(),
        known,
        nonzero: vec![],
        fresh: ctx.fresh,
        infeasible: false,
        values: BTreeMap::new(),
        pivots_used: BTreeSet::new(),
        log: vec![],
        vlog: vec![],
        origins: ctx.origins.clone(),
        ub_origin: ctx.ub_origin.clone(),
        vsupport: BTreeMap::new(),
        infeasible_support: BTreeSet::new(),
    };
    let mut s = Search {
        outputs: ctx.outputs.clone(),
        branches: 0,
        rules: BTreeMap::new(),
        lemmas: BTreeSet::new(),
        stuck: BTreeSet::new(),
        overflow: false,
        probing: false,
        deadline: std::time::Instant::now() + module_budget(),
        phase_us: [0; 4],
    };
    let derivation = s.run(st, 0);
    tracing::debug!(
        "phase census: pass {} ms, tighten {} ms, eliminate {} ms, probe {} ms, branches {}",
        s.phase_us[0] / 1000,
        s.phase_us[1] / 1000,
        s.phase_us[2] / 1000,
        s.phase_us[3] / 1000,
        s.branches
    );
    if std::time::Instant::now() > s.deadline {
        return Verdict::Timeout;
    }
    if s.overflow {
        return Verdict::TooManyBranches;
    }
    if s.stuck.is_empty() {
        Verdict::Determined { branches: s.branches, rules: s.rules, lemmas: s.lemmas, derivation }
    } else {
        Verdict::Stuck {
            branches: s.branches,
            stuck_outputs: s.stuck.into_iter().collect(),
            opaque: ctx.opaque,
        }
    }
}

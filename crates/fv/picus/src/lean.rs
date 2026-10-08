//! Lean 4 backend: renders an extracted [`PicusProgram`] as a Lean file whose theorems state the
//! determinism obligations Picus would check.
//!
//! For every module `M` the file contains
//!
//! ```lean
//! namespace M
//! structure W where v0 : F ... vn : F        -- every variable the module mentions
//! def constraints (w : W) : Prop := c₁ ∧ … ∧ cₖ ∧ Aux.rel [..] [..] ∧ …
//! def inputs (w : W) : List F := [...]      -- module inputs
//! def outputs (w : W) : List F := [...]     -- module outputs
//! def assumed (w : W) : List F := [...]     -- `assume-deterministic` expressions
//! def rel (ins outs : List F) : Prop := ∃ w, constraints w ∧ inputs w = ins ∧ outputs w = outs
//! theorem deterministic (h_Aux : ∀ i o o', Aux.rel i o → Aux.rel i o' → o = o') …
//!     (w w' : W) (hw : constraints w) (hw' : constraints w')
//!     (hin : inputs w = inputs w') (hassume : assumed w = assumed w') :
//!     outputs w = outputs w' := by picus_det
//! theorem postconditions (w : W) (hw : constraints w) : p₁ ∧ … := by picus_det
//! end M
//! ```
//!
//! Abstract helper modules (byte-table operations the extractor does not expand) get an
//! `opaque rel` and their determinism is a *hypothesis* of every theorem that calls them, never
//! an axiom.  `picus_det` (defined in `ZirenDet/Basic.lean`) tries the cheap closers and falls
//! back to `sorry`, so a file always elaborates and the remaining obligations are visible as
//! `sorry` warnings.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use crate::{
    pcl::{PicusCall, PicusConstraint, PicusExpr, PicusModule, PicusProgram},
    propagate::{to_poly, DerivEnd, Derivation, Poly, Rule, ASSUMED_ORIGIN, INPUT_ORIGIN, P},
};

/// Derivations of the modules the analyser determined, by module name: `write_module` replays
/// them as the determinism proof instead of the generic `picus_det` search.
pub static DERIVATIONS: std::sync::Mutex<BTreeMap<String, Derivation>> =
    std::sync::Mutex::new(BTreeMap::new());

/// Diagnosis mode (`--derive-diagnose`): an open step is admitted with `sorry`, so the replay
/// runs on and reports every open step; otherwise it fails and the theorem falls back to
/// `picus_det`, so a replay never does worse than the generic search.
pub static REPLAY_DIAGNOSE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Percentage applied to every per-attempt heartbeat cap (`PICUS_CAP_SCALE`, default 100): a
/// diagnosis run lowers it to classify open steps quickly.
fn cap_scale() -> u64 {
    std::env::var("PICUS_CAP_SCALE").ok().and_then(|v| v.parse().ok()).unwrap_or(100)
}

/// How an open step gives up (see [`REPLAY_DIAGNOSE`]).
fn give_up() -> &'static str {
    if REPLAY_DIAGNOSE.load(std::sync::atomic::Ordering::Relaxed) {
        "sorry"
    } else {
        "fail"
    }
}

/// The per-step closer: field reasoning first, then the integer lift, else the step is left
/// open with a `PICUS_OPEN <what>` trace.
fn step(what: &str) -> String {
    format!(
        "first | picus_cap 50000 grind | picus_cap 200000 picus_finish | (trace \"PICUS_OPEN {what}\"; {})",
        give_up()
    )
}

/// At most this many equations are subtracted pairwise by the staged attempt of [`focused`],
/// those mentioning the step's variable first.
const MAX_DIFF: usize = 16;

/// An interface list longer than this is split into its equations by one `simp` of the whole
/// list equality and a projection per entry.  Indexing it entry by entry rewrites
/// `getElem?_cons_succ` down the list for every index, `Θ(n³)` terms for `n` entries (730 inputs
/// do not elaborate in hours); shorter lists keep the per-index form.
const LONG_INTERFACE: usize = 400;

/// A branch with more steps than this keeps no inline copy of a step's tactic behind its
/// lemma: the copies make the main theorem's tactic block megabytes long (U256XU2048Mul's
/// 1,493 steps: 10 MB) and it does not elaborate in hours, while a missed lemma is reported
/// either way.
const INLINE_FALLBACK_STEPS: usize = 600;

/// A constraint set with more conjuncts than this is unfolded once (`dsimp` of its chunk
/// definitions, which also reduces the fields of the destructured witness) and split by
/// `And.left`/`And.right` projections instead of `obtain`: destructuring thousands of conjuncts
/// one `cases` at a time over a witness of thousands of fields did not finish in a quarter of an
/// hour for U256XU2048Mul's 2,900.
const LONG_CONJUNCTION: usize = 2000;

/// [`step`] focused on `keep`: every other hypothesis is cleared first, since `grind` gives up
/// in the full context of a large module.  The staged attempt adds the difference of the two
/// witnesses' copies of each equation in `diff`, splits the bits that gate a range, and
/// closes every branch by the integer finish, the local pipeline or a contradiction; the last
/// attempt widens to `wide`.  A step that may split tries the range-checked word first; a step
/// with a hand-written gadget proof `hg` tries it alone before anything else.  The
/// pruned attempt takes the difference of the equations in `own` (those that mention the
/// step's variable), drops them, and keeps only what is within three hypotheses of the goal:
/// the analyser's support is a union over the derivation and drowns `omega` otherwise.  A
/// carry bit written as `E·(E − 1) = 0` over an expression `E` is split and differenced.
fn focused(
    keep: &[String],
    wide: &[String],
    diff: &[u32],
    own: &[u32],
    split: bool,
    what: &str,
) -> String {
    if keep.is_empty() {
        return step(what);
    }
    let k = keep.join(" ");
    let c = |n: u64| n * cap_scale() / 100;
    let chain = "first | (picus_clear_unbounded; picus_clear_nonlinear; picus_finish) | (picus_clear_unbounded; picus_finish) | picus_finish | (picus_clear_unbounded; picus_clear_nonlinear; picus_finish_dvd) | picus_local_diff | picus_local | (exfalso; grind) | grind";
    let (haves, normalize) = if diff.is_empty() {
        (String::new(), String::new())
    } else {
        let haves: String =
            diff.iter().map(|o| format!("have q{o} := congrArg₂ HSub.hSub d{o} c{o}; ")).collect();
        let qs: Vec<String> = diff.iter().map(|o| format!("q{o}")).collect();
        (haves, format!("(try ring_nf at {}); ", qs.join(" ")))
    };
    let staged = format!(
        "picus_cap {} (clear * - {k}; {haves}{normalize}(try picus_bits); (try picus_pair_elim); (try picus_split_range_gates); all_goals ({chain})) | ",
        c(400000),
    );
    let split = if split {
        format!(
            "picus_cap {} (clear * - {k}; picus_prune_depth 2; picus_split_goal_bits; all_goals (first | rfl | (exfalso; (try picus_subst_consts); all_goals (simp only [mul_zero, zero_mul, mul_one, one_mul, sub_zero, zero_sub, sub_self, add_zero, zero_add, neg_eq_zero, one_ne_zero, zero_ne_one] at *); done) | (exfalso; grind))) | picus_cap {} (clear * - {k}; picus_split_goal_bits; all_goals (try simp only [zero_mul, one_mul, mul_zero, mul_one, sub_self, zero_sub, sub_zero] at *); all_goals picus_local) | picus_cap {} (clear * - {k}; {haves}{normalize}(try picus_pair_elim); picus_split_bits 4; all_goals ({chain})) | ",
            c(200000),
            c(200000),
            c(400000)
        )
    } else {
        String::new()
    };
    let wider = if wide.len() > keep.len() {
        format!("picus_cap {} (clear * - {}; picus_local) | ", c(400000), wide.join(" "))
    } else {
        String::new()
    };
    let pruned = {
        let haves: String =
            own.iter().map(|o| format!("have q{o} := congrArg₂ HSub.hSub d{o} c{o}; ")).collect();
        let normalize = if own.is_empty() {
            String::new()
        } else {
            let qs: Vec<String> = own.iter().map(|o| format!("q{o}")).collect();
            let cs: Vec<String> = own.iter().map(|o| format!("c{o} d{o}")).collect();
            format!("(try ring_nf at {}); (try clear {}); ", qs.join(" "), cs.join(" "))
        };
        format!(
            "picus_cap {} (clear * - {k}; {haves}{normalize}picus_prune_depth 3; (try picus_subst_consts); all_goals ((try picus_subst_defs); (try picus_bits); first | picus_finish | picus_finish_dvd | picus_local)) | ",
            c(400000)
        )
    };
    let from_gadget = if keep.iter().any(|h| h == "hg") {
        format!("picus_cap {} (simp only [hg]) | ", c(50000))
    } else {
        String::new()
    };
    let canonical = if split.is_empty() {
        String::new()
    } else {
        format!("picus_cap {} (clear * - {k}; picus_canonical_word) | ", c(100000))
    };
    format!(
        "first | {from_gadget}{canonical}picus_cap {} (clear * - {k}; grind) | picus_cap {} (clear * - {k}; picus_finish) | picus_cap {} (clear * - {k}; picus_local) | picus_cap {} (clear * - {k}; picus_local_diff) | picus_cap {} (clear * - {k}; (try picus_subst_consts); all_goals (picus_quad_bits; all_goals (picus_prune_depth 1; first | picus_finish | picus_finish_dvd))) | {pruned}{staged}{split}{wider}(trace \"PICUS_OPEN {what}\"; {})",
        c(50000),
        c(100000),
        c(400000),
        c(400000),
        c(400000),
        give_up()
    )
}

/// A hypothesis of the replay that is not a conjunct, as the step lemmas restate it.
#[derive(Clone)]
enum Dyn {
    /// `¬ x_v = 0`.
    NotZero(usize),
    /// `p = 0`, or `¬ p = 0`.
    Poly(Poly, bool),
    /// A pending step equality `y_v = x_v`.
    Pending(usize),
    /// An input or assumed equality `e(w) = e(w')` that was not substituted.
    Expr(PicusExpr),
    /// The gadget facts `x_a = y_b ∧ …`.
    Gadget(Vec<(usize, usize)>),
    /// A closed statement.
    Text(String),
}

/// Replays a [`Derivation`] as a tactic proof of `deterministic`.
///
/// Both witnesses are split into their fields (`x…` for `w`, `y…` for `w'`), both constraint
/// sets into their conjuncts (`c…`, `d…`), and every input equality is substituted (before
/// the constraint sets are split: a substitution costs one pass over every hypothesis).  Each
/// step then proves `y_v = x_v` with [`STEP`] and substitutes it, so later steps see one copy of
/// every determined variable; a split becomes a case analysis on values both witnesses share.
/// Consecutive steps the analyser took by one rule from the same conjuncts (the bytes of a
/// word) are all proved before any is substituted, so each is proved from the whole equation;
/// a later step of the group keeps the equalities the earlier ones proved.
struct Replay<'a> {
    vars: &'a BTreeSet<usize>,
    m: &'a PicusModule,
    out: String,
    /// The current name of each variable of `w` and `w'`: `x…`/`y…`, a constant after a case
    /// substitution, and `y_v ↦ x_v` once `v` is determined or an input.
    xmap: BTreeMap<usize, String>,
    ymap: BTreeMap<usize, String>,
    /// The hypotheses beyond the conjuncts, with how to state them under the current names.
    dynamic: BTreeMap<String, Dyn>,
    /// The step lemmas, one top-level theorem per replayed step.
    lemmas: Vec<String>,
    hyp: usize,
    /// Hypotheses every step keeps: the helper-call determinism assumptions, the input and
    /// assumed equalities that were not substituted, and the case hypotheses in scope.
    always: Vec<String>,
    /// The variables of each conjunct, for [`Replay::widen`].
    conj_vars: Vec<BTreeSet<usize>>,
    /// Whether each conjunct is an equation `e = 0` over two or more variables, whose two
    /// copies subtract to an equation over the step's still-undetermined variables (the known
    /// terms cancel after `subst`); a one-variable equation (a bit) is kept whole.
    eqs: Vec<bool>,
}

impl Replay<'_> {
    fn line(&mut self, indent: usize, text: &str) {
        self.out.push_str(&" ".repeat(indent));
        self.out.push_str(text);
        self.out.push('\n');
    }

    fn fresh(&mut self) -> String {
        self.hyp += 1;
        format!("hs{}", self.hyp)
    }

    fn xn(&self, v: usize) -> String {
        self.xmap.get(&v).cloned().unwrap_or_else(|| format!("x{v}"))
    }

    fn yn(&self, v: usize) -> String {
        self.ymap.get(&v).cloned().unwrap_or_else(|| format!("y{v}"))
    }

    /// Case substitution `x_v := c`: every name that was `x_v` becomes `c`.
    fn fix(&mut self, v: usize, c: &str) {
        let old = self.xn(v);
        self.xmap.insert(v, c.to_string());
        let ys: Vec<usize> =
            self.ymap.iter().filter(|(_, n)| **n == old).map(|(k, _)| *k).collect();
        for k in ys {
            self.ymap.insert(k, c.to_string());
        }
    }

    /// The statement of hypothesis `h` under the current names, if the replay knows it.
    fn hyp_type(&self, h: &str) -> Option<(String, Option<usize>)> {
        let nconj = self.m.constraints.len() + self.m.calls.len();
        if let Some(rest) = h.strip_prefix('c').or_else(|| h.strip_prefix('d')) {
            if let Ok(o) = rest.parse::<usize>() {
                if o < nconj {
                    let names = self.conj_vars[o]
                        .iter()
                        .map(|&v| if h.starts_with('c') { self.xn(v) } else { self.yn(v) })
                        .collect::<Vec<_>>();
                    let args = names.join(" ");
                    let sep = if args.is_empty() { "" } else { " " };
                    return Some((format!("cj{o}{sep}{args}"), Some(o)));
                }
            }
        }
        let x = |v: usize| self.xn(v);
        let y = |v: usize| self.yn(v);
        let t = match self.dynamic.get(h)? {
            Dyn::NotZero(v) => format!("¬ {} = 0", self.xn(*v)),
            Dyn::Poly(p, zero) => {
                let body = self.poly_n(p)?;
                if *zero {
                    format!("{body} = 0")
                } else {
                    format!("¬ {body} = 0")
                }
            }
            Dyn::Pending(v) => format!("{} = {}", self.yn(*v), self.xn(*v)),
            Dyn::Expr(e) => format!("{} = {}", render_expr_n(e, &x), render_expr_n(e, &y)),
            Dyn::Gadget(pairs) => pairs
                .iter()
                .map(|&(a, b)| format!("{} = {}", self.xn(a), self.yn(b)))
                .collect::<Vec<_>>()
                .join(" ∧ "),
            Dyn::Text(t) => t.clone(),
        };
        Some((t, None))
    }

    /// Emits `tactic` proving `goal` from the hypotheses `hyps` as a top-level lemma and
    /// returns its application, or `None` when a hypothesis cannot be restated.
    fn lemma(&mut self, hyps: &[String], goal: &str, tactic: &str) -> Option<String> {
        let mut names: Vec<String> = vec![];
        for h in hyps {
            for tok in h.split(';').next().unwrap_or("").split_whitespace() {
                if !names.iter().any(|n| n == tok) {
                    names.push(tok.to_string());
                }
            }
        }
        let mut binders = vec![];
        let mut defs = BTreeSet::new();
        for n in &names {
            let (t, o) = self.hyp_type(n)?;
            if let Some(o) = o {
                defs.insert(o);
            }
            binders.push(format!("({n} : {t})"));
        }
        let mut vars: BTreeSet<(char, usize)> = BTreeSet::new();
        for text in binders.iter().map(String::as_str).chain(std::iter::once(goal)) {
            let b = text.as_bytes();
            let mut i = 0;
            while i < b.len() {
                let c = b[i] as char;
                let boundary =
                    i == 0 || !(b[i - 1] as char).is_ascii_alphanumeric() && b[i - 1] != b'_';
                if (c == 'x' || c == 'y') && boundary {
                    let mut j = i + 1;
                    while j < b.len() && (b[j] as char).is_ascii_digit() {
                        j += 1;
                    }
                    let end_ok =
                        j == b.len() || !(b[j] as char).is_ascii_alphanumeric() && b[j] != b'_';
                    if j > i + 1 && end_ok {
                        vars.insert((c, text[i + 1..j].parse().unwrap()));
                    }
                    i = j;
                } else {
                    i += 1;
                }
            }
        }
        let n = self.lemmas.len();
        let vs: Vec<String> = vars.iter().map(|(c, v)| format!("{c}{v}")).collect();
        let unfold = if defs.is_empty() {
            String::new()
        } else {
            let ds: Vec<String> = defs.iter().map(|o| format!("cj{o}")).collect();
            format!("(try dsimp only [{}] at *); ", ds.join(", "))
        };
        let head = if vs.is_empty() { String::new() } else { format!(" {{{} : F}}", vs.join(" ")) };
        self.lemmas.push(format!(
            "theorem st{n}{head}\n    {} :\n    {goal} := by\n  {unfold}{tactic}\n",
            binders.join(" ")
        ));
        Some(format!("st{n} {}", names.join(" ")))
    }

    fn poly_n(&self, p: &Poly) -> Option<String> {
        let mut terms = vec![];
        for (mono, c) in p.terms() {
            let mut factors = vec![];
            for &(v, e) in mono {
                if !self.vars.contains(&v) {
                    return None;
                }
                let n = self.xn(v);
                factors.push(if e == 1 { n } else { format!("{n} ^ {e}") });
            }
            let coef = if c > 0x7f00_0001 / 2 {
                format!("-({} : F)", 0x7f00_0001 - c)
            } else {
                format!("({c} : F)")
            };
            terms.push(if factors.is_empty() {
                coef
            } else if c == 1 {
                factors.join(" * ")
            } else {
                format!("{coef} * {}", factors.join(" * "))
            });
        }
        Some(if terms.is_empty() { "(0 : F)".into() } else { terms.join(" + ") })
    }

    /// The part of a step's `support` near `v`: the conjuncts reached from `v` through
    /// variables still undetermined, plus those over only the variables already reached.  The
    /// analyser's support is a union over the whole derivation, so a step deep in a chain
    /// carries every conjunct upstream of it, all of whose variables are determined by now.
    /// Only a large support that shrinks by half is replaced.
    fn localize(&self, v: usize, support: &BTreeSet<u32>) -> BTreeSet<u32> {
        let min: usize =
            std::env::var("PICUS_LOCALIZE_MIN").ok().and_then(|v| v.parse().ok()).unwrap_or(24);
        if support.len() < min {
            return support.clone();
        }
        let conj = |o: u32| self.conj_vars.get(o as usize);
        let mut open: BTreeSet<usize> = BTreeSet::from([v]);
        let mut out: BTreeSet<u32> = BTreeSet::new();
        loop {
            let before = out.len();
            for &o in support {
                if out.contains(&o) || o >= ASSUMED_ORIGIN || o >= INPUT_ORIGIN {
                    continue;
                }
                let Some(vs) = conj(o) else { continue };
                if vs.iter().any(|u| open.contains(u)) {
                    out.insert(o);
                    open.extend(vs.iter().copied().filter(|&u| self.xn(u) != self.yn(u)));
                }
            }
            if out.len() == before {
                break;
            }
        }
        let reached: BTreeSet<usize> =
            out.iter().filter_map(|&o| conj(o)).flatten().copied().collect();
        for &o in support {
            if let Some(vs) = conj(o) {
                if !vs.is_empty() && vs.iter().all(|u| reached.contains(u)) {
                    out.insert(o);
                }
            }
        }
        out.extend(support.iter().copied().filter(|&o| o >= ASSUMED_ORIGIN || o >= INPUT_ORIGIN));
        if out.is_empty() || out.len() * 2 > support.len() {
            support.clone()
        } else {
            out
        }
    }

    /// The is-zero pair `1 − inv·S − z = 0`, `α·z·S = 0` (`α = ±1`) over a known sum `S`:
    /// returns `(a, inv, z, S, (b, α))` for the conjuncts `a` and `b` in `support`, `b` when present.
    fn iszero_pair(
        &self,
        support: &BTreeSet<u32>,
    ) -> Option<(u32, usize, usize, Poly, Option<(u32, u64)>)> {
        let polys: Vec<(u32, Poly)> = support
            .iter()
            .filter_map(|&o| match self.m.constraints.get(o as usize)? {
                PicusConstraint::Eq(e) => Some((o, to_poly(e)?)),
                _ => None,
            })
            .collect();
        let same = |u: usize| self.xn(u) == self.yn(u);
        for (a, p) in &polys {
            let terms: Vec<(&[(usize, u32)], u64)> = p.terms().collect();
            if terms.iter().find(|(m, _)| m.is_empty()).map(|t| t.1) != Some(1) {
                continue;
            }
            let Some(z) = terms.iter().find_map(|(m, c)| match m {
                [(z, 1)] if *c == P - 1 => Some(*z),
                _ => None,
            }) else {
                continue;
            };
            let rest: Vec<&(&[(usize, u32)], u64)> =
                terms.iter().filter(|(m, _)| m.len() >= 2 || m.len() == 1 && m[0].0 != z).collect();
            if rest.is_empty() {
                continue;
            }
            let Some(inv) = (0..rest[0].0.len()).map(|i| rest[0].0[i].0).find(|&u| {
                rest.iter().all(|(m, _)| {
                    m.iter().filter(|(w, _)| *w == u).map(|(_, e)| *e).sum::<u32>() == 1
                })
            }) else {
                continue;
            };
            if rest.len() + 2 != terms.len() || p.degree_in(inv) != 1 {
                continue;
            }
            let (s_neg, _) = p.split_linear(inv);
            let s = s_neg.scale(P - 1);
            if s.vars().iter().any(|&u| !same(u) || u == z || u == inv) {
                continue;
            }
            let gate = polys.iter().find_map(|(b, q)| {
                if q.degree_in(z) != 1 {
                    return None;
                }
                let (qz, q0) = q.split_linear(z);
                if q0.terms().next().is_some() {
                    return None;
                }
                [1, P - 1].into_iter().find(|&alpha| qz == s.scale(alpha)).map(|alpha| (*b, alpha))
            });
            return Some((*a, inv, z, s, gate));
        }
        None
    }

    /// The is-zero flag and its inverse witness as direct proofs: the flag by the split
    /// `S = 0 ∨ S ≠ 0`, the inverse (once the flag is known) by cancelling `S ≠ 0`.
    fn iszero_step(&self, v: usize, support: &BTreeSet<u32>) -> Option<String> {
        let (a, inv, z, s, gate) = self.iszero_pair(support)?;
        let st = self.poly_n(&s)?;
        let (x, y) = (self.xn(v), self.yn(v));
        if let (true, Some((b, alpha))) = (v == z, gate) {
            let sign = if alpha == 1 { "" } else { "-" };
            let (xi, yi) = (self.xn(inv), self.yn(inv));
            Some(format!(
                "refine (eq_or_ne ({st}) 0).elim (fun hs => ?_) (fun hs => ?_); linear_combination c{a} - d{a} - ({yi} - {xi}) * hs; have hx : {x} = 0 := (mul_eq_zero.mp (show {x} * ({st}) = 0 by linear_combination {sign}c{b})).resolve_right hs; have hy : {y} = 0 := (mul_eq_zero.mp (show {y} * ({st}) = 0 by linear_combination {sign}d{b})).resolve_right hs; rw [hx, hy]"
            ))
        } else if v == inv && self.xn(z) == self.yn(z) {
            let zx = self.xn(z);
            Some(format!(
                "have hs : ({st}) ≠ 0 := fun h => absurd (show (1 : F) - {zx} = 0 by linear_combination c{a} + {x} * h) (by norm_num); exact mul_right_cancel₀ hs (by linear_combination c{a} - d{a})"
            ))
        } else {
            None
        }
    }

    /// A conjunct `A·v + R = 0` with a constant `A ≠ 0` and every other variable already the
    /// same in both witnesses: the copies subtract to `A·(v' − v) = 0`.  Prefers a conjunct of
    /// `support`; returns the hypotheses and the tactic.
    fn linear_solve(&self, v: usize, support: &BTreeSet<u32>) -> Option<(Vec<String>, String)> {
        let same = |u: usize| self.xn(u) == self.yn(u);
        let candidates =
            support.iter().map(|&o| o as usize).chain(0..self.m.constraints.len()).filter(|&o| {
                self.conj_vars
                    .get(o)
                    .is_some_and(|vs| vs.contains(&v) && vs.iter().all(|&u| u == v || same(u)))
            });
        for o in candidates {
            let Some(PicusConstraint::Eq(e)) = self.m.constraints.get(o) else { continue };
            let Some(p) = to_poly(e) else { continue };
            if p.degree_in(v) != 1 || !p.vars().iter().all(|&u| self.vars.contains(&u)) {
                continue;
            }
            let Some(a) = p.split_linear(v).0.as_constant_pub() else { continue };
            if a == 0 {
                continue;
            }
            let lit = if a > P / 2 { format!("(-{} : F)", P - a) } else { format!("({a} : F)") };
            let (x, y) = (self.xn(v), self.yn(v));
            let tactic = format!(
                "exact sub_eq_zero.mp ((mul_eq_zero.mp (show {lit} * ({y} - {x}) = 0 by linear_combination d{o} - c{o})).resolve_left (by decide))"
            );
            return Some((vec![format!("c{o}"), format!("d{o}")], tactic));
        }
        None
    }

    /// The positional step over two unknowns: a conjunct linear in `v` and one other unknown `u`
    /// with constant weights `a_v`, `a_u`, every other variable the same in both witnesses, and
    /// range conjuncts `v ≤ B_v`, `u ≤ B_u` under which `a_v·d_v + a_u·d_u = 0` has no other
    /// solution (a carry row fixing a result byte and a 16-bit carry at once).  The copies
    /// subtract to that small equation and the integer finish closes it.
    fn positional_diff(&self, v: usize, support: &BTreeSet<u32>) -> Option<(Vec<String>, String)> {
        let same = |u: usize| self.xn(u) == self.yn(u);
        let bound = |u: usize| -> Option<(usize, u64)> {
            self.m.constraints.iter().enumerate().find_map(|(o, c)| match c {
                PicusConstraint::Leq(a, b) => match (a.as_ref(), b.as_ref()) {
                    (PicusExpr::Var(w), PicusExpr::Const(k)) if *w == u => Some((o, *k)),
                    _ => None,
                },
                _ => None,
            })
        };
        let signed = |a: u64| -> i128 {
            if a > P / 2 {
                a as i128 - P as i128
            } else {
                a as i128
            }
        };
        for o in support.iter().map(|&o| o as usize) {
            let Some(vs) = self.conj_vars.get(o) else { continue };
            let open: Vec<usize> = vs.iter().copied().filter(|&u| !same(u)).collect();
            let [a, b] = open.as_slice() else { continue };
            if *a != v && *b != v {
                continue;
            }
            let u = if *a == v { *b } else { *a };
            let Some(PicusConstraint::Eq(e)) = self.m.constraints.get(o) else { continue };
            let Some(p) = to_poly(e) else { continue };
            if p.degree_in(v) != 1 || p.degree_in(u) != 1 {
                continue;
            }
            let (Some(av), Some(au)) =
                (p.split_linear(v).0.as_constant_pub(), p.split_linear(u).0.as_constant_pub())
            else {
                continue;
            };
            let (Some((ov, bv)), Some((ou, bu))) = (bound(v), bound(u)) else { continue };
            let (sv, su) = (signed(av), signed(au));
            if sv == 0 || su == 0 || sv.abs() * bv as i128 + su.abs() * bu as i128 >= P as i128 {
                continue;
            }
            let (mut x, mut y) = (sv.abs(), su.abs());
            while y != 0 {
                (x, y) = (y, x % y);
            }
            if su.abs() / x <= bv as i128 && sv.abs() / x <= bu as i128 {
                continue;
            }
            let lit = |s: i128| format!("({s} : F)");
            let tactic = format!(
                "have hq : {} * ({} - {}) + {} * ({} - {}) = 0 := (by linear_combination d{o} - c{o}); clear * - hq c{ov} d{ov} c{ou} d{ou}; picus_finish_dvd",
                lit(sv),
                self.yn(v),
                self.xn(v),
                lit(su),
                self.yn(u),
                self.xn(u)
            );
            let names =
                [o, ov, ou].iter().flat_map(|o| [format!("c{o}"), format!("d{o}")]).collect();
            return Some((names, tactic));
        }
        None
    }

    /// A range flag `v`: a bit with `v·(t − K) = 0` and `(t·(1 − v)).val < K` over a known `t`
    /// (a canonical word's top-byte check).  `v = 1` forces `t = K` and `v = 0` forces
    /// `t < K`, so the two witnesses cannot disagree.  Returns the hypotheses and the tactic.
    fn range_flag_step(&self, v: usize, support: &BTreeSet<u32>) -> Option<(Vec<String>, String)> {
        let same = |u: usize| self.xn(u) == self.yn(u);
        let poly = |o: usize| match self.m.constraints.get(o) {
            Some(PicusConstraint::Eq(e)) => to_poly(e),
            _ => None,
        };
        let sup: Vec<usize> = support.iter().map(|&o| o as usize).collect();
        let bit = sup.iter().copied().find(|&o| {
            poly(o).is_some_and(|p| {
                let t: Vec<(&[(usize, u32)], u64)> = p.terms().collect();
                t.len() == 2
                    && t.iter().any(|(m, c)| *m == [(v, 2)] && *c == 1)
                    && t.iter().any(|(m, c)| *m == [(v, 1)] && *c == P - 1)
            })
        })?;
        for &g in &sup {
            let Some(p) = poly(g) else { continue };
            let t: Vec<(&[(usize, u32)], u64)> = p.terms().collect();
            let [(m1, c1), (m2, c2)] = t.as_slice() else { continue };
            let (prod, lin) =
                if m1.len() == 2 { ((m1, c1), (m2, c2)) } else { ((m2, c2), (m1, c1)) };
            let ([(a, 1), (b, 1)], 1) = (*prod.0, *prod.1) else { continue };
            let tv = if *a == v {
                *b
            } else if *b == v {
                *a
            } else {
                continue;
            };
            if *lin.0 != [(v, 1)] || !same(tv) {
                continue;
            }
            let k = P - *lin.1;
            let lt = sup.iter().copied().find(|&o| match self.m.constraints.get(o) {
                Some(PicusConstraint::Lt(_, b)) => {
                    matches!(b.as_ref(), PicusExpr::Const(c) if *c == k)
                        && self
                            .conj_vars
                            .get(o)
                            .is_some_and(|vs| vs.len() == 2 && vs.contains(&v) && vs.contains(&tv))
                }
                _ => false,
            });
            let Some(l) = lt else { continue };
            let t = self.xn(tv);
            let tactic = format!(
                "rcases ZirenDet.bit_cases c{bit} with h | h <;> rcases ZirenDet.bit_cases d{bit} with h' | h' <;> subst h h' <;> first | rfl | (exfalso; first | exact absurd (show ({t}).val < {k} by simpa using c{l}) (by rw [show {t} = ({k} : F) by linear_combination d{g}]; decide) | exact absurd (show ({t}).val < {k} by simpa using d{l}) (by rw [show {t} = ({k} : F) by linear_combination c{g}]; decide))"
            );
            let names =
                [bit, g, l].iter().flat_map(|o| [format!("c{o}"), format!("d{o}")]).collect();
            return Some((names, tactic));
        }
        None
    }

    /// A value the analyser learned, `x_v = c`, proved from the first witness's conjuncts
    /// `support` once `v` is determined, then substituted as a case split's constant is.
    fn value_fix(&mut self, v: usize, c: u64, support: &BTreeSet<u32>, indent: usize) {
        let x = self.xn(v);
        if !self.vars.contains(&v) || x != self.yn(v) || !x.starts_with('x') {
            return;
        }
        let mut keep = self.always.clone();
        keep.extend(
            support
                .iter()
                .filter(|&&o| o < ASSUMED_ORIGIN.min(INPUT_ORIGIN))
                .map(|o| format!("c{o}")),
        );
        let mut wide = self.always.clone();
        wide.extend(
            self.widen(support)
                .iter()
                .filter(|&&o| o < ASSUMED_ORIGIN.min(INPUT_ORIGIN))
                .map(|o| format!("c{o}")),
        );
        let lit = if c > P / 2 { format!("(-{} : F)", P - c) } else { format!("({c} : F)") };
        let tactic = focused(&keep, &wide, &[], &[], false, &format!("value x{v}"));
        let goal = format!("{x} = {lit}");
        let mut hyps = keep.clone();
        hyps.extend(wide.iter().cloned());
        let proof = match self.lemma(&hyps, &goal, &tactic) {
            Some(app) => {
                format!("first | exact {app} | (trace \"PICUS_LEMMA_MISS x{v}\"; {tactic})")
            }
            None => tactic,
        };
        self.line(indent, &format!("have k{v} : {goal} := by {proof}"));
        self.line(indent, &format!("subst k{v}"));
        self.fix(v, &lit);
    }

    /// `y_v = x_v` read off the gadget summary `hg`, when `gadget_det` concludes `w.v = w'.v`:
    /// the conjunct's projection `hg.2…2.1`, reversed.  Used for a gadget step with an empty
    /// support (the summary is its whole reason): [`Replay::keep`] then keeps no hypothesis, not
    /// even `hg`, so its lemma would state only the equalities pending in its group, which do not
    /// determine `v`.
    fn gadget_projection_step(&self, v: usize) -> Option<(Vec<String>, String)> {
        let Some(Dyn::Gadget(pairs)) = self.dynamic.get("hg") else { return None };
        let i = pairs.iter().position(|&(a, b)| a == v && b == v)?;
        let last = if i + 1 == pairs.len() { "" } else { ".1" };
        Some((vec!["hg".to_string()], format!("exact (hg{}{last}).symm", ".2".repeat(i))))
    }

    /// The `GtColsBytes` result through `gt_bytes_det`, found by the shapes of its conjuncts
    /// (gate `g` already the constant `1`): the two lookups `r·g − 1 = 0 ↔ bc·g < ac·g` and
    /// `(1 − r)·h − 1 = 0 ↔ ac·h < bc·h`, the selections `g·(ac − Σ aᵢ·fᵢ)` and
    /// `g·(bc − Σ bᵢ·fᵢ)`, the equalities above each flag, and the bits; `h` is boolean by its
    /// own bit constraint or, when the chip only pins `h = g·Σ fᵢ`, by the sum's bit constraint
    /// through `hh`.  Returns the hypotheses and the proof of `y_v = x_v`.
    fn gt_bytes_step(&self, v: usize) -> Option<(Vec<String>, String)> {
        type Terms = BTreeMap<Vec<(usize, u32)>, u64>;
        let terms = |p: &Poly| -> Terms { p.terms().map(|(m, c)| (m.to_vec(), c)).collect() };
        let mono = |vs: &[(usize, u32)]| -> Vec<(usize, u32)> {
            let mut m = vs.to_vec();
            m.sort();
            m
        };
        let mut eqs: Vec<(usize, Terms)> = vec![];
        let mut iffs: Vec<(usize, Terms, Terms, Terms)> = vec![];
        for (o, c) in self.m.constraints.iter().enumerate() {
            match c {
                PicusConstraint::Eq(e) => {
                    if let Some(p) = to_poly(e) {
                        eqs.push((o, terms(&p)));
                    }
                }
                PicusConstraint::Iff(l, r) => {
                    if let (PicusConstraint::Eq(le), PicusConstraint::Lt(a, b)) = (&**l, &**r) {
                        if let (Some(lp), Some(ap), Some(bp)) =
                            (to_poly(le), to_poly(a), to_poly(b))
                        {
                            iffs.push((o, terms(&lp), terms(&ap), terms(&bp)));
                        }
                    }
                }
                _ => {}
            }
        }
        let single = |t: &Terms| -> Option<Vec<(usize, u32)>> {
            match t.iter().collect::<Vec<_>>()[..] {
                [(m, 1)] => Some(m.clone()),
                _ => None,
            }
        };
        let (o1, g, ac, bc) = iffs.iter().find_map(|(o, lp, a, b)| {
            if lp.len() != 2 || lp.get(&vec![]) != Some(&(P - 1)) {
                return None;
            }
            let (m, c) = lp.iter().find(|(m, _)| !m.is_empty())?;
            let g = match m[..] {
                [(p, 1), (q, 1)] if *c == 1 && (p == v || q == v) => {
                    if p == v {
                        q
                    } else {
                        p
                    }
                }
                _ => return None,
            };
            let pick = |m: Vec<(usize, u32)>| match m[..] {
                [(p, 1), (q, 1)] if p == g || q == g => Some(if p == g { q } else { p }),
                _ => None,
            };
            Some((*o, g, pick(single(b)?)?, pick(single(a)?)?))
        })?;
        if self.xn(g) != "(1 : F)" {
            return None;
        }
        let (o2, h) = iffs.iter().find_map(|(o, lp, a, b)| {
            if lp.len() != 3 || lp.get(&vec![]) != Some(&(P - 1)) {
                return None;
            }
            let h = lp.iter().find_map(|(m, c)| match m[..] {
                [(h, 1)] if *c == 1 && h != v => Some(h),
                _ => None,
            })?;
            let ok = lp.get(&mono(&[(v, 1), (h, 1)])) == Some(&(P - 1))
                && single(a)? == mono(&[(ac, 1), (h, 1)])
                && single(b)? == mono(&[(bc, 1), (h, 1)]);
            ok.then_some((*o, h))
        })?;
        let sel = |t: usize| -> Option<(usize, Vec<(usize, usize)>)> {
            eqs.iter().find_map(|(o, tm)| {
                if tm.len() != 5 || tm.get(&mono(&[(g, 1), (t, 1)])) != Some(&1) {
                    return None;
                }
                let pairs: Option<Vec<(usize, usize)>> = tm
                    .iter()
                    .filter(|(m, _)| m.len() == 3)
                    .map(|(m, c)| {
                        let rest: Vec<usize> = m.iter().map(|x| x.0).filter(|&x| x != g).collect();
                        (*c == P - 1 && rest.len() == 2 && m.iter().all(|x| x.1 == 1))
                            .then(|| (rest[0], rest[1]))
                    })
                    .collect();
                let pairs = pairs?;
                (pairs.len() == 4).then_some((*o, pairs))
            })
        };
        let (oa, pa) = sel(ac)?;
        let (ob, pb) = sel(bc)?;
        let bvars: BTreeSet<usize> = pb.iter().flat_map(|&(p, q)| [p, q]).collect();
        let mut bytes: Vec<(usize, usize, usize)> = vec![];
        for &(p, q) in &pa {
            let (f, a) = if bvars.contains(&p) { (p, q) } else { (q, p) };
            let b = pb.iter().find_map(|&(s, t)| {
                if s == f {
                    Some(t)
                } else if t == f {
                    Some(s)
                } else {
                    None
                }
            })?;
            bytes.push((f, a, b));
        }
        let flags: BTreeSet<usize> = bytes.iter().map(|x| x.0).collect();
        let mut ranked: Vec<(usize, u32, (usize, usize, usize))> = vec![];
        for &(f, a, b) in &bytes {
            let (oe, n) = eqs.iter().find_map(|(o, tm)| {
                let vs: BTreeSet<usize> = tm.keys().flatten().map(|x| x.0).collect();
                let others: Vec<usize> =
                    vs.iter().copied().filter(|&x| x != g && x != a && x != b).collect();
                (vs.contains(&a)
                    && vs.contains(&b)
                    && vs.contains(&g)
                    && !others.is_empty()
                    && others.iter().all(|x| flags.contains(x))
                    && others.contains(&f))
                .then_some((*o, others.len() as u32))
            })?;
            ranked.push((oe, n, (f, a, b)));
        }
        ranked.sort_by_key(|r| std::cmp::Reverse(r.1));
        if ranked.iter().map(|r| r.1).collect::<Vec<_>>() != vec![4, 3, 2, 1] {
            return None;
        }
        let quad = |x: usize| -> Option<usize> {
            eqs.iter().find_map(|(o, tm)| {
                let ok = tm.len() == 2
                    && tm.get(&mono(&[(g, 1), (x, 2)])) == Some(&1)
                    && tm.get(&mono(&[(g, 1), (x, 1)])) == Some(&(P - 1));
                ok.then_some(*o)
            })
        };
        // `h = Σ fᵢ` either under the gate, `g·(h − Σ fᵢ)`, or with `h` itself ungated,
        // `h − g·Σ fᵢ`, the form that also pins the lookup multiplicity to zero off real rows.
        let hh = eqs.iter().find_map(|(o, tm)| {
            let ok = tm.len() == 5
                && (tm.get(&mono(&[(g, 1), (h, 1)])) == Some(&1)
                    || tm.get(&mono(&[(h, 1)])) == Some(&1))
                && flags.iter().all(|&f| tm.get(&mono(&[(g, 1), (f, 1)])) == Some(&(P - 1)));
            ok.then_some(*o)
        })?;
        let hr = quad(v)?;
        // `h` boolean: either its own bit constraint `g·(h² − h)`, or derived from the sum's,
        // `g·(Σ fᵢ)·(Σ fᵢ − 1)` (4 squares, 6 doubled cross terms, 4 linear), together with `hh`.
        let sum_bool = || -> Option<usize> {
            let fl: Vec<usize> = flags.iter().copied().collect();
            eqs.iter().find_map(|(o, tm)| {
                let ok = tm.len() == 14
                    && fl.iter().all(|&f| {
                        tm.get(&mono(&[(g, 1), (f, 2)])) == Some(&1)
                            && tm.get(&mono(&[(g, 1), (f, 1)])) == Some(&(P - 1))
                    })
                    && fl.iter().enumerate().all(|(i, &f1)| {
                        fl.iter()
                            .skip(i + 1)
                            .all(|&f2| tm.get(&mono(&[(g, 1), (f1, 1), (f2, 1)])) == Some(&2))
                    });
                ok.then_some(*o)
            })
        };
        let (hhb, hhb_from_sum) = match quad(h) {
            Some(o) => (o, false),
            None => (sum_bool()?, true),
        };
        let fbits: Vec<usize> = ranked.iter().map(|r| quad(r.2 .0)).collect::<Option<_>>()?;
        let order: Vec<(usize, usize, usize)> = ranked.iter().map(|r| r.2).collect();
        let eo: Vec<usize> = ranked.iter().map(|r| r.0).collect();
        if order.iter().any(|&(_, a, b)| self.xn(a) != self.yn(a) || self.xn(b) != self.yn(b)) {
            return None;
        }
        let lc = |p: char, o: usize| format!("(by linear_combination {p}{o})");
        let side = |p: char| -> String {
            let n = |x: usize| if p == 'c' { self.xn(x) } else { self.yn(x) };
            let mut args: Vec<String> = order.iter().map(|&(f, _, _)| n(f)).collect();
            args.extend([n(h), n(ac), n(bc), n(v)]);
            args.join(" ")
        };
        let hyps = |p: char| -> String {
            let mut hs: Vec<String> = fbits.iter().map(|&o| lc(p, o)).collect();
            hs.push(lc(p, hh));
            if hhb_from_sum {
                // h(h − 1) = S(S − 1) + (h + S − 1)(h − S) with S = Σ fᵢ
                let n = |x: usize| if p == 'c' { self.xn(x) } else { self.yn(x) };
                let s: Vec<String> = flags.iter().map(|&f| n(f)).collect();
                hs.push(format!(
                    "(by linear_combination {p}{hhb} + ({} + {} - 1) * {p}{hh})",
                    n(h),
                    s.join(" + ")
                ));
            } else {
                hs.push(lc(p, hhb));
            }
            hs.extend(eo.iter().rev().map(|&o| lc(p, o)));
            hs.push(lc(p, oa));
            hs.push(lc(p, ob));
            hs.push(lc(p, hr));
            hs.push(format!("{p}{o1}"));
            hs.push(format!("{p}{o2}"));
            hs.join(" ")
        };
        let ab: Vec<String> = order
            .iter()
            .map(|&(_, a, _)| self.xn(a))
            .chain(order.iter().map(|&(_, _, b)| self.xn(b)))
            .collect();
        let tactic = format!(
            "exact ZirenDet.GtBytes.gt_bytes_det {} {} {} {} {}",
            ab.join(" "),
            side('c'),
            side('d'),
            hyps('c'),
            hyps('d')
        );
        let mut used: Vec<usize> = fbits.clone();
        used.extend([hh, hhb, oa, ob, hr, o1, o2]);
        used.extend(eo.iter().copied());
        let names: Vec<String> =
            used.iter().flat_map(|o| [format!("c{o}"), format!("d{o}")]).collect();
        Some((names, tactic))
    }

    /// The positional one-hot step through `onehot_lin_det`: a one-hot group `Σ b = 1` of bits
    /// containing `v` and a linear conjunct `Σ a_b·b + r = 0` over the group with pairwise
    /// distinct constant weights `a_b` and a known rest `r`; both witnesses' groups are then
    /// equal, so `v` is.
    fn onehot_positional(&self, v: usize, support: &BTreeSet<u32>) -> Option<String> {
        let polys: Vec<(u32, Poly)> = support
            .iter()
            .filter_map(|&o| match self.m.constraints.get(o as usize)? {
                PicusConstraint::Eq(e) => Some((o, to_poly(e)?)),
                _ => None,
            })
            .collect();
        let same = |u: usize| self.xn(u) == self.yn(u);
        let bit_of = |b: usize| {
            polys.iter().find_map(|(o, p)| {
                let t: Vec<(&[(usize, u32)], u64)> = p.terms().collect();
                let ok = t.len() == 2
                    && t.iter().any(|(m, c)| *m == [(b, 2)] && *c == 1)
                    && t.iter().any(|(m, c)| *m == [(b, 1)] && *c == P - 1);
                ok.then_some(*o)
            })
        };
        for (os, p) in &polys {
            let terms: Vec<(&[(usize, u32)], u64)> = p.terms().collect();
            if terms.iter().find(|(m, _)| m.is_empty()).map(|t| t.1) != Some(P - 1) {
                continue;
            }
            let group: Vec<usize> = terms
                .iter()
                .filter_map(|(m, c)| match m {
                    [(b, 1)] if *c == 1 => Some(*b),
                    _ => None,
                })
                .collect();
            if group.len() < 2 || group.len() + 1 != terms.len() || !group.contains(&v) {
                continue;
            }
            let Some(bits) = group.iter().map(|&b| bit_of(b)).collect::<Option<Vec<u32>>>() else {
                continue;
            };
            for (ol, q) in &polys {
                if ol == os || !group.iter().any(|&b| q.degree_in(b) == 1) {
                    continue;
                }
                let mut weights = vec![];
                let mut ok = true;
                for &b in &group {
                    match q.degree_in(b) {
                        0 => weights.push(0),
                        1 => match q.split_linear(b).0.as_constant_pub() {
                            Some(a) => weights.push(a),
                            None => ok = false,
                        },
                        _ => ok = false,
                    }
                }
                let rest_known = q.vars().iter().all(|&u| group.contains(&u) || same(u));
                let distinct = weights.iter().collect::<BTreeSet<_>>().len() == weights.len();
                if !ok || !rest_known || !distinct {
                    continue;
                }
                let n = group.len();
                let idx = group.iter().position(|&b| b == v)?;
                let cs: Vec<String> =
                    weights
                        .iter()
                        .map(|&a| {
                            if a > P / 2 {
                                format!("(-{} : F)", P - a)
                            } else {
                                format!("({a} : F)")
                            }
                        })
                        .collect();
                let xs: Vec<String> = group.iter().map(|&b| self.xn(b)).collect();
                let ys: Vec<String> = group.iter().map(|&b| self.yn(b)).collect();
                let cb: Vec<String> = bits.iter().map(|o| format!("exact c{o}")).collect();
                let db: Vec<String> = bits.iter().map(|o| format!("exact d{o}")).collect();
                return Some(format!(
                    "exact (congrFun (ZirenDet.OneHot.onehot_lin_det (n := {n}) (by norm_num [KB]) ![{}] (by decide) ![{}] ![{}] (fun i => by fin_cases i <;> first | {}) (by simp [Fin.sum_univ_succ]; linear_combination c{os}) (fun i => by fin_cases i <;> first | {}) (by simp [Fin.sum_univ_succ]; linear_combination d{os}) (by simp [Fin.sum_univ_succ]; linear_combination c{ol} - d{ol})) {idx}).symm",
                    cs.join(", "),
                    xs.join(", "),
                    ys.join(", "),
                    cb.join(" | "),
                    db.join(" | ")
                ));
            }
        }
        None
    }

    /// Every one-hot sum over bits among the conjuncts: `(o, members, bit conjuncts, negated)`
    /// for `Σ b − 1 = 0` (`negated` for `1 − Σ b = 0`), each member with a conjunct `b·(b − 1) = 0`.
    fn onehot_groups(&self) -> Vec<(u32, Vec<usize>, Vec<u32>, bool)> {
        let polys: Vec<(u32, Poly)> = (0..self.m.constraints.len() as u32)
            .filter_map(|o| match self.m.constraints.get(o as usize)? {
                PicusConstraint::Eq(e) => Some((o, to_poly(e)?)),
                _ => None,
            })
            .collect();
        let mut bit: HashMap<usize, u32> = HashMap::new();
        for (o, p) in &polys {
            let t: Vec<(&[(usize, u32)], u64)> = p.terms().collect();
            if let [(m1, c1), (m2, c2)] = t.as_slice() {
                for (sq, s1, lin, s2) in [(m1, c1, m2, c2), (m2, c2, m1, c1)] {
                    if let ([(b, 2)], [(b2, 1)]) = (*sq, *lin) {
                        if b == b2 && *s1 == 1 && *s2 == P - 1 {
                            bit.entry(*b).or_insert(*o);
                        }
                    }
                }
            }
        }
        let mut out = vec![];
        for (o, p) in &polys {
            let t: Vec<(&[(usize, u32)], u64)> = p.terms().collect();
            let konst = t.iter().find(|(m, _)| m.is_empty()).map(|x| x.1);
            let (neg, unit) = match konst {
                Some(k) if k == P - 1 => (false, 1),
                Some(1) => (true, P - 1),
                _ => continue,
            };
            let members: Vec<usize> = t
                .iter()
                .filter_map(|(m, c)| match m {
                    [(b, 1)] if *c == unit => Some(*b),
                    _ => None,
                })
                .collect();
            if members.len() < 2 || members.len() + 1 != t.len() {
                continue;
            }
            let Some(bits) =
                members.iter().map(|b| bit.get(b).copied()).collect::<Option<Vec<_>>>()
            else {
                continue;
            };
            out.push((*o, members, bits, neg));
        }
        out
    }

    /// The positional step over two one-hot groups `b` (containing `v`) and `z` through
    /// `onehot2_lin_det`: a linear conjunct `Σ c_i b_i + Σ d_j z_j + r = 0` with constant weights
    /// whose pair sums `c_i + d_j` are distinct and a known rest `r` (a row position
    /// `index = Σ i·octet_i + Σ 8j·cycle_j`).  Returns the hypotheses and the tactic.
    ///
    /// With `zero_weight` the conjunct may also leave `v` out (weight `c_v = 0`, the octet-0 flag
    /// of that position): distinct pair sums fix the whole group `b`, so `v` with it.
    fn onehot2_positional(&self, v: usize, zero_weight: bool) -> Option<(Vec<String>, String)> {
        let same = |u: usize| self.xn(u) == self.yn(u);
        let groups = self.onehot_groups();
        for (ol, e) in self.m.constraints.iter().enumerate() {
            let PicusConstraint::Eq(e) = e else { continue };
            let Some(q) = to_poly(e) else { continue };
            let dv = q.degree_in(v);
            if dv > 1
                || (dv == 0 && !zero_weight)
                || q.terms().any(|(m, _)| m.iter().map(|x| x.1).sum::<u32>() > 1)
            {
                continue;
            }
            let unknown: Vec<usize> = q.vars().into_iter().filter(|&u| !same(u)).collect();
            for g1 in groups.iter().filter(|g| g.1.contains(&v)) {
                let rest: Vec<usize> =
                    unknown.iter().copied().filter(|u| !g1.1.contains(u)).collect();
                if rest.is_empty() {
                    continue;
                }
                let Some(g2) = groups
                    .iter()
                    .filter(|g| rest.iter().all(|u| g.1.contains(u)))
                    .filter(|g| g.1.iter().all(|u| !g1.1.contains(u)))
                    .min_by_key(|g| g.1.len())
                else {
                    continue;
                };
                let weight = |b: usize| -> Option<u64> {
                    match q.degree_in(b) {
                        0 => Some(0),
                        1 => q.split_linear(b).0.as_constant_pub(),
                        _ => None,
                    }
                };
                let Some(cs) = g1.1.iter().map(|&b| weight(b)).collect::<Option<Vec<_>>>() else {
                    continue;
                };
                let Some(ds) = g2.1.iter().map(|&b| weight(b)).collect::<Option<Vec<_>>>() else {
                    continue;
                };
                let mut sums = BTreeSet::new();
                if !cs.iter().all(|&c| ds.iter().all(|&d| sums.insert((c + d) % P))) {
                    continue;
                }
                let konst = |a: &u64| {
                    if *a > P / 2 {
                        format!("(-{} : F)", P - a)
                    } else {
                        format!("({a} : F)")
                    }
                };
                let vec = |g: &[usize], f: &dyn Fn(usize) -> String| {
                    g.iter().map(|&b| f(b)).collect::<Vec<_>>().join(", ")
                };
                let bits = |bs: &[u32], p: char| {
                    format!(
                        "(fun i => by fin_cases i; exacts [{}])",
                        bs.iter().map(|o| format!("{p}{o}")).collect::<Vec<_>>().join(", ")
                    )
                };
                let sum = |g: &(u32, Vec<usize>, Vec<u32>, bool), p: char| {
                    let s = if g.3 { "-" } else { "" };
                    format!("(by simp [Fin.sum_univ_succ]; linear_combination {s}{p}{})", g.0)
                };
                let Some(idx) = g1.1.iter().position(|&b| b == v) else { continue };
                let tactic = format!(
                    "exact (congrFun (ZirenDet.OneHot.onehot2_lin_det (n := {}) (m := {}) (by norm_num [KB]) (by norm_num [KB]) ![{}] ![{}] (by decide) ![{}] ![{}] ![{}] ![{}] {} {} {} {} {} {} {} {} (by simp [Fin.sum_univ_succ]; linear_combination c{ol} - d{ol})).1 {idx}).symm",
                    g1.1.len(),
                    g2.1.len(),
                    cs.iter().map(konst).collect::<Vec<_>>().join(", "),
                    ds.iter().map(konst).collect::<Vec<_>>().join(", "),
                    vec(&g1.1, &|b| self.xn(b)),
                    vec(&g1.1, &|b| self.yn(b)),
                    vec(&g2.1, &|b| self.xn(b)),
                    vec(&g2.1, &|b| self.yn(b)),
                    bits(&g1.2, 'c'),
                    sum(g1, 'c'),
                    bits(&g2.2, 'c'),
                    sum(g2, 'c'),
                    bits(&g1.2, 'd'),
                    sum(g1, 'd'),
                    bits(&g2.2, 'd'),
                    sum(g2, 'd'),
                );
                let mut used: Vec<u32> = vec![ol as u32, g1.0, g2.0];
                used.extend(g1.2.iter().chain(g2.2.iter()).copied());
                let names = used.iter().flat_map(|o| [format!("c{o}"), format!("d{o}")]).collect();
                return Some((names, tactic));
            }
        }
        None
    }

    /// The gated step over two known one-hot groups `b`, `z` as one identity: a gate
    /// `α·b_i·z_j·v + r_ij = 0` (`α = ±1`, `r_ij` known) for every pair, so the copies subtract
    /// to `α·b_i·z_j·(v' − v)` and, with `Σ_ij b_i z_j = S_b·S_z`,
    /// `v' − v = α⁻¹·Σ (d_ij − c_ij) − (v' − v)·S_z·(S_b − 1) − (v' − v)·(S_z − 1)`
    /// (a round constant selected by a (cycle, octet) pair).  Returns the hypotheses and tactic.
    fn onehot_gate2(&self, v: usize) -> Option<(Vec<String>, String)> {
        let same = |u: usize| self.xn(u) == self.yn(u);
        let mut gates: HashMap<(usize, usize), (u32, u64)> = HashMap::new();
        for (o, e) in self.m.constraints.iter().enumerate() {
            let PicusConstraint::Eq(e) = e else { continue };
            let Some(p) = to_poly(e) else { continue };
            if p.degree_in(v) != 1 || !p.vars().iter().all(|&u| u == v || same(u)) {
                continue;
            }
            let (a, _) = p.split_linear(v);
            let terms: Vec<(&[(usize, u32)], u64)> = a.terms().collect();
            let [([(b, 1), (z, 1)], alpha)] = terms.as_slice() else { continue };
            if *alpha == 1 || *alpha == P - 1 {
                gates.entry((*b.min(z), *b.max(z))).or_insert((o as u32, *alpha));
            }
        }
        if gates.len() < 4 {
            return None;
        }
        let groups = self.onehot_groups();
        let known: Vec<&(u32, Vec<usize>, Vec<u32>, bool)> =
            groups.iter().filter(|g| g.1.iter().all(|&u| same(u))).collect();
        for g1 in &known {
            for g2 in &known {
                if g1.0 == g2.0 || g1.1.iter().any(|u| g2.1.contains(u)) {
                    continue;
                }
                let mut gs = vec![];
                for &b in &g1.1 {
                    for &z in &g2.1 {
                        match gates.get(&(b.min(z), b.max(z))) {
                            Some(g) => gs.push(*g),
                            None => break,
                        }
                    }
                }
                if gs.len() != g1.1.len() * g2.1.len() || gs.iter().any(|g| g.1 != gs[0].1) {
                    continue;
                }
                let diffs: Vec<String> = gs.iter().map(|(o, _)| format!("(d{o} - c{o})")).collect();
                let sign = if gs[0].1 == 1 { "" } else { "-" };
                let (y, x) = (self.yn(v), self.xn(v));
                let s2: Vec<String> = g2.1.iter().map(|&u| self.xn(u)).collect();
                let e = |g: &(u32, Vec<usize>, Vec<u32>, bool)| {
                    if g.3 {
                        format!("(-1 : F) * c{}", g.0)
                    } else {
                        format!("c{}", g.0)
                    }
                };
                let tactic = format!(
                    "linear_combination {sign}({}) - ({y} - {x}) * ({}) * {} - ({y} - {x}) * {}",
                    diffs.join(" + "),
                    s2.join(" + "),
                    e(g1),
                    e(g2)
                );
                let mut used: Vec<u32> = gs.iter().map(|g| g.0).collect();
                used.extend([g1.0, g2.0]);
                let names = used.iter().flat_map(|o| [format!("c{o}"), format!("d{o}")]).collect();
                return Some((names, tactic));
            }
        }
        None
    }

    /// The gated one-hot step as one identity.  With a one-hot `Σ_b b − 1 = 0` and, for each
    /// member `b`, a gate `α·b·v + r_b = 0` whose rest `r_b` is known (the same in both
    /// witnesses), the copies subtract to `α·b·(v' − v)`, so
    /// `v' − v = α⁻¹·Σ_b (d_b − c_b) − (v' − v)·(Σ_b b − 1)` for `α = ±1`.
    fn onehot_gate(&self, v: usize, support: &BTreeSet<u32>) -> Option<String> {
        let polys: Vec<(u32, Poly)> = support
            .iter()
            .filter_map(|&o| match self.m.constraints.get(o as usize)? {
                PicusConstraint::Eq(e) => Some((o, to_poly(e)?)),
                _ => None,
            })
            .collect();
        let same = |u: usize| self.xn(u) == self.yn(u);
        let mut gates: HashMap<usize, (u32, u64)> = HashMap::new();
        for (o, p) in &polys {
            if p.degree_in(v) != 1 || !p.vars().iter().all(|&u| u == v || same(u)) {
                continue;
            }
            let (a, _) = p.split_linear(v);
            let terms: Vec<(&[(usize, u32)], u64)> = a.terms().collect();
            let [([(b, 1)], alpha)] = terms.as_slice() else { continue };
            if *alpha == 1 || *alpha == P - 1 {
                gates.entry(*b).or_insert((*o, *alpha));
            }
        }
        for (o1, p) in &polys {
            let terms: Vec<(&[(usize, u32)], u64)> = p.terms().collect();
            if terms.iter().filter(|(m, _)| m.is_empty()).map(|(_, c)| *c).next() != Some(P - 1) {
                continue;
            }
            let bits: Vec<usize> = terms
                .iter()
                .filter(|(m, _)| !m.is_empty())
                .filter_map(|(m, c)| match m {
                    [(b, 1)] if *c == 1 => Some(*b),
                    _ => None,
                })
                .collect();
            if bits.len() < 2 || bits.len() + 1 != terms.len() || !bits.iter().all(|&b| same(b)) {
                continue;
            }
            let Some(gs) = bits.iter().map(|b| gates.get(b).copied()).collect::<Option<Vec<_>>>()
            else {
                continue;
            };
            let alpha = gs[0].1;
            if gs.iter().any(|g| g.1 != alpha) {
                continue;
            }
            let diffs: Vec<String> = gs.iter().map(|(o, _)| format!("(d{o} - c{o})")).collect();
            let sign = if alpha == 1 { "" } else { "-" };
            let (y, x) = (self.yn(v), self.xn(v));
            return Some(format!(
                "linear_combination {sign}({}) - ({y} - {x}) * c{o1}",
                diffs.join(" + ")
            ));
        }
        None
    }

    /// `support` plus every conjunct sharing a variable with it (the analyser's field reasoning
    /// can skip a bit or range fact the integer lift needs), capped so the context stays small.
    fn widen(&self, support: &BTreeSet<u32>) -> BTreeSet<u32> {
        const WIDE_MAX: usize = 96;
        const SMALL_CONJUNCT: usize = 12;
        let seen: BTreeSet<usize> = support
            .iter()
            .filter_map(|&o| self.conj_vars.get(o as usize))
            .flatten()
            .copied()
            .collect();
        let near: Vec<u32> = (0..self.conj_vars.len() as u32)
            .filter(|&j| !support.contains(&j))
            .filter(|&j| self.conj_vars[j as usize].iter().any(|v| seen.contains(v)))
            .collect();
        let mut out = support.clone();
        if near.len() + support.len() <= WIDE_MAX {
            out.extend(near);
        } else {
            out.extend(
                near.into_iter()
                    .filter(|&j| self.conj_vars[j as usize].len() <= SMALL_CONJUNCT)
                    .take(WIDE_MAX),
            );
        }
        out
    }

    /// The hypotheses behind the conjuncts `support`, plus [`Replay::always`].
    fn keep(&self, support: &BTreeSet<u32>) -> Vec<String> {
        if support.is_empty() {
            return vec![];
        }
        let mut out = self.always.clone();
        for &o in support {
            if o >= ASSUMED_ORIGIN || o >= INPUT_ORIGIN {
                continue;
            }
            out.push(format!("c{o}"));
            out.push(format!("d{o}"));
        }
        out
    }

    fn poly(&self, p: &Poly) -> Option<String> {
        let mut terms = vec![];
        for (mono, c) in p.terms() {
            let mut factors = vec![];
            for &(v, e) in mono {
                if !self.vars.contains(&v) {
                    return None;
                }
                factors.push(if e == 1 { format!("x{v}") } else { format!("x{v} ^ {e}") });
            }
            let coef = if c > 0x7f00_0001 / 2 {
                format!("-({} : F)", 0x7f00_0001 - c)
            } else {
                format!("({c} : F)")
            };
            terms.push(if factors.is_empty() {
                coef
            } else if c == 1 {
                factors.join(" * ")
            } else {
                format!("{coef} * {}", factors.join(" * "))
            });
        }
        Some(if terms.is_empty() { "(0 : F)".into() } else { terms.join(" + ") })
    }

    /// Replays one branch; the names it fixes and substitutes stay local to it, so a sibling
    /// branch (a separate Lean goal) starts from the names of the split point.
    fn branch(&mut self, d: &Derivation, indent: usize) {
        let saved = (self.xmap.clone(), self.ymap.clone());
        self.branch_body(d, indent);
        (self.xmap, self.ymap) = saved;
    }

    fn branch_body(&mut self, d: &Derivation, indent: usize) {
        let steps: Vec<(usize, &(usize, Rule, BTreeSet<u32>))> =
            d.steps.iter().enumerate().filter(|(_, s)| self.vars.contains(&s.0)).collect();
        let mut pending: Vec<usize> = vec![];
        let mut values = d.values.iter().peekable();
        while let Some((_, v, c, sup)) = values.next_if(|x| x.0 == 0) {
            self.value_fix(*v, *c, sup, indent);
        }
        for (i, (j, (v, rule, support))) in
            steps.iter().map(|(j, s)| (*j, (&s.0, &s.1, &s.2))).enumerate()
        {
            let v = *v;
            let whole = support;
            let local = self.localize(v, whole);
            let support = &local;
            let mut keep = self.keep(support);
            let mut wide = self.keep(&self.widen(support));
            if !pending.is_empty() {
                let earlier: Vec<String> = pending.iter().map(|p| format!("e{p}")).collect();
                let tail = format!("{}; (try subst_vars)", earlier.join(" "));
                keep.push(tail.clone());
                wide.push(tail);
            }
            let eqs: Vec<u32> = support
                .iter()
                .copied()
                .filter(|&o| self.eqs.get(o as usize).copied().unwrap_or(false))
                .collect();
            let (mut diff, rest): (Vec<u32>, Vec<u32>) =
                eqs.into_iter().partition(|&o| self.conj_vars[o as usize].contains(&v));
            let own: Vec<u32> = diff.iter().copied().take(MAX_DIFF).collect();
            diff.extend(rest);
            diff.truncate(MAX_DIFF);
            let tactic = focused(
                &keep,
                &wide,
                &diff,
                &own,
                matches!(rule, Rule::Probe | Rule::SmallDomain | Rule::Gadget),
                &format!("step x{v} {rule:?}"),
            );
            let tactic = match (rule, self.onehot_gate(v, support)) {
                (Rule::OneHot, Some(lc)) if pending.is_empty() => {
                    format!("first | ({lc}) | {tactic}")
                }
                _ => tactic,
            };
            let tactic = match (rule, self.onehot_positional(v, support)) {
                (Rule::OneHot, Some(t)) => format!("first | ({t}) | {tactic}"),
                _ => tactic,
            };
            let tactic = match (rule, self.iszero_step(v, support)) {
                (Rule::IsZero | Rule::LinearInverse, Some(t)) => {
                    format!("first | ({t}) | {tactic}")
                }
                _ => tactic,
            };
            let mut hyps = keep.clone();
            hyps.extend(wide.iter().cloned());
            let goal = format!("{} = {}", self.yn(v), self.xn(v));
            let onehot_open = matches!(rule, Rule::OneHot)
                && self.onehot_positional(v, support).is_none()
                && (!pending.is_empty() || self.onehot_gate(v, support).is_none());
            let zero_weight = if onehot_open
                && self.onehot2_positional(v, false).is_none()
                && self.onehot_gate2(v).is_none()
            {
                self.onehot2_positional(v, true)
            } else {
                None
            };
            let hyp_names: BTreeSet<&str> = hyps
                .iter()
                .flat_map(|h| h.split(';').next().unwrap_or("").split_whitespace())
                .collect();
            let (tactic, zero_weight) = match zero_weight {
                Some((names, t))
                    if !keep.is_empty() && names.iter().all(|n| hyp_names.contains(n.as_str())) =>
                {
                    (format!("first | ({t}) | {tactic}"), None)
                }
                other => (tactic, other),
            };
            let gt = match rule {
                Rule::Gadget => whole
                    .is_empty()
                    .then(|| self.gadget_projection_step(v))
                    .flatten()
                    .or_else(|| self.gt_bytes_step(v))
                    .or_else(|| self.range_flag_step(v, support)),
                Rule::OneHot if onehot_open => self
                    .onehot2_positional(v, false)
                    .or_else(|| self.onehot_gate2(v))
                    .or(zero_weight),
                Rule::Positional => {
                    self.linear_solve(v, support).or_else(|| self.positional_diff(v, support))
                }
                _ => None,
            };
            let special = gt.and_then(|(names, t)| self.lemma(&names, &goal, &t));
            let applied = if special.is_some() || keep.is_empty() {
                special
            } else {
                self.lemma(&hyps, &goal, &tactic)
            };
            let fallback = if steps.len() > INLINE_FALLBACK_STEPS { give_up() } else { &tactic };
            let proof = match applied {
                Some(app) => {
                    format!("first | exact {app} | (trace \"PICUS_LEMMA_MISS x{v}\"; {fallback})")
                }
                None => tactic,
            };
            self.line(indent, &format!("have e{v} : y{v} = x{v} := by {proof}"));
            pending.push(v);
            self.dynamic.insert(format!("e{v}"), Dyn::Pending(v));
            let grouped = steps.get(i + 1).is_some_and(|n| n.1 .1 == *rule && n.1 .2 == *whole);
            if !grouped {
                for v in pending.drain(..) {
                    self.line(indent, &format!("replace e{v} := e{v}.symm; subst e{v}"));
                    self.dynamic.remove(&format!("e{v}"));
                    let x = self.xn(v);
                    self.ymap.insert(v, x);
                }
                while let Some((_, v, c, sup)) = values.next_if(|x| x.0 <= j + 1) {
                    self.value_fix(*v, *c, sup, indent);
                }
            }
        }
        for (_, v, c, sup) in values {
            self.value_fix(*v, *c, sup, indent);
        }
        match &d.end {
            DerivEnd::Done => self.line(
                indent,
                &format!(
                    "first | rfl | (simp only [outputs, List.cons.injEq, and_true]; constructorm* _ ∧ _ <;> first | rfl | trivial | (picus_open_goal; {}))",
                    give_up()
                ),
            ),
            DerivEnd::Infeasible { support } => {
                let keep = self.keep(support);
                let wide = self.keep(&self.widen(support));
                let c = |n: u64| n * cap_scale() / 100;
                let close = "first | grind | picus_finish | picus_local | (picus_split_bits 4; all_goals (first | grind | picus_finish | picus_local))";
                let mut tac = String::from("first");
                for (hyps, cap) in [(&keep, 200000), (&wide, 400000)] {
                    if hyps.is_empty() {
                        continue;
                    }
                    tac.push_str(&format!(
                        " | picus_cap {} (exfalso; clear * - {}; {close})",
                        c(cap),
                        hyps.join(" ")
                    ));
                }
                tac.push_str(&format!(
                    " | picus_cap {} (exfalso; {close}) | (trace \"PICUS_OPEN infeasible\"; {})",
                    c(400000),
                    give_up()
                ));
                self.line(indent, &tac)
            }
            DerivEnd::Open => {
                self.line(indent, &format!("(trace \"PICUS_OPEN open-branch\"; {})", give_up()))
            }
            DerivEnd::Bit { var, support, zero, one } => {
                if !self.vars.contains(var) {
                    self.line(indent, &format!("(trace \"PICUS_OPEN unrenderable\"; {})", give_up()));
                    return;
                }
                let h = self.fresh();
                let direct = self
                    .m
                    .constraints
                    .iter()
                    .enumerate()
                    .find_map(|(o, c)| match c {
                        PicusConstraint::Eq(e) => {
                            let t: BTreeMap<Vec<(usize, u32)>, u64> =
                                to_poly(e)?.terms().map(|(m, c)| (m.to_vec(), c)).collect();
                            let ok = t.len() == 2
                                && t.get(&vec![(*var, 2)]) == Some(&1)
                                && t.get(&vec![(*var, 1)]) == Some(&(P - 1));
                            ok.then_some(o)
                        }
                        _ => None,
                    })
                    .map(|o| {
                        format!(
                            "(rcases mul_eq_zero.mp (show x{var} * (x{var} - 1) = 0 by have q := c{o}; (try dsimp only [cj{o}] at q); linear_combination q) with q | q; exact Or.inl q; exact Or.inr (sub_eq_zero.mp q)) | "
                        )
                    })
                    .unwrap_or_default();
                self.line(
                    indent,
                    &format!(
                        "have {h} : x{var} = 0 ∨ x{var} = 1 := by first | {direct}picus_bit_hyp | {}",
                        focused(
                            &self.keep(support),
                            &self.keep(&self.widen(support)),
                            &[],
                            &[],
                            false,
                            &format!("bit x{var}")
                        )
                    ),
                );
                self.line(indent, &format!("rcases {h} with {h} | {h}"));
                for (sub, c) in [(zero, "(0 : F)"), (one, "(1 : F)")] {
                    self.line(indent, &format!("· subst {h}"));
                    let saved = (self.xmap.clone(), self.ymap.clone());
                    self.fix(*var, c);
                    self.branch(sub, indent + 2);
                    (self.xmap, self.ymap) = saved;
                }
            }
            DerivEnd::OneHot { bits, support, branches } => {
                let keep = self.keep(support);
                let wide = self.keep(&self.widen(support));
                if bits.iter().any(|b| !self.vars.contains(b)) {
                    self.line(indent, &format!("(trace \"PICUS_OPEN unrenderable\"; {})", give_up()));
                    return;
                }
                let mut depth = indent;
                let entry = (self.xmap.clone(), self.ymap.clone());
                for (k, (&b, sub)) in bits.iter().zip(branches).enumerate() {
                    let h = self.fresh();
                    let only_b = BTreeSet::from([b]);
                    let bit_conj: String = (0..self.m.constraints.len())
                        .filter(|&o| self.conj_vars[o] == only_b && !self.eqs[o])
                        .map(|o| format!("exact (ZirenDet.bit_cases c{o}).symm | "))
                        .collect();
                    self.line(
                        depth,
                        &format!(
                            "have {h} : x{b} = 1 ∨ x{b} = 0 := by first | {bit_conj}{}",
                            focused(&keep, &wide, &[], &[], false, &format!("bit x{b}"))
                        ),
                    );
                    self.line(depth, &format!("rcases {h} with {h} | {h}"));
                    self.line(depth, &format!("· subst {h}"));
                    let saved = (self.xmap.clone(), self.ymap.clone());
                    self.fix(b, "(1 : F)");
                    for &o in bits.iter().skip(k + 1) {
                        self.line(
                            depth + 2,
                            &format!("have e{o} : x{o} = 0 := by {}", focused(&keep, &wide, &[], &[], false, &format!("onehot x{o}"))),
                        );
                        self.line(depth + 2, &format!("subst e{o}"));
                        self.fix(o, "(0 : F)");
                    }
                    self.branch(sub, depth + 2);
                    (self.xmap, self.ymap) = saved;
                    self.line(depth, &format!("· subst {h}"));
                    self.fix(b, "(0 : F)");
                    depth += 2;
                    if k + 1 == bits.len() {
                        self.line(
                            depth,
                            &format!("exfalso; {}", focused(&keep, &wide, &[], &[], false, "onehot-none")),
                        );
                    }
                }
                (self.xmap, self.ymap) = entry;
            }
            DerivEnd::Coef { poly, pivot, zero, nonzero } => {
                let Some(p) = self.poly(poly) else {
                    self.line(indent, &format!("(trace \"PICUS_OPEN unrenderable\"; {})", give_up()));
                    return;
                };
                let h = self.fresh();
                let terms: Vec<_> = poly.terms().collect();
                if let [(&[(v, 1)], _)] = terms.as_slice() {
                    self.line(indent, &format!("by_cases {h} : x{v} = 0"));
                    self.line(indent, &format!("· subst {h}"));
                    let saved = (self.xmap.clone(), self.ymap.clone());
                    self.fix(v, "(0 : F)");
                    self.branch(&zero[0], indent + 2);
                    (self.xmap, self.ymap) = saved;
                    self.always.push(h.clone());
                    self.dynamic.insert(h.clone(), Dyn::NotZero(v));
                    self.line(indent, "· skip");
                    self.branch(nonzero, indent + 2);
                    self.always.pop();
                    self.dynamic.remove(&h);
                    return;
                }
                self.line(indent, &format!("by_cases {h} : {p} = 0"));
                self.always.push(h.clone());
                self.dynamic.insert(h.clone(), Dyn::Poly(poly.clone(), true));
                if *pivot {
                    self.line(indent, "· skip");
                    self.branch(&zero[0], indent + 2);
                } else {
                    let mono: Vec<usize> = poly
                        .terms()
                        .next()
                        .map(|(m, _)| m.iter().map(|&(v, _)| v).collect())
                        .unwrap_or_default();
                    let alts: Vec<String> = mono.iter().map(|v| format!("x{v} = 0")).collect();
                    let names: Vec<String> = mono.iter().map(|_| h.clone() + "z").collect();
                    self.line(
                        indent,
                        &format!(
                            "· have {h}z : {} := by {}",
                            alts.join(" ∨ "),
                            step("monomial")
                        ),
                    );
                    self.line(indent + 2, &format!("rcases {h}z with {}", names.join(" | ")));
                    for (sub, &mv) in zero.iter().zip(&mono) {
                        self.line(indent + 2, &format!("· subst {h}z"));
                        let saved = (self.xmap.clone(), self.ymap.clone());
                        self.fix(mv, "(0 : F)");
                        self.branch(sub, indent + 4);
                        (self.xmap, self.ymap) = saved;
                    }
                }
                self.line(indent, "· skip");
                self.dynamic.insert(h.clone(), Dyn::Poly(poly.clone(), false));
                self.branch(nonzero, indent + 2);
                self.always.pop();
                self.dynamic.remove(&h);
            }
        }
    }
}

/// The proof of `deterministic` replaying `d` (see [`Replay`]).
/// The pattern that names a witness's fields `p0, p1, …`.
fn fields_pattern(vars: &BTreeSet<usize>, p: &str) -> String {
    vars.iter().map(|v| format!("{p}{v}")).collect::<Vec<_>>().join(", ")
}

/// The tactic that splits the constraint set `h` into its conjuncts `p0, p1, …`: first into
/// its chunks, then chunk by chunk.  One nested pattern over several hundred conjuncts takes
/// minutes to elaborate; the chunks take a second each.
fn open_conjuncts(chunks: &[usize], p: &str, h: &str) -> String {
    open_conjuncts_used(chunks, p, h, None)
}

/// [`open_conjuncts`] naming only the conjuncts in `used` when the set is long (see
/// [`LONG_CONJUNCTION`]); every conjunct otherwise.
fn open_conjuncts_used(
    chunks: &[usize],
    p: &str,
    h: &str,
    used: Option<&BTreeSet<usize>>,
) -> String {
    let mut k = 0;
    let groups: Vec<(String, Vec<String>)> = chunks
        .iter()
        .map(|&n| {
            let names: Vec<String> = (k..k + n).map(|i| format!("{p}{i}")).collect();
            let group = if n == 1 { names[0].clone() } else { format!("{p}{k}g") };
            k += n;
            (group, names)
        })
        .collect();
    let mut steps = vec![];
    if k > LONG_CONJUNCTION {
        let proj = |h: &str, j: usize, n: usize| {
            let mut t = h.to_string();
            for _ in 0..j {
                t = format!("And.right ({t})");
            }
            if j + 1 < n {
                format!("And.left ({t})")
            } else {
                t
            }
        };
        let wanted = |name: &str| {
            used.is_none_or(|u| name[p.len()..].parse::<usize>().is_ok_and(|i| u.contains(&i)))
        };
        for (gi, (group, names)) in groups.iter().enumerate() {
            if !names.iter().any(|n| wanted(n)) {
                continue;
            }
            let g = proj(h, gi, groups.len());
            if names.len() == 1 {
                steps.push(format!("have {group} := {g}"));
                continue;
            }
            steps.push(format!("have {group} := {g}"));
            for (j, name) in names.iter().enumerate() {
                if wanted(name) {
                    steps.push(format!("have {name} := {}", proj(group, j, names.len())));
                }
            }
            steps.push(format!("clear {group}"));
        }
        return steps.join("; ");
    }
    if groups.len() == 1 {
        let (_, names) = &groups[0];
        steps.push(if names.len() == 1 {
            format!("obtain {} := {h}", names[0])
        } else {
            format!("obtain ⟨{}⟩ := {h}", names.join(", "))
        });
    } else {
        let all: Vec<&str> = groups.iter().map(|g| g.0.as_str()).collect();
        steps.push(format!("obtain ⟨{}⟩ := {h}", all.join(", ")));
        for (group, names) in &groups {
            if names.len() > 1 {
                steps.push(format!("obtain ⟨{}⟩ := {group}", names.join(", ")));
            }
        }
    }
    steps.join("; ")
}

/// Where hand-written proofs of gadget determinism live, one file per module identifier.
fn snippet_dir() -> std::path::PathBuf {
    std::env::var_os("PICUS_SNIPPET_DIR").map(Into::into).unwrap_or_else(|| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../lean4/snippets")
    })
}

/// The hand-written proof for module `ident`, with its placeholders filled: `%OPEN_W%` and
/// `%OPEN_W'%` split the two witnesses into fields `x…` and `y…`, `%OPEN_HW%` and
/// `%OPEN_HW'%` split the two constraint sets into conjuncts `c…` and `d…`.  A snippet states
/// `gadget_det (w w' : W) (hw : constraints w) (hw' : constraints w') (hin : inputs w = inputs w')`,
/// a conjunction of equalities `w.v = w'.v` over the columns its gadgets determine.
fn snippet(ident: &str, vars: &BTreeSet<usize>, chunks: &[usize]) -> Option<String> {
    let text = std::fs::read_to_string(snippet_dir().join(format!("{ident}.lean"))).ok()?;
    let text = fill_projections(&text, chunks);
    Some(
        text.replace("%OPEN_W'%", &format!("obtain ⟨{}⟩ := w'", fields_pattern(vars, "y")))
            .replace("%OPEN_W%", &format!("obtain ⟨{}⟩ := w", fields_pattern(vars, "x")))
            .replace("%OPEN_HW'%", &open_conjuncts(chunks, "d", "hw'"))
            .replace("%OPEN_HW%", &open_conjuncts(chunks, "c", "hw")),
    )
}

/// Input variables a module's bit postconditions assume to be bits, by module name: filled by
/// the CLI's triage from the obligations the engine could close only on that assumption.
pub static ASSUMED_BITS: std::sync::Mutex<BTreeMap<String, BTreeSet<usize>>> =
    std::sync::Mutex::new(BTreeMap::new());

/// A hand-written proof of module `ident`'s `postconditions`, read from
/// `<ident>_postconditions.lean` in the snippet directory.  The file holds whole theorems, one per
/// chip whose module has that name; a proof is used only when its statement is exactly the one
/// generated (`stmt`), so a snippet written for another chip, or for an older constraint system,
/// is never applied.
fn postconditions_snippet(ident: &str, stmt: &str) -> Option<String> {
    let text =
        std::fs::read_to_string(snippet_dir().join(format!("{ident}_postconditions.lean"))).ok()?;
    let at = text.find(stmt)? + stmt.len();
    let end = text[at..].find("theorem postconditions").map_or(text.len(), |e| at + e);
    let proof = text[at..end].trim_end();
    Some(
        proof
            .lines()
            .take_while(|l| !l.starts_with("/-"))
            .collect::<Vec<_>>()
            .join("\n")
            .trim_end()
            .to_string(),
    )
}

/// Replaces `%PROJ_Cn%` (`%PROJ_Dn%`) in a snippet by the projection of conjunct `n` out of
/// `hw : constraints w` (`hw'`).  `constraints` is the conjunction of the chunk definitions
/// `constraints_k`, each the conjunction of `chunks[k]` conjuncts, so conjunct `n` is reached
/// through its chunk; a snippet that passes `hw` to lemmas projects each conjunct where it is used,
/// in that lemma's own small context.
fn fill_projections(text: &str, chunks: &[usize]) -> String {
    let proj = |h: &str, n: usize| -> Option<String> {
        let mut k = 0;
        let mut j = n;
        while k < chunks.len() && j >= chunks[k] {
            j -= chunks[k];
            k += 1;
        }
        if k == chunks.len() {
            return None;
        }
        let mut t = h.to_string();
        for _ in 0..k {
            t = format!("And.right ({t})");
        }
        if k + 1 < chunks.len() {
            t = format!("And.left ({t})");
        }
        for _ in 0..j {
            t = format!("And.right ({t})");
        }
        if j + 1 < chunks[k] {
            t = format!("And.left ({t})");
        }
        Some(t)
    };
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("%PROJ_") {
        out.push_str(&rest[..at]);
        let tail = &rest[at + 6..];
        let side = tail.chars().next();
        let digits: String = tail[1..].chars().take_while(char::is_ascii_digit).collect();
        let close = 1 + digits.len();
        let filled = match (side, digits.parse::<usize>(), tail[close..].starts_with('%')) {
            (Some('C'), Ok(n), true) => proj("hw", n),
            (Some('D'), Ok(n), true) => proj("hw'", n),
            _ => None,
        };
        match filled {
            Some(t) => {
                out.push_str(&t);
                rest = &tail[close + 1..];
            }
            None => {
                out.push_str("%PROJ_");
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The equalities `w.v_a = w'.v_b` a snippet's `gadget_det` concludes.
fn gadget_pairs(text: &str) -> Vec<(usize, usize)> {
    let Some(start) = text.find("theorem gadget_det") else { return vec![] };
    let rest = &text[start..];
    let head = "(hin : inputs w = inputs w') :";
    let Some(colon) = rest.find(head) else { return vec![] };
    let rest = &rest[colon + head.len()..];
    let end = rest.find(":= by").unwrap_or(rest.len());
    let stmt = &rest[..end];
    let mut out = vec![];
    for part in stmt.split('∧') {
        let part = part.trim();
        if let Some((a, b)) = part.split_once(" = ") {
            let a = a.trim().trim_start_matches(|c: char| !c.is_ascii_digit() && c != 'w');
            let pa = a.strip_prefix("w.v").and_then(|x| x.trim().parse::<usize>().ok());
            let pb = b.trim().strip_prefix("w'.v").and_then(|x| x.trim().parse::<usize>().ok());
            if let (Some(pa), Some(pb)) = (pa, pb) {
                out.push((pa, pb));
            }
        }
    }
    out
}

fn replay_proof(
    m: &PicusModule,
    vars: &BTreeSet<usize>,
    chunks: &[usize],
    helpers: &[String],
    d: &Derivation,
    gadget: Option<Vec<(usize, usize)>>,
) -> (String, Vec<String>) {
    let gadget_det = gadget.is_some();
    let fields = |p: &str| fields_pattern(vars, p);
    let conj = |p: &str, h: &str| open_conjuncts(chunks, p, h);
    let mut always: Vec<String> = helpers.to_vec();
    for (list, hyp) in [(&m.inputs, "hin"), (&m.assume_deterministic, "hassume")] {
        for (j, e) in list.iter().enumerate() {
            if !matches!(e, PicusExpr::Var(_)) {
                always.push(format!("{hyp}{j}"));
            }
        }
    }
    let conj_vars: Vec<BTreeSet<usize>> = m
        .constraints
        .iter()
        .map(|c| {
            let mut vs = BTreeSet::new();
            collect_vars_constraint(c, &mut vs);
            vs
        })
        .chain(m.calls.iter().map(|call| {
            let mut vs = BTreeSet::new();
            for e in call.inputs.iter().chain(&call.outputs) {
                collect_vars_expr(e, &mut vs);
            }
            vs
        }))
        .collect();
    let eqs: Vec<bool> = m
        .constraints
        .iter()
        .zip(&conj_vars)
        .map(|(c, vs)| matches!(c, PicusConstraint::Eq(_)) && vs.len() >= 2)
        .collect();
    if gadget_det {
        always.push("hg".to_string());
    }
    let mut dynamic = BTreeMap::new();
    for h in helpers {
        let ci = h.trim_start_matches("h_");
        dynamic.insert(
            h.clone(),
            Dyn::Text(format!("∀ i o o', {ci}.rel i o → {ci}.rel i o' → o = o'")),
        );
    }
    let mut ymap = BTreeMap::new();
    for (list, hyp) in [(&m.inputs, "hin"), (&m.assume_deterministic, "hassume")] {
        for (j, e) in list.iter().enumerate() {
            match e {
                PicusExpr::Var(v) => {
                    ymap.insert(*v, format!("x{v}"));
                }
                _ => {
                    dynamic.insert(format!("{hyp}{j}"), Dyn::Expr(e.clone()));
                }
            }
        }
    }
    if let Some(pairs) = gadget {
        dynamic.insert("hg".to_string(), Dyn::Gadget(pairs));
    }
    let mut r = Replay {
        vars,
        m,
        out: String::new(),
        xmap: BTreeMap::new(),
        ymap,
        dynamic,
        lemmas: vec![],
        hyp: 0,
        always,
        conj_vars,
        eqs,
    };
    r.line(0, "(");
    if gadget_det {
        r.line(4, "have hg := gadget_det w w' hw hw' hin");
    }
    r.line(4, &format!("obtain ⟨{}⟩ := w", fields("x")));
    r.line(4, &format!("obtain ⟨{}⟩ := w'", fields("y")));
    let mut substituted = BTreeSet::new();
    for (list, hyp) in [(&m.inputs, "hin"), (&m.assume_deterministic, "hassume")] {
        let def = if hyp == "hin" { "inputs" } else { "assumed" };
        if list.len() > LONG_INTERFACE {
            let n = list.len();
            r.line(
                4,
                &format!(
                    "have {hyp}L := {hyp}; simp only [{def}, List.cons.injEq, and_true] at {hyp}L"
                ),
            );
            for j in 0..n {
                let tail = if j + 1 < n { ".1" } else { "" };
                r.line(4, &format!("have {hyp}{j} := {hyp}L{}{tail}", ".2".repeat(j)));
            }
            r.line(4, &format!("clear {hyp}L"));
            for (j, e) in list.iter().enumerate() {
                if let PicusExpr::Var(v) = e {
                    if substituted.insert(*v) {
                        r.line(4, &format!("subst {hyp}{j}"));
                    }
                }
            }
            continue;
        }
        for (j, e) in list.iter().enumerate() {
            r.line(
                4,
                &format!(
                    "have {hyp}{j} := congrArg (·[{j}]?) {hyp}; simp only [{def}, List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at {hyp}{j}"
                ),
            );
            if let PicusExpr::Var(v) = e {
                if substituted.insert(*v) {
                    r.line(4, &format!("subst {hyp}{j}"));
                }
            }
        }
    }
    if !chunks.is_empty() {
        if chunks.iter().sum::<usize>() > LONG_CONJUNCTION {
            let defs: Vec<String> = std::iter::once("constraints".to_string())
                .chain((0..chunks.len()).map(|k| format!("constraints_{k}")))
                .collect();
            r.line(4, &format!("dsimp only [{}] at hw hw'", defs.join(", ")));
        }
        r.line(4, "%OPEN_C_USED%");
        r.line(4, "%OPEN_D_USED%");
    }
    r.line(4, "dsimp only at *");
    r.branch(d, 4);
    r.line(2, ")");
    let long = chunks.iter().sum::<usize>() > LONG_CONJUNCTION;
    let used = |p: char| -> BTreeSet<usize> {
        let b = r.out.as_bytes();
        let mut out = BTreeSet::new();
        for i in 0..b.len() {
            if b[i] == p as u8
                && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'))
            {
                let mut j = i + 1;
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
                let end = j == b.len()
                    || !(b[j].is_ascii_alphanumeric() || b[j] == b'_' || b[j] == b'\'');
                if j > i + 1 && end {
                    out.insert(r.out[i + 1..j].parse().unwrap());
                }
            }
        }
        out
    };
    let (uc, ud) = (used('c'), used('d'));
    let (oc, od) = if long {
        (
            open_conjuncts_used(chunks, "c", "hw", Some(&uc)),
            open_conjuncts_used(chunks, "d", "hw'", Some(&ud)),
        )
    } else {
        (conj("c", "hw"), conj("d", "hw'"))
    };
    r.out = r.out.replace("%OPEN_C_USED%", &oc).replace("%OPEN_D_USED%", &od);
    (r.out, r.lemmas)
}

/// Lean identifier for a Picus module / chip name.
pub fn lean_ident(name: &str) -> String {
    let mut out = String::new();
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    let out = out.trim_matches('_').to_string();
    if out.is_empty() || out.chars().next().unwrap().is_ascii_digit() {
        format!("M_{out}")
    } else {
        out
    }
}

/// Adds every variable of `e` to `out`.
pub fn collect_vars_expr(e: &PicusExpr, out: &mut BTreeSet<usize>) {
    match e {
        PicusExpr::Const(_) => {}
        PicusExpr::Var(v) => {
            out.insert(*v);
        }
        PicusExpr::Add(a, b)
        | PicusExpr::Sub(a, b)
        | PicusExpr::Mul(a, b)
        | PicusExpr::Div(a, b) => {
            collect_vars_expr(a, out);
            collect_vars_expr(b, out);
        }
        PicusExpr::Neg(a) | PicusExpr::Pow(_, a) => collect_vars_expr(a, out),
    }
}

/// Adds every variable of `c` to `out`.
pub fn collect_vars_constraint(c: &PicusConstraint, out: &mut BTreeSet<usize>) {
    match c {
        PicusConstraint::Lt(a, b)
        | PicusConstraint::Leq(a, b)
        | PicusConstraint::Gt(a, b)
        | PicusConstraint::Geq(a, b) => {
            collect_vars_expr(a, out);
            collect_vars_expr(b, out);
        }
        PicusConstraint::Implies(a, b)
        | PicusConstraint::Iff(a, b)
        | PicusConstraint::And(a, b)
        | PicusConstraint::Or(a, b) => {
            collect_vars_constraint(a, out);
            collect_vars_constraint(b, out);
        }
        PicusConstraint::Not(a) => collect_vars_constraint(a, out),
        PicusConstraint::Eq(e) => collect_vars_expr(e, out),
    }
}

/// KoalaBear modulus, for rendering constants in the form the Lean automation wants.
const KB: u64 = 0x7f00_0001;

/// Renders a field constant so that its integer meaning is visible to `omega`:
/// `c > p/2` is written as the negative `-(p - c)`, and the inverse of a power of two `2^k`
/// (`k ≤ 30`) as `(2^k : F)⁻¹`.  Everything else is the literal.
fn render_const(c: u64) -> String {
    let c = c % KB;
    if c <= KB / 2 {
        return format!("({c} : F)");
    }
    for k in 1..=30u32 {
        let pow = 1u64 << k;
        if (c as u128 * pow as u128) % KB as u128 == 1 {
            return format!("(({pow} : F)⁻¹)");
        }
        let neg = KB - c;
        if (neg as u128 * pow as u128) % KB as u128 == 1 {
            return format!("(-({pow} : F)⁻¹)");
        }
    }
    format!("(-{} : F)", KB - c)
}

fn render_expr(e: &PicusExpr) -> String {
    render_expr_n(e, &|v| format!("w.v{v}"))
}

/// [`render_expr`] with variable `v` written `name(v)`.
fn render_expr_n(e: &PicusExpr, name: &dyn Fn(usize) -> String) -> String {
    let r = |e: &PicusExpr| render_expr_n(e, name);
    match e {
        PicusExpr::Const(c) => render_const(*c),
        PicusExpr::Var(v) => name(*v),
        PicusExpr::Add(a, b) => format!("({} + {})", r(a), r(b)),
        PicusExpr::Sub(a, b) => format!("({} - {})", r(a), r(b)),
        PicusExpr::Mul(a, b) => format!("({} * {})", r(a), r(b)),
        PicusExpr::Div(a, b) => format!("({} * ({})⁻¹)", r(a), r(b)),
        PicusExpr::Neg(a) => format!("(-{})", r(a)),
        PicusExpr::Pow(k, a) => format!("({} ^ {k})", r(a)),
    }
}

fn render_constraint(c: &PicusConstraint) -> String {
    render_constraint_n(c, &|v| format!("w.v{v}"))
}

/// [`render_constraint`] with variable `v` written `name(v)`.
fn render_constraint_n(c: &PicusConstraint, name: &dyn Fn(usize) -> String) -> String {
    let e = |x: &PicusExpr| render_expr_n(x, name);
    let r = |x: &PicusConstraint| render_constraint_n(x, name);
    match c {
        PicusConstraint::Eq(x) => format!("{} = 0", e(x)),
        PicusConstraint::Lt(a, b) => match b.as_ref() {
            PicusExpr::Const(c) => format!("({}).val < {}", e(a), c % KB),
            _ => format!("({}).val < ({}).val", e(a), e(b)),
        },
        PicusConstraint::Leq(a, b) => match b.as_ref() {
            PicusExpr::Const(c) => format!("({}).val ≤ {}", e(a), c % KB),
            _ => format!("({}).val ≤ ({}).val", e(a), e(b)),
        },
        PicusConstraint::Gt(a, b) => format!("({}).val > ({}).val", e(a), e(b)),
        PicusConstraint::Geq(a, b) => format!("({}).val ≥ ({}).val", e(a), e(b)),
        PicusConstraint::Implies(a, b) => format!("({} → {})", r(a), r(b)),
        PicusConstraint::Iff(a, b) => format!("({} ↔ {})", r(a), r(b)),
        PicusConstraint::And(a, b) => format!("({} ∧ {})", r(a), r(b)),
        PicusConstraint::Or(a, b) => format!("({} ∨ {})", r(a), r(b)),
        PicusConstraint::Not(a) => format!("¬ {}", r(a)),
    }
}

fn render_list(exprs: &[PicusExpr]) -> String {
    render_list_n(exprs, &|v| format!("w.v{v}"))
}

fn render_list_n(exprs: &[PicusExpr], name: &dyn Fn(usize) -> String) -> String {
    format!("[{}]", exprs.iter().map(|e| render_expr_n(e, name)).collect::<Vec<_>>().join(", "))
}

fn render_call(call: &PicusCall) -> String {
    render_call_n(call, &|v| format!("w.v{v}"))
}

fn render_call_n(call: &PicusCall, name: &dyn Fn(usize) -> String) -> String {
    format!(
        "{}.rel {} {}",
        lean_ident(&call.mod_name),
        render_list_n(&call.inputs, name),
        render_list_n(&call.outputs, name)
    )
}

/// A module with no constraints and no calls is an abstract summary (a byte-table operation or
/// an unexpanded helper): its relation is opaque and its determinism is assumed by callers.
fn is_abstract(m: &PicusModule) -> bool {
    m.constraints.is_empty() && m.calls.is_empty() && m.postconditions.is_empty()
}

fn write_module(
    w: &mut impl Write,
    m: &PicusModule,
    names: &HashMap<usize, String>,
    all_modules: &BTreeMap<String, PicusModule>,
) -> io::Result<()> {
    let ident = lean_ident(&m.name);
    let mut vars = BTreeSet::new();
    for e in m.inputs.iter().chain(&m.outputs).chain(&m.assume_deterministic) {
        collect_vars_expr(e, &mut vars);
    }
    for c in m.constraints.iter().chain(&m.postconditions) {
        collect_vars_constraint(c, &mut vars);
    }
    for call in &m.calls {
        for e in call.inputs.iter().chain(&call.outputs) {
            collect_vars_expr(e, &mut vars);
        }
    }

    writeln!(w, "/-! ### Module `{}` -/", m.name)?;
    writeln!(w, "namespace {ident}\n")?;

    if is_abstract(m) {
        writeln!(
            w,
            "/-- Abstract helper: {} input(s), {} output(s).  Its relation is left opaque; every\n\
             caller takes its determinism as a hypothesis. -/",
            m.inputs.len(),
            m.outputs.len()
        )?;
        writeln!(w, "opaque rel : List F → List F → Prop\n")?;
        writeln!(w, "end {ident}\n")?;
        return Ok(());
    }

    writeln!(w, "/-- The witness row: one field element per variable the module mentions. -/")?;
    writeln!(w, "structure W where")?;
    if vars.is_empty() {
        writeln!(w, "  dummy : F := 0")?;
    }
    for v in &vars {
        match names.get(v) {
            Some(n) => writeln!(w, "  /-- `{n}` -/\n  v{v} : F")?,
            None => writeln!(w, "  v{v} : F")?,
        }
    }
    writeln!(w)?;

    const CHUNK: usize = 48;
    let mut conj: Vec<String> = m.constraints.iter().map(render_constraint).collect();
    conj.extend(m.calls.iter().map(render_call));
    let chunks: Vec<&[String]> = conj.chunks(CHUNK).collect();
    let chunk_names: Vec<String> = (0..chunks.len()).map(|k| format!("constraints_{k}")).collect();
    writeln!(
        w,
        "/-- Every polynomial identity, range fact and helper-module call of the module. -/"
    )?;
    if conj.is_empty() {
        writeln!(w, "def constraints (_w : W) : Prop := True\n")?;
    } else {
        for (k, chunk) in chunks.iter().enumerate() {
            writeln!(w, "def constraints_{k} (w : W) : Prop :=")?;
            for (i, c) in chunk.iter().enumerate() {
                let sep = if i + 1 == chunk.len() { "" } else { " ∧" };
                writeln!(w, "  {c}{sep}")?;
            }
            writeln!(w)?;
        }
        writeln!(w, "def constraints (w : W) : Prop :=")?;
        for (k, name) in chunk_names.iter().enumerate() {
            let sep = if k + 1 == chunk_names.len() { "" } else { " ∧" };
            writeln!(w, "  {name} w{sep}")?;
        }
        writeln!(w)?;
    }
    const AUTOMATION_MAX_CONJUNCTS: usize = 600;
    const AUTOMATION_MAX_VARS: usize = 400;
    fn has_case_split(c: &PicusConstraint) -> bool {
        match c {
            PicusConstraint::Iff(..) | PicusConstraint::Implies(..) => true,
            PicusConstraint::And(a, b) | PicusConstraint::Or(a, b) => {
                has_case_split(a) || has_case_split(b)
            }
            PicusConstraint::Not(a) => has_case_split(a),
            _ => false,
        }
    }
    let case_splits = m.constraints.iter().any(has_case_split);
    let automate =
        conj.len() <= AUTOMATION_MAX_CONJUNCTS && vars.len() <= AUTOMATION_MAX_VARS && !case_splits;
    let chunk_sizes: Vec<usize> = chunks.iter().map(|c| c.len()).collect();
    let proof_snippet = snippet(&lean_ident(&m.name), &vars, &chunk_sizes);
    let mut step_lemmas: Vec<String> = vec![];
    let replay = if vars.is_empty() {
        None
    } else {
        DERIVATIONS.lock().unwrap().get(&m.name).map(|d| {
            let fallback = if chunk_names.is_empty() {
                "picus_det".to_string()
            } else {
                format!("picus_det [{}]", chunk_names.join(", "))
            };
            let helpers: Vec<String> = m
                .calls
                .iter()
                .map(|c| format!("h_{}", lean_ident(&c.mod_name)))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let gadget = proof_snippet.as_ref().map(|t| gadget_pairs(t));
            let (replay, lemmas) = replay_proof(m, &vars, &chunk_sizes, &helpers, d, gadget);
            step_lemmas = lemmas;
            if REPLAY_DIAGNOSE.load(std::sync::atomic::Ordering::Relaxed) {
                format!("picus_safe {replay}")
            } else {
                format!("first\n  | picus_budget {replay}\n  | picus_safe ({fallback})")
            }
        })
    };
    let tactic = if case_splits {
        "sorry -- comparison case-splits (Iff/Implies): automation skipped, left open".to_string()
    } else if !automate {
        format!(
            "sorry -- {} conjuncts / {} variables: above the automation threshold, left open",
            conj.len(),
            vars.len()
        )
    } else if chunk_names.is_empty() {
        "picus_safe picus_det".to_string()
    } else {
        format!("picus_safe (picus_det [{}])", chunk_names.join(", "))
    };

    let list_def = |w: &mut dyn Write, name: &str, exprs: &[PicusExpr]| -> io::Result<()> {
        if exprs.is_empty() {
            writeln!(w, "def {name} (_w : W) : List F := []")
        } else {
            writeln!(w, "def {name} (w : W) : List F :=\n  {}", render_list(exprs))
        }
    };
    if let Some((ins, outs)) = crate::picus_builder::PORT_ORIGINS.lock().unwrap().get(&m.name) {
        let fmt = |ports: &[PicusExpr], origins: &[String]| -> String {
            ports
                .iter()
                .zip(origins)
                .map(|(p, o)| format!("{} = {o}", render_expr(p).trim_start_matches("w.")))
                .collect::<Vec<_>>()
                .join(", ")
        };
        writeln!(w, "/-- Interface provenance (which lookup each port comes from).\n  inputs:  {}\n  outputs: {} -/",
            fmt(&m.inputs, ins), fmt(&m.outputs, outs))?;
        writeln!(
            w,
            "def input_origins : List String := [{}]",
            ins.iter().map(|o| format!("\"{o}\"")).collect::<Vec<_>>().join(", ")
        )?;
        writeln!(
            w,
            "def output_origins : List String := [{}]",
            outs.iter().map(|o| format!("\"{o}\"")).collect::<Vec<_>>().join(", ")
        )?;
        let mut emit_named = |prefix: &str,
                              ports: &[PicusExpr],
                              origins: &[String]|
         -> io::Result<()> {
            let mut groups: Vec<(String, Vec<String>)> = Vec::new();
            for (p, o) in ports.iter().zip(origins) {
                let (base, _idx) = match o.rfind('[') {
                    Some(i)
                        if o.ends_with(']')
                            && o[i + 1..o.len() - 1].chars().all(|c| c.is_ascii_digit()) =>
                    {
                        (o[..i].to_string(), true)
                    }
                    _ => (o.clone(), false),
                };
                let rendered = render_expr(p);
                match groups.iter_mut().find(|(b, _)| *b == base) {
                    Some((_, v)) => v.push(rendered),
                    None => groups.push((base, vec![rendered])),
                }
            }
            for (base, exprs) in groups {
                let ident = lean_ident(&base.replace(['.', '[', ']'], "_"));
                if exprs.len() == 1 && !base.contains("val") {
                    writeln!(w, "def {prefix}_{ident} (w : W) : F := {}", exprs[0])?;
                } else {
                    writeln!(w, "def {prefix}_{ident} (w : W) : List F := [{}]", exprs.join(", "))?;
                }
            }
            Ok(())
        };
        emit_named("in", &m.inputs, ins)?;
        emit_named("out", &m.outputs, outs)?;
        writeln!(w)?;
    }
    list_def(w, "inputs", &m.inputs)?;
    list_def(w, "outputs", &m.outputs)?;
    list_def(w, "assumed", &m.assume_deterministic)?;
    writeln!(w)?;
    writeln!(
        w,
        "/-- The module as a relation between its input and output lists. -/\n\
         def rel (ins outs : List F) : Prop :=\n  ∃ w : W, constraints w ∧ inputs w = ins ∧ outputs w = outs\n"
    )?;

    let mut callees: BTreeSet<String> = BTreeSet::new();
    for call in &m.calls {
        callees.insert(call.mod_name.clone());
    }
    let mut hyps = Vec::new();
    for callee in &callees {
        let ci = lean_ident(callee);
        let note = match all_modules.get(callee) {
            Some(cm) if !is_abstract(cm) => format!(" -- discharged by `{ci}.deterministic`"),
            _ => " -- abstract helper: assumed".to_string(),
        };
        hyps.push(format!("    (h_{ci} : ∀ i o o', {ci}.rel i o → {ci}.rel i o' → o = o'){note}"));
    }

    if let Some(text) = &proof_snippet {
        writeln!(w, "{text}")?;
    }
    if !step_lemmas.is_empty() {
        writeln!(w, "/-! Conjuncts as definitions over their variables, and one lemma per replayed step. -/")?;
        let calls = m.calls.iter();
        let conjuncts: Vec<(Option<&PicusConstraint>, Option<&PicusCall>)> = m
            .constraints
            .iter()
            .map(|c| (Some(c), None))
            .chain(calls.map(|c| (None, Some(c))))
            .collect();
        for (o, (c, call)) in conjuncts.iter().enumerate() {
            let mut vs = BTreeSet::new();
            match (c, call) {
                (Some(c), _) => collect_vars_constraint(c, &mut vs),
                (_, Some(call)) => {
                    for e in call.inputs.iter().chain(&call.outputs) {
                        collect_vars_expr(e, &mut vs);
                    }
                }
                _ => {}
            }
            let name = |v: usize| format!("x{v}");
            let body = match (c, call) {
                (Some(c), _) => render_constraint_n(c, &name),
                (_, Some(call)) => render_call_n(call, &name),
                _ => unreachable!(),
            };
            let params: Vec<String> = vs.iter().map(|v| format!("x{v}")).collect();
            if params.is_empty() {
                writeln!(w, "def cj{o} : Prop := {body}")?;
            } else {
                writeln!(w, "def cj{o} ({} : F) : Prop := {body}", params.join(" "))?;
            }
        }
        writeln!(w)?;
        for l in &step_lemmas {
            writeln!(w, "{l}")?;
        }
    }
    if m.name != "top" && m.name != "padding" {
        writeln!(w, "/-- Determinism: equal inputs (and equal assumed-deterministic values) force equal outputs. -/")?;
        writeln!(w, "theorem deterministic")?;
        for h in &hyps {
            writeln!(w, "{h}")?;
        }
        writeln!(
            w,
            "    (w w' : W) (hw : constraints w) (hw' : constraints w')\n\
             \x20   (hin : inputs w = inputs w') (hassume : assumed w = assumed w') :\n\
             \x20   outputs w = outputs w' := by\n\
             \x20 {}\n",
            replay.as_deref().unwrap_or(&tactic)
        )?;
    }

    if !m.postconditions.is_empty() {
        let what = if m.name == "padding" {
            "Inert padding: with `is_real` and every selector at zero, every lookup multiplicity is zero."
        } else if m.name == "top" {
            "Selector-shape / bit postconditions implied by the constraints."
        } else {
            "Every lookup multiplicity of a real row is a bit."
        };
        writeln!(w, "/-- {what} -/")?;
        let posts: Vec<String> = m.postconditions.iter().map(render_constraint).collect();
        // Multiplicities that are bits only because an input the row receives from another
        // table is one (an opcode flag of the program table) take that as a hypothesis.
        let assumed_bits: Vec<usize> = ASSUMED_BITS
            .lock()
            .unwrap()
            .get(&m.name)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();
        let mut stmt = String::from("theorem postconditions (w : W) (hw : constraints w)");
        for v in &assumed_bits {
            stmt.push_str(&format!("\n    (hbit_v{v} : w.v{v} * (w.v{v} - (1 : F)) = 0)"));
        }
        stmt.push_str(" :\n");
        for (i, p) in posts.iter().enumerate() {
            let sep = if i + 1 == posts.len() { " := by" } else { " ∧" };
            stmt.push_str(&format!("    {p}{sep}\n"));
        }
        // The postconditions speak about a few columns, so a proof unfolds only the chunks
        // that mention them or their definitions (two hops), not the whole module.
        let mut post_vars = BTreeSet::new();
        for c in &m.postconditions {
            collect_vars_constraint(c, &mut post_vars);
        }
        let conj_vars: Vec<BTreeSet<usize>> = m
            .constraints
            .iter()
            .map(|c| {
                let mut vs = BTreeSet::new();
                collect_vars_constraint(c, &mut vs);
                vs
            })
            .chain(m.calls.iter().map(|call| {
                let mut vs = BTreeSet::new();
                for e in call.inputs.iter().chain(&call.outputs) {
                    collect_vars_expr(e, &mut vs);
                }
                vs
            }))
            .collect();
        let reach_of = |seed: &BTreeSet<usize>| -> BTreeSet<usize> {
            let mut reach = seed.clone();
            let mut used: BTreeSet<usize> = BTreeSet::new();
            for _ in 0..2 {
                for (i, vs) in conj_vars.iter().enumerate() {
                    if !vs.is_disjoint(&reach) {
                        used.insert(i);
                    }
                }
                for i in &used {
                    reach.extend(&conj_vars[*i]);
                }
            }
            used
        };
        let chunk_of = |i: usize| i / CHUNK;
        let projection = |k: usize| -> String {
            let last = chunks.len() - 1;
            let mut p = String::from("hw");
            for _ in 0..k.min(last) {
                p.push_str(".2");
            }
            if k < last {
                p.push_str(".1");
            }
            p
        };
        let extract = |keep: &BTreeSet<usize>| -> String {
            let ks: BTreeSet<usize> = keep.iter().map(|i| chunk_of(*i)).collect();
            let mut t = String::new();
            for k in &ks {
                let n = chunks[*k].len();
                t.push_str(&format!("have hk{k} : constraints_{k} w := {}; ", projection(*k)));
                t.push_str(&format!("simp only [constraints_{k}] at hk{k}; "));
                if n == 1 {
                    t.push_str(&format!("have c{k}_0 := hk{k}; clear hk{k}; "));
                } else {
                    let names: Vec<String> = (0..n).map(|i| format!("c{k}_{i}")).collect();
                    t.push_str(&format!("obtain ⟨{}⟩ := hk{k}; ", names.join(", ")));
                }
                let drop: Vec<String> = (0..n)
                    .filter(|i| !keep.contains(&(k * CHUNK + i)))
                    .map(|i| format!("c{k}_{i}"))
                    .collect();
                if !drop.is_empty() {
                    t.push_str(&format!("clear {}; ", drop.join(" ")));
                }
            }
            t.push_str("clear hw");
            t
        };
        // The proof of one conjunct: project the conjuncts that reach its columns out of
        // `hw` (first the small polynomial ones, then all of them, then with the goal's bits
        // split) and let `grind` find the consequence; `picus_safe` admits it if every
        // attempt fails.
        let post_proof = |seed: &BTreeSet<usize>| -> String {
            let used = reach_of(seed);
            if used.is_empty() {
                return "picus_safe grind".to_string();
            }
            let small: BTreeSet<usize> = used
                .iter()
                .copied()
                .filter(|i| {
                    conj[*i].len() <= 200 && !conj[*i].contains(".val") && !conj[*i].contains("⁻¹")
                })
                .collect();
            let mut alts = Vec::new();
            if !small.is_empty() && small.len() < used.len() {
                alts.push(format!("({}; grind)", extract(&small)));
            }
            alts.push(format!("({}; grind)", extract(&used)));
            alts.push(format!("({}; picus_split_bits 4; all_goals grind)", extract(&used)));
            format!("picus_safe (first\n    | {})", alts.join("\n    | "))
        };
        let _ = post_vars;
        let hyps: String = assumed_bits.iter().map(|v| format!(" hbit_v{v}")).collect();
        match postconditions_snippet(&ident, &stmt) {
            Some(proof) => {
                write!(w, "{stmt}")?;
                writeln!(w, "{proof}\n")?
            }
            None if m.name == "top" => {
                write!(w, "{stmt}")?;
                writeln!(w, "  {tactic}\n")?
            }
            None => {
                // One lemma per conjunct, each over the conjuncts that reach its columns.
                let mut lemmas = String::new();
                let mut terms = Vec::new();
                for (i, c) in m.postconditions.iter().enumerate() {
                    let mut seed = BTreeSet::new();
                    collect_vars_constraint(c, &mut seed);
                    let mut head =
                        format!("theorem postcondition_{i} (w : W) (hw : constraints w)");
                    for v in &assumed_bits {
                        head.push_str(&format!(
                            "\n    (hbit_v{v} : w.v{v} * (w.v{v} - (1 : F)) = 0)"
                        ));
                    }
                    lemmas.push_str(&format!(
                        "{head} :\n    {} := by\n  {}\n\n",
                        posts[i],
                        post_proof(&seed)
                    ));
                    terms.push(format!("postcondition_{i} w hw{hyps}"));
                }
                write!(w, "{lemmas}")?;
                write!(w, "{stmt}")?;
                if terms.len() == 1 {
                    writeln!(w, "  exact {}\n", terms[0])?;
                } else {
                    writeln!(w, "  exact ⟨{}⟩\n", terms.join(", "))?;
                }
            }
        }
    }

    writeln!(w, "end {ident}\n")?;
    Ok(())
}

/// Writes `<out_dir>/ZirenDet/Chips/<Chip>.lean` for `program` and returns the path.
pub fn write_chip(
    program: &PicusProgram,
    chip: &str,
    out_dir: &Path,
    names: &HashMap<usize, String>,
) -> io::Result<PathBuf> {
    let chip_ident = lean_ident(chip);
    let dir = out_dir.join("ZirenDet").join("Chips");
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{chip_ident}.lean"));
    let mut f = fs::File::create(&path)?;
    writeln!(
        f,
        "/-\n  Generated by `cargo run -p zkm-picus -- --chip {chip} --format lean`.\n  \
         Do not edit: regenerate after any change to the chip's AIR.\n-/\n\
         import ZirenDet.Basic\nimport ZirenDet.Replay\nimport ZirenDet.GadgetProofs\n\nset_option maxRecDepth 4000000\nset_option maxHeartbeats 0\nset_option picus.safeHeartbeats 400000000\nset_option linter.dupNamespace false\nset_option linter.unusedTactic false\nset_option linter.unreachableTactic false\nset_option linter.unusedSimpArgs false\nset_option linter.all false\n\nnamespace ZirenDet.Chips.{chip_ident}\n\nopen ZirenDet\n"
    )?;
    let modules = program.modules();
    for m in modules.values().filter(|m| is_abstract(m)) {
        write_module(&mut f, m, names, modules)?;
    }
    for m in modules.values().filter(|m| !is_abstract(m)) {
        write_module(&mut f, m, names, modules)?;
    }
    writeln!(f, "end ZirenDet.Chips.{chip_ident}\n")?;
    writeln!(f, "#print \"PICUS_FILE_DONE\"")?;
    Ok(path)
}

/// Writes the shared prelude (`ZirenDet/Basic.lean`) if it is missing, (re)writes the root module
/// `ZirenDet.lean` importing the hand-written library, and (re)writes `ZirenDet/Chips.lean`
/// importing every generated chip file present on disk and the bridges built on them.  Chip files
/// are generated (`check/regen_all.sh`), not committed, so the root never names one.
pub fn write_project_files(out_dir: &Path) -> io::Result<()> {
    let basic = out_dir.join("ZirenDet").join("Basic.lean");
    if !basic.exists() {
        fs::create_dir_all(basic.parent().unwrap())?;
        fs::write(
            &basic,
            r#"import ZirenDet.Lib

/-!
# Ziren determinism prelude

Generated once; the field `F`, the lifting lemmas and the `picus_det` tactic live in the
hand-maintained `ZirenDet/Lib.lean`.
-/
"#,
        )?;
    }
    let chips_dir = out_dir.join("ZirenDet").join("Chips");
    let mut chips: Vec<String> = Vec::new();
    if chips_dir.exists() {
        for entry in fs::read_dir(&chips_dir)? {
            let p = entry?.path();
            if p.extension().and_then(|e| e.to_str()) == Some("lean") {
                if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                    chips.push(stem.to_string());
                }
            }
        }
    }
    chips.sort();
    let mut root = String::from("import ZirenDet.Basic\n");
    let mut all_chips = String::new();
    for c in &chips {
        all_chips.push_str(&format!("import ZirenDet.Chips.{c}\n"));
    }
    for m in [
        "Isa",
        "IsaVectors",
        "IsaDecode",
        "Gadgets",
        "Replay",
        "LeadingOne",
        "DivRem",
        "CanonicalWord",
        "FieldOp",
        "Pratt",
        "Primes",
        "Edwards",
        "Keccak",
        "OneHot",
        "GtBytes",
        "Septic",
        "GadgetProofs",
    ] {
        if out_dir.join("ZirenDet").join(format!("{m}.lean")).exists() {
            root.push_str(&format!("import ZirenDet.{m}\n"));
        }
    }
    let bridge_dir = out_dir.join("ZirenDet").join("Bridge");
    if bridge_dir.exists() {
        let mut bridges: Vec<String> = fs::read_dir(&bridge_dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("lean"))
            .filter_map(|p| p.file_stem().and_then(|s| s.to_str()).map(|s| s.to_string()))
            .collect();
        bridges.sort();
        for b in bridges {
            all_chips.push_str(&format!("import ZirenDet.Bridge.{b}\n"));
        }
    }
    fs::write(out_dir.join("ZirenDet.lean"), root)?;
    if !chips.is_empty() {
        fs::write(out_dir.join("ZirenDet").join("Chips.lean"), all_chips)?;
    }
    Ok(())
}

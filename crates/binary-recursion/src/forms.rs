//! whir-gc experiment: the linear forms of its columns a table reads.
//!
//! Each constraint and bus field of a table, evaluated symbolically, is
//! normalised to a sum of products of linear "atoms" times one linear form,
//! terms with the same atoms merged: `bit * (x + x')` summed over a word
//! becomes `bit * W` for one form `W`.  The atoms and the forms left are
//! every linear form of the columns the table reads; an independent subset
//! of them, sparsest first, spans them all, so every constraint and bus field
//! is a polynomial in those forms (and the other trace's columns).
//!
//! An opening may then send one value per form, and hand the AIR columns a
//! right inverse of the forms makes of the values.  A trace whose forms are
//! not fewer than the columns it reads keeps sending its columns.

use std::collections::{BTreeMap, HashMap};

use p3_air::symbolic::{AirLayout, BaseEntry, BaseLeaf, SymbolicExpr, SymbolicExpression};
use p3_air::{BaseAir, LinearForms};
use p3_binary_field::TowerLevel;
use p3_bus::{BusActivation, BusSymbolicBuilder};
use p3_field::{Field, PrimeCharacteristicRing};

use crate::machine::TapeAir;
use crate::tape::F;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
enum Col {
    Main(usize),
    Prep(usize),
}

fn f(x: u128) -> F {
    F::from_repr(x)
}

/// An affine form: column coefficients and a constant, as representations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Aff {
    lin: BTreeMap<Col, u128>,
    c: u128,
}

impl Aff {
    fn constant(c: F) -> Self {
        Self { lin: BTreeMap::new(), c: c.to_repr() }
    }

    fn add(&mut self, other: &Self, s: F) {
        for (&col, &v) in &other.lin {
            let entry = self.lin.entry(col).or_insert(0);
            *entry = (f(*entry) + s * f(v)).to_repr();
            if *entry == 0 {
                self.lin.remove(&col);
            }
        }
        self.c = (f(self.c) + s * f(other.c)).to_repr();
    }

    fn scaled(&self, s: F) -> Self {
        let mut out = Self::default();
        out.add(self, s);
        out
    }
}

/// A sum of products of atoms, each times an affine form.
type Rep = BTreeMap<Vec<usize>, Aff>;

#[derive(Default)]
struct Walk {
    atoms: HashMap<(Vec<(Col, u128)>, u128), usize>,
    externals: HashMap<String, usize>,
    forms: Vec<BTreeMap<Col, u128>>,
    next: usize,
    memo: HashMap<usize, Rep>,
}

impl Walk {
    fn atom(&mut self, a: &Aff) -> usize {
        let (_, &first) = a.lin.iter().next().expect("an atom reads a column");
        let n = a.scaled(f(first).inverse());
        let key = (n.lin.iter().map(|(&c, &v)| (c, v)).collect::<Vec<_>>(), n.c);
        if let Some(&id) = self.atoms.get(&key) {
            return id;
        }
        let id = self.next;
        self.next += 1;
        self.atoms.insert(key, id);
        self.forms.push(a.lin.clone());
        id
    }

    fn external(&mut self, name: String) -> Rep {
        let next = self.next;
        let id = *self.externals.entry(name).or_insert(next);
        if id == next {
            self.next += 1;
        }
        Rep::from([(vec![id], Aff::constant(F::ONE))])
    }

    fn merge(into: &mut Rep, from: &Rep, s: F) {
        for (m, a) in from {
            let entry = into.entry(m.clone()).or_default();
            entry.add(a, s);
            if entry.lin.is_empty() && entry.c == 0 {
                into.remove(m);
            }
        }
    }

    fn as_constant(r: &Rep) -> Option<F> {
        match r.len() {
            0 => Some(F::ZERO),
            1 => {
                let (m, a) = r.iter().next().expect("one term");
                (m.is_empty() && a.lin.is_empty()).then(|| f(a.c))
            }
            _ => None,
        }
    }

    fn rep(&mut self, e: &SymbolicExpression<F>) -> Rep {
        let key = e as *const _ as usize;
        if let Some(r) = self.memo.get(&key) {
            return r.clone();
        }
        let r = match e {
            SymbolicExpr::Leaf(BaseLeaf::Variable(v)) => {
                let col = match v.entry {
                    BaseEntry::Main { offset: 0 } => Some(Col::Main(v.index)),
                    BaseEntry::Preprocessed { offset: 0 } => Some(Col::Prep(v.index)),
                    _ => None,
                };
                match col {
                    Some(col) => {
                        let mut a = Aff::default();
                        a.lin.insert(col, 1);
                        Rep::from([(Vec::new(), a)])
                    }
                    None => self.external(format!("{:?}/{}", v.entry, v.index)),
                }
            }
            SymbolicExpr::Leaf(BaseLeaf::Constant(c)) => {
                if *c == F::ZERO {
                    Rep::new()
                } else {
                    Rep::from([(Vec::new(), Aff::constant(*c))])
                }
            }
            SymbolicExpr::Leaf(other) => self.external(format!("{other:?}")),
            SymbolicExpr::Add { x, y, .. } => {
                let mut r = self.rep(x);
                let ry = self.rep(y);
                Self::merge(&mut r, &ry, F::ONE);
                r
            }
            SymbolicExpr::Sub { x, y, .. } => {
                let mut r = self.rep(x);
                let ry = self.rep(y);
                Self::merge(&mut r, &ry, F::NEG_ONE);
                r
            }
            SymbolicExpr::Neg { x, .. } => {
                let mut r = Rep::new();
                let rx = self.rep(x);
                Self::merge(&mut r, &rx, F::NEG_ONE);
                r
            }
            SymbolicExpr::Mul { x, y, .. } => {
                let rx = self.rep(x);
                let ry = self.rep(y);
                let mut r = Rep::new();
                if let Some(c) = Self::as_constant(&rx) {
                    Self::merge(&mut r, &ry, c);
                } else if let Some(c) = Self::as_constant(&ry) {
                    Self::merge(&mut r, &rx, c);
                } else {
                    for (ma, la) in &rx {
                        for (mb, lb) in &ry {
                            let mut m: Vec<usize> = ma.iter().chain(mb).copied().collect();
                            let rest = if la.lin.is_empty() {
                                lb.scaled(f(la.c))
                            } else if lb.lin.is_empty() {
                                la.scaled(f(lb.c))
                            } else {
                                // The thinner form becomes an atom, the wider stays linear.
                                let (atom, rest) =
                                    if la.lin.len() <= lb.lin.len() { (la, lb) } else { (lb, la) };
                                m.push(self.atom(atom));
                                rest.clone()
                            };
                            m.sort_unstable();
                            Self::merge(&mut r, &Rep::from([(m, rest)]), F::ONE);
                        }
                    }
                }
                r
            }
        };
        self.memo.insert(key, r.clone());
        r
    }

    fn root(&mut self, e: &SymbolicExpression<F>) {
        let r = self.rep(e);
        for a in r.values() {
            if !a.lin.is_empty() {
                self.forms.push(a.lin.clone());
            }
        }
    }
}

/// Every linear form of its columns the table reads, main and preprocessed apart.
fn read_forms(air: &TapeAir) -> (Vec<Vec<(usize, F)>>, Vec<Vec<(usize, F)>>) {
    let builder = BusSymbolicBuilder::<F, F>::from_air(air, AirLayout::from_air::<F>(air));
    let mut walk = Walk::default();
    // Memoised by address: every expression must outlive the walk.
    let constraints = builder.base_constraints();
    for c in &constraints {
        walk.root(c);
    }
    for interaction in builder.interactions() {
        for field in &interaction.fields {
            walk.root(field);
        }
        match &interaction.activation {
            BusActivation::Boolean(e) => walk.root(e),
            other => panic!("an activation the forms do not cover: {other:?}"),
        }
    }
    let split = |main: bool| -> Vec<Vec<(usize, F)>> {
        let mut seen = std::collections::HashSet::new();
        walk.forms
            .iter()
            .map(|form| {
                form.iter()
                    .filter_map(|(&col, &v)| match (col, main) {
                        (Col::Main(i), true) | (Col::Prep(i), false) => Some((i, f(v))),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            })
            .filter(|form| !form.is_empty() && seen.insert(form.iter().map(|&(i, v)| (i, v.to_repr())).collect::<Vec<_>>()))
            .collect()
    };
    (split(true), split(false))
}

/// An independent subset of `forms`, sparsest first, and a right inverse of it.
fn basis_and_inverse(forms: &[Vec<(usize, F)>], width: usize) -> LinearForms {
    let mut order: Vec<usize> = (0..forms.len()).collect();
    order.sort_by_key(|&i| forms[i].len());
    // Rows kept reduced: (row over the columns, its combination of the chosen forms).
    let mut rows: Vec<(Vec<F>, Vec<F>)> = Vec::new();
    let mut pivots: Vec<usize> = Vec::new();
    let mut chosen: Vec<usize> = Vec::new();
    for &i in &order {
        let mut v = vec![F::ZERO; width];
        for &(c, x) in &forms[i] {
            v[c] += x;
        }
        let mut t = vec![F::ZERO; chosen.len() + 1];
        t[chosen.len()] = F::ONE;
        for ((row, comb), &p) in rows.iter().zip(&pivots) {
            let x = v[p];
            if x != F::ZERO {
                for (vi, ri) in v.iter_mut().zip(row) {
                    *vi -= x * *ri;
                }
                for (ti, ci) in t.iter_mut().zip(comb) {
                    *ti -= x * *ci;
                }
            }
        }
        let Some(p) = v.iter().position(|x| *x != F::ZERO) else { continue };
        let s = v[p].inverse();
        let row: Vec<F> = v.iter().map(|x| *x * s).collect();
        let comb: Vec<F> = t.iter().map(|x| *x * s).collect();
        // Earlier rows reduced against the new pivot, so each pivot column is a unit.
        for ((other, other_comb), _) in rows.iter_mut().zip(&pivots) {
            let x = other[p];
            if x != F::ZERO {
                for (oi, ri) in other.iter_mut().zip(&row) {
                    *oi -= x * *ri;
                }
                other_comb.resize(comb.len(), F::ZERO);
                for (oi, ci) in other_comb.iter_mut().zip(&comb) {
                    *oi -= x * *ci;
                }
            }
        }
        for (_, other_comb) in rows.iter_mut() {
            other_comb.resize(comb.len(), F::ZERO);
        }
        rows.push((row, comb));
        pivots.push(p);
        chosen.push(i);
    }
    // Column p_k takes sum_j comb_k[j] * form_j; every other column is zero.
    let mut inverse = vec![Vec::new(); width];
    for ((_, comb), &p) in rows.iter().zip(&pivots) {
        inverse[p] = comb
            .iter()
            .enumerate()
            .filter(|(_, x)| **x != F::ZERO)
            .map(|(j, x)| (j, x.to_repr()))
            .collect();
    }
    let selected: Vec<Vec<(usize, u128)>> = chosen
        .iter()
        .map(|&i| forms[i].iter().map(|&(c, x)| (c, x.to_repr())).collect())
        .collect();
    // The inverse is a right inverse: form j of the column it makes of form k is [j == k].
    for (j, form) in selected.iter().enumerate() {
        let mut value = vec![F::ZERO; selected.len()];
        for &(c, x) in form {
            for &(k, y) in &inverse[c] {
                value[k] += f(x) * f(y);
            }
        }
        for (k, v) in value.into_iter().enumerate() {
            assert_eq!(v, if j == k { F::ONE } else { F::ZERO }, "the forms' inverse");
        }
    }
    LinearForms { forms: selected, inverse }
}

/// Values a trace's opening carries with forms: one per form, then the column
/// rounds and the fold.
#[must_use]
pub fn wire_len(forms: usize, width: usize) -> usize {
    forms + 2 * width.next_power_of_two().trailing_zeros() as usize + 1
}

/// The table's main and preprocessed forms, each when fewer than the columns read.
///
/// `varying` names the preprocessed columns that differ between rows: the
/// others are known, and a form reading only them is too.
#[must_use]
pub fn table_forms(air: &TapeAir) -> (Option<LinearForms>, Option<LinearForms>) {
    // Derived once per table: the preprocessed columns are read off the dense trace.
    static CACHE: std::sync::LazyLock<
        std::sync::Mutex<HashMap<(usize, String), (Option<LinearForms>, Option<LinearForms>)>>,
    > = std::sync::LazyLock::new(Default::default);
    let key = (air as *const TapeAir as usize, air.name().to_string());
    if let Some(cached) = CACHE.lock().expect("the forms cache").get(&key) {
        return cached.clone();
    }
    let derived = derive_table_forms(air);
    CACHE.lock().expect("the forms cache").insert(key, derived.clone());
    derived
}

fn derive_table_forms(air: &TapeAir) -> (Option<LinearForms>, Option<LinearForms>) {
    let (main, prep) = read_forms(air);
    let main_width = BaseAir::<F>::width(air);
    let prep_width = BaseAir::<F>::preprocessed_width(air);
    let worth = |forms: &[Vec<(usize, F)>], width: usize, varies: &dyn Fn(usize) -> bool| {
        let lf = basis_and_inverse(forms, width);
        let mut read: Vec<bool> = vec![false; width];
        for form in &lf.forms {
            for &(c, _) in form {
                read[c] = true;
            }
        }
        let columns = (0..width).filter(|&c| read[c] && varies(c)).count();
        let unknown = lf.forms.iter().filter(|form| form.iter().any(|&(c, _)| varies(c))).count();
        (wire_len(unknown, width) < columns).then_some(lf)
    };
    let main_forms = (main_width > 0).then(|| worth(&main, main_width, &|_| true)).flatten();
    let prep_forms = (prep_width > 0)
        .then(|| {
            let trace = BaseAir::<F>::preprocessed_trace(air).expect("a preprocessed trace");
            let rows = trace.values.len() / trace.width;
            let varies: Vec<bool> = (0..trace.width)
                .map(|c| (1..rows).any(|r| trace.values[r * trace.width + c] != trace.values[c]))
                .collect();
            worth(&prep, prep_width, &|c| varies[c]).map(|lf| over_fixed_trace(lf, &trace.values, trace.width))
        })
        .flatten();
    (main_forms, prep_forms)
}

/// Each column of a fixed trace over a GF(2) basis of its columns and the all-ones
/// column: the chosen original columns, and per column the set of chosen columns (bit
/// `width` for the ones column) that sum to it over every row.
fn column_relations(values: &[F], width: usize) -> (Vec<usize>, Vec<Vec<u64>>) {
    let rows = values.len() / width;
    let words = rows.div_ceil(64);
    let combo_words = (width + 1).div_ceil(64);
    let column = |c: usize| -> Vec<u64> {
        let mut bits = vec![0u64; words];
        for r in 0..rows {
            let v = values[r * width + c];
            assert!(v == F::ZERO || v == F::ONE, "a preprocessed cell is a bit");
            if v == F::ONE {
                bits[r / 64] |= 1 << (r % 64);
            }
        }
        bits
    };
    let mut ones = vec![u64::MAX; words];
    if rows % 64 != 0 {
        ones[words - 1] = (1u64 << (rows % 64)) - 1;
    }
    let mut basis: Vec<(usize, Vec<u64>, Vec<u64>)> = Vec::new();
    let mut chosen = Vec::new();
    let mut expressed = vec![Vec::new(); width];
    for c in std::iter::once(width).chain(0..width) {
        let mut v = if c == width { ones.clone() } else { column(c) };
        let mut combo = vec![0u64; combo_words];
        combo[c / 64] |= 1 << (c % 64);
        for (pivot, bvec, bcombo) in &basis {
            if bvec.len() == v.len() && v[pivot / 64] >> (pivot % 64) & 1 == 1 {
                for (x, y) in v.iter_mut().zip(bvec) {
                    *x ^= y;
                }
                for (x, y) in combo.iter_mut().zip(bcombo) {
                    *x ^= y;
                }
            }
        }
        match v.iter().position(|&w| w != 0) {
            Some(word) => {
                let pivot = word * 64 + v[word].trailing_zeros() as usize;
                basis.push((pivot, v, combo));
                if c < width {
                    chosen.push(c);
                    let mut own = vec![0u64; combo_words];
                    own[c / 64] |= 1 << (c % 64);
                    expressed[c] = own;
                }
            }
            None => {
                if c < width {
                    let mut rest = combo;
                    rest[c / 64] &= !(1 << (c % 64));
                    expressed[c] = rest;
                }
            }
        }
    }
    (chosen, expressed)
}

/// Keep only the forms independent over the fixed trace, and rebuild the rest.
///
/// A form of fixed columns is, over every row, a fixed combination of a column basis
/// and the all-ones column, so its value at any point is that combination of the basis
/// values and a constant.  A form dependent on the kept ones is therefore an affine
/// function of their values, and the right inverse becomes affine: the verifier reads
/// the kept forms only.
fn over_fixed_trace(lf: LinearForms, values: &[F], width: usize) -> LinearForms {
    let (chosen, expressed) = column_relations(values, width);
    let index: HashMap<usize, usize> = chosen.iter().enumerate().map(|(i, &c)| (c, i)).collect();
    // Each form over the basis, and its constant part.
    let rows: Vec<(Vec<F>, F)> = lf
        .forms
        .iter()
        .map(|form| {
            let mut row = vec![F::ZERO; chosen.len()];
            let mut constant = F::ZERO;
            for &(c, x) in form {
                let x = f(x);
                for o in 0..=width {
                    if expressed[c][o / 64] >> (o % 64) & 1 == 1 {
                        if o == width {
                            constant += x;
                        } else {
                            row[index[&o]] += x;
                        }
                    }
                }
            }
            (row, constant)
        })
        .collect();
    // Independent forms in order; each dependent form as a combination of them.
    let mut kept: Vec<usize> = Vec::new();
    let mut reduced: Vec<(usize, Vec<F>, Vec<F>)> = Vec::new();
    let mut combination: Vec<Option<Vec<F>>> = vec![None; rows.len()];
    for (j, (row, _)) in rows.iter().enumerate() {
        let mut a = row.clone();
        let mut acc = vec![F::ZERO; kept.len()];
        for (pivot, brow, bcomb) in &reduced {
            let x = a[*pivot];
            if x != F::ZERO {
                for (ai, bi) in a.iter_mut().zip(brow) {
                    *ai -= x * *bi;
                }
                for (ci, bi) in acc.iter_mut().zip(bcomb) {
                    *ci += x * *bi;
                }
            }
        }
        match a.iter().position(|x| *x != F::ZERO) {
            None => combination[j] = Some(acc),
            Some(pivot) => {
                let k = kept.len();
                kept.push(j);
                let s = a[pivot].inverse();
                let brow: Vec<F> = a.iter().map(|x| *x * s).collect();
                let mut bcomb: Vec<F> = acc.iter().map(|x| -*x * s).collect();
                bcomb.resize(k + 1, F::ZERO);
                bcomb[k] = s;
                for (_, _, other) in reduced.iter_mut() {
                    other.resize(k + 1, F::ZERO);
                }
                reduced.push((pivot, brow, bcomb));
            }
        }
    }
    let position: HashMap<usize, usize> = kept.iter().enumerate().map(|(i, &j)| (j, i)).collect();
    // Every form as an affine function of the kept forms: coefficients and a constant.
    let affine: Vec<(Vec<F>, F)> = (0..rows.len())
        .map(|j| match position.get(&j) {
            Some(&k) => {
                let mut coefficients = vec![F::ZERO; kept.len()];
                coefficients[k] = F::ONE;
                (coefficients, F::ZERO)
            }
            None => {
                let mut coefficients = combination[j].clone().expect("a dependent form");
                coefficients.resize(kept.len(), F::ZERO);
                let constant = rows[j].1
                    - coefficients.iter().zip(&kept).map(|(t, &s)| *t * rows[s].1).sum::<F>();
                (coefficients, constant)
            }
        })
        .collect();
    let inverse: Vec<Vec<(usize, u128)>> = lf
        .inverse
        .iter()
        .map(|column| {
            let mut coefficients = vec![F::ZERO; kept.len()];
            let mut constant = F::ZERO;
            for &(j, r) in column {
                let r = f(r);
                for (c, t) in coefficients.iter_mut().zip(&affine[j].0) {
                    *c += r * *t;
                }
                constant += r * affine[j].1;
            }
            let mut out: Vec<(usize, u128)> = coefficients
                .iter()
                .enumerate()
                .filter(|(_, x)| **x != F::ZERO)
                .map(|(k, x)| (k, x.to_repr()))
                .collect();
            if constant != F::ZERO {
                out.push((usize::MAX, constant.to_repr()));
            }
            out
        })
        .collect();
    // The kept forms, rebuilt through the inverse, must give back every form's value at
    // the fixed trace's rows (checked on a few rows).
    let forms: Vec<Vec<(usize, u128)>> = kept.iter().map(|&j| lf.forms[j].clone()).collect();
    let rows_count = values.len() / width;
    for r in (0..rows_count).step_by((rows_count / 7).max(1)).take(8) {
        let row = &values[r * width..(r + 1) * width];
        let kept_values: Vec<F> = forms
            .iter()
            .map(|form| form.iter().map(|&(c, x)| f(x) * row[c]).sum())
            .collect();
        let rebuilt: Vec<F> = inverse
            .iter()
            .map(|column| {
                column
                    .iter()
                    .map(|&(k, x)| f(x) * if k == usize::MAX { F::ONE } else { kept_values[k] })
                    .sum()
            })
            .collect();
        for form in &lf.forms {
            let at = |cols: &[F]| -> F { form.iter().map(|&(c, x)| f(x) * cols[c]).sum() };
            assert_eq!(at(&rebuilt), at(row), "the affine inverse rebuilds every form");
        }
    }
    LinearForms { forms, inverse }
}

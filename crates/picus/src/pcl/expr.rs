use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, OnceLock, RwLock,
    },
    u64,
};

/// Mapping from column ids to variable names. This mapping should be derived in the `PicusInfo` struct
static PICUS_NAMES_GLOBAL: OnceLock<RwLock<HashMap<usize, String>>> = OnceLock::new();

/// Maintains col indices for fresh variables during the course of extraction
static FRESH_VAR_CTR: OnceLock<AtomicUsize> = OnceLock::new();
pub fn set_picus_names(map: HashMap<usize, String>) {
    let _ = PICUS_NAMES_GLOBAL.set(RwLock::new(map));
}

// Get or initialize the fresh var counter
fn ctr() -> &'static AtomicUsize {
    FRESH_VAR_CTR.get_or_init(|| AtomicUsize::new(0))
}

// set the fresh counter val to something
pub fn initialize_fresh_var_ctr(val: usize) {
    let _ = FRESH_VAR_CTR.set(AtomicUsize::new(val));
}

// update the counter
pub fn fresh_picus_var() -> PicusExpr {
    let cur_var = ctr().load(Ordering::Relaxed);
    ctr().store(cur_var + 1, Ordering::Relaxed);
    PicusExpr::Var(PicusVar::new(cur_var))
}

use p3_field::{FieldAlgebra, PrimeField32};

/// Global, thread-safe holder for the PCL prime field modulus.
///
/// This is initialized exactly once via [`set_field_modulus`]. Arithmetic
/// that combines only constants will be reduced modulo this value when set.
static FIELD_MODULUS: OnceLock<Arc<u64>> = OnceLock::new();
pub type Felt = p3_koala_bear::KoalaBear;

/// Sets the field modulus for PCL
pub fn set_field_modulus(p: u64) -> Result<(), u64> {
    // set only once; returns Err(p) if already set
    FIELD_MODULUS.set(Arc::new(p)).map_err(|arc| Arc::try_unwrap(arc).unwrap_or_else(|a| *a))
}

/// Get PCL field modulus
pub fn current_modulus() -> Option<u64> {
    FIELD_MODULUS.get().map(|a| **a)
}

/// Given an integer reduce it into the field
pub fn reduce_mod(c: i64) -> u64 {
    if let Some(p) = current_modulus() {
        (c % (p as i64)) as u64
    } else {
        c as u64
    }
}

/// Arithmetic expressions over the Picus constraint language (PCL).
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum PicusExpr {
    /// Constant field element. We use a `u64` to be safe because the prime is 31 bits and we don't want to deal with
    /// underflows or overflows
    Const(u64),
    /// Variable identified by `(name, index, tag)`, printed as `name_index_tag`. NOTE: Tag might
    /// be droppable
    Var(PicusVar),
    /// Add.
    Add(Box<PicusExpr>, Box<PicusExpr>),
    /// Sub.
    Sub(Box<PicusExpr>, Box<PicusExpr>),
    /// Mul
    Mul(Box<PicusExpr>, Box<PicusExpr>),
    /// Div (probably can delete)
    Div(Box<PicusExpr>, Box<PicusExpr>),
    /// Unary negation.
    Neg(Box<PicusExpr>),
    /// Exponentiation
    Pow(u64, Box<PicusExpr>),
}

impl Default for PicusExpr {
    fn default() -> Self {
        PicusExpr::Const(0)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct PicusVar {
    pub id: usize,
}

impl PicusVar {
    pub fn new(id: usize) -> Self {
        PicusVar { id }
    }
}

impl Display for PicusVar {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(lock) = PICUS_NAMES_GLOBAL.get() {
            if let Some(name) = lock.read().unwrap().get(&self.id) {
                return f.write_str(name);
            }
        }
        write!(f, "v{}", self.id)
    }
}

impl From<PicusVar> for PicusExpr {
    fn from(value: PicusVar) -> Self {
        PicusExpr::Var(value.clone())
    }
}

impl From<Felt> for PicusExpr {
    fn from(value: Felt) -> Self {
        PicusExpr::Const(value.as_canonical_u32().into())
    }
}

impl Add<Felt> for PicusVar {
    type Output = PicusExpr;

    fn add(self, rhs: Felt) -> Self::Output {
        PrimeField32::as_canonical_u32(&rhs).into()
    }
}

impl Add<PicusVar> for PicusVar {
    type Output = PicusExpr;

    fn add(self, rhs: PicusVar) -> Self::Output {
        PicusExpr::Add(Box::new(self.into()), Box::new(rhs.into()))
    }
}

impl Add<PicusExpr> for PicusVar {
    type Output = PicusExpr;

    fn add(self, rhs: PicusExpr) -> Self::Output {
        let left_expr: PicusExpr = self.into();
        left_expr + rhs
    }
}

impl Sub<Felt> for PicusVar {
    type Output = PicusExpr;

    fn sub(self, rhs: Felt) -> Self::Output {
        let self_expr: PicusExpr = self.into();
        self_expr - rhs
    }
}

impl Sub<PicusVar> for PicusVar {
    type Output = PicusExpr;

    fn sub(self, rhs: PicusVar) -> Self::Output {
        let self_expr: PicusExpr = self.into();
        let rhs_expr: PicusExpr = rhs.into();
        self_expr - rhs_expr
    }
}

impl Sub<PicusExpr> for PicusVar {
    type Output = PicusExpr;

    fn sub(self, rhs: PicusExpr) -> Self::Output {
        let self_expr: PicusExpr = self.into();
        self_expr - rhs
    }
}

impl Mul<PicusVar> for PicusVar {
    type Output = PicusExpr;

    fn mul(self, rhs: PicusVar) -> Self::Output {
        let self_expr: PicusExpr = self.into();
        let rhs_expr: PicusExpr = rhs.into();
        self_expr * rhs_expr
    }
}

impl Mul<Felt> for PicusVar {
    type Output = PicusExpr;

    fn mul(self, rhs: Felt) -> Self::Output {
        let self_expr: PicusExpr = self.into();
        self_expr * rhs
    }
}

impl Mul<PicusExpr> for PicusVar {
    type Output = PicusExpr;

    fn mul(self, rhs: PicusExpr) -> Self::Output {
        let self_expr: PicusExpr = self.into();
        self_expr * rhs
    }
}

impl Sum for PicusExpr {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut output: PicusExpr = 0.into();
        for item in iter {
            output = output + item;
        }
        output
    }
}

impl Product for PicusExpr {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut output: PicusExpr = 1.into();
        for item in iter {
            output = output * item;
        }
        output
    }
}

impl PicusExpr {
    /// Approximate tree size (number of nodes).
    ///
    /// Useful as a heuristic for introducing temporary variables (e.g., to keep
    /// expressions small for solvers). `Pow` is counted as 1 by design.
    #[must_use]
    pub fn size(&self) -> usize {
        match self {
            Self::Const(_) | Self::Var(_) | Self::Pow(_, _) => 1,
            Self::Add(a, b) | Self::Sub(a, b) | Self::Mul(a, b) | Self::Div(a, b) => {
                1 + a.size() + b.size()
            }
            Self::Neg(a) => 1 + a.size(),
        }
    }
    /// Helper to construct a `Var` with a column index.
    pub fn var(idx: usize) -> Self {
        PicusExpr::Var(PicusVar { id: idx })
    }
    #[must_use]
    /// Convenience for exponentiating by a non-negative `u32` power.
    pub fn pow(self, k: u32) -> Self {
        PicusExpr::Pow(k.into(), Box::new(self))
    }
    /// Returns `true` iff this is exactly the constant zero.
    #[inline]
    #[must_use]
    pub fn is_const_zero(&self) -> bool {
        matches!(self, PicusExpr::Const(c) if *c == 0)
    }
}

macro_rules! impl_from_ints {
    ($($t:ty),* $(,)?) => {$(
        impl From<$t> for PicusExpr {
            fn from(v: $t) -> Self {
                PicusExpr::Const(v as u64)
            }
        }
    )*}
}

impl_from_ints!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);

/// Pointwise addition with light constant folding.
///
/// - If both sides are constant, the sum is reduced modulo the current field (if set).
/// - Adding zero returns the other side.
/// - Otherwise, constructs `Add(lhs, rhs)`.
impl Add<PicusExpr> for PicusExpr {
    type Output = PicusExpr;
    fn add(self, rhs: PicusExpr) -> Self::Output {
        let lhs = self.clone();
        match (lhs.clone(), rhs.clone()) {
            (PicusExpr::Const(c_1), PicusExpr::Const(c_2)) => {
                (reduce_mod((c_1 + c_2) as i64)).into()
            }
            (PicusExpr::Const(c), _) => {
                if c == 0 {
                    rhs
                } else {
                    PicusExpr::Add(Box::new(lhs), Box::new(rhs))
                }
            }
            (_, PicusExpr::Const(c)) => {
                if c == 0 {
                    lhs
                } else {
                    PicusExpr::Add(Box::new(lhs), Box::new(rhs))
                }
            }
            _ => PicusExpr::Add(Box::new(lhs), Box::new(rhs)),
        }
    }
}

impl Add<Felt> for PicusExpr {
    type Output = PicusExpr;

    fn add(self, rhs: Felt) -> Self::Output {
        let rhs_expr: Self = rhs.into();
        self + rhs_expr
    }
}

impl Add<PicusVar> for PicusExpr {
    type Output = PicusExpr;

    fn add(self, rhs: PicusVar) -> Self::Output {
        let rhs_expr: Self = rhs.into();
        self + rhs_expr
    }
}

impl AddAssign<PicusExpr> for PicusExpr {
    fn add_assign(&mut self, rhs: PicusExpr) {
        *self = self.clone() + rhs;
    }
}

/// Pointwise subtraction with light constant folding.
///
/// - If both sides are constant, the difference is reduced modulo the current field (if set).
/// - Subtracting zero returns the left-hand side.
/// - Otherwise, constructs `Sub(lhs, rhs)`.
impl Sub<PicusExpr> for PicusExpr {
    type Output = PicusExpr;
    fn sub(self, rhs: PicusExpr) -> Self::Output {
        let lhs = self.clone();
        match (lhs.clone(), rhs.clone()) {
            (PicusExpr::Const(c_1), PicusExpr::Const(c_2)) => {
                reduce_mod((c_1 as i64) - (c_2 as i64)).into()
            }
            (_, PicusExpr::Const(c)) => {
                if c == 0 {
                    lhs
                } else {
                    PicusExpr::Sub(Box::new(self), Box::new(rhs))
                }
            }
            _ => PicusExpr::Sub(Box::new(self), Box::new(rhs)),
        }
    }
}

impl Sub<Felt> for PicusExpr {
    type Output = PicusExpr;

    fn sub(self, rhs: Felt) -> Self::Output {
        let rhs_expr: Self = rhs.into();
        self - rhs_expr
    }
}

impl Sub<PicusVar> for PicusExpr {
    type Output = PicusExpr;

    fn sub(self, rhs: PicusVar) -> Self::Output {
        let rhs_expr: Self = rhs.into();
        self - rhs_expr
    }
}

impl SubAssign<PicusExpr> for PicusExpr {
    fn sub_assign(&mut self, rhs: PicusExpr) {
        *self = self.clone() - rhs;
    }
}

/// Unary negation with constant folding.
///
/// - If the input is a constant, returns the additive inverse reduced modulo the current field (if
///   set). Otherwise constructs `Neg`.
impl Neg for PicusExpr {
    type Output = PicusExpr;
    fn neg(self) -> Self::Output {
        let lhs = self.clone();
        match lhs.clone() {
            PicusExpr::Const(c) => reduce_mod((current_modulus().unwrap() - c) as i64).into(),
            _ => PicusExpr::Neg(Box::new(lhs)),
        }
    }
}

/// Pointwise multiplication with light constant folding and scalar routing.
///
/// - If either side is a constant, routes to the `(PicusExpr * Integer)` impl to share logic.
/// - Otherwise constructs `Mul(lhs, rhs)`.
impl Mul<PicusExpr> for PicusExpr {
    type Output = PicusExpr;
    fn mul(self, rhs: PicusExpr) -> Self::Output {
        let lhs = self.clone();
        match (lhs.clone(), rhs.clone()) {
            (PicusExpr::Const(c), _) => rhs * c,
            (_, PicusExpr::Const(c)) => lhs * c,
            _ => PicusExpr::Mul(Box::new(lhs), Box::new(rhs)),
        }
    }
}

impl Mul<Felt> for PicusExpr {
    type Output = PicusExpr;

    fn mul(self, rhs: Felt) -> Self::Output {
        let rhs_expr: PicusExpr = rhs.into();
        self * rhs_expr
    }
}

impl Mul<PicusVar> for PicusExpr {
    type Output = PicusExpr;

    fn mul(self, rhs: PicusVar) -> Self::Output {
        let rhs_expr: PicusExpr = rhs.into();
        self * rhs_expr
    }
}

impl MulAssign<PicusExpr> for PicusExpr {
    fn mul_assign(&mut self, rhs: PicusExpr) {
        *self = self.clone() * rhs;
    }
}

/// Scalar multiplication with constant folding.
///
/// - Multiplying by `0` yields `0`.
/// - Multiplying by `1` yields the original expression.
/// - If the left is also a constant, multiply and reduce modulo the current field (if set).
/// - Otherwise constructs `Mul(lhs, Const(rhs))`.
impl Mul<u64> for PicusExpr {
    type Output = PicusExpr;
    fn mul(self, rhs: u64) -> Self::Output {
        if rhs == 0 {
            return PicusExpr::Const(0);
        }
        if rhs == 1 {
            return self.clone();
        }
        let lhs = self.clone();
        match lhs {
            PicusExpr::Const(c_1) => reduce_mod((c_1 * rhs) as i64).into(),
            _ => PicusExpr::Mul(Box::new(lhs), Box::new(rhs.into())),
        }
    }
}

impl FieldAlgebra for PicusExpr {
    type F = Felt;

    const ZERO: Self = PicusExpr::Const(0);

    const ONE: Self = PicusExpr::Const(1);

    const TWO: Self = PicusExpr::Const(2);

    const NEG_ONE: Self = PicusExpr::Const(u64::MAX);

    fn from_f(f: Self::F) -> Self {
        f.into()
    }

    fn from_bool(b: bool) -> Self {
        if b {
            PicusExpr::Const(1)
        } else {
            PicusExpr::Const(0)
        }
    }

    fn from_canonical_u8(n: u8) -> Self {
        n.into()
    }

    fn from_canonical_u16(n: u16) -> Self {
        n.into()
    }

    fn from_canonical_u32(n: u32) -> Self {
        n.into()
    }

    fn from_canonical_u64(n: u64) -> Self {
        n.into()
    }

    fn from_canonical_usize(n: usize) -> Self {
        n.into()
    }

    fn from_wrapped_u32(n: u32) -> Self {
        n.into()
    }

    fn from_wrapped_u64(n: u64) -> Self {
        n.into()
    }
}

/// Boolean/relational constraints over `PicusExpr`.
#[derive(Debug, Clone)]
pub enum PicusConstraint {
    /// x < y
    Lt(Box<PicusExpr>, Box<PicusExpr>),
    /// x <= y
    Leq(Box<PicusExpr>, Box<PicusExpr>),
    /// x > y
    Gt(Box<PicusExpr>, Box<PicusExpr>),
    /// x >= y
    Geq(Box<PicusExpr>, Box<PicusExpr>),
    /// p => q
    Implies(Box<PicusConstraint>, Box<PicusConstraint>),
    /// -p
    Not(Box<PicusConstraint>),
    /// p <=> q
    Iff(Box<PicusConstraint>, Box<PicusConstraint>),
    /// p && q
    And(Box<PicusConstraint>, Box<PicusConstraint>),
    /// p || q
    Or(Box<PicusConstraint>, Box<PicusConstraint>),
    /// Canonical equality-to-zero form: `Eq(e)` represents `e = 0`.
    Eq(Box<PicusExpr>),
}

impl PicusConstraint {
    /// Build an equality constraint `left = right` by moving to zero:
    /// returns `Eq(left - right)`.
    #[must_use]
    pub fn new_equality(left: PicusExpr, right: PicusExpr) -> PicusConstraint {
        PicusConstraint::Eq(Box::new(left - right))
    }

    /// Build a comparison constraint `left < right`
    #[must_use]
    pub fn new_lt(left: PicusExpr, right: PicusExpr) -> PicusConstraint {
        PicusConstraint::Lt(Box::new(left), Box::new(right))
    }

    /// Build a comparison constraint `left <= right`
    #[must_use]
    pub fn new_leq(left: PicusExpr, right: PicusExpr) -> PicusConstraint {
        PicusConstraint::Leq(Box::new(left), Box::new(right))
    }

    /// Build a comparison constraint `left > right`
    #[must_use]
    pub fn new_gt(left: PicusExpr, right: PicusExpr) -> PicusConstraint {
        PicusConstraint::Gt(Box::new(left), Box::new(right))
    }

    /// Build a comparison constraint `left >= right`
    #[must_use]
    pub fn new_geq(left: PicusExpr, right: PicusExpr) -> PicusConstraint {
        PicusConstraint::Geq(Box::new(left), Box::new(right))
    }

    /// Assumes ``l`` and ``u`` fit into the prime
    /// Generates constraints l <= e <= u
    #[must_use]
    pub fn in_range(e: PicusExpr, l: usize, u: usize) -> Vec<PicusConstraint> {
        assert!(l < u);
        vec![PicusConstraint::new_geq(e.clone(), l.into()), PicusConstraint::new_leq(e, u.into())]
    }
}

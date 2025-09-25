use std::{
    collections::BTreeMap,
    fmt::{self, Display, Formatter},
    fs::File,
    io::{self, Write},
    path::Path,
};

use crate::pcl::{
    expr::{PicusConstraint, PicusExpr},
    partial_evaluate, PicusVar,
};

/// A call to another Picus module (by name).
///
/// Renders to the PCL s-expression:
///
/// ```text
/// (call [<outputs...>] <mod_name> [<inputs...>])
/// ```
///
/// where both `outputs` and `inputs` are printed using `Display` for `PicusExpr`,
/// enclosed in `[...]` and space-separated.
#[derive(Debug, Clone, Default)]
pub struct PicusCall {
    /// Callee module name. This will oftentimes be specialized (e.g., suffixed with constants)
    /// by the compiler to facilitate partial evaluation of the callee.
    pub mod_name: String,
    /// Expressions that *receive* the callee results at the call site.
    /// (Printed first in the call s-expression.)
    pub outputs: Vec<PicusExpr>,
    /// Expressions that are *passed* to the callee.
    /// (Printed last in the call s-expression.)
    pub inputs: Vec<PicusExpr>,
}

/// A single Picus module and its contents.
///
/// A module has a name, a list of input/output expressions (ports),
/// a set of constraints, optional postconditions, assumptions about
/// determinism, and a list of nested calls to other modules.
///
/// The textual form emitted by [`PicusModule::dump`] is a sequence
/// of PCL s-expressions wrapped between `(begin-module <name>)` and
/// `(end-module)`.
#[derive(Debug, Clone, Default)]
pub struct PicusModule {
    /// Module identifier used in `(begin-module <name>)`.
    pub name: String,
    /// Module inputs (printed as `(input <expr>)`).
    pub inputs: Vec<PicusExpr>,
    /// Module outputs (printed as `(output <expr>)`).
    pub outputs: Vec<PicusExpr>,
    /// Circuit constraints enforced within the module (printed as `(assert <constraint>)`).
    pub constraints: Vec<PicusConstraint>,
    /// Constraints to be treated as postconditions (printed as `(post-condition <constraint>)`).
    pub postconditions: Vec<PicusConstraint>,
    /// Expressions assumed to be deterministic (printed as `(assume-deterministic <expr>)`).
    pub assume_deterministic: Vec<PicusExpr>,
    /// Nested calls emitted inside the module body.
    pub calls: Vec<PicusCall>,
}

impl PicusModule {
    /// Construct an empty Picus module with the given `name`.
    #[must_use]
    pub fn new(name: String) -> Self {
        PicusModule {
            name,
            inputs: Vec::new(),
            outputs: Vec::new(),
            constraints: Vec::new(),
            postconditions: Vec::new(),
            assume_deterministic: Vec::new(),
            calls: Vec::new(),
        }
    }

    #[must_use]
    /// Construct a new Picus module by partially evaluating the module's constraints
    /// with the given values
    pub fn partial_eval(&self, env: &BTreeMap<PicusVar, u64>) -> Self {
        let mut name = self.name.clone();
        for (k, v) in env {
            name += &format!("{k}_{v}");
        }
        let constraints = partial_evaluate(&self.constraints, &env);
        let postconditions = partial_evaluate(&self.postconditions, &env);
        PicusModule {
            name,
            inputs: self.inputs.clone(),
            outputs: self.outputs.clone(),
            constraints,
            postconditions,
            assume_deterministic: self.assume_deterministic.clone(),
            calls: self.calls.clone(),
        }
    }
}

impl Display for PicusModule {
    /// Serialize this module into a sequence of PCL lines.
    ///
    /// Output shape:
    ///
    /// ```text
    /// (begin-module <name>)
    /// (input <expr>)*
    /// (output <expr>)*
    /// (assert <constraint>)*
    /// (post-condition <constraint>)*
    /// (assume-deterministic <expr>)*
    /// (call [<outs>] <mod> [<ins>])*
    /// (end-module)
    /// ```
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "(begin-module {})", self.name)?;

        for inp in &self.inputs {
            writeln!(f, "(input {inp})")?;
        }
        for out in &self.outputs {
            writeln!(f, "(output {out})")?;
        }
        for c in &self.constraints {
            writeln!(f, "(assert {c})")?;
        }
        for c in &self.postconditions {
            writeln!(f, "(post-condition {c})")?;
        }
        for e in &self.assume_deterministic {
            writeln!(f, "(assume-deterministic {e})")?;
        }
        for call in &self.calls {
            writeln!(f, "{call}")?;
        }

        write!(f, "(end-module)")
    }
}

/// Print a Picus arithmetic expression in PCL s-expression syntax.
///
/// Examples:
///
/// - `Const(5)`         → `5`
/// - `Var("x",1,0)`     → `x_1_0`
/// - `Add(a,b)`         → `(+ a b)`
/// - `Neg(e)`           → `(- e)`
/// - `Pow(2, e)`        → `(pow 2 e)`
impl Display for PicusExpr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use PicusExpr::{Add, Const, Div, Mul, Neg, Pow, Sub, Var};
        match self {
            Const(v) => write!(f, "{v}"),
            Var(id) => write!(f, "{id}"),
            Add(a, b) => write!(f, "(+ {a} {b})"),
            Sub(a, b) => write!(f, "(- {a} {b})"),
            Mul(a, b) => write!(f, "(* {a} {b})"),
            Div(a, b) => write!(f, "(/ {a} {b})"),
            Neg(a) => write!(f, "(- {a})"),
            Pow(c, e) => write!(f, "(pow {c} {e})"),
        }
    }
}

/// Print a Picus logical/relational constraint in PCL s-expression syntax.
///
/// Notes:
/// - Equalities are represented canonically as `(= <expr> 0)`, i.e., `Eq(e)` means `e = 0`.
/// - Composite forms (`=>`, `<=>`, `&&`, `||`, `!`) print recursively using `Display` on nested
///   constraints/expressions.
impl Display for PicusConstraint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use PicusConstraint::{And, Eq, Geq, Gt, Iff, Implies, Leq, Lt, Not, Or};
        match self {
            Lt(e1, e2) => write!(f, "(< {e1} {e2})"),
            Leq(e1, e2) => write!(f, "(<= {e1} {e2})"),
            Gt(e1, e2) => write!(f, "(> {e1} {e2})"),
            Geq(e1, e2) => write!(f, "(>= {e1} {e2})"),
            Eq(e) => write!(f, "(= {e} 0)"),
            Implies(c1, c2) => write!(f, "(=> {c1} {c2})"),
            Iff(c1, c2) => write!(f, "(<=> {c1} {c2})"),
            Not(c) => write!(f, "(! {c})"),
            And(c1, c2) => write!(f, "(&& {c1} {c2})"),
            Or(c1, c2) => write!(f, "(|| {c1} {c2})"),
        }
    }
}

/// Print a `(call ...)` s-expression for a [`PicusCall`].
///
/// Uses the `Display` implementation of `PicusExpr` for both output and input
/// vectors via [`write_expr_slice`].
impl Display for PicusCall {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("(call ")?;
        write_expr_slice(f, &self.outputs)?;
        write!(f, " {}", self.mod_name)?;
        f.write_str(" ")?;
        write_expr_slice(f, &self.inputs)?;
        f.write_str(")")
    }
}

/// Write a slice of expressions as a bracketed, space-separated list.
///
/// Example: `[e1 e2 e3]`.
///
/// This helper relies on `Display` for `PicusExpr`.
fn write_expr_slice(f: &mut Formatter<'_>, exprs: &[PicusExpr]) -> fmt::Result {
    f.write_str("[")?;
    for (i, e) in exprs.iter().enumerate() {
        if i > 0 {
            f.write_str(" ")?;
        }
        write!(f, "{e}")?;
    }
    f.write_str("]")
}

/// A complete Picus program: the prime field and an ordered set of modules.
///
/// The `modules` map is a `BTreeMap` so that serialization is deterministic
/// across runs (keys are emitted in sorted order).
#[derive(Debug, Clone, Default)]
pub struct PicusProgram {
    /// Prime modulus for the field in which all arithmetic takes place.
    /// It is assumed the value is prime.
    prime: u64,
    /// All modules in this program, keyed by module name.
    modules: BTreeMap<String, PicusModule>,
}

impl PicusProgram {
    /// Create a new empty program over the given prime field.
    #[must_use]
    pub fn new(prime: u64) -> Self {
        PicusProgram { prime, modules: BTreeMap::new() }
    }

    /// Move all entries from `modules` into this program.
    ///
    /// This uses `BTreeMap::append`, transferring ownership of all modules
    /// from the argument map and leaving it empty.
    pub fn add_modules(&mut self, modules: &mut BTreeMap<String, PicusModule>) {
        self.modules.append(modules);
    }

    /// Write the serialized program to any `Write` sink.
    pub fn write_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        write!(w, "{self}")
    }

    /// Write the serialized program to `path`, creating parent directories if needed.
    pub fn write_to_path<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut f = File::create(path)?;
        self.write_to(&mut f)
    }
}

/// Serialize the whole program into PCL text.
///
/// Output begins with `(prime-number <p>)`, followed by each module’s
/// PCL block separated by a blank line. Module order is stable due to
/// `BTreeMap` key ordering.
impl Display for PicusProgram {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "(prime-number {})", self.prime)?;
        // Separate modules with a single blank line, deterministic order via BTreeMap.
        let mut first = true;
        for m in self.modules.values() {
            if !first {
                writeln!(f)?;
            }
            first = false;
            writeln!(f, "{m}")?;
        }
        Ok(())
    }
}

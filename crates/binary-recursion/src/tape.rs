//! The tape a traced verification records: every operation on a proof value,
//! with its value in the honest run.
//!
//! A variable is the result of one operation and is written once.  The
//! operations are the arithmetic of `GF(2^128)` and the conditions the
//! verifier checked, each of which the program must enforce: an equality the
//! verifier relied on is asserted, and an inequality it branched on is
//! asserted too, so the program follows the honest control flow and rejects
//! any proof that would leave it.

use core::cell::RefCell;

use p3_binary_field::{BinaryField128, TowerLevel};
use p3_field::Field;

/// The field of every recorded value.
pub type F = BinaryField128;

/// A recorded variable.
pub type Var = u32;

/// An operand of an operation: a variable or a constant of the program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operand {
    Var(Var),
    Const(F),
}

/// One recorded operation.  The value-producing ones define the next
/// variable; the assertions define none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// A value of the proof, the `n`-th read.
    Input(usize),
    /// `a + b`.
    Add(Operand, Operand),
    /// `a * b`.
    Mul(Operand, Operand),
    /// `1 / a`; enforcing it enforces `a != 0`.
    Inv(Operand),
    /// `a = b`.
    AssertEq(Operand, Operand),
    /// `a != 0`.
    AssertNonZero(Operand),
    /// The sixteen little-endian bytes of `a`'s representation, each a
    /// variable whose value is that byte.
    ToBytes(Operand),
    /// The element whose representation has these sixteen little-endian
    /// bytes.
    FromBytes(Vec<Operand>),
    /// The eight bits of a byte, lowest first, each `0` or `1`.
    ByteBits(Operand),
    /// The Blake3 digest of a byte string, thirty-two byte variables.
    Blake3(Vec<Operand>),
    /// The bit matrix whose rows are these elements, at most 128, read by
    /// column: 128 variables, column `v` having bit `u` set exactly when row
    /// `u` has bit `v` set.
    Transpose(Vec<Operand>),
    /// `b` if the bit `s` is one, `a` if it is zero.
    Select(Operand, Operand, Operand),
}

impl Op {
    /// The number of variables the operation defines.
    #[must_use]
    pub const fn defines(&self) -> usize {
        match self {
            Self::AssertEq(..) | Self::AssertNonZero(_) => 0,
            Self::ToBytes(_) => 16,
            Self::ByteBits(_) => 8,
            Self::Blake3(_) => 32,
            Self::Transpose(_) => 128,
            Self::Input(_)
            | Self::Add(..)
            | Self::Mul(..)
            | Self::Inv(_)
            | Self::FromBytes(_)
            | Self::Select(..) => 1,
        }
    }
}

/// The index of an operation's kind in [`Tape::KINDS`].
#[must_use]
pub const fn kind_index(op: &Op) -> usize {
    match op {
        Op::Input(_) => 0,
        Op::Add(..) => 1,
        Op::Mul(..) => 2,
        Op::Inv(_) => 3,
        Op::AssertEq(..) => 4,
        Op::AssertNonZero(_) => 5,
        Op::ToBytes(_) => 6,
        Op::FromBytes(_) => 7,
        Op::ByteBits(_) => 8,
        Op::Blake3(_) => 9,
        Op::Transpose(_) => 10,
        Op::Select(..) => 11,
    }
}

/// A recorded program and the values of its variables in the run that
/// recorded it.
#[derive(Clone, Debug, Default)]
pub struct Tape {
    /// The operations, in order.
    pub ops: Vec<Op>,
    /// The value of each variable.
    pub values: Vec<F>,
    /// The first variable each operation defines, if any.
    pub defined: Vec<Option<Var>>,
    /// The proof values read, in order.
    pub inputs: Vec<F>,
}

impl Tape {
    /// The number of operations of each kind, by [`Self::KINDS`].
    #[must_use]
    pub fn census(&self) -> [usize; 12] {
        let mut counts = [0; 12];
        for op in &self.ops {
            let k = kind_index(op);
            counts[k] += 1;
        }
        counts
    }

    /// The names of the kinds [`Self::census`] counts.
    pub const KINDS: [&'static str; 12] = [
        "input",
        "add",
        "mul",
        "inv",
        "assert_eq",
        "assert_nonzero",
        "to_bytes",
        "from_bytes",
        "byte_bits",
        "blake3",
        "transpose",
        "select",
    ];

    /// The bytes the Blake3 operations hash, in total.
    #[must_use]
    pub fn hashed_bytes(&self) -> usize {
        self.ops
            .iter()
            .map(|op| match op {
                Op::Blake3(bytes) => bytes.len(),
                _ => 0,
            })
            .sum()
    }

    /// The operands each operation reads, in order.
    #[must_use]
    pub fn operands(op: &Op) -> Vec<Operand> {
        match op {
            Op::Input(_) => Vec::new(),
            Op::Add(a, b) | Op::Mul(a, b) | Op::AssertEq(a, b) => vec![*a, *b],
            Op::Inv(a) | Op::AssertNonZero(a) | Op::ToBytes(a) | Op::ByteBits(a) => vec![*a],
            Op::FromBytes(xs) | Op::Blake3(xs) | Op::Transpose(xs) => xs.clone(),
            Op::Select(s, a, b) => vec![*s, *a, *b],
        }
    }

    /// How many times each variable is read.
    #[must_use]
    pub fn read_counts(&self) -> Vec<u32> {
        let mut reads = vec![0u32; self.values.len()];
        for op in &self.ops {
            for operand in Self::operands(op) {
                if let Operand::Var(v) = operand {
                    reads[v as usize] += 1;
                }
            }
        }
        reads
    }

    /// The value of an operand in the recorded run.
    pub fn value(&self, operand: Operand) -> F {
        match operand {
            Operand::Var(v) => self.values[v as usize],
            Operand::Const(c) => c,
        }
    }
}

/// The bit matrix whose rows are `rows`, at most 128, read by column.
#[must_use]
pub fn transpose(rows: &[u128]) -> [u128; 128] {
    assert!(rows.len() <= 128, "a column of 128 bits holds at most 128 rows");
    core::array::from_fn(|v| {
        rows.iter().enumerate().fold(0u128, |column, (u, row)| column | (((row >> v) & 1) << u))
    })
}

/// Why a run of a recorded program on some inputs fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunError {
    /// The program reads another number of inputs.
    Inputs { expected: usize, actual: usize },
    /// Operation `op` inverts zero.
    Inverse { op: usize },
    /// Operation `op` asserts two different values equal.
    NotEqual { op: usize },
    /// Operation `op` asserts zero nonzero.
    Zero { op: usize },
    /// Operation `op` reads a value as a byte that is not one.
    NotByte { op: usize },
    /// Operation `op` reads a value as a bit that is not one.
    NotBit { op: usize },
}

/// The byte `x` holds, if it holds one.
fn as_byte(x: F) -> Option<u8> {
    u8::try_from(x.to_repr()).ok()
}

impl Tape {
    /// Run the program on `inputs`, checking every condition it recorded,
    /// and return the value of every variable.
    ///
    /// Each operation's result is recomputed from its operands, so this is
    /// the program's meaning: it accepts exactly the inputs on which every
    /// recorded condition holds.  On the inputs it was recorded with it
    /// reproduces the recorded values.
    ///
    /// # Errors
    /// Returns the first condition that fails.
    pub fn run(&self, inputs: &[F]) -> Result<Vec<F>, RunError> {
        if inputs.len() != self.inputs.len() {
            return Err(RunError::Inputs { expected: self.inputs.len(), actual: inputs.len() });
        }
        let mut values: Vec<F> = Vec::with_capacity(self.values.len());
        let read = |values: &[F], operand: &Operand| match *operand {
            Operand::Var(v) => values[v as usize],
            Operand::Const(c) => c,
        };
        let bytes = |values: &[F], operands: &[Operand], op: usize| {
            operands
                .iter()
                .map(|b| as_byte(read(values, b)).ok_or(RunError::NotByte { op }))
                .collect::<Result<Vec<u8>, _>>()
        };
        for (op, operation) in self.ops.iter().enumerate() {
            match operation {
                Op::Input(n) => values.push(inputs[*n]),
                Op::Add(a, b) => values.push(read(&values, a) + read(&values, b)),
                Op::Mul(a, b) => values.push(read(&values, a) * read(&values, b)),
                Op::Inv(a) => {
                    let inverse = read(&values, a).try_inverse().ok_or(RunError::Inverse { op })?;
                    values.push(inverse);
                }
                Op::AssertEq(a, b) => {
                    if read(&values, a) != read(&values, b) {
                        return Err(RunError::NotEqual { op });
                    }
                }
                Op::AssertNonZero(a) => {
                    if read(&values, a).is_zero() {
                        return Err(RunError::Zero { op });
                    }
                }
                Op::ToBytes(a) => {
                    let repr = read(&values, a).to_repr();
                    values.extend(repr.to_le_bytes().map(|b| F::from_repr(u128::from(b))));
                }
                Op::FromBytes(operands) => {
                    let mut le = [0u8; 16];
                    le[..operands.len()].copy_from_slice(&bytes(&values, operands, op)?);
                    values.push(F::from_repr(u128::from_le_bytes(le)));
                }
                Op::ByteBits(b) => {
                    let byte = as_byte(read(&values, b)).ok_or(RunError::NotByte { op })?;
                    values.extend((0..8).map(|i| F::from_repr(u128::from((byte >> i) & 1))));
                }
                Op::Blake3(operands) => {
                    let message = bytes(&values, operands, op)?;
                    let digest: [u8; 32] =
                        p3_symmetric::CryptographicHasher::hash_iter(&p3_blake3::Blake3, message);
                    values.extend(digest.map(|b| F::from_repr(u128::from(b))));
                }
                Op::Select(selector, a, b) => {
                    let selector = read(&values, selector).to_repr();
                    if selector > 1 {
                        return Err(RunError::NotBit { op });
                    }
                    values.push(if selector == 1 { read(&values, b) } else { read(&values, a) });
                }
                Op::Transpose(rows) => {
                    let rows: Vec<u128> =
                        rows.iter().map(|row| read(&values, row).to_repr()).collect();
                    values.extend(transpose(&rows).map(F::from_repr));
                }
            }
        }
        Ok(values)
    }
}

std::thread_local! {
    static TAPE: RefCell<Option<Tape>> = const { RefCell::new(None) };
    static PROFILE: RefCell<Option<Profile>> = const { RefCell::new(None) };
}

/// Samples of where a recording's multiplications and hashes come from.
#[derive(Clone, Debug, Default)]
pub struct Profile {
    /// One multiplication in this many is sampled.
    pub every: usize,
    multiplications: usize,
    /// Each sample: its weight (multiplications, or bytes hashed), whether
    /// it is a hash, and the function names on the stack, innermost first.
    pub samples: Vec<(usize, bool, Vec<String>)>,
}

/// Frames that say nothing about which part of the verifier a sample
/// belongs to: iterator plumbing, closures, the thread-local access.
const PLUMBING: [&str; 26] = [
    "try_with",
    "with",
    "try_from_fn_erased",
    "try_from_fn",
    "from_fn",
    "map",
    "fold",
    "try_fold",
    "sum",
    "call_once",
    "call_mut",
    "next",
    "for_each",
    "collect",
    "from_iter",
    "extend",
    "extend_trusted",
    "mul",
    "add",
    "sub",
    "push",
    "spec_extend",
    "product",
    "mul_assign",
    "add_assign",
    "__iterator_get_unchecked",
];

impl Profile {
    /// Multiplications and hashed bytes by the `depth` innermost frames
    /// that are not plumbing, largest first.
    #[must_use]
    pub fn by_signature(&self, depth: usize) -> Vec<(String, usize, usize)> {
        let mut totals: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
        for (weight, is_hash, stack) in &self.samples {
            let frames: Vec<&str> = stack
                .iter()
                .map(String::as_str)
                .filter(|frame| !PLUMBING.contains(frame) && !frame.starts_with("{closure"))
                .take(depth)
                .collect();
            let entry = totals.entry(frames.join(" < ")).or_default();
            if *is_hash {
                entry.1 += weight;
            } else {
                entry.0 += weight;
            }
        }
        let mut rows: Vec<(String, usize, usize)> =
            totals.into_iter().map(|(signature, (muls, bytes))| (signature, muls, bytes)).collect();
        rows.sort_by_key(|(_, muls, bytes)| core::cmp::Reverse(muls * 64 + bytes));
        rows
    }
}

/// Sample the stack of one multiplication in `every`, and of every hash,
/// in recordings on this thread until [`take_profile`].
pub fn profile(every: usize) {
    PROFILE.with(|profile| *profile.borrow_mut() = Some(Profile { every, ..Profile::default() }));
}

/// The samples taken since [`profile`], ending the sampling.
#[must_use]
pub fn take_profile() -> Option<Profile> {
    PROFILE.with(|profile| profile.borrow_mut().take())
}

/// `name` without generic arguments.
fn strip_generics(name: &str) -> String {
    let mut depth = 0usize;
    name.chars()
        .filter(|&c| {
            match c {
                '<' => depth += 1,
                '>' => depth = depth.saturating_sub(1),
                _ => return depth == 0,
            }
            false
        })
        .collect()
}

/// A frame's function as `Type as Trait::function`, or its path, without
/// generic arguments: a type named only as an argument is not the frame's.
fn frame_name(name: &str) -> String {
    let Some(inner) = name.strip_prefix('<') else { return strip_generics(name) };
    let mut depth = 1usize;
    let close = inner.char_indices().find_map(|(i, c)| {
        match c {
            '<' => depth += 1,
            '>' => depth -= 1,
            _ => {}
        }
        (depth == 0).then_some(i)
    });
    let Some(close) = close else { return strip_generics(name) };
    let (head, rest) = (&inner[..close], &inner[close + 1..]);
    let mut depth = 0usize;
    let split = head.char_indices().find(|&(i, c)| {
        match c {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ => {}
        }
        depth == 0 && head[i..].starts_with(" as ")
    });
    match split {
        Some((i, _)) => format!(
            "{} as {}{}",
            strip_generics(&head[..i]),
            strip_generics(&head[i + 4..]),
            strip_generics(rest)
        ),
        None => format!("{}{}", strip_generics(head), strip_generics(rest)),
    }
}

/// The functions on the stack, innermost first.
fn stack() -> Vec<String> {
    std::backtrace::Backtrace::force_capture()
        .to_string()
        .lines()
        .filter_map(|line| line.trim_start().split_once(": ").map(|(_, name)| name))
        .filter(|name| name.contains("p3_") || name.contains("zkm_binary_recursion"))
        .map(frame_name)
        .collect()
}

/// Sample `op` if a profile is being taken.
fn sample(op: &Op) {
    PROFILE.with(|profile| {
        let mut profile = profile.borrow_mut();
        let Some(profile) = profile.as_mut() else { return };
        match op {
            Op::Mul(..) => {
                profile.multiplications += 1;
                if profile.multiplications % profile.every == 0 {
                    profile.samples.push((profile.every, false, stack()));
                }
            }
            Op::Blake3(bytes) => profile.samples.push((bytes.len(), true, stack())),
            _ => {}
        }
    });
}

/// Run `f` recording onto a fresh tape, and return its result with the tape.
///
/// The run is confined to one thread, the only worker of a pool of its own:
/// Plonky3 splits work with rayon, and on one worker every split runs on the
/// recording thread, in order, so the tape is the same on every run.
///
/// # Panics
/// Panics if a recording is already in progress on this thread, or if the
/// pool cannot be built.
pub fn record<R: Send>(f: impl FnOnce() -> R + Send) -> (R, Tape) {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .expect("a one-thread pool for the recording");
    pool.install(|| {
        TAPE.with(|tape| {
            assert!(tape.borrow().is_none(), "a recording is already in progress");
            *tape.borrow_mut() = Some(Tape::default());
        });
        let result = f();
        let tape =
            TAPE.with(|tape| tape.borrow_mut().take().expect("the recording is in progress"));
        (result, tape)
    })
}

/// Whether a recording is in progress on this thread.
#[must_use]
pub fn recording() -> bool {
    TAPE.with(|tape| tape.borrow().is_some())
}

/// Append `op`, whose results have `values`, one per variable it defines,
/// and return the first variable it defines.
///
/// # Panics
/// Panics if no recording is in progress: an operation on a proof value
/// outside a recording would be lost.  Panics if `values` does not hold one
/// value per variable the operation defines.
pub fn push(op: Op, values: &[F]) -> Option<Var> {
    assert_eq!(values.len(), op.defines(), "one value per variable defined");
    TAPE.with(|tape| {
        let mut tape = tape.borrow_mut();
        let tape = tape.as_mut().expect("an operation on a traced value outside a recording");
        let defined = (!values.is_empty()).then(|| {
            let var = Var::try_from(tape.values.len()).expect("fewer than 2^32 variables");
            tape.values.extend_from_slice(values);
            var
        });
        if let Op::Input(_) = op {
            tape.inputs.push(values[0]);
        }
        sample(&op);
        tape.ops.push(op);
        tape.defined.push(defined);
        defined
    })
}

/// The number of proof values read so far.
#[must_use]
pub fn inputs_read() -> usize {
    TAPE.with(|tape| tape.borrow().as_ref().map_or(0, |tape| tape.inputs.len()))
}

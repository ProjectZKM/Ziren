//! The AIR builder that records a chip's constraints and lookups, and the emitter that turns one
//! recorded evaluation into a Picus module.
//!
//! # How a chip becomes a module
//!
//! 1. [`PicusBuilder`] evaluates `chip.air.eval` once.  Its `Expr` type is Plonky3's
//!    `SymbolicExpression<KoalaBear>`, so the builder is a plain `AirBuilder` +
//!    `MessageBuilder`; it only collects `assert_zero` polynomials and `send` / `receive`
//!    lookups.
//! 2. [`extract_module`] lowers what was collected (see [`crate::lower`]), specializes it with
//!    the selector / `is_real` environment, and derives the module *interface* from the lookups:
//!
//!    | lookup kind                 | `send`                    | `receive`                 |
//!    |-----------------------------|---------------------------|---------------------------|
//!    | `Program` (pc, instruction) | inputs                    | —                         |
//!    | `Memory` (prev / current)   | prev record = inputs      | current record = outputs  |
//!    | `State` (shard, clk, pc, …) | next state = outputs      | current state = inputs    |
//!    | `Syscall`                   | outputs (the call)        | inputs (the callee)       |
//!    | `SyscallResult`             | result = outputs of the chip computing it (`SysLinux`, `SyscallPrecompile`), inputs elsewhere; args = inputs | same |
//!    | `Global`, `is_receive` = 1  | inputs (from another shard) | —                       |
//!    | `Global`, `is_send` = 1     | outputs (to another shard)  | —                       |
//!    | `Global`, flags are columns | outputs                   | inputs                    |
//!    | chaining buses (`GlobalAccumulation`, `MemoryGlobal*Control`, `PrecompileChain`, …) | outputs | inputs |
//!    | `Byte`                      | lowered to range / bit constraints or abstract calls  |
//!
//!    That is the "interaction-driven" interface: whatever a row consumes from another table is
//!    an input, whatever it produces for another table is an output, and the determinism
//!    question is "given the inputs, are the outputs (and the annotated columns) unique?".
//!    `#[picus(input)]` / `#[picus(output)]` annotations add columns to that interface.
//!
//! The Instruction bus and its opcode routing (the old `opcode_spec`) are gone: every
//! instruction chip carries its own frame, so a chip module is self-contained.

use std::collections::{BTreeMap, BTreeSet};

use p3_air::symbolic::{BaseEntry, BaseLeaf, SymbolicExpression, SymbolicVariable};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_matrix::dense::RowMajorMatrix;
use zkm_core_executor::ByteOpcode;
use zkm_pcs::{
    AirLookup, Chip, LookupKind, LookupScope, MachineAir, MessageBuilder, PicusInfo,
    PROOF_MAX_NUM_PVS,
};

use crate::{
    lower::{Lowerer, VarLayout},
    pcl::{
        fresh_picus_expr, partial_evaluate_expr, Felt, PicusCall, PicusConstraint, PicusExpr,
        PicusModule,
    },
    propagate::{GadgetMark, GADGET_MARKS},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmoduleMode {
    /// Ignore every lookup.  Used for the `top` module, which proves the selector shape from the
    /// chip's polynomial constraints alone.
    Ignore,
    /// Lower lookups into interface ports, range constraints and helper-module calls.
    Inline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShrCarrySummaryMode {
    /// Keep `ShrCarry` abstract as a module call.
    AbstractModule,
    /// Lower `ShrCarry` into explicit case-split constraints.
    Precise,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ColumnOutputMode {
    /// Only expose ports inferred from lookups and explicit Picus annotations.
    InteractionsOnly,
    /// Additionally expose every unspecialized column that is not an input as an output.
    AllNonInputsAreOutputs,
}

#[derive(Clone, Copy, Debug)]
pub struct ExtractionConfig {
    pub submodule_mode: SubmoduleMode,
    pub shr_carry: ShrCarrySummaryMode,
    pub column_output_mode: ColumnOutputMode,
    /// Sub-tree size above which the lowering binds an expression to a fresh variable; 0 = off.
    pub reify_threshold: usize,
}

/// Records one evaluation of a chip's AIR.
pub struct PicusBuilder {
    pub layout: VarLayout,
    preprocessed: RowMajorMatrix<SymbolicVariable<Felt>>,
    main: RowMajorMatrix<SymbolicVariable<Felt>>,
    public_values: Vec<SymbolicVariable<Felt>>,
    pub constraints: Vec<SymbolicExpression<Felt>>,
    pub sends: Vec<AirLookup<SymbolicExpression<Felt>>>,
    pub receives: Vec<AirLookup<SymbolicExpression<Felt>>>,
    /// Gadgets the AIR marked, in evaluation order (see `MessageBuilder::annotate`).
    pub gadgets: Vec<(&'static str, Vec<AirLookup<SymbolicExpression<Felt>>>)>,
}

impl PicusBuilder {
    pub fn new(main_width: usize, preprocessed_width: usize) -> Self {
        let prep_width = preprocessed_width.max(1);
        let layout = VarLayout { main_width, prep_width, num_public: PROOF_MAX_NUM_PVS };
        let prep_values = [0, 1]
            .into_iter()
            .flat_map(|offset| {
                (0..prep_width).map(move |column| {
                    SymbolicVariable::new(BaseEntry::Preprocessed { offset }, column)
                })
            })
            .collect();
        let main_values = [0, 1]
            .into_iter()
            .flat_map(|offset| {
                (0..main_width)
                    .map(move |column| SymbolicVariable::new(BaseEntry::Main { offset }, column))
            })
            .collect();
        let public_values =
            (0..PROOF_MAX_NUM_PVS).map(|i| SymbolicVariable::new(BaseEntry::Public, i)).collect();
        Self {
            layout,
            preprocessed: RowMajorMatrix::new(prep_values, prep_width),
            main: RowMajorMatrix::new(main_values, main_width),
            public_values,
            constraints: Vec::new(),
            sends: Vec::new(),
            receives: Vec::new(),
            gadgets: Vec::new(),
        }
    }
}

impl AirBuilder for PicusBuilder {
    type F = Felt;
    type Expr = SymbolicExpression<Felt>;
    type Var = SymbolicVariable<Felt>;
    type PreprocessedWindow = RowMajorMatrix<Self::Var>;
    type MainWindow = RowMajorMatrix<Self::Var>;
    type PublicVar = SymbolicVariable<Felt>;

    fn main(&self) -> Self::MainWindow {
        self.main.clone()
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed
    }

    fn is_first_row(&self) -> Self::Expr {
        SymbolicExpression::Leaf(BaseLeaf::IsFirstRow)
    }

    fn is_last_row(&self) -> Self::Expr {
        SymbolicExpression::Leaf(BaseLeaf::IsLastRow)
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        assert_eq!(size, 2, "PicusBuilder only supports a transition window of size 2");
        SymbolicExpression::Leaf(BaseLeaf::IsTransition)
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.constraints.push(x.into());
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        &self.public_values
    }
}

impl MessageBuilder<AirLookup<SymbolicExpression<Felt>>> for PicusBuilder {
    fn send(&mut self, message: AirLookup<SymbolicExpression<Felt>>, _scope: LookupScope) {
        self.sends.push(message);
    }

    fn receive(&mut self, message: AirLookup<SymbolicExpression<Felt>>, _scope: LookupScope) {
        self.receives.push(message);
    }

    fn annotate<O: FnOnce() -> Vec<AirLookup<SymbolicExpression<Felt>>>>(
        &mut self,
        gadget: &'static str,
        operands: O,
    ) {
        self.gadgets.push((gadget, operands()));
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Port {
    Input,
    Output,
}

/// Turns one recorded evaluation into a [`PicusModule`] under a specialization environment.
/// Chips that compute a syscall's result from its arguments (see
/// `Emitter::handle_syscall_result`).
const SYSCALL_RESULT_PRODUCERS: &[&str] = &["SysLinux", "SyscallPrecompile"];

/// Chips whose rows are the memory's initial contents.  The words they send to the global bus
/// are not computed from anything: the program image is fixed by the verifying key and the
/// hint words are the prover's input, so the tuple is an input of the row and determinism is
/// stated for what the row derives from it.
const INITIAL_MEMORY_TABLES: &[&str] = &["MemoryGlobalInit"];

/// Chips whose rows stand at a shard boundary for the accesses the shard cannot see.  Their
/// memory-bus messages carry the timestamps the row forwards, so every field is a port: the
/// tuple the row consumes (what the shard's last access produced) is an input with its
/// multiplicity, and the tuple it produces for the shard's first access is an output.  On the memory bus a send consumes a
/// tuple and a receive produces one, so the row's send is the input.
const SHARD_BOUNDARY_TABLES: &[&str] = &["MemoryLocal"];

/// Columns the determinism statement takes as inputs although no bus carries them, as
/// `(chip, field, column within the field, origin)`: witness freedom the protocol accepts by
/// design, which the statement names instead of quantifying away.  The Global chip's `lift_x`
/// offset is a byte the prover picks among those that lift the message to a curve point
/// (`GlobalLookupOperation::offset`, the first column of `lookup`); any such offset is sound
/// because `values[6] < 2^16` keeps the encoding injective, as in SP1.
///
/// `KeccakSpongeControl` spreads one call over a chain of rows, one per absorbed block, and a
/// row's place in that chain (`is_first_block`, `is_final_block`) is fixed by the other ends of
/// its lookups, not by the row: the syscall is sent once, so exactly the call's first row
/// receives it, and a block is final when the call's length `(block + 1)·rate` is reached, which
/// the bus-B chain from the first row enforces.  Determinism is stated given that place.
const CHOSEN_INPUTS: &[(&str, &str, usize, &str)] = &[
    ("Global", "lookup", 0, "column.lookup.offset"),
    ("KeccakSpongeControl", "is_first_block", 0, "column.is_first_block"),
    ("KeccakSpongeControl", "is_final_block", 0, "column.is_final_block"),
];

struct Emitter<'a> {
    cfg: ExtractionConfig,
    env: &'a BTreeMap<usize, u64>,
    module: PicusModule,
    aux_modules: BTreeMap<String, PicusModule>,
    inputs_seen: BTreeSet<String>,
    outputs_seen: BTreeSet<String>,
    /// Where each interface port came from (`program.op_b[2]`, `mem_write[0].val[1]`, …), in
    /// the order of `module.inputs` / `module.outputs`; consumed by the Lean backend.
    input_origins: Vec<String>,
    output_origins: Vec<String>,
    mem_reads: usize,
    mem_writes: usize,
}

impl<'a> Emitter<'a> {
    fn specialize(&self, e: PicusExpr) -> PicusExpr {
        if self.env.is_empty() {
            e
        } else {
            partial_evaluate_expr(&e, self.env)
        }
    }

    fn push_constraint(&mut self, c: PicusConstraint) {
        self.module.constraints.push(c);
    }

    fn push_port(&mut self, port: Port, expr: PicusExpr) {
        self.push_port_from(port, expr, "annotation");
    }

    fn push_port_from(&mut self, port: Port, expr: PicusExpr, origin: &str) {
        let key = expr.to_string();
        match port {
            Port::Input => {
                if self.inputs_seen.insert(key) {
                    self.module.inputs.push(expr);
                    self.input_origins.push(origin.to_string());
                }
            }
            Port::Output => {
                if self.outputs_seen.insert(key) {
                    self.module.outputs.push(expr);
                    self.output_origins.push(origin.to_string());
                }
            }
        }
    }

    /// Exposes `value * multiplicity` as a port.  A bare variable under multiplicity one is
    /// exposed directly; anything else is bound to a fresh variable first, because Picus ports
    /// must be variables.
    fn bind_port(&mut self, port: Port, value: &PicusExpr, multiplicity: &PicusExpr, origin: &str) {
        match (value, multiplicity) {
            (PicusExpr::Const(_), _) => {}
            (PicusExpr::Var(_), PicusExpr::Const(1)) => {
                self.push_port_from(port, value.clone(), origin)
            }
            _ => {
                let v = fresh_picus_expr();
                self.push_constraint(PicusConstraint::new_equality(
                    v.clone(),
                    value.clone() * multiplicity.clone(),
                ));
                self.push_port_from(port, v, origin);
            }
        }
    }

    fn bind_ports(
        &mut self,
        port: Port,
        values: &[PicusExpr],
        multiplicity: &PicusExpr,
        origin: &str,
    ) {
        for (i, v) in values.iter().enumerate() {
            self.bind_port(port, v, multiplicity, &format!("{origin}[{i}]"));
        }
    }

    fn abstract_call(&mut self, name: &str, inputs: &[PicusExpr], outputs: &[PicusExpr]) {
        if !self.aux_modules.contains_key(name) {
            let m = PicusModule::build_empty(name.to_string(), inputs.len(), outputs.len().max(1));
            self.aux_modules.insert(name.to_string(), m);
        }
        let outputs: Vec<PicusExpr> =
            if outputs.is_empty() { vec![fresh_picus_expr()] } else { outputs.to_vec() };
        self.module.calls.push(PicusCall::new(name.to_string(), &outputs, inputs));
    }

    // ----------------------------------------------------------------------------------------
    // Byte table: the only lookup that is lowered to constraints rather than ports.
    // Layout: values = [opcode, a1, a2, b, c]  (see `ByteAirBuilder::send_byte_pair`).
    // ----------------------------------------------------------------------------------------

    /// Byte-table lookups.  Every row of the table (`bytes::ByteChip::trace`) has operands
    /// `b, c ∈ [0, 255]` and, for AND/OR/XOR/NOR/SLL, a byte result, so a lookup implies those
    /// ranges on top of the opcode's relation.
    fn handle_byte(&mut self, multiplicity: PicusExpr, values: &[PicusExpr]) {
        if matches!(multiplicity, PicusExpr::Const(0)) {
            return;
        }
        assert_eq!(values.len(), 5, "byte lookup must carry [opcode, a1, a2, b, c]");
        let opcode = match values[0] {
            PicusExpr::Const(v) => v,
            _ => {
                if self.cfg.submodule_mode == SubmoduleMode::Ignore {
                    return;
                }
                panic!(
                    "byte lookup opcode is not a constant after specialization in module {} ({})",
                    self.module.name, values[0]
                )
            }
        };
        let (a1, a2, b, c) = (&values[1], &values[2], &values[3], &values[4]);
        let range = |this: &mut Self, e: &PicusExpr, bound: u64| {
            if let PicusExpr::Const(v) = e {
                assert!(*v <= bound, "constant {v} out of range {bound}");
            } else {
                this.push_constraint(PicusConstraint::new_leq(
                    e.clone() * multiplicity.clone(),
                    PicusExpr::Const(bound),
                ));
            }
        };
        let table_ops = [
            ByteOpcode::AND,
            ByteOpcode::OR,
            ByteOpcode::XOR,
            ByteOpcode::NOR,
            ByteOpcode::SLL,
            ByteOpcode::LTU,
        ];
        if table_ops.iter().any(|op| *op as u64 == opcode) {
            range(self, b, 255);
            range(self, c, 255);
            if opcode != ByteOpcode::LTU as u64 {
                range(self, a1, 255);
            }
        }
        match opcode {
            x if x == ByteOpcode::U8Range as u64 => {
                for e in [a1, a2, b, c] {
                    range(self, e, 255);
                }
            }
            x if x == ByteOpcode::U16Range as u64 => {
                for e in [a1, a2, b, c] {
                    range(self, e, 65535);
                }
            }
            x if x == ByteOpcode::Range as u64 => match b {
                PicusExpr::Const(bits) => {
                    assert!(*bits < 32);
                    range(self, a1, (1u64 << bits) - 1);
                }
                _ => self.abstract_call("byte_range", &[a1.clone(), b.clone()], &[]),
            },
            x if x == ByteOpcode::MSB as u64 => {
                if !matches!(b, PicusExpr::Const(_)) {
                    let lo = fresh_picus_expr();
                    self.push_constraint(PicusConstraint::new_leq(
                        lo.clone() * multiplicity.clone(),
                        PicusExpr::Const(127),
                    ));
                    self.push_constraint(PicusConstraint::Eq(Box::new(
                        multiplicity.clone() * a1.clone() * (a1.clone() - PicusExpr::Const(1)),
                    )));
                    self.push_constraint(PicusConstraint::Eq(Box::new(
                        multiplicity.clone()
                            * (b.clone() - (a1.clone() * PicusExpr::Const(128) + lo)),
                    )));
                }
            }
            x if x == ByteOpcode::LTU as u64 => {
                let m = &multiplicity;
                let gated = |e: &PicusExpr| e.clone() * m.clone();
                match (a1, c) {
                    (PicusExpr::Const(1), PicusExpr::Const(k)) if *k >= 1 => {
                        self.push_constraint(PicusConstraint::new_lt(gated(b), c.clone()))
                    }
                    (PicusExpr::Const(1), _) => self.push_constraint(PicusConstraint::new_lt(
                        gated(b),
                        gated(c) + (PicusExpr::Const(1) - m.clone()),
                    )),
                    (PicusExpr::Const(0), _) => {
                        self.push_constraint(PicusConstraint::new_geq(gated(b), gated(c)))
                    }
                    _ => {
                        self.push_constraint(PicusConstraint::Eq(Box::new(
                            m.clone() * a1.clone() * (a1.clone() - PicusExpr::Const(1)),
                        )));
                        self.push_constraint(PicusConstraint::Iff(
                            Box::new(PicusConstraint::new_equality(gated(a1), 1.into())),
                            Box::new(PicusConstraint::new_lt(gated(b), gated(c))),
                        ));
                    }
                }
            }
            x if x == ByteOpcode::ShrCarry as u64 => match self.cfg.shr_carry {
                ShrCarrySummaryMode::AbstractModule => self.abstract_call(
                    "byte_shr_carry",
                    &[b.clone() * multiplicity.clone(), c.clone() * multiplicity.clone()],
                    &[a1.clone() * multiplicity.clone(), a2.clone() * multiplicity.clone()],
                ),
                ShrCarrySummaryMode::Precise => self.shr_carry_precise(&multiplicity, values),
            },
            x if x == ByteOpcode::AND as u64 => {
                self.bitwise_call("byte_and", a1, b, c, &multiplicity, 0)
            }
            x if x == ByteOpcode::OR as u64 => {
                self.bitwise_call("byte_or", a1, b, c, &multiplicity, 0)
            }
            x if x == ByteOpcode::XOR as u64 => {
                self.bitwise_call("byte_xor", a1, b, c, &multiplicity, 0)
            }
            x if x == ByteOpcode::NOR as u64 => {
                self.bitwise_call("byte_nor", a1, b, c, &multiplicity, 255)
            }
            x if x == ByteOpcode::SLL as u64 => {
                self.bitwise_call("byte_sll", a1, b, c, &multiplicity, 0)
            }
            other => panic!("unknown byte opcode {other}"),
        }
    }

    /// A bitwise table lookup under multiplicity `m`, a bit.  A row that does not look up
    /// (`m = 0`) is not constrained by the table, so the call is stated on gated operands:
    /// `rel [b·m, c·m] [a·m + (1 − m)·at_zero]`, where `at_zero` is the operation's value at
    /// `(0, 0)`, the table row the gated call names when `m = 0`.  An `AND` with `127` or `1`
    /// splits a byte, so it is stated exactly: `b = 128·hi + a` with `a < 128` and `hi` a bit,
    /// or `b = 2·hi + a` with `a` a bit and `hi ≤ 127`.
    fn bitwise_call(
        &mut self,
        name: &str,
        a1: &PicusExpr,
        b: &PicusExpr,
        c: &PicusExpr,
        m: &PicusExpr,
        at_zero: u64,
    ) {
        let gated = |e: &PicusExpr| e.clone() * m.clone();
        if name == "byte_and" && matches!(c, PicusExpr::Const(127)) {
            let hi = fresh_picus_expr();
            self.push_constraint(PicusConstraint::new_lt(gated(a1), 128.into()));
            self.push_constraint(PicusConstraint::Eq(Box::new(
                m.clone() * hi.clone() * (hi.clone() - PicusExpr::Const(1)),
            )));
            self.push_constraint(PicusConstraint::Eq(Box::new(
                m.clone() * (b.clone() - (hi * 128 + a1.clone())),
            )));
            return;
        }
        if name == "byte_and" && matches!(c, PicusExpr::Const(1)) {
            let hi = fresh_picus_expr();
            self.push_constraint(PicusConstraint::Eq(Box::new(
                m.clone() * a1.clone() * (a1.clone() - PicusExpr::Const(1)),
            )));
            self.push_constraint(PicusConstraint::new_leq(gated(&hi), 127.into()));
            self.push_constraint(PicusConstraint::Eq(Box::new(
                m.clone() * (b.clone() - (hi * 2 + a1.clone())),
            )));
            return;
        }
        let out = if matches!(m, PicusExpr::Const(1)) {
            a1.clone()
        } else {
            gated(a1) + (PicusExpr::Const(1) - m.clone()) * PicusExpr::Const(at_zero)
        };
        let ins = if matches!(m, PicusExpr::Const(1)) {
            [b.clone(), c.clone()]
        } else {
            [gated(b), gated(c)]
        };
        self.abstract_call(name, &ins, std::slice::from_ref(&out));
    }

    /// Precise summary for `ByteOpcode::ShrCarry` (values = [op, out, carry, input, shift]).
    fn shr_carry_precise(&mut self, multiplicity: &PicusExpr, values: &[PicusExpr]) {
        let out = values[1].clone();
        let carry = values[2].clone();
        let input = values[3].clone();
        let shift = values[4].clone();
        for (e, bound) in [(&out, 255), (&input, 255), (&carry, 255), (&shift, 7)] {
            self.push_constraint(PicusConstraint::new_leq(
                e.clone() * multiplicity.clone(),
                PicusExpr::Const(bound),
            ));
        }
        for i in 0..8u64 {
            let cond = PicusConstraint::new_equality(shift.clone(), PicusExpr::Const(i));
            let consequence = if i == 0 {
                PicusConstraint::And(
                    Box::new(PicusConstraint::Eq(Box::new(
                        multiplicity.clone() * (out.clone() - input.clone()),
                    ))),
                    Box::new(PicusConstraint::Eq(Box::new(multiplicity.clone() * carry.clone()))),
                )
            } else {
                let p2 = 1u64 << i;
                PicusConstraint::And(
                    Box::new(PicusConstraint::Eq(Box::new(
                        multiplicity.clone()
                            * (input.clone()
                                - (out.clone() * PicusExpr::Const(p2) + carry.clone())),
                    ))),
                    Box::new(PicusConstraint::new_lt(
                        carry.clone() * multiplicity.clone(),
                        PicusExpr::Const(p2),
                    )),
                )
            };
            self.push_constraint(PicusConstraint::Implies(Box::new(cond), Box::new(consequence)));
        }
    }

    // ----------------------------------------------------------------------------------------
    // Port-defining lookups.
    // ----------------------------------------------------------------------------------------

    /// Memory records are `[shard, clk, addr, value limbs...]`.  The previous record (sent) is
    /// what the row reads; the current record (received) is what it writes.
    fn handle_memory(&mut self, multiplicity: PicusExpr, values: &[PicusExpr], is_send: bool) {
        if matches!(multiplicity, PicusExpr::Const(0)) {
            return;
        }
        assert!(values.len() >= 4, "memory lookup must carry addr + value limbs");
        let chip = self.module.name.split("__").next().unwrap_or_default();
        if SHARD_BOUNDARY_TABLES.contains(&chip) {
            let (port, tag) =
                if is_send { (Port::Input, "mem_final") } else { (Port::Output, "mem_initial") };
            let k = if is_send { self.mem_reads } else { self.mem_writes };
            if is_send {
                self.mem_reads += 1
            } else {
                self.mem_writes += 1
            }
            self.bind_port(
                Port::Input,
                &multiplicity,
                &PicusExpr::Const(1),
                &format!("{tag}[{k}].multiplicity"),
            );
            self.bind_ports(port, values, &multiplicity, &format!("{tag}[{k}]"));
            return;
        }
        let port = if is_send { Port::Input } else { Port::Output };
        let k = if is_send { self.mem_reads } else { self.mem_writes };
        if is_send {
            self.mem_reads += 1
        } else {
            self.mem_writes += 1
        }
        let tag = if is_send { "mem_read" } else { "mem_write" };
        self.bind_port(port, &values[2], &multiplicity, &format!("{tag}[{k}].addr"));
        for (i, limb) in values[3..].iter().enumerate() {
            self.bind_port(port, limb, &multiplicity, &format!("{tag}[{k}].val[{i}]"));
            if is_send && !matches!(limb, PicusExpr::Const(_)) {
                self.push_constraint(PicusConstraint::new_leq(
                    limb.clone() * multiplicity.clone(),
                    PicusExpr::Const(255),
                ));
            }
        }
    }

    /// `[pc, instruction fields...]`: the fetched program row is external context.
    fn handle_program(&mut self, multiplicity: PicusExpr, values: &[PicusExpr]) {
        if matches!(multiplicity, PicusExpr::Const(0)) {
            return;
        }
        const NAMES: [&str; 14] = [
            "program.pc",
            "program.opcode",
            "program.op_a",
            "program.op_b[0]",
            "program.op_b[1]",
            "program.op_b[2]",
            "program.op_b[3]",
            "program.op_c[0]",
            "program.op_c[1]",
            "program.op_c[2]",
            "program.op_c[3]",
            "program.op_a_0",
            "program.imm_b",
            "program.imm_c",
        ];
        for (i, v) in values.iter().enumerate() {
            let origin =
                NAMES.get(i).map(|s| s.to_string()).unwrap_or_else(|| format!("program[{i}]"));
            self.bind_port(Port::Input, v, &multiplicity, &origin);
        }
    }

    /// Generic chaining bus: what a row receives is its incoming state, what it sends is the
    /// state it hands to the next row (or table).
    fn handle_chain(
        &mut self,
        kind: &str,
        multiplicity: PicusExpr,
        values: &[PicusExpr],
        is_send: bool,
    ) {
        if matches!(multiplicity, PicusExpr::Const(0)) {
            return;
        }
        let port = if is_send { Port::Output } else { Port::Input };
        let dir = if is_send { "send" } else { "recv" };
        self.bind_ports(port, values, &multiplicity, &format!("{kind}_{dir}"));
    }

    /// Global-bus messages are `[message (7), is_send, is_receive, kind]`, always sent on the
    /// local bus to the Global chip; the cross-shard direction is the flag pair.  A message whose
    /// `is_receive` flag is set (the constant one, or the lookup's own multiplicity when a row
    /// packs several gated entries) carries values produced in another shard, so its fields are inputs of this row; one whose `is_send` flag is the
    /// constant one carries values this row produces, so its fields are outputs.  Flags that
    /// are columns (the Global chip itself) keep the direction of the local lookup.
    fn handle_global(&mut self, multiplicity: PicusExpr, values: &[PicusExpr], is_send: bool) {
        if matches!(multiplicity, PicusExpr::Const(0)) {
            return;
        }
        if is_send && values.len() == 10 {
            let set = |e: &PicusExpr| matches!(e, PicusExpr::Const(1)) || *e == multiplicity;
            let clear = |e: &PicusExpr| matches!(e, PicusExpr::Const(0));
            let receive = set(&values[8]) && clear(&values[7]);
            let send = set(&values[7]) && clear(&values[8]);
            if receive || send {
                let chip = self.module.name.split("__").next().unwrap_or_default();
                let image = send && INITIAL_MEMORY_TABLES.contains(&chip);
                let port = if receive || image { Port::Input } else { Port::Output };
                let dir = if image {
                    "image"
                } else if receive {
                    "recv"
                } else {
                    "send"
                };
                self.bind_ports(port, &values[..7], &multiplicity, &format!("global_{dir}"));
                return;
            }
        }
        self.handle_chain("global", multiplicity, values, is_send);
    }

    /// Syscall lookups are `[shard, clk, syscall_id, arg1, arg2]`; timing is routing metadata.
    fn handle_syscall(&mut self, multiplicity: PicusExpr, values: &[PicusExpr], is_send: bool) {
        if matches!(multiplicity, PicusExpr::Const(0)) {
            return;
        }
        assert!(
            values.len() == 5 || values.len() == 8,
            "syscall lookup must carry 5 values (reduced args) or 8 (half-word args + is_linux)"
        );
        let port = if is_send { Port::Output } else { Port::Input };
        let dir = if is_send { "send" } else { "recv" };
        self.bind_ports(port, values, &multiplicity, &format!("syscall_{dir}"));
    }

    /// `[shard, clk, result_lo, result_hi, arg1_lo, arg1_hi, arg2_lo, arg2_hi]`.  The result
    /// originates at the instruction chip (the register value it writes back) and is relayed
    /// through the core-shard syscall chip, the global bus and the precompile-shard syscall
    /// chip to the Linux syscall chip, which checks it: a sender produces the result (output),
    /// a receiver consumes it (input).  The argument halves are inputs on both sides.
    /// A syscall result is an output of the chip that computes it from the arguments and an input
    /// of the chip that consumes it.  The bus direction does not say which: a linux syscall's
    /// result is sent by the calling instruction and received (and computed) by
    /// [`SYSCALL_RESULT_PRODUCERS`]' `SysLinux`, while a precompile's is sent (computed) by
    /// `SyscallPrecompile` and received by `SyscallCore`.
    fn handle_syscall_result(
        &mut self,
        multiplicity: PicusExpr,
        values: &[PicusExpr],
        is_send: bool,
    ) {
        if matches!(multiplicity, PicusExpr::Const(0)) {
            return;
        }
        assert_eq!(values.len(), 8, "syscall result lookup must carry 8 values");
        let chip = self.module.name.split("__").next().unwrap_or_default();
        let _ = is_send;
        let result_port =
            if SYSCALL_RESULT_PRODUCERS.contains(&chip) { Port::Output } else { Port::Input };
        self.bind_ports(Port::Input, &values[0..2], &multiplicity, "syscall_result.at");
        self.bind_ports(result_port, &values[2..4], &multiplicity, "syscall_result.result");
        self.bind_ports(Port::Input, &values[4..8], &multiplicity, "syscall_result.arg");
        for half in &values[4..8] {
            if !matches!(half, PicusExpr::Const(_)) {
                self.push_constraint(PicusConstraint::new_leq(
                    half.clone() * multiplicity.clone(),
                    PicusExpr::Const(65535),
                ));
            }
        }
    }

    fn handle_lookup(&mut self, lookup: &AirLookup<PicusExpr>, is_send: bool) {
        if self.cfg.submodule_mode == SubmoduleMode::Ignore {
            return;
        }
        let m = lookup.multiplicity.clone();
        let v = &lookup.values;
        match lookup.kind {
            LookupKind::Byte => {
                if is_send {
                    self.handle_byte(m, v);
                }
            }
            LookupKind::Memory => self.handle_memory(m, v, is_send),
            LookupKind::Program => {
                if is_send {
                    self.handle_program(m, v);
                }
            }
            LookupKind::Syscall => self.handle_syscall(m, v, is_send),
            LookupKind::SyscallResult => self.handle_syscall_result(m, v, is_send),
            LookupKind::Instruction => {
                panic!(
                    "the Instruction bus no longer exists; chip {} still sends on it",
                    self.module.name
                )
            }
            LookupKind::Range => self.handle_chain("range", m, v, is_send),
            LookupKind::Global => self.handle_global(m, v, is_send),
            other => {
                let kind = format!("{other:?}").to_lowercase();
                self.handle_chain(&kind, m, v, is_send)
            }
        }
    }
}

/// Column-index environment for one specialization pass.
///
/// `is_real = 1` removes vacuous gating; a one-hot selector assignment folds the opcode flags to
/// constants so byte-table opcodes and multiplicities become decidable.
pub fn build_selector_env(
    picus_info: &PicusInfo,
    selected_selector_col: Option<usize>,
    specialize_is_real: bool,
) -> BTreeMap<usize, u64> {
    let mut env = BTreeMap::new();
    if specialize_is_real {
        if let Some(id) = picus_info.is_real_index {
            env.insert(id, 1);
        }
    }
    if let Some(selected_col) = selected_selector_col {
        env.insert(selected_col, 1);
        for (other_selector_col, _) in &picus_info.selector_indices {
            if *other_selector_col != selected_col {
                env.insert(*other_selector_col, 0);
            }
        }
    }
    env
}

/// Evaluates `chip` once and lowers the result into a module named `module_name`.
///
/// Returns the module and the abstract helper modules it calls.
pub fn extract_module<A>(
    chip: &Chip<Felt, A>,
    module_name: String,
    env: &BTreeMap<usize, u64>,
    cfg: ExtractionConfig,
) -> (PicusModule, BTreeMap<String, PicusModule>)
where
    A: MachineAir<Felt> + BaseAir<Felt> + Air<PicusBuilder>,
{
    let mut builder = PicusBuilder::new(chip.air.width(), chip.preprocessed_width());
    chip.air.eval(&mut builder);

    let mut lowerer = Lowerer::new(&builder.layout, cfg.reify_threshold);
    let lower_lookup = |lowerer: &mut Lowerer, l: &AirLookup<SymbolicExpression<Felt>>| {
        AirLookup::<PicusExpr>::new(
            l.values.iter().map(|e| lowerer.lower(e)).collect(),
            lowerer.lower(&l.multiplicity),
            l.kind,
        )
    };
    let constraints: Vec<PicusExpr> =
        builder.constraints.iter().map(|e| lowerer.lower(e)).collect();
    let sends: Vec<_> = builder.sends.iter().map(|l| lower_lookup(&mut lowerer, l)).collect();
    let receives: Vec<_> = builder.receives.iter().map(|l| lower_lookup(&mut lowerer, l)).collect();
    let bindings = std::mem::take(&mut lowerer.bindings);
    drop(lowerer);
    let mut plain = Lowerer::new(&builder.layout, 0);
    let gadgets: Vec<(&'static str, PicusExpr, Vec<Vec<PicusExpr>>)> = builder
        .gadgets
        .iter()
        .map(|(g, ops)| {
            let gate = ops.first().map_or(PicusExpr::Const(1), |o| plain.lower(&o.multiplicity));
            let ops = ops.iter().map(|o| o.values.iter().map(|e| plain.lower(e)).collect());
            (*g, gate, ops.collect())
        })
        .collect();
    drop(plain);
    drop(builder.constraints);
    drop(builder.sends);
    drop(builder.receives);

    let mut em = Emitter {
        cfg,
        env,
        module: PicusModule::new(module_name),
        aux_modules: BTreeMap::new(),
        inputs_seen: BTreeSet::new(),
        outputs_seen: BTreeSet::new(),
        input_origins: Vec::new(),
        output_origins: Vec::new(),
        mem_reads: 0,
        mem_writes: 0,
    };

    for c in constraints {
        let c = em.specialize(c);
        if c.is_const_zero() {
            continue;
        }
        em.push_constraint(PicusConstraint::Eq(Box::new(c)));
    }
    for b in bindings {
        let b = match b {
            PicusConstraint::Eq(e) => PicusConstraint::Eq(Box::new(em.specialize(*e))),
            other => other,
        };
        em.push_constraint(b);
    }
    let specialize_lookup = |em: &Emitter, l: AirLookup<PicusExpr>| {
        AirLookup::new(
            l.values.into_iter().map(|e| em.specialize(e)).collect(),
            em.specialize(l.multiplicity),
            l.kind,
        )
    };
    for l in sends {
        let l = specialize_lookup(&em, l);
        em.handle_lookup(&l, true);
    }
    for l in receives {
        let l = specialize_lookup(&em, l);
        em.handle_lookup(&l, false);
    }

    let info = chip.picus_info();
    let width = builder.layout.main_width;
    let annotated = |ranges: &[(usize, usize, String)]| -> Vec<usize> {
        ranges
            .iter()
            .flat_map(|(s, e, _)| *s..*e)
            .filter(|c| *c < width && !env.contains_key(c))
            .collect()
    };
    for col in annotated(&info.input_ranges) {
        let name = info.col_to_name.get(&col).cloned().unwrap_or_default();
        em.push_port_from(Port::Input, PicusExpr::Var(col), &format!("column.{name}"));
    }
    let chip_name = chip.name();
    for (_, field, at, origin) in CHOSEN_INPUTS.iter().filter(|(c, ..)| *c == chip_name) {
        if let Some((start, _)) = info.name_to_colrange.get(*field) {
            let col = start + at;
            if col < width && !env.contains_key(&col) {
                em.push_port_from(Port::Input, PicusExpr::Var(col), origin);
            }
        }
    }
    for col in annotated(&info.output_ranges) {
        let name = info.col_to_name.get(&col).cloned().unwrap_or_default();
        em.push_port_from(Port::Output, PicusExpr::Var(col), &format!("column.{name}"));
    }
    if cfg.column_output_mode == ColumnOutputMode::AllNonInputsAreOutputs {
        for col in 0..width {
            if env.contains_key(&col) {
                continue;
            }
            let v = PicusExpr::Var(col);
            if !em.inputs_seen.contains(&v.to_string()) {
                em.push_port(Port::Output, v);
            }
        }
    }

    PORT_ORIGINS
        .lock()
        .unwrap()
        .insert(em.module.name.clone(), (em.input_origins.clone(), em.output_origins.clone()));
    let (hints, gadgets): (Vec<_>, Vec<_>) =
        gadgets.into_iter().partition(|(gadget, _, _)| *gadget == "hint_input");
    for (_, gate, operands) in hints {
        let gate = em.specialize(gate);
        for (i, v) in operands.into_iter().flatten().enumerate() {
            let v = em.specialize(v);
            em.bind_port(Port::Input, &v, &gate, &format!("hint[{i}]"));
        }
    }
    PORT_ORIGINS
        .lock()
        .unwrap()
        .insert(em.module.name.clone(), (em.input_origins.clone(), em.output_origins.clone()));
    let marks = gadgets
        .into_iter()
        .map(|(gadget, gate, operands)| GadgetMark {
            gadget,
            gate: em.specialize(gate),
            operands: operands
                .into_iter()
                .map(|o| o.into_iter().map(|e| em.specialize(e)).collect())
                .collect(),
        })
        .collect();
    GADGET_MARKS.lock().unwrap().insert(em.module.name.clone(), marks);
    (em.module, em.aux_modules)
}

/// Port origins of every module extracted in this process, by module name (see
/// [`Emitter::input_origins`]).  The CLI hands them to the Lean backend.
pub static PORT_ORIGINS: std::sync::Mutex<BTreeMap<String, (Vec<String>, Vec<String>)>> =
    std::sync::Mutex::new(BTreeMap::new());

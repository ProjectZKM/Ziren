use std::collections::BTreeMap;

use crate::{
    opcode_spec::{spec_for, IndexSlice},
    pcl::{
        fresh_picus_expr, fresh_picus_var, fresh_picus_var_id, partial_evaluate_expr, Felt,
        PicusAtom, PicusCall, PicusConstraint, PicusExpr, PicusModule,
    },
    syscall_spec::spec_for_sender,
};
use p3_air::{AirBuilder, AirBuilderWithPublicValues, PairBuilder};
use p3_matrix::dense::{DenseMatrix, RowMajorMatrix};
use p3_matrix::Matrix;
use zkm_core_executor::{ByteOpcode, Opcode};
use zkm_stark::{
    AirLookup, Chip, LookupKind, MachineAir, MessageBuilder, OperationSummaryAirBuilder, Word,
    ZKM_PROOF_NUM_PV_ELTS,
};

/// Controls how instruction and syscall lookups are represented during extraction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmoduleMode {
    /// Ignore instruction submodules entirely.
    /// Use this when building the top module that proves selector determinism/shape
    /// and should not recursively inline instruction chip constraints.
    Ignore,
    /// Recursively inline instruction submodule constraints into the current module.
    Inline,
    /// Keep instruction submodules separate (currently behaves like `Inline`).
    Submodule,
}

/// Controls how `ByteOpcode::ShrCarry` is summarized in the extracted module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShrCarrySummaryMode {
    /// Keep ShrCarry abstract as a module call.
    AbstractModule,
    /// Lower ShrCarry into explicit case-split constraints.
    Precise,
}

/// Controls which chip columns become explicit Picus module outputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ColumnOutputMode {
    /// Only expose ports inferred from interactions, summaries, and explicit Picus annotations.
    InteractionsOnly,
    /// Expose every primary-row column as an output unless it is annotated as an input.
    AllNonInputsAreOutputs,
}

/// Selects which trace shape the extracted module is meant to model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtractionPhase {
    /// Trace of length 1.
    SingleRow,
    /// First row of a multi-row trace.
    FirstRow,
    /// Interior row of a multi-row trace.
    Transition,
    /// Last real row before padding begins.
    Boundary,
    /// Final trace row.
    LastRow,
}

impl ExtractionPhase {
    /// Returns every extraction phase relevant for the chip's row model.
    ///
    /// `local_only` chips never materialize successor rows, so they skip
    /// transition-specific phases such as `Boundary`.
    pub fn all(local_only: bool) -> Vec<Self> {
        let mut phases = vec![Self::SingleRow, Self::FirstRow, Self::Transition, Self::LastRow];
        if !local_only {
            phases.insert(3, Self::Boundary);
        }
        phases
    }

    /// Returns the stable suffix used in generated module names for this phase.
    pub fn module_suffix(self) -> &'static str {
        match self {
            Self::SingleRow => "single_row",
            Self::FirstRow => "first_row",
            Self::Transition => "transition",
            Self::Boundary => "boundary",
            Self::LastRow => "last_row",
        }
    }

    fn is_first_row(self) -> bool {
        matches!(self, Self::SingleRow | Self::FirstRow)
    }

    fn is_last_row(self) -> bool {
        matches!(self, Self::SingleRow | Self::LastRow)
    }

    fn is_transition(self, local_only: bool) -> bool {
        !local_only && matches!(self, Self::FirstRow | Self::Transition | Self::Boundary)
    }

    /// Returns the number of concrete trace rows materialized for this phase.
    ///
    /// `FirstRow` and `Transition` use 3 rows so we can re-run the AIR on
    /// `(row1, row2)` and prove that the exposed successor row is itself locally
    /// feasible. `Boundary` stops at 2 rows because its successor is padding and
    /// is not exposed.
    pub fn row_count(self, local_only: bool) -> usize {
        if local_only {
            1
        } else if self.requires_shifted_eval(local_only) {
            3
        } else {
            2
        }
    }

    /// Returns whether this phase needs a shifted second AIR evaluation.
    ///
    /// The shifted pass reinterprets the exposed successor row as the local row
    /// of a fresh transition window to prove that successor is itself feasible.
    pub fn requires_shifted_eval(self, local_only: bool) -> bool {
        !local_only && matches!(self, Self::FirstRow | Self::Transition)
    }

    /// Returns the phase semantics used by the shifted AIR pass, if any.
    ///
    /// The shifted pass treats the exposed successor row as an ordinary interior
    /// row. This intentionally drops `FirstRow` semantics on the second eval.
    pub fn shifted_eval_phase(self, local_only: bool) -> Option<Self> {
        self.requires_shifted_eval(local_only).then_some(Self::Transition)
    }

    fn exposes_transition_inputs(self, local_only: bool) -> bool {
        !local_only
            && matches!(self, Self::FirstRow | Self::Transition | Self::Boundary | Self::LastRow)
    }

    /// Returns whether this phase should export the immediate successor row as outputs.
    ///
    /// `Boundary` deliberately returns `false`: its successor is padding and
    /// should remain existential.
    pub fn exposes_next_row_outputs(self, local_only: bool) -> bool {
        !local_only && matches!(self, Self::FirstRow | Self::Transition)
    }

    /// The synthesized second row is partially specialized only when the phase
    /// already determines whether that row is real.
    fn next_is_real(self) -> Option<u64> {
        match self {
            Self::FirstRow | Self::Transition => Some(1),
            Self::Boundary => Some(0),
            Self::SingleRow | Self::LastRow => None,
        }
    }
}

/// `AirBuilder` implementation that lowers one chip/phase view into a Picus module.
#[derive(Clone)]
pub struct PicusBuilder<'chips, A: MachineAir<Felt>> {
    pub preprocessed: RowMajorMatrix<PicusAtom>,
    pub main: RowMajorMatrix<PicusAtom>,
    pub public_values: Vec<PicusAtom>,
    pub picus_module: PicusModule,
    pub global_send_outputs: Vec<PicusExpr>,
    pub aux_modules: BTreeMap<String, PicusModule>,
    pub chips: &'chips [Chip<Felt, A>],
    pub extract_modularly: bool,
    pub submodule_mode: SubmoduleMode,
    pub shr_carry_summary_mode: ShrCarrySummaryMode,
    pub phase: ExtractionPhase,
    pub local_only: bool,
    /// Hidden witness rows used by shifted re-evaluation should add
    /// constraints, but must not leak new module interface ports.
    pub capture_interface: bool,
    /// Fixed assignments used to specialize expressions during extraction.
    /// This allows opcodes/selectors to fold to constants before dispatch logic.
    pub specialization_env: BTreeMap<usize, u64>,
    pub concrete_pending_tasks: Vec<ConcretePendingTask>,
    pub symbolic_pending_tasks: Vec<SymbolicPendingTask>,
}

#[derive(Clone)]
pub struct ConcretePendingTask {
    pub chip_name: String,
    pub main_vars: Vec<PicusAtom>,
    pub multiplicity: PicusExpr,
    pub selector: String,
    pub capture_interface: bool,
}

impl ConcretePendingTask {
    /// Returns the concrete Picus variable id assigned to a target chip column.
    ///
    /// Deferred sub-chip extraction stores a concrete main-row assignment for the
    /// callee chip. This helper maps a column index in that callee back to the
    /// variable id used in the caller's module.
    pub fn get_actual_var_num_for_col(&self, col_num: usize) -> usize {
        assert!(col_num < self.main_vars.len());
        let main_var = self.main_vars[col_num];
        match main_var {
            PicusAtom::Var(v) => v,
            PicusAtom::Const(_) => panic!("Expected a variable not a constant"),
        }
    }
}

#[derive(Clone)]
pub struct SymbolicPendingTask {
    pub selector: PicusExpr,
    pub multiplicity: PicusExpr,
    pub capture_interface: bool,
}

impl<'chips, A: MachineAir<Felt>> PicusBuilder<'chips, A> {
    /// Builds a Picus extraction builder for one chip under one phase/environment.
    ///
    /// The builder materializes the trace rows needed by `phase`, optionally
    /// specializes selected columns to constants, and records whether this pass
    /// should contribute interface ports or only additional constraints.
    pub fn new(
        chip_to_analyze: &'chips Chip<Felt, A>,
        picus_module: PicusModule,
        chips: &'chips [Chip<Felt, A>],
        main_vars: Option<Vec<PicusAtom>>,
        specialization_env: Option<BTreeMap<usize, u64>>,
        submodule_mode: Option<SubmoduleMode>,
        shr_carry_summary_mode: Option<ShrCarrySummaryMode>,
        phase: Option<ExtractionPhase>,
        capture_interface: Option<bool>,
    ) -> Self {
        let width = chip_to_analyze.air.width();
        let specialization_env = specialization_env.unwrap_or_default();
        let phase = phase.unwrap_or(ExtractionPhase::SingleRow);
        let local_only = chip_to_analyze.local_only();
        let capture_interface = capture_interface.unwrap_or(true);
        // Initialize the public values.
        let public_values = (0..ZKM_PROOF_NUM_PV_ELTS).map(PicusAtom::new_var).collect();
        // Initialize the preprocessed and main traces.
        let row: Vec<PicusAtom> =
            (0..chip_to_analyze.preprocessed_width()).map(PicusAtom::new_var).collect();
        let preprocessed = DenseMatrix::new_row(row);
        let mut main = if let Some(vars) = main_vars {
            assert_eq!(vars.len(), width);
            vars
        } else {
            (0..width).map(PicusAtom::new_var).collect()
        };
        if !local_only {
            for row_idx in 1..phase.row_count(local_only) {
                let mut next_row = (0..width).map(|_| fresh_picus_var()).collect::<Vec<_>>();
                // Only the immediate successor row participates in the primary
                // phase interface. Later rows exist solely to witness the shifted
                // AIR pass and remain fully existential.
                if row_idx == 1 {
                    if let Some(next_is_real) = phase.next_is_real() {
                        if let Some(is_real_idx) = chip_to_analyze.picus_info().is_real_index {
                            next_row[is_real_idx] = PicusAtom::Const(next_is_real);
                        }
                    }
                }
                main.extend(next_row);
            }
        }
        // Specialize main-row variables to constants for this extraction pass.
        // We key by variable id instead of column index so this also works for
        // sub-chip builders whose main vars may be remapped.
        for atom in &mut main {
            if let PicusAtom::Var(v) = atom {
                if let Some(value) = specialization_env.get(v) {
                    *atom = PicusAtom::Const(*value);
                }
            }
        }
        let aux_modules = BTreeMap::new();
        Self {
            preprocessed,
            main: RowMajorMatrix::new(main, width),
            public_values,
            picus_module,
            global_send_outputs: Vec::new(),
            aux_modules,
            chips,
            extract_modularly: false,
            submodule_mode: submodule_mode.unwrap_or(SubmoduleMode::Inline),
            shr_carry_summary_mode: shr_carry_summary_mode
                .unwrap_or(ShrCarrySummaryMode::AbstractModule),
            phase,
            local_only,
            capture_interface,
            specialization_env,
            concrete_pending_tasks: Vec::new(),
            symbolic_pending_tasks: Vec::new(),
        }
    }

    fn specialize_expr(&self, expr: &PicusExpr) -> PicusExpr {
        if self.specialization_env.is_empty() {
            expr.clone()
        } else {
            partial_evaluate_expr(expr, &self.specialization_env)
        }
    }

    fn is_selector_module_builder(&self) -> bool {
        self.submodule_mode == SubmoduleMode::Ignore
    }

    fn push_input_port(&mut self, expr: PicusExpr) {
        if self.capture_interface {
            self.picus_module.inputs.push(expr);
        }
    }

    fn push_output_port(&mut self, expr: PicusExpr) {
        if self.capture_interface {
            self.picus_module.outputs.push(expr);
        }
    }

    fn push_global_output_port(&mut self, expr: PicusExpr) {
        if self.capture_interface {
            self.picus_module.outputs.push(expr.clone());
            self.global_send_outputs.push(expr);
        }
    }

    fn add_guarded_constraint(&mut self, is_real: PicusExpr, constraint: PicusConstraint) {
        match is_real {
            PicusExpr::Const(0) => {}
            PicusExpr::Const(1) => self.picus_module.constraints.push(constraint),
            _ => self.picus_module.constraints.push(constraint.apply_multiplier(is_real)),
        }
    }

    fn and_constraints(
        left: PicusConstraint,
        right: PicusConstraint,
        rest: impl IntoIterator<Item = PicusConstraint>,
    ) -> PicusConstraint {
        rest.into_iter().fold(PicusConstraint::And(Box::new(left), Box::new(right)), |acc, next| {
            PicusConstraint::And(Box::new(acc), Box::new(next))
        })
    }

    fn expose_row_ranges_as_outputs(&mut self, row_idx: usize, ranges: &[(usize, usize, String)]) {
        if !self.capture_interface {
            return;
        }
        let width = self.main.width();
        let row = self.main.row_slice(row_idx);
        for (start, end, _) in ranges {
            assert!(*start <= *end && *end <= width);
            for col_idx in *start..*end {
                let expr: PicusExpr = row[col_idx].into();
                if !self.picus_module.outputs.contains(&expr) {
                    self.picus_module.outputs.push(expr);
                }
            }
        }
    }

    fn expose_row_ranges_as_inputs(&mut self, row_idx: usize, ranges: &[(usize, usize, String)]) {
        if !self.capture_interface {
            return;
        }
        let width = self.main.width();
        let row = self.main.row_slice(row_idx);
        for (start, end, _) in ranges {
            assert!(*start <= *end && *end <= width);
            for col_idx in *start..*end {
                let expr: PicusExpr = row[col_idx].into();
                if !self.picus_module.inputs.contains(&expr) {
                    self.picus_module.inputs.push(expr);
                }
            }
        }
    }

    /// Exposes the primary-row outputs explicitly annotated in `PicusInfo`.
    pub fn expose_annotated_primary_outputs(&mut self, output_ranges: &[(usize, usize, String)]) {
        self.expose_row_ranges_as_outputs(0, output_ranges);
    }

    /// Exposes carried state that must be supplied as inputs to this phase.
    ///
    /// Transition inputs always come from the current row, even for phases that
    /// also materialize successor rows.
    pub fn expose_transition_inputs(&mut self, transition_input_ranges: &[(usize, usize, String)]) {
        if !self.phase.exposes_transition_inputs(self.local_only) {
            return;
        }
        // Transition inputs always refer to the current row's carried state.
        self.expose_row_ranges_as_inputs(0, transition_input_ranges);
    }

    /// Exposes the immediate successor row's annotated transition outputs.
    ///
    /// Hidden witness rows used by shifted evaluation stay existential and are
    /// never surfaced through the module interface.
    pub fn expose_transition_outputs(
        &mut self,
        transition_output_ranges: &[(usize, usize, String)],
    ) {
        if self.local_only || !self.phase.exposes_next_row_outputs(self.local_only) {
            return;
        }
        // Only expose the immediate successor row. Any third row is existential
        // support for the shifted AIR evaluation and should stay hidden.
        self.expose_row_ranges_as_outputs(1, transition_output_ranges);
    }

    /// Exposes every primary-row column except those explicitly marked as inputs.
    ///
    /// This is the broadest output mode and is intended for debugging or very
    /// aggressive interface generation.
    pub fn expose_primary_row_non_inputs_as_outputs(
        &mut self,
        input_ranges: &[(usize, usize, String)],
    ) {
        let width = self.main.width();
        let mut is_input = vec![false; width];
        for (start, end, _) in input_ranges {
            assert!(*start <= *end && *end <= width);
            for idx in *start..*end {
                is_input[idx] = true;
            }
        }

        for (col_idx, atom) in self.main.row_slice(0).iter().enumerate() {
            if is_input[col_idx] {
                continue;
            }
            let expr: PicusExpr = (*atom).into();
            if !self.picus_module.outputs.contains(&expr) {
                self.picus_module.outputs.push(expr);
            }
        }
    }

    /// Exposes the entire immediate successor row as outputs.
    ///
    /// This is only used by the broad `AllNonInputsAreOutputs` mode and still
    /// stops at the immediate successor row.
    pub fn expose_full_next_row_as_outputs(&mut self) {
        if self.local_only || !self.phase.exposes_next_row_outputs(self.local_only) {
            return;
        }
        for atom in self.main.row_slice(1).iter() {
            let expr: PicusExpr = (*atom).into();
            if !self.picus_module.outputs.contains(&expr) {
                self.picus_module.outputs.push(expr);
            }
        }
    }

    /// Precise summary for ByteOpcode::ShrCarry.
    ///
    /// Inputs/outputs follow byte interaction ordering:
    /// - values[1] = out
    /// - values[2] = carry
    /// - values[3] = input
    /// - values[4] = num_bits_to_shift
    ///
    /// Semantics:
    /// - num_bits_to_shift in [0, 7]
    /// - out, carry are bytes
    /// - if shift = 0: out = input and carry = 0
    /// - if shift = i > 0: input = out * 2^i + carry and carry < 2^i
    fn summarize_shr_carry_precise(&mut self, multiplicity: PicusExpr, values: &[PicusExpr]) {
        let out = values[1].clone();
        let carry = values[2].clone();
        let input = values[3].clone();
        let num_bits_to_shift = values[4].clone();

        // Base range constraints.
        self.picus_module.constraints.push(PicusConstraint::new_leq(
            out.clone() * multiplicity.clone(),
            PicusExpr::Const(255),
        ));
        self.picus_module.constraints.push(PicusConstraint::new_leq(
            input.clone() * multiplicity.clone(),
            PicusExpr::Const(255),
        ));
        self.picus_module.constraints.push(PicusConstraint::new_leq(
            carry.clone() * multiplicity.clone(),
            PicusExpr::Const(255),
        ));
        self.picus_module.constraints.push(PicusConstraint::new_leq(
            num_bits_to_shift.clone() * multiplicity.clone(),
            PicusExpr::Const(7),
        ));

        // Case split by shift amount i in [0, 7].
        for i in 0..8u64 {
            let cond =
                PicusConstraint::new_equality(num_bits_to_shift.clone(), PicusExpr::Const(i));
            let consequence = if i == 0 {
                PicusConstraint::And(
                    Box::new(PicusConstraint::new_equality(out.clone(), input.clone())),
                    Box::new(PicusConstraint::new_equality(carry.clone(), PicusExpr::Const(0))),
                )
            } else {
                let p2 = 1u64 << i;
                PicusConstraint::And(
                    Box::new(PicusConstraint::new_equality(
                        input.clone(),
                        out.clone() * PicusExpr::Const(p2) + carry.clone(),
                    )),
                    Box::new(PicusConstraint::new_lt(
                        carry.clone() * multiplicity.clone(),
                        PicusExpr::Const(p2),
                    )),
                )
            };
            self.picus_module
                .constraints
                .push(PicusConstraint::Implies(Box::new(cond), Box::new(consequence)));
        }
    }

    fn is_default_bitwise_byte_opcode(opcode: u64) -> bool {
        matches!(
            opcode,
            x if x == ByteOpcode::AND as u64
                || x == ByteOpcode::OR as u64
                || x == ByteOpcode::XOR as u64
                || x == ByteOpcode::NOR as u64
        )
    }

    fn add_default_bitwise_byte_call(&mut self, values: &[PicusExpr]) {
        let byte_mod_name = "byte_interaction_mod".to_string();
        if !self.aux_modules.contains_key(&byte_mod_name) {
            let byte_mod = PicusModule::build_empty(byte_mod_name.clone(), 2, 1);
            self.aux_modules.insert(byte_mod_name.clone(), byte_mod);
        }
        assert!(values.len() == 5);
        self.picus_module.calls.push(PicusCall::new(byte_mod_name, &values[1..2], &values[3..5]));
    }

    fn try_add_and_127_optimization(&mut self, values: &[PicusExpr]) -> bool {
        if !matches!(values[0], PicusExpr::Const(v) if v == ByteOpcode::AND as u64) {
            return false;
        }
        if !matches!(values[4], PicusExpr::Const(127)) {
            return false;
        }

        let var_hi = fresh_picus_expr();
        self.picus_module.constraints.push(PicusConstraint::new_lt(values[1].clone(), 128.into()));
        self.picus_module.constraints.push(PicusConstraint::new_bit(var_hi.clone()));
        self.picus_module.constraints.push(PicusConstraint::new_equality(
            values[3].clone(),
            var_hi * 128 + values[1].clone(),
        ));
        true
    }

    /// Looks up a chip by name in the extraction universe.
    ///
    /// The extractor keeps chips in a flat slice because the total count is
    /// small, so a linear scan is sufficient here.
    pub fn get_chip(&self, name: &str) -> &'chips Chip<Felt, A> {
        self.chips
            .iter()
            .find(|c| c.name() == name)
            .unwrap_or_else(|| panic!("No chip found named {name}"))
    }

    // Picus does not have native support for interactions so we need to convert the interaction
    // to Picus constructs. Most byte interactions appear to be range constraints
    fn handle_byte_interaction(&mut self, multiplicity: PicusExpr, values: &[PicusExpr]) {
        match values[0] {
            PicusExpr::Const(v) => {
                if v == (ByteOpcode::U8Range as u64) {
                    for val in &values[1..] {
                        if let PicusExpr::Const(v) = val {
                            assert!(*v < 256);
                            continue;
                        } else {
                            self.picus_module.constraints.push(PicusConstraint::new_leq(
                                val.clone() * multiplicity.clone(),
                                255.into(),
                            ))
                        }
                    }
                } else if v == (ByteOpcode::U16Range as u64) {
                    for val in &values[1..] {
                        if let PicusExpr::Const(v) = val {
                            assert!(*v < 65536);
                            continue;
                        } else {
                            self.picus_module.constraints.push(PicusConstraint::new_leq(
                                val.clone() * multiplicity.clone(),
                                65535.into(),
                            ))
                        }
                    }
                } else if v == (ByteOpcode::MSB as u64) {
                    let msb = values[1].clone();
                    let bytes = [values[3].clone(), values[4].clone()];
                    let picus127_const = PicusExpr::Const(127);
                    for byte in &bytes {
                        if let PicusExpr::Const(0) = byte {
                            continue;
                        }
                        let fresh_picus_var: PicusExpr = fresh_picus_expr();
                        self.picus_module.constraints.push(PicusConstraint::new_leq(
                            fresh_picus_var.clone() * multiplicity.clone(),
                            picus127_const.clone(),
                        ));
                        self.picus_module.constraints.push(PicusConstraint::Eq(Box::new(
                            multiplicity.clone()
                                * msb.clone()
                                * (msb.clone() - PicusExpr::Const(1)),
                        )));
                        let decomp =
                            byte.clone() - (msb.clone() * PicusExpr::Const(128) + fresh_picus_var);
                        self.picus_module
                            .constraints
                            .push(PicusConstraint::Eq(Box::new(multiplicity.clone() * decomp)));
                    }
                } else if v == (ByteOpcode::ShrCarry as u64) {
                    match self.shr_carry_summary_mode {
                        ShrCarrySummaryMode::AbstractModule => {
                            if !self.aux_modules.contains_key("ShrCarry") {
                                let carry_module =
                                    PicusModule::build_empty("ShrCarry".to_string(), 2, 2);
                                self.aux_modules.insert("ShrCarry".to_string(), carry_module);
                            }
                            let shrcarry = PicusCall::new(
                                "ShrCarry".to_string(),
                                &[values[1].clone(), values[2].clone()],
                                &[values[3].clone(), values[4].clone()],
                            );
                            self.picus_module.calls.push(shrcarry);
                        }
                        ShrCarrySummaryMode::Precise => {
                            self.summarize_shr_carry_precise(multiplicity.clone(), values);
                        }
                    }
                } else if v == (ByteOpcode::LTU as u64) {
                    let lt_const = PicusConstraint::new_lt(values[2].clone(), values[3].clone());
                    if let PicusExpr::Const(1) = values[1] {
                        self.picus_module.constraints.push(lt_const);
                    } else {
                        let bit_const = PicusConstraint::new_bit(values[1].clone());
                        let eq_one = PicusConstraint::new_equality(values[1].clone(), 1.into());
                        self.picus_module.constraints.extend_from_slice(&[
                            PicusConstraint::Iff(Box::new(eq_one), Box::new(lt_const)),
                            bit_const,
                        ]);
                    }
                } else if Self::is_default_bitwise_byte_opcode(v)
                    && !self.try_add_and_127_optimization(values)
                {
                    self.add_default_bitwise_byte_call(values);
                }
            }
            // TODO: It might be fine if the first argument isn't a constant. We need to multiply the values
            // in the interaction with the multiplicities
            _ => {
                // if the interaction isn't constant then the only case that should happen
                // is if we are building the selector module where our selectors are variables and not
                // constants. As such, we don't care about these interactions since all the selector constraints
                // are not interaction dependent.
                if !self.is_selector_module_builder() {
                    panic!(
                        "byte lookup first argument is not a constant {:?}!",
                        self.picus_module.name
                    )
                }
            }
        }
    }

    // The receive instruction interaction is used to determine which columns are inputs/outputs.
    // In particular, the following values correspond to inputs and outputs:
    //    - values[2] -> pc (input)
    //    - values[3] -> next_pc (output)
    //    - values[4] -> next_next_pc (output)
    //    - values[6] -> opcode (assume deterministic)
    //    - values[7-10] -> a (input iff op_a_immutable = 1, else output)
    //    - values[11-14] -> b (input)
    //    - values[15-18] -> c (input)
    //    - values[19-22] -> hi (input iff is_rw_a = 1, else output)
    fn handle_receive_instruction(&mut self, multiplicity: PicusExpr, values: &[PicusExpr]) {
        // Inactive receives should not contribute any constraints or ports.
        if matches!(multiplicity, PicusExpr::Const(0)) {
            return;
        }
        // Creating a fresh var because picus outputs need to be variables.
        // When performing partial evaluation,
        let eq_mul = |multiplicity: &PicusExpr, val: &PicusExpr, var: &PicusExpr| {
            PicusConstraint::new_equality(var.clone(), val.clone() * multiplicity.clone())
        };
        let u8_range =
            |var: &PicusExpr| PicusConstraint::new_leq(var.clone(), PicusExpr::Const(255));
        // handle pc constraints
        {
            // get the pc value
            let pc_val = values[2].clone();
            // make sure the pc is either a constant or variable
            assert!(matches!(pc_val, PicusExpr::Const(_) | PicusExpr::Var(_)));
            if let PicusExpr::Var(_) = pc_val {
                // if the pc is a variable we mark it as an input
                self.push_input_port(pc_val.clone());
            }
            // allocate a fresh var for pc out
            let next_pc_out = fresh_picus_expr();
            // mark it as an output
            self.push_output_port(next_pc_out.clone());
            // assign it conditionally to the corresponding element in the value array
            self.picus_module.constraints.push(eq_mul(&multiplicity, &values[3], &next_pc_out));
            // the cpu table should constrain next_pc = pc + 4 always due to delay-slot semantics of MIPS
            // so we add that constraint here
            self.picus_module.constraints.push(PicusConstraint::new_equality(
                values[3].clone(),
                pc_val.clone() + PicusExpr::Const(4),
            ));
        }
        // We assume the opcode is deterministic
        self.picus_module.assume_deterministic.push(values[6].clone());
        // values[23] is op_a_immutable and values[24] is is_rw_a.
        // Require concrete booleans so I/O direction is unambiguous.
        let op_a_immutable = match values[23] {
            PicusExpr::Const(0) => false,
            PicusExpr::Const(1) => true,
            PicusExpr::Const(v) => panic!("Expected op_a_immutable to be 0 or 1, got {v}"),
            _ => panic!("Expected op_a_immutable to be constant (0/1), got symbolic expression"),
        };
        let is_rw_a = match values[24] {
            PicusExpr::Const(0) => false,
            PicusExpr::Const(1) => true,
            PicusExpr::Const(v) => panic!("Expected is_rw_a to be 0 or 1, got {v}"),
            _ => panic!("Expected is_rw_a to be constant (0/1), got symbolic expression"),
        };
        // Always expose `next_next_pc` as an output; it is often zero but still part of the
        // instruction interface.
        let next_next_pc_out = fresh_picus_expr();
        self.picus_module.constraints.push(eq_mul(&multiplicity, &values[4], &next_next_pc_out));
        self.push_output_port(next_next_pc_out);
        // We need to mark some of the register values as inputs and other values as outputs.
        // In particular, the parameters `b` and `c` to `receive_instruction` are inputs and
        // parameter `a` is an output when `is_sequential` is 1. `b` and `c` are at indexes 11-14 and 15-18 in `values` whereas
        // `a` is at indexes 7-10. As in the code above, we need to create variables for the outputs since
        // Picus requires the inputs and outputs to be variables.
        for value in values.iter().take(11).skip(7) {
            let a_var = fresh_picus_expr();
            if op_a_immutable {
                self.push_input_port(a_var.clone());
            } else {
                self.push_output_port(a_var.clone());
            }
            self.picus_module.constraints.push(eq_mul(&multiplicity, value, &a_var));
            // Mirrors CPU's limb range check: crates/core/machine/src/cpu/air/register.rs
            // (`builder.slice_range_check_u8(&local.op_a_access.access.value.0, local.is_real)`).
            self.picus_module.constraints.push(u8_range(&a_var));
        }
        for value in values.iter().take(15).skip(11) {
            let b_var = fresh_picus_expr();
            self.push_input_port(b_var.clone());
            self.picus_module.constraints.push(eq_mul(&multiplicity, value, &b_var));
        }
        for value in values.iter().take(19).skip(15) {
            let c_var = fresh_picus_expr();
            self.push_input_port(c_var.clone());
            self.picus_module.constraints.push(eq_mul(&multiplicity, value, &c_var));
        }
        // Route HI values by is_rw_a.
        for value in values.iter().take(23).skip(19) {
            let hi_var = fresh_picus_expr();
            if is_rw_a {
                self.push_input_port(hi_var.clone());
            } else {
                self.push_output_port(hi_var.clone());
            }
            self.picus_module.constraints.push(eq_mul(&multiplicity, value, &hi_var));
        }
    }

    // Memory lookups are encoded as:
    //   [shard/prev_shard, clk/prev_clk, addr, value_0, value_1, ...]
    // For extraction we intentionally ignore shard/clk and only expose addr + value limbs.
    // `send` corresponds to a read (input) while `receive` corresponds to a write (output).
    fn handle_memory_interaction(
        &mut self,
        multiplicity: PicusExpr,
        values: &[PicusExpr],
        is_send: bool,
    ) {
        if matches!(multiplicity, PicusExpr::Const(0)) {
            return;
        }
        assert!(values.len() >= 4, "Expected memory lookup to include addr + value limbs");

        let eq_mul = |multiplicity: &PicusExpr, val: &PicusExpr, var: &PicusExpr| {
            PicusConstraint::new_equality(var.clone(), val.clone() * multiplicity.clone())
        };

        let addr_var = fresh_picus_expr();
        if is_send {
            self.push_input_port(addr_var.clone());
        } else {
            self.push_output_port(addr_var.clone());
        }
        self.picus_module.constraints.push(eq_mul(&multiplicity, &values[2], &addr_var));

        for value in values.iter().skip(3) {
            let value_var = fresh_picus_expr();
            if is_send {
                self.push_input_port(value_var.clone());
                self.picus_module
                    .constraints
                    .push(PicusConstraint::new_lt(value_var.clone(), PicusExpr::Const(255)));
            } else {
                self.push_output_port(value_var.clone());
            }
            self.picus_module.constraints.push(eq_mul(&multiplicity, value, &value_var));
        }
    }

    fn handle_receive_syscall(&mut self, multiplicity: PicusExpr, values: &[PicusExpr]) {
        if matches!(multiplicity, PicusExpr::Const(0)) {
            return;
        }
        assert_eq!(values.len(), 5, "Expected syscall lookup to contain 5 values");

        let eq_mul = |multiplicity: &PicusExpr, val: &PicusExpr, var: &PicusExpr| {
            PicusConstraint::new_equality(var.clone(), val.clone() * multiplicity.clone())
        };

        let syscall_id_var = fresh_picus_expr();
        self.push_input_port(syscall_id_var.clone());
        self.picus_module.constraints.push(eq_mul(&multiplicity, &values[2], &syscall_id_var));

        for value in values.iter().skip(3) {
            let input_var = fresh_picus_expr();
            self.push_input_port(input_var.clone());
            self.picus_module.constraints.push(eq_mul(&multiplicity, value, &input_var));
        }
    }

    fn handle_receive_global(&mut self, multiplicity: PicusExpr, values: &[PicusExpr]) {
        if matches!(multiplicity, PicusExpr::Const(0)) {
            return;
        }

        let eq_mul = |multiplicity: &PicusExpr, val: &PicusExpr, var: &PicusExpr| {
            PicusConstraint::new_equality(var.clone(), val.clone() * multiplicity.clone())
        };

        for value in values {
            let input_var = fresh_picus_expr();
            self.push_input_port(input_var.clone());
            self.picus_module.constraints.push(eq_mul(&multiplicity, value, &input_var));
        }
    }

    fn handle_send_global(&mut self, multiplicity: PicusExpr, values: &[PicusExpr]) {
        if matches!(multiplicity, PicusExpr::Const(0)) {
            return;
        }

        let eq_mul = |multiplicity: &PicusExpr, val: &PicusExpr, var: &PicusExpr| {
            PicusConstraint::new_equality(var.clone(), val.clone() * multiplicity.clone())
        };

        for value in values {
            let output_var = fresh_picus_expr();
            self.push_global_output_port(output_var.clone());
            self.picus_module.constraints.push(eq_mul(&multiplicity, value, &output_var));
        }
    }

    fn add_abstract_syscall_call(&mut self, multiplicity: PicusExpr, values: &[PicusExpr]) {
        let module_name = "SyscallLookup".to_string();
        if !self.aux_modules.contains_key(&module_name) {
            // Picus requires modules to expose at least one output, even for abstract summaries.
            let syscall_module = PicusModule::build_empty(module_name.clone(), values.len(), 1);
            self.aux_modules.insert(module_name.clone(), syscall_module);
        }

        let inputs =
            values.iter().map(|value| value.clone() * multiplicity.clone()).collect::<Vec<_>>();
        let dummy_output = fresh_picus_expr();
        self.picus_module.calls.push(PicusCall::new(module_name, &[dummy_output], &inputs));
    }

    fn get_main_vars_for_named_call(
        &mut self,
        chip_name: &str,
        arg_to_colname: &[(IndexSlice, &'static str)],
        message_values: &[PicusExpr],
    ) -> Option<Vec<PicusAtom>> {
        let target_chip = self.get_chip(chip_name);
        let mut target_main_vals: Vec<PicusAtom> =
            (0..target_chip.air.width()).map(|_| fresh_picus_var()).collect();

        let target_picus_info = target_chip.picus_info();
        for (slice, name) in arg_to_colname {
            let colrange = target_picus_info.name_to_colrange.get(*name).unwrap();
            match *slice {
                IndexSlice::Range { start, end } => {
                    assert!(colrange.1 - colrange.0 >= end - start);
                    for i in start..end {
                        if let PicusExpr::Var(v) = message_values[i].clone() {
                            target_main_vals[colrange.0 + i - start] = PicusAtom::Var(v);
                        } else if let PicusExpr::Const(c) = message_values[i].clone() {
                            target_main_vals[colrange.0 + i - start] = PicusAtom::Const(c);
                        } else {
                            let id = fresh_picus_var_id();
                            let fresh_var = PicusAtom::Var(id);
                            self.picus_module.constraints.push(PicusConstraint::new_equality(
                                PicusExpr::Var(id),
                                message_values[i].clone(),
                            ));
                            target_main_vals[colrange.0 + i - start] = fresh_var;
                        }
                    }
                }
                IndexSlice::Single(col) => {
                    assert_eq!(colrange.1 - colrange.0, 1);
                    if let PicusExpr::Var(v) = message_values[col].clone() {
                        target_main_vals[colrange.0] = PicusAtom::Var(v);
                    } else if let PicusExpr::Const(c) = message_values[col].clone() {
                        target_main_vals[colrange.0] = PicusAtom::Const(c);
                    } else {
                        let fresh_var = fresh_picus_var_id();
                        self.picus_module.constraints.push(PicusConstraint::new_equality(
                            PicusExpr::Var(fresh_var),
                            message_values[col].clone(),
                        ));
                        target_main_vals[colrange.0] = PicusAtom::Var(fresh_var);
                    }
                }
            }
        }
        Some(target_main_vals)
    }

    fn get_main_vars_for_call(&mut self, message_values: &[PicusExpr]) -> Option<Vec<PicusAtom>> {
        let opcode_spec = match message_values[6].clone() {
            PicusExpr::Const(v) => {
                assert!(v < Opcode::UNIMPL as u64);
                spec_for(Opcode::try_from(v as u8).unwrap())
            }
            _ => panic!("Opcode should be constant"),
        };
        self.get_main_vars_for_named_call(
            opcode_spec.chip,
            opcode_spec.arg_to_colname,
            message_values,
        )
    }
}

impl<'chips, A: MachineAir<Felt>> PairBuilder for PicusBuilder<'chips, A> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed.clone()
    }
}

impl<'chips, A: MachineAir<Felt>> AirBuilderWithPublicValues for PicusBuilder<'chips, A> {
    type PublicVar = PicusAtom;

    fn public_values(&self) -> &[Self::PublicVar] {
        &self.public_values
    }
}

impl<'chips, A: MachineAir<Felt>> MessageBuilder<AirLookup<PicusExpr>> for PicusBuilder<'chips, A> {
    fn send(&mut self, message: AirLookup<PicusExpr>, _scope: zkm_stark::LookupScope) {
        // Apply specialization first so opcode routing can see concrete values whenever
        // selector assignments make them decidable.
        let specialized_values: Vec<PicusExpr> =
            message.values.iter().map(|expr| self.specialize_expr(expr)).collect();
        let specialized_multiplicity = self.specialize_expr(&message.multiplicity);
        match message.kind {
            LookupKind::Byte => {
                self.handle_byte_interaction(specialized_multiplicity, &specialized_values);
            }
            LookupKind::Memory => {
                self.handle_memory_interaction(specialized_multiplicity, &specialized_values, true);
            }
            LookupKind::Instruction => {
                if self.submodule_mode == SubmoduleMode::Ignore {
                    return;
                }
                let opcode_spec = match specialized_values[6].clone() {
                    PicusExpr::Const(v) => {
                        assert!(v < Opcode::UNIMPL as u64);
                        spec_for(Opcode::try_from(v as u8).unwrap())
                    }
                    _ => panic!(
                        "Expected opcode val to be a constant after specialization: Got: {}",
                        specialized_values[6]
                    ),
                };
                let target_chip = self.get_chip(opcode_spec.chip);
                let main_vars = self.get_main_vars_for_call(&specialized_values);
                if let Some(vars) = main_vars {
                    self.concrete_pending_tasks.push(ConcretePendingTask {
                        chip_name: target_chip.name(),
                        main_vars: vars,
                        multiplicity: specialized_multiplicity,
                        selector: opcode_spec.selector.to_string(),
                        capture_interface: self.capture_interface,
                    });
                } else {
                    self.symbolic_pending_tasks.push(SymbolicPendingTask {
                        selector: specialized_values[6].clone(),
                        multiplicity: specialized_multiplicity,
                        capture_interface: self.capture_interface,
                    })
                }
            }
            LookupKind::Syscall => {
                if matches!(specialized_multiplicity, PicusExpr::Const(0)) {
                    return;
                }

                if self.submodule_mode == SubmoduleMode::Ignore {
                    return;
                }

                if let Some(syscall_spec) = spec_for_sender(&self.picus_module.name) {
                    let main_vars = self.get_main_vars_for_named_call(
                        syscall_spec.chip,
                        syscall_spec.arg_to_colname,
                        &specialized_values,
                    );
                    if let Some(vars) = main_vars {
                        self.concrete_pending_tasks.push(ConcretePendingTask {
                            chip_name: syscall_spec.chip.to_string(),
                            main_vars: vars,
                            multiplicity: specialized_multiplicity,
                            selector: syscall_spec.selector.to_string(),
                            capture_interface: self.capture_interface,
                        });
                        return;
                    }
                }

                self.add_abstract_syscall_call(specialized_multiplicity, &specialized_values);
            }
            LookupKind::Global => {
                if matches!(specialized_multiplicity, PicusExpr::Const(0))
                    || self.submodule_mode == SubmoduleMode::Ignore
                {
                    return;
                }

                self.handle_send_global(specialized_multiplicity, &specialized_values);
            }
            _ => todo!("handle send: {}", message.kind),
        }
    }

    fn receive(&mut self, message: AirLookup<PicusExpr>, _scope: zkm_stark::LookupScope) {
        // initialize another chip
        // call eval with builder?
        let specialized_values: Vec<PicusExpr> =
            message.values.iter().map(|expr| self.specialize_expr(expr)).collect();
        let specialized_multiplicity = self.specialize_expr(&message.multiplicity);
        match message.kind {
            LookupKind::Instruction => {
                if self.submodule_mode == SubmoduleMode::Ignore {
                    self.picus_module.assume_deterministic.push(specialized_values[6].clone());
                    return;
                }
                self.handle_receive_instruction(specialized_multiplicity, &specialized_values);
            }
            LookupKind::Memory => {
                self.handle_memory_interaction(
                    specialized_multiplicity,
                    &specialized_values,
                    false,
                );
            }
            LookupKind::Syscall => {
                self.handle_receive_syscall(specialized_multiplicity, &specialized_values);
            }
            LookupKind::Global => {
                self.handle_receive_global(specialized_multiplicity, &specialized_values);
            }
            _ => todo!("handle receive: {}", message.kind),
        }
    }
}

impl<'chips, A: MachineAir<Felt>> OperationSummaryAirBuilder for PicusBuilder<'chips, A> {
    fn try_emit_is_zero_summary(
        &mut self,
        input: Self::Expr,
        result: Self::Expr,
        is_real: Self::Expr,
    ) -> bool {
        self.add_guarded_constraint(is_real.clone(), PicusConstraint::new_bit(result.clone()));
        self.add_guarded_constraint(
            is_real.clone(),
            PicusConstraint::new_equality(result.clone() * input.clone(), PicusExpr::Const(0)),
        );
        self.add_guarded_constraint(
            is_real,
            PicusConstraint::Implies(
                Box::new(PicusConstraint::new_equality(input, PicusExpr::Const(0))),
                Box::new(PicusConstraint::new_equality(result, PicusExpr::Const(1))),
            ),
        );
        true
    }

    fn try_emit_is_zero_word_summary(
        &mut self,
        input: Word<Self::Expr>,
        is_lower_half_zero: Self::Expr,
        is_upper_half_zero: Self::Expr,
        result: Self::Expr,
        is_real: Self::Expr,
    ) -> bool {
        for flag in [is_lower_half_zero.clone(), is_upper_half_zero.clone(), result.clone()] {
            self.add_guarded_constraint(is_real.clone(), PicusConstraint::new_bit(flag));
        }

        for limb in [input[0].clone(), input[1].clone()] {
            self.add_guarded_constraint(
                is_real.clone(),
                PicusConstraint::new_equality(
                    is_lower_half_zero.clone() * limb,
                    PicusExpr::Const(0),
                ),
            );
        }
        for limb in [input[2].clone(), input[3].clone()] {
            self.add_guarded_constraint(
                is_real.clone(),
                PicusConstraint::new_equality(
                    is_upper_half_zero.clone() * limb,
                    PicusExpr::Const(0),
                ),
            );
        }

        let lower_zero = Self::and_constraints(
            PicusConstraint::new_equality(input[0].clone(), PicusExpr::Const(0)),
            PicusConstraint::new_equality(input[1].clone(), PicusExpr::Const(0)),
            [],
        );
        let upper_zero = Self::and_constraints(
            PicusConstraint::new_equality(input[2].clone(), PicusExpr::Const(0)),
            PicusConstraint::new_equality(input[3].clone(), PicusExpr::Const(0)),
            [],
        );

        self.add_guarded_constraint(
            is_real.clone(),
            PicusConstraint::Implies(
                Box::new(lower_zero),
                Box::new(PicusConstraint::new_equality(
                    is_lower_half_zero.clone(),
                    PicusExpr::Const(1),
                )),
            ),
        );
        self.add_guarded_constraint(
            is_real.clone(),
            PicusConstraint::Implies(
                Box::new(upper_zero),
                Box::new(PicusConstraint::new_equality(
                    is_upper_half_zero.clone(),
                    PicusExpr::Const(1),
                )),
            ),
        );

        self.add_guarded_constraint(
            is_real,
            PicusConstraint::new_equality(result, is_lower_half_zero * is_upper_half_zero),
        );
        true
    }
}

impl<'chips, A: MachineAir<Felt>> AirBuilder for PicusBuilder<'chips, A> {
    type F = Felt;
    type Var = PicusAtom;
    type Expr = PicusExpr;

    type M = RowMajorMatrix<Self::Var>;

    fn main(&self) -> Self::M {
        self.main.clone()
    }

    fn is_first_row(&self) -> Self::Expr {
        PicusExpr::Const(self.phase.is_first_row().into())
    }

    fn is_last_row(&self) -> Self::Expr {
        PicusExpr::Const(self.phase.is_last_row().into())
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        if size == 2 {
            PicusExpr::Const(self.phase.is_transition(self.local_only).into())
        } else {
            panic!("PicusBuilder only supports a transition window size of 2")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.picus_module.constraints.push(PicusConstraint::Eq(Box::new(x.into())))
    }
}

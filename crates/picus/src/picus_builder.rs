use std::collections::BTreeMap;

use crate::{
    opcode_spec::{spec_for, IndexSlice},
    pcl::{
        fresh_picus_expr, fresh_picus_var, fresh_picus_var_id, partial_evaluate_expr, Felt,
        PicusAtom, PicusCall, PicusConstraint, PicusExpr, PicusModule,
    },
};
use p3_air::{AirBuilder, AirBuilderWithPublicValues, PairBuilder};
use p3_matrix::dense::{DenseMatrix, RowMajorMatrix};
use zkm_core_executor::{ByteOpcode, Opcode};
use zkm_stark::{AirLookup, Chip, LookupKind, MachineAir, MessageBuilder, ZKM_PROOF_NUM_PV_ELTS};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShrCarrySummaryMode {
    /// Keep ShrCarry abstract as a module call.
    AbstractModule,
    /// Lower ShrCarry into explicit case-split constraints.
    Precise,
}

/// Implementation `AirBuilder` which builds Picus programs
#[derive(Clone)]
pub struct PicusBuilder<'chips, A: MachineAir<Felt>> {
    pub preprocessed: RowMajorMatrix<PicusAtom>,
    pub main: RowMajorMatrix<PicusAtom>,
    pub public_values: Vec<PicusAtom>,
    pub picus_module: PicusModule,
    pub aux_modules: BTreeMap<String, PicusModule>,
    pub chips: &'chips [Chip<Felt, A>],
    pub extract_modularly: bool,
    pub submodule_mode: SubmoduleMode,
    pub shr_carry_summary_mode: ShrCarrySummaryMode,
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
}

impl ConcretePendingTask {
    // Gets the var number located at column `col_num` in the target chip
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
}

impl<'chips, A: MachineAir<Felt>> PicusBuilder<'chips, A> {
    /// Constructor for the builder
    pub fn new(
        chip_to_analyze: &'chips Chip<Felt, A>,
        picus_module: PicusModule,
        chips: &'chips [Chip<Felt, A>],
        main_vars: Option<Vec<PicusAtom>>,
        specialization_env: Option<BTreeMap<usize, u64>>,
        submodule_mode: Option<SubmoduleMode>,
        shr_carry_summary_mode: Option<ShrCarrySummaryMode>,
    ) -> Self {
        let width = chip_to_analyze.air.width();
        let specialization_env = specialization_env.unwrap_or_default();
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
            aux_modules,
            chips,
            extract_modularly: false,
            submodule_mode: submodule_mode.unwrap_or(SubmoduleMode::Inline),
            shr_carry_summary_mode: shr_carry_summary_mode
                .unwrap_or(ShrCarrySummaryMode::AbstractModule),
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

    /// Gets a chip by name or panics if no chip is found. Kept as a slice since the number of chips is small
    /// < 200
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
                } else if v == (ByteOpcode::AND as u64) {
                    if let PicusExpr::Const(127) = values[4] {
                        let var_hi = fresh_picus_expr();
                        self.picus_module
                            .constraints
                            .push(PicusConstraint::new_lt(values[1].clone(), 128.into()));
                        self.picus_module
                            .constraints
                            .push(PicusConstraint::new_bit(var_hi.clone()));
                        self.picus_module.constraints.push(PicusConstraint::new_equality(
                            values[3].clone(),
                            var_hi * 128 + values[1].clone(),
                        ));
                    }
                } else {
                    panic!("Unhandled byte interaction")
                }
            }
            // TODO: It might be fine if the first argument isn't a constant. We need to multiply the values
            // in the interaction with the multiplicities
            _ => {
                let byte_mod_name = "byte_interaction_mod".to_string();
                if !self.aux_modules.contains_key(&byte_mod_name) {
                    let byte_mod = PicusModule::build_empty(byte_mod_name.clone(), 2, 1);
                    self.aux_modules.insert(byte_mod_name.clone(), byte_mod);
                }
                assert!(values.len() == 5);
                self.picus_module.calls.push(PicusCall::new(
                    byte_mod_name.clone(),
                    &values[1..2],
                    &values[3..5],
                ));
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
                self.picus_module.inputs.push(pc_val.clone());
            }
            // allocate a fresh var for pc out
            let next_pc_out = fresh_picus_expr();
            // mark it as an output
            self.picus_module.outputs.push(next_pc_out.clone());
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
        self.picus_module.outputs.push(next_next_pc_out);
        // We need to mark some of the register values as inputs and other values as outputs.
        // In particular, the parameters `b` and `c` to `receive_instruction` are inputs and
        // parameter `a` is an output when `is_sequential` is 1. `b` and `c` are at indexes 11-14 and 15-18 in `values` whereas
        // `a` is at indexes 7-10. As in the code above, we need to create variables for the outputs since
        // Picus requires the inputs and outputs to be variables.
        for value in values.iter().take(11).skip(7) {
            let a_var = fresh_picus_expr();
            if op_a_immutable {
                self.picus_module.inputs.push(a_var.clone());
            } else {
                self.picus_module.outputs.push(a_var.clone());
            }
            self.picus_module.constraints.push(eq_mul(&multiplicity, value, &a_var));
            // Mirrors CPU's limb range check: crates/core/machine/src/cpu/air/register.rs
            // (`builder.slice_range_check_u8(&local.op_a_access.access.value.0, local.is_real)`).
            self.picus_module.constraints.push(u8_range(&a_var));
        }
        for value in values.iter().take(15).skip(11) {
            let b_var = fresh_picus_expr();
            self.picus_module.inputs.push(b_var.clone());
            self.picus_module.constraints.push(eq_mul(&multiplicity, value, &b_var));
        }
        for value in values.iter().take(19).skip(15) {
            let c_var = fresh_picus_expr();
            self.picus_module.inputs.push(c_var.clone());
            self.picus_module.constraints.push(eq_mul(&multiplicity, value, &c_var));
        }
        // Route HI values by is_rw_a.
        for value in values.iter().take(23).skip(19) {
            let hi_var = fresh_picus_expr();
            if is_rw_a {
                self.picus_module.inputs.push(hi_var.clone());
            } else {
                self.picus_module.outputs.push(hi_var.clone());
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
        println!("MEMORY MULTIPLICITY: {multiplicity}");
        assert!(values.len() >= 4, "Expected memory lookup to include addr + value limbs");

        let eq_mul = |multiplicity: &PicusExpr, val: &PicusExpr, var: &PicusExpr| {
            PicusConstraint::new_equality(var.clone(), val.clone() * multiplicity.clone())
        };

        let addr_var = fresh_picus_expr();
        if is_send {
            self.picus_module.inputs.push(addr_var.clone());
        } else {
            self.picus_module.outputs.push(addr_var.clone());
        }
        self.picus_module.constraints.push(eq_mul(&multiplicity, &values[2], &addr_var));

        for value in values.iter().skip(3) {
            let value_var = fresh_picus_expr();
            if is_send {
                self.picus_module.inputs.push(value_var.clone());
                self.picus_module
                    .constraints
                    .push(PicusConstraint::new_lt(value_var.clone(), PicusExpr::Const(255)));
            } else {
                self.picus_module.outputs.push(value_var.clone());
            }
            self.picus_module.constraints.push(eq_mul(&multiplicity, value, &value_var));
        }
    }

    fn get_main_vars_for_call(&mut self, message_values: &[PicusExpr]) -> Option<Vec<PicusAtom>> {
        let opcode_spec = match message_values[6].clone() {
            PicusExpr::Const(v) => {
                assert!(v < Opcode::UNIMPL as u64);
                spec_for(Opcode::try_from(v as u8).unwrap())
            }
            _ => panic!("Opcode should be constant"),
        };
        let target_chip = self.get_chip(opcode_spec.chip);
        let mut target_main_vals: Vec<PicusAtom> =
            (0..target_chip.air.width()).map(|_| fresh_picus_var()).collect();

        let target_picus_info = target_chip.picus_info();
        for (slice, name) in opcode_spec.arg_to_colname {
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
}

impl<'chips, A: MachineAir<Felt>> PairBuilder for PicusBuilder<'chips, A> {
    fn preprocessed(&self) -> Self::M {
        todo!()
    }
}

impl<'chips, A: MachineAir<Felt>> AirBuilderWithPublicValues for PicusBuilder<'chips, A> {
    type PublicVar = PicusAtom;

    fn public_values(&self) -> &[Self::PublicVar] {
        todo!()
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
                    });
                } else {
                    self.symbolic_pending_tasks.push(SymbolicPendingTask {
                        selector: specialized_values[6].clone(),
                        multiplicity: specialized_multiplicity,
                    })
                }
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
            _ => todo!("handle receive: {}", message.kind),
        }
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
        todo!()
    }

    fn is_last_row(&self) -> Self::Expr {
        todo!()
    }

    fn is_transition_window(&self, _size: usize) -> Self::Expr {
        todo!()
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.picus_module.constraints.push(PicusConstraint::Eq(Box::new(x.into())))
    }
}

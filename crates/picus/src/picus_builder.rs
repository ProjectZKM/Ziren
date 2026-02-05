use std::collections::BTreeMap;

use crate::{
    opcode_spec::{IndexSlice, spec_for},
    pcl::{
        Felt, PicusAtom, PicusCall, PicusConstraint, PicusExpr, PicusModule, fresh_picus_expr, fresh_picus_var, fresh_picus_var_id
    },
};
use p3_air::{AirBuilder, AirBuilderWithPublicValues, PairBuilder};
use p3_matrix::dense::{DenseMatrix, RowMajorMatrix};
use zkm_core_executor::{ByteOpcode, Opcode};
use zkm_stark::{AirLookup, Chip, LookupKind, MachineAir, MessageBuilder, ZKM_PROOF_NUM_PV_ELTS};

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
    pub multiplier: PicusExpr,
    pub pending_tasks: Vec<PendingTask>,
}

#[derive(Clone)]
pub struct PendingTask {
    pub chip_name: String,
    pub main_vars: Vec<PicusAtom>,
    pub multiplicity: PicusExpr,
    pub selector: String,
}

impl<'chips, A: MachineAir<Felt>> PicusBuilder<'chips, A> {
    /// Constructor for the builder
    pub fn new(
        chip_to_analyze: &'chips Chip<Felt, A>,
        picus_module: PicusModule,
        chips: &'chips [Chip<Felt, A>],
        main_vars: Option<Vec<PicusAtom>>,
        multiplier: Option<PicusExpr>,
    ) -> Self {
        let width = chip_to_analyze.air.width();
        // Initialize the public values.
        let public_values = (0..ZKM_PROOF_NUM_PV_ELTS).map(PicusAtom::new_var).collect();
        // Initialize the preprocessed and main traces.
        let row: Vec<PicusAtom> =
            (0..chip_to_analyze.preprocessed_width()).map(PicusAtom::new_var).collect();
        let preprocessed = DenseMatrix::new_row(row);
        let main = if let Some(vars) = main_vars {
            assert_eq!(vars.len(), width);
            vars
        } else {
            (0..width).map(PicusAtom::new_var).collect()
        };
        let multiplier =
            if let Some(expr) = multiplier { expr.clone() } else { PicusExpr::Const(1) };
        let aux_modules = BTreeMap::new();
        Self {
            preprocessed,
            main: RowMajorMatrix::new(main, width),
            public_values,
            picus_module,
            aux_modules,
            chips,
            multiplier,
            extract_modularly: false,
            pending_tasks: Vec::new(),
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
    fn handle_byte_interaction(&mut self, multiplicity: PicusExpr, values: &Vec<PicusExpr>) {
        match values[0] {
            PicusExpr::Const(v) => {
                if v == (ByteOpcode::U8Range as u64) {
                    for val in &values[1..] {
                        if let PicusExpr::Const(v) = val {
                            assert!(*v < 256);
                            continue;
                        } else {
                            self.picus_module.constraints.push(PicusConstraint::new_lt(
                                val.clone() * multiplicity.clone(),
                                256.into(),
                            ))
                        }
                    }
                } else if v == (ByteOpcode::U16Range as u64) {
                    for val in &values[1..] {
                        if let PicusExpr::Const(v) = val {
                            assert!(*v < 65536);
                            continue;
                        } else {
                            self.picus_module.constraints.push(PicusConstraint::new_lt(
                                val.clone() * multiplicity.clone(),
                                65536.into(),
                            ))
                        }
                    }
                } else if v == (ByteOpcode::MSB as u64) {
                    let msb = values[1].clone();
                    let bytes = [values[3].clone(), values[4].clone()];
                    let picus128_const = PicusExpr::Const(128);
                    for byte in &bytes {
                        if let PicusExpr::Const(0) = byte {
                            continue;
                        }
                        let fresh_picus_var: PicusExpr = fresh_picus_expr();
                        self.picus_module.constraints.push(PicusConstraint::new_lt(
                            fresh_picus_var.clone(),
                            picus128_const.clone(),
                        ));
                        self.picus_module.constraints.push(PicusConstraint::Eq(Box::new(
                            msb.clone() * (msb.clone() - PicusExpr::Const(1)),
                        )));
                        let decomp =
                            byte.clone() - (msb.clone() * picus128_const.clone() + fresh_picus_var);
                        self.picus_module.constraints.push(PicusConstraint::Eq(Box::new(decomp)));
                    }
                } else if v == (ByteOpcode::ShrCarry as u64) {
                    if !self.aux_modules.contains_key("ShrCarry") {
                        let carry_module = PicusModule::build_empty("ShrCarry".to_string(), 2, 2);
                        self.aux_modules.insert("ShrCarry".to_string(), carry_module);
                    }
                    let shrcarry = PicusCall::new(
                        "ShrCarry".to_string(),
                        &[values[1].clone(), values[2].clone()],
                        &[values[3].clone(), values[4].clone()],
                    );
                    self.picus_module.calls.push(shrcarry);
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
                    println!("values: {values:#?}");
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
            _ => panic!("Byte interaction but first argument isn't a constant"),
        }
    }

    // The receive instruction interaction is used to determine which columns are inputs/outputs.
    // In particular, the following values correspond to inputs and outputs:
    //    - values[2] -> pc (input)
    //    - values[3] -> next_pc (output)
    //    - values[6-9] -> a (output)
    //    - values[10-13] -> b (input)
    //    - values[14-17] -> c (input)
    //    - TODO (Add high and low)
    fn handle_receive_instruction(&mut self, multiplicity: PicusExpr, values: &Vec<PicusExpr>) {
        // Creating a fresh var because picus outputs need to be variables.
        // When performing partial evaluation,
        let next_pc_out = fresh_picus_expr();
        let eq_mul = |multiplicity: &PicusExpr, val: &PicusExpr, var: &PicusExpr| {
            PicusConstraint::new_equality(var.clone(), val.clone() * multiplicity.clone())
        };
        self.picus_module.outputs.push(next_pc_out.clone());
        self.picus_module.constraints.push(eq_mul(&multiplicity, &values[3], &next_pc_out));
        // If this is a sequential instruction then we can assume next-pc is deterministic as we will check its
        // determinism in the CPU chip. Otherwise, we have to prove it is deterministic. The flag for specifying the
        // if the instruction is sequential is stored at index 27.
        if let PicusExpr::Const(1) = values[27].clone() {
            self.picus_module.assume_deterministic.push(next_pc_out);
        }
        // We need to mark some of the register values as inputs and other values as outputs.
        // In particular, the parameters `b` and `c` to `receive_instruction` are inputs and
        // parameter `a` is an output. `b` and `c` are at indexes 10-13 and 14-17 in `values` whereas
        // `a` is at indexes 6-9. As in the code above, we need to create variables for the outputs since
        // Picus requires the inputs and outputs to be variables.
        for i in 6..=9 {
            let a_var = fresh_picus_expr();
            self.picus_module.outputs.push(a_var.clone());
            self.picus_module.constraints.push(eq_mul(&multiplicity, &values[i], &a_var));
        }
        for i in 10..=13 {
            let b_var = fresh_picus_expr();
            self.picus_module.inputs.push(b_var.clone());
            self.picus_module.constraints.push(eq_mul(&multiplicity, &values[i], &b_var));
        }
        for i in 14..=17 {
            let c_var = fresh_picus_expr();
            self.picus_module.inputs.push(c_var.clone());
            self.picus_module.constraints.push(eq_mul(&multiplicity, &values[i], &c_var));
        }
    }

    fn get_main_vars_for_call(&mut self, message_values: &[PicusExpr]) -> Vec<PicusAtom> {
        println!("MESSAGE VALUES: {message_values:?}");
        let opcode_spec = match message_values[5].clone() {
            PicusExpr::Const(v) => {
                assert!(v < Opcode::UNIMPL as u64);
                spec_for(Opcode::try_from(v as u8).unwrap())
            }
            _ => panic!("Expected opcode val to be a constant: Got: {}", message_values[5]),
        };
        let target_chip = self.get_chip(opcode_spec.chip);
        let mut target_main_vals: Vec<PicusAtom> =
            (0..target_chip.air.width()).map(|_| fresh_picus_var()).collect();

        let target_picus_info = target_chip.picus_info();
        println!("Target picus info: {target_picus_info:?}");
        for (slice, name) in opcode_spec.arg_to_colname {
            println!("Name: {:?}", name);
            let colrange = target_picus_info.name_to_colrange.get(*name).unwrap();
            match slice.clone() {
                IndexSlice::Range { start, end } => {
                    assert!(colrange.1 - colrange.0 >= end - start);
                    for i in start..end {
                        if let PicusExpr::Var(v) = message_values[i].clone() {
                            target_main_vals[colrange.0 + i - start] = PicusAtom::Var(v);
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
        println!("Target main vals: {:?}", target_main_vals);
        target_main_vals
    }
}

impl<'a, 'chips, A: MachineAir<Felt>> PairBuilder for PicusBuilder<'chips, A> {
    fn preprocessed(&self) -> Self::M {
        todo!()
    }
}

impl<'a, 'chips, A: MachineAir<Felt>> AirBuilderWithPublicValues for PicusBuilder<'chips, A> {
    type PublicVar = PicusAtom;

    fn public_values(&self) -> &[Self::PublicVar] {
        todo!()
    }
}

impl<'a, 'chips, A: MachineAir<Felt>> MessageBuilder<AirLookup<PicusExpr>>
    for PicusBuilder<'chips, A>
{
    fn send(&mut self, message: AirLookup<PicusExpr>, _scope: zkm_stark::LookupScope) {
        match message.kind {
            LookupKind::Byte => {
                self.handle_byte_interaction(message.multiplicity, &message.values);
            }
            LookupKind::Memory => {
                // TODO: fill in
            }
            LookupKind::Instruction => {
                let opcode_spec = match message.values[5].clone() {
                    PicusExpr::Const(v) => {
                        assert!(v < Opcode::UNIMPL as u64);
                        spec_for(Opcode::try_from(v as u8).unwrap())
                    }
                    _ => panic!("Expected opcode val to be a constant: Got: {}", message.values[5]),
                };
                let target_chip = self.get_chip(opcode_spec.chip);

                let main_vars = self.get_main_vars_for_call(&message.values);
                self.pending_tasks.push(PendingTask {
                    chip_name: target_chip.name(),
                    main_vars,
                    multiplicity: message.multiplicity,
                    selector: opcode_spec.selector.to_string(),
                })
            }
            _ => todo!("handle send: {}", message.kind),
        }
    }

    fn receive(&mut self, message: AirLookup<PicusExpr>, _scope: zkm_stark::LookupScope) {
        // initialize another chip
        // call eval with builder?
        match message.kind {
            LookupKind::Instruction => {
                self.handle_receive_instruction(message.multiplicity, &message.values);
            }
            LookupKind::Memory => {
                // TODO: fill in
            }
            _ => todo!("handle receive: {}", message.kind),
        }
    }
}

impl<'a, 'chips, A: MachineAir<Felt>> AirBuilder for PicusBuilder<'chips, A> {
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

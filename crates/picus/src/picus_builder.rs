use std::collections::BTreeMap;

use crate::pcl::{fresh_picus_var, Felt, PicusConstraint, PicusExpr, PicusModule, PicusVar};
use p3_air::{AirBuilder, AirBuilderWithPublicValues, PairBuilder};
use p3_matrix::dense::{DenseMatrix, RowMajorMatrix};
use zkm_core_executor::ByteOpcode;
use zkm_stark::{AirLookup, LookupKind, MessageBuilder};

/// Implementation `AirBuilder` which builds Picus programs
pub struct PicusBuilder {
    pub preprocessed: RowMajorMatrix<PicusVar>,
    pub main: RowMajorMatrix<PicusVar>,
    pub public_values: Vec<PicusVar>,
    pub picus_module: PicusModule,
    pub aux_modules: BTreeMap<String, PicusModule>,
}

impl PicusBuilder {
    /// Constructor for the builder
    pub fn new(
        preprocessed_width: usize,
        width: usize,
        num_public_values: usize,
        picus_module: PicusModule,
    ) -> Self {
        // Initialize the public values.
        let public_values = (0..num_public_values).map(PicusVar::new).collect();
        // Initialize the preprocessed and main traces.
        let row: Vec<PicusVar> = (0..preprocessed_width).map(PicusVar::new).collect();
        let preprocessed = DenseMatrix::new_row(row);
        let main = (0..width).map(PicusVar::new).collect();
        let aux_modules = BTreeMap::new();
        Self {
            preprocessed,
            main: RowMajorMatrix::new(main, width),
            public_values,
            picus_module,
            aux_modules,
        }
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
                } else if v == (ByteOpcode::MSB as u64) {
                    let msb = values[1].clone();
                    let byte = values[2].clone();
                    let fresh_picus_var: PicusExpr = fresh_picus_var();
                    let picus128_const = PicusExpr::Const(128);
                    self.picus_module.constraints.push(PicusConstraint::new_lt(
                        fresh_picus_var.clone(),
                        picus128_const.clone(),
                    ));

                    self.picus_module.constraints.push(PicusConstraint::Eq(Box::new(
                        msb.clone() * (msb.clone() - PicusExpr::Const(1)),
                    )));
                    let decomp = byte - (msb * picus128_const + fresh_picus_var);
                    self.picus_module.constraints.push(PicusConstraint::Eq(Box::new(decomp)));
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
        let next_pc_out = fresh_picus_var();
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
            let a_var = fresh_picus_var();
            self.picus_module.outputs.push(a_var.clone());
            self.picus_module.constraints.push(eq_mul(&multiplicity, &values[i], &a_var));
        }
        for i in 10..=13 {
            let b_var = fresh_picus_var();
            self.picus_module.inputs.push(b_var.clone());
            self.picus_module.constraints.push(eq_mul(&multiplicity, &values[i], &b_var));
        }
        for i in 14..=17 {
            let c_var = fresh_picus_var();
            self.picus_module.inputs.push(c_var.clone());
            self.picus_module.constraints.push(eq_mul(&multiplicity, &values[i], &c_var));
        }
    }
}

impl<'a> PairBuilder for PicusBuilder {
    fn preprocessed(&self) -> Self::M {
        todo!()
    }
}

impl<'a> AirBuilderWithPublicValues for PicusBuilder {
    type PublicVar = PicusVar;

    fn public_values(&self) -> &[Self::PublicVar] {
        todo!()
    }
}

impl<'a> MessageBuilder<AirLookup<PicusExpr>> for PicusBuilder {
    fn send(&mut self, message: AirLookup<PicusExpr>, _scope: zkm_stark::LookupScope) {
        match message.kind {
            LookupKind::Byte => {
                self.handle_byte_interaction(message.multiplicity, &message.values);
            }
            LookupKind::Memory => {
                // TODO: fill in
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

impl<'a> AirBuilder for PicusBuilder {
    type F = Felt;
    type Var = PicusVar;
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
        self.picus_module.constraints.push(PicusConstraint::Eq(Box::new(x.into())));
    }
}

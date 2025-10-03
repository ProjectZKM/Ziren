use std::collections::BTreeMap;

use crate::pcl::{
    fresh_picus_var, Felt, PicusCall, PicusConstraint, PicusExpr, PicusModule, PicusVar,
};
use p3_air::{AirBuilder, AirBuilderWithPublicValues, PairBuilder};
use p3_matrix::dense::{DenseMatrix, RowMajorMatrix};
use zkm_core_executor::ByteOpcode;
use zkm_stark::{AirLookup, LookupKind, MessageBuilder};

const RECEIVE_INSTRUCTION: &str = "Receive_Instruction";

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

    // for a receive instruction we will generate a picus module called `receive_instruction`. The module will be a stub as follows:
    // ```
    // (begin-module Receive_Interaction)
    // (input v0)
    // (input v2)
    // ...
    // (input vk)
    // (assume-deterministic v1)
    // (output v1)
    // (end-module)
    // ```
    // the main idea is we can verify the constraints for the other side of the interaction separately. When verifying a chip that uses the interaction
    // we mainly care that the the right values are passed to the interaction. In particular:
    //    - values[0] (pc) -- this is an input.
    //    - values[1] (next_pc) -- this is an output.
    //    - rest are treated as inputs for now.
    fn handle_receive_instruction(&mut self, multiplicity: PicusExpr, values: &Vec<PicusExpr>) {
        let next_pc_idx = 3;
        if !self.aux_modules.contains_key(RECEIVE_INSTRUCTION) {
            // build the receive instruction module
            let mut receive_mod = PicusModule::new(RECEIVE_INSTRUCTION.to_string());
            for i in 0..values.len() {
                let var = fresh_picus_var();
                if i == next_pc_idx {
                    receive_mod.outputs.push(var.clone());
                    receive_mod.assume_deterministic.push(var.clone());
                } else {
                    receive_mod.inputs.push(var)
                }
            }
            self.aux_modules.insert(RECEIVE_INSTRUCTION.to_string(), receive_mod);
        }
        let mut inputs = Vec::new();
        let outputs = vec![multiplicity.clone() * values[next_pc_idx].clone()];
        for (i, input) in values.iter().enumerate() {
            if i == next_pc_idx {
                continue;
            }
            inputs.push(multiplicity.clone() * input.clone());
        }
        self.picus_module.calls.push(PicusCall {
            inputs,
            outputs,
            mod_name: RECEIVE_INSTRUCTION.to_string(),
        });
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

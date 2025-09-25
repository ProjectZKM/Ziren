use p3_air::{AirBuilder, AirBuilderWithPublicValues, PairBuilder};
use p3_matrix::dense::{DenseMatrix, RowMajorMatrix};
use zkm_core_executor::ByteOpcode;

use crate::pcl::{Felt, PicusConstraint, PicusExpr, PicusModule, PicusVar};
use zkm_stark::{AirLookup, LookupKind, MessageBuilder};

/// Implementation `AirBuilder` which builds Picus programs
pub struct PicusBuilder {
    pub preprocessed: RowMajorMatrix<PicusVar>,
    pub main: RowMajorMatrix<PicusVar>,
    pub public_values: Vec<PicusVar>,
    pub picus_module: PicusModule,
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
        Self { preprocessed, main: RowMajorMatrix::new(main, width), public_values, picus_module }
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
                }
            }
            // TODO: It might be fine if the first argument isn't a constant. We need to multiply the values
            // in the interaction with the multiplicities
            _ => panic!("Byte interaction but first argument isn't a constant"),
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
            _ => todo!("handle byte: {}", message.kind),
        }
    }

    fn receive(&mut self, _message: AirLookup<PicusExpr>, _scope: zkm_stark::LookupScope) {}
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

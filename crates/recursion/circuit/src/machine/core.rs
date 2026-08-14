use zkm_pcs::shape::OrderedShape;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZKMRecursionShape {
    pub proof_shapes: Vec<OrderedShape>,
    pub is_complete: bool,
}

impl From<OrderedShape> for ZKMRecursionShape {
    fn from(proof_shape: OrderedShape) -> Self {
        Self { proof_shapes: vec![proof_shape], is_complete: false }
    }
}

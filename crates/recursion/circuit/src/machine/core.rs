
use p3_koala_bear::KoalaBear;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use zkm_pcs::{
    shape::OrderedShape,
    Dom,
};

use zkm_pcs::{ShardProof, StarkGenericConfig, StarkVerifyingKey};

use zkm_recursion_compiler::ir::Felt;

use zkm_recursion_core::DIGEST_SIZE;

use crate::{
    stark::ShardProofVariable,
    CircuitConfig, KoalaBearFriParameters, KoalaBearFriParametersVariable, VerifyingKeyVariable,
};

pub struct ZKMRecursionWitnessVariable<
    C: CircuitConfig<F = KoalaBear>,
    SC: KoalaBearFriParametersVariable<C>,
> {
    pub vk: VerifyingKeyVariable<C, SC>,
    pub shard_proofs: Vec<ShardProofVariable<C, SC>>,
    pub is_complete: Felt<C::F>,
    pub is_first_shard: Felt<C::F>,
    pub vk_root: [Felt<C::F>; DIGEST_SIZE],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "ShardProof<SC>: Serialize, Dom<SC>: Serialize"))]
#[serde(bound(deserialize = "ShardProof<SC>: Deserialize<'de>, Dom<SC>: DeserializeOwned"))]
pub struct ZKMRecursionWitnessValues<SC: StarkGenericConfig> {
    pub vk: StarkVerifyingKey<SC>,
    pub shard_proofs: Vec<ShardProof<SC>>,
    pub is_complete: bool,
    pub is_first_shard: bool,
    pub vk_root: [SC::Val; DIGEST_SIZE],
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZKMRecursionShape {
    pub proof_shapes: Vec<OrderedShape>,
    pub is_complete: bool,
}


impl<SC: KoalaBearFriParameters> ZKMRecursionWitnessValues<SC> {
    pub fn shape(&self) -> ZKMRecursionShape {
        let proof_shapes = self.shard_proofs.iter().map(|proof| proof.shape()).collect();

        ZKMRecursionShape { proof_shapes, is_complete: self.is_complete }
    }
}

impl From<OrderedShape> for ZKMRecursionShape {
    fn from(proof_shape: OrderedShape) -> Self {
        Self { proof_shapes: vec![proof_shape], is_complete: false }
    }
}

use std::{
    array,
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    mem::MaybeUninit,
};

use itertools::Itertools;
use p3_commit::Mmcs;
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zkm_core_machine::{
    cpu::MAX_CPU_LOG_DEGREE,
    mips::{MipsAir, MAX_LOG_NUMBER_OF_SHARDS},
};

use zkm_recursion_core::air::PV_DIGEST_NUM_WORDS;
use zkm_stark::air::LookupScope;
use zkm_stark::air::MachineAir;
use zkm_stark::{
    air::{PublicValues, POSEIDON_NUM_WORDS},
    koala_bear_poseidon2::KoalaBearPoseidon2,
    shape::OrderedShape,
    Dom, StarkMachine, Word,
};

use zkm_stark::{ShardProof, StarkGenericConfig, StarkVerifyingKey};

use zkm_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Config, Felt, SymbolicFelt},
};

use zkm_recursion_core::{
    air::{RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS},
    DIGEST_SIZE,
};

use crate::{
    challenger::{CanObserveVariable, DuplexChallengerVariable},
    machine::{assert_complete, recursion_public_values_digest},
    stark::{ShardProofVariable, StarkVerifier},
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

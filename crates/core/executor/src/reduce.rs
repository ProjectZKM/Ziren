use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zkm_stark::{Dom, ShardProof, StarkGenericConfig, StarkVerifyingKey};
/// An intermediate proof which proves the execution.
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound(serialize = "ShardProof<SC>: Serialize, Dom<SC>: Serialize"))]
#[serde(bound(deserialize = "ShardProof<SC>: Deserialize<'de>, Dom<SC>: DeserializeOwned"))]
pub struct ZKMReduceProof<SC: StarkGenericConfig> {
    /// The compress verifying key associated with the proof.
    pub vk: StarkVerifyingKey<SC>,
    /// The shard proof representing the compressed proof.
    pub proof: ShardProof<SC>,
}

impl<SC: StarkGenericConfig> std::fmt::Debug for ZKMReduceProof<SC> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("ZKMReduceProof");
        debug_struct.field("vk", &self.vk);
        debug_struct.field("proof", &self.proof);
        debug_struct.finish()
    }
}

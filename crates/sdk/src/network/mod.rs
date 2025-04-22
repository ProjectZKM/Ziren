use serde::{Deserialize, Serialize};

pub mod prover;


#[derive(Debug, Default, Clone)]
pub struct NetworkClientCfg {
    pub endpoint: String,
    pub ca_cert_path: String,
    pub cert_path: String,
    pub key_path: String,
    pub domain_name: String,
    pub proof_network_privkey: String,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct ProverInput {
    pub elf: Vec<u8>,
    pub public_inputstream: Vec<u8>,
    pub private_inputstream: Vec<u8>,
    pub seg_size: u32,
    pub execute_only: bool,
    pub composite_proof: bool,
    pub receipt_inputs: Vec<Vec<u8>>,
    pub receipts: Vec<Vec<u8>>,
    pub proof_results_path: String,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct ProverResult {
    pub total_steps: u64,
    pub split_cost: u64,
    pub output_stream: Vec<u8>,
    pub proof_with_public_inputs: Vec<u8>,
    pub stark_proof: Vec<u8>,
    pub public_values: Vec<u8>,
    pub receipt: Vec<u8>,
    pub elf_id: Vec<u8>,
}
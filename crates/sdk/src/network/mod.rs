use std::env;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use zkm_core_machine::io::ZKMStdin;
use zkm_primitives::io::ZKMPublicValues;
use crate::{utils, NetworkProver, ProverClient};
use crate::utils::block_on;

pub mod prover;


#[derive(Debug, Default, Clone)]
pub struct NetworkClientCfg {
    pub endpoint: Option<String>,
    pub ca_cert_path: Option<String>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub domain_name: Option<String>,
    pub proof_network_privkey: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct ProverInput {
    pub elf: Vec<u8>,
    pub public_inputstream: Vec<u8>,
    pub private_inputstream: Vec<u8>,
    pub shard_size: u32,
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

#[test]
fn test_proof_network_fib() {
    utils::setup_logger();
    let endpoint = Some(env::var("ENDPOINT").unwrap_or("https://152.32.186.45:20002".to_string()));
    let domain_name = Some(env::var("DOMAIN_NAME").unwrap_or("stage".to_string()));
    let proof_network_privkey = Some(env::var("ZKM_PRIVATE_KEY")
        .expect("ZKM_PRIVATE_KEY must be set for remote proving"));
    let current_dir = env::current_dir().expect("Failed to get current directory");
    let ca_cert_path = Some(current_dir.join("tool/ca.pem").to_string_lossy().to_string());
    let cert_path = Some(current_dir.join("tool/.pem").to_string_lossy().to_string());
    let key_path = Some(current_dir.join("tool/.key").to_string_lossy().to_string());
    
    let network_cfg = NetworkClientCfg {
        endpoint,
        ca_cert_path,
        cert_path,
        key_path,
        domain_name,
        proof_network_privkey,
    };

    let mut stdin = ZKMStdin::new();
    stdin.write(&10usize);
    let elf = test_artifacts::FIBONACCI_ELF;
    
    let client = ProverClient::network(&network_cfg);
    let (pk, vk) = client.setup(elf);
    let mut proof = client.prove(&pk, stdin).run().unwrap();
    client.verify(&proof, &vk).unwrap();
    
    // Test invalid public values.
    proof.public_values = ZKMPublicValues::from(&[255, 4, 84]);
    if client.verify(&proof, &vk).is_ok() {
        panic!("verified proof with invalid public values")
    }
}
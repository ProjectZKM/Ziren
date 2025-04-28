use serde::{Deserialize, Serialize};
use std::env;

pub mod prover;

#[derive(Debug, Clone)]
pub struct NetworkClientCfg {
    pub endpoint: Option<String>,
    pub ca_cert_path: Option<String>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub domain_name: Option<String>,
    pub proof_network_privkey: Option<String>,
}

impl Default for NetworkClientCfg {
    fn default() -> Self {
        let endpoint =
            Some(env::var("ENDPOINT").unwrap_or("https://152.32.186.45:20002".to_string()));
        let domain_name = Some(env::var("DOMAIN_NAME").unwrap_or("stage".to_string()));
        let proof_network_privkey = Some(
            env::var("ZKM_PRIVATE_KEY").expect("ZKM_PRIVATE_KEY must be set for remote proving"),
        );
        let current_dir = env::current_dir().expect("Failed to get current directory");
        let ca_cert_path = Some(current_dir.join("tool/ca.pem").to_string_lossy().to_string());
        let cert_path =
            Some(env::var("CERT_PATH").expect("CERT_PATH must be set for remote proving"));
        let key_path = Some(env::var("KEY_PATH").expect("KEY_PATH must be set for remote proving"));

        Self { endpoint, ca_cert_path, cert_path, key_path, domain_name, proof_network_privkey }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProverInput {
    pub elf: Vec<u8>,
    pub public_inputstream: Vec<u8>,
    pub private_inputstream: Vec<u8>,
    pub shard_size: u32,
    // pub execute_only: bool,
    pub composite_proof: bool,
    pub receipt_inputs: Vec<Vec<u8>>,
    pub receipts: Vec<Vec<u8>>,
    pub asset_url: String,
    pub use_network_vk: bool,
    pub proof_results_path: String,
}

impl Default for ProverInput {
    fn default() -> Self {
        let composite_proof = env::var("COMPOSITE_PROOF")
            .ok()
            .and_then(|seg| seg.parse::<bool>().ok())
            .unwrap_or(false);
        let shard_size =
            env::var("SHARD_SIZE").ok().and_then(|seg| seg.parse::<usize>().ok()).unwrap_or(65536)
                as u32;
        let current_dir = env::current_dir().expect("Failed to get current directory");
        let proof_results_path =
            env::var("PROOF_RESULTS_PATH").unwrap_or(current_dir.to_string_lossy().to_string());
        let asset_url = env::var("ASSET_URL").unwrap_or("http://152.32.186.45:20001".to_string());
        let use_network_vk = env::var("USE_NETWORK_VK")
            .ok()
            .and_then(|seg| seg.parse::<bool>().ok())
            .unwrap_or(true);
        Self {
            elf: vec![],
            public_inputstream: vec![],
            private_inputstream: vec![],
            shard_size,
            composite_proof,
            receipt_inputs: vec![],
            receipts: vec![],
            asset_url,
            proof_results_path,
            use_network_vk,
        }
    }
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::{utils, ProverClient};
    use std::{env, fs};
    use zkm_core_machine::io::ZKMStdin;
    use zkm_prover::ZKMVerifyingKey;
    #[ignore]
    #[test]
    fn test_proof_network_fib() {
        utils::setup_logger();
        let network_cfg = NetworkClientCfg::default();

        let mut stdin = ZKMStdin::new();
        stdin.write(&10usize);
        let elf = test_artifacts::FIBONACCI_ELF;
        let proof_results_path = env::var("PROOF_RESULTS_PATH").unwrap_or(".".to_string());

        let client = ProverClient::network(&network_cfg);
        let (tem_pk, _) = client.setup(elf);
        let proof = client.prove(&tem_pk, stdin).run().unwrap();

        let vk_path = format!("{proof_results_path}/vk.bin");
        let vk_data = fs::read(&vk_path).expect("Failed to read vk.bin");
        let vk = bincode::deserialize::<ZKMVerifyingKey>(&vk_data).unwrap();
        client.verify(&proof, &vk).unwrap();
    }
}

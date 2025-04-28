use serde::{Deserialize, Serialize};
use std::env;

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

impl NetworkClientCfg {
    pub fn from_env() -> Self {
        let endpoint =
            Some(env::var("ENDPOINT").unwrap_or("https://152.32.186.45:20002".to_string()));
        let domain_name = Some(env::var("DOMAIN_NAME").unwrap_or("stage".to_string()));
        let proof_network_privkey = Some(
            env::var("ZKM_PRIVATE_KEY").expect("ZKM_PRIVATE_KEY must be set for remote proving"),
        );
        // Default ca cert directory
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let ca_cert_path = Some(manifest_dir.join("tool/ca.pem").to_string_lossy().to_string());
        let cert_path =
            Some(env::var("CERT_PATH").expect("CERT_PATH must be set for remote proving"));
        let key_path = Some(env::var("KEY_PATH").expect("KEY_PATH must be set for remote proving"));

        Self { endpoint, ca_cert_path, cert_path, key_path, domain_name, proof_network_privkey }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProverInput {
    pub elf: Vec<u8>,
    // pub public_inputstream: Vec<u8>,
    pub private_inputstream: Vec<u8>,
    // pub execute_only: bool,
    pub receipts: Vec<Vec<u8>>,
    pub asset_url: String,
    pub vk_dir: Option<String>,
}

impl Default for ProverInput {
    fn default() -> Self {
        let vk_dir = env::var("VK_DIR").ok();
        let asset_url = env::var("ASSET_URL").unwrap_or("http://152.32.186.45:20001".to_string());
        Self {
            elf: vec![],
            // public_inputstream: vec![],
            private_inputstream: vec![],
            receipts: vec![],
            asset_url,
            vk_dir,
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
    use crate::network::prover::read_verifying_key_from_file;
    use crate::{utils, ProverClient};
    use std::env;
    use zkm_core_machine::io::ZKMStdin;
    #[ignore]
    #[test]
    fn test_proof_network_fib() {
        utils::setup_logger();

        let mut stdin = ZKMStdin::new();
        stdin.write(&10usize);
        let elf = test_artifacts::FIBONACCI_ELF;
        let vk_dir = env::var("VK_DIR").unwrap_or(".".to_string());

        let client = ProverClient::network();
        let (tem_pk, _) = client.setup(elf);
        let proof = client.prove(&tem_pk, stdin).run().unwrap();

        let vk_path = format!("{vk_dir}/vk.bin");
        let vk = read_verifying_key_from_file(vk_path.as_str()).unwrap();
        client.verify(&proof, &vk).unwrap();
    }
}

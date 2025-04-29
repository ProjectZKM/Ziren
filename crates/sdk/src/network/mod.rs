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
        let proof_network_privkey = Some(
            env::var("ZKM_PRIVATE_KEY").expect("ZKM_PRIVATE_KEY must be set for remote proving"),
        );
        let endpoint =
            Some(env::var("ENDPOINT").unwrap_or("https://152.32.186.45:20002".to_string()));
        let domain_name = Some(env::var("DOMAIN_NAME").unwrap_or("stage".to_string()));
        // Default ca cert directory
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let ca_cert_path = Some(
            env::var("CA_CERT_PATH")
                .unwrap_or(manifest_dir.join("tool/ca.pem").to_string_lossy().to_string()),
        );
        let cert_path = env::var("CERT_PATH").ok();
        let key_path = env::var("KEY_PATH").ok();

        Self { endpoint, ca_cert_path, cert_path, key_path, domain_name, proof_network_privkey }
    }
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct ProverInput {
    pub elf: Vec<u8>,
    // pub public_inputstream: Vec<u8>,
    pub private_inputstream: Vec<u8>,
    // pub execute_only: bool,
    pub receipts: Vec<Vec<u8>>,
}

#[cfg(test)]
mod test {
    use crate::{utils, ProverClient};
    use zkm_core_machine::io::ZKMStdin;

    #[ignore]
    #[test]
    fn test_proof_network_fib() {
        utils::setup_logger();

        let mut stdin = ZKMStdin::new();
        stdin.write(&10usize);
        let elf = test_artifacts::FIBONACCI_ELF;
        let client = ProverClient::network();
        let (pk, vk) = client.setup(elf);
        let proof = client.prove(&pk, stdin).run().unwrap();
        client.verify(&proof, &vk).unwrap();
    }
}

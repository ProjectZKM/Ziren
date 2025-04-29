use serde::{Deserialize, Serialize};
pub mod prover;

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

use crate::network::prover::stage_service::Step;
use serde::{Deserialize, Serialize};
use std::fmt;

pub mod prover;

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct ProverInput {
    pub elf: Vec<u8>,
    // pub public_inputstream: Vec<u8>,
    pub private_inputstream: Vec<u8>,
    // pub execute_only: bool,
    pub receipts: Vec<Vec<u8>>,
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Step::Init => "Generate_proof : queuing the task.",
            Step::InSplit => "Generate_proof : splitting the task.",
            Step::InProve => "Generate_proof : proving the task.",
            Step::InAgg => "Generate_proof : aggregating the proof.",
            Step::InSnark => "Generate_proof : snark-wrapping the proof.",
            Step::End => "Generate_proof : completed.",
        };
        write!(f, "{s}")
    }
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

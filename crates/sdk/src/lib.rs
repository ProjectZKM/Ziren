//! # Ziren SDK
//!
//! A library for interacting with the Ziren zkVM.

pub mod action;
// pub mod artifacts;
pub mod install;

#[cfg(feature = "network")]
pub use crate::network::prover::NetworkProver;
use cfg_if::cfg_if;
use std::env;
use zkm_cuda::ZKMGpuServer;

pub mod network;
pub mod proof;
pub mod provers;
pub mod utils;

pub use proof::*;
pub use provers::ZKMVerificationError;
use zkm_prover::components::DefaultProverComponents;

#[cfg(feature = "network")]
pub use provers::{CpuProver, MockProver, Prover};

pub use zkm_build::include_elf;
pub use zkm_core_executor::{ExecutionReport, HookEnv, ZKMContext, ZKMContextBuilder};
pub use zkm_core_machine::{io::ZKMStdin, ZKM_CIRCUIT_VERSION};
pub use zkm_primitives::io::ZKMPublicValues;
pub use zkm_prover::{
    CoreSC, HashableKey, InnerSC, OuterSC, PlonkBn254Proof, ProverMode, ZKMProver, ZKMProvingKey,
    ZKMVerifyingKey,
};

// Re-export the utilities.
use crate::{provers::CudaProver, utils::block_on};
pub use utils::setup_logger;

/// A client for interacting with Ziren.
pub struct ProverClient {
    /// The underlying prover implementation.
    pub prover: Box<dyn Prover<DefaultProverComponents>>,
}

impl ProverClient {
    /// Creates a new [ProverClient].
    ///
    /// Setting the `ZKM_PROVER` environment variable can change the prover used under the hood.
    /// - `local` (default): Uses [CpuProver] or [CudaProver] if the `cuda` feature is enabled.
    ///   Recommended for proving end-to-end locally.
    /// - `mock`: Uses [MockProver]. Recommended for testing and development.
    /// - `network`: Uses [NetworkProver]. Recommended for outsourcing proof generation to an RPC.
    ///
    /// ### Examples
    ///
    /// ```no_run
    /// use zkm_sdk::ProverClient;
    ///
    /// std::env::set_var("ZKM_PROVER", "local");
    /// let client = ProverClient::new();
    /// ```
    pub fn new() -> Self {
        #[allow(unreachable_code)]
        match env::var("ZKM_PROVER").unwrap_or("local".to_string()).to_lowercase().as_str() {
            "mock" => Self { prover: Box::new(MockProver::new()) },
            "cpu" | "local" => {
                #[cfg(debug_assertions)]
                eprintln!("Warning: Local prover in dev mode is not recommended. Proof generation may be slow.");
                Self {
                    prover: Box::new(CpuProver::new()),
                }
            }
            "cuda" => Self {
                prover: Box::new(CudaProver::new(ZKMProver::new(), ZKMGpuServer::default()))
            },
            "network" => {
                cfg_if! {
                   if #[cfg(feature = "network")] {
                        Self {
                            prover: Box::new(NetworkProver::from_env().unwrap()),
                        }
                    } else {
                        panic!("network feature is not enabled")
                    }
                }
            }
            _ => panic!(
                "invalid value for ZKM_PROVER environment variable: expected 'local', 'mock', or 'network'"
            ),
        }
    }

    /// Returns a [ProverClientBuilder] to easily create a [ProverClient].
    pub fn builder() -> ProverClientBuilder {
        ProverClientBuilder::default()
    }

    /// Creates a new [ProverClient] with the mock prover.
    ///
    /// ### Examples
    ///
    /// ```no_run
    /// use zkm_sdk::ProverClient;
    ///
    /// let client = ProverClient::mock();
    /// ```
    pub fn mock() -> Self {
        Self { prover: Box::new(MockProver::new()) }
    }

    /// Creates a new [ProverClient] with the local prover, using the CPU.
    ///
    /// ### Examples
    ///
    /// ```no_run
    /// use zkm_sdk::ProverClient;
    ///
    /// let client = ProverClient::local();
    /// ```
    #[deprecated(note = "Please use `cpu` instead")]
    pub fn local() -> Self {
        Self { prover: Box::new(CpuProver::new()) }
    }

    /// Creates a new [ProverClient] with the local prover, using the CPU.
    ///
    /// ### Examples
    ///
    /// ```no_run
    /// use zkm_sdk::ProverClient;
    ///
    /// let client = ProverClient::cpu();
    /// ```
    pub fn cpu() -> Self {
        Self { prover: Box::new(CpuProver::new()) }
    }

    /// Creates a new [ProverClient] with the local prover, using the GPU.
    ///
    /// ### Examples
    ///
    /// ```no_run
    /// use zkm_sdk::ProverClient;
    ///
    /// let client = ProverClient::cuda();
    /// ```
    pub fn cuda() -> Self {
        Self { prover: Box::new(CudaProver::new(ZKMProver::new(), ZKMGpuServer::default())) }
    }

    /// Creates a new [ProverClient] with the network prover.
    ///
    /// ### Examples
    ///
    /// ```no_run
    /// use std::env;
    /// use zkm_sdk::ProverClient;
    ///
    /// let client = ProverClient::network();
    /// ```
    #[cfg(feature = "network")]
    pub fn network() -> Self {
        cfg_if! {
            if #[cfg(feature = "network")] {
                Self {
                    prover: Box::new(NetworkProver::from_env().unwrap()),
                }
            } else {
                panic!("network feature is not enabled")
            }
        }
    }

    /// Prepare to execute the given program on the given input (without generating a proof).
    /// The returned [action::Execute] may be configured via its methods before running.
    /// For example, calling [action::Execute::with_hook] registers hooks for execution.
    ///
    /// To execute, call [action::Execute::run], which returns
    /// the public values and execution report of the program after it has been executed.
    ///
    /// ### Examples
    /// ```no_run
    /// use zkm_sdk::{ProverClient, ZKMContext, ZKMStdin};
    ///
    /// // Load the program.
    /// let elf = test_artifacts::FIBONACCI_ELF;
    ///
    /// // Initialize the prover client.
    /// let client = ProverClient::new();
    ///
    /// // Setup the inputs.
    /// let mut stdin = ZKMStdin::new();
    /// stdin.write(&10usize);
    ///
    /// // Execute the program on the inputs.
    /// let (public_values, report) = client.execute(elf, stdin).run().unwrap();
    /// ```
    pub fn execute<'a>(&'a self, elf: &'a [u8], stdin: ZKMStdin) -> action::Execute<'a> {
        action::Execute::new(self.prover.as_ref(), elf, stdin)
    }

    /// Prepare to prove the execution of the given program with the given input in the default
    /// mode. The returned [action::Prove] may be configured via its methods before running.
    /// For example, calling [action::Prove::compressed] sets the mode to compressed mode.
    ///
    /// To prove, call [action::Prove::run], which returns a proof of the program's execution.
    /// By default the proof generated will not be compressed to constant size.
    /// To create a more succinct proof, use the [action::Prove::compressed],
    /// [action::Prove::plonk], or [action::Prove::groth16] methods.
    ///
    /// ### Examples
    /// ```no_run
    /// use zkm_sdk::{ProverClient, ZKMContext, ZKMStdin};
    ///
    /// // Load the program.
    /// let elf = test_artifacts::FIBONACCI_ELF;
    ///
    /// // Initialize the prover client.
    /// let client = ProverClient::new();
    ///
    /// // Setup the program.
    /// let (pk, vk) = client.setup(elf);
    ///
    /// // Setup the inputs.
    /// let mut stdin = ZKMStdin::new();
    /// stdin.write(&10usize);
    ///
    /// // Generate the proof.
    /// let proof = client.prove(&pk, stdin).run().unwrap();
    /// ```
    pub fn prove<'a>(&'a self, pk: &'a ZKMProvingKey, stdin: ZKMStdin) -> action::Prove<'a> {
        action::Prove::new(self.prover.as_ref(), pk, stdin)
    }

    /// Verifies that the given proof is valid and matches the given verification key produced by
    /// [Self::setup].
    ///
    /// ### Examples
    /// ```no_run
    /// use zkm_sdk::{ProverClient, ZKMStdin};
    ///
    /// let elf = test_artifacts::FIBONACCI_ELF;
    /// let client = ProverClient::new();
    /// let (pk, vk) = client.setup(elf);
    /// let mut stdin = ZKMStdin::new();
    /// stdin.write(&10usize);
    /// let proof = client.prove(&pk, stdin).run().unwrap();
    /// client.verify(&proof, &vk).unwrap();
    /// ```
    pub fn verify(
        &self,
        proof: &ZKMProofWithPublicValues,
        vk: &ZKMVerifyingKey,
    ) -> Result<(), ZKMVerificationError> {
        self.prover.verify(proof, vk)
    }

    /// Gets the current version of the Ziren zkVM.
    ///
    /// Note: This is not the same as the version of the Ziren SDK.
    pub fn version(&self) -> String {
        ZKM_CIRCUIT_VERSION.to_string()
    }

    /// Setup a program to be proven and verified by the Ziren MIPS zkVM by computing the proving
    /// and verifying keys.
    ///
    /// The proving key and verifying key essentially embed the program, as well as other auxiliary
    /// data (such as lookup tables) that are used to prove the program's correctness.
    ///
    /// ### Examples
    /// ```no_run
    /// use zkm_sdk::{ProverClient, ZKMStdin};
    ///
    /// let elf = test_artifacts::FIBONACCI_ELF;
    /// let client = ProverClient::new();
    /// let mut stdin = ZKMStdin::new();
    /// stdin.write(&10usize);
    /// let (pk, vk) = client.setup(elf);
    /// ```
    pub fn setup(&self, elf: &[u8]) -> (ZKMProvingKey, ZKMVerifyingKey) {
        self.prover.setup(elf)
    }
}

impl Default for ProverClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder type for [`ProverClient`].
#[derive(Debug, Default)]
pub struct ProverClientBuilder {
    mode: Option<ProverMode>,
    private_key: Option<String>,
    rpc_url: Option<String>,
    skip_simulation: bool,
}

impl ProverClientBuilder {
    /// Sets the mode of the prover client being created.
    pub fn mode(mut self, mode: ProverMode) -> Self {
        self.mode = Some(mode);
        self
    }

    ///  Sets the private key.
    pub fn private_key(mut self, private_key: String) -> Self {
        self.private_key = Some(private_key);
        self
    }

    /// Sets the RPC URL.
    pub fn rpc_url(mut self, rpc_url: String) -> Self {
        self.rpc_url = Some(rpc_url);
        self
    }

    /// Skips simulation.
    pub fn skip_simulation(mut self) -> Self {
        self.skip_simulation = true;
        self
    }

    /// Builds a [ProverClient], using the provided private key.
    pub fn build(self) -> ProverClient {
        match self.mode.expect("The prover mode is required") {
            ProverMode::Cpu => ProverClient::cpu(),
            ProverMode::Cuda => ProverClient::cuda(),
            ProverMode::Network => {
                cfg_if! {
                   if #[cfg(feature = "network")] {
                        ProverClient {
                            prover: Box::new(NetworkProver::from_env().unwrap()),
                        }
                    } else {
                        panic!("network feature is not enabled")
                    }
                }
            }
            ProverMode::Mock => ProverClient::mock(),
        }
    }
}

/// Builder type for network prover.
#[cfg(feature = "network")]
#[derive(Debug, Default)]
pub struct NetworkProverBuilder {
    private_key: Option<String>,
    rpc_url: Option<String>,
    skip_simulation: bool,
}

#[cfg(feature = "network")]
impl NetworkProverBuilder {
    ///  Sets the private key.
    pub fn private_key(mut self, private_key: String) -> Self {
        self.private_key = Some(private_key);
        self
    }

    /// Sets the RPC URL.
    pub fn rpc_url(mut self, rpc_url: String) -> Self {
        self.rpc_url = Some(rpc_url);
        self
    }

    /// Skips simulation.
    pub fn skip_simulation(mut self) -> Self {
        self.skip_simulation = true;
        self
    }

    // /// Creates a new [NetworkProverV1].
    // #[cfg(feature = "network")]
    // pub fn build(self) -> NetworkProverV1 {
    //     let private_key = self.private_key.expect("The private key is required");

    //     NetworkProverV1::new(&private_key, self.rpc_url, self.skip_simulation)
    // }

    /// Creates a new [NetworkProverV2].
    #[cfg(feature = "network-v2")]
    pub fn build_v2(self) -> NetworkProverV2 {
        let private_key = self.private_key.expect("The private key is required");

        NetworkProverV2::new(&private_key, self.rpc_url, self.skip_simulation)
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::committed_public_values;
    use crate::ZKMProof;
    use crate::ZKMProof::Groth16;
    use crate::{utils, ProverClient, ZKMStdin};
    use p3_field::PrimeField;
    use zkm_primitives::io::ZKMPublicValues;
    use zkm_prover::HashableKey;

    #[test]
    fn test_execute() {
        utils::setup_logger();
        let client = ProverClient::cpu();
        let elf = test_artifacts::FIBONACCI_ELF;
        let mut stdin = ZKMStdin::new();
        stdin.write(&10usize);
        let (_, _report) = client.execute(elf, stdin).run().unwrap();
        // tracing::info!("gas = {}", report.estimate_gas());
    }

    #[test]
    #[should_panic]
    fn test_execute_panic() {
        utils::setup_logger();
        let client = ProverClient::cpu();
        let elf = test_artifacts::PANIC_ELF;
        let mut stdin = ZKMStdin::new();
        stdin.write(&10usize);
        client.execute(elf, stdin).run().unwrap();
    }

    #[should_panic]
    #[test]
    fn test_cycle_limit_fail() {
        utils::setup_logger();
        let client = ProverClient::cpu();
        let elf = test_artifacts::PANIC_ELF;
        let mut stdin = ZKMStdin::new();
        stdin.write(&10usize);
        client.execute(elf, stdin).max_cycles(1).run().unwrap();
    }

    #[test]
    fn test_e2e_core() {
        utils::setup_logger();
        let client = ProverClient::cpu();
        let elf = test_artifacts::FIBONACCI_ELF;
        let (pk, vk) = client.setup(elf);
        let mut stdin = ZKMStdin::new();
        stdin.write(&10usize);

        // Generate proof & verify.
        let mut proof = client.prove(&pk, stdin).run().unwrap();
        client.verify(&proof, &vk).unwrap();

        // Test invalid public values.
        proof.public_values = ZKMPublicValues::from(&[255, 4, 84]);
        if client.verify(&proof, &vk).is_ok() {
            panic!("verified proof with invalid public values")
        }
    }

    #[test]
    fn test_e2e_compressed() {
        utils::setup_logger();
        let client = ProverClient::cpu();
        let elf = test_artifacts::FIBONACCI_ELF;
        let (pk, vk) = client.setup(elf);
        let mut stdin = ZKMStdin::new();
        stdin.write(&10usize);

        // Generate proof & verify.
        let mut proof = client.prove(&pk, stdin).compressed().run().unwrap();
        client.verify(&proof, &vk).unwrap();

        // Test invalid public values.
        proof.public_values = ZKMPublicValues::from(&[255, 4, 84]);
        if client.verify(&proof, &vk).is_ok() {
            panic!("verified proof with invalid public values")
        }
    }

    #[test]
    fn test_e2e_prove_plonk() {
        utils::setup_logger();
        let client = ProverClient::cpu();
        let elf = test_artifacts::FIBONACCI_ELF;
        let (pk, vk) = client.setup(elf);
        let mut stdin = ZKMStdin::new();
        stdin.write(&10usize);

        // Generate proof & verify.
        let mut proof = client.prove(&pk, stdin).plonk().run().unwrap();
        client.verify(&proof, &vk).unwrap();

        // Test invalid public values.
        proof.public_values = ZKMPublicValues::from(&[255, 4, 84]);
        if client.verify(&proof, &vk).is_ok() {
            panic!("verified proof with invalid public values")
        }
    }

    #[test]
    fn test_e2e_prove_groth16() {
        utils::setup_logger();
        let client = ProverClient::cpu();
        let elf = test_artifacts::HELLO_WORLD_ELF;
        let (pk, vk) = client.setup(elf);
        let stdin = ZKMStdin::new();

        // Generate proof & verify.
        let proof = client.prove(&pk, stdin).groth16().run().unwrap();
        client.verify(&proof, &vk).unwrap();
    }

    #[test]
    fn test_e2e_prove_plonk_mock() {
        utils::setup_logger();
        let client = ProverClient::mock();
        let elf = test_artifacts::FIBONACCI_ELF;
        let (pk, vk) = client.setup(elf);
        let mut stdin = ZKMStdin::new();
        stdin.write(&10usize);
        let proof = client.prove(&pk, stdin).plonk().run().unwrap();
        client.verify(&proof, &vk).unwrap();
    }

    #[test]
    fn test_groth16_public_values() {
        let client = ProverClient::cpu();
        let elf = test_artifacts::HELLO_WORLD_ELF;
        let (pk, vk) = client.setup(elf);
        let stdin = ZKMStdin::new();

        // Generate proof & verify.
        let proof = client.prove(&pk, stdin).groth16().run().unwrap();
        client.verify(&proof, &vk).unwrap();

        let string_input = b"hello world".to_vec();
        let guest_committed_values = bincode::serialize(&string_input).unwrap();
        assert_eq!(proof.public_values.as_ref(), guest_committed_values);

        let inner_proof = match proof.proof.clone() {
            Groth16(proof) => proof,
            _ => panic!("expected a compressed proof"),
        };

        let vk_hash = vk.hash_bn254().as_canonical_biguint().to_string();
        assert_eq!(vk_hash, inner_proof.public_inputs[0], "vk hash does not match");

        let committed_public_values = committed_public_values(proof.public_values.as_ref());
        assert_eq!(
            committed_public_values, inner_proof.public_inputs[1],
            "committed public values does not match"
        );
    }

    #[test]
    fn test_compress_to_groth16() {
        utils::setup_logger();
        let client = ProverClient::new();
        let elf = test_artifacts::HELLO_WORLD_ELF;
        let (pk, vk) = client.setup(elf);
        let stdin = ZKMStdin::new();

        // Generate proof & verify.
        let proof = client.prove(&pk, stdin.clone()).compressed().run().unwrap();
        client.verify(&proof, &vk).unwrap();

        //--------------------------------------------

        let client = ProverClient::new();

        let mut stdin = ZKMStdin::new();
        stdin.write::<ZKMPublicValues>(&proof.public_values);

        let ZKMProof::Compressed(proof) = proof.proof else { panic!() };
        stdin.write_proof(*proof, vk.vk.clone());

        let proof = client.prove(&pk, stdin).compress_to_groth16().run().unwrap();
        client.verify(&proof, &vk).unwrap();
    }
}

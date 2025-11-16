use std::{
    collections::HashMap,
    error::Error as StdError,
    future::Future,
    process::{Command, Stdio},
    sync::LazyLock,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use reqwest::{Request, Response};
use serde::{Deserialize, Serialize};
use tokio::task::block_in_place;
use twirp::{
    async_trait,
    reqwest::{self},
    url::Url,
    Client, ClientError, Middleware, Next,
};
use zkm_core_machine::{io::ZKMStdin, reduce::ZKMReduceProof, utils::ZKMCoreProverError};
use zkm_prover::{
    InnerSC, OuterSC, ZKMCoreProof, ZKMProvingKey, ZKMRecursionProverError, ZKMVerifyingKey,
};

use crate::api::{ProverServiceClient, ReadyRequest};

pub mod api {
    include!(concat!(env!("OUT_DIR"), "/api.rs"));
}

static GPU_CONTAINERS: LazyLock<Mutex<HashMap<String, Arc<AtomicBool>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// A remote client to [zkm_prover::ZKMProver] that runs inside a container.
///
/// This is currently used to provide experimental support for GPU hardware acceleration.
///
/// **WARNING**: This is an experimental feature and may not work as expected.
pub struct ZKMCudaProver {
    /// The gRPC client to communicate with the container.
    client: Client,
    /// The GPU server container, if managed by the prover.
    managed_container: Option<CudaProverContainer>,
}

pub struct CudaProverContainer {
    /// The name of the container.
    name: String,
    /// A flag to indicate whether the container has already been cleaned up.
    cleaned_up: Arc<AtomicBool>,
}

/// The payload for the [zkm_prover::ZKMProver::setup] method.
///
/// This object is used to serialize and deserialize the payloads for the GPU server.
#[derive(Serialize, Deserialize)]
pub struct SetupRequestPayload {
    pub elf: Vec<u8>,
}

/// The payload for the [zkm_prover::ZKMProver::setup] method response.
///
/// We use this object to serialize and deserialize the payload from the server to the client.
#[derive(Serialize, Deserialize)]
pub struct SetupResponsePayload {
    pub pk: ZKMProvingKey,
    pub vk: ZKMVerifyingKey,
}

/// The payload for the [zkm_prover::ZKMProver::prove_core] method.
///
/// This object is used to serialize and deserialize the payloads for the GPU server.
#[derive(Serialize, Deserialize)]
pub struct ProveCoreRequestPayload {
    /// The input stream.
    pub stdin: ZKMStdin,
}

/// The payload for the [zkm_prover::ZKMProver::stateless_prove_core] method.
///
/// This object is used to serialize and deserialize the payloads for the GPU server.
/// The proving key is sent in the payload with the request to allow the GPU server to generate
/// proofs without re-generating the proving key.
#[derive(Serialize, Deserialize)]
pub struct StatelessProveCoreRequestPayload {
    /// The input stream.
    pub stdin: ZKMStdin,
    /// The proving key.
    pub pk: ZKMProvingKey,
}

/// The payload for the [zkm_prover::ZKMProver::compress] method.
///
/// This object is used to serialize and deserialize the payloads for the GPU server.
#[derive(Serialize, Deserialize)]
pub struct CompressRequestPayload {
    /// The verifying key.
    pub vk: ZKMVerifyingKey,
    /// The core proof.
    pub proof: ZKMCoreProof,
    /// The deferred proofs.
    pub deferred_proofs: Vec<ZKMReduceProof<InnerSC>>,
}

/// The payload for the [zkm_prover::ZKMProver::shrink] method.
///
/// This object is used to serialize and deserialize the payloads for the GPU server.
#[derive(Serialize, Deserialize)]
pub struct ShrinkRequestPayload {
    pub reduced_proof: ZKMReduceProof<InnerSC>,
}

/// The payload for the [zkm_prover::ZKMProver::wrap_bn254] method.
///
/// This object is used to serialize and deserialize the payloads for the GPU server.
#[derive(Serialize, Deserialize)]
pub struct WrapRequestPayload {
    pub reduced_proof: ZKMReduceProof<InnerSC>,
}

/// Defines how the GPU server is created.
#[derive(Debug)]
pub enum ZKMGpuServer {
    External { endpoint: String },
    Local { visible_device_index: Option<u64>, port: Option<u64> },
}

impl Default for ZKMGpuServer {
    fn default() -> Self {
        if std::env::var("CUDA_RUN_DOCKER")
            .map(|s| s == "1" || s.to_lowercase() == "true")
            .unwrap_or(true)
        {
            let visible_device_index =
                if let Ok(device) = std::env::var("CUDA_VISIBLE_DEVICE_INDEX") {
                    Some(device.parse().expect("Invalid CUDA device index"))
                } else {
                    None
                };
            let port = if let Ok(port) = std::env::var("CUDA_PORT") {
                Some(port.parse().expect("Invalid CUDA local server port"))
            } else {
                None
            };
            return Self::Local { visible_device_index, port };
        }

        let endpoint =
            std::env::var("CUDA_ENDPOINT").unwrap_or("http://localhost:3000/twirp/".to_string());
        Self::External { endpoint }
    }
}

impl ZKMCudaProver {
    /// Creates a new [ZKMCudaProver] that can be used to communicate with the GPU server at
    /// `gpu_endpoint`, or if not provided, create one that runs inside a Docker container.
    pub fn new(gpu_server: ZKMGpuServer) -> Result<Self, Box<dyn StdError>> {
        let reqwest_middlewares = vec![Box::new(LoggingMiddleware) as Box<dyn Middleware>];

        let prover = match gpu_server {
            ZKMGpuServer::External { endpoint } => {
                let client = Client::new(
                    Url::parse(&endpoint).expect("failed to parse url"),
                    reqwest::Client::new(),
                    reqwest_middlewares,
                )
                .expect("failed to create client");

                ZKMCudaProver { client, managed_container: None }
            }
            ZKMGpuServer::Local { visible_device_index, port } => {
                Self::start_gpu_server(reqwest_middlewares, visible_device_index, port)?
            }
        };

        let timeout = Duration::from_secs(300);
        let start_time = Instant::now();

        block_on(async {
            tracing::info!("waiting for proving server to be ready");
            loop {
                if start_time.elapsed() > timeout {
                    return Err("Timeout: proving server did not become ready within 300 seconds. Please check your Docker container and network settings.".to_string());
                }

                let request = ReadyRequest {};
                match prover.client.ready(request).await {
                    Ok(response) if response.ready => {
                        tracing::info!("proving server is ready");
                        break;
                    }
                    Ok(_) => {
                        tracing::info!("proving server is not ready, retrying...");
                    }
                    Err(e) => {
                        tracing::warn!("Error checking server readiness: {}", e);
                    }
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Ok(())
        })?;

        Ok(prover)
    }

    fn check_docker_availability() -> Result<bool, Box<dyn std::error::Error>> {
        match Command::new("docker").arg("version").output() {
            Ok(output) => Ok(output.status.success()),
            Err(_) => Ok(false),
        }
    }

    fn start_gpu_server(
        reqwest_middlewares: Vec<Box<dyn Middleware>>,
        visible_device_index: Option<u64>,
        port: Option<u64>,
    ) -> Result<ZKMCudaProver, Box<dyn StdError>> {
        // If the gpu endpoint url hasn't been provided, we start the Docker container
        let container_name =
            port.map(|p| format!("ziren-gpu-{p}")).unwrap_or("ziren-gpu".to_string());
        let image_name = std::env::var("ZKM_GPU_IMAGE")
            .unwrap_or_else(|_| "projectzkm/ziren-gpu:latest".to_string());

        let cleaned_up = Arc::new(AtomicBool::new(false));
        let port = port.unwrap_or(3000);
        let gpus = visible_device_index.map(|i| format!("device={i}")).unwrap_or("all".to_string());

        // Check if Docker is available and the user has necessary permissions
        if !Self::check_docker_availability()? {
            return Err("Docker is not available or you don't have the necessary permissions. Please ensure Docker is installed and you are part of the docker group.".into());
        }

        // Pull the docker image if it's not present
        if let Err(e) = Command::new("docker").args(["pull", &image_name]).output() {
            return Err(format!("Failed to pull Docker image: {e}. Please check your internet connection and Docker permissions.").into());
        }

        // Start the docker container
        let rust_log_level = std::env::var("RUST_LOG").unwrap_or_else(|_| "none".to_string());
        Command::new("docker")
            .args([
                "run",
                "-e",
                &format!("RUST_LOG={rust_log_level}"),
                "-p",
                &format!("{port}:3000"),
                "--rm",
                "--gpus",
                &gpus,
                "--name",
                &container_name,
                &image_name,
            ])
            // Redirect stdout and stderr to the parent process
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("Failed to start Docker container: {e}. Please check your Docker installation and permissions."))?;

        GPU_CONTAINERS.lock()?.insert(container_name.clone(), cleaned_up.clone());

        // Kill the container on control-c
        // The error returned by set_handler is ignored to avoid panic when the handler has already
        // been set.
        let _ = ctrlc::set_handler(move || {
            tracing::info!("received Ctrl+C, cleaning up...");

            for (container_name, cleanup_flag) in GPU_CONTAINERS.lock().unwrap().iter() {
                if !cleanup_flag.load(Ordering::SeqCst) {
                    cleanup_container(container_name);
                    cleanup_flag.store(true, Ordering::SeqCst);
                }
            }
            std::process::exit(0);
        });

        // Wait a few seconds for the container to start
        std::thread::sleep(Duration::from_secs(2));

        let client = Client::new(
            Url::parse(&format!("http://localhost:{port}/twirp/")).expect("failed to parse url"),
            reqwest::Client::new(),
            reqwest_middlewares,
        )
        .expect("failed to create client");

        Ok(ZKMCudaProver {
            client,
            managed_container: Some(CudaProverContainer { name: container_name, cleaned_up }),
        })
    }

    /// Executes the [zkm_prover::ZKMProver::setup] method inside the container.
    pub fn setup(&self, elf: &[u8]) -> Result<(ZKMProvingKey, ZKMVerifyingKey), Box<dyn StdError>> {
        let payload = SetupRequestPayload { elf: elf.to_vec() };
        let request = crate::api::SetupRequest { data: bincode::serialize(&payload).unwrap() };
        let response = block_on(async { self.client.setup(request).await }).unwrap();
        let payload: SetupResponsePayload = bincode::deserialize(&response.result).unwrap();
        Ok((payload.pk, payload.vk))
    }

    /// Executes the [zkm_prover::ZKMProver::prove_core] method inside the container.
    ///
    /// You will need at least 24GB of VRAM to run this method.
    pub fn prove_core(&self, stdin: &ZKMStdin) -> Result<ZKMCoreProof, ZKMCoreProverError> {
        let payload = ProveCoreRequestPayload { stdin: stdin.clone() };
        let request = crate::api::ProveCoreRequest { data: bincode::serialize(&payload).unwrap() };
        let response = block_on(async { self.client.prove_core(request).await }).unwrap();
        let proof: ZKMCoreProof = bincode::deserialize(&response.result).unwrap();
        Ok(proof)
    }

    /// Executes the [zkm_prover::ZKMProver::prove_core] method inside the container.
    ///
    /// You will need at least 24GB of VRAM to run this method.
    pub fn prove_core_stateless(
        &self,
        pk: &ZKMProvingKey,
        stdin: &ZKMStdin,
    ) -> Result<ZKMCoreProof, ZKMCoreProverError> {
        let payload = StatelessProveCoreRequestPayload { pk: pk.clone(), stdin: stdin.clone() };
        let request = crate::api::ProveCoreRequest { data: bincode::serialize(&payload).unwrap() };
        let response = block_on(async { self.client.prove_core_stateless(request).await }).unwrap();
        let proof: ZKMCoreProof = bincode::deserialize(&response.result).unwrap();
        Ok(proof)
    }

    /// Executes the [zkm_prover::ZKMProver::compress] method inside the container.
    ///
    /// You will need at least 24GB of VRAM to run this method.
    pub fn compress(
        &self,
        vk: &ZKMVerifyingKey,
        proof: ZKMCoreProof,
        deferred_proofs: Vec<ZKMReduceProof<InnerSC>>,
    ) -> Result<ZKMReduceProof<InnerSC>, ZKMRecursionProverError> {
        let payload = CompressRequestPayload { vk: vk.clone(), proof, deferred_proofs };
        let request = crate::api::CompressRequest { data: bincode::serialize(&payload).unwrap() };

        let response = block_on(async { self.client.compress(request).await }).unwrap();
        let proof: ZKMReduceProof<InnerSC> = bincode::deserialize(&response.result).unwrap();
        Ok(proof)
    }

    /// Executes the [zkm_prover::ZKMProver::shrink] method inside the container.
    ///
    /// You will need at least 24GB of VRAM to run this method.
    pub fn shrink(
        &self,
        reduced_proof: ZKMReduceProof<InnerSC>,
    ) -> Result<ZKMReduceProof<InnerSC>, ZKMRecursionProverError> {
        let payload = ShrinkRequestPayload { reduced_proof: reduced_proof.clone() };
        let request = crate::api::ShrinkRequest { data: bincode::serialize(&payload).unwrap() };

        let response = block_on(async { self.client.shrink(request).await }).unwrap();
        let proof: ZKMReduceProof<InnerSC> = bincode::deserialize(&response.result).unwrap();
        Ok(proof)
    }

    /// Executes the [zkm_prover::ZKMProver::wrap_bn254] method inside the container.
    ///
    /// You will need at least 24GB of VRAM to run this method.
    pub fn wrap_bn254(
        &self,
        reduced_proof: ZKMReduceProof<InnerSC>,
    ) -> Result<ZKMReduceProof<OuterSC>, ZKMRecursionProverError> {
        let payload = WrapRequestPayload { reduced_proof: reduced_proof.clone() };
        let request = crate::api::WrapRequest { data: bincode::serialize(&payload).unwrap() };

        let response = block_on(async { self.client.wrap(request).await }).unwrap();
        let proof: ZKMReduceProof<OuterSC> = bincode::deserialize(&response.result).unwrap();
        Ok(proof)
    }
}

impl Default for ZKMCudaProver {
    fn default() -> Self {
        Self::new(Default::default()).expect("Failed to create ZKMCudaProver")
    }
}

impl Drop for ZKMCudaProver {
    fn drop(&mut self) {
        if let Some(container) = &self.managed_container {
            if !container.cleaned_up.load(Ordering::SeqCst) {
                tracing::debug!("dropping ZKMProverClient, cleaning up...");
                cleanup_container(&container.name);
                container.cleaned_up.store(true, Ordering::SeqCst);
            }
        }
    }
}

/// Cleans up the a docker container with the given name.
fn cleanup_container(container_name: &str) {
    if let Err(e) = Command::new("docker").args(["rm", "-f", container_name]).output() {
        eprintln!(
            "Failed to remove container: {e}. You may need to manually remove it using 'docker rm -f {container_name}'"
        );
    }
}

/// Utility method for blocking on an async function.
///
/// If we're already in a tokio runtime, we'll block in place. Otherwise, we'll create a new
/// runtime.
pub fn block_on<T>(fut: impl Future<Output = T>) -> T {
    // Handle case if we're already in an tokio runtime.
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        block_in_place(|| handle.block_on(fut))
    } else {
        // Otherwise create a new runtime.
        let rt = tokio::runtime::Runtime::new().expect("Failed to create a new runtime");
        rt.block_on(fut)
    }
}

struct LoggingMiddleware;

pub type Result<T, E = ClientError> = std::result::Result<T, E>;

#[async_trait]
impl Middleware for LoggingMiddleware {
    async fn handle(&self, req: Request, next: Next<'_>) -> Result<Response> {
        let response = next.run(req).await;
        match response {
            Ok(response) => {
                tracing::info!("{:?}", response);
                Ok(response)
            }
            Err(e) => Err(e),
        }
    }
}

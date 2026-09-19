use std::{
    collections::HashMap,
    error::Error as StdError,
    future::Future,
    process::{Command, Stdio},
    sync::LazyLock,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
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
    /// What the server reported spending on the calls since the last
    /// [`Self::take_server_prove_ms`], in milliseconds.
    ///
    /// A caller that times the RPC itself also times the request waiting for
    /// the server's prover, which is not proving time: a pipelined caller can
    /// have the next request in flight while the current one is still being
    /// proved.  The server times only its own work and reports it here.
    server_prove_ms: AtomicU64,
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
    /// The caller will send the core proof straight back in a `compress`
    /// request.  The server keeps the shard proofs (and the stdin) for that
    /// request and answers this one with an EMPTY proof body -- public values
    /// and the cycle count only -- instead of shipping ~140 MB down and then
    /// back up.  Ignored by servers that predate the field (serde default).
    #[serde(default)]
    pub retain_for_compress: bool,
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
                    Some(device.parse().unwrap_or_else(|e| {
                        panic!("CUDA_VISIBLE_DEVICE_INDEX=`{device}` is not an index: {e}")
                    }))
                } else {
                    None
                };
            let port = if let Ok(port) = std::env::var("CUDA_PORT") {
                Some(port.parse().unwrap_or_else(|e| {
                    panic!("CUDA_PORT=`{port}` is not a port number: {e}")
                }))
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

/// Every RPC error names the operation it came from. Six methods share one
/// transport, so "the CUDA prover failed" does not say which call died, and a
/// version-skew decode failure is indistinguishable from a dead socket without
/// it. These four map the two remote-boundary failures -- transport and codec --
/// into the error type each method already declares.
///
/// Both are ordinary remote failures, not invariant violations: a restarted
/// container, a truncated reply, or a server built from a different commit must
/// surface as the declared `Err`, not terminate the caller's process.
fn core_transport(op: &'static str, e: impl std::fmt::Display) -> ZKMCoreProverError {
    ZKMCoreProverError::IoError(std::io::Error::other(format!("CUDA RPC `{op}` failed: {e}")))
}

fn core_codec(op: &'static str, what: &'static str, e: impl std::fmt::Display) -> ZKMCoreProverError {
    ZKMCoreProverError::SerializationError(Box::new(bincode::ErrorKind::Custom(format!(
        "CUDA RPC `{op}`: could not {what}: {e} (a truncated reply or a server/client version \
         mismatch reaches here)"
    ))))
}

fn rec_transport(op: &'static str, e: impl std::fmt::Display) -> ZKMRecursionProverError {
    ZKMRecursionProverError::RuntimeError(format!("CUDA RPC `{op}` failed: {e}"))
}

fn rec_codec(op: &'static str, what: &'static str, e: impl std::fmt::Display) -> ZKMRecursionProverError {
    ZKMRecursionProverError::RuntimeError(format!(
        "CUDA RPC `{op}`: could not {what}: {e} (a truncated reply or a server/client version \
         mismatch reaches here)"
    ))
}

impl ZKMCudaProver {
    /// Creates a new [ZKMCudaProver] that can be used to communicate with the GPU server at
    /// `gpu_endpoint`, or if not provided, create one that runs inside a Docker container.
    pub fn new(gpu_server: ZKMGpuServer) -> Result<Self, Box<dyn StdError>> {
        let reqwest_middlewares = vec![Box::new(LoggingMiddleware) as Box<dyn Middleware>];

        let prover = match gpu_server {
            ZKMGpuServer::External { endpoint } => {
                // `CUDA_ENDPOINT` is configuration: a typo in it must be a
                // returned error, not a panic out of a `Result`-returning fn.
                let url = Url::parse(&endpoint)
                    .map_err(|e| format!("CUDA_ENDPOINT `{endpoint}` is not a URL: {e}"))?;
                let client = Client::new(url, reqwest::Client::new(), reqwest_middlewares)
                    .map_err(|e| format!("could not create the CUDA RPC client: {e}"))?;

                ZKMCudaProver {
                    client,
                    managed_container: None,
                    server_prove_ms: AtomicU64::new(0),
                }
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
        // This container receives the private witness input and runs on the
        // proving host with GPU access, so which bytes it is remains a security
        // decision. A tag is MUTABLE: whoever controls the registry or the tag
        // controls the code that sees the witness. `ZKM_GPU_IMAGE` accepts a
        // digest (`repo@sha256:...`), which is what production should set; a
        // reviewed digest cannot be hard-coded here without someone reviewing
        // it, so the default stays a tag and says so.
        let image_name = std::env::var("ZKM_GPU_IMAGE")
            .unwrap_or_else(|_| "projectzkm/ziren-gpu:latest".to_string());
        if !image_name.contains("@sha256:") {
            tracing::warn!(
                "the CUDA prover image {image_name:?} is not pinned by digest; it is resolved \
                 fresh from the registry and receives the private witness input. Set \
                 ZKM_GPU_IMAGE to a reviewed repo@sha256:... digest for anything but local \
                 development."
            );
        }

        let cleaned_up = Arc::new(AtomicBool::new(false));
        let port = port.unwrap_or(3000);
        let gpus = visible_device_index.map(|i| format!("device={i}")).unwrap_or("all".to_string());

        // Check if Docker is available and the user has necessary permissions
        if !Self::check_docker_availability()? {
            return Err("Docker is not available or you don't have the necessary permissions. Please ensure Docker is installed and you are part of the docker group.".into());
        }

        // Pull the image, and require that the pull actually SUCCEEDED.
        //
        // `output()` is `Ok` whenever docker could be spawned, whatever docker
        // then reported, so this used to check only that the binary exists: a
        // failed pull -- no network, no credentials, tag withdrawn -- fell
        // through to `docker run` on whatever stale local image happened to be
        // lying around, silently proving with code nobody selected.
        let pull = Command::new("docker")
            .args(["pull", &image_name])
            .output()
            .map_err(|e| format!("Failed to run `docker pull`: {e}. Please check your Docker installation and permissions."))?;
        if !pull.status.success() {
            return Err(format!(
                "`docker pull {image_name}` failed ({}): {}. Refusing to fall back to a local \
                 image that may differ from the requested one.",
                pull.status,
                String::from_utf8_lossy(&pull.stderr).trim(),
            )
            .into());
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

            // `unwrap_or_else(into_inner)`, not `unwrap`: the lock is poisoned
            // exactly when another thread panicked, which is when this handler
            // most needs to run. Panicking here instead leaks the container.
            let containers =
                GPU_CONTAINERS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            for (container_name, cleanup_flag) in containers.iter() {
                if !cleanup_flag.load(Ordering::SeqCst) {
                    cleanup_container(container_name);
                    cleanup_flag.store(true, Ordering::SeqCst);
                }
            }
            std::process::exit(0);
        });

        // Wait a few seconds for the container to start
        std::thread::sleep(Duration::from_secs(2));

        let endpoint = format!("http://localhost:{port}/twirp/");
        let url =
            Url::parse(&endpoint).map_err(|e| format!("`{endpoint}` is not a URL: {e}"))?;
        let client = Client::new(url, reqwest::Client::new(), reqwest_middlewares)
            .map_err(|e| format!("could not create the CUDA RPC client: {e}"))?;

        Ok(ZKMCudaProver {
            client,
            managed_container: Some(CudaProverContainer { name: container_name, cleaned_up }),
            server_prove_ms: AtomicU64::new(0),
        })
    }

    /// Add what the server reported spending on one call.
    fn record_server_prove_ms(&self, ms: u64) {
        if ms > 0 {
            self.server_prove_ms.fetch_add(ms, Ordering::Relaxed);
        }
    }

    /// What the server reported spending since the last call to this, in
    /// milliseconds; `None` when it reported nothing (a server that predates
    /// the field).  Reading it clears the accumulator.
    pub fn take_server_prove_ms(&self) -> Option<u64> {
        match self.server_prove_ms.swap(0, Ordering::Relaxed) {
            0 => None,
            ms => Some(ms),
        }
    }

    /// Executes the [zkm_prover::ZKMProver::setup] method inside the container.
    pub fn setup(&self, elf: &[u8]) -> Result<(ZKMProvingKey, ZKMVerifyingKey), Box<dyn StdError>> {
        let payload = SetupRequestPayload { elf: elf.to_vec() };
        let data = bincode::serialize(&payload)
            .map_err(|e| format!("CUDA RPC `setup`: could not encode the request: {e}"))?;
        let request = crate::api::SetupRequest { data };
        let response = block_on(async { self.client.setup(request).await })
            .map_err(|e| format!("CUDA RPC `setup` failed: {e}"))?;
        let payload: SetupResponsePayload =
            bincode::deserialize(&response.result).map_err(|e| {
                format!(
                    "CUDA RPC `setup`: could not decode the response: {e} (a truncated reply or a \
                     server/client version mismatch reaches here)"
                )
            })?;
        Ok((payload.pk, payload.vk))
    }

    /// Executes the [zkm_prover::ZKMProver::prove_core] method inside the container.
    ///
    /// You will need at least 24GB of VRAM to run this method.
    pub fn prove_core(&self, stdin: &ZKMStdin) -> Result<ZKMCoreProof, ZKMCoreProverError> {
        let payload = ProveCoreRequestPayload { stdin: stdin.clone() };
        let data = bincode::serialize(&payload)
            .map_err(|e| core_codec("prove_core", "encode the request", e))?;
        let request = crate::api::ProveCoreRequest { data };
        let response = block_on(async { self.client.prove_core(request).await })
            .map_err(|e| core_transport("prove_core", e))?;
        self.record_server_prove_ms(response.prove_ms);
        let proof: ZKMCoreProof = bincode::deserialize(&response.result)
            .map_err(|e| core_codec("prove_core", "decode the response", e))?;
        Ok(proof)
    }

    /// Executes the [zkm_prover::ZKMProver::stateless_prove_core] method inside the container.
    ///
    /// You will need at least 24GB of VRAM to run this method.
    pub fn prove_core_stateless(
        &self,
        pk: &ZKMProvingKey,
        stdin: &ZKMStdin,
    ) -> Result<ZKMCoreProof, ZKMCoreProverError> {
        self.prove_core_stateless_retaining(pk, stdin, false)
    }

    /// [`Self::prove_core_stateless`] for a caller that will [`Self::compress`]
    /// the result next: with `retain_for_compress` the server keeps the shard
    /// proofs and the returned [`ZKMCoreProof`] carries an empty proof body
    /// (public values and cycles are real).  Hand that value to `compress`
    /// unchanged; the server substitutes what it kept.
    pub fn prove_core_stateless_retaining(
        &self,
        pk: &ZKMProvingKey,
        stdin: &ZKMStdin,
        retain_for_compress: bool,
    ) -> Result<ZKMCoreProof, ZKMCoreProverError> {
        let payload = StatelessProveCoreRequestPayload {
            pk: pk.clone(),
            stdin: stdin.clone(),
            retain_for_compress,
        };
        let data = bincode::serialize(&payload)
            .map_err(|e| core_codec("prove_core_stateless", "encode the request", e))?;
        let request = crate::api::ProveCoreRequest { data };
        let response = block_on(async { self.client.prove_core_stateless(request).await })
            .map_err(|e| core_transport("prove_core_stateless", e))?;
        self.record_server_prove_ms(response.prove_ms);
        let proof: ZKMCoreProof = bincode::deserialize(&response.result)
            .map_err(|e| core_codec("prove_core_stateless", "decode the response", e))?;
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
        let data = bincode::serialize(&payload)
            .map_err(|e| rec_codec("compress", "encode the request", e))?;
        let request = crate::api::CompressRequest { data };
        let response = block_on(async { self.client.compress(request).await })
            .map_err(|e| rec_transport("compress", e))?;
        self.record_server_prove_ms(response.prove_ms);
        let proof: ZKMReduceProof<InnerSC> = bincode::deserialize(&response.result)
            .map_err(|e| rec_codec("compress", "decode the response", e))?;
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
        let data = bincode::serialize(&payload)
            .map_err(|e| rec_codec("shrink", "encode the request", e))?;
        let request = crate::api::ShrinkRequest { data };
        let response = block_on(async { self.client.shrink(request).await })
            .map_err(|e| rec_transport("shrink", e))?;
        let proof: ZKMReduceProof<InnerSC> = bincode::deserialize(&response.result)
            .map_err(|e| rec_codec("shrink", "decode the response", e))?;
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
        let data = bincode::serialize(&payload)
            .map_err(|e| rec_codec("wrap_bn254", "encode the request", e))?;
        let request = crate::api::WrapRequest { data };
        let response = block_on(async { self.client.wrap(request).await })
            .map_err(|e| rec_transport("wrap_bn254", e))?;
        let proof: ZKMReduceProof<OuterSC> = bincode::deserialize(&response.result)
            .map_err(|e| rec_codec("wrap_bn254", "decode the response", e))?;
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
                tracing::debug!("Dropping ZKMCudaProver, cleaning up...");
                cleanup_container(&container.name);
                container.cleaned_up.store(true, Ordering::SeqCst);
            }
        }
    }
}

/// Cleans up a Docker container with the given name.
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

#[cfg(test)]
impl ZKMCudaProver {
    /// `new` blocks for up to 300 seconds waiting for the server to report
    /// ready, so the tests build the client directly. Nothing else differs.
    fn connect_without_waiting(endpoint: &str) -> std::result::Result<Self, Box<dyn StdError>> {
        let client = Client::new(
            Url::parse(endpoint)?,
            reqwest::Client::new(),
            vec![Box::new(LoggingMiddleware) as Box<dyn Middleware>],
        )?;
        Ok(ZKMCudaProver { client, managed_container: None, server_prove_ms: AtomicU64::new(0) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A port nothing is listening on: bound to reserve it, then dropped.
    fn dead_endpoint() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        format!("http://127.0.0.1:{port}/twirp/")
    }

    #[test]
    fn an_unreachable_server_is_an_error_not_a_panic() {
        let prover =
            ZKMCudaProver::connect_without_waiting(&dead_endpoint()).expect("the client builds");

        // `setup` returns Box<dyn StdError>, `prove_core` returns
        // ZKMCoreProverError: both used to unwrap the transport result.
        // `let ... else` rather than `expect_err`, because the Ok types here do
        // not implement Debug.
        let Err(err) = prover.setup(&[]) else { panic!("a refused connection must be an error") };
        assert!(format!("{err}").contains("setup"), "the operation is named: {err}");

        let Err(err) = prover.prove_core(&ZKMStdin::new()) else {
            panic!("a refused connection must be an error")
        };
        assert!(matches!(err, ZKMCoreProverError::IoError(_)), "got: {err}");
        assert!(format!("{err}").contains("prove_core"), "the operation is named: {err}");
    }

    #[test]
    fn a_malformed_endpoint_is_an_error_not_a_panic() {
        let Err(err) = ZKMCudaProver::new(ZKMGpuServer::External { endpoint: "not a url".into() })
        else {
            panic!("a bad endpoint must be an error")
        };
        assert!(format!("{err}").contains("CUDA_ENDPOINT"), "got: {err}");
    }

    /// A truncated reply, or one from a server built at a different commit,
    /// arrives as bytes that do not decode. That is the shape of version skew.
    #[test]
    fn an_undecodable_response_is_a_typed_error_naming_the_call() {
        let garbage = [0xffu8; 8];

        let Err(e) = bincode::deserialize::<ZKMCoreProof>(&garbage)
            .map_err(|e| core_codec("prove_core", "decode the response", e))
        else {
            panic!("garbage must not decode")
        };
        assert!(matches!(e, ZKMCoreProverError::SerializationError(_)), "got: {e}");
        let msg = format!("{e}");
        assert!(msg.contains("prove_core") && msg.contains("version mismatch"), "got: {msg}");

        let Err(e) = bincode::deserialize::<ZKMReduceProof<InnerSC>>(&garbage)
            .map_err(|e| rec_codec("compress", "decode the response", e))
        else {
            panic!("garbage must not decode")
        };
        assert!(matches!(e, ZKMRecursionProverError::RuntimeError(_)), "got: {e}");
        assert!(format!("{e}").contains("compress"), "got: {e}");
    }
}

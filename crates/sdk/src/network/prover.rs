use stage_service::stage_service_client::StageServiceClient;
use stage_service::{GenerateProofRequest, GetStatusRequest};

use std::path::Path;
use std::time::Instant;
use std::{env, fs};

use ethers::signers::{LocalWallet, Signer};
use tokio::time::sleep;
use tokio::time::Duration;
use tonic::transport::Endpoint;
use tonic::transport::{Certificate, Identity};
use tonic::transport::{Channel, ClientTlsConfig};

use crate::network::ProverInput;
use crate::{block_on, CpuProver, Prover, ZKMProof, ZKMProofKind, ZKMProofWithPublicValues};
use anyhow::{bail, Result};
use async_trait::async_trait;
use zkm_core_executor::ZKMContext;
use zkm_core_machine::io::ZKMStdin;
use zkm_core_machine::ZKM_CIRCUIT_VERSION;
use zkm_primitives::io::ZKMPublicValues;
use zkm_prover::components::DefaultProverComponents;
use zkm_prover::{ZKMProver, ZKMProvingKey, ZKMVerifyingKey};

#[derive(Clone)]
pub struct Config {
    pub ca_cert: Option<Certificate>,
    pub identity: Option<Identity>,
}

pub mod stage_service {
    tonic::include_proto!("stage.v1");
}

use crate::network::prover::stage_service::{Status, Step};
use crate::provers::{ProofOpts, ProverType};

const DEFAULT_POLL_INTERVAL: u64 = 3000; // 3s
const MIN_POLL_INTERVAL: u64 = 100; // 100ms

pub struct NetworkProver {
    pub endpoint: Endpoint,
    pub wallet: LocalWallet,
    pub local_prover: CpuProver,
    // Polling interval (milliseconds) for checking proof status,
    // default is 3000 milliseconds
    pub poll_interval: u64,
}

impl NetworkProver {
    /// Build from the environment alone.
    pub fn from_env() -> anyhow::Result<NetworkProver> {
        Self::with_overrides(None, None)
    }

    /// Build from explicit credentials/endpoint, falling back to the
    /// environment for whatever is not supplied.
    ///
    /// `ProverClientBuilder::private_key` / `rpc_url` used to be accepted and
    /// then dropped, because network mode always called `from_env()`: a caller
    /// could believe it had selected one key and endpoint while the SDK
    /// connected with unrelated environment credentials.
    pub fn with_overrides(
        private_key: Option<String>,
        rpc_url: Option<String>,
    ) -> anyhow::Result<NetworkProver> {
        let proof_network_privkey = Some(match private_key {
            Some(k) => k,
            None => env::var("ZKM_PRIVATE_KEY")
                .map_err(|_| anyhow::anyhow!("ZKM_PRIVATE_KEY must be set for remote proving"))?,
        });
        let endpoint = Some(match rpc_url {
            Some(u) => u,
            None => env::var("ENDPOINT").unwrap_or("https://152.32.186.45:20002".to_string()),
        });
        let domain_name = Some(env::var("DOMAIN_NAME").unwrap_or("stage".to_string()));
        // The CA used to verify the proving network's certificate.
        //
        // This used to fall back SILENTLY to the repository's bundled
        // `tool/ca.pem`, whose private key (`tool/ca.key`) is committed and
        // therefore public: anyone can mint a certificate under it, so trusting
        // it means any endpoint can impersonate the proving network -- and
        // network proving sends the guest ELF and the private input stream
        // there. The fixture is fine for tests; making it the default was not.
        //
        // `CA_CERT_PATH` is now required, with the bundled fixture reachable
        // only by opting in explicitly.
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let allow_test_ca = env::var("ZKM_ALLOW_INSECURE_TEST_CA")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let ca_cert_path = match env::var("CA_CERT_PATH") {
            Ok(p) => Some(p),
            Err(_) if allow_test_ca => {
                tracing::warn!(
                    "using the bundled INSECURE test CA: its private key is public, so this \
                     connection can be impersonated. Never send sensitive witness data over it."
                );
                Some(manifest_dir.join("tool/ca.pem").to_string_lossy().to_string())
            }
            Err(_) => None,
        };
        let ssl_cert_path = env::var("SSL_CERT_PATH").ok();
        let ssl_key_path = env::var("SSL_KEY_PATH").ok();
        let ssl_config = match (ssl_cert_path.as_ref(), ssl_key_path.as_ref()) {
            (Some(ssl_cert_path), Some(ssl_key_path)) => {
                let ca = ca_cert_path.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "SSL_CERT_PATH/SSL_KEY_PATH are set but CA_CERT_PATH is not. Set it to \
                         the CA that signs the proving network's certificate. To use the \
                         repository's bundled test CA -- whose private key is PUBLIC, so the \
                         connection can be impersonated -- set ZKM_ALLOW_INSECURE_TEST_CA=1."
                    )
                })?;
                let (ca_cert, identity) =
                    get_cert_and_identity(ca, ssl_cert_path.as_ref(), ssl_key_path.as_ref())?;
                Some(Config { ca_cert, identity })
            }
            _ => None,
        };

        let endpoint_para = endpoint.to_owned().expect("ENDPOINT must be set");
        let endpoint = match ssl_config {
            Some(config) => {
                let mut tls_config = ClientTlsConfig::new()
                    .domain_name(domain_name.to_owned().expect("DOMAIN_NAME must be set"));
                if let Some(ca_cert) = config.ca_cert {
                    tls_config = tls_config.ca_certificate(ca_cert);
                }
                if let Some(identity) = config.identity {
                    tls_config = tls_config.identity(identity);
                }
                Endpoint::new(endpoint_para.to_owned())?.tls_config(tls_config)?
            }
            None => Endpoint::new(endpoint_para.to_owned())?,
        };

        let private_key = proof_network_privkey.to_owned().expect("set just above");
        if private_key.is_empty() {
            anyhow::bail!("the proving-network private key is empty");
        }
        let wallet = private_key.parse::<LocalWallet>()?;
        let local_prover = CpuProver::new();
        let mut poll_interval = env::var("ZKM_PROOF_POLL_INTERVAL")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_POLL_INTERVAL);

        if poll_interval < MIN_POLL_INTERVAL {
            poll_interval = MIN_POLL_INTERVAL;
        }

        Ok(NetworkProver { endpoint, wallet, local_prover, poll_interval })
    }

    pub async fn sign_ecdsa(&self, request: &mut GenerateProofRequest) -> Result<()> {
        let sign_data = match request.block_no {
            Some(block_no) => {
                format!("{}&{}&{}", request.proof_id, block_no, request.seg_size)
            }
            None => {
                format!("{}&{}", request.proof_id, request.seg_size)
            }
        };
        let signature = self.wallet.sign_message(sign_data).await?;
        request.signature = signature.to_string();
        Ok(())
    }

    pub async fn download_file(url: &str) -> Result<Vec<u8>> {
        let response = reqwest::get(url).await?;
        // Without this an error page is returned as if it were proof bytes, and
        // the failure surfaces later as an unintelligible decode error.
        let response = response
            .error_for_status()
            .map_err(|e| anyhow::anyhow!("downloading {url} failed: {e}"))?;
        let content = response.bytes().await?;
        Ok(content.to_vec())
    }

    /// Connect to the proving network.
    ///
    /// Fallible on purpose: an unreachable or misconfigured endpoint is an
    /// ordinary remote failure, and this used to `expect` and take the caller's
    /// process down with it.
    pub async fn connect(&self) -> Result<StageServiceClient<Channel>> {
        StageServiceClient::connect(self.endpoint.clone())
            .await
            .map_err(|e| anyhow::anyhow!("could not connect to the proving network: {e}"))
    }

    async fn request_proof(&self, input: ProverInput, kind: ZKMProofKind) -> Result<String> {
        let seg_size =
            env::var("SHARD_SIZE").ok().and_then(|s| s.parse::<u32>().ok()).unwrap_or_default();

        // set the maximum number of prover nodes needed for the proof generation
        let max_prover_num =
            env::var("MAX_PROVER_NUM").ok().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);

        // Single-node mode
        // When enabled, the proving process runs entirely on one node,
        // without splitting into multiple tasks.
        let single_node =
            env::var("SINGLE_NODE").ok().and_then(|s| s.parse::<bool>().ok()).unwrap_or(false);

        let from_step =
            if kind == ZKMProofKind::CompressToGroth16 { Some(Step::InAgg.into()) } else { None };

        let target_step = if kind == ZKMProofKind::Compressed {
            Step::InAgg
        } else if kind == ZKMProofKind::Groth16 || kind == ZKMProofKind::CompressToGroth16 {
            Step::InSnark
        } else {
            unimplemented!("unsupported ZKMProofKind")
        };

        let mut request = GenerateProofRequest {
            proof_id: uuid::Uuid::new_v4().to_string(),
            elf_data: input.elf,
            elf_id: input.elf_id,
            private_input_stream: input.private_inputstream,
            seg_size,
            target_step: Some(target_step.into()),
            from_step,
            receipt_inputs: input.receipts,
            max_prover_num,
            single_node,
            ..Default::default()
        };

        self.sign_ecdsa(&mut request).await?;
        let mut client = self.connect().await?;

        let start = tokio::time::Instant::now();
        let response = client.generate_proof(request).await?.into_inner();
        tracing::info!("[request proof] get response: {:?}", start.elapsed());

        Ok(response.proof_id)
    }

    async fn wait_proof(
        &self,
        proof_id: &str,
        kind: ZKMProofKind,
        timeout: Option<Duration>,
    ) -> Result<(ZKMProof, ZKMPublicValues, u64)> {
        let start_time = Instant::now();
        let mut client = self.connect().await?;
        loop {
            if let Some(timeout) = timeout {
                if start_time.elapsed() > timeout {
                    bail!("Proof generation timed out.");
                }
            }

            let get_status_request = GetStatusRequest { proof_id: proof_id.to_string() };
            let get_status_response = client.get_status(get_status_request).await?.into_inner();

            match Status::from_i32(get_status_response.status) {
                Some(Status::Computing) => {
                    // An unrecognised step means the server is newer than this
                    // client, which is normal skew -- it is not grounds for
                    // aborting a proof that is still progressing.
                    match Step::from_i32(get_status_response.step) {
                        Some(step) => log::info!("proof_id: {proof_id}, step: {step}"),
                        None => log::info!(
                            "proof_id: {proof_id}, step: {} (unknown to this client)",
                            get_status_response.step
                        ),
                    }
                    sleep(Duration::from_millis(self.poll_interval)).await;
                }
                Some(Status::Success) => {
                    let public_values = if kind == ZKMProofKind::CompressToGroth16 {
                        ZKMPublicValues::default()
                    } else {
                        let public_values_bytes =
                            NetworkProver::download_file(&get_status_response.public_values_url)
                                .await?;
                        ZKMPublicValues::from(&public_values_bytes)
                    };

                    // proof
                    let proof: ZKMProof =
                        serde_json::from_slice(&get_status_response.proof_with_public_inputs)
                            .expect("Failed to deserialize proof");
                    let cycles = get_status_response.total_steps;
                    let proving_time = get_status_response.proving_time;
                    tracing::info!(
                        "Proof generation completed successfully, proof_id: {proof_id}, cycles: {cycles}, proving time: {proving_time}ms"
                    );
                    return Ok((proof, public_values, cycles));
                }
                _ => {
                    log::error!(
                        "generate_proof failed status: {}, proof_id: {proof_id}",
                        get_status_response.status
                    );
                    bail!(
                        "generate_proof failed status: {}, proof_id: {proof_id}",
                        get_status_response.status
                    );
                }
            }
        }
    }

    pub async fn prove_with_cycles(
        &self,
        elf: &[u8],
        stdin: ZKMStdin,
        kind: ZKMProofKind,
        // The SHA-256 hash of the ELF, without the 0x prefix.
        // If this field is not none, the network prover will use it to index the cached ELF.
        elf_id: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<(ZKMProofWithPublicValues, u64)> {
        let private_input = stdin.buffer.clone();
        let mut pri_buf = Vec::new();
        bincode::serialize_into(&mut pri_buf, &private_input)?;

        let mut receipts = Vec::new();
        let proofs = stdin.proofs.clone();
        // todo: adapt to proof network after its updating
        for proof in proofs {
            let mut receipt = Vec::new();
            bincode::serialize_into(&mut receipt, &proof)?;
            receipts.push(receipt);
        }

        let elf = if elf_id.is_none() { elf.to_vec() } else { Default::default() };

        let prover_input = ProverInput { elf, private_inputstream: pri_buf, elf_id, receipts };

        log::info!("calling request_proof.");
        let proof_id = self.request_proof(prover_input, kind).await?;

        log::info!("calling wait_proof, proof_id={proof_id}");
        let (proof, mut public_values, cycles) = self.wait_proof(&proof_id, kind, timeout).await?;

        if kind == ZKMProofKind::CompressToGroth16 {
            assert_eq!(private_input.len(), 1);
            public_values = bincode::deserialize(private_input.last().unwrap())?;
        }

        Ok((
            ZKMProofWithPublicValues {
                proof,
                public_values,
                zkm_version: ZKM_CIRCUIT_VERSION.to_string(),
            },
            cycles,
        ))
    }
}

#[async_trait]
impl Prover<DefaultProverComponents> for NetworkProver {
    fn id(&self) -> ProverType {
        ProverType::Network
    }

    fn zkm_prover(&self) -> &ZKMProver<DefaultProverComponents> {
        self.local_prover.zkm_prover()
    }

    fn setup(&self, elf: &[u8]) -> (ZKMProvingKey, ZKMVerifyingKey) {
        self.local_prover.setup(elf)
    }

    /// The proof network can generate Compressed or Groth16 proof.
    fn prove_impl<'a>(
        &'a self,
        pk: &ZKMProvingKey,
        stdin: ZKMStdin,
        opts: ProofOpts,
        _context: ZKMContext<'a>,
        kind: ZKMProofKind,
        elf_id: Option<String>,
    ) -> Result<(ZKMProofWithPublicValues, u64)> {
        // `Prove::timeout` reaches `ProofOpts`; passing `None` here meant a
        // stalled remote request polled forever despite an explicit timeout.
        block_on(self.prove_with_cycles(&pk.elf, stdin, kind, elf_id, opts.timeout))
    }
}

fn get_cert_and_identity(
    ca_cert_path: &str,
    ssl_cert_path: &str,
    ssl_key_path: &str,
) -> anyhow::Result<(Option<Certificate>, Option<Identity>)> {
    let ca_cert_path = Path::new(ca_cert_path);
    let cert_path = Path::new(ssl_cert_path);
    let key_path = Path::new(ssl_key_path);
    if !ca_cert_path.is_file() || !cert_path.is_file() || !key_path.is_file() {
        bail!("both ca_cert_path, ssl_cert_path and ssl_key_path should be valid file")
    }
    let mut ca: Option<Certificate> = None;
    let mut identity: Option<Identity> = None;
    if ca_cert_path.is_file() {
        let ca_cert = fs::read(ca_cert_path)
            .unwrap_or_else(|err| panic!("Failed to read {ca_cert_path:?}, err: {err:?}"));
        ca = Some(Certificate::from_pem(ca_cert));
    }

    if cert_path.is_file() && key_path.is_file() {
        let cert = fs::read(cert_path)
            .unwrap_or_else(|err| panic!("Failed to read {cert_path:?}, err: {err:?}"));
        let key = fs::read(key_path)
            .unwrap_or_else(|err| panic!("Failed to read {key_path:?}, err: {err:?}"));
        identity = Some(Identity::from_pem(cert, key));
    }
    Ok((ca, identity))
}

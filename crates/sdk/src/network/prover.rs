use stage_service::stage_service_client::StageServiceClient;
use stage_service::{GenerateProofRequest, GetStatusRequest};

use std::time::Instant;
use std::{env, fs};

use tokio::time::sleep;
use tokio::time::Duration;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::transport::Certificate;
use tonic::transport::Endpoint;
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

pub mod stage_service {
    tonic::include_proto!("stage.v1");
}

use crate::network::prover::stage_service::{Status, Step};
use crate::provers::{ProofOpts, ProverType};

const DEFAULT_POLL_INTERVAL: u64 = 3000; // 3s
const MIN_POLL_INTERVAL: u64 = 100; // 100ms

pub struct NetworkProver {
    pub endpoint: Endpoint,
    pub local_prover: CpuProver,
    /// `Bearer <token>`, sent on every proof RPC.
    pub bearer: MetadataValue<Ascii>,
    // Polling interval (milliseconds) for checking proof status,
    // default is 3000 milliseconds
    pub poll_interval: u64,
}

impl NetworkProver {
    /// Build from the environment alone.
    pub fn from_env() -> anyhow::Result<NetworkProver> {
        Self::with_overrides(None, None)
    }

    /// Build from an explicit token file and endpoint, falling back to
    /// `FLEET_TOKEN_FILE` and `ENDPOINT` for whichever is absent.
    ///
    /// `ProverClientBuilder::token_file` / `rpc_url` route here, so explicit
    /// values always win over the environment. The token is the only
    /// credential: it is sent as `authorization: Bearer` on every proof RPC.
    pub fn with_overrides(
        token_file: Option<String>,
        rpc_url: Option<String>,
    ) -> anyhow::Result<NetworkProver> {
        let token_file = match token_file {
            Some(path) => path,
            None => env::var("FLEET_TOKEN_FILE")
                .map_err(|_| anyhow::anyhow!("FLEET_TOKEN_FILE must be set for remote proving"))?,
        };
        let token = fs::read_to_string(&token_file)
            .map_err(|e| anyhow::anyhow!("reading the token file {token_file}: {e}"))?;
        let token = token.trim();
        if token.is_empty() {
            bail!("the token file {token_file} is empty");
        }
        let bearer = format!("Bearer {token}")
            .parse::<MetadataValue<Ascii>>()
            .map_err(|_| anyhow::anyhow!("the token file {token_file} does not hold a token"))?;

        let endpoint = match rpc_url {
            Some(u) => u,
            None => env::var("ENDPOINT")
                .map_err(|_| anyhow::anyhow!("ENDPOINT must be set for remote proving"))?,
        };
        // Server-authenticated TLS: the CA from CA_CERT_PATH, else the system roots; the
        // server name from DOMAIN_NAME, else the endpoint's host.
        let endpoint = if endpoint.starts_with("https://") {
            let host = endpoint.parse::<tonic::codegen::http::Uri>()?.host().map(str::to_owned);
            let server_name = env::var("DOMAIN_NAME")
                .ok()
                .or(host)
                .ok_or_else(|| anyhow::anyhow!("the endpoint {endpoint} has no host"))?;
            let mut tls_config = ClientTlsConfig::new().domain_name(server_name);
            if let Ok(ca) = env::var("CA_CERT_PATH") {
                let pem =
                    fs::read(&ca).map_err(|e| anyhow::anyhow!("reading CA_CERT_PATH {ca}: {e}"))?;
                tls_config = tls_config.ca_certificate(Certificate::from_pem(pem));
            }
            Endpoint::new(endpoint)?.tls_config(tls_config)?
        } else {
            Endpoint::new(endpoint)?
        };

        let local_prover = CpuProver::new();
        let mut poll_interval = env::var("ZKM_PROOF_POLL_INTERVAL")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_POLL_INTERVAL);

        if poll_interval < MIN_POLL_INTERVAL {
            poll_interval = MIN_POLL_INTERVAL;
        }

        Ok(NetworkProver { endpoint, local_prover, bearer, poll_interval })
    }

    pub async fn download_file(url: &str) -> Result<Vec<u8>> {
        let response = reqwest::get(url).await?;
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

    fn authorized<T>(&self, message: T) -> tonic::Request<T> {
        let mut request = tonic::Request::new(message);
        request.metadata_mut().insert("authorization", self.bearer.clone());
        request
    }

    async fn request_proof(&self, input: ProverInput, kind: ZKMProofKind) -> Result<String> {
        let seg_size =
            env::var("SHARD_SIZE").ok().and_then(|s| s.parse::<u32>().ok()).unwrap_or_default();

        let max_prover_num =
            env::var("MAX_PROVER_NUM").ok().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);

        let single_node =
            env::var("SINGLE_NODE").ok().and_then(|s| s.parse::<bool>().ok()).unwrap_or(false);

        let from_step =
            if kind == ZKMProofKind::CompressToGroth16 { Some(Step::InAgg.into()) } else { None };

        let target_step = if kind == ZKMProofKind::Compressed {
            Step::InAgg
        } else if kind == ZKMProofKind::Groth16 || kind == ZKMProofKind::CompressToGroth16 {
            Step::InSnark
        } else {
            return Err(anyhow::anyhow!("the proving network does not produce {kind:?} proofs"));
        };

        let request = GenerateProofRequest {
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

        let mut client = self.connect().await?;

        let start = tokio::time::Instant::now();
        let response = client.generate_proof(self.authorized(request)).await?.into_inner();
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
            let get_status_response =
                client.get_status(self.authorized(get_status_request)).await?.into_inner();

            match Status::try_from(get_status_response.status).ok() {
                Some(Status::Computing) => {
                    match Step::try_from(get_status_response.step).ok() {
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

                    let proof: ZKMProof =
                        serde_json::from_slice(&get_status_response.proof_with_public_inputs)
                            .map_err(|e| {
                                anyhow::anyhow!(
                                    "proving network returned a proof this client cannot \
                                     deserialize ({} bytes): {e}",
                                    get_status_response.proof_with_public_inputs.len(),
                                )
                            })?;
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

    /// Proves `elf` on the network; returns the proof and its cycle count.
    ///
    /// * `elf_id`: hex SHA-256 of the ELF without `0x`; when set, the network
    ///   prover indexes its cached ELF by it.
    pub async fn prove_with_cycles(
        &self,
        elf: &[u8],
        stdin: ZKMStdin,
        kind: ZKMProofKind,
        elf_id: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<(ZKMProofWithPublicValues, u64)> {
        let private_input = stdin.buffer.clone();
        let mut pri_buf = Vec::new();
        bincode::serialize_into(&mut pri_buf, &private_input)?;

        let mut receipts = Vec::new();
        let proofs = stdin.proofs.clone();
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
            let [only] = private_input.as_slice() else {
                anyhow::bail!(
                    "CompressToGroth16 takes exactly one private input, got {}",
                    private_input.len(),
                );
            };
            public_values = bincode::deserialize(only)?;
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
        block_on(self.prove_with_cycles(&pk.elf, stdin, kind, elf_id, opts.timeout))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "needs a proving network: ENDPOINT and FLEET_TOKEN_FILE"]
    fn the_proving_network_accepts_the_token() {
        let prover = NetworkProver::from_env().unwrap();
        crate::block_on(async {
            let mut client = prover.connect().await.unwrap();
            let request =
                prover.authorized(GetStatusRequest { proof_id: uuid::Uuid::new_v4().to_string() });
            if let Err(status) = client.get_status(request).await {
                assert_ne!(status.code(), tonic::Code::Unauthenticated, "{status}");
            }
        });
    }

    #[test]
    fn proof_requests_carry_the_fleet_token() {
        let path = env::temp_dir().join(format!("fleet-token-{}", std::process::id()));
        let token = "ab".repeat(48);
        fs::write(&path, format!("{token}\n")).unwrap();
        let prover = NetworkProver::with_overrides(
            Some(path.to_string_lossy().to_string()),
            Some("http://127.0.0.1:1".to_string()),
        );
        fs::remove_file(&path).unwrap();

        let request = prover.unwrap().authorized(GetStatusRequest { proof_id: "p".to_string() });
        let header = request.metadata().get("authorization").expect("no authorization header");
        assert_eq!(header.to_str().unwrap(), format!("Bearer {token}"));
    }

    #[test]
    fn a_missing_or_empty_token_is_refused() {
        let missing = env::temp_dir().join(format!("no-fleet-token-{}", std::process::id()));
        let endpoint = Some("http://127.0.0.1:1".to_string());
        assert!(NetworkProver::with_overrides(
            Some(missing.to_string_lossy().to_string()),
            endpoint.clone()
        )
        .is_err());
        let empty = env::temp_dir().join(format!("empty-fleet-token-{}", std::process::id()));
        fs::write(&empty, "\n").unwrap();
        let built =
            NetworkProver::with_overrides(Some(empty.to_string_lossy().to_string()), endpoint);
        fs::remove_file(&empty).unwrap();
        assert!(built.is_err());
    }
}

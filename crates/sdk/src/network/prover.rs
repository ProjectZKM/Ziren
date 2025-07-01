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

pub struct NetworkProver {
    pub endpoint: Endpoint,
    pub wallet: LocalWallet,
    pub local_prover: CpuProver,
}

impl NetworkProver {
    pub fn from_env() -> anyhow::Result<NetworkProver> {
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
        let ssl_cert_path = env::var("SSL_CERT_PATH").ok();
        let ssl_key_path = env::var("SSL_KEY_PATH").ok();
        let ssl_config = if ca_cert_path.as_ref().is_none() {
            None
        } else {
            let (ca_cert, identity) = get_cert_and_identity(
                ca_cert_path.as_ref().expect("CA_CERT_PATH not set"),
                ssl_cert_path.as_ref().expect("SSL_CERT_PATH not set"),
                ssl_key_path.as_ref().expect("SSL_KEY_PATH not set"),
            )?;
            Some(Config { ca_cert, identity })
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

        let private_key = proof_network_privkey.to_owned().expect("ZKM_PRIVATE_KEY must be set");
        if private_key.is_empty() {
            panic!("Please set the ZKM_PRIVATE_KEY");
        }
        let wallet = private_key.parse::<LocalWallet>()?;
        let local_prover = CpuProver::new();
        Ok(NetworkProver { endpoint, wallet, local_prover })
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
        let content = response.bytes().await?;
        Ok(content.to_vec())
    }

    pub async fn connect(&self) -> StageServiceClient<Channel> {
        StageServiceClient::connect(self.endpoint.clone())
            .await
            .expect("connect: {self.endpoint:?}")
    }

    async fn request_proof(&self, input: &ProverInput, kind: ZKMProofKind) -> Result<String> {
        let seg_size =
            env::var("SHARD_SIZE").ok().and_then(|s| s.parse::<u32>().ok()).unwrap_or_default();

        let from_step =
            if kind == ZKMProofKind::CompressToGroth16 { Some(Step::InAgg.into()) } else { None };

        let target_step = if kind == ZKMProofKind::Compressed {
            Step::InAgg
        } else if kind == ZKMProofKind::Groth16 || kind == ZKMProofKind::CompressToGroth16 {
            Step::InSnark
        } else {
            unimplemented!("unsupported ZKMProofKind")
        };

        let proof_id = uuid::Uuid::new_v4().to_string();
        let mut request = GenerateProofRequest {
            proof_id: proof_id.clone(),
            elf_data: input.elf.clone(),
            private_input_stream: input.private_inputstream.clone(),
            seg_size,
            target_step: Some(target_step.into()),
            from_step,
            ..Default::default()
        };
        for receipt_input in input.receipts.iter() {
            request.receipt_inputs.push(receipt_input.clone());
        }
        self.sign_ecdsa(&mut request).await?;
        let mut client = self.connect().await;
        let response = client.generate_proof(request).await?.into_inner();

        Ok(response.proof_id)
    }

    async fn wait_proof(
        &self,
        proof_id: &str,
        kind: ZKMProofKind,
        timeout: Option<Duration>,
    ) -> Result<(ZKMProof, ZKMPublicValues)> {
        let start_time = Instant::now();
        let mut client = self.connect().await;
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
                    match Step::from_i32(get_status_response.step) {
                        Some(step) => log::info!("Generate_proof: {step}"),
                        None => todo!(),
                    }
                    sleep(Duration::from_secs(5)).await;
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
                    return Ok((proof, public_values));
                }
                _ => {
                    log::error!("generate_proof failed status: {}", get_status_response.status);
                    bail!("generate_proof failed status: {}", get_status_response.status);
                }
            }
        }
    }

    pub(crate) async fn prove(
        &self,
        elf: &[u8],
        stdin: ZKMStdin,
        kind: ZKMProofKind,
        timeout: Option<Duration>,
    ) -> Result<ZKMProofWithPublicValues> {
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
        let prover_input =
            ProverInput { elf: elf.to_vec(), private_inputstream: pri_buf, receipts };

        log::info!("calling request_proof.");
        let proof_id = self.request_proof(&prover_input, kind).await?;

        log::info!("calling wait_proof, proof_id={proof_id}");
        let (proof, mut public_values) = self.wait_proof(&proof_id, kind, timeout).await?;

        if kind == ZKMProofKind::CompressToGroth16 {
            assert_eq!(private_input.len(), 1);
            public_values = bincode::deserialize(private_input.last().unwrap())?;
        }

        Ok(ZKMProofWithPublicValues {
            proof,
            public_values,
            stdin,
            zkm_version: ZKM_CIRCUIT_VERSION.to_string(),
        })
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
        _opts: ProofOpts,
        _context: ZKMContext<'a>,
        kind: ZKMProofKind,
    ) -> Result<ZKMProofWithPublicValues> {
        block_on(self.prove(&pk.elf, stdin, kind, None))
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

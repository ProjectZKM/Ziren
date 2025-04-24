use std::{env, fs};
use std::fs::File;
use std::io::Write;
use stage_service::stage_service_client::StageServiceClient;
use stage_service::{GenerateProofRequest, GetStatusRequest};

use std::path::Path;
use std::time::Instant;
use tonic::transport::Endpoint;
use tonic::transport::{Certificate, Identity};
use tonic::transport::{Channel, ClientTlsConfig};

// use crate::prover::{ClientCfg, Prover, ProverInput, ProverResult};
use ethers::signers::{LocalWallet, Signer};
use tokio::time::sleep;
use tokio::time::Duration;

use anyhow::{bail, Result};
use async_trait::async_trait;
use tonic::{IntoRequest, Request};
use twirp::tower::ServiceExt;
use zkm_core_executor::{ZKMContext, ZKMReduceProof};
use zkm_core_machine::io::ZKMStdin;
use zkm_core_machine::ZKM_CIRCUIT_VERSION;
use zkm_primitives::io::ZKMPublicValues;
use zkm_prover::components::DefaultProverComponents;
use zkm_prover::{InnerSC, ZKMProver, ZKMProvingKey, ZKMVerifyingKey};
use crate::{block_on, CpuProver, Prover, ZKMProof, ZKMProofKind, ZKMProofWithPublicValues};
use crate::network::{NetworkClientCfg, ProverInput, ProverResult};

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
    pub async fn new(client_config: &NetworkClientCfg) -> anyhow::Result<NetworkProver> {
        let ssl_config = if client_config.ca_cert_path.as_ref().is_none() {
            None
        } else {
            let (ca_cert, identity) = get_cert_and_identity(
                client_config.ca_cert_path.as_ref().expect("CA_CERT_PATH not set"),
                client_config.cert_path.as_ref().expect("CERT_PATH not set"),
                client_config.key_path.as_ref().expect("KEY_PATH not set"),
            )
                .await?;
            Some(Config { ca_cert, identity })
        };

        let endpoint_para = client_config.endpoint.to_owned().expect("ENDPOINT must be set");
        let endpoint = match ssl_config {
            Some(config) => {
                let mut tls_config = ClientTlsConfig::new().domain_name(
                    client_config.domain_name.to_owned().expect("DOMAIN_NAME must be set"),
                );
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

        let private_key =
            client_config.proof_network_privkey.to_owned().expect("PRIVATE_KEY must be set");
        if private_key.is_empty() {
            panic!("Please set the PRIVATE_KEY");
        }
        // let stage_client = StageServiceClient::connect(endpoint).await?;
        let wallet = private_key.parse::<LocalWallet>()?;
        let local_prover = CpuProver::new();
        Ok(NetworkProver { endpoint, wallet, local_prover})
    }

    pub async fn sign_ecdsa(&self, request: &mut GenerateProofRequest) {
        let sign_data = match request.block_no {
            Some(block_no) => {
                format!("{}&{}&{}", request.proof_id, block_no, request.seg_size)
            }
            None => {
                format!("{}&{}", request.proof_id, request.seg_size)
            }
        };
        let signature = self.wallet.sign_message(sign_data).await.unwrap();
        request.signature = signature.to_string();
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

    async fn request_proof<'a>(&self, input: &'a ProverInput) -> Result<String> {
        let proof_id = uuid::Uuid::new_v4().to_string();
        let mut request = GenerateProofRequest {
            proof_id: proof_id.clone(),
            elf_data: input.elf.clone(),
            seg_size: input.shard_size,
            public_input_stream: input.public_inputstream.clone(),
            private_input_stream: input.private_inputstream.clone(),
            execute_only: input.execute_only,
            // composite_proof: input.composite_proof,
            precompile: input.composite_proof,
            ..Default::default()
        };
        for receipt in input.receipts.iter() {
            // request.receipts.push(receipt.clone());
            request.receipt.push(receipt.clone());
        }
        for receipt_input in input.receipt_inputs.iter() {
            // request.receipt_inputs.push(receipt_input.clone());
            request.receipt_input.push(receipt_input.clone());
        }
        self.sign_ecdsa(&mut request).await;
        let mut client = self.connect().await;
        let response = client.generate_proof(request).await?.into_inner();

        Ok(response.proof_id)
    }

    async fn wait_proof<'a>(
        &self,
        proof_id: &'a str,
        timeout: Option<Duration>,
    ) -> Result<(ZKMProof, ZKMPublicValues)> {
        let start_time = Instant::now();
        let mut split_start_time = Instant::now();
        let mut split_end_time = Instant::now();
        let mut client = self.connect().await;
        let mut last_step = 0;
        loop {
            if let Some(timeout) = timeout {
                if start_time.elapsed() > timeout {
                    bail!("Proof generation timed out.");
                }
            }

            let get_status_request = GetStatusRequest { proof_id: proof_id.to_string() };
            let get_status_response = client.get_status(get_status_request).await?.into_inner();
            
            match Status::from_i32(get_status_response.status as i32) {
                Some(Status::Computing) => {
                    match Step::from_i32(get_status_response.step) {
                        Some(Step::Init) => log::info!("generate_proof : queuing the task."),
                        Some(Step::InSplit) => {
                            if last_step == 0 {
                                split_start_time = Instant::now();
                            }
                            log::info!("generate_proof : splitting the task.");
                        }
                        Some(Step::InProve) => {
                            if last_step == 1 {
                                split_end_time = Instant::now();
                            }
                            log::info!("generate_proof : proving the task.");
                        }
                        Some(Step::InAgg) => log::info!("generate_proof : aggregating the proof."),
                        Some(Step::InAggAll) => {
                            log::info!("generate_proof : aggregating the proof.")
                        }
                        Some(Step::InFinal) => log::info!("generate_proof : snark-wrapping the proof."),
                        Some(Step::End) => log::info!("generate_proof : completing the proof."),
                        None => todo!(),
                    }
                    last_step = get_status_response.step;
                    sleep(Duration::from_secs(30)).await;
                }
                Some(Status::Success) => {
                    let public_values_bytes = NetworkProver::download_file(&get_status_response.public_values_url).await?;
                    let public_values: ZKMPublicValues = ZKMPublicValues::from(&public_values_bytes);
                    println!("public_values: {:?}", public_values);
                    println!("output: {:?}", get_status_response.output_stream);

                    let proof: ZKMProof = serde_json::from_slice(&get_status_response.proof_with_public_inputs)
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

    pub(crate) async fn prove<'a>(
        &self,
        elf: &[u8],
        stdin: ZKMStdin,
        timeout: Option<Duration>,
    ) -> Result<ZKMProofWithPublicValues> {
        let execute_only =
            env::var("EXECUTE_ONLY").ok().and_then(|seg| seg.parse::<bool>().ok()).unwrap_or(false);
        let composite_proof = env::var("COMPOSITE_PROOF").ok().and_then(|seg| seg.parse::<bool>().ok()).unwrap_or(false);
        let shard_size = env::var("SHARD_SIZE").ok().and_then(|seg| seg.parse::<usize>().ok()).unwrap_or(65536) as u32;
        let proof_results_path =
            env::var("PROOF_RESULTS_PATH").unwrap_or("./proofs".to_string());

        let private_input = stdin.buffer.clone();
        let mut pri_buf = Vec::new();
        bincode::serialize_into(&mut pri_buf, &private_input).expect("private_input serialization failed");
        let mut receipts = Vec::new();
        let proofs = stdin.proofs.clone();
        // todo: adapt to proof network after its updating
        for proof in proofs {
            let mut receipt = Vec::new();
            bincode::serialize_into(&mut receipt, &proof).expect("private_input serialization failed");
            receipts.push(receipt);
        }

        let prover_input = ProverInput {
            elf: elf.to_vec(),
            shard_size,
            execute_only,
            composite_proof,
            proof_results_path,
            private_inputstream: pri_buf,
            receipts,
            ..Default::default()
        };

        log::info!("calling request_proof.");
        let proof_id = self.request_proof(&prover_input).await?;

        log::info!("calling wait_proof, proof_id={}", proof_id);
        let (proof, public_values) =  self.wait_proof(&proof_id, timeout).await?;
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

    fn prove<'a>(&'a self, pk: &ZKMProvingKey, stdin: ZKMStdin, _opts: ProofOpts, _context: ZKMContext<'a>, _kind: ZKMProofKind) -> Result<ZKMProofWithPublicValues> {
        block_on(self.prove(&pk.elf, stdin, None))
    }
}

async fn get_cert_and_identity(
    ca_cert_path: &str,
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<(Option<Certificate>, Option<Identity>)> {
    let ca_cert_path = Path::new(ca_cert_path);
    let cert_path = Path::new(cert_path);
    let key_path = Path::new(key_path);
    if !ca_cert_path.is_file() || !cert_path.is_file() || !key_path.is_file() {
        bail!("both ca_cert_path, cert_path and key_path should be valid file")
    }
    let mut ca: Option<Certificate> = None;
    let mut identity: Option<Identity> = None;
    if ca_cert_path.is_file() {
        let ca_cert = tokio::fs::read(ca_cert_path)
            .await
            .unwrap_or_else(|err| panic!("Failed to read {:?}, err: {:?}", ca_cert_path, err));
        ca = Some(Certificate::from_pem(ca_cert));
    }

    if cert_path.is_file() && key_path.is_file() {
        let cert = tokio::fs::read(cert_path)
            .await
            .unwrap_or_else(|err| panic!("Failed to read {:?}, err: {:?}", cert_path, err));
        let key = tokio::fs::read(key_path)
            .await
            .unwrap_or_else(|err| panic!("Failed to read {:?}, err: {:?}", key_path, err));
        identity = Some(Identity::from_pem(cert, key));
    }
    Ok((ca, identity))
}

pub fn save_data_to_file<P: AsRef<Path>, D: AsRef<[u8]>>(
    output_dir: P,
    file_name: &str,
    data: D,
) -> anyhow::Result<()> {
    // Create the output directory
    let output_dir = output_dir.as_ref();
    log::info!("create dir: {}", output_dir.display());
    fs::create_dir_all(output_dir)?;

    // Build the full file path
    let output_path = output_dir.join(file_name);

    // Open the file and write the data
    let mut file = File::create(&output_path)?;
    file.write_all(data.as_ref())?;

    let bytes_written = data.as_ref().len();
    log::info!("Successfully written {} bytes.", bytes_written);

    Ok(())
}
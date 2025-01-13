# Host Program

In a zkMIPS application, the host is the machine that is running the zkMIPS. The host is an untrusted agent that sets up the zkVM environment and handles inputs/outputs during execution for guest.

## Example: [sha2-rust](https://github.com/zkMIPS/zkm-project-template/blob/main/host-program/sha2-rust/src/main.rs)

This host program sends the private input pri_input = vec![5u8; 1024] and its hash (hash(pri_input)) to the guest program for verification of the hash value.

Step1. Read environment variables. The default values can be found in [run-proving.sh](https://github.com/zkMIPS/zkm-project-template/blob/main/host-program/run-proving.sh)

> If the environmental variable `PROOF_RESULTS_PATH` is not set, the proof results file will be saved in zkm-project-template/contracts/{src, verifier}; if the environmental variable `PROOF_RESULTS_PATH` is set, after the proof is completed, the proof results file needs to be copied from from `PROOF_RESULTS_PATH`/{src, verifier} to the corresponding zkm-project-template/contracts/{src, verifier}.

> The environment variable `VERIFYING_KEY_PATH` specifies the location of the verification key (vk). If this variable is not set to zkm-project-template/contracts/src, you should copy the `VERIFYING_KEY_PATH`/verifier.sol to zkm-project-template/contracts/src/ after executing the host program.

> The environment variable `SETUP_FLAG` is set to "true", it will generate the proving key (pk), the verification key (vk) and the verifier contract and store them at the path indicated by `VERIFYING_KEY_PATH`.Then, the `SETUP_FLAG` should be set to "false" , next executing the host will generate the snark proof using the same pk and vk.

> The environmental variable `SEG_SIZE` in the run_proving.sh affects the final proof generation.

> The guest program's ELF with the input is split into segments according the `SEG_SIZE`, based on the cycle count.

> When generating proofs on the local machine, if the log shows "[the seg_num is:1 ]", please reduce `SEG_SIZE` or increase the input. If generating proofs through the proof network, `SEG_SIZE` must be within the range [65536, 262144].

> When generating the proof via restful API, must set the `PRIVATE_KEY` and `ZKM_PROVER=network`. The `PRIVATE_KEY` can be applied for through the [application platform](https://www.zkm.io/apply).

```rust
env_logger::try_init().unwrap_or_default();
let seg_size = env::var("SEG_SIZE")
    .ok()
    .and_then(|seg| seg.parse::<u32>().ok())
    .unwrap_or(65536);

let execute_only = env::var("EXECUTE_ONLY")
    .ok()
    .and_then(|seg| seg.parse::<bool>().ok())
    .unwrap_or(false);

let setup_flag = env::var("SETUP_FLAG")
    .ok()
    .and_then(|seg| seg.parse::<bool>().ok())
    .unwrap_or(false);

let elf_path = env::var("ELF_PATH").unwrap_or(env!("GUEST_TARGET_PATH").to_string());
let proof_results_path = env::var("PROOF_RESULTS_PATH").unwrap_or("../contracts".to_string());
let vk_path = env::var("VERIFYING_KEY_PATH").unwrap_or("/tmp/input".to_string());
let zkm_prover_type = env::var("ZKM_PROVER").expect("ZKM PROVER is missing");

// network proving
let endpoint = env::var("ENDPOINT").unwrap_or("".to_string());
let ca_cert_path = env::var("CA_CERT_PATH").unwrap_or("".to_string());
let cert_path = env::var("CERT_PATH").unwrap_or("".to_string());
let key_path = env::var("KEY_PATH").unwrap_or("".to_string());
let domain_name = env::var("DOMAIN_NAME").unwrap_or("".to_string());
let private_key = env::var("PROOF_NETWORK_PRVKEY").unwrap_or("".to_string());
```

Step2. Construct the `ProverClient` using environment variables.

```rust
let mut client_config: ClientCfg =
    ClientCfg::new(zkm_prover_type.to_owned(), vk_path.to_owned());

if !is_local_prover(&zkm_prover_type) {
    client_config.set_network(
        endpoint,
        ca_cert_path,
        cert_path,
        key_path,
        domain_name,
        private_key,
    );
}

log::info!("new prover client:");
let prover_client = ProverClient::new(&client_config).await;
log::info!("new prover client,ok.");
```

Step3. Construct the `ProverInput`.

```rust
 let mut prover_input = ProverInput {
    elf: read(elf_path).unwrap(),
    seg_size,
    execute_only,
    ..Default::default()
};

// If the guest program does't have inputs, it does't need the setting.
set_guest_input(&mut prover_input, None);
```

Step4. Setup: generate the proving key (pk), the verification key (vk), and the verifier contract and store them at the path indicated by `VERIFYING_KEY_PATH`. Then, the `SETUP_FLAG` should be set to "false" , next executing the host will generate the snark proof using the same pk and vk.

```rust
//  excuting the setup_and_generate_sol_verifier
if setup_flag {
    match prover_client
        .setup_and_generate_sol_verifier(&zkm_prover_type, &vk_path, &prover_input)
        .await
    {
        Ok(()) => log::info!("Succussfully setup_and_generate_sol_verifier."),
        Err(e) => {
            log::info!("Error during setup_and_generate_sol_verifier: {}", e);
            bail!("Failed to setup_and_generate_sol_verifier.");
        }
    }
}
```

Step5. Proving: generate the zk-SNARK proof and store it at the path indicated by `PROOF_RESULTS_PATH`.

```rust
let proving_result = prover_client.prover.prove(&prover_input, None).await;
match proving_result {
    Ok(Some(prover_result)) => {
        if !execute_only {
            // excute the guest program and generate the proof
            prover_client
                .process_proof_results(
                    &prover_result,
                    &prover_input,
                    &proof_results_path,
                    &zkm_prover_type,
                )
                .expect("process proof results error");
        } else {
            // only excute the guest program without generating the proof.
            // the sha2-rust guest program has outputs messages, which are basic type.
            prover_client
                .print_guest_execution_output(true, &prover_result)
                .expect("print guest program excution's output false.");
        }
    }
    Ok(none) => {
        log::info!("Failed to generate proof.The result is None.");
        bail!("Failed to generate proof.");
    }
    Err(e) => {
        log::info!("Failed to generate proof. error: {}", e);
        bail!("Failed to generate proof.");
    }
}
```

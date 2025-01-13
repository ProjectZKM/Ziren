# Trusted Setup

The zk-SNARK protocols often require a trusted setup to generate a CRS (Common Reference String), proving key and verification key.

Groth16 requires sampling five random field elements to generate the proving and verifying keys: τ, α, β, γ, and σ. These are considered toxic waste and should be discarded and completely forgotten once the keys have been generated, as they could be used to create fake proofs that the verifier would accept. The main solution to this deployment issue is to run the setup through an MPC (multi-party computation).

## Example: [sha2-rust](https://github.com/zkMIPS/zkm-project-template/blob/main/host-program/sha2-rust/src/main.rs)

The generated proving key (pk), verifying key (vk), and verifier contract will be stored at the path indicated by `VERIFYING_KEY_PATH`.

```rust
// excuting the setup_and_generate_sol_verifier
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

The process runs `groth16.Setup` with provided R1CS and outputs a key pair associated with the circuit.

Note that careful consideration must be given to this step in production environment. Because `groth16.Setup` uses some randomness to precompute the proving and verifying keys. If the process or machine leaks this randomness, an attacker could break the ZKP protocol.

```go
func (obj *SnarkProver) SetupAndGenerateSolVerifier(inputdir string) error {
	circuitPath := inputdir + "/circuit"
	pkPath := inputdir + "/proving.key"
	vkPath := inputdir + "/verifying.key"
	_, err := os.Stat(circuitPath)

	if os.IsNotExist(err) {
		commonCircuitData, _ := types.ReadCommonCircuitData(inputdir + "/common_circuit_data.json")
		proofWithPisData, _ := types.ReadProofWithPublicInputs(inputdir + "/proof_with_public_inputs.json")
		proofWithPis := variables.DeserializeProofWithPublicInputs(proofWithPisData)

		verifierOnlyCircuitRawData, _ := types.ReadVerifierOnlyCircuitData(inputdir + "/verifier_only_circuit_data.json")
		verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(verifierOnlyCircuitRawData)

		circuit := verifier.ExampleVerifierCircuit{
			PublicInputsHash:        proofWithPis.PublicInputsHash,
			Proof:                   proofWithPis.Proof,
			PublicInputs:            proofWithPis.PublicInputs,
			VerifierOnlyCircuitData: verifierOnlyCircuitData,
			CommonCircuitData:       commonCircuitData,
		}

		var builder frontend.NewBuilder = r1cs.NewBuilder
		obj.r1cs_circuit, _ = frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
		fR1CS, _ := os.Create(circuitPath)
		obj.r1cs_circuit.WriteTo(fR1CS)
		fR1CS.Close()
	}

	_, err = os.Stat(pkPath)
	if os.IsNotExist(err) {
		obj.pk, obj.vk, err = groth16.Setup(obj.r1cs_circuit)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fPK, _ := os.Create(pkPath)
		obj.pk.WriteTo(fPK)
		fPK.Close()

		if obj.vk != nil {
			fVK, _ := os.Create(vkPath)
			obj.vk.WriteTo(fVK)
			fVK.Close()
		}
	}

	if err := obj.generateVerifySol(inputdir); err != nil {
		return err
	}

	return nil
}
```

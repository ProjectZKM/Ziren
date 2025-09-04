# Groth16 Trusted Setup

The zk-SNARK protocols often require a trusted setup to generate a CRS (Common Reference String), proving key and verification key.

Groth16 requires sampling five random field elements to generate the proving and verifying keys: τ, α, β, γ, and σ. These are considered toxic waste and should be discarded and completely forgotten once the keys have been generated, as they could be used to create fake proofs that the verifier would accept. The main solution to this deployment issue is to run the setup through an MPC (multi-party computation).

The Groth16 proof system requires a two-phase trusted setup:
- Phase 1 (Universal): Known as a 'Powers of Tau ceremony', applicable to all circuits.
- Phase 2 (Circuit-Specific): Unique setup required for each individual circuit.

## Prerequisites

Download the Plonk SRS keys and prepare the directory to generate Groth16 setup keys.

```bash
make build-circuits
```

The trusted setup process will overwrite the proving key, verifying key, and the relevant
contracts in the `build/groth16` directory:

```bash
Ziren/crates/prover$ tree build/groth16
build/groth16
├── constraints.json
├── groth16_circuit.bin
├── groth16_pk.bin
├── Groth16Verifier.sol
├── groth16_vk.bin
├── groth16_witness.json
└── ZKMVerifierGroth16.sol
```

## Powers of Tau

Download the powers of tau file for the given number of constraints. You will need to choose the 
number based on the number of constraints in the circuit (nearest power of 2 above the number of constraints).

```bash
export NB_CONSTRAINTS_LOG2=23
wget https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_${NB_CONSTRAINTS_LOG2}.ptau \
    -O powersOfTau28_hez_final.ptau
```

## Semaphore Install

```bash
git clone https://github.com/ProjectZKM/semaphore-gnark-11.git -b zkm2 semaphore-mtb-setup
cd semaphore-mtb-setup
go build
cd ..
cp semaphore-mtb-setup/semaphore-mtb-setup semaphore-gnark-11
```

## Phase 1 Setup

```bash
mkdir -p trusted-setup
./semaphore-gnark-11 p1i powersOfTau28_hez_final.ptau trusted-setup/phase1
```

## Phase 2 Setup

```bash
./semaphore-gnark-11 p2n trusted-setup/phase1 build/groth16/groth16_circuit.bin trusted-setup/phase2 trusted-setup/evals
```

## Phase 2 Contributions

```bash
./semaphore-gnark-11 p2c trusted-setup/phase2 trusted-setup/phase2-1-zkm
./semaphore-gnark-11 p2c trusted-setup/phase2-1-zkm trusted-setup/phase2-2-goat
./semaphore-gnark-11 p2c trusted-setup/phase2-2-goat trusted-setup/phase2-3-metis
cp trusted-setup/phase2-3-metis trusted-setup/phase2-final
```

## Export Keys

```bash
./semaphore-gnark-11 key trusted-setup/phase1 trusted-setup/phase2-final trusted-setup/evals build/groth16/groth16_circuit.bin
cp pk trusted-setup/groth16_pk.bin
cp vk trusted-setup/groth16_vk.bin
```

## Export Verifier

```bash
./semaphore-gnark-11 sol vk
cp Groth16Verifier.sol trusted-setup/Groth16Verifier.sol
```

## Override Existing Build

```bash
cp trusted-setup/groth16_pk.bin build/groth16/groth16_pk.bin
cp trusted-setup/groth16_vk.bin build/groth16/groth16_vk.bin
cp trusted-setup/Groth16Verifier.sol build/groth16/Groth16Verifier.sol
```

## Override Existing VKs

```bash
cp build/groth16/groth16_vk.bin ../verifier/bn254-vk/
cp build/plonk/plonk_vk.bin ../verifier/bn254-vk/
```

## Post Trusted Setup

```bash
cargo run --bin post_trusted_setup --release -- --build-dir build/groth16
```

## Release

```bash
make release-circuits
```

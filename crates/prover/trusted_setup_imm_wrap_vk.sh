# Build a Groth16 verification key (vk) is not affected by the Ziren upgrade.
#---------------Usage---------------
# cd Ziren/crates/prover
# sh trusted_setup_imm_wrap_vk.sh
#-----------------------------------

echo "--------Prerequisites--------"
make build-circuits-imm-wrap-vk

echo "--------Powers of Tau--------"
if [ ! -f "powersOfTau28_hez_final.ptau" ]; then
    export NB_CONSTRAINTS_LOG2=23
    wget https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_${NB_CONSTRAINTS_LOG2}.ptau \
        -O powersOfTau28_hez_final.ptau
fi

echo "--------Semaphore Install--------"
git clone https://github.com/ProjectZKM/semaphore-gnark-11.git -b zkm2 semaphore-mtb-setup
cd semaphore-mtb-setup
go build
cd ..
cp semaphore-mtb-setup/semaphore-mtb-setup semaphore-gnark-11

echo "--------Phase 1 Setup--------"
mkdir -p trusted-setup-imm-wrap-vk
./semaphore-gnark-11 p1i powersOfTau28_hez_final.ptau trusted-setup-imm-wrap-vk/phase1

echo "--------Phase 2 Setup--------"
./semaphore-gnark-11 p2n trusted-setup-imm-wrap-vk/phase1 build-imm-wrap-vk/groth16/groth16_circuit.bin trusted-setup-imm-wrap-vk/phase2 trusted-setup-imm-wrap-vk/evals

echo "--------Phase 2 Contributions--------"
./semaphore-gnark-11 p2c trusted-setup-imm-wrap-vk/phase2 trusted-setup-imm-wrap-vk/phase2-1-zkm
./semaphore-gnark-11 p2c trusted-setup-imm-wrap-vk/phase2-1-zkm trusted-setup-imm-wrap-vk/phase2-2-goat
./semaphore-gnark-11 p2c trusted-setup-imm-wrap-vk/phase2-2-goat trusted-setup-imm-wrap-vk/phase2-3-metis
cp trusted-setup-imm-wrap-vk/phase2-3-metis trusted-setup-imm-wrap-vk/phase2-final

echo "--------Export Keys--------"
./semaphore-gnark-11 key trusted-setup-imm-wrap-vk/phase1 trusted-setup-imm-wrap-vk/phase2-final trusted-setup-imm-wrap-vk/evals build-imm-wrap-vk/groth16/groth16_circuit.bin
cp pk trusted-setup-imm-wrap-vk/groth16_pk.bin
cp vk trusted-setup-imm-wrap-vk/groth16_vk.bin

echo "--------Export Verifier--------"
./semaphore-gnark-11 sol vk
cp Groth16Verifier.sol trusted-setup-imm-wrap-vk/Groth16Verifier.sol

echo "--------Override Existing Build--------"
cp trusted-setup-imm-wrap-vk/groth16_pk.bin build-imm-wrap-vk/groth16/groth16_pk.bin
cp trusted-setup-imm-wrap-vk/groth16_vk.bin build-imm-wrap-vk/groth16/groth16_vk.bin
cp trusted-setup-imm-wrap-vk/Groth16Verifier.sol build-imm-wrap-vk/groth16/Groth16Verifier.sol

echo "--------Override Existing VKs--------"
cp build-imm-wrap-vk/groth16/groth16_vk.bin ../verifier/bn254-vk/imm_groth16_vk.bin
cp build-imm-wrap-vk/groth16/part_start_vk.bin ../verifier/bn254-vk/part_start_vk.bin

echo "--------Post Trusted Setup--------"
cargo run --bin post_trusted_setup --release -- --build-dir build-imm-wrap-vk/groth16

echo "--------[TODO] Release--------"
# make release-circuits-imm-wrap-vk

echo "--------[TODO] Clear--------"
# rm -rf build-imm-wrap-vk powersOfTau28_hez_final.ptau semaphore-gnark-11 \
    # semaphore-mtb-setup trusted-setup-imm-wrap-vk pk vk Groth16Verifier.sol

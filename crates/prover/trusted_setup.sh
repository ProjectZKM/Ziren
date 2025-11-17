#---------------Usage---------------
# cd Ziren/crates/prover
# sh trusted_setup.sh
#-----------------------------------

echo "--------Prerequisites--------"
make build-circuits

echo "--------Powers of Tau--------"
export NB_CONSTRAINTS_LOG2=23
wget https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_${NB_CONSTRAINTS_LOG2}.ptau \
    -O powersOfTau28_hez_final.ptau

echo "--------Semaphore Install--------"
git clone https://github.com/ProjectZKM/semaphore-gnark-11.git -b zkm2 semaphore-mtb-setup
cd semaphore-mtb-setup
go build
cd ..
cp semaphore-mtb-setup/semaphore-mtb-setup semaphore-gnark-11

echo "--------Phase 1 Setup--------"
mkdir -p trusted-setup
./semaphore-gnark-11 p1i powersOfTau28_hez_final.ptau trusted-setup/phase1

echo "--------Phase 2 Setup--------"
./semaphore-gnark-11 p2n trusted-setup/phase1 build/groth16/groth16_circuit.bin trusted-setup/phase2 trusted-setup/evals

echo "--------Phase 2 Contributions--------"
./semaphore-gnark-11 p2c trusted-setup/phase2 trusted-setup/phase2-1-zkm
./semaphore-gnark-11 p2c trusted-setup/phase2-1-zkm trusted-setup/phase2-2-goat
./semaphore-gnark-11 p2c trusted-setup/phase2-2-goat trusted-setup/phase2-3-metis
cp trusted-setup/phase2-3-metis trusted-setup/phase2-final

echo "--------Export Keys--------"
./semaphore-gnark-11 key trusted-setup/phase1 trusted-setup/phase2-final trusted-setup/evals build/groth16/groth16_circuit.bin
cp pk trusted-setup/groth16_pk.bin
cp vk trusted-setup/groth16_vk.bin

echo "--------Export Verifier--------"
./semaphore-gnark-11 sol vk
cp Groth16Verifier.sol trusted-setup/Groth16Verifier.sol

echo "--------Override Existing Build--------"
cp trusted-setup/groth16_pk.bin build/groth16/groth16_pk.bin
cp trusted-setup/groth16_vk.bin build/groth16/groth16_vk.bin
cp trusted-setup/Groth16Verifier.sol build/groth16/Groth16Verifier.sol

echo "--------Override Existing VKs--------"
cp build/groth16/groth16_vk.bin ../verifier/bn254-vk/
cp build/plonk/plonk_vk.bin ../verifier/bn254-vk/

echo "--------Post Trusted Setup--------"
cargo run --bin post_trusted_setup --release -- --build-dir build/groth16

echo "--------[TODO] Release--------"
# make release-circuits

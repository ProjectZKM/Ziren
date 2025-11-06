# Generate Shapes

#---------------Usage---------------
# $ ls -l
# Ziren
# ziren-shape-bin

# $ cd Ziren
# $ bash crates/prover/collect.sh
#-----------------------------------

# Full Generation
WORKLOADS=(
    "../ziren-shape-bin/chess"
    "../ziren-shape-bin/fibonacci-1k"
    "../ziren-shape-bin/fibonacci-10k"
    "../ziren-shape-bin/fibonacci-100k"
    "../ziren-shape-bin/fibonacci-1m"
    "../ziren-shape-bin/fibonacci-10m"
    "../ziren-shape-bin/fibonacci-100m"
    "../ziren-shape-bin/json"
    "../ziren-shape-bin/sha2-100kb"
    "../ziren-shape-bin/sha2-1mb"
    "../ziren-shape-bin/sha2-10mb"
    "../ziren-shape-bin/ssz-withdrawals"
    "../ziren-shape-bin/tendermint"
)

RUST_LOG=info cargo run --release -p zkm-prover --bin find_maximal_shapes -- \
    --shard-sizes "17 18 19 20 21 22" \
    --list "${WORKLOADS[*]}"

# Generate Shapes for the GOAT Chain using RETH
RUST_LOG=info cargo run --release -p zkm-prover --bin find_maximal_shapes -- \
    --initial "maximal_shapes.json" \
    --shard-sizes "17 18 19 20 21 22" \
    --reth \
    --elf "../ziren-shape-bin/goat/reth" \
    --stdin "../ziren-shape-bin/goat/stdin" \
    --start-block 7561350 \
    --end-block 7561550

# Generate Shapes for the ETH Chain using RETH
RUST_LOG=info cargo run --release -p zkm-prover --bin find_maximal_shapes -- \
    --initial "maximal_shapes.json" \
    --shard-sizes "17 18 19 20 21 22" \
    --reth \
    --elf "../ziren-shape-bin/reth/reth" \
    --stdin "../ziren-shape-bin/reth/stdin" \
    --start-block 23694436 \
    --end-block 23701500

# Generate Shapes for the ETH Chain using GETH
# RUST_LOG=info cargo run --release -p zkm-prover --bin find_maximal_shapes -- \
#     --initial "maximal_shapes.json" \
#     --shard-sizes "17 18 19 20 21 22" \
#     --geth \
#     --elf "../ziren-shape-bin/geth/keeper" \
#     --stdin "../ziren-shape-bin/geth/payloads" \
#     --start-block 1153024 \
#     --end-block 1153279

RUST_LOG=info cargo run --release -p zkm-prover --bin find_small_shapes -- \
    --maximal-shapes-json "maximal_shapes.json" \
    --log2-memory-heights "17 18 19 20 21 22"

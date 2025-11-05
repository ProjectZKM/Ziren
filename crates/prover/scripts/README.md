# Generate Shapes

## Full Generation

```
$ ls -l
Ziren
ziren-shape-bin

$ cd Ziren
```

```
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

RUST_LOG=info cargo run --release -p zkm-prover --bin find_small_shapes -- \
    --maximal-shapes-json "maximal_shapes.json" \
    --log2-memory-heights "17 18 19 20 21 22"
```

## Incremental Generation​​

```
WORKLOADS=(
    "../ziren-shape-bin/tendermint"
)

RUST_LOG=info cargo run --release -p zkm-prover --bin find_maximal_shapes -- \
    --initial "maximal_shapes.json" \
    --shard-sizes "17 18 19 20 21 22" \
    --list "${WORKLOADS[*]}"

RUST_LOG=info cargo run --release -p zkm-prover --bin find_small_shapes -- \
    --maximal-shapes-json "maximal_shapes.json" \
    --log2-memory-heights "17 18 19 20 21 22"
```

# Generate Shapes for the GOAT Chain using RETH

```
$ ls ../ziren-shape-bin/goat/stdin

7561350-stdin.bin  7561398-stdin.bin  7561446-stdin.bin  7561494-stdin.bin  7561542-stdin.bin
...
```

```
RUST_LOG=info cargo run --release -p zkm-prover --bin find_maximal_shapes -- \
    --initial "maximal_shapes.json" \
    --shard-sizes "17 18 19 20 21 22" \
    --reth \
    --elf "../ziren-shape-bin/goat/reth" \
    --stdin "../ziren-shape-bin/goat/stdin" \
    --start-block 7561350 \
    --end-block 7561550
```

# Generate Shapes for the ETH Chain using RETH

```
$ ls ../ziren-shape-bin/reth/stdin

23694436-stdin.bin  23694526-stdin.bin  23694614-stdin.bin  23694708-stdin.bin  23694805-stdin.bin
...
```

```
RUST_LOG=info cargo run --release -p zkm-prover --bin find_maximal_shapes -- \
    --initial "maximal_shapes.json" \
    --shard-sizes "17 18 19 20 21 22" \
    --reth \
    --elf "../ziren-shape-bin/reth/reth" \
    --stdin "../ziren-shape-bin/reth/stdin" \
    --start-block 23694436 \
    --end-block 23701500
```

# Generate Shapes for the ETH Chain using GETH

```
$ ls ../ziren-shape-bin/geth/

119800_payload.rlp  11982d_payload.rlp  119859_payload.rlp  119884_payload.rlp  1198c9_payload.rlp
...
```

```
RUST_LOG=info cargo run --release -p zkm-prover --bin find_maximal_shapes -- \
    --initial "maximal_shapes.json" \
    --shard-sizes "17 18 19 20 21 22" \
    --geth \
    --elf "../ziren-shape-bin/geth/keeper" \
    --stdin "../ziren-shape-bin/geth/payloads" \
    --start-block 1153024 \
    --end-block 1153279
```

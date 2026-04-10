# Keeper

See more [Keeper - geth as a zkvm guest](https://github.com/ethereum/go-ethereum/tree/master/cmd/keeper#keeper---geth-as-a-zkvm-guest).

## Usage

### Fetch payload from RPC and prove

```bash
# latest block
cargo run --release --bin keeper-host -- \
  --rpc http://localhost:8545 \
  --block latest

# specific block (hex)
cargo run --release --bin keeper-host -- \
  --rpc http://localhost:8545 \
  --block 0x11982d
```

### Save payload only (no proving)

```bash
cargo run --release --bin keeper-host -- \
  --save \
  --rpc http://localhost:8545 \
  --block latest
```

The payload file will be saved as `{block_number_hex}_payload.rlp` in the current directory.

### Execute only (no proving)

```bash
# from RPC
cargo run --release --bin keeper-host -- \
  --execute \
  --rpc http://localhost:8545 \
  --block latest

# from file
cargo run --release --bin keeper-host -- --execute 11982d_payload.rlp
```

### Continuous mode (follow new blocks)

```bash
# follow and prove each new block
cargo run --release --bin keeper-host -- \
  --rpc http://localhost:8545 \
  --block latest \
  --follow \
  --poll-interval 5

# follow and save payloads only
cargo run --release --bin keeper-host -- \
  --rpc http://localhost:8545 \
  --block 0x11982d \
  --follow \
  --save \
  --poll-interval 5
```

Press `Ctrl+C` to stop follow mode.

### Prove from a payload file

```bash
cargo run --release --bin keeper-host -- 11982d_payload.rlp
```

## Payload Generator (Go)

A standalone Go tool under `host/payloadgen/` that generates keeper payloads using go-ethereum's RPC directly. Useful for verifying correctness of the Rust payload implementation in `host/src/payload.rs`.

> **Note:** `go.mod` uses a local replace directive pointing to `/data/stephen/go-ethereum`. Adjust the path if your go-ethereum checkout is elsewhere.

### Generate a single payload

```bash
cd host/payloadgen
go run . -rpc http://localhost:8545 -block 0x11982d -out-dir ./payloads
```

### Follow mode (continuously generate)

```bash
go run . -rpc http://localhost:8545 -block latest -follow -poll-interval 5s -out-dir ./payloads
```

### Compare Go and Rust payloads

```bash
# Generate with Go
cd host/payloadgen
go run . -rpc http://localhost:8545 -block 0x11982d -out-dir /tmp/go_payloads

# Generate with Rust
cd ../..
cargo run --release --bin keeper-host -- --save --rpc http://localhost:8545 --block 0x11982d

# Compare
diff <(xxd /tmp/go_payloads/11982d_payload.rlp) <(xxd 11982d_payload.rlp)
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-rpc` | `http://127.0.0.1:8545` | Geth JSON-RPC URL (must enable debug namespace) |
| `-block` | `latest` | Block number (decimal/hex) or `latest` |
| `-out-dir` | `/data/stephen/ziren-shape-bin/geth/payloads` | Output directory |
| `-timeout` | `20s` | RPC call timeout |
| `-follow` | `false` | Continuously generate payloads for new blocks |
| `-poll-interval` | `5s` | Polling interval in follow mode |
| `-skip-existing` | `true` | Skip if output file already exists |

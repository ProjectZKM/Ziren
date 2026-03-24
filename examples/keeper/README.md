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

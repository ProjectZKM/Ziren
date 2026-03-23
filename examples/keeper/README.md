# Keeper

See more [Keeper - geth as a zkvm guest](https://github.com/ethereum/go-ethereum/tree/master/cmd/keeper#keeper---geth-as-a-zkvm-guest).

## Usage

### Fetch payload from RPC and prove

```bash
# latest block
cargo run --release --bin keeper-host -- \
  --rpc http://localhost:8545 \
  --block latest

# specific block
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

The payload file will be saved as `{block_number}_payload.rlp` in the current directory.

### Prove from a payload file

```bash
cargo run --release --bin keeper-host -- 1155117_payload.rlp
```

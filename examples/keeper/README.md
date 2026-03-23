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

### Prove from a payload file

```bash
cargo run --release --bin keeper-host -- /tmp/1155117_payload.rlp
```

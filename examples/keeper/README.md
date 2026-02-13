# Keeper

See more [Keeper - geth as a zkvm guest](https://github.com/ethereum/go-ethereum/tree/master/cmd/keeper#keeper---geth-as-a-zkvm-guest).

## Payload Generation

Generate keeper payload files (`*_payload.rlp`) from Ethereum JSON-RPC:

```bash
cd examples/keeper/host/payloadgen
```

Single block:

```bash
# latest block
go run . \
  --rpc http://localhost:8545 \
  --block latest \
  --out-dir /tmp
```

Continuous generation (follow new blocks):

```bash
# start from latest and keep generating
go run . \
  --rpc http://localhost:8545 \
  --block latest \
  --follow \
  --poll-interval 5s \
  --out-dir /tmp

# start from specific block and keep generating
go run . \
  --rpc http://localhost:8545 \
  --block 0x11982d \
  --follow \
  --poll-interval 5s \
  --out-dir /tmp
```

Press `Ctrl+C` to stop follow mode gracefully.

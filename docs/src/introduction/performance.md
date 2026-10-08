# Performance

## Metrics

Three quantities describe a zkVM's performance:

- **Instruction efficiency**: the committed trace area (cells) and bus interactions one executed instruction costs. It is a property of the arithmetization, independent of the hardware.
- **Proving throughput**: guest cycles proved per second on named hardware, from reading the input to writing the compressed proof. It is a rate, not a clock frequency. One cycle is one executed MIPS instruction; a precompile call is one cycle and many rows of its chip.
- **Proof size**: the bytes of the compressed proof a verifier reads.

Proving cost follows from throughput and the price of the hardware: the cost of a proof is its proving time multiplied by the cost per second of the machine. [ethproofs.org](https://ethproofs.org/) reports proving time, proof size and cost per Mgas for Ethereum mainnet blocks proved by each zkVM.

To reproduce measurements on your own hardware, use the [zkvm-benchmarks](https://github.com/ProjectZKM/zkvm-benchmarks) suite.

## Measurements

The figures below are from the Ziren V2.0 paper (`docs/paper`). The workload is Ethereum mainnet blocks executed by MIPS32 builds of two execution clients, Reth (Rust) and the block keeper of Geth (Go). The hardware is NVIDIA RTX 5090 GPUs (32 GB) in a host with an AMD EPYC 9355 processor and 925 GB of memory.

The proving throughput and the proof size are of the released configuration. The GPU kernel profile and the executor rates were measured on revisions of the v2.0.0 branch that precede the release in two respects: the Poseidon2 permutation used 13 partial rounds instead of the released 20, and the lookup challenge was not ground.

### Instruction efficiency

Committed cells and bus interactions for one row of the most frequent chips. The frame (fetch, operand reads, register write and the `(pc, next_pc)` pair) is shared by every instruction chip:

| Chip | cells: frame | cells: own | cells: row | interactions: row |
|------|-------------:|-----------:|-----------:|------------------:|
| `AddSubImm` | 29 | 4 | 33 | 16 |
| `AddSub` | 32 | 4 | 36 | 20 |
| `Bitwise` | 32 | 5 | 37 | 24 |
| `Lt` | 32 | 18 | 50 | 23 |
| `ShiftLeftImm` | 26 | 19 | 45 | 20 |
| `ShiftRight` | 32 | 57 | 89 | 45 |
| `Branch` | 29 | 27 | 56 | ≤ 25 |
| `LoadWord` | 29 | 19 | 48 | 25 |
| `StoreWord` | 29 | 23 | 52 | 25 |
| `LoadNarrow` | 29 | 30 | 59 | 26 |
| `Mul` | 32 | 42 | 74 | 42 |
| `DivRem` | 32 | 131 | 163 | 64 |

Over a whole block the cost per instruction is higher, mainly because of the per-shard memory-argument rows. Block 25,955,640 (495.6 million cycles) commits 29.2 G cells and 12.8 G (row, interaction) pairs: 59.5 cells and 26.2 pairs per executed instruction. The cross-shard `Global` chip holds 15% of the area (8.9 cells per instruction), because every word a shard touches costs two of its rows. The figure depends on the workload: a block that uses more precompiles has more cells per cycle.

### Proving throughput

The same 16 consecutive Ethereum mainnet blocks, 26,138,415 to 26,138,430, proved with both clients on the same GPUs. Proving time runs from the prove request to the compressed proof, warm, and excludes the client's execution and verification; throughput is guest cycles divided by it. For each client the rows give the range, the median and the 99th percentile over the 16 blocks (by linear interpolation between order statistics), and the sums over all 16.

| Client | | Guest cycles | Shards | 1 GPU (s) | 8 GPUs (s) | 1 GPU (MHz) | 8 GPUs (MHz) |
|--------|-|-------------:|-------:|----------:|-----------:|------------:|-------------:|
| Reth | range | 43–508 M | 33–164 | 16.3–75.2 | 6.7–14.1 | 2.6–6.8 | 6.4–36.0 |
| | median | 193 M | 87 | 40.4 | 9.7 | 4.8 | 20.2 |
| | p99 | 484 M | 158 | 72.5 | 13.7 | 6.7 | 35.1 |
| | all 16 | 3.45 G | 1,490 | 691 | 161 | 5.0 | 21.4 |
| Geth | range | 0.25–2.99 G | 64–537 | 33.6–252 | 9.8–39.1 | 7.6–12.2 | 25.8–76.4 |
| | median | 1.27 G | 268 | 124.5 | 22.4 | 10.4 | 57.3 |
| | p99 | 2.87 G | 518 | 242.9 | 37.8 | 12.1 | 75.8 |
| | all 16 | 22.67 G | 4,471 | 2,102 | 373 | 10.8 | 60.8 |

A shard costs about 0.47 s on one GPU under either guest, so proving time follows the number of shards, not the number of cycles. The Reth guest runs more of its work in precompiles, so its shards close after 2.3 million cycles on average against 5.1 million for Geth: it proves at a lower rate and still proves every block 2.1 to 3.8 times faster than Geth on one GPU, and 1.5 to 2.8 times faster on eight. Eight GPUs reduce the summed proving time 5.6 times for Geth and 4.3 times for Reth; the gap to linear scaling is the serial recursion tail after the last shard and the start-up interval before every GPU has a shard.

Scaling across GPUs, for three of these blocks proved with Reth (median of three consecutive warm proofs):

| Block (guest cycles) | 1 GPU (s) | 2 GPUs (s) | 4 GPUs (s) | 1 GPU (MHz) | 2 GPUs (MHz) | 4 GPUs (MHz) |
|----------------------|----------:|-----------:|-----------:|------------:|-------------:|-------------:|
| 26,138,428 (206 M) | 40.9 | 21.5 | 12.5 | 5.0 | 9.6 | 16.5 |
| 26,138,416 (348 M) | 54.8 | 28.8 | 16.3 | 6.4 | 12.1 | 21.4 |
| 26,138,421 (508 M) | 75.1 | 38.9 | 21.3 | 6.8 | 13.0 | 23.8 |

Two GPUs prove each block 1.9 times faster than one, and four 3.3 to 3.5 times faster.

On a GPU, the lookup argument (LogUp-GKR) takes 42% of kernel time and WHIR commitment and opening 19%, in a ten-shard profile. The lookup cost scales with (row, interaction) pairs, so memory instructions, which carry 25 to 26 interactions per row, account for 47% of all pairs.

### Execution

On one core of an AMD EPYC 9355:

| Executor | Rate |
|----------|-----:|
| JIT compiler, once compiled (496 M-cycle block) | 198 MHz |
| JIT compiler, including its compilation pass | 166 MHz |
| Interpreter, without the event record | 40.6 MHz |
| Interpreter, with the event record | 14.6 MHz |

With one GPU, execution does not limit proving. With several GPUs fed by one host, each GPU worker re-executes the shard it proves.

### Proof size

The compressed proof is 274 KiB (280,653 bytes): the root of the recursion tree is proved under a compress schedule (rate 1/8, Johnson-bound WHIR), and since the root program is the same for every tree, the size does not depend on the guest or the length of the execution. Openings of the first WHIR oracle account for most of it. The native verifier checks it in 73 ms. Groth16 and PLONK proofs wrapped from it are constant-size SNARKs for on-chain verification.

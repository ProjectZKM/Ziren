# Performance

Version 2.1.0 (24 November 2026) proves 25 Ethereum mainnet blocks with the Reth guest in a median of **15.1 s per block on two RTX 5090 GPUs** (21.2 MHz aggregate) and **13.7 s on four** (23.2 MHz). The eight-GPU benchmarks of version 2.0 (1 November 2026) reach **75.1 MHz**, with **65.3 MHz aggregate throughput** across 15 blocks using Geth. The compressed proof measures **291,162 bytes (284 KiB)** with **17.7 ms native verification**. The workloads and measurement conditions are detailed below.

## Metrics

Three quantities describe a zkVM's performance:

- **Instruction efficiency**: the committed trace area (cells) and bus interactions one executed instruction costs. It is a property of the arithmetization, independent of the hardware.
- **Proving throughput**: guest cycles divided by proving time on named hardware, reported in MHz (10⁶ guest instructions/s). The GPU benchmarks below measure from the prove request at the prover to the compressed proof, excluding client execution and verification. One cycle is one executed MIPS instruction; a precompile call counts as one cycle but contributes many rows to its chip.
- **Proof size**: the bytes of the compressed proof a verifier reads.

Proving cost follows from throughput and the price of the hardware: the cost of a proof is its proving time multiplied by the cost per second of the machine. [ethproofs.org](https://ethproofs.org/) reports proving time, proof size and cost per Mgas for Ethereum mainnet blocks proved by each zkVM.

To reproduce measurements on your own hardware, use the [zkvm-benchmarks](https://github.com/ProjectZKM/zkvm-benchmarks) suite.

## Measurements

The figures below are those of the Ziren paper (`docs/paper`), with the instruction-efficiency table brought to version 2.1.0. The throughput workload is Ethereum mainnet blocks executed by MIPS32 builds of two execution clients, Reth (Rust) and the block keeper of Geth (Go). The hardware is NVIDIA RTX 5090 GPUs (32 GB) in a host with an AMD EPYC 9355 processor, 124 vCPUs and 925 GiB of memory. The throughput runs use driver 570.153.02 and CUDA 12.8 on Ubuntu 22.04, with the GPU server in a CUDA 12.8.1 container based on Ubuntu 24.04.

The one-, two- and four-GPU Reth measurements and the proof-size and native-verification measurements are of version 2.1.0, taken on 24 November 2026. The two-client table, with its eight-GPU columns, is of version 2.0, measured on 1 November 2026, and has not been rerun. These results should be interpreted within their respective versions.

### Instruction efficiency

Committed cells and bus interactions for one row of the most frequent chips. The frame (fetch, operand reads, register write and the `(pc, next_pc)` pair) is shared by every instruction chip:

| Chip | cells: frame | cells: own | cells: row | interactions: row |
|------|-------------:|-----------:|-----------:|------------------:|
| `AddSubImm` | 27 | 4 | 31 | 13 |
| `AddSub` | 29 | 4 | 33 | 16 |
| `Bitwise` | 29 | 5 | 34 | 20 |
| `Lt` | 29 | 18 | 47 | 19 |
| `ShiftLeftImm` | 24 | 19 | 43 | 17 |
| `ShiftRight` | 29 | 57 | 86 | 41 |
| `Branch` | 27 | 23 | 50 | ≤ 18 |
| `LoadWord` | 27 | 19 | 46 | 20 |
| `StoreWord` | 27 | 19 | 46 | 20 |
| `LoadNarrow` | 27 | 30 | 57 | 21 |
| `Mul` | 29 | 42 | 71 | 38 |
| `DivRem` | 29 | 131 | 160 | 60 |

Version 2.1.0 removes one column and one lookup from every register access, and six lookups from a branch: a register row with three accesses is three cells and three interactions lighter than in version 2.0.

Over a whole block the cost per instruction is higher, mainly because of the per-shard memory-argument rows. At version 2.0, block 25,955,640 (495.6 million cycles) commits 29.2 G cells and 12.8 G (row, interaction) pairs: 58.9 cells and 25.8 pairs per executed instruction. The cross-shard `Global` chip holds 15% of the area (8.8 cells per instruction), because every word a shard touches costs two of its rows. The figure depends on the workload: a block that uses more precompiles has more cells per cycle.

### Proving throughput

#### Version 2.1.0: Reth on one, two and four GPUs

25 Ethereum mainnet blocks in the range 26,413,605 to 26,413,714, proved with the Reth guest: 72 to 579 million cycles each, 8.31 G in total. Each run proves ten other blocks first, so every measured proof is warm. Proving time runs from the prove request to the compressed proof and excludes the client's execution and verification. Every proof was checked by the native verifier, with the recursion-key allowlist enabled.

| GPUs | Total (s) | Aggregate (MHz) | Median block (s) | 90th percentile (s) | Slowest block (s) |
|-----:|----------:|----------------:|-----------------:|--------------------:|------------------:|
| 1 | 592.6 | 14.0 | 22.6 | 34.0 | 41.3 |
| 2 | 391.5 | 21.2 | 15.1 | 22.4 | 29.8 |
| 4 | 357.4 | 23.2 | 13.7 | 20.3 | 27.1 |

Three of these blocks (minimum, median and maximum guest cycles of the set; mean of three consecutive warm proofs):

| Block (guest cycles) | 1 GPU (s) | 2 GPUs (s) | 4 GPUs (s) | 1 GPU (MHz) | 2 GPUs (MHz) | 4 GPUs (MHz) |
|----------------------|----------:|-----------:|-----------:|------------:|-------------:|-------------:|
| 26,413,689 (72 M) | 7.6 | 5.4 | 4.5 | 9.4 | 13.4 | 16.1 |
| 26,413,708 (338 M) | 24.9 | 16.7 | 14.4 | 13.6 | 20.3 | 23.5 |
| 26,413,640 (579 M) | 41.8 | 27.0 | 26.4 | 13.8 | 21.5 | 21.9 |

Two GPUs are 1.51 times faster than one, and four take 9% less time than two. One GPU alone finishes the set in 592.6 s, so the cards are idle for at least a quarter of the time on two GPUs and for more than half on four: the rest of a block's time is work that does not spread over GPUs, namely the host re-executing each shard and generating its traces, and the serial end of the recursion.

Against the prover without the two changes of this version, on the same blocks and the same two GPUs, with the runs interleaved, version 2.1.0 takes 8.7% less proving time (436.8 s to 398.6 s for the 25 blocks, every block faster), and 11.3% less on four GPUs. The gain comes from the univariate skip in the zerocheck, which cuts its kernel time by 28%, and from the lighter register and branch lookups (see [STARK Protocol](../design/stark.md) and [Memory](../design/chips/memory.md)).

#### Version 2.0: two execution clients, one and eight GPUs

Both rows use 15 consecutive Ethereum mainnet blocks, 26,303,831 to 26,303,845, proved on one GPU (and on eight GPUs for the 8-GPU columns). Proving time runs from the prove request to the compressed proof, warm, and excludes the client's execution and verification; throughput is guest cycles divided by it. For each client, the range row gives the minimum and maximum per-block values. In the total (15) row, guest cycles and shards are sums across the 15 blocks; proving time and throughput use blocks 2 to 15 only, since block 1 includes cold-start cost. Every proof in the 11 October 2026 rerun passed native verification. The benchmark logs and build and runtime metadata are archived separately.

| Client | Summary | Guest cycles | Shards | 1 GPU (s) | 8 GPUs (s) | 1 GPU (MHz) | 8 GPUs (MHz) |
|--------|---------|-------------:|-------:|----------:|-----------:|------------:|-------------:|
| Reth | range | 29.8–358 M | 17–140 | 7.7–51.1 | 3.7–14.5 | 3.9–7.5 | 8.1–33.7 |
| | total (15) | 3.21 G | 1,280 | 433 | 116.5 | 6.9 | 25.6 |
| Geth | range | 0.27–4.63 G | 92–1,425 | 31.7–418 | 7.4–62.0 | 8.5–11.1 | 36.4–75.1 |
| | total (15) | 31.35 G | 9,917 | 2,837 | 452 | 10.4 | 65.3 |

Shard counts vary slightly between runs: block 26,303,831 closes 90 shards on one GPU and 92 on eight.

A block costs in proportion to its shards, not its cycles: a shard takes about 0.36 s on one GPU for Reth and 0.30 s for Geth. The Reth guest runs more of its work in precompiles, so its shards close after 2.5 million cycles on average against 3.2 million for Geth: it proves at a lower rate and still finishes every block sooner. Its blocks are also smaller, so on eight GPUs the serial recursion tail after the last shard is a larger share of each.

Scaling across GPUs at version 2.0, for three of these blocks proved with Reth (minimum, median and maximum guest cycles of the set; mean of three consecutive warm proofs):

| Block (guest cycles) | 1 GPU (s) | 2 GPUs (s) | 4 GPUs (s) | 1 GPU (MHz) | 2 GPUs (MHz) | 4 GPUs (MHz) |
|----------------------|----------:|-----------:|-----------:|------------:|-------------:|-------------:|
| 26,303,841 (30 M) | 7.9 | 5.3 | 5.7 | 3.8 | 5.7 | 5.2 |
| 26,303,840 (204 M) | 31.5 | 23.2 | 11.2 | 6.5 | 8.8 | 18.2 |
| 26,303,843 (358 M) | 51.3 | 28.2 | 16.7 | 7.0 | 12.7 | 21.4 |

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

On 24 November 2026, a freshly generated Fibonacci proof (`n = 500`) at version 2.1.0 was measured with both the prover's in-circuit child-key allowlist checks and the native verifier's root-key check enabled, using the regenerated map of 12,226 supported verification keys. Native verification used the AMD EPYC 9355 host with 24 Rayon threads.

| Measurement | Result |
|-------------|-------:|
| Compressed proof including its recursion key (`ZKMReduceProof`) | 291,162 bytes (284 KiB) |
| Native verification, median of five warm runs | 17.7 ms |
| Range of that median over six repetitions | 16.4–20.3 ms |

The same measurement on the previous version, taken alongside, gives 290,530 bytes and 22.0 ms: the univariate skip's first message has 61 coefficients where the four rounds it replaces had 20, which adds 632 bytes. The verifier's jagged evaluation goes through all sixteen values of the four skipped row bits for every column; it now evaluates each column directly at its integer offsets, which takes a few multiplications per layer and makes verification faster than before the skip. Verification time excludes proving, setup, deserialization and one warm-up verification. The compressed proof uses the root's compress schedule (rate 1/8, Johnson-bound WHIR); openings of the first WHIR oracle account for most of its size. For a fixed root program and commitment shape, proof size is independent of the guest's execution length. Groth16 and PLONK wrapping produce separate constant-size SNARKs for on-chain verification; the measurements above are for the native compressed proof.

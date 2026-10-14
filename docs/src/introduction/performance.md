# Performance

The latest Ethereum block benchmarks (11 October 2026) reach **75.8 MHz** on eight RTX 5090 GPUs, with **60.6 MHz aggregate throughput** across 15 blocks using Geth. The latest compressed-proof benchmark (14 October 2026) measures **290,643 bytes (284 KiB)** and **25.2 ms native verification**. The workloads and measurement conditions are detailed below.

## Metrics

Three quantities describe a zkVM's performance:

- **Instruction efficiency**: the committed trace area (cells) and bus interactions one executed instruction costs. It is a property of the arithmetization, independent of the hardware.
- **Proving throughput**: guest cycles divided by proving time on named hardware, reported in MHz (10⁶ guest instructions/s). The GPU benchmarks below measure from the prove request at the prover to the compressed proof, excluding client execution and verification. One cycle is one executed MIPS instruction; a precompile call counts as one cycle but contributes many rows to its chip.
- **Proof size**: the bytes of the compressed proof a verifier reads.

Proving cost follows from throughput and the price of the hardware: the cost of a proof is its proving time multiplied by the cost per second of the machine. [ethproofs.org](https://ethproofs.org/) reports proving time, proof size and cost per Mgas for Ethereum mainnet blocks proved by each zkVM.

To reproduce measurements on your own hardware, use the [zkvm-benchmarks](https://github.com/ProjectZKM/zkvm-benchmarks) suite.

## Measurements

The figures below are from the Ziren V2.0 paper (`docs/paper`). The throughput workload is Ethereum mainnet blocks executed by MIPS32 builds of two execution clients, Reth (Rust) and the block keeper of Geth (Go). The hardware is NVIDIA RTX 5090 GPUs (32 GB) in a host with an AMD EPYC 9355 processor, 124 vCPUs and 925 GiB of memory. The throughput runs use driver 570.153.02 and CUDA 12.8 on Ubuntu 22.04, with the GPU server in a CUDA 12.8.1 container based on Ubuntu 24.04.

The throughput tables were rerun on 11 October 2026, before the subsequent Linux syscall and Poseidon2 address constraint fixes. The proof-size and native-verification measurements were rerun on 14 October 2026 at revision `cf0b3742`, with both fixes and the regenerated verification-key map. The GPU kernel profile and executor rates are historical measurements from an earlier configuration, including 13 Poseidon2 partial rounds rather than the corrected 20 and no lookup-challenge grinding. These results should be interpreted within their respective configurations.

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

Over a whole block the cost per instruction is higher, mainly because of the per-shard memory-argument rows. Block 25,955,640 (495.6 million cycles) commits 29.2 G cells and 12.8 G (row, interaction) pairs: 58.9 cells and 25.8 pairs per executed instruction. The cross-shard `Global` chip holds 15% of the area (8.8 cells per instruction), because every word a shard touches costs two of its rows. The figure depends on the workload: a block that uses more precompiles has more cells per cycle.

### Proving throughput

The same 15 consecutive Ethereum mainnet blocks, 26,138,416 to 26,138,430, proved with both clients on the same GPUs. The initial block 26,138,415 is excluded to avoid startup effects, as are the separately flagged warm-up proofs. Proving time runs from the prove request to the compressed proof, warm, and excludes the client's execution and verification; throughput is guest cycles divided by it. For each client, the range row gives the minimum and maximum per-block values. In the total (15) row, guest cycles, shards and proving time are sums across the 15 blocks; throughput is total guest cycles divided by total proving time. Every proof in the 11 October 2026 rerun passed native verification. The benchmark logs and build and runtime metadata are archived separately.

| Client | Summary | Guest cycles | Shards | 1 GPU (s) | 8 GPUs (s) | 1 GPU (MHz) | 8 GPUs (MHz) |
|--------|---------|-------------:|-------:|----------:|-----------:|------------:|-------------:|
| Reth | range | 43–508 M | 33–164 | 16.4–76.6 | 6.3–14.3 | 2.6–6.6 | 6.8–35.5 |
| | total (15) | 3.30 G | 1,409 | 661 | 153 | 5.0 | 21.5 |
| Geth | range | 0.25–2.99 G | 64–537 | 33.9–257 | 10.3–39.4 | 7.5–12.0 | 24.6–75.8 |
| | total (15) | 21.65 G | 4,251 | 2,020 | 358 | 10.7 | 60.6 |

A block costs in proportion to its shards, not its cycles: a shard takes about 0.47 s on one GPU under either guest. The Reth guest runs more of its work in precompiles, so its shards close after 2.3 million cycles on average against 5.1 million for Geth: it proves at a lower rate and still finishes every block sooner. Its blocks are also smaller, so on eight GPUs the serial recursion tail after the last shard is a larger share of each.

Scaling across GPUs, for three of these blocks proved with Reth (mean of three consecutive warm proofs):

| Block (guest cycles) | 1 GPU (s) | 2 GPUs (s) | 4 GPUs (s) | 1 GPU (MHz) | 2 GPUs (MHz) | 4 GPUs (MHz) |
|----------------------|----------:|-----------:|-----------:|------------:|-------------:|-------------:|
| 26,138,428 (206 M) | 41.4 | 21.5 | 12.5 | 5.0 | 9.6 | 16.5 |
| 26,138,416 (348 M) | 55.1 | 29.2 | 16.4 | 6.3 | 11.9 | 21.2 |
| 26,138,421 (508 M) | 75.8 | 38.9 | 21.5 | 6.7 | 13.1 | 23.6 |

Two GPUs prove each block 1.9 to 2.0 times faster than one, and four 3.3 to 3.5 times faster.

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

On 14 October 2026, a freshly generated Fibonacci proof (`n = 500`) at revision `cf0b3742` was measured with both the prover's in-circuit child-key allowlist checks and the native verifier's root-key check enabled, using the regenerated map of 6,494 supported verification keys. Proving used one RTX 5090; native verification used the AMD EPYC 9355 host with 24 Rayon threads.

| Measurement | Result |
|-------------|-------:|
| Compressed proof including its recursion key (`ZKMReduceProof`) | 290,643 bytes (284 KiB) |
| SDK container including variant, public outputs and version | 290,681 bytes |
| Native verification, median of five warm runs | 25.2 ms |
| Native verification, range across those runs | 24.8–25.3 ms |

Verification time excludes proving, setup, deserialization and one warm-up verification. The compressed proof uses the root's compress schedule (rate 1/8, Johnson-bound WHIR); openings of the first WHIR oracle account for most of its size. For a fixed root program and commitment shape, proof size is independent of the guest's execution length. Groth16 and PLONK wrapping produce separate constant-size SNARKs for on-chain verification; the measurements above are for the native compressed proof.

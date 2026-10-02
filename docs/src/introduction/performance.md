# Performance

## Metrics

Three quantities describe a zkVM's performance:

- **Instruction efficiency**: the committed trace area (cells) and bus interactions one executed instruction costs. It is a property of the arithmetization, independent of the hardware.
- **Proving throughput**: guest cycles proved per second on named hardware, from reading the input to writing the compressed proof. It is a rate, not a clock frequency. One cycle is one executed MIPS instruction; a precompile call is one cycle and many rows of its chip.
- **Proof size**: the bytes of the compressed proof a verifier reads.

Proving cost follows from throughput and the price of the hardware: the cost of a proof is its proving time multiplied by the cost per second of the machine. [ethproofs.org](https://ethproofs.org/) reports proving time, proof size and cost per Mgas for Ethereum mainnet blocks proved by each zkVM.

To reproduce measurements on your own hardware, use the [zkvm-benchmarks](https://github.com/ProjectZKM/zkvm-benchmarks) suite.

## Measurements

The figures below are from the Ziren V2.0 paper (`docs/paper`). The workload is Ethereum mainnet blocks executed by a MIPS32 build of the `reth` execution client. The hardware is NVIDIA RTX 5090 GPUs (32 GB) in a host with an AMD EPYC 9355 processor and 925 GB of memory.

The proving times and proof size were measured on revisions of the v2.0.0 branch that precede the release in two respects: the Poseidon2 permutation used 13 partial rounds instead of the released 20, and the lookup challenge was not ground. The released configuration therefore differs from these numbers by an unmeasured amount.

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

One RTX 5090 proves a 288-million-cycle block at 5.9 MHz. Multi-GPU results, on warm wall-clock time of three consecutive proofs:

| Block (guest cycles) | 1 GPU (s) | 2 GPUs (s) | 4 GPUs (s) | 1 GPU (MHz) | 2 GPUs (MHz) | 4 GPUs (MHz) |
|----------------------|----------:|-----------:|-----------:|------------:|-------------:|-------------:|
| 420 M | 65.9 | 34.3 | 21.0 | 6.4 | 12.2 | 20.0 |
| 530 M | 84.3 | 44.7 | 26.5 | 6.3 | 11.9 | 20.0 |
| 912 M | 124.3 | 65.0 | 38.0 | 7.3 | 14.0 | 24.0 |

Four GPUs reach 3.1 to 3.3 times the throughput of one. The gap to linear scaling is the serial recursion tail over the last shards and the start-up interval before every GPU has a shard.

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

The compressed proof is 603 KiB (617,618 bytes in an instrumented run) and does not grow with the length of the execution. Openings of the first WHIR oracle account for 79% of it. Groth16 and PLONK proofs wrapped from it are constant-size SNARKs for on-chain verification.

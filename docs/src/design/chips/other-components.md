# Other Components

Besides the ALU, flow-control and memory chips, the core machine has the program table, two lookup tables, the chips for the remaining instructions, the syscall and precompile chips, and the `Global` chip. The recursion machine that verifies shard proofs is a separate machine with its own chips; it is described in [Recursive STARK](../prover-architecture/recursive-stark.md).

## Program chip

A preprocessed table with one row per instruction of the program image. The preprocessed columns are `pc` and the decoded instruction (`opcode`, `op_a`, `op_b`, `op_c`, `imm_b`, `imm_c`, `op_a_0`), and the only main column is a multiplicity. Every instruction row sends `(pc, instruction)` on the `Program` bus and the program chip receives it with the multiplicity. The preprocessed commitment is part of the verifying key, so a prover can only execute instructions of the committed program at the addresses where they were loaded.

## Lookup tables

- `ByteLookup` is preprocessed over all pairs of bytes, \\( 2^{16} \\) rows. For each pair it lists the results of `AND`, `OR`, `XOR`, `NOR`, `SLL`, `ShrCarry` and `LTU`, the `MSB` of a byte, and the `U8Range` and `U16Range` checks, with one multiplicity column per operation. Lookups have the form `(op, a, b, c)`.
- `RangeLookup` is preprocessed with the pairs `(a, bits)` for \\( a < 2^{bits} \\) and \\( bits \le 10 \\). Its main use is the 10-bit high limb of 26-bit timestamps.

## Other instruction chips

- `MovCond` proves the conditional moves `MOVZ` and `MOVN` (opcodes `MEQ` and `MNE`) and the byte swap `WSBH`.
- `MiscInstrs` proves `INS`, `EXT`, the sign extensions `SEB` and `SEH` (opcode `SEXT`), the multiply-accumulate instructions `MADD`, `MADDU`, `MSUB` and `MSUBU`, which read and write `HI` and `LO`, and the trap `TEQ`.
- `SyscallInstrs` proves the `syscall` instruction. The syscall number and two arguments are the registers `$v0`, `$a0` and `$a1`. The row:
  - sends the call on the `Syscall` bus when a precompile or a Linux syscall must prove it;
  - advances `clk` by the call's extra cycles;
  - writes the result to `$v0`;
  - handles `COMMIT` and `COMMIT_DEFERRED_PROOFS` by checking the committed word against the shard's public `committed_value_digest` or `deferred_proofs_digest`;
  - on `HALT` or `exit_group`, sets `next_pc` to 0 and requires the exit code to equal the public `exit_code`.

## Syscalls and precompiles

- `SyscallCore` and `SyscallPrecompile` connect execution shards to precompile shards. Precompile events are proved in separate shards, so a syscall made in an execution shard is sent as a `Global` message by `SyscallCore` and received by `SyscallPrecompile` in the shard that proves it.
- `SysLinux` proves the results of the supported Linux syscalls: `mmap`/`mmap2`, `brk`, `clone`, `exit_group`, `fcntl`, `read` and `write`.
- The precompile chips each prove one operation over memory:
  - hashing: `Sha256Extend` and `Sha256Compress` (each with a control chip), `KeccakSponge` (with a control chip) and `Poseidon2Permute`;
  - elliptic curves: `Ed25519Add`, `Ed25519Decompress`, the add, double and decompress chips for secp256k1, secp256r1 and BLS12-381, and add and double for BN254;
  - field arithmetic: base-field `Fp`, `Fp2Mul` and `Fp2AddSub` for BN254 and BLS12-381;
  - big integers: `Uint256Mul` (multiplication modulo a 256-bit modulus) and `U256x2048Mul`.

  A precompile row receives the call from the `Syscall` bus with its `(shard, clk)`, reads and writes memory at that timestamp through the memory argument, and range-checks every word it writes. The list of syscalls is in [MIPS ISA](../../mips-vm/mips-isa.md), and the guest interface in [Precompiles](../../dev/precompiles.md).

## Global chip

The `Global` chip receives every message on the `Global` bus, that is, every value that must travel between shards: the initial and final value of each memory address a shard touches (from `MemoryLocal`, `MemoryGlobalInit` and `MemoryGlobalFinal`) and each syscall sent to a precompile shard. A message is seven field elements plus a `kind` and a send or receive flag. The chip maps it to a point on an elliptic curve over the degree-7 extension of KoalaBear and adds the points up with the `GlobalAccumulation` bus. The shard's resulting sum is a public value, and the recursion checks that the sums of all shards add to zero. The construction is described in [Memory Consistency Checking](../memory-checking.md).

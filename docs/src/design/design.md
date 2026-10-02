# Design

Ziren is a zkVM for the MIPS32r2 instruction set. It proves that a guest program, compiled to a MIPS ELF, ran to completion on given inputs and produced given public outputs. This section describes Ziren V2.0: the machine that is proved, the proof system that proves it, and the recursion that turns many shard proofs into one small proof.

- **The machine**

  The execution trace is split into *chips*: fixed-width tables over the KoalaBear field \\(p = 2^{31} - 2^{24} + 1\\). There is no central CPU table. Every executed instruction occupies one row in the chip of its opcode family (AddSub, Branch, LoadWord, ...), and each such row carries an *instruction frame*: the program fetch, the three register accesses and the `(clk, pc)` hand-off to the next instruction. Constraints are local to one row and of degree at most three; every relation between rows or between chips is an interaction on a named *bus*. Memory, byte and range lookups, syscalls and precompiles are chips on the same buses. See [State Machine](./chips/state-machine.md) and [Arithmetization](./arithmetization.md).

- **The shard argument**

  A long execution is cut into *shards*, each proved on its own. A shard proof commits to all of the shard's traces with one jagged polynomial commitment, proves every bus balance with one LogUp-GKR argument and every chip's constraints with one zerocheck, and opens the committed columns with WHIR. See [Lookup Arguments](./lookup-arguments.md) and [STARK Protocol](./stark.md).

- **Memory across shards**

  Within a shard, memory is checked with timestamped read/write tuples on the memory bus. Across shards, every value a shard leaves for a later one is sent as a point on an elliptic curve over the degree-7 extension of KoalaBear, and the sum of all shards' points must be the identity. See [Memory Consistency Checking](./memory-checking.md) and [Continuation](./continuation.md).

- **Recursion and the SNARK**

  A recursion machine verifies shard proofs inside its own programs: a *normalize* (leaf) program verifies one shard, *compose* programs merge up to three adjacent results, and a *shrink* and a *wrap* step prepare the final proof for a BN254 SNARK. The wrap proof is verified in a Groth16 or PLONK circuit for on-chain use. See [Prover Architecture](./prover-architecture/prover-architecture.md).

- **Proof composition**

  A guest can verify other Ziren proofs through the `verify_zkm_proof` syscall; those proofs are checked by the recursion tree as *deferred* proofs. See [Proof Composition](./prover-architecture/proof-composition.md).

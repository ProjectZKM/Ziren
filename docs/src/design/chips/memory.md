# Memory

The Memory Chip family manages memory operations in the MIPS execution environment through specialized column-based constraints. It covers five core subsystems: MemoryGlobal, MemoryLocal, MemoryProgram, MemoryAccess, and MemoryInstructions. Together, they enforce the correct execution of MIPS memory operations..

## MemoryGlobal 
Handles cross-shard memory management, initialization/finalization of global memory blocks, enforcement of address continuity, and verification of zero-register protection

Major Columns:

- ​Address Tracking: Monitors shard ID and 32-bit memory addresses, while enforceing sequential order.
- ​Value Validation: Stores 4-byte memory values with byte-level decomposition.
- ​Control Flags: Identify valid operations and mark terminal addresses in access sequences.
- ​Zero-Register Protection: Flags operations targeting protected memory regions.

Key Constraints:

- Addresses must follow strict ascending order verified via 32-bit comparator checks.
- Memory at address 0 remains immutable after initialization.
- Cross-shard finalization requires consistency with Global Chip.

## MemoryLocal

Maintains single-shard memory operations, tracking read/write events within a shard and preserving initial and final value consistency between consecutive shards.

Major Columns:

- ​Shard Identification: Tracks initial/final shard IDs for multi-shard transitions.
- ​Temporal Metadata: Records start/end clock cycles of memory operations.
- ​Value States: Preserves original and modified values for atomicity checks.
- ​Time Difference Limbs: Splits clock differentials for range verification.

Key Constraints:

- Final values must correspond to explicit write operations.
- Overlapping accesses require a minimum 1-clock gap between operations.
- Decomposed bytes must recompose to valid 32-bit words.

## MemoryProgram 

Responsible for locking executable code into immutable memory regions during proof generation, preventing runtime modification.

Major Columns:

- ​Address-Value Binding: Maps fixed addresses to preloaded executable code.
- Lock Flags: Enforces write protection for program memory regions.
- Multiplicity Checks: Ensures single initialization of static memory.

Key Constraints:

- Preloaded addresses cannot be modified during runtime.
- Each code shard address must be initialized exactly once.
- Access attempts to locked regions trigger validation failures.

## MemoryAccess 

Ensures global state synchronization, maintaining memory coherence across shards via multiset hashing.

Major Columns:

- ​Previous State Tracking: Stores prior shard ID and timestamp for dependency checks.
- Time Difference Analysis: Splits timestamp gaps into 16-bit and 8-bit components.
- Shard Transition Flags: Differentiate intra-shard vs. cross-shard operations.

Key Constraints:

- Cross-shard operations must reference valid prior states.
- Timestamp differences must be constrained within 24-bit range (16+8 bit decomposition).
- Intra-shard operations require sequential clock progression.

## MemoryInstructions
Validates MIPS load/store operations, verifying semantics of memory-related instructions (e.g., LW, SW, LB) and alignment rules.

Major Columns:

- ​Instruction Type Flags: Identifies various memory operations (LW/SB/SC/etc.).
- ​Address Alignment: Tracks least-significant address bits for format checks.
- ​Sign Conversion: Manages sign-extension logic for narrow-width loads.
- ​Atomic Operation Bindings: Establishes linkage between load-linked (LL) to store-conditional (SC) events.

Key Constraints:

- Word operations (LW/SW) require 4-byte alignment (enforced by verifying last 2 address bits = 0).
- Signed loads (LB/LH) perform extension using most significant bit/byte.
- SC operations succeed only if memory remains unchanged since the corresponding LL.
- Address ranges are validated through bitwise decomposition checks.

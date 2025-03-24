# Memory

The Memory Chip family manages memory operations in the MIPS execution environment through specialized column-based constraints. This document covers three core subsystems:

- ​Global Memory (handles initial/final memory states)
- ​Local Memory (manages runtime access patterns)
​- Memory Program (coordinates memory-CPU interactions)

A multiset-hashing-based offline memory consistency checking system ensures complete memory access trace validation.

## ​Global Memory Chip

The Global Memory Chip employs a dual-phase verification mechanism (initialization/finalization) to establish a provable memory lifecycle model. Initialization and finalization memory state share the same shape (i.e., of the same table columns).

```rust
pub struct MemoryInitCols<T: Copy> {
    pub shard: T,                  // Shard number of the memory access
    pub timestamp: T,              // Timestamp of the memory access
    pub addr: T,                   // Address of the memory access
    pub lt_cols: AssertLtColsBits<T, 32>, // Assertions for strictly increasing address
    pub addr_bits: KoalaBearBitDecomposition<T>, // Bit decomposition of `addr`
    pub value: [T; 32],            // Value of the memory access
    pub is_real: T,                // Whether the access is real
    pub is_next_comp: T,           // Assertion flag for `addr < addr_next`
    pub is_prev_addr_zero: IsZeroOperation<T>, // Witness for previous address being zero
    pub is_first_comp: T,          // Auxiliary column: `(1 - is_prev_addr_zero.result) * is_first_row`
    pub is_last_addr: T,           // Flag for the last non-padded address
}
```

## Local Memory Chip

Local Memory chip records memory access during program execution.
 
```rust
pub struct MemoryAccessCols<T> {
    pub value: Word<T>,          // Value of the memory access
    pub prev_shard: T,           // Shard of the previous memory access
    pub prev_clk: T,             // Timestamp of the previous memory access
    pub compare_clk: T,          // True if current shard == previous shard, else false
    pub diff_16bit_limb: T,      // Least significant 16-bit limb of timestamp difference
    pub diff_8bit_limb: T,       // Most significant 8-bit limb of timestamp difference
}
```

## Memory Program Chip

The Memory Program Chip serves as a bridge between the Memory Chip, the CPU Chip, and the processed Program Chip, ensuring that all memory accesses are necessary for program execution.

```rust
pub struct MemoryAccessCols<T> {
    pub value: Word<T>,          // Value of the memory access
    pub prev_shard: T,           // Shard of the previous memory access
    pub prev_clk: T,             // Timestamp of the previous memory access
    pub compare_clk: T,          // True if current shard == previous shard, else false
    pub diff_16bit_limb: T,      // Least significant 16-bit limb of timestamp difference
    pub diff_8bit_limb: T,       // Most significant 8-bit limb of timestamp difference
}
```

```rust
pub struct MemoryProgramPreprocessedCols<T> {
    pub addr: T,
    pub value: Word<T>,
    pub is_real: T,
}
```
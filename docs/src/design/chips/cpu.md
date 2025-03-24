# CPU 

The CPU Chip handles the core logic for processing MIPS instructions. Each program cycle corresponds to a table row accessed via the pc column in the preprocessed Program table. Constraints on pc transitions, clock cycles, and operand handling are enforced through column-based verification.

The CPU architecture employs a structured column-based design to manage instruction execution, branching/jump logic, memory operations, and system calls. Key components are organized into specialized modules (represented as specific columns in the CPU table) with clearly defined constraints and interactions. The CPU table uses selector columns to distinguish instruction types and perform corresponding constraint validation.

## Column Classification & Functional Modules

### Core Module
The central component tracking instruction execution details including clock/shard management, program counter flow, and instruction selection flags. Collaborates with other modules to enforce MIPS instruction correctness through column constraints.

```rust
pub struct CpuCols<T: Copy> {
    // Processor context
    pub shard: T,          // Execution shard ID
    pub clk: T,            // Cycle counter
    pub clk_16bit_limb: T, // Lower 16 bits of clock
    pub clk_8bit_limb: T,  // Upper 8 bits of clock

    // Program counter management
    pub pc: T,             // Current program counter
    pub next_pc: T,        // Next program counter
    pub next_next_pc: T,   // Subsequent program counter

    // Instruction pipeline
    pub instruction: InstructionCols<T>,  // Decoded operation
    pub selectors: OpcodeSelectorCols<T>, // Operation type flags

    // Memory interfaces 
    pub op_hi_access: MemoryReadWriteCols<T>, // High register access
    pub op_a_access: MemoryReadWriteCols<T>, // Primary operand access
    pub op_b_access: MemoryReadCols<T>,      // Secondary operand access
    pub op_c_access: MemoryReadCols<T>,      // Tertiary operand access

    // Execution context 
    pub opcode_specific_columns: OpcodeSpecificCols<T>, // Instruction-type specific data
    pub is_real: T,              // Valid instruction flag
    pub branching: T,            // Branch taken flag
    pub not_branching: T,        // Branch not taken flag

    // Value status flags 
    pub mem_value_is_neg_not_x0: T,  // Negative memory load (non-zero register)
    pub mem_value_is_pos_not_x0: T,  // Positive memory load (non-zero register)
    pub unsigned_mem_val: Word<T>,   // Raw memory value

    // System call handling 
    pub syscall_mul_send_to_table: T,       // Syscall table selector
    pub syscall_range_check_operand: T,     // Syscall parameter validator

    // Control flow 
    pub is_sequential_instr: T,  // Sequential execution flag
}
```


### Instruction Module
Records opcode and operands, with validation through interactions with Program Chip, Memory Chip, and ALU Chip.

```Rust
pub struct InstructionCols<T> {
    pub opcode: T,          // Operation identifier
    pub op_hi: Word<T>,     // the higher bits of the output.
    pub op_a: Word<T>,      // First operand (register/immediate)
    pub op_b: Word<T>,      // Second operand
    pub op_c: Word<T>,      // Third operand
    pub op_a_0: T           // Flag: Is op_a register ZERO?
}
```
## Branch Module
Handles conditional branching through comparative flags and address validation. 

```Rust
pub struct BranchCols<T> {
    pub next_pc: Word<T>,       // Sequential program counter
    pub next_pc_range_checker: KoalaBearWordRangeChecker<T>, 
    pub target_pc: Word<T>,     // Branch target address
    pub target_pc_range_checker: KoalaBearWordRangeChecker<T>, 
    pub a_eq_b: T,              // Equality comparator flag
    pub a_eq_0: T,              // Whether a equals 0.
    pub a_gt_0: T,              // Whether a is greater than 0.
    pub a_lt_0: T               // Signed comparison flag，whether a is less than 0
}
```

## Memory Module
Manages address calculation and data access patterns.

```Rust
pub struct MemoryColumns<T> {
    pub addr_word: Word<T>,                  // Full memory address
    pub addr_word_range_checker: KoalaBearWordRangeChecker<T>,
    pub aa_least_sig_byte_decomp: [T; 6],    // Address alignment bits
    pub addr_aligned: T,                     // 4-byte aligned address
    pub addr_offset: T,                      // Byte offset (0-3)
    pub memory_access: MemoryReadWriteCols<T>, // Access context
    pub offset_is_one: T,                    // Offset position flags
    pub offset_is_two: T,
    pub offset_is_three: T,
    pub most_sig_byte_decomp: [T; 8]         // Value sign analysis
}
```

Additional modules like ​Jump and ​Syscall complete the MIPS instruction lifecycle by marking jump operations and system call handling through specialized column constraints.

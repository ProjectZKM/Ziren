# Other Components

Excepts for CPU Chip, Memory Chips and ALU chips, we also have Program Chip, Bytes Chip, customized Poseidon2 chip, STARK compression chip, STARK-to-SNARK adapter chip, and precompiled Chips .

In addition to the CPU, Memory, and ALU chips, ZKM2 incorporates several specialized components:

- ​Program Chip - Manages instruction preprocessing
- Bytes Chip - Handles byte operations and u16 range check
- Poseidon2 Hash Chip - Cryptographic primitive implementation
- ​STARK Compression/SNARK-to-SNARK Adapter - Proof system optimization
- ​Precompiled Chips - Accelerated cryptographic operations


## Program Chip

Program Chip establishes program execution constraints through preprocessed instruction mapping. The CPU chip performs lookups against this verified instruction set.

```rust
pub struct ProgramPreprocessedCols<T> {
    pub pc: T,                      // Verified program counter
    pub instruction: InstructionCols<T>,  // Decoded operation
    pub selectors: OpcodeSelectorCols<T>, // Instruction type flags
}
```

## Bytes Chip
The Bytes Chip is a preprocessed table usde to validate 16-bit unsigned integer range check and  byte logic/arithmetic operations.

```rust
pub struct BytePreprocessedCols<T> {
    pub a: T,          // First operand
    pub b: T,          // Second operand
    
    // Bitwise Operations
    pub and: T,        // Bitwise AND(a, b)
    pub or: T,         // Bitwise OR(a, b)
    pub xor: T,        // Bitwise XOR(a, b)
    pub nor: T,        // Bitwise NOR(a, b)
    
    // Shift Operations
    pub sll: T,        // Logical left shift
    pub srl: T,        // Logical right shift
    pub sra: T,        // Arithmetic right shift
    pub shr_carry: T,  // Shift carry flag
    
    // Comparison Logic
    pub ltu: T,        // Unsigned less-than
    
    // Value Analysis
    pub msb: T,        // Most significant bit
    pub value_u16: T   // Verified 16-bit value
}
```

## Poseidon2 Hash Chip
ZKM2 implements the [Poseidon2](https://eprint.iacr.org/2023/323) permutation with KoalaBear field optimizations.

```rust
pub struct PermutationConfig {
    // Field Parameters
    pub field_type: KoalaBear,       // Prime field 2³¹ - 2²⁴ + 1
    pub extension_degree: usize,     // Quartic extension (4)
    
    // Cryptographic Components
    pub perm: Poseidon2KoalaBear<16>, // 16-element state
    pub hash: PaddingFreeSponge<...>, // Sponge construction
    pub compress: TruncatedPermutation<...>, // Output compression
    
    // Security Parameters
    pub fri_config: FriConfig,      // FRI protocol configuration
    pub security_level: u32,        // 100-bit security target
    pub digest_size: usize = 8      // 256-bit output
}
```

Poseidon2 is an optimized version of Poseidon, in which Poseidon is a sponge hash function, while Poseidon2 is either a sponge hash function or a compression function depending on its use case. Second, Poseidon2 introduces multiple linear layer (multiplication with a matrix) to improve efficiency.

- The external initial permutation mixes the input with an MDS matrix and initial constants, applying S-box transformations to enhance diffusion.
- The internal permutation rounds add a round constant, perform a non-linear S-box on the first element, adjust the state based on the sum of its elements, and then mix the state with an MDS matrix.
- The external terminal permutation finalizes the state using terminal constants and further mixing.

ZKM2 use custom chip for Poseidon2 computation, which is part of the custom chip for STARK compression and STARK-to-SNARK adapter.


## ​STARK Compression/SNARK-to-SNARK Adapter

Three proofs are used in ZKM2
- Segment Proofs: Used to verify correct execution of patched MIPS instrucitons (call a segment).
- STARK Compressed Proof: Compress segements proof into one STARK proof.
- STARK-to-SNARK Adapter: Transform final STARK proof into Groth16-compatibole SNARK proof.

After emulating MIPS instructions into STARK circuits, where each circuit processes fixed-length instruction segments, and after deriving the corresponding segment STARK proofs, these proofs are first compressed into a single STARK proof. This consolidated proof is then transformed into a SNARK proof. The chips responsible for STARK compression and the STARK-to-SNARK adapter are custom-designed specifically for proof verification over the KoalaBear field.

## Precompiled Chips

Another category of chips extensively utilized in ZKM2 is Precompiled Chips. These chips are specifically designed to handle widely used but computationally intensive cryptographic operations, such as hash functions and signature schemes. 

Unlike the approach of emulating MIPS instructions, ZKM2 delegates these computations to dedicated precompiled chips. The CPU table then performs lookups to retrieve the appropriate values from these chips (precompiles are invoked via syscalls). Precompiles have the capability to directly read from and write to memory through the memory argument. They are typically provided with a clock (clk) value and pointers to memory addresses, which specify the locations for reading or writing data during the operation. For a comprehensive list of precompiled tables, refer to refer to [this section](../../../mips-vm/emulator.md).

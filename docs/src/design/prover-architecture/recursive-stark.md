# Recursive STARK

Ziren zkVM’s STARK aggregation framework is designed to efficiently prove the correct execution of complex MIPS programs. The system decomposes a single computation trace into parallelizable **shard proofs** and recursively compresses them into a single succinct STARK proof, ready for SNARK-layer wrapping and blockchain verification.

## Shard Proof Generation

The first phase of the Ziren proving pipeline focuses on **decomposing program execution** and independently proving each segment in parallel. This is achieved through three tightly-coupled stages, each powered by a modular, multi-chip AIR engine (**MipsAir**).

### 1. **Execution Sharding**

Ziren starts by splitting the full program (typically a compiled MIPS ELF binary) into fixed-size **execution shards**. Each shard represents a window of sequential instructions and maintains precise **context bridging**—ensuring register state, memory, and all side effects remain coherent at shard boundaries. This enables sharding without losing program integrity.

**Implementation Details:**

- **Key functions:**
    - `ZKMProver::get_program(elf)` — Loads and prepares the program, setting up all state for sharding.
    - `ZKMProver::setup(elf)` — Generates proving and verifying keys for all instruction groups.
- **AIR Mechanism:**
    - **MipsAir** is constructed as an enum, with each variant (“chip”) corresponding to a specific instruction type or system event (e.g., arithmetic, memory, branch, syscall, cryptographic precompiles).
    - Each chip maintains its own trace table and constraints; all are initialized at this stage for the full instruction set.

### 2. **Trace Generation** (MipsAir Multi-Chip AIR)

Within each execution shard, Ziren simulates the MIPS instruction flow, recording every register transition, memory access, and I/O event. All transitions are encoded into **polynomial trace tables**—the algebraic backbone of STARK proofs.

**Implementation Details:**

- **Execution & Tracing:**
    - For every executed instruction, Ziren routes events to the appropriate **MipsAir chip**. For example, an `ADD` triggers `AddSubChip`, a `LW` updates `MemoryInstructionsChip`, a `SHA256` syscall triggers `Sha256CompressChip`, etc.
    - Control flow, branching, and exception handling are similarly mapped to dedicated chips.
    - Chips such as `CpuChip`, `ProgramChip`, and `MemoryGlobalChip` capture global state transitions, while chips like `SyscallChip` or `KeccakSpongeChip` handle cryptographic or syscall logic.
- **Trace Table Output:**
    - Each chip serializes its events into field-valued tables (the “AIR trace”), ensuring all constraints are algebraically represented for later proof.
    - This multi-chip design makes it straightforward to extend the VM: new instructions simply require a new chip and AIR variant.
- **Key function:**
    - `ZKMProver::prove_core(pk, stdin, opts, context)` — Runs the program shard, collects execution traces for each chip, and prepares them for proof.
    - Internally uses: `zkm_core_machine::utils::prove_with_context` for low-level trace and context handling.

### 3. **Shard Proof Construction**

Once the trace for a shard is complete, Ziren independently generates a STARK proof for each shard using a **combination of FRI (Fast Reed-Solomon IOP) and Merkle tree-based polynomial commitments**. These proofs are self-contained, enabling parallel generation across multiple worker threads or machines.

**Implementation Details:**

- **Proof Orchestration:**
    - All per-chip traces are aggregated by a `StarkMachine<MipsAir>`, which enforces constraints, computes Merkle roots for polynomial commitments, and runs the FRI protocol.
- **Data Structures:**
    - `ZKMCoreProof` — Aggregates all individual `ShardProof`s.
    - `ShardProof` — Contains the FRI transcript, Merkle root, and public values for a single execution shard.
- **Parallelism:**
    - Shard proofs are generated in parallel, as all trace and constraint evaluation is isolated to each shard.

**Engineering Note:**

By leveraging parallelism and a modular multi-chip AIR design, Ziren dramatically reduces total proving time and supports rapid evolution of the underlying VM semantics.

## Recursive Aggregation

After all shard proofs are generated, Ziren applies a **multi-layer recursive aggregation engine** to compress them into a single STARK proof. This process, powered by the **RecursionAir** engine, enables massive scalability and seamless integration with SNARK-friendly elliptic curves.

### 1. **Proof Normalization & Context Bridging**

First, each `ShardProof` is transformed into a **recursive-friendly witness** (`ZKMRecursionWitnessValues`). This step ensures proof structure uniformity and preserves all execution context between adjacent shards—critical for program soundness and security.

**Implementation Details:**

- **Normalization:**
    - Converts each `ShardProof`’s output (public values, Merkle roots, context states) into a fixed, circuit-friendly format.
    - Prepares all inputs for aggregation in recursive circuits, ensuring that context (memory, registers, I/O, etc.) remains consistent and sound.
- **Key function:**
    - `ZKMProver::get_recursion_core_inputs(vk, shard_proofs, batch_size, is_complete)`

### 2. **Batch Optimization & Input Arrangement**

To maximize efficiency, proofs are batched and arranged for recursive composition. The engine organizes these as first-layer inputs—each batch ready to be compressed in the recursion circuit.

**Implementation Details:**

- **Batching Strategy:**
    - Groups normalized proofs for input to the first aggregation layer, optimizing hardware utilization and recursion circuit size.
    - Handles deferred proofs if the total shard count is not a perfect power-of-two.
- **Key function:**
    - `ZKMProver::get_first_layer_inputs(vk, shard_proofs, deferred_proofs, batch_size)`

### 3. **Multi-Phase Recursive Composition** (RecursionAir Multi-Chip AIR)

### a. **Base Layer Aggregation**

The engine feeds the normalized, batched shard proofs into **initial recursive verification circuits**. These circuits verify the correctness of each proof and output **first-layer aggregation certificates**.

**Implementation Details:**

- **RecursionAir AIR:**
    - `RecursionAir` is built as an enum, where each variant/chip models a different aspect of recursive aggregation (e.g., `BatchFRIChip` for FRI folding, `MemoryVarChip`/`MemoryConstChip` for state, `Poseidon2SkinnyChip`/`Poseidon2WideChip` for recursive hashing).
    - Each chip encodes algebraic constraints for verifying subproofs and producing compressed outputs.

### b. **Intermediate Layers: Recursive Compression**

Certificates from the previous layer are grouped (typically “2-to-1”) and recursively combined by deeper aggregation circuits. Each recursion layer reduces the number of certificates by half, until only one remains.

**Implementation Details:**

- **Layered Aggregation:**
    - Aggregation layers repeat the RecursionAir circuit, each time taking outputs from the previous layer as new inputs.
    - `FriFoldChip` and `BatchFRIChip` are critical for FRI-based recursive combination of subproofs.

### c. **Final Compression**

The final recursion layer outputs a single **ZKMReduceProof**, representing the proof for the entire program execution.

- **Key function:**
    - `ZKMProver::compress(vk, core_proof, deferred_proofs, opts)`
    - Recursively calls `recursion_program`, `compress_program`, and—when needed—`deferred_program` for full aggregation.

## Pipeline Advantages

- **Parallel Proof Generation:** Sharding the execution trace enables Ziren to exploit all available hardware, scaling from a laptop to a compute cluster.
- **Modular, Extensible AIR:** Both `MipsAir` and `RecursionAir` are designed as multi-chip enums—adding new instructions, syscalls, or recursive strategies simply requires implementing a new chip and variant.
- **Efficient Recursive Compression:** The multi-layer aggregation pipeline enables succinct proofs even for extremely long or complex program traces.
- **Seamless SNARK Integration:** The final, aggregated STARK proof is compact and “SNARK-friendly,” ready for fast Plonk/Groth16 wrapping and on-chain verification.

## **Source Mapping Table**

| Pipeline Stage | Core Implementation Functions/Structs | AIR Engines/Structs |
| --- | --- | --- |
| Execution Shard | `get_program`, `setup` | `MipsAir` |
| Trace Generation | `prove_core`, `zkm_core_machine::utils::prove_with_context` | `MipsAir` (multi-chip AIR) |
| Shard Proof | `ZKMCoreProof`, `ShardProof` |  |
| Normalization | `get_recursion_core_inputs`, `ZKMRecursionWitnessValues` |  |
| Batch Optimization | `get_first_layer_inputs` |  |
| Recursion/Compress | `compress`, `recursion_program`, `compress_program`, `deferred_program` | `RecursionAir` (multi-chip AIR) |

### **Implementation MipsAir and RecursionAir**

### **MipsAir: Multi-Chip AIR for MIPS Execution**

The `MipsAir` engine acts as the backbone of the zkVM’s MIPS execution trace algebraization. It is constructed as a Rust enum, where each **variant (“chip”) models a particular MIPS instruction, memory access, system event, or cryptographic precompile**.

### **Chip Responsibilities**

| Chip Variant | Responsibility / Encoded Logic |
| --- | --- |
| `ProgramChip` | Static program table: instruction fetch, program counter, static code checks |
| `CpuChip` | Main MIPS CPU state: PC, registers, instruction decode/dispatch, cycle tracking |
| `AddSubChip` | Arithmetic: addition/subtraction, overflow detection, flag logic |
| `MulChip`, `DivRemChip` | Multiplication, division, modulus, including handling for MIPS-specific edge cases |
| `MemoryInstructionsChip` | Memory access: loads/stores, address translation, memory consistency |
| `MemoryGlobalChip` | Global memory state, initialization and finalization of memory regions |
| `BitwiseChip`, `ShiftLeft`, `ShiftRightChip` | Bitwise ops, logical/arithmetic shift left/right |
| `BranchChip`, `JumpChip` | Control flow: conditional branches, jumps, branching logic |
| `LtChip`, `CloClzChip` | Comparison, leading-zero/count instructions |
| `SyscallChip`, `SyscallInstrsChip` | System call dispatch, I/O events |
| `KeccakSpongeChip`, `Sha256CompressChip`, ... | Cryptographic precompiles, including circuit-level hash and EC operations |
| ... | ... (Elliptic curve, BLS12-381/BN254 operations, modular arithmetic, etc.) |

### **Data Flow**

- **During simulation**, every MIPS instruction and system event is routed to the corresponding chip.
- **Each chip**:
    - Maintains its own trace table, with columns for all relevant fields (inputs, outputs, flags, auxiliary data).
    - Defines algebraic constraints that express correct behavior.
        - *Example*: `AddSubChip` ensures \\(z=x+yz = x + y\\) and correct overflow flag.
        - *Example*: `MemoryInstructionsChip` ensures memory consistency across reads/writes.
- **All chips** are orchestrated by the `StarkMachine<MipsAir>`, which ensures that constraints are enforced both **within** and **across** chips (e.g., register handover between CPU and memory chips).

### **Typical Polynomial Constraint (Example)**

- **Addition**:
    
    \\( \text{AddSubChip: } r_{\text{out}} = r_{\text{in1}} + r_{\text{in2}} \\)
    
- **Memory consistency**:
    
    \\( \text{MemoryInstrs: } \forall\ (a, v)\ \text{write},\ \mathrm{read}(a)\ \text{must see latest } v \\)
    
- **Branch correctness**:
    
    \\( \text{BranchChip: } \text{if}\ cond \to PC_{\text{next}} = target \\)
    
- **Cryptographic precompiles** (e.g., SHA256 step):
    
  \\( \text{Sha256CompressChip: } h_{\text{out}} = \text{SHA256 round}(h_{\text{in}}, w)\ \\)


### **Trace Construction and Proving**

- **Trace Generation**: For every instruction/event, update relevant chip traces and context.
- **Proving**: `prove_core` calls all chips’ constraint checkers; all traces are committed via Merkle roots; FRI is run for low-degree testing.

### **Key Call Relationships**

- `MipsAir::chips()` — Returns all chips needed for the program.
- `MipsAir::machine(config)` — Constructs the STARK machine over all active chips.
- `ZKMProver::prove_core` → `StarkMachine<MipsAir>::prove` — Main proof generation logic; coordinates all chip constraints and witness extraction.

### **RecursionAir: Multi-Chip AIR for Proof Aggregation**

The `RecursionAir` engine is architected for **recursive aggregation and verification** of shard proofs. It shares the multi-chip enum structure of `MipsAir`, but each chip targets aggregation, folding, and recursive hashing.

### **Chip Responsibilities**

| Chip Variant | Responsibility / Encoded Logic |
| --- | --- |
| `MemoryVarChip`, `MemoryConstChip` | Carries over and verifies state for variable/constant memory in recursion |
| `BaseAluChip`, `ExtAluChip` | Encodes base and extension field arithmetic needed for proof normalization or hashing |
| `Poseidon2SkinnyChip`, `Poseidon2WideChip` | Recursively hashes context or proof artifacts with efficient sponge functions |
| `BatchFRIChip`, `FriFoldChip` | Aggregates and verifies FRI transcripts/roots for recursive folding of subproofs |
| `ExpReverseBitsLenChip` | Handles bit-reversal, reordering, or compression in the recursive transcript |
| `SelectChip` | Circuit-level selectors/multiplexers for variable context or proof branching |
| `PublicValuesChip` | Maintains and compresses public values through recursion layers |

### **Data Flow**

- **Input**: All normalized `ShardProof`s are transformed into fixed-length witness vectors.
- **Aggregation**:
    - Base layer: Inputs are fed into chips modeling recursive FRI, Merkle verification, hash merging.
    - Intermediate/final layers: Proofs/certificates are recursively compressed, context is validated at each stage.
- **Output**: The final layer emits a single, compact, recursively-aggregated STARK proof.

### **Typical Polynomial Constraint (Example)**

- **Recursive FRI folding**:
    
    \\( \text{BatchFRIChip: } FRI_{\text{agg}} = FRI_{\text{1}} \circ FRI_{\text{2}} \\)
    
- **Recursive hashing**:
    
    \\( \text{Poseidon2WideChip: } H_\text{out} = \text{Poseidon2}(H_{\text{in}})\ \\)
    
- **Context consistency**:
    
   \\( \text{MemoryVarChip: } context_{\text{next}} = context_{\text{curr}} + \text{delta} \\)
    

### **Key Call Relationships**

- `RecursionAir::machine_wide_with_all_chips(config)` / `machine_skinny_with_all_chips(config)` — Build the recursive proof circuit with the chosen hash function variant.
- `ZKMProver::compress` → recursively calls aggregation and compression logic, passing inputs through multiple RecursionAir layers.
- `get_recursion_core_inputs`, `get_first_layer_inputs` — Normalize and batch inputs for the recursive pipeline.

---

## **Summary Table: AIR and Chip Mapping**

| Phase | Engine/AIR | Key Chips Used | Example Constraint |
| --- | --- | --- | --- |
| MIPS Execution Trace | `MipsAir` | `CpuChip`, `AddSubChip`, `MemoryInstructionsChip`, `Sha256CompressChip`, ... |  \\( r_{\text{out}} = r_{\text{in1}} + r_{\text{in2}} \\) |
| Shard Proof | `StarkMachine` | All `MipsAir` chips | Merkle/Fri roots for all traces |
| Aggregation (Base) | `RecursionAir` | `BatchFRIChip`, `Poseidon2WideChip`, `MemoryVarChip` | \\( H_\text{out} = \text{Poseidon2}(H_{\text{in}})\ \\) |
| Aggregation (Layers) | `RecursionAir` | All aggregation and context chips | Recursive FRI, context bridging |
| Final Proof | `RecursionAir` | Output chip, public values chip | Output compression, public value mapping |
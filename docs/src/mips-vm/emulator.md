# Emulator Design

The instruction emulator is a critical component of the MIPS Virtual Machine (VM) in ZKM2. It is responsible for accurately simulating the execution of MIPS instructions while ensuring compatibility with the STARK framework. The design of the emulator must balance performance, correctness, and integration with the STARK proof system to enable efficient and verifiable computation.

## Execution process of MIPS instructions

The execution process of MIPS program is as follows: (The left is the common execution process, and the right is process of execution with segment splitting.)

![elf_execution_process](./elf_execuition_process.png)

Here, "segments" are used to partition large programs for convenient proving. The main steps are as follows:  

**​Initialization Phase:**
- load_elf: Load MIPS ELF binaries into virtual memory.
- patch_elf: Bypass non-provable runtime checks (e.g., dynamic linker validations).
- patch_stack: Initialize stack with program arguments.

**​Execution Loop:**
- split_seg: Generate the pre-memory-image of the current segment (including the system architecture state) and the pre/post image_id, and use this information to generate the segment data structure and write it to the corresponding segment output file.
- step: Execute an instruction. In the common execution process, directly determine whether the execution exit condition is triggered after the step. If triggered, enter the exit process, otherwise continue to execute the next step; if it is a segment-splitting execution process, after checking the exit condition, also check whether the number of currently executed steps reaches the segment threshold. 

**​Termination:**
- Exit: End program execution.

## Core data structures

The core data structures used in the system include:

- InstrumentedState: Tracks the overall simulation state, including the MIPS architecture state, segment ID, pre-segment state (e.g., PC, image ID, hash root, input), and I/O writers.

  ```
  pub struct InstrumentedState {
    pub state: Box<State>, // MIPS emulator state
    stdout_writer: Box<dyn Write>, // stdout writer
    stderr_writer: Box<dyn Write>, // stderr writer
    pub pre_segment_id: u32, // previous segment ID
    pre_pc: u32, // previous PC
    pre_image_id: [u8; 32], // previous image ID
    pre_hash_root: [u8; 32], // previous hash root
    block_path: String, // block path
    pre_input: Vec<Vec<u8>>, // previous input
    pre_input_ptr: usize, // input pointer
    pre_public_values: Vec<u8>, // previous public values
    pre_public_values_ptr: usize, // public values pointer
  }
  ```
- State: Maintains the MIPS architecture state, including registers, memory, program counter (PC), heap/brk pointers, and execution metrics (steps, cycles).
  ```
  pub struct State {
    pub memory: Box<Memory>, // memory state
    pub registers: [u32; 32], // MIPS general-purpose registers
    pub pc: u32, // current PC
    next_pc: u32, // next PC
    hi: u32, // high register (multiplier/divider)
    lo: u32, // low register (multiplier/divider)
    heap: u32, // heap pointer
    brk: u32, // brk pointer
    local_user: u32, // TLB address
    pub step: u64, // current step
    pub total_step: u64, // total steps
    pub cycle: u64, // current cycle
    pub total_cycle: u64, // total cycles
    pub input_stream: Vec<Vec<u8>>, // input stream
    pub input_stream_ptr: usize, // input stream pointer
    pub public_values_stream: Vec<u8>, // public values stream
    pub public_values_stream_ptr: usize, // public values pointer
    pub exited: bool, // exit flag
    pub exit_code: u8, // exit code
    dump_info: bool, // debug flag
  }
  ```
- Memory: Manages the memory image and access traces, including page caching and read/write traces of the current segment.

  ```
  pub struct Memory {
    pages: BTreeMap<u32, Rc<RefCell<CachedPage>>>, // memory pages
    last_page_keys: [Option<u32>; 2], // cached page keys
    last_page: [Option<Rc<RefCell<CachedPage>>>; 2], // cached pages
    addr: u32, // current address
    count: u32, // access count
    rtrace: BTreeMap<u32, [u8; PAGE_SIZE]>, // read trace
    wtrace: [BTreeMap<u32, Rc<RefCell<CachedPage>>>; 3], // write trace
  }
  ```
- Segment: Tracks segment-specific information, including memory image, PC, segment ID, hash roots, and input/public value streams.

  ```
  pub struct Segment {
    pub mem_image: BTreeMap<u32, u32>, // initial memory image
    pub pc: u32, // initial PC
    pub segment_id: u32, // segment ID
    pub pre_image_id: [u8; 32], // pre-segment image ID
    pub pre_hash_root: [u8; 32], // pre-segment hash root
    pub image_id: [u8; 32], // post-segment image ID
    pub page_hash_root: [u8; 32], // post-segment hash root
    pub end_pc: u32, // end PC
    pub step: u64, // segment steps
    pub input_stream: Vec<Vec<u8>>, // input stream
    pub input_stream_ptr: usize, // input stream pointer
    pub public_values_stream: Vec<u8>, // public values stream
    pub public_values_stream_ptr: usize, // public values pointer
  }
  ```
These structures collectively enable the simulation of MIPS programs, state management, and integration with the ZKM2 proving framework.

## Instruction Emulator

The instruction emulator is a foundational element of the ZKM2, enabling accurate simulation of MIPS programs while generating execution traces for STARK validation. By combining MIPS ISA compliance with ZKP-friendly optimizations, the emulator provides a robust and performant foundation for the zkVM system.

**Key features of the instruction emulator:**
- MIPS ISA compliance:
The emulator supports full compliance with ​MIPS-I ISA, provides ​Turing-complete execution capability for high level language programs.
- Efficient emulation engine:
The emulator simulates the MIPS CPU pipeline, including the Arithmetic Logic Unit (ALU), registers, and control logic.
It handles instruction decoding, execution, and state transitions, ensuring accurate emulation of the MIPS architecture. 
- Integration with STARK framework:
The emulator generates detailed execution traces, including register updates, memory accesses, and instruction executions. These traces are structured as several tables (CPU, ALU, Memory, Bytecodes, etc.; see [chip_design](../../design/design.md) for more details), which are designed to facilitate efficient arithmetization and validation by the STARK proof system.

ZKM2 executor simulates the execution of the MIPS instructions (in forms of ELF file), recording all state changes and computational steps to form a complete execution trace. This trace serves as the core data for generating the zero-knowledge proof, ensuring that the proof accurately reflects the real execution of the program. Subsequently, the ZKM prover efficiently processes and compresses the generated trace to produce a zero-knowledge proof. 

## Circuit Module
In the realm of circuit design, ZKM2 employs a highly modular architecture, meticulously segmenting the entire MIPS program into distinct submodules, each with clearly delineated functions. This approach ensures rigorous management and verification of the execution state across all components. The system initiates with memory consistency checks, followed by a systematic division of the program into several specialized sections: kernel, memory, CPU, arithmetic logic unit (ALU), hashing, and byte processing, among others. 

***The kernel module*** serves as the cornerstone of the system, overseeing the program's entry and exit points. It is tasked with maintaining the stability and consistency of the system state, ensuring a robust foundation for all operations.

***The memory module*** delineates between global and local memory with precision, establishing well-defined boundaries for data access and state transitions. This segregation enhances data integrity and facilitates efficient memory management.

***The CPU module*** is the workhorse of the system, executing core tasks such as branch and jump operations, memory I/O, register manipulation, and system calls. Its role is pivotal in ensuring the precise execution of program logic.

***The ALU module*** is dedicated to arithmetic and logical computations, providing support for a wide array of specific operations, including specialized instructions like CLO/Z. Its efficiency and accuracy are crucial for the computational integrity of the emulator.

Furthermore, ***dedicated hashing*** and ***byte processing*** modules are integral to the system, managing data validation and processing with high precision. Lastly, the ***bus module*** enables efficient communication and data exchange between the various submodules through its cross-table lookup functionality. 



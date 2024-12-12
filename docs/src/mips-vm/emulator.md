# Emulator

The emulator mainly implements the simulation operation of MIPS instruction set and provides interfaces to run MIPS ELF program and generate segments. All the code can be found in [zkm/emulator](https://github.com/zkMIPS/zkm/tree/main/emulator).



## Execution process

The execution process of MIPS program is as follows: (The left is common execution process, The right is process of execution with segments splitting)

![elf_execuition_process](./elf_execuition_process.png)

The main steps are as follows:

- load_elf: Load mips programs into simulated memory.
- patch_elf: Hide some ignorable processes (such as some checks in runtime).
- patch_stack: Initialize the initial runtime stack (including filling program parameters into the stack).
- step: Execute an instruction. In the common execution process, directly determine whether the execution exit condition is triggered after the step. If triggered, enter the exit process, otherwise continue to execute the next step; if it is a segments-splitting execution process, after checking the exit condition Also check whether the number of currently executed steps reaches the segment threshold. If it does, enter the split_seg process. If the exit condition is triggered, enter the split_seg + exit process.
- split_seg: Generate the pre-memory-image of the current segment (including the system architecture state) and the pre/post image_id, and use this information to generate the segment data structure and write it to the corresponding segment output file.
- Exit: End program execution.



## Main data structure

The main data structures used include: 

- InstrumentedState:  Maintain the overall information of simulation system, includes the MIPS architecture state, current segment id, pre-state of current segment, such as pc, image id, hash root,  input, .etc.

  ```
  pub struct InstrumentedState {
     /// state stores the state of the MIPS emulator
     pub state: Box<State>,
  
  
     /// writer for stdout
     stdout_writer: Box<dyn Write>,
     /// writer for stderr
     stderr_writer: Box<dyn Write>,
  
  
     pub pre_segment_id: u32,
     pre_pc: u32,
     pre_image_id: [u8; 32],
     pre_hash_root: [u8; 32],
     block_path: String,
     pre_input: Vec<Vec<u8>>,
     pre_input_ptr: usize,
     pre_public_values: Vec<u8>,
     pre_public_values_ptr: usize,
  }
  ```

  

- State:  Maintain the MiPS architecture state(register, memory, heap pointer, .etc. ) of simulation system.

  ```
  pub struct State {
     pub memory: Box<Memory>,
  
  
     /// the 32 general purpose registers of MIPS.
     pub registers: [u32; 32],
     /// the pc register stores the current execution instruction address.
     pub pc: u32,
     /// the next pc stores the next execution instruction address.
     next_pc: u32,
     /// the hi register stores the multiplier/divider result high(remainder) part.
     hi: u32,
     /// the low register stores the multiplier/divider result low(quotient) part.
     lo: u32,
  
  
     /// heap handles the mmap syscall.
     heap: u32,
  
  
     /// brk handles the brk syscall
     brk: u32,
  
  
     /// tlb addr
     local_user: u32,
  
  
     /// step tracks the total step has been executed.
     pub step: u64,
     pub total_step: u64,
  
  
     /// cycle tracks the total cycle has been executed.
     pub cycle: u64,
     pub total_cycle: u64,
  
  
     /// A stream of input values (global to the entire program).
     pub input_stream: Vec<Vec<u8>>,
  
  
     /// A ptr to the current position in the input stream incremented by HINT_READ opcode.
     pub input_stream_ptr: usize,
  
  
     /// A stream of public values from the program (global to entire program).
     pub public_values_stream: Vec<u8>,
  
  
     /// A ptr to the current position in the public values stream, incremented when reading from public_values_stream.
     pub public_values_stream_ptr: usize,
  
  
     pub exited: bool,
     pub exit_code: u8,
     dump_info: bool,
  }
  ```

  

- Memory: Maintain the current memory image of the system and the access trace information of the current segment.

  ```
  pub struct Memory {
     /// page index -> cached page
     pages: BTreeMap<u32, Rc<RefCell<CachedPage>>>,
  
  
     // two caches: we often read instructions from one page, and do memory things with another page.
     // this prevents map lookups each instruction
     last_page_keys: [Option<u32>; 2],
     last_page: [Option<Rc<RefCell<CachedPage>>>; 2],
  
  
     // for implement std::io::Read trait
     addr: u32,
     count: u32,
  
  
     rtrace: BTreeMap<u32, [u8; PAGE_SIZE]>,
     wtrace: [BTreeMap<u32, Rc<RefCell<CachedPage>>>; 3],
  }
  
  ```

  

- Segment: Maintain the segment related information.

  ```
  pub struct Segment {
     pub mem_image: BTreeMap<u32, u32>,  // initial memory image of segment
     pub pc: u32,                        // initial pc
     pub segment_id: u32,                // segment id
     pub pre_image_id: [u8; 32],         // image id of segment pre state 
     pub pre_hash_root: [u8; 32],       // hash root of segment pre memory image      
     pub image_id: [u8; 32],            // image id of segment post state 
     pub page_hash_root: [u8; 32],      // hash root of segment post memory image
     pub end_pc: u32,                   // end pc
     pub step: u64,                     // step number of cur segment
     pub input_stream: Vec<Vec<u8>>,
     pub input_stream_ptr: usize,
     pub public_values_stream: Vec<u8>,
     pub public_values_stream_ptr: usize,
  }
  
  ```



## Instruction simulation

The emulator uses the instruction parsing method to execute instructions: first fetch the instruction, then parse and execute the corresponding function according to the instruction encoding, and update the system State/Memory status.
The main code: mips_step() can be found in [state.rs](https://github.com/zkMIPS/zkm/blob/main/emulator/src/state.rs).

The supported ISA can be found in [mips_isa](./mips_isa.md).



### Memory simulation and image_id computation

The memory is organized in a hash tree, with page (4KB) as node. The starting address of the hash page is 0x8000000, and the program address space is 0~0x8000000. The root hash page address is 0x81020000. As shown below:

![memory](./memory.png)



The calculation process of page hash and Image id is as follows:

1. Organize the memory (Mem) in pages (4KB), calculate the corresponding hash, and store it in the corresponding hash page;
2. Recursively calculate the hash value of the hash page until there is only one hash page left, which is the root hash page;
3. Write the register information at the 0x400 offset from the hash page, calculate the hash value of the root hash page, and wait until the root hash value;
4. Splice the root hash value and the corresponding pc value together, calculate the hash value, and obtain the image id.


In order to reduce the frequency of page hash updates, the modified memory pages will be recorded during instruction execution. Therefore, during the image ID calculation process, only the corresponding hash pages need to be recursively updated for these modified memory pages to calculate the root hash and image ID.

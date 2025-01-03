//! Programs that can be executed by the ZKM.

extern crate alloc;
// use crate::poseidon_sponge::poseidon_sponge_stark::poseidon;
use alloc::collections::BTreeMap;
use anyhow::{anyhow, bail, Context, Result};
use elf::{endian::BigEndian, file::Class, ElfBytes};
use std::io::Read;
use zkm2_core_emulator::memory::{INIT_SP, WORD_SIZE};

use p3_field::Field;
use p3_maybe_rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use zkm2_stark::air::{MachineAir, MachineProgram};

use crate::{CoreShape, Instruction};

pub const PAGE_SIZE: u32 = 4096;

/// A program that can be executed by the ZKM.
#[derive(PartialEq, Eq, Debug, Clone, Default, Serialize, Deserialize)]
pub struct Program {
    pub instructions: Vec<Instruction>,
    /// The entrypoint of the program, PC
    pub pc_start: u32,
    pub pc_base: u32,
    pub next_pc: u32,
    /// The initial memory image
    pub image: BTreeMap<u32, u32>,
    pub gprs: [usize; 32],
    pub lo: usize,
    pub hi: usize,
    pub heap: usize,
    pub brk: usize,
    pub local_user: usize,
    pub end_pc: usize,
    pub step: usize,
    pub image_id: [u8; 32],
    pub pre_image_id: [u8; 32],
    pub pre_hash_root: [u8; 32],
    pub page_hash_root: [u8; 32],
    pub input_stream: Vec<Vec<u8>>,
    pub input_stream_ptr: usize,
    pub public_values_stream: Vec<u8>,
    pub public_values_stream_ptr: usize,
    /// The shape for the preprocessed tables.
    // todo: check if necessary
    pub preprocessed_shape: Option<CoreShape>,
}

impl Program {
    #[must_use]
    pub fn new(instructions: Vec<Instruction>, pc_start: u32, pc_base: u32) -> Self {
        Self {
            instructions,
            pc_start,
            pc_base,
            next_pc: pc_start + 4,
            ..Default::default()
        }
    }

    /// Initialize a MIPS Program from an appropriate ELF file
    pub fn from(input: &[u8], max_mem: u32) -> Result<Program> {
        let mut image: BTreeMap<u32, u32> = BTreeMap::new();
        let elf = ElfBytes::<BigEndian>::minimal_parse(input)
            .map_err(|err| anyhow!("Elf parse error: {err}"))?;
        if elf.ehdr.class != Class::ELF32 {
            bail!("Not a 32-bit ELF");
        }
        if elf.ehdr.e_machine != elf::abi::EM_MIPS {
            bail!("Invalid machine type, must be MIPS");
        }
        if elf.ehdr.e_type != elf::abi::ET_EXEC {
            bail!("Invalid ELF type, must be executable");
        }
        let entry: u32 = elf
            .ehdr
            .e_entry
            .try_into()
            .map_err(|err| anyhow!("e_entry was larger than 32 bits. {err}"))?;
        if entry >= max_mem || entry % WORD_SIZE as u32 != 0 {
            bail!("Invalid entrypoint");
        }
        let segments = elf.segments().ok_or(anyhow!("Missing segment table"))?;
        if segments.len() > 256 {
            bail!("Too many program headers");
        }

        let mut instructions: Vec<u32> = Vec::new();
        let mut base_address = u32::MAX;

        let mut hiaddr = 0u32;

        for segment in segments.iter().filter(|x| x.p_type == elf::abi::PT_LOAD) {
            let file_size: u32 = segment
                .p_filesz
                .try_into()
                .map_err(|err| anyhow!("filesize was larger than 32 bits. {err}"))?;
            if file_size >= max_mem {
                bail!("Invalid segment file_size");
            }
            let mem_size: u32 = segment
                .p_memsz
                .try_into()
                .map_err(|err| anyhow!("mem_size was larger than 32 bits {err}"))?;
            if mem_size >= max_mem {
                bail!("Invalid segment mem_size");
            }
            let vaddr: u32 = segment
                .p_vaddr
                .try_into()
                .map_err(|err| anyhow!("vaddr is larger than 32 bits. {err}"))?;
            if vaddr % WORD_SIZE as u32 != 0 {
                bail!("vaddr {vaddr:08x} is unaligned");
            }
            if (segment.p_flags & elf::abi::PF_X) != 0 && base_address > vaddr {
                base_address = vaddr;
            }

            let a = vaddr + mem_size;
            if a > hiaddr {
                hiaddr = a;
            }

            let offset: u32 = segment
                .p_offset
                .try_into()
                .map_err(|err| anyhow!("offset is larger than 32 bits. {err}"))?;
            for i in (0..mem_size).step_by(WORD_SIZE) {
                let addr = vaddr.checked_add(i).context("Invalid segment vaddr")?;
                if addr >= max_mem {
                    bail!("Address [0x{addr:08x}] exceeds maximum address for guest programs [0x{max_mem:08x}]");
                }
                if i >= file_size {
                    // Past the file size, all zeros.
                    image.insert(addr, 0);
                } else {
                    let mut word = 0;
                    // Don't read past the end of the file.
                    let len = core::cmp::min(file_size - i, WORD_SIZE as u32);
                    for j in 0..len {
                        let offset = (offset + i + j) as usize;
                        let byte = input.get(offset).context("Invalid segment offset")?;
                        word |= (*byte as u32) << (j * 8);
                    }
                    image.insert(addr, word);
                    // todo: check it
                    if (segment.p_flags & elf::abi::PF_X) != 0 {
                        instructions.push(word);
                    }
                }
            }
        }

        let brk = hiaddr - (hiaddr & (PAGE_SIZE - 1)) + PAGE_SIZE;

        let (symtab, strtab) = elf
            .symbol_table()
            .expect("Failed to read symbol table")
            .expect("Failed to find symbol table");

        // PatchGO
        for symbol in symtab.iter() {
            let name = strtab
                .get(symbol.st_name as usize)
                .expect("Failed to get name from strtab");

            let addr: u32 = symbol
                .st_value
                .try_into()
                .map_err(|err| anyhow!("offset is larger than 32 bits. {err}"))?;

            match name {
                "runtime.gcenable" |
                "runtime.init.5" |         // patch out: init() { go forcegchelper() }
                "runtime.main.func1" |        // patch out: main.func() { newm(sysmon, ....) }
                "runtime.deductSweepCredit" | // uses floating point nums and interacts with gc we disabled
                "runtime.(*gcControllerState).commit" |
                // these prometheus packages rely on concurrent background things. We cannot run those.
                "github.com/prometheus/client_golang/prometheus.init" |
                "github.com/prometheus/client_golang/prometheus.init.0" |
                "github.com/prometheus/procfs.init" |
                "github.com/prometheus/common/model.init" |
                "github.com/prometheus/client_model/go.init" |
                "github.com/prometheus/client_model/go.init.0" |
                "github.com/prometheus/client_model/go.init.1" |
                // skip flag pkg init, we need to debug arg-processing more to see why this fails
                "flag.init" |
                // We need to patch this out, we don't pass float64nan because we don't support floats
                "runtime.check" => {
                    // MIPS32 patch: ret (pseudo instruction)
                    // 03e00008 = jr $ra = ret (pseudo instruction)
                    // 00000000 = nop (executes with delay-slot, but does nothing)
                    image.insert(addr, 0x0800e003);
                    image.insert(addr + 4, 0);
                },
                "runtime.MemProfileRate" => { image.insert(addr, 0) ; },
                &_ => (),
            }
        }

        // PatchStack
        let mut sp = INIT_SP - 4 * PAGE_SIZE;
        // allocate 1 page for the initial stack data, and 16KB = 4 pages for the stack to grow
        for i in (0..5 * PAGE_SIZE).step_by(WORD_SIZE) {
            image.insert(sp + i, 0);
        }

        sp = INIT_SP;
        // init argc, argv, aux on stack
        image.insert(sp + 4, 0x42u32.to_be()); // argc = 0 (argument count)
        image.insert(sp + 4 * 2, 0x35u32.to_be()); // argv[n] = 0 (terminating argv)
        image.insert(sp + 4 * 3, 0); // envp[term] = 0 (no env vars)
        image.insert(sp + 4 * 4, 6u32.to_be()); // auxv[0] = _AT_PAGESZ = 6 (key)
        image.insert(sp + 4 * 5, 4096u32.to_be()); // auxv[1] = page size of 4 KiB (value) - (== minPhysPageSize)
        image.insert(sp + 4 * 6, 25u32.to_be()); // auxv[2] = AT_RANDOM
        image.insert(sp + 4 * 7, (sp + 4 * 9).to_be()); // auxv[3] = address of 16 bytes containing random value
        image.insert(sp + 4 * 8, 0); // auxv[term] = 0

        image.insert(sp + 4 * 9, 0x34322343u32.to_be());
        image.insert(sp + 4 * 10, 0x54323423u32.to_be());
        image.insert(sp + 4 * 11, 0x44572234u32.to_be());
        image.insert(sp + 4 * 12, 0x90032dd2u32.to_be());

        let mut gprs = [0; 32];
        gprs[29] = INIT_SP as usize;

        let lo = 0;
        let hi = 0;
        let heap = 0x20000000;
        let end_pc: u32 = 0;

        // this is just for test
        let mut final_data = [0u8; 36];
        let page_hash_root = [1u8; 32];
        final_data[0..32].copy_from_slice(&page_hash_root);
        final_data[32..].copy_from_slice(&end_pc.to_be_bytes());

        // todo: use poseidon2
        // let image_id_u64s = poseidon::<GoldilocksField>(&final_data);
        let image_id_u64s = vec![0u64; 4];
        let image_id = image_id_u64s
            .iter()
            .flat_map(|&num| num.to_le_bytes())
            .collect::<Vec<_>>();

        let pre_hash_root = [1u8; 32];
        final_data[0..32].copy_from_slice(&pre_hash_root);
        final_data[32..].copy_from_slice(&entry.to_be_bytes());

        // todo: use poseidon2
        // let pre_image_id_u64s = poseidon::<GoldilocksField>(&final_data);
        let pre_image_id_u64s = vec![0u64; 4];
        let pre_image_id = pre_image_id_u64s
            .iter()
            .flat_map(|&num| num.to_le_bytes())
            .collect::<Vec<_>>();

        // decode each instruction
        let instructions: Vec<_> = instructions
            .par_iter()
            .map(|inst| Instruction::decode_from(*inst).unwrap())
            .collect();

        Ok(Program {
            instructions,
            pc_start: entry,
            pc_base: base_address,
            next_pc: entry + 4,
            image,
            gprs,
            lo,
            hi,
            heap,
            brk: brk as usize,
            local_user: 0,
            end_pc: end_pc as usize,
            step: 0,
            image_id: image_id.try_into().unwrap(),
            pre_image_id: pre_image_id.try_into().unwrap(),
            pre_hash_root,
            page_hash_root,
            input_stream: Vec::new(),
            input_stream_ptr: 0,
            public_values_stream: Vec::new(),
            public_values_stream_ptr: 0,
            preprocessed_shape: None,
        })
    }

    /// Create a new [Program].

    /// Disassemble a RV32IM ELF to a program that be executed by the VM from a file path.
    ///
    /// # Errors
    ///
    /// This function will return an error if the file cannot be opened or read.
    pub fn from_elf(path: &str) -> eyre::Result<Self> {
        let mut elf_code = Vec::new();
        std::fs::File::open(path)?.read_to_end(&mut elf_code)?;
        let max_mem = 0x80000000;
        Ok(Program::from(&elf_code, max_mem).unwrap())
    }

    /// Custom logic for padding the trace to a power of two according to the proof shape.
    pub fn fixed_log2_rows<F: Field, A: MachineAir<F>>(&self, air: &A) -> Option<usize> {
        self.preprocessed_shape
            .as_ref()
            .map(|shape| {
                shape
                    .inner
                    .get(&air.name())
                    .unwrap_or_else(|| panic!("Chip {} not found in specified shape", air.name()))
            })
            .copied()
    }

    #[must_use]
    /// Fetch the instruction at the given program counter.
    pub fn fetch(&self, pc: u32) -> Instruction {
        let idx = ((pc - self.pc_base) / 4) as usize;
        self.instructions[idx]
    }
}

impl<F: Field> MachineProgram<F> for Program {
    fn pc_start(&self) -> F {
        F::from_canonical_u32(self.pc_start)
    }
}

/*
#[cfg(test)]
mod test {
    use crate::cpu::kernel::elf::*;
    use std::fs::File;
    use std::io::{BufReader, Read};
    use zkm_emulator::utils::get_block_path;

    #[test]
    fn load_and_check_mips_elf() {
        env_logger::try_init().unwrap_or_default();
        let mut reader = BufReader::new(File::open("../emulator/test-vectors/hello").unwrap());
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).unwrap();
        let max_mem = 0x80000000;
        let mut p: Program = Program::load_elf(&buffer, max_mem).unwrap();
        log::info!("entry: {}", p.entry);

        let real_blockpath = get_block_path("../emulator/test-vectors", "13284491", "input");
        log::info!("real block path: {}", real_blockpath);
        p.load_block(&real_blockpath).unwrap();

        p.image.iter().for_each(|(k, v)| {
            if *k > INIT_SP && *k < INIT_SP + 50 {
                log::debug!("{:X}: {:X}", k, v.to_be());
            }

            if *k > 0x30000000 && *k < 0x30000020 {
                log::debug!("{:X}: {:X}", k, v.to_be());
            }
        })
    }
}
 */

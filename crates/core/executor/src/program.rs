//! Programs that can be executed by the ZKM.

extern crate alloc;
// use crate::poseidon_sponge::poseidon_sponge_stark::poseidon;
use alloc::collections::BTreeMap;
use anyhow::{anyhow, bail, Context, Result};
use elf::{endian::BigEndian, file::Class, ElfBytes};
use std::io::Read;
use num::PrimInt;

use p3_field::Field;
use p3_maybe_rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use zkm2_stark::air::{MachineAir, MachineProgram};

use crate::{CoreShape, Instruction};

pub const PAGE_SIZE: u32 = 4096;
pub const MAX_MEMORY: usize = 0x10000000;
pub const INIT_SP: u32 = MAX_MEMORY as u32 - 0x4000;
pub const WORD_SIZE: usize = core::mem::size_of::<u32>();

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
    /// The shape for the preprocessed tables.
    // todo: check if necessary
    pub preprocessed_shape: Option<CoreShape>,

    /// The initial memory image, useful for global constants.
    pub memory_image: hashbrown::HashMap<u32, u32>,
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
    pub fn from(input: &[u8], max_mem: u32, args: Vec<&str>) -> Result<Program> {
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
                        // todo: check it BIG_ENDIAN
                        word |= (*byte as u32) << (24 - j * 8);
                    }
                    image.insert(addr, word);
                    // todo: check it
                    if (segment.p_flags & elf::abi::PF_X) != 0 {
                        instructions.push(word);
                    }
                }
            }
        }

        let mut gprs = [0; 32];
        gprs[29] = INIT_SP as usize;

        let lo = 0;
        let hi = 0;

        // initialize gprs
        gprs.iter().enumerate().for_each(|(i, &x)| {
            image.insert(i as u32, x as u32);
        });
        image.insert(32, lo as u32);
        image.insert(33, hi as u32);

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
            preprocessed_shape: None,
            memory_image: hashbrown::HashMap::new(),
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
        Ok(Program::from(&elf_code, max_mem, vec![]).unwrap())
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

//! Programs that can be executed by the zkMIPS.

extern crate alloc;

use alloc::collections::BTreeMap;
use anyhow::{anyhow, bail, Context, Result};
use elf::{endian::LittleEndian, file::Class, ElfBytes};
use std::str::FromStr;

use p3_field::Field;
use p3_field::FieldExtensionAlgebra;
use p3_field::PrimeField32;
use p3_maybe_rayon::prelude::IntoParallelIterator;
use p3_maybe_rayon::prelude::IntoParallelRefIterator;
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator};
use serde::{Deserialize, Serialize};
use zkm_stark::air::{MachineAir, MachineProgram};
use zkm_stark::septic_curve::{SepticCurve, SepticCurveComplete};
use zkm_stark::septic_digest::SepticDigest;
use zkm_stark::septic_extension::SepticExtension;
use zkm_stark::shape::Shape;
use zkm_stark::LookupKind;

use crate::{Instruction, MipsAirId};

pub const PAGE_SIZE: u32 = 4096;
pub const MAX_MEMORY: usize = 0x10000000;
pub const INIT_SP: u32 = MAX_MEMORY as u32 - 0x4000;
pub const WORD_SIZE: usize = core::mem::size_of::<u32>();

/// A program that can be executed by the ZKM.
#[derive(PartialEq, Debug, Clone, Default, Serialize, Deserialize)]
pub struct Program {
    pub instructions: Vec<Instruction>,
    /// The entrypoint of the program, PC
    pub pc_start: u32,
    pub pc_base: u32,
    pub next_pc: u32,
    /// The initial memory image
    pub image: BTreeMap<u32, u32>,
    /// The shape for the preprocessed tables.
    pub preprocessed_shape: Option<Shape<MipsAirId>>,
}

impl Program {
    #[must_use]
    pub fn new(instructions: Vec<Instruction>, pc_start: u32, pc_base: u32) -> Self {
        Self { instructions, pc_start, pc_base, next_pc: pc_start + 4, ..Default::default() }
    }

    /// Initialize a MIPS Program from an appropriate ELF file
    pub fn from(elf_code: &[u8]) -> Result<Program> {
        let max_mem = 0x80000000; // todo: confirm it

        let mut image: BTreeMap<u32, u32> = BTreeMap::new();
        let elf = ElfBytes::<LittleEndian>::minimal_parse(elf_code)
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
        if entry >= max_mem || !entry.is_multiple_of(WORD_SIZE as u32) {
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
            if !vaddr.is_multiple_of(WORD_SIZE as u32) {
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
                        let byte = elf_code.get(offset).context("Invalid segment offset")?;
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

        // decode each instruction
        let instructions: Vec<_> =
            instructions.par_iter().map(|inst| Instruction::decode_from(*inst).unwrap()).collect();

        Ok(Program {
            instructions,
            pc_start: entry,
            pc_base: base_address,
            next_pc: entry + 4,
            image,
            preprocessed_shape: None,
        })
    }

    /// Custom logic for padding the trace to a power of two according to the proof shape.
    pub fn fixed_log2_rows<F: Field, A: MachineAir<F>>(&self, air: &A) -> Option<usize> {
        let id = MipsAirId::from_str(&air.name()).unwrap();
        self.preprocessed_shape.as_ref().map(|shape| {
            shape
                .log2_height(&id)
                .unwrap_or_else(|| panic!("Chip {} not found in specified shape", air.name()))
        })
    }

    #[must_use]
    /// Fetch the instruction at the given program counter.
    pub fn fetch(&self, pc: u32) -> Instruction {
        let idx = ((pc - self.pc_base) / 4) as usize;
        self.instructions[idx]
    }
}

impl<F: PrimeField32> MachineProgram<F> for Program {
    fn pc_start(&self) -> F {
        F::from_canonical_u32(self.pc_start)
    }

    fn initial_global_cumulative_sum(&self) -> SepticDigest<F> {
        let mut digests: Vec<SepticCurveComplete<F>> = self
            .image
            .iter()
            .par_bridge()
            .map(|(&addr, &word)| {
                let values = [
                    (LookupKind::Memory as u32) << 16,
                    0,
                    addr,
                    word & 255,
                    (word >> 8) & 255,
                    (word >> 16) & 255,
                    (word >> 24) & 255,
                ];
                let x_start =
                    SepticExtension::<F>::from_base_fn(|i| F::from_canonical_u32(values[i]));
                let (point, _, _, _) = SepticCurve::<F>::lift_x(x_start);
                SepticCurveComplete::Affine(point.neg())
            })
            .collect();
        digests.push(SepticCurveComplete::Affine(SepticDigest::<F>::zero().0));
        SepticDigest(
            digests.into_par_iter().reduce(|| SepticCurveComplete::Infinity, |a, b| a + b).point(),
        )
    }
}

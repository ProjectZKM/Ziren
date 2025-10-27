//! Programs that can be executed by the Ziren.

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

use crate::{Instruction, MipsAirId, Register};

pub const MAX_MEMORY: usize = 0x7F000000;
pub const MAX_CODE_MEMORY: usize = 0x3F000000;
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
        let max_mem = MAX_CODE_MEMORY as u32;

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

        let mut patch_list: BTreeMap<u32, u32> = BTreeMap::new();
        patch_elf(&elf, &mut patch_list);
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
                    if patch_list.contains_key(&addr) {
                        word = patch_list[&addr];
                    } else {
                        let len = core::cmp::min(file_size - i, WORD_SIZE as u32);
                        for j in 0..len {
                            let offset = (offset + i + j) as usize;
                            let byte = elf_code.get(offset).context("Invalid segment offset")?;
                            word |= (*byte as u32) << (j * 8);
                        }
                    }
                    image.insert(addr, word);
                    // todo: check it
                    if (segment.p_flags & elf::abi::PF_X) != 0 {
                        instructions.push(word);
                    }
                }
                if addr > hiaddr {
                    hiaddr = addr;
                }
            }
        }

        image.insert(Register::BRK as u32, hiaddr); // $brk
        image.insert(Register::HEAP as u32, 0x20000000); // $heap

        patch_stack(&mut image);

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

pub fn patch_elf(f: &elf::ElfBytes<LittleEndian>, patch_list: &mut BTreeMap<u32, u32>) {
    let symbols = f
        .symbol_table()
        .expect("failed to read symbols table, cannot patch program")
        .expect("failed to parse symbols table, cannot patch program");

    let mut exit_new = 0;
    let mut exit_old = 0;
    for symbol in symbols.0 {
        match symbols.1.get(symbol.st_name as usize) {
            Ok(name) => match name {
                "runtime.gcenable"
                | "runtime.init.5"
                | "runtime.main.func1"
                | "runtime.deductSweepCredit"
                | "runtime.(*gcControllerState).commit"
                | "github.com/prometheus/client_golang/prometheus.init"
                | "github.com/prometheus/client_golang/prometheus.init.0"
                | "github.com/prometheus/procfs.init"
                | "github.com/prometheus/common/model.init"
                | "github.com/prometheus/client_model/go.init"
                | "github.com/prometheus/client_model/go.init.0"
                | "github.com/prometheus/client_model/go.init.1"
                | "flag.init"
                | "runtime.check"
                | "runtime.checkfds"
                | "_dl_discover_osversion"
                | "internal/runtime/exithook.Run" => {
                    patch_list.insert(
                        symbol.st_value as u32,
                        0x03e00008, // jalr $ra, $zero
                    );
                    patch_list.insert(
                        (symbol.st_value + 4) as u32,
                        0x0, // nop
                    );
                }

                "runtime.exit" => {
                    exit_old = symbol.st_value as u32;
                }
                "runtime.MemProfileRate" => {
                    patch_list.insert(
                        symbol.st_value as u32,
                        0x0, // nop
                    );
                }
                "zkvm.RuntimeExit" => {
                    exit_new = symbol.st_value as u32;
                }
                _ => {
                    if name.contains("sys_common") && name.contains("thread_info") {
                        patch_list.insert(
                            symbol.st_value as u32,
                            0x03e00008, // jalr $ra, $zero
                        );
                        patch_list.insert(
                            (symbol.st_value + 4) as u32,
                            0x0, // nop
                        );
                    }
                }
            },
            Err(e) => {
                log::warn!("parse symbol failed, {e}");
                continue;
            }
        }
    }

    if exit_new != 0 && exit_old != 0 {
        patch_list.insert(
            exit_old,
            0x08000000 | (exit_new >> 2), // j exit_new
        );
        patch_list.insert(
            exit_old + 4,
            0x0, // nop
        );
    }
}

pub fn patch_stack(image: &mut BTreeMap<u32, u32>) {
    let sp: u32 = INIT_SP;

    image.insert(Register::SP as u32, sp); // $sp

    let mut store_mem = |addr: u32, v: u32| {
        image.insert(addr, v);
    };

    let index = 0;
    // init argc,  argv, aux on stack
    store_mem(sp, index);
    let mut cur_sp = sp + 4 * (index + 1);
    store_mem(cur_sp, 0x00); // argv[n] = 0 (terminating argv)
    cur_sp += 4;
    store_mem(cur_sp, 0x00); // envp[term] = 0 (no env vars)
    cur_sp += 4;

    store_mem(cur_sp, 0x06); // auxv[0] = _AT_PAGESZ = 6 (key)
    store_mem(cur_sp + 4, 0x1000); // auxv[1] = page size of 4 KiB (value)
    cur_sp += 8;

    store_mem(cur_sp, 0x0b); // auxv[0] = AT_UID = 11 (key)
    store_mem(cur_sp + 4, 0x3e8); // auxv[1] = Real uid (value)
    cur_sp += 8;
    store_mem(cur_sp, 0x0c); // auxv[0] = AT_EUID = 12 (key)
    store_mem(cur_sp + 4, 0x3e8); // auxv[1] = Effective uid (value)
    cur_sp += 8;
    store_mem(cur_sp, 0x0d); // auxv[0] = AT_GID = 13 (key)
    store_mem(cur_sp + 4, 0x3e8); // auxv[1] = Real gid (value)
    cur_sp += 8;
    store_mem(cur_sp, 0x0e); // auxv[0] = AT_EGID = 14 (key)
    store_mem(cur_sp + 4, 0x3e8); // auxv[1] = Effective gid (value)
    cur_sp += 8;
    store_mem(cur_sp, 0x10); // auxv[0] = AT_HWCAP = 16 (key)
    store_mem(cur_sp + 4, 0x00); // auxv[1] =  arch dependent hints at CPU capabilities (value)
    cur_sp += 8;
    store_mem(cur_sp, 0x11); // auxv[0] = AT_CLKTCK = 17 (key)
    store_mem(cur_sp + 4, 0x64); // auxv[1] = Frequency of times() (value)
    cur_sp += 8;
    store_mem(cur_sp, 0x17); // auxv[0] = AT_SECURE = 23 (key)
    store_mem(cur_sp + 4, 0x00); // auxv[1] = secure mode boolean (value)
    cur_sp += 8;

    store_mem(cur_sp, 0x19); // auxv[4] = AT_RANDOM = 25 (key)
    store_mem(cur_sp + 4, cur_sp + 12); // auxv[5] = address of 16 bytes containing random value
    cur_sp += 8;
    store_mem(cur_sp, 0); // auxv[term] = 0
    cur_sp += 4;
    store_mem(cur_sp, 0x5f28df1d); // auxv[term] = 0
    store_mem(cur_sp + 4, 0x2cd1002a); // auxv[term] = 0
    store_mem(cur_sp + 8, 0x5ff9f682); // auxv[term] = 0
    store_mem(cur_sp + 12, 0xd4d8d538); // auxv[term] = 0
    cur_sp += 16;
    store_mem(cur_sp, 0x00); // auxv[term] = 0
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
                let (point, _) = SepticCurve::<F>::lift_x(x_start);
                SepticCurveComplete::Affine(point.neg())
            })
            .collect();
        digests.push(SepticCurveComplete::Affine(SepticDigest::<F>::zero().0));
        SepticDigest(
            digests.into_par_iter().reduce(|| SepticCurveComplete::Infinity, |a, b| a + b).point(),
        )
    }
}

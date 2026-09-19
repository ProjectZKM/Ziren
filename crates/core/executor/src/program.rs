//! Programs that can be executed by the Ziren.

extern crate alloc;

use alloc::collections::BTreeMap;
use anyhow::{anyhow, bail, Context, Result};
use elf::{endian::LittleEndian, file::Class, ElfBytes};
use std::str::FromStr;

use p3_field::BasedVectorSpace;
use p3_field::Field;
use p3_field::PrimeField32;
use p3_maybe_rayon::prelude::IndexedParallelIterator;
use p3_maybe_rayon::prelude::IntoParallelIterator;
use p3_maybe_rayon::prelude::IntoParallelRefIterator;
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator};
use serde::{Deserialize, Serialize};
use zkm_pcs::air::{MachineAir, MachineProgram};
use zkm_pcs::septic_curve::{SepticCurve, SepticCurveComplete};
use zkm_pcs::septic_digest::SepticDigest;
use zkm_pcs::septic_extension::SepticExtension;
use zkm_pcs::shape::Shape;
use zkm_pcs::LookupKind;

use crate::{Instruction, MipsAirId, Register};

pub const MAX_MEMORY: usize = 0x7F000000;
pub const MAX_CODE_MEMORY: usize = 0x3F000000;
pub const INIT_SP: u32 = MAX_MEMORY as u32 - 0x4000;
pub const WORD_SIZE: usize = core::mem::size_of::<u32>();
/// Upper bound on the instruction image, in words. See `Program::from`.
pub const MAX_INSTRUCTIONS: usize = 1 << 26;

/// A `PT_LOAD` header after narrowing to 32 bits and bounds-checking: what
/// `Program::from` needs in order to lay segments out by virtual address.
struct LoadSegment {
    vaddr: u32,
    offset: u32,
    file_size: u32,
    mem_size: u32,
    executable: bool,
}

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
        patch_elf(&elf, &mut patch_list)?;
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

        // Narrow and bounds-check every PT_LOAD header BEFORE materializing any of
        // them, so a rejection cannot leave a half-built image behind.
        let mut loads: Vec<LoadSegment> = Vec::new();
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
            // A file image larger than the memory image would read bytes the
            // segment never maps.
            if file_size > mem_size {
                bail!("Invalid segment: p_filesz 0x{file_size:x} exceeds p_memsz 0x{mem_size:x}");
            }
            let vaddr: u32 = segment
                .p_vaddr
                .try_into()
                .map_err(|err| anyhow!("vaddr is larger than 32 bits. {err}"))?;
            if !vaddr.is_multiple_of(WORD_SIZE as u32) {
                bail!("vaddr {vaddr:08x} is unaligned");
            }
            let offset: u32 = segment
                .p_offset
                .try_into()
                .map_err(|err| anyhow!("offset is larger than 32 bits. {err}"))?;
            let executable = (segment.p_flags & elf::abi::PF_X) != 0;
            // The instruction image is indexed by word, so a trailing partial word
            // of executable memory has no slot to live in.
            if executable && !mem_size.is_multiple_of(WORD_SIZE as u32) {
                bail!("executable segment at 0x{vaddr:08x} has unaligned p_memsz 0x{mem_size:x}");
            }
            let end = vaddr
                .checked_add(mem_size)
                .with_context(|| format!("segment at 0x{vaddr:08x} wraps the address space"))?;
            if end > max_mem {
                bail!(
                    "Address [0x{end:08x}] exceeds maximum address for guest programs [0x{max_mem:08x}]"
                );
            }
            loads.push(LoadSegment { vaddr, offset, file_size, mem_size, executable });
        }

        // Place by virtual address, not by header order. `fetch` and the
        // preprocessed Program AIR both index the instruction image as
        // `(pc - pc_base) / 4`, so header order is not the layout; appending in
        // header order decoded a reordered ELF at the wrong PCs. Overlaps are
        // rejected rather than resolved, because "the last header wins" is not
        // defined ELF semantics yet silently decided which of two words a pc runs.
        loads.sort_by_key(|s| s.vaddr);
        for pair in loads.windows(2) {
            let (prev, next) = (&pair[0], &pair[1]);
            let prev_end = prev.vaddr + prev.mem_size; // no overflow: checked above
            if next.vaddr < prev_end {
                bail!(
                    "PT_LOAD segments overlap: 0x{:08x}..0x{prev_end:08x} and 0x{:08x}",
                    prev.vaddr,
                    next.vaddr
                );
            }
        }

        // Exactly one contiguous executable interval. A sparse image would need
        // every hole filled with a word that faults when executed, and
        // `pc_base + idx * 4` in the preprocessed Program trace would stop
        // describing the mapping. Every guest we build links a single executable
        // PT_LOAD, so requiring this costs nothing and turns "decodes the wrong
        // words" into a load error.
        let exec: Vec<&LoadSegment> = loads.iter().filter(|s| s.executable).collect();
        let (Some(first_exec), Some(last_exec)) = (exec.first(), exec.last()) else {
            bail!("No executable PT_LOAD segment: there is nothing to run");
        };
        for pair in exec.windows(2) {
            let (prev, next) = (pair[0], pair[1]);
            let prev_end = prev.vaddr + prev.mem_size;
            if next.vaddr != prev_end {
                bail!(
                    "executable segments are not contiguous: a 0x{:x}-byte gap between \
                     0x{prev_end:08x} and 0x{:08x}",
                    next.vaddr - prev_end,
                    next.vaddr
                );
            }
        }
        let base_address = first_exec.vaddr;
        let exec_end = last_exec.vaddr + last_exec.mem_size;
        let n_words = ((exec_end - base_address) / WORD_SIZE as u32) as usize;
        // Not a soundness bound -- a program this size cannot be proven -- but the
        // zero tail of an executable segment is declared by `p_memsz`, so without
        // a cap a 100-byte ELF could ask for a gigabyte-sized instruction image.
        if n_words > MAX_INSTRUCTIONS {
            bail!("executable image is {n_words} words, over the {MAX_INSTRUCTIONS}-word limit");
        }
        // `pc_start` is the first index read out of that image.
        if entry < base_address || entry >= exec_end {
            bail!(
                "entrypoint 0x{entry:08x} is outside the executable range \
                 0x{base_address:08x}..0x{exec_end:08x}"
            );
        }

        let mut words: Vec<u32> = vec![0; n_words];
        let mut hiaddr = 0u32;

        for &LoadSegment { vaddr, offset, file_size, mem_size, executable } in &loads {
            for i in (0..mem_size).step_by(WORD_SIZE) {
                let addr = vaddr + i; // no overflow: `vaddr + mem_size` was checked
                let word = if i >= file_size {
                    // Past the file size, all zeros.
                    0
                } else if let Some(patched) = patch_list.get(&addr) {
                    *patched
                } else {
                    let mut word = 0;
                    // Don't read past the end of the file.
                    let len = core::cmp::min(file_size - i, WORD_SIZE as u32);
                    for j in 0..len {
                        let offset = (offset + i + j) as usize;
                        let byte = elf_code.get(offset).context("Invalid segment offset")?;
                        word |= (*byte as u32) << (j * 8);
                    }
                    word
                };
                image.insert(addr, word);
                if executable {
                    // The zero tail of a `p_memsz > p_filesz` executable segment gets
                    // a slot too: it is mapped, `image` holds it, and a pc can reach
                    // it. Pushing only the file-backed words left the vector short
                    // and shifted every later segment's instructions off their PCs.
                    words[((addr - base_address) / WORD_SIZE as u32) as usize] = word;
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
        let instructions: Vec<_> = words
            .par_iter()
            .enumerate()
            .map(|(idx, word)| {
                Instruction::decode_from(*word).map_err(|err| {
                    let pc = base_address + (idx as u32) * WORD_SIZE as u32;
                    anyhow!("could not decode 0x{word:08x} at pc 0x{pc:08x}: {err}")
                })
            })
            .collect::<Result<Vec<_>>>()?;

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
    #[inline]
    /// Fetch the instruction at the given program counter.
    /// `pc` must lie in the program's executable range. That holds for the
    /// entrypoint by construction -- `Program::from` rejects an entry outside it --
    /// and for every later pc because each executed pc is looked up in the
    /// preprocessed Program table, which contains exactly
    /// `pc_base .. pc_base + 4 * instructions.len()`.
    pub fn fetch(&self, pc: u32) -> Instruction {
        // `wrapping_sub` then `get`: one bounds check, the same as indexing, but a
        // pc below `pc_base` now names itself instead of underflowing first.
        let idx = (pc.wrapping_sub(self.pc_base) / 4) as usize;
        match self.instructions.get(idx) {
            Some(instruction) => *instruction,
            None => panic!(
                "pc 0x{pc:08x} is outside the program 0x{:08x}..0x{:08x}",
                self.pc_base,
                self.pc_base.saturating_add(4 * self.instructions.len() as u32)
            ),
        }
    }
}

/// Collect the optional runtime patches a Go guest needs, keyed by address.
///
/// The patches are an OPTIMISATION -- they stub out runtime entry points the
/// zkVM does not need -- so a program without a symbol table simply has none.
/// This used to `expect` twice: a valid STRIPPED ELF has no symbol table, and
/// `Program::from` is a fallible API that panicked on it instead of loading.
/// A genuine parse failure is still an error, and now propagates as one.
pub fn patch_elf(
    f: &elf::ElfBytes<LittleEndian>,
    patch_list: &mut BTreeMap<u32, u32>,
) -> Result<()> {
    let symbols = match f.symbol_table().map_err(|e| {
        anyhow::anyhow!("failed to parse the ELF symbol table, cannot patch program: {e}")
    })? {
        Some(symbols) => symbols,
        // Stripped: nothing to patch, which is not an error.
        None => return Ok(()),
    };

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
    Ok(())
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
        F::from_u32(self.pc_start)
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
                    SepticExtension::<F>::from_basis_coefficients_fn(|i| F::from_u32(values[i]));
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

#[cfg(test)]
mod tests {
    use super::{Instruction, Program};

    /// A minimal 32-bit little-endian MIPS `ET_EXEC` with one executable
    /// `PT_LOAD` and NO symbol table.
    ///
    /// Hand-assembled rather than taken from the test artifacts, because the
    /// point is the absence of a section/symbol table: a stripped binary is a
    /// valid ELF, and `Program::from` used to panic on it inside `patch_elf`
    /// (`symbol_table().expect(..).expect(..)`) despite being a fallible API.
    fn stripped_mips_elf() -> Vec<u8> {
        mips_elf(
            0x0040_0000,
            &[Seg {
                vaddr: 0x0040_0000,
                words: vec![0x2021_0001, 0x2021_0002, 0x2021_0003, 0x0000_0000],
                mem_words: 4,
                flags: PF_RX,
            }],
        )
    }

    const PF_RX: u32 = 5;
    const PF_RW: u32 = 6;

    /// One `PT_LOAD` to emit. `mem_words` may exceed `words.len()`, which is a
    /// `p_memsz > p_filesz` segment: the tail is mapped but not file-backed.
    struct Seg {
        vaddr: u32,
        words: Vec<u32>,
        mem_words: usize,
        flags: u32,
    }

    /// Assemble a stripped 32-bit little-endian MIPS `ET_EXEC` with the given
    /// segments, emitted as program headers in exactly the order supplied -- which
    /// is the point of several tests below, since header order is not layout.
    fn mips_elf(entry: u32, segs: &[Seg]) -> Vec<u8> {
        const EHDR: usize = 52;
        const PHDR: usize = 32;
        let phnum = segs.len();
        let mut body_off = EHDR + PHDR * phnum;

        let mut e = Vec::new();
        e.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
        e.push(1); // ELFCLASS32
        e.push(1); // ELFDATA2LSB
        e.push(1); // EV_CURRENT
        e.extend_from_slice(&[0u8; 9]); // padding
        e.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        e.extend_from_slice(&8u16.to_le_bytes()); // EM_MIPS
        e.extend_from_slice(&1u32.to_le_bytes()); // e_version
        e.extend_from_slice(&entry.to_le_bytes()); // e_entry
        e.extend_from_slice(&(EHDR as u32).to_le_bytes()); // e_phoff
        e.extend_from_slice(&0u32.to_le_bytes()); // e_shoff: none -> stripped
        e.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        e.extend_from_slice(&(EHDR as u16).to_le_bytes()); // e_ehsize
        e.extend_from_slice(&(PHDR as u16).to_le_bytes()); // e_phentsize
        e.extend_from_slice(&(phnum as u16).to_le_bytes()); // e_phnum
        e.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
        e.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
        e.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
        assert_eq!(e.len(), EHDR);

        let mut body = Vec::new();
        for seg in segs {
            let file_sz = (seg.words.len() * 4) as u32;
            let mem_sz = (seg.mem_words * 4) as u32;
            e.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
            e.extend_from_slice(&(body_off as u32).to_le_bytes()); // p_offset
            e.extend_from_slice(&seg.vaddr.to_le_bytes()); // p_vaddr
            e.extend_from_slice(&seg.vaddr.to_le_bytes()); // p_paddr
            e.extend_from_slice(&file_sz.to_le_bytes()); // p_filesz
            e.extend_from_slice(&mem_sz.to_le_bytes()); // p_memsz
            e.extend_from_slice(&seg.flags.to_le_bytes());
            e.extend_from_slice(&4u32.to_le_bytes()); // p_align
            for w in &seg.words {
                body.extend_from_slice(&w.to_le_bytes());
            }
            body_off += seg.words.len() * 4;
        }
        assert_eq!(e.len(), EHDR + PHDR * phnum);
        e.extend_from_slice(&body);
        e
    }

    /// `addiu $1, $1, imm` -- distinguishable per word, so a test can say which
    /// word landed at which pc.
    fn addiu(imm: u16) -> u32 {
        0x2421_0000 | imm as u32
    }

    #[test]
    fn a_stripped_elf_loads_without_patches() {
        let program = Program::from(&stripped_mips_elf())
            .expect("a stripped ELF is valid and must load, not panic");
        assert_eq!(program.pc_start, 0x0040_0000);
        assert!(!program.instructions.is_empty(), "the executable segment was decoded");
    }

    #[test]
    fn a_truncated_elf_is_an_error() {
        let full = stripped_mips_elf();
        // Every prefix: none may panic, and none may load.
        for n in 0..full.len() {
            assert!(
                Program::from(&full[..n]).is_err(),
                "a {n}-byte prefix of an ELF must be rejected, not accepted"
            );
        }
    }

    #[test]
    fn executable_segments_are_placed_by_virtual_address_not_header_order() {
        // Two adjacent executable segments, emitted HIGHEST FIRST. Appending in
        // header order put the 0x400010 words at pc 0x400000 and vice versa; every
        // pc in the program decoded the other segment's instruction.
        let elf = mips_elf(
            0x0040_0000,
            &[
                Seg {
                    vaddr: 0x0040_0010,
                    words: vec![addiu(0x10), addiu(0x11), addiu(0x12), addiu(0x13)],
                    mem_words: 4,
                    flags: PF_RX,
                },
                Seg {
                    vaddr: 0x0040_0000,
                    words: vec![addiu(0), addiu(1), addiu(2), addiu(3)],
                    mem_words: 4,
                    flags: PF_RX,
                },
            ],
        );
        let p = Program::from(&elf).expect("two adjacent executable segments are one image");
        assert_eq!(p.pc_base, 0x0040_0000, "pc_base is the LOWEST executable vaddr");
        assert_eq!(p.instructions.len(), 8);
        // The instruction at each pc must be the word the ELF maps there, which is
        // exactly what `image` says independently of the layout decision.
        for i in 0..8u32 {
            let pc = 0x0040_0000 + i * 4;
            let expected = Instruction::decode_from(p.image[&pc]).unwrap();
            assert_eq!(p.fetch(pc), expected, "pc 0x{pc:08x} decoded the wrong word");
        }
        // And concretely: the second header's words come first.
        assert_eq!(p.fetch(0x0040_0000).op_c, 0);
        assert_eq!(p.fetch(0x0040_0010).op_c, 0x10);
    }

    #[test]
    fn a_gap_between_executable_segments_is_an_error() {
        // 0x400000..0x400010 and 0x400020..: `(pc - pc_base) / 4` cannot describe a
        // hole, so this must be refused rather than silently compacted.
        let elf = mips_elf(
            0x0040_0000,
            &[
                Seg {
                    vaddr: 0x0040_0000,
                    words: vec![addiu(0), addiu(1), addiu(2), addiu(3)],
                    mem_words: 4,
                    flags: PF_RX,
                },
                Seg {
                    vaddr: 0x0040_0020,
                    words: vec![addiu(0x20)],
                    mem_words: 1,
                    flags: PF_RX,
                },
            ],
        );
        let err = Program::from(&elf).expect_err("a gapped executable image must be rejected");
        assert!(
            format!("{err}").contains("not contiguous"),
            "the error should name the gap, got: {err}"
        );
    }

    #[test]
    fn overlapping_load_segments_are_an_error() {
        let elf = mips_elf(
            0x0040_0000,
            &[
                Seg {
                    vaddr: 0x0040_0000,
                    words: vec![addiu(0), addiu(1), addiu(2), addiu(3)],
                    mem_words: 4,
                    flags: PF_RX,
                },
                // Starts inside the first segment: whichever header is applied last
                // used to win, deciding which word a pc runs.
                Seg { vaddr: 0x0040_0008, words: vec![0xdead_beef], mem_words: 1, flags: PF_RW },
            ],
        );
        let err = Program::from(&elf).expect_err("overlapping PT_LOAD must be rejected");
        assert!(format!("{err}").contains("overlap"), "got: {err}");
    }

    #[test]
    fn an_entrypoint_outside_the_executable_range_is_an_error() {
        // Below `pc_base` and one word past the end. The first used to reach
        // `fetch`'s unchecked `pc - pc_base` subtraction.
        for entry in [0x003f_fffc, 0x0040_0010] {
            let elf = mips_elf(
                entry,
                &[Seg {
                    vaddr: 0x0040_0000,
                    words: vec![addiu(0), addiu(1), addiu(2), addiu(3)],
                    mem_words: 4,
                    flags: PF_RX,
                }],
            );
            let err = Program::from(&elf)
                .err()
                .unwrap_or_else(|| panic!("entry 0x{entry:08x} must be rejected"));
            assert!(format!("{err}").contains("entrypoint"), "got: {err}");
        }
        // The boundary values themselves are fine.
        for entry in [0x0040_0000, 0x0040_000c] {
            let elf = mips_elf(
                entry,
                &[Seg {
                    vaddr: 0x0040_0000,
                    words: vec![addiu(0), addiu(1), addiu(2), addiu(3)],
                    mem_words: 4,
                    flags: PF_RX,
                }],
            );
            assert_eq!(
                Program::from(&elf).expect("an in-range entry must load").pc_start,
                entry
            );
        }
    }

    #[test]
    fn an_executable_zero_tail_still_gets_its_own_pcs() {
        // `p_memsz > p_filesz` on an executable segment: the tail is mapped zeros.
        // Pushing only file-backed words left `instructions` two short, so the next
        // segment's words answered for the tail's PCs.
        let elf = mips_elf(
            0x0040_0000,
            &[
                Seg {
                    vaddr: 0x0040_0000,
                    words: vec![addiu(0), addiu(1)],
                    mem_words: 4,
                    flags: PF_RX,
                },
                Seg {
                    vaddr: 0x0040_0010,
                    words: vec![addiu(0x10), addiu(0x11)],
                    mem_words: 2,
                    flags: PF_RX,
                },
            ],
        );
        let p = Program::from(&elf).expect("a mapped zero tail is valid");
        assert_eq!(p.instructions.len(), 6);
        assert_eq!(p.fetch(0x0040_0000).op_c, 0);
        assert_eq!(p.fetch(0x0040_0004).op_c, 1);
        // The tail: word 0 decodes as `sll $0, $0, 0`, and `image` agrees.
        assert_eq!(p.image[&0x0040_0008], 0);
        assert_eq!(p.fetch(0x0040_0008), Instruction::decode_from(0).unwrap());
        // And the next segment is still on its own PCs, not shifted down.
        assert_eq!(p.fetch(0x0040_0010).op_c, 0x10);
        assert_eq!(p.fetch(0x0040_0014).op_c, 0x11);
    }

    #[test]
    fn an_elf_with_no_executable_segment_is_an_error() {
        let elf = mips_elf(
            0x0040_0000,
            &[Seg { vaddr: 0x0040_0000, words: vec![0, 0], mem_words: 2, flags: PF_RW }],
        );
        let err = Program::from(&elf).expect_err("nothing to run");
        assert!(format!("{err}").contains("executable"), "got: {err}");
    }

    #[test]
    fn a_filesz_larger_than_memsz_is_an_error() {
        let mut elf = mips_elf(
            0x0040_0000,
            &[Seg {
                vaddr: 0x0040_0000,
                words: vec![addiu(0), addiu(1)],
                mem_words: 2,
                flags: PF_RX,
            }],
        );
        // p_memsz sits 4 bytes after p_filesz in the 32-bit program header.
        let memsz_at = 52 + 20;
        elf[memsz_at..memsz_at + 4].copy_from_slice(&4u32.to_le_bytes());
        let err = Program::from(&elf).expect_err("p_filesz > p_memsz maps fewer bytes than it reads");
        assert!(format!("{err}").contains("exceeds p_memsz"), "got: {err}");
    }

    #[test]
    fn the_test_artifact_loads_as_one_contiguous_executable_image() {
        // The guard behind the contiguity requirement: if a toolchain change ever
        // emits a second, non-adjacent executable segment, the load fails here
        // rather than decoding at the wrong PCs inside a proof. Asserted
        // structurally, not against pinned values, so regenerating the guest is
        // not a spurious failure.
        let p = Program::from(include_bytes!("../../../prover/elf/mipsel-zkm-zkvm-elf"))
            .expect("the test artifact must load");
        assert!(!p.instructions.is_empty());
        let end = p.pc_base + 4 * p.instructions.len() as u32;
        assert!(p.pc_start >= p.pc_base && p.pc_start < end, "the entrypoint is in range");
        // Every pc the instruction image claims is actually mapped: that is what
        // "one contiguous interval indexed from pc_base" means.
        for i in 0..p.instructions.len() as u32 {
            let pc = p.pc_base + i * 4;
            let word = *p.image.get(&pc).unwrap_or_else(|| panic!("pc 0x{pc:08x} is not mapped"));
            assert_eq!(p.fetch(pc), Instruction::decode_from(word).unwrap());
        }
    }
}

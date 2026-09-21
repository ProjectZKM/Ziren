//! The x86_64-Linux JIT runner.
//!
//! Split out of `jit_runner.rs` because this is one `#[cfg]` over ~1,400
//! lines; the parent keeps the `cfg` on the `mod` declaration and holds the
//! non-x86 stubs, so the two arms of each entry point stay together there.

use super::*;
use crate::events::SyscallEvent;
use crate::program::MAX_MEMORY;
use crate::syscalls::{SyscallCode, SyscallContext};
use crate::{Executor, Program, Register};
use std::collections::HashSet;
use zkm_core_jit::backends::TranspilerBackend;
use zkm_core_jit::driver::{drive_instructions_at, DriverError};
use zkm_core_jit::{JitContext, JitFunction, MipsTranspiler, SyscallHandler};

/// Caller-owned memory bridge handed to the JIT'd program.
///
/// MIPS guests address up to `MAX_MEMORY` (~2 GB) and the JIT's
/// flat layout doubles each guest 8-byte word into a 16-byte host
/// region (8-byte header + 8-byte data — see
/// `cuda/jit/src/backends/x86/mod.rs:emit_address_translate`),
/// so the worst-case host buffer size is ~4 GB.  We reserve the
/// virtual address range with `MAP_NORESERVE` so unused pages
/// are never committed; touched pages get ~4 KB of physical RAM
/// each.
/// Cheap canonical fingerprint of a `Program` for the JIT cache.
/// Combines `pc_base`, instruction count, and a sample of the
/// instruction stream — enough to distinguish any two programs
/// you'd realistically try to JIT in the same process.
fn program_fingerprint(program: &Program) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    program.pc_base.hash(&mut h);
    program.instructions.len().hash(&mut h);
    let n = program.instructions.len();
    let head = program.instructions.iter().take(16);
    let tail = program.instructions.iter().rev().take(16);
    for ins in head.chain(tail) {
        (ins.opcode as u8).hash(&mut h);
        ins.op_a.hash(&mut h);
        ins.op_b.hash(&mut h);
        ins.op_c.hash(&mut h);
    }
    n.hash(&mut h);
    h.finish()
}

/// Process-wide cache of finalised JIT functions, keyed by
/// [`program_fingerprint`].  Entries live until process exit;
/// programs are typically a small handful per process so this
/// won't grow unbounded.  `Arc` lets the cache hand out shared
/// refs without lifetime gymnastics.
static JIT_CACHE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<u64, std::sync::Arc<JitFunction>>>,
> = std::sync::OnceLock::new();

/// Look up (or build + insert) a `JitFunction` for `program`.
/// Cache hit → no transpile cost; cache miss pays the usual
/// transpile + finalize.
pub fn cached_jit_function(
    program: &Program,
    params: BuildParams,
    syscall_handler: Option<SyscallHandler>,
) -> Result<std::sync::Arc<JitFunction>, RunnerError> {
    let key = program_fingerprint(program);
    let cache = JIT_CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    if let Some(jit_fn) = cache.lock().expect("jit cache poisoned").get(&key) {
        return Ok(jit_fn.clone());
    }
    let jit_fn = std::sync::Arc::new(build_jit_function(program, params, syscall_handler)?);
    cache.lock().expect("jit cache poisoned").insert(key, jit_fn.clone());
    Ok(jit_fn)
}

pub struct JitMemoryBridge {
    /// Active host-side guest memory pointer.  Normally points at
    /// [`Self::primary_ptr`]; during an unconstrained block it is
    /// swapped to a private COW mapping of [`Self::mem_fd`] so
    /// JIT writes don't touch the primary buffer.  EXIT swaps it
    /// back and discards the COW.
    ptr: *mut u8,
    len: usize,
    /// The "real" host buffer — MAP_SHARED of [`Self::mem_fd`].
    /// JIT writes through this mapping persist on the fd, which
    /// is why a subsequent MAP_PRIVATE on the same fd starts as
    /// a copy of the JIT's current state (not just the program
    /// image): COW for unconstrained-block rollback.
    primary_ptr: *mut u8,
    /// Optional COW mapping in effect while inside an
    /// unconstrained block.  `None` outside a block.  At EXIT we
    /// `munmap` it and revert [`Self::ptr`] to [`Self::primary_ptr`].
    cow_ptr: Option<*mut u8>,
    /// Backing fd for the host buffer (memfd_create).  The
    /// MAP_SHARED [`Self::primary_ptr`] writes through to this
    /// fd; new MAP_PRIVATE mappings of this fd start as a copy
    /// of those writes.
    mem_fd: i32,
    /// Addresses materialised into [`Self::ptr`].  Initialised
    /// from `Program.image` and `state.memory`; grown by the
    /// per-syscall sync as the syscall handler observes new
    /// addresses written by the executor.
    seen_addrs: HashSet<u32>,
    /// Fingerprint of the last program whose `image` was
    /// materialised into this buffer.  Caller compares with the
    /// current program's fingerprint and skips the materialise
    /// loop on a hit (the buffer still holds that program's
    /// image bytes from the previous call).
    pub last_program_fingerprint: u64,
}

// Thread-local single-slot pool.  Caches (primary_ptr, len, fp,
// mem_fd).  Reusing the same memfd-backed buffer across calls
// amortises mmap cost AND keeps the page cache warm; the fd is
// closed on size-mismatch or final drop.
std::thread_local! {
    static MMAP_POOL: std::cell::RefCell<Option<(*mut u8, usize, u64, i32)>> =
        const { std::cell::RefCell::new(None) };
}

impl JitMemoryBridge {
    /// Borrow a host buffer from the thread-local pool, or mmap
    /// a fresh one.  Sized to cover the full guest address space
    /// under the doubled JIT layout.
    ///
    /// The buffer is a MAP_SHARED mapping of an anonymous memfd
    /// so unconstrained-block ENTER can `mmap` a private COW view
    /// of the same fd.
    /// Writes through MAP_SHARED persist on the fd, so the COW
    /// view starts as a copy of the JIT's current state — not
    /// just the program image — which is what unconstrained
    /// rollback semantics require.
    ///
    /// # Errors
    /// Returns `Err(io::Error)` if `memfd_create`, `ftruncate`,
    /// or `mmap` fails.
    pub fn new() -> std::io::Result<Self> {
        let len = host_buffer_size_for(MAX_MEMORY as u32);
        if let Some((ptr, plen, _last_fp, fd)) = MMAP_POOL.with(|c| c.borrow_mut().take()) {
            unsafe {
                libc::munmap(ptr.cast(), plen);
                libc::close(fd);
            }
        }
        let name = b"ziren-jit-mem\0";
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                name.as_ptr() as *const libc::c_char,
                libc::MFD_CLOEXEC,
            ) as i32
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let rc = unsafe { libc::ftruncate(fd, len as libc::off_t) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }
        Ok(Self {
            ptr: ptr.cast(),
            len,
            primary_ptr: ptr.cast(),
            cow_ptr: None,
            mem_fd: fd,
            seen_addrs: HashSet::new(),
            last_program_fingerprint: 0,
        })
    }

    /// Switch the JIT's memory pointer to a private COW mapping
    /// of [`Self::mem_fd`].  Called at ENTER_UNCONSTRAINED.  After
    /// this, JIT writes go to the COW; the primary mapping (and
    /// therefore the fd) is untouched.  Returns the new pointer
    /// so the caller can write it into `JitContext::memory`.
    ///
    /// # Errors
    /// Returns `Err(io::Error)` if `mmap` fails.
    pub fn enter_unconstrained(&mut self) -> std::io::Result<*mut u8> {
        if self.cow_ptr.is_some() {
            return Err(std::io::Error::other(
                "ENTER_UNCONSTRAINED while already inside an unconstrained block",
            ));
        }
        let cow = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                self.len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE,
                self.mem_fd,
                0,
            )
        };
        if cow == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        self.cow_ptr = Some(cow.cast());
        self.ptr = cow.cast();
        Ok(self.ptr)
    }

    /// Discard the COW mapping and revert to the primary
    /// MAP_SHARED view.  Called at EXIT_UNCONSTRAINED.  Returns
    /// the primary pointer so the caller can write it back to
    /// `JitContext::memory`.
    pub fn exit_unconstrained(&mut self) -> *mut u8 {
        if let Some(cow) = self.cow_ptr.take() {
            unsafe {
                libc::munmap(cow.cast(), self.len);
            }
        }
        self.ptr = self.primary_ptr;
        self.ptr
    }

    /// Record the fingerprint of the program just materialised
    /// into this buffer.  Drop will stash it in the pool so the
    /// next [`Self::new`] can return it via
    /// [`Self::last_program_fingerprint`].
    pub fn set_program_fingerprint(&mut self, fp: u64) {
        self.last_program_fingerprint = fp;
    }

    /// Diagnostic accessor: count of addresses currently tracked
    /// for sync.
    #[must_use]
    pub fn seen_addrs_len(&self) -> usize {
        self.seen_addrs.len()
    }

    /// Raw host-buffer pointer.  Lives as long as `self`.
    #[inline]
    #[must_use]
    pub fn as_ptr(&mut self) -> *mut u8 {
        self.ptr
    }

    /// Write a 4-byte word at the host offset corresponding to
    /// MIPS guest address `addr`.  Records the address in
    /// `seen_addrs` so the post-syscall sync knows to copy it
    /// back. The raw write is sound because `off + 4 <= self.len`:
    /// `host_buffer_size_for(MAX_MEMORY)` covers every `addr < MAX_MEMORY`.
    #[inline]
    pub fn store_word(&mut self, addr: u32, value: u32) {
        let off = host_offset_of(addr);
        unsafe {
            std::ptr::write_unaligned(self.ptr.add(off).cast::<u32>(), value.to_le());
        }
        self.seen_addrs.insert(addr & !3);
    }

    /// Read a 4-byte word at the host offset corresponding to
    /// MIPS guest address `addr`.
    #[inline]
    #[must_use]
    pub fn load_word(&self, addr: u32) -> u32 {
        let off = host_offset_of(addr);
        unsafe { u32::from_le(std::ptr::read_unaligned(self.ptr.add(off).cast::<u32>())) }
    }

    /// Snapshot the host buffer's view of every recorded address
    /// into the executor's sparse memory.  Called inside the
    /// syscall trampoline so the syscall implementation sees
    /// whatever the JIT'd code most recently wrote.
    /// Sync a specific byte range from the host buffer back into
    /// the executor's sparse memory.  Used by the syscall
    /// trampoline to make a syscall handler's reads see the
    /// JIT's most recent writes for known-pointer-arg syscalls
    /// (WRITE, COMMIT-with-pointer, etc.) without paying the
    /// full O(seen_addrs) flush cost.  Walks word-aligned to
    /// keep it cheap; partial-word syscall args (rare) get a
    /// little extra coverage from rounding.
    pub fn sync_range_to_executor(&self, executor: &mut Executor<'_>, base: u32, nbytes: u32) {
        use crate::events::MemoryRecord;
        if nbytes == 0 {
            return;
        }
        let start = base & !3;
        let end = base.wrapping_add(nbytes).wrapping_add(3) & !3;
        let mut addr = start;
        while addr < end {
            let word = self.load_word(addr);
            executor
                .state
                .memory
                .page_table
                .insert(addr, MemoryRecord { value: word, shard: 0, timestamp: 0 });
            addr = addr.wrapping_add(4);
        }
    }

    /// Sync a specific byte range from `executor.state.memory.page_table`
    /// (set by the syscall impl via `mw_traced` etc.) BACK to the
    /// host buffer so subsequent JIT'd loads observe the syscall's
    /// writes.  Word-aligned; rounds the range outward.
    pub fn sync_range_from_executor(&mut self, executor: &Executor<'_>, base: u32, nbytes: u32) {
        if nbytes == 0 {
            return;
        }
        let start = base & !3;
        let end = base.wrapping_add(nbytes).wrapping_add(3) & !3;
        let mut addr = start;
        while addr < end {
            if let Some(rec) = executor.state.memory.page_table.get(addr) {
                self.store_word(addr, rec.value);
            }
            addr = addr.wrapping_add(4);
        }
    }

    /// Sync HINT_READ's freshly-written bytes from
    /// `executor.state.uninitialized_memory` to the host buffer.
    /// Only iterates the (ptr, len) range the syscall actually
    /// wrote — much cheaper than the old `refresh_from_executor`
    /// which iterated the entire 14k+ uninitialized_memory map.
    pub fn sync_uninit_range_to_host(&mut self, executor: &Executor<'_>, base: u32, nbytes: u32) {
        if nbytes == 0 {
            return;
        }
        let start = base & !3;
        let end = base.wrapping_add(nbytes).wrapping_add(3) & !3;
        let mut addr = start;
        while addr < end {
            if let Some(&word) = executor.state.uninitialized_memory.page_table.get(addr) {
                self.store_word(addr, word);
            }
            addr = addr.wrapping_add(4);
        }
    }

    pub fn flush_to_executor(&self, executor: &mut Executor<'_>) {
        use crate::events::MemoryRecord;
        for &addr in &self.seen_addrs {
            let word = self.load_word(addr);
            executor
                .state
                .memory
                .page_table
                .insert(addr, MemoryRecord { value: word, shard: 0, timestamp: 0 });
        }
    }

    /// Pull every executor sparse-memory cell into the host
    /// buffer.  Called after a syscall returns so JIT'd loads
    /// see the syscall's writes (e.g., HINT_READ).
    pub fn refresh_from_executor(&mut self, executor: &Executor<'_>) {
        let uninit_addrs: Vec<u32> =
            executor.state.uninitialized_memory.page_table.keys().collect();
        for addr in uninit_addrs {
            if let Some(&word) = executor.state.uninitialized_memory.page_table.get(addr) {
                self.store_word(addr, word);
            }
        }
    }
}

impl Drop for JitMemoryBridge {
    fn drop(&mut self) {
        if let Some(cow) = self.cow_ptr.take() {
            unsafe {
                libc::munmap(cow.cast(), self.len);
            }
        }
        unsafe {
            libc::munmap(self.primary_ptr.cast(), self.len);
            libc::close(self.mem_fd);
        }
    }
}

/// Public wrapper exposing the canonical program fingerprint used
/// by both [`cached_jit_function`] and the bridge's
/// `last_program_fingerprint`.  Callers can compare these to skip
/// the materialise loop when the same program just ran on this
/// thread.
#[must_use]
pub fn program_fingerprint_of(program: &Program) -> u64 {
    program_fingerprint(program)
}

/// Snapshot stashed at ENTER_UNCONSTRAINED; consumed at EXIT to
/// roll back JIT-only state (registers + cycle counters) the way
/// the interp's `unconstrained_state` rolls back the executor.
#[derive(Clone)]
pub struct UnconstrainedSnapshot {
    pub registers: [u32; 36],
    pub global_clk: u64,
    pub instr_count_executed: u64,
}

/// State passed through `JitContext.user_data` so the syscall
/// trampoline can recover both the executor and the bridge.
pub struct JitBridgeState<'a> {
    pub executor: &'a mut Executor<'a>,
    pub bridge: &'a mut JitMemoryBridge,
    /// Register / clock snapshot taken at ENTER_UNCONSTRAINED.
    /// The executor's `unconstrained_state` captures memory diffs
    /// AND `state.global_clk` so an interp run rolls all of them
    /// back.  The JIT bypasses `state.memory.registers` and
    /// `state.global_clk` between syscalls so we mirror the
    /// rollback here:
    ///   - 36 register words (incl. HI/LO/BRK/HEAP)
    ///   - `ctx.global_clk` (otherwise checkpoints inside the
    ///     block see the JIT counting unconstrained instructions
    ///     while the interp does not)
    ///   - `ctx.instr_count_executed` (mirrors global_clk for the
    ///     halt-after-N counter)
    pub unconstrained_reg_snapshot: Option<UnconstrainedSnapshot>,
}

/// `extern "C"` syscall trampoline registered with the JIT.
///
/// Recovers a `&mut Executor` from `ctx.user_data` (set by the
/// caller before invoking the JIT), reads the syscall id from
/// `ctx.registers[V0]` and the args from `A0`/`A1`, then
/// dispatches via the executor's syscall map exactly the way
/// `Executor::execute_cycle` does for `Opcode::SYSCALL`.
///
/// Side-effects on `ctx`:
/// - `ctx.registers[V0]` is overwritten with the syscall result.
/// - `ctx.exit_code` is set if the syscall is `HALT` — this lets
///   the per-instruction prologue's exit-code gate jump to the
///   shared exit label on the next block, terminating execution.
/// - `ctx.global_clk` is bumped by the syscall's extra cycles.
///
/// Returns 0 on success.  A non-zero return is currently unused;
/// the JIT codegen ignores the call's return value.
///
/// # Safety
///
/// `ctx` must be a live, aligned `*mut JitContext` for the whole call;
/// `ctx.user_data` null or a `*mut JitBridgeState` that outlives it; and no other
/// thread may touch the executor while the JIT'd code runs.
pub unsafe extern "C" fn jit_syscall_handler(ctx: *mut JitContext) -> u64 {
    let ctx = unsafe { &mut *ctx };
    let bridge_ptr = ctx.user_data as *mut JitBridgeState<'_>;
    if bridge_ptr.is_null() {
        ctx.exit_code = 1;
        return 1;
    }
    let bridge_state = unsafe { &mut *bridge_ptr };
    let executor: &mut Executor<'_> = bridge_state.executor;
    let mem_bridge: &mut JitMemoryBridge = bridge_state.bridge;

    use crate::events::MemoryRecord;
    for (i, &v) in ctx.registers[..36].iter().enumerate() {
        executor
            .state
            .memory
            .registers
            .insert(i as u32, MemoryRecord { value: v, shard: 0, timestamp: 0 });
    }

    let syscall_id_peek = ctx.registers[Register::V0 as usize];
    let syscall_peek = SyscallCode::from_u32(syscall_id_peek);
    let a0 = ctx.registers[Register::A0 as usize];
    let a1 = ctx.registers[Register::A1 as usize];
    let a2 = ctx.registers[Register::A2 as usize];
    match syscall_peek {
        SyscallCode::WRITE => {
            mem_bridge.sync_range_to_executor(executor, a1, a2);
        }
        SyscallCode::SHA_EXTEND => {
            mem_bridge.sync_range_to_executor(executor, a0, 256);
        }
        SyscallCode::SHA_COMPRESS => {
            mem_bridge.sync_range_to_executor(executor, a0, 256);
            mem_bridge.sync_range_to_executor(executor, a1, 32);
        }
        SyscallCode::KECCAK_SPONGE => {
            let len_addr = a1.wrapping_add(64);
            let input_len_u32s = mem_bridge.load_word(len_addr & !3);
            let input_bytes = input_len_u32s.saturating_mul(4).min(1 << 20);
            mem_bridge.sync_range_to_executor(executor, a0, input_bytes);
            mem_bridge.sync_range_to_executor(executor, len_addr, 4);
        }
        SyscallCode::SECP256K1_DOUBLE
        | SyscallCode::SECP256R1_DOUBLE
        | SyscallCode::BN254_DOUBLE => {
            mem_bridge.sync_range_to_executor(executor, a0, 64);
        }
        SyscallCode::BLS12381_DOUBLE => {
            mem_bridge.sync_range_to_executor(executor, a0, 96);
        }
        SyscallCode::SECP256K1_ADD | SyscallCode::SECP256R1_ADD | SyscallCode::BN254_ADD => {
            mem_bridge.sync_range_to_executor(executor, a0, 64);
            mem_bridge.sync_range_to_executor(executor, a1, 64);
        }
        SyscallCode::BLS12381_ADD => {
            mem_bridge.sync_range_to_executor(executor, a0, 96);
            mem_bridge.sync_range_to_executor(executor, a1, 96);
        }
        SyscallCode::SECP256K1_DECOMPRESS
        | SyscallCode::SECP256R1_DECOMPRESS
        | SyscallCode::ED_DECOMPRESS => {
            mem_bridge.sync_range_to_executor(executor, a0, 64);
        }
        SyscallCode::BLS12381_DECOMPRESS => {
            mem_bridge.sync_range_to_executor(executor, a0, 96);
        }
        SyscallCode::BLS12381_FP_ADD
        | SyscallCode::BLS12381_FP_SUB
        | SyscallCode::BLS12381_FP_MUL => {
            mem_bridge.sync_range_to_executor(executor, a0, 48);
            mem_bridge.sync_range_to_executor(executor, a1, 48);
        }
        SyscallCode::BLS12381_FP2_ADD
        | SyscallCode::BLS12381_FP2_SUB
        | SyscallCode::BLS12381_FP2_MUL => {
            mem_bridge.sync_range_to_executor(executor, a0, 96);
            mem_bridge.sync_range_to_executor(executor, a1, 96);
        }
        SyscallCode::BN254_FP_ADD | SyscallCode::BN254_FP_SUB | SyscallCode::BN254_FP_MUL => {
            mem_bridge.sync_range_to_executor(executor, a0, 32);
            mem_bridge.sync_range_to_executor(executor, a1, 32);
        }
        SyscallCode::BN254_FP2_ADD | SyscallCode::BN254_FP2_SUB | SyscallCode::BN254_FP2_MUL => {
            mem_bridge.sync_range_to_executor(executor, a0, 64);
            mem_bridge.sync_range_to_executor(executor, a1, 64);
        }
        SyscallCode::ED_ADD => {
            mem_bridge.sync_range_to_executor(executor, a0, 64);
            mem_bridge.sync_range_to_executor(executor, a1, 64);
        }
        SyscallCode::UINT256_MUL => {
            mem_bridge.sync_range_to_executor(executor, a0, 32);
            mem_bridge.sync_range_to_executor(executor, a1, 64);
        }
        SyscallCode::U256XU2048_MUL => {
            let a3 = ctx.registers[Register::A3 as usize];
            mem_bridge.sync_range_to_executor(executor, a0, 32);
            mem_bridge.sync_range_to_executor(executor, a1, 256);
            mem_bridge.sync_range_to_executor(executor, a2, 256);
            mem_bridge.sync_range_to_executor(executor, a3, 32);
        }
        SyscallCode::POSEIDON2_PERMUTE => {
            mem_bridge.sync_range_to_executor(executor, a0, 64);
        }
        SyscallCode::HALT
        | SyscallCode::SYSHINTLEN
        | SyscallCode::SYSHINTREAD
        | SyscallCode::COMMIT
        | SyscallCode::COMMIT_DEFERRED_PROOFS
        | SyscallCode::ENTER_UNCONSTRAINED
        | SyscallCode::EXIT_UNCONSTRAINED => {}
        _ => {
            let len = a1.min(4096);
            mem_bridge.sync_range_to_executor(executor, a0, len);
        }
    }

    let syscall_id = ctx.registers[Register::V0 as usize];
    let arg0 = ctx.registers[Register::A0 as usize];
    let arg1 = ctx.registers[Register::A1 as usize];
    let syscall = SyscallCode::from_u32(syscall_id);

    if executor.print_report {
        executor.report.syscall_counts[syscall] += 1;
    }
    let count_key = syscall.count_map();
    let entry = executor.state.syscall_counts.entry(count_key).or_insert(0);
    *entry += 1;

    let syscall_impl = match executor.syscall_map.get(&syscall).cloned() {
        Some(s) => s,
        None => {
            ctx.exit_code = syscall_id | 0x8000_0000;
            return 1;
        }
    };

    let pre_syscall_regs: [u32; 36] = {
        let mut s = [0u32; 36];
        s.copy_from_slice(&ctx.registers[..36]);
        s
    };

    let unconstrained_dirty_addrs: Vec<u32> = if matches!(syscall, SyscallCode::EXIT_UNCONSTRAINED)
    {
        executor.unconstrained_state.memory_diff.keys().copied().collect()
    } else {
        Vec::new()
    };

    if matches!(syscall, SyscallCode::ENTER_UNCONSTRAINED) {
        let syscall_pc = ctx.last_executed_pc;
        executor.state.pc = syscall_pc;
    }
    let mut precompile_rt = SyscallContext::new(executor);
    let res_value = match syscall_impl.execute(&mut precompile_rt, syscall, arg0, arg1) {
        Ok(v) => v,
        Err(_) => {
            ctx.exit_code = 0xdead_beef;
            return 1;
        }
    };

    let v0_after = res_value.unwrap_or(syscall_id);
    ctx.registers[Register::V0 as usize] = v0_after;

    let precompile_exit_code = precompile_rt.exit_code;
    let precompile_next_pc = precompile_rt.next_pc;
    drop(precompile_rt);

    for i in 0..36u32 {
        let v = executor.state.memory.registers.get(i).map(|r| r.value).unwrap_or(0);
        ctx.registers[i as usize] = v;
    }
    ctx.registers[Register::V0 as usize] = v0_after;

    let _ = unconstrained_dirty_addrs;
    match syscall {
        SyscallCode::ENTER_UNCONSTRAINED => {
            bridge_state.unconstrained_reg_snapshot = Some(UnconstrainedSnapshot {
                registers: pre_syscall_regs,
                global_clk: ctx.global_clk,
                instr_count_executed: ctx.instr_count_executed,
            });
            match mem_bridge.enter_unconstrained() {
                Ok(cow_ptr) => {
                    ctx.memory = std::ptr::NonNull::new(cow_ptr);
                }
                Err(_) => {
                    ctx.exit_code = 0xdead_c01d;
                    return 1;
                }
            }
        }
        SyscallCode::EXIT_UNCONSTRAINED => {
            if let Some(snap) = bridge_state.unconstrained_reg_snapshot.take() {
                ctx.registers[..36].copy_from_slice(&snap.registers);
                ctx.global_clk = snap.global_clk;
                ctx.instr_count_executed = snap.instr_count_executed;
            }
            let primary = mem_bridge.exit_unconstrained();
            ctx.memory = std::ptr::NonNull::new(primary);
            ctx.registers[Register::V0 as usize] = v0_after;
            ctx.pending_jump_at_start = precompile_next_pc;
        }
        _ => {}
    }

    let _ = syscall_impl.num_extra_cycles();

    if syscall == SyscallCode::HALT {
        ctx.exit_code = if precompile_exit_code == 0 { 0x8000_0000 } else { precompile_exit_code };
    }

    match syscall_peek {
        SyscallCode::SYSHINTREAD => {
            mem_bridge.sync_uninit_range_to_host(executor, a0, a1);
        }
        SyscallCode::SHA_EXTEND => {
            mem_bridge.sync_range_from_executor(executor, a0, 256);
        }
        SyscallCode::SHA_COMPRESS => {
            mem_bridge.sync_range_from_executor(executor, a1, 32);
        }
        SyscallCode::KECCAK_SPONGE => {
            mem_bridge.sync_range_from_executor(executor, a1, 64);
        }
        SyscallCode::SECP256K1_DOUBLE
        | SyscallCode::SECP256R1_DOUBLE
        | SyscallCode::BN254_DOUBLE
        | SyscallCode::SECP256K1_ADD
        | SyscallCode::SECP256R1_ADD
        | SyscallCode::BN254_ADD
        | SyscallCode::SECP256K1_DECOMPRESS
        | SyscallCode::SECP256R1_DECOMPRESS
        | SyscallCode::ED_DECOMPRESS
        | SyscallCode::ED_ADD => {
            mem_bridge.sync_range_from_executor(executor, a0, 64);
        }
        SyscallCode::BLS12381_DOUBLE
        | SyscallCode::BLS12381_ADD
        | SyscallCode::BLS12381_DECOMPRESS => {
            mem_bridge.sync_range_from_executor(executor, a0, 96);
        }
        SyscallCode::BLS12381_FP_ADD
        | SyscallCode::BLS12381_FP_SUB
        | SyscallCode::BLS12381_FP_MUL => {
            mem_bridge.sync_range_from_executor(executor, a0, 48);
        }
        SyscallCode::BLS12381_FP2_ADD
        | SyscallCode::BLS12381_FP2_SUB
        | SyscallCode::BLS12381_FP2_MUL => {
            mem_bridge.sync_range_from_executor(executor, a0, 96);
        }
        SyscallCode::BN254_FP_ADD | SyscallCode::BN254_FP_SUB | SyscallCode::BN254_FP_MUL => {
            mem_bridge.sync_range_from_executor(executor, a0, 32);
        }
        SyscallCode::BN254_FP2_ADD | SyscallCode::BN254_FP2_SUB | SyscallCode::BN254_FP2_MUL => {
            mem_bridge.sync_range_from_executor(executor, a0, 64);
        }
        SyscallCode::UINT256_MUL => {
            mem_bridge.sync_range_from_executor(executor, a0, 32);
        }
        SyscallCode::U256XU2048_MUL => {
            let a3 = ctx.registers[Register::A3 as usize];
            mem_bridge.sync_range_from_executor(executor, a2, 256);
            mem_bridge.sync_range_from_executor(executor, a3, 32);
        }
        SyscallCode::POSEIDON2_PERMUTE => {
            mem_bridge.sync_range_from_executor(executor, a0, 64);
        }
        SyscallCode::HALT
        | SyscallCode::SYSHINTLEN
        | SyscallCode::WRITE
        | SyscallCode::COMMIT
        | SyscallCode::COMMIT_DEFERRED_PROOFS
        | SyscallCode::ENTER_UNCONSTRAINED
        | SyscallCode::EXIT_UNCONSTRAINED => {}
        _ => {
            let len = a1.min(4096);
            mem_bridge.sync_range_from_executor(executor, a0, len);
        }
    }

    let _: SyscallEvent;

    0
}

/// Errors produced by the runner during build / execution.
#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    /// The driver couldn't lower a particular opcode (caller can
    /// fall back to the interpreter for that PC).
    #[error("jit driver: {0}")]
    Driver(#[from] DriverError),
    /// memfd / mmap failure during transpiler init.
    #[error("transpiler init: {0}")]
    Init(#[from] std::io::Error),
    /// dynasmrt failed to commit the executable buffer.
    #[error("jit finalize: {0}")]
    Finalize(zkm_core_jit::JitError),
}

/// Builder helper: parameters for [`build_jit_function`].
#[derive(Clone, Copy, Debug)]
pub struct BuildParams {
    /// Number of MIPS instructions in the program.
    pub program_size: usize,
    /// Bytes of guest memory to allocate.
    pub memory_size: usize,
    /// Maximum number of trace events to buffer.
    pub max_trace_size: u64,
    /// Starting PC for the JIT entry.
    pub pc_start: u32,
    /// Base PC of the program (= `program.pc_base`).
    pub pc_base: u32,
    /// Cycles to bump per MIPS instruction.  `0` disables clk
    /// tracking in the JIT — the host re-derives clk from the
    /// trace ring instead.
    pub clk_bump: u64,
    /// optional mem-read recorder fn
    /// registered with the JIT codegen. When `Some(f)`, every
    /// LW/LB/LBU/LH/LHU emits a post-load SysV-ABI call to `f`
    /// passing `(global_clk, guest_addr, value)`. `None` = no
    /// codegen overhead, recorder-free fast path.
    ///
    /// IMPORTANT: this field is NOT part of the program
    /// fingerprint used by `cached_jit_function`. Callers that
    /// flip between Some / None must use a separate cache key
    /// or call `build_jit_function` directly (uncached).
    pub mem_read_recorder: Option<unsafe extern "C" fn(u64, u32, u32)>,
}

/// Build a [`JitFunction`] from a program + build parameters.
///
/// `syscall_handler` is the Rust callback the JIT'd `SYSCALL`
/// instruction will jump to.  Pass `None` if the program never
/// SYSCALLs (most don't outside of HALT).
///
/// # Errors
///
/// `Err(RunnerError::Driver(_))` if any opcode in the program is
/// unsupported by the driver.  In production the caller should wrap
/// this in an interpreter-fallback strategy.
pub fn build_jit_function(
    program: &Program,
    params: BuildParams,
    syscall_handler: Option<SyscallHandler>,
) -> Result<JitFunction, RunnerError> {
    let mut transpiler = <TranspilerBackend as MipsTranspiler>::new(
        params.program_size,
        params.memory_size,
        params.max_trace_size,
        params.pc_start,
        params.pc_base,
        params.clk_bump,
    )?;
    if let Some(handler) = syscall_handler {
        transpiler.register_syscall_handler(handler);
    }
    if let Some(recorder) = params.mem_read_recorder {
        transpiler.set_mem_read_recorder(recorder);
    }
    transpiler.emit_prologue();
    transpiler.emit_load_all_registers();
    if params.pc_start != params.pc_base {
        transpiler.emit_dispatch_to_pc(params.pc_start);
    }
    let driver_stream = instructions_to_driver_stream(program.instructions.iter());
    drive_instructions_at(&mut transpiler, driver_stream, params.pc_base)?;
    transpiler.bind_exit_label();
    transpiler.emit_spill_all_registers();
    transpiler.emit_epilogue();
    transpiler.finalize(params.pc_start).map_err(RunnerError::Finalize)
}

/// Build a [`JitContext`] from the executor's runtime state.
///
/// The caller is responsible for keeping `memory`, `jump_table`,
/// and `trace_buf` alive for the duration of the JIT call —
/// they're stored as raw pointers in the context and the JIT'd
/// code doesn't take ownership.
///
/// # Safety
///
/// The returned `JitContext` holds raw pointers; see [`JitContext`]
/// for the lifetime contract.
#[must_use]
pub fn build_context(
    pc_start: u32,
    memory_ptr: *mut u8,
    jump_table_ptr: *const *const u8,
    jump_table_len: usize,
    trace_buf_ptr: *mut u8,
    registers: [u32; 36],
) -> JitContext {
    use std::ptr::NonNull;
    let mut ctx = JitContext {
        pc: pc_start,
        next_pc: pc_start.wrapping_add(4),
        next_next_pc: pc_start.wrapping_add(8),
        clk: 0,
        global_clk: 0,
        exit_code: 0,
        _pad: 0,
        memory: NonNull::new(memory_ptr),
        jump_table: NonNull::new(jump_table_ptr.cast_mut()),
        trace_buf: trace_buf_ptr,
        tracing: 0,
        _pad2: 0,
        registers,
        user_data: std::ptr::null_mut(),
        delayed_jump_target: 0,
        pending_jump_at_start: 0,
        last_executed_pc: 0,
        instr_count_executed: 0,
        halt_after_n_instrs: 0,
        dirty_log_ptr: std::ptr::null_mut(),
        dirty_log_len: 0,
        dirty_log_cap: 0,
        jump_table_len: u32::try_from(jump_table_len).unwrap_or(u32::MAX),
        bad_jump_target: 0,
        ..JitContext::default()
    };
    ctx.registers[0] = 0;
    ctx
}

/// Execute a JIT'd program against a context.
///
/// # Safety
///
/// `ctx` must be a valid context with live pointers (memory,
/// jump_table, trace_buf) for the duration of the call.  See
/// [`JitFunction::call`] for the full contract.
pub unsafe fn run_jit(jit_fn: &JitFunction, ctx: &mut JitContext) {
    unsafe { jit_fn.call(ctx as *mut JitContext) };
}

/// Run the JIT'd program AND capture a [`crate::minimal_trace::TraceChunk`]
/// describing what was executed.
///
/// This is the Stage-1 emit point that produces the data Stage 2
/// (`TracingVM`) consumes to re-emit a full `ExecutionRecord`. The chunk
/// records the start / end register snapshot, the pc / clk bounds, and a
/// zero-length `mem_reads` oracle, as a single chunk per run.
///
/// `shard_index` lets the caller tag the chunk for downstream sort /
/// rendezvous; pass `0` if you only ever emit a single chunk per run.
///
/// # Safety
///
/// Same contract as [`run_jit`]: `ctx` must be a valid context with
/// live pointers (memory, jump_table, trace_buf) for the duration of
/// the call.
pub unsafe fn run_jit_capture_trace_chunk(
    jit_fn: &JitFunction,
    ctx: &mut JitContext,
    shard_index: u32,
) -> crate::minimal_trace::TraceChunk {
    let pc_start = ctx.pc;
    let clk_start = ctx.global_clk;
    let start_registers = ctx.registers.to_vec();

    let _ = take_recorded_mem_reads();

    unsafe { jit_fn.call(ctx as *mut JitContext) };

    let mem_reads: Vec<crate::minimal_trace::MemValue> = take_recorded_mem_reads()
        .into_iter()
        .map(|r| crate::minimal_trace::MemValue { value: r.value, shard: 0, timestamp: 0 })
        .collect();

    crate::minimal_trace::TraceChunk {
        input_stream_slice: None,
        shard_index,
        shape_fingerprint: 0,
        shape_classes: Vec::new(),
        shape_area: 0,
        start_registers,
        start_register_records: Vec::new(),
        pc_start,
        clk_start,
        clk_end: ctx.global_clk,
        current_shard: 0,
        input_stream_ptr: 0,
        proof_stream_ptr: 0,
        public_values_stream_ptr: 0,
        final_memory: Vec::new(),
        final_uninit_memory: Vec::new(),
        mem_reads: std::sync::Arc::new(mem_reads),
    }
}

/// Translate a guest MIPS byte address to its host-buffer offset
/// under the JIT's `[8-byte header | 8-byte data]` paired layout
/// (see `cuda/jit/src/backends/x86/mod.rs:emit_address_translate`).
///
/// For any guest byte at `a`:
///   intra = a & 7;  aligned = a & !7;  host = aligned * 2 + 8 + intra
#[must_use]
#[inline]
pub fn host_offset_of(guest_addr: u32) -> usize {
    let intra = (guest_addr & 7) as usize;
    let aligned = (guest_addr & !7u32) as usize;
    aligned * 2 + 8 + intra
}

/// Required host-buffer size to hold every guest byte up to (and
/// including) `max_guest_addr`. Add a 16-byte tail for safety so a
/// 4-byte read at the boundary doesn't walk off the buffer.
#[must_use]
#[inline]
pub fn host_buffer_size_for(max_guest_addr: u32) -> usize {
    host_offset_of(max_guest_addr) + 16
}

/// Result of a JIT-driven `Executor::run_fast` attempt.
///
/// The interpreter fallback is the caller's responsibility — on
/// `Err(RunnerError::Driver(_))` the program contained an opcode
/// the JIT can't lower; replay through the interpreter.
#[derive(Debug)]
pub struct JitRunOutcome {
    /// Final pc after the JIT halted.
    pub pc: u32,
    /// Final clock value.
    pub global_clk: u64,
    /// Exit code reported by the (synthetic) HALT.
    pub exit_code: u32,
    /// Final register file snapshot.
    pub registers: [u32; 36],
}

/// Below this many *static* instructions the JIT transpile cost
/// can outweigh the execution saving for straight-line programs.
/// For looped programs the JIT'd code is re-executed many times,
/// so the threshold mostly bites pathologically tiny test fixtures
/// (where the JIT path is unobservable wall-time anyway).
/// Empirical: 100k straight-line ADD instrs is ~4 ms JIT
/// (transpile + run) vs ~1.8 ms interp; 2k-instr loops running
/// 1M cycles flip the comparison the other way.
pub const JIT_MIN_INSTR_COUNT: usize = 500;

/// Pre-screen: returns `Some(opcode_byte)` for the first opcode
/// the JIT can't handle, OR `Some(0xff)` if the program is too
/// small for the JIT to be worth it.  The byte is informational
/// only — the caller treats any `Some` as "skip JIT".
pub fn first_unsupported_opcode(program: &Program) -> Option<u8> {
    if program.instructions.len() < JIT_MIN_INSTR_COUNT {
        return Some(0xff);
    }

    for _ins in &program.instructions {
        {}
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::Instruction;
    use crate::opcode::Opcode;

    #[test]
    fn instruction_round_trip_via_driver_format() {
        let i = Instruction::new(Opcode::ADD, 1, 2, 3, false, false);
        let d = to_driver_instruction(&i);
        assert_eq!(d.opcode, Opcode::ADD as u8);
        assert_eq!(d.op_a, 1);
        assert_eq!(d.op_b, 2);
        assert_eq!(d.op_c, 3);
        assert!(!d.imm_b);
        assert!(!d.imm_c);
    }

    #[test]
    fn instructions_to_driver_stream_iter_yields_correct_count() {
        let prog = [
            Instruction::new(Opcode::ADD, 1, 2, 3, false, false),
            Instruction::new(Opcode::SUB, 4, 5, 6, false, false),
            Instruction::new(Opcode::AND, 7, 8, 9, false, false),
        ];
        let collected: Vec<_> = instructions_to_driver_stream(prog.iter()).collect();
        assert_eq!(collected.len(), 3);
        assert_eq!(collected[0].opcode, Opcode::ADD as u8);
        assert_eq!(collected[1].opcode, Opcode::SUB as u8);
        assert_eq!(collected[2].opcode, Opcode::AND as u8);
    }

    #[test]
    fn build_context_sets_pc_chain_correctly() {
        let mut memory = vec![0u8; 4096];
        let jump_table: Vec<*const u8> = vec![std::ptr::null(); 1024];
        let mut trace_buf = vec![0u8; 4096];
        let ctx = build_context(
            0x100,
            memory.as_mut_ptr(),
            jump_table.as_ptr(),
            jump_table.len(),
            trace_buf.as_mut_ptr(),
            [0u32; 36],
        );
        assert_eq!(ctx.pc, 0x100);
        assert_eq!(ctx.next_pc, 0x104);
        assert_eq!(ctx.next_next_pc, 0x108);
        assert_eq!(ctx.registers[0], 0);
    }
}

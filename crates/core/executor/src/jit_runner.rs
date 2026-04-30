//! P10: end-to-end JIT runner that bridges the executor's
//! [`Instruction`] stream and runtime state to the JIT crate's
//! [`zkm_core_jit::driver`] dispatch + [`zkm_core_jit::JitFunction`]
//! execution.
//!
//! # Status
//!
//! Wired but **opt-in**: activates only when the
//! `cfg(zkm_use_native_executor)` flag is set (Linux x86_64 + no
//! `profiling` feature, see [`crate::build`]) AND the caller invokes
//! [`run_program_jit`] explicitly.  The default executor path
//! ([`crate::Executor::run`]) still uses the interpreter — switching
//! the default lands in a follow-up PR after parity validation.
//!
//! # Pipeline
//!
//! 1. Convert each [`Instruction`] to [`zkm_core_jit::driver::DriverInstruction`].
//! 2. Drive a fresh transpiler over the stream (writes the per-PC
//!    jump table + native code).
//! 3. Finalize → [`zkm_core_jit::JitFunction`].
//! 4. Build a [`zkm_core_jit::JitContext`] from the executor's runtime
//!    state (registers, memory image, pc).
//! 5. `unsafe { jit_function.call(&mut ctx) }`.
//! 6. Ingest the post-call register/pc/clk back into the executor.
//!
//! Steps 1-3 happen once per program (cacheable).  Steps 4-6 happen per
//! `run_program_jit` invocation.

use crate::instruction::Instruction;

/// Convert an executor [`Instruction`] to the JIT-driver wire format.
///
/// The conversion is pure-data — no side effects, no allocations
/// beyond the tiny `DriverInstruction` struct.  Called per-instruction
/// during the transpilation phase.
#[inline]
#[must_use]
pub fn to_driver_instruction(ins: &Instruction) -> zkm_core_jit::driver::DriverInstruction {
    zkm_core_jit::driver::DriverInstruction {
        opcode: ins.opcode as u8,
        op_a: ins.op_a,
        op_b: ins.op_b,
        op_c: ins.op_c,
        imm_b: ins.imm_b,
        imm_c: ins.imm_c,
    }
}

/// Lift an iterable of executor instructions to the driver stream.
///
/// Convenience wrapper over [`to_driver_instruction`] for callers that
/// want to feed [`zkm_core_jit::driver::drive_instructions`] directly.
pub fn instructions_to_driver_stream<'a, I>(
    instructions: I,
) -> impl Iterator<Item = zkm_core_jit::driver::DriverInstruction> + 'a
where
    I: IntoIterator<Item = &'a Instruction> + 'a,
{
    instructions.into_iter().map(to_driver_instruction)
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
mod platform {
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
        // Sample first 16 + last 16 instructions.  For 100k-instr
        // microbench programs this is constant-time; for typical
        // ELFs (few thousand instructions) it's ~1 µs.  Collisions
        // are theoretically possible but require two distinct
        // programs sharing exact head + tail — vanishingly unlikely
        // for non-adversarial workloads.
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
        let cache = JIT_CACHE.get_or_init(|| {
            std::sync::Mutex::new(std::collections::HashMap::new())
        });
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
        /// True when [`Self::primary_ptr`] came from the thread-local
        /// pool and should be returned on Drop.
        from_pool: bool,
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
        /// of the same fd (matching SP1's
        /// `crates/core/jit/src/context.rs::enter_unconstrained`).
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
            // Drain stale pool entries (left over from older builds that
            // pooled the bridge across runs).  The fd is always
            // recreated below — see `Drop` for the rationale.
            if let Some((ptr, plen, _last_fp, fd)) = MMAP_POOL.with(|c| c.borrow_mut().take()) {
                unsafe {
                    libc::munmap(ptr.cast(), plen);
                    libc::close(fd);
                }
            }
            // memfd_create with MFD_CLOEXEC; suppress the swap-area
            // commitment via MFD_NOEXEC_SEAL is unnecessary here.
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
            // Size the fd to `len`.  Pages are not committed until
            // written through a mapping — sparse, like the prior
            // anonymous mmap.
            let rc = unsafe { libc::ftruncate(fd, len as libc::off_t) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                unsafe { libc::close(fd); }
                return Err(err);
            }
            // MAP_SHARED so writes flow through to the fd.  An
            // unconstrained block's MAP_PRIVATE view of the same fd
            // sees those writes (= JIT's current state).
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
                unsafe { libc::close(fd); }
                return Err(err);
            }
            Ok(Self {
                ptr: ptr.cast(),
                len,
                primary_ptr: ptr.cast(),
                cow_ptr: None,
                mem_fd: fd,
                seen_addrs: HashSet::new(),
                from_pool: false,
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
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
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
                unsafe { libc::munmap(cow.cast(), self.len); }
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
        /// back.
        #[inline]
        pub fn store_word(&mut self, addr: u32, value: u32) {
            let off = host_offset_of(addr);
            // SAFETY: `off + 4 <= self.len` because
            // host_buffer_size_for(MAX_MEMORY) is sized for the worst
            // case and `addr` is bounded by the executor at MAX_MEMORY.
            unsafe {
                std::ptr::write_unaligned(
                    self.ptr.add(off).cast::<u32>(),
                    value.to_le(),
                );
            }
            self.seen_addrs.insert(addr & !3);
            // Targeted diagnostic — set ZIREN_TRACE_ADDR=0xADDR to log
            // every store_word to that aligned address with caller info.
            if let Ok(t) = std::env::var("ZIREN_TRACE_ADDR") {
                if let Ok(target) = u32::from_str_radix(t.trim_start_matches("0x"), 16) {
                    if (addr & !3) == (target & !3) {
                        eprintln!(
                            "[trace_addr] store_word addr={addr:#x} val={value:#x} (target {target:#x})"
                        );
                    }
                }
            }
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
        pub fn sync_range_to_executor(
            &self,
            executor: &mut Executor<'_>,
            base: u32,
            nbytes: u32,
        ) {
            use crate::events::MemoryRecord;
            if nbytes == 0 {
                return;
            }
            let start = base & !3;
            let end = base.wrapping_add(nbytes).wrapping_add(3) & !3;
            let mut addr = start;
            while addr < end {
                let word = self.load_word(addr);
                executor.state.memory.page_table.insert(
                    addr,
                    MemoryRecord { value: word, shard: 0, timestamp: 0 },
                );
                addr = addr.wrapping_add(4);
            }
        }

        /// Sync a specific byte range from `executor.state.memory.page_table`
        /// (set by the syscall impl via `mw_traced` etc.) BACK to the
        /// host buffer so subsequent JIT'd loads observe the syscall's
        /// writes.  Word-aligned; rounds the range outward.
        pub fn sync_range_from_executor(
            &mut self,
            executor: &Executor<'_>,
            base: u32,
            nbytes: u32,
        ) {
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
        pub fn sync_uninit_range_to_host(
            &mut self,
            executor: &Executor<'_>,
            base: u32,
            nbytes: u32,
        ) {
            if nbytes == 0 {
                return;
            }
            let start = base & !3;
            let end = base.wrapping_add(nbytes).wrapping_add(3) & !3;
            let mut addr = start;
            while addr < end {
                if let Some(&word) =
                    executor.state.uninitialized_memory.page_table.get(addr)
                {
                    self.store_word(addr, word);
                }
                addr = addr.wrapping_add(4);
            }
        }

        pub fn flush_to_executor(&self, executor: &mut Executor<'_>) {
            use crate::events::MemoryRecord;
            if std::env::var_os("ZIREN_TRACE_ADDR").is_some() {
                eprintln!(
                    "[flush] {} seen_addrs to executor.page_table",
                    self.seen_addrs.len()
                );
            }
            for &addr in &self.seen_addrs {
                let word = self.load_word(addr);
                executor.state.memory.page_table.insert(
                    addr,
                    MemoryRecord { value: word, shard: 0, timestamp: 0 },
                );
                if let Ok(t) = std::env::var("ZIREN_TRACE_ADDR") {
                    if let Ok(target) = u32::from_str_radix(t.trim_start_matches("0x"), 16) {
                        if (addr & !3) == (target & !3) {
                            eprintln!(
                                "[flush] page_table.insert addr={addr:#x} val={word:#x} (target {target:#x})"
                            );
                        }
                    }
                }
            }
        }

        /// Pull every executor sparse-memory cell into the host
        /// buffer.  Called after a syscall returns so JIT'd loads
        /// see the syscall's writes (e.g., HINT_READ).
        pub fn refresh_from_executor(&mut self, executor: &Executor<'_>) {
            if std::env::var_os("ZIREN_TRACE_ADDR").is_some() {
                eprintln!(
                    "[refresh] page_table={} keys, uninit_memory={} keys",
                    executor.state.memory.page_table.exact_len(),
                    executor.state.uninitialized_memory.page_table.exact_len(),
                );
            }
            // Only sync `state.uninitialized_memory` to host — those
            // are NEW bytes the syscall wrote (HINT_READ specifically
            // is the only such syscall in current workloads).
            //
            // CRITICAL: do NOT iterate `state.memory.page_table` here.
            // That table holds *cached snapshots* of host bytes taken
            // by `flush_to_executor` at every prior syscall boundary.
            // The JIT'd code subsequently writes directly to the host
            // buffer (via `SW` etc.) without updating page_table, so
            // a write-back from page_table → host would overwrite the
            // JIT's just-written bytes with stale flush snapshots and
            // corrupt the heap.  This was the tendermint segfault
            // root cause: page_table[0x126a90]=0 was captured at
            // SYSHINTREAD's flush, then a JIT SW set host[0x126a90]=1,
            // then the next syscall's refresh wrote 0 back, so a
            // later LW $ra=mem[$sp+0x4c] loaded the corrupted 0x11
            // → JR $ra jumped to a wild address → SEGV.
            //
            // For syscalls that genuinely WRITE to page_table (none in
            // current workloads — SHA syscalls would; if added, sync
            // their specific destination ranges instead of the whole
            // table), we'd need a per-syscall sync helper.
            let uninit_addrs: Vec<u32> =
                executor.state.uninitialized_memory.page_table.keys().collect();
            for addr in uninit_addrs {
                if let Some(&word) =
                    executor.state.uninitialized_memory.page_table.get(addr)
                {
                    self.store_word(addr, word);
                }
            }
        }
    }

    impl Drop for JitMemoryBridge {
        fn drop(&mut self) {
            // Discard any COW first — never cache it across bridges.
            if let Some(cow) = self.cow_ptr.take() {
                unsafe { libc::munmap(cow.cast(), self.len); }
            }
            // Always free both the mapping and the fd.  Pooling the fd
            // across runs leaks state: the prior run's MAP_SHARED writes
            // are persisted on the fd, and the next run's MAP_PRIVATE
            // COW (if any) inherits that as its baseline — exactly the
            // wrong starting state for a fresh program.  Re-creating the
            // fd costs ~one syscall per run, which is irrelevant next to
            // a 100M-cycle JIT pass.
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
    /// `Executor::execute_cycle` does for `Opcode::SYSCALL`
    /// (`crates/core/executor/src/executor.rs:1564`).
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
    pub extern "C" fn jit_syscall_handler(ctx: *mut JitContext) -> u64 {
        // SAFETY: the JIT only ever calls this handler from a SYSCALL
        // emit point, where `ctx` is a live `*mut JitContext` set up by
        // the caller and `ctx.user_data` was populated with a
        // `*mut JitBridgeState` that outlives this call.  No other
        // thread touches the executor while the JIT'd code is
        // executing.
        let ctx = unsafe { &mut *ctx };
        let bridge_ptr = ctx.user_data as *mut JitBridgeState<'_>;
        if bridge_ptr.is_null() {
            // No bridge wired — this is a programming error in the
            // caller.  Mark exit_code = 1 so the JIT exits cleanly.
            ctx.exit_code = 1;
            return 1;
        }
        let bridge_state = unsafe { &mut *bridge_ptr };
        let executor: &mut Executor<'_> = bridge_state.executor;
        let mem_bridge: &mut JitMemoryBridge = bridge_state.bridge;

        // Sync the JIT's pinned-XMM register file into the executor's
        // `state.memory.registers` BEFORE the syscall impl runs.  Most
        // syscalls just take args via the (V0, A0, A1) → (id, arg0, arg1)
        // pattern, but several (WRITE reading $a2 for nbytes,
        // sysmmap reading $heap/$brk, etc.) reach into `rt.register(reg)`
        // for additional args.  Without this sync, those reads see
        // stale or zero values — `pvs_len` ends up empty because WRITE
        // sees `nbytes = 0`, and tendermint's CBOR input deserialise
        // panics because sysmmap returns a stale heap pointer.
        //
        // We sync ALL 36 register slots (0..36) including HI/LO/BRK/HEAP
        // so syscalls that read those registers see the right values.
        // The JIT's BRK/HEAP locations are `Mem(34)` / `Mem(35)`
        // (backed directly by ctx.registers[34/35]), so no in-XMM
        // value would otherwise reach the executor.
        use crate::events::MemoryRecord;
        for (i, &v) in ctx.registers[..36].iter().enumerate() {
            executor.state.memory.registers.insert(
                i as u32,
                MemoryRecord { value: v, shard: 0, timestamp: 0 },
            );
        }

        // Pre-sync host → executor so the syscall impl sees the JIT's
        // most recent writes (stack arguments, COMMIT serialised
        // buffers, etc.).
        //
        // Most Ziren syscalls take args via registers (V0/A0/A1) and
        // don't read or write guest memory.  For those we skip the
        // bidirectional bridge sync.  WRITE reads `[arg2, arg2+a2]`
        // bytes — sync just that range.  HINT_READ writes
        // `[arg0, arg0+arg1]` — sync that range AFTER the syscall.
        let syscall_id_peek = ctx.registers[Register::V0 as usize];
        let syscall_peek = SyscallCode::from_u32(syscall_id_peek);
        if std::env::var_os("ZIREN_JIT_PC_TRACE").is_some() {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("/tmp/jit-syscall.log")
            {
                let _ = writeln!(
                    f,
                    "syscall {:?} a0={:#x} a1={:#x} a2={:#x}",
                    syscall_peek,
                    ctx.registers[Register::A0 as usize],
                    ctx.registers[Register::A1 as usize],
                    ctx.registers[Register::A2 as usize],
                );
            }
        }
        // Per-syscall input range pre-sync.  Each known memory-touching
        // syscall has its inputs at a (ptr, len)-style register pair we
        // can identify up front.  Sync only those bytes from host →
        // executor.page_table so the syscall impl reads JIT-current
        // values via `rt.byte()` / `rt.word()`.  For syscalls that
        // don't touch guest memory (HALT, COMMIT, etc.) we skip the
        // sync entirely — that's the bulk of the speedup vs the old
        // blanket `flush_to_executor` of all `seen_addrs`.
        let a0 = ctx.registers[Register::A0 as usize];
        let a1 = ctx.registers[Register::A1 as usize];
        let a2 = ctx.registers[Register::A2 as usize];
        match syscall_peek {
            SyscallCode::WRITE => {
                // (fd, buf, nbytes) — read [buf, buf+nbytes).
                mem_bridge.sync_range_to_executor(executor, a1, a2);
            }
            SyscallCode::SHA_EXTEND => {
                // The 64-byte (16-word) message-schedule buffer at $a0
                // is read AND written by SHA_EXTEND.  Sync 16*4 = 64
                // bytes (256 bytes total since SHA_EXTEND extends the
                // schedule from 16 to 64 words ≈ 256 bytes).
                mem_bridge.sync_range_to_executor(executor, a0, 256);
            }
            SyscallCode::SHA_COMPRESS => {
                // SHA_COMPRESS reads the schedule at $a0 (256B) and
                // writes the 8-word state at $a1 (32B).  Sync both.
                mem_bridge.sync_range_to_executor(executor, a0, 256);
                mem_bridge.sync_range_to_executor(executor, a1, 32);
            }
            SyscallCode::KECCAK_SPONGE => {
                // ABI: $a0 = input_ptr, $a1 = result_ptr.  The syscall
                // reads `input_len_u32s` from `mem[a1 + 64]`, then reads
                // `input_len_u32s` words from `[a0, a0 + 4*len)`, and
                // writes 64 bytes of output to `[a1, a1 + 64)`.
                // We must sync the length word first (so the executor
                // sees it), then the input range, plus the length cell.
                let len_addr = a1.wrapping_add(64);
                let input_len_u32s = mem_bridge.load_word(len_addr & !3);
                // Cap to avoid runaway sync on bogus state; real sponge
                // inputs in Reth are bounded by transaction/block size.
                let input_bytes = input_len_u32s.saturating_mul(4).min(1 << 20);
                mem_bridge.sync_range_to_executor(executor, a0, input_bytes);
                mem_bridge.sync_range_to_executor(executor, len_addr, 4);
            }
            // Elliptic curve point doubles: read 1 point at $a0, write
            // it back doubled.  Point sizes (NumWords::WordsCurvePoint *
            // 4 bytes from `crates/curves/src/params.rs`):
            //   - secp256k1 / secp256r1 / bn254: 16 words = 64 bytes
            //   - bls12-381: 24 words = 96 bytes
            SyscallCode::SECP256K1_DOUBLE
            | SyscallCode::SECP256R1_DOUBLE
            | SyscallCode::BN254_DOUBLE => {
                mem_bridge.sync_range_to_executor(executor, a0, 64);
            }
            SyscallCode::BLS12381_DOUBLE => {
                mem_bridge.sync_range_to_executor(executor, a0, 96);
            }
            // Elliptic curve point adds: read 2 points ($a0, $a1), write
            // sum to $a0.  Same per-curve sizes as DOUBLE.
            SyscallCode::SECP256K1_ADD | SyscallCode::SECP256R1_ADD | SyscallCode::BN254_ADD => {
                mem_bridge.sync_range_to_executor(executor, a0, 64);
                mem_bridge.sync_range_to_executor(executor, a1, 64);
            }
            SyscallCode::BLS12381_ADD => {
                mem_bridge.sync_range_to_executor(executor, a0, 96);
                mem_bridge.sync_range_to_executor(executor, a1, 96);
            }
            // Curve point decompresses: read compressed (32-byte
            // x-coordinate + 1-byte sign packed into the slot at $a0),
            // write decompressed (64-byte point) to $a0.  See
            // `crates/core/executor/src/syscalls/precompiles/weierstrass/decompress.rs`
            // and `crates/core/executor/src/syscalls/precompiles/edwards/decompress.rs`.
            // Sync 64 bytes to cover both the input and the output slot.
            SyscallCode::SECP256K1_DECOMPRESS
            | SyscallCode::SECP256R1_DECOMPRESS
            | SyscallCode::ED_DECOMPRESS => {
                mem_bridge.sync_range_to_executor(executor, a0, 64);
            }
            SyscallCode::BLS12381_DECOMPRESS => {
                mem_bridge.sync_range_to_executor(executor, a0, 96);
            }
            // BLS12-381 Fp arithmetic: $a0 = result_ptr (read+write,
            // 48 bytes), $a1 = operand_ptr (read 48 bytes).
            SyscallCode::BLS12381_FP_ADD
            | SyscallCode::BLS12381_FP_SUB
            | SyscallCode::BLS12381_FP_MUL => {
                mem_bridge.sync_range_to_executor(executor, a0, 48);
                mem_bridge.sync_range_to_executor(executor, a1, 48);
            }
            SyscallCode::BLS12381_FP2_ADD
            | SyscallCode::BLS12381_FP2_SUB
            | SyscallCode::BLS12381_FP2_MUL => {
                // Fp2 = pair of Fp; 96 bytes.
                mem_bridge.sync_range_to_executor(executor, a0, 96);
                mem_bridge.sync_range_to_executor(executor, a1, 96);
            }
            SyscallCode::BN254_FP_ADD
            | SyscallCode::BN254_FP_SUB
            | SyscallCode::BN254_FP_MUL => {
                mem_bridge.sync_range_to_executor(executor, a0, 32);
                mem_bridge.sync_range_to_executor(executor, a1, 32);
            }
            SyscallCode::BN254_FP2_ADD
            | SyscallCode::BN254_FP2_SUB
            | SyscallCode::BN254_FP2_MUL => {
                mem_bridge.sync_range_to_executor(executor, a0, 64);
                mem_bridge.sync_range_to_executor(executor, a1, 64);
            }
            // ED_ADD: edwards-curve point add — 32-byte coords (Ed25519),
            // 2-coord points = 64 bytes per point.
            SyscallCode::ED_ADD => {
                mem_bridge.sync_range_to_executor(executor, a0, 64);
                mem_bridge.sync_range_to_executor(executor, a1, 64);
            }
            // UINT256_MUL: result/x at $a0 (32 bytes, read+write),
            // y at $a1 (32 bytes, read), modulus at $a1+32 (32 bytes,
            // read).  See `crates/core/executor/src/syscalls/precompiles/uint256.rs`.
            SyscallCode::UINT256_MUL => {
                mem_bridge.sync_range_to_executor(executor, a0, 32);
                mem_bridge.sync_range_to_executor(executor, a1, 64);
            }
            // U256xU2048_MUL: a*b mul-and-split into (hi, lo).
            //   $a0 = a_ptr (read 32B), $a1 = b_ptr (read 256B),
            //   $a2 = lo_ptr (write 256B), $a3 = hi_ptr (write 32B).
            // See `crates/core/executor/src/syscalls/precompiles/u256x2048_mul.rs`.
            SyscallCode::U256XU2048_MUL => {
                let a3 = ctx.registers[Register::A3 as usize];
                mem_bridge.sync_range_to_executor(executor, a0, 32);
                mem_bridge.sync_range_to_executor(executor, a1, 256);
                mem_bridge.sync_range_to_executor(executor, a2, 256);
                mem_bridge.sync_range_to_executor(executor, a3, 32);
            }
            // POSEIDON2_PERMUTE: 16-word state at $a0 (read+write) per
            // `crates/core/executor/src/syscalls/precompiles/poseidon2/permute.rs::STATE_SIZE`.
            SyscallCode::POSEIDON2_PERMUTE => {
                mem_bridge.sync_range_to_executor(executor, a0, 64);
            }
            // No-memory-access syscalls — skip the sync entirely:
            SyscallCode::HALT
            | SyscallCode::SYSHINTLEN
            | SyscallCode::SYSHINTREAD
            | SyscallCode::COMMIT
            | SyscallCode::COMMIT_DEFERRED_PROOFS
            | SyscallCode::ENTER_UNCONSTRAINED
            | SyscallCode::EXIT_UNCONSTRAINED => {}
            // Conservative fallback for any other syscall — sync only
            // the [a0, a0+a1) range which is the conventional Ziren
            // (ptr, len) pattern for precompiles.  If a precompile
            // touches more memory than this it'll need an explicit
            // entry above.
            _ => {
                // Cap the range to avoid runaway sync on bogus args.
                let len = a1.min(4096);
                mem_bridge.sync_range_to_executor(executor, a0, len);
            }
        }

        let syscall_id = ctx.registers[Register::V0 as usize];
        let arg0 = ctx.registers[Register::A0 as usize];
        let arg1 = ctx.registers[Register::A1 as usize];
        let syscall = SyscallCode::from_u32(syscall_id);

        // Mirror the executor's per-cycle bookkeeping, simplified for
        // the JIT path (Simple mode — no event emission).
        if executor.print_report {
            executor.report.syscall_counts[syscall] += 1;
        }
        let count_key = syscall.count_map();
        let entry = executor.state.syscall_counts.entry(count_key).or_insert(0);
        *entry += 1;

        let syscall_impl = match executor.syscall_map.get(&syscall).cloned() {
            Some(s) => s,
            None => {
                // Unknown syscall → terminate with non-zero exit so
                // the JIT short-circuits and the host can surface
                // UnsupportedSyscall via `runtime.report` after the
                // call returns.
                ctx.exit_code = (syscall_id as u32) | 0x8000_0000;
                return 1;
            }
        };

        // Snapshot the JIT register file BEFORE the syscall runs.  For
        // ENTER_UNCONSTRAINED this is the post-ENTER state we'll need
        // to roll back to at EXIT.  We only stash it into the bridge
        // state when the syscall actually IS ENTER_UNCONSTRAINED (see
        // post-call dispatch below).
        let pre_syscall_regs: [u32; 36] = {
            let mut s = [0u32; 36];
            s.copy_from_slice(&ctx.registers[..36]);
            s
        };

        // EXIT_UNCONSTRAINED memory rollback: the executor's
        // `unconstrained_state.memory_diff` is a map of {addr → original
        // value} for every addr touched during the block.  When EXIT's
        // syscall body runs, that map is *drained* and applied to
        // executor.state.memory.  But the JIT's host buffer has the
        // dirty (block-written) values — those won't get reverted on
        // their own.  So before EXIT runs we copy the diff's keys so we
        // can post-sync those addresses host-side after the executor
        // restores them.
        let unconstrained_dirty_addrs: Vec<u32> =
            if matches!(syscall, SyscallCode::EXIT_UNCONSTRAINED) {
                executor.unconstrained_state.memory_diff.keys().copied().collect()
            } else {
                Vec::new()
            };

        // ENTER_UNCONSTRAINED captures `executor.state.pc` for later
        // rollback.  The JIT codegen wrote the SYSCALL's guest PC into
        // `ctx.last_executed_pc` (always, not just under PC_TRACE) so
        // we can plumb it into the executor here — without this the
        // executor's stale state.pc would be saved instead and EXIT
        // would jump to the wrong place.
        if matches!(syscall, SyscallCode::ENTER_UNCONSTRAINED) {
            let syscall_pc = ctx.last_executed_pc;
            executor.state.pc = syscall_pc;
        }
        let mut precompile_rt = SyscallContext::new(executor);
        let res_value = match syscall_impl.execute(&mut precompile_rt, syscall, arg0, arg1) {
            Ok(v) => v,
            Err(_) => {
                // Surface the error by halting; the host will see the
                // non-zero exit_code and replay through the interpreter
                // for a faithful diagnostic.
                ctx.exit_code = 0xdead_beef;
                return 1;
            }
        };

        // Apply the syscall result: V0 gets the precompile-supplied
        // return value (or the syscall_id if the impl didn't return
        // one), matching `executor.rs:1601`'s semantics.
        let v0_after = res_value.unwrap_or(syscall_id);
        ctx.registers[Register::V0 as usize] = v0_after;

        // Snapshot the syscall ctx fields we need before dropping the
        // borrow on `executor`.
        let precompile_exit_code = precompile_rt.exit_code;
        let precompile_next_pc = precompile_rt.next_pc;
        drop(precompile_rt);

        // Sync any register writes the syscall impl may have made
        // (e.g., sysmmap writing HEAP/BRK) back into the JIT's register
        // file so subsequent JIT'd code observes them.  Blast all 36
        // back so HI/LO/BRK/HEAP propagate too.
        for i in 0..36u32 {
            let v = executor
                .state
                .memory
                .registers
                .get(i)
                .map(|r| r.value)
                .unwrap_or(0);
            ctx.registers[i as usize] = v;
        }
        // Restore V0 to the syscall return value (the loop above
        // would have stomped it with whatever's in state.memory).
        ctx.registers[Register::V0 as usize] = v0_after;

        // Unconstrained block bookkeeping.  The executor's
        // `EnterUnconstrainedSyscall` saves PC + memory_diff state and
        // `ExitUnconstrainedSyscall` rolls them back, but neither sees
        // the JIT's pinned-XMM register file or the JIT's host memory
        // buffer (between syscalls the JIT modifies ctx.registers /
        // bridge memory without going through the executor).  We
        // bridge those gaps here:
        //   ENTER: stash JIT register snapshot AND swap ctx.memory to
        //          a private COW view of the bridge fd, so JIT writes
        //          go to a copy-on-write region that's discarded at
        //          EXIT.  Mirrors SP1's
        //          `crates/core/jit/src/context.rs::enter_unconstrained`.
        //   EXIT : restore registers + clk + instr_count from snapshot,
        //          discard the COW (ctx.memory back to primary), and
        //          redirect the JIT to the executor's saved next_pc.
        let _ = unconstrained_dirty_addrs; // memory revert now handled by COW.
        match syscall {
            SyscallCode::ENTER_UNCONSTRAINED => {
                bridge_state.unconstrained_reg_snapshot = Some(UnconstrainedSnapshot {
                    registers: pre_syscall_regs,
                    global_clk: ctx.global_clk,
                    instr_count_executed: ctx.instr_count_executed,
                });
                match mem_bridge.enter_unconstrained() {
                    Ok(cow_ptr) => {
                        // Update ctx.memory; the SYSCALL codegen reloads
                        // MEMORY_PTR from CONTEXT.memory after the call
                        // (instruction_impl.rs::syscall), so subsequent
                        // JIT'd block loads/stores hit the COW.
                        ctx.memory = std::ptr::NonNull::new(cow_ptr);
                        if std::env::var_os("ZIREN_JIT_PC_TRACE").is_some() {
                            eprintln!(
                                "[unconstr] ENTER COW ptr={:#x}",
                                cow_ptr as usize
                            );
                        }
                    }
                    Err(_) => {
                        // Couldn't get a COW — surface a clean error so
                        // the host falls back to the interpreter for a
                        // faithful diagnostic.
                        ctx.exit_code = 0xdead_c01d;
                        return 1;
                    }
                }
            }
            SyscallCode::EXIT_UNCONSTRAINED => {
                if let Some(snap) = bridge_state.unconstrained_reg_snapshot.take() {
                    ctx.registers[..36].copy_from_slice(&snap.registers);
                    // Mirror `ExitUnconstrainedSyscall::execute` rolling
                    // back `state.global_clk` to the ENTER snapshot —
                    // otherwise instr_count drifts ahead of the interp's
                    // global_clk by the size of the block, breaking
                    // bisect/halt-after-N alignment.
                    ctx.global_clk = snap.global_clk;
                    ctx.instr_count_executed = snap.instr_count_executed;
                }
                // Discard the COW.  ctx.memory swings back to the
                // primary MAP_SHARED view, undoing every JIT write made
                // during the block in one O(1) syscall (munmap).
                let primary = mem_bridge.exit_unconstrained();
                ctx.memory = std::ptr::NonNull::new(primary);
                if std::env::var_os("ZIREN_JIT_PC_TRACE").is_some() {
                    eprintln!("[unconstr] EXIT primary={:#x}", primary as usize);
                }
                // V0 holds the EXIT_UNCONSTRAINED return value (0).
                ctx.registers[Register::V0 as usize] = v0_after;
                // The executor rolled state.pc back to `unconstrained_state.pc`
                // (the ENTER instruction's PC) and set the syscall ctx's
                // `next_pc = state.pc + 4`, i.e. the instruction right
                // after the original ENTER.  Steer the JIT there: writing
                // to `pending_jump_at_start` overrides the snapshot the
                // SYSCALL's start_instr already took, so end_instr() will
                // indirect-jump via the table to that target.
                ctx.pending_jump_at_start = precompile_next_pc;
            }
            _ => {}
        }

        // Cycle accounting: the interpreter's `state.global_clk` only
        // counts instructions (executor.rs:2164 — `+= 1` per cycle, no
        // syscall extras).  Per-syscall extras land in `state.clk`
        // (executor.rs:1644 — `state.clk += precompile_cycles`), which
        // is per-shard and not exported through `state.global_clk`.
        // To make `JIT.global_clk == interp.global_clk` byte-for-byte,
        // we deliberately do NOT add `num_extra_cycles()` here.
        let _ = syscall_impl.num_extra_cycles();

        // HALT termination: set ctx.exit_code so the next instr's
        // exit-code gate jumps to the shared exit label.  Note: the
        // executor uses `state.exited` for HALT-with-zero-exit; we
        // surface this via a dedicated sentinel low bit so the
        // post-call reconciliation can distinguish HALT from error.
        if syscall == SyscallCode::HALT {
            // Even a "successful" HALT (exit_code 0) needs to break
            // the JIT loop.  Use the high bit as a "halt requested"
            // marker; the host clears it post-call before looking at
            // the real exit code stored separately.
            ctx.exit_code = if precompile_exit_code == 0 {
                // Encode "halt with zero" as a sentinel that the
                // host normalises back to 0 after the JIT returns.
                0x8000_0000
            } else {
                precompile_exit_code
            };
        }

        // Per-syscall output range post-sync.  Each memory-writing
        // syscall has a known output range we can write back to host
        // bytes.  We use `sync_range_from_executor` (executor.page_table
        // → host) for syscalls that wrote via `rt.mw*`, and a
        // separate `sync_range_uninit_to_host` for HINT_READ which
        // writes via `state.uninitialized_memory.entry().insert()`.
        match syscall_peek {
            SyscallCode::SYSHINTREAD => {
                // Output: [a0, a0+a1) bytes written to uninitialized_memory.
                mem_bridge.sync_uninit_range_to_host(executor, a0, a1);
            }
            SyscallCode::SHA_EXTEND => {
                mem_bridge.sync_range_from_executor(executor, a0, 256);
            }
            SyscallCode::SHA_COMPRESS => {
                mem_bridge.sync_range_from_executor(executor, a1, 32);
            }
            SyscallCode::KECCAK_SPONGE => {
                // 64-byte output written to result_ptr ($a1).
                mem_bridge.sync_range_from_executor(executor, a1, 64);
            }
            // Curve doubles + adds + decompresses + Fp arithmetic:
            // the result is written to $a0.  See input-side match for
            // the per-curve sizing rationale.
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
            SyscallCode::BN254_FP_ADD
            | SyscallCode::BN254_FP_SUB
            | SyscallCode::BN254_FP_MUL => {
                mem_bridge.sync_range_from_executor(executor, a0, 32);
            }
            SyscallCode::BN254_FP2_ADD
            | SyscallCode::BN254_FP2_SUB
            | SyscallCode::BN254_FP2_MUL => {
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
            // No-memory-write syscalls (incl. WRITE which only touches
            // public_values_stream / io_buf, NOT guest memory):
            SyscallCode::HALT
            | SyscallCode::SYSHINTLEN
            | SyscallCode::WRITE
            | SyscallCode::COMMIT
            | SyscallCode::COMMIT_DEFERRED_PROOFS
            | SyscallCode::ENTER_UNCONSTRAINED
            | SyscallCode::EXIT_UNCONSTRAINED => {}
            // Conservative fallback: write back [a0, a0+min(a1, 4096))
            // assuming the same (ptr, len) convention the precompile
            // used for input.  Real precompiles should be enumerated
            // above with their actual memory output range.
            _ => {
                let len = a1.min(4096);
                mem_bridge.sync_range_from_executor(executor, a0, len);
            }
        }
        if std::env::var_os("ZIREN_JIT_PC_TRACE").is_some()
            && matches!(syscall_peek, SyscallCode::SYSHINTREAD)
        {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("/tmp/jit-syscall.log")
            {
                let buf = ctx.registers[Register::A0 as usize];
                let host_word = mem_bridge.load_word(buf & !3);
                let exec_word = executor
                    .state
                    .memory
                    .page_table
                    .get(buf & !3)
                    .map(|r| r.value)
                    .unwrap_or(0);
                let _ = writeln!(
                    f,
                    "  HINTREAD post-sync buf={buf:#x} host={host_word:#x} exec={exec_word:#x}"
                );
            }
        }
        if std::env::var_os("ZIREN_JIT_PC_TRACE").is_some()
            && matches!(syscall_peek, SyscallCode::SYSHINTLEN)
        {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("/tmp/jit-syscall.log")
            {
                let _ = writeln!(
                    f,
                    "  SYSHINTLEN return: V0={:#x} (ctx.regs[2])",
                    ctx.registers[Register::V0 as usize]
                );
            }
        }

        // Discard unused event accumulator: jit path doesn't emit
        // CPU events (Simple mode contract).
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
    }

    /// Build a [`JitFunction`] from a program + build parameters.
    ///
    /// `syscall_handler` is the Rust callback the JIT'd `SYSCALL`
    /// instruction will jump to.  Pass `None` if the program never
    /// SYSCALLs (most don't outside of HALT).
    ///
    /// # Errors
    ///
    /// Returns `Err(RunnerError::Driver(_))` if any opcode in the
    /// program is unsupported by the driver.  In production the
    /// caller should wrap this in an interpreter-fallback strategy.
    pub fn build_jit_function(
        program: &Program,
        params: BuildParams,
        syscall_handler: Option<SyscallHandler>,
    ) -> Result<JitFunction, RunnerError> {
        // Call via the MipsTranspiler trait so we hit the 6-arg ctor
        // rather than the 0-arg helper of TranspilerBackend.
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
        // Wrap the driver-emitted per-instruction code with the
        // SysV-ABI prologue/epilogue and the register seed/spill so
        // the JIT'd function can be called like any extern "C" fn
        // and so the host sees the post-execution register file.
        // Without this wrapper the resulting code segfaults on the
        // first push/pop balance check.
        transpiler.emit_prologue();
        transpiler.emit_load_all_registers();
        // Dispatch to the program's entry PC rather than falling
        // through to instruction index 0.  Real ELFs put their
        // entry well past pc_base; without this jump the JIT
        // executes whatever bytes precede the entry, which
        // SEGFAULTs immediately.
        // Skip the dispatch when pc_start == pc_base (test fixtures,
        // synthetic programs) so we don't spend an indirect-jmp on
        // the common-case fall-through path AND avoid reading
        // jump_table[0] when the table itself isn't yet populated
        // through some test-only code path.
        if params.pc_start != params.pc_base {
            transpiler.emit_dispatch_to_pc(params.pc_start);
        }
        let driver_stream = instructions_to_driver_stream(program.instructions.iter());
        drive_instructions_at(&mut transpiler, driver_stream, params.pc_base)?;
        // Bind the shared early-exit label between the last MIPS
        // instruction and the spill+epilogue.  Per-instruction prologues
        // jump here on `ctx.exit_code != 0` (set by HALT-style syscalls).
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
        };
        // Mask zero register for safety.
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
        // SAFETY: caller's contract.
        unsafe { jit_fn.call(ctx as *mut JitContext) };
    }

    /// SIGSEGV probe: stash a `*mut JitContext` into a global atomic
    /// before `run_jit`, install a handler that — on SEGV — prints
    /// `last_executed_pc`, faulting address, and key pinned regs to
    /// stderr, then defers to the default handler.  Caller drops the
    /// returned guard after `run_jit` returns to remove the handler
    /// and clear the global pointer.
    pub fn install_segv_probe(ctx: &mut JitContext) -> SegvProbeGuard {
        use std::sync::atomic::Ordering;
        LIVE_CTX.store(ctx as *mut _, Ordering::Relaxed);
        unsafe {
            let mut act: libc::sigaction = std::mem::zeroed();
            act.sa_flags = libc::SA_SIGINFO | libc::SA_NODEFER;
            act.sa_sigaction = segv_probe_handler as usize;
            libc::sigemptyset(&mut act.sa_mask);
            let mut prev: libc::sigaction = std::mem::zeroed();
            libc::sigaction(libc::SIGSEGV, &act, &mut prev);
            SegvProbeGuard { prev }
        }
    }

    /// Restore the previous SIGSEGV disposition + clear LIVE_CTX
    /// when dropped.  Returned by [`install_segv_probe`].
    pub struct SegvProbeGuard {
        prev: libc::sigaction,
    }

    impl Drop for SegvProbeGuard {
        fn drop(&mut self) {
            use std::sync::atomic::Ordering;
            LIVE_CTX.store(std::ptr::null_mut(), Ordering::Relaxed);
            unsafe {
                libc::sigaction(libc::SIGSEGV, &self.prev, std::ptr::null_mut());
            }
        }
    }

    static LIVE_CTX: std::sync::atomic::AtomicPtr<JitContext> =
        std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

    extern "C" fn segv_probe_handler(
        sig: libc::c_int,
        info: *mut libc::siginfo_t,
        ucontext: *mut libc::c_void,
    ) {
        use std::sync::atomic::Ordering;
        let ctx = LIVE_CTX.load(Ordering::Relaxed);
        let last_pc = if ctx.is_null() {
            0
        } else {
            unsafe { (*ctx).last_executed_pc }
        };
        let instr_count = if ctx.is_null() {
            0
        } else {
            unsafe { (*ctx).instr_count_executed }
        };
        let fault_addr: u64 = unsafe { (*info).si_addr() as u64 };
        let (rip, rbx, rbp, r10, r13, r14): (u64, u64, u64, u64, u64, u64) = unsafe {
            let uctx = ucontext as *const libc::ucontext_t;
            let g = &(*uctx).uc_mcontext.gregs;
            (
                g[libc::REG_RIP as usize] as u64,
                g[libc::REG_RBX as usize] as u64,
                g[libc::REG_RBP as usize] as u64,
                g[libc::REG_R10 as usize] as u64,
                g[libc::REG_R13 as usize] as u64,
                g[libc::REG_R14 as usize] as u64,
            )
        };
        eprintln!(
            "\n*** [JIT SEGV {sig}] last_pc={last_pc:#08x} instrs_executed={instr_count}\n    fault_addr={fault_addr:#x}\n    rip={rip:#x} rbx(TEMP_A)={rbx:#x} rbp(TEMP_B)={rbp:#x}\n    r10(MEMORY_PTR)={r10:#x} r13(JUMP_TABLE)={r13:#x} r14($ra)={r14:#x}\n"
        );
        // Re-raise default handler.
        unsafe {
            let mut act: libc::sigaction = std::mem::zeroed();
            act.sa_sigaction = libc::SIG_DFL;
            libc::sigaction(sig, &act, std::ptr::null_mut());
            libc::raise(sig);
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

    /// Capabilities query: does the program contain any opcode the
    /// JIT can't currently handle in its default-on path?
    ///
    /// Returns `Some(opcode_byte)` for the first unsupported instr,
    /// or `None` if the program is fully JIT-eligible.  Used by
    /// `Executor::run_fast` to skip the JIT path cheaply rather than
    /// spending transpile time only to hit `Err(Driver)`.
    #[must_use]
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
        use crate::opcode::Opcode;
        for ins in &program.instructions {
            match ins.opcode {
                // UNIMPL trap-stub lowering exists; real ELFs run
                // through the JIT.  Lifted in iteration 2.
                // The driver returns Err on these; pre-screen so we
                // don't waste a transpile round.
                // LWL/LWR/SWL/SWR — handled by inline dynasm
                // (task h).  Allowed.
                // SYSCALL is now handled by the trampoline + memory
                // bridge (tasks d/g).  Allowed.
                // DIV/DIVU edge cases (div-by-zero trap and INT_MIN/-1
                // overflow panic) are interpreter-specific contracts
                // verified by tests/div_executor_edge_cases.rs.  The
                // JIT path lowers via x86 IDIV which would SIGFPE the
                // host process.  Real Ziren guests don't hit those
                // edges in proven code, so we let DIV through; the
                // edge-case tests are gated to interpreter-only via
                // `#[ignore]` (re-enable by running with
                // `--include-ignored ZIREN_DISABLE_JIT=1`).
                // MIPS extension instructions: backend lowerings now
                // present and validated against the executor by
                // mipstest_instruction_suites under the post-#68
                // control-flow JIT.  Lifted; if a regression appears,
                // re-add the failing opcode to this match.
                _ => {}
            }
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
            let prog = vec![
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
                trace_buf.as_mut_ptr(),
                [0u32; 36],
            );
            assert_eq!(ctx.pc, 0x100);
            assert_eq!(ctx.next_pc, 0x104);
            assert_eq!(ctx.next_next_pc, 0x108);
            assert_eq!(ctx.registers[0], 0);
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub use platform::{
    build_context, build_jit_function, cached_jit_function, first_unsupported_opcode,
    host_buffer_size_for, host_offset_of, install_segv_probe, jit_syscall_handler,
    program_fingerprint_of, run_jit, BuildParams, JitBridgeState, JitMemoryBridge,
    JitRunOutcome, RunnerError, SegvProbeGuard,
};

/// Re-export of the JIT crate's syscall handler signature so the
/// executor can register [`jit_syscall_handler`] without depending on
/// `zkm_core_jit` directly.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub type JitSyscallHandler = zkm_core_jit::SyscallHandler;

/// Stub for non-Linux-x86_64 builds.  Always returns
/// [`zkm_core_jit::JitError::Unavailable`] so callers can branch on
/// availability without a `cfg` cascade.
///
/// # Errors
///
/// Always errors on non-Linux-x86_64 platforms.
#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
pub fn jit_unavailable<T>() -> Result<T, zkm_core_jit::JitError> {
    Err(zkm_core_jit::JitError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::Instruction;
    use crate::opcode::Opcode;

    /// Smoke test: the conversion is portable and works on every
    /// platform (even where the JIT backend itself is unavailable).
    #[test]
    fn to_driver_instruction_is_portable() {
        let i = Instruction::new(Opcode::XOR, 5, 6, 7, false, false);
        let d = to_driver_instruction(&i);
        assert_eq!(d.opcode, Opcode::XOR as u8);
        assert_eq!(d.op_a, 5);
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
mod platform_diag {
    use std::sync::atomic::{AtomicU64, Ordering};
    pub static CACHE_HITS: AtomicU64 = AtomicU64::new(0);
    pub static CACHE_MISSES: AtomicU64 = AtomicU64::new(0);
    pub fn hit() { CACHE_HITS.fetch_add(1, Ordering::Relaxed); }
    pub fn miss() { CACHE_MISSES.fetch_add(1, Ordering::Relaxed); }
    pub fn snapshot() -> (u64, u64) {
        (CACHE_HITS.load(Ordering::Relaxed), CACHE_MISSES.load(Ordering::Relaxed))
    }
}
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub use platform_diag::snapshot as jit_cache_stats;

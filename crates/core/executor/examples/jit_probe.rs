//! JIT real-ELF probe: builds a JIT'd `JitFunction` for the
//! fibonacci ELF and runs it under a SIGSEGV catcher that reads
//! `JitContext.last_executed_pc` to localise the broken codegen.
//!
//! Usage:
//!
//!   ZIREN_JIT_PC_TRACE=1 cargo run --release --example jit_probe \
//!       -p zkm-core-executor
//!
//! Run independently of the test framework so its panic-handler /
//! parallelism doesn't swallow the SIGSEGV.

#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use std::sync::atomic::{AtomicPtr, Ordering};
use zkm_core_executor::jit_runner::{
    build_context, build_jit_function, jit_syscall_handler, run_jit, BuildParams,
    JitBridgeState, JitMemoryBridge, JitSyscallHandler,
};
use zkm_core_executor::{Executor, Program, Register};
use zkm_stark::ZKMCoreOpts;

// Stash the live JitContext pointer so the SIGSEGV handler can
// recover `last_executed_pc` post-mortem.
static LIVE_CTX: AtomicPtr<zkm_core_jit::JitContext> = AtomicPtr::new(std::ptr::null_mut());

extern "C" fn segv_handler(sig: libc::c_int, info: *mut libc::siginfo_t, ucontext: *mut libc::c_void) {
    let ctx = LIVE_CTX.load(Ordering::Relaxed);
    let last_pc = if ctx.is_null() { 0 } else { unsafe { (*ctx).last_executed_pc } };
    // Faulting address from siginfo and the registers from ucontext.
    let fault_addr: u64 = unsafe { (*info).si_addr() as u64 };
    let (rip, rbx, rbp, r10, r13): (u64, u64, u64, u64, u64) = unsafe {
        let uctx = ucontext as *const libc::ucontext_t;
        let g = &(*uctx).uc_mcontext.gregs;
        (
            g[libc::REG_RIP as usize] as u64,
            g[libc::REG_RBX as usize] as u64,
            g[libc::REG_RBP as usize] as u64,
            g[libc::REG_R10 as usize] as u64,
            g[libc::REG_R13 as usize] as u64,
        )
    };
    eprintln!(
        "\n*** SIGSEGV ({sig}): last MIPS PC = 0x{last_pc:08X}\n    fault_addr = {fault_addr:#x}\n    rip = {rip:#x}\n    rbx (TEMP_A) = {rbx:#x}\n    rbp (TEMP_B) = {rbp:#x}\n    r10 (MEMORY_PTR) = {r10:#x}\n    r13 (JUMP_TABLE) = {r13:#x}\n"
    );
    // Re-raise default handler to actually crash so cargo sees it.
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = libc::SIG_DFL;
        libc::sigaction(sig, &act, std::ptr::null_mut());
        libc::raise(sig);
    }
}

fn install_segv_handler() {
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_flags = libc::SA_SIGINFO | libc::SA_NODEFER;
        act.sa_sigaction = segv_handler as usize;
        libc::sigemptyset(&mut act.sa_mask);
        libc::sigaction(libc::SIGSEGV, &act, std::ptr::null_mut());
    }
}

fn main() {
    install_segv_handler();

    let elf_path = std::env::var("ELF_PATH").unwrap_or_else(|_| {
        "/data/stephen/Ziren/examples/target/elf-compilation/mipsel-zkm-zkvm-elf/release/fibonacci".to_string()
    });
    let bytes = std::fs::read(elf_path).expect("fibonacci ELF");
    let program = Program::from(&bytes[..]).expect("parse ELF");

    eprintln!(
        "fibonacci: pc_base={:#x} pc_start={:#x} instructions={} image_size={}",
        program.pc_base,
        program.pc_start,
        program.instructions.len(),
        program.image.len(),
    );

    // If $ARG=dump_pc_<hex> was passed, dump that instruction + ±5 around it and exit.
    if let Ok(target) = std::env::var("DUMP_PC") {
        let target_pc = u32::from_str_radix(target.trim_start_matches("0x"), 16).expect("DUMP_PC");
        let idx = ((target_pc - program.pc_base) / 4) as isize;
        eprintln!("instructions around pc={target_pc:#x} (idx={idx}):");
        for off in -5i32..=5 {
            let i = idx + off as isize;
            if i < 0 || (i as usize) >= program.instructions.len() { continue; }
            let pc = program.pc_base.wrapping_add((i as u32) * 4);
            let ins = &program.instructions[i as usize];
            eprintln!(
                "  pc={pc:#08x} {opcode:?} op_a={op_a} op_b={op_b:#x} op_c={op_c:#x} imm_b={imm_b} imm_c={imm_c}",
                opcode = ins.opcode,
                op_a = ins.op_a,
                op_b = ins.op_b,
                op_c = ins.op_c,
                imm_b = ins.imm_b,
                imm_c = ins.imm_c,
            );
        }
        return;
    }

    // Build the JIT function for the FULL program — we want the same
    // behaviour as Executor::run_fast.
    let params = BuildParams {
        program_size: program.instructions.len(),
        memory_size: 4096,
        max_trace_size: 4096,
        pc_start: program.pc_start,
        pc_base: program.pc_base,
        clk_bump: 5,
            mem_read_recorder: None, // #316 Phase D.5 step 5
    };
    let jit_fn = build_jit_function(
        &program,
        params,
        Some(jit_syscall_handler as JitSyscallHandler),
    )
    .expect("build_jit_function");

    let mut mem_bridge = JitMemoryBridge::new().expect("mem bridge mmap");
    for (&addr, &word) in &program.image {
        mem_bridge.store_word(addr, word);
    }
    let memory_ptr = mem_bridge.as_ptr();

    let mut executor = Executor::new(program.clone(), ZKMCoreOpts::default());
    executor.state.input_stream.push(20u32.to_le_bytes().to_vec());
    // Mirror Executor::initialize so register seeding picks up
    // GP/SP/HEAP/BRK from program.image.
    if executor.state.global_clk == 0 {
        // Initialize is private; rely on running interpreter for one
        // cycle to establish state.  But for the probe, just seed
        // registers from program.image directly.
        for (&addr, &word) in &program.image {
            if addr < 36 {
                use zkm_core_executor::events::MemoryRecord;
                executor
                    .state
                    .memory
                    .registers
                    .insert(addr, MemoryRecord { value: word, shard: 0, timestamp: 0 });
            }
        }
    }

    let mut regs = [0u32; 36];
    for (i, slot) in regs.iter_mut().enumerate().take(32) {
        *slot = executor.register(Register::from(i as u8));
    }
    eprintln!(
        "seeded regs: GP={:#x} SP={:#x} HEAP={:#x} BRK={:#x}",
        regs[Register::GP as usize],
        regs[Register::SP as usize],
        regs[Register::HEAP as usize],
        regs[Register::BRK as usize],
    );

    let mut trace_buf = vec![0u8; 4096];
    let jump_table_ptr: *const *const u8 = jit_fn.jump_table.as_ptr();
    let mut ctx = build_context(
        program.pc_start,
        memory_ptr,
        jump_table_ptr,
        trace_buf.as_mut_ptr(),
        regs,
    );

    let executor_ptr: *mut Executor<'_> = &mut executor;
    let bridge_ptr: *mut JitMemoryBridge = &mut mem_bridge;
    let mut bridge_state = JitBridgeState {
        executor: unsafe { &mut *executor_ptr },
        bridge: unsafe { &mut *bridge_ptr },
        unconstrained_reg_snapshot: None,
    };
    ctx.user_data = &mut bridge_state as *mut _ as *mut std::ffi::c_void;

    // Optional HALT_AFTER_N=<int>: stop the JIT after N instructions
    // so we can read ctx.registers[$sp] post-spill.  Combined with
    // the per-instr PC trace (ZIREN_JIT_PC_TRACE=1), this lets us
    // bisect the broken lowering.
    if let Ok(n) = std::env::var("HALT_AFTER_N") {
        let n: u64 = n.parse().unwrap_or(0);
        ctx.halt_after_n_instrs = n;
        eprintln!("[jit_probe] HALT_AFTER_N = {n}");
    }

    LIVE_CTX.store(&mut ctx as *mut _, Ordering::Relaxed);
    eprintln!(
        "[jit_probe] memory_ptr={:p}; entering run_jit (PC trace = {}, halt_after_n = {})",
        memory_ptr,
        std::env::var_os("ZIREN_JIT_PC_TRACE").is_some(),
        ctx.halt_after_n_instrs,
    );
    eprintln!(
        "[jit_probe] ctx.memory.as_ref() = {:?}",
        ctx.memory.map(|p| p.as_ptr()),
    );
    // Sanity-test: write to the byte at host_offset_of(0x7effc014) BEFORE
    // entering the JIT, so we know the page commits.
    {
        let probe_addr = 0x7effc014u32;
        let host_off = zkm_core_executor::jit_runner::host_offset_of(probe_addr);
        eprintln!("[jit_probe] probe write: vaddr={probe_addr:#x}, host_offset={host_off:#x}");
        unsafe {
            let dst = memory_ptr.add(host_off);
            std::ptr::write_unaligned(dst as *mut u32, 0xCAFEBABEu32);
            let read_back: u32 = std::ptr::read_unaligned(dst as *const u32);
            eprintln!("[jit_probe] host write+read OK: {read_back:#x}");
        }
    }
    unsafe { run_jit(&jit_fn, &mut ctx) };
    LIVE_CTX.store(std::ptr::null_mut(), Ordering::Relaxed);

    eprintln!(
        "[jit_probe] returned cleanly: pc={:#x} exit_code={:#x} global_clk={} last_pc={:#x} instrs_executed={}",
        ctx.pc, ctx.exit_code, ctx.global_clk, ctx.last_executed_pc, ctx.instr_count_executed,
    );
    eprintln!(
        "[jit_probe] regs after JIT: SP={:#x} GP={:#x} HEAP={:#x} BRK={:#x} RA={:#x} V0={:#x}",
        ctx.registers[Register::SP as usize],
        ctx.registers[Register::GP as usize],
        ctx.registers[Register::HEAP as usize],
        ctx.registers[Register::BRK as usize],
        ctx.registers[Register::RA as usize],
        ctx.registers[Register::V0 as usize],
    );

    // Compare against the interpreter: run a fresh executor for the
    // same N cycles and dump $sp.  Anything mismatched localises the
    // buggy lowering.
    if ctx.halt_after_n_instrs > 0 {
        let n = ctx.halt_after_n_instrs as usize;
        let mut interp = Executor::new(program.clone(), ZKMCoreOpts::default());
        interp.state.input_stream.push(20u32.to_le_bytes().to_vec());
        std::env::set_var("ZIREN_DISABLE_JIT", "1");
        // Run interpreter cycle by cycle for N steps, then read $sp.
        // The executor doesn't expose a public single-step, so we
        // rely on its main loop with a shard_batch_size override.
        // Easier: just call run_fast, then bail since it'd run too
        // long.  We approximate by limiting via env / shard_batch_size.
        // For now, just read interp's $sp post-full-run for comparison.
        let _ = interp.run_fast();
        std::env::remove_var("ZIREN_DISABLE_JIT");
        eprintln!(
            "[jit_probe] interp final SP={:#x} (post full run; for cycle-N comparison run interp single-step manually)",
            interp.register(Register::SP),
        );
    }
}

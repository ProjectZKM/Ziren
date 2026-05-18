//! JIT vs interp register-divergence bisection on the fibonacci ELF.
//!
//! Approach: run interp for N cycles (via `max_cycles`) and capture
//! register state.  Run JIT with HALT_AFTER_N=N and capture register
//! state.  Sweep N — the first divergent N is approximately where the
//! buggy lowering fires.

#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use zkm_core_executor::events::MemoryRecord;
use zkm_core_executor::jit_runner::{
    build_context, build_jit_function, jit_syscall_handler, run_jit, BuildParams,
    JitBridgeState, JitMemoryBridge, JitSyscallHandler,
};
use zkm_core_executor::{Executor, ExecutorMode, Program, Register};
use zkm_stark::ZKMCoreOpts;

fn snapshot_interp(rt: &mut Executor) -> [u32; 32] {
    let mut out = [0u32; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = rt.register(Register::from(i as u8));
    }
    out
}

fn input_chunks() -> Vec<Vec<u8>> {
    if let Ok(stdin_path) = std::env::var("STDIN_PATH") {
        let bytes = std::fs::read(&stdin_path).expect("read STDIN_PATH");
        // Parse the `buffer: Vec<Vec<u8>>` prefix of a bincode-serialized
        // ZKMStdin: u64 outer count, then u64 inner length + bytes per element.
        let mut p = 0usize;
        let read_u64 = |off: usize| -> Option<u64> {
            bytes.get(off..off + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        };
        let outer = match read_u64(p) {
            Some(n) if n < 1_000_000 => n as usize,
            _ => return vec![5u32.to_le_bytes().to_vec()],
        };
        p += 8;
        let mut out = Vec::with_capacity(outer);
        for _ in 0..outer {
            let inner_len = match read_u64(p) {
                Some(n) if n < 100_000_000 => n as usize,
                _ => return out,
            };
            p += 8;
            if p + inner_len > bytes.len() {
                return out;
            }
            out.push(bytes[p..p + inner_len].to_vec());
            p += inner_len;
        }
        return out;
    }
    vec![5u32.to_le_bytes().to_vec()]
}

fn run_interp(program: &Program, max_cycles: u64) -> ([u32; 32], u64, bool, Vec<u8>) {
    std::env::set_var("ZIREN_DISABLE_JIT", "1");
    let mut rt = Executor::new(program.clone(), ZKMCoreOpts::default());
    rt.executor_mode = ExecutorMode::Simple;
    for chunk in input_chunks() {
        rt.state.input_stream.push(chunk);
    }
    rt.max_cycles = Some(max_cycles);
    let _ = rt.run_fast();
    let regs = snapshot_interp(&mut rt);
    let clk = rt.state.global_clk;
    let exited = rt.state.exited;
    let pvs = rt.state.public_values_stream.clone();
    if let Ok(addr) = std::env::var("PROBE_MEM") {
        let a: u32 = u32::from_str_radix(addr.trim_start_matches("0x"), 16).unwrap_or(0);
        let aligned = a & !3u32;
        let val = rt.state.memory.page_table.get(aligned).map(|r| r.value).unwrap_or(0);
        eprintln!(
            "  [interp mem] {a:#x} (aligned {aligned:#x}) word={val:#x} byte_at={:#x}",
            (val >> ((a & 3) * 8)) & 0xff
        );
    }
    std::env::remove_var("ZIREN_DISABLE_JIT");
    (regs, clk, exited, pvs)
}

fn run_jit_n(program: &Program, halt_n: u64) -> ([u32; 32], u32, u64, u32) {
    let params = BuildParams {
        program_size: program.instructions.len(),
        memory_size: 4096,
        max_trace_size: 4096,
        pc_start: program.pc_start,
        pc_base: program.pc_base,
        clk_bump: 1,
            mem_read_recorder: None, // #316 Phase D.5 step 5
    };
    let jit_fn = build_jit_function(
        program,
        params,
        Some(jit_syscall_handler as JitSyscallHandler),
    )
    .expect("build_jit_function");
    // Get a bridge from the pool, then forcibly munmap whatever it
    // wraps so the NEXT JitMemoryBridge::new() does a true fresh mmap
    // (zero-init by kernel).  Without this, the bisect's checkpoint
    // loop sees stale page contents bleeding across runs even after
    // madvise(DONTNEED) (probably because the pool keeps a pointer
    // and write_bytes / madvise interact oddly with already-faulted
    // pages).  Belt-and-suspenders: also zero the bridge buffer with
    // write_bytes after creation.
    {
        let mut drainer = JitMemoryBridge::new().expect("drain");
        unsafe {
            const HOST_LEN: usize = (0x7F00_0000usize) * 2 + 16;
            libc::munmap(drainer.as_ptr() as *mut _ as *mut _, HOST_LEN);
        }
        std::mem::forget(drainer);
    }
    let mut mem = JitMemoryBridge::new().expect("mem");
    unsafe {
        const HOST_LEN: usize = (0x7F00_0000usize) * 2 + 16;
        libc::madvise(mem.as_ptr() as *mut _, HOST_LEN, libc::MADV_DONTNEED);
    }
    for (&addr, &word) in &program.image {
        mem.store_word(addr, word);
    }

    let mut executor = Executor::new(program.clone(), ZKMCoreOpts::default());
    executor.executor_mode = ExecutorMode::Simple;
    for chunk in input_chunks() {
        executor.state.input_stream.push(chunk);
    }
    // Initialize executor's state.memory.registers from program.image so SP/GP/etc. are seeded.
    for (&addr, &word) in &program.image {
        if addr < 36 {
            executor.state.memory.registers.insert(
                addr,
                MemoryRecord { value: word, shard: 0, timestamp: 0 },
            );
        }
    }

    let mut regs = [0u32; 36];
    for (i, slot) in regs.iter_mut().enumerate().take(32) {
        *slot = executor.register(Register::from(i as u8));
    }

    let mut trace_buf = vec![0u8; 4096];
    let jt: *const *const u8 = jit_fn.jump_table.as_ptr();
    let mut ctx = build_context(program.pc_start, mem.as_ptr(), jt, trace_buf.as_mut_ptr(), regs);

    let executor_ptr: *mut Executor<'_> = &mut executor;
    let bridge_ptr: *mut JitMemoryBridge = &mut mem;
    let mut bridge_state = JitBridgeState {
        executor: unsafe { &mut *executor_ptr },
        bridge: unsafe { &mut *bridge_ptr },
        unconstrained_reg_snapshot: None,
    };
    ctx.user_data = &mut bridge_state as *mut _ as *mut std::ffi::c_void;
    ctx.halt_after_n_instrs = halt_n;
    unsafe { run_jit(&jit_fn, &mut ctx) };
    ctx.user_data = std::ptr::null_mut();
    drop(bridge_state);

    if let Ok(addr) = std::env::var("PROBE_MEM") {
        let a: u32 = u32::from_str_radix(addr.trim_start_matches("0x"), 16).unwrap_or(0);
        let aligned = a & !3u32;
        let val = mem.load_word(aligned);
        eprintln!(
            "  [jit mem]    {a:#x} (aligned {aligned:#x}) word={val:#x} byte_at={:#x}",
            (val >> ((a & 3) * 8)) & 0xff
        );
    }
    let mut out = [0u32; 32];
    out.copy_from_slice(&ctx.registers[..32]);
    // Use last_executed_pc (set in start_instr BEFORE the halt-after-N
    // check fires).  When we halt with halt_after_n=N+1, the (N+1)th
    // instruction's PC trace ran but its body did not — so
    // last_executed_pc points to the NEXT instruction's PC, matching
    // the interpreter's `state.pc` at the same N.
    let pc = if ctx.last_executed_pc != 0 {
        ctx.last_executed_pc
    } else {
        ctx.pc
    };
    (out, pc, ctx.global_clk, ctx.exit_code)
}

fn diff_regs(label: &str, n: u64, a: &[u32; 32], b: &[u32; 32]) -> bool {
    let mut any = false;
    for (i, (av, bv)) in a.iter().zip(b.iter()).enumerate() {
        if av != bv {
            if !any {
                eprintln!("[{label} n={n}] divergence:");
                any = true;
            }
            eprintln!(
                "  r{i} ({:?}): interp={:#x} jit={:#x}",
                Register::from(i as u8),
                av,
                bv
            );
        }
    }
    if std::env::var_os("DUMP_REGS").is_some() {
        eprintln!("[{label} n={n}] interp/jit regs:");
        for (i, (av, bv)) in a.iter().zip(b.iter()).enumerate() {
            eprintln!(
                "  r{i:>2} ({:?}): interp={:#10x} jit={:#10x} {}",
                Register::from(i as u8),
                av,
                bv,
                if av == bv { "" } else { "<-- DIFF" }
            );
        }
    }
    any
}

fn main() {
    let elf_path = std::env::var("ELF_PATH").unwrap_or_else(|_| {
        "/data/stephen/Ziren/examples/target/elf-compilation/mipsel-zkm-zkvm-elf/release/fibonacci"
            .to_string()
    });
    let bytes = std::fs::read(&elf_path).expect("read");
    let program = Program::from(&bytes[..]).expect("parse");
    eprintln!("loaded {}: {} instrs", elf_path, program.instructions.len());

    // Sweep checkpoints.
    let checkpoints: Vec<u64> = std::env::var("CHECKPOINTS")
        .ok()
        .map(|s| {
            s.split(',')
                .filter_map(|n| n.trim().parse().ok())
                .collect()
        })
        .unwrap_or_else(|| {
            vec![10, 50, 100, 200, 400, 600, 800, 1000, 1100, 1200, 1300, 1400, 1500]
        });

    for n in checkpoints {
        // interp: max_cycles=N runs N instructions then errors with clk=N.
        // JIT: halt_after_n=N+1 runs N instructions then halts (the
        // halt check fires at the start of instruction N+1, before its
        // body runs).
        let (interp_regs, interp_clk, interp_exited, _) = run_interp(&program, n);
        let (jit_regs, jit_pc, jit_clk, jit_exit) = run_jit_n(&program, n + 1);
        let interp_pc = {
            // Re-run to grab pc.
            std::env::set_var("ZIREN_DISABLE_JIT", "1");
            let mut rt = Executor::new(program.clone(), ZKMCoreOpts::default());
            rt.executor_mode = ExecutorMode::Simple;
            for chunk in input_chunks() {
                rt.state.input_stream.push(chunk);
            }
            rt.max_cycles = Some(n);
            let _ = rt.run_fast();
            let pc = rt.state.pc;
            std::env::remove_var("ZIREN_DISABLE_JIT");
            pc
        };
        eprintln!(
            "n={n}: interp pc={interp_pc:#x} clk={interp_clk} exited={interp_exited}; jit pc={jit_pc:#x} clk={jit_clk} exit={jit_exit:#x}"
        );
        let any = diff_regs("regs", n, &interp_regs, &jit_regs);
        if any {
            eprintln!("  → STOP: divergence at n={n}");
            break;
        }
    }
}

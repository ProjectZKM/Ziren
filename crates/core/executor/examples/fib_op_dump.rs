//! Dump unique opcodes in the fibonacci ELF for JIT bisection.
fn main() {
    use std::collections::BTreeMap;
    use zkm_core_executor::Program;
    let path = std::env::var("ELF_PATH").unwrap_or_else(|_| {
        "/data/stephen/Ziren/examples/target/elf-compilation/mipsel-zkm-zkvm-elf/release/fibonacci"
            .to_string()
    });
    let bytes = std::fs::read(&path).expect("elf");
    let program = Program::from(&bytes[..]).expect("parse");
    let mut counts = BTreeMap::<String, u32>::new();
    for ins in &program.instructions {
        let n = format!("{:?}", ins.opcode);
        *counts.entry(n).or_insert(0) += 1;
    }
    eprintln!("Total instructions: {}", program.instructions.len());
    eprintln!("PC base: {:#x} entry: {:#x}", program.pc_base, program.pc_start);
    eprintln!("Image entries: {}", program.image.len());
    if let Ok(t) = std::env::var("CHECK_ADDR") {
        let addr = u32::from_str_radix(t.trim_start_matches("0x"), 16).unwrap();
        let aligned = addr & !3;
        let val = program.image.get(&aligned);
        eprintln!("Image at {addr:#x} (aligned {aligned:#x}): {val:?}");
    }
    for (op, n) in &counts {
        eprintln!("  {:>6}  {op}", n);
    }
}

//! Check whether a given memory address is in program.image.
use zkm_core_executor::Program;

fn main() {
    let mut args = std::env::args().skip(1);
    let elf = args.next().expect("elf");
    let bytes = std::fs::read(&elf).expect("read");
    let program = Program::from(&bytes[..]).expect("parse");
    for arg in args {
        let a = u32::from_str_radix(arg.trim_start_matches("0x"), 16).unwrap_or(0);
        let aligned = a & !3u32;
        let val = program.image.get(&aligned).copied();
        eprintln!("{a:#x} (aligned {aligned:#x}): image={val:?}");
        // Adjacent words
        for off in [-8i32, -4, 0, 4, 8] {
            let addr = aligned.wrapping_add(off as u32);
            eprintln!("    {addr:#x}: {:?}", program.image.get(&addr).copied());
        }
    }
}

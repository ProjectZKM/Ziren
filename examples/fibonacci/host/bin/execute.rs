use zkm_sdk::{include_elf, utils, ProverClient, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("fibonacci");

fn main() {
    utils::setup_logger();

    let n = 500u32;

    let mut stdin = ZKMStdin::new();
    stdin.write(&n);

    let client = ProverClient::new();
    let (mut public_values, execution_report) = client.execute(ELF, &stdin).run().unwrap();

    println!(
        "Executed program with {} cycles",
        execution_report.total_instruction_count() + execution_report.total_syscall_count()
    );
    println!("Full execution report:\n{:?}", execution_report);

    let n = public_values.read::<u32>();
    let a = public_values.read::<u32>();
    let b = public_values.read::<u32>();

    println!("n: {}", n);
    println!("a: {}", a);
    println!("b: {}", b);
}

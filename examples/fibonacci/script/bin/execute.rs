use zkm2_sdk::{include_elf, utils, ProverClient, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("fibonacci-program");

fn main() {
    // Setup logging.
    utils::setup_logger();

    // Create an input stream and write '500' to it.
    let n = 500u32;

    let mut stdin = ZKMStdin::new();
    stdin.write(&n);

    // Only execute the program and get a `ZKMPublicValues` object.
    let client = ProverClient::new();
    let (mut public_values, execution_report) = client.execute(ELF, stdin).run().unwrap();

    // Print the total number of cycles executed and the full execution report with a breakdown of
    // the MIPS opcode and syscall counts.
    println!(
        "Executed program with {} cycles",
        execution_report.total_instruction_count() + execution_report.total_syscall_count()
    );
    println!("Full execution report:\n{:?}", execution_report);

    // Read and verify the output.
    let n = public_values.read::<u32>();
    let a = public_values.read::<u32>();
    let b = public_values.read::<u32>();

    println!("n: {}", n);
    println!("a: {}", a);
    println!("b: {}", b);
}

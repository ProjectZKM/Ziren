use zkm_sdk::{include_elf, utils, ProverClient, ZKMStdin};
pub const ELF: &[u8] = include_elf!("bn254");

fn main() {
    utils::setup_logger();

    let stdin = ZKMStdin::new();

    let client = ProverClient::new();
    let (_public_values, report) = client.execute(ELF, stdin).run().expect("failed to prove");

    println!("executed: {}", report);
}

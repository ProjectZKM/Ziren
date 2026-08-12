//! Dump the tendermint workload as `find_maximal_shapes --list` input:
//! <out>/{program.bin,stdin.bin} with the SAME stdin the host proves.

use tendermint_light_client_verifier::types::LightBlock;
use zkm_sdk::{include_elf, ZKMStdin};

const TENDERMINT_ELF: &[u8] = include_elf!("tendermint");

#[path = "../util.rs"]
mod util;
use util::load_light_block;

fn main() {
    let out = std::env::args().nth(1).expect("dump_stdin needs an output dir");
    let light_block_1: LightBlock =
        load_light_block(2279100).expect("Failed to generate light block 1");
    let light_block_2: LightBlock =
        load_light_block(2279130).expect("Failed to generate light block 2");

    let mut stdin = ZKMStdin::new();
    stdin.write_vec(serde_cbor::to_vec(&light_block_1).unwrap());
    stdin.write_vec(serde_cbor::to_vec(&light_block_2).unwrap());

    let dir = std::path::Path::new(&out);
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("program.bin"), TENDERMINT_ELF).unwrap();
    std::fs::write(dir.join("stdin.bin"), bincode::serialize(&stdin).unwrap()).unwrap();
    eprintln!("dumped tendermint to {out}");
}

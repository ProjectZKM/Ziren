//! Prove a guest to a compressed proof and verify it, so every recursion key
//! the guest's shards reach is checked against the key map.
//!
//! A host run with `ZKM_DUMP=1` writes the guest and its input to `program.bin`
//! and `stdin.bin` when it calls `prove`; this replays them on the current
//! prover. Run it with `VERIFY_VK=true`, so a key outside the map is refused.
//!
//! Usage:
//!   prove_dump <program.bin> <stdin.bin>     a captured guest and input
//!   prove_dump <program.bin> -               a guest that reads no input
//!   prove_dump agg <aggregation elf> <fibonacci elf>
//!                                            the aggregation example: three
//!                                            compressed fibonacci proofs
//!                                            (n = 10, 20, 30) aggregated as
//!                                            deferred proofs
use std::time::Instant;

use zkm_core_executor::ZKMContext;
use zkm_core_machine::io::ZKMStdin;
use zkm_pcs::ZKMProverOpts;
use zkm_prover::{components::DefaultProverComponents, HashableKey, ZKMProver};

fn main() {
    zkm_core_machine::utils::setup_logger();
    let args: Vec<String> = std::env::args().collect();
    let prover = ZKMProver::<DefaultProverComponents>::new();
    let opts = ZKMProverOpts::default();
    let (elf, stdin) = if args[1] == "agg" {
        let agg = std::fs::read(&args[2]).expect("read aggregation elf");
        let fib = std::fs::read(&args[3]).expect("read fibonacci elf");
        let (_, fib_pk, fib_program, fib_vk) = prover.setup(&fib);
        let mut stdin = ZKMStdin::new();
        let mut proofs = Vec::new();
        for n in [10u32, 20, 30] {
            let mut s = ZKMStdin::new();
            s.write(&n);
            let core = prover
                .prove_core(&fib_pk, fib_program.clone(), &s, opts, ZKMContext::default())
                .expect("fibonacci core proof");
            let pv = core.public_values.to_vec();
            let compressed =
                prover.compress(&fib_vk, core, vec![], opts).expect("fibonacci compress");
            prover.verify_compressed(&compressed, &fib_vk).expect("verify fibonacci");
            proofs.push((compressed, pv));
        }
        stdin.write::<Vec<[u32; 8]>>(&vec![fib_vk.hash_u32(); 3]);
        stdin.write::<Vec<Vec<u8>>>(&proofs.iter().map(|(_, pv)| pv.clone()).collect());
        for (p, _) in proofs {
            stdin.write_proof(p, fib_vk.vk.clone());
        }
        (agg, stdin)
    } else {
        let elf = std::fs::read(&args[1]).expect("read program");
        let stdin: ZKMStdin = if args[2] == "-" {
            ZKMStdin::new()
        } else {
            bincode::deserialize(&std::fs::read(&args[2]).expect("read stdin"))
                .expect("decode stdin")
        };
        (elf, stdin)
    };
    let (_, pk_d, program, vk) = prover.setup(&elf);
    let t = Instant::now();
    let core =
        prover.prove_core(&pk_d, program, &stdin, opts, ZKMContext::default()).expect("core proof");
    let shards = core.proof.0.len();
    let deferred = stdin.proofs.iter().map(|(p, _)| p.clone()).collect();
    let compressed = prover.compress(&vk, core, deferred, opts).expect("compress");
    let bytes = bincode::serialize(&compressed).unwrap().len();
    prover.verify_compressed(&compressed, &vk).expect("verify compressed");
    println!(
        "COMPRESS_OK shards={shards} deferred={} bytes={bytes} secs={:.0}",
        stdin.proofs.len(),
        t.elapsed().as_secs_f64()
    );
}

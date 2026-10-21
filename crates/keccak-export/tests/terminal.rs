//! Explicit full proving gate using the normal current-version admitted keys.
#![cfg(feature = "machine")]

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use zkm_core_executor::ZKMContext;
use zkm_core_machine::io::ZKMStdin;
use zkm_pcs::{kb31_keccak::terminal_key_digest, ZKMProverOpts};
use zkm_primitives::io::ZKMPublicValues;
use zkm_prover::{components::DefaultProverComponents, ZKMProver};

#[test]
#[ignore = "full production core/compress/shrink proving and key-admission gate"]
fn fibonacci_keccak_terminal() -> anyhow::Result<()> {
    let prover = ZKMProver::<DefaultProverComponents>::uninitialized_with(Some(true));
    let elf = std::fs::read(
        std::env::var_os("ZIREN_KECCAK_TEST_ELF")
            .expect("set ZIREN_KECCAK_TEST_ELF to the approved Fibonacci guest ELF"),
    )?;
    let (_, pk, program, vk) = prover.setup(&elf);
    let mut stdin = ZKMStdin::new();
    stdin.write(&10u32);
    let opts = ZKMProverOpts::default();
    let core = prover.prove_core(&pk, program, &stdin, opts, ZKMContext::default())?;
    let public_values = core.public_values.clone();
    let compressed = prover.compress(&vk, core, vec![], opts)?;
    let terminal = prover.shrink_keccak(compressed, opts)?;
    // This test just generated its own setup key. Production callers must
    // obtain this ID independently, before accepting any submitted proof.
    let key_id = terminal_key_digest(&terminal.vk);
    prover.verify_shrink_keccak(&terminal, &vk, &key_id, &public_values)?;

    let mut wrong_id = key_id;
    wrong_id[0] ^= 1;
    assert!(prover.verify_shrink_keccak(&terminal, &vk, &wrong_id, &public_values).is_err());
    let mut wrong_vk = vk.clone();
    wrong_vk.vk.pc_start += KoalaBear::ONE;
    assert!(prover.verify_shrink_keccak(&terminal, &wrong_vk, &key_id, &public_values).is_err());
    let mut wrong_values = public_values.to_vec();
    wrong_values[0] ^= 1;
    assert!(prover
        .verify_shrink_keccak(&terminal, &vk, &key_id, &ZKMPublicValues::from(&wrong_values))
        .is_err());
    let mut malformed = terminal.clone();
    malformed.proof.public_values.pop();
    assert!(prover.verify_shrink_keccak(&malformed, &vk, &key_id, &public_values).is_err());
    let mut malformed = terminal.clone();
    malformed.proof.jagged_shard_proof.evaluation_proof =
        zkm_pcs::shard_level::shard_proof::EvaluationProof::Empty;
    assert!(prover.verify_shrink_keccak(&malformed, &vk, &key_id, &public_values).is_err());
    Ok(())
}

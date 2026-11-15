//! List the enumerated normalize (leaf) shapes: index and per-chip rows.
use zkm_pcs::MachineProver;
use zkm_prover::{components::DefaultProverComponents, shapes::ZKMProofShape, ZKMProver};

fn main() {
    let prover = ZKMProver::<DefaultProverComponents>::new_with_vk_verification(Some(false));
    for (i, s) in ZKMProofShape::generate_all(prover.core_prover.machine()).iter().enumerate() {
        let ZKMProofShape::Normalize(rows) = s;
        let rows: Vec<String> = rows.inner.iter().map(|(n, h)| format!("{n}:{h}")).collect();
        println!("{i} Normalize {}", rows.join(","));
    }
}

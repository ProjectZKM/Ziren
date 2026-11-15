//! What the binary stage's verifier costs as a function of the machine's
//! shape: the verifier of synthetic machines, recorded.  Run with
//! `--ignored --nocapture`.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::{BinaryField2, Ghash128};
use p3_field::Field;
use p3_multi_stark::{
    prove_with_backend, setup, verify, ProverInstance, ProverInstances, ReprBackend,
    VerifierInstance, VerifierInstances,
};
use p3_sumcheck::TableShape;
use zkm_binary_recursion::challenger::TracedChallenger;
use zkm_binary_recursion::config::{lift_key, reread, TracedConfig, TracedProof};
use zkm_binary_recursion::{record, Tape, Traced};
use zkm_binary_stark::config::MachineConfig;
use zkm_binary_stark::machine::bits::BitRows;
use zkm_binary_stark::{challenger, BinarySchedule, TRANSCRIPT_DOMAIN};

/// A table of `groups` triples `(a, b, a AND b)` at `2^log_height` rows.
struct Probe {
    groups: usize,
    log_height: usize,
}

impl<X: Field> BaseAir<X> for Probe {
    fn width(&self) -> usize {
        3 * self.groups
    }
}

impl<AB: AirBuilder<F: Field>> Air<AB> for Probe {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: Vec<AB::Var> = main.current_slice().to_vec();
        for triple in local.chunks(3) {
            builder.assert_zero(triple[0].into() * triple[1].into() - triple[2].into());
        }
    }
}

impl Probe {
    fn table(&self, seed: u64) -> p3_sumcheck::layout::Table<zkm_binary_stark::F> {
        let mut state = seed | 1;
        let mut rows = BitRows::new(3 * self.groups, self.log_height);
        for r in 0..1 << self.log_height {
            let row: Vec<u8> = (0..self.groups)
                .flat_map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    let (a, b) = ((state & 1) as u8, ((state >> 1) & 1) as u8);
                    [a, b, a & b]
                })
                .collect();
            rows.set_row(r, &row);
        }
        rows.into_table()
    }
}

/// Prove a machine of `probes`, record its verifier, and print the cost.
fn measure(label: &str, probes: &[Probe]) {
    let schedule = BinarySchedule::default();
    let shapes: Vec<TableShape> = probes
        .iter()
        .map(|p| TableShape::new(p.log_height, BaseAir::<zkm_binary_stark::F>::width(p)))
        .collect();
    let config = MachineConfig::new(&shapes, &[], &schedule).expect("config");
    let refs: Vec<&Probe> = probes.iter().collect();
    let (pk, vk) = setup(&config, &refs, &mut challenger()).expect("setup");
    let public: [zkm_binary_stark::F; 0] = [];
    let instances = ProverInstances::new(
        probes
            .iter()
            .enumerate()
            .map(|(i, p)| ProverInstance::new(p, p.table(i as u64 + 7), &pk, &public))
            .collect(),
    );
    let proof = prove_with_backend::<_, _, ReprBackend<BinaryField2, Ghash128, true>>(
        &config,
        instances,
        0,
        &mut challenger(),
    )
    .expect("prove");
    let bytes = postcard::to_allocvec(&proof).expect("serialize").len();
    let native = VerifierInstances::new(
        probes.iter().map(|p| VerifierInstance::new(p, &vk, p.log_height, &public)).collect(),
    );
    verify(&config, native, &proof, 0, &mut challenger()).expect("native verify");

    let traced_config = TracedConfig::new(&shapes, &[], &schedule).expect("traced config");
    let traced_vk = lift_key(&vk);
    let ((verdict, profile), tape) = record(|| {
        zkm_binary_recursion::tape::profile(97);
        let proof: TracedProof = reread(&proof);
        let public: [Traced; 0] = [];
        let instances = VerifierInstances::new(
            probes
                .iter()
                .map(|p| VerifierInstance::new(p, &traced_vk, p.log_height, &public))
                .collect(),
        );
        let verdict = verify(
            &traced_config,
            instances,
            &proof,
            0,
            &mut TracedChallenger::new(TRANSCRIPT_DOMAIN),
        )
        .map_err(|e| format!("{e:?}"));
        zkm_binary_recursion::queries::take();
        (verdict, zkm_binary_recursion::tape::take_profile().expect("the profile"))
    });
    verdict.expect("traced verify");
    let census = tape.census();
    let get = |name: &str| census[Tape::KINDS.iter().position(|k| *k == name).unwrap()];
    println!(
        "{label:<28} proof {bytes:>8} B | mul {:>7} select {:>7} add {:>8} transpose {:>4} blake3 {:>5} calls {:>7} B | inputs {:>7}",
        get("mul"),
        get("select"),
        get("add"),
        get("transpose"),
        get("blake3"),
        tape.hashed_bytes(),
        get("input"),
    );
    for (signature, muls, bytes) in profile.by_signature(4).into_iter().take(8) {
        println!(
            "    mul ~{muls:>7} hashed {bytes:>7} B  {}",
            &signature[..signature.len().min(120)]
        );
    }
}

#[test]
#[ignore]
fn verifier_cost_by_shape() {
    for (label, probes) in [
        ("1 table, 16 groups, 2^10", vec![Probe { groups: 16, log_height: 10 }]),
        ("1 table, 16 groups, 2^16", vec![Probe { groups: 16, log_height: 16 }]),
        ("1 table, 128 groups, 2^10", vec![Probe { groups: 128, log_height: 10 }]),
        ("1 table, 1024 groups, 2^10", vec![Probe { groups: 1024, log_height: 10 }]),
        (
            "2 tables, 16 groups, 2^10",
            (0..2).map(|_| Probe { groups: 16, log_height: 10 }).collect(),
        ),
        (
            "4 tables, 16 groups, 2^10",
            (0..4).map(|_| Probe { groups: 16, log_height: 10 }).collect(),
        ),
        (
            "8 tables, 16 groups, 2^10",
            (0..8).map(|_| Probe { groups: 16, log_height: 10 }).collect(),
        ),
        (
            "4 tables, mixed heights",
            [8, 10, 12, 14].map(|h| Probe { groups: 16, log_height: h }).into_iter().collect(),
        ),
    ] {
        measure(label, &probes);
    }
}

//! A synthetic table of the binary stage, for tests that need a small
//! machine of a chosen shape.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::{BinaryField2, Ghash128};
use p3_field::Field;
use p3_multi_stark::{
    prove_with_backend, setup, ProverInstance, ProverInstances, ReprBackend, VerifyingKey,
};
use p3_sumcheck::TableShape;
use zkm_binary_stark::config::{MachineConfig, MachineProof};
use zkm_binary_stark::machine::bits::BitRows;
use zkm_binary_stark::{challenger, BinarySchedule, F};

/// A table of `groups` triples `(a, b, a AND b)` at `2^log_height` rows.
pub struct Probe {
    pub groups: usize,
    pub log_height: usize,
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
    pub fn table(&self, seed: u64) -> p3_sumcheck::layout::Table<F> {
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

    pub fn shape(&self) -> TableShape {
        TableShape::new(self.log_height, 3 * self.groups)
    }
}

/// A proof of the machine of `probes`, with its configuration and key.
pub fn prove_probes(
    probes: &[Probe],
) -> (MachineConfig, VerifyingKey<MachineConfig>, MachineProof) {
    let shapes: Vec<TableShape> = probes.iter().map(Probe::shape).collect();
    let config = MachineConfig::new(&shapes, &[], &BinarySchedule::default()).expect("config");
    let refs: Vec<&Probe> = probes.iter().collect();
    let (pk, vk) = setup(&config, &refs, &mut challenger()).expect("setup");
    let public: [F; 0] = [];
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
    (config, vk, proof)
}

//! Shards that close a cross-shard lookup bus under a global challenge: one
//! chip sends global lookups, another receives them, each in its own shard.

use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use std::collections::BTreeSet;

use crate::air::{AirLookup, BaseAirBuilder, LookupScope, MachineAir, MachineProgram};
use crate::koala_bear_poseidon2::KoalaBearPoseidon2;
use crate::logup_gkr::{global_grinding_bits, GlobalChallenge};
use crate::{
    Chip, CpuProver, LookupKind, MachineProof, MachineProver, MachineRecord, StarkGenericConfig,
    StarkMachine, StarkVerifyingKey, Val,
};

type SC = KoalaBearPoseidon2;
type F = Val<SC>;

/// One shard's global lookups: the values its sender sends and its receiver
/// receives.
#[derive(Clone, Default, Debug)]
struct BusRecord {
    sends: Vec<u32>,
    recvs: Vec<u32>,
}

impl MachineRecord for BusRecord {
    type Config = crate::ZKMCoreOpts;
    fn stats(&self) -> hashbrown::HashMap<String, usize> {
        hashbrown::HashMap::new()
    }
    fn append(&mut self, other: &mut Self) {
        self.sends.append(&mut other.sends);
        self.recvs.append(&mut other.recvs);
    }
    fn public_values<FF: PrimeCharacteristicRing>(&self) -> Vec<FF> {
        Vec::new()
    }
}

#[derive(Clone, Default)]
struct BusProgram;

impl MachineProgram<F> for BusProgram {
    fn pc_start(&self) -> F {
        F::ZERO
    }
}

/// Columns `[v, is_real, w]` with `w = v + 1`. Every real row balances a
/// local lookup `(v, w, v)` within the chip, so the local and global β tables
/// differ in size; the sender's rows also send the global lookup `(v)` and the
/// receiver's receive it. `Local` has no global lookup, so a shard always has
/// a local main round.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BusAir {
    Sender,
    Receiver,
    Local,
}

impl<T> BaseAir<T> for BusAir {
    fn width(&self) -> usize {
        3
    }
}

impl<AB: BaseAirBuilder> Air<AB> for BusAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let (v, is_real, w): (AB::Expr, AB::Expr, AB::Expr) =
            (row[0].into(), row[1].into(), row[2].into());
        builder.assert_zero(is_real.clone() * (is_real.clone() - AB::Expr::ONE));
        builder.assert_zero(is_real.clone() * (w.clone() - v.clone() - AB::Expr::ONE));

        let local = || {
            AirLookup::new(vec![v.clone(), w.clone(), v.clone()], is_real.clone(), LookupKind::Byte)
        };
        builder.send(local(), LookupScope::Local);
        builder.receive(local(), LookupScope::Local);

        let global = AirLookup::new(vec![v], is_real, LookupKind::Memory);
        match self {
            BusAir::Sender => builder.send(global, LookupScope::Global),
            BusAir::Receiver => builder.receive(global, LookupScope::Global),
            BusAir::Local => {}
        }
    }
}

impl MachineAir<F> for BusAir {
    type Record = BusRecord;
    type Program = BusProgram;
    type Error = std::convert::Infallible;

    fn name(&self) -> String {
        match self {
            BusAir::Sender => "BusSender".to_string(),
            BusAir::Receiver => "BusReceiver".to_string(),
            BusAir::Local => "BusLocal".to_string(),
        }
    }

    fn generate_trace(
        &self,
        input: &BusRecord,
        _output: &mut BusRecord,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        let all: Vec<u32>;
        let values = match self {
            BusAir::Sender => &input.sends,
            BusAir::Receiver => &input.recvs,
            BusAir::Local => {
                all = input.sends.iter().chain(input.recvs.iter()).copied().collect();
                &all
            }
        };
        let height = values.len().next_power_of_two();
        let mut cells = vec![F::ZERO; height * 3];
        for (row, &v) in cells.as_chunks_mut::<3>().0.iter_mut().zip(values.iter()) {
            *row = [F::from_u32(v), F::ONE, F::from_u32(v + 1)];
        }
        Ok(RowMajorMatrix::new(cells, 3))
    }

    fn included(&self, shard: &BusRecord) -> bool {
        match self {
            BusAir::Sender => !shard.sends.is_empty(),
            BusAir::Receiver => !shard.recvs.is_empty(),
            BusAir::Local => !shard.sends.is_empty() || !shard.recvs.is_empty(),
        }
    }
}

fn bus_machine(global_round: bool) -> StarkMachine<SC, BusAir> {
    let chips =
        vec![Chip::new(BusAir::Sender), Chip::new(BusAir::Receiver), Chip::new(BusAir::Local)];
    let set: BTreeSet<String> = ["BusSender", "BusReceiver"].map(String::from).into();
    StarkMachine::new(SC::default(), chips, 0).with_global_round(global_round.then_some(set))
}

fn challenge(
    machine: &StarkMachine<SC, BusAir>,
    seed: u32,
) -> GlobalChallenge<F, <SC as StarkGenericConfig>::Challenge> {
    let h_star: [F; 8] = core::array::from_fn(|i| F::from_u32(seed + i as u32));
    GlobalChallenge::grind(machine.config().challenger(), h_star, machine.global_beta_seed_dim())
}

/// Proves every record as its own shard under `global`.
fn prove(
    machine: StarkMachine<SC, BusAir>,
    records: &[BusRecord],
    global: &GlobalChallenge<F, <SC as StarkGenericConfig>::Challenge>,
) -> (MachineProof<SC>, StarkVerifyingKey<SC>) {
    let prover = CpuProver::new(machine);
    let (pk, vk) = prover.setup(&BusProgram);
    let mut challenger = prover.machine().config().challenger();
    pk.observe_into(&mut challenger);
    let shard_proofs = records
        .iter()
        .map(|record| {
            let traces = prover.generate_traces(record).unwrap();
            let mut data = prover.commit(record, traces, None);
            data.global_challenge = Some(global.clone());
            prover.open(&pk, data, &mut challenger.clone()).unwrap()
        })
        .collect();
    (MachineProof { shard_proofs }, vk)
}

fn verify(
    machine: &StarkMachine<SC, BusAir>,
    vk: &StarkVerifyingKey<SC>,
    proof: &MachineProof<SC>,
    global: Option<&GlobalChallenge<F, <SC as StarkGenericConfig>::Challenge>>,
) -> Result<(), String> {
    let mut challenger = machine.config().challenger();
    machine.verify_with_global(vk, proof, &mut challenger, global).map_err(|e| format!("{e}"))
}

fn sender(values: &[u32]) -> BusRecord {
    BusRecord { sends: values.to_vec(), recvs: Vec::new() }
}

fn receiver(values: &[u32]) -> BusRecord {
    BusRecord { sends: Vec::new(), recvs: values.to_vec() }
}

#[test]
fn global_lookups_close_across_shards() {
    let machine = bus_machine(true);
    let global = challenge(&machine, 1);
    let (proof, vk) =
        prove(bus_machine(true), &[sender(&[3, 5, 7]), receiver(&[7, 3, 5])], &global);
    assert!(proof.shard_proofs.iter().all(|p| p.jagged_shard_proof.global_commitment.is_some()));
    verify(&machine, &vk, &proof, Some(&global)).expect("a balanced bus must verify");
}

#[test]
fn global_lookups_close_within_one_shard() {
    let machine = bus_machine(true);
    let global = challenge(&machine, 2);
    let record = BusRecord { sends: vec![1, 2, 9], recvs: vec![9, 1, 2] };
    let (proof, vk) = prove(bus_machine(true), &[record], &global);
    verify(&machine, &vk, &proof, Some(&global)).expect("a shard that closes its own bus verifies");
}

#[test]
fn an_unbalanced_global_bus_is_rejected() {
    let machine = bus_machine(true);
    let global = challenge(&machine, 3);
    let (proof, vk) =
        prove(bus_machine(true), &[sender(&[3, 5, 7]), receiver(&[3, 5, 8])], &global);
    let err =
        verify(&machine, &vk, &proof, Some(&global)).expect_err("the global sums do not cancel");
    assert!(err.contains("Non-zero cumulative sum"), "{err}");

    let (one_sided, vk) = prove(bus_machine(true), &[sender(&[3, 5, 7])], &global);
    verify(&machine, &vk, &one_sided, Some(&global))
        .expect_err("an unmatched send must be rejected");
}

#[test]
fn shards_proven_under_another_challenge_are_rejected() {
    let machine = bus_machine(true);
    let global = challenge(&machine, 4);
    let other = challenge(&machine, 5);
    let (proof, vk) = prove(bus_machine(true), &[sender(&[3, 5, 7]), receiver(&[7, 3, 5])], &other);
    verify(&machine, &vk, &proof, Some(&global))
        .expect_err("a proof under another challenge must not verify under this one");

    let (mixed_a, vk) = prove(bus_machine(true), &[sender(&[3, 5, 7])], &global);
    let (mixed_b, _) = prove(bus_machine(true), &[receiver(&[7, 3, 5])], &other);
    let mixed = MachineProof {
        shard_proofs: vec![mixed_a.shard_proofs[0].clone(), mixed_b.shard_proofs[0].clone()],
    };
    verify(&machine, &vk, &mixed, Some(&global))
        .expect_err("shards proven under different challenges must not combine");
}

#[test]
fn the_global_challenge_must_fit_the_machine() {
    let machine = bus_machine(true);
    let global = challenge(&machine, 6);
    let (proof, vk) = prove(bus_machine(true), &[sender(&[3]), receiver(&[3])], &global);
    let err = verify(&machine, &vk, &proof, None)
        .expect_err("a machine with global lookups needs a challenge");
    assert!(err.contains("Invalid global challenge"), "{err}");

    let mut short = global.clone();
    short.betas.truncate(1);
    let err = verify(&machine, &vk, &proof, Some(&short)).expect_err("a β table of the wrong size");
    assert!(err.contains("Invalid global challenge"), "{err}");

    let unsplit = bus_machine(false);
    let err = verify(&unsplit, &vk, &proof, Some(&global))
        .expect_err("a global lookup chip outside the global round");
    assert!(err.contains("not in the machine's global round"), "{err}");
}

#[test]
fn the_global_sum_is_read_off_the_gkr_output() {
    let machine = bus_machine(true);
    let global = challenge(&machine, 7);
    let (mut proof, vk) =
        prove(bus_machine(true), &[sender(&[3, 5, 7]), receiver(&[7, 3, 5])], &global);
    let output = &mut proof.shard_proofs[0].jagged_shard_proof.logup_gkr_proof.circuit_output;
    let scale = <SC as StarkGenericConfig>::Challenge::from_u32(3);
    output.numerator[0] *= scale;
    output.denominator[0] *= scale;
    verify(&machine, &vk, &proof, Some(&global))
        .expect_err("a rescaled output fraction keeps its value but not its GKR binding");
}

#[test]
fn the_global_challenge_carries_its_proof_of_work() {
    let machine = bus_machine(true);
    let global = challenge(&machine, 7);
    let dim = machine.global_beta_seed_dim();
    let derive =
        |w: F| GlobalChallenge::derive(machine.config().challenger(), global.h_star, w, dim);
    assert_eq!(derive(global.pow_witness).as_ref(), Some(&global), "the ground witness passes");
    if global_grinding_bits() > 0 {
        let below =
            if global.pow_witness == F::ZERO { F::ONE } else { global.pow_witness - F::ONE };
        assert!(derive(below).is_none(), "the grind returns the smallest witness that passes");
    }
}

#[test]
fn a_proof_verifies_only_under_its_global_proof_of_work() {
    let machine = bus_machine(true);
    let prover = CpuProver::new(bus_machine(true));
    let (pk, vk) = prover.setup(&BusProgram);
    let records = vec![sender(&[3, 5, 7]), receiver(&[7, 3, 5])];
    let proof = prover
        .prove(&pk, records, &mut machine.config().challenger(), crate::ZKMCoreOpts::default())
        .unwrap();
    let witnesses: Vec<_> =
        proof.shard_proofs.iter().map(|p| p.jagged_shard_proof.global_pow_witness).collect();
    assert!(witnesses.iter().all(|w| w.is_some() && *w == witnesses[0]), "{witnesses:?}");
    let verify = |proof: &MachineProof<SC>| {
        machine.verify(&vk, proof, &mut machine.config().challenger()).map_err(|e| format!("{e}"))
    };
    verify(&proof).expect("an honest proof verifies");

    let mut split = proof.clone();
    let w = split.shard_proofs[1].jagged_shard_proof.global_pow_witness.as_mut().unwrap();
    *w += F::ONE;
    let err = verify(&split).expect_err("shards with different witnesses");
    assert!(err.contains("different global proof-of-work witnesses"), "{err}");

    let mut missing = proof.clone();
    missing.shard_proofs[0].jagged_shard_proof.global_pow_witness = None;
    let err = verify(&missing).expect_err("a shard without a witness");
    assert!(err.contains("no global proof-of-work witness"), "{err}");

    if global_grinding_bits() > 0 {
        let w0 = witnesses[0].unwrap();
        let below = if w0 == F::ZERO { F::ONE } else { w0 - F::ONE };
        let mut failing = proof.clone();
        for shard in &mut failing.shard_proofs {
            shard.jagged_shard_proof.global_pow_witness = Some(below);
        }
        let err = verify(&failing).expect_err("a witness that fails the proof of work");
        assert!(err.contains("witness fails"), "{err}");
    }
}

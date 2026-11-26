//! Shards that close a cross-shard lookup bus in global proofs: one chip
//! sends global lookups, another receives them, each in its own shard.

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
/// a main round.
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

fn sender(values: &[u32]) -> BusRecord {
    BusRecord { sends: values.to_vec(), recvs: Vec::new() }
}

fn receiver(values: &[u32]) -> BusRecord {
    BusRecord { sends: Vec::new(), recvs: values.to_vec() }
}

#[test]
fn the_global_challenge_carries_its_proof_of_work() {
    let machine = deferring_machine();
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

/// The bus machine with its global lookups deferred to global proofs.
fn deferring_machine() -> StarkMachine<SC, BusAir> {
    bus_machine(true).with_deferred_global_lookups()
}

/// Proves `records` in one pass, each as its own shard.
fn prove_with_deferred_global_lookups(
    records: &[BusRecord],
) -> (MachineProof<SC>, StarkVerifyingKey<SC>) {
    let prover = CpuProver::new(deferring_machine());
    let (pk, vk) = prover.setup(&BusProgram);
    let mut challenger = prover.machine().config().challenger();
    let proof = prover
        .prove(&pk, records.to_vec(), &mut challenger, crate::ZKMCoreOpts::default())
        .expect("the shards prove");
    (proof, vk)
}

fn verify_with_deferred_global_lookups(
    vk: &StarkVerifyingKey<SC>,
    proof: &MachineProof<SC>,
) -> Result<(), String> {
    let machine = deferring_machine();
    let mut challenger = machine.config().challenger();
    machine.verify(vk, proof, &mut challenger).map_err(|e| format!("{e:?}"))
}

#[test]
fn deferred_global_lookups_close_across_shards() {
    let (proof, vk) =
        prove_with_deferred_global_lookups(&[sender(&[3, 5, 7]), receiver(&[7, 3, 5])]);
    assert_eq!(proof.global_proofs.len(), 2);
    assert!(proof.shard_proofs.iter().all(|p| p.jagged_shard_proof.global_pow_witness.is_none()));
    verify_with_deferred_global_lookups(&vk, &proof).expect("a balanced bus must verify");
}

#[test]
fn an_unbalanced_deferred_bus_is_rejected() {
    let (proof, vk) =
        prove_with_deferred_global_lookups(&[sender(&[3, 5, 7]), receiver(&[7, 3, 6])]);
    let error = verify_with_deferred_global_lookups(&vk, &proof)
        .expect_err("an unbalanced bus must not verify");
    assert!(error.contains("sum"), "{error}");

    let (one_sided, vk) = prove_with_deferred_global_lookups(&[sender(&[3, 5, 7])]);
    verify_with_deferred_global_lookups(&vk, &one_sided)
        .expect_err("an unmatched send must be rejected");
}

#[test]
fn deferred_global_lookups_close_within_one_shard() {
    let record = BusRecord { sends: vec![1, 2, 9], recvs: vec![9, 1, 2] };
    let (proof, vk) = prove_with_deferred_global_lookups(&[record]);
    assert_eq!(proof.global_proofs.len(), 1);
    verify_with_deferred_global_lookups(&vk, &proof)
        .expect("a shard that closes its own bus verifies");
}

#[test]
fn the_global_sum_is_read_off_the_gkr_output() {
    let (mut proof, vk) =
        prove_with_deferred_global_lookups(&[sender(&[3, 5, 7]), receiver(&[7, 3, 5])]);
    let output = &mut proof.global_proofs[0].jagged_shard_proof.logup_gkr_proof.circuit_output;
    let scale = <SC as StarkGenericConfig>::Challenge::from_u32(3);
    output.numerator[0] *= scale;
    output.denominator[0] *= scale;
    verify_with_deferred_global_lookups(&vk, &proof)
        .expect_err("a rescaled output fraction keeps its value but not its GKR binding");
}

#[test]
fn global_lookups_in_a_shard_proof_are_refused() {
    let prover = CpuProver::new(bus_machine(true));
    let (pk, _) = prover.setup(&BusProgram);
    let records = vec![sender(&[3]), receiver(&[3])];
    let mut challenger = prover.machine().config().challenger();
    assert!(
        prover.prove(&pk, records, &mut challenger, crate::ZKMCoreOpts::default()).is_err(),
        "a machine that does not defer its global lookups was proved",
    );

    let (proof, vk) = prove_with_deferred_global_lookups(&[sender(&[3]), receiver(&[3])]);
    let machine = bus_machine(true);
    let error = machine
        .verify(&vk, &proof, &mut machine.config().challenger())
        .map_err(|e| format!("{e:?}"))
        .expect_err("a machine that does not defer its global lookups verified a proof");
    assert!(error.contains("with_deferred_global_lookups"), "{error}");
}

#[test]
#[should_panic(expected = "not in the machine's global round")]
fn a_deferred_global_lookup_needs_the_global_round() {
    let _ = bus_machine(false).with_deferred_global_lookups();
}

#[test]
fn every_global_round_needs_its_global_proof() {
    let (proof, vk) =
        prove_with_deferred_global_lookups(&[sender(&[3, 5, 7]), receiver(&[7, 3, 5])]);

    let mut dropped = proof.clone();
    dropped.global_proofs.pop();
    verify_with_deferred_global_lookups(&vk, &dropped)
        .expect_err("a shard without its global proof");

    let mut none = proof.clone();
    none.global_proofs.clear();
    verify_with_deferred_global_lookups(&vk, &none).expect_err("no global proofs at all");

    let mut swapped = proof.clone();
    swapped.global_proofs.swap(0, 1);
    verify_with_deferred_global_lookups(&vk, &swapped)
        .expect_err("global proofs out of shard order");

    let mut repeated = proof;
    repeated.global_proofs[1] = repeated.global_proofs[0].clone();
    verify_with_deferred_global_lookups(&vk, &repeated)
        .expect_err("one global proof standing in for two shards");
}

#[test]
fn a_global_proof_opens_the_round_its_shard_committed() {
    let (proof, vk) =
        prove_with_deferred_global_lookups(&[sender(&[3, 5, 7]), receiver(&[7, 3, 5])]);
    let (other, _) =
        prove_with_deferred_global_lookups(&[sender(&[3, 5, 8]), receiver(&[8, 3, 5])]);

    let mut mixed = proof.clone();
    mixed.global_proofs = other.global_proofs.clone();
    verify_with_deferred_global_lookups(&vk, &mixed).expect_err("global proofs of other tables");

    let mut mixed = proof;
    mixed.shard_proofs[0] = other.shard_proofs[0].clone();
    verify_with_deferred_global_lookups(&vk, &mixed)
        .expect_err("a shard replaced after the challenge was drawn");
}

#[test]
fn deferred_global_proofs_carry_the_proof_of_work() {
    let (proof, vk) =
        prove_with_deferred_global_lookups(&[sender(&[3, 5, 7]), receiver(&[7, 3, 5])]);
    let witnesses: Vec<_> =
        proof.global_proofs.iter().map(|p| p.jagged_shard_proof.global_pow_witness).collect();
    assert!(witnesses.iter().all(|w| w.is_some() && *w == witnesses[0]), "{witnesses:?}");

    let mut split = proof.clone();
    let w = split.global_proofs[1].jagged_shard_proof.global_pow_witness.as_mut().unwrap();
    *w += F::ONE;
    let error = verify_with_deferred_global_lookups(&vk, &split)
        .expect_err("global proofs with different witnesses");
    assert!(error.contains("different global proof-of-work witnesses"), "{error}");

    let mut missing = proof.clone();
    missing.global_proofs[0].jagged_shard_proof.global_pow_witness = None;
    let error = verify_with_deferred_global_lookups(&vk, &missing)
        .expect_err("a global proof without the witness");
    assert!(error.contains("no global proof-of-work witness"), "{error}");

    if global_grinding_bits() > 0 {
        let w0 = witnesses[0].unwrap();
        let below = if w0 == F::ZERO { F::ONE } else { w0 - F::ONE };
        let mut failing = proof;
        for global_proof in failing.global_proofs.iter_mut() {
            global_proof.jagged_shard_proof.global_pow_witness = Some(below);
        }
        let error = verify_with_deferred_global_lookups(&vk, &failing)
            .expect_err("a witness that fails the proof of work");
        assert!(error.contains("witness fails"), "{error}");
    }
}

#[test]
fn a_shard_without_a_global_round_needs_no_global_proof() {
    let machine = deferring_machine();
    assert!(machine.defers_global_lookups() && !machine.has_global_lookups());
    let (proof, vk) = prove_with_deferred_global_lookups(&[sender(&[4, 9]), receiver(&[9, 4])]);
    let mut extra = proof.clone();
    extra.global_proofs.push(proof.global_proofs[0].clone());
    verify_with_deferred_global_lookups(&vk, &extra)
        .expect_err("more global proofs than global rounds");
}

#[test]
fn the_verifier_bounds_the_global_lookup_count() {
    use crate::logup_gkr::{max_global_lookup_units, GLOBAL_LOOKUP_UNIT_BITS};

    let machine = deferring_machine();
    let (proof, _) =
        prove_with_deferred_global_lookups(&[sender(&[3, 5, 7]), receiver(&[7, 3, 5])]);
    let small = machine
        .global_round_binding(&proof.shard_proofs[0])
        .expect("the sender's shard commits a global round");
    let rows: usize = small.chips.iter().map(|(_, height)| height).sum();
    assert_eq!(machine.global_lookup_count(&small), rows as u64, "one global lookup a row");
    machine.check_global_lookup_count([&small]).expect("a few lookups");

    let round_of = |lookups: u64| {
        let mut round = small.clone();
        for (_, height) in round.chips.iter_mut() {
            *height = 0;
        }
        round.chips[0].1 = lookups as usize;
        round
    };
    let max = max_global_lookup_units::<F>();
    let characteristic = u64::from(<F as p3_field::PrimeField32>::ORDER_U32);
    let largest = round_of(((max - 1) << GLOBAL_LOOKUP_UNIT_BITS) + 1);
    machine.check_global_lookup_count([&largest]).expect("a round that counts every unit");
    machine
        .check_global_lookup_count([&largest, &small])
        .expect_err("two rounds that count one unit too many");
    machine
        .check_global_lookup_count([&round_of(characteristic)])
        .expect_err("as many lookups as the field's characteristic");
    machine
        .check_global_lookup_count([
            &round_of(characteristic / 2 + 1),
            &round_of(characteristic / 2),
        ])
        .expect_err("two rounds that reach the characteristic together");
}

#[test]
fn shard_proofs_alone_do_not_close_a_deferred_bus() {
    let machine = deferring_machine();
    let (proof, vk) =
        prove_with_deferred_global_lookups(&[sender(&[3, 5, 7]), receiver(&[7, 3, 6])]);
    machine
        .verify_shard_proofs(&vk, &proof, &mut machine.config().challenger())
        .expect("each shard proof verifies on its own");
    verify_with_deferred_global_lookups(&vk, &proof).expect_err("the bus is unbalanced");
}

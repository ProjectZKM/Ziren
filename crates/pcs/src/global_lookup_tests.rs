//! Shards that close a cross-shard lookup bus in global proofs: one chip
//! sends global lookups, another receives them, each in its own shard.

use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use std::collections::BTreeSet;

use crate::air::{AirLookup, BaseAirBuilder, LookupScope, MachineAir, MachineProgram};
use crate::koala_bear_poseidon2::KoalaBearPoseidon2;
use crate::logup_gkr::{global_grinding_bits, GlobalChallenge, GlobalRoundBinding};
use crate::{
    Chip, CpuProver, LookupKind, MachineProof, MachineProver, MachineRecord, ShardProof,
    StarkGenericConfig, StarkMachine, StarkProvingKey, StarkVerifyingKey, Traces, Val,
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
        .expect("global proofs open the shards' rounds in any order");

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

/// Proves `records`, each as its own shard, with the global round of shard
/// `i` on lane `lanes[i]` of the global hash chain: a prover that assigns
/// the lanes itself.
fn prove_on_chain_lanes(
    records: &[BusRecord],
    lanes: &[u8],
) -> (MachineProof<SC>, StarkVerifyingKey<SC>) {
    let prover = CpuProver::new(deferring_machine());
    let machine = prover.machine();
    let (pk, vk) = prover.setup(&BusProgram);
    let mut challenger = machine.config().challenger();
    crate::MachineProvingKey::observe_into(&pk, &mut challenger);
    assert_eq!(records.len(), lanes.len());
    let (shard_proofs, tables): (Vec<_>, Vec<_>) = records
        .iter()
        .zip(lanes)
        .map(|(record, lane)| {
            let traces = prover.generate_traces(record).expect("the traces generate");
            let data = prover.commit(record, traces, None);
            let tables = prover.global_round_tables(&data);
            let mut proof =
                prover.open(&pk, data, &mut challenger.clone()).expect("the shard proves");
            proof.global_chain_lane = *lane;
            (proof, tables)
        })
        .unzip();
    let rounds: Vec<_> =
        shard_proofs.iter().map(|proof| machine.global_round_binding(proof)).collect();
    let global = machine
        .global_challenge(&challenger, rounds.iter().map(Option::as_ref), lanes.iter().copied())
        .expect("the machine has global lookups");
    let global_proofs = rounds
        .iter()
        .zip(tables)
        .filter_map(|(round, tables)| Some((round.as_ref()?, tables?)))
        .map(|(round, tables)| {
            prover
                .prove_global_round(&pk, round, tables, &global, &challenger)
                .expect("the global round proves")
        })
        .collect();
    (MachineProof { shard_proofs, global_proofs }, vk)
}

/// Ten shards whose sends and receives cancel across them.
fn ten_shards() -> Vec<BusRecord> {
    (0..5u32)
        .flat_map(|i| [sender(&[3 * i + 1, 3 * i + 2]), receiver(&[3 * i + 2, 3 * i + 1])])
        .collect()
}

#[test]
fn the_prover_spreads_the_global_rounds_over_the_chain_lanes() {
    let (proof, vk) = prove_with_deferred_global_lookups(&ten_shards());
    let lanes: Vec<u8> = proof.shard_proofs.iter().map(|shard| shard.global_chain_lane).collect();
    assert_eq!(lanes, [0, 1, 2, 3, 4, 5, 6, 7, 0, 1], "the rounds take the lanes in turn");
    verify_with_deferred_global_lookups(&vk, &proof).expect("rounds on every lane verify");

    let mut moved = proof.clone();
    moved.shard_proofs[3].global_chain_lane = 6;
    verify_with_deferred_global_lookups(&vk, &moved)
        .expect_err("a round moved to another lane after the challenge was drawn");

    let mut swapped = proof.clone();
    swapped.shard_proofs[2].global_chain_lane = 5;
    swapped.shard_proofs[5].global_chain_lane = 2;
    verify_with_deferred_global_lookups(&vk, &swapped)
        .expect_err("two rounds that trade their lanes");

    let mut no_lane = proof;
    no_lane.shard_proofs[9].global_chain_lane = crate::logup_gkr::GLOBAL_CHAIN_LANE_COUNT as u8;
    let error = verify_with_deferred_global_lookups(&vk, &no_lane)
        .expect_err("a round on a lane that does not exist");
    assert!(error.contains("lane 8"), "{error}");
}

#[test]
fn a_prover_chooses_the_chain_lane_of_each_global_round() {
    let records = ten_shards();
    let chosen = [2, 2, 7, 2, 7, 7, 0, 2, 7, 0];
    let (proof, vk) = prove_on_chain_lanes(&records, &chosen);
    verify_with_deferred_global_lookups(&vk, &proof).expect("any lane is valid for any round");

    let (one_lane, vk) = prove_on_chain_lanes(&records[..4], &[4; 4]);
    verify_with_deferred_global_lookups(&vk, &one_lane).expect("every round on one lane");

    let mut reordered = one_lane;
    reordered.shard_proofs.swap(1, 3);
    reordered.global_proofs.swap(1, 3);
    verify_with_deferred_global_lookups(&vk, &reordered)
        .expect_err("a lane binds the order of its rounds");
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

/// Shards proved one by one, with what a prover holds to open their global
/// rounds: every shard's round and its tables, the challenge the rounds fix,
/// and the challenger after the verifying key.
struct CommittedShards {
    prover: CpuProver<SC, BusAir>,
    pk: StarkProvingKey<SC>,
    vk: StarkVerifyingKey<SC>,
    shard_proofs: Vec<ShardProof<SC>>,
    rounds: Vec<GlobalRoundBinding<F>>,
    tables: Vec<Traces<F>>,
    global: GlobalChallenge<F, <SC as StarkGenericConfig>::Challenge>,
    vk_challenger: <SC as StarkGenericConfig>::Challenger,
}

impl CommittedShards {
    /// Proves `records`, each as its own shard with a global round.
    fn prove(records: &[BusRecord]) -> Self {
        let prover = CpuProver::new(deferring_machine());
        let (pk, vk) = prover.setup(&BusProgram);
        let mut vk_challenger = prover.machine().config().challenger();
        pk.observe_into(&mut vk_challenger);
        let (mut shard_proofs, tables): (Vec<_>, Vec<_>) = records
            .iter()
            .map(|record| {
                let traces = prover.generate_traces(record).unwrap();
                let data = prover.commit(record, traces, None);
                let tables = prover.global_round_tables(&data).expect("a global round");
                (prover.open(&pk, data, &mut vk_challenger.clone()).unwrap(), tables)
            })
            .unzip();
        prover.machine().assign_global_chain_lanes(&mut shard_proofs);
        let rounds: Vec<_> = shard_proofs
            .iter()
            .map(|proof| prover.machine().global_round_binding(proof).expect("a global round"))
            .collect();
        let global = prover
            .machine()
            .global_challenge(
                &vk_challenger,
                rounds.iter().map(Some),
                shard_proofs.iter().map(|shard| shard.global_chain_lane),
            )
            .expect("the bus machine has global lookups");
        Self { prover, pk, vk, shard_proofs, rounds, tables, global, vk_challenger }
    }

    /// One global proof that opens the rounds of the shards `group`, in that
    /// order.
    fn global_proof(&self, group: &[usize]) -> ShardProof<SC> {
        let opened: Vec<_> =
            group.iter().map(|&i| (&self.rounds[i], self.tables[i].clone())).collect();
        crate::prover::prove_global_rounds(
            self.prover.machine(),
            &self.pk,
            &opened,
            &self.global,
            &self.vk_challenger,
        )
    }

    /// The machine proof whose global proofs open the rounds of `groups`.
    fn proof(&self, groups: &[&[usize]]) -> MachineProof<SC> {
        MachineProof {
            shard_proofs: self.shard_proofs.clone(),
            global_proofs: groups.iter().map(|group| self.global_proof(group)).collect(),
        }
    }

    fn verify(&self, proof: &MachineProof<SC>) -> Result<(), String> {
        verify_with_deferred_global_lookups(&self.vk, proof)
    }

    /// The verifier's result on `proof` as the global proof of the rounds of the shards
    /// `group`, in that order.
    fn verify_global_proof(&self, group: &[usize], proof: &ShardProof<SC>) -> Result<(), String> {
        let rounds: Vec<_> = group.iter().map(|&i| &self.rounds[i]).collect();
        self.prover
            .machine()
            .verify_global_proof(&self.vk, &self.vk_challenger, &rounds, proof, &self.global)
            .map(|_| ())
            .map_err(|e| format!("{e:?}"))
    }
}

/// Five shards that close the bus together. The rounds of shards 1 and 3
/// hold the same chip at the same height; no other two rounds share a shape.
fn five_shards() -> Vec<BusRecord> {
    vec![
        sender(&[3, 5, 7, 11]),
        receiver(&[7, 3]),
        BusRecord { sends: vec![1, 2, 4], recvs: vec![4, 1, 2] },
        receiver(&[5, 11]),
        BusRecord { sends: vec![9], recvs: vec![9] },
    ]
}

#[test]
fn one_global_proof_opens_several_rounds() {
    let shards = CommittedShards::prove(&five_shards());
    let proof = shards.proof(&[&[0, 1, 2], &[3, 4]]);
    let slots: Vec<_> = proof
        .global_proofs
        .iter()
        .map(|p| p.jagged_shard_proof.preceding_rounds.len() + 1)
        .collect();
    assert_eq!(slots, [3, 2], "each global proof commits one round a slot");
    shards.verify(&proof).expect("grouped global proofs close a balanced bus");

    let all = shards.proof(&[&[0, 1, 2, 3, 4]]);
    shards.verify(&all).expect("one global proof opens every round");

    let mut unbalanced = five_shards();
    unbalanced[3].recvs[1] = 12;
    let shards = CommittedShards::prove(&unbalanced);
    let error = shards
        .verify(&shards.proof(&[&[0, 1, 2], &[3, 4]]))
        .expect_err("grouped global proofs must not close an unbalanced bus");
    assert!(error.contains("sum"), "{error}");
}

#[test]
fn global_proofs_open_the_rounds_in_any_order_and_grouping() {
    let shards = CommittedShards::prove(&five_shards());
    let groupings: [&[&[usize]]; 3] =
        [&[&[4, 1], &[2], &[0, 3]], &[&[3, 2, 1, 0], &[4]], &[&[2], &[4], &[0], &[3], &[1]]];
    for groups in groupings {
        shards.verify(&shards.proof(groups)).unwrap_or_else(|e| panic!("{groups:?}: {e}"));
    }
}

#[test]
fn a_global_proof_opens_its_rounds_in_slot_order() {
    let shards = CommittedShards::prove(&five_shards());
    let proof = shards.global_proof(&[0, 2, 1]);
    shards.verify_global_proof(&[0, 2, 1], &proof).expect("the rounds in the proof's slot order");
    shards
        .verify_global_proof(&[2, 0, 1], &proof)
        .expect_err("the preceding rounds in another order");
    shards.verify_global_proof(&[0, 1, 2], &proof).expect_err("the main round in another slot");
    shards.verify_global_proof(&[0, 2], &proof).expect_err("fewer rounds than slots");
    shards.verify_global_proof(&[0, 2, 1, 3], &proof).expect_err("more rounds than slots");

    let same_shape = shards.global_proof(&[1, 3]);
    shards.verify_global_proof(&[1, 3], &same_shape).expect("the rounds in slot order");
    shards
        .verify_global_proof(&[3, 1], &same_shape)
        .expect_err("two rounds of one shape in each other's slot");

    let mut swapped = shards.proof(&[&[1, 3], &[0, 2, 4]]);
    let slots = &mut swapped.global_proofs[0].jagged_shard_proof;
    core::mem::swap(&mut slots.preceding_rounds[0].commitment, &mut slots.main_commitment);
    core::mem::swap(
        &mut slots.preceding_rounds[0].original_commitment,
        &mut slots.main_original_commitment,
    );
    shards.verify(&swapped).expect_err("a global proof with the commitments of two slots swapped");
}

#[test]
fn every_global_round_is_opened_exactly_once() {
    let shards = CommittedShards::prove(&five_shards());

    let error = shards
        .verify(&shards.proof(&[&[0, 1, 2], &[2, 4]]))
        .expect_err("a round opened twice and another not at all");
    assert!(error.contains("another global proof opens"), "{error}");

    let error = shards
        .verify(&shards.proof(&[&[0, 1, 2], &[2, 3, 4]]))
        .expect_err("a round opened by two global proofs");
    assert!(error.contains("another global proof opens"), "{error}");

    let error = shards
        .verify(&shards.proof(&[&[0, 1, 1], &[2, 3, 4]]))
        .expect_err("a round opened in two slots of one global proof");
    assert!(error.contains("another global proof opens"), "{error}");

    let error = shards
        .verify(&shards.proof(&[&[0, 1], &[2, 3]]))
        .expect_err("a round no global proof opens");
    assert!(error.contains("opened by no global proof"), "{error}");
}

#[test]
fn a_preceding_round_of_a_global_proof_is_the_one_its_shard_committed() {
    let shards = CommittedShards::prove(&five_shards());
    let honest = shards.proof(&[&[1, 2], &[3, 0, 4]]);
    shards.verify(&honest).expect("the honest grouping verifies");

    let other = *shards.shard_proofs[3].jagged_shard_proof.global_round().unwrap();
    assert_eq!(shards.rounds[1].chips, shards.rounds[3].chips, "two rounds of one shape");
    let mut replaced = honest.clone();
    replaced.global_proofs[0].jagged_shard_proof.preceding_rounds[0] = other;
    shards
        .verify_global_proof(&[3, 2], &replaced.global_proofs[0])
        .expect_err("a proof of one shard's tables under another shard's commitment");
    shards
        .verify_global_proof(&[1, 2], &replaced.global_proofs[0])
        .expect_err("a preceding commitment other than the bound round's");
    shards.verify(&replaced).expect_err("a preceding round replaced by another shard's");

    let mut observed_only = honest.clone();
    observed_only.global_proofs[0].jagged_shard_proof.preceding_rounds[0].commitment =
        other.commitment;
    shards.verify(&observed_only).expect_err("a preceding round's observed commitment replaced");

    let mut height = honest;
    let heights = &mut height.global_proofs[0].jagged_shard_proof.chip_heights;
    *heights.get_mut("00.BusReceiver").unwrap() += 1;
    shards.verify(&height).expect_err("a preceding round's table at another height");
}

#[test]
fn global_rounds_share_a_proof_within_the_area_limit() {
    let machine = deferring_machine();
    let round_of = |height| GlobalRoundBinding {
        commitment: [F::ZERO; 8],
        chips: vec![("BusSender".to_string(), height)],
    };
    let small = &round_of(1);
    let large = round_of(1 << 28);
    let block = 1usize << crate::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT;
    let limit = 1usize << crate::jagged::MAX_ROUND_LOG_AREA;
    let area = |round| machine.global_round_blocks(round) * block;
    assert!(area(&large) < limit && 2 * area(&large) >= limit);
    assert!(area(&large) + 2 * area(small) < limit);

    let groups = |rounds: &[&GlobalRoundBinding<F>], per_proof| {
        machine.global_proof_groups(rounds.iter().copied(), per_proof)
    };
    assert_eq!(groups(&[small; 7], 3), [0..3, 3..6, 6..7]);
    assert_eq!(groups(&[small; 3], 1), [0..1, 1..2, 2..3]);
    assert_eq!(groups(&[&large, &large, small, small, small], 3), [0..1, 1..4, 4..5]);
    assert_eq!(groups(&[small, &large, &large, small], 8), [0..2, 2..4]);
    let max = crate::logup_gkr::MAX_GLOBAL_ROUNDS_PER_PROOF;
    assert_eq!(groups(&vec![small; max + 4], usize::MAX), [0..max, max..max + 4]);
}

/// A lane's rounds share a global proof while they hold the same chips at
/// the same number of stacking blocks, within the bounds on a proof's rounds,
/// weight and area; the lanes of a proof are grouped apart, each in order.
#[test]
fn a_chain_lane_groups_its_rounds_of_one_shape() {
    use crate::logup_gkr::{GLOBAL_LEAF_CELLS, GLOBAL_LEAF_FIXED_CELLS};
    let machine = deferring_machine();
    let round_of = |chips: &[(&str, usize)]| GlobalRoundBinding {
        commitment: [F::ZERO; 8],
        chips: chips.iter().map(|(name, height)| (name.to_string(), *height)).collect(),
    };
    let sender = &round_of(&[("BusSender", 1)]);
    let both = &round_of(&[("BusReceiver", 1), ("BusSender", 1)]);
    let groups = |rounds: &[&GlobalRoundBinding<F>], per_proof| {
        machine.global_chain_lane_proof_groups(rounds.iter().copied(), per_proof)
    };
    assert_eq!(
        groups(&[sender, sender, sender, both, both, sender], 8),
        [0..3, 3..5, 5..6],
        "a change of chips starts a proof"
    );
    assert_eq!(groups(&[both; 20], 8), [0..8, 8..16, 16..20]);
    assert_eq!(groups(&[both; 5], 2), [0..2, 2..4, 4..5]);
    let by_cells =
        (GLOBAL_LEAF_CELLS - GLOBAL_LEAF_FIXED_CELLS) / machine.global_round_leaf_cells(both);
    let by_rows =
        crate::logup_gkr::global_rounds_within_the_row_cube(machine.global_round_blocks(both));
    let fit = by_cells.min(by_rows);
    assert!(fit < crate::logup_gkr::MAX_GLOBAL_ROUNDS_PER_PROOF);
    assert_eq!(
        groups(&[both; 40], usize::MAX),
        [0..fit, fit..40],
        "small rounds fill a proof by what its program holds"
    );

    let limit = 1usize << crate::jagged::MAX_ROUND_LOG_AREA;
    let block = 1usize << crate::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT;
    let by_weight = |round: &GlobalRoundBinding<F>| {
        (GLOBAL_LEAF_CELLS - GLOBAL_LEAF_FIXED_CELLS) / machine.global_round_leaf_cells(round)
    };
    let tall = (1usize..)
        .map(|rows| round_of(&[("BusSender", rows << 20)]))
        .find(|round| {
            let blocks = machine.global_round_blocks(round);
            blocks > crate::jagged::GLOBAL_ROUND_PIN_BLOCKS
                && by_weight(round) < (limit - 1) / (blocks * block)
        })
        .expect("a round of a larger class that shares a proof by weight");
    let fit = by_weight(&tall).min(crate::logup_gkr::global_rounds_within_the_row_cube(
        machine.global_round_blocks(&tall),
    ));
    assert!(fit < crate::logup_gkr::MAX_GLOBAL_ROUNDS_PER_PROOF);
    let rounds = [sender, sender]
        .into_iter()
        .chain(core::iter::repeat_n(&tall, fit + 1))
        .chain([sender])
        .collect::<Vec<_>>();
    assert_eq!(
        groups(&rounds, usize::MAX),
        [0..2, 2..2 + fit, 2 + fit..3 + fit, 3 + fit..4 + fit],
        "rounds of more blocks start a proof and share it by weight"
    );

    let large = round_of(&[("BusSender", (1 << 29) / 3)]);
    let blocks = machine.global_round_blocks(&large);
    assert!(
        GLOBAL_LEAF_FIXED_CELLS + 2 * machine.global_round_leaf_cells(&large) <= GLOBAL_LEAF_CELLS
    );
    assert!(2 * blocks * block >= limit);
    assert_eq!(
        groups(&[&large, &large, &large], 8),
        [0..1, 1..2, 2..3],
        "two rounds within the weight of a proof but past its area"
    );

    let by_lane = machine.global_proof_groups_by_lane(
        [
            (1, sender, 0),
            (0, both, 1),
            (1, sender, 2),
            (0, sender, 3),
            (1, both, 4),
            (0, sender, 5),
        ],
        8,
    );
    let kept = |group: &Vec<(&GlobalRoundBinding<F>, usize)>| {
        group.iter().map(|(_, kept)| *kept).collect::<Vec<_>>()
    };
    assert_eq!(
        by_lane.iter().map(kept).collect::<Vec<_>>(),
        [vec![1], vec![3, 5], vec![0, 2], vec![4]]
    );
    assert!(by_lane
        .iter()
        .flatten()
        .all(|(round, kept)| { *round == if [1, 4].contains(kept) { both } else { sender } }));
}

/// The bus machine with its global lookups deferred, whose global rounds
/// commit the family of both bus chips.
fn family_machine() -> StarkMachine<SC, BusAir> {
    let family: BTreeSet<String> = ["BusSender", "BusReceiver"].map(String::from).into();
    bus_machine(true).with_global_families(vec![family]).with_deferred_global_lookups()
}

/// On a machine with a family of global-round chips, a shard that sends and
/// a shard that receives both commit the two chips, the one each lacks
/// without rows: their rounds have one shape and the bus closes. A table
/// without rows cannot be given a row afterwards, in its opened height or in
/// the heights the transcript observes.
#[test]
fn a_global_round_commits_its_family() {
    let prover = CpuProver::new(family_machine());
    let (pk, vk) = prover.setup(&BusProgram);
    let machine = prover.machine();
    let proof = prover
        .prove(
            &pk,
            vec![sender(&[3, 5, 7]), receiver(&[7, 3, 5])],
            &mut machine.config().challenger(),
            crate::ZKMCoreOpts::default(),
        )
        .expect("the shards prove");
    let rounds = proof
        .shard_proofs
        .iter()
        .map(|shard| machine.global_round_binding(shard).expect("the shard's global round"))
        .collect::<Vec<_>>();
    let chips = |heights: [usize; 2]| {
        ["BusReceiver", "BusSender"].map(String::from).into_iter().zip(heights).collect::<Vec<_>>()
    };
    assert_eq!(rounds[0].chips, chips([0, 4]));
    assert_eq!(rounds[1].chips, chips([4, 0]));
    assert_eq!(
        machine.global_chain_lane_proof_groups(rounds.iter(), 8).first(),
        Some(&(0..2)),
        "the rounds of a sending and a receiving shard do not share a global proof"
    );

    let verify = |proof: &MachineProof<SC>| {
        machine.verify(&vk, proof, &mut machine.config().challenger()).map_err(|e| format!("{e:?}"))
    };
    verify(&proof).expect("the bus closes over rounds padded to their family");

    let one = <SC as StarkGenericConfig>::Challenge::ONE;
    let mut opened = proof.clone();
    let global = &mut opened.global_proofs[0].jagged_shard_proof;
    let empty =
        global.chip_heights.values().position(|height| *height == 0).expect("a table without rows");
    *global.opened_values.chips[empty].quotient[0].last_mut().unwrap() = one;
    verify(&opened).expect_err("a table without rows opened a row");

    let mut observed = opened.clone();
    let global = &mut observed.global_proofs[0].jagged_shard_proof;
    *global.chip_heights.values_mut().nth(empty).unwrap() = 1;
    verify(&observed).expect_err("a table without rows was given a row its shard did not commit");

    let mut shard = proof.clone();
    let of_shard = &mut shard.shard_proofs[0].jagged_shard_proof;
    let empty = of_shard
        .chip_heights
        .values()
        .position(|height| *height == 0)
        .expect("a table without rows");
    *of_shard.opened_values.chips[empty].quotient[0].last_mut().unwrap() = one;
    *of_shard.chip_heights.values_mut().nth(empty).unwrap() = 1;
    verify(&shard).expect_err("a shard gave a row to a table it committed without rows");
}

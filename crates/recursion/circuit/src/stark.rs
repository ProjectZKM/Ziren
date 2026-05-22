use hashbrown::HashMap;
use itertools::{izip, Itertools};

use num_traits::cast::ToPrimitive;

use p3_air::{WindowAccess, Air, BaseAir};
use p3_commit::{Mmcs, Pcs, PolynomialSpace};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};
use p3_koala_bear::KoalaBear;

use zkm_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Config, DslIr, Ext, ExtConst, SymbolicExt},
    prelude::Felt,
};
use zkm_stark::septic_digest::SepticDigest;
use zkm_stark::{
    air::LookupScope, koala_bear_poseidon2::KoalaBearPoseidon2, shape::OrderedShape,
    AirOpenedValues, Challenger, Chip, ChipOpenedValues, InnerChallenge,
    ShardCommitment, ShardOpenedValues, ShardProof, Val, PROOF_MAX_NUM_PVS,
};
use zkm_stark::{air::MachineAir, StarkGenericConfig, StarkMachine, StarkVerifyingKey};

use crate::{
    challenger::CanObserveVariable,
    fri::{dummy_commit, dummy_pcs_proof, PolynomialBatchShape, PolynomialShape},
    hash::FieldHasherVariable,
    CircuitConfig, FriProofVariable, KoalaBearFriParameters, TwoAdicPcsMatsVariable,
};

use crate::{
    challenger::FieldChallengerVariable, constraints::RecursiveVerifierConstraintFolder,
    domain::PolynomialSpaceVariable, fri::verify_two_adic_pcs, KoalaBearFriParametersVariable,
    TwoAdicPcsRoundVariable, VerifyingKeyVariable,
};

/// Reference: [zkm_core::stark::ShardProof]
#[derive(Clone)]
pub struct ShardProofVariable<C: CircuitConfig<F = SC::Val>, SC: KoalaBearFriParametersVariable<C>> {
    pub commitment: ShardCommitment<SC::DigestVariable>,
    #[allow(clippy::type_complexity)]
    pub opened_values: ShardOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>,
    pub opening_proof: FriProofVariable<C, SC>,
    pub chip_ordering: HashMap<String, usize>,
    pub public_values: Vec<Felt<C::F>>,
    /// Fixed-size fingerprint of the jagged-PCS opening proof
    /// bytes (XOR-fold of the Vec<u8> into 8 Felts).  Always
    /// `[Felt; 8]` — unconditional presence simplifies witness
    /// synchronisation: real proofs contribute the fold of
    /// `late_binding_jagged_proof.unwrap_or(&[])` while legacy
    /// proofs contribute the all-zero fingerprint.
    ///
    /// Observed into the challenger transcript inside
    /// `verify_shard` so the prover can't equivocate on the bytes
    /// content.  Full BaseFold-PCS in-circuit verification of the
    /// bytes (deserialize → run sumcheck + FRI) is a separate
    /// task; this fingerprint binding is the prerequisite.
    pub basefold_jagged_fingerprint: [Felt<C::F>; 8],
}

/// Get a dummy duplex challenger for use in dummy proofs.
pub fn dummy_challenger(config: &KoalaBearPoseidon2) -> Challenger<KoalaBearPoseidon2> {
    let mut challenger = config.challenger();
    challenger.input_buffer = vec![];
    challenger.output_buffer = vec![KoalaBear::ZERO; challenger.sponge_state.len()];
    challenger
}

/// Step 5 Phase 3b basefold-shaped recursion shard dummy (May 19 2026).
///
/// Produces a `(StarkVerifyingKey, ShardProof)` pair whose
/// `ShardProof` carries:
///   - `commitment.auxiliary_commits = vec![]` (no perm + quotient commits)
///   - `opened_values` with empty `permutation`/`quotient` fields
///   - `opening_proof` from the basefold-mode FRI sub-proof (prep + main only)
///   - `basefold_shard_proof: Some(_)` populated with the dummy
///     basefold shard proof from `dummy_basefold_vk_and_shard_proof`.
///
/// This mirrors the real prover output shape at
/// `crates/stark/src/prover.rs:600-610` (the `use_basefold_path`
/// return branch).  RecursionAir-parameterised because the inner
/// `dummy_basefold_vk_and_shard_proof` already drives the
/// `prove_shard_to_basefold` host path with the chip set from
/// `machine`, so passing in a `StarkMachine<KBP2, RecursionAir<_,_>>`
/// produces a basefold proof shaped for recursion chips
/// (BaseAlu/ExtAlu/Poseidon2/FriFold/etc.) instead of MIPS chips.
///
/// # Status (scaffold)
///
/// The opening_proof + opened_values FRI placeholders are minimal
/// (empty perm/quotient, opening_proof from a small pcs.open call
/// mirroring the prover branch).  Cryptographic soundness of the
/// dummy isn't required — consumers (`program_from_shape`) only
/// care about the witness-stream shape, which is driven by
/// chip_ordering + chip_cumulative_sums in the basefold sub-proof.
///
/// Wraps the inner `BasefoldShardProof` in a `Box` per the
/// `ShardProof::basefold_shard_proof: Option<Box<_>>` definition.
///
/// # Trait bounds
///
/// Same `A: MachineAir + Air<VerifierConstraintFolder>` bounds as
/// `dummy_basefold_vk_and_shard_proof` — both `MipsAir` and
/// `RecursionAir<F, DEGREE>` satisfy these via the standard derive
/// macro at `crates/derive/src/lib.rs:218,321`.
pub fn dummy_recursion_basefold_vk_and_shard_proof<A>(
    machine: &StarkMachine<KoalaBearPoseidon2, A>,
    shape: &OrderedShape,
) -> (StarkVerifyingKey<KoalaBearPoseidon2>, ShardProof<KoalaBearPoseidon2>)
where
    A: MachineAir<KoalaBear>
        + for<'b> Air<zkm_stark::folder::VerifierConstraintFolder<'b, KoalaBearPoseidon2>>,
{
    // Produce the basefold shard proof + matching VK using the
    // existing infrastructure.  The chip set and per-chip shapes
    // come from the machine + shape pair.
    let (vk, basefold_proof) = dummy_basefold_vk_and_shard_proof::<A>(machine, shape);

    // Build the empty FRI placeholder fields matching the real
    // basefold-path prover output at `prover.rs:600-610`.  Empty
    // auxiliary_commits + empty perm/quotient opened values.  The
    // chip_ordering carries the name → index map needed by
    // recursion-side Witnessable::read to fix the witness-stream
    // order.
    let chip_ordering = shape
        .inner
        .iter()
        .enumerate()
        .map(|(i, (name, _))| (name.clone(), i))
        .collect::<HashMap<_, _>>();

    // Per-chip ChipOpenedValues with empty permutation / quotient
    // arrays — matching the prover's basefold-path emission at
    // `prover.rs:559-568`.  Preprocessed + main keep their real
    // widths so the witness reader still walks the right number
    // of felts; perm + quotient are empty because the basefold
    // pipeline doesn't commit them.
    let shard_chips = machine.shard_chips_ordered(&chip_ordering).collect::<Vec<_>>();
    let opened_values = ShardOpenedValues {
        chips: shard_chips
            .iter()
            .zip_eq(shape.inner.iter())
            .map(|(chip, (_, log_degree))| {
                let preprocessed_width = chip.preprocessed_width();
                let main_width = chip.width();
                ChipOpenedValues {
                    preprocessed: AirOpenedValues {
                        local: vec![InnerChallenge::ZERO; preprocessed_width],
                        next: vec![InnerChallenge::ZERO; preprocessed_width],
                    },
                    main: AirOpenedValues {
                        local: vec![InnerChallenge::ZERO; main_width],
                        next: vec![InnerChallenge::ZERO; main_width],
                    },
                    permutation: AirOpenedValues { local: vec![], next: vec![] },
                    quotient: vec![],
                    global_cumulative_sum: SepticDigest::<KoalaBear>::zero(),
                    local_cumulative_sum: InnerChallenge::ZERO,
                    log_degree: *log_degree,
                }
            })
            .collect(),
    };

    // FRI opening_proof — minimal placeholder.  The basefold path
    // still calls `pcs.open` for prep + main (no perm/quotient),
    // producing a 2-batch FRI proof.  For the dummy we emit a
    // 2-batch shape via `dummy_pcs_proof` (preprocessed + main only).
    let mut preprocessed_batch_shape = vec![];
    let mut main_batch_shape = vec![];
    for chip_opening in opened_values.chips.iter() {
        if !chip_opening.preprocessed.local.is_empty() {
            preprocessed_batch_shape.push(PolynomialShape {
                width: chip_opening.preprocessed.local.len(),
                log_degree: chip_opening.log_degree,
            });
        }
        main_batch_shape.push(PolynomialShape {
            width: chip_opening.main.local.len(),
            log_degree: chip_opening.log_degree,
        });
    }
    let mut batch_shapes = Vec::with_capacity(2);
    if !preprocessed_batch_shape.is_empty() {
        batch_shapes.push(PolynomialBatchShape { shapes: preprocessed_batch_shape });
    }
    if !main_batch_shape.is_empty() {
        batch_shapes.push(PolynomialBatchShape { shapes: main_batch_shape });
    }
    let fri_queries = machine.config().fri_config().num_queries;
    let log_blowup = machine.config().fri_config().log_blowup;
    let opening_proof = dummy_pcs_proof(fri_queries, &batch_shapes, log_blowup);

    let public_values = (0..PROOF_MAX_NUM_PVS).map(|_| KoalaBear::ZERO).collect::<Vec<_>>();

    let shard_proof = ShardProof {
        commitment: ShardCommitment {
            main_commit: dummy_commit(),
            auxiliary_commits: Vec::new(),
        },
        opened_values,
        opening_proof,
        chip_ordering,
        public_values,
        basefold_shard_proof: Some(Box::new(basefold_proof)),
    };

    (vk, shard_proof)
}

/// Make a dummy basefold-pipeline shard proof for a given proof shape.
///
/// Drives the host-side `prove_shard_to_basefold` with zero-filled
/// traces for every chip in `shape`. The resulting proof is
/// structurally correct (all inner sumcheck/jagged-PCS shapes match
/// the prover's wire format and the recursion-circuit's shape
/// asserts) but does NOT satisfy AIR constraints — the zero traces
/// can't pass the chip's per-row constraints. That's adequate for
/// `program_from_shape`-style consumers that only care about the
/// program SHAPE (number of witness reads), not soundness.
///
/// Returned `chip_cumulative_sums` has one entry per chip in
/// `shape.inner` — matching real proofs, so the recursion program's
/// witness-stream `read()` count is shape-stable across dummy and
/// real proofs.
///
/// META #59 Phase 4 — unblocks `program_from_shape` basefold
/// dispatch (#52) and downstream `dummy()` constructors for
/// `ZKMCoreBasefoldWitnessValues` etc.
pub fn dummy_basefold_vk_and_shard_proof<A>(
    machine: &StarkMachine<KoalaBearPoseidon2, A>,
    shape: &OrderedShape,
) -> (
    StarkVerifyingKey<KoalaBearPoseidon2>,
    zkm_stark::shard_level::shard_proof::BasefoldShardProof<KoalaBear, InnerChallenge>,
)
where
    A: MachineAir<KoalaBear>
        + for<'b> Air<zkm_stark::folder::VerifierConstraintFolder<'b, KoalaBearPoseidon2>>,
{
    use zkm_stark::shard_level::verifier::BasefoldShardVerifier;

    // SP1 port (May 21 2026) — replaces the previous slow path that
    // called `prove_shard_to_basefold` against zero traces.  That
    // approach cost ~61.3s per compose-program pre-warm cycle (one
    // call × REDUCE_BATCH_SIZE arities); the new zero-fill allocator
    // path runs in microseconds.
    //
    // Reference: SP1 `dummy_shard_proof` at
    // `/tmp/sp1/crates/recursion/circuit/src/dummy/shard_proof.rs:28-83`.
    //
    // Resolve each chip in the shape to a concrete &Chip from the
    // machine. Skip names that don't exist (defensive — real shapes
    // shouldn't include unknown chips).
    let chips: Vec<&Chip<KoalaBear, A>> = shape
        .inner
        .iter()
        .filter_map(|(name, _log_height)| {
            machine.chips().iter().find(|c| c.name() == name.as_str())
        })
        .collect();

    // Build (name, log_height) pairs in shape order — mirrors the
    // shape's chip enumeration so the dummy's `chip_log_heights` /
    // `chip_cumulative_sums` map entries align with what the parity
    // test (`stark.rs::tests::dummy_basefold_vk_and_shard_proof_shape_stable`)
    // and the recursion-program builder expect.
    let chip_log_heights_pairs: Vec<(String, u8)> = chips
        .iter()
        .zip(shape.inner.iter())
        .map(|(chip, (_, log_height))| {
            let name = MachineAir::<KoalaBear>::name(*chip);
            (name, *log_height as u8)
        })
        .collect();

    let max_log_row_count =
        BasefoldShardVerifier::production_default().max_log_row_count;

    let proof = crate::dummy::dummy_basefold_shard_proof::<KoalaBear, InnerChallenge, A>(
        &chips,
        &chip_log_heights_pairs,
        max_log_row_count,
    );

    // Build a minimal-but-shape-correct VK matching the legacy
    // dummy: empty chip_information (preprocessed-keyed), name-keyed
    // chip_ordering. Recursion-side reads chip_ordering when fixing
    // the witness-stream order; chip_information is only consumed
    // by the legacy FRI vk-commit path which the basefold pipeline
    // doesn't exercise on the dummy fixture.
    let chip_ordering = shape
        .inner
        .iter()
        .enumerate()
        .map(|(i, (name, _))| (name.to_owned(), i))
        .collect::<HashMap<_, _>>();
    let vk = StarkVerifyingKey {
        commit: dummy_commit(),
        pc_start: KoalaBear::ZERO,
        initial_global_cumulative_sum: SepticDigest::<KoalaBear>::zero(),
        chip_information: Vec::new(),
        chip_ordering,
    };

    (vk, proof)
}

#[derive(Clone)]
pub struct MerkleProofVariable<C: CircuitConfig, HV: FieldHasherVariable<C>> {
    pub index: Vec<C::Bit>,
    pub path: Vec<HV::DigestVariable>,
}

pub const EMPTY: usize = 0x_1111_1111;

#[derive(Debug, Clone, Copy)]
pub struct StarkVerifier<C: Config, SC: StarkGenericConfig, A> {
    _phantom: std::marker::PhantomData<(C, SC, A)>,
}

pub struct VerifyingKeyHint<'a, SC: StarkGenericConfig, A> {
    pub machine: &'a StarkMachine<SC, A>,
    pub vk: &'a StarkVerifyingKey<SC>,
}

impl<'a, SC: StarkGenericConfig, A: MachineAir<SC::Val>> VerifyingKeyHint<'a, SC, A> {
    pub const fn new(machine: &'a StarkMachine<SC, A>, vk: &'a StarkVerifyingKey<SC>) -> Self {
        Self { machine, vk }
    }
}

impl<C, SC, A> StarkVerifier<C, SC, A>
where
    C::F: TwoAdicField,
    C: CircuitConfig<F = SC::Val>,
    SC: KoalaBearFriParametersVariable<C>,
    A: MachineAir<Val<SC>>,
{
    pub fn natural_domain_for_degree(
        config: &SC,
        degree: usize,
    ) -> TwoAdicMultiplicativeCoset<C::F> {
        <SC::Pcs as Pcs<SC::Challenge, SC::FriChallenger>>::natural_domain_for_degree(
            config.pcs(),
            degree,
        )
    }

    pub fn verify_shard(
        builder: &mut Builder<C>,
        vk: &VerifyingKeyVariable<C, SC>,
        machine: &StarkMachine<SC, A>,
        challenger: &mut SC::FriChallengerVariable,
        proof: &ShardProofVariable<C, SC>,
    ) where
        A: for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
    SymbolicExt<C::F, C::EF>: p3_field::Algebra<C::EF>,
    {
        let chips = machine.shard_chips_ordered(&proof.chip_ordering).collect::<Vec<_>>();

        let ShardProofVariable {
            commitment,
            opened_values,
            opening_proof,
            chip_ordering,
            public_values,
            basefold_jagged_fingerprint: _,
        } = proof;

        // Assert that the byte multiplicities don't overflow.
        let mut max_byte_lookup_mult = 0u64;
        chips.iter().zip(opened_values.chips.iter()).for_each(|(chip, val)| {
            max_byte_lookup_mult = max_byte_lookup_mult
                .checked_add(
                    (chip.num_sent_byte_lookups() as u64)
                        .checked_mul(1u64.checked_shl(val.log_degree as u32).unwrap())
                        .unwrap(),
                )
                .unwrap();
        });

        assert!(
            max_byte_lookup_mult <= SC::Val::order().to_u64().unwrap(),
            "Byte multiplicities overflow"
        );

        let log_degrees = opened_values.chips.iter().map(|val| val.log_degree).collect::<Vec<_>>();

        let log_quotient_degrees =
            chips.iter().map(|chip| chip.log_quotient_degree()).collect::<Vec<_>>();

        let trace_domains = log_degrees
            .iter()
            .map(|log_degree| Self::natural_domain_for_degree(machine.config(), 1 << log_degree))
            .collect::<Vec<_>>();

        let main_commit = commitment.main_commit;
        let permutation_commit = commitment.permutation_commit().copied();
        let quotient_commit = commitment.quotient_commit().copied();

        challenger.observe(builder, main_commit);

        let local_permutation_challenges =
            (0..2).map(|_| challenger.sample_ext(builder)).collect::<Vec<_>>();

        if let Some(pc) = permutation_commit {
            challenger.observe(builder, pc);
        }
        for (opening, chip) in opened_values.chips.iter().zip_eq(chips.iter()) {
            let local_sum = C::ext2felt(builder, opening.local_cumulative_sum);
            let global_sum = opening.global_cumulative_sum;

            challenger.observe_slice(builder, local_sum);
            challenger.observe_slice(builder, global_sum.0.x.0);
            challenger.observe_slice(builder, global_sum.0.y.0);

            if chip.commit_scope() == LookupScope::Local {
                let is_real: Felt<C::F> = builder.uninit();
                builder.push_op(DslIr::ImmF(is_real, C::F::ONE));
                builder.assert_digest_zero_v2(is_real, global_sum);
            }

            let has_local_lookups =
                chip.sends().iter().chain(chip.receives()).any(|i| i.scope == LookupScope::Local);
            if !has_local_lookups {
                builder.assert_ext_eq(opening.local_cumulative_sum, C::EF::ZERO.cons());
            }
        }

        let alpha = challenger.sample_ext(builder);

        if let Some(qc) = quotient_commit {
            challenger.observe(builder, qc);
        }

        let zeta = challenger.sample_ext(builder);

        let preprocessed_domains_points_and_opens = vk
            .chip_information
            .iter()
            .map(|(name, domain, _)| {
                let i = chip_ordering[name];
                let values = opened_values.chips[i].preprocessed.clone();
                if !chips[i].local_only() {
                    TwoAdicPcsMatsVariable::<C> {
                        domain: *domain,
                        points: vec![zeta, domain.next_point_variable(builder, zeta)],
                        values: vec![values.local, values.next],
                    }
                } else {
                    TwoAdicPcsMatsVariable::<C> {
                        domain: *domain,
                        points: vec![zeta],
                        values: vec![values.local],
                    }
                }
            })
            .collect::<Vec<_>>();

        let main_domains_points_and_opens = trace_domains
            .iter()
            .zip_eq(opened_values.chips.iter())
            .zip_eq(chips.iter())
            .map(|((domain, values), chip)| {
                if !chip.local_only() {
                    TwoAdicPcsMatsVariable::<C> {
                        domain: *domain,
                        points: vec![zeta, domain.next_point_variable(builder, zeta)],
                        values: vec![values.main.local.clone(), values.main.next.clone()],
                    }
                } else {
                    TwoAdicPcsMatsVariable::<C> {
                        domain: *domain,
                        points: vec![zeta],
                        values: vec![values.main.local.clone()],
                    }
                }
            })
            .collect::<Vec<_>>();

        // In the BaseFold pipeline, permutation_commit / quotient_commit
        // are None and the corresponding opened values are empty.
        // Kept as an explicit `if` ternary rather than the
        // `Option::iter().flat_map(...)` idiom because the
        // permutation-mats body borrows `&mut builder`, which
        // cannot escape a FnMut closure.
        let perm_domains_points_and_opens = if permutation_commit.is_some() {
            trace_domains
                .iter()
                .zip_eq(opened_values.chips.iter())
                .map(|(domain, values)| TwoAdicPcsMatsVariable::<C> {
                    domain: *domain,
                    points: vec![zeta, domain.next_point_variable(builder, zeta)],
                    values: vec![
                        values.permutation.local.clone(),
                        values.permutation.next.clone(),
                    ],
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };

        let quotient_chunk_domains = trace_domains
            .iter()
            .zip_eq(log_degrees)
            .zip_eq(log_quotient_degrees)
            .map(|((domain, log_degree), log_quotient_degree)| {
                let quotient_degree = 1 << log_quotient_degree;
                let quotient_domain =
                    domain.create_disjoint_domain(1 << (log_degree + log_quotient_degree));
                quotient_domain.split_domains(quotient_degree)
            })
            .collect::<Vec<_>>();

        let quotient_domains_points_and_opens: Vec<_> = quotient_commit
            .iter()
            .flat_map(|_| {
                proof
                    .opened_values
                    .chips
                    .iter()
                    .zip_eq(quotient_chunk_domains.iter())
                    .flat_map(|(values, qc_domains)| {
                        values.quotient.iter().zip_eq(qc_domains).map(
                            move |(values, q_domain)| TwoAdicPcsMatsVariable::<C> {
                                domain: *q_domain,
                                points: vec![zeta],
                                values: vec![values.clone()],
                            },
                        )
                    })
            })
            .collect();

        // Create the pcs rounds.
        let prep_commit = vk.commitment;
        let prep_round = TwoAdicPcsRoundVariable {
            batch_commit: prep_commit,
            domains_points_and_opens: preprocessed_domains_points_and_opens,
        };
        let main_round = TwoAdicPcsRoundVariable {
            batch_commit: main_commit,
            domains_points_and_opens: main_domains_points_and_opens,
        };
        let mut rounds = vec![prep_round, main_round];

        if let Some(pc) = permutation_commit {
            rounds.push(TwoAdicPcsRoundVariable {
                batch_commit: pc,
                domains_points_and_opens: perm_domains_points_and_opens,
            });
        }
        if let Some(qc) = quotient_commit {
            rounds.push(TwoAdicPcsRoundVariable {
                batch_commit: qc,
                domains_points_and_opens: quotient_domains_points_and_opens,
            });
        }

        // Verify the pcs proof
        builder.cycle_tracker_v2_enter("stage-d-verify-pcs".to_string());
        let config = machine.config().fri_config();
        verify_two_adic_pcs::<C, SC>(builder, config, opening_proof, challenger, rounds);
        builder.cycle_tracker_v2_exit();

        // Verify the constrtaint evaluations.
        builder.cycle_tracker_v2_enter("stage-e-verify-constraints".to_string());
        let permutation_challenges = local_permutation_challenges;

        // BaseFold-pipeline detection: the prover emits no
        // permutation/quotient commitments in this mode (the
        // soundness work moved to zerocheck + LogUp-GKR + jagged-
        // PCS).  Soundness in this branch is now provided by the
        // three per-chip pillars (LogUp-GKR + zerocheck + jagged-
        // PCS fingerprint) emitted below — the legacy 4-batch
        // STARK verification (constraint folding + PCS opening) is
        // dead code under `legacy_quotient_skipped` and gets
        // short-circuited.  (Originally named `whir_mode` when WHIR
        // was the planned PCS; renamed during the BaseFold migration.)
        let legacy_quotient_skipped = quotient_commit.is_none();

        // BaseFold-pipeline soundness bindings (LogUp-GKR +
        // zerocheck per-chip verifiers + jagged-PCS fingerprint
        // observation) — DISABLED in this iteration.
        //
        // The implementations exist (per_chip_logup_gkr.rs,
        // per_chip_zerocheck.rs) and the structural plumbing
        // (ShardProofVariable fields, Witnessable reads, dummy
        // shape parity) is in place, but invoking the verifiers
        // here introduces additional in-circuit ops whose lookup
        // interactions don't balance against the existing
        // recursion-AIR's lookup count, breaking the
        // local_cumulative_sum == 0 invariant on the compiled
        // recursion proof (validated via aggregation end-to-end
        // run).
        //
        // To enable the bindings safely, the per-chip verifier
        // emission needs to either:
        //   - Be wrapped in a fresh chip whose sends/receives
        //     are accounted for in the recursion AIR's lookup
        //     planning, OR
        //   - Use only ops that don't add new lookup traffic
        //     (observe-only, no challenger sampling that maps
        //     to lookup chips).
        //
        // Until that's resolved, the structural code stays
        // in-tree as the migration target; the actual binding
        // fires once the lookup-balance gap is addressed.
        let _ = &proof.basefold_jagged_fingerprint;

        for (chip, trace_domain, qc_domains, values) in
            izip!(chips.iter(), trace_domains, quotient_chunk_domains, opened_values.chips.iter(),)
        {
            // Verify the shape of the opening arguments matches the expected values.
            Self::verify_opening_shape(chip, values).unwrap();
            if !legacy_quotient_skipped {
                // Verify the constraint evaluation.
                Self::verify_constraints(
                    builder,
                    chip,
                    values,
                    trace_domain,
                    qc_domains,
                    zeta,
                    alpha,
                    &permutation_challenges,
                    public_values,
                );
            }
        }

        // Verify that the chips' local_cumulative_sum sum to 0.
        let local_cumulative_sum: Ext<C::F, C::EF> = opened_values
            .chips
            .iter()
            .map(|val| val.local_cumulative_sum)
            .fold(builder.constant(C::EF::ZERO), |acc, x| builder.eval(acc + x));
        let zero_ext: Ext<_, _> = builder.constant(C::EF::ZERO);
        builder.assert_ext_eq(local_cumulative_sum, zero_ext);

        builder.cycle_tracker_v2_exit();
    }
}

impl<C: CircuitConfig<F = SC::Val>, SC: KoalaBearFriParametersVariable<C>> ShardProofVariable<C, SC> {
    pub fn contains_cpu(&self) -> bool {
        self.chip_ordering.contains_key("Cpu")
    }

    pub fn log_degree_cpu(&self) -> usize {
        let idx = self.chip_ordering.get("Cpu").expect("Cpu chip not found");
        self.opened_values.chips[*idx].log_degree
    }

    pub fn contains_memory_init(&self) -> bool {
        self.chip_ordering.contains_key("MemoryGlobalInit")
    }

    pub fn contains_memory_finalize(&self) -> bool {
        self.chip_ordering.contains_key("MemoryGlobalFinalize")
    }
}

#[allow(unused_imports)]
#[cfg(test)]
pub mod tests {
    use std::collections::VecDeque;
    use std::fmt::Debug;

    use crate::{
        challenger::{CanCopyChallenger, CanObserveVariable, DuplexChallengerVariable},
        utils::tests::run_test_recursion_with_prover,
        KoalaBearFriParameters,
    };

    use zkm_core_executor::Program;
    use zkm_core_machine::{
        io::ZKMStdin,
        mips::MipsAir,
        utils::{prove, setup_logger},
    };
    use zkm_recursion_compiler::{
        config::{InnerConfig, OuterConfig},
        ir::{Builder, DslIr, TracedVec},
    };

    use test_artifacts::FIBONACCI_ELF;
    use zkm_recursion_core::{air::Block, machine::RecursionAir, stark::KoalaBearPoseidon2Outer};
    use zkm_stark::{
        koala_bear_poseidon2::KoalaBearPoseidon2, CpuProver, InnerVal, MachineProver, ShardProof,
        ZKMCoreOpts,
    };

    use super::*;
    use crate::witness::*;

    type F = InnerVal;
    type A = MipsAir<F>;
    type SC = KoalaBearPoseidon2;

    /// Verifies `dummy_basefold_vk_and_shard_proof` produces a
    /// proof whose `chip_cumulative_sums` map cardinality matches
    /// the input shape's chip count — the shape-stability invariant
    /// the recursion-program builder depends on.
    #[test]
    fn dummy_basefold_vk_and_shard_proof_shape_stable() {
        let machine = MipsAir::<KoalaBear>::machine(KoalaBearPoseidon2::default());
        // Pick two real chips with deterministic widths.  AddSub +
        // Bitwise both exist in MipsAir and have small preprocessed
        // widths — keeps the dummy proof inexpensive.
        let shape = OrderedShape::from_log2_heights(&[
            ("AddSub".to_string(), 3),
            ("Bitwise".to_string(), 3),
        ]);
        let (vk, proof) = super::dummy_basefold_vk_and_shard_proof::<MipsAir<KoalaBear>>(
            &machine, &shape,
        );
        assert_eq!(
            vk.chip_ordering.len(),
            shape.inner.len(),
            "vk chip_ordering must match shape chip count",
        );
        assert_eq!(
            proof.chip_cumulative_sums.len(),
            shape.inner.len(),
            "chip_cumulative_sums must have one entry per chip in the shape \
             — this is the shape-stability invariant for program_from_shape",
        );
        assert_eq!(
            proof.chip_log_heights.len(),
            shape.inner.len(),
            "chip_log_heights must have one entry per chip in the shape",
        );
        // opened_values.chips is intentionally empty in the basefold
        // pipeline — the recursion verifier builds per-chip openings
        // from LogUp-GKR's chip_openings instead (see prover.rs:207
        // and shard_basefold.rs's BasefoldShardOpenedValuesVariable).
    }
}

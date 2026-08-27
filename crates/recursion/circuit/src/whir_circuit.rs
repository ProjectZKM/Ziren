//! In-circuit verifier for the stacked-WHIR inner PCS.
//!
//! The WHIR sibling of [`crate::basefold_verifier`]: verifies a
//! [`zkm_pcs::whir::stacked::StackedWhirProof`] inside the recursion circuit,
//! replaying the EXACT transcript of the host
//! `StackedWhirVerifier::verify_trusted_evaluation`
//! (crates/pcs/src/whir/stacked.rs) — observe echoed batch evaluations, draw
//! λ, walk each round's folding sumcheck, Merkle-bind every STIR/final query
//! opening, and close with the terminal identity over the mixed
//! Lagrange/monomial constraint set.
//!
//! Shape philosophy matches the BaseFold circuit verifier: everything
//! structural (round count, folding factor, stripe counts, domain sizes, PoW
//! bit budgets, path depths) is COMPILE-TIME from the `WhirConfig` + the
//! round stripe counts, so the emitted program is value-independent; only
//! field elements and digests are witnessed.

use p3_field::PrimeCharacteristicRing;
use p3_field::TwoAdicField;
use zkm_pcs::whir::config::WhirConfig;
use zkm_pcs::{InnerChallenge, InnerVal};
use zkm_recursion_compiler::ir::{Builder, Ext, Felt, SymbolicExt};

use crate::challenger::{CanObserveVariable, FieldChallengerVariable};
use crate::hash::FieldHasherVariable;
use crate::logup_gkr::{evaluate_mle_ext, observe_ext_element};
use crate::witness::{WitnessWriter, Witnessable};
use crate::CircuitConfig;

/// One opened Merkle leaf: the per-matrix opened rows plus the sibling path.
/// Mirror of the host [`zkm_pcs::basefold::proof::LeafOpening`].
#[derive(Clone)]
pub struct RecursiveWhirLeafOpening<F, EF, Dig> {
    /// Round-0 stripe rows: one inner vec per committed stripe matrix at
    /// this index, each `2^ff` base felts.  Empty for later-round leaves.
    pub values: Vec<Vec<F>>,
    /// Later-round leaf: the `2^ff` EF codeword values (the host commits
    /// their base limbs; the circuit re-derives the limbs via `ext2felt`
    /// for the leaf hash — `CircuitFelts2Ext` is gnark-only, so the EF
    /// values are witnessed directly, exactly like the BaseFold
    /// commit-phase openings).  Empty for round-0 leaves.
    pub ef_values: Vec<EF>,
    /// Sibling digests, leaf-to-root.
    pub path: Vec<Dig>,
}

/// One round's query openings (final queries ride in the last entry).
/// Mirror of the host [`zkm_pcs::basefold::proof::MerkleOpening`].
#[derive(Clone)]
pub struct RecursiveWhirMerkleOpening<F, EF, Dig> {
    pub leaves: Vec<RecursiveWhirLeafOpening<F, EF, Dig>>,
}

/// In-circuit mirror of the host
/// [`zkm_pcs::whir::stacked::StackedWhirProof`]. Instantiated with concrete
/// `InnerVal`/`InnerChallenge`/`[InnerVal; 8]` on the host (lift) side and
/// with `Felt`/`Ext`/`DigestVariable` on the circuit side.
#[derive(Clone)]
pub struct RecursiveStackedWhirProof<F, EF, Dig> {
    /// Per-round folding-sumcheck messages, EXCLUDING the final round
    /// (outer = round, inner = the `folding_factor` degree-2 messages,
    /// each `[c0, c1, c2]`).
    pub round_sumcheck_polys: Vec<Vec<[EF; 3]>>,
    /// Per-round OOD answers on the newly committed folded polynomial.
    pub round_ood_answers: Vec<Vec<EF>>,
    /// Per-round Merkle roots of the folded codewords.
    pub round_commitments: Vec<Dig>,
    /// Per-round query openings of the PREVIOUS codeword; the LAST entry
    /// holds the final queries.
    pub round_query_openings: Vec<RecursiveWhirMerkleOpening<F, EF, Dig>>,
    /// The fully folded polynomial (`2^final_log` monomial coefficients).
    pub final_poly: Vec<EF>,
    /// The final round's folding-sumcheck messages.
    pub final_sumcheck_polys: Vec<[EF; 3]>,
    /// Flat grinding witnesses: per-variable folding PoW interleaved with
    /// each round's query PoW, in prover emission order.
    pub folding_pow: Vec<F>,
    /// Final-query grinding witness.
    pub final_pow: F,
    /// Echoed per-round per-stripe evaluations at the stack point.
    pub batch_evaluations: Vec<Vec<EF>>,
}

/// Extract the host-value mirror from a host stacked-WHIR proof.
pub fn host_stacked_whir_to_recursive(
    proof: &zkm_pcs::whir::stacked::StackedWhirProof<
        InnerVal,
        InnerChallenge,
        zkm_pcs::jagged_pcs::JaggedMmcs,
    >,
) -> RecursiveStackedWhirProof<InnerVal, InnerChallenge, [InnerVal; 8]> {
    let whir = &proof.whir_proof;
    let conv_msgs = |msgs: &[zkm_pcs::whir::proof::SumcheckPoly<InnerChallenge>]| {
        msgs.iter()
            .map(|p| {
                assert_eq!(p.0.len(), 3, "whir sumcheck message must be degree 2");
                [p.0[0], p.0[1], p.0[2]]
            })
            .collect::<Vec<_>>()
    };
    RecursiveStackedWhirProof {
        round_sumcheck_polys: whir.round_sumcheck_polys.iter().map(|r| conv_msgs(r)).collect(),
        round_ood_answers: whir.round_ood_answers.clone(),
        round_commitments: whir
            .round_commitments
            .iter()
            .map(|c| {
                let roots = c.roots();
                assert_eq!(roots.len(), 1, "whir round commitment must be a height-0 cap");
                roots[0]
            })
            .collect(),
        round_query_openings: whir
            .round_query_openings
            .iter()
            .enumerate()
            .map(|(i, op)| RecursiveWhirMerkleOpening {
                leaves: op
                    .leaves
                    .iter()
                    .map(|l| {
                        if i == 0 {
                            // Round-0 (or a single-round final): stripe rows.
                            RecursiveWhirLeafOpening {
                                values: l.values.clone(),
                                ef_values: Vec::new(),
                                path: l.proof.clone(),
                            }
                        } else {
                            use p3_field::BasedVectorSpace;
                            const D: usize = 4;
                            assert_eq!(l.values.len(), 1, "whir ef leaf is one matrix");
                            let ef_values = l.values[0]
                                .chunks_exact(D)
                                .map(|c| {
                                    <InnerChallenge as BasedVectorSpace<InnerVal>>::
                                        from_basis_coefficients_iter(c.iter().copied())
                                    .expect("EF parse")
                                })
                                .collect();
                            RecursiveWhirLeafOpening {
                                values: Vec::new(),
                                ef_values,
                                path: l.proof.clone(),
                            }
                        }
                    })
                    .collect(),
            })
            .collect(),
        final_poly: whir.final_poly.clone(),
        final_sumcheck_polys: conv_msgs(&whir.final_sumcheck_polys),
        folding_pow: whir.folding_pow.iter().map(|p| p.0).collect(),
        final_pow: whir.final_pow.0,
        batch_evaluations: proof.batch_evaluations.clone(),
    }
}

/// Witness the host mirror into circuit variables, element by element, in
/// declaration order.  [`write_stacked_whir_to_stream`] mirrors the order.
pub fn read_stacked_whir_from_stream<C>(
    host: &RecursiveStackedWhirProof<InnerVal, InnerChallenge, [InnerVal; 8]>,
    builder: &mut Builder<C>,
) -> RecursiveStackedWhirProof<Felt<C::F>, Ext<C::F, C::EF>, [Felt<C::F>; 8]>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    RecursiveStackedWhirProof {
        round_sumcheck_polys: host
            .round_sumcheck_polys
            .iter()
            .map(|r| r.iter().map(|m| core::array::from_fn(|i| m[i].read(builder))).collect())
            .collect(),
        round_ood_answers: host
            .round_ood_answers
            .iter()
            .map(|r| r.iter().map(|a| a.read(builder)).collect())
            .collect(),
        round_commitments: host
            .round_commitments
            .iter()
            .map(|d| core::array::from_fn(|i| d[i].read(builder)))
            .collect(),
        round_query_openings: host
            .round_query_openings
            .iter()
            .map(|op| RecursiveWhirMerkleOpening {
                leaves: op
                    .leaves
                    .iter()
                    .map(|l| RecursiveWhirLeafOpening {
                        values: l
                            .values
                            .iter()
                            .map(|row| row.iter().map(|v| v.read(builder)).collect())
                            .collect(),
                        ef_values: l.ef_values.iter().map(|v| v.read(builder)).collect(),
                        path: l
                            .path
                            .iter()
                            .map(|d| core::array::from_fn(|i| d[i].read(builder)))
                            .collect(),
                    })
                    .collect(),
            })
            .collect(),
        final_poly: host.final_poly.iter().map(|c| c.read(builder)).collect(),
        final_sumcheck_polys: host
            .final_sumcheck_polys
            .iter()
            .map(|m| core::array::from_fn(|i| m[i].read(builder)))
            .collect(),
        folding_pow: host.folding_pow.iter().map(|p| p.read(builder)).collect(),
        final_pow: host.final_pow.read(builder),
        batch_evaluations: host
            .batch_evaluations
            .iter()
            .map(|r| r.iter().map(|e| e.read(builder)).collect())
            .collect(),
    }
}

/// Stream-write the host mirror; MUST match [`read_stacked_whir_from_stream`]
/// element order exactly.
pub fn write_stacked_whir_to_stream<C>(
    host: &RecursiveStackedWhirProof<InnerVal, InnerChallenge, [InnerVal; 8]>,
    witness: &mut impl WitnessWriter<C>,
) where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    for r in &host.round_sumcheck_polys {
        for m in r {
            for c in m {
                c.write(witness);
            }
        }
    }
    for r in &host.round_ood_answers {
        for a in r {
            a.write(witness);
        }
    }
    for d in &host.round_commitments {
        for f in d {
            f.write(witness);
        }
    }
    for op in &host.round_query_openings {
        for l in &op.leaves {
            for row in &l.values {
                for v in row {
                    v.write(witness);
                }
            }
            for v in &l.ef_values {
                v.write(witness);
            }
            for d in &l.path {
                for f in d {
                    f.write(witness);
                }
            }
        }
    }
    for c in &host.final_poly {
        c.write(witness);
    }
    for m in &host.final_sumcheck_polys {
        for c in m {
            c.write(witness);
        }
    }
    for p in &host.folding_pow {
        p.write(witness);
    }
    host.final_pow.write(witness);
    for r in &host.batch_evaluations {
        for e in r {
            e.write(witness);
        }
    }
}

/// In-circuit verifier for a stacked-WHIR batched opening.  Generic over
/// the Merkle hasher `HV` exactly like
/// [`crate::basefold_verifier::RecursiveBasefoldVerifier`]; defaults to the
/// inner KoalaBear Poseidon2 ring (the only ring that verifies WHIR core
/// proofs — recursion shards stay BaseFold).
pub struct RecursiveStackedWhirVerifier<HV = zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2> {
    pub config: WhirConfig,
    pub log_stacking_height: u32,
    pub _hasher: core::marker::PhantomData<HV>,
}

impl<HV> Clone for RecursiveStackedWhirVerifier<HV> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            log_stacking_height: self.log_stacking_height,
            _hasher: core::marker::PhantomData,
        }
    }
}

/// `g^index` for a compile-time base `g` and an LSB-first index bit vector:
/// `Π_j select(bit_j, g^(2^j), 1)`.
fn exp_bits_lsb<C: CircuitConfig>(
    builder: &mut Builder<C>,
    base: C::F,
    bits: &[C::Bit],
) -> Felt<C::F> {
    let mut result: Felt<C::F> = builder.constant(C::F::ONE);
    let mut pow = base;
    for bit in bits {
        let factor = C::select_const_f(builder, bit.clone(), C::F::ONE, pow);
        result = builder.eval(result * factor);
        pow = pow * pow;
    }
    result
}

/// Walk a Merkle path from a hashed leaf and bind the root to `commitment`.
/// Direction bit at level `k` = index bit `k` (LSB-first, full-height tree
/// — mirror of the host `MerkleTreeMmcs::verify_batch`).
fn merkle_bind_leaf<C, HV>(
    builder: &mut Builder<C>,
    leaf_felts: &[Felt<C::F>],
    path: &[HV::DigestVariable],
    index_bits: &[C::Bit],
    commitment: &HV::DigestVariable,
) where
    C: CircuitConfig,
    HV: FieldHasherVariable<C>,
{
    assert_eq!(path.len(), index_bits.len(), "whir merkle path must consume every index bit");
    let mut digest = HV::hash(builder, leaf_felts);
    for (level, sibling) in path.iter().enumerate() {
        let bit = index_bits[level].clone();
        let pair = HV::select_chain_digest(builder, bit, [digest, *sibling]);
        digest = HV::compress(builder, pair);
    }
    HV::assert_digest_eq(builder, digest, *commitment);
}

/// A deferred terminal constraint (mirror of the host verifier's `C` enum).
enum TerminalConstraint<C: zkm_recursion_compiler::ir::Config> {
    Lagrange { point: Vec<Ext<C::F, C::EF>>, coeff: Ext<C::F, C::EF>, vars: usize },
    Monomial { point: Vec<Ext<C::F, C::EF>>, coeff: Ext<C::F, C::EF>, vars: usize },
}

impl<HVOuter> RecursiveStackedWhirVerifier<HVOuter> {
    /// Monomial-basis multilinear evaluation `Σ_i coeffs[i]·Π_j pt[j]^bit_j(i)`
    /// (LSB-first) — mirror of the host `mono_eval_lsb`.
    fn mono_eval_lsb<C: CircuitConfig>(
        builder: &mut Builder<C>,
        coeffs: &[Ext<C::F, C::EF>],
        point: &[Ext<C::F, C::EF>],
    ) -> Ext<C::F, C::EF> {
        assert_eq!(coeffs.len(), 1usize << point.len());
        let mut weights: Vec<SymbolicExt<C::F, C::EF>> = vec![SymbolicExt::ONE];
        for &p in point {
            let p_sym: SymbolicExt<C::F, C::EF> = p.into();
            let old = weights.len();
            let mut next = Vec::with_capacity(old * 2);
            for w in &weights {
                next.push(*w);
            }
            for w in &weights[..old] {
                next.push(*w * p_sym);
            }
            weights = next;
        }
        let acc = coeffs
            .iter()
            .zip(&weights)
            .map(|(c, w)| SymbolicExt::<C::F, C::EF>::from(*c) * *w)
            .fold(SymbolicExt::ZERO, |a, b| a + b);
        builder.eval(acc)
    }

    /// Verify a stacked-WHIR batched opening in-circuit.
    ///
    /// Exact transcript mirror of the host
    /// `StackedWhirVerifier::verify_trusted_evaluation`; the caller has
    /// already witnessed `commitments` (and observed them wherever the host
    /// flow observes them) and provides `stack_point` from its own claim
    /// structure.  The echoed `proof.batch_evaluations` are bound by the
    /// caller (the jagged layer interpolates them against its claim).
    #[allow(clippy::too_many_arguments)]
    pub fn verify<C, FC, HV>(
        &self,
        builder: &mut Builder<C>,
        commitments: &[HV::DigestVariable],
        round_stripe_counts: &[usize],
        stack_point: &[Ext<C::F, C::EF>],
        batch_evaluations: &[Vec<Ext<C::F, C::EF>>],
        proof: &RecursiveStackedWhirProof<Felt<C::F>, Ext<C::F, C::EF>, HV::DigestVariable>,
        challenger: &mut FC,
    ) where
        C: CircuitConfig,
        FC: FieldChallengerVariable<C, C::Bit> + CanObserveVariable<C, HV::DigestVariable>,
        HV: FieldHasherVariable<C>,
    {
        let lsh = self.log_stacking_height as usize;
        let ff = self.config.round_parameters[0].folding_factor;
        let num_rounds = self.config.round_parameters.len();
        let folds: Vec<usize> =
            self.config.round_parameters.iter().map(|rp| rp.folding_factor).collect();
        let n = lsh;
        let final_log = n - folds.iter().sum::<usize>();

        // ── Structural shape checks (compile-time). ──
        assert_eq!(proof.final_poly.len(), 1usize << final_log, "whir final_poly len");
        assert_eq!(batch_evaluations.len(), round_stripe_counts.len(), "whir round count");
        assert_eq!(commitments.len(), round_stripe_counts.len(), "whir commitment count");
        for (evals, &cnt) in batch_evaluations.iter().zip(round_stripe_counts) {
            assert_eq!(evals.len(), cnt, "whir stripe count");
        }
        assert_eq!(
            self.config.starting_ood_samples, 0,
            "stacked WHIR carries its OOD in round constraints"
        );

        // ── Replay claim batching: observe echoed evals, draw λ. ──
        for round in batch_evaluations {
            for &e in round {
                observe_ext_element::<C, FC>(builder, challenger, e);
            }
        }
        let lambda = challenger.sample_ext(builder);
        let one: Ext<C::F, C::EF> = builder.constant(C::EF::ONE);
        let mut lam = one;
        let mut lambda_powers_per_round: Vec<Vec<Ext<C::F, C::EF>>> = Vec::new();
        let mut claim_sym = SymbolicExt::<C::F, C::EF>::ZERO;
        for round in batch_evaluations {
            let mut powers = Vec::with_capacity(round.len());
            for &e in round {
                claim_sym = claim_sym + SymbolicExt::from(lam) * e;
                powers.push(lam);
                lam = builder.eval(lam * lambda);
            }
            lambda_powers_per_round.push(powers);
        }
        let mut claim: Ext<C::F, C::EF> = builder.eval(claim_sym);

        // The (unused) starting-OOD batching draw — transcript sync.
        let _batch = challenger.sample_ext(builder);

        let mut constraints: Vec<TerminalConstraint<C>> = vec![TerminalConstraint::Lagrange {
            point: stack_point.to_vec(),
            coeff: one,
            vars: n,
        }];

        let mut prev_domain_log = (lsh - ff) + self.config.starting_log_inv_rate;
        let mut prev_round0 = true;
        let mut all_fr: Vec<Ext<C::F, C::EF>> = Vec::with_capacity(n - final_log);
        let mut pow_flat = 0usize;
        let mut folded_vars = 0usize;
        for (r, round_cfg) in self.config.round_parameters.iter().enumerate() {
            let msgs: &[[Ext<C::F, C::EF>; 3]] = if r + 1 == num_rounds {
                &proof.final_sumcheck_polys
            } else {
                &proof.round_sumcheck_polys[r]
            };
            assert_eq!(msgs.len(), round_cfg.folding_factor, "whir round messages");
            let mut this_round_randomness: Vec<Ext<C::F, C::EF>> = Vec::with_capacity(ff);
            for (var, poly) in msgs.iter().enumerate() {
                let (c0, c1, c2) = (poly[0], poly[1], poly[2]);
                // Host: c0 + (c0 + c1 + c2) == claim.
                builder.assert_ext_eq(
                    SymbolicExt::from(c0) + c0 + c1 + c2,
                    SymbolicExt::from(claim),
                );
                observe_ext_element::<C, FC>(builder, challenger, c0);
                observe_ext_element::<C, FC>(builder, challenger, c1);
                observe_ext_element::<C, FC>(builder, challenger, c2);
                let pow = proof.folding_pow[pow_flat];
                pow_flat += 1;
                challenger.check_witness(
                    builder,
                    round_cfg.pow_bits.get(var).copied().unwrap_or(0),
                    pow,
                );
                let rc = challenger.sample_ext(builder);
                claim = builder.eval(SymbolicExt::from(c0) + c1 * rc + c2 * rc * rc);
                all_fr.push(rc);
                this_round_randomness.push(rc);
            }
            folded_vars += round_cfg.folding_factor;

            if r + 1 == num_rounds {
                break;
            }

            challenger.observe(builder, proof.round_commitments[r]);
            let rem = n - folded_vars;
            let ood_answers = &proof.round_ood_answers[r];
            assert_eq!(ood_answers.len(), round_cfg.ood_samples, "whir ood count");
            let mut ood_points: Vec<Vec<Ext<C::F, C::EF>>> = Vec::with_capacity(ood_answers.len());
            for ans in ood_answers.iter() {
                let pt: Vec<Ext<C::F, C::EF>> =
                    (0..rem).map(|_| challenger.sample_ext(builder)).collect();
                observe_ext_element::<C, FC>(builder, challenger, *ans);
                ood_points.push(pt);
            }

            let query_pow = proof.folding_pow[pow_flat];
            pow_flat += 1;
            challenger.check_witness(builder, round_cfg.queries_pow_bits, query_pow);
            let index_bit_vecs: Vec<Vec<C::Bit>> = (0..round_cfg.num_queries)
                .map(|_| challenger.sample_bits(builder, prev_domain_log))
                .collect();

            let openings = &proof.round_query_openings[r];
            let leaves_per_query = if prev_round0 { commitments.len() } else { 1 };
            assert_eq!(
                openings.leaves.len(),
                index_bit_vecs.len() * leaves_per_query,
                "whir query openings"
            );
            let g_prev = C::F::two_adic_generator(prev_domain_log);
            let mut stir_points: Vec<Vec<Ext<C::F, C::EF>>> =
                Vec::with_capacity(index_bit_vecs.len());
            let mut stir_values: Vec<Ext<C::F, C::EF>> = Vec::with_capacity(index_bit_vecs.len());
            for (qi, bits) in index_bit_vecs.iter().enumerate() {
                let virt_leaf: Vec<Ext<C::F, C::EF>> = if prev_round0 {
                    let mut acc =
                        vec![SymbolicExt::<C::F, C::EF>::ZERO; 1usize << ff];
                    for (ri, commitment) in commitments.iter().enumerate() {
                        let leaf = &openings.leaves[qi * leaves_per_query + ri];
                        assert_eq!(leaf.values.len(), round_stripe_counts[ri], "whir stripe rows");
                        let leaf_felts: Vec<Felt<C::F>> =
                            leaf.values.iter().flatten().copied().collect();
                        merkle_bind_leaf::<C, HV>(builder, &leaf_felts, &leaf.path, bits, commitment);
                        for (row, &lp) in leaf.values.iter().zip(&lambda_powers_per_round[ri]) {
                            assert_eq!(row.len(), 1usize << ff, "whir stripe row width");
                            for (a, &s) in acc.iter_mut().zip(row.iter()) {
                                *a = *a + SymbolicExt::from(lp) * s;
                            }
                        }
                    }
                    acc.into_iter().map(|a| builder.eval(a)).collect()
                } else {
                    let leaf = &openings.leaves[qi];
                        assert_eq!(
                        leaf.ef_values.len(),
                        1usize << round_cfg.folding_factor,
                        "whir ef leaf width"
                    );
                    let leaf_felts: Vec<Felt<C::F>> = leaf
                        .ef_values
                        .iter()
                        .flat_map(|v| C::ext2felt(builder, *v))
                        .collect();
                    merkle_bind_leaf::<C, HV>(
                        builder,
                        &leaf_felts,
                        &leaf.path,
                        bits,
                        &proof.round_commitments[r - 1],
                    );
                    leaf.ef_values.clone()
                };
                let stir = evaluate_mle_ext::<C>(builder, &virt_leaf, &this_round_randomness);
                stir_values.push(stir);
                // stir point = map_to_pow_lsb(g_prev^idx, rem) = [x, x², x⁴, …].
                let x_felt = exp_bits_lsb::<C>(builder, g_prev, bits);
                let mut pt = Vec::with_capacity(rem);
                let mut cur: Ext<C::F, C::EF> = builder.eval(SymbolicExt::from(x_felt));
                for _ in 0..rem {
                    pt.push(cur);
                    cur = builder.eval(cur * cur);
                }
                stir_points.push(pt);
            }

            let round_batch = challenger.sample_ext(builder);
            let mut cc = round_batch;
            let mut claim_add = SymbolicExt::<C::F, C::EF>::from(claim);
            for (ans, pt) in ood_answers.iter().zip(ood_points) {
                claim_add = claim_add + SymbolicExt::from(cc) * *ans;
                constraints.push(TerminalConstraint::Lagrange { point: pt, coeff: cc, vars: rem });
                cc = builder.eval(cc * round_batch);
            }
            for (v, pt) in stir_values.iter().zip(stir_points) {
                claim_add = claim_add + SymbolicExt::from(cc) * *v;
                constraints.push(TerminalConstraint::Monomial { point: pt, coeff: cc, vars: rem });
                cc = builder.eval(cc * round_batch);
            }
            claim = builder.eval(claim_add);

            prev_domain_log =
                (rem - self.config.round_parameters[r + 1].folding_factor)
                    + round_cfg.log_inv_rate;
            prev_round0 = false;
        }

        // ── Final PoW + final queries. ──
        challenger.check_witness(builder, self.config.final_pow_bits, proof.final_pow);
        let final_openings = proof.round_query_openings.last().unwrap();
        let leaves_per_query = if prev_round0 { commitments.len() } else { 1 };
        assert_eq!(
            final_openings.leaves.len(),
            self.config.final_queries * leaves_per_query,
            "whir final query count"
        );
        let g_final = C::F::two_adic_generator(prev_domain_log);
        let last_ff = *folds.last().unwrap();
        let last_randomness = all_fr[all_fr.len() - last_ff..].to_vec();
        for q in 0..self.config.final_queries {
            let bits = challenger.sample_bits(builder, prev_domain_log);
            let virt_leaf: Vec<Ext<C::F, C::EF>> = if prev_round0 {
                let mut acc = vec![SymbolicExt::<C::F, C::EF>::ZERO; 1usize << last_ff];
                for (ri, commitment) in commitments.iter().enumerate() {
                    let leaf = &final_openings.leaves[q * leaves_per_query + ri];
                    assert_eq!(leaf.values.len(), round_stripe_counts[ri], "whir final rows");
                    let leaf_felts: Vec<Felt<C::F>> =
                        leaf.values.iter().flatten().copied().collect();
                    merkle_bind_leaf::<C, HV>(builder, &leaf_felts, &leaf.path, &bits, commitment);
                    for (row, &lp) in leaf.values.iter().zip(&lambda_powers_per_round[ri]) {
                        for (a, &s) in acc.iter_mut().zip(row.iter()) {
                            *a = *a + SymbolicExt::from(lp) * s;
                        }
                    }
                }
                acc.into_iter().map(|a| builder.eval(a)).collect()
            } else {
                let leaf = &final_openings.leaves[q];
                assert_eq!(leaf.ef_values.len(), 1usize << last_ff, "whir final leaf width");
                let leaf_felts: Vec<Felt<C::F>> = leaf
                    .ef_values
                    .iter()
                    .flat_map(|v| C::ext2felt(builder, *v))
                    .collect();
                merkle_bind_leaf::<C, HV>(
                    builder,
                    &leaf_felts,
                    &leaf.path,
                    &bits,
                    proof.round_commitments.last().unwrap(),
                );
                leaf.ef_values.clone()
            };
            let folded = evaluate_mle_ext::<C>(builder, &virt_leaf, &last_randomness);
            // expected = mono_eval_lsb(final_poly, map_to_pow_lsb(g_final^idx)).
            let x_felt = exp_bits_lsb::<C>(builder, g_final, &bits);
            let mut pt = Vec::with_capacity(final_log);
            let mut cur: Ext<C::F, C::EF> = builder.eval(SymbolicExt::from(x_felt));
            for _ in 0..final_log {
                pt.push(cur);
                cur = builder.eval(cur * cur);
            }
            let expected = Self::mono_eval_lsb::<C>(builder, &proof.final_poly, &pt);
            builder.assert_ext_eq(folded, expected);
        }

        // ── Terminal identity. ──
        let mut total = SymbolicExt::<C::F, C::EF>::ZERO;
        for c in &constraints {
            match c {
                TerminalConstraint::Lagrange { point, coeff, vars } => {
                    let k = vars - final_log;
                    let fr = &all_fr[(n - vars)..(n - vars) + k];
                    let mut eq_part = SymbolicExt::<C::F, C::EF>::ONE;
                    for (x, y) in point[..k].iter().zip(fr) {
                        let x_s = SymbolicExt::from(*x);
                        let y_s = SymbolicExt::from(*y);
                        eq_part = eq_part
                            * (x_s * y_s
                                + (SymbolicExt::<C::F, C::EF>::ONE - x_s)
                                    * (SymbolicExt::<C::F, C::EF>::ONE - y_s));
                    }
                    let f_part = evaluate_mle_ext::<C>(builder, &proof.final_poly, &point[k..]);
                    total = total + SymbolicExt::from(*coeff) * eq_part * f_part;
                }
                TerminalConstraint::Monomial { point, coeff, vars } => {
                    let k = vars - final_log;
                    let fr = &all_fr[(n - vars)..(n - vars) + k];
                    let mut fold_part = SymbolicExt::<C::F, C::EF>::ONE;
                    for (x, y) in point[..k].iter().zip(fr) {
                        let x_s = SymbolicExt::from(*x);
                        let y_s = SymbolicExt::from(*y);
                        fold_part =
                            fold_part * (SymbolicExt::<C::F, C::EF>::ONE - y_s + y_s * x_s);
                    }
                    let f_part = Self::mono_eval_lsb::<C>(builder, &proof.final_poly, &point[k..]);
                    total = total + SymbolicExt::from(*coeff) * fold_part * f_part;
                }
            }
        }
        builder.assert_ext_eq(total, SymbolicExt::from(claim));
    }
}

/// Wires the stacked-WHIR verifier into the shared stacked-PCS layer:
/// [`crate::recursive_stacked_pcs::RecursiveStackedPcsVerifier`] does the
/// batch-point interpolation bind (the in-circuit mirror of the host
/// `verify_jagged_whir_rounds` StackingMismatch check plus the FS point
/// extension), then delegates here with the wrapper-carried
/// `batch_evaluations` — the ONE witnessed copy both the interpolation and
/// this verifier's λ-batching consume.
///
/// The per-round stripe counts come from the `batch_evaluations` SHAPE
/// (compile-time program structure); each round-0 Merkle leaf hashes exactly
/// `stripe_count` rows, so a mis-shaped count fails the digest bind against
/// the FS-observed (main) / vk-pinned (preprocessed) commitment.
impl<C, FC, HV> crate::recursive_stacked_pcs::RecursiveMultilinearPcsVerifier<C, FC>
    for RecursiveStackedWhirVerifier<HV>
where
    C: CircuitConfig,
    FC: FieldChallengerVariable<C, C::Bit> + CanObserveVariable<C, HV::DigestVariable>,
    HV: FieldHasherVariable<C>,
{
    type Commitment = HV::DigestVariable;
    type Proof = RecursiveStackedWhirProof<Felt<C::F>, Ext<C::F, C::EF>, HV::DigestVariable>;

    fn observe_commitment(
        &self,
        builder: &mut Builder<C>,
        challenger: &mut FC,
        commitment: &Self::Commitment,
    ) {
        challenger.observe(builder, *commitment);
    }

    fn verify_untrusted_evaluations(
        &self,
        builder: &mut Builder<C>,
        commitments: &[Self::Commitment],
        stack_point: &[Ext<C::F, C::EF>],
        batch_evaluations: &[Vec<Ext<C::F, C::EF>>],
        proof: &Self::Proof,
        challenger: &mut FC,
    ) {
        let counts: Vec<usize> = batch_evaluations.iter().map(|r| r.len()).collect();
        self.verify::<C, FC, HV>(
            builder,
            commitments,
            &counts,
            stack_point,
            batch_evaluations,
            proof,
            challenger,
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use p3_dft::Radix2DitParallel;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use zkm_pcs::basefold::mle::Mle;
    use zkm_pcs::jagged_pcs::JaggedMmcs;
    use zkm_pcs::{InnerChallenger, InnerCompress, InnerHash, InnerPerm};
    use zkm_pcs::whir::jagged::whir_config_for_stack;
    use zkm_pcs::whir::stacked::{StackedWhirProver, StackedWhirVerifier};
    use zkm_pcs::{InnerChallenge, InnerVal};
    use zkm_primitives::poseidon2_init;
    use zkm_recursion_compiler::config::InnerConfig;
    use zkm_recursion_compiler::ir::Builder;

    use super::*;
    use crate::challenger::DuplexChallengerVariable;
    use crate::utils::tests::run_test_recursion;
    use crate::witness::WitnessBlock;

    type F = InnerVal;
    type EF = InnerChallenge;

    fn build_mmcs() -> JaggedMmcs {
        let perm: InnerPerm = poseidon2_init();
        JaggedMmcs::new(InnerHash::new(perm.clone()), InnerCompress::new(perm), 0)
    }

    fn rand_kb(rng: &mut StdRng) -> F {
        use p3_field::PrimeField32;
        F::from_u32(rng.gen_range(0..F::ORDER_U32))
    }

    /// Host-prove a small stacked-WHIR instance (the shape of the pcs
    /// `stacked_roundtrip_verifies` test, generated by the production
    /// `whir_config_for_stack`), then verify it IN-CIRCUIT with witnessed
    /// values, executing the program through the recursion runtime.
    /// `tamper` mutates the proof's host mirror before witnessing, for the
    /// negative tests.
    fn run_whir_circuit_roundtrip(
        tamper: impl FnOnce(
            &mut RecursiveStackedWhirProof<InnerVal, InnerChallenge, [InnerVal; 8]>,
        ),
    ) {
        let lsh = 9usize;
        run_whir_circuit_roundtrip_with(lsh, whir_config_for_stack(lsh, 3, 0), tamper);
    }

    fn run_whir_circuit_roundtrip_with(
        lsh: usize,
        cfg: zkm_pcs::whir::config::WhirConfig,
        tamper: impl FnOnce(
            &mut RecursiveStackedWhirProof<InnerVal, InnerChallenge, [InnerVal; 8]>,
        ),
    ) {
        let mut rng = StdRng::seed_from_u64(0x57AC);

        let dft = Arc::new(Radix2DitParallel::<F>::default());
        let ef_dft = Arc::new(Radix2DitParallel::<EF>::default());
        let prover =
            StackedWhirProver::<F, EF, _, _>::new(build_mmcs(), dft, cfg.clone(), lsh as u32);

        let mk_stripe = |rng: &mut StdRng| {
            let v: Vec<F> = (0..(1usize << lsh)).map(|_| rand_kb(rng)).collect();
            Arc::new(Mle::from_row_major(RowMajorMatrix::new(v, 1)))
        };
        let round_a = prover.commit_stripes(vec![
            mk_stripe(&mut rng),
            mk_stripe(&mut rng),
            mk_stripe(&mut rng),
        ]);
        let round_b = prover.commit_stripes(vec![mk_stripe(&mut rng), mk_stripe(&mut rng)]);

        let stack_point: Vec<EF> = (0..lsh)
            .map(|_| {
                use p3_field::BasedVectorSpace;
                <EF as BasedVectorSpace<F>>::from_basis_coefficients_iter(
                    (0..4).map(|_| rand_kb(&mut rng)),
                )
                .unwrap()
            })
            .collect();

        let mut p_chal = InnerChallenger::new(poseidon2_init());
        let proof = prover.prove_trusted_evaluation(
            Arc::clone(&ef_dft),
            stack_point.clone(),
            &[&round_a, &round_b],
            &mut p_chal,
        );

        // Sanity: the HOST verifier accepts (the circuit must mirror it).
        let host_verifier =
            StackedWhirVerifier::<F, EF, _>::new(build_mmcs(), cfg.clone(), lsh as u32);
        let commitments = vec![round_a.commitment.clone(), round_b.commitment.clone()];
        let mut v_chal = InnerChallenger::new(poseidon2_init());
        host_verifier
            .verify_trusted_evaluation(&commitments, &[3, 2], &stack_point, &proof, &mut v_chal)
            .expect("host verify must accept before the circuit test means anything");

        // Host mirror (+ optional tamper for the negative tests).
        let mut host_mirror = host_stacked_whir_to_recursive(&proof);
        tamper(&mut host_mirror);
        let commitment_roots: Vec<[F; 8]> = commitments
            .iter()
            .map(|c| {
                let roots = c.roots();
                assert_eq!(roots.len(), 1);
                roots[0]
            })
            .collect();

        // ── Build the circuit. ──
        let mut builder = Builder::<InnerConfig>::default();
        let commit_vars: Vec<[zkm_recursion_compiler::ir::Felt<F>; 8]> = commitment_roots
            .iter()
            .map(|d| core::array::from_fn(|i| d[i].read(&mut builder)))
            .collect();
        let stack_point_vars: Vec<zkm_recursion_compiler::ir::Ext<F, EF>> =
            stack_point.iter().map(|x| x.read(&mut builder)).collect();
        let proof_var = read_stacked_whir_from_stream(&host_mirror, &mut builder);
        let mut challenger = DuplexChallengerVariable::new(&mut builder);
        let verifier = RecursiveStackedWhirVerifier::<
            zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
        > {
            config: cfg,
            log_stacking_height: lsh as u32,
            _hasher: core::marker::PhantomData,
        };
        verifier.verify::<InnerConfig, _, zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2>(
            &mut builder,
            &commit_vars,
            &[3, 2],
            &stack_point_vars,
            &proof_var.batch_evaluations.clone(),
            &proof_var,
            &mut challenger,
        );

        // ── Witness stream, same order as the reads above. ──
        let mut witness_stream: Vec<WitnessBlock<InnerConfig>> = Vec::new();
        for d in &commitment_roots {
            for f in d {
                Witnessable::<InnerConfig>::write(f, &mut witness_stream);
            }
        }
        for x in &stack_point {
            Witnessable::<InnerConfig>::write(x, &mut witness_stream);
        }
        write_stacked_whir_to_stream::<InnerConfig>(&host_mirror, &mut witness_stream);

        run_test_recursion(builder.into_operations(), witness_stream);
    }

    /// POSITIVE: an honest stacked-WHIR proof verifies in-circuit.
    #[test]
    fn whir_circuit_roundtrip_mixed_fold_schedule() {
        // Per-round fold factors differ (round-0 leaves 2^2, later 2^3) and
        // the final polynomial has 2^4 coefficients — the shape of the
        // production core config's [4,7,7]+final schedule at test scale.
        run_whir_circuit_roundtrip_with(
            9,
            zkm_pcs::whir::jagged::whir_config_for_fold_schedule(9, &[2, 3], 4),
            |_| {},
        );
    }

    #[test]
    fn whir_circuit_roundtrip_verifies() {
        run_whir_circuit_roundtrip(|_| {});
    }

    /// NEGATIVE: tampering an echoed batch evaluation is rejected (the
    /// λ-batched claim no longer matches the sumcheck).
    #[test]
    #[should_panic]
    fn whir_circuit_rejects_tampered_batch_evaluation() {
        use p3_field::PrimeCharacteristicRing;
        run_whir_circuit_roundtrip(|host| {
            host.batch_evaluations[0][1] += InnerChallenge::ONE;
        });
    }

    /// NEGATIVE: tampering the final polynomial is rejected (terminal
    /// identity + final-query consistency).
    #[test]
    #[should_panic]
    fn whir_circuit_rejects_tampered_final_poly() {
        use p3_field::PrimeCharacteristicRing;
        run_whir_circuit_roundtrip(|host| {
            host.final_poly[0] += InnerChallenge::ONE;
        });
    }

    /// NEGATIVE: tampering an opened leaf value is rejected (Merkle bind).
    #[test]
    #[should_panic]
    fn whir_circuit_rejects_tampered_leaf() {
        use p3_field::PrimeCharacteristicRing;
        run_whir_circuit_roundtrip(|host| {
            host.round_query_openings[0].leaves[0].values[0][0] += InnerVal::ONE;
        });
    }
}

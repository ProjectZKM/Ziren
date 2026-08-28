//! Stacked WHIR — the multi-stripe, multi-round batched form the shard-level
//! PCS needs (the WHIR counterpart of `basefold::stacked`).
//!
//! The stacked layer interleaves a heterogeneous MLE batch into equal-height
//! stripes (`2^log_stacking_height` each) and commits a round's stripes in ONE
//! Merkle tree; opening batches EVERY stripe of EVERY round into a single
//! virtual polynomial `F = Σ_i λ^{i} · stripe_i` (λ drawn after the claims are
//! known) whose evaluation at the stack point is the matching combination of
//! the per-stripe claims.  WHIR then runs on `F`:
//!
//!   * the START "commitment" of the WHIR instance is the set of round trees —
//!     a STIR query at index `j` opens every stripe's interleaved row and the
//!     verifier combines them with the SAME λ powers before folding, so the
//!     virtual polynomial's codeword row is derived from authenticated data;
//!   * every later round commits the (single) folded polynomial exactly as
//!     [`super::interleaved`] does.
//!
//! The stripes share one height, so their interleaved codewords share one
//! domain and the trees stack cleanly.

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_commit::Mmcs;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, PrimeField64, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use crate::basefold::mle::Mle;
use crate::basefold::proof::{LeafOpening, MerkleOpening};
use crate::whir::config::WhirConfig;
use crate::whir::interleaved::{map_to_pow_lsb, mono_eval_lsb};
use crate::whir::proof::{ProofOfWork, SumcheckPoly, WhirProof};
use crate::whir::sumcheck::{eq_table, WhirFolder};
use crate::whir::verifier::WhirVerifierError;

/// Prover-side data for one committed round of stacked WHIR.
pub struct StackedWhirProverData<F: p3_field::Field, MT: Mmcs<F>> {
    /// The stripes as committed (each `2^log_stacking_height` values).
    pub stripes: Vec<Arc<Mle<F>>>,
    /// The Merkle tree over the stripes' interleaved codewords.
    pub prover_data: MT::ProverData<RowMajorMatrix<F>>,
    pub commitment: MT::Commitment,
}

/// The stacked WHIR proof: the inner WHIR proof plus the echoed per-round
/// per-stripe evaluations at the stack point (the verifier interpolates these
/// against the batch coordinates, exactly as the BaseFold stacked layer does).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(bound = "")]
pub struct StackedWhirProof<F: p3_field::Field, EF: ExtensionField<F>, MT: Mmcs<F>> {
    pub whir_proof: WhirProof<F, EF, MT>,
    pub batch_evaluations: Vec<Vec<EF>>,
}

/// Device backend for the FIRST folding batch of the stacked-WHIR open.
///
/// The stacked open touches stacking-height-sized (`2^lsh`) data in exactly
/// four places: the per-stripe evaluations at the stack point, the λ-combined
/// virtual polynomial + eq weight, the first `folding_factor` degree-2 fold
/// variables, and the round-0 query openings of the stripe trees.  Everything
/// after the first fold batch operates on `2^(lsh-ff)`-sized vectors, which
/// are host-trivial.  This trait carries exactly those four pieces so a GPU
/// prover can keep the big vectors device-resident while the TRANSCRIPT
/// logic stays in the one host implementation below (an engine of `None`
/// is byte-identical to the pure-host path).
///
/// Pair convention throughout: lo = index `2i`, hi = `2i+1`, matching
/// [`crate::basefold::mle::Mle::fix_last_variable`] and [`WhirFolder`].
pub trait WhirRound0Engine<F: p3_field::Field, EF, MT: Mmcs<F>> {
    /// Per-round per-stripe evaluations at the stack point — the same shape
    /// (round-major, stripe-minor) the host computes from `d.stripes`.
    fn stripe_evals(&mut self, stack_point: &[EF]) -> Vec<Vec<EF>>;
    /// Build the λ-combined virtual polynomial and the eq(stack_point)
    /// weight, both of length `2^lsh`, on the backend.
    fn init(&mut self, lambda: EF, stack_point: &[EF]);
    /// `(c0, c2)` of the CURRENT variable: `c0 = Σ w_lo·f_lo`,
    /// `c2 = Σ (f_hi−f_lo)(w_hi−w_lo)`.
    fn c0_c2(&mut self) -> (EF, EF);
    /// Fold both vectors by the sampled challenge (halving their length).
    fn apply_rc(&mut self, rc: EF);
    /// Materialize `(f, weight)` after the `folding_factor` folds.
    fn extract(&mut self) -> (Vec<EF>, Vec<EF>);
    /// Round-0 query opening of the stripe trees at `index`: one
    /// [`LeafOpening`] per committed round, in round order, each carrying
    /// every stripe's row (the exact shape `mmcs.open_batch` returns on the
    /// host path).
    fn open_query(&mut self, index: usize) -> Vec<LeafOpening<F, MT>>;
    /// All round-0 query openings at once — `indices.len()` entries, each the
    /// [`Self::open_query`] result for that index.  A device backend overrides
    /// this to batch the leaf-row gather + path walk over every query.
    fn open_queries(&mut self, indices: &[usize]) -> Vec<Vec<LeafOpening<F, MT>>> {
        indices.iter().map(|&i| self.open_query(i)).collect()
    }
}

/// Env-gated (`ZIREN_WHIR_OPEN_TIMING=1`) section timers for the stacked
/// open — process-global sums, dumped every 32 opens.  Diagnostic only.
mod open_timing {
    use core::sync::atomic::{AtomicU64, Ordering};
    pub static ENGINE: AtomicU64 = AtomicU64::new(0);
    pub static FOLDS: AtomicU64 = AtomicU64::new(0);
    pub static COMMITS: AtomicU64 = AtomicU64::new(0);
    pub static OOD: AtomicU64 = AtomicU64::new(0);
    pub static QUERIES: AtomicU64 = AtomicU64::new(0);
    pub static CONSTRAINTS: AtomicU64 = AtomicU64::new(0);
    pub static FINAL: AtomicU64 = AtomicU64::new(0);
    pub static OPENS: AtomicU64 = AtomicU64::new(0);

    pub fn enabled() -> bool {
        static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ON.get_or_init(|| std::env::var("ZIREN_WHIR_OPEN_TIMING").is_ok())
    }

    pub struct Timer(std::time::Instant, &'static AtomicU64);
    impl Timer {
        pub fn new(slot: &'static AtomicU64) -> Option<Self> {
            enabled().then(|| Timer(std::time::Instant::now(), slot))
        }
    }
    impl Drop for Timer {
        fn drop(&mut self) {
            self.1.fetch_add(self.0.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }
    }

    pub fn tick_open() {
        if !enabled() {
            return;
        }
        let n = OPENS.fetch_add(1, Ordering::Relaxed) + 1;
        if n % 32 == 0 {
            let g = |a: &AtomicU64| a.load(Ordering::Relaxed) as f64 / 1e9;
            eprintln!(
                "#WHIR-OPEN-TIMING n={n} engine={:.2}s folds={:.2}s commits={:.2}s ood={:.2}s queries={:.2}s constraints={:.2}s final={:.2}s",
                g(&ENGINE), g(&FOLDS), g(&COMMITS), g(&OOD), g(&QUERIES), g(&CONSTRAINTS), g(&FINAL)
            );
        }
    }
}

pub struct StackedWhirProver<F: p3_field::Field, EF, MT: Mmcs<F>, D> {
    pub mmcs: MT,
    pub dft: Arc<D>,
    pub config: WhirConfig,
    pub log_stacking_height: u32,
    _ef: core::marker::PhantomData<(F, EF)>,
}

impl<F, EF, MT, D> StackedWhirProver<F, EF, MT, D>
where
    F: TwoAdicField + PrimeField64,
    EF: ExtensionField<F> + TwoAdicField,
    MT: Mmcs<F, Commitment: Clone, ProverData<RowMajorMatrix<F>>: 'static>,
    D: TwoAdicSubgroupDft<F>,
{
    pub fn new(mmcs: MT, dft: Arc<D>, config: WhirConfig, log_stacking_height: u32) -> Self {
        Self { mmcs, dft, config, log_stacking_height, _ef: core::marker::PhantomData }
    }

    fn ff(&self) -> usize {
        self.config.round_parameters[0].folding_factor
    }

    /// Interleaved-encode one stripe (base field) to its codeword matrix.
    fn encode_stripe(&self, stripe: &Mle<F>) -> RowMajorMatrix<F> {
        let ff = self.ff();
        let width = 1usize << ff;
        let mut padded = stripe.guts().as_slice().to_vec();
        padded.resize(padded.len() << self.config.starting_log_inv_rate, F::ZERO);
        self.dft.dft_batch(RowMajorMatrix::new(padded, width)).to_row_major_matrix()
    }

    /// Commit one round: every stripe's interleaved codeword goes into one
    /// Merkle tree (equal heights — one matrix per stripe, so an opened index
    /// yields every stripe's row).
    pub fn commit_stripes(&self, stripes: Vec<Arc<Mle<F>>>) -> StackedWhirProverData<F, MT> {
        let mats: Vec<RowMajorMatrix<F>> = stripes.iter().map(|s| self.encode_stripe(s)).collect();
        let (commitment, prover_data) = self.mmcs.commit(mats);
        StackedWhirProverData { stripes, prover_data, commitment }
    }

    /// Batched open: prove that, for each round `r` and stripe `i`, the stripe
    /// evaluates at `stack_point` to `batch_evaluations[r][i]` — by running
    /// WHIR on the λ-combined virtual polynomial.
    ///
    /// Transcript: observe nothing for the commitments here (the caller
    /// observed them at commit time); draw λ; run WHIR with the batched claim.
    pub fn prove_trusted_evaluation<EFDft, Challenger>(
        &self,
        ef_dft: Arc<EFDft>,
        stack_point: Vec<EF>,
        prover_data: &[&StackedWhirProverData<F, MT>],
        challenger: &mut Challenger,
    ) -> StackedWhirProof<F, EF, MT>
    where
        EFDft: TwoAdicSubgroupDft<EF>,
        Challenger: FieldChallenger<F>
            + GrindingChallenger<Witness = F>
            + CanObserve<MT::Commitment>,
    {
        self.prove_trusted_evaluation_with_engine(ef_dft, stack_point, prover_data, challenger, None)
    }

    /// [`Self::prove_trusted_evaluation`] with an optional
    /// [`WhirRound0Engine`] carrying the stacking-height-sized work.  With
    /// `None` this IS the plain host path, byte-for-byte; with an engine the
    /// TRANSCRIPT stays identical (the engine only computes what the host
    /// vectors would have).
    pub fn prove_trusted_evaluation_with_engine<EFDft, Challenger>(
        &self,
        ef_dft: Arc<EFDft>,
        stack_point: Vec<EF>,
        prover_data: &[&StackedWhirProverData<F, MT>],
        challenger: &mut Challenger,
        mut engine: Option<&mut dyn WhirRound0Engine<F, EF, MT>>,
    ) -> StackedWhirProof<F, EF, MT>
    where
        EFDft: TwoAdicSubgroupDft<EF>,
        Challenger: FieldChallenger<F>
            + GrindingChallenger<Witness = F>
            + CanObserve<MT::Commitment>,
    {
        let lsh = self.log_stacking_height as usize;
        let ff = self.ff();
        let num_rounds = self.config.round_parameters.len();
        debug_assert_eq!(stack_point.len(), lsh);

        // Per-round per-stripe claims at the stack point (echoed in the proof).
        let batch_evaluations: Vec<Vec<EF>> = if let Some(e) = engine.as_deref_mut() {
            e.stripe_evals(&stack_point)
        } else {
            prover_data
                .iter()
                .map(|d| d.stripes.iter().map(|s| s.eval_at::<EF>(&stack_point)[0]).collect())
                .collect()
        };
        for round in &batch_evaluations {
            for &e in round {
                challenger.observe_algebra_element(e);
            }
        }

        // λ batches all stripes of all rounds into one virtual polynomial.
        // The claim is the same λ-combination of the echoed evaluations; the
        // materialized `virt` vector is host-mode only (the engine holds it).
        let lambda: EF = challenger.sample_algebra_element();
        let mut claim = EF::ZERO;
        let mut lam = EF::ONE;
        for evals in &batch_evaluations {
            for &e in evals {
                claim += lam * e;
                lam *= lambda;
            }
        }
        let virt: Vec<EF> = if engine.is_none() {
            let mut virt: Vec<EF> = alloc::vec![EF::ZERO; 1usize << lsh];
            let mut lam = EF::ONE;
            for d in prover_data.iter() {
                for stripe in d.stripes.iter() {
                    for (v, &st) in virt.iter_mut().zip(stripe.guts().as_slice()) {
                        *v += lam * st;
                    }
                    lam *= lambda;
                }
            }
            virt
        } else {
            Vec::new()
        };

        // ---- WHIR on the virtual polynomial. ----
        // Starting OOD on `virt`.  An engine carries no starting-OOD path:
        // the stacked configuration pins `starting_ood_samples = 0` (OOD
        // rides in round constraints), so the loop below is empty there and
        // `virt_mle` is never evaluated.
        let n = lsh;
        assert!(
            engine.is_none() || self.config.starting_ood_samples == 0,
            "WhirRound0Engine requires starting_ood_samples == 0 (stacked config)"
        );
        let mut start_ood_points = Vec::with_capacity(self.config.starting_ood_samples);
        let mut start_ood_answers = Vec::with_capacity(self.config.starting_ood_samples);
        for _ in 0..self.config.starting_ood_samples {
            let virt_mle = Mle::<EF>::from_row_major(RowMajorMatrix::new(virt.clone(), 1));
            let pt: Vec<EF> = (0..n).map(|_| challenger.sample_algebra_element()).collect();
            let ans = virt_mle.eval_at::<EF>(&pt)[0];
            challenger.observe_algebra_element(ans);
            start_ood_points.push(pt);
            start_ood_answers.push(ans);
        }
        let batch: EF = challenger.sample_algebra_element();
        let mut claimed_sum = claim;
        let mut coeff = batch;
        for &a in &start_ood_answers {
            claimed_sum += coeff * a;
            coeff *= batch;
        }
        let mut folder = if let Some(e) = engine.as_deref_mut() {
            // The engine holds virt + eq(stack_point) device-side; the host
            // folder starts EMPTY and receives the folded (small) vectors
            // after the first fold batch.
            e.init(lambda, &stack_point);
            WhirFolder { f_vec: Vec::new(), weight: Vec::new(), claimed_sum }
        } else {
            let mut weight = eq_table(n, &stack_point);
            {
                let mut c = batch;
                for pt in &start_ood_points {
                    let eqt = eq_table(n, pt);
                    for (w, ei) in weight.iter_mut().zip(&eqt) {
                        *w += c * *ei;
                    }
                    c *= batch;
                }
            }
            WhirFolder { f_vec: virt, weight, claimed_sum }
        };

        let mut prev_domain_log = (lsh - ff) + self.config.starting_log_inv_rate;
        // Round 0 queries the STRIPE trees (multi-matrix, base field); later
        // rounds query the single folded EF codeword.
        let mut prev_single: Option<MT::ProverData<RowMajorMatrix<F>>> = None;

        let mut round_sumcheck_polys: Vec<Vec<SumcheckPoly<EF>>> = Vec::new();
        let mut round_ood_answers: Vec<Vec<EF>> = Vec::new();
        let mut round_commitments: Vec<MT::Commitment> = Vec::new();
        let mut round_query_openings: Vec<MerkleOpening<F, MT>> = Vec::new();
        let mut folding_pow: Vec<ProofOfWork<F>> = Vec::new();

        for (r, round_cfg) in self.config.round_parameters.iter().enumerate() {
            let _t_fold = open_timing::Timer::new(if r == 0 {
                &open_timing::ENGINE
            } else {
                &open_timing::FOLDS
            });
            let mut this_round_randomness = Vec::new();
            let polys = if r == 0 && engine.is_some() {
                // First fold batch on the engine: SAME transcript as
                // `WhirFolder::fold_variables`, with (c0, c2) and the folds
                // computed device-side.  The folded (small) vectors then
                // seed the host folder for every later round.
                let e = engine.as_deref_mut().unwrap();
                let mut out = Vec::with_capacity(round_cfg.folding_factor);
                for var in 0..round_cfg.folding_factor {
                    let (c0, c2) = e.c0_c2();
                    let c1 = folder.claimed_sum - c0.double() - c2;
                    challenger.observe_algebra_element(c0);
                    challenger.observe_algebra_element(c1);
                    challenger.observe_algebra_element(c2);
                    let pow =
                        challenger.grind(round_cfg.pow_bits.get(var).copied().unwrap_or(0));
                    let rc: EF = challenger.sample_algebra_element();
                    folder.claimed_sum = c0 + c1 * rc + c2 * rc * rc;
                    e.apply_rc(rc);
                    this_round_randomness.push(rc);
                    out.push((
                        SumcheckPoly(alloc::vec![c0, c1, c2]),
                        ProofOfWork(pow),
                    ));
                }
                let (f, w) = e.extract();
                folder.f_vec = f;
                folder.weight = w;
                out
            } else {
                folder.fold_variables::<F, _>(
                    round_cfg.folding_factor,
                    &round_cfg.pow_bits,
                    challenger,
                    &mut this_round_randomness,
                )
            };
            round_sumcheck_polys.push(polys.iter().map(|(p, _)| p.clone()).collect());
            for (_, pow) in &polys {
                folding_pow.push(pow.clone());
            }

            if r + 1 == num_rounds {
                break;
            }

            drop(_t_fold);
            let _t_commit = open_timing::Timer::new(&open_timing::COMMITS);
            // Commit the folded polynomial (single EF poly, interleaved).
            // Leaf width follows the NEXT round's folding factor - that
            // round's stir fold consumes one leaf per query.
            let next_ff = self.config.round_parameters[r + 1].folding_factor;
            let rem = folder.f_vec.len().trailing_zeros() as usize;
            let width = 1usize << next_ff;
            let mut padded = folder.f_vec.clone();
            padded.resize(padded.len() << round_cfg.log_inv_rate, EF::ZERO);
            let ef_mat =
                ef_dft.dft_batch(RowMajorMatrix::new(padded, width)).to_row_major_matrix();
            let base_vals: Vec<F> = ef_mat
                .values
                .iter()
                .flat_map(|e| e.as_basis_coefficients_slice().iter().copied())
                .collect();
            let leaves = RowMajorMatrix::new(base_vals, width * EF::DIMENSION);
            let this_domain_log = (rem - next_ff) + round_cfg.log_inv_rate;
            let (commitment, this_data) = self.mmcs.commit(alloc::vec![leaves]);
            challenger.observe(commitment.clone());
            round_commitments.push(commitment);

            drop(_t_commit);
            let _t_ood = open_timing::Timer::new(&open_timing::OOD);
            // Fresh OOD on the folded polynomial.
            let folded = Mle::<EF>::from_row_major(RowMajorMatrix::new(folder.f_vec.clone(), 1));
            let mut ood_points = Vec::with_capacity(round_cfg.ood_samples);
            let mut ood_answers = Vec::with_capacity(round_cfg.ood_samples);
            for _ in 0..round_cfg.ood_samples {
                let pt: Vec<EF> = (0..rem).map(|_| challenger.sample_algebra_element()).collect();
                let ans = folded.eval_at::<EF>(&pt)[0];
                challenger.observe_algebra_element(ans);
                ood_points.push(pt);
                ood_answers.push(ans);
            }
            round_ood_answers.push(ood_answers.clone());

            drop(_t_ood);
            let _t_q = open_timing::Timer::new(&open_timing::QUERIES);
            // Query PoW + indices into the PREVIOUS codeword.
            folding_pow.push(ProofOfWork(challenger.grind(round_cfg.queries_pow_bits)));
            let mask = (1usize << prev_domain_log) - 1;
            let indices: Vec<usize> = (0..round_cfg.num_queries)
                .map(|_| challenger.sample_bits(prev_domain_log) & mask)
                .collect();

            let g_prev = EF::two_adic_generator(prev_domain_log);
            let mut leaves_open = Vec::with_capacity(indices.len());
            let mut stir_points: Vec<Vec<EF>> = Vec::with_capacity(indices.len());
            let mut stir_values = Vec::with_capacity(indices.len());
            // Round 0 with an engine: fetch every query's openings in ONE
            // batched call (device gather + path walk over all indices),
            // then serve the loop from the batch.
            let mut engine_batch: Option<alloc::collections::VecDeque<Vec<LeafOpening<F, MT>>>> =
                match (&prev_single, engine.as_deref_mut()) {
                    (None, Some(e)) => Some(e.open_queries(&indices).into()),
                    _ => None,
                };
            for &idx in &indices {
                let (virt_leaf, opened) = match &prev_single {
                    None => {
                        // Round 0: open every stripe row of every round tree
                        // and λ-combine.  With an engine the openings come off
                        // the device-resident trees; the λ-combination is the
                        // same host arithmetic either way.
                        let opened: Vec<LeafOpening<F, MT>> =
                            if let Some(batch) = engine_batch.as_mut() {
                                batch.pop_front().expect("one batch entry per query index")
                            } else {
                                let mut all = Vec::with_capacity(prover_data.len());
                                for d in prover_data.iter() {
                                    let opening = self.mmcs.open_batch(idx, &d.prover_data);
                                    all.push(LeafOpening {
                                        values: opening.opened_values,
                                        proof: opening.opening_proof,
                                    });
                                }
                                all
                            };
                        let mut virt_leaf =
                            alloc::vec![EF::ZERO; 1usize << round_cfg.folding_factor];
                        let mut lam = EF::ONE;
                        for leaf in &opened {
                            for stripe_row in &leaf.values {
                                for (v, &st) in virt_leaf.iter_mut().zip(stripe_row.iter()) {
                                    *v += lam * st;
                                }
                                lam *= lambda;
                            }
                        }
                        (virt_leaf, opened)
                    }
                    Some(data) => {
                        let opening = self.mmcs.open_batch(idx, data);
                        let leaf = &opening.opened_values[0];
                        let virt_leaf: Vec<EF> = leaf
                            .chunks_exact(EF::DIMENSION)
                            .map(|c| {
                                EF::from_basis_coefficients_iter(c.iter().copied()).unwrap()
                            })
                            .collect();
                        (
                            virt_leaf,
                            alloc::vec![LeafOpening {
                                values: opening.opened_values,
                                proof: opening.opening_proof,
                            }],
                        )
                    }
                };
                let stir = Mle::from_row_major(RowMajorMatrix::new(virt_leaf, 1))
                    .eval_at::<EF>(&this_round_randomness)[0];
                stir_values.push(stir);
                stir_points.push(map_to_pow_lsb(EF::from(g_prev.exp_u64(idx as u64)), rem));
                for o in opened {
                    leaves_open.push(o);
                }
            }
            round_query_openings.push(MerkleOpening { leaves: leaves_open });

            drop(_t_q);
            let _t_c = open_timing::Timer::new(&open_timing::CONSTRAINTS);
            let round_batch: EF = challenger.sample_algebra_element();
            folder.add_ood_constraints(&ood_points, &ood_answers, round_batch);
            let start_coeff = round_batch.exp_u64((ood_points.len() + 1) as u64);
            folder.add_monomial_constraints(&stir_points, &stir_values, round_batch, start_coeff);

            prev_domain_log = this_domain_log;
            prev_single = Some(this_data);
        }

        let _t_final = open_timing::Timer::new(&open_timing::FINAL);
        // Final queries against the last committed codeword (or, when no round
        // ever commits, the stripe trees).
        let final_poly = folder.f_vec.clone();
        let final_pow = ProofOfWork(challenger.grind(self.config.final_pow_bits));
        let final_mask = (1usize << prev_domain_log) - 1;
        let mut final_leaves = Vec::with_capacity(self.config.final_queries);
        for _ in 0..self.config.final_queries {
            let idx = challenger.sample_bits(prev_domain_log) & final_mask;
            match &prev_single {
                Some(data) => {
                    let opening = self.mmcs.open_batch(idx, data);
                    final_leaves.push(LeafOpening {
                        values: opening.opened_values,
                        proof: opening.opening_proof,
                    });
                }
                None => {
                    // Single-round shape: the final queries open the stripe
                    // trees directly.  The engine path pins num_rounds >= 2
                    // (production shape), so this arm stays host-only.
                    assert!(
                        engine.is_none(),
                        "WhirRound0Engine requires >= 2 rounds (final queries open a folded codeword)"
                    );
                    for d in prover_data.iter() {
                        let opening = self.mmcs.open_batch(idx, &d.prover_data);
                        final_leaves.push(LeafOpening {
                            values: opening.opened_values,
                            proof: opening.opening_proof,
                        });
                    }
                }
            }
        }
        round_query_openings.push(MerkleOpening { leaves: final_leaves });

        let final_sumcheck_polys: Vec<SumcheckPoly<EF>> =
            round_sumcheck_polys.pop().unwrap_or_default();

        {
            drop(_t_final);
            open_timing::tick_open();
        }
        StackedWhirProof {
            whir_proof: WhirProof {
                round_sumcheck_polys,
                round_ood_answers,
                round_commitments,
                round_query_openings,
                final_poly,
                final_sumcheck_polys,
                folding_pow,
                final_pow,
            },
            batch_evaluations,
        }
    }
}

/// The stacked WHIR verifier.
pub struct StackedWhirVerifier<F: p3_field::Field, EF, MT: Mmcs<F>> {
    pub mmcs: MT,
    pub config: WhirConfig,
    pub log_stacking_height: u32,
    _ef: core::marker::PhantomData<(F, EF)>,
}

impl<F, EF, MT> StackedWhirVerifier<F, EF, MT>
where
    F: TwoAdicField + PrimeField64,
    EF: ExtensionField<F> + TwoAdicField,
    MT: Mmcs<F, Commitment: Clone>,
{
    pub fn new(mmcs: MT, config: WhirConfig, log_stacking_height: u32) -> Self {
        Self { mmcs, config, log_stacking_height, _ef: core::marker::PhantomData }
    }

    fn lagrange_eq(a: &[EF], b: &[EF]) -> EF {
        a.iter().zip(b).map(|(&x, &y)| x * y + (EF::ONE - x) * (EF::ONE - y)).product()
    }

    fn monomial_fold(a: &[EF], b: &[EF]) -> EF {
        a.iter().zip(b).map(|(&x, &y)| EF::ONE - y + y * x).product()
    }

    /// Verify a batched stacked opening.  `round_stripe_counts[r]` is the
    /// number of stripes committed in round `r` (bound by the caller from the
    /// round's area, exactly as the BaseFold stacked verifier does);
    /// `expected_claim`, when supplied, must equal the λ-combination of the
    /// echoed batch evaluations that the caller has SEPARATELY bound to its
    /// own claim structure (the jagged layer interpolates them itself).
    #[allow(clippy::too_many_arguments)]
    pub fn verify_trusted_evaluation<Challenger>(
        &self,
        commitments: &[MT::Commitment],
        round_stripe_counts: &[usize],
        stack_point: &[EF],
        proof: &StackedWhirProof<F, EF, MT>,
        challenger: &mut Challenger,
    ) -> Result<(), WhirVerifierError>
    where
        Challenger: FieldChallenger<F>
            + GrindingChallenger<Witness = F>
            + CanObserve<MT::Commitment>,
    {
        let lsh = self.log_stacking_height as usize;
        let ff = self.config.round_parameters[0].folding_factor;
        let num_rounds = self.config.round_parameters.len();
        let folds: alloc::vec::Vec<usize> =
            self.config.round_parameters.iter().map(|rp| rp.folding_factor).collect();
        let n = lsh;
        let final_log = n - folds.iter().sum::<usize>();
        let whir = &proof.whir_proof;
        if whir.final_poly.len() != 1usize << final_log {
            return Err(WhirVerifierError::IncorrectShape("final_poly".into()));
        }
        if proof.batch_evaluations.len() != round_stripe_counts.len()
            || commitments.len() != round_stripe_counts.len()
        {
            return Err(WhirVerifierError::IncorrectShape("round count".into()));
        }
        for (evals, &cnt) in proof.batch_evaluations.iter().zip(round_stripe_counts) {
            if evals.len() != cnt {
                return Err(WhirVerifierError::IncorrectShape("stripe count".into()));
            }
        }

        // Replay claim batching.
        for round in &proof.batch_evaluations {
            for &e in round {
                challenger.observe_algebra_element(e);
            }
        }
        let lambda: EF = challenger.sample_algebra_element();
        let mut claim = EF::ZERO;
        let mut lam = EF::ONE;
        let mut lambda_powers_per_round: Vec<Vec<EF>> = Vec::new();
        for round in &proof.batch_evaluations {
            let mut powers = Vec::with_capacity(round.len());
            for &e in round {
                claim += lam * e;
                powers.push(lam);
                lam *= lambda;
            }
            lambda_powers_per_round.push(powers);
        }

        // Starting OOD replay (points re-derived, answers read from... the
        // prover observed answers it computed; here the answers are carried in
        // the round-0 slot of the transcript — the stacked prover observes
        // them, so re-derive by sampling points and reading the observed
        // answers is impossible without them in the proof.  The stacked WHIR
        // start OOD answers ride in `whir.round_ood_answers`?  No — they are
        // BOUND via the constraint system below, so the proof carries them in
        // the first entry of `start_ood` — see `StackedWhirProof` layout.
        // For now the start OOD count is zero in the stacked configuration.
        if self.config.starting_ood_samples != 0 {
            return Err(WhirVerifierError::IncorrectShape(
                "stacked WHIR carries its OOD in round constraints; set starting_ood_samples=0"
                    .into(),
            ));
        }
        let _batch: EF = challenger.sample_algebra_element();

        enum C<EF> {
            Lagrange { point: Vec<EF>, coeff: EF, vars: usize },
            Monomial { point: Vec<EF>, coeff: EF, vars: usize },
        }
        let mut claim = claim;
        let mut constraints: Vec<C<EF>> =
            alloc::vec![C::Lagrange { point: stack_point.to_vec(), coeff: EF::ONE, vars: n }];

        let mut prev_domain_log = (lsh - ff) + self.config.starting_log_inv_rate;
        let mut prev_round0 = true;
        let mut all_fr: Vec<EF> = Vec::with_capacity(n - final_log);
        let mut pow_flat = 0usize;
        let mut folded_vars = 0usize;
        for (r, round_cfg) in self.config.round_parameters.iter().enumerate() {
            let msgs: &[SumcheckPoly<EF>] = if r + 1 == num_rounds {
                &whir.final_sumcheck_polys
            } else {
                &whir.round_sumcheck_polys[r]
            };
            if msgs.len() != round_cfg.folding_factor {
                return Err(WhirVerifierError::IncorrectShape("round messages".into()));
            }
            let mut this_round_randomness: Vec<EF> = Vec::with_capacity(ff);
            for (var, poly) in msgs.iter().enumerate() {
                let c = &poly.0;
                if c.len() != 3 {
                    return Err(WhirVerifierError::IncorrectShape("degree-2".into()));
                }
                let (c0, c1, c2) = (c[0], c[1], c[2]);
                if c0 + (c0 + c1 + c2) != claim {
                    return Err(WhirVerifierError::SumcheckMismatch { round: r, var });
                }
                challenger.observe_algebra_element(c0);
                challenger.observe_algebra_element(c1);
                challenger.observe_algebra_element(c2);
                let pow = &whir.folding_pow[pow_flat];
                pow_flat += 1;
                if !challenger
                    .check_witness(round_cfg.pow_bits.get(var).copied().unwrap_or(0), pow.0)
                {
                    return Err(WhirVerifierError::PowMismatch { round: r, var });
                }
                let rc: EF = challenger.sample_algebra_element();
                claim = c0 + c1 * rc + c2 * rc * rc;
                all_fr.push(rc);
                this_round_randomness.push(rc);
            }
            folded_vars += round_cfg.folding_factor;

            if r + 1 == num_rounds {
                break;
            }

            challenger.observe(whir.round_commitments[r].clone());
            let rem = n - folded_vars;
            let ood_answers = &whir.round_ood_answers[r];
            let mut ood_points: Vec<Vec<EF>> = Vec::with_capacity(ood_answers.len());
            for ans in ood_answers.iter() {
                let pt: Vec<EF> = (0..rem).map(|_| challenger.sample_algebra_element()).collect();
                challenger.observe_algebra_element(*ans);
                ood_points.push(pt);
            }

            let query_pow = &whir.folding_pow[pow_flat];
            pow_flat += 1;
            if !challenger.check_witness(round_cfg.queries_pow_bits, query_pow.0) {
                return Err(WhirVerifierError::PowMismatch { round: r, var: usize::MAX });
            }
            let mask = (1usize << prev_domain_log) - 1;
            let indices: Vec<usize> = (0..round_cfg.num_queries)
                .map(|_| challenger.sample_bits(prev_domain_log) & mask)
                .collect();

            let openings = &whir.round_query_openings[r];
            let leaves_per_query = if prev_round0 { commitments.len() } else { 1 };
            if openings.leaves.len() != indices.len() * leaves_per_query {
                return Err(WhirVerifierError::IncorrectShape("query openings".into()));
            }
            let g_prev = EF::two_adic_generator(prev_domain_log);
            let mut stir_points: Vec<Vec<EF>> = Vec::with_capacity(indices.len());
            let mut stir_values: Vec<EF> = Vec::with_capacity(indices.len());
            for (qi, &idx) in indices.iter().enumerate() {
                let virt_leaf: Vec<EF> = if prev_round0 {
                    let mut virt_leaf =
                        alloc::vec![EF::ZERO; 1usize << round_cfg.folding_factor];
                    for (ri, commitment) in commitments.iter().enumerate() {
                        let leaf = &openings.leaves[qi * leaves_per_query + ri];
                        let stripe_count = round_stripe_counts[ri];
                        if leaf.values.len() != stripe_count {
                            return Err(WhirVerifierError::IncorrectShape("stripe rows".into()));
                        }
                        let dims: Vec<p3_matrix::Dimensions> = (0..stripe_count)
                            .map(|_| p3_matrix::Dimensions {
                                width: 1usize << round_cfg.folding_factor,
                                height: 1usize << prev_domain_log,
                            })
                            .collect();
                        let opened = p3_commit::BatchOpeningRef {
                            opened_values: &leaf.values,
                            opening_proof: &leaf.proof,
                        };
                        self.mmcs
                            .verify_batch(commitment, &dims, idx, opened)
                            .map_err(|_| WhirVerifierError::IncorrectShape("merkle".into()))?;
                        for (row, &lp) in
                            leaf.values.iter().zip(&lambda_powers_per_round[ri])
                        {
                            for (v, &s) in virt_leaf.iter_mut().zip(row.iter()) {
                                *v += lp * s;
                            }
                        }
                    }
                    virt_leaf
                } else {
                    let leaf = &openings.leaves[qi];
                    let dims = alloc::vec![p3_matrix::Dimensions {
                        width: (1usize << round_cfg.folding_factor) * EF::DIMENSION,
                        height: 1usize << prev_domain_log,
                    }];
                    let opened = p3_commit::BatchOpeningRef {
                        opened_values: &leaf.values,
                        opening_proof: &leaf.proof,
                    };
                    self.mmcs
                        .verify_batch(&whir.round_commitments[r - 1], &dims, idx, opened)
                        .map_err(|_| WhirVerifierError::IncorrectShape("merkle".into()))?;
                    leaf.values[0]
                        .chunks_exact(EF::DIMENSION)
                        .map(|c| EF::from_basis_coefficients_iter(c.iter().copied()).unwrap())
                        .collect()
                };
                let stir = Mle::from_row_major(RowMajorMatrix::new(virt_leaf, 1))
                    .eval_at::<EF>(&this_round_randomness)[0];
                stir_values.push(stir);
                stir_points.push(map_to_pow_lsb(EF::from(g_prev.exp_u64(idx as u64)), rem));
            }

            let round_batch: EF = challenger.sample_algebra_element();
            let mut cc = round_batch;
            for (a, p) in ood_answers.iter().zip(&ood_points) {
                claim += cc * *a;
                constraints.push(C::Lagrange { point: p.clone(), coeff: cc, vars: rem });
                cc *= round_batch;
            }
            for (v, p) in stir_values.iter().zip(&stir_points) {
                claim += cc * *v;
                constraints.push(C::Monomial { point: p.clone(), coeff: cc, vars: rem });
                cc *= round_batch;
            }

            prev_domain_log =
                (rem - self.config.round_parameters[r + 1].folding_factor)
                    + round_cfg.log_inv_rate;
            prev_round0 = false;
        }

        // Final PoW + final queries.
        if !challenger.check_witness(self.config.final_pow_bits, whir.final_pow.0) {
            return Err(WhirVerifierError::PowMismatch { round: num_rounds, var: usize::MAX });
        }
        let final_mask = (1usize << prev_domain_log) - 1;
        let final_openings = whir.round_query_openings.last().unwrap();
        let leaves_per_query = if prev_round0 { commitments.len() } else { 1 };
        if final_openings.leaves.len() != self.config.final_queries * leaves_per_query {
            return Err(WhirVerifierError::IncorrectShape("final query count".into()));
        }
        let g_final = EF::two_adic_generator(prev_domain_log);
        let last_ff = *folds.last().unwrap();
        let last_randomness = &all_fr[all_fr.len() - last_ff..];
        for q in 0..self.config.final_queries {
            let idx = challenger.sample_bits(prev_domain_log) & final_mask;
            let virt_leaf: Vec<EF> = if prev_round0 {
                let mut virt_leaf = alloc::vec![EF::ZERO; 1usize << last_ff];
                for (ri, commitment) in commitments.iter().enumerate() {
                    let leaf = &final_openings.leaves[q * leaves_per_query + ri];
                    let stripe_count = round_stripe_counts[ri];
                    let dims: Vec<p3_matrix::Dimensions> = (0..stripe_count)
                        .map(|_| p3_matrix::Dimensions {
                            width: 1usize << last_ff,
                            height: 1usize << prev_domain_log,
                        })
                        .collect();
                    let opened = p3_commit::BatchOpeningRef {
                        opened_values: &leaf.values,
                        opening_proof: &leaf.proof,
                    };
                    self.mmcs
                        .verify_batch(commitment, &dims, idx, opened)
                        .map_err(|_| WhirVerifierError::IncorrectShape("final merkle".into()))?;
                    for (row, &lp) in leaf.values.iter().zip(&lambda_powers_per_round[ri]) {
                        for (v, &s) in virt_leaf.iter_mut().zip(row.iter()) {
                            *v += lp * s;
                        }
                    }
                }
                virt_leaf
            } else {
                let leaf = &final_openings.leaves[q];
                let dims = alloc::vec![p3_matrix::Dimensions {
                    width: (1usize << last_ff) * EF::DIMENSION,
                    height: 1usize << prev_domain_log,
                }];
                let opened = p3_commit::BatchOpeningRef {
                    opened_values: &leaf.values,
                    opening_proof: &leaf.proof,
                };
                self.mmcs
                    .verify_batch(
                        whir.round_commitments.last().unwrap(),
                        &dims,
                        idx,
                        opened,
                    )
                    .map_err(|_| WhirVerifierError::IncorrectShape("final merkle".into()))?;
                leaf.values[0]
                    .chunks_exact(EF::DIMENSION)
                    .map(|c| EF::from_basis_coefficients_iter(c.iter().copied()).unwrap())
                    .collect()
            };
            let folded = Mle::from_row_major(RowMajorMatrix::new(virt_leaf, 1))
                .eval_at::<EF>(last_randomness)[0];
            let expected = mono_eval_lsb(
                &whir.final_poly,
                &map_to_pow_lsb(EF::from(g_final.exp_u64(idx as u64)), final_log),
            );
            if folded != expected {
                return Err(WhirVerifierError::TerminalMismatch);
            }
        }

        // Terminal identity.
        let final_mle = Mle::from_row_major(RowMajorMatrix::new(whir.final_poly.clone(), 1));
        let mut total = EF::ZERO;
        for c in &constraints {
            match c {
                C::Lagrange { point: p, coeff, vars } => {
                    let k = vars - final_log;
                    let eq_part = Self::lagrange_eq(&p[..k], &all_fr[(n - vars)..(n - vars) + k]);
                    let f_part = final_mle.eval_at::<EF>(&p[k..])[0];
                    total += *coeff * eq_part * f_part;
                }
                C::Monomial { point: p, coeff, vars } => {
                    let k = vars - final_log;
                    let fold_part =
                        Self::monomial_fold(&p[..k], &all_fr[(n - vars)..(n - vars) + k]);
                    let f_part = mono_eval_lsb(&whir.final_poly, &p[k..]);
                    total += *coeff * fold_part * f_part;
                }
            }
        }
        if total != claim {
            return Err(WhirVerifierError::TerminalMismatch);
        }
        Ok(())
    }
}

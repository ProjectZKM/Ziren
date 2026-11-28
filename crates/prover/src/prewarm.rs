//! Building the compose and wrap programs and keys ahead of the first proof.

use crate::*;

impl<C: ZKMProverComponents> ZKMProver<C> {
    /// Build EVERY compose program a run can reach, once, at construction —
    /// and pin its proving key with it.
    ///
    /// A compose program is a function of its children's PIN-CLASS tuple (in
    /// order), the arity and `is_complete`: a child's proof geometry is its
    /// class's, so a dummy child built at the class's shape describes every
    /// real child of that class.  Two classes at arities `1..=REDUCE_BATCH_SIZE`
    /// is a small, known set, so the whole of it is a construction cost paid
    /// once per process instead of a per-node cost paid on the card thread
    /// mid-block (measured Sep 11: ~7 s apiece, re-paid after every worker
    /// respawn).
    ///
    /// Bails when `compress_shape_config` is None (`FIX_RECURSION_SHAPES=false`
    /// — no classes to enumerate) or it has no shapes (defensive).
    ///
    /// Public so a prover built with [`Self::uninitialized`] can run it later,
    /// for instance on a background thread while it already proves: a node
    /// that needs a program before the pre-warm reaches it builds the program
    /// itself, and the program cache keeps whichever copy lands first.
    pub fn prewarm_compose_programs(&self) {
        let Some(recursion_shape_config) = self.compress_shape_config.as_ref() else {
            tracing::debug!(
                "compose pre-warm skipped: compress_shape_config is None \
                 (FIX_RECURSION_SHAPES=false)"
            );
            return;
        };

        let classes = recursion_shape_config.all_shapes();
        if classes.is_empty() {
            tracing::debug!(
                "compose pre-warm skipped: recursion_shape_config has no allowed shapes"
            );
            return;
        }

        let merkle_tree_height = self.recursion_vk_tree.height;

        let prewarm_start = std::time::Instant::now();
        let prewarm_classes: Vec<usize> = match env::var("ZIREN_PREWARM_BANDS") {
            Ok(v) => v
                .split(',')
                .filter_map(|t| t.trim().parse::<usize>().ok())
                .filter(|b| *b < classes.len())
                .collect(),
            Err(_) => (0..classes.len()).collect(),
        };
        let mixed = zkm_pcs::diagnostics::env_flag("ZIREN_PREWARM_MIXED", true);
        let mut pairs: Vec<(Vec<usize>, bool)> = Vec::new();
        for arity in 1..=REDUCE_BATCH_SIZE {
            let tuples: Vec<Vec<usize>> = if mixed {
                let mut acc: Vec<Vec<usize>> = vec![Vec::new()];
                for _ in 0..arity {
                    acc = acc
                        .iter()
                        .flat_map(|t| {
                            prewarm_classes.iter().map(move |b| {
                                let mut u = t.clone();
                                u.push(*b);
                                u
                            })
                        })
                        .collect();
                }
                acc
            } else {
                prewarm_classes.iter().map(|b| vec![*b; arity]).collect()
            };
            for t in tuples {
                if t.len() == 1 {
                    pairs.push((t.clone(), true));
                }
                pairs.push((t, false));
            }
        }
        let n_pairs = pairs.len();
        let prewarm_threads = env::var("ZIREN_PREWARM_THREADS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(4);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(prewarm_threads)
            .build()
            .expect("compose pre-warm pool");
        pool.install(|| {
            pairs.into_par_iter().for_each(|(tuple, is_complete)| {
                let arity = tuple.len();
                let class_tuple = format!("{tuple:?}");
                let child_shapes: Vec<_> = tuple
                    .iter()
                    .map(|b| {
                        RecursionShapeConfig::<KoalaBear, CompressAir<KoalaBear>>::as_ordered_shape(
                            &classes[*b],
                        )
                    })
                    .collect();
                let compress_shape = ZKMCompressShape::from(child_shapes);
                let shape = ZKMCompressWithVkeyShape { compress_shape, merkle_tree_height };
                let mut witness = ZKMCompressWitnessValues::<InnerSC>::dummy(
                    self.compress_prover.machine(),
                    &shape,
                );
                witness.is_complete = is_complete;
                if zkm_pcs::diagnostics::shape_events_enabled() {
                    tracing::debug!(
                        target: zkm_pcs::diagnostics::SHAPE_TARGET,
                        stage = "prewarm",
                        shape_key = format_args!("{:016x}", witness.shape_key()),
                        children = class_tuple,
                        arity,
                        components = witness.shape_diag(),
                        "program shape"
                    );
                }
                let per_pair_start = std::time::Instant::now();
                let (_program, digest) = self.compose_program(&witness);
                self.pin_recursion_pk(digest);
                tracing::debug!(
                    "compose pre-warm: classes={class_tuple} arity={arity} \
                     is_complete={is_complete} in {:?}",
                    per_pair_start.elapsed()
                );
            })
        });
        tracing::debug!("compose pre-warm: {n_pairs} (child classes, arity) pairs");
        tracing::debug!(
            "compose pre-warm: arity 1..={} done in {:?}",
            REDUCE_BATCH_SIZE,
            prewarm_start.elapsed()
        );
    }

    /// Build the wrap program into [`Self::wrap_programs_cache`]
    /// ahead of the first wrap, on the host only.
    ///
    /// The wrap program depends only on the frozen shrink shape
    /// ([`Self::shrink_shape`]), so a dummy shrink proof of that shape has
    /// the shape key of every real one and builds the same program.  Should
    /// the two keys ever differ, the first wrap misses and builds its own.
    pub fn prewarm_wrap_program(&self) {
        let _ = self.wrap_program_cached(&self.dummy_wrap_input());
    }

    /// Populate the wrap program and key caches before the first wrap.
    ///
    /// Calls the wrap prover's setup, which requires device access for
    /// device-backed provers.
    pub fn prewarm_wrap_keys(&self) {
        let (program, digest) = self.wrap_program_cached(&self.dummy_wrap_input());
        let _ = self.wrap_keys_cached(&program, digest);
    }
}

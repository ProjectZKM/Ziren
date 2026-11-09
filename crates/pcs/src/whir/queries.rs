//! The query indices of a WHIR phase, as every party draws them.
//!
//! A phase opens `q` positions of a codeword of `2^d` leaves.  Drawn
//! independently, each position is `d` uniform bits.  Drawn in strata, `q`
//! is written as a sum of powers of two, largest first, and a summand `2^c`
//! draws one position in each of the `2^c` subtrees of depth `c`: the top
//! `c` bits of the position count the subtree, the low `d - c` bits are
//! uniform.  The prover, the host verifier and the circuit all build their
//! indices through [`query_strata`], so the three cannot disagree on which
//! bits a query draws.
//!
//! Soundness is not lost: a summand misses a set of relative density
//! `delta` with probability `prod_j (1 - delta_j)` over the subtrees'
//! densities `delta_j`, which averages to `delta`, and the product is at
//! most `(1 - delta)^(2^c)` by the AM-GM inequality.  What the strata buy is
//! structure.  A query of depth `c` reaches, `d - c` levels above its leaf,
//! a node whose position is fixed by the protocol, and the `2^c` queries of
//! the summand reach every node of that level.  A verifier therefore hashes
//! each query's path for `d - c` levels, hashes the fixed top of the tree
//! once from the nodes the queries reached, and reads no sibling for the
//! top levels at all.

use alloc::vec::Vec;

use crate::whir::config::WhirConfig;

/// One query's place in a phase: the top `depth` bits of its index are the
/// constant `stratum`, the remaining bits are drawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryStratum {
    pub depth: usize,
    pub stratum: usize,
}

impl QueryStratum {
    /// The index of a query at drawn low bits `low` over `2^domain_log`
    /// leaves.
    pub const fn index(self, domain_log: usize, low: usize) -> usize {
        (self.stratum << (domain_log - self.depth)) | low
    }

    /// The bits a query of this stratum draws over `2^domain_log` leaves.
    pub const fn drawn_bits(self, domain_log: usize) -> usize {
        domain_log - self.depth
    }
}

/// The depths of the strata of `num_queries` queries, largest first: the set
/// bits of the count.
pub fn stratum_depths(num_queries: usize) -> Vec<usize> {
    let mut remaining = num_queries;
    let mut depths = Vec::with_capacity(num_queries.count_ones() as usize);
    while remaining != 0 {
        let depth = usize::BITS as usize - 1 - remaining.leading_zeros() as usize;
        depths.push(depth);
        remaining -= 1usize << depth;
    }
    depths
}

/// The strata of a phase of `num_queries` queries, in the order the queries
/// are drawn: with `stratified`, every summand `2^c` of the count
/// contributes the strata `0..2^c` of depth `c`, largest summand first;
/// without it, every query is the one stratum of depth zero.
pub fn query_strata(num_queries: usize, stratified: bool) -> Vec<QueryStratum> {
    if !stratified {
        return alloc::vec![QueryStratum { depth: 0, stratum: 0 }; num_queries];
    }
    let mut strata = Vec::with_capacity(num_queries);
    for depth in stratum_depths(num_queries) {
        strata.extend((0..1usize << depth).map(|stratum| QueryStratum { depth, stratum }));
    }
    strata
}

/// Draw the indices of one phase over `2^domain_log` leaves: `draw(bits)` is
/// one uniform draw of `bits` bits from the transcript, called once per
/// query in query order.  Every stratum must leave at least one bit to
/// draw, which holds when the queries are fewer than the leaves.
pub fn draw_query_indices(
    domain_log: usize,
    num_queries: usize,
    stratified: bool,
    mut draw: impl FnMut(usize) -> usize,
) -> Vec<usize> {
    query_strata(num_queries, stratified)
        .into_iter()
        .map(|stratum| {
            assert!(
                stratum.depth < domain_log,
                "a stratum of depth {} over 2^{domain_log} leaves",
                stratum.depth
            );
            let bits = stratum.drawn_bits(domain_log);
            let low = draw(bits) & ((1usize << bits) - 1);
            stratum.index(domain_log, low)
        })
        .collect()
}

/// One query phase of a schedule: the codeword it opens has `2^domain_log`
/// leaves and it opens `num_queries` of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryPhase {
    pub domain_log: usize,
    pub num_queries: usize,
}

/// The query phases of a stacked schedule at stacking height `lsh`, in
/// transcript order: round `r` of the committed rounds opens the codeword
/// the round before it committed (the stripe trees for round zero), and the
/// final queries open the last committed codeword.  Mirrors the domain
/// bookkeeping of the stacked prover and verifier.
pub fn query_phases(config: &WhirConfig, lsh: usize) -> Vec<QueryPhase> {
    let rounds = &config.round_parameters;
    let num_rounds = rounds.len();
    let mut phases = Vec::with_capacity(num_rounds);
    let mut folded = 0usize;
    let mut domain_log = (lsh - rounds[0].folding_factor) + config.starting_log_inv_rate;
    for (r, round) in rounds.iter().enumerate().take(num_rounds - 1) {
        phases.push(QueryPhase { domain_log, num_queries: round.num_queries });
        folded += round.folding_factor;
        domain_log = (lsh - folded - rounds[r + 1].folding_factor) + round.log_inv_rate;
    }
    phases.push(QueryPhase { domain_log, num_queries: config.final_queries });
    phases
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::{draw_query_indices, query_phases, query_strata, stratum_depths, QueryStratum};
    use crate::whir::jagged::whir_config_for_fold_schedule;

    /// The depths are the set bits of the count, largest first.
    #[test]
    fn strata_are_the_set_bits_of_the_count() {
        assert_eq!(stratum_depths(0), Vec::<usize>::new());
        assert_eq!(stratum_depths(1), alloc::vec![0]);
        assert_eq!(stratum_depths(68), alloc::vec![6, 2]);
        assert_eq!(stratum_depths(30), alloc::vec![4, 3, 2, 1]);
        let strata = query_strata(5, true);
        assert_eq!(strata.len(), 5);
        assert_eq!(strata[0], QueryStratum { depth: 2, stratum: 0 });
        assert_eq!(strata[3], QueryStratum { depth: 2, stratum: 3 });
        assert_eq!(strata[4], QueryStratum { depth: 0, stratum: 0 });
        assert!(query_strata(5, false).iter().all(|s| *s == QueryStratum { depth: 0, stratum: 0 }));
    }

    /// Stratified draws land one query in each subtree of a summand and
    /// consume exactly the bits below the stratum; independent draws
    /// consume every bit.
    #[test]
    fn stratified_indices_cover_every_subtree() {
        let mut drawn: Vec<usize> = Vec::new();
        let indices = draw_query_indices(6, 5, true, |bits| {
            drawn.push(bits);
            0x2A
        });
        assert_eq!(drawn, alloc::vec![4, 4, 4, 4, 6]);
        let subtrees: Vec<usize> = indices[..4].iter().map(|&i| i >> 4).collect();
        assert_eq!(subtrees, alloc::vec![0, 1, 2, 3]);
        assert!(indices.iter().all(|&i| i < 64));
        assert_eq!(indices[4], 0x2A);

        let mut drawn: Vec<usize> = Vec::new();
        let indices = draw_query_indices(6, 5, false, |bits| {
            drawn.push(bits);
            0x7F
        });
        assert_eq!(drawn, alloc::vec![6; 5]);
        assert!(indices.iter().all(|&i| i == 63));
    }

    /// The phases walk the domains the stacked prover opens: the stripe
    /// trees at the starting rate, then each committed codeword at its
    /// round's rate.
    #[test]
    fn phases_follow_the_fold_schedule() {
        let mut config = whir_config_for_fold_schedule(9, &[2, 3], 4);
        config.starting_log_inv_rate = 3;
        config.round_parameters[0].num_queries = 7;
        config.final_queries = 5;
        let phases = query_phases(&config, 9);
        assert_eq!(phases.len(), 2);
        assert_eq!((phases[0].domain_log, phases[0].num_queries), (10, 7));
        assert_eq!(
            (phases[1].domain_log, phases[1].num_queries),
            (9 - 2 - 3 + config.round_parameters[0].log_inv_rate, 5)
        );
    }
}

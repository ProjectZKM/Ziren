//! Canonical binary Merkle multiproofs.
//!
//! A batch of `q` authentication paths into one binary tree of height `h`
//! carries `q · h` sibling digests, but paths of nearby leaves share their
//! upper levels and a sibling that is itself an ancestor of another opened
//! leaf is recomputable.  The canonical multiproof transmits exactly the
//! digests the verifier cannot recompute, in one fixed order:
//!
//! ```text
//!   K_0     = the distinct opened leaf positions
//!   level l : for k in K_l ascending, if k ^ 1 ∉ K_l, transmit node (l, k ^ 1)
//!   K_{l+1} = { k >> 1 : k ∈ K_l }
//! ```
//!
//! for `l = 0, …, h - 1`.  The verifier replays the same walk, so the
//! transmitted list must be consumed exactly: a missing digest, a surplus
//! digest, a reordering (which moves digests to other positions and changes
//! the recomputed root), and two openings of one position with different leaf
//! digests are all rejected.  Node `(l, p)` hashes as
//! `compress([node(l-1, 2p), node(l-1, 2p + 1)])`, the convention of a binary
//! Merkle tree whose path entry `l` for leaf `i` is node `(l, (i >> l) ^ 1)`.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use p3_symmetric::PseudoCompressionFunction;

/// Why a multiproof failed to encode or verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MultiproofError {
    /// A leaf position is at least `2^height`.
    IndexOutOfRange { index: usize },
    /// An authentication path does not have `height` entries.
    PathLength { index: usize, len: usize },
    /// Two openings disagree on the digest at one tree position.
    Conflict { level: usize, position: usize },
    /// The digest list ended before the walk did.
    MissingNode { level: usize, position: usize },
    /// Digests remain after the walk reached the root.
    SurplusNodes { remaining: usize },
    /// The recomputed root differs from the commitment.
    RootMismatch,
    /// No leaf was opened.
    Empty,
}

/// The tree positions `(level, position)` a canonical multiproof transmits,
/// in transmission order, for leaves `indices` of a tree of height `height`.
pub fn multiproof_positions(
    height: usize,
    indices: &[usize],
) -> Result<Vec<(usize, usize)>, MultiproofError> {
    let mut known: Vec<usize> = Vec::with_capacity(indices.len());
    for &index in indices {
        if height < usize::BITS as usize && index >> height != 0 {
            return Err(MultiproofError::IndexOutOfRange { index });
        }
        known.push(index);
    }
    known.sort_unstable();
    known.dedup();
    let mut out = Vec::new();
    for level in 0..height {
        let mut next = Vec::with_capacity(known.len());
        let mut i = 0;
        while i < known.len() {
            let k = known[i];
            if k & 1 == 0 && i + 1 < known.len() && known[i + 1] == k + 1 {
                i += 2;
            } else {
                out.push((level, k ^ 1));
                i += 1;
            }
            next.push(k >> 1);
        }
        next.dedup();
        known = next;
    }
    Ok(out)
}

/// The canonical multiproof digests of a batch of individual authentication
/// paths `openings = [(leaf index, path)]` into one tree of height `height`,
/// where `path[l]` is node `(l, (index >> l) ^ 1)`.  Two paths that disagree
/// on a shared node are rejected.
pub fn encode_multiproof<D: Copy + Eq>(
    height: usize,
    openings: &[(usize, &[D])],
) -> Result<Vec<D>, MultiproofError> {
    let mut nodes: BTreeMap<(usize, usize), D> = BTreeMap::new();
    for &(index, path) in openings {
        if path.len() != height {
            return Err(MultiproofError::PathLength { index, len: path.len() });
        }
        for (level, &digest) in path.iter().enumerate() {
            let position = (index >> level) ^ 1;
            match nodes.get(&(level, position)) {
                Some(existing) if *existing != digest => {
                    return Err(MultiproofError::Conflict { level, position });
                }
                Some(_) => {}
                None => {
                    nodes.insert((level, position), digest);
                }
            }
        }
    }
    let indices: Vec<usize> = openings.iter().map(|&(index, _)| index).collect();
    multiproof_positions(height, &indices)?
        .into_iter()
        .map(|(level, position)| {
            nodes
                .get(&(level, position))
                .copied()
                .ok_or(MultiproofError::MissingNode { level, position })
        })
        .collect()
}

/// The root of a binary tree of height `height` from one leaf digest and its
/// individual authentication path.
pub fn root_from_path<D: Copy, C: PseudoCompressionFunction<D, 2>>(
    compress: &C,
    mut index: usize,
    leaf: D,
    path: &[D],
) -> D {
    let mut digest = leaf;
    for &sibling in path {
        digest = if index & 1 == 0 {
            compress.compress([digest, sibling])
        } else {
            compress.compress([sibling, digest])
        };
        index >>= 1;
    }
    digest
}

/// Verify a canonical multiproof: `leaves = [(leaf index, leaf digest)]` in
/// any order and with repetitions, `nodes` the transmitted digests in
/// canonical order, against `root` for a tree of height `height`.
pub fn verify_multiproof<D: Copy + Eq, C: PseudoCompressionFunction<D, 2>>(
    compress: &C,
    root: &D,
    height: usize,
    leaves: &[(usize, D)],
    nodes: &[D],
) -> Result<(), MultiproofError> {
    if walk(compress, height, leaves, nodes, |_, _, _| {})? == *root {
        Ok(())
    } else {
        Err(MultiproofError::RootMismatch)
    }
}

/// The individual authentication paths a canonical multiproof encodes: for
/// every entry of `leaves = [(leaf index, leaf digest)]`, in input order, the
/// path whose entry `l` is node `(l, (index >> l) ^ 1)`.
///
/// The paths are a function of the untrusted inputs only; they authenticate
/// nothing until each is checked against the commitment, so a caller that
/// feeds them to the ordinary per-path Merkle check inherits exactly that
/// check's soundness.  The node list must still be consumed exactly, so every
/// multiproof has one expansion and every expansion one multiproof.
pub fn expand_multiproof<D: Copy + Eq, C: PseudoCompressionFunction<D, 2>>(
    compress: &C,
    height: usize,
    leaves: &[(usize, D)],
    nodes: &[D],
) -> Result<Vec<Vec<D>>, MultiproofError> {
    let mut tree: BTreeMap<(usize, usize), D> = BTreeMap::new();
    walk(compress, height, leaves, nodes, |level, position, digest| {
        tree.insert((level, position), digest);
    })?;
    leaves
        .iter()
        .map(|&(index, _)| {
            (0..height)
                .map(|level| {
                    let position = (index >> level) ^ 1;
                    tree.get(&(level, position))
                        .copied()
                        .ok_or(MultiproofError::MissingNode { level, position })
                })
                .collect()
        })
        .collect()
}

/// The canonical walk shared by [`verify_multiproof`] and
/// [`expand_multiproof`]: consumes `nodes` exactly, reports every node below
/// the root it learns as `(level, position, digest)`, and returns the root.
fn walk<D: Copy + Eq, C: PseudoCompressionFunction<D, 2>>(
    compress: &C,
    height: usize,
    leaves: &[(usize, D)],
    nodes: &[D],
    mut visit: impl FnMut(usize, usize, D),
) -> Result<D, MultiproofError> {
    if leaves.is_empty() {
        return Err(MultiproofError::Empty);
    }
    let mut known: Vec<(usize, D)> = Vec::with_capacity(leaves.len());
    for &(index, digest) in leaves {
        if height < usize::BITS as usize && index >> height != 0 {
            return Err(MultiproofError::IndexOutOfRange { index });
        }
        known.push((index, digest));
    }
    known.sort_by_key(|&(index, _)| index);
    let mut distinct: Vec<(usize, D)> = Vec::with_capacity(known.len());
    for (index, digest) in known {
        match distinct.last() {
            Some(&(last, existing)) if last == index => {
                if existing != digest {
                    return Err(MultiproofError::Conflict { level: 0, position: index });
                }
            }
            _ => distinct.push((index, digest)),
        }
    }
    let mut known = distinct;
    let mut stream = nodes.iter();
    for level in 0..height {
        let mut next: Vec<(usize, D)> = Vec::with_capacity(known.len());
        let mut i = 0;
        while i < known.len() {
            let (k, digest) = known[i];
            visit(level, k, digest);
            let parent = if k & 1 == 0 && i + 1 < known.len() && known[i + 1].0 == k + 1 {
                let right = known[i + 1].1;
                visit(level, k + 1, right);
                i += 2;
                compress.compress([digest, right])
            } else {
                let sibling = *stream
                    .next()
                    .ok_or(MultiproofError::MissingNode { level, position: k ^ 1 })?;
                visit(level, k ^ 1, sibling);
                i += 1;
                if k & 1 == 0 {
                    compress.compress([digest, sibling])
                } else {
                    compress.compress([sibling, digest])
                }
            };
            next.push((k >> 1, parent));
        }
        known = next;
    }
    let remaining = stream.count();
    if remaining != 0 {
        return Err(MultiproofError::SurplusNodes { remaining });
    }
    match known.as_slice() {
        [(0, root)] => Ok(*root),
        _ => Err(MultiproofError::RootMismatch),
    }
}

std::thread_local! {
    static QUERY_LOG: core::cell::RefCell<Option<Vec<(usize, Vec<usize>)>>> =
        const { core::cell::RefCell::new(None) };
}

/// Restores the enclosing query log when a [`with_query_log`] scope ends,
/// unwinding included.
struct QueryLogScope(Option<Option<Vec<(usize, Vec<usize>)>>>);

impl Drop for QueryLogScope {
    fn drop(&mut self) {
        if let Some(outer) = self.0.take() {
            QUERY_LOG.with(|log| *log.borrow_mut() = outer);
        }
    }
}

/// Runs `f` and returns, with its result, the `(tree height, query indices)`
/// of every query phase a stacked WHIR verifier ran on this thread inside
/// `f`, in transcript order.  The indices are the verifier's own
/// Fiat-Shamir samples, which is what a multiproof of that phase is keyed by.
pub fn with_query_log<R>(f: impl FnOnce() -> R) -> (R, Vec<(usize, Vec<usize>)>) {
    let mut scope = QueryLogScope(Some(QUERY_LOG.with(|log| log.replace(Some(Vec::new())))));
    let result = f();
    let outer = scope.0.take().unwrap_or_default();
    let recorded = QUERY_LOG.with(|log| log.replace(outer));
    (result, recorded.unwrap_or_default())
}

/// Appends one query phase to the enclosing [`with_query_log`], if any.
pub(crate) fn log_queries(height: usize, indices: &[usize]) {
    QUERY_LOG.with(|log| {
        if let Some(phases) = log.borrow_mut().as_mut() {
            phases.push((height, indices.to_vec()));
        }
    });
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use p3_symmetric::PseudoCompressionFunction;

    use super::*;

    /// A non-commutative test compression on `u64` digests.
    #[derive(Clone)]
    struct Mix;

    impl PseudoCompressionFunction<u64, 2> for Mix {
        fn compress(&self, [a, b]: [u64; 2]) -> u64 {
            a.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(17) ^ b.wrapping_add(0x5555)
        }
    }

    fn tree(height: usize) -> Vec<Vec<u64>> {
        let mut levels = vec![(0..1u64 << height).map(|i| i * 7 + 3).collect::<Vec<_>>()];
        for _ in 0..height {
            let prev = levels.last().unwrap();
            levels.push(prev.chunks(2).map(|c| Mix.compress([c[0], c[1]])).collect());
        }
        levels
    }

    fn path(levels: &[Vec<u64>], index: usize) -> Vec<u64> {
        (0..levels.len() - 1).map(|l| levels[l][(index >> l) ^ 1]).collect()
    }

    fn fixture(indices: &[usize]) -> (u64, Vec<(usize, u64)>, Vec<u64>) {
        let height = 8;
        let levels = tree(height);
        let root = levels[height][0];
        let paths: Vec<Vec<u64>> = indices.iter().map(|&i| path(&levels, i)).collect();
        let openings: Vec<(usize, &[u64])> =
            indices.iter().zip(&paths).map(|(&i, p)| (i, p.as_slice())).collect();
        let nodes = encode_multiproof(height, &openings).unwrap();
        let leaves = indices.iter().map(|&i| (i, levels[0][i])).collect();
        (root, leaves, nodes)
    }

    const QUERIES: [usize; 9] = [200, 3, 2, 17, 200, 255, 0, 128, 129];

    #[test]
    fn round_trip_and_node_count() {
        let (root, leaves, nodes) = fixture(&QUERIES);
        for (i, p) in leaves.iter().zip(QUERIES) {
            assert_eq!(i.0, p);
        }
        assert_eq!(verify_multiproof(&Mix, &root, 8, &leaves, &nodes), Ok(()));
        assert_eq!(nodes.len(), multiproof_positions(8, &QUERIES).unwrap().len());
        assert!(nodes.len() < 8 * QUERIES.len());
        let levels = tree(8);
        for &i in &QUERIES {
            assert_eq!(root_from_path(&Mix, i, levels[0][i], &path(&levels, i)), root);
        }
    }

    #[test]
    fn rejects_missing_surplus_reordered_conflicting() {
        let (root, leaves, nodes) = fixture(&QUERIES);
        let mut missing = nodes.clone();
        missing.pop();
        assert!(matches!(
            verify_multiproof(&Mix, &root, 8, &leaves, &missing),
            Err(MultiproofError::MissingNode { .. })
        ));
        let mut surplus = nodes.clone();
        surplus.push(nodes[0]);
        assert_eq!(
            verify_multiproof(&Mix, &root, 8, &leaves, &surplus),
            Err(MultiproofError::SurplusNodes { remaining: 1 })
        );
        let mut reordered = nodes.clone();
        reordered.swap(0, 1);
        assert_eq!(
            verify_multiproof(&Mix, &root, 8, &leaves, &reordered),
            Err(MultiproofError::RootMismatch)
        );
        let mut conflicting = leaves.clone();
        conflicting.push((200, 1));
        assert!(matches!(
            verify_multiproof(&Mix, &root, 8, &conflicting, &nodes),
            Err(MultiproofError::Conflict { level: 0, position: 200 })
        ));
        let mut wrong_leaf = leaves.clone();
        wrong_leaf[1].1 ^= 1;
        assert_eq!(
            verify_multiproof(&Mix, &root, 8, &wrong_leaf, &nodes),
            Err(MultiproofError::RootMismatch)
        );
        let mut out_of_range = leaves;
        out_of_range.push((256, 0));
        assert_eq!(
            verify_multiproof(&Mix, &root, 8, &out_of_range, &nodes),
            Err(MultiproofError::IndexOutOfRange { index: 256 })
        );
    }

    #[test]
    fn expansion_reproduces_every_path() {
        let (_, leaves, nodes) = fixture(&QUERIES);
        let levels = tree(8);
        let paths = expand_multiproof(&Mix, 8, &leaves, &nodes).unwrap();
        assert_eq!(paths.len(), QUERIES.len());
        for (&i, p) in QUERIES.iter().zip(&paths) {
            assert_eq!(*p, path(&levels, i));
        }
        let mut missing = nodes.clone();
        missing.pop();
        assert!(matches!(
            expand_multiproof(&Mix, 8, &leaves, &missing),
            Err(MultiproofError::MissingNode { .. })
        ));
        let mut surplus = nodes.clone();
        surplus.push(nodes[0]);
        assert_eq!(
            expand_multiproof(&Mix, 8, &leaves, &surplus),
            Err(MultiproofError::SurplusNodes { remaining: 1 })
        );
        let mut conflicting = leaves.clone();
        conflicting.push((3, 1));
        assert!(matches!(
            expand_multiproof(&Mix, 8, &conflicting, &nodes),
            Err(MultiproofError::Conflict { level: 0, position: 3 })
        ));
        let mut out_of_range = leaves;
        out_of_range.push((256, 0));
        assert_eq!(
            expand_multiproof(&Mix, 8, &out_of_range, &nodes),
            Err(MultiproofError::IndexOutOfRange { index: 256 })
        );
    }

    #[test]
    fn query_log_is_scoped() {
        log_queries(3, &[1]);
        let ((), outer) = with_query_log(|| {
            log_queries(4, &[2, 3]);
            let ((), inner) = with_query_log(|| log_queries(5, &[4]));
            assert_eq!(inner, vec![(5, vec![4])]);
            log_queries(6, &[5]);
        });
        assert_eq!(outer, vec![(4, vec![2, 3]), (6, vec![5])]);
        let ((), empty) = with_query_log(|| {});
        assert!(empty.is_empty());
    }

    #[test]
    fn encode_rejects_inconsistent_paths() {
        let levels = tree(8);
        let a = path(&levels, 4);
        let mut b = path(&levels, 5);
        b[3] ^= 1;
        assert!(matches!(
            encode_multiproof(8, &[(4, a.as_slice()), (5, b.as_slice())]),
            Err(MultiproofError::Conflict { level: 3, .. })
        ));
    }
}

# Stark

## The Concepts

### Field

* BabyBear
* Mersenne31


### Hash

1. CryptographicHasher: PaddingFreeSponge, a padding-free, overwrite-mode sponge function.
2. CompressionFunction: An `N`-to-1 compression function collision-resistant in a hash tree setting

#### Multiple Layers

* External Initial Layer
* Internal Layer
* External Terminal Layer

#### Permutation

Multiply a 4-element vector x by a 4x4 matrix.

* Mat4
* HL Mat4

#### Hasher

Poseidon2BabyBear


### MMC: Mixed Matric Commitment Scheme

A "Mixed Matrix Commitment Scheme" (MMCS) is a generalization of a vector commitment scheme.
It supports committing to matrices and then opening rows. It is also batch-oriented; one can commit to a batch of matrices at once even if their widths and heights differ.

When a particular row index is opened, it is interpreted directly as a row index for matrices
with the largest height. For matrices with smaller heights, some bits of the row index are
removed (from the least-significant side) to get the effective row index. These semantics are
useful in the FRI protocol.

A MerkleTreeMmmcs is used in our zkVM, which uses BabyBear as a leaf value and a packed value as the node value.

### Challenger

A transcript that digests public input and common parameters, and generates randoms for challenging in PCS.

```Rust
fn observe(value) {
    output_buffer.clear();
    input_buffer.push(value);
    if input_buffer.len() == RATE {
        drain();
        outstate = permute();
        output_bufer.extend(outstate[..RATE])
    }
}
```

The function `drain` behaves different for different challanger.

### DFT

* Radix2DitParallel: a parallel FFT algorithm which divides a butterfly network's layers into two halves.
* RecursiveDft: a decimation-in-frequency in the forward direction, decimation-in-time in the backward (inverse) direction.

### PCS

A (not necessarily hiding) polynomial commitment scheme, for committing to (batches of) polynomials.

* TwoAdicFriPcs:
* CirclePcs

## Implementations

There are two impls in current Plonky3, Two-Adic PCS and Circle Stark.

### Two Adic

#### Proving

1. Commit to the matrices

```Rust
(commits: [Root], prover_datas: [MerkleTree]) = PCS::commit(matrices);
```

2. Create a `Challenger`, and commit the Merkle Root

```
challener.observe(commit);
zeta = challenger.sample_ext();
points = vec![vec![zeta]; N_mats]
```

3. Open the points and generate the proof

* Calculate quotient polynomials Qs

// Batch combination challenge
\\[\alpha =  challenger.sample\\_ext(); \\]

\\[ Qs(X) = \sum_{i=0}^{N_{mats}} \alpha^i \cdot \frac{(p(X) - y_)}{X - z}\\]

Where p is the polynomial in point-value format in prover_data matrices, y = p(z), z is zeta.

X is in domain.

* Run the FRI on Qs

**Commit Phase**


```
commit_phase_commits = []
commit_phase_data = []
while folded.len() > config.blowup() {
    let leaves = Matrix::new(folded, 2)
    (commit, _prover_data) = commit_matrix(leaves);
    challenger.observe(commit) // commit phase commits
    commit_phase_commits.push(commit); commit_phase_data.push(_prover_data);

    let beta = challenger.sample_ext();
    folded = fold_matrix(beta, leaves); // reduce the domain size

    merge_same_degree_polys(Qs, folded)
}

final_pols = foled[0];
challenger.observe_ext(final_pols)

return (commit_phase_commits, commit_phase_data, final_pols)
```

Do `queries` times `Query` and `Answer`.

**Query Phase**


```
let global_max_height = mats.iter().map(|m| m.height()).max().unwrap();
let log_global_max_height = log2_strict_usize(global_max_height);

query_proofs = [];
for i in 0..num_queruies{
    ## open input / open_batch
    for index, data in prover_data {
        let log_max_height = log2_strict_usize(self.mmcs.get_max_height(data));
        (opened_value, opening_proof) = open_batch(index >> (log_global_max_height - log_max_height), data);
        input_proof = (opened_value, opening_proof);
    }

    ## answer query
    for data in commit_phase_data {
        (opened_value, opening_proof) = open_batch((index >> i)>>1, data);
        commit_phase_openings = (opened_value, opening_proof);
    }
    query_proofs.push(QueryProof(input_proof, commit_phase_openings))
}

return query_proofs;
```

The final proof is `(commits, opened values, fri proofs)`, where:
```
opened values = y
fri proofs = (commit_phase_commits, query_proofs, final_pols, pow_witness)
```

#### Verifying

1. Create the challenger and sample \\( \alpha \\) from challenger.

2. The challenger observes all the `commit_phase_commits` from fri proofs and final_pols, and samples all the `betas`.

3. check witness. 

4. Iterate `fri_proof.query_proofs` and verify each query.

```Rust
for qp in &proof.query_proofs {
    let index = challenger.sample_bits(log_max_height + g.extra_query_index_bits());
    let ro = open_input(index, &qp.input_proof).map_err(FriError::InputError)?;

    debug_assert!(
        ro.iter().tuple_windows().all(|((l, _), (r, _))| l > r),
        "reduced openings sorted by height descending"
    );

    let folded_eval = verify_query(
        g,
        config,
        index >> g.extra_query_index_bits(),
        izip!(
            &betas,
            &proof.commit_phase_commits,
            &qp.commit_phase_openings
        ),
        ro,
        log_max_height,
    )?;

    if folded_eval != proof.final_poly {
        return Err(FriError::FinalPolyMismatch);
    }
}
```

**open_input**




**verify_query**



### Circle Stark

TBD

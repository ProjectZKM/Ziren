# STARK Protocol

This page describes how one shard is proved: the *shard argument*. Its inputs are the shard's chip traces (see [Arithmetization](./arithmetization.md)) and its public values. The argument has four parts, run in this order under one Fiat-Shamir transcript:

1. a commitment to all main traces of the shard with one *jagged* polynomial commitment;
2. a LogUp-GKR argument that every bus balances;
3. a *zerocheck* that every chip's constraints hold on every row;
4. an opening of the committed columns at one random point, proved with WHIR.

The code is in `crates/pcs/src/shard_level/` (prover and verifier), `crates/pcs/src/jagged*.rs` and `crates/pcs/src/whir/`.

## Fields, hash and transcript

- Base field: KoalaBear, \\( p = 2^{31} - 2^{24} + 1 \\).
- Challenge field: the degree-4 extension, `BinomialExtensionField<KoalaBear, 4>`.
- Hash: Poseidon2 over KoalaBear with width 16. Merkle trees use a padding-free sponge for leaves and a truncated permutation for internal nodes, with 8-element digests.
- Transcript: a duplex challenger on the same permutation.

The wrap proof, which is verified inside a BN254 SNARK, uses a different hash and challenger (see [STARK to SNARK](./prover-architecture/stark-to-snark.md)).

## Traces as multilinear polynomials

Each column of a chip trace with \\( 2^n \\) rows is read as the multilinear extension of its values over the Boolean hypercube \\( \\{0,1\\}^n \\). There are no cyclic domains, no "next row" and no quotient polynomial. A chip's constraints are polynomials \\( C_j \\) in the values of one row (main and preprocessed columns, plus public values), of degree at most 3.

## Transcript prologue

The verifier observes the verifying key (the preprocessed commitment, the start `pc`, the initial global digest and the chip layout). For each shard it then observes the public values, the main commitment, and the number, heights and names of the chips present. Binding the heights before any challenge prevents the prover from choosing trace dimensions after seeing randomness.

## Lookup argument

The first sub-argument proves that every bus balances. The prover grinds a proof of work, then runs LogUp-GKR over all interactions of all chips (see [Lookup Arguments](./lookup-arguments.md)). It ends with claimed evaluations of the columns that appear in interactions, at a random point.

## Zerocheck

The zerocheck proves that every constraint vanishes on every real row. Constraints are batched within a chip with powers of a challenge \\( \alpha \\), giving \\( C(x) = \sum_j \alpha^j C_j(x) \\), and across chips with powers of a challenge \\( \lambda \\). The GKR's column claims are folded into the same sum with a third challenge. The prover then runs one sumcheck for

\\[ \sum_{b \in \\{0,1\\}^n} \mathrm{eq}(r, b) \cdot C(b) = \text{(the combination of the GKR claims)}, \\]

where \\( r \\) is a random point and \\( \mathrm{eq} \\) is the multilinear equality polynomial. Each round polynomial has degree 4 (degree 3 from the constraints, 1 from \\( \mathrm{eq} \\)), and there is one round per row variable of a fixed cube, \\( 2^{22} \\) rows for core shards (`CORE_MAX_LOG_ROW_COUNT`). A chip shorter than the cube is extended virtually, and the contribution of the virtual rows is removed analytically, so they need not satisfy the constraints. The sumcheck ends with claimed evaluations of every column of every chip at one point \\( z^* \\).

## Jagged commitment

A shard has dozens of chips with different heights and widths. Committing each separately would cost one Merkle tree and one opening per chip. Ziren uses a jagged polynomial commitment ([Jagged Polynomial Commitments](https://eprint.iacr.org/2025/917)). All columns of all chips are concatenated into one dense vector

\\[ q = [\\, T_0[:,0] \mid T_0[:,1] \mid \cdots \mid T_N[:,w_N - 1] \\,] \\]

without padding the columns to a common height. Prefix sums \\( t_k \\) of the column heights record where each column starts. The sparse "table of all columns" is related to \\( q \\) by

\\[ p(z_r, z_c) = \sum_j q(j) \cdot \mathrm{eq}(\mathrm{row}(j), z_r) \cdot \mathrm{eq}(\mathrm{col}(j), z_c), \\]

where \\( \mathrm{col}(j) \\) and \\( \mathrm{row}(j) \\) are the column and row that position \\( j \\) belongs to according to \\( t \\).

The dense vector is cut into stripes of \\( 2^{21} \\) values (the stacking height, `DEFAULT_LOG_STACKING_HEIGHT`). Each stripe is Reed-Solomon encoded, and all stripes of a round are committed in one Merkle tree. The preprocessed traces form a round committed at setup, whose root is in the verifying key; the main traces form a round committed per shard.

To open the columns at \\( z^* \\), a sumcheck reduces the per-column claims to one claim about \\( q \\) at a random point. The verifier evaluates the jagged indicator from the heights it already observed. The heights are part of the transcript, so the verifier checks the layout it was committed to. The claim about \\( q \\) is proved with WHIR.

## WHIR

[WHIR](https://eprint.iacr.org/2024/1586) is a multilinear polynomial commitment built on Reed-Solomon proximity testing. The stripes of both committed rounds are batched into one virtual polynomial \\( F = \sum_i \mu^i \cdot \mathrm{stripe}_i \\), and \\( \mu \\) is drawn after the claims are fixed. The prover grinds before the batching challenge. WHIR then alternates folding sumchecks, commitments to the folded codeword at a lower rate, out-of-domain samples and queries into the previous codeword. Each query opens a Merkle path, and a round-0 query opens the same row of every stripe.

The production schedule for a core shard (`core_whir_config` in `crates/pcs/src/whir/jagged.rs`) is:

| Parameter | Value |
|---|---|
| Stacking height | \\( 2^{21} \\) |
| Starting rate | \\( \rho = 2^{-2} \\); each committed round divides it by 8 |
| Folding factors | 3, then 6, 6 |
| Queries per round | 124, 88, 85 (final: 85) |
| Out-of-domain samples | 2 per committed round |
| Query grinding | 22 bits (`ZIREN_WHIR_QUERY_GRINDING_BITS`) |
| Batching grinding | 14 bits (`ZIREN_WHIR_BATCH_GRINDING_BITS`) |
| LogUp-GKR grinding | 22 bits (`ZIREN_LOGUP_GRINDING_BITS`) |

The query counts are not listed in the code but solved. In the unique-decoding regime, a query into a code of rate \\( \rho \\) is worth \\( -\log_2((1 + \rho)/2) \\) bits, so a round with \\( q \\) queries and \\( g \\) grinding bits gives \\( q \cdot (-\log_2((1+\rho)/2)) + g \\) bits. The solver picks the least \\( q \\) that reaches the per-component target, `ZIREN_SOUNDNESS_TARGET_BITS` (default 106). At the defaults:

\\[ 124 \cdot 0.678 + 22 = 106.08, \quad 88 \cdot 0.956 + 22 = 106.09, \quad 85 \cdot 0.994 + 22 = 106.52. \\]

The target is 106 rather than 100 because a shard transcript has about two dozen components, and a union bound over them should still exceed 100 bits: \\( 100 + \log_2 24 \approx 104.6 \\). Lowering a grinding parameter through the environment raises the query counts instead of weakening a round. These are bounds on the interactive protocol; the Fiat-Shamir transformation costs a further factor in the number of hash queries an adversary makes.

## Verification

The verifier, `verify_shard` in `crates/pcs/src/shard_level/verifier.rs`:

1. replays the prologue;
2. checks the LogUp-GKR proof, using the public values for the endpoints of the `State`, `GlobalAccumulation` and global-memory control buses;
3. checks the zerocheck sumcheck and recomputes every chip's batched constraint at \\( z^* \\) from the claimed column values;
4. checks the jagged reduction and the WHIR proof against the preprocessed root in the verifying key and the shard's main commitment.

Checks between shards (the `pc` chain, shard numbers, memory address ranges, the global digest) are not part of the shard argument. The recursion enforces them (see [Recursive STARK](./prover-architecture/recursive-stark.md)).

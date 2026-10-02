# Lookup Arguments

A lookup argument proves that every value a table *looks up* appears in another table. Ziren uses one general form of it for every relation between rows and between chips: each chip row *sends* or *receives* tuples on named buses, and a single argument per shard proves that on every bus the multiset of sent tuples equals the multiset of received tuples. A byte range check, an instruction fetch, a memory access and the hand-off from one instruction to the next are all instances. See [State Machine](./chips/state-machine.md) for the list of buses.

## LogUp

Ziren uses the logarithmic-derivative form of the multiset check, [LogUp](https://eprint.iacr.org/2022/1530). A multiset \\( \\{ f_j \\} \\) with multiplicities \\( m_j \\) equals a multiset \\( \\{ t_i \\} \\) with multiplicities \\( m'_i \\) exactly when, as rational functions of \\( X \\),

\\[ \sum_j \frac{m_j}{X + f_j} = \sum_i \frac{m'_i}{X + t_i}. \\]

The verifier checks the identity at a random \\( X = \alpha \\). A false identity survives only if \\( \alpha \\) is a root of a nonzero polynomial whose degree is bounded by the total number of terms, so the error is at most that number divided by the size of the extension field.

A tuple \\( (v_1, \dots, v_k) \\) on bus \\( b \\) is compressed to a single field element, its *fingerprint*, with further random challenges:

\\[ f = \alpha + \beta_0 \cdot b + \sum_{j=1}^{k} \beta_j \cdot v_j. \\]

Each interaction contributes the fraction \\( m / f \\), with \\( m \\) the row's multiplicity expression for a send and \\( -m \\) for a receive. The multiplicity is a column expression, typically `is_real` or a selector, and is zero on padding rows. The argument holds when the sum of all fractions over all rows of all chips in the shard is zero. The exception is buses that the shard's public values close (`State`, `GlobalAccumulation` and the two global-memory control buses), where the sum must equal the fractions of the boundary tuples the verifier computes from the public values.

The challenges are drawn from the degree-4 extension of KoalaBear after the prover has committed to all traces.

## Proving the sum with GKR

The sum has one term per (row, interaction) pair, many millions per shard. Ziren does not commit to running-sum columns. It proves the sum with the [GKR](https://eprint.iacr.org/2023/1284) protocol for fractional sums (LogUp-GKR):

1. Each chip's `(numerator, denominator)` pairs form a table indexed by row and interaction. Chips are padded to a common number of rows and interactions with the neutral fraction \\( 0/1 \\).
2. A layered circuit adds the fractions pairwise: \\( \frac{n_0}{d_0} + \frac{n_1}{d_1} = \frac{n_0 d_1 + n_1 d_0}{d_0 d_1} \\). Each layer halves the row dimension, and the last layer combines interactions and chips into one fraction.
3. The prover sends the output fraction, and the verifier checks that it matches the expected total. Then, layer by layer, a sumcheck reduces a claim about one layer's multilinear extensions to a claim about the layer below at a new random point.
4. At the bottom, the claim is about the numerator and denominator at a random point. These are low-degree expressions in the chips' columns, so it reduces to claims about the multilinear extensions of the trace columns at that point.

These column claims are not checked by the lookup argument itself. They are passed to the zerocheck, which batches them with the constraint check, and the resulting openings are proved by the polynomial commitment (see [STARK Protocol](./stark.md)). Before the first GKR challenge is sampled, the prover grinds a proof of work of `ZIREN_LOGUP_GRINDING_BITS` bits (default 22). The grind raises the soundness of this step to the per-component target.

## Byte and range lookups

The two lookup tables are preprocessed chips that receive on the `Byte` and `Range` buses.

- `ByteLookup` has one row for each pair of bytes \\( (b, c) \\), \\( 2^{16} \\) rows. The preprocessed columns hold the result of each byte operation on that pair (`AND`, `OR`, `XOR`, `NOR`, `SLL`, shift-right with carry, `LTU`, `MSB`), and the pair itself doubles as a 16-bit value for `U16Range`. A lookup `(op, a, b, c)` claims that `a` is the result of `op` on `b` and `c` (or, for range checks, that the operand is in range). The main trace has one multiplicity column per operation.
- `RangeLookup` holds the pairs `(a, bits)` with \\( a < 2^{bits} \\) for \\( bits \le 10 \\). The machine uses it for limbs narrower than a byte or a half-word, chiefly the 10-bit high limb of a 26-bit timestamp.

For example, the check that a word consists of four bytes is two `U8Range` lookups, `(U8Range, 0, b_0, b_1)` and `(U8Range, 0, b_2, b_3)`. Each tuple exists in the table only if both bytes are below 256. The table row for that pair counts the requests in its `U8Range` multiplicity column, and bus balance forces the counts to be right.

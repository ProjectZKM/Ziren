# Memory Consistency Checking

[Offline memory checking](https://georgwiese.github.io/crypto-summaries/Concepts/Protocols/Offline-Memory-Checking) lets a prover show that a read/write memory was used correctly: every read returns the value most recently written to that address. Unlike online checking with Merkle paths, it checks nothing per access. Each access adds tuples to two multisets, and one equality check between the multisets at the end covers all accesses. Ziren uses it for registers and memory alike, within a shard through the lookup argument and across shards through a multiset hash on an elliptic curve.

## Read set and write set

The read set \\( RS \\) and write set \\( WS \\) are multisets of tuples \\( (a, v, c) \\): an address, a value and a timestamp.

- **Initialization.** \\( RS = WS = \emptyset \\). For every address \\( a_i \\) with initial value \\( v_i \\), add \\( (a_i, v_i, 0) \\) to \\( WS \\).
- **Access.** To access address \\( a \\) at time \\( c_{now} \\), take the last tuple \\( (a, v, c) \\) written for \\( a \\), add it to \\( RS \\), and add \\( (a, v', c_{now}) \\) to \\( WS \\). For a read \\( v' = v \\); for a write \\( v' \\) is the new value.
- **Post-processing.** For every address, add its last tuple in \\( WS \\) to \\( RS \\).

The memory was used correctly if:

1. the sets were initialized correctly;
2. at every access \\( c < c_{now} \\), so the timestamps of an address strictly increase;
3. a read adds the same value to \\( RS \\) and \\( WS \\);
4. after post-processing, \\( RS = WS \\).

Suppose the first incorrect read of address \\( a \\) returns \\( (a, v', c') \\) instead of the last written \\( (a, v, c) \\). All tuples in \\( WS \\) are distinct because timestamps strictly increase, and \\( (a, v', c') \\) was never written. So \\( RS \\) contains a tuple that \\( WS \\) does not contain, and no later step can remove it. Then \\( RS \neq WS \\).

## Within a shard

A shard's accesses are tuples `(shard, clk, addr, value)` on the `Memory` bus. The timestamp is the pair `(shard, clk)`.

- An access sends its previous tuple `(prev_shard, prev_clk, addr, prev_value)` (the read) and receives its new tuple (the write). It asserts that `(shard, clk)` is strictly larger than `(prev_shard, prev_clk)`. When the shards are equal, the difference `clk - prev_clk - 1` is split into a 16-bit and a 10-bit limb and both are range-checked, which proves `clk > prev_clk` because both clocks are below \\( 2^{26} \\). Otherwise the same check is applied to the shards.
- `MemoryLocal` has one row per address the shard touches. The row supplies the address's first tuple in the shard and consumes its last one.
- Registers are addresses 0 to 35. `MemoryBump` inserts a read of every touched register at `(shard, 0)`, so the check for every other register access compares clocks only (see [Memory](./chips/memory.md)).

The `Memory` bus balances when the sends equal the receives, which is condition 4 for the shard. The LogUp-GKR argument proves it together with all other buses (see [Lookup Arguments](./lookup-arguments.md)).

## Across shards

The first and last tuple of each address in a shard must also match the neighbouring shards. These tuples go on the `Global` bus:

- `MemoryLocal` *receives* the address's initial tuple and *sends* its final tuple.
- `MemoryGlobalInit` sends the initial value of each address outside the program image, at timestamp `(0, 0)`.
- `MemoryGlobalFinal` receives the final value of each touched address.
- The initial values of the program image are not rows. Their contribution is precomputed at setup as the verifying key's `initial_global_cumulative_sum`.

Because shards are proved independently, the lookup argument, which only balances within one shard, cannot match these messages. Instead each message is hashed to a point on an elliptic curve, the `Global` chip adds up the shard's points, and the shard's sum is a public value. The recursion adds the sums of all shards and the verifying key's initial sum, and the root checks that the total is the neutral digest. A matching send and receive map to opposite points and cancel. The same mechanism carries syscalls from an execution shard to the precompile shard that proves them.

## Multiset hashing

A multiset hash maps a multiset to a short value such that it is infeasible to find two different multisets with the same hash, and such that the hash can be updated one element at a time in any order. Ziren maps each element to a point on an elliptic curve and hashes a multiset to the sum of its points.

To map a message \\( m = (m_0, \dots, m_6) \\) to a point, Ziren follows [Constraint-Friendly Map-to-Elliptic-Curve-Group Relations and Their Applications](https://eprint.iacr.org/2025/1503) and uses the message directly as the \\( x \\)-coordinate, without hashing it first:

- \\( x_0 = m_0 + 2^{16} \cdot kind \\), where \\( m_0 \\) is range-checked to 16 bits and \\( kind \\) names the bus the message came from;
- \\( x_i = m_i \\) for \\( 1 \le i \le 5 \\);
- \\( x_6 = 256 \cdot m_6 + t \\), where \\( m_6 \\) is a byte and \\( t \\) is an 8-bit tweak.

The prover tries tweaks \\( t = 0, 1, \dots \\) until \\( x \\) is on the curve. For the square root \\( y \\), the top coefficient \\( y_6 \\) fixes the sign. A received message must have \\( 1 \le y_6 \le 63 \cdot 2^{24} \\), and a sent message \\( 2^{30} + 1 \le y_6 \le p - 1 \\). The two ranges are disjoint and mirror each other under \\( y \mapsto -y \\), so a send and the matching receive give opposite points. Each row sets exactly one of `is_send` and `is_receive`.

The `Global` chip adds the points in a chain on the `GlobalAccumulation` bus using the chord formula. It witnesses \\( (x_2 - x_1)^{-1} \\) at each step so that doubling and adding an inverse are not provable. Sums start at a fixed point derived from \\( \sqrt{2} \\), and that point is the neutral digest.

The parameters are:

- base field KoalaBear, \\( p = 2^{31} - 2^{24} + 1 \\);
- extension \\( \mathbb{F}_{p^7} = \mathbb{F}_p[z]/(z^7 + 2z - 8) \\);
- curve \\( y^2 = x^3 + 3z \cdot x - 3 \\).

## Elliptic curve selection over the KoalaBear extension field

**Objective**

Find an elliptic curve over the degree-7 extension of KoalaBear, \\( p = 2^{31} - 2^{24} + 1 \\), with more than 100 bits of security against known attacks and cheap arithmetic.

**Code location**

The search is in [septic-curve-over-koalabear](https://github.com/ProjectZKM/septic-curve-over-koalabear), a fork of [Cheetah](https://github.com/toposware/cheetah), which finds a curve over a sextic extension of the Goldilocks prime \\( 2^{64} - 2^{32} + 1 \\).

**Construction**

- Step 1: sparse irreducible polynomial.
  - Requirements: few nonzero coefficients, small coefficients, irreducible over the base field.
  - Implementation (`septic_search.sage`): `poly = find_sparse_irreducible_poly(Fpx, extension_degree, use_root=True)`.
  - Result: \\( z^7 + 2z - 8 \\).

- Step 2: candidate curves.
  - Form \\( y^2 = x^3 + ax + b \\) with small coefficients.
  - Search in `septic_search.sage`:
    ```
    for i in range(wid, 1000000000, processes):
        coeff_a = 3 * a  # Fixed coefficient scaling
        coeff_b = i - 3
        E = EllipticCurve(extension, [coeff_a, coeff_b])
    ```
  - Result: \\( a = 3z \\), \\( b = -3 \\), with \\( z \\) the generator of the extension.

- Step 3: security checks.
  - Pollard rho: the largest prime factor of the group order has more than 210 bits.
    ```
    prime_order = list(ecm.factor(n))[-1]
    assert prime_order.nbits() > 210
    ```
  - Embedding degree:
    ```
    embedding_degree = calculate_embedding_degree(E)
    assert embedding_degree.nbits() > EMBEDDING_DEGREE_SECURITY
    ```
  - The same two checks for the quadratic twist.

- Step 4: complex discriminant.
  With \\( n \\) the order of the curve, \\( D = (p^7 + 1 - n)^2 - 4p^7 \\) must be a large negative integer (absolute value above 100 bits) whose square-free part exceeds 100 bits. Run `sage verify.sage` to check.

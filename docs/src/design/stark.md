# STARK Protocol

## Polynomial Constraint System Architecture

Following [arithmetization](./arithmetization.md), the computation is represented through a structured polynomial system.

### Core Components
- ​Execution Trace Polynomials
  
  Encode state transitions across computation steps as:
  \\[ T_i(x) = \sum_{k=0}^{N-1} t_{i,k} \cdot L_k(x),\\]
  where \\(L_k(x)\\) are Lagrange basis polynomials over domain H. 
​
- Constraint Polynomials
  Encode verification conditions as algebraic relations:
  \\[C_j(x) = R_j(T_1(x),T_2(x), \cdots, T_m(x), T_1(g \cdot x), T_2(g \cdot x), \cdots, T_m(g \cdot x)) = 0,\\]
  for all \\(x \in H\\), where \\(g\\) is the generator of H.

### Constraint Aggregation
For proof efficiency, we combine constraints using:
\\[C_{comb}(x) = \sum_j \alpha_j C_j(x),\\]
where \\( \alpha_j\\) are derived through the Fiat-Shamir transformation.

## Mixed Matrix Commitment Scheme (MMCS)

### Polynomial Commitments in STARK

STARK uses Merkle trees for polynomial commitments:

- Setup: No trusted setup is needed, but a hash function for Merkle tree construction must be predefined. We use Poseidon2 as the predefined hash function.

- Commit: Evaluate polynomials at all roots of unity in its domain, construct a Merkle tree with these values as leaves, and publish the root as the commitment.

- Open: The verifier selects a random challenge point, and the prover provides the value and Merkle path for verification.

### Batch Commitment Protocol

The "Mixed Matrix Commitment Scheme" (MMCS) is a generalization of a vector commitment scheme used in Ziren. It supports:

- Committing to matrices.
- Opening rows.
- Batch operations - committing to multiple matrices simultaneously, even when they differ in dimensions.

When opening a particular row index:

- For matrices with maximum height: use the full row index.
- For smaller matrices: truncate least-significant bits of the index.

These semantics are particularly useful in the FRI protocol.

### Low-Degree Extension (LDE)

Suppose the trace polynomials are initially of length \\(N\\). For security, we evaluate them on a larger domain (e.g., \\(2^k \cdot N\\)), called the LDE domain.

Using Lagrange interpolation:
- Compute polynomial coefficients.
- Extend evaluations to the larger domain,

Ziren implements this via Radix2DitParallel - a parallel FFT algorithm that divides butterfly network layers into two halves.

## Low-Degree Enforcement

### Quotient Polynomial Construction

To prove \\(C_{comb}(x)\\) vanishes over subset \\(H\\), construct quotient polynomial \\(Q(x)\\):
\\[Q(x) = \frac{C_{comb}(x)} {Z_{H}(x)} = \frac{\sum_j \alpha_j C_j(x)}{\prod_{h \in H}(x-h)}.\\]

The existence of such a low-degree \\(Q(x)\\) proves \\(C_{comb}(x)\\) vanishes over \\(H\\).

## FRI Protocol 

The Fast Reed-Solomon Interactive Oracle Proof (FRI) protocol proves the low-degree of \\(P(x)\\). Ziren optimizes FRI by leveraging:
- Algebraic structure of quartic extension \\(\mathbb{F}_{p^4}\\).
- KoalaBear prime field \\(p = 2^{31} - 2^{24} + 1\\).
- Efficient Poseidon2 hash computation.

**Three-Phase FRI Procedure**
- Commitment Phase:

  - The prover splits \\(P(x)\\) into two lower-degree polynomials \\(P_0(x)\\), \\(P_1(x)\\), such that: \\(P(x) = P_0(x^2) + x \cdot P_1(x^2)\\).

  - The verifier sends a random challenge \\(\alpha \in  \mathbb{F}_{p^4}\\) 
  - The prover computes a new polynomial: \\(P'(x) = P_0(x) + \alpha \cdot P_1(x)\\), and sends the commitment of the polynomials to the verifier.

- ​Recursive Reduction:
  - Repeat splitting process for \\(P'(x)\\).
  - Halve degree each iteration until constant term or degree ≤ d.

- ​Verification Phase:
  - Verifier checks consistency between committed values at random point \\(z\\) in initial subgroup.

## Verifying 

### Verification contents
To ensure the correctness of the folding process in a FRI-based proof system, the verifier performs checks over multiple rounds using randomly chosen points from the evaluation domain. In each round, the verifier essentially re-executes a step of the folding process and verifies that the values provided by the prover are consistent with the committed Merkle root. The detailed interaction for a single round is as follows:

1. The verifier randomly selects a point \\(t \in \Omega\\).
2. The prover returns the evaluation \\(p(t)\\) along with the corresponding Merkle proof to verify its inclusion in the committed polynomial.

Then, for each folding round \\(i = 1\\) to \\(\log d\\) (d: polynomial degree): 

1. The verifier updates the query point using the rule \\(t \leftarrow t^2\\), simulating the recursive domain reduction of FRI.
2. The prover returns the folded evaluation \\(P_{\text{fold}}(t)\\) and the corresponding Merkle path.
3. The verifier checks whether the folding constraint holds: \\(P_{\text{fold}}(t) = P_e(t) + t \cdot P_o(t)\\), where \\(P_e(t)\\) and \\(P_o(t)\\) are the even and odd parts of the polynomial at the given layer.

4. This phase will end until a predefined threshold or the polynomial is reduced to a constant.

### Grinding Factor & Repeating Factor

Given the probabilistic nature of STARK verification, the protocol prevents brute-force attacks by requiring either:
- A Proof of Work (PoW) accompanying each proof, or
- multiple verification rounds.

This approach significantly increases the computational cost of malicious attempts. In Ziren, we employ multiple verification rounds to achieve the desired security level.

## Security Configurations

Ziren supports two security levels, selectable at compile time:

### 100-bit Security (Default)

Uses a **quartic extension** (D=4) over KoalaBear:

| Parameter | Value |
|-----------|-------|
| Base field | KoalaBear (p = 2^31 - 2^24 + 1, ~31 bits) |
| Extension field | BinomialExtensionField<KoalaBear, 4> (~124 bits) |
| FRI queries | 84 |
| Proof-of-work | 16 bits |
| Protocol security | 84 bits (100 - 16 PoW) |
| Security model | Unique Decoding (proven) |

Config: `KoalaBearPoseidon2` / `KoalaBearPoseidon2Inner`

### Configurable Security with D=5 (Quintic Extension)

The quintic extension config `KoalaBearPoseidon2D5` supports any security level up to ~155 bits. FRI queries are automatically derived from the target:

```rust
// 128-bit security
let config = KoalaBearPoseidon2D5::with_security(128);

// Or any other target
let config = KoalaBearPoseidon2D5::with_security(112);
```

| Parameter | Value |
|-----------|-------|
| Base field | KoalaBear (p = 2^31 - 2^24 + 1, ~31 bits) |
| Extension field | QuinticTrinomialExtensionField<KoalaBear> (~155 bits) |
| FRI queries | Auto-derived from security target |
| Proof-of-work | 16 bits |
| Security model | Unique Decoding / Johnson Bound (proven) |

Reference: [Plonky3-recursion](https://github.com/Plonky3/Plonky3-recursion) uses D=5 for KoalaBear with parameterized security. The Johnson Bound proximity gaps from [BCSS25] (Ben-Sasson, Carmon, Haboeck, Kopparty, Saraf, 2025) improve the error bound from O(n^2/eta^7) to O(n/eta^5), enabling provable 128-bit security.

**Trade-offs vs D=4 at same security level:**
- Proofs are ~20% larger (more queries needed at higher targets)
- Verification is ~15% slower (quintic field arithmetic vs quartic)
- Proving is ~10% slower (wider extension)
- No security conjectures required at 128-bit

## WHIR PCS (Alternative to FRI)

WHIR (Worst-case to average-case reduction for Interactive Reed-Solomon) is an alternative polynomial commitment scheme available via the `whir` feature flag.

### How WHIR Differs from FRI

| Property | FRI | WHIR |
|----------|-----|------|
| Polynomial type | Univariate | Multilinear |
| Reduction method | Domain halving | Folding + sumcheck |
| Vars per round | 1 | 4 (configurable) |
| Proof structure | Merkle paths at each round | Merkle paths + sumcheck proofs |

### Performance (100-bit security, 2^20 trace)

| Metric | FRI | WHIR | Improvement |
|--------|-----|------|-------------|
| Proof size | ~53 KB | ~14 KB | 3.6x smaller |
| Verification hashes | 1,680 | 455 | 3.7x faster |
| Prover cost | baseline | comparable | ~neutral |

### WHIR Security Levels

WHIR PCS is generic over the challenge field and security level:

```rust
// 100-bit with D=4
let params = whir_parameters(100);
let pcs = koalabear_whir_pcs::<WhirChallenge>(num_vars, params);

// 128-bit with D=5
let params = whir_parameters(128);
let pcs = koalabear_whir_pcs::<Whir128Challenge>(num_vars, params);
```

The `whir_parameters()` function automatically selects the soundness assumption:
- `<= 100 bits`: Capacity Bound (conjectured, most efficient)
- `> 100 bits`: Johnson Bound (proven via [BCSS25], requires D=5)

### Integration Status

WHIR implements the `MultilinearPcs` trait, not the univariate `Pcs` trait used by the current STARK pipeline. Full integration requires either an adapter from `MultilinearPcs` to `Pcs`, or a new STARK pipeline built on `MultilinearPcs` (as done in [Plonky3-recursion](https://github.com/Plonky3/Plonky3-recursion)). The parameter configuration and type aliases are available in `zkm_stark::whir_config` (feature-gated).

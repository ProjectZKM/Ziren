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

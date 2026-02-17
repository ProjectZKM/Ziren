# Memory Consistency Checking

[Offline memory checking](https://georgwiese.github.io/crypto-summaries/Concepts/Protocols/Offline-Memory-Checking) is a method that enables a prover to demonstrate to a verifier that a read/write memory was used correctly. In such a memory system, a value \\(v\\) can be written to an address \\(a\\) and subsequently retrieved. This technique allows the verifier to efficiently confirm that the prover adhered to the memory's rules (i.e., that the value returned by any read operation is indeed the most recent value that was written to that memory address).

This is in contrast to "online memory checking" techniques like Merkle hashing which ​immediately verify that a memory read was done correctly by insisting that each read includes an authentication path. Merkle hashing is  ​computationally expensive on a per-read basis for ZK provers, and offline memory checking suffices for zkVM design.

Ziren replaces ZKM's online memory checking with LtHash-based offline memory checking for improved efficiency. Ziren verifies the consistency of read/write operations by constructing a read set \\(RS\\) and a write set \\(WS\\), then proving their equivalence. This mechanism uses an additive LtHash-style multiset digest to ensure memory integrity efficiently. Below is a detailed breakdown of its key components.

## Construction of Read Set and Write Set

Definition: The read set \\(RS\\) and write set  \\(WS\\) are sets of tuples \\(a, v, c\\), where:

- \\(a\\): Memory address
- \\(v\\): Value stored at address \\(a\\)
- \\(c\\): Operation counter

**Three-Stage Construction**

Initialization:

- \\(RS = WS = \emptyset\\);
- All memory cells \\(a_i\\) are initialized with some value \\(v_i\\) at op count \\(c=0\\). Add the initial tuples to the write set \\(WS = WS \bigcup \\{(a_i, v_i, 0)\\}\\) for all \\(i\\).

Read and write operations:
- ​Read Operation, for reading a value from address \\(a\\):
  - Find the last tuple \\((a, v, c)\\) added to write set \\(WS\\) with the address \\(a\\).
  - \\(RS = RS \bigcup \\{(a, v, c)\\}\\) and \\(WS = WS \bigcup \\{(a, v, c_{now})\\}\\), with \\(c_{now}\\) the current op count.
- ​Write Operation, for writing a value \\(v'\\) to address \\(a\\):
  - Find the last tuple \\((a, v, c)\\) added to write set \\(WR\\) with the address \\(a\\). 
  - \\(RS = RS \bigcup \\{(a, v, c)\\}\\) and \\(WS = WS \bigcup \\{(a, v', c_{now})\\}\\).

Post-processing：

- For all memory cells \\(a_i\\), add the last tuple \\((a_i, v_i, c_i)\\) in write set \\(WS\\) to \\(RS\\): \\(RS = RS \bigcup \\{(a_i, v_i, c_i)\\}\\).


## Core Observation

The prover adheres to the memory rules ​if the following conditions hold:

1) The read and write sets are correctly initialized; 
2) For each address \\(a_i\\), the instruction count added to \\(WS\\) strictly increases over time;
3) ​For read operations: Tuples added to \\(RS\\) and \\(WS\\) must have the same value.
4) ​For write operations: The operation counter of the tuple in \\(RS\\) must be less than that in \\(WS\\).
5) After post-processing, \\(RS = WS\\).

Brief Proof: Consider the first erroneous read memory operation. Assume that a read operation was expected to return the tuple \\((a,v,c)\\), but it actually returned an incorrect tuple \\((a, v' \neq v, c')\\) and added it to read set \\(RS\\). Note that all tuples in \\(WS\\) are distinct. After adding \\((a,v',c_{now})\\) to \\(WS\\), the tuples \\((a,v,c)\\) and \\((a,v',c_{now})\\) are not in the read set \\(RS\\). According to restriction 3, after each read-write operation, there are always at least two tuples in \\(WS\\) that are not in \\(RS\\), making it impossible to adjust to \\(RS = WS\\) through post-processing.

## LtHash-Based Multiset Hashing

Multiset hashing maps a (multi-)set to a short digest. In Ziren, this is implemented with an LtHash-style additive construction that is order-independent and incremental.

### Detailed Parameters (Current Implementation)

- Base field: KoalaBear prime field \\(\mathbb{F}_p\\), \\(p = 2^{31} - 2^{24} + 1\\).
- LtHash coordinate dimension: \\(N = 24\\).
- Message width: 10 field elements per event.
- Message layout for global/memory events:
  \\[
  m = [m_0,\dots,m_9] =
  [\text{shard},\text{clk},\text{addr},\text{val}_0,\text{val}_1,\text{val}_2,\text{val}_3,0,0,\text{kind}]
  \\]
- Coefficient generation (deterministic, prover-independent), for row \\(i\\in[0,N-1]\\), column \\(j\\in[0,9]\\):
  \\[
  a=(i+1)\cdot 0x9E3779B185EBCA87,\;
  b=(j+1)\cdot 0xC2B2AE3D27D4EB4F
  \\]
  \\[
  c_{i,j} = \big((a+b)\cdot 0x165667B19E3779F9\big)\bmod 2^{32},
  \quad c_{i,j}\in \mathbb{F}_p\ \text{via wrapped u32 embedding}
  \\]
- Per-event LtHash coordinates:
  \\[
  H(m)_i=\sum_{j=0}^{9} c_{i,j}\cdot m_j,\quad i=0,\dots,N-1
  \\]
- Signed accumulation rule:
  - receive event: add \\(+H(m)\\)
  - send event: add \\(-H(m)\\)
- Segmented accumulation:
  - segment index: \\(\mathrm{seg} = \lfloor \mathrm{clk}/2^{20} \rfloor\\)
  - segment bound: \\(2^{20}\\) real events per segment
  - segment count: 16
  - maximum real events per shard: \\(2^{24}\\)
  - cumulative exposed columns: \\(24\times 16=384\\)

### AIR-Enforced Relations

For each row, the AIR enforces:
- boolean constraints on `is_send`, `is_receive`, `is_real`, and one-hot segment selector;
- exact LtHash coordinate computation from message columns and fixed coefficients;
- signed hash relation:
  \\[
  h_t^{(i)} = (r_t - s_t)\cdot u_t^{(i)}
  \\]
  where \\(r_t,s_t\in\{0,1\}\\) are receive/send flags and \\(u_t^{(i)}\\) is the unsigned LtHash coordinate;
- segmented running-sum transition:
  \\[
  S_{t+1}^{(s,i)} = S_t^{(s,i)} + b_{t+1}^{(s)} \cdot h_{t+1}^{(i)}
  \\]
  where \\(b_{t+1}^{(s)} \in \{0,1\}\\) is the one-hot segment selector and \\(h_{t+1}^{(i)}\\) is the signed LtHash coordinate at row \\(t+1\\);
  with first-row initialization constrained consistently.

### Security Proof Sketch

#### Theorem 1 (Constraint Soundness)

If all AIR constraints above are satisfied, then the exposed cumulative LtHash state equals the exact signed sum of all real events, partitioned by segment.

Reason: this follows directly from first-row initialization and the per-step transition equality.

#### Theorem 2 (Memory-Consistency Reduction)

Suppose an adversary outputs a proof accepted by the verifier while the final read/write multisets differ. Then at least one of the following must hold:
- some lookup/AIR constraint is violated (contradicting proof validity), or
- a non-trivial LtHash collision is found:
  \\[
  \sum_k \sigma_k H(m_k)=0,\;\sigma_k\in\{+1,-1\}
  \]
  for a non-empty unmatched multiset difference.

So protocol soundness reduces to constraint soundness plus LtHash collision resistance for the encoded event domain.

#### Collision Bound (Random-Matrix Heuristic)

Under the standard heuristic that the coefficient matrix \\(C=(c_{i,j})\\) behaves like a random matrix over \\(\mathbb{F}_p\\), for any fixed non-zero aggregate difference \\(\Delta\), the probability that \\(C\Delta=0\\) is approximately:
\\[
\Pr\left[C\Delta=0\right]\approx p^{-N}
\\]
With current parameters \\(p\approx 2^{31}\\), \\(N=24\\), this is about \\(2^{-744}\\) per fixed attempt.

> Note: This is a proof sketch under an explicit random-matrix heuristic. A full cryptographic reduction for this exact deterministic coefficient construction is not yet included in this document.

## Appendix: Formal Security Argument for LtHash Memory Checking

This appendix provides a stricter, reduction-style argument for the current LtHash memory-checking design.

### A.1 Threat Model and Security Goal

- Adversary model: probabilistic polynomial-time prover \\(\mathcal{P}^*\\).
- Verifier accepts only if all STARK/AIR/lookup constraints are satisfied and final boundary checks pass.
- Security goal (memory soundness): except with negligible probability, an accepted proof implies the read/write multisets are equal after prescribed initialization and post-processing rules.

Formally, let \\(\mathsf{Acc}\\) denote the event "verifier accepts" and let \\(\mathsf{BadMem}\\) denote "offline memory relation is false" (i.e., final \\(RS \neq WS\\) as multisets of tuples). We need:
\\[
\Pr\left[\mathsf{Acc} \wedge \mathsf{BadMem}\right] \le \varepsilon_{\text{total}}
\\]
for negligible \\(\varepsilon_{\text{total}}\\).

### A.2 LtHash Assumption (Explicit)

Define encoded-event map \\(\mathsf{Enc}: \mathcal{D}\to \mathbb{F}_p^{10}\\) and linear map \\(H:\mathbb{F}_p^{10}\to\mathbb{F}_p^{24}\\):
\\[
H(m)_i = \sum_{j=0}^{9} c_{i,j} m_j
\\]
with fixed deterministic coefficients \\(c_{i,j}\\).

For a signed multiset difference \\(\Delta=\{(\sigma_k,m_k)\}_k\\), \\(\sigma_k\in\{+1,-1\}\\), define:
\\[
\mathsf{Agg}(\Delta)=\sum_k \sigma_k H(m_k)\in\mathbb{F}_p^{24}.
\\]

Assumption (LtHash collision resistance on domain \\(\mathcal{D}\\)): finding non-empty \\(\Delta\\) with \\(\mathsf{Agg}(\Delta)=0\\) is computationally infeasible, except probability \\(\varepsilon_{\text{LtHash}}\\).

### A.3 Constraint Soundness Lemma

Lemma 1. If AIR transition, boolean, one-hot, and coordinate constraints are all satisfied, the committed cumulative columns equal the exact segmented signed sum of all real events.

Proof sketch:
1. First-row constraints bind initial cumulative value to first-row signed delta.
2. Transition constraints enforce next cumulative = current cumulative + current-row delta contribution (for the selected segment).
3. One-hot segment selector guarantees exactly one segment receives each real event contribution.
4. Coordinate constraints bind each per-row \\(u_t^{(i)}\\) to the fixed linear function \\(H(m)\\).
By induction over rows, cumulative columns equal the exact segmented accumulation.

### A.4 Reduction from Memory Forgery to LtHash Collision

Lemma 2. Assume lookup constraints correctly enforce local event semantics (send/receive typing, message format, and membership constraints). If verifier accepts and \\(RS \neq WS\\), then either:
- a constraint system soundness failure occurs (probability \\(\varepsilon_{\text{STARK}}\\)), or
- a non-empty signed difference \\(\Delta\\) with \\(\mathsf{Agg}(\Delta)=0\\) exists (LtHash collision event).

Reason:
1. Under valid local constraints, all emitted rows correspond to well-formed encoded events.
2. By Lemma 1, accepted proof fixes cumulative digest to true signed sum of emitted events.
3. Acceptance requires final boundary/cumulative condition corresponding to zero net digest.
4. If underlying multisets differ, the signed difference is non-empty, yet aggregate equals zero, yielding collision.

### A.5 Segmentation Does Not Weaken Security

Lemma 3. Segmenting accumulation by \\(\mathrm{seg}=\lfloor \mathrm{clk}/2^{20}\rfloor\\) is equivalent to hashing with domain separation by segment index.

Reason:
- The proof tracks 16 independent 24-dimensional sums.
- Final equality requires every segment-coordinate pair to satisfy zero net sum.
- Any forgery induces either:
  - collision within one segment, or
  - coordinated multi-segment collision that is still a non-trivial solution to the global linear system over all 384 coordinates.

Thus segmentation changes representation/efficiency, not the underlying reduction structure.

### A.6 Main Soundness Theorem

Theorem. Under:
- STARK/AIR/lookup soundness with error \\(\varepsilon_{\text{STARK}}\\),
- LtHash collision-resistance assumption on encoded domain with error \\(\varepsilon_{\text{LtHash}}\\),

the memory-checking protocol satisfies:
\\[
\Pr\left[\mathsf{Acc} \wedge \mathsf{BadMem}\right] \le \varepsilon_{\text{STARK}} + \varepsilon_{\text{LtHash}}.
\\]

Proof:
Apply Lemma 2 and union bound over the two bad events.

### A.7 Parameterized Bound (Heuristic Instantiation)

Under the random-matrix heuristic for \\(C=(c_{i,j})\\):
\\[
\varepsilon_{\text{LtHash}} \approx p^{-24}.
\\]
With \\(p \approx 2^{31}\\):
\\[
\varepsilon_{\text{LtHash}} \approx 2^{-744}.
\\]
Hence:
\\[
\varepsilon_{\text{total}} \lesssim \varepsilon_{\text{STARK}} + 2^{-744}.
\\]

This term is dominated by \\(\varepsilon_{\text{STARK}}\\) in practical deployments.

## Deprecated: EC-Based Multiset Hashing (Historical)

> Deprecated: This section documents the previous EC-based multiset hashing design that has been replaced by LtHash in the current implementation.

### Multiset Hashing (Legacy)

Multiset hashing maps a (multi-)set to a short string, making it computationally infeasible to find two distinct sets with the same hash. The hash is computed incrementally, with order-independence as a key property.

#### Implementation on Elliptic Curve (Legacy)

Let \\(G\\) denote the group of points \\((x,y)\\) on the elliptic curve defined by \\(y^2 = x^3 +Ax+B\\), including the point at infinity. We adopt a hash-to-group approach following the framework described in [Constraint-Friendly Map-to-Elliptic-Curve-Group Relations and Their Applications](https://eprint.iacr.org/2025/1503.pdf). To map a set element to a point on the curve, we first assign it directly to the \\(x\\)-coordinate of a candidate point without an intermediate hashing step. Since this \\(x\\)-value may not correspond to a valid point on the curve, we apply an 8-bit tweak \\(t\\) to adjust it. The sign of the resulting \\(y\\)-coordinate is constrained to prevent ambiguity, either by restricting \\(y\\) to be a quadratic residue or by imposing explicit range checks. Furthermore, the message length is bounded by 110 bits, and the base field of the curve operates over the 7th extension field of the KoalaBear Prime to ensure a security level of at least 100 bits.

Legacy parameters:
- KoalaBear Prime field: \\(\mathbb{F}_P\\), with \\(P = 2^{31} - 2^{24} +1\\).
- Septic extension field: defined under irreducible polynomial \\(u^7 + 2u - 8\\).
- Elliptic curve: defined with \\(A = 3*u, B = -3\\) (provides >=102-bit security).

### Elliptic Curve Selection over KoalaBear Prime Extension Field (Legacy)

#### Objective

Construct an elliptic curve over the 7th-degree extension field of KoalaBear Prime \\(P = 2^{31} - 2^{24} +1\\), achieving >100-bit security against known attacks while maintaining computational efficiency.

#### Code Location

Implementation available [here](https://github.com/ProjectZKM/septic-curve-over-koalabear). It is a fork from [Cheetah](https://github.com/toposware/cheetah) that finds secure curve over a sextic extension of Goldilock Prime \\(2^{64} - 2^{32} + 1\\).

#### Construction Workflow

- Step 1: Sparse Irreducible Polynomial Selection
  Requirements:
  - Minimal non-zero coefficients in polynomial
  - Small absolute values of non-zero coefficients
  - Irreducibility over base field
  Implementation (septic_search.sage):
  - `poly = find_sparse_irreducible_poly(Fpx, extension_degree, use_root=True)`
  - The selected polynomial: \\(x^7 + 2x - 8\\). This sparse form minimizes arithmetic complexity while ensuring irreducibility.

- Step 2: Candidate Curve Filtering
  Curve form: \\(y^2 = x^3 + ax + b\\), with small |a| and |b| to optimize arithmetic operations.
  Parameter search in septic_search.sage:
  ```text
  for i in range(wid, 1000000000, processes):
      coeff_a = 3 * a  # Fixed coefficient scaling
      coeff_b = i - 3
      E = EllipticCurve(extension, [coeff_a, coeff_b])
  ```
  Final parameters chosen: \\(a = 3u, b = -3\\) (with \\(u\\) as extension field generator).

- Step 3: Security Validation
  Pollard-Rho resistance:
  ```text
  prime_order = list(ecm.factor(n))[-1]
  assert prime_order.nbits() > 210
  ```
  Embedding degree check:
  ```text
  embedding_degree = calculate_embedding_degree(E)
  assert embedding_degree.nbits() > EMBEDDING_DEGREE_SECURITY
  ```
  Twist security:
  - Pollard-Rho resistance
  - Embedding degree check

- Step 4: Complex Discriminant Verification
  Check discriminant condition for secure parameterization:
  \\[
  D=(P^7 + 1 - n)^2 - 4P^7
  \\]
  where \\(n\\) is the full order of the original curve. \\(D\\) must satisfy:
  - Large negative integer (absolute value > 100 bits)
  - Square-free part > 100 bits
  Validation command:
  - `sage verify.sage`

The selected curve achieves >100-bit security. This construction follows NIST-recommended practices while optimizing for zkSNARK arithmetic circuits through sparse polynomial selection and small curve coefficients.

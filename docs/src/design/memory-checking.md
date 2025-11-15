# Memory Consistency Checking

[Offline memory checking](https://georgwiese.github.io/crypto-summaries/Concepts/Protocols/Offline-Memory-Checking) is a method that enables a prover to demonstrate to a verifier that a read/write memory was used correctly. In such a memory system, a value \\(v\\) can be written to an addresses \\(a\\) and subsequently retrieved. This technique allows the verifier to efficiently confirm that the prover adhered to the memory's rules (i.e., that the value returned by any read operation is indeed the most recent value that was written to that memory address).

This is in contrast to "online memory checking" techniques like Merkle hashing which ​immediately verify that a memory read was done correctly by insisting that each read includes an authentication path. Merkle hashing is  ​computationally expensive on a per-read basis for ZK provers, and offline memory checking suffices for zkVM design.

Ziren replaces ZKM’s online memory checking with multiset-hashing-based offline memory checking for improved efficiency. Ziren's verifies the consistency of read/write operations by constructing a ​read set \\(RS\\) and a ​write set \\(WS\\) and proving their equivalence. This mechanism leverages ​multiset hashing on an elliptic curve over KoalaBear Prime's 7th extension field to ensure memory integrity efficiently. Below is a detailed breakdown of its key components.

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

## Multiset Hashing

Multiset hashing maps a (multi-)set to a short string, making it computationally infeasible to find two distinct sets with the same hash. The hash is computed incrementally, with ​order-independence as a key property.

**Implementation on Elliptic Curve**

Let \\(G\\) denote the group of points \\((x,y)\\) on the elliptic curve defined by \\(y^2 = x^3 +Ax+B\\), including the point at infinity. We adopt a hash-to-group approach following the framework described in [Constraint-Friendly Map-to-Elliptic-Curve-Group Relations and Their
Applications](https://eprint.iacr.org/2025/1503.pdf). To map a set element to a point on the curve, we first assign it directly to the \\(x\\)-coordinate of a candidate point—without an intermediate hashing step. Since this \\(x\\)-value may not correspond to a valid point on the curve, we apply an 8-bit tweak \\(t\\) to adjust it. The sign of the resulting \\(y\\)-coordinate is constrained to prevent ambiguity, either by restricting \\(y\\) to be a quadratic residue or by imposing explicit range checks. Furthermore, the message length is bounded by 110 bits, and the base field of the curve operates over the 7th extension field of the KolearBear Prime to ensure a security level of at least 100 bits.

In Ziren, the following parameters are used.
- KoalaBear Prime field: \\(\mathbb{F}_P\\), with \\(P = 2^{31} - 2^{24} +1\\).
- Septic extension field: Defined under irreducible polynomial \\( u^7 + 2u -8\\).
- Elliptic curve: Defined with \\(A = 3*u , B= -3\\) (provides ≥102-bit security).


## Elliptic Curve Selection over KoalaBear Prime Extension Field

**Objective**

Construct an elliptic curve over the 7th-degree extension field of KoalaBear Prime \\(P = 2^{31} - 2^{24} +1\\), achieving >100-bit security against known attacks while maintaining computational efficiency.

**Code Location**

Implementation available [here](
https://github.com/ProjectZKM/septic-curve-over-koalabear). It is a fork from [Cheetah](https://github.com/toposware/cheetah) that finds secure curve over a sextic extension of Goldilock Prime \\(2^{64} - 2^{32} + 1\\).

**Construction Workflow**

- Step 1: Sparse Irreducible Polynomial Selection
  - Requirements​​:
    - Minimal non-zero coefficients in polynomial
    - Small absolute values of non-zero coefficients
    - Irreducibility over base field
  - Implementation​​ (septic_search.sage):
    - `poly = find_sparse_irreducible_poly(Fpx, extension_degree, use_root=True)`
    - The selected polynomial: \\(x^7 + 2x - 8\\). This sparse form minimizes arithmetic complexity while ensuring irreducibility.

- Step 2: Candidate Curve Filtering
  - ​Curve Form​​: \\(y^2 = x^3 + ax + b\\), with small |a| and |b| to optimize arithmetic operations.
  - ​Parameter Search​ in septic_search.sage​:
    ```
    for i in range(wid, 1000000000, processes):
        coeff_a = 3 * a  # Fixed coefficient scaling
        coeff_b = i - 3
        E = EllipticCurve(extension, [coeff_a, coeff_b])
    ```
  - Final parameters chosen: \\(a = 3u, b = -3\\) (with \\(u\\) as extension field generator).

- Step 3: Security Validation
  - Pollard-Rho Resistance​​

    Verify prime subgroup order > 210 bits:
    ```
    prime_order = list(ecm.factor(n))[-1]
    assert prime_order.nbits() > 210
    ```
  - ​​Embedding Degree Check​​:
    ```
    embedding_degree = calculate_embedding_degree(E)
    assert embedding_degree.nbits() > EMBEDDING_DEGREE_SECURITY
    ```
  - ​Twist Security​​:
    - Pollard-Rho Resistance​​
    - ​Embedding Degree Check​​

- Step 4: Complex Discriminant Verification

  Check discriminant condition for secure parameterization: \\( D=(P^7 + 1 − n)^ 2 - 4P^7 \\), where \\(n\\) is the full order of the original curve. Where \\(\text{D}\\) must satisfies:
  - Large negative integer (absolute value > 100 bits)  
  - ​​Square-free part​​ > 100 bits ​​
  
  ​​Validation command​​:
  `sage verify.sage`

The selected curve achieves ​​>100-bit security​​. This construction follows NIST-recommended practices while optimizing for zkSNARK arithmetic circuits through ​​sparse polynomial selection​​ and ​​small curve coefficients​​.
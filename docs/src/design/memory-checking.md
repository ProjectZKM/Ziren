# Memory Consistency Checking

[Offline memory checking](https://georgwiese.github.io/crypto-summaries/Concepts/Protocols/Offline-Memory-Checking) is a method that enables a prover to demonstrate to a verifier that a read/write memory was used correctly. In such a memory system, a value \\(v\\) can be written to an addresses \\(a\\) and subsequently retrieved. This technique allows the verifier to efficiently confirm that the prover adhered to the memory's rules (i.e., that the value returned by any read operation is indeed the most recent value that was written to that memory address).

This is in contrast to "online memory checking" techniques like Merkle hashing which ​immediately verify that a memory read was done correctly by insisting that each read includes an authentication path. Merkle hashing is  ​computationally expensive on a per-read basis for ZK provers, and offline memory checking suffices for zkVM design.

ZKM2 replaces ZKM’s online memory checking with multiset-hashing-based offline memory checking for improved efficiency. ZKM2's verifies the consistency of read/write operations by constructing a ​read set \\(RS\\) and a ​write set \\(WS\\) and proving their equivalence. This mechanism leverages ​multiset hashing on an elliptic curve over KoalaBear Prime's 7th extension field to ensure memory integrity efficiently. Below is a detailed breakdown of its key components.

## Construction of read set \\(RS\\) and write set \\(WS\\) 

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


## Core observation

The prover adheres to the memory rules ​if the following conditions hold:

1) The read and write sets are correctly initialized; 
2) For each address \\(a_i\\), the instruction count added to \\(WS\\) strictly increases over time;
3) ​For read operations: Tuples added to \\(RS\\) and \\(WS\\) must have the same value.
4) ​For write operations: The operation counter of the tuple in \\(RS\\) must be less than that in \\(WS\\).
5) After post-processing, \\(RS = WS\\).

Brief Proof: Consider the first erroneous read memory operation. Assume that a read operation was expected to return the tuple \\((a,v,c)\\), but it actually returned an incorrect tuple \\((a, v' \neq v, c')\\) and added it to read set \\(RS\\). Note that all tuples in \\(WS\\) are distinct. After adding \\((a,v',c_{now})\\) to \\(WS\\), the tuples \\((a,v,c)\\) and \\((a,v',c_{now})\\) are not in the read set \\(RS\\). According to restriction 3, after each read-write operation, there are always at least two tuples in \\(WS\\) that are not in \\(RS\\), making it impossible to adjust to \\(RS = WS\\) through post-processing.

## Multiset hashing method

Multiset hashing maps a (multi-)set to a short string, making it computationally infeasible to find two distinct sets with the same hash. The hash is computed incrementally, with ​order-independence as a key property.

**Implementation on an Elliptic Curve**

Consider the group \\(G\\) as the set of points \\((x,y)\\) on the elliptic curve \\(y^2 = x^3 +Ax+B\\) (including the point at infinity). We can implement a hash-to-group approach. To hash a set element into a point on the elliptic curve, we first map the set element to the \\(x\\)-coordinate of the point. Since this may not be a valid \\(x\\)-coordinate on the elliptic curve, we add an 8-bit tweak \\(t\\). Additionally, we constrain the sign of the \\(y\\)-coordinate to prevent flipping, either by ensuring \\(y\\) is a quadratic residue or by adding range checks.



In ZKM2, the following parameters are used.
- KoalaBear Prime field: \\(\mathbb{F}_P\\), with \\(P = 2^31 - 2^24 +1\\).
- Septic extension field: Defined under irreducible polynomial \\( u^7 + 2u -8\\).
- Elliptic curve: Defined with \\(A = 3*u , B= -3\\) (provides ≥102-bit security).
- Hash algorithm: Poseidon2 is used as the hash algorithm.

**Example: Columns and Constraints Construction**

Columns:

- \\(a\\): address of the operation;
- \\(v_r, v_w\\): values added to the read/write sets;
- \\(c_r, c_w\\): op counters added to the read/write sets;
- \\(f_r, f_w\\): mapping of a set element to a single value, ensuring the mapping is injective (e.g., if \\(a, v, c\\) are all within 32 bits, we can use \\(f = a << 72 + v << 40 + c << 8\\));
- \\(t_r, t_w\\):  8-bit tweak;
- \\(x_r, x_w\\): \\(x\\)-coordinate, satisfying \\(x = f + t\\);
- \\(y_r, y_w\\): \\(y\\)-coordinate;
- \\(z_r, z_w\\): satisfying \\(y = z^2\\), ensuring \\(y\\) is a quadratic residue;
- \\(h_r, h_w\\): current hash value of the read/write sets.

 Constraints:

1) Range checks for  \\(a, v, c, t\\);
2) Monotonic counters: \\(c_{now} = c_w > c_r\\);
3) Curve validation: \\(x= a << 72 + v << 40 + c << 8 + t, y^2 = x^3 + A x + B, y = z^2\\);
4) Hash accumulation: \\(h = h_{old} + (x,y)\\);
5) Final equivalence: \\(h_r = h_w\\).

Note: The actual ZKM2 implementation involves ​more columns and complex constraints compared to this simplified example.

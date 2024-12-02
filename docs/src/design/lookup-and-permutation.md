# Lookup and Permutation Argument

The Lookup arguments allow to prove that the elements of a committed vector come from a
(bigger) committed table, which is used to implement the communication buses in zkVM. Broadly speaking, these protocols enable one to prove a statement of the form:

- Given a table \\( T={t_i},i=0,…,N−1 \\) of distinct values (referred to as ‘rows’),
- and a list of lookups \\( F={f_j}, j=0,…,m−1 \\) (which may occur multiple times),
- all the lookups are contained in the table, i.e., \\( F \subseteq T \\).


In this framework, the table T is generally considered public, while the list of lookups F is treated as a private witness. One can conceptualize the table as holding all permissible values for a given variable, and the lookups as specific instances of this variable generated during the execution of a particular program. The statement being proven confirms that the variable remained within legal bounds throughout that program’s execution.

For the purposes of this discussion, it’s assumed that m<N, and in most cases m≪N, unless stated otherwise. We aim to review the evolution and variety of available lookup protocols and explore the diverse applications of proving such statements.

## Multiset Check

\\[ \prod_i (X - f_i) = \prod_j (X - t_j) \\]

where \\( X \\) is over \\( \mathbb{F} \\). We can select \\( \alpha \overset{{\scriptscriptstyle\$}}{\leftarrow} \mathbb{F} \\), and reduce the above polynomial identity check to a grand product.

Furthermore, if  \\( F \subseteq T \\), such that, iff \\( \exists (m_j) \\), such that


\\[ \prod_i (X - f_i) = \prod_j (X - t_j)^{m_j} \\]


Specially, if \\( m_j \\) are all ones, we have a Multiset equality problem.  It seems the problem has been solved, but the computing complexity is related to the size of set \\( T \\), which maybe very large.

## Plookup

Plookup is one of the earliest lookup protocols. The prover’s computational complexity is O(NlogN) field operations, and the protocol can be generalized to handle multiple tables and vector lookups. It sorts the elements of vector f and table t by ascending, and defines

\\[ \{(s_k, s_{k+1})\} = \{(t_j, t_{j+1}) \} \cup \{(f_i, f_{i+1}) \}  \\]

as multisets, and we take a check of:

\\[ \prod_k (X + s_k + Y \cdot s_{k+1}) = \prod_i (X + f_i + Y \cdot f_{i+1}) \prod_j (X + t_j +   Y \cdot t_{j+1} ) \\]

over \\( \mathbb{F} \\).

And we can reduce it by grand product again.

## LogUp

Logup efficiently proves that a set of witness values exists in a Boolean hypercube lookup table. Using logarithmic derivatives, it converts set inclusion into a rational function equality check, requiring the prover to provide only a multiplicity function. LogUp is more efficient than multivariate Plookup variants, requiring 3–4 times fewer Oracle commitments. It also compares favorably to Plookup’s bounded multiplicity optimization for large batch sizes. The method is versatile, extending to vector-valued lookups, and adaptable for range proofs. It’s particularly relevant for SNARKs like PLONK and Aurora, and applications such as tinyRAM and zkEVM.


Using the LogUp construction instead of a simple multiset check with running products reduces the computational effort for the prover and the verifier. .

\\[ \sum_{i=0}^l \frac{1}{\alpha - f_i} = \sum_{i=0}^n \frac{m_i}{\alpha - t_i} \\]

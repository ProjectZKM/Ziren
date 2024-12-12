# Stark

## Field

* BabyBear
* Mersenne31


## Hash

1. CryptographicHasher: PaddingFreeSponge, a padding-free, overwrite-mode sponge function.
2. CompressionFunction: An `N`-to-1 compression function collision-resistant in a hash tree setting

### Multiple Layers

* External Initial Layer
* Internal Layer
* External Terminal Layer

### Permutation

Multiply a 4-element vector x by a 4x4 matrix.

* Mat4
* HL Mat4

### Hasher

Poseidon2BabyBear


## MMC: Mixed Matric Commitment Scheme

A "Mixed Matrix Commitment Scheme" (MMCS) is a generalization of a vector commitment scheme.
It supports committing to matrices and then opening rows. It is also batch-oriented; one can commit to a batch of matrices at once even if their widths and heights differ.

When a particular row index is opened, it is interpreted directly as a row index for matrices
with the largest height. For matrices with smaller heights, some bits of the row index are
removed (from the least-significant side) to get the effective row index. These semantics are
useful in the FRI protocol.

A MerkleTreeMmmcs is used in our zkVM, which uses BabyBear as a leaf value and a packed value as the node value.

## Challenger

A transcript that digests public input and common parameters, and generates randoms for challenging in PCS.

## DFT

* Radix2DitParallel: a parallel FFT algorithm which divides a butterfly network's layers into two halves.
* RecursiveDft: a decimation-in-frequency in the forward direction, decimation-in-time in the backward (inverse) direction.

## PCS

A (not necessarily hiding) polynomial commitment scheme, for committing to (batches of) polynomials.

* TwoAdicFriPcs:
* CirclePcs

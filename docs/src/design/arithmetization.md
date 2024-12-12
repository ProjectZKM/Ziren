# Arithmetization

Arithmetization is a technique adapted to interactive proof systems. It consists in the reduction of
computational problems to algebraic problems, involving "low-degree" polynomials over a finite field - i.e. the
degree is significantly smaller than the field size. The arithmetization process employed in STARKs is comprised
by different stages of algebraic transformations.

[Details](https://eprint.iacr.org/2023/661.pdf)

## AIR

Algebraic Intermediate Representation

An AIR \\( \mathrm{P} \\) over a field \\( \mathrm{F} \\) has a length n and width w.

\\( \mathrm{P} \\) is defined by a set of constraint polynomials \\( \{ f_i \} \\) of a certain predefined degree d in 2w variables.

An execution trace \\( \mathrm{T} \\) for \\( \mathrm{P} \\) consists of n vectors of length w of elements of 𝐹, that we think of as "rows of width w". 𝑇 is valid, if substituting the 2𝑤 values from any two consecutive rows to any constraint polynomial \\( f_i \\) evaluates to zero.

[Details](https://hackmd.io/@aztec-network/plonk-arithmetiization-air)

### PAIR: Preprocessed AIR

In a Preprocessed AIR, or PAIR 𝑇, we have an additional parameter 𝑡, and 𝑡 preprocessed/predefined columns, \\( c_1, c_2, ..., c_t \in \mathrm{F}^n \\).
An execution trace now consists of the \\( c_i \\) in addition to the 𝑤 columns supplied by the prover.

We usually call those predefined columns as contant state variables. and an AIR is a PAIR with 0 constant variable.

## Circuit Builder

zkMIPS leverages PAIR to build its arithmetization system.

### Basic Air Builder

```rust
/// An AIR (algebraic intermediate representation).
pub trait BaseAir<F>: Sync {
    /// The number of columns (a.k.a. registers) in this AIR.
    fn width(&self) -> usize;

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        None
    }
}

```
#### Syntax

* Expr: a communicative algebra on a finite field

* Var: a communicative algebra on Expr.

* Matrix: A matrix that each cell is variable.

#### Template Builders

* AirBuilderWithPublicValues: a builder who defines the public inputs
* PairBuilder: a builder who defines the pre-defined state variables
* PermutationAirBuilder: a builder whose constraints are enfoced by a permutation check.

### Sub Builder

* FilteredAirBuilder: a sub builder whose constraints are enforced by a condition.
* SubBuilder

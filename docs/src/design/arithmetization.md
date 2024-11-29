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

## PAIR

Preprocessed AIR


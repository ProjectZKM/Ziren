# Program

In Ziren, a prover runs a public program on private inputs and wants to convince a verifier that the program executed correctly and produced the asserted output, without revealing anything about the inputs or the intermediate state of the computation.

![program](/dev/program.jpg)

All inputs are private; the program and its committed output are public.

From a developer's perspective a Ziren application has two parts: the program to be proved and the program that proves it.
The former is called the [`guest`](/dev/guest-program.md), and the latter the [`host`](/dev/host-program.md).

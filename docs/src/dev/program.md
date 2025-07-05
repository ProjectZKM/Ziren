# Program

The setting of Ziren is that Prover runs a public program on private inputs
and wants to convince Verifier that the program has executed correctly and produces an
asserted output, without revealing anything about the computation’s input or intermediate
state.

![program](/dev/program.jpg)

We consider all the inputs as private, the program and output should be public.

The program can be separated into 2 parts from a developer's perspective, the program to be proved and the program to prove. 
The former program we call it [`guest`](/dev/guest-program.md), and the latter is [`host`](/dev/host-program.md).





# Benchmarks and Performance

To measure the performance of a zkVM's performance, `Efficiency` and `Cost` are two important metrics. 

**Efficiency** 

The `Efficiency`, or cycles per instruction, means how many cycles the the zkVM can prove in one second. One cycle is usually mapped to `one` MIPS instruction in zkVM. 

For each MIPS instruction, it goes through two main phases, executing phase and proving phase, to generate the proof. In the executing phase, we need to run the MIPS VM(Emulator) to generate the execution trace, which is handled by single process. 


**Cost**





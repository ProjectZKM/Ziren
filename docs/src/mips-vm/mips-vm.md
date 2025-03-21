# MIPS Virtual Machine

ZKM2 implements ​a STARK-optimized MIPS Virtual Machine (VM) that combines ​full MIPS-I ISA compliance with ​zk-proof-specific constraints. This architecture bridges ​mature processor design and ​modern cryptographic verification, delivering ​faster proof generation than widely adopted RISC-V-based alternatives.

Leveraging three decades of MIPS microarchitecture refinement, ZKM2 selects MIPS32r2 for ​three strategic advantages over RISC-V alternatives:

- Extended control flow. 
The ​256MiB direct jump range (J/JAL) enables ​single-instruction leaps between distant code segments - critical for STARK circuit partitioning and recursive proof composition.
- Hardware-grade bit manipulation.
15 dedicated bitwise instructions (CLO/WSBH/EXT/INS) reduce bitmask operation constraints through native rotate/shift hardware mapping.
- Arithmetic acceleration. The ​MADDU instruction enables ​single-cycle 64-bit multiplication instruction, which results shorter trace rows than RISC-V's sequential instructions MUL+HADD.


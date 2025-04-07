<p align="center">
    <img alt="zkmreadme" width="1412" src="https://i.ibb.co/xDTXTgH/zkmreadme.gif">
</p>
<p align="center">
    <a href="https://discord.gg/zkm"><img src="https://img.shields.io/discord/700454073459015690?logo=discord"/></a>
    <a href="https://twitter.com/ProjectZKM"><img src="https://img.shields.io/twitter/follow/ProjectZKM?style=social"/></a>
    <a href="https://GitHub.com/zkMIPS"><img src="https://img.shields.io/badge/contributors-22-ee8449"/></a>
</p>

# zkMIPS

zkMIPS is the next generation of zkMIPS for real-time proving, and zkMIPS is an open-source, simple, stable, and universal zero-knowledge virtual machine on MIPS32R2 instruction set architecture(ISA).


zkMIPS is the industry's first zero-knowledge proof virtual machine supporting the MIPS instruction set, developed by the ZKM team, enabling zero-knowledge proof generation for general-purpose computation. zkMIPS is fully open-source and comes equipped with a comprehensive developer toolkit and an efficient proof network. The Entangled Rollup protocol, built on zkMIPS, is a native asset cross-chain circulation protocol, with typical application cases including Metis Hybrid Rollup and GOAT Network.


## Why MIPS?

* MIPS is stable and comprehensive and has an established ecosystem and a great compatibility, like Optimizm Fraud proof VM
* MIPS32r2 vs RISCV32IM
> * J/JAL series instructions have a jump range of up to 256MiB
> * Rich bit manipulation instructions
> * More conditional selection instructions, MOVZ, MOVN etc.

## Acknowledgements
The zkMIPS draws inspiration from the following projects, which represents the cutting-edge zero-knowledge proof systems. 
- [Plonky3](https://github.com/Plonky3/Plonky3): zkMIPS proving backend is based on Plonky3.
- [SP1](https://github.com/succinctlabs/sp1): zkMIPS recursion compiler, circuit builder, precompiles originate from SP1.
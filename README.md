<p align="center">
    <img alt="zkmreadme" width="1412" src="https://i.ibb.co/xDTXTgH/zkmreadme.gif">
</p>
<p align="center">
    <a href="https://discord.gg/zkm"><img src="https://img.shields.io/discord/700454073459015690?logo=discord"/></a>
    <a href="https://twitter.com/ProjectZKM"><img src="https://img.shields.io/twitter/follow/ProjectZKM?style=social"/></a>
    <a href="https://GitHub.com/zkMIPS"><img src="https://img.shields.io/badge/contributors-22-ee8449"/></a>
</p>

# zkMIPS<sup>+</sup> 

zkMIPS<sup>+</sup>  is the next generation of zkMIPS for real-time proving, and zkMIPS is an open-source, simple, stable, and universal zero-knowledge virtual machine on MIPS32R2 instruction set architecture(ISA). 

ZKM is a general verifiable computing infrastructure on zkMIPS, empowering Ethereum as the Global Settlement Layer.

## Why MIPS?

* MIPS is stable and comprehensive and has an established ecosystem and a great compatibility, like Optimizm Fraud proof VM
* MIPS32r2 vs RISCV32IM
> * J/JAL series instructions have a jump range of up to 256MiB
> * Rich bit manipulation instructions
> * More conditional selection instructions, MOVZ, MOVN etc.

## Acknowledgements
The zkMIPS<sup>+</sup> draws inspiration from the following projects, which represents the cutting-edge zero-knowledge proof systems. 
- [Plonky3](https://github.com/Plonky3/Plonky3): zkMIPS<sup>+</sup>'s proving backend is based on Plonky3.
- [SP1](https://github.com/succinctlabs/sp1): zkMIPS<sup>+</sup>'s recursion compiler, circuit builder, precompiles originate from SP1.
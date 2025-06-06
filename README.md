<p align="center">
    <img alt="zkmreadme" width="1412" src="https://i.ibb.co/xDTXTgH/zkmreadme.gif">
</p>
<p align="center">
    <a href="https://discord.gg/zkm"><img src="https://img.shields.io/discord/700454073459015690?logo=discord"/></a>
    <a href="https://x.com/ProjectZKM"><img src="https://img.shields.io/twitter/follow/ProjectZKM?style=social"/></a>
    <a href="https://GitHub.com/zkMIPS"><img src="https://img.shields.io/badge/contributors-22-ee8449"/></a>
</p>

# zkMIPS

zkMIPS is an open-source, simple, stable, and universal zero-knowledge virtual machine on MIPS32r2 instruction set architecture(ISA).


zkMIPS is the industry's first zero-knowledge proof virtual machine supporting the MIPS instruction set, developed by the ZKM team, enabling zero-knowledge proof generation for general-purpose computation. zkMIPS is fully open-source, equipped with a comprehensive developer toolkit and an efficient proof network. The Entangled Rollup protocol, designed specifically to utilize zkMIPS, is a native asset cross-chain circulation protocol, with example application cases including the Metis Hybrid Rollup design and the GOAT Network Bitcoin L2.


## Why MIPS vs other ISA's?

**MIPS32r2 is more consistent and offers more complex opcodes**

* The J/JAL instructions support jump ranges of up to 256MiB, offering greater flexibility for large-scale data processing and complex control flow scenarios.
* MIPS32r2 has rich set of bit manipulation instructions and additional conditional move instructions (such as MOVZ and MOVN) that ensure precise data handling.
* MIPS32r2 has integer multiply-add/sub instructions, which can improve arithmetic computation efficiency.
* MIPS32r2 has SEH and SEB sign extension instructions, which make it very convenient to perform sign extension operations on char and short type data.

**MIPS32r2 has a more established ecosystem**

* All instructions in MIPS32r2, as a whole, are very mature and widely used for more than 20 years. There will be no compatibility issues between ISA modules, and there will be no turmoil caused by manufacturer disputes.
* MIPS has been successfully applied to Optimism's Fraud Proof VM.

## Acknowledgements
zkMIPS draws inspiration from the following projects, which represents the cutting-edge zero-knowledge proof systems. 
- [Plonky3](https://github.com/Plonky3/Plonky3): zkMIPS proving backend is based on Plonky3.
- [SP1](https://github.com/succinctlabs/sp1): zkMIPS circuit builder, recursion compiler, and precompiles originate from SP1.

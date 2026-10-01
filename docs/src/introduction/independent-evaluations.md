# Independent Evaluations

* Ziren (v1.1.4) underwent an independent evaluation by [Prooflab](https://prooflab.dev/). 

Recommended use cases for Ziren as noted in the report are Bitcoin L2 implementations, hybrid (combining ZK and optimistic) rollups, zkML verification and cross-chain applications. View the full evaluation report for Ziren [here](https://github.com/ProofLabDev/prooflab-research-samples/blob/main/zkVMs/ziren_evaluation_report.md).


* [SoK: Understanding zkVM: From Research to Practice](https://eprint.iacr.org/2026/525.pdf) (Yang, Cheng, Tang, Yang, Zhang and Ren; Zhejiang University, University of Sussex and Singapore Management University; IACR ePrint 2026/525).

The survey decomposes zkVMs into an ISA layer, a VM layer and a proving layer and evaluates representative systems. It describes Ziren as taking a deliberate architectural bet on MIPS32, prioritizing instruction regularity and constraint uniformity over RISC-V ecosystem convenience (zkVM-level instruction efficiency).


* [Efficient Branch-and-Bound Testing and Verification of zkVMs](https://arxiv.org/abs/2609.15020) (Takahashi, Jana and Yang; Columbia University; arXiv 2609.15020).

The paper presents ZEBRA, a framework that checks zkVM constraint tables against their instruction semantics by interval-based branch-and-bound search, and evaluates it on five Plonky3-based zkVMs: Pico, SP1, Sphinx, Valida and Ziren, the only one targeting MIPS.

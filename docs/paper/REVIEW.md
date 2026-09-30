# Review of “Ziren 2.0”

## 1. Professionalism

The paper has a strong organizing idea: following ISA, AIR, PCS, IOPP, and recursion in order makes a complicated system unusually approachable. The chip-width, WHIR-schedule, proof-anatomy, and kernel/area tables are useful, and the prose is generally controlled. In its current form, however, it reads more like an excellent implementation white paper than a venue-ready systems/cryptography paper.

- **The security claim is not defined.** “A zero-knowledge virtual machine (zkVM) turns the execution of an ordinary program into a succinct proof” (`sections/01_introduction.tex`, ~line 4), but the described Merkle/WHIR protocol has no stated blinding, simulator, leakage statement, or zero-knowledge theorem. The paper must either specify how zero knowledge is obtained and what is hidden, or consistently call Ziren a verifiable VM/STARK prover. It also needs a formal execution relation, completeness statement, and end-to-end (knowledge-)soundness theorem.

- **The stated soundness composition is internally unresolved.** The paper says, “Round-by-round soundness of the compiled argument is bounded by the sum of the errors of the transcript's rounds” (`sections/06_iopp.tex`, ~line 47), but later concludes, “the minimum, 64, is the proof's level” (`sections/06_iopp.tex`, ~line 51). Taking the minimum of per-component bit values is not the same as taking the negative logarithm of their summed errors; with several terms near \(2^{-64}\), the total is below 64 bits unless the reported component numbers already include a union bound. Similarly, “64 bits provable in the unique-decoding regime, 96 bits on the outer wrap ring” (`main.tex`, ~line 94) needs to say explicitly that wrapping cannot raise the end-to-end level above that of the inner proof. Publish the exact calculator input and full error sum, not only rounded component minima.

- **Two performance rows conflict with their own caption and arithmetic.** The census caption identifies “86 shards” under the “deployed schedule before the changes” (`sections/08_performance.tex`, ~line 10), while the deployed row is `Deployed: UDR-64 schedule, no lookup grinding & 130 & 74.1` (~line 41), apparently for the same block and schedule. Further, the last two rows are `... & 130 & 70.4 & neutral` and `... & 114 & 67.1 & $-5.7\%$` (~lines 44–45): \(70.4\to67.1\) is a 4.7% reduction, not 5.7%. The prose then says, “16 fewer shards save 4\,s” (~line 50), whereas the displayed medians differ by 3.3 s. These numbers must be reconciled or explicitly assigned to different runs/configurations.

- **Rate terminology changes meaning.** WHIR “halves the evaluation domain each round so that the rate improves” (`sections/01_introduction.tex`, ~line 16); the protocol section says “the rate drops from \(\rho\) to \(2^{1-k}\rho\)” (`sections/06_iopp.tex`, ~line 8); and the schedule says “The rate escalates by three bits per committed round” (~line 40). The table shows that \(\rho\) decreases from \(1/4\) to \(1/32\) to \(1/256\), while 
\(\log_2(1/\rho)\) increases. Use “redundancy increases” or name the inverse-rate quantity every time.

- **The cross-shard digest is security-critical but absent from the accounting.** “Ziren 2.0 follows the elliptic-curve digest construction of SP1: an interaction tuple ... is mapped to a point on a curve over ... \(\mathbb F_{p^7}\)” (`sections/04_air.tex`, ~line 64), and the next paragraph gives a prover-chosen lift offset and sign bands (~line 66). There is no theorem establishing encoding injectivity/collision resistance, treatment of exceptional curve-addition cases, group-order/security assumptions, or a corresponding term in the component list at `sections/06_iopp.tex`, ~line 51. This needs a precise construction and reduction, not an implementation sketch.

- **The trust boundary is ambiguous.** “The check is optional in the deployed service, whose verifier trusts the key digests it receives” (`sections/07_recursion.tex`, ~line 12). A verifier that accepts attacker-selected key digests does not establish execution of the advertised machine. State who authenticates which root key, make allowlisting mandatory in the claimed protocol (or model an external authenticated configuration), and include this binding in the theorem.

- **The evaluation is too narrow for the comparative language.** “All numbers in this section are for one NVIDIA RTX 5090 ... [on] block 25,907,955” (`sections/08_performance.tex`, ~line 4). Yet the paper claims a “Position among single-GPU provers” and mixes 5090 and 4090 public medians before giving paired ratios (`sections/08_performance.tex`, ~lines 52–54). Report commit IDs, CPU/RAM/driver/power settings, run count and raw variance, proof level/size for every system, and a workload suite or block distribution. Separate same-hardware, same-input comparisons from dashboard context. “bit-exact ... by a differential test in continuous integration, so the JIT is a pure speed-up” (`sections/03_isa.tex`, ~line 47) should likewise be softened: differential testing is evidence, not a proof of equivalence.

- **Presentation and sourcing need one more pass.** Figure 1's caption—“The proving pipeline ... leaves verify shard proofs and a range tree of composes merges them” (`sections/01_introduction.tex`, ~line 23)—is a useful overview, but the paper needs diagrams for the memory chains, dense/jagged coordinates, and recursion/public-value bindings. Units alternate among “618 KB” (`main.tex`, ~line 94), “228 KiB” and “617,618 bytes” (`sections/06_iopp.tex`, ~line 53); standardize them. The bibliography substitutes project pages for technical sources—`RISC0: A general-purpose zero-knowledge virtual machine` (`main.bbl`, ~lines 92–95) and `SP1: A performant, open-source, contributor-friendly zkVM` (~lines 102–106)—and even misspells Haböck as “Habök” (~lines 58–60). Replace promotional phrases such as “production MIPS zkVM” (`sections/01_introduction.tex`, ~line 30) with auditable scope/version claims.

## 2. Contribution

**(a) Genuinely novel techniques.** As written, no new cryptographic primitive is established. The best candidate systems technique is the MIPS instruction-frame design plus clock-zero register shadow reads, but novelty requires comparison with the no-central-CPU/chip designs in *OpenVM Whitepaper*, Valida, and SP1 Hypercube, and with SP1's memory argument. The septic cross-shard digest is explicitly inherited from SP1, so only the narrower three-byte range-check/lift implementation might be new; it needs both a comparison and a security proof before being claimed as a contribution.

**(b) Novel combinations and engineering.** The clearest contribution is the claimed first published composition of *Jagged Polynomial Commitments (or: How to Stack Multilinears)* with *WHIR: Reed–Solomon Proximity Testing with Super-Fast Verification*, including a concrete KoalaBear schedule and recursive verifier. Its closest baseline is SP1 Hypercube's Jagged PCS, followed by BaseFold and WHIR separately; the paper should state exactly what changed relative to SP1 code/protocol and measure Jagged-over-WHIR against Jagged-over-BaseFold. A second contribution is a complete MIPS32r2 adaptation of the SP1-style chip/LogUp-GKR/zerocheck/recursion stack, with a JIT and MIPS-specific unaligned-access chips; its closest comparisons are zkMIPS and Cannon/Kona for semantics/toolchain compatibility, and SP1/OpenVM for arithmetization. The census-driven column, lookup, and shard-size optimizations are credible engineering contributions, but need reproducible ablations across more inputs.

**(c) Standard or adopted material.** Multilinear extensions, sumcheck/zerocheck, AIR chips and buses, offline multiset memory checking, LogUp-GKR, Jagged PCS, WHIR, BaseFold-style outer commitments, recursive aggregation, Fiat–Shamir/Merkle compilation, and Groth16 wrapping are prior techniques. They should be labeled as adopted components, with Ziren's modifications isolated in a “baseline / change / consequence” table. The paper already acknowledges substantial modeling on SP1; its novelty claim should therefore be “a MIPS instantiation and evaluated integration,” not a new zkVM proof paradigm.

## 3. Related work

Section 9 names several systems but rarely compares design axes. A reviewer would expect the following expansion (including deeper treatment of works already cited):

**zkVMs.**

- **SP1 and SP1 Hypercube** — compare inherited chip/frame, LogUp-GKR, Jagged PCS, recursion, JIT, and global-memory mechanisms component by component.
- **RISC Zero, *RISC Zero zkVM: Scalable, Transparent Arguments of RISC-V Integrity*** — contrast the RISC-V control table, DEEP-ALI/FRI stack, continuations, and security targets.
- **Jolt, *Jolt: SNARKs for Virtual Machines via Lookups*** — distinguish opcode-table “lookup singularity” and sumcheck/PCS costs from Ziren's opcode chips and interaction lookups.
- **ZisK** (the ZisK architecture/documentation) — compare its custom micro-ISA/transpilation, PIL2/proof stack, segmentation, and single-GPU block-proving methodology.
- **Airbender** (the `zksync-airbender` design documentation) — compare M31, degree-two AIR, DEEP-FRI, recursion, and the security/performance tradeoff rather than only dashboard time.
- **Ceno, *Ceno: Non-uniform, Segment and Parallel Zero-Knowledge Virtual Machine*** — contrast non-uniform basic-block circuits, GKR, memory checking, and segment parallelism with chip tables and shards.
- **OpenVM, *OpenVM Whitepaper*** — compare its “no-CPU” modular instruction-executor chips directly with Ziren's instruction-frame claim.
- **Cairo, *Cairo: A Turing-complete STARK-friendly CPU Architecture*** — separate Cairo's proof-oriented ISA/builtins and permutation memory from compatibility-first MIPS plus precompiles.
- **Nexus, *Nexus 1.0: Enabling Verifiable Computation*** — contrast folding/IVC and distributed proof accumulation with STARK shards and a range-merge recursion tree.
- **Valida/Lita, *Valida ISA Spec, version 1.0: A zk-Optimized Instruction Set Architecture*** — compare its modular chip ancestry and ZK-optimized ISA against Ziren's inherited hardware ISA.

**Small-field STARKs and frameworks.**

- **Plonky3** — identify the exact revision and which field, Poseidon2, AIR, PCS, and GPU components are reused versus replaced; cite the toolkit and its security audit.
- **Circle STARKs** — contrast M31 circle domains and circle FRI with KoalaBear's two-adic domains and explain the arithmetic/domain tradeoff.
- **M31/Airbender and BabyBear/Goldilocks systems** — provide a short field-selection comparison covering SIMD arithmetic, extension size, two-adicity, hash choice, and soundness ceiling.

**Lookup arguments.**

- **Haböck, *Multivariate Lookups Based on Logarithmic Derivatives* (LogUp)** — identify the base rational-sum identity and Ziren's bus/fingerprint instantiation.
- **Papini–Haböck, *Improving Logarithmic Derivative Lookups Using GKR*** — specify what is standard LogUp-GKR and what Ziren changes in batching/layer layout.
- **Setty–Thaler–Wahby, *Unlocking the Lookup Singularity with Lasso*** — compare structured/indexed tables, committed multiplicities, and prover work for Ziren's byte/program tables.
- **Eagen–Fiore–Gabizon, *cq: Cached Quotients for Fast Lookups*** — explain why preprocessing-friendly univariate cq loses to LogUp-GKR for this multilinear, many-bus workload.

**Multilinear PCS and IOPPs.**

- **BaseFold, *Efficient Field-Agnostic Polynomial Commitment Schemes from Foldable Codes*** — give a measured, parameter-matched baseline rather than only the historical 94-query description.
- **WHIR** and **STIR, *Reed–Solomon Proximity Testing with Fewer Queries*** — separate their published protocol contributions from Ziren's re-encoding schedule and interleaved layout.
- **Binius, *Succinct Arguments over Towers of Binary Fields*, and FRI-Binius, *Polylogarithmic Proofs for Multilinears over Binary Towers*** — compare binary-tower packing and small-field commitment cost with 31-bit KoalaBear.
- **Brakedown, *Linear-Time and Field-Agnostic SNARKs for R1CS*, and Ligero, *Lightweight Sublinear Arguments Without a Trusted Setup*** — position linear-code/interleaved commitments on prover time, verifier time, and proof size.
- **Hemo et al., *Jagged Polynomial Commitments (or: How to Stack Multilinears)*, and SP1 Hypercube** — state that jagged/sparse commitment is prior work and isolate Ziren's WHIR integration and layout choices.

**GKR/sumcheck-heavy zkVMs.** Jolt should be compared on instruction evaluation via Lasso and commitment costs, while Ceno should be compared on GKR-based non-uniform segments and memory/control-flow reconstruction; both are closer architectural alternatives than the current prose suggests.

**MIPS execution systems.** **Optimism Cannon** should be compared for MIPS semantics, delay slots, memory/preimage ABI, and compatibility while noting that it is an interactive fault proof; **Kona** should be discussed as the Rust fault-proof-program/toolchain ecosystem and a compatibility workload, not mislabeled as a zkVM; **zkMIPS, *An Advanced Zero-Knowledge Proof Solution for MIPS Architecture*** is the direct prior validity-proof system and requires a feature, proof-stack, security, and performance comparison.

**Soundness analysis and tooling.** Compare the checked-in configuration/results with the Ethereum Foundation's **soundcalc**, RISC Zero's executable STARK soundness calculator, *ethSTARK Documentation—Version 1.2*, *DEEP-FRI: Sampling Outside the Box Improves Soundness*, and *Proximity Gaps for Reed–Solomon Codes*; explicitly identify which bounds are proven, conjectured, classical-ROM, and system-composed.

## 4. Ten prioritized concrete edits

1. Define the exact MIPS execution relation and public statement; add completeness, knowledge-soundness, and zero-knowledge claims/proofs, or remove “zero-knowledge” if the construction is non-hiding.
2. Recompute and reconcile every schedule/performance number, especially 86 versus 130 shards, 70.4-to-67.1 versus 5.7%, and 3.3 versus 4 seconds; label every table with one immutable configuration.
3. Check in and cite the exact soundcalc input/output; show the transcript-wide union bound, Fiat–Shamir/ROM model, grinding model, and end-to-end minimum across inner, recursion, outer, and Groth16 layers.
4. Formalize the septic digest: encoding and lift, injectivity/collision assumption, group order, exceptional additions, accumulated-public-value binding, and its concrete soundness term.
5. Make verifying-key binding part of the protocol statement and mandatory verifier path, or explicitly model the authenticated external service configuration.
6. Rewrite Contributions and Related Work around a comparison matrix separating new techniques, new integrations, inherited SP1 components, and standard proof-system machinery.
7. Provide a reproducibility appendix/artifact with repository commit, parameters, build commands, GPU/CPU/RAM/software/power details, raw ABBA samples, and exact proof files.
8. Evaluate multiple blocks and microbenchmarks; add same-input/same-hardware baselines and parameter-matched Jagged-WHIR versus Jagged-BaseFold/previous-Ziren ablations.
9. Add diagrams/pseudocode for instruction-frame chaining, local/global memory, dense-to-jagged coordinates, WHIR transcript order, and recursion/public-value verification.
10. Perform a terminology/bibliography copyedit: standardize rate versus inverse rate and KB versus KiB, replace project homepages with technical sources, fix names, version all “production/deployed” claims, and remove promotional wording.

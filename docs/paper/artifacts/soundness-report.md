# Reproduced interactive soundness

Ziren `cf0b3742`; soundcalc `d683f29183d8e831fb0bd8fdb8c39ce8598e43ab`.
Transcript profile `71a49cf2564480354be2cd1b7e0c0bb379720c7c1a07cc6912f676ec54967f69`.

Component errors are floored to integer bits by soundcalc, then summed.
The final-query term (`fin`) is included once. No wrap or Fiat–Shamir bound is claimed here.

| Component group | Core | Compress root |
| --- | ---: | ---: |
| Query phases | 104.42 | 104.91 |
| Folding rounds | 100.93 | 101.69 |
| LogUp-GKR | 106.00 | 116.00 |
| Batching | 107.00 | 103.00 |
| Zerocheck | 109.00 | 114.00 |
| Reduction to the dense polynomial | 116.00 | 116.00 |
| Out-of-domain samples | 213.00 | 200.00 |
| **Union over the stage** | **100.74** | **101.10** |

One core proof plus one root: 99.91 bits.
Example with 149 core-schedule proofs and one root: 93.51 bits.

Individual components and exact input hashes are in `soundness-results.json`.

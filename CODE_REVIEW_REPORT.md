# Ziren Repository Code Review Report

Date: 2026-09-19  
Repository-wide review baseline: `ab35b61fcd4475a16fc4e96e643b0fb8236982ff` (`feat/upgrade-plonky3`)  
Latest status correction: 2026-09-20, current worktree at HEAD `0935382bc99496f8a6e2198ea366649dfee2a1f2`; ZR-03, ZR-10, ZR-16, and ZR-18 were re-checked in implementation and regression-test source rather than inferred from the earlier table  
Review type: repository-wide correctness, security, reliability, API, design, style, and source-level performance review

## Executive summary

The review originally found 27 confirmed security, correctness, reliability, API, and proof-system problems: five Critical, seven High, thirteen Medium, and two Low. Several were repaired while the audit was running, and later protocol follow-ups added separately numbered findings. At the current revision, ZR-03, ZR-10, ZR-16, and ZR-18 are fully closed: the optional `ark` loaders are bounds-checked, mutable CUDA images require explicit opt-in while the default path requires a digest, ELF executable segments are validated and placed by virtual address with bounds-checked fetches, and CUDA RPC transport/codec failures are propagated. The authoritative current protocol disposition, including ZR-23/ZR-24, is recorded in “Current-Revision Implementation, Protocol, Soundness, and Performance Follow-Up” below. Older finding bodies are retained as historical descriptions of the vulnerable revisions and are not current open-status statements.

A current source-only remediation re-check confirms that ZR-03, ZR-10, ZR-16, and ZR-18 are fully fixed for their reported mechanisms. ZR-03 now uses checked optional-`ark` proof/VK parsing with truncation and hostile-count regressions. ZR-10 refuses an unpinned CUDA image unless the user explicitly opts into mutable development images, and still rejects a failed pull. ZR-16 orders executable segments by virtual address, validates overlap/gaps/entry point/image size, and bounds-checks fetch; its adversarial multi-segment tests are present. ZR-18 maps CUDA setup/core/compress/shrink/wrap transport and codec failures to errors and has unavailable/malformed-response regressions. The current ZR-23/ZR-24 disposition and protocol evidence appear in the final follow-up section rather than this historical summary.

The checkout later advanced to `548a0dc4`. The focused stacking-height review at that revision confirms that the fixed value 21 is correct for the current protocol: inner BaseFold and WHIR use a size-`2^23` initial codeword domain, while wrap BaseFold uses `21 + 3 = 24`, exactly KoalaBear's two-adicity. Restoring a trace-area-dependent clamp would again make recursion program/VK shape witness-dependent. The defect is instead at the trust boundary: native verification consumes `bundle.commit.log_stacking_height` from the serialized proof without enforcing the production value, while recursion explicitly requires 21. This is ZR-27 below.

The earlier validation snapshot failed the repository formatting gate; it was not rerun after the later cleanup commits. Commit `392d2d28` replaces the previously vacuous hint-seam regression with tests that execute both `HINT_LEN` and `HINT_READ`, require a shard boundary inside the seam, and inspect the captured input window, closing the reported ZR-12 test gap at source level.

The proposed Proving Cost Estimation standard in `eth-act/zkevm-standards#36` was reviewed against Ziren's implementation and against every public review comment on the pull request. Ziren has useful building blocks, but it does not currently implement the proposed contract. The proposal also leaves quantized-cost attribution under-specified in a way directly exposed by Ziren's per-AIR power-of-two padding.

## Validation performed

- `cargo check --workspace --all-targets`: passed.
- `cargo test -p zkm-core-executor --lib`: passed, 89 tests.
- `cargo test -p zkm-core-executor --test div_executor_edge_cases -- --ignored`: passed because the ignored regression explicitly expects the interpreter's `INT_MIN / -1` panic, confirming ZR-04 is currently codified rather than prevented.
- `cargo test -p zkm-verifier --lib -- --list`: at the earlier validation revision, compiled successfully with only seven happy-path/E2E tests registered. Later commit `b574a610` adds parser- and public-entry malformed/truncation/count tests; this audit reviewed those tests in source but did not rerun the command.
- `cargo fmt --all -- --check`: failed with repository-wide formatting differences, including the current commit.
- OpenSSL public-key comparison confirmed that the tracked test `crates/sdk/tool/ca.key` matches the bundled `ca.pem`.
- A temporary WHIR differential test proved that a verifier configured with one OOD sample accepts a proof produced with zero OOD samples. The temporary test was removed after execution (`1 passed`, `191 filtered out`).
- Manual native/recursive PCS data-flow comparison found that recursive WHIR enforces the configured OOD count, while the reviewed native WHIR verifier does not, and that recursive BaseFold omits the native verifier’s sumcheck, terminal-claim, and per-round query-chain constraints.
- A source-only differential review against the official SP1 v6.3.1 tag (`8252c2905ce32964df68248117015c61ebb854db`) compared native and recursive BaseFold, stacked PCS, jagged geometry binding, proof shape, and transcript order. It confirmed that SP1 binds every untrusted evaluation claim before sampling the BaseFold batching point, whereas the then-reviewed Ziren revision did not; this yielded ZR-26. No tests or proof generation were used for this differential pass.
- A source-only remediation pass at `8714d6ea` re-derived ZR-26 and compared the host prover, native verifier, recursion circuit, witness plumbing, and private `ziren-gpu` branch `fix/zr26-observe-claims` at `e9e27800`. All four implementations now absorb the same round-major extension-field claim sequence before batch grinding and before the batching point; the circuit and GPU adapters decompose extension elements in basis-coefficient order, matching the host challenger. The same witnessed vector drives both the stacked interpolation equality and the recursive BaseFold verification. The Ziren commit reports PCS and E2E gates, but this audit did not rerun them because this follow-up was explicitly source-only.
- A source-only remediation pass at `39ee07c0` reviewed `611382d7` (ZR-15) and the then-current ZR-05 tests. The former places a minimum-length guard before every reported fixed slice/typed `Borrow` in both native verification entry points; exact-length rejection still occurs in `verify_shard`, so the reported short-vector panic is closed. At that revision, the surplus test deliberately pinned a permissive default. Later commit `4da2cb35` removes that default and makes the same branch reject; this audit reviewed the later diff in source but did not rerun either test set.
- Historical snapshot at `0c87d343` (superseded by the later closure commits): ZR-03 still had incomplete bounds checks across the PLONK, pairing-VK, STARK, and optional-`ark` paths at that revision. The current optional-`ark` state was re-checked separately and is recorded as fixed below.
- A source-only review of the separate `wip/zr24-outer-component-openings` commit `75fab083` localized its reported honest-proof failure. Plonky3's `MerkleTreeMmcs` hashes same-height matrix rows by flattening them, and Ziren's in-circuit BN254 leaf sponge matches the host `MultiField32PaddingFreeSponge`; the hash primitive is not the evidenced mismatch. The outer lift instead populates `original_commitments` with the main root followed by zero placeholders, while native verification and `component_openings` use preceding/preprocessed rounds first and the main round last. Activating component verification therefore compares the first preprocessed opening with the main root at `HV::assert_digest_eq`. This also explains why disabling the later query-chain equality leaves the identical digest constraint failure. No tests or proof generation were run for this diagnosis.
- A second source-only pass at `02a651a0` reviewed code structure and source-derived performance costs across PCS/IOPP, recursive circuit construction, prover orchestration, and executor replay. It compared the recursive BaseFold loop structure with the local official SP1 v6.3.1 checkout. No benchmark, test, proof generation, or remote execution was used for this performance pass; all expected wins below require profiling confirmation.
- A source-only remediation pass at `ab35b61f` reviewed `prove_jagged_basefold_rounds_generic` and its native verifier counterpart. The patch correctly replaces mixed WHIR/BaseFold fallback with a fail-fast invariant, requires all BaseFold round prover data to use the same stacking height, requires all WHIR round data to use the same stacking height, and removes a dead local. The pass also confirmed that native verification independently recomputes the branching-program weight in `verify_jagged_reduction` and checks `current_claim == q_at_z * w_at_z`; host-only replay of the separate jagged-evaluation transcript is therefore not an omitted native closing check. This follow-up was manual and source-only: no test, proof generation, benchmark, or remote execution was run.
- A source-only protocol-profile pass at `548a0dc4` reviewed `pick_log_stacking_height`, both BaseFold configurations, the WHIR fold schedule, commit/open call sites, native shard verification, and the recursion fixed-height guard. It confirmed that 21 is the correct fixed production value, that changing only the picker cannot implement a coherent adaptive-height profile, and that native verification fails to bind the proof-carried height to that production profile. No test, proof generation, benchmark, or remote execution was run for this pass.
- A source-only remediation pass reviewed the ZR-22 fix in `385188b2`. The zero-coordinate branch now evaluates the unconstrained `g(1)` endpoint from `current_mle` and leaves the nonzero hot path unchanged. The added chosen-point roundtrips cover zero at every coordinate, all-zero, all-one, and a Boolean mix at folding arities 1 and 2. The algorithmic repair is correct; this audit did not rerun the tests.
- A historical source-only remediation sweep reviewed the scoped diffs for `c38e42cd` (ZR-01/ZR-08), `b574a610` and `548a0dc4` (early ZR-03 and network error handling), `4da2cb35` (ZR-05/ZR-11/ZR-13), `00fc2a13` (ZR-06/ZR-07/ZR-09), `418fd44f` (early ZR-16), `a4831e33` (ZR-17 and early ZR-18), `392d2d28` (ZR-12/ZR-19), and `ca8bb158` (early ZR-10). Later commits `49b76544`, `4e880d96`, `0214fe02`, and `51a653af` supersede those four partial snapshots; the status table below has been updated to the current source-level conclusions.
- The recursive BaseFold short-query path was traced through `lift_empty_placeholder`, the real bundle witness lift, dummy proof construction, and the recursion shape signature. The one-query placeholder is confined to `Empty`/malformed compatibility paths; production dummy programs construct a shape-faithful `Bundle` with the full configured query count, and query/path lengths are included in the program shape key. This was therefore not promoted to a separate exploitable finding. The verifier uses `min(configured, supplied)` and conditional Merkle skips, which remain fail-open and should be replaced with exact shape requirements as part of ZR-20/ZR-24.
- `cargo test -p zkm-recursion-circuit jagged_pcs_lift::tests --lib`: passed, 3 tests. These are placeholder-shape smoke tests; they do not execute the production BaseFold soundness constraints.
- `cargo test -p zkm-recursion-circuit dummy::basefold_shard_proof::tests --lib`: passed, 4 tests, confirming dummy packing/sumcheck shape construction.
- `cargo test -p zkm-recursion-circuit basefold_verifier::tests --lib`: 10 tests passed; four positive recursion-runtime tests were still executing with no failure after roughly 13 minutes of test-binary runtime and were interrupted as too expensive for this audit loop. This is recorded as incomplete, not as a pass.
- `cargo test -p zkm-pcs whir --lib` on the current worktree: passed, 13 tests; one benchmark ignored.
- `cargo test -p zkm-pcs basefold --lib`: passed, 17 tests; one benchmark ignored.
- Findings outside the explicitly named focused follow-ups remain scoped to the repository-wide baseline and the identified ZR-24 WIP commit. No product source files were modified by this review. The former `jagged_pcs.rs` documentation work is now commit `e1401e19`; warning cleanup is commit `90f2f74a`; and the concurrently observed jagged-evaluation test work is commit `862e174c`. None changes the ZR-27 data flow. The only file modified by the audit is this report.



## Follow-up remediation review

The checkout advanced while the audit was running. Source-only follow-ups reviewed the current-branch remediation commits named below and the separate ZR-24 WIP at `75fab083`; no additional tests, proof generation, or remote execution were used for the latest pass. Pre-existing product-source changes were preserved. “Fixed” below means the patch closes the reported source-level mechanism, not that every integration artifact, deployment, or regenerated verification key was independently tested.

| Finding | Current source-level remediation status |
|---|---|
| ZR-01 | Fixed for the reported arbitrary host write in `c38e42cd`. Extraction is in-process, staged, and rejects absolute/traversing paths, escaping links, and special entries. Artifact authenticity is still not digest/signature-pinned and remains recommended defense in depth. |
| ZR-02 | Fixed in `970c4b5c` for the reported public-fork threat: the persistent self-hosted runner no longer executes untrusted fork PR code. |
| ZR-03 | Fixed. The default loaders are total over the reported malformed inputs, and `49b76544` converts the optional `ark` proof/VK loaders to checked fixed-size reads and checked count/offset arithmetic. Regressions cover every proof/VK truncation prefix and a hostile `num_k`. An explicit `--features ark` CI job remains advisable so this non-default path cannot rot unnoticed. |
| ZR-04 | Fixed in `0016f608`; `d967e2f5` makes the signed `MIN / -1` parity regression always-on. |
| ZR-05 | Fixed in `02a651a0` plus `4da2cb35`. Both exhaustion and surplus entries now return `ReplayOracleDesync`, the fail-open environment switch is removed, and focused regressions distinguish the two directions. |
| ZR-06 | Fixed in `00fc2a13`: `ProofOpts.timeout` is forwarded into remote polling. A stalled mock-server regression is still desirable. |
| ZR-07 | Fixed in `00fc2a13`: builder key/endpoint overrides reach `NetworkProver`, the secondary builder has a `build`, and the unused `skip_simulation` setters are removed. |
| ZR-08 | Fixed for the reported partial-cache acceptance in `c38e42cd`: HTTP errors fail, extraction occurs in a sibling staging directory, failures clean staging, and only a successful final rename creates the installation marker. |
| ZR-09 | Fixed in `00fc2a13`: empty `Core` proofs and short fixed-layout public values return `MalformedProof`; representable unsupported variants return `UnsupportedProofKind`. |
| ZR-10 | Fixed for the reported default-path supply-chain mechanism in `4e880d96`. A digest-pinned `ZKM_GPU_IMAGE` is required by default; mutable references, including the legacy `latest` value, are rejected unless `ZKM_ALLOW_MUTABLE_GPU_IMAGE=1` explicitly enables development behavior. Failed pulls remain fatal. |
| ZR-11 | Fixed in `4da2cb35`: the `profiling` feature is declared and now controls the native-executor cfg as documented. |
| ZR-12 | Fixed at source/test level in `392d2d28`: the replacement regressions execute `HINT_LEN`/`HINT_READ`, prove the shard fence split the seam, and inspect the captured window. |
| ZR-13 | Fixed in `4da2cb35`: `ProverClient::id` delegates to the wrapped prover instead of `todo!()`. |
| ZR-14 | Fixed in `63884db2`: the cached recursion program is checked against its own offset invariant. |
| ZR-15 | Fixed for the reported panic in `611382d7`. Both public verification entry points reject short vectors before fixed slicing/borrowing; an infallible low-level layout cast remains a hardening target. |
| ZR-16 | Fixed in `0214fe02`. Executable loads are sorted and placed by `p_vaddr`; overlaps, inter-segment gaps, missing executable segments, out-of-range entry points, and oversized images are rejected; instruction fetch uses checked indexing. The adversarial reordered/gapped/overlapping/invalid-entry multi-segment regressions are present. |
| ZR-17 | Fixed for the runtime trust-boundary issue in `a4831e33`. The SDK no longer silently falls back to the public test CA; using it requires `ZKM_ALLOW_INSECURE_TEST_CA=1` and emits a warning. Production packaging should still exclude the private fixture. |
| ZR-18 | Fixed in `51a653af`. CUDA setup, core, stateless core, compress, shrink, and wrap RPCs map transport and response-codec failures to typed errors. Regressions cover an unavailable server, malformed endpoint, and undecodable response. Remaining fail-fast environment/configuration reads are outside the untrusted RPC response boundary. |
| ZR-19 | Fixed at source level in `392d2d28`: report aggregation now preserves/adds scope cycles, open scopes are stored as a stack, and duplicate, unknown, non-LIFO, and unclosed markers are diagnosed with focused tests. |
| ZR-20 | Fixed in `64a46fca`: recursive BaseFold now constrains every evaluation-sumcheck transition and the terminal polynomial. Independent ZR-24 still prevents the full PCS from being sound. |
| ZR-21 | Fixed in `64d9cd1e`: native WHIR requires the configured OOD-answer count and rejects truncated vectors. |
| ZR-22 | Fixed in `385188b2`: at a zero coordinate the prover evaluates the actual unconstrained `g(1)` endpoint; chosen zero/Boolean-point roundtrips cover folding arities 1 and 2. |
| ZR-23 | Open, partially fixed in `024b1266`. The main raw commitment is rebound to `proof.main_commitment`; the current branch still does not bind proof-controlled preceding commitments to `vk.commit` or `bundle.y_per_chip` to the shard openings. |
| ZR-24 | Open, partially patched in `747caa24`. The equality is conditional on component openings that production omits. WIP `75fab083` carries them but orders lifted roots incompatibly and rejects an honest proof. |
| ZR-25 | Fixed in `2707a719`: active KoalaBear verifiers reject `EvaluationProof::Empty`. |
| ZR-26 | Fixed at source level in `8714d6ea`; private `ziren-gpu` commit `e9e27800` mirrors the claim-before-challenge transcript. Release remains coupled and requires regenerated/versioned recursion artifacts plus a four-way regression. |
| ZR-27 | Open. Production construction and recursion fix the height at 21, but native verification still derives protocol geometry from proof-carried `log_stacking_height`; see the full finding below. |

The BaseFold endpoint representation was also re-derived manually. `[g(0), g(1)]` is intentionally converted into the monomial fold `g(0) + beta * g(1)` after each Lagrange consistency check; this matches `Mle::fold` and the FRI codeword fold and is not a bug. The original ZR-22 diagnosis was valid because at `r = 0` the prior claim determines only `g(0)`, while the subsequent monomial fold still needs the actual `g(1)`; `385188b2` now evaluates that endpoint correctly.

### Multi-round jagged prover follow-up at `ab35b61f`

The new multi-round guards are algorithmically correct and run before `prove_jagged_basefold_linear_core` samples `z_col`, so rejecting an invalid round set cannot leave a partially advanced Fiat-Shamir transcript. In particular:

- a mixture of rounds with and without `whir_data` now fails instead of falling back to a BaseFold opening against one or more WHIR roots;
- the BaseFold-side `JaggedProverDataGeneric` records must agree on `log_stacking_height` before the shared stripe count and `effective_area` are computed; and
- WHIR-side prover-data records must agree on `log_stacking_height` before the WHIR configuration and stack point are selected.

No new soundness regression was found in this patch. One residual invariant should nevertheless be centralized as defense in depth. The reduction and `effective_area` use `precomputed.prover_data.{area,log_stacking_height}`, the WHIR opening uses `precomputed.whir_data`, and the returned bundle exposes `precomputed.commit.{area,log_stacking_height}` to the verifier. The new assertions compare BaseFold records with other BaseFold records and WHIR records with other WHIR records, but do not require the three representations of each individual round to agree. Normal constructors currently produce matching values, so this is not promoted to a confirmed exploitable finding. A single pre-transcript validator should still require, for every round:

```text
commit.area == prover_data.area
commit.log_stacking_height == prover_data.log_stacking_height

and, when whir_data is present:

whir_data.area == prover_data.area
whir_data.log_stacking_height == prover_data.log_stacking_height
```

The same review corrected a potential false positive: the native verifier does not rely on the separately supplied `jagged_eval` proof to obtain the closing weight. `verify_jagged_reduction` directly evaluates the branching-program expression from public offsets and checks `current_claim == q_at_z * w_at_z`. Native replay of `jagged_eval` is used to preserve the transcript consumed by the subsequent PCS opening; the recursive verifier uses the full structural proof to obtain the same relation efficiently in-circuit.

## SP1 v6.3.1 differential PCS/IOPP review

Reference: [official SP1 v6.3.1 release](https://github.com/succinctlabs/sp1/releases/tag/v6.3.1), commit `8252c2905ce32964df68248117015c61ebb854db`. The comparison used SP1 native and recursive BaseFold, stacked PCS, and jagged verifier implementations. It also checked the row-count/prefix-sum invariant described by SP1 [GHSA-63x8-x938-vx33 advisory](https://github.com/succinctlabs/sp1/security/advisories/GHSA-63x8-x938-vx33).

| Area | SP1 v6.3.1 invariant | Ziren status | Verdict |
|---|---|---|---|
| BaseFold evaluation sumcheck | Reconstruct the batched claim, check every Lagrange transition, and equate the terminal monomial fold with `final_poly`. | Present after `64a46fca`. | Aligned. |
| FRI selected-value chain | Before every fold, assert the query-selected value in the authenticated block equals the running folded value. | Added conditionally in `747caa24`, but skipped on the production outer path because component openings are absent. WIP `75fab083` carries them but checks preceding-round openings against `[main_root, zero, ...]` rather than `[preceding_roots..., main_root]`, rejecting honest proofs. | Unaligned; ZR-24 remains open. |
| Adaptive claim binding | Observe every untrusted evaluation claim before grinding and sampling the batching point, in the prover, native verifier, and recursive verifier. | Present after `8714d6ea`; the paired GPU implementation at `e9e27800` observes the identical claim sequence. | Aligned at source level; atomic deployment and VK regeneration remain required. |
| Jagged row-count geometry | Reconstruct prefix sums from row counts inside the recursive verifier, compare every prefix, and bind the terminal total area. | Ziren performs the same accumulator/prefix/final-area chain and additionally bounds witnessed heights against the opened cube. | Aligned in the inner/circuit path. The outer host path has the separate ZR-23 binds. |
| Missing/empty PCS proof | The active proof is a concrete `StackedBasefoldProof`; there is no accepted `Empty` alternative. | `2707a719` rejects `Empty` after the KoalaBear type gate. | Aligned after remediation. |
| Variable order | SP1 fixes the last coordinate first and reverses the verifier point. | Ziren fixes the first coordinate first and consumes the natural point order. Prover, native verifier, MLE fold, and circuit agree. | Intentional relabelling, not a finding. |
| Folding arity | One variable and one commitment per BaseFold round. | Ziren supports `log_folding_arity > 1` and authenticates a `2^k`-value block per round. The block selection and successive interpolation equations match its native verifier, but this extension is outside SP1 analyzed protocol. | Ziren-specific proof obligation. |
| Zero evaluation coordinate | SP1 derives `g(1)` by division by the coordinate, so zero is unsupported. | Ziren commit `385188b2` explicitly evaluates `g(1)` from the current MLE when the coordinate is zero and adds chosen Boolean-point roundtrips. | Intentional correctness extension; ZR-22 fixed. |

The important distinction is that mirrored coordinate order and larger folding arity are protocol variants, while ZR-24 removes a binding equation and the pre-`8714d6ea` implementation of ZR-26 left batching randomness adaptive. The ZR-26 mechanism is now repaired; SP1 audit or soundness analysis still cannot be inherited for Ziren-specific variants merely because the surrounding type and transcript structure is similar.

## Findings

The finding bodies and suggested comments below preserve the original vulnerable-state analysis so the defect mechanism remains auditable. The **Follow-up remediation review** table above is authoritative for current source-level status; a historical suggested comment is not a request to reapply a fix already marked fixed there.

### ZR-01 — High — Circuit artifact extraction permits writes outside the install directory

Location: `crates/sdk/src/install.rs:84-111`

`install_circuit_artifacts` downloads an unauthenticated-by-content tarball and invokes `tar -Pxzf`. The `-P` option preserves absolute paths, so an archive containing absolute paths can overwrite files outside `build_dir`. The archive is not pinned by a digest or signature. Compromise of the S3 object, publishing pipeline, DNS/TLS trust chain, or credentials therefore becomes arbitrary file overwrite on every SDK host that auto-installs artifacts.

Recommendation:

- Remove `-P`.
- Validate every archive entry and reject absolute paths, `..` traversal, device nodes, and escaping symlink/hardlink targets.
- Verify a version-pinned SHA-256 digest or signature before extraction.
- Prefer an in-process archive reader with explicit path containment checks.

Suggested review comment:

> `tar -P` preserves absolute paths, so this remotely downloaded archive can write outside `build_dir`. Because the archive is not digest- or signature-verified, a compromised artifact can overwrite arbitrary files on the proving host. Please remove `-P`, reject absolute/traversing/link-escape entries, and verify a pinned digest before extraction.

### ZR-02 — High — Pull-request code executes on a persistent self-hosted runner

Location: `.github/workflows/ci.yml:3-9,43-55`

The workflow is triggered by `pull_request` and runs `cargo test` from the checked-out change on `self-hosted-cpu`. Rust build scripts and tests execute arbitrary native code. For a public repository, any approved fork PR can therefore execute attacker-controlled code on a persistent organization runner, where it can inspect the host, poison caches/toolchains, attack adjacent services, or steal any credentials available to the runner.

Recommendation:

- Run untrusted PR jobs only on ephemeral isolated runners with no persistent credentials or network reachability.
- Restrict the existing self-hosted job to trusted branches after merge, or gate it behind a trusted workflow that checks out a reviewed commit SHA.
- Re-image the runner after each job if self-hosting is required.

Suggested review comment:

> This `pull_request` job executes contributor-controlled Rust build scripts/tests on `self-hosted-cpu`. That is arbitrary native code on a persistent runner. Please move PR validation to an ephemeral isolated runner and reserve the self-hosted machine for trusted post-merge commits.

### ZR-03 — High — Public verification APIs panic on malformed proof, key, and hash inputs

**Current status (2026-09-20): closed.** The optional `ark` half was completed in `49b76544` with checked reads/count arithmetic and truncation/hostile-count regressions. The analysis below describes the original and intermediate vulnerable revisions.

Locations:

- `crates/verifier/src/stark/mod.rs:110-150`
- `crates/verifier/src/plonk/mod.rs:52-111`
- `crates/verifier/src/groth16/converter.rs:17-53`
- `crates/verifier/src/plonk/converter.rs:18-164`
- `crates/verifier/src/groth16/ark_converter.rs:222-269` (`ark` feature)
- `crates/verifier/src/utils.rs:26-31`
- `crates/verifier/src/constants.rs:18-33`

These APIs accept untrusted byte slices and return `Result`, but malformed inputs reach `expect`, `panic!`, unchecked range slicing, and unchecked string byte slicing. Examples include `proof[..4]`, fixed proof/VK ranges, `&zkm_vkey_hash[2..]`, and a panicking compressed-point flag conversion. A verification service can be terminated with a short proof/VK or a short/non-ASCII vkey string instead of receiving a verification error.

Remediation review at `0c87d343`: the changed checks are individually correct, but the finding is not closed.

- `PlonkVerifier::verify` now rejects a proof shorter than its four-byte prefix, both proof loaders check their first fixed sections, `CompressedPointFlag` is fallible, and `decode_zkm_vkey_hash` uses `strip_prefix`.
- `load_plonk_proof_from_bytes` checks only bytes `0..384`. Its very next read is `buffer[384..416]`; therefore a 384-byte input still panics. All later scalar/point slices and both `num_bsb22_commitments` loops remain unchecked. The required minimum is `768 + 96 * num_bsb22_commitments`, computed with checked arithmetic.
- `load_plonk_verifying_key_from_bytes` and `load_groth16_verifying_key_from_bytes` still index caller-supplied VK bytes directly, including loops driven by counts parsed from those bytes. Both are reached from public `verify_gnark_proof` APIs.
- `StarkVerifier::verify` and `verify_proof` still `expect` both bincode decodes and `panic!` for any valid non-`Compressed` enum variant. `verify` can additionally reach an infallible fixed-layout `Borrow` on proof-controlled public-value bytes.
- With the optional `ark` feature, public proof and VK converters still use unchecked slices followed by `try_into().unwrap()`.
- The commit adds no empty/truncated/count-overflow/wrong-variant regression. Its recorded happy-path package run cannot establish totality over arbitrary bytes.

Recommendation:

- Validate the complete variable-length layout with checked multiplication/addition before allocating or indexing; preferably use a checked cursor so later fields cannot regress to raw slices.
- Apply the same parser discipline to proof and VK loaders, including the optional `ark` implementation.
- Replace deserialization `expect` and enum `panic!` branches with error variants.
- Add tests asserting every public verifier returns `Err` for empty, every one-byte truncation boundary, wrong variants, invalid flags, and oversized counts. A small fuzz target over the public APIs would pin the stronger no-panic property.

Suggested review comments:

> The new `get` closure only protects the first 384 proof bytes. An exactly 384-byte raw PLONK proof passes all six new reads and then panics immediately at `buffer[384..416]` on line 137; the later 64/96/128-byte reads and both `num_bsb22_commitments` loops have the same issue. Please validate `768 + 96 * num_bsb22_commitments` with checked arithmetic (or parse through a checked cursor) before any of these reads, and add truncation tests past byte 384.

> The public `verify_gnark_proof` methods still parse caller-supplied VKs with direct indexing. An empty PLONK VK panics at `buffer[0]`, and an empty Groth16 VK panics at `buffer[..32]`; attacker-controlled count fields can also drive the parsers past the end. Please harden the complete VK layouts, not only the proof prefixes, and mirror the fix in the `ark` converters.

> ZR-03 also covered the public STARK verifier, but both entry points still call `bincode::deserialize(...).expect(...)` and `panic!` on a non-`Compressed` proof variant. Arbitrary proof/VK bytes therefore still terminate a verification service instead of returning `StarkError`. Please map decode/variant failures to typed errors and add empty, corrupt, wrong-variant, and short-public-values tests.

### ZR-04 — High — Signed division overflow has different JIT and trace semantics

Locations:

- `crates/core/executor/src/executor.rs:2601-2659`
- `crates/core/jit/src/backends/x86/producer.rs:728-753`
- `crates/core/executor/src/jit_runner.rs:1408-1416`
- `crates/core/executor/tests/div_executor_edge_cases.rs:49-91`

The interpreter evaluates signed `i32` division directly. `i32::MIN / -1` panics in Rust, while the JIT intentionally uses 64-bit `idiv` and returns `0x80000000`. The AIR explicitly supports this overflow case. Consequently, a sufficiently large program can complete the fast JIT execution phase and then panic when the tracing/interpreter phase replays the same instruction. The existing test is ignored and asserts the panic rather than enforcing parity.

The comments in `jit_runner.rs` are also stale: the current control-flow JIT traps a zero divisor before `idiv` and uses a 64-bit divide for the overflow case, so it no longer has the stated host `SIGFPE` behavior.

Recommendation:

- Implement signed DIV/MOD with explicit `i32::MIN && divisor == -1` handling in the interpreter, matching the JIT and AIR.
- Convert the ignored edge tests into always-on JIT/interpreter/AIR parity tests.
- Update the stale JIT comments.

Suggested review comment:

> `i32::MIN / -1` panics here, while the JIT deliberately returns `0x80000000` and the DivRem AIR supports the overflow row. That lets fast execution succeed and trace generation later crash on the same guest. Please handle this case explicitly and make the ignored edge test an always-on JIT/interpreter parity test.

### ZR-05 — Medium — Replay-memory oracle corruption is logged but execution continues with fallback state

Locations:

- `crates/core/executor/src/executor.rs:2955-2973`
- `crates/core/executor/src/executor.rs:778-800,871-935,1194-1258`
- `crates/core/executor/src/tracing_vm.rs:216-285`

When a replay oracle is exhausted, `take_replay_mem` logs once and returns `None`. Callers then fall through to paged/default memory and continue producing a record. `TracingVM` neither checks that the oracle was fully consumed nor converts exhaustion into an `ExecutionError`. This violates the claimed lockstep invariant and can turn an upstream capture bug or corrupted chunk into a divergent trace whose actual cause is only a once-per-process log message.

Remediation review through `39ee07c0`: `02a651a0` records exhaustion and rejects the completed chunk, closing the silent-divergence path, and `39ee07c0` adds a focused truncated-oracle regression. Surplus entries are still accepted by default and only warn; the new surplus test deliberately pins that behavior. It also depends on the ambient process environment being unset and does not exercise `ZKM_REPLAY_STRICT=1`, so the strict rejection branch remains unpinned. This finding is therefore only partially fixed.

Recommendation:

- Distinguish "not replaying/register access" from "replay oracle exhausted" in the return type.
- Return an execution error immediately on exhaustion.
- At chunk completion, require `pos == entries.len()` and reject unconsumed entries.
- Add tests for truncated and overlong `mem_reads` oracles.

Suggested review comment:

> The truncated-oracle regression correctly pins exhaustion rejection, but the second test pins the still-permissive default rather than the strict surplus-rejection arm. Please factor the surplus policy out of the ambient process environment (or serialize a scoped environment guard), add a deterministic `strict=true` rejection test, and flip production to fail closed after the stated campaign. Until then `pos != entries.len()` remains an accepted replay desynchronization.

### ZR-06 — Medium — Network proof timeouts configured by the public API are discarded

Locations:

- `crates/sdk/src/action.rs:223-228`
- `crates/sdk/src/network/prover.rs:313-323`

`Prove::timeout` stores a timeout in `ProofOpts`, but `NetworkProver::prove_impl` names the options `_opts` and always passes `None` to `prove_with_cycles`. A stalled remote proving request can therefore poll forever despite an explicit caller timeout.

Recommendation: pass `_opts.timeout` into `prove_with_cycles` and add a network-prover test with a permanently `Computing` mock server.

Suggested review comment:

> The public `.timeout(...)` option reaches `ProofOpts`, but this implementation discards it and passes `None`, so network proving can poll forever. Please forward `opts.timeout` and cover it with a stalled-status test.

### ZR-07 — Medium — `ProverClientBuilder` silently ignores its credential and endpoint settings

Location: `crates/sdk/src/lib.rs:298-381`

The builder exposes `private_key`, `rpc_url`, and `skip_simulation`, but `build` uses only `mode`; network mode calls `NetworkProver::from_env()`. Thus a caller can supply a key and endpoint and still connect with unrelated environment credentials/default endpoint. `NetworkProverBuilder` exposes the same setters but has no `build` method at all.

Recommendation:

- Construct `NetworkProver` from the builder fields.
- Make required values explicit and return `Result` for missing/invalid configuration.
- Remove unsupported setters rather than silently accepting them.

Suggested review comment:

> These builder fields are never read: `build()` selects only `mode` and network mode reloads credentials/endpoint from the environment. A caller can believe it selected one key/RPC while the SDK uses another. Please wire the fields into construction or remove the setters.

### ZR-08 — Medium — Failed artifact installation poisons the cache and reports success

Location: `crates/sdk/src/install.rs:42-70,84-111,121-142`

The installer creates `build_dir` before downloading, treats directory existence as successful installation, does not call `error_for_status`, and ignores the exit status returned by `tar`. A 404 page, truncated download, disk error, or extraction failure can leave an empty/partial directory; all later calls then report that artifacts "already seem to exist" and skip repair.

Recommendation:

- Download and extract into a temporary sibling directory.
- Check HTTP status, exact byte count, digest, and subprocess/extractor result.
- Atomically rename into place only after validating the expected manifest/files.

Suggested review comment:

> `build_dir` is created before the download and later treated as the installation marker, while the HTTP and `tar` exit statuses are not validated. Any failed/404/truncated install leaves a permanent partial cache that future calls accept. Please stage in a temp directory, validate, then atomically rename.

### ZR-09 — Medium — SDK verification panics for representable proof variants and empty core proofs

Location: `crates/sdk/src/provers/mod.rs:145-226`

`ZKMProof` publicly includes empty `Core`, `DvSnark`, and `CompressToGroth16` values. Verification calls `proof.last().unwrap()` for `Core` and ends with `_ => unreachable!()` for unsupported variants. Deserialized or remotely supplied data can therefore panic a caller instead of returning `ZKMVerificationError`.

Recommendation: add explicit `MalformedProof` and `UnsupportedProofKind` errors, reject empty shard vectors before indexing, and never use `unreachable!()` for public serialized enums.

Suggested review comment:

> This enum is public and deserializable, so an empty `Core` vector or a `DvSnark`/`CompressToGroth16` variant is reachable input. `last().unwrap()`/`unreachable!()` turns that into a process panic. Please return a typed malformed/unsupported-proof error.

### ZR-10 — Medium — Default CUDA execution pulls and runs a mutable `latest` image

**Current status (2026-09-20): closed.** Commit `4e880d96` makes digest pinning mandatory on the default path and requires explicit `ZKM_ALLOW_MUTABLE_GPU_IMAGE=1` opt-in for mutable development images. The analysis below describes the original vulnerable revision.

Location: `crates/cuda/src/lib.rs:244-287`

The default local CUDA path pulls `projectzkm/ziren-gpu:latest` and executes it with access to private witness input and the GPU. The image is neither digest-pinned nor signature-verified, and the result status of `docker pull` is ignored. A registry/tag compromise silently changes code executed on proving hosts; a failed pull may silently fall back to a stale local image.

Recommendation: pin the production image by immutable digest, verify provenance/signature, check `docker pull` success, and require an explicit opt-in to mutable development tags.

Suggested review comment:

> The default path executes the mutable `projectzkm/ziren-gpu:latest` image and does not check whether `docker pull` succeeded. Please pin a reviewed digest (and verify provenance/signature) because this container receives private witness data and executes on the proving host.

### ZR-11 — Low — The executor's `profiling` feature gate does not exist

Locations:

- `crates/core/executor/build.rs:1-35`
- `crates/core/executor/Cargo.toml:66-68`

The build script uses `cfg(feature = "profiling")` to disable native JIT execution, but the crate declares only `bigint-rug` and `pre-alloc`. Cargo reports `unexpected cfg value: profiling`, and the intended feature can never be enabled. On Linux x86-64, `zkm_use_native_executor` is therefore always emitted at build time.

Recommendation: declare and document the feature in this crate, or remove the dead feature branch and use one supported configuration mechanism.

Suggested review comment:

> `profiling` is not declared in this crate's feature table, so this condition is always false and Cargo warns on every build. The documented way to compile out the native executor does not work. Please declare/forward the feature or remove the dead gate.

### ZR-12 — Medium — The current hint seam fix lacks a test that exercises the failing seam

Locations:

- `crates/core/executor/src/executor.rs:3028-3047`
- `crates/core/executor/src/tracing_vm.rs:552-597`

The current commit changes the captured input window from `[from, ptr)` to `[from, ptr + 1)`, but its only related test builds 4,000 `ADD` instructions and supplies no hint entries. It never executes `HINT_LEN` or `HINT_READ`, never seals a chunk between them, and therefore passes under both the old and new implementations.

Recommendation: add a regression program/test that places the shard boundary after `HINT_LEN` and before its matching `HINT_READ`, then assert replay succeeds and matches the sequential record. Also run `cargo fmt`; the changed expression currently fails the formatting gate.

Suggested review comment:

> The existing `hint_slices_match_the_finished_stream` test contains only `ADD`s and an empty input stream, so it cannot fail with the old `[from, ptr)` code. Please add a regression that actually seals between `HINT_LEN` and `HINT_READ` and compares sequential vs replay output.

### ZR-13 — Low — Public `ProverClient::id()` is unconditionally unimplemented

Location: `crates/sdk/src/provers/mod.rs:230-233`

Calling the `Prover` trait's `id()` method on `ProverClient` always panics even though the wrapped CPU, CUDA, mock, and network provers all implement it.

Recommendation: delegate to `self.prover.id()` and add a test for every constructor.

Suggested review comment:

> `ProverClient` wraps a prover that already implements `id()`, but this public trait method always panics. Please delegate to `self.prover.id()` and cover all client modes.

### ZR-14 — High — Safe public recursion-program APIs can violate invariants required by unsafe parallel memory

Locations:

- `crates/recursion/core/src/runtime/program.rs:12-61`
- `crates/recursion/core/src/runtime/seq_block.rs:33-53`
- `crates/recursion/core/src/runtime/analyzed.rs:104-187`
- `crates/recursion/core/src/runtime/mod.rs:503-549,617-623`
- `crates/recursion/core/src/runtime/memory.rs:106-203`
- `crates/recursion/core/src/runtime/record.rs:120-152,190-250`
- `crates/prover/src/program_cache.rs:69-108`

The parallel runtime implements `Sync` manually for `UnsafeCell`-backed memory and event buffers. Its safety requires parallel subprograms to have disjoint writes, no cross-block read/write dependencies, valid analyzed offsets, and event counts that exactly match the instruction stream. None of these conditions is enforced at the safe API boundary:

- `RecursionProgram::new` accepts any public `RawProgram`, including a `SeqBlock::Parallel` whose children access the same address.
- `RecursionProgram` derives `Deserialize`, and its analyzed `seq_blocks` and `event_counts` fields are public, so callers can construct or mutate inconsistent analyzed programs without `unsafe`.
- The compiler records `DslIrBlock::addrs_written`, but lowering discards that range without checking it.
- The production disk cache deserializes a `RecursionProgram` directly from an environment-selected, shared directory and does not re-analyze or validate it. The executable fingerprint separates builds but provides no integrity protection against corruption or another writer.

The runtime then executes parallel children with Rayon and calls `mr_unchecked`/`mw_unchecked` through shared references. Overlapping accesses can therefore cause an actual Rust data race, while inconsistent offsets/counts can produce duplicate writes or convert uninitialized event slots into typed values in `into_record`. A corrupt or writable cache is one concrete route into this unsafe state. This makes the unsafe implementation unsound from safe Rust, rather than merely producing a bad proof.

Recommendation:

- Make analyzed instructions, analyzed program fields, and event counts private and deserialize through a validating/raw representation that reruns analysis.
- Make construction of `SeqBlock::Parallel` validated (or `unsafe`) and verify read/write sets before enabling parallel execution.
- Keep the address-range metadata through lowering and reject overlap/cross-block dependencies.
- Replace the raw event transmute with initialization tracking, or at minimum validate all counts/offsets before execution and conversion.
- Add Miri/loom-style tests plus adversarial programs with duplicate writes, read-after-write dependencies, forged offsets, and forged event counts.

Suggested review comment:

> The `unsafe impl Sync` and unchecked memory/event writes rely on disjoint parallel addresses and synchronized analyzed offsets/counts, but safe public APIs do not enforce either invariant: `RecursionProgram::new` accepts arbitrary `Parallel` blocks, and the derived-deserializable analyzed fields are public. A safe caller can therefore create overlapping parallel reads/writes (a Rust data race) or inconsistent event buffers. Please make these representations private, validate/re-analyze at every construction/deserialization boundary, and only enter the parallel unsafe path after proving the access sets are disjoint.

### ZR-15 — Medium — Native proof verification slices public values before its existing shape check

Locations:

- `crates/pcs/src/machine.rs:1219-1259`
- `crates/pcs/src/shard_level/verifier.rs:161-167`
- `crates/prover/src/verify.rs:61-94`
- `crates/pcs/src/air/public_values.rs:129-149`

`StarkMachine::verify` performs `&shard_proof.public_values[0..self.num_pv_elts()]` before calling `Verifier::verify_shard`, even though that callee already has a typed `PublicValuesLengthMismatch` check. `ZKMProver::verify` has an earlier occurrence: it converts every shard's public-value slice into `PublicValues` before invoking the machine. The conversion's length assertion is only a `debug_assert`; the following fixed slice still panics in release builds. Since shard proofs are serializable and can carry a zero-length public-values vector, a malformed proof can crash native/SDK verification instead of returning `MachineVerificationError`.

Remediation review at `611382d7`: the reported panic is fixed. Both entry points scan all shards and reject `len < num_pv_elts` before any fixed slice or `Borrow`; an overlong vector is safe at those early reads and is rejected later by `verify_shard`'s exact-length check. The patch returns a generic `InvalidPublicValues` instead of preserving `PublicValuesLengthMismatch`, leaves the infallible unsafe-layout `Borrow` available to other callers, and adds no empty/short/overlong public-entry regression. Those are hardening and coverage gaps, not a bypass of this fix.

Recommendation:

- Check every shard's public-value length once, before any slicing or `Borrow` conversion.
- Replace the slice `Borrow` implementation with a fallible `TryFrom<&[T]>` for untrusted data.
- Preserve and return `PublicValuesLengthMismatch` through the machine and SDK error types.
- Add empty, short, and overlong public-values tests at all public verification entry points.

Suggested review comment:

> The new guards close the two reported short-vector panics. I would still add empty/short/overlong tests through both public verification entry points and replace the proof-controlled slice `Borrow` with a fallible conversion; otherwise this safety property remains distributed between the new minimum-length guards and a later exact-length check, and another caller can reuse the infallible layout cast without either guard.

### ZR-16 — Medium — ELF loading panics on stripped inputs and loses executable-segment addresses

**Current status (2026-09-20): closed.** Commit `0214fe02` completes virtual-address placement, layout/entry/image validation, checked fetch, and adversarial multi-segment regressions. The analysis below describes the original vulnerable revision.

Locations:

- `crates/core/executor/src/program.rs:51-167`
- `crates/core/executor/src/program.rs:180-193`

`Program::from` is a fallible API, but `patch_elf` unconditionally calls `symbol_table().expect(...).expect(...)`. A valid stripped ELF has no symbol table and therefore panics instead of loading without optional runtime patches or returning an error. The loader also appends every executable `PT_LOAD` word to one `instructions` vector in program-header iteration order while `fetch` indexes that vector as `(pc - min_executable_vaddr) / 4`. It does not insert gaps or place words by virtual address. Valid ELFs with discontiguous, reordered, or overlapping executable segments are consequently decoded at the wrong PCs. An entry point outside that synthetic contiguous interval can also reach unchecked subtraction/indexing.

Recommendation:

- Treat a missing symbol table as "no optional patches" and propagate actual parse failures with `?`.
- Build the instruction image by virtual address (or require and validate exactly one contiguous executable interval).
- Reject overlaps, `p_filesz > p_memsz`, arithmetic overflow, and entry points outside executable mapped ranges.
- Make `fetch` fallible or validate the initial and every control-flow PC before indexing.
- Add stripped, multi-segment, gapped, reordered, overlapping, and invalid-entry ELF tests.

Suggested review comment:

> `Program::from` is declared fallible, but `patch_elf` panics for a valid stripped ELF because `symbol_table()` returns `None`. Also, executable segments are appended rather than placed at `p_vaddr`, while `fetch` assumes one contiguous image from `pc_base`; a valid gapped or reordered multi-segment ELF executes different words than its virtual mapping. Please make symbols optional and construct/validate the instruction image by virtual address.

### ZR-17 — Medium — Bundled test CA is not isolated from runtime network configuration

Locations:

- `crates/sdk/tool/ca.key`
- `crates/sdk/tool/ca.pem`
- `crates/sdk/tool/certgen.sh:82-113,148-170`
- `crates/sdk/src/network/prover.rs:59-90`
- `docs/src/dev/prover.md:178-208`

The project has confirmed that `ca.key` and `ca.pem` are test PKI, so committing the private key is not by itself a production-secret exposure. The repository does not, however, enforce that boundary. When client certificate variables are set, the runtime SDK silently loads the bundled `tool/ca.pem` unless `CA_CERT_PATH` is provided. The default endpoint/domain are a shared `stage` service, the network-prover documentation directs users to these files, and `certgen.sh` defaults to the bundled CA key and can issue both client- and server-auth certificates.

Anyone can mint certificates under this intentionally public test CA. That is acceptable only for environments explicitly treated as insecure and carrying no sensitive data. Any shared stage, downstream deployment, or copied configuration that trusts it can be impersonated; network proving sends the ELF and private input stream to the endpoint. The confirmed issue is therefore the absence of a test-only configuration boundary, not disclosure of a production key.

Recommendation:

- Rename the files as explicitly insecure test fixtures and document that no sensitive witness or credential may be sent through an environment that trusts them.
- Do not make the bundled CA a runtime fallback. Require an explicit `CA_CERT_PATH`, or gate test PKI behind an opt-in test feature/configuration.
- Prefer per-run or per-deployment ephemeral test CAs so unrelated test environments cannot impersonate one another.
- Ensure production packaging excludes the private key and production configuration rejects the test CA fingerprint.
- If any non-test or sensitive shared environment currently trusts this CA, rotate that environment's CA and issued certificates; otherwise no emergency production rotation is implied.

Suggested review comment:

> I understand that `ca.key` is intentionally public test PKI, so this is not a production-secret leak. The remaining problem is that the runtime SDK silently falls back to its matching `ca.pem` for mTLS, the documented default is the shared `stage` endpoint, and `certgen.sh` uses this CA by default. Please make the insecure test boundary explicit: require an opt-in test flag or explicit CA path, exclude the private key from production packages, and reject this test CA in production. If stage can receive sensitive witness data, it should use a private per-environment CA as well.

### ZR-18 — Medium — Remote proving APIs panic on transport failures and server-controlled data

**Current status (2026-09-20): closed.** Commit `51a653af` removes the remaining CUDA RPC transport/codec unwraps and adds unavailable/malformed-response regressions. The analysis below describes the original vulnerable revision.

Locations:

- `crates/sdk/src/network/prover.rs:52-110,127-137,188-245`
- `crates/cuda/src/lib.rs:335-435`

Both remote-prover layers expose fallible APIs, but ordinary remote failures and malformed responses pass through `expect`, `unwrap`, `todo!`, and `assert_eq!`. The network prover panics if connection fails, if the server reports an unknown step, or if returned proof JSON is malformed. It also downloads proof/public-value URLs without `error_for_status`. Every CUDA RPC method unwraps transport and bincode decoding even though its signature returns `Result`. A disconnected container, version skew, truncated reply, or compromised endpoint can therefore terminate the host process rather than producing the declared error.

Recommendation:

- Make `connect` return `Result` and propagate tonic/reqwest failures.
- Reject non-success HTTP status codes before consuming response bodies.
- Map unknown enum values and deserialization failures to typed protocol/version errors.
- Replace every CUDA transport/serialization unwrap with `?` plus an error conversion that preserves the operation name.
- Add unavailable-server, unknown-enum, invalid-JSON, invalid-bincode, and version-skew tests.

Suggested review comment:

> These methods return `Result`, but every CUDA RPC transport and response decode is unwrapped; the network client similarly panics on connect failure, unknown server enum values, and malformed proof JSON. Those are normal remote-boundary failures (including version skew), not invariant violations. Please propagate typed transport/protocol errors and add malformed-response tests so an unavailable or compromised prover cannot crash the caller.

### ZR-19 — Medium — Cycle-scope accounting silently accepts malformed nesting and loses data on report aggregation

Locations:

- `crates/core/executor/src/syscalls/write.rs:89-153`
- `crates/core/executor/src/report.rs:13-54`
- `crates/core/machine/src/utils/prove.rs:227-284`

The cycle tracker stores open scopes in a name-keyed `HashMap`, not a stack. Starting an already-open name silently overwrites its original start, ending an outer name while an inner name remains open succeeds, ending an unknown name is ignored, and execution termination does not reject unclosed scopes. These cases produce plausible but incorrect attribution.

In addition, `ExecutionReport::add_assign` merges opcode counts, syscall counts, and touched addresses but omits `cycle_tracker` entirely. The proving pipeline aggregates reports with that operator, so any scope measurements present in the component report are dropped.

Recommendation:

- Represent open scopes as an ordered stack plus a set for duplicate detection.
- Return an instrumentation error for duplicate opens, non-LIFO or unknown closes, and scopes left open at termination.
- Define and implement merge semantics for completed scope measurements in `AddAssign`.
- Add nested, repeated, mismatched, unclosed, and multi-report aggregation tests.

Suggested review comment:

> The tracker is a name-keyed map rather than a stack, so duplicate starts overwrite their start time, out-of-order ends succeed, missing ends are ignored, and unclosed scopes survive termination. Also, `ExecutionReport::add_assign` drops the `cycle_tracker` field when reports are aggregated. Please enforce stack discipline with explicit instrumentation errors and merge completed scope counts in report aggregation.


### ZR-20 — Critical — Recursive BaseFold omits the evaluation sumcheck constraints

Locations:

- `crates/recursion/circuit/src/basefold_verifier.rs:1022-1205,1459-1461`
- `crates/recursion/circuit/src/recursive_stacked_pcs.rs:211-244`
- Native reference checks: `crates/pcs/src/basefold/verifier.rs:169-183,290-294`
- Unused host-shape checks: `crates/recursion/circuit/src/basefold_verifier.rs:345-418,507-549`

The production in-circuit BaseFold verifier samples the batching coefficients, observes each univariate message, samples every beta, verifies the component Merkle openings, and verifies the FRI fold chain. It never computes the batched evaluation claim from `batch_evaluations`, never asserts the per-round identities

`claim_i = (1 - stack_point[i]) * g_i(0) + stack_point[i] * g_i(1)`,

and never enforces the terminal identity

`final_poly = g_last(0) + beta_last * g_last(1)`.

Those checks exist in the native verifier and in the host-only scaffold helpers, but the production `verify_untrusted_evaluations` implementation only absorbs the messages into Fiat-Shamir and ends after the query/Merkle loop. The stacked wrapper constrains the outer evaluation claim to the prover-supplied `batch_evaluations`, then forwards those values to this verifier; because their values are not consumed by any BaseFold equality, they are not linked to the committed polynomials.

A malicious recursive prover can therefore reuse a valid low-degree/Fri opening for a commitment while replacing `batch_evaluations` with values that satisfy an arbitrary outer claim. The component queries continue to prove proximity of the committed codeword, but no equation says that the claimed evaluation is its evaluation at `stack_point`. This breaks the binding property required from the PCS and can invalidate every recursion layer that selects BaseFold.

Recommendation:

- Port the native verifier logic exactly: compute `eval_claim` from the sampled partial-Lagrange coefficients and `batch_evaluations`; assert the first and every subsequent sumcheck transition at `stack_point`; update the running claim with each beta; and assert the final claim against `final_poly`.
- Use the same witnessed `batch_evaluations` values for both the stacked interpolation and the inner sumcheck.
- Add full circuit-execution negative tests that mutate one batch evaluation, one univariate coefficient, each stack-point coordinate, and `final_poly`. The WHIR circuit already has the appropriate tampered-batch-evaluation test pattern.

Suggested review comment:

> The production recursive BaseFold path only absorbs `uni_poly` and samples betas; it never constrains `eval_claim == (1-x_i)g_i(0)+x_i g_i(1)` for any round and never binds the last sumcheck claim to `final_poly`. The host-only helper contains these checks, and the native verifier enforces them, but `verify_untrusted_evaluations` does not call or reproduce them. As a result, `batch_evaluations` can be changed to satisfy an arbitrary outer claim while the Merkle/FRI proof remains an opening of an unrelated committed polynomial. Please port the native sumcheck and terminal constraints into the circuit and add a circuit test that rejects a tampered batch evaluation.

### ZR-21 — High — Native WHIR accepts fewer OOD samples than the verifier configuration requires

Locations:

- `crates/pcs/src/whir/config.rs:18-35`
- `crates/pcs/src/whir/jagged.rs:99-165`
- `crates/pcs/src/whir/stacked.rs:573-585,992-1000,1073-1084`
- Recursive comparison: `crates/recursion/circuit/src/whir_circuit.rs:496-505`

Production config sets `ood_samples = 2` for every committed WHIR round, and the prover emits exactly that many answers. The native verifier instead iterates over the proof-provided `round_ood_answers[r]` and uses that vector length to decide how many OOD points, transcript observations, and terminal constraints exist. It never compares the length with `round_cfg.ood_samples`.

This is a proof-controlled security-parameter downgrade. A proof generated with zero OOD samples is accepted by a verifier configured to require OOD sampling, so the accepted protocol is not the protocol described by `WhirConfig` or used in its soundness analysis. It also makes the native and recursive verifiers accept different languages: the recursive verifier has an exact `assert_eq!(ood_answers.len(), round_cfg.ood_samples)` check.

A temporary differential test confirmed the mismatch: the prover used the verifier config with only `ood_samples` changed from one to zero; all `round_ood_answers` were empty; the stronger native verifier returned `Ok(())`. The test passed and was then removed, leaving the source tree unchanged.

The precise bit loss from removing the OOD constraints requires a WHIR soundness calculation, so this report does not claim a complete forgery from this issue alone. It does establish that the verifier fails to enforce the configured protocol and invalidates any security claim that assumes those OOD checks are mandatory.

Recommendation:

- Before transcript replay, require every non-final round to have exactly `round_cfg.ood_samples` answers and require the outer OOD-answer vector count to match the number of applicable rounds.
- Mirror all recursive-verifier shape checks in the native verifier.
- Add prover/verifier config-mismatch tests for OOD counts, queries, folding factors, rates, and PoW schedules, plus a native-versus-recursive acceptance differential suite.

Suggested review comment:

> `round_cfg.ood_samples` controls what the prover emits, but the native verifier accepts whatever length is supplied in `proof.round_ood_answers[r]`. I reproduced this with a zero-OOD proof accepted by a verifier configured for one OOD sample. That silently downgrades the configured WHIR protocol and diverges from the recursive verifier, which checks the exact count. Please reject unless `ood_answers.len() == round_cfg.ood_samples` before drawing OOD points or building terminal constraints.

### ZR-22 — Medium — BaseFold prover emits an invalid sumcheck message when an evaluation coordinate is zero

Location: `crates/pcs/src/basefold/prover.rs:449-464`

For each multilinear round the prover computes `g(0)` and derives `g(1)` from

`g(r) = (1-r)g(0) + r g(1)`.

The rearrangement divides by `r`, so the code special-cases `r == 0` by setting `one_val = 0`. This is not an algebraic solution: when `r = 0`, the claim fixes only `g(0)`, while `g(1)` must still be evaluated from the current MLE because the verifier later samples a generally nonzero beta and continues with `g(beta)`. Unless the actual `g(1)` happens to be zero, the following round or final consistency check rejects an otherwise valid opening.

Random extension-field points hit exactly zero with negligible probability, so ordinary randomized tests miss the defect. The public PCS algorithm must nevertheless support arbitrary points, including Boolean points and points supplied by higher-level reductions. The issue is deterministic for a nonzero `g(1)` and is visible directly from the sumcheck identity.

Recommendation:

- Evaluate both endpoints from `current_mle` every round, or at least evaluate `g(1)` explicitly when `r == 0`; do not invent a value for the unconstrained endpoint.
- Add roundtrip tests with zero in the first, middle, and last coordinate, and with all-zero/all-one Boolean points, across every supported folding arity.

Suggested review comment:

> When `r == 0`, the claim determines only `g(0)`; setting `g(1) = 0` is not valid. The next beta fold needs the actual `g(1)` from `current_mle`, so a legitimate opening at a zero-containing point normally fails in the next sumcheck/final check. Please evaluate the one endpoint explicitly in this branch and add Boolean-point roundtrip tests.

Remediation review at `385188b2`: fixed. The special branch now constructs the remaining evaluation point with leading coordinate one and obtains `g(1)` through `current_mle.eval_at`, exactly as required by the multilinear restriction. The ordinary `r != 0` branch retains the derived endpoint and therefore pays no additional full-MLE evaluation cost. The new deterministic tests exercise every zero position and representative Boolean points at folding arities 1 and 2, covering the cases the previous random tests almost surely missed.


### ZR-23 — Critical — Outer jagged BaseFold verification leaves its trace commitment and claims unbound

Locations:

- `crates/pcs/src/shard_level/prover.rs:135-187`
- `crates/pcs/src/shard_level/verifier.rs:319-405,497-589`
- `crates/pcs/src/jagged_pcs.rs:1785-1850,2022-2135`
- Inner reference binding: `crates/pcs/src/shard_level/verifier.rs:990-1059`

The outer/wrap ring stores `digest_felts(raw_bn254_commitment)` in `proof.main_commitment` and absorbs those eight KoalaBear felts in the shard Fiat-Shamir prologue. The prover comment says that the outer ring will re-bind the BN254 commitment in its registered verification hook. That re-bind is absent.

`verify_jagged_pcs_host` takes an early outer-ring branch and calls `verify_jagged_basefold_inner_generic` with `skip_commit_observe = true`. The generic verifier opens `bundle.commit.original_commitment`, but it neither projects that commitment with `BasefoldRing::digest_felts` nor compares the result with the already-observed `proof.main_commitment`. Therefore the PCS commitment authenticated by the Merkle/FRI proof is not the commitment that seeded Fiat-Shamir.

The same early return bypasses two additional bindings that the inner verifier explicitly treats as soundness guards:

- It supplies `bundle.preceding_commits`, which are proof-controlled, directly as the preprocessed rounds and never re-derives their geometry-bound digest or compares it with `vk.commit`.
- Although `verify_jagged_pcs_host` receives `opened_values`, the outer branch never passes or compares `opened_values.chips[].main.local` to `bundle.y_per_chip`. The jagged reduction is therefore driven by one set of column claims while zerocheck is driven by another.

These are not only transcript-format differences. An adversarial prover can construct the AIR/zerocheck portion around chosen point openings and construct a valid low-degree BaseFold bundle for a different polynomial and different `y_per_chip`; no outer host-verifier equation requires the two halves to describe the same committed trace. Likewise, any preprocessed round in the bundle is not pinned to the verifying key. This defeats the commitment-binding property of the outer shard verifier.

Recommendation:

- Pass the transcript-observed `proof.main_commitment`, `vk.commit`, machine-derived preprocessed geometry, and `opened_values` into the outer verifier.
- Require `BasefoldRing::digest_felts(bundle.commit.original_commitment) == proof.main_commitment` before any challenge derived from that transcript is trusted.
- Reproduce the inner preprocessed re-bind against `vk.commit`; never use `bundle.preceding_commits` as trusted roots.
- Reproduce the inner opened-value cross-bind at the same `z_col`, or share one ring-generic implementation so the outer branch cannot omit soundness checks.
- Add negative outer-ring tests for a substituted raw commitment, substituted preceding commitment, modified packing geometry, and independently valid but different `y_per_chip` versus `opened_values`.

Suggested review comment:

> The outer `Bytes` branch returns through `verify_jagged_basefold_inner_generic` before the bindings enforced by the inner path. With `skip_commit_observe=true`, the BN254 commitment opened by BaseFold is never projected and compared to the eight-felt `proof.main_commitment` that seeded Fiat-Shamir; proof-controlled `preceding_commits` are never rebound to `vk.commit`; and `bundle.y_per_chip` is never cross-checked against `opened_values.main.local`. This lets the zerocheck/AIR openings and the valid PCS bundle describe different traces. Please make these three binds ring-generic and add substitution tests for each boundary.


### ZR-24 — Critical — Recursive BaseFold does not link queried values across the FRI folding chain

Locations:

- `crates/recursion/circuit/src/basefold_verifier.rs:1334-1505`
- WIP `75fab083`: `crates/recursion/circuit/src/basefold_witness.rs:647-788`
- `crates/recursion/circuit/src/shard_level_witness.rs:1194-1205,1421-1433`
- `crates/pcs/src/jagged_pcs.rs:914-925,2110-2113`
- Native reference check: `crates/pcs/src/basefold/verifier.rs:325-423`

For each Fiat-Shamir query, the recursive verifier authenticates the component leaf and every commit-phase leaf. It computes `initial_eval` from the component openings, initializes `folded = initial_eval`, and then loops over the commit-phase blocks. However, `emit_basefold_block_fold` receives only the block, domain point, index bits, and betas; it never receives the running folded value. The caller immediately overwrites `folded` with the independently folded block result.

Consequently the circuit never enforces the native verifier condition `block[index_low_bits] == folded_eval` at round zero or any later round. There is no equality linking:

1. the value opened from the original component commitment to the selected value in the first FRI leaf;
2. the folded result of one FRI commitment to the selected value in the next commitment; or
3. any earlier round to the final round that is compared with `final_poly`.

Merkle authentication alone only proves that each block belongs to its own root. Without the cross-round value equalities, those roots can commit to unrelated codewords. The final assertion constrains only the last independently folded block to `final_poly`; it does not establish that the final polynomial descends from the original committed polynomial. This independently breaks BaseFold proximity/opening soundness even if the missing sumcheck constraints in ZR-20 are restored.

Remediation review: `747caa24` adds the missing selected-value equality, but only when `component_openings` is non-empty; canonical outer witness code still drops those openings. WIP `75fab083` carries them and reports that the honest Groth16 circuit then fails at a BN254 `assertIsEqual`, unchanged when the query-chain equality itself is disabled.

The WIP failure is a commitment-vector ordering defect, not an evidenced mismatch in the BN254 Poseidon leaf hash:

1. `component_polynomials_query_openings_and_proofs` follows the batched opening round order: every preceding/preprocessed round first, then the main round. Native verification constructs its commitment vector in exactly that order.
2. `JaggedBasefoldBundleGeneric::preceding_commits` explicitly stores the raw roots of all rounds before the last.
3. `lift_jagged_basefold_bundle_outer`, however, sets `original_commitments` to the witnessed main root followed by zero digests: `[main_root, 0, ...]`.
4. Once the WIP activates component verification, `component_openings[0]` is therefore authenticated against `commitments[0] == main_root`, although it belongs to the preceding/preprocessed root. The first `HV::assert_digest_eq` must fail. Disabling the later chain equality cannot change that result.

Plonky3's `MerkleTreeMmcs::verify_batch` hashes all same-height opened matrix rows by flattening them, which matches Ziren's `op.leaf_values.iter().flatten()` circuit preimage. The outer `FieldHasherVariable::hash` also mirrors the host `MultiField32PaddingFreeSponge` rate and 32-bit packing. Those source comparisons rule out the WIP commit's leading hash-preimage hypothesis for this trace.

Recommendation:

- Keep the selected-value equality from `747caa24`, carry component openings on the outer witness, and make the check unconditional for the production proof shape.
- Witness the complete raw commitment vector in native order: `preceding_commits` followed by `bundle.commit.original_commitment`. Require its length to equal `component_openings.len()` and the evaluation-claim round count; do not synthesize zero placeholders.
- As part of ZR-23, bind each preceding/preprocessed raw root and its geometry to the corresponding verifying-key commitment. Merely accepting proof-supplied preceding roots would repair completeness but leave soundness open.
- Require exact commit-round and query shapes rather than truncating with `min`.
- Add full circuit negative tests that mutate the selected element in round zero and every later round while repairing its Merkle path; each mutation must be rejected by the chain equality rather than only by Merkle authentication.
- Add an honest two-round outer fixture that distinguishes the preceding and main roots, asserts the exact order at the lift boundary, and verifies every component path before the FRI chain. Track the reported 95.0% use of the 2^25 constraint ceiling as a release blocker; either recover measured headroom or move to a 2^26 ceremony before relying on this repair.

Suggested review comment:

> The recursive FRI query loop computes `initial_eval`, assigns it to `folded`, and then immediately overwrites `folded` with `emit_basefold_block_fold(block, ...)`. Unlike native `verify_queries`, it never asserts `block[index_low_bits] == folded` before a round. Therefore the component opening and every FRI commitment can describe unrelated codewords; only the last block is compared with `final_poly`. Please assert the selected block element equals the running folded value at every round, then update the accumulator, and add a circuit test that substitutes an authenticated but inconsistent round leaf.

WIP follow-up comment:

> Carrying the component openings exposes a pre-existing commitment-order bug in the outer lift. The host proof and native verifier order rounds as `preceding_commits` first and `bundle.commit.original_commitment` last, but `lift_jagged_basefold_bundle_outer` currently builds `original_commitments` as `[main_root, zero, ...]`. Thus `component_openings[0]` (the preprocessed round) is checked against the main root, which explains the unchanged BN254 `assert_digest_eq` failure even when the later query-chain equality is disabled. Please witness `preceding_commits ++ [main]` in that exact order, assert the round counts match, and bind every preceding root/geometry to the VK rather than replacing it with a zero or trusting the proof. Add an honest two-round path test before merging; the recorded 95% use of the 2^25 ceiling also needs an explicit headroom decision.

### ZR-25 — Critical — KoalaBear shard verification accepts an empty PCS proof and skips commitment binding

Locations:

- `crates/pcs/src/shard_level/shard_proof.rs:38-61,96-107`
- `crates/pcs/src/shard_level/verifier.rs:484-519,589-596`

`EvaluationProof` is a public Serde-tagged field of `BasefoldShardProof`, and its default is `Empty`. The verifier first uses compile-time type checks to establish that it is verifying a KoalaBear/BaseFold shard. Despite that, both subsequent dispatches treat the proof-controlled `Empty` variant as success: the outer branch returns `Ok(())` before deserializing or verifying the BN254 bundle, and the inner branch returns `Ok(())` before constructing or verifying the jagged PCS opening.

`Empty` is documented for non-KoalaBear/non-MIPS shards, but those configurations have already returned through the preceding type gate. It is therefore not a valid compatibility case inside either KoalaBear branch. Replacing the evaluation-proof field does not alter the transcript prologue, which has already absorbed `main_commitment`; zerocheck and LogUp continue to consume the supplied opened values, but no Merkle/FRI/WHIR equation binds those values to that commitment. This removes the oracle-consistency assumption on which the algebraic checks rely and breaks shard-proof soundness.

Recommendation:

- After the type gate selects a KoalaBear PCS configuration, reject `EvaluationProof::Empty` as `IncorrectShape` or `MissingEvaluationProof`.
- Require `Bytes` for the outer ring and a valid `Bundle`/supported serialized bundle for the inner ring; do not use a permissive default for an active PCS field.
- Keep the non-KoalaBear skip only in the earlier compile-time configuration branch.
- Add inner and outer negative tests that take an otherwise valid shard proof, replace only `evaluation_proof` with `Empty`, and require rejection before any opened value is trusted.

Suggested review comment:

> At this point the TypeId gate has already selected a KoalaBear/BaseFold verifier, so `EvaluationProof::Empty` cannot mean “this configuration has no jagged PCS.” Both the outer and inner matches nevertheless return `Ok(())`, skipping every commitment-opening check while zerocheck continues to use proof-supplied openings. Since this enum is deserializable and defaults to `Empty`, please reject it for active KoalaBear configurations and add substitution tests for both rings.

### ZR-26 — Critical — BaseFold samples batching randomness before binding the claimed evaluation vector

Locations:

- `crates/pcs/src/basefold/prover.rs:378-416`
- `crates/pcs/src/basefold/verifier.rs:81-113`
- `crates/pcs/src/basefold/stacked.rs:378-401,471-489`
- `crates/recursion/circuit/src/recursive_stacked_pcs.rs:114-123,181-245`
- `crates/recursion/circuit/src/basefold_verifier.rs:1022-1056`
- SP1 reference: `slop/crates/basefold-prover/src/prover.rs`, `slop/crates/basefold/src/verifier.rs`, and `crates/recursion/circuit/src/basefold/mod.rs` at v6.3.1

Ziren treats the per-stripe `batch_evaluations` as trusted for transcript purposes. The prover calls `prove_trusted_mle_evaluations`, the native stacked verifier calls `verify_mle_evaluations` directly, and the recursive verifier explicitly comments that the untrusted values are never observed. It verifies the batch-grinding witness and samples the BaseFold batching point before any transcript operation depends on those claims.

SP1 does the opposite at all three boundaries. Its untrusted prover and native verifier absorb every constant-length extension-field evaluation before entering the trusted BaseFold routine, its recursive `verify_untrusted_evaluations` default absorbs every evaluation before delegation, and its stacked verifier selects that untrusted interface. This ordering is a soundness condition, not a cosmetic transcript difference.

Let `v_i = f_i(s)` be the true evaluations at the stack point of the committed stripe polynomials, and let `y_i` be the values supplied in `proof.batch_evaluations`. The stacked reduction checks

`sum_i a_i y_i = q`,

where `a` is the multilinear Lagrange vector at the batch point and `q` is the outer jagged claim. BaseFold later samples a second Lagrange vector `lambda` and, after the ZR-20 repair, proves only

`sum_i lambda_i y_i = sum_i lambda_i v_i`.

Because `y` was not absorbed before `lambda` was sampled, a malicious prover may choose it after both coefficient vectors are known. With at least two stripe claims and linearly independent `a` and `lambda`, the two equations can be solved for `y` for an arbitrary target `q`; with more claims there is an affine space of solutions. The prover then supplies a valid BaseFold opening of the real random combination `sum_i lambda_i f_i` while the stacked equation reports the attacker-selected outer value. This attack survives a correct evaluation sumcheck, a correct FRI query chain, and valid Merkle proofs, because it exploits adaptivity before those checks.

Production proofs have multiple stripes or commitment rounds, including the preprocessed/main batched layout, so the vulnerable dimension is not merely a degenerate test shape. The result is a failure of evaluation binding: the jagged/zerocheck side can be reconciled with a scalar that is not the committed dense polynomial evaluation.

Remediation review at `8714d6ea`: the algorithmic repair is correct. The host prover and native verifier iterate `evaluation_claims` in the same round-major order and call `observe_algebra_element` before `deterministic_grind`/`check_witness` and before sampling the batching point. The recursive verifier observes the same variables through `observe_ext_element`, whose basis-coefficient decomposition matches the host challenger, before its identical two phases. `RecursiveStackedPcsVerifier` uses the same witnessed `proof.batch_evaluations` for the stacked MLE equality and for this BaseFold call, so there is no alternate unobserved claim copy. Private `ziren-gpu` commit `e9e27800` adds the same sequence to `basefold/src/fri.rs`; its `ChallengerTranscript::observe_ext` iterates the same basis-coefficient order. Consequently `lambda` is now a Fiat-Shamir function of `y`, and the post-challenge two-linear-equation attack no longer applies except with the intended random-oracle soundness probability.

The remaining risk is integration, not the repaired equation. The Ziren and GPU commits are in separate repositories, and the change moves every downstream challenge and recursion VK. Shipping either side alone rejects every GPU-produced proof; retaining old VK/program/artifact caches after the circuit change also creates a version-skew failure. The patch adds explanatory comments but no focused attack regression or machine-readable four-way transcript trace.

Recommendation:

- Merge and deploy Ziren `8714d6ea` and `ziren-gpu` `e9e27800` atomically; pin the compatible pair in build/deployment metadata rather than relying on branch names.
- Regenerate and version every affected recursion program, VK, allowlist entry, and proof cache. Reject mixed protocol-profile digests before proof verification.
- Bind exact claim-vector shapes separately so that the flattened transcript encoding does not have to carry structural domain separation.
- Add a negative test that constructs the old nonzero correction vector after a recorded pre-fix batching challenge and proves it is rejected once the claims are absorbed.
- Add a transcript-trace differential test over host prove, host verify, recursion-circuit construction, and GPU prove, comparing typed events and absorbed basis coefficients through query sampling.

Suggested review comment:

> The new order closes ZR-26: host prove/verify, the recursion circuit, and `ziren-gpu` `e9e27800` now absorb the same round-major claim vector before grinding and sampling `lambda`. Because this forks the transcript and moves every recursion VK, please make the two-repository revision pair atomic in deployment, regenerate/version all VK and program artifacts, and add a four-way transcript-trace plus the old adaptive-correction attack as a negative regression. Existing roundtrip tests establish parity only for the paths they execute; they do not prevent a future implementation from silently omitting this event again.

### ZR-27 — High — Native verification trusts a proof-controlled stacking height that production defines as fixed

Locations:

- `crates/pcs/src/jagged_pcs.rs:44-58,76-108,497,535,1905-1970,2118-2150`
- `crates/pcs/src/jagged.rs:218-224,335,470,695`
- `crates/pcs/src/whir/jagged.rs:120-163,204-208,280-287`
- `crates/pcs/src/shard_level/verifier.rs:737-738,1088-1090`
- `crates/recursion/circuit/src/shard_level_witness.rs:27-66`
- `crates/recursion/circuit/src/basefold_verifier.rs:638-655,1767-1790`

`pick_log_stacking_height` is no longer an adaptive choice: it ignores `total_entries` and always returns `DEFAULT_LOG_STACKING_HEIGHT = 21`. This is algorithmically correct for the current production profile. Inner BaseFold uses `log_blowup = 2`, giving an initial log-domain size of 23; WHIR also starts at inverse-rate log 2 and uses the documented `[3, 6, 6]` fold schedule; wrap BaseFold uses `log_blowup = 3`, giving `21 + 3 = 24`, exactly KoalaBear's two-adicity. A height above 21 is therefore invalid for wrap, while a trace-dependent height below 21 changes the number of FRI/WHIR rounds, Merkle depths, transcript shape, recursion program, and verification key.

The recursion witness boundary recognizes this and calls `assert_recursion_stacking_height_fixed`, requiring both height 21 and the corresponding commitment-round count. Native verification does not enforce the same invariant. `JaggedCommitGeneric` is deserializable, and the host verifier uses `bundle.commit.log_stacking_height` to derive stripe counts, effective areas, evaluation-point length, BaseFold/WHIR configuration, and Merkle geometry. The value also reaches unchecked shifts such as `1usize << log_stacking_height`; WHIR performs `checked_sub(3).expect(...)`. A malformed proof can therefore select a different protocol profile or drive a `Result`/boolean-returning verification path into a panic. More fundamentally, native and recursive verification accept different proof languages: recursion requires 21, while native verification attempts to interpret the proof-carried value.

This is not an argument to restore the old data-dependent clamp. `chips_to_mles_owned` and the metadata builders already pad using the fixed constant before the picker is called, and several shape/VK paths hard-code 21. Changing this function alone would merely repartition already padded data while forking the transcript and recursion shape; it would not implement a coherent memory optimization. If another stacking height is ever needed, it must be a separately analyzed, explicitly versioned protocol profile selected from trusted verifier configuration, not from the proof.

The public low-level multi-round opening helpers also index `rounds[0]` and inherit its height without locally requiring a non-empty slice or equality across all rounds. The current high-level jagged prover now checks round equality, but direct callers of these public helpers can bypass that invariant. The lowest reusable layer should enforce it.

Recommendation:

- At every production native verification entry point, reject immediately unless `bundle.commit.log_stacking_height == DEFAULT_LOG_STACKING_HEIGHT`; perform this before shifts, allocation, transcript sampling, or configuration construction.
- Stop using a serialized proof field as the source of protocol parameters. Select a trusted, versioned `BasefoldProtocolProfile` and compare all proof metadata with it.
- If generic non-production profiles remain supported, validate their range with checked shifts and checked additions, require `height + log_blowup <= TWO_ADICITY`, validate the WHIR fold schedule, and return a typed shape/configuration error rather than panicking.
- Make both public multi-round open functions reject empty input and require every round to use the same height before reading `rounds[0]`.
- Rename `pick_log_stacking_height` to express that it returns a fixed profile constant, or remove the unused argument. Delete the stale clamping narrative in `JaggedCommitGeneric` and the recursive BaseFold comments/tests that still describe production clamping.

Suggested review comment:

> `pick_log_stacking_height` now correctly fixes the production profile at 21, but native verification still trusts `bundle.commit.log_stacking_height` from the serialized proof and uses it for shifts, stripe geometry, WHIR/BaseFold configuration, Merkle dimensions, and transcript shape. Recursion explicitly rejects any value other than 21, so the two verifiers currently accept different languages; small/large malformed values can also reach `checked_sub(...).expect(...)` or unchecked shifts. Please reject `log_stacking_height != DEFAULT_LOG_STACKING_HEIGHT` at the native proof boundary before any derived computation. If alternate heights are intentional, select them through a trusted, versioned protocol profile with checked two-adicity/range validation rather than through proof metadata. The low-level multi-round open helpers should also reject empty or mixed-height round slices locally.

## Assessment of zkevm-standards PR #36

Source reviewed: [eth-act/zkevm-standards PR #36 — Proving Cost Estimation](https://github.com/eth-act/zkevm-standards/pull/36)

### What the existing reviewers already covered

The following points are already present in the public discussion and should not be resubmitted as duplicate review comments:

- Mauro Toscano approved the direction but recommended standardized real proving benchmarks to validate optimizations suggested by the proxy metric.
- Ayush Shukla argued that a guaranteed one-dimensional linear relation is too strong, especially for parallel proving where the critical path matters, and gave a witness-generation counterexample in which equal trace dimensions/constraint degrees have very different host-computation costs.
- Yi Sun requested changes because guest `cost_scope` instrumentation expands the security-critical VM surface for profiling that could live in an emulator-only feature.
- `@frisitano`, `@yi-sun`, and the follow-up discussion converged toward an emulator/flamegraph-oriented standard; `@jsign` and `@marcinbugaj` noted the tradeoff between symbol-based attribution and LTO/inlining.
- The discussion already identifies rows, trace width, constraints, opcodes, and memory as distinct cost dimensions that are difficult to collapse exactly.

### Ziren's current conformance status

Ziren is not currently conformant with the proposed text:

| Proposed requirement | Ziren status | Evidence |
|---|---|---|
| One scalar proving-cost metric from ordinary emulation | Missing | `ExecutionReport` returns opcode/syscall counts, touched addresses, and cycle counts; internal padded-area accounting drives shape/shard decisions but is not surfaced as one report metric. |
| Deterministic metric version reported beside the value | Missing | `ExecutionReport` has no cost-model version or configuration identifier. |
| Portable `zkvm_cost_scope_start/end(uint8_t)` ABI | Missing | Ziren recognizes vendor-specific text written to stdout, such as `cycle-tracker-report-start: setup`. |
| Scope values use the same unit as the total metric | Missing | Scope attribution is elapsed guest cycles; the closest cost model is weighted, padded per-AIR area. |
| Markers do not alter the metric | Not satisfied | Formatting/writing marker strings executes guest instructions, memory operations, and a write syscall that are included in execution accounting. |
| Stack discipline and diagnostic instrumentation errors | Partially satisfied, non-portable | Commit `392d2d28` replaces the name-keyed map with a stack and diagnoses duplicate, unknown, non-LIFO, and unclosed markers. The mechanism is still Ziren-specific text instrumentation rather than the proposed portable ABI. |
| Attribution survives report composition | Satisfied for current internal reports | Commit `392d2d28` makes `ExecutionReport::add_assign` add every `cycle_tracker` entry across shard reports. |

### New PR comments worth submitting

These comments are intentionally distinct from the concerns already raised by other reviewers.

#### Comment 1 — Quantization contradicts additive/reconcilable scope attribution

Suggested location: “Cost attribution scopes” / “Reconciliation with the metric,” with a cross-reference to “Determinism, quantization, and the limits of prediction.”

> The attribution contract appears to require scope costs to use the same unit as `C` and reconcile with its execution-dependent part, while the rationale derives attribution from additivity. That is not defined for the quantized cost models the proposal explicitly permits. For example, Ziren's closest estimator charges each AIR as `next_power_of_two(event_count) * width`, so `C(A ∪ B) != C(A) + C(B)`; a boundary crossed while executing B can add padding whose cause is shared with all earlier work. Please specify whether implementations must allocate marginal boundary costs in execution order, report an unpadded additive proxy, or use another allocation rule, and whether all top-level scope/unscoped values must sum exactly to `C - fixed`. Without a rule, conforming implementations can produce materially different scope costs for the same execution.

#### Comment 2 — A global 8-bit identifier has no collision-safe library composition

Suggested location: the `uint8_t scope` API and “An identifier is open at most once.”

> How should independently developed libraries allocate the global 8-bit `scope` identifiers? There is no namespace or registration mechanism, and only 256 values, so two dependencies can choose the same ID. If their calls nest, an otherwise valid application becomes an instrumentation error under the uniqueness rule; if they do not nest, their unrelated totals are silently merged. Please define collision-safe allocation (for example linker-assigned IDs backed by metadata) or use a wider/stable identifier that libraries can generate independently.

#### Comment 3 — The static-library ABI does not by itself make markers inert or zero-cost

Suggested location: “Inertness.”

> The text says these are ordinary unmangled functions from the vendor static library, but also requires them not to change `C` and says a proving build may compile them away. An ordinary call still executes call/return, argument setup, and usually a syscall or memory operations; in Ziren's current stdout-based tracker, that instrumentation is directly counted. If the emulator intercepts behavior that the proving execution omits, the two executions can also diverge. Please define the mechanism that makes markers semantically and metrically inert (compiler intrinsic, reserved instruction/syscall with identical emulator/prover semantics, or a precisely specified subtraction rule) and require a conformance test showing that adding markers leaves both guest outputs and total `C` unchanged.

#### Comment 4 — The version needs to identify the complete cost-relevant configuration

Suggested location: “The metric is versioned.”

> Please require the reported version to bind the full cost-relevant machine/prover configuration, not just an implementation release's model name. In Ziren, shard size, per-chip shape limits, AIR widths, lookup structure, PCS/hash choice, and recursion/compression pipeline can change padding and downstream proof work for the same execution. If two configurations can emit the same version string while assigning different `C`, the comparison guard fails. A stable circuit/configuration digest plus a model revision (with specified serialization) would make this check machine-verifiable.

### Recommended position on PR #36

Request changes, but focus the review on specification precision rather than rejecting emulator-side cost estimation. The direction is useful and Ziren already demonstrates that emulator-derived profiles can guide optimization. Before standardization, the proposal should:

1. Weaken the universal linearity/monotonicity guarantee as the existing reviewers requested.
2. Decide whether portable guest scopes are required or whether emulator-only symbol/DWARF profiling is sufficient.
3. Define attribution for non-additive quantized models.
4. Provide collision-safe identifiers and a concrete inert marker mechanism.
5. Bind cost values to an unambiguous model/circuit/configuration version.
6. Include a conformance suite: same program/input determinism, marker-invariance, malformed nesting, version changes, boundary quantization, and correlation against standard proving workloads.

## Re-review of ethereum/soundcalc PR #91

Source reviewed: [ethereum/soundcalc PR #91 — Let a jagged circuit sit on WHIR and add Ziren](https://github.com/ethereum/soundcalc/pull/91), head `d8d8d936ee2ac7fa6394aaae04e728378f70d0db` (remote head rechecked on 2026-09-18).

The pull request had not changed at the time of this renewed review: it still contained two commits, and the GitHub API returned no reviews, inline comments, or issue comments. Ziren's `8714d6ea` fix makes the BaseFold claim-before-challenge transcript ordering sound, but does not change the PCS parameters represented by this pull request and does not resolve the following model errors. The current PR should not be used to claim 100-bit composed Ziren soundness.

### SC91-01 — High — The WHIR batch cardinality and batching law do not match Ziren

The Ziren TOML sets `dense_batch = 32`, `power_batching = false`, and `multilinear_batching = true`. In Ziren, however, `DEFAULT_BATCH_SIZE = 32` is explicitly a packing constant with no soundness implication. The WHIR prover computes one evaluation per actual stripe, flattens the stripes across every commitment round, and combines all of them with `1, lambda, lambda^2, ...`. Therefore the soundness batch cardinality is `sum_r num_stripes[r]`, which depends on the committed round areas; it is not the packing width 32. The law is power batching, not independent affine batching.

The new WHIR loader does not pass `multilinear_batching` into `WHIRConfig`, and `WHIR` inherits the PCS default `False`, so the TOML flag is inert. With `power_batching = false`, soundcalc models the stronger independent-linear case while Ziren actually uses one challenge's powers. This overstates batching security and uses the wrong cardinality in any batch-dependent proof-size/error term.

Suggested review comment:

> `dense_batch = 32` is not Ziren's WHIR soundness batch size. Ziren defines `DEFAULT_BATCH_SIZE` as “purely a packing constant”; the WHIR prover then flattens every actual stripe from every commitment round and batches them as `1, lambda, lambda^2, ...`. Thus `t = sum_r num_stripes[r]` and this is power batching. Also, `multilinear_batching` is not passed to `WHIRConfig`, so that TOML flag is currently inert and `power_batching = false` selects soundcalc's independent-linear formula. Please derive `t` from the round stripe census and model the actual powers-of-lambda law.

### SC91-02 — High — `total = min(component_bits)` is not a composed soundness bound

`JaggedCircuit.get_security_levels` reports `all_levels["total"] = min(all_levels.values())`. Multiple possible failure events are conservatively composed by adding their error probabilities (the union bound does not require independence), not by selecting only the largest error. Equivalently, if component security levels are `s_i`, a conservative aggregate is `-log2(sum_i 2^-s_i)` unless a tighter joint argument is supplied. For the submitted Ziren schedule, the three WHIR query terms alone are approximately 100.08, 100.09, and 100.52 bits; their union bound is approximately 98.6 bits before adding batching, OOD, zerocheck, or lookup errors. Reporting the minimum as “100 bits” therefore overstates the composed claim.

Suggested review comment:

> The `total` line cannot be `min(component_bits)`: that keeps only the largest single error and drops all other failure events. Please aggregate in error space, e.g. `-log2(sum(2**(-s_i) for s_i in applicable_levels))`, or document and implement a tighter joint proof. On the submitted Ziren parameters, the three query-round terms alone compose to about 98.6 bits, although each is individually just above 100 bits.

### SC91-03 — High — The wrap LogUp model includes 16 grinding bits that Ziren does not execute

The wrap circuit sets `grinding_bits_lookup = 16`. Current Ziren's `GkrGrind` performs the 16-bit grind only for the inner KoalaBear `DuplexChallenger`. For every other challenger, explicitly including the outer/wrap BN254 `MultiField32Challenger`, the prover returns zero without observing a witness and the verifier accepts without checking one. Soundcalc therefore credits the outer LogUp term with a 16-bit reduction in error that the deployed protocol does not have.

Suggested review comment:

> The wrap section should not set `grinding_bits_lookup = 16`. Ziren's `GkrGrind` explicitly makes grinding a no-op for the outer BN254 `MultiField32Challenger`, and the matching verifier accepts without checking a witness. Crediting 16 bits here overstates the wrap LogUp soundness by up to 16 bits. Please set the outer value to zero (or change and verify the Ziren protocol first).

### SC91-04 — Medium — Explicit WHIR rate schedules are not validated at every round

The new `log_inv_rates` override checks its length, first value, and positivity, then validates two-adicity only for the initial rate. An arbitrary later override can request an interleaved FFT domain unsupported by the field. For each interleaved round `i`, the construction requires at least

`log_degrees[i] + log_inv_rates[i] - folding_factors[i] <= field.two_adicity`.

The submitted Ziren schedule `[2, 5, 8, 8]` with folding factors `[3, 6, 6]` passes the applicable checks, so this is an API-validity defect rather than a rejection of that schedule.

Suggested review comment:

> Once `log_inv_rates` can override the recurrence, validating only the initial domain is insufficient. A later rate may exceed the field's two-adicity even when entry 0 is valid. Please validate every interleaved round with `log_degrees[i] + log_inv_rates[i] - folding_factors[i] <= field.two_adicity` (and validate any separately committed final domain according to its construction).

### SC91-05 — Medium — The Ziren parameter provenance is not reproducible

The configuration says the census was generated “at the deployed revision” but does not record a Ziren commit, GPU commit, census artifact digest, or protocol-profile digest. This is material because the audited branch changed WHIR OOD enforcement, BaseFold transcript order, folding parameters, and recursion VKs during the review. A version string of `2.0` cannot establish which implementation the numbers describe.

Suggested review comment:

> Please replace “at the deployed revision” with the exact Ziren commit, paired `ziren-gpu` commit where relevant, census command/output digest, and a digest of every soundness-relevant profile. The current `version = "2.0"` is not enough to reproduce or audit these values, especially across transcript/VK-changing fixes.

Recommended position on PR #91: request changes. The WHIR plumbing and explicit rate-schedule support are useful, and the submitted rate sequence itself is consistent with Ziren, but the batch model, aggregate-security calculation, and outer LogUp grinding parameter materially overstate the claimed security.

## Code style, architecture, and source-derived performance review

This pass is source-only. It identifies concrete extra allocations, repeated scans, synchronization, and configuration duplication, but it does not attach percentage speedups without a benchmark. Recommendations that preserve the transcript and accepted language are separated from protocol-parameter changes, which require a new soundness analysis and regenerated artifacts.

### Design and maintainability findings

#### D-01 — Protocol configuration has multiple writable sources of truth

The host config in `crates/pcs/src/basefold/config.rs:147-199`, the circuit config in `crates/recursion/circuit/src/basefold_verifier.rs:39-120`, and the per-ring config in `crates/pcs/src/config.rs:224-237` independently encode rate, query count, PoW, folding arity, and domain size. The drift is already visible in comments: `BasefoldVerifierParams` still labels 4/100 as production defaults, and `BasefoldRing::fri_config` still documents the retired 1/94/16 profile while the implementation uses 2/124/16 with folding-log 3.

The environment override is more serious than documentation drift. Any accepted `ZIREN_BASEFOLD_LOG_BLOWUP` value returns `FriConfig::new(log_blowup, 100, 16)`, which also resets folding-log from 3 to 1, while the recursive production verifier remains hard-coded to 2/124/16 and folding-log 3. The comments themselves state that most override values do not survive recursion. A process-local environment variable should not silently select a different proof protocol.

Recommendation: define one immutable, serializable `BasefoldProtocolProfile` containing every transcript- and shape-relevant parameter; derive native prover, native verifier, recursive verifier, witness lift, and dummy shape from it. Bind a canonical profile digest into the VK/program cache key. Remove the production environment override or make it an explicit dev-only profile that cannot be confused with production.

#### D-02 — Transcript choreography is duplicated instead of represented as a protocol state machine

BaseFold transcript order and claim reduction are manually replayed in the prover, native verifier, and recursive verifier. ZR-20, ZR-24, and the now-repaired ZR-26 are three independent historical examples of one implementation omitting an event or equality present in another. Larger folding arity adds another Ziren-specific branch that SP1 v6.3.1 does not analyze.

Recommendation: introduce typed transcript phases and shared event helpers for claim absorption, batch grind, batching challenge, round message/commit observation, beta sampling, final polynomial, query grind, and query sampling. The prover and both verifiers should consume the same declarative schedule while supplying different actions. Add a transcript-trace differential test that records event tags and absorbed field elements for native prove, native verify, and recursive witness generation.

#### D-03 — Ring dispatch relies on runtime type erasure and ownership-sensitive unsafe casts

`crates/pcs/src/shard_level/verifier.rs:497-1100` combines `TypeId` gates, `Any` downcasts, `transmute_copy`, slice reinterpretation, and `Vec::from_raw_parts`. One cast handles a heap-owning Merkle cap through `ManuallyDrop` specifically to avoid a double free. These casts are locally explained, but the proof of safety is distributed across runtime branches and comments rather than encoded in types.

Recommendation: move conversion, commitment projection, challenger access, and PCS verification behind a sealed ring adapter with concrete associated types. Keep separate typed inner and outer entry points and share only a generic, safe verifier core. This should remove the `TypeId` gate and all ownership-relabeling casts from the verification path.

#### D-04 — Core modules and functions carry too many responsibilities

The production portions of `executor.rs` and `prover/src/lib.rs` are roughly 4,400 and 2,500 lines before their large test/probe sections. `verify_jagged_pcs_host` spans about 700 lines, `verify_logup_gkr_host` about 490, and `ZKMProver::compress` about 410. The repository also has 2,000-3,000-line PCS and witness modules, many `too_many_arguments` suppressions, a module-wide `allow(unused_variables)` in the recursive BaseFold verifier, and crate-wide lint suppressions in the prover.

Recommendation: split by invariant boundary rather than file length alone. Suggested units are geometry decoding/validation, transcript replay, opening authentication, ring adaptation, recursion witness conversion, key caching, and reduction-tree orchestration. Replace long argument lists with immutable context objects such as `JaggedVerifyContext` and `BasefoldProtocolProfile`; do not hide mutable challenger state inside those contexts.

#### D-05 — Legacy wire compatibility and verification errors are implicit

Several proof fields use `serde(default)` and interpret an empty vector as a legacy encoding. The same jagged verification layer returns `bool` and prints rejection details with `eprintln!`, forcing callers to collapse coverage, geometry, transcript, Merkle, and algebra failures into one string. Implicit empty-value versioning makes deletion, truncation, and old-format data difficult to distinguish.

Recommendation: add an explicit proof-format version with strict per-version shape decoding, and return a structured `JaggedVerifyError` with phase and index information. Logging belongs at the application boundary; the verifier library should be deterministic and side-effect free.

#### D-06 — Production comments contain stale specifications and incident history

Concrete examples include the 4/100 field documentation beside the actual 2/124/16 circuit profile, the retired 1/94/16 documentation in `BasefoldRing`, `Last-coordinate-first` immediately before code that deliberately folds the first remaining coordinate, and the `minimal_trace.rs` TODO claiming the memory oracle is unpopulated while current replay treats it as load-bearing. At reviewed revision `ab35b61f`, two multi-round jagged comments also stated that a round exactly filling whole stripes still commits one additional full stripe, whereas `next_multiple_of` leaves an exact multiple unchanged and the prover merely appends a zero-height padding column to stabilize the layout. Commit `e1401e19` corrects the `PackingMeta` explanation in `jagged_pcs.rs`; the parallel explanation in `shard_level/prover.rs` remains stale. The current `JaggedCommitGeneric` field documentation and several recursive BaseFold comments/tests also still describe a production stacking-height clamp that `pick_log_stacking_height` no longer performs. There are also duplicate lint attributes and multi-page incident/measurement narratives embedded in hot functions.

Recommendation: keep short invariant comments beside code, move benchmark tables and incident narratives to versioned ADRs, and add doc assertions that compare every exported production profile. Remove file-wide lint suppression and fix or narrowly annotate each remaining warning.

### Performance recommendations

| Priority | Opportunity | Source evidence and cost mechanism | Recommended change | Validation gate |
|---|---|---|---|---|
| P0 | Wire the recursion proving-key cache into `compress` | `RecursionPkCache` has measured motivation and public `get/insert` helpers at `prover/src/lib.rs:330-423,885-915`, but a repository-wide call search finds no hot-path use of either helper. Every compression node calls `compress_prover.setup(&program)` at line 1996. | Key by `setup_digest(program)`; use cached `Arc<(pk,vk)>` on a hit; on a miss, coordinate one builder per key with a per-key `OnceLock` or equivalent before publishing. Budget eviction by bytes, not only entry count, because comments place individual keys in the hundreds of MiB. | Report hit/miss/build/wait counts, setup wall time, peak RSS, and duplicate builds on repeated blocks. Preserve identical VK hashes. |
| P0 | Fuse BaseFold batching into one tiled pass | `basefold/prover.rs:320-357` launches two full `par_iter_mut` accumulator scans for every MLE/codeword pair. For `M` inputs and `N` rows, input reads remain `O(MN)`, but accumulator read-modify-write traffic and Rayon dispatch also repeat `M` times; the source comment gives examples as large as 67 million codeword rows per pair. | Flatten coefficient/matrix descriptors once, then parallelize by row tiles. Each worker computes all input contributions for its row range and writes each accumulator slot once. Keep the evaluation-claim scalar reduction in the same descriptor walk. | Benchmark 1, 4, 16, and production-width polynomial batches; collect memory bandwidth, Rayon task count, wall time, and byte-identical proof output. |
| P0 | Remove per-query recursive BaseFold block cloning and selection vectors | `basefold_verifier.rs:1283-1291` clones every round block for every query. Lines 1458-1472 then clone the block again and allocate `lo`, `hi`, and selected vectors at every arity level; line 1521 allocates another flattened leaf vector. These are host circuit-builder allocations, not proof constraints. | Borrow blocks directly from the proof. Pass slice iterators to `select_chain_ef` instead of materializing `lo/hi`, reuse one small work buffer, and hash fixed-width leaf limbs without an intermediate heap vector. Consider SP1 v6.3.1 style round-major traversal so all queries for one commitment are processed together. | Compare emitted instruction stream, constraint count, build wall time, allocation count/bytes, and peak RSS. The generated program and accepted language must be unchanged. |
| P0 | Parallelize jagged prefix checks at chip-sized granularity without expanding row counts | `recursive_jagged_pcs.rs:386-410` expands one row-count handle per column and emits a serial dependency chain. The comment correctly rejects one parallel block per column after a measured 6.8 GB allocation failure, but the same invariant can be written as independent local equations between adjacent prefix handles. | Stream nested row/column ranges without `repeated_row_counts`. Express each link as `prefix[i+1] = prefix[i] + height[i]`, plus the initial-zero and terminal-area equations. Group chips into at most about 64 IR blocks, following the existing chunked pattern in `compress_basefold.rs:1189-1306`. | Require identical honest and adversarial outcomes, the same algebraic link count, bounded block count, lower builder allocations, and improved recursion-runtime utilization. |
| P1 | Shrink the recursion IR representation and make reservation shape-aware | `recursion/compiler/src/ir/builder.rs:28-36` documents `DslIr` at about 680 bytes and a 10-million-op top-level reservation, or 6.8 GB of virtual address space per builder. Per-item parallel blocks have already caused multi-gigabyte allocation failures. | Box or arena-store large enum payloads, represent operands by compact IDs, and reserve from a cached shape/program-size estimate instead of a universal 10 million. Longer term, add safe CSE/DCE so callers do not manually hoist repeated expressions throughout circuit code. | Measure `size_of::<DslIr>()`, allocated/retained bytes, peak RSS, compile wall time, and exact program equivalence. |
| P1 | Remove mutex-wrapped standard channels from the compression pipeline | `ZKMProver::compress` wraps every `SyncSender` and every receiver in `Arc<Mutex<_>>`. Senders are already cloneable; a blocking send/receive occurs while holding the wrapper lock, serializing queue access and complicating shutdown. | Use cloned `SyncSender` values immediately, or switch the full pipeline to a cloneable bounded MPMC channel such as crossbeam. Preserve bounded backpressure and make channel closure the termination signal. | Record queue wait time, worker idle time, throughput, and shutdown behavior under 1, 2, 4, and production worker counts. |
| P1 | Share replay streams instead of cloning them per shard | `tracing_vm.rs:171-188` clones each chunk hint window and clones the complete proof stream into every replay worker. The program and memory oracle already use `Arc` specifically to avoid this pattern. | Store immutable input/proof streams as `Arc<[... ]>` with per-worker cursor/range metadata; make chunk windows cheap shared slices. | Measure bytes cloned and peak RSS on workloads with hints and deferred proofs; retain byte-exact replay. |
| P2 | Reuse BaseFold fold-domain twiddles | `basefold/fri.rs:190-204` allocates, fills, and bit-reverses `halve_inv_powers` on every fold level and every proof. | Cache immutable tables by log-domain size in the prover, or generate the bit-reversed powers directly into a reusable buffer. Bound cache memory and share tables across shards. | Benchmark separately because field multiplication versus memory traffic and cache size can reverse the win. |
| P2 | Replace per-group jagged verifier copies with borrowed views | `jagged_pcs.rs:1672-1696` clones chip metadata, every row point, every claim vector, optional opened values, and offsets before verifying each group. The dominant production shape is often one group, where all copies are avoidable. | Introduce `JaggedPackingRef` and membership-indexed iterators; let reduction/opening verification consume borrowed views. | Track allocation bytes and host verification wall time for large chip counts and multi-group proofs. |

### Performance guardrails and implementation order

Do not tune `log_blowup`, query count, PoW, or folding arity as ordinary performance knobs. They change security, proof shape, transcript order, and verification keys; Ziren folding-log 3 is also outside the SP1 v6.3.1 analyzed protocol. Optimize data movement and circuit construction first.

Recommended order:

1. Instrument and connect the existing proving-key cache, with duplicate-build suppression and an RSS budget.
2. Fuse BaseFold batching and add proof-byte differential tests.
3. Remove recursive query allocations and implement chip-chunked prefix checks while asserting identical generated programs/constraints.
4. Replace mutex-wrapped channels and share replay streams.
5. Redesign the large IR representation only after the above metrics show circuit build memory remains a dominant limit.
6. Evaluate twiddle caching and borrowed jagged views as profile-driven follow-ups.

## Test and CI gaps

- ZR-27 has no proof-boundary regression that mutates `log_stacking_height` to 0, 2, 20, 22, `usize::BITS`, or `u32::MAX` and requires a typed rejection without panic. There is also no direct-call test requiring the public multi-round open helpers to reject empty and mixed-height round slices. If alternate non-production profiles remain supported, each needs an explicit profile/two-adicity test rather than a proof-selected height.
- The `ab35b61f` jagged multi-round guards have no focused regression for mixed WHIR/BaseFold rounds, inconsistent BaseFold round stacking heights, inconsistent WHIR round stacking heights, or disagreement among one round's `commit`, `prover_data`, and `whir_data` area/height fields. The last case is not currently rejected.
- ZR-03 now has optional-`ark` proof/VK all-prefix truncation tests and a hostile-`num_k` regression in addition to the default-loader malformed-input tests. Add an explicit `cargo test -p zkm-verifier --features ark` CI job so the non-default implementation and these regressions are compiled continuously.
- Outer-ring jagged BaseFold has no negative tests substituting the raw main commitment, preprocessed commitment, packing geometry, or `y_per_chip` independently of shard openings.
- Recursive BaseFold has no production-circuit negative test that mutates `batch_evaluations`, a sumcheck message, the evaluation point, the terminal polynomial, or an authenticated cross-round FRI leaf; its host-shape helper tests do not exercise the production constraint emitter. The ZR-24 WIP also lacks an honest two-round outer test that distinguishes `[preceding/preprocessed, main]` commitment order and checks every component Merkle path before the query chain.
- The ZR-26 repair has no focused adversarial regression that replays the old post-challenge correction-vector attack, and there is no typed transcript-trace differential across host prove, host verify, recursion circuit, and GPU prove. Existing E2E roundtrips can detect some current desynchronization but do not pin the security-critical event order against future drift.
- Native WHIR has no differential test requiring proof OOD-answer counts to match `WhirConfig`, and there is no native-versus-recursive acceptance parity suite.
- BaseFold now has focused zero/Boolean-coordinate roundtrips for folding arities 1 and 2 (`385188b2`); retain these as the ZR-22 regression and extend them if additional folding arities become production-supported.
- Replay tests now cover fail-closed exhaustion and surplus rejection. Reordered/corrupted oracle contents and multi-chunk differential replay remain uncovered.
- Artifact installation now tests honest extraction, truncated archives, parent/absolute traversal, symlink escape, and special entries. It still lacks an HTTP error-server integration test, hard-link cases, concurrent installers, manifest validation, and digest/signature verification.
- Network timeout and builder-field behavior are not tested.
- CUDA RPC regressions now cover an unavailable server, a malformed endpoint, and an undecodable response. Retain those tests; the separate network client would still benefit from explicit unknown-enum, malformed-JSON, and version-skew fixtures.
- The recursion runtime has no adversarial tests for overlapping parallel memory accesses or forged analyzed offsets/event counts; its existing tests exercise only valid compiler output.
- The ZR-15 guards have no public-entry regression for empty, short, or overlong public-values vectors, and the underlying slice `Borrow` remains infallible.
- ZR-16 now includes adversarial reordered, gapped, overlapping, and out-of-range-entry multi-segment tests in addition to stripped/truncated ELF coverage. Retain these as loader security regressions.
- Cycle tracking now tests duplicate, non-LIFO, unknown, and nested scopes plus report aggregation; warning emission and end-of-execution unclosed-scope diagnostics are not directly asserted.
- `cargo fmt --all -- --check` failed at the earlier validation snapshot and was not rerun after the later cleanup commits.
- The undeclared `profiling` warning is fixed in `4da2cb35`, and `90f2f74a` targets the remaining `zkm-pcs` warnings. A full workspace `clippy -D warnings` gate was not rerun in this source-only update.

## Recommended priority

1. Stop relying on the outer jagged BaseFold host verifier until ZR-23 and ZR-24 are fixed and adversarial tests prove that raw commitments, verifying-key commitments, trace openings, and every cross-round FRI value are mutually bound. Do not merge WIP `75fab083` until the outer lift carries `[preceding_roots..., main_root]`, each preceding root is rebound to the VK, the honest two-round circuit passes, and the 2^25/2^26 constraint-headroom decision is explicit.
2. Bind the production native verifier to the fixed stacking-height profile before any derived computation, harden generic profile arithmetic, enforce empty/mixed-round checks at the reusable opening layer, and add native/recursive acceptance-parity tests (ZR-27).
3. Land Ziren `8714d6ea` and `ziren-gpu` `e9e27800` atomically, regenerate/version every affected recursion VK and program artifact, reject mixed profile digests, and add the ZR-26 attack and four-way transcript-trace regressions.
4. Keep ZR-03 and ZR-18 closed by compiling/testing the optional `ark` feature in CI and retaining the CUDA malformed-boundary regressions; separately replace the ZR-15 low-level infallible public-values cast with a fallible layout conversion.
5. Retain the ZR-16 ELF virtual-layout, invalid-entry, size-limit, and checked-fetch regressions.
6. Retain ZR-10's default digest requirement and explicit mutable-image development opt-in. Separately add digest/signature or manifest authentication for downloaded circuit artifacts while preserving the ZR-01/ZR-08 containment and atomic-install fixes.
7. Retain the ZR-02 runner guard, ZR-04 arithmetic parity regression, ZR-05 fail-closed replay tests, ZR-12 real hint-seam regression, ZR-14 cache invariant, ZR-17 explicit test-CA boundary, ZR-19 scope-stack tests, ZR-21 WHIR shape checks, and ZR-22 chosen-point tests.
8. Rerun the repository formatting and full workspace `clippy -D warnings` gates after the concurrent cleanup commits.

---

# Paper Pre-Submission Review

Date: 2026-09-19  
Scope: `docs/paper/main.tex`, all active section and figure sources, the generated 36-page `main.pdf`, bibliography output, and the current comparison set of SP1, OpenVM, ZisK, and Jolt  
Method: five-dimension supervisor-style review covering macro logic, writing, grammar, LaTeX, and figure quality  
Review mode: source and compiled-artifact inspection only; no paper source was modified during this review

## Review summary

**Score: 3/10 — Major Revision; do not submit the current version.**

| Severity | Count |
|---|---:|
| Critical | 3 |
| Major | 6 |
| Minor | 7 |

The three submission-blocking repairs are:

1. Define whether the public relation proves only executions with exit status zero, and make the relation, completeness claim, emulator behavior, and arithmetisation agree.
2. Make the cross-shard elliptic-curve encoding a well-defined function and state a quantitative security assumption for it.
3. Regenerate keys, proofs, proof-size measurements, and end-to-end performance data under the corrected Poseidon2 schedule.

The paper is unusually candid about its limitations and already contains useful component-level protocol detail. The blocking issue is not presentation alone: several headline claims currently exceed the relation, assumptions, verification coverage, or experimental evidence actually established by the manuscript.

## 1. Macro logic and technical soundness

### PR-01 — Critical — The public relation admits executions that the arithmetisation cannot prove

The informal theorem and public-relation section both state, “Honest executions produce accepting proofs” (`docs/paper/sections/01_introduction.tex:16,58`). The relation exposes an arbitrary exit status `e`. In contrast, the verification section states:

> The single exception halts with a non-zero exit code, which the emulator accepts and the arithmetisation does not admit as a valid execution to prove.

(`docs/paper/sections/075_verification.tex:15`)

The advertised completeness statement is therefore false as written. Either the public relation must require `e = 0`, with all completeness claims narrowed to successfully terminating executions, or the AIR must support the non-zero exits admitted by `Emulate`.

### PR-02 — Critical — The cross-shard digest encoding is not a function of the claimed message

The AIR section says:

> the message is the x-coordinate, up to a prover-chosen byte offset ... that makes the cubic have a root

and later argues that “the message and the offset are recoverable from the point” (`docs/paper/sections/04_air.tex:98-114`). The security statement nevertheless uses the notation `enc(m_i)`. If the offset is prover-chosen and is not part of `m`, `enc(m)` is multivalued. Injectivity of `(m, offset)` does not by itself define an injective function of `m`.

The paper should either enforce a canonical offset, such as the smallest admissible offset, including the corresponding AIR constraints, or formally define the encoded domain as `(m, offset)` and prove that equality of encoded multisets implies equality after projecting away the offsets. Assumption 5.4 must then quantify the adversary, allowed messages/offsets, query budget, security parameter, and error probability. The current unquantified `epsilon_digest` term is not sufficient for a theorem-level soundness claim.

### PR-03 — Critical — The evaluated proofs do not instantiate the protocol described by the corrected paper

The research question asks whether the prover is competitive with RISC-V systems (`docs/paper/sections/01_introduction.tex:9`). The manuscript then states:

> All timings predate the Poseidon2 round correction ... they are not measurements of the corrected release.

(`docs/paper/sections/01_introduction.tex:21`)

The threats-to-validity section further explains that the correction invalidates the corresponding keys and proofs (`docs/paper/sections/08_performance.tex:160`). Consequently, the paper has no corrected-release end-to-end time, proof size, or proof artifact supporting its principal systems claim.

Rerun at least one full block with the corrected 8+20 schedule and publish the matching Ziren revision, GPU revision, configuration digest, keys, proof, verification result, raw per-run timings, and hardware/software environment. Pre-correction measurements may remain as historical ablations, but they cannot establish final-system throughput or proof size.

### PR-04 — Major — Lookup multiset equivalence is stated as deterministic when it is probabilistic

The preliminaries say:

> because multiplicities stay small, the fraction identity ... is equivalent to this multiset equality

(`docs/paper/sections/02_preliminaries.tex:24`)

Small multiplicities prevent counter wraparound in the base field. They do not eliminate collisions in random tuple compression or evaluation at sampled challenges. The text should separate these facts and state the lookup implication with its Schwartz-Zippel/fingerprint error rather than calling it unconditionally equivalent.

### PR-05 — Major — “The constraint system is itself verified” overstates the reported coverage

The introduction asks for a constraint system that “is itself verified” (`docs/paper/sections/01_introduction.tex:9`). The actual result closes 17 of 106 generated obligations, while 22 are open, 41 are not attempted, and 26 are unfinished; the recursion machine is outside the extraction (`docs/paper/sections/075_verification.tex:32`). The manuscript also relies on an unproved real-row-exhaustiveness premise.

Unless coverage is substantially expanded, the title-level and contribution-level language should consistently describe “a verification workflow with partial theorem coverage,” not a verified constraint system. The abstract, introduction, theorem discussion, and conclusion should all use the same scope.

### PR-06 — Major — The comparison table is not versioned and misses the closest current design overlap

The table describes OpenVM as “FRI (Plonky3)” and Jolt as “multilinear PCS” (`docs/paper/sections/01_introduction.tex:122-133`). Current OpenVM SWIRL explicitly combines stacked WHIR with LogUp interaction reductions, making it directly relevant to Ziren's central Jagged-over-WHIR design. Current Jolt documentation describes Dory as the default PCS backend and Akita as a lattice-based alternative.

Every comparison row should name a version, commit, or retrieval date. The revised comparison should directly contrast Ziren and SWIRL on stacking, LogUp reduction, WHIR scheduling, field choice, and soundness accounting. It should also cover the current formal-verification status of SP1, OpenVM, and Jolt because verification is one of the paper's comparison axes.

Relevant current primary sources:

- OpenVM SWIRL: <https://openvm.dev/swirl.pdf>
- OpenVM formal verification: <https://github.com/openvm-org/openvm-fv>
- SP1 implementation: <https://github.com/succinctlabs/sp1>
- SP1 Lean verification: <https://github.com/succinctlabs/sp1-lean>
- JoltBook: <https://jolt.a16zcrypto.com/>
- Jolt formal verification: <https://eprint.iacr.org/2024/1841>
- ZisK implementation: <https://github.com/0xPolygonHermez/zisk>

### PR-07 — Major — The reported 28% improvement is confounded

The introduction attributes `-28%` to “the lookup circuit's layer order” (`docs/paper/sections/01_introduction.tex:21`). The performance section instead states that both LSB pairing and doubled shard size are enabled and reports “-28% for the pair” (`docs/paper/sections/08_performance.tex:119`). The current experiment cannot assign the combined improvement to layer order.

Add a 2-by-2 ablation covering old/new pairing and old/doubled shard size. If one combination fails because of memory pressure, report that failure separately. Until that experiment exists, describe the result only as a combined configuration change.

## 2. Writing and organization

### PR-08 — Minor — Contributions arrive after too much technical and evaluative material

“The paper makes four scoped contributions” appears only after the theorem, protocol explanation, headline performance table, verification result, and two figures (`docs/paper/sections/01_introduction.tex:96`). A full Open Problems subsection then appears before related work and before the method sections.

Move a compact contribution list immediately after the research question and prior work gap. Move Open Problems to a discussion section near the conclusion. This will make the introduction follow motivation, gap, approach, contributions, results, and scope in that order.

### PR-09 — Minor — “Byte-identical transformation” contradicts the reported record changes

The performance section says that each change “is a byte-identical transformation of the record” (`docs/paper/sections/08_performance.tex:25`), while the accompanying table removes fields and changes record widths. The intended claim appears to be semantic or witness equivalence, not byte identity.

Replace the phrase with “preserves the represented execution semantics” or “is witness-equivalent,” and identify which layouts and verifying keys change.

### PR-10 — Minor — A performance-table value is missing its unit

Table 4 presents the `events/shard` row as approximately `1000 -> 462 MB` (`docs/paper/sections/08_performance.tex:37`). The old value lacks the same unit as the new value, and the metric name is easy to confuse with an event count.

Write `1,000 MB -> 462 MB` and separate metric, value, and unit into distinct columns.

## 3. English grammar

### PR-11 — Minor — Inconsistent tense in the abstract

The sentence “It closes 17 of 106 ... and found a genuine ...” (`docs/paper/main.tex:125`) mixes present and past tense under one subject. This violates the review's G3 tense-consistency rule.

Use either “It closes ... and identifies ...” or “It has closed ... and has found ...”.

### PR-12 — Minor — Nonparallel predicates obscure the comparison limitation

The sentence below has nonparallel coordination:

> The direct evidence is limited to historical dashboard context against ZisK, uses different proof conditions and is not a same-hardware external baseline.

(`docs/paper/sections/08_performance.tex:155`)

This violates G4, which requires a clear main clause and parallel connections. Suggested replacement:

> The only direct evidence is historical dashboard context against ZisK. That comparison uses different proof conditions and is not a same-hardware baseline.

## 4. LaTeX and formatting

### PR-13 — Major — The defects table floats into the References section

The appendix begins the defects table with `\begin{table}[t]` (`docs/paper/sections/appendix_ipcore.tex:53`), and the bibliography follows immediately after the appendix input. In the compiled PDF, the “References” heading appears before Table 9, and the table then interrupts the bibliography.

Insert `\FloatBarrier` or `\clearpage` before `\bibliography`, or place this large appendix table on a dedicated float page and still clear pending floats before the references.

### PR-14 — Minor — Bibliography warnings remain in the submission build

`docs/paper/main.blg` reports an empty `booktitle` for `plookup` and reports that `lund1992algebraic` and `barrington1989bounded` use both volume and number fields in incompatible entry types.

Encode the journal papers as `@article`. Give `plookup` a correct proceedings entry or use an appropriate `@misc`/online entry. Rebuild until BibTeX is warning-free.

Positive formatting checks: the inspected build has no undefined references or citations and no overfull boxes. Numbered equations are labeled and referenced. The figures are vector-generated rather than embedded raster images. Venue template, page-limit, and bibliography-style compliance cannot be judged until a target venue is named.

## 5. Figure quality

### PR-15 — Major — Figure 4 is not legible at normal page scale

`docs/paper/figures/frame.tex` combines three units, four state boxes, two long bus tuples, internal equations, access pins, and a sub-cycle ruler in a roughly twenty-unit-wide TikZ canvas. Scaling that canvas to text width makes labels such as the fetch tuple, memory tuple, and unit equations too small to read in the compiled PDF.

Split the figure into two panels: one for state/program/memory flow across instructions, and one enlarged unit showing the four access positions. Move long tuples and detailed equations to the caption or body. Target a final printed label size of at least approximately 8 pt.

### PR-16 — Minor — “Deployed stack” is misleading for invalidated historical data

The scaling figure labels one curve “420 M-cycle block, deployed stack” (`docs/paper/figures/scaling.tex:18`). The paper elsewhere explains that all curves use the pre-correction schedule and no longer correspond to valid corrected-release keys or proofs.

Rename the curve “historical pre-correction stack” and state in the caption that none of the plotted throughput values measures the corrected release.

## Full banned-language and punctuation scan

The scan covered `main.tex`, every active file under `docs/paper/sections`, all active TikZ figure sources, `references.bib`, and the generated `main.bbl`.

- No banned AI-tone vocabulary was found in author-written paper prose.
- No Unicode em dash was found in author-written paper prose.
- Triple hyphens occur only in source comments, table placeholders, and preserved bibliography titles.
- `general-purpose` occurs only in an unused bibliography title and is not an author-prose finding.

## Submission recommendation

**Major Revision; do not submit the current version.**

A new submission-readiness review should be run after all three Critical findings are repaired. That review should require:

1. one internally consistent public relation and completeness theorem;
2. a functional and quantitatively stated digest encoding assumption;
3. a corrected-release proof artifact and performance run;
4. an unconfounded lookup-layer/shard-size ablation;
5. a versioned four-system comparison including OpenVM SWIRL; and
6. a clean PDF in which Figure 4 is legible and no appendix float enters the references.

---

# Current-Revision Implementation, Protocol, Soundness, and Performance Follow-Up

Date: 2026-09-19  
Revision reviewed: `feb3d1481358bd091aa210991d0d7bf5e8b2ec84` (`feat/upgrade-plonky3`)  
Scope: current Ziren source, with emphasis on the jagged reduction, WHIR/BaseFold IOPP paths, native/recursive verifier parity, cross-shard digest constraints, proof-boundary totality, and prover memory/time costs  
Method: manual algorithm and source review plus focused local tests. The Flounder CLI was not installed in this workspace, so no Flounder run or execution-backed Flounder confirmation is claimed in this section.

## Executive conclusion

The current revision contains meaningful repairs: the main commitment is rebound to the opening, preprocessed geometry is rebound to the verifying key, jagged column claims are linked to the shard openings, optional arkworks parsing is bounds-checked, ELF virtual placement is validated, and CUDA RPC failures are returned instead of unwrapped. The recent `eq_mle_table`, trace-evaluation, and codeword-ownership optimizations are algebraically correct in the reviewed source.

The proof stack is not yet ready for a 100-bit production claim. Two coupled Critical issues remain open in the production outer-recursion path, and this pass found two additional soundness issues:

| ID | Severity | Status | Summary |
|---|---|---|---|
| ZR-23 | Critical | Open in outer recursion; native host and inner lift fixed | The outer/gnark lift does not carry the real preceding raw roots in proof round order or bind their projected, geometry-bound commitments to the VK. It instead constructs `[main, zero, ...]` and sets modified commitments equal to originals. |
| ZR-24 | Critical | Confirmed open | The outer recursive BaseFold witness still drops component openings, so the first FRI query value is not authenticated to the original round commitments. |
| ZR-28 | High | Algebraically confirmed; attacker reachability not demonstrated | The global-digest chord equations become identically zero on a doubling step and allow the running digest to jump to any on-curve point. |
| ZR-29 | High | Confirmed configuration/accounting mismatch | The outer/wrap LogUp-GKR grind is a no-op, while `ziren.soundcalc.toml` credits it with 16 bits. The checked-in 100-bit report therefore does not describe the implemented wrap transcript. |
| ZR-27 | Medium | Partially fixed | Non-production stacking heights are eventually rejected, but the main host verifier performs proof-selected shift/rounding arithmetic before reaching that guard. |

Evidence labels in this section are deliberate. “Confirmed” means the relevant acceptance path or polynomial identity was traced in the current source. It does not mean that an end-to-end malicious proof was generated. ZR-28 in particular has a confirmed algebraic underconstraint but no demonstrated way to force the exceptional point from all other AIR constraints.

## Remediation re-check

| Prior item | Current disposition | Evidence |
|---|---|---|
| ZR-03, optional arkworks parser totality | Fixed at source level | `crates/verifier/src/groth16/ark_converter.rs:235-294` uses checked fixed-size reads and checked count/offset arithmetic. All-prefix proof/VK truncation and hostile-count regressions are present at lines 307-349. |
| ZR-10, mutable default CUDA image | Fixed at source level | `crates/cuda/src/lib.rs:266-302` rejects a mutable image reference by default and requires explicit `ZKM_ALLOW_MUTABLE_GPU_IMAGE=1` opt-in; pull failures are errors at lines 313-331. |
| ZR-16, ELF virtual-address placement | Fixed at source level | `crates/core/executor/src/program.rs:110-223,268-284` validates load sizes/address bounds, sorts and places segments by virtual address, rejects overlaps/gaps/missing-exec/out-of-range-entry/oversized-image cases, and bounds-checks fetch. The named adversarial regressions are at lines 583-685. |
| ZR-18, CUDA RPC unwraps | Fixed at the untrusted RPC boundary | The setup/core/stateless/compress/shrink/wrap calls in `crates/cuda/src/lib.rs:410-535` map transport and codec errors. Unavailable-server, malformed-endpoint, and undecodable-response regressions are at lines 626-690. Environment configuration still intentionally fails fast, but remote response failures no longer panic. |
| ZR-23, jagged commitment/opening cross-binding | Open in outer recursion; fixed in the native host and inner lift | `crates/pcs/src/shard_level/verifier.rs:596-628,1054-1157` contains the native main-root, opened-claim, and preprocessed-root/VK binds. The inner lift correctly constructs `[preceding..., main]` raw and modified vectors at `crates/recursion/circuit/src/shard_level_witness.rs:2111-2127`. The distinct outer/gnark lift still constructs `[main, zero, ...]` and clones it as the modified vector at lines 1419-1438; its dispatch does not receive the already-computed `preceding_commitments`. Thus the outer recursive equivalent of the ZR-23 bind remains open. |
| ZR-24, recursive first-query authentication | Still open on the production outer path | `read_basefold_proof_outer_from_stream` still constructs `component_openings: Vec::new()` at `crates/recursion/circuit/src/basefold_witness.rs:646-702`. The verifier only recomputes and Merkle-authenticates `initial_eval` when that vector is nonempty (`basefold_verifier.rs:1321-1417`) and explicitly records the check as inert on the outer path at lines 1471-1484. |
| ZR-27, stacking-height binding | Partially fixed | `verify_one_jagged_group` and `verify_jagged_basefold_inner_generic` reject a non-default height at `crates/pcs/src/jagged_pcs.rs:1798` and `:2086`. The public host verifier first consumes the proof height at `crates/pcs/src/shard_level/verifier.rs:737,814,1088-1090`; `committed_dense_len` performs `1usize << log_stacking_height` at `crates/pcs/src/jagged.rs:218-225`. |

### ZR-23 / ZR-24 focused re-review — both remain open and must land atomically

This focused source and algorithm review was repeated at `feb3d1481358bd091aa210991d0d7bf5e8b2ec84`. The only intervening commit after the previous baseline changes the BaseFold blowup override; it does not touch either finding. Flounder is not installed in this workspace, so the conclusions below are manual source-level confirmations, not execution-backed exploit confirmations.

The producer and native verifier use one unambiguous round order. `prove_jagged_basefold_rounds_generic` receives preceding/preprocessed rounds first and the main round last, stores the earlier raw roots in `bundle.preceding_commits`, and stores the last round in `bundle.commit` (`crates/pcs/src/jagged_pcs.rs:1276-1591`). `BasefoldVerifier` then zips the same per-round component openings with the commitment vector (`crates/pcs/src/basefold/verifier.rs:138-278`). The required recursive vector is therefore:

```text
original_commitments = [preceding_raw_roots..., main_raw_root]
component_openings[r] authenticates against original_commitments[r]
project(main_raw_root) = transcript-observed main commitment
hash_bind(project(preceding_raw_root[r]), geometry[r]) = VK commitment[r]
```

The inner recursion lift implements its ring's corresponding raw/modified construction at `crates/recursion/circuit/src/shard_level_witness.rs:2111-2127`. The outer/gnark lift is a separate implementation and still constructs `original_commitments = [main_root, zero, ...]`, then clones it into an otherwise inert `modified_commitments` vector at lines 1419-1438. Although `verify_wrap_basefold_core` computes the preprocessed `(raw, modified)` pair at `crates/recursion/circuit/src/machine/wrap_basefold.rs:254-261`, its `OuterBundle` dispatch at lines 319-375 does not pass that pair into the outer lift. Nor does the outer lift constrain the witnessed BN254 main root's KoalaBear projection to the main commitment observed in the shard transcript. These are the remaining outer-recursive ZR-23 defects.

Current `HEAD` masks that ordering defect by deleting all outer component openings. `read_basefold_proof_outer_from_stream` returns `component_openings: Vec::new()` and its writer emits none (`crates/recursion/circuit/src/basefold_witness.rs:646-746`). Consequently the recursive verifier takes its fallback initial value from the first FRI block and skips every selected-value equality at `crates/recursion/circuit/src/basefold_verifier.rs:1331-1417,1436-1484`. The authenticated commit-phase blocks and terminal polynomial can therefore be individually consistent without being linked to one another or to the originally committed component polynomials. This confirms ZR-24 as a current soundness failure at the algorithm/constraint level.

WIP `75fab083` writes and reads the missing component leaves and Merkle paths, but changes no commitment construction. With that WIP, `component_openings[0]` belongs to the preceding/preprocessed round while `commitments[0]` is the main root. The first `HV::assert_digest_eq` must therefore reject an honest two-round proof. This is a completeness failure introduced by applying the ZR-24 transport patch without the ZR-23 ordering/VK-bind patch; it is not evidence that the leaf hash is wrong. Disabling the later FRI selected-value equality cannot affect this earlier Merkle-root mismatch.

The safe patch boundary is therefore atomic:

1. witness every `bundle.preceding_commits` raw root plus the main raw root, in `[preceding..., main]` order;
2. constrain the main BN254 root's KoalaBear projection to the transcript-observed main commitment, and project/re-bind every preceding root and its committed geometry to the corresponding VK commitment inside the outer circuit rather than trusting proof-carried roots;
3. carry all outer component leaf values and Merkle paths as witness data and require exact round/query/path shapes;
4. make the component-to-first-FRI and every later FRI selected-value equality unconditional for the production outer proof shape; and
5. reject any mismatch among commitment count, component-opening rounds, batch-evaluation rounds, and configured opening rounds before indexing.

Do not merge `75fab083` alone. A code-only repair can be prepared and reviewed independently, but activating these Merkle paths and equalities changes the outer constraint system. Release closure requires regenerated recursion programs/VKs and `vk_map`/`vk_root`, plus new circuit-specific Groth16 setup material and verifier artifacts under the repository's documented trusted-setup process. The published artifact cannot remain valid for the changed circuit.

Required regression gate: an honest two-round outer proof with distinct preceding and main roots must pass; swapping the two roots or independently mutating the preceding leaf/path, main leaf/path, geometry/VK binding, first FRI block, or any later selected FRI value must fail. Old-circuit/new-proof and new-circuit/old-proof artifact combinations must also fail explicitly rather than falling through a compatibility path.

### ZR-24 — Critical — Outer recursion still accepts an unauthenticated first BaseFold query value

The recursive verifier now contains the correct binding logic when `component_openings` is populated:

1. recompute the batched initial codeword value from the opened component leaves;
2. authenticate those leaves against every original round commitment;
3. assert that the selected value in the first folding block equals that authenticated value; and
4. continue the ordinary round-to-round FRI chain.

The outer witness reader deletes precisely the data required by steps 1 and 2. With an empty vector, `initial_eval` falls back to `blocks[0][0]`, and every selected-value equality is skipped. Later block Merkle paths authenticate each block to its own commit-phase root, but no equality proves that adjacent blocks belong to one folding chain or that its start is the batching of the preprocessed and main polynomials committed by the shard.

Required repair:

- write and read outer component leaf values and Merkle paths as witness data;
- authenticate every original round root, in `[preprocessed..., main]` order;
- remove the empty-vector fallback from production profiles;
- add a two-round outer negative test that independently mutates a component leaf, its path, the raw preprocessed root, the main root, and the first FRI block value; and
- measure the resulting constraint count and ptau headroom. Do not replace witness data with approximately 25 MB of program constants merely to make the current branch execute.

### ZR-28 — High — Incomplete curve-addition constraints collapse on doubling

For current sum `P1`, event point `P2`, and claimed next sum `P3`, the AIR enforces the two chord identities implemented by `SepticCurve::sum_checker_x/y`:

```text
Cx = (x1 + x2 + x3) (x2 - x1)^2 - (y2 - y1)^2
Cy = (y1 + y3) (x2 - x1) - (y2 - y1) (x1 - x3)
```

`GlobalAccumulationOperation::eval_accumulation` asserts `Cx = 0` and, on real rows, `Cy = 0` (`crates/core/machine/src/operations/global_accumulation.rs:163-191`). It separately checks that the current and next running digests lie on the curve.

When `P2 = P1`, both coordinate differences are zero. Consequently `Cx = Cy = 0` for every `P3`; the only remaining restriction is that `P3` is on the curve. The honest trace generator does not have this behavior: `SepticCurveComplete::add` takes the doubling branch at `crates/pcs/src/septic_curve.rs:198-216`. Native witness generation therefore computes the correct double while the AIR accepts an arbitrary on-curve successor at the same event.

This is an algebraic underconstraint. A complete forged execution still needs a reachable interaction encoding whose point equals the running sum; that preimage/reachability step was not demonstrated in this pass. The paper currently says a trace reaching doubling “fails the addition identities” (`docs/paper/sections/04_air.tex:100`), which is the opposite of the implemented polynomial behavior.

Required repair: implement complete addition constraints, including a sound doubling branch and the point-at-infinity representation. If the design instead relies on exceptional additions being unreachable, enforce `x2 - x1 != 0` with an inverse witness on every real row and state a separate quantitative reachability assumption that covers every prover-admissible `(message, offset)` encoding. The current “no reachable vanishing combination” assumption does not by itself prove this local denominator is nonzero.

### ZR-29 — High — The wrap soundness report counts grinding that the protocol does not perform

The shared constant is 16 bits, and the inner challenger really grinds. The outer/wrap implementations deliberately do not:

- host: `GkrGrind::gkr_grind` returns `F::ZERO` for a non-inner challenger and `gkr_check_witness` accepts without changing the transcript (`crates/pcs/src/logup_gkr.rs:27-79`);
- circuit: `MultiField32ChallengerVariable::gkr_check_witness` is an explicit no-op (`crates/recursion/circuit/src/challenger.rs:431-438`); and
- both the host and recursive LogUp verifiers call this config-aware no-op.

In contrast, `docs/soundness/ziren.soundcalc.toml:137` sets `grinding_bits_lookup = 16` for wrap, and the generated report credits wrap LogUp-GKR with 112 bits. Under the additive PoW accounting used by that report, removing an unperformed 16-bit grind leaves approximately 96 bits, below the stated 100-bit target. The exact report must be regenerated with the implemented transcript; the checked-in input is also stale, identifying revision `fdcb6a07` rather than the reviewed `d2f06b9d`.

Required repair: either implement and constrain the 16-bit grind for the outer `MultiField32` transcript, or select stronger non-grinding lookup parameters and regenerate the report. Add a test that records the prover, native verifier, and recursive verifier transcript events and proves that the counted grind both advances the transcript and rejects an invalid witness in every production ring.

### ZR-27 follow-up — Reject proof-selected geometry before using it

Commit `33140f22` prevents eventual acceptance of a non-production stacking height. It does not make the public verifier total over malformed proofs. In the inner branch, `verify_jagged_pcs_host` reads `bundle.commit.log_stacking_height`, computes `1 << h`, calls `committed_dense_len`, and derives areas before delegating to either guarded verifier. A hostile `u32` height can therefore panic under checked shift arithmetic or produce meaningless release geometry before the intended rejection.

Move the equality check immediately after bundle decoding in both ring branches, before commitment projection, metadata reconstruction, shifts, rounding, allocation sizes, or point slicing. Derive all later geometry from `DEFAULT_LOG_STACKING_HEIGHT`, not from the already-validated proof field. Extend the regression through the public shard-verification entry point with `0`, `2`, `20`, `22`, `usize::BITS`, and `u32::MAX`, and require a typed error without unwind.

## Protocol-correctness review of recent changes

The following changes are correct in the reviewed source:

- `eq_mle_table_iter` preallocates one `2^m` table and writes the new high half before overwriting the low half. The source value for each pair is therefore preserved, and the table remains in LSB-first Boolean-index order. `eq_mle_table_rev` changes only coordinate iteration order.
- `evaluate_trace_columns_at_point` uses `k = ceil(log2(height))`, builds `eq(r[0..k], row)`, and multiplies by `product_{i >= k}(1-r_i)`. Because every represented row has zero high bits, this is exactly the full-cube padded MLE. The row-blocked base-field multiplication changes evaluation order only; field addition is exact.
- `take_codeword_values` moves the encoded codeword through `Arc::try_unwrap` and clones only if ownership is unexpectedly shared. It changes ownership cost, not codeword order or transcript contents.
- The inner BaseFold `(log_blowup=2, queries=124, query-PoW=16)` and outer BaseFold `(3,94,22)` unique-decoding calculations are internally consistent with their comments: approximately 100.08 and 100.03 bits respectively. This does not cure ZR-24 or ZR-29, and the WHIR result remains explicitly unique-decoding-regime only.
- The preprocessed commitment repair uses the raw root for Merkle authentication and separately recomputes the geometry-bound digest compared with the VK. This is the correct separation of opening root and shape binding.

The `ZIREN_BASEFOLD_LOG_BLOWUP` escape hatch is not elevated to a new end-to-end soundness finding in the current architecture. Inner production proofs use WHIR, while the outer ring overrides the BaseFold profile with fixed wrap parameters. The environment-selected BaseFold profile is nevertheless reached by the inner default commit path because that path constructs a shadow BaseFold commitment before constructing the live WHIR commitment. It should be removed or isolated behind an explicit benchmark-only API so that a future BaseFold fallback cannot silently inherit a sub-100-bit profile.

## Performance review

### P0 — Eliminate the discarded BaseFold commitment on every inner WHIR commit

`BasefoldRing::commit_multilinears` first calls `commit_jagged_pcs_generic`, which stacks the dense polynomial, Reed-Solomon encodes it, and builds a BaseFold Merkle tree. When `WHIR_INNER_PCS` is true, the method then reconstructs a dense vector from the retained interleaved MLEs, runs a second commitment under WHIR, returns the WHIR root, and leaves the BaseFold tree unused (`crates/pcs/src/config.rs:290-356`).

Split stacking/interleaving from PCS commitment. A shared preparation function should return packing metadata plus the interleaved MLEs once; WHIR and BaseFold should consume that prepared representation directly. The inner path must never encode or hash a BaseFold codeword, and it should not materialize `dense -> MLE -> interleaved -> dense -> MLE` merely to cross an API boundary. Measure setup/commit time, peak RSS, encoded field elements, and hash permutations separately for preprocessed and main rounds.

### P0 — Actually use the recursion proving-key cache

The cache implementation and public `recursion_pk_cache_get/insert` methods exist at `crates/prover/src/lib.rs:884-917`, but a current call search finds no production user. The compression worker still executes `self.compress_prover.setup(&program)` for every node at line 1995. Wire the cache around this setup and suppress duplicate concurrent builds per digest. The existing capacity is entry-count based even though comments place entries at hundreds of MiB; add byte accounting and an RSS budget.

### P0 — Repair ZR-24 with witnessed openings, not program constants

The verifier comments estimate approximately 25 MB if outer component openings are embedded as constants. They are proof data and should be witnessed. Stream them in a round/query-major layout that lets the circuit authenticate and release one query at a time. Benchmark constraint count, builder allocations, generated instruction count, witness bytes, solve time, and ptau headroom before selecting the final layout.

### P1 — Fuse BaseFold batching by row tile

`BasefoldProver::batch` still performs a parallel read/modify/write pass over the full MLE accumulator and another over the full codeword accumulator for every input matrix. Flatten `(coefficient slice, matrix slice)` descriptors once, parallelize over row tiles, and accumulate all input contributions in a worker-local scalar/vector before writing each output row once. Preserve the current scalar evaluation reduction in the same descriptor order and require proof-byte equivalence.

### P1 — Remove remaining ownership and verifier clones

- `views_over_owned` copies every `RowMajorMatrix.values` into a new `Arc<Mle>` (`crates/pcs/src/jagged_pcs.rs:1136-1151`). Add a consuming constructor that moves the vectors.
- Per-group verification still clones chip metadata, row points, claims, opened values, and offsets before calling `verify_one_jagged_group`. Replace these with membership-indexed borrowed views.
- The recursive BaseFold verifier clones every query block and repeatedly materializes `lo`, `hi`, and selected vectors. Borrow the proof blocks and reuse a fixed scratch buffer without changing emitted constraints.

### Validated performance changes

- The one-allocation `eq_mle_table` rewrite is correct and removes repeated table growth/copies.
- The truncated equality table and row-major trace-column evaluator avoid work proportional to the maximum shard cube for short traces.
- Moving uniquely owned encoded codewords removes a full codeword clone on the normal path.

These wins should be benchmarked independently. Do not trade away query count, blowup, OOD samples, or PoW to recover their cost; those values are protocol parameters and must move only with a regenerated soundness report, recursive programs, and verification keys.

## Required regression gates

1. Outer two-round BaseFold: component leaf/path/root/first-block mutations must each fail in the production recursive circuit.
2. Global digest: a direct doubling witness with an arbitrary on-curve successor must fail after the fix; ordinary addition, doubling, inverse, and infinity cases need separate tests.
3. Wrap LogUp grinding: invalid witnesses must fail and transcript traces must match across prove, native verify, and recursive verify.
4. Public stacking-height boundary: all hostile heights must return an error without panic before geometry arithmetic.
5. Jagged cross-binding: independently substitute the raw main root, raw preprocessed root, modified VK root, packing counts, and `y_per_chip`.
6. Native/recursive acceptance parity for both inner WHIR and outer BaseFold, using the same malformed-proof corpus.
7. Performance: establish byte-identical proofs for ownership/data-layout optimizations and identical accepted languages for circuit-builder allocation changes.

## Updated priority

1. Close the coupled outer-recursive portions of ZR-23 and ZR-24 atomically before relying on the outer recursive BaseFold proof.
2. Fix or explicitly rule out exceptional global-digest additions (ZR-28), and correct the paper's contrary claim.
3. Make the implemented outer LogUp transcript match the soundness input, then regenerate `ziren.soundcalc.toml` and its report at the release revision (ZR-29).
4. Move the stacking-height guard to the deserialization boundary and make geometry arithmetic checked (ZR-27).
5. Remove the shadow BaseFold commit from the inner WHIR path and connect the recursion proving-key cache.
6. Run the adversarial circuit tests above, regenerate all affected programs/VKs, and only then repeat full corrected-release performance measurements.

## Validation performed for this follow-up

| Command | Result | Coverage |
|---|---|---|
| `cargo test -p zkm-pcs --lib` | PASS: 192 passed, 0 failed, 5 ignored | BaseFold and WHIR roundtrips, jagged reduction/cross-binding, stacking-height rejection, equality-table and trace-evaluation regressions, zerocheck/LogUp helpers, and proof serialization. Runtime: 1195.79 s. |
| `cargo test -p zkm-verifier --features ark malformed_input --lib` | PASS: 12 passed, 0 failed | Every proof/VK truncation boundary, hostile proof-controlled counts, malformed STARK bytes, public-value/hash decoding, and arkworks parser totality. |
| `cargo test -p zkm-core-executor program::tests --lib` | PASS: 10 passed, 0 failed | ELF truncation, file/memory sizes, virtual-address ordering, gaps/overlap, executable tails, and entrypoint bounds. |
| `cargo test -p zkm-cuda --lib` | PASS: 3 passed, 0 failed | Malformed endpoint, unreachable service, and undecodable response return errors rather than panicking. |
| `cargo fmt --all -- --check` | FAIL | The current tree has widespread rustfmt drift across executor/JIT, PCS, recursion, SDK, and verifier sources. No automatic formatting was applied because the working tree contains user changes. |

The test passes establish honest-path and existing negative-test behavior; they do not close ZR-24, ZR-28, or ZR-29 because the required adversarial cases do not yet exist. A full workspace Clippy gate, production recursive/Groth16 end-to-end proof, and GPU benchmark were not run in this follow-up. Compilation also emits existing unused-variable, dead-code, missing-documentation, ambiguous-re-export, function-pointer-cast, and future-incompatibility warnings, so the repository is not currently warning-clean.

---

# Focused Review of `prove_jagged_basefold_rounds_generic`

Date: 2026-09-20  
Revision reviewed: `3aa9176fedc6b63b444ea86517c231de209f8b27` (`ci: run the verifier malformed-input guards, including optional ark feature`)  
Scope: `crates/pcs/src/jagged_pcs.rs:1276-1592`, its shared linear core, the jagged reduction, production caller, native verifier, and BaseFold/WHIR opening interfaces  
Method: manual source and algorithm review with prover/verifier equation replay. The Flounder CLI is not installed in this workspace, so this section does not claim Flounder execution confirmation. A focused debug-mode round-trip test was started with the exact enabled test path but was interrupted after more than two minutes without completing; it is recorded as inconclusive, not as a pass or failure.

## Conclusion and security disposition

No new exploitable soundness vulnerability was found in `prove_jagged_basefold_rounds_generic`. Its multi-round layout, jagged reduction, transcript order, and output commitment order are internally consistent with the reviewed native verifier, provided the precomputed round objects satisfy the construction invariants established by the production commit path.

In particular, this function is not the source of ZR-23/ZR-24's outer-recursion ordering failure. It receives rounds in `[preceding/preprocessed..., main]` order, places the earlier raw roots in `preceding_commits`, and places the last round's commitment in `commit`. The later outer witness lift is the component that reconstructs the incompatible root vector discussed under ZR-23/ZR-24.

The remaining items below are prover-side hardening, performance, design, and test-coverage observations. They are not assigned new ZR vulnerability identifiers because no new accepting invalid-proof path was demonstrated.

## Algorithm replay

For round `r`, let `V_r` be its packed real-cell count, `A_r` its committed area, and

```text
B_r = sum_{i < r} A_i.
```

The function shifts every real-column offset in round `r` by `B_r` and inserts explicit zero columns covering the committed gap `[B_r + V_r, B_r + A_r)`. The reduction polynomial is therefore the concatenation

```text
Q = Q_0 || 0^(A_0 - V_0) || Q_1 || 0^(A_1 - V_1) || ... .
```

For global column `k`, row `j`, and packed offset `o_k`, the constructed weight table is

```text
W[o_k + j] = chi_k(z_col) * chi_j(z_row).
```

Consequently, when each supplied column claim is the corresponding row-MLE evaluation,

```text
sum_x Q[x] * W[x]
    = sum_k chi_k(z_col) * y_k
    = t.
```

The Hadamard sumcheck reduces this identity to `t = Q(z*) * W(z*)`; the jagged-evaluation protocol recomputes `W(z*)` from the public offsets and transcript points; and the final BaseFold or WHIR opening authenticates `Q(z*)` against all round commitments. The reversal of the reduction point before the branching-program evaluation matches the verifier's big-endian index convention.

For a common stacking height `H = 2^s`, the batched opening dimension is computed as

```text
total_stripes  = sum_r (A_r / H)
effective_area = H * next_power_of_two(total_stripes).
```

This is exactly the power-of-two closure of `sum_r A_r` when every `A_r` is a nonzero multiple of `H`. The commit path currently supplies that property, and the function already rejects disagreement in `s` across rounds. The property should nevertheless be asserted locally because the generic API otherwise silently right-shifts malformed areas.

## Review observations

### Major performance — the generic path materializes both full reduction operands

The reduction closure allocates the complete extension-field weight table and a complete base-field `dense_q`. It also reconstructs a temporary `round_dense` for each round and copies its committed-area prefix into `dense_q`. Peak memory therefore includes the full `W`, full `Q`, the largest temporary round reconstruction, and the PCS/sumcheck working state.

The repository already documents that materializing and folding the weight table at `log_dense_size == 28` cost approximately 4.0 GiB of allocation plus a 4.0 GiB clone and 14.7 seconds in the measured core-reth case (`crates/pcs/src/jagged_sumcheck.rs:238-253`). Exact current peak memory must be re-benchmarked, but this function still invokes the same full-table constructor.

Recommended changes:

1. use the existing `build_fused_weight_inputs` factors and derive `chi_k(z_col) * row_eq[j]` inside a tiled sumcheck fold instead of materializing `W`;
2. represent concatenated round data as borrowed or moved `LongMle` segments so the reduction can read `Q_r || zero-padding` without reconstructing and copying every round into one vector; and
3. record peak RSS, allocation bytes, reduction time, and proof-byte equivalence independently for inner and outer rings.

### Low reliability — `saturating_sub` hides an invalid precomputed area

The padding calculation currently uses:

```rust
let pad = area.saturating_sub(pk.total_values);
```

`area < pk.total_values` is not a legitimate zero-padding case. It means the precomputed commitment and packing metadata disagree. Converting that state to `pad == 0` defers the failure to a less intelligible offset, bounds, or opening mismatch. Replace the subtraction with `checked_sub(...).expect(...)` or return a typed construction error.

### Low reliability — stripe alignment and effective-area equivalence are implicit

The code checks that every round reports the same `log_stacking_height`, but computes each stripe count with `area >> log_stacking_height` without asserting exact divisibility. Add local checks that:

```text
area > 0
area % (1 << log_stacking_height) == 0
effective_area == next_power_of_two(sum_r area)
packing.log_dense_size() == log2(effective_area)
```

Use checked shifts for the generic boundary. These conditions hold for production-generated objects today; the purpose is to make the generic function fail at the violated invariant rather than truncate or overflow.

The shared `prove_jagged_basefold_linear_core` similarly derives a dimension using `area.trailing_zeros()`, which is `log2(area)` only for a power of two. This caller passes `effective_area`, which is a power of two, but the public helper should assert that requirement directly.

### Low API/design — the round object advertises invariants it does not enforce

`JaggedOpenRound::chip_traces` is not read by this function. The values in `r_row_per_chip` are also algebraically subsumed by the full `z_row` weight table; only their outer shape remains relevant to verification. In addition, the generic prover does not locally require:

```text
claims.len() == packing.chip_infos.len()
r_row_per_chip.len() == packing.chip_infos.len()
claims[i].len() == packing.chip_infos[i].column_count
```

The production caller constructs consistent arrays, and verifier-side dimension/cross-binding checks reject most malformed bundles, so this is not a demonstrated soundness bypass. It is nevertheless an unsafe generic API contract: mismatches can produce a panic or an unverifiable proof far from their origin. Introduce a validated round/layout constructor, or remove the unused trace field and legacy per-chip row values after checking wire/API compatibility.

### Design clarity — one function owns too many protocol layers

The function currently performs round-layout validation, padding normalization, dense reconstruction, reduction construction, backend selection, transcript execution, PCS opening, and bundle serialization. Its name also says BaseFold although it may emit a WHIR proof, and the `fri` argument is silently unused in WHIR mode.

A clearer split would be:

1. `ValidatedMultiRoundLayout::new(rounds, z_row)` for all shape, ordering, area, and padding invariants;
2. a backend-neutral reduction input over borrowed/moved segments;
3. an explicit `JaggedOpeningBackend::{BaseFold, Whir}` configuration; and
4. backend-specific open functions returning a proof enum, removing the `RefCell<Option<_>>` plus empty BaseFold placeholder used to transport a WHIR result through the shared closure.

## Test gap — the generic multi-round contract lacks a direct regression

The direct BaseFold round-trip test in `jagged_pcs.rs` exercises a single main round. Lower-level stacked BaseFold has two-round tests, and WHIR has layout tests, but these do not directly validate this function's complete `[preprocessed, main]` jagged packing and bundle assembly.

Add a production-shaped two-round test that:

1. commits distinct preprocessed and main rounds and proves them in that order;
2. uses different real sizes, including one zero-size stacking gap and one nonzero gap;
3. covers both natural padding and a fixed area pin;
4. checks every rebased offset and padding-column height;
5. asserts `preceding_commits == [preprocessed_raw_root]` and `commit == main_commit`;
6. round-trips through the native verifier and the applicable outer-ring verifier; and
7. rejects swapped roots, mixed WHIR/BaseFold data, mismatched stacking heights, malformed claim widths, and non-aligned areas.

This is a high-priority regression because the existing ZR-23/ZR-24 failure is also a two-round commitment-order problem, even though its defect lies downstream of this prover function.

## Validation record

| Command | Result | Interpretation |
|---|---|---|
| `cargo test -p zkm-pcs --lib -- --list` | PASS; 201 tests enumerated | Confirmed the exact enabled test path and current test inventory. |
| `cargo test -p zkm-pcs jagged_pcs::test::test_jagged_basefold_roundtrip --lib` | INCONCLUSIVE; interrupted after more than two minutes | The enabled single-round test began execution but did not finish within the review window. This is neither acceptance evidence nor a test failure. |

No product source files were modified during this focused review. Only this report was updated.
# Protocol Soundness Follow-Up at `26befa33`

## Scope and evidence boundary

This source-only pass reviews the acceptance language of the jagged reduction,
the native inner and outer verifiers, and the recursive BaseFold verifier. It
uses SP1 v6.3.1 at `9ce13607e9f464b9d5ccd8b4a6478de0e8f8bf1b` as the
reference for exact round/evaluation cardinality, geometry-to-commitment
binding, and recursive prefix-sum consistency.

No tests, proof generation, or exploit construction were run in this pass.
“Confirmed” means that the accepting source path and omitted equation or
cardinality check were traced end to end; it does not mean that an end-to-end
malicious recursive or Groth16 proof was generated.

This section supersedes earlier status statements for ZR-23 and ZR-24:

| ID | Severity | Current status | Result |
|---|---:|---|---|
| ZR-23 | Critical | Partial; remains open | The supplied roots and claims have new bindings, but exact round/column coverage and outer geometry binding remain incomplete. |
| ZR-24 | Critical | Fixed at source level; artifact verification pending | Outer component openings are transported, authenticated in proof round order, and linked through the FRI fold chain. |
| ZR-30 | Critical | Open; newly confirmed | A proof can shorten a per-chip `y_per_chip` vector, causing the reduction and cross-bind to ignore machine-validated AIR opening columns. |
| ZR-31 | Critical | Open; newly confirmed on the native outer verifier | A proof can omit the preprocessed round because only supplied preceding roots are checked. |

## SP1 comparison

The current SP1 native jagged verifier requires the commitment, evaluation,
row-count, column-count, and original-commitment vectors to have the
verifier-configured round count. It also requires each round's evaluation
vector to contain exactly the sum of that round's real column counts. SP1 then
recomputes a modified commitment from the raw root and complete row/column
geometry. Its recursive verifier reconstructs each column prefix from those row
counts and checks the prefixes and terminal area against the evaluation layout.

Ziren implements the recursive prefix/terminal-area bridge and authenticates
each supplied BaseFold component opening. The remaining divergence is
coverage: several checks prove that every *presented* object is valid without
proving that every object required by the machine is present. SP1 advisory
`GHSA-63x8-x938-vx33` treats the analogous commitment/evaluation geometry
split as a soundness vulnerability even without a demonstrated arbitrary-proof
exploit.

## ZR-30 — Critical — Per-chip column claims can be shortened

### Evidence

`verify_jagged_reduction` checks `y_per_chip.len() == chip_infos.len()`, but
never checks

```text
y_per_chip[i].len() == packing.chip_infos[i].column_count.
```

It constructs the initial claim by iterating only over supplied values:

```text
t = sum_{i,j < y_per_chip[i].len()}
        chi_{k(i,j)}(z_col) * y_per_chip[i][j].
```

`cross_bind_openings` rejects only when
`opened_main[i].len() < y_per_chip[i].len()`. A strict-prefix claim vector
therefore causes both the reduction and cross-bind to ignore the opening
suffix, even though the shard verifier separately requires the complete AIR
width.

Relevant locations:

- `crates/pcs/src/jagged_sumcheck.rs:175-209`;
- `crates/pcs/src/jagged_pcs.rs:1881-1924`; and
- `crates/pcs/src/shard_level/verifier.rs:176-215`.

For machine width `w` and `m < w`, an accepting construction can use:

```text
AIR openings: [o_0, ..., o_{m-1}, o_m, ..., o_{w-1}]
y_per_chip:   [o_0, ..., o_{m-1}]
committed Q:  [honest prefix columns, zero, ..., zero]
```

The cross-bind sees only the first `m` openings. The omitted committed columns
contribute zero to the jagged reduction, while the AIR/zerocheck suffix is not
tied to a committed trace polynomial. This is a PCS-to-AIR binding failure.

The recursive verifier derives its claim vector from full fixed-shape
`opened_values`, so this also creates a native/recursive acceptance mismatch.

### Independent geometry representations

`PackingMeta` serializes both flat `column_counts` and per-round
`round_counts`. The outer machine-width pin checks `round_counts`, while
`build_jagged_verify_inputs` and the reduction consume `column_counts`. No
check requires the two layouts to agree. A bundle may therefore keep
`round_counts` machine-correct while shrinking flat `column_counts`, offsets,
and `y_per_chip`. The rebuilt opening vector checks the number of groups, not
each group's exact width.

Relevant locations:

- `crates/pcs/src/jagged_pcs.rs:816-878`;
- `crates/pcs/src/jagged_pcs.rs:2124-2165`; and
- `crates/pcs/src/shard_level/verifier.rs:671-755`.

### Required remediation

Reject before sampling `z_col` unless:

```text
y_per_chip.len() == chip_infos.len()
y_per_chip[i].len() == chip_infos[i].column_count
opened_main[i].len() == y_per_chip[i].len()
sum_i y_per_chip[i].len() == offsets.len() - 1
column_counts == canonical_flatten(round_counts, padding_heights)
```

The safer design removes independently serialized `y_per_chip` and derives
the reduction claim from machine-validated trace openings, as SP1 does. Packing
geometry should likewise have one canonical source.

### Ready-to-submit comments

> `oc.len() < yc.len()` is not a sufficient coverage check. `verify_jagged_reduction` never requires `y_per_chip[i].len() == chip_infos[i].column_count`, so a proof may shorten `y_per_chip[i]`; both the reduction claim and this cross-bind then ignore the suffix of the machine-validated opening vector. The omitted committed columns can be zero while AIR consumes arbitrary unauthenticated suffix openings. Please require exact per-chip and total-column coverage before sampling `z_col`, or derive the reduction claim directly from the trusted opened values as SP1 does.

> The width pin validates `packing.round_counts`, but `build_jagged_verify_inputs` and the reduction consume the independently deserialized `packing.column_counts`. No check requires these representations to describe the same flattened layout. Please canonicalize from one source, or reject unless `column_counts` exactly equals the round-major real widths plus one entry for every padding column and the offsets scan matches it.

## ZR-31 — Critical — The native outer verifier does not require the preprocessed round

The wrap machine has preprocessed columns and constructs
`[preprocessed, main]`. The native outer verifier instead iterates over the
proof's `round_counts` and treats the last supplied round as main. It validates
each supplied `preceding_commit`, but never requires one when
`prep_chip_dims` is nonempty.

With `preceding_commits == []` and a one-round packing:

1. the only round is treated as main;
2. the preprocessed width/root branches are skipped;
3. the VK comparison loop is vacuous;
4. BaseFold receives only the main commitment and area; and
5. `num_expected_commitments` is initialized from that proof-derived length.

The downstream shape checks are internally exact for the wrong shortened
statement. Zerocheck still consumes
`opened_values.chips[*].preprocessed.local`, but those fixed-column
evaluations are not authenticated to `vk.commit`.

Relevant locations:

- `crates/pcs/src/shard_level/verifier.rs:671-818`;
- `crates/pcs/src/jagged_pcs.rs:689-705`; and
- `crates/pcs/src/jagged_pcs.rs:2292-2308`.

The recursive outer lift has the same fail-open construction invariant: a
present key cap asserts only `preceding_commits.len() <= 1` and performs the
root equality only if the vector is nonempty
(`crates/recursion/circuit/src/shard_level_witness.rs:1549-1566`). A correctly
generated fixed Groth16 program normally bakes the honest two-round shape, so
this does not itself demonstrate a forged published Groth16 proof. It does show
that native verification accepts a larger statement language.

Require:

```text
expected_preceding = 1 if prep_chip_dims is nonempty else 0
preceding_commits.len() == expected_preceding
round_counts.len() == expected_preceding + 1
padding_heights.len() == round_counts.len()
BaseFold commitment/evaluation/component-opening rounds == round_counts.len()
```

> Comparing every supplied preceding root is not a coverage check. When `prep_chip_dims` is nonempty, an empty `preceding_commits` plus a one-round packing skips the preprocessed PCS opening entirely, while zerocheck still consumes preprocessed openings. Require exactly one preceding round when the machine has preprocessed columns, zero otherwise, and require `round_counts.len() == padding_heights.len() == preceding_commits.len() + 1`. The recursive outer lift should likewise require equality, not `<= 1` followed by a conditional root check.

## ZR-23 residual — Outer geometry remains unbound before `z_col`

The current outer path pins a supplied preprocessed raw root to the raw key root
and pins per-chip widths to the machine. It does not bind row counts, offsets,
or the complete canonical packing geometry to the key or Fiat-Shamir transcript
before sampling `z_col`.

`build_jagged_verify_inputs` derives row counts from proof-supplied offsets,
and the generic verifier evaluates the weight polynomial using that layout.
Because the outer key stores an unmixed raw root, root equality does not state
how the dense commitment is partitioned into chip columns. This remains the
same protocol class as SP1's commitment/evaluation geometry split.

ZR-30's consistency checks do not close this residual. Complete remediation
requires committing or observing a canonical geometry digest before `z_col`
and checking that the jagged evaluator uses the same geometry. The
preprocessed geometry must be pinned by the VK. This changes the transcript/key
relation and requires regenerated and versioned recursion/Groth16 artifacts.

## ZR-24 remediation status

The outer witness reader/writer now carries component leaves and paths; lifted
roots are ordered `[preceding_roots..., main_root]`; and the recursive verifier
reconstructs the initial query value, authenticates every component leaf,
checks every selected FRI value against the running fold, and authenticates the
commit-phase chain and terminal polynomial.

Commit `caa6dadb` adds a positive component-opening test and four
single-mutation tests covering the leaf, path sibling, root, and position.
These make the exercised equality non-vacuous. They do not test exact round or
column coverage and therefore do not address ZR-30 or ZR-31.

ZR-24 is closed at source level. Release closure still requires an honest
production-shaped two-round recursive proof, regenerated VK/program/Groth16
artifacts, and negative tests for an omitted round, a truncated claim vector,
and disagreeing flat/per-round geometry.

## Protocol-priority recommendations

1. Fix ZR-30 and ZR-31 before treating the native outer verifier as a security
   boundary.
2. Use one canonical machine-derived round/column layout across AIR, jagged
   reduction, stacked PCS, BaseFold, native verification, and recursion.
3. Bind canonical outer geometry before `z_col`, then regenerate and version
   affected recursive and Groth16 artifacts.
4. Add native/recursive acceptance-parity tests for omitted and extra rounds,
   shortened and extended `y_per_chip`, contradictory count representations,
   and reordered commitments.
5. Treat Merkle-path mutation tests as authentication tests, not coverage
   tests; every proof vector also needs a machine- or key-derived exact
   cardinality invariant.

No product source files were modified during this protocol follow-up. Only this
report was updated.

# Current PCS, WHIR, Tensor-Backend, and GPU-Context Audit at c8accdf9

## Scope and evidence boundary

This section is the authoritative follow-up for the current source tree at
c8accdf941a332a55c402306977f02ad86e7209e, with the adjacent ziren-gpu tree
inspected at db8d3c0258aafe09990930999a4c5f388bd2b8b6. It covers the native
and recursive stacked-WHIR transcript, the jagged-to-PCS binding, the BaseFold
verifier's malformed-proof behavior, the backend-generic tensor abstraction,
open_timing, naming in shard_level, and gpu_worker_context.rs.

The protocol conclusions are manual source-level findings. No forged proof or
memory-corruption executable was constructed. The focused WHIR unit suite was
run only as an honest-path baseline; it does not exercise surplus proof-vector
elements or an adaptively selected final polynomial.

This section supersedes the earlier current-status rows for ZR-23, ZR-24,
ZR-30, and ZR-31:

| ID | Current source-level status | Result |
|---|---|---|
| ZR-23 | Closed for the previously reported outer path | c8accdf9 pins outer main geometry to transcript-observed heights and machine widths, and pins outer preprocessed geometry to the verifying key. ZR-34 below is a distinct inner-path cardinality bypass. Artifact/deployment state was not assessed. |
| ZR-24 | Closed | Component openings and the FRI chain remain authenticated in the reviewed source. |
| ZR-30 | Closed | 0935382b enforces exact per-chip claim coverage and a canonical flat/per-round packing. |
| ZR-31 | Closed | 0935382b requires the machine-derived number of outer preceding rounds and the exact outer round count. |

## New findings

| ID | Severity | Status | Summary |
|---|---:|---|---|
| ZR-32 | Critical | Open | Stacked WHIR can select an unobserved surplus tail commitment for its final Merkle authentication. |
| ZR-33 | Critical | Open | WHIR does not absorb the revealed final polynomial before final PoW and query sampling. |
| ZR-34 | High | Open | The inner jagged verifier applies its machine-geometry pin only when a proof-controlled round count already has the expected value. |
| ZR-35 | Medium | Open | A wide BaseFold leaf panics before the verifier reaches its existing shape rejection. |
| ZR-36 | Critical | Open | Safe generic tensor APIs byte-copy or byte-initialize arbitrary T, violating ownership and value validity. |
| ZR-37 | Critical | Open | Safe generic tensor APIs form host references to CUDA memory and allow asynchronous copies to outlive host borrows. |
| ZR-38 | High | Open | Buffer<T, A> is unconditionally Send + Sync, including non-thread-safe T. |
| ZR-39 | Medium | Open | CpuBackend::allocate constructs NonNull from a possibly null allocator result. |
| ZR-40 | High | Open | The checked-in soundness input models a different batching law and cardinality from the implemented stacked opening. |
| ZR-41 | Medium | Open | The protocol-profile digest omits most WHIR and BaseFold transcript parameters despite claiming complete coverage. |
| ZR-42 | Low | Open design defect | BasefoldShard* and the shard_level module documentation describe BaseFold even when the proof carries WHIR. |
| ZR-43 | Low | Open design defect | GpuPoolWorkerGuard clears rather than restores the prior thread-local device context. |

## ZR-32 — Critical — Stacked WHIR's final root can come from an unobserved surplus tail

### Evidence

StackedWhirVerifier::verify_trusted_evaluation iterates the configured round
count. For each non-final folding round it absorbs
whir.round_commitments[r] and verifies the next round against the fixed r - 1
entry (crates/pcs/src/whir/stacked.rs:955-997 and :1029-1086). It never
requires exact top-level lengths for round_commitments, round_query_openings,
round_sumcheck_polys, round_ood_answers, or folding_pow.

The final phase does not use the commitment at the canonical configured index.
It instead selects proof-supplied tails:

    final_openings   = round_query_openings.last()
    final_commitment = round_commitments.last()

These selections occur at crates/pcs/src/whir/stacked.rs:1121-1125 and
:1167-1174. Appending one commitment and one final-opening set therefore
changes the root and leaves used by the final query check without changing the
commitments absorbed into Fiat-Shamir. The final indices are sampled before
this surplus root is authenticated. A prover can consequently construct the
selected Merkle tree after learning the sampled positions; the final STIR
check is no longer tied to the codeword root that the transcript fixed.

The recursive implementation repeats the same indexing rule: fixed [r]
commitments are absorbed at crates/recursion/circuit/src/whir_circuit.rs:459-493,
but final openings and the final root use .last() at :610-665. Its vector
shapes are baked from the host mirror when a program is built, so exploitability
of a particular published recursive artifact depends on that artifact's fixed
shape. The native verifier accepts the variable-length serialized proof
directly and has no such qualification.

The SP1 v6.3.1 reference does not have this ambiguity. Its native verifier
rejects unless all top-level vectors have exact configuration-derived lengths
(/tmp/sp1-v6.3.1/slop/crates/whir/src/verifier.rs:181-190) and tracks one
prev_commitment through the rounds; the final opening is checked against that
tracked root (:451-495).

### Impact

This removes the Fiat-Shamir binding of the final oracle in the production
stacked-WHIR verifier and breaks the PCS soundness argument, rather than merely
creating alternate encodings of one valid proof.

### Closure condition

Closure requires exact configuration-derived cardinalities for every proof
vector and final authentication against the canonical tracked commitment and
opening indices. No tail selection may allow a surplus proof element to
replace a transcript-observed object.

## ZR-33 — Critical — The final WHIR polynomial is selected after final queries are known

### Evidence

The stacked prover computes final_poly and immediately grinds and samples the
final queries, without observing the polynomial
(crates/pcs/src/whir/stacked.rs:759-774). The native verifier performs the
same order: it checks final_pow, samples indices, and only reads final_poly in
the equality and terminal checks
(crates/pcs/src/whir/stacked.rs:1116-1193). No observe call for final_poly
exists in the native WHIR modules or the recursive verifier.

The same omission exists in the standalone interleaved verifier
(crates/pcs/src/whir/interleaved.rs:655-696) and in the recursive stacked
verifier (crates/recursion/circuit/src/whir_circuit.rs:610-677).

SP1 performs the required ordering explicitly: it absorbs the complete final
polynomial at /tmp/sp1-v6.3.1/slop/crates/whir/src/verifier.rs:461-470, then
checks final PoW and samples final indices at :474-480.

For the production Ziren schedule, lsh = 21, folds are [3, 6, 6], and the
revealed polynomial has 2^6 = 64 coefficients, while the final phase samples
85 queries with 16 bits of grinding
(crates/pcs/src/whir/jagged.rs:120-165). Because the coefficients are not
Fiat-Shamir-bound first, a noninteractive prover learns all final positions
before selecting those 64 degrees of freedom. The final round therefore is not
the 85-query committed-polynomial experiment used by the documented
soundness calculation. Tampering with one coefficient after an honest proof is
still rejected; that test does not cover adaptive selection of the whole
polynomial.

### Impact

The advertised final-round query bound does not apply. This is independent of
ZR-32: exact proof-vector lengths would still leave the final polynomial
adaptive, while observing the polynomial would still leave the surplus-root
substitution of ZR-32.

### Closure condition

The complete final polynomial must be transcript-bound before the final
grinding witness and final query indices are derived, identically in prover,
native verifier, and recursive verifier.

## ZR-34 — High — Inner machine geometry is conditional on a proof-controlled round count

### Evidence

The outer branch now requires exactly expected_preceding + 1 rounds at
crates/pcs/src/shard_level/verifier.rs:824-844. The inner branch does not have
the corresponding unconditional check. It computes
expected_rounds = usize::from(n_prep > 0) + 1, but checks the main round
against machine widths and transcript-observed heights only inside:

    if let Some(main_round) = round_counts.last() {
        if round_counts.len() == expected_rounds {
            check_round_geometry(...)
        }
    }

This occurs at crates/pcs/src/shard_level/verifier.rs:1089-1103.

Thus an empty legacy list on a no-preprocessed machine, or a list with surplus
round metadata, skips the newly added machine-geometry equality. The canonical
packing check does not close this: it deliberately accepts an empty legacy
round_counts (crates/pcs/src/jagged_pcs.rs:2716-2724), and for a nonempty list
it proves only that the proof's two serialized geometry representations agree
with each other.

The rest of the inner construction treats the flat entries after the first
preprocessed segment as the main chips and converts every remaining entry to a
zero padding claim (crates/pcs/src/shard_level/verifier.rs:1105-1207 and
:1295-1321). Meanwhile the main commitment hash uses round_counts.last()
(:393-424). With surplus metadata, the geometry hashed as main and the
geometry aligned with the AIR openings are therefore not the same round. Exact
column-claim coverage does not independently pin the main row counts.

### Impact

The source accepts a proof language in which the new machine/transcript
geometry bind is optional. This reopens the inner version of the geometry class
that c8accdf9 intended to close. No end-to-end forged proof was constructed,
so this finding is rated High rather than asserting a demonstrated arbitrary
proof forgery.

### Closure condition

The inner path must reject unless the per-round and padding vectors have the
exact machine-derived round count before it chooses a main round or consumes
flat packing metadata. Legacy empty geometry cannot be an accepting production
case when the verifier relies on that geometry for the PCS statement.

## ZR-35 — Medium — BaseFold panics on a wide malformed leaf

### Evidence

The native BaseFold verifier slices the round's coefficient range at
crates/pcs/src/basefold/verifier.rs:243, then indexes
round_coeffs[poly_offset + k] for every proof-supplied leaf value at :245-255.
It checks poly_offset != round_polys only after that loop at :258-262.

A leaf narrower than expected reaches the error. A leaf wider than expected
indexes beyond round_coeffs first and panics. Merkle verification occurs later,
so it cannot turn this into a normal rejection.

### Impact

A malformed proof can terminate a native verification process that exposes a
Result-returning API. This is a proof-boundary denial of service, not a
soundness bypass.

### Closure condition

Every leaf/matrix width must be validated before coefficient indexing, and all
malformed widths must return IncorrectShape without unwinding.

## ZR-36 — Critical — Safe tensor operations violate Rust ownership and value validity

### Evidence

Buffer<T, A> has no T: Copy or equivalent plain-data invariant, but its safe
APIs treat every T as bytes:

- Clone copies raw storage for arbitrary T at
  crates/pcs/src/tensor/buffer.rs:1263-1292;
- extend_from_device_slice and extend_from_host_slice perform raw copies for
  arbitrary T at :466-496 and :529-560;
- safe write_bytes marks arbitrary byte patterns as initialized T at
  :649-691; and
- Tensor::zeros_in<T, A> exposes that operation for arbitrary T at
  crates/pcs/src/tensor/tensor.rs:61-75.

For CpuBackend, safe conversion from and back to Vec<T> exists at
crates/pcs/src/tensor/buffer.rs:1086-1104 and :1117-1149. A safe program can
therefore wrap a Vec<Rc<_>>, byte-clone the buffer, convert both copies back to
vectors, and create duplicate ownership of one Rc. Safe zeroing can also
materialize invalid values such as zero NonZeroU8 or invalid enum
discriminants.

### Impact

These are safe-Rust use-after-free/double-ownership and invalid-value paths.
The issue is in the public abstraction, independent of whether current PCS
callers happen to instantiate only field elements.

### Closure condition

Safe raw-copy and byte-initialization operations must be restricted to element
types for which those operations preserve ownership and validity. Operations
that can create arbitrary invalid T cannot remain safe and generic.

## ZR-37 — Critical — The generic tensor API assumes device pointers are host references and asynchronous copies are complete

### Evidence

The adjacent ziren-gpu tree implements CudaBackend with cudaMallocAsync,
cudaMemcpyAsync, and cudaMemsetAsync, and explicitly states that no operation
synchronizes (../ziren-gpu/core/src/device/backend.rs:1-24 and :75-142). It
also exposes real Buffer<T, CudaBackend> and Mle<T, CudaBackend> conversions
at :181-232.

The shared Buffer nevertheless implements safe indexing and dereference for
every backend by calling std::slice::from_raw_parts on the backend pointer
(crates/pcs/src/tensor/buffer.rs:1194-1244). Constructing a Rust slice already
requires host-addressable valid memory; a CUDA device pointer does not satisfy
that requirement.

The safe extend_from_host_slice submits a possibly asynchronous host-to-device
copy and returns while its borrowed source may immediately expire
(crates/pcs/src/tensor/buffer.rs:499-560). Its documentation claims that the
implementation keeps source memory valid, but no ownership or completion
token does so. Init::copy_into_host is also safe: it submits device-to-host
copy into a stack MaybeUninit<T> and immediately calls assume_init, without
synchronization (crates/pcs/src/tensor/init.rs:32-50).

### Impact

Safe calls can create invalid host references to device memory, allow an async
DMA read to outlive its host allocation, or read uninitialized/stale data
before an async D2H copy completes. This is a concrete incompatibility between
the public backend contract and its real external implementor.

### Closure condition

Safe APIs must distinguish host-addressable from device-only storage, and an
asynchronous backend may not let a safe copy return while borrowed host memory
or an unread destination can outlive the operation's completion.

## ZR-38 — High — Buffer<T, A> is Send + Sync for every T

crates/pcs/src/tensor/buffer.rs:72-73 contains:

    unsafe impl<T, A: Backend> Send for Buffer<T, A> {}
    unsafe impl<T, A: Backend> Sync for Buffer<T, A> {}

No T: Send or T: Sync condition exists. A safe Buffer<Rc<_>, CpuBackend> or
Buffer<Cell<_>, CpuBackend> can therefore cross or be shared across threads,
contradicting the element type's thread-safety contract. Together with safe
into_vec, this is a concrete safe-Rust route to operating on non-thread-safe
ownership state from another thread.

Closure requires the auto-trait conditions to preserve the element type's
Send/Sync requirements and any backend-specific thread/stream affinity.

## ZR-39 — Medium — CpuBackend turns allocation failure into undefined behavior

CpuBackend::allocate calls std::alloc::alloc and immediately passes the result
to NonNull::new_unchecked (crates/pcs/src/tensor/backend/cpu.rs:38-43).
std::alloc::alloc may return null on allocation failure, while this allocator
trait already returns a Result. Constructing NonNull from that result violates
its invariant before the caller can report AllocError.

This is an OOM-path memory-safety defect. Normal-capacity and zero-capacity
paths do not demonstrate it; RawBuffer avoids calling the allocator for a
zero-sized layout.

## ZR-40 — High — The checked-in soundness model does not describe the implemented batch

docs/soundness/ziren.soundcalc.toml assigns dense_batch = 32,
power_batching = false, and multilinear_batching = true to the core and
compress WHIR circuits (:33-58 and :75-100). The implemented stacked WHIR
opening instead samples one lambda and batches every stripe of every
commitment round under successive powers
(crates/pcs/src/whir/stacked.rs:902-919).

The batch cardinality is the sum of the per-round stripe counts, not
DEFAULT_BATCH_SIZE = 32; 32 is a packing width. The batching law is powers of
one challenge, while power_batching = false selects the stronger affine model
in the checked-in soundcalc patch. The jagged interpolation at batch_point is
a separate reduction and does not make the WHIR lambda batch
multilinear_batching = true.

The existing generated report also publishes the minimum component level,
whereas errors across components and across core/compress/wrap compose by a
union bound. docs/soundness/composed_security.md computes 96.67 bits from the
generated component values, but that number inherits the incorrect batching
model and is therefore not a validated lower bound for this implementation.
ZR-33 independently invalidates the final-round experiment assumed by the
model.

### Impact

Neither the checked-in 100-bit figure nor the derived 96.67-bit composition is
a supported soundness level for the reviewed implementation. This finding is
about model-to-code correspondence; it does not assign a replacement numeric
security level.

## ZR-41 — Medium — The protocol-profile digest is not a complete protocol profile

crates/pcs/src/profile.rs:38-61 says the list contains every
transcript-affecting parameter and event order, but the list contains only the
jagged stacking height, BaseFold batch-grinding bits, LogUp-GKR grinding bits,
and three revision markers.

It omits, among other transcript inputs, the WHIR fold schedule, rate schedule,
per-round and final query counts, OOD counts, all WHIR PoW bits, final
polynomial degree, and the BaseFold FRI query/folding/blowup parameters. A
change to any omitted field changes proof compatibility while leaving
transcript_profile_digest() unchanged. ZR-33's missing final-polynomial event
is likewise not represented.

### Impact

The digest cannot provide the startup mismatch detection or protocol identity
claimed by its module documentation. This is an operational integrity defect,
not by itself a proof-acceptance bypass.

## ZR-42 — Low — The shard proof's BaseFold naming no longer describes its protocol

The directory name shard_level is broad but factually correct: the module
orchestrates the complete per-shard LogUp-GKR, zerocheck, evaluation-opening,
and verification pipeline. The inaccurate part is the BaseFold-specific
surface:

- crates/pcs/src/shard_level/mod.rs:1-2 calls the whole module a
  “Shard-level BaseFold proof pipeline”;
- the complete proof and verifier remain BasefoldShardProof and
  BasefoldShardVerifier (shard_proof.rs:63 and verifier.rs:87); and
- EvaluationProof::Bundle may carry whir_proof, with production core proofs
  selecting WHIR (crates/pcs/src/jagged_pcs.rs:920-926).

This is not a cryptographic flaw. It is a design-contract defect: public type
names claim a dense PCS that the value may not use, which makes protocol
selection and audit traces ambiguous.

## ZR-43 — Low — GpuPoolWorkerGuard is not nest-safe

gpu_worker_context.rs is live, not removable dead code. The adjacent GPU tree
constructs the guard in pipeline, multi-GPU, subprocess, and shard-prover
workers (../ziren-gpu/prover/src/pipeline/prover.rs:281-286,
../ziren-gpu/prover/src/core_multi_gpu.rs:412-420, :2657-2666, and
:6724-6729; ../ziren-gpu/shard-prover/src/lib.rs:1491-1495). A device GKR
hook reads it and deliberately falls back when it is absent
(../ziren-gpu/basefold/src/device_gkr_circuit.rs:186-194). Its current role is
to prevent off-pool threads from dispatching against the wrong device.

The guard itself does not preserve nesting. new overwrites the TLS value and
stores no prior state; Drop always writes None
(crates/pcs/src/gpu_worker_context.rs:86-103). An inner guard therefore clears
an outer worker context when it drops. No currently traced call stack was shown
to nest two guards, so this is rated as a design/reliability defect rather than
a demonstrated production failure.

## Audited determinations that are not new vulnerabilities

### open_timing

open_timing is not needed for protocol correctness, soundness, transcript
parity, or normal execution. It is an environment-gated prover diagnostic.
With the variable absent, each timer performs a cached enable check and creates
no Instant (crates/pcs/src/whir/stacked.rs:178-247). No repository consumer
parses its output.

When enabled, its 17 atomics are process-global, never reset, aggregate
concurrent opens and configurations, and contain intentionally nested counters.
The output is therefore cumulative section duration mass, not one proof's
latency and not per-GPU timing. The source already labels it “Diagnostic only”;
no security finding is assigned as long as those values are not represented as
benchmark or single-proof latency data.

### tensor/backend's ziren-gpu references

The external references are technically justified. zkm-pcs owns the generic
traits and host implementation; the adjacent ziren-gpu repository owns the
only CUDA implementation and the zero-copy device-buffer/MLE bridge. This is a
cross-repository ABI boundary, not an unexplained product description. The
current production-use search found constructors and tests for the device MLE
bridge but did not find a production call to into_device_mle; the live
cross-repository safety contract still exists because CudaBackend implements
the public traits. ZR-36 through ZR-39 are the strict defects at that boundary.

### Standalone WhirVerifier

crates/pcs/src/whir/verifier.rs explicitly does not authenticate STIR Merkle
openings (:1-20). Repository call sites use it only in tests; the production
jagged path uses StackedWhirVerifier. It is therefore not counted as another
production soundness finding in this pass. It remains an intentionally
incomplete public verification API and must not be treated as a complete PCS
verifier.

## Validation record

| Command | Result | Interpretation |
|---|---|---|
| cargo test -p zkm-pcs whir::test --lib -- --nocapture | PASS: 10 passed, 1 ignored, 218 filtered; 125.73 s | Honest tower, interleaved, stacked, and jagged-WHIR paths agree at current HEAD. The ignored target is the performance benchmark. |
| git diff --check | PASS before the report append | Existing tracked worktree changes had no whitespace errors. |

No product source file was changed by this audit section. The only audit write
is this append to CODE_REVIEW_REPORT.md; pre-existing paper and figure changes
were left untouched.

# Re-review of the current fixes at 27dd8414

## Baseline and evidence boundary

This follow-up reviews HEAD
`27dd84141adb886b213555e340bd9d9025bbfea7`, including:

- `b9d6a899`, which makes the inner jagged round count mandatory and expands
  the protocol-profile input;
- `14af2217`, which fixes the stacked-WHIR surplus-tail selection and binds the
  final polynomial before final grinding and query sampling; and
- `c03e9b43`, which separates structural jagged-proof decoding from the
  untrusted verification decode and corrects `MipsAirId::Range` iteration
  order; and
- `27dd8414`, which supplies the input now read by the Fibonacci guest to the
  core-machine test executors and proving re-executions.

The adjacent `ziren-gpu` tree remains at
`db8d3c0258aafe09990930999a4c5f388bd2b8b6`; none of the files supporting
ZR-37 or ZR-43 changed. The previously concurrent edits to
`crates/core/machine/src/mips/mod.rs` and
`crates/core/machine/src/utils/test_harness.rs` were committed as `27dd8414`
during the validation run and are reviewed separately below. This audit did
not modify them.

The Flounder CLI is not installed in this environment (`command -v flounder`
returned no executable), so no Flounder control-plane run or isolated
execution confirmation exists for this pass. Findings below distinguish
source confirmation from executed regression evidence.

## Strict status at this baseline

| ID | Severity | Current status | Strict result |
|---|---:|---|---|
| ZR-27 | Defence-in-depth | Closed in the reviewed source | `c03e9b43` keeps structural decoding for the recursion lift while both untrusted byte-verification sites use the protocol-checking decoder; already-structured bundles retain their per-use height checks. |
| ZR-32 | Critical | Closed in source; regression executed | `14af2217` requires exact configured cardinalities before drawing challenges and authenticates the final phase against canonical round indices. |
| ZR-33 | Critical | Closed in source; honest/tamper regressions executed | Native stacked/interleaved prover and verifier plus the recursive verifier absorb the final polynomial before final PoW and queries. This is source-confirmed and honest/tamper-path tested, not an executed adaptive-forgery reproduction. |
| ZR-34 | High | Closed in source | `b9d6a899` unconditionally requires the machine-derived inner round count before checking the main-round geometry. |
| ZR-35 | Medium | Open, unchanged | No change reached the BaseFold wide-leaf indexing path. |
| ZR-36 | Critical | Open, unchanged | The safe generic raw-copy/byte-initialization APIs are unchanged. |
| ZR-37 | Critical | Open, unchanged | The host-reference and asynchronous CUDA-copy contract is unchanged in both repositories. |
| ZR-38 | High | Open, unchanged | `Buffer<T, A>` remains unconditionally `Send + Sync`. |
| ZR-39 | Medium | Open, unchanged | `CpuBackend::allocate` still constructs `NonNull` without a null check. |
| ZR-40 | High | Open, unchanged | No tracked soundness-model change corrects the stacked-WHIR batching law or validates the published aggregate bit claim. |
| ZR-41 | Medium | Open; partial remediation only | Current configuration fields are now absorbed, but an actual WHIR transcript change kept the same digest, and no runtime consumer enforces the digest. |
| ZR-42 | Low | Open design defect, unchanged | The remaining BaseFold-specific shard proof names are unchanged. |
| ZR-43 | Low | Open design defect, unchanged | The TLS guard still clears rather than restores a prior nested worker context. |
| ZR-44 | High | Open | The checked-in VK allowlist does not contain the production WHIR leaf program and predates the latest transcript change; the only repository WHIR e2e disables VK membership. |
| ZR-45 | Low | Open test-design defect | `27dd8414` passes Fibonacci stdin to the BaseFold `simple_program` no-shape control but not to its stated WHIR control twin, so the paired regression no longer has identical inputs. |

## Fix review

### ZR-32 — the canonical final WHIR oracle is now selected

`StackedWhirVerifier::verify_trusted_evaluation` now rejects any mismatch in
the exact configured lengths of `round_commitments`, `round_ood_answers`,
`round_sumcheck_polys`, `round_query_openings`, `final_sumcheck_polys`, and
`folding_pow` before replaying any challenge
(`crates/pcs/src/whir/stacked.rs:906-941`). The final openings are taken from
`num_rounds - 1`, and the final committed root from `num_rounds - 2`, rather
than from proof-controlled tails (:1177-1185 and :1227-1237).

The regression in `crates/pcs/src/whir/test.rs:626-684` appends a duplicate
tail independently to five proof vectors and requires rejection. The focused
WHIR suite executed those controls successfully. The recursive verifier also
uses the canonical indices
(`crates/recursion/circuit/src/whir_circuit.rs:618-624` and :673-680), so a
surplus recursive witness no longer substitutes
the final root even though its host-provided shape would compile as a distinct
program.

Strict verdict: the reported surplus-tail authentication substitution is
closed at the source boundary reviewed here.

### ZR-33 — final-polynomial Fiat-Shamir ordering now matches WHIR

The final polynomial is absorbed coefficient-by-coefficient before
`final_pow` is generated or checked and before any final index is sampled in:

- the stacked prover (`crates/pcs/src/whir/stacked.rs:762-787`);
- the stacked native verifier (:1167-1191);
- the interleaved prover and verifier
  (`crates/pcs/src/whir/interleaved.rs:410-423` and :661-675); and
- the recursive verifier
  (`crates/recursion/circuit/src/whir_circuit.rs:610-641`).

The recursive path decomposes each extension element into base-field limbs via
`observe_ext_element`, matching the convention used for the other native/
recursive extension-field transcript messages. The ordering also matches SP1
WHIR, which validates the fixed final-polynomial length, absorbs that constant-
length extension slice, checks final PoW, and only then samples final indices
(SP1 v6.3.1, `slop/crates/whir/src/verifier.rs:461-480`, inspected in the local
reference checkout).

Strict verdict: the source-level Fiat-Shamir ordering defect is closed. The
ordinary final-polynomial tamper test is not evidence that the old adaptive
selection attack was executed; it only confirms constraint enforcement on an
honest-shape proof.

### ZR-34 — the inner geometry pin is no longer conditional

The inner verifier computes `expected_rounds = usize::from(n_prep > 0) + 1`,
rejects every different `combined_packing.round_counts.len()`, and only then
selects the main round and calls `check_round_geometry`
(`crates/pcs/src/shard_level/verifier.rs:1093-1115`). Empty legacy metadata and
surplus round metadata can no longer bypass the machine-derived width/height
pin.

Strict verdict: the reported conditional-bypass path is closed in source. No
dedicated adversarial unit test for empty and surplus inner round lists was
found in this pass, so this closure is not labelled execution-confirmed.

### c03e9b43 decoder split

`JaggedPcsProof::from_bytes` is now explicitly structural, while
`from_bytes_for_verification` adds the fixed protocol stacking-height check
(`crates/pcs/src/jagged_pcs.rs:1067-1110`). The two untrusted byte consumers in
`crates/pcs/src/shard_level/verifier.rs:592-605` and :916-927 use the strict
variant. Recursion-only structural consumers continue to receive the real
bundle rather than treating a foreign-height, otherwise parseable proof as
`None` and silently replacing it with the empty placeholder. The direct
structured-bundle verification checks at `jagged_pcs.rs:2250-2264` and
:2518-2523 remain in place.

The `MipsAirId::Range` move is also internally consistent: its discriminant
remains 65, while declaration iteration now matches the actual insertion order
`Byte, Range, SysLinux` in `MipsAir::get_chips_and_costs`. The only repository
consumer of `MipsAirId::iter()` is the explicit order-parity test, so no
serialized identifier or production shape-key ordering changed in the traced
call graph.

### 27dd8414 Fibonacci-input test repair and ZR-45

The Fibonacci guest now reads a serialized `u32`. Every changed Fibonacci call
site in `crates/core/machine/src/mips/mod.rs` supplies `fib_stdin()` both to an
explicitly constructed `Executor` and to the later proving re-execution when
both phases exist. The new `run_test_with_stdin` helper in
`crates/core/machine/src/utils/test_harness.rs:69-82` applies the same input to
those two phases, consistently with the pre-existing `run_test_io` flow. The
new HEAD compiles all `zkm-core-machine` test targets.

These changes are confined to a `#[cfg(test)]` module and a documented
test/example harness; no PCS, transcript, verifier, recursion circuit, or
production proving path changed. They therefore do not alter any protocol
finding above.

One edit is not a Fibonacci repair. `test_simple_prove_no_shape` executes
`simple_program()` without input and then calls `run_test_core` with
`fib_stdin()` (`mips/mod.rs:982-994`). Its stated WHIR control twin passes an
empty `ZKMStdin` (:997-1011). The simple guest does not read the surplus input,
so this is not a proof-language or soundness defect, but the two tests no longer
exercise the same harness input despite the explicit control-twin claim.

Strict verdict: the Fibonacci-input execution failures are repaired in the
reviewed test paths. ZR-45 remains open at Low severity as a regression-design
integrity defect with no production impact established.

## ZR-41 remains open — the digest does not identify or enforce the protocol

`b9d6a899` does absorb every field currently present in `WhirConfig` and
`FriConfig`, and its parameter-mutation tests pass. That closes the specific
list of configuration omissions reported previously, but not the property the
module claims.

The decisive counterexample is already in the reviewed history:

1. `b9d6a899` pins the digest to
   `2968c9ff1a0811a467451d5f36fd9b167220bef01d686dcb4771800c2700a372`.
2. `14af2217` changes the Fiat-Shamir transcript by inserting the final-
   polynomial observation and explicitly states that every recursion VK moves.
3. `git diff b9d6a899..c03e9b43 -- crates/pcs/src/profile.rs` is empty. The old
   and new, proof-incompatible protocols therefore expose the same profile
   digest.

There is no WHIR final-polynomial-order revision in `TRANSCRIPT_PROFILE`.
Configuration absorption cannot detect an event-order change. It is also not
"covered by construction": `absorb_whir_config` and `absorb_fri_config` list
fields manually, so adding a struct field does not make either function fail to
compile. The current tests only mutate the fields the test author already
listed.

Repository-wide searches found no caller of `transcript_profile_digest()` or
`transcript_profile_digest_hex()` outside their definitions, tests, and the
soundness document, and no caller in the adjacent `ziren-gpu` tree. The claimed
startup mismatch rejection therefore does not exist in the reviewed code.

Finally, `push_u64` emits only two 31-bit limbs and masks each with
`0x7fff_ffff` (`profile.rs:112-117`), dropping bits 62 and 63. Contrary to its
documentation, the encoding is not injective over its declared `u64` domain;
values separated only in either high bit collide before hashing. Production
parameters are much smaller, so this is not assigned a separate exploit
severity, but it is another false completeness property.

Strict verdict: ZR-41 remains open at Medium severity. The present function is
a tested digest of the currently enumerated values, not a protocol identity or
an enforced mixed-build boundary.

## ZR-44 — High — production WHIR recursion is absent from the checked-in VK allowlist

The default core path uses jagged WHIR, and the repository's dedicated WHIR
compress test states that its leaf program is a new recursion shape whose VK is
"not in the enumerated vk_map yet". The test sets `VERIFY_VK=false` before
running (`crates/prover/src/lib.rs:3413-3439`).

That is not the production default. `ZKMProver::new` defaults
`VERIFY_VK` to true and loads `crates/prover/vk_map.bin`
(`crates/prover/src/lib.rs:633-650`). When membership is enabled,
`make_basefold_merkle_proofs` panics if a child VK digest is absent
(:2471-2493). When it is disabled, the circuit still authenticates some dummy-
map leaf but deliberately omits equality between that leaf and the actual
child VK digest (`crates/recursion/circuit/src/machine/vkey_proof.rs:85-95`).

The checked-in `vk_map.bin` and `dummy_vk_map.bin` were last changed by
`47e6a644` on 2026-09-18. Neither artifact changed in `14af2217` or
`c03e9b43`, despite the former changing the recursive WHIR verifier transcript
and therefore its program VK. No checked-in VK, VK-root, or proof artifact was
updated with these fixes.

### Impact

The repository does not contain a self-consistent default-configuration path
that both accepts the current production WHIR leaf program and enforces its
membership in the checked-in recursion allowlist. With the default gate on,
the missing key is an availability/proving blocker. Turning the gate off also
turns off the child-VK-to-allowlist-leaf equality, so that execution is not
evidence of production VK membership or end-to-end artifact validity.

This is source and repository-artifact evidence only. The deployed map,
environment, recursion keys, and Groth16 ceremony artifacts were not inspected,
so this finding makes no claim about the live deployment state.

## Validation record

| Command | Result | Interpretation |
|---|---|---|
| `cargo test -p zkm-pcs whir::test --lib -- --nocapture` | PASS: 10 passed, 1 ignored, 220 filtered | Honest tower/interleaved/stacked/jagged paths agree; the stacked test executes all five surplus-tail rejection controls. |
| `cargo test -p zkm-pcs profile::tests --lib -- --nocapture` | PASS: 5 passed | Every currently enumerated WHIR/FRI field mutation moves the absorbed stream and the current digest pin matches. It does not refute ZR-41's event-order and enforcement counterexamples. |
| `cargo test -p zkm-pcs a_bundle_with_a_foreign_stacking_height_does_not_decode --lib -- --nocapture` | PASS: 1 passed, 230 filtered; 659.69 s | The strict untrusted-input decoder rejects every foreign stacking height exercised by the regression. |
| `cargo test -p zkm-recursion-circuit whir_circuit --lib -- --nocapture` | PASS: 5 passed, 126 filtered; 3,805.69 s | Full CPU recursion proofs pass for the uniform and mixed fold schedules; three circuit-runtime controls reject a tampered batch evaluation, final polynomial, and Merkle leaf. This still does not reproduce the old adaptive Fiat-Shamir attack. |
| `cargo check -p zkm-core-machine --tests` | PASS | The newly committed stdin helper and all updated core-machine unit-test call sites compile at `27dd8414`. |
| `git diff --check` | PASS | The current tracked worktree changes contain no whitespace errors. |

No product source file was changed by this re-review. Only this report was
appended; all concurrent worktree changes were preserved.

# Status review of the 2026-09-20 audit-fix series

## Evidence boundary

This pass answers which of the remaining findings can be closed after the
latest fixes. The source baselines at the end of the review are:

- the local report workspace and the canonical Ziren tree on
  `ant-5090-2:~/sd/Ziren` are both at
  `11cef6074248664617eeae60fd077fd671a9359f`. The concurrent uncommitted
  VK-shape diagnostic edits to `crates/prover/src/lib.rs` and
  `crates/prover/src/shapes.rs` were not used as closure evidence or
  modified by this audit; and
- the authoritative GPU tree on `ant-5090-2:~/sd/ziren-gpu` is at
  `904cb3ce293313f4b984d7eb38bbab654796ead2`. Its untracked top-level
  `vk_map.bin` was not used or modified.

The older adjacent local `/data/stephen/ziren-gpu` clone is not authoritative
and is excluded from the final GPU classifications. The Flounder CLI is not
installed in this environment, so this is a source review plus focused
execution evidence, not a Flounder control-plane result.

## Strict current status

| ID | Severity | Current status | Strict result |
|---|---:|---|---|
| ZR-23 | Critical | Closed, unchanged | The latest series changes names and ancillary controls, not the already-reviewed commitment ordering or outer binding. No regression was found in the spot-checked source path. |
| ZR-24 | Critical | Closed, unchanged | Component openings and the FRI first-query authentication remain present; the latest series does not remove those checks. |
| ZR-35 | Medium | **Closed** | The verifier checks each leaf's exact width before indexing its round coefficient slice; both wide- and narrow-leaf rejection regressions pass. |
| ZR-36 | Critical | **Closed in the main source** | Byte-copying safe APIs and clone operations require `T: Copy`; arbitrary byte initialization is unsafe; zero initialization requires `Zeroable`; host dereference is separately gated. |
| ZR-37 | Critical | **Open; partially fixed** | `HostAddressable` closes the device-pointer-as-host-reference half. The authoritative CUDA `DeviceMemory` implementation still returns after enqueueing async copies and memset, contrary to the main trait's mandatory completion contract. |
| ZR-38 | High | **Closed** | `Buffer<T, A>` now implements `Send` only for `T: Send` and `Sync` only for `T: Sync`. |
| ZR-39 | Medium | **Closed** | `CpuBackend::allocate` converts a null allocator result to `AllocError` instead of constructing an invalid `NonNull`. |
| ZR-40 | High | **Open; publication impact contained, model not fixed** | The generated report now prominently disclaims its stale 100-bit figure, but the input still labels `dense_batch = 220` a conservative upper bound while the enumerator permits a combined preprocessed-plus-main count below 227, i.e. up to 226. No supported generator has recomputed the corrected model. |
| ZR-41 | Medium | **Closed at the reviewed artifact boundary** | Transcript event revisions are explicit, integer encoding is injective, configuration coverage uses exhaustive destructures, and the default VK-map load rejects a profile mismatch. The checked-in map profile equals the pinned current digest. |
| ZR-42 | Low | **Open; partially fixed** | The internal proof/verifier/opened-value/constraint-folder names were substantially corrected, but the public `ShardProof::basefold_shard_proof` field and its documentation still call a `JaggedShardProof` carrying either BaseFold or WHIR a “shard-level BaseFold proof.” |
| ZR-43 | Low | **Closed in the authoritative GPU tree** | Ownership moved to `zkm-gpu-core`; all reviewed GPU call sites use that module; the guard restores the previous TLS value on drop. Five direct unit tests, including nesting and panic unwinding, pass. |
| ZR-44 | High | **Closed by owner disposition, with bounded evidence** | The VK map and root were regenerated together at `d5ee27e`, then extended at `11cef607` with the missing keys observed from production block 26017940; that block reportedly passes with `VERIFY_VK=true`. The commit explicitly does not establish general shape coverage. |
| ZR-45 | Low | **Open, unchanged** | The claimed BaseFold/WHIR control twins still execute the same program with different stdin: the BaseFold case passes `fib_stdin()`, while the WHIR case passes `ZKMStdin::new()`. |

Thus, among ZR-35 through ZR-45, ZR-35, ZR-36, ZR-38, ZR-39, ZR-41,
ZR-43, and ZR-44 are closed. ZR-37, ZR-40, ZR-42, and ZR-45 remain open.

## Closure evidence

### ZR-35 — malformed BaseFold leaves now reject before indexing

`crates/pcs/src/basefold/verifier.rs:237-280` derives the number of
polynomials in the round, obtains the corresponding coefficient range through
`get`, computes the total width of each supplied leaf, and returns
`IncorrectShape` unless the width exactly equals the round claim count. The
coefficient indexing at lines 274-279 therefore occurs only after the equality
check. The focused regression executed both surplus- and deficient-width
controls successfully.

### ZR-36, ZR-38 and ZR-39 — the main tensor unsoundnesses are closed

The current tensor surface carries the missing type obligations:

- `Buffer`, `Tensor`, and `Mle` clone paths and safe raw-copy extension
  paths require `T: Copy`;
- `Buffer::write_bytes` is unsafe and documents the value-validity
  obligation, while zero construction uses the unsafe marker trait
  `Zeroable`;
- `Deref` and `Index` exist only for a `HostAddressable` backend;
- the raw-pointer auto-traits are conditional on `T: Send` and `T: Sync`;
  and
- the CPU allocator uses `NonNull::new(...).ok_or(AllocError)?`.

The `Zeroable` value test passes. These controls close the ownership,
value-validity, auto-trait, and null-pointer findings in the main repository.
They do not close ZR-37's separate asynchronous-backend contract violation.

### ZR-41 — the protocol profile is now complete for its stated mechanism and consumed

Commit `fb7d737` replaces field-by-field configuration access with exhaustive
destructuring of `WhirConfig`, every `RoundConfig`, and `FriConfig`.
Adding a configuration field now fails compilation until the digest code
classifies it. Earlier fixes also:

- add revisions for final-polynomial-before-grinding and exact WHIR round
  cardinalities; and
- encode every `u64` as three base-`2^24` limbs, which is injective in the
  KoalaBear field.

Commit `522a21a` supplies the missing production consumer. When
`VERIFY_VK=true` (the default), `ZKMProver::new` compares
`crates/prover/vk_map_profile.txt` with this build's profile before loading
`vk_map.bin` and stops immediately on a mismatch. The recorded profile,
`5f0c3cd40898194906e28b051315082a68dfd7d93dc983564d000dc0266f206b`,
equals the digest pinned by `profile_digest_is_pinned`. The seven focused PCS
profile tests pass, including high-bit encoding and foreign-profile rejection.

This closes ZR-41 at the concrete binary-to-VK-map artifact boundary reviewed
here. It is not a claim that every possible external process transport
performs an independent handshake.

### ZR-43 — the guard moved to the repository that owns the GPU context

Main commit `6feac6c9` deletes the GPU-only TLS module from `zkm-pcs`.
GPU commit `904cb3c` adds the same facility to
`zkm_gpu_core::gpu_worker_context` and updates the prover, pipeline,
shard-prover, dispatch, and test call sites to the new owner. The guard stores
`current_gpu_pool_worker_device()` at construction and writes that saved
value back in `Drop`, so nested guards unwind to the enclosing device rather
than clearing the context.

Compiling `core/src/gpu_worker_context.rs` directly with `rustc --test` and
placing the binary under `~/sd/tmp` executed all five tests successfully:
empty context, single guard, nested device restoration, deep nesting, and
panic unwinding.

### ZR-44 — owner-closed after map/root regeneration and a production-block gate

Commit `d5ee27e` changes both `crates/prover/vk_map.bin` and
`crates/verifier/bn254-vk/vk_root.bin` for the current transcript. Commit
`11cef607` then records that enumeration alone missed most leaf keys emitted
by production block 26017940, unions that block's 57 observed leaf keys into
the map, and changes the root again. The final committed map SHA-256 is
`e6b5144b39da394c73647e495441a7c5b611a7920b0bd4faa2d3c811bfb4820c`,
and the final committed root is
`00cd6f0599e8e7acc84e53b7dd1841ad4b857cfc9a08621931ccff86eb33f2ca`.
The map's checked-in profile is the current pinned digest described under
ZR-41.

The `11cef607` commit records an executed production-block control with
`VERIFY_VK=true`, `RETH_RC=0`, 102 accepted child leaves, and zero rejected
leaves. This audit did not independently rerun that 52.3-second production
gate. The same commit expressly states that one block does not establish
general coverage and that unseen blocks should still be expected to reject
until a broader collection exists.

Per the owner's instruction, ZR-44 is removed from the active findings. The
closure is therefore a disposition backed by a regenerated profile-bound
artifact and one recorded production workload, not proof that the current
map covers every reachable leaf shape. It also does not assert that the
separately generated Groth16 or PLONK artifacts were regenerated.

## Findings that remain open

### ZR-37 — the remote CUDA backend contradicts the safe trait contract

Both the local and remote Ziren `DeviceMemory` trait state that
`copy_nonoverlapping` and `write_bytes` **must be complete when they
return**, because safe callers can end a host borrow or read the destination
immediately afterwards.

At authoritative GPU revision `904cb3c`,
`core/src/device/backend.rs:16-24` explicitly says every operation is async
and none synchronizes. Its `DeviceMemory for CudaBackend` implementation at
lines 103-136 calls the async H2D, D2H, D2D, and memset functions and returns
their enqueue result without a completion barrier. This permits a safe
`extend_from_host_slice` caller to release its source while CUDA may still
read it, and permits a safe D2H consumer to observe the destination before it
has been initialized.

The `HostAddressable` repair is valid and closes the other half of ZR-37, but
the async lifetime/completion half remains a Critical open finding.

### ZR-40 — a disclaimer is not a corrected soundness calculation

Commit `77932a2` appropriately marks
`docs/soundness/ziren.soundcalc-report.md` as stale and unsupported. That
prevents the displayed 100-bit headline from being presented as a current
bound, but does not validate the model.

The remaining concrete mismatch is:

1. `ziren.soundcalc.toml` says the core batch is conservatively bounded by
   `ceil(460,000,000 / 2^21) = 220`.
2. `crates/prover/src/shapes.rs` defines
   `MAX_BLOCKS = (ELEMENT_THRESHOLD >> 21) + 8 = 227`.
3. Its concatenated preprocessed-plus-main guard accepts totals strictly below
   that value, so the enumerated admissible ceiling is 226, not 220.

No reachability proof in the reviewed code reduces that declared ceiling back
to 220. In addition, the checked-in generator cannot express the non-uniform
`[3, 6, 6]` fold schedule, so the corrected input has not produced a
supported aggregate bound. ZR-40 remains open.

### ZR-42 — the public proof payload still has the wrong protocol name

Commits `8460f902` and `54b4f6e` correctly rename the main
`JaggedShardProof`, verifier, error, opened values, constraint folders,
zerocheck verifier, verifying-key variable, and assembly function. Names that
refer specifically to the dense BaseFold PCS remain appropriately unchanged.

The public boundary still contradicts that distinction:
`crates/pcs/src/types.rs:70-81` calls
`ShardProof::basefold_shard_proof` “the shard-level BaseFold proof,” while
its type is `JaggedShardProof` and its evaluation-proof enum can carry WHIR.
The same field name propagates through both Ziren and ziren-gpu. The reported
design ambiguity therefore remains, although its internal surface has been
substantially reduced.

### ZR-45 — the paired PCS regression still does not hold inputs constant

At remote Ziren HEAD, `test_simple_prove_no_shape` still invokes
`run_test_core(..., fib_stdin(), None)`, while the immediately following
`test_simple_prove_whir_inner_pcs`, described as its control twin, invokes
`run_test_core(..., ZKMStdin::new(), None)`. The program is the same but its
input is not. No commit in the reviewed fix series changes this test.

## Validation record

| Command or check | Result | Interpretation |
|---|---|---|
| `cargo check -p zkm-pcs --all-targets` at final HEAD `11cef607` | PASS, clean | The PCS changes compile across all targets; the earlier warnings are fixed by `e644b14`. |
| `cargo test -p zkm-pcs a_leaf_ --lib -- --nocapture` | PASS: 2 passed | Wide and narrow malformed BaseFold leaves reject. |
| `cargo test -p zkm-pcs profile::tests --lib -- --nocapture` | PASS: 7 passed | Current parameter mutations, encoding, digest pin, and mismatch rejection behave as intended. |
| `cargo test -p zkm-pcs zeroed_bytes_are_the_additive_identity --lib -- --nocapture` | PASS: 1 passed | The zero-value control executes through the `Zeroable` contract. |
| Remote `rustc --test core/src/gpu_worker_context.rs` with output under `~/sd/tmp` | PASS: 5 passed | ZR-43's TLS restoration, nesting, and unwind behavior execute successfully. |
| Remote `cargo test -p zkm-gpu-core gpu_worker_context --lib --locked` with `CARGO_TARGET_DIR` under `~/sd/tmp` | BLOCKED before tests | The Ziren recursion build script requires a target-directory layout it did not receive, and the selected Go toolchain rejects the repository's `go.mod`. This is not a test failure; the self-contained module tests above were then executed directly. |
| VK-map profile literal versus PCS digest pin | MATCH: `5f0c3cd4...206b` | The default artifact consumer accepts the map under the committed current profile. |
| Committed VK-map and VK-root comparison at `d5ee27e` and `11cef607` | BOTH CHANGED TOGETHER TWICE | The transcript regeneration moved both artifacts; the production-block key union then moved both again. |

This review changed no product source, VK artifact, or remote repository. It
only appended this section to `CODE_REVIEW_REPORT.md`; all concurrent local
and remote worktree changes were preserved.

# Re-review at Ziren `fb46b8a1` and ziren-gpu `9c9d958d`

## Evidence boundary

This pass reviews the fixes in Ziren commits `9025bcb4` and `fb46b8a1`, and
the CUDA completion fix in ziren-gpu commit `9c9d958d`. The exact source
states are:

- local Ziren branch `feat/upgrade-plonky3` at
  `fb46b8a1ba6cf7013a6fb123a8ad9c7bf6c6c960`, equal to its tracked
  `origin/feat/upgrade-plonky3` at review time; and
- remote ziren-gpu branch `feat/gpu-basefold-primitives-2` at
  `9c9d958d0b58437c13afe00147fa6e23ceb6ade4`, equal to its tracked remote.

The remote Ziren checkout is one commit behind the local audit-fix branch at
`9025bcb4` and has concurrent modified VK artifacts. It was used only to
establish the GPU checkout's current path dependency; none of its files was
modified. The GPU checkout's untracked `vk_map.bin` was likewise not used or
modified. The Flounder CLI is not installed, so this is a manual source audit
plus focused execution evidence, not a Flounder control-plane result.

## Strict status after the new fixes

| ID | Severity | Current status | Strict result |
|---|---:|---|---|
| ZR-37 | Critical | **Closed in source** | The authoritative CUDA backend now synchronizes H2D, D2H, D2D and memset operations before the trait call returns. This satisfies the main repository's `DeviceMemory` completion and safe-borrow contract. |
| ZR-40 | High | **Open; attempted fix is not a valid upper bound** | `dense_batch = 226` is derived from an enumeration-only guard that `9025bcb4` immediately stops using for normalize proofs. The production prover/verifier does not enforce the same combined-round bound, and an admitted `2^22` Program band plus a near-cap main round already commits 32 + 224 = 256 stripes. |
| ZR-42 | Low | **Open; partially fixed** | The public field is correctly renamed `jagged_shard_proof`, but the public `basefold()` accessor and BaseFold-only payload documentation remain. More importantly, the tracked GPU branch still accesses the removed `basefold_shard_proof` field, so the reviewed branch pair is source-incompatible. |
| ZR-44 | High | **Closed by owner disposition, unchanged** | `9025bcb4` makes the bounded nature of the closure more explicit: normalize keys cannot be enumerated from the machine and are collected from actual proofs. This does not establish general workload coverage, but does not reopen the owner-closed finding. |
| ZR-45 | Low | **Open; partially fixed** | Both tests now use empty stdin, closing the reported input mismatch. They still instantiate the same `CpuProver` and the same ring whose `WHIR_INNER_PCS` is fixed to `true`; the purported BaseFold control is therefore another WHIR run, not a BaseFold/WHIR control pair. |
| ZR-46 | Low | **Open; new regression** | `generate` still constructs the complete normalize `small_shapes` sweep and discards it, so the claimed removal retains its cost. A default, non-ignored prover test also still requires an emitted normalize shape and now deterministically fails. |

The active set among these findings is therefore ZR-40, ZR-42, ZR-45 and
ZR-46. ZR-37 is closed by the GPU source fix. ZR-44 retains its earlier
bounded, owner-directed closure.

## ZR-37 closure analysis

At ziren-gpu `core/src/device/backend.rs:110-157`, all three arms of
`copy_nonoverlapping` enqueue their CUDA copy and then call
`self.synchronize()` before returning. `write_bytes` does the same after
`mem_set_async`. Allocation remains stream-ordered and asynchronous under the
separate `Allocator` contract; that does not violate `DeviceMemory`'s
complete-on-return requirement.

This closes both consequences of the original finding: a safe H2D caller can
end its source borrow after return without CUDA retaining a live read, and a
safe D2H/D2D/memset caller can consume the destination immediately. The commit
records seven passing on-device `cuda_backend` tests. Independent execution in
this pass was blocked before tests by the remote environment: its Go toolchain
rejects the repository's `go.mod`, CUDA headers were not visible to `nvcc`, and
the root filesystem initially had only 12 MB free. These are build-environment
failures, not failed test assertions, so closure rests on direct inspection of
the complete source path rather than a claimed independent device pass.

## ZR-40 remains open: 226 is not the protocol batch ceiling

The revised soundness input at
`docs/soundness/ziren.soundcalc.toml:43-54` treats 226 as an upper bound because
`crates/prover/src/shapes.rs:685-742` discards enumerated shapes whose
preprocessed and main stripe counts total 227 or more. That is not a live
protocol invariant:

1. The very next logic at `shapes.rs:762-788` states that normalize shapes are
   not enumerated, and reduces the computed `small_shapes` to an unused
   reference. The focused `generate_emits_no_normalize_shapes` regression
   passes and reports only 14 compress, 14 deferred and one shrink shape.
2. The executor's `ELEMENT_THRESHOLD` limits the unpadded **main** trace area.
   It neither includes the preprocessed round nor enforces
   `prep_blocks + main_blocks < 227`.
3. `committed_dense_len` at `crates/pcs/src/jagged.rs:218-225` rounds each
   non-small round separately: first to a `2^21` stripe count, then, above
   four stripes, to a multiple of eight.

The configured, admitted `2^22` Program band gives a concrete counterexample
to the claimed bound. The preprocessed dimensions are:

- Program: `2^22` rows by 14 columns;
- Byte: `2^16` rows by 12 columns; and
- Range: `2^11` rows by 2 columns.

Their raw area is
`2^22 * 14 + 2^16 * 12 + 2^11 * 2 = 59,510,784` cells. This is 29 raw
`2^21` stripes and therefore 32 committed stripes. A main round at the default
460,000,000-cell area fence needs 220 raw stripes and is rounded to 224.
Consequently the two-round lambda batch can already be 256 stripes before
considering the executor's final-event overshoot. The value 226 is therefore
not conservative for the source's admitted program band.

This is a model/publication finding, not evidence that the live PCS verifier
accepts an invalid opening: the implementation derives the real stripe count
from the committed round metadata. The unsupported checked-in soundness claim
remains the affected boundary.

## ZR-42 remains open: the rename stops at, and breaks, a public boundary

The primary field and its top-level documentation are now accurate:
`ShardProof::jagged_shard_proof` carries a `JaggedShardProof` whose dense PCS
can be WHIR or BaseFold. The remaining public surface still says the opposite:

- `crates/pcs/src/types.rs:124-130` exposes `pub fn basefold()` and reports a
  missing “basefold payload” while returning `JaggedShardProof`;
- the same file describes the cumulative sums as belonging to the “BaseFold
  payload”; and
- the prover hook remains `attach_shard_basefold_side_channel`, even though
  its documentation points to `jagged_shard_proof`.

This is not only stale prose. At tracked ziren-gpu `9c9d958d`, the pipeline,
core multi-GPU, shard prover, worker, orchestrator and performance paths still
read or assign `proof.basefold_shard_proof`. That field no longer exists at
Ziren `fb46b8a1`. The two reviewed tracked branch heads therefore cannot be
compiled together without a companion API update. ZR-42 remains an open
design/API consistency defect.

## ZR-45 remains open: matching stdin does not create the claimed control

`test_simple_prove_no_shape` and `test_simple_prove_whir_inner_pcs` now use the
same program, `shape_config: None`, and `ZKMStdin::new()`. This closes the
specific stdin mismatch.

However, both call the same `run_test_core::<CpuProver<_, _>>` with no PCS
override. The second test correctly documents WHIR as the core-machine default
and checks that `whir_proof.is_some()`. The shared configuration confirms this
at `crates/pcs/src/kb31_poseidon2.rs:347-348` with
`WHIR_INNER_PCS: bool = true`. Therefore the first test's comment that it is a
“BaseFold control twin” is false: both executions select WHIR. Passing both
tests cannot detect a BaseFold-versus-WHIR behavioral regression.

## ZR-46 — discarded normalize enumeration still executes and breaks a default test

Commit `9025bcb4` changes the output iterator so it emits only compress,
deferred and shrink shapes. It does not remove the preceding normalize sweep.
`crates/prover/src/shapes.rs:703-760` still constructs the full
`small_shapes: Vec<OrderedShape>` by sweeping every cluster, Program height,
main-block target and padding target. Lines 762-788 then retain it only through
`let _ = &small_shapes`; no returned value consumes it.

The cost is observable. The focused
`generate_emits_no_normalize_shapes` test spent 49.07 seconds in its test body
to return only 29 shapes. Callers such as `build_vk_map`, `dummy_vk_map`, and
the shape-analysis scripts still enter the same dead sweep before receiving
the 29-shape tail. Thus the commit removes normalize keys from the resulting
map, but does not remove their enumeration work.

The test suite was not made internally consistent with the new contract.
The default, non-ignored
`tests::normalize_program_cache_key_implies_identical_program` still calls
`ZKMProofShape::generate(...).find_map(ZKMProofShape::Recursion)` and then
executes `.expect("the enumeration emits normalize shapes")` at
`crates/prover/src/lib.rs:2850`. The targeted test deterministically panicked
at that line: zero passed, one failed. Its 461.42-second runtime in this pass
was under concurrent proof-test load and is not used as a standalone
benchmark; the failure itself is load-independent.

ZR-46 is a tooling, test-design and offline performance defect. No production
proof or verifier path calls the stale assertion, so it is not classified as
a protocol-soundness defect.

## Validation record

| Command or check | Result | Interpretation |
|---|---|---|
| `cargo test -p zkm-prover generate_emits_no_normalize_shapes --lib -- --nocapture` | PASS: 1 passed | Current generation emits 14 compress, 14 deferred, one shrink and no normalize shapes; the guard used to justify 226 is not a normalize-proof coverage/enforcement mechanism. |
| `cargo test -p zkm-prover normalize_program_cache_key_implies_identical_program --lib -- --nocapture` | **FAIL: 0 passed, 1 failed** | The non-ignored regression panics at `crates/prover/src/lib.rs:2850` because it still requires a normalize shape from an iterator now specified to emit none. |
| `cargo test -p zkm-core-machine test_simple_prove_no_shape --lib -- --nocapture` | PASS: 1 passed in 558.99 s | The repaired empty-stdin test still proves and verifies, but its shared ring selects WHIR; it is not a BaseFold control. |
| `cargo test -p zkm-core-machine test_simple_prove_whir_inner_pcs --lib -- --nocapture` | PASS: 1 passed in 606.77 s | The explicit WHIR test proves, verifies, and asserts that its proof contains the WHIR payload. Together the two passes do not establish a PCS differential. |
| `cargo check -p zkm-pcs --all-targets` | PASS | All PCS targets compile at `fb46b8a1`. |
| `cargo check -p zkm-prover --all-targets` | PASS | All prover targets compile at `fb46b8a1`; compile success does not execute the stale test above. |
| Direct inspection of `committed_dense_len` and the admitted preprocessed band | COUNTEREXAMPLE: 32 prep + 224 main = 256 | `dense_batch = 226` is not an upper bound for the configured `2^22` Program band. |
| Remote `cargo test -p zkm-gpu-core --test cuda_backend --locked -- --nocapture` with `CARGO_TARGET_DIR=~/sd/tmp/ziren-gpu-zr37/target` | BLOCKED before tests | Old Go syntax support, missing CUDA headers, and disk exhaustion prevented an independent run; no test assertion executed. |
| Ziren `fb46b8a1` field search versus ziren-gpu `9c9d958d` field search | INCOMPATIBLE | Main exposes `jagged_shard_proof`; GPU still has multiple compiled accesses to `basefold_shard_proof`. |

The failed remote build created 2.7 GB only under the audit-owned
`~/sd/tmp/ziren-gpu-zr37` directory. That exact temporary directory was
deleted after the failure, restoring the space; no repository or pre-existing
remote file was removed. No product source, VK artifact, or remote checkout
was changed by this pass. Only this report was appended.

# Concurrent uncommitted proof-payload follow-up

## Evidence boundary

After the committed `fb46b8a1` review and its tests completed, a concurrent
actor modified ten tracked files in this same worktree. Those edits were not
made, formatted, or otherwise altered by this audit. This follow-up records
the stabilized snapshot that was present when the cross-package compile gate
completed; it does not treat uncommitted work as closure evidence for the
committed branch.

The snapshot changes `ShardProof::jagged_shard_proof` from
`Option<Box<JaggedShardProof>>` to `Box<JaggedShardProof>`, removes the
corresponding missing-payload branches, and changes the GPU extension hook
from a mutating `attach_shard_basefold_side_channel` method to a returning
`reprove_shrink_shard` method. It compiles across the local PCS, prover, SDK,
and core-machine targets after its call sites were updated.

## Strict result

| ID | Severity | Status in the uncommitted snapshot | Result |
|---|---:|---|---|
| ZR-42 | Low | **Still open** | Making the payload structurally mandatory does not rename the public `basefold()` accessor or its BaseFold-only documentation. The tracked GPU branch still uses the removed field name and the old attach-hook signature, so the cross-repository API is now further out of sync. |
| ZR-47 | Medium | **Open if this WIP lands** | Removing the outer `Option` changes the public bincode layout of core/compressed proofs without a format revision or an old-layout decoder. Existing serialized receipts and producer/consumer pairs built from different revisions are not compatible. |

No new PCS or verifier soundness defect was found in making the payload
mandatory. An invalid all-zero payload remains invalid and the verifier still
runs the full jagged proof checks. ZR-47 is a serialization and interoperability
finding, not a forged-proof acceptance claim.

## ZR-47 — the mandatory payload silently changes the public proof wire format

`ShardProof` derives `Serialize` and `Deserialize`. Under the committed type,
a populated payload serializes as an `Option::Some` discriminant followed by
the boxed `JaggedShardProof`. The WIP type serializes the boxed proof directly,
removing that discriminant and shifting every following byte of the nested
proof. This is a structural encoding change; unlike the preceding field-name
rename, it is not wire-neutral under bincode.

The affected encoding is public rather than an internal cache detail:

- `crates/sdk/src/proof.rs:70-78` specifies that a compressed proof's bytes are
  the bincode serialization of `ZKMProof` and implements exactly that;
- `crates/sdk/src/network/prover.rs:354` serializes proof receipts with
  bincode; and
- no format version, compatibility enum, or custom deserializer for the old
  `Option<Box<_>>` layout appears in the WIP.

The six passing `jagged_shard_proof` tests exercise the inner
`JaggedShardProof`'s MessagePack and legacy-inner-proof formats. They do not
serialize the outer `ShardProof` before and after the `Option` removal, so they
do not cover this compatibility boundary.

## Concurrent-WIP validation

| Command or check | Result | Interpretation |
|---|---|---|
| `cargo check -p zkm-pcs -p zkm-prover -p zkm-sdk -p zkm-core-machine --all-targets` | PASS after call-site updates | The stabilized local WIP is internally type-consistent. This says nothing about the unmodified tracked GPU repository or old serialized proofs. |
| `cargo test -p zkm-pcs jagged_shard_proof --lib -- --nocapture` | PASS: 6 passed | Inner jagged-proof construction and its existing serialization tests remain valid; the outer `ShardProof` layout change is untested. |
| Main/GPU API comparison | INCOMPATIBLE | The main WIP uses mandatory `jagged_shard_proof` and `reprove_shrink_shard`; ziren-gpu `9c9d958d` still uses optional `basefold_shard_proof` and the former attach flow. |

ZR-40, ZR-45 and ZR-46 are unaffected by this WIP and remain open. ZR-37
and the owner-disposed ZR-44 retain the statuses recorded above.

# Focused re-review of ZR-45 and ZR-46 after `46a34cc8`

## Evidence boundary

This re-review examined committed HEAD `46a34cc8` plus the current uncommitted
changes to `crates/prover/src/shapes.rs` and `crates/prover/src/lib.rs`. Those
two source changes appeared concurrently and were not authored or modified by
this audit. Consequently, closure below is explicitly attributed to the
working-tree patch; it is not yet closure in the committed branch. The
Flounder executable was not installed in this environment, so the result rests
on direct source tracing and the focused local tests recorded below.

## Strict result

| ID | Severity | Current status | Strict result |
|---|---:|---|---|
| ZR-45 | Low | **Open; no PCS-selection fix** | The stdin mismatch remains fixed, but both alleged twins still call the same `run_test_core::<CpuProver<_, _>>`. That harness constructs `KoalaBearPoseidon2`, whose `WHIR_INNER_PCS` constant is `true`. Both tests therefore execute WHIR; the first test is not a BaseFold control. |
| ZR-46 | Low | **Closed in the current uncommitted working tree; open at committed HEAD** | The discarded normalize-shape sweep is now actually deleted, and the stale non-ignored cache-key test no longer asks `generate` for a `Recursion` shape. Both focused regressions pass. |

No protocol-correctness or proof-soundness finding was added by this pass.
ZR-45 is a missing differential-test/design defect. ZR-46 was an offline
enumeration-cost and test-consistency defect.

## ZR-45 remains open: both sides still select WHIR

The control and WHIR tests at `crates/core/machine/src/mips/mod.rs:981-1025`
use the same program, empty stdin, `shape_config: None`, prover type and helper:

```rust
run_test_core::<CpuProver<_, _>>(runtime, ZKMStdin::new(), None)
```

The helper is not PCS-parametric at that call boundary. At
`crates/core/machine/src/utils/test_harness.rs:85-92` it constructs
`KoalaBearPoseidon2::new()` and builds the MIPS machine from that configuration.
The selected ring fixes `WHIR_INNER_PCS: bool = true` at
`crates/pcs/src/kb31_poseidon2.rs:347-348`. The only `false` implementation
found is the outer recursion configuration at
`crates/recursion/core/src/stark/config.rs:205`; neither core-machine test uses
it.

The explicit WHIR test's `whir_proof.is_some()` assertion correctly proves
that its run took the WHIR branch. It does not distinguish the first test,
because the first reaches the identical constant through the identical helper.
Commit `46a34cc8` only adapted access to the now-mandatory jagged proof payload;
it added no BaseFold configuration or selector. Thus the comment calling
`test_simple_prove_no_shape` a “BaseFold control twin” remains false, and two
passing executions cannot detect a BaseFold-versus-WHIR regression.

## ZR-46 is closed by the current working-tree patch

The prior defect had two independent observable parts, and both are removed in
the current patch:

1. `ZKMProofShape::generate` no longer builds `small_shapes`. The patch deletes
   the cluster, Program-height, main-block and padding-target sweep rather than
   retaining it behind `let _ = &small_shapes`. The function now begins
   directly with the actually returned compress/deferred/shrink enumeration at
   `crates/prover/src/shapes.rs:362-470`.
2. `normalize_program_cache_key_implies_identical_program` no longer calls
   `generate(...).find_map(ZKMProofShape::Recursion)` and therefore no longer
   contradicts the documented zero-normalize output. At
   `crates/prover/src/lib.rs:2768-2781` it derives its sample from
   `CoreShapeConfig::maximal_core_shapes(21)`, the same source used by
   `generate_maximal_shapes`, then still exercises both required directions:
   equal cache keys imply byte-identical programs, while changing the chip set
   changes the key.

The performance effect is directly observable. With the patch,
`generate_emits_no_normalize_shapes` still reports 14 compress, 14 deferred
and one shrink shape, but its test body completes in `0.00s`; the same test
previously spent 49.07 seconds executing the discarded normalize sweep. The
rewritten cache-key regression also completes successfully rather than
panicking on a nonexistent emitted normalize shape.

## Focused validation

| Command or check | Result | Interpretation |
|---|---|---|
| `cargo test -p zkm-prover generate_emits_no_normalize_shapes --lib -- --nocapture` | **PASS: 1 passed; test body 0.00s** | The returned set remains 14 compress, 14 deferred and one shrink shape, with no normalize shapes; the prior ~49 s dead enumeration is gone. |
| `cargo test -p zkm-prover normalize_program_cache_key_implies_identical_program --lib -- --nocapture` | **PASS: 1 passed; test body 404.86s** | The replacement fixture is constructible and the cache-key/program-byte invariants pass. The wall time was under concurrent release-test load and is not used as a performance benchmark. |
| Direct configuration trace for both ZR-45 tests | **Same WHIR configuration** | Both instantiate `KoalaBearPoseidon2`; its `WHIR_INNER_PCS` is `true`. No BaseFold control is executed. |

Only this report was changed by the audit. The concurrent product-source patch
was left untouched.

# Canonical final re-review of ZR-45 and ZR-46 at `d6e3c784`

## Superseding status

This section supersedes the provisional working-tree status immediately above.
The reviewed fixes are now committed, the product-source worktree is clean, and
`d6e3c784` is both the local and tracked branch head.

| ID | Severity | Final status | Strict result |
|---|---:|---|---|
| ZR-45 | Low | **Closed** | The false BaseFold/WHIR control pairing was removed. The core test now claims and pins only the WHIR path, while actual BaseFold commit/open/verify coverage remains on the only production ring that selects it, `KoalaBearPoseidon2Outer`. |
| ZR-46 | Low | **Closed** | The unused normalize enumeration was deleted, its 49-second dead cost is absent, and the formerly contradictory cache-key regression now builds an admitted maximal core shape. Both focused ZR-46 tests pass. |

No new protocol-correctness or proof-soundness defect was found while closing
these two test/tooling findings.

## ZR-45 closure: remove the nonexistent control, retain real scheme coverage

The committed code no longer contains `test_simple_prove_no_shape` or its
incorrect “BaseFold control twin” claim. `test_simple_prove` remains a generic
smoke test. `test_simple_prove_whir_inner_pcs` is now the only scheme-specific
core test and still requires `whir_proof.is_some()` at
`crates/core/machine/src/mips/mod.rs:1026-1053`.

This separation matches the actual type-level dispatch:

- the core helper constructs `KoalaBearPoseidon2`, whose
  `WHIR_INNER_PCS` is `true`; and
- `KoalaBearPoseidon2Outer` is the production implementation whose
  `WHIR_INNER_PCS` is `false`.

The BaseFold side is not merely documented elsewhere. At
`crates/recursion/core/src/stark/config.rs:485-613`,
`test_basefold_jagged_pcs_roundtrip_bn254` obtains the outer ring's
`bf_mmcs()`, commits, opens and verifies the jagged polynomial through the
generic BaseFold functions. The adjacent bundle and two-round substitution
tests exercise the higher-level outer BaseFold path. The focused round-trip
passed at the canonical head. Thus ZR-45 closes because the suite no longer
misrepresents two identical WHIR executions as a PCS differential, while both
schemes retain tests on the rings that actually select them.

This closure does not assert that the core machine gained a BaseFold mode; it
did not. It records that the invalid test-design claim and input-pair contract
were removed rather than left misleading.

## ZR-46 closure: dead enumeration and stale fixture are both gone

`ZKMProofShape::generate` at `crates/prover/src/shapes.rs:362-470` now starts
with the compress/deferred/shrink class enumeration. No `small_shapes` value,
cluster sweep, Program-height sweep, main-block sweep, padding-target sweep, or
discarding `let _ = &small_shapes` remains.

The cache-key regression at `crates/prover/src/lib.rs:2752-2848` now derives
its starting point from `CoreShapeConfig::maximal_core_shapes(21)`. It no
longer searches `generate` for a `ZKMProofShape::Recursion` value that the
generator explicitly does not emit. The test continues to check both relevant
directions: collisions across height-only variants must compile to identical
program bytes, and removal of a chip must change the cache key.

## Canonical validation record

| Command or check | Result | Interpretation |
|---|---|---|
| `cargo test -p zkm-recursion-core test_basefold_jagged_pcs_roundtrip_bn254 --lib -- --nocapture` | **PASS: 1 passed; 736.75s** | The outer BN254 ring executes an actual BaseFold jagged-PCS commit/open/verify round-trip. Runtime was under concurrent release-test load and is not a benchmark. |
| `cargo test -p zkm-prover generate_emits_no_normalize_shapes --lib -- --nocapture` | **PASS: 1 passed; test body 0.00s** | Canonical HEAD emits 14 compress, 14 deferred and one shrink shape, no normalize shapes, without the former ~49-second discarded sweep. |
| `cargo test -p zkm-prover normalize_program_cache_key_implies_identical_program --lib -- --nocapture` | **PASS: 1 passed; test body 404.86s** | The repaired fixture exercises the intended cache-key invariant instead of panicking while looking for a nonexistent emitted normalize shape. This was run on the reviewed patch that was then committed unchanged in the relevant functions. |
| Source trace of the two production ring implementations | **PASS** | Inner `KoalaBearPoseidon2` selects WHIR; outer `KoalaBearPoseidon2Outer` selects BaseFold. The tests now reflect that boundary. |

Only `CODE_REVIEW_REPORT.md` was modified by this audit pass.


# Focused audit of `prove_shard_with_data_boxed` and `prove_shard_with_data`

## Evidence boundary

The functions were reviewed at local HEAD `4c9e6cf6`. Their documentation-only
rewrite is committed in `396eb12e`; both source files are byte-identical between
that revision and `4c9e6cf6`. At the end of the pass the product-source
worktree was clean, while the tracked remote branch still pointed to
`5ec556cd`. The Flounder executable was not installed, so this is a direct
source/call-graph audit backed by the focused compilation and end-to-end test
below.

The device mirror was inspected read-only at ziren-gpu `9118645`. Its two
modified generated files and untracked `vk_map.bin` predated this pass and were
not touched.

## Strict result

**No new protocol-correctness or proof-soundness finding was confirmed in
either function.** The boxed adapter and the shard body preserve the required
commit/open data identity and reproduce the verifier's Fiat-Shamir sequence.
The GPU body follows the same sequence and uses the same proof-assembly helpers.

One non-security design limitation remains: `prove_shard_with_data` and
`ShardData` are public, although the function is an internal protocol driver
whose valid construction depends on parallel arrays, one fixed cube, and
commit/precompute/trace coherence. An out-of-tree caller can violate those
preconditions and obtain a panic or an unverifiable proof. No repository or
GPU production call exposes such values to untrusted proof input, and the
verifier still rejects inconsistent commitments/openings, so this is not
assigned a ZR finding or a soundness severity.

## `prove_shard_with_data_boxed`

The function is a private CPU adapter, not an independent proving algorithm.
Its security-relevant behavior is correct:

1. It clones the challenger passed at the exact post-public-value snapshot and
   advances only that per-shard clone. `StarkMachine::verify` independently
   clones the same base state per shard and performs the same public-value
   observation before entering the shard verifier.
2. `CpuProver::commit` constructs `RetainedJaggedCommit` containing the
   transcript digest, BaseFold/WHIR precompute, and name-keyed main trace store
   from the same cells. The adapter takes the store from that same owned object
   and passes the remaining digest/precompute to the shard body. The normal CPU
   call path therefore cannot mix a commitment from one trace with constraints
   evaluated on another trace.
3. The KoalaBear value/challenge type identities, fixed cube, and exact
   trace/chip count are release assertions. Each chip is then looked up by
   name; together with the `BTreeMap` trace representation, this removes both
   positional truncation and duplicate-name ambiguity.
4. Preprocessed traces are selected from the proving key by chip name and
   padded virtually to the same cube. A chip with no preprocessed column gets
   a width-zero stand-in; the actual opened preprocessed round is later driven
   by the proving key commitment's own `packing.chip_infos`.
5. Boxing occurs only after the full proof is produced. It changes ownership
   and `ShardProof` size, not transcript state, proof bytes, error checks, or
   verifier selection.

The `Option<RetainedJaggedCommit>` parameter is broader than this adapter's
actual contract: it immediately requires `Some(main_store)`. That is internally
consistent because the preceding KoalaBear type gate is exactly the branch on
which `CpuProver::commit` retains the store. The lower-level shard function's
`None` recomputation branch is not reached through this adapter.

## `prove_shard_with_data`

The transcript and algebraic chain are internally consistent:

```text
public values
  -> main commitment
  -> chip count and per-chip raw height/name
  -> LogUp-GKR
  -> alpha and GKR opening batch challenge
  -> zerocheck (lambda sampled inside)
  -> length-prefixed prep/main openings at z*
  -> preprocessed round, then main jagged opening
  -> proof assembly (transcript-silent)
```

The host verifier mirrors this ordering. The same raw height feeds the
transcript, `chip_heights`, and the degree-bit decomposition. The zerocheck
residual supplies the main-column `y_per_chip` claims directly; it is also the
source of `opened_values`, so the AIR evaluation and PCS opening do not receive
independent prover-selected values.

The two commitment rounds are sourced correctly:

- the preprocessed traces, claims and precompute come from the proving key;
  their order is read from its commitment packing; and
- the main traces and precompute come from the retained shard commit, with the
  fallback recomputing both from the same name-keyed store.

For the inner ring, the observed main digest binds the raw commitment root and
per-chip geometry, and the verifier recomputes that binding. For the outer
ring, the verifier projects the actual opened bundle commitment back to the
eight observed felts. In both cases, supplying a mismatched retained precompute
or trace store can at most produce a rejected proof; it does not decouple the
AIR openings from an accepted PCS opening.

The unsafe relabels are guarded by release-mode `TypeId` equality for both the
base and extension fields. Each owned `PaddedMle` clone is wrapped in
`ManuallyDrop` before `transmute_copy`, and each vector relabel reuses the
allocation only when the element types are identical. No unchecked cross-type
layout assumption remains on the production inner or outer rings.

## CPU/GPU parity

The device-native implementation at ziren-gpu `9118645` reproduces the same
phase ordering, challenge sampling, zerocheck-opening observation, proving-key
preprocessed round, and final assembly helpers. Its fold-orientation resolver
returns `Msb`, matching the CPU function. Device height and cumulative-sum
metadata come from `DeviceShardTraces`; host traces use the same `PaddedMle`
semantics. No transcript-order or claimed-opening divergence was found by the
static comparison.

The GPU implementation duplicates the small prologue helper because device
heights require a provider. Unlike the shared CPU helper it does not assert the
parallel-array lengths locally, but its `shared_trace_mles` vector is built by
mapping every chip immediately before the call, so the reviewed production
path constructs equal lengths. This is an internal robustness difference, not
an exploitable verifier gap.

## Performance and design observations

- Main trace cells are moved once into `Mle` storage during generation. Later
  `PaddedMle` copies in both functions are `Arc` reference-count changes, not
  trace-sized copies.
- The expensive main commitment is computed in `commit` and retained for
  `open`; the boxed adapter does not recommit it.
- Proof boxing is appropriate for the kilobyte-scale nested payload and occurs
  once per shard.
- Per-chip name allocation in the proving-key lookup and the linear search for
  each preprocessed chip are bounded by the small machine chip count; no
  trace-size-dependent avoidable work was found in these two functions.
- Internal invariant failures use assertions/panics even though `CpuProver::open`
  returns `Result`. These failures arise from locally constructed proving keys,
  trace stores, or machine metadata, not from an untrusted proof presented to a
  verifier; they are therefore an availability/debuggability property rather
  than a proof-system security finding.

## Validation record

| Command or check | Result | Interpretation |
|---|---|---|
| `cargo check -p zkm-pcs --all-targets` | **PASS** | The reviewed generic CPU prover, shard body, verifier mirrors and all PCS test targets compile. |
| `cargo test -p zkm-core-machine test_simple_prove_whir_inner_pcs --lib -- --nocapture` | **PASS: 1 passed; 324.40s** | Exercises `CpuProver::commit`, `prove_shard_with_data_boxed`, `prove_shard_with_data`, jagged-WHIR opening, and host verification end to end. |
| Direct transcript comparison with ziren-gpu `9118645` | **No divergence found** | Phase order, challenge order, height/name observations, residual opening observation and assembly agree; this is static evidence, not a claimed GPU runtime test. |
| Diff of `396eb12e..4c9e6cf6` for the two reviewed files | **Empty** | Later local commits did not change either reviewed implementation. |

Only `CODE_REVIEW_REPORT.md` was modified by this audit pass.
# Focused Protocol Audit of `prove_trusted_evaluations`

## Evidence boundary

The audit began at committed revision `715391ef` and completed at local HEAD
`1e26869b`; the intervening commit changes only VK-map/profile artifacts.
`715391ef` changes this function's documentation only, while its executable
body is still the body introduced by `a7732617`. The matching native
inner/outer verifiers, jagged
reduction, multi-round BaseFold/WHIR open, and the production construction of
`trace_at_z` were followed end to end.

The device mirror was inspected read-only at
`ant-5090-2:~/sd/ziren-gpu`, revision `df44240`. Its pre-existing untracked
`vk_map.bin` was not touched. SP1 v6.3.1 at pinned revision `8252c29` was
used as the comparison implementation. The Flounder executable is not
installed, so this section records a manual source and algorithm audit rather
than a Flounder run.

During validation, a concurrent worktree-wide documentation rewrite grew to
515 product-file modifications and temporarily made the tree syntactically
invalid. It includes comment-only edits around `prove_trusted_evaluations`,
but the executable body remains unchanged. The WIP was neither changed nor
included in the reviewed committed boundary.

## Strict verdict

**No new accepting-invalid-proof path or proof-soundness defect was confirmed
in the host `prove_trusted_evaluations` protocol.** The main and
preprocessed evaluation claims are fixed in the transcript before the fresh
column point is sampled, the jagged reduction is computed over the data behind
the precomputed commitments, and the verifier derives its reduction claim from
the openings consumed by the AIR rather than trusting the bundle's duplicate
`y_per_chip` field.

Two Low-severity defects were confirmed. Neither changes the current
verifier's accepted language:

| ID | Severity | Status | Strict result |
|---|---:|---|---|
| ZR-48 | Low | Open documentation defect | The current contract and adjacent comments describe a different mixing polynomial and several false data-flow properties. |
| ZR-49 | Low | Open GPU parity/reliability defect | The device multi-round mirror omits the host's fail-fast shape and precompute-consistency checks; malformed internal state can fail late, panic, or emit a proof the verifier rejects. |

## Protocol replay

Let `Q` be the dense polynomial obtained by concatenating the committed
preprocessed round, its zero stacking padding, the committed main round, and
its zero stacking padding. Let global column `k` start at packed offset
`o_k`, and let `y_k` be that column's evaluation at the shared zerocheck
point `z_row`.

The security-relevant order is:

```text
C_main and chip geometry
  -> LogUp-GKR
  -> zerocheck
  -> observe length-prefixed prep(z_row) and main(z_row)
  -> sample z_col
  -> jagged reduction
  -> jagged-evaluation proof
  -> WHIR/BaseFold opening
```

The prior observation of both the commitment and openings is load-bearing.
Once `z_col` is sampled, the column weights are the partial-Lagrange values

```text
lambda_k = chi_k(z_col),
```

and the dense weight polynomial is

```text
W[o_k + j] = chi_k(z_col) * chi_j(z_row).
```

Therefore the round-zero claim is

```text
t = sum_k chi_k(z_col) * y_k
  = sum_x Q[x] * W[x].
```

The Hadamard sumcheck reduces this to

```text
t = Q(r) * W(r).
```

The jagged-evaluation sub-protocol derives `W(r)` from the canonical offsets,
`z_row`, `z_col`, and the reduction point. The final WHIR or BaseFold
opening authenticates `Q(r)` against every round commitment. Thus the
evaluation claim is connected to the committed traces through one continuous
Fiat-Shamir chain.

The verifier-side binding is stronger than merely trusting the serialized
`bundle.y_per_chip`:

1. `opened_values` is the same `trace_at_z` data consumed by zerocheck and
   was observed before `z_col`.
2. Both native verifier branches pass the reconstructed preprocessed/main
   `opened_values` into `verify_jagged_reduction`; those values determine
   its round-zero claim.
3. The verifier also checks
   `sum_k chi_k(z_col) * opened_k =
   sum_k chi_k(z_col) * bundle_y_k` and requires exact per-chip column
   cardinality.
4. Canonical packing checks tie the flat offsets and column counts to the
   machine-pinned per-round geometry.
5. The preprocessed raw root is rebound to the verifying key, while the
   bundle's terminal commitment is rebound to the transcript-observed main
   commitment.

Consequently, a caller-supplied wrong `pre_y_per_chip`, point suffix, round
shape, or precompute does not create an accepting proof. On the reviewed
production path it either trips a prover assertion, yields an unverifiable
proof, or is rejected by independent verifier reconstruction.

## Round, point, and claim semantics

The two rounds are correctly ordered as `[preprocessed, main]`. Their
columns form one global column space and share one `z_col`; there is not a
separate column challenge per round. The proof carries every earlier raw root
in `preceding_commits` and the last round's commitment in `commit`, which
matches both host verifier branches.

`trace_at_z` contains padded multilinear evaluations at the full zerocheck
point, in `prep || main` order. This matches the reduction's full
`eq(z_row, row)` table. The trailing per-chip `r_row_per_chip` values are
currently algebraically ignored by `build_weight_table`; only their outer
cardinality remains checked. Thus no trailing/full-point mismatch was found.

The release-mode `TypeId` gate establishes
`Val<SC> == KoalaBear` and
`Challenge<SC> == KoalaBear^4` before any vector, slice, or
`PaddedMle` relabel. The `ManuallyDrop` ownership handling is consistent:
the reviewed casts are no-op relabels between identical concrete types, not
cross-layout conversions.

## SP1 comparison

SP1 v6.3.1 follows the same core argument in
`slop/crates/jagged/src/prover.rs:162-327` and
`slop/crates/jagged/src/verifier.rs:109-382`: it samples a fresh `z_col`,
evaluates the flattened column-claim MLE there, reduces the jagged dense
polynomial by sumcheck, verifies the jagged weight evaluation, and opens the
reduced dense claim with the stacked PCS.

SP1 supplies evaluation claims to the verifier as external inputs and enforces
exact commitment-round, claim-round, row-count, column-count, root, and padding
cardinalities before the algebraic checks. Ziren reaches the same security
boundary through `opened_values`, exact width checks, canonical packing, root
rebinding, and the cross-bind. The host Ziren prover additionally rejects
claim-count, claim-width, row-point-count, area, scheme, and stacking-height
inconsistencies before drawing `z_col`. No security-relevant deviation from
the SP1 trusted-evaluation structure was found.

## ZR-48 — the current function contract states the wrong protocol

The documentation added in `715391ef` says the jagged sumcheck reduces

```text
sum_(i,k) beta^(i,k) * y_(i,k).
```

That is not the implemented polynomial. `beta` is the earlier zerocheck/GKR
opening-batch challenge. The trusted-evaluation phase samples the vector
`z_col` and uses `chi_k(z_col)`, as shown above and explicitly stated in
`crates/pcs/src/jagged_sumcheck.rs:27-33`.

The same local contract says a missing `heights[i]` “falls back to the
provider,” but this host function has no provider and uses `1`. It says the
claim vector is empty for an “empty chip,” although a zero-row, nonzero-width
chip must carry one zero claim per column; only a zero-width chip carries an
empty vector. Adjacent comments also say the outer implementation ignores
`pre_y_per_chip`, although the outer generic prover consumes
`JaggedOpenRound.claims`, and say the verifier samples each round's
`z_col`, although the concatenated rounds share one `z_col`.

These are documentation errors, not executable soundness defects. They are
security-relevant design debt because they misstate the random polynomial and
the round transcript at the exact public boundary intended to document them.

## ZR-49 — GPU multi-round invariant checks lag the host

At remote revision `df44240`,
`basefold/src/device_jagged_trusted_eval.rs:686-1085` duplicates the host
multi-round orchestration but does not duplicate its current fail-fast
contract. In particular, the device path does not locally require:

```text
chips.len() == main_traces.len()
claims.len() == packing.chip_infos.len()
r_row.len() == packing.chip_infos.len()
claims[i].len() == packing.chip_infos[i].column_count
commit.area == prover_data.area
commit.log_stacking_height == prover_data.log_stacking_height
WHIR geometry == BaseFold prover-data geometry
all rounds have one common stacking height
area > 0 and area % stripe == 0
effective_area == next_power_of_two(sum(round areas))
```

It also still computes padding with
`area.saturating_sub(pk.total_values)`, whereas the host treats
`area < total_values` as inconsistent precomputed state.

The inputs are locally produced and the native/recursive verifiers reconstruct
geometry and commitments independently, so this audit did not find a way to
turn the omission into an accepted invalid proof. The strict impact is
cross-backend behavioral drift: an inconsistent cache, provider, or
precomputed object is rejected at the host boundary but can proceed into
device allocation, reduction, or opening and fail later.

## Performance and design result

The function still constructs two collections that no longer carry algebraic
content:

- `JaggedOpenRound.chip_traces` is not read by
  `prove_jagged_rounds_generic`; constructing the main and preprocessed views
  performs string clones, `Arc` increments, and unsafe generic relabels that
  do not affect the opening.
- The values inside `r_row_per_chip` are ignored by the full-row weight
  construction; only the vector count is used as a shape guard. The function
  nevertheless allocates and copies every suffix for both rounds.

`bundle.y_per_chip` also serializes a second copy of the preprocessed and
main openings already present in `opened_values`. The verifier correctly
uses `opened_values` as the reduction claim and uses the duplicate only for
the aggregate cross-bind. These are bounded per-column costs, not
trace-size-dependent work, and no security severity is assigned to them.

## Validation record

| Command or check | Result | Interpretation |
|---|---|---|
| `cargo test -p zkm-pcs two_round_rejects_malformed_claim_width --lib -- --nocapture` | **PASS: 1 passed; 142.77s** | The host multi-round boundary rejects a 3-value claim for a 2-column committed chip before sampling the jagged challenges. |
| `cargo test -p zkm-pcs crossbind_rejects_divergent_openings --lib -- --nocapture` in a clean `1e26869b` snapshot | **PASS: 1 passed; 136.22s** | An honest opening verifies, while changing one AIR-consumed opening is rejected by the cross-bind. The clean snapshot isolated this result from the concurrently broken worktree. |
| Static native inner/outer verifier replay | **No divergence found** | Both branches derive the reduction claim from AIR-consumed openings, require exact claim widths, pin canonical packing, and bind preceding/main roots. |
| Read-only comparison with ziren-gpu `df44240` | **ZR-49 confirmed** | Transcript order and algebra match, but the device multi-round construction lacks the host's fail-fast invariant set. |
| SP1 v6.3.1 `8252c29` comparison | **Same trusted-evaluation structure** | Fresh column-point MLE batching, jagged sumcheck, jagged evaluator, and dense PCS opening agree at the protocol level. |

Only this report was modified by this audit. All concurrent product-source
changes were preserved untouched.

# WHIR Claim/Opening and Proof-Size Audit at `ee4e0620a358`

This follow-up distinguishes the statements that the jagged layer asks WHIR
to prove from the Merkle data that WHIR uses as evidence, and evaluates the
available proof-size levers. It does not change the source or recommend
reducing security parameters to meet an EthProofs size target.

## Claims are statements; query openings are authentication evidence

For a polynomial commitment `C = Commit(f)`, an evaluation claim is the
statement `(z, y)` that `f(z) = y`. The claim is not evidence of its own
truth. An opening proof is the witness that lets the verifier check this
statement against `C`.

That distinction maps to the implementation as follows:

- `verify_jagged_whir_rounds` receives the upper-layer
  `evaluation_claim`. It interpolates the proof's echoed
  `batch_evaluations` at the batch coordinates and requires the result to
  equal that claim (`crates/pcs/src/whir/jagged.rs:290-337`).
- `verify_trusted_evaluation` absorbs the per-stripe evaluations and samples
  `lambda`, then constructs the single WHIR claim
  `sum_i lambda^i * batch_evaluations[i]`
  (`crates/pcs/src/whir/stacked.rs:865-895`). The echoed evaluations and the
  per-round OOD answers are prover-supplied claims; the transcript and later
  sumcheck constraints bind them, but they are not Merkle paths.
- `WhirProof::round_query_openings` contains the evidence sampled after the
  commitments: each `LeafOpening` carries the opened codeword/stripe values
  and the authentication path to the relevant Merkle root
  (`crates/pcs/src/whir/proof.rs:55-72`,
  `crates/pcs/src/basefold/proof.rs:25-40`). Sumcheck messages, the authenticated
  random leaves, and the revealed final polynomial jointly establish the
  claimed evaluation.

The word "opening" is sometimes used at the PCS API level for the whole
`(y, proof)` result. In `round_query_openings`, however, it specifically means
the low-level Merkle leaf values and paths. Replacing those values with the
claim, or treating OOD answers as already authenticated openings, would remove
the commitment binding.

The archived block-25907955 census illustrates the size consequence, although
it predates the current query schedule: `batch_evaluations` occupied 1,560
bytes while `round_query_openings` occupied 761,720 bytes (88.7% of the full
proof), of which round 0 occupied 680,072 bytes. The generated current
soundcalc report estimates the compress circuit at 504 KiB expected / 570 KiB
worst case, but that is a model rather than a measurement of the exact
EthProofs wire serialization. A new production proof must be measured before
claiming that the deployed artifact is below a particular byte limit.

## ZR-50 — Low — the WHIR parameter comment overstates the later-round margin

`crates/pcs/src/whir/jagged.rs:99-108` states the unique-decoding query term as

```text
q * -log2((1 + rho) / 2) + query_pow_bits
```

but annotates the rate-`2^-5` contribution as `0.978` and the rate-`2^-8`
contribution as `0.997`. The exact values under that stated formula are
`0.9556058806` and `0.9943754508`. The implemented integer budgets therefore
have the following simple per-round margins:

| queried code rate | queries | query PoW | stated-formula result |
|---:|---:|---:|---:|
| `2^-2` | 124 | 16 | 100.080916 bits |
| `2^-5` | 88 | 16 | 100.093317 bits, not 102 |
| `2^-8` | 85 | 16 | 100.521913 bits |

The parameters still clear 100 bits under this calculation, so this is not an
executable soundness defect. The correction matters for optimization: removing
one query from any of these three rows takes that row below 100 bits. There is
no unused two-bit margin in round 1. This per-round calculation also must not
be confused with composed system security: the checked-in union-bound report
already records 97.74 bits for core, 98.16 for compress, and 96.70 bits for the
whole core/compress/wrap chain.

Strict remediation is to correct the coefficients and reported round-1 total
in the source comment and add a test that derives the minimum integer query
counts from the same formula used by the soundness model. ZR-50 remains open
until the source and generated model are checked against one shared parameter
calculation.

## Proof-size optimization assessment

For round 0, the dominant value payload is approximately proportional to

```text
num_queries * 2^round0_folding_factor * sum(committed stripe counts).
```

Later-round payloads are proportional to their query counts and packed
extension-field leaf widths. Merkle paths add approximately one digest per
tree level per independently encoded query. This produces the following
strict ordering of useful work.

### 1. Measure the current wire artifact before changing the protocol

The existing `compress_proof_size_census_block25907955.md` is an archive of an
older schedule. The baseline must be regenerated from the current production
HEAD and the exact object submitted by the EthProofs client. The census must
separate, per round, opened field values, authentication nodes, vector/format
overhead, and the non-WHIR payload. It must also record proving time, verifier
cycles, and peak memory; an internal proof struct or Base64 length is not the
submission size.

### 2. Canonical Merkle multiproofs preserve sampling and can remove path duplication

The current format serializes one complete `MT::Proof` per `LeafOpening`.
Authentication paths for different queries share internal tree nodes. A
canonical multiproof can transmit the leaf values once plus a unique ordered
set of sibling nodes. This leaves the commitments, transcript-derived query
indices, query count, opened values, and soundness parameters unchanged.

The saving is limited to paths: it cannot remove the dominant stripe values.
It is therefore expected to save tens of KiB rather than the whole round-0
payload. A valid implementation must reject missing, surplus, reordered, or
conflicting nodes, bind matrix dimensions and tree height, and be implemented
identically in the native, recursive, and WASM verifiers. Deduplicating an
accidentally repeated query index is also safe if every transcript sample is
still processed, but collisions are too rare to be a primary optimization.

### 3. Search the fold schedule, especially the first folding factor

Production currently uses a first folding factor of 3 and later factors of 6.
`whir_config_for_fold_schedule` already supports non-uniform schedules. A
candidate with first factor 2 halves the round-0 leaf-value width, while
increasing the number of round-0 Merkle leaves and the path by one level and
usually doubling the small final polynomial. Because the archived proof was
dominated by round-0 values, `[2, 6, 6, ...]` is the highest-potential
parameter experiment, but it is not approved by inspection alone. It requires
soundcalc, recursive-verifier, proving-time, and memory measurements for every
supported stacking height (20, 22, and 24).

### 4. Trade a larger LDE for fewer queries only with a full cost model

At a fixed 16-bit query grind and a 100-bit per-round target, the stated
unique-decoding formula gives:

| `log_inv_rate` | rate | minimum queries |
|---:|---:|---:|
| 2 | `1/4` | 124 |
| 3 | `1/8` | 102 |
| 4 | `1/16` | 93 |
| 5 | `1/32` | 88 |

Moving round 0 from rate `1/4` to `1/8` removes 22 query leaves but doubles
the LDE and Merkle domain and adds one path node per remaining query. It is a
proof-size versus encoding/commit time, memory, and hashing trade, not a free
reduction. The complete WHIR/OOD/batching analysis, not only the table above,
must approve any candidate.

### 5. Query PoW is an exponential and generally unattractive substitute

Adding eight query-grinding bits permits approximately eleven fewer round-0
queries under the simple formula, but raises expected grind work from `2^16`
to `2^24`, a 256-fold increase for roughly a nine-percent query reduction.
It is not a competitive default for a benchmark that also reports proving
time. The existing eight-bit *batching* grind is a different event and must
not be counted a second time as query soundness.

### 6. Removing stripe values requires a new binding protocol

Round 0 authenticates every committed stripe value needed to construct the
post-claim random combination `F = sum_i lambda^i * stripe_i`. Sending only
the combined leaf would let the prover choose it after learning `lambda`,
because the hash-based Merkle commitment is not homomorphic. A smaller
aggregate opening therefore needs a separate linking argument or a different
commitment scheme. It is a protocol redesign, not a serialization change.

Claim/OOD encoding, enum tags, vector lengths, Base64, and HTTP compression
are non-dominant. Truncating digests, dropping opened values, correlating
queries across rounds, or lowering 124/88/85 without a replacement soundness
budget are not valid optimizations.

## Required experiment matrix

The minimum useful comparison on one block, guest VK, revision, and hardware
is:

| candidate | round-0 fold | round-0 rate | round-0 queries | additional change |
|---|---:|---:|---:|---|
| A | 3 | `1/4` | 124 | current baseline |
| B | 2 | `1/4` | 124 | narrower first leaves |
| C | 3 | `1/8` | 102 | larger LDE |
| D | 2 | `1/8` | 102 | combined parameter candidate |
| E | best sound candidate | best sound candidate | derived | canonical multiproof |

Each result must report the exact serialized compressed-proof bytes, values
and path bytes per WHIR round, total proving time, WHIR-open time, verifier
cycles, peak VRAM, and the minimum component and composed soundness figures.
Any transcript, proof-format, or verifier change requires a new protocol
profile digest and regenerated recursion keys/verifier artifacts before an
EthProofs cluster version can accept it.


# Whole-Circuit Soundness Re-Review at `43dcf888`

## Evidence boundary

Reviewed revision: `43dcf88886eeeca19a4a7340e9339aa88aa2b177`. The current baseline has removed the canonical Merkle multiproof experiment, so the proof-size multiproof discussion above is historical/protocol-design analysis, not a current verifier obligation.

Flounder CLI automation was unavailable in this environment, so this is a manual source review with focused local tests.

## Strict result

| Area | Current status | Strict audit result |
|---|---|---|
| ZR-23 outer jagged commitment/root order | **Closed at source level** | Current outer lift reads component openings and constructs `original_commitments = preceding_roots ++ [commit_root]` instead of the stale `[main, zero, ...]` order. If a VK preprocessed cap is present, the first preceding root is constrained to that cap. |
| ZR-24 recursive first-query/component binding | **Closed at source level; positive runtime gate incomplete** | Current recursive BaseFold recomputes the component leaf linear combination, Merkle-authenticates it to the per-round commitment, asserts residual path bits are zero, asserts the selected block value equals the running folded value, and then verifies later query-phase commitments. Four corruption tests for leaf/path/root/position reject. The honest positive test was still running after several minutes and was interrupted, so this review does not claim a completed full recursive positive proof. |
| WHIR PCS | **No open issue found in this pass** | Profile tests pass, query counts match the unique-decoding minimum used by the model, and `stacked_roundtrip_verifies` passes on the current per-path opening format. |
| Core field-output canonicality | **Closed for reviewed paths** | Ed25519 add and decompression now reject old non-canonical memory-output witnesses. Current source also range-checks Weierstrass add/double outputs, Weierstrass decompression negated output, Fp/Fp2 outputs, and uint256-style outputs where needed. |
| Raw Weierstrass add/double division by zero | **Open soundness issue** | `FieldOpCols::Div` only proves `result * denominator = numerator (mod p)` and explicitly does not prove denominator nonzero. `WeierstrassAddAssign` and `WeierstrassDoubleAssign` feed raw guest memory into division formulas without enforcing their preconditions. When add is called with `P == Q`, or double is called on an invalid point with both numerator and denominator zero, the slope is unconstrained in the AIR while the executor either panics or follows a deterministic zero-inverse path. A malicious trace can therefore prove a syscall execution the honest executor would not produce. |

## ZR-51 - High - Raw Weierstrass add/double can satisfy the AIR with an arbitrary slope on 0/0 division

`FieldOpCols` documents the division contract as `result * b = a mod M` and states that division by zero is the caller's responsibility (`crates/core/machine/src/operations/field/field_op.rs:18-30`). Its evaluator implements exactly that multiplication relation (`field_op.rs:383-391`) plus byte-range checks, but no `b != 0` witness.

`WeierstrassAddAssign` computes `slope = (q_y - p_y) / (q_x - p_x)` and calls this generic division gadget without a nonzero-denominator guard (`crates/core/machine/src/syscall/precompiles/weierstrass/weierstrass_add.rs:89-101,292-303`). If guest memory supplies the same point twice, both numerator and denominator are zero. The AIR then accepts any slope and consequently any canonical output consistent with the later slope equations and memory write binding.

The honest executor does not accept that same raw syscall path: it constructs points directly from guest memory and calls `p_affine + q_affine` (`crates/core/executor/src/events/precompiles/ec.rs:119-125`), while `sw_add` panics when the two points are identical (`crates/curves/src/weierstrass/mod.rs:199-203`). This is therefore an executor/AIR semantic split for arbitrary guest raw syscalls, not only an internal documentation problem.

`WeierstrassDoubleAssign` has the same division-gadget dependency with `slope = (3*x^2 + a) / (2*y)` (`crates/core/machine/src/syscall/precompiles/weierstrass/weierstrass_double.rs:85-116,337-372`). For valid prime-order curve points the zero-denominator case is not expected, but the raw syscall does not enforce on-curve membership. Invalid guest memory can choose `y = 0` and `3*x^2 + a = 0` for the relevant curve parameters, so the AIR again leaves the slope free while the executor's curve code maps a zero inverse to zero and emits a deterministic result (`crates/curves/src/weierstrass/mod.rs:188-197,225-242`).

Severity is High under the VM soundness model because an arbitrary guest ELF can issue raw precompile syscalls; the proof system should not accept a trace for a syscall execution that the honest executor would reject or compute differently. If raw syscall inputs are intentionally outside the language, that precondition must be enforced by the CPU/syscall AIR boundary rather than by host comments.

## Current closure notes

The non-canonical decompression concern is closed in the current source. Ed25519 decompression has `neg_x_range` populated and evaluated before the sign-selected `neg_x` is bound to memory (`crates/core/machine/src/syscall/precompiles/edwards/ed_decompress.rs:55-63,96-104,149-156,173-178`). Weierstrass decompression has `neg_y_range_check` populated/evaluated before either LSB or lexicographic sign selection binds `neg_y` to memory (`crates/core/machine/src/syscall/precompiles/weierstrass/weierstrass_decompress.rs:62-69,139-143,353-380`). The explicit secp256k1 old-attack arithmetic still exists (`sqrt(36) = p - 6` and `p + 6 < 2^256`), but the current `< p` range check rejects that forged memory value.

The previous ZR-23/ZR-24 report section is stale for this revision. Current outer code reads component openings from the stream (`crates/recursion/circuit/src/basefold_witness.rs:608-685`), requires one component-opening round per opened round, constructs `preceding_roots ++ [commit_root]`, and binds the VK preprocessed cap when present (`crates/recursion/circuit/src/shard_level_witness.rs:1277-1331`). The recursive verifier now Merkle-authenticates each component leaf to the round commitment and links the selected component value into the FRI fold chain (`crates/recursion/circuit/src/basefold_verifier.rs:982-1122`).

## Validation record

| Command or check | Result | Interpretation |
|---|---|---|
| `cargo check -p zkm-core-machine` | **PASS** | Current non-test core machine source compiles. |
| `cargo test -p zkm-core-machine non_canonical --lib -- --nocapture` | **PASS: 2 passed** | Ed25519 add and Ed25519 decompress reject old non-canonical memory-output witnesses through the new range constraints. |
| `cargo test -p zkm-pcs profile::tests --lib -- --nocapture` | **PASS: 7 passed** | PCS profile encoding/digest pinning remains stable at this revision. |
| `cargo test -p zkm-pcs query_counts_are_the_unique_decoding_minimum --lib -- --nocapture` | **PASS: 1 passed** | WHIR query counts still match the modeled unique-decoding minimum. |
| `cargo test -p zkm-pcs whir::test::stacked_roundtrip_verifies --lib -- --nocapture` | **PASS: 1 passed** | Current per-path WHIR stacked opening verifies on the focused roundtrip. |
| `cargo test -p zkm-recursion-circuit component_binding_ --lib -- --nocapture` | **INTERRUPTED after four expected-panic tests passed** | Corrupted component leaf, path, root, and position all reject. The honest positive test was still running after several minutes and was interrupted, so it is not counted as a pass. |
| `cargo test -p zkm-core-machine test_weierstrass_k256_decompress --lib -- --nocapture` | **INTERRUPTED** | Full prover smoke test exceeded the audit wait budget; no assertion failure was observed before interruption. Source-level range checks are the closure evidence for this pass. |

# Current Performance, Allocation, Parallelism, and Code-Health Audit at `5b628fb6`

## Evidence boundary

Reviewed revision: `5b628fb630c7ca6383e01c2ce45e1355a80ef668`. This is a source-level performance audit of the current CPU executor, shard prover, BaseFold/WHIR PCS, recursion compression driver, and their production comments. It specifically checks avoidable copies/clones, dead or duplicated work, Rayon structure, and allocation behavior. No percentage speedup is claimed without a representative benchmark. The severity labels below rate deterministic wasted work and peak-memory risk, not proof-system soundness.

Flounder CLI automation was unavailable in this environment. The pass therefore used manual call-graph tracing, focused repository searches, and Clippy's clone/allocation lints. No source implementation was changed by this pass.

## Strict current result

| ID | Severity | Status | Result |
|---|---:|---|---|
| PERF-01 | High | **Open** | Every inner-ring WHIR commit first constructs a complete BaseFold commitment and Merkle tree, then reconstructs dense data and commits it again under WHIR. The BaseFold tree is not verified on this path. |
| PERF-02 | High | **Open** | `ExecutionRecord::new_preallocated` applies one occurrence-based capacity to every event vector and to the distinct-key byte-lookup map. At default settings the initial reservation is `2^21` entries per container. |
| PERF-03 | High | **Open on the host/fallback WHIR path** | The WHIR adapter converts width-32 stripes into 32 owned width-1 polynomials and then copies each polynomial again into its encoded buffer; host opening also creates a full extension-field scratch vector per stripe evaluation. |
| PERF-04 | Medium | **Open** | A recursion proving-key cache is implemented and exposed, but the compression hot path still calls `compress_prover.setup(&program)` for every received node. |
| PERF-05 | Medium | **Open** | Borrowing ownership bridges clone complete trace matrices even where the comments state that callers own and use the inputs once. |
| PERF-06 | Medium | **Open** | Keccak sponge execution materializes and copies multiple input-sized buffers before recording one event. |
| PERF-07 | Medium design / Low runtime | **Open** | Three legacy WHIR prover/verifier variants are public production modules but have no non-test callers; their module-level protocol comments have drifted from the stacked production implementation. |
| PERF-08 | Medium | **Open** | BaseFold batching uses Rayon, but launches two whole-output parallel scans for every input MLE/codeword pair instead of one row-tiled scan over all inputs. |

## PERF-01 — inner WHIR pays for a discarded BaseFold commitment

`BasefoldRing::commit_multilinears` always materializes the jagged dense polynomial and calls `commit_jagged_pcs_generic` (`crates/pcs/src/config.rs:295-322`). That call performs BaseFold stacking, Reed-Solomon encoding, and an MMCS commitment. When `WHIR_INNER_PCS` is true, the same function then reconstructs a dense vector from the retained BaseFold interleaved MLEs and calls `commit_jagged_whir_generic` (`config.rs:324-341`). The trait comment itself confirms that the BaseFold Merkle tree is dead and retained data is needed only for the later reduction (`config.rs:281-284`).

The current inner configuration sets `WHIR_INNER_PCS = true` (`crates/pcs/src/kb31_poseidon2.rs:339`). Therefore this is current production work, not an inactive alternative: each inner preprocessed/main commitment incurs a dense materialization, a BaseFold interleave/encode/Merkle build, a reverse dense reconstruction, and a WHIR interleave/encode/Merkle build. Keeping the layout MLEs does not require keeping the unused BaseFold codewords or Merkle prover data.

Required performance fix: separate jagged packing/stacking from the PCS-specific encode-and-commit step. On the WHIR branch, retain only the layout/interleaved data required by the jagged reduction and build only the WHIR commitment. Validation must compare packing metadata, claims, transcript events, proof bytes, and accepted proofs before and after the change; protocol parameters must not change.

## PERF-02 — uniform record preallocation reserves the wrong cardinality

The default shard size is `2^24` cycles (`crates/pcs/src/opts.rs:230-239`). Executor construction divides this by eight and passes `2^21` to `ExecutionRecord::new_preallocated` (`crates/core/executor/src/executor.rs:598-599`). The constructor reserves that full capacity independently for roughly twenty mutually exclusive event vectors and also calls `byte_lookups.reserve(reservation_size)` (`record.rs:310-348`).

The documented heuristic is only that no *single* event kind tends to exceed one eighth of the shard (`record.rs:313-315`); it is not an upper bound and cannot justify reserving that amount for every event kind simultaneously. More importantly, `byte_lookups` is a multiplicity `HashMap<ByteLookupEvent, usize>`, whose capacity is the number of distinct lookup keys, not the number of lookup occurrences (`events/byte.rs:11-20`). Applying the instruction-occurrence estimate to that map is dimensionally wrong. Parallel replay constructs one such record for every chunk before the `par_iter` executes (`tracing_vm.rs:397-409`), multiplying unused capacities across all chunks.

Required performance fix: use per-field reservation estimates derived from an opcode/event census, and cap the byte map by measured distinct-key cardinality rather than shard cycles. Record actual length/capacity ratios per event family in a production-shaped benchmark. The constructor comment must stop describing every reserved container as a `Vec`; the map has different sizing semantics.

## PERF-03 — WHIR undoes packed stacking and repeats trace-sized copies

The protocol fixes the stacking height at 21 and the packing width at 32 (`crates/pcs/src/jagged_pcs.rs:76-98`). `commit_jagged_whir_generic` first builds those packed stripes, but `split_stripes_to_polys` immediately allocates one new vector per column and copies every cell out of each width-32 stripe (`crates/pcs/src/whir/jagged.rs:158-199`). `StackedWhirProver::encode_stripe` then clones each width-1 polynomial into another vector and resizes it for the code rate before the DFT (`crates/pcs/src/whir/stacked.rs:279-294`). The original width-1 polynomials remain retained in `StackedWhirProverData`, so the copies overlap in lifetime with commitment data.

The CPU opening path repeats work at the same scale. For each retained width-1 stripe it calls `Mle::eval_at`; that method converts the complete base-field vector into a new extension-field vector and then performs all folding rounds serially (`crates/pcs/src/whir/stacked.rs:347-354`, `crates/pcs/src/basefold/mle.rs:157-180`). Construction of the lambda-combined virtual polynomial is also a serial stripe-by-stripe traversal (`stacked.rs:374-384`). The GPU engine may replace these opening operations, so this finding is specifically confirmed for the generic CPU/fallback path; the commit-side split is present in the generic WHIR commit itself.

Required performance fix: preserve the width-32 representation through WHIR evaluation and encoding, returning the 32 evaluations together instead of deinterleaving into owned width-1 MLEs. If an intermediate fix is needed, use bounded batches and reusable scratch storage. A naive outer `par_iter` over width-1 stripes is not acceptable: each task can allocate a `2^21`-element extension-field scratch vector, so unconstrained parallelism would trade wall time for a large peak-RSS increase. Parallelize row tiles within a bounded packed buffer instead.

## PERF-04 — the recursion proving-key cache is not connected to compression

`recursion_pk_cache_get` and `recursion_pk_cache_insert` are implemented at `crates/prover/src/lib.rs:793-815`, but the only repository call sites are their definitions. The compression worker still executes `self.compress_prover.setup(&program)` for every received `(range, program, record, traces)` tuple (`lib.rs:1703-1707`). This repeats key setup for repeated recursion programs and makes the existing cache dead infrastructure on this hot path.

Required performance fix: key the setup by `recursion_pk_cache_key(program)`, use the cached `Arc<(pk, vk)>`, and coordinate concurrent misses so only one worker builds a given key. The validation gate is identical VK hashes plus cache hit/miss/build/wait counts and peak RSS; entry-count eviction alone is insufficient for large proving keys.

## PERF-05 — trace ownership bridges perform full matrix copies

`views_over_owned` accepts a borrowed slice and clones every `RowMajorMatrix.values` into a new `Arc<Mle>` (`crates/pcs/src/jagged_pcs.rs:1139-1159`). The comment already says a consuming variant could move the vectors because callers pass one-use locals, but incorrectly claims that those callers live only in `ziren-gpu`: current in-repository callers exist in `crates/pcs/src/kb31_poseidon2.rs:315-323` and `crates/recursion/core/src/stark/config.rs:426-434`. `splice_device_remat_traces` has the same ownership problem for present rematerialized matrices (`crates/pcs/src/shard_level/prover.rs:563-587`), although no in-repository call to that public bridge was found.

Required performance fix: add consuming entry points that move `String` and `RowMajorMatrix.values` into their MLEs, and keep borrowed variants only for callers that genuinely need to retain the matrices. This is distinct from `PaddedMle::clone`: `PaddedMle` stores `Option<Arc<Mle<_>>>` (`multilinear/padded.rs:119-127`), so `trace_views = shared_trace_mles.to_vec()` and the nearby `pm.clone()` operations are descriptor/`Arc` clones, not trace-sized cell copies.

## PERF-06 — Keccak sponge builds avoidable input-sized temporaries

The Keccak sponge syscall reads `input_values`, clones the read records with `extend_from_slice`, converts the entire input into a second `Vec<u64>`, then clones `input_values` again into the event (`crates/core/executor/src/syscalls/precompiles/keccak/sponge.rs:30-51,70-83`). The final output is also built as a growable vector even though its length is fixed. Clippy independently reports the final `input_values.clone()` as redundant.

Required performance fix: move `input_records` and `input_values` into the event, absorb pairs of input `u32` values directly from `input_values.chunks_exact(2)` without an intermediate `Vec<u64>`, and build the fixed-size output array directly. `xored_state_list` is witness data and is not classified as removable by this audit.

## PERF-07 — legacy WHIR implementations and comments have drifted

The production jagged path uses `StackedWhirProver`/`StackedWhirVerifier`. Repository-wide call tracing finds `WhirProver::prove`, `prove_rounds`, `prove_interleaved`, `WhirVerifier`, and `WhirInterleavedVerifier` invoked only from `crates/pcs/src/whir/test.rs`; nevertheless `full_prover`, `interleaved`, `prover`, `round_prover`, and `verifier` are all public unconditional modules (`whir/mod.rs:56-66`). This compiles and maintains three folding/opening implementations with different coverage and semantics.

The drift is already visible in comments. `whir/mod.rs:48-54` says STIR authentication and the jagged/recursive integration are future phases even though stacked WHIR and `whir_circuit.rs` are current. `whir/stacked.rs:72-74` describes production folds as `[4, 7, 7]`, while the current production config documents and constructs `[3, 6, 6, ...]` (`whir/jagged.rs:114-119`). These are protocol comments and should not contradict executable parameters.

Required code-health fix: keep one production round engine; test-only experimental variants should be gated as tests or an explicit experimental feature. Move the shared error type out of the legacy verifier before gating it. Update the module overview and fold schedule in the same change. The expected runtime gain is small, but eliminating divergent protocol implementations reduces compile work and future soundness/performance drift.

## PERF-08 — current Rayon batching repeats full-memory passes

`BasefoldProver::batch` already uses Rayon, but for every MLE/codeword pair it launches a full `par_iter_mut` pass over `batched_mle` and another over `batched_codeword_ef` (`crates/pcs/src/basefold/prover.rs:248-307`). With `M` inputs and `N` output rows, arithmetic is necessarily `O(MN)`, but this loop order also performs `M` read-modify-write passes over each large accumulator and pays repeated Rayon scheduling/barrier costs.

Required performance fix: flatten immutable input descriptors once, then parallelize over disjoint output row tiles. Each worker should traverse all descriptors for its tile and write each accumulator row once. This is the appropriate Rayon opportunity because it preserves bounded scratch memory; parallelizing whole PCS instances or width-1 WHIR stripes would multiply large live buffers. Require byte-identical proofs and benchmark memory bandwidth, task count, wall time, and peak RSS.

## Mechanical clone results that are not hotspots

Focused Clippy found small redundant clones at `crates/core/executor/src/events/precompiles/ec.rs:220`, `crates/pcs/src/basefold/verifier.rs:135`, and redundant chip-name string construction at `crates/pcs/src/prover.rs:692` / `crates/pcs/src/shard_level/prover.rs:1001`. These should be cleaned up, but they are bounded by a field element or the small machine chip count and are not trace-sized performance findings. Generic AIR-expression clones were also excluded because their concrete production representation is frequently copy-sized and Clippy's generic warning does not establish heap traffic.

## Validation record

| Command or check | Result | Interpretation |
|---|---|---|
| `cargo clippy -p zkm-pcs -p zkm-core-executor -p zkm-prover --all-targets -- -W clippy::redundant_clone -W clippy::unnecessary_to_owned -W clippy::needless_collect` | **PASS** | All reviewed targets compile; the focused lints corroborate the Keccak clone and several bounded mechanical cleanups. |
| Repository-wide call search for legacy WHIR entry points | **Only test callers found** | The stacked implementation is the production path; the other public implementations currently add production compile/maintenance surface. |
| Repository-wide call search for recursion PK cache methods | **Definitions only** | The current compression worker does not consume the implemented cache. |
| Source-level allocation and ownership tracing | **Eight open performance/design findings** | Costs are established by explicit reserve/clone/materialize/encode loops; exact speedups and RSS reductions remain benchmark-dependent. |

# Current TODO and Incomplete-Code Register at `5b628fb6`

## Scope and counting rule

The source tree contains **23 explicit `TODO` markers on 23 lines in 17 files** after excluding `target`, `.git`, `Cargo.lock`, and this report. No explicit `FIXME`, `HACK`, or `XXX` marker was found. The 23 markers divide into **18 live code/design/operational markers**, **4 stale markers whose stated work is already complete or whose surrounding code is dead**, and **1 intentional documentation-example placeholder**.

This count is marker-based, not issue-based: the same gnark environment-variable defect appears three times, and the two trusted-setup scripts contain four release/cleanup markers. A second pass inspected `unimplemented!`/panic placeholders separately, because those are real incomplete interfaces even though they are not labelled TODO.

No new proof-system soundness defect is established merely by these markers. The protocol-adjacent entries below are classified according to their demonstrated effect: artifact correctness, unsafe implementation contracts, deterministic build behavior, auditability, performance, or maintainability.

## Strict priority register

| ID | Severity | Status | Marker(s) | Strict audit result |
|---|---:|---|---|---|
| TODO-01 | High operational | **Open** | `crates/prover/scripts/write_basefold_vk_map.rs:29-31` | The registered binary writes hard-coded compress-VK hashes that its own comment says do not match the current Poseidon2 rounds, recursion programs, or guest. Running it against `crates/prover/vk_map.bin` can replace the deployed membership map with stale keys. This should not remain an executable artifact-generation path in its current form. It is an availability/release-integrity risk; no verifier acceptance bypass was found. |
| TODO-02 | High design/safety | **Open** | `crates/pcs/src/tensor/backend/mod.rs:29-35` | `Backend` is an `unsafe trait` with an empty safety contract, while the comments identify an external `ziren-gpu` implementation. The required coherence between allocator ownership, `DeviceMemory` operations, clone equivalence, async-copy lifetime/completion, deallocation, and thread safety is therefore unstated and cannot be audited at the implementation boundary. This is a safety-contract defect, not evidence of a concrete current UB execution. |
| TODO-03 | Medium | **Open** | `crates/recursion/gnark-ffi/go/zkm/build.go:30-32,207-210,431-434` | `BuildPlonk`, `BuildGroth16`, and `BuildDvSnark` mutate process-global `CONSTRAINTS_JSON`/`GROTH16` state without serialization or restoration. The exported C build entry points are not locked, although the test entry points explicitly use `testMutex` for this reason. Concurrent builds in one process can read the wrong circuit configuration. These three markers are one root cause. |
| TODO-04 | Medium performance | **Open; duplicate of PERF-05** | `crates/pcs/src/jagged_pcs.rs:1144-1155` | `views_over_owned` deep-copies every trace matrix into a new `Arc<Mle>` despite one-use owned callers. The comment is also stale in claiming callers live only in `ziren-gpu`; current in-tree callers exist in `kb31_poseidon2.rs` and recursion `stark/config.rs`. |
| TODO-05 | Medium auditability | **Open** | `crates/recursion/gnark-ffi/go/zkm/poseidon2/poseidon2_koalabear.go:121-124` | The cryptographic diffusion constants are preceded only by `todo: update` and a moving `main`-branch URL. The marker does not establish that the constants are wrong, but it leaves no pinned source revision or stated acceptance condition from which the circuit/host parameter match can be audited. |
| TODO-06 | Medium safety documentation | **Open** | `crates/pcs/src/tensor/raw_buffer.rs:116-124` | Public unsafe `allocator_mut` has no safety contract. Mutating allocator state must not invalidate ownership, layout, provenance, or later deallocation of the allocation already stored in `RawBuffer`; that obligation is currently documented only indirectly at a higher wrapper. |
| TODO-07 | Low design | **Open** | `crates/pcs/src/shape/mod.rs:86-94` | `Shape::included` allocates/parses `air.name()` back into key type `K` and unwraps the parse. A stable typed AIR identifier is still absent, leaving identity coupled to display naming and a possible panic on an incompatible name/key representation. |
| TODO-08 | Low maintainability | **Open** | `crates/recursion/core/src/runtime/mod.rs:52,111-113` | The runtime retains a glob-import cleanup marker and an unbounded “fully document” marker. The latter says features of the old runtime are missing but does not enumerate them, so it is not an actionable completeness specification. |
| TODO-09 | Operational | **Open/manual** | `crates/prover/trusted_setup.sh:75-80`; `trusted_setup_imm_wrap_vk.sh:66-71` | Both trusted-setup scripts deliberately stop with release and cleanup commands commented out. They generate/copy artifacts but do not complete publication or cleanup. The four markers must remain classified as manual ceremony/release steps; they are not proof-verification defects. |
| TODO-10 | Architecture limitation | **Open/inherited** | `crates/go-runtime/zkvm_overlay/runtime/sys_linux_mipsx.s:447` | The MIPS overlay lacks Go runtime `stackcheck`. This is a recorded runtime-port limitation. No repository implementation or current exploitability claim was found in this pass. |
| TODO-11 | Low naming/API debt | **Open** | `crates/recursion/circuit/src/witness/mod.rs:25` | `Witnessable` still carries a temporary uniqueness-driven name. This has no runtime or protocol effect. |
| TODO-12 | Low dead API | **Open** | `crates/prover/src/lib.rs:824-826` | Public `ZKMProver::initialize` claims to initialize programs and keys but is an empty no-op. Even if retained only for compatibility, its current documentation is false and callers can incorrectly believe eager initialization occurred. |

## Stale markers that should not be reported as open implementation work

| Location | Current evidence | Disposition |
|---|---|---|
| `crates/core/executor/src/minimal_trace.rs:40-45` | The executor now appends pre-access reads to `recording_chunk_mem_reads`, seals them into each chunk, and replay consumes the positional oracle in `tracing_vm.rs`. | **Resolved behavior, stale comment.** Remove or rewrite the TODO; it currently contradicts a load-bearing replay invariant. |
| `crates/core/executor/src/record.rs:183` | `ExecutionRecord` already has register and immediate bitwise event vectors, and the executor records/appends them. | **Resolved behavior, stale comment.** |
| `crates/core/machine/include/utils.hpp:159-162` | The helper is used for DIV/MOD signedness; DIVU/MODU are the unsigned cases, and the Rust executor uses the same classification. | **Misleading marker.** There are no additional signed div/rem opcodes to add at this call site; the helper should instead be named/documented for its actual scope. |
| `crates/prover/src/lib.rs:221-227` | `TODO: FIX` annotates a fully commented-out obsolete shape-download block. | **Dead comment.** Delete rather than track as an open fix. |

`docs/src/dev/proof-aggregation.md:39` is an intentional placeholder inside an example (`Do something interesting with the proofs here`) and is excluded from product debt.

## Unlabelled incomplete public or protocol-adjacent interfaces

These are not part of the 23-marker count, but they must not disappear from an inventory of unfinished code:

| Severity | Location | Strict audit result |
|---:|---|---|
| Medium reliability | `crates/sdk/src/install.rs:42-49`; `network/prover.rs:197-206`; `proof.rs:58-100` | Public SDK methods use `unimplemented!` for unsupported artifact/proof variants. `ZKMProof` publicly exposes six variants, while `raw()` accepts two and `bytes()` accepts three. Unsupported user input therefore aborts the process instead of returning a typed error. |
| Low latent | `crates/verifier/src/plonk/kzg.rs:138-152` | The one-digest KZG batch case panics. The current PLONK verifier always supplies two digests at `verify.rs:271-277`, so the branch is unreachable on that verified path but remains an incomplete internal interface. |
| Low latent | `crates/verifier/src/plonk/hash_to_field.rs:97-104` | `WrappedHashToField` implements `std::hash::Hasher` but panics in `finish()`. The current verifier calls its domain-specific `sum()` method and does not call `finish`; generic `Hasher` consumers would panic. |
| Low/profile-bounded | `crates/pcs/src/jagged_long.rs:142-154` | Multi-component folding at `log_stacking_height <= 2` is explicitly unimplemented and guarded by an assertion. Current production stacking height is much larger, so this is a fail-fast parameter limitation rather than an accepted invalid proof. |
| Low latent | `crates/recursion/circuit/src/lib.rs:721-730` | `KoalaBearPoseidon2Outer::challenger_shape` panics. No current call site was found, but the trait implementation advertises a method it cannot satisfy. |

The `unimplemented!` methods in the public-values and BaseFold constraint folders are deliberately impossible AIR-builder operations for those specialized folders; the derive/compiler arms reject unsupported input shapes at compile time. They are fail-fast invariants and are not classified as TODO debt unless a reachable generic caller is identified.

## Required disposition summary

1. **Block use of the stale VK-map writer** until its inputs are generated from the current recursion programs and protocol profile; it must not be able to overwrite a release artifact from known-stale constants.
2. **Specify the `Backend` and `allocator_mut` unsafe contracts** before treating external CUDA implementations as auditable.
3. **Serialize or eliminate process-global gnark build configuration**, including restoration of prior environment state.
4. **Remove the four resolved/dead TODO markers** so future audits do not reopen closed work.
5. Track the remaining operational, performance, documentation, and naming items at their stated severity; none of them should be promoted to a protocol-soundness finding without additional reachability or adversarial evidence.

## Validation record

| Check | Result |
|---|---|
| Case-insensitive word scan for `TODO|FIXME|HACK|XXX` over source/docs with build/report exclusions | **23 TODO markers; 0 FIXME/HACK/XXX; 17 files.** |
| Source inspection of all 23 marker sites | **18 live debt/operational markers, 4 stale markers, 1 documentation-example placeholder.** |
| `unimplemented!`/`todo!` scan plus current call-site tracing | **Five material latent/public-interface groups recorded above; specialized fail-fast folder/derive branches excluded.** |
| Protocol impact review | **No new verifier soundness bypass established by this TODO pass.** |

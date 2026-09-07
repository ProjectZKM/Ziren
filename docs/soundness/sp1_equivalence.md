# Is Ziren's proof system the same as SP1's, and what does that buy us?

Working document, 7 September 2026. Ziren at `feat/upgrade-plonky3`; SP1 at v6.3.1
(`7ea83d0`, `/data/stephen/sp1-latest`).

**Why this comes before a soundness proof.** Ziren's shard prover is a port of SP1
Hypercube's transcript. Wherever the two run *the same protocol*, SP1's analysis, its audits
and the literature they rest on carry over, and our job is to say so precisely. Wherever they
diverge, nothing carries over and the obligation is ours. So the first step of proving
soundness is drawing that line, item by item. This document draws it; the obligations it
leaves are the contents of the soundness proof.

A caution that shapes the whole exercise: **an audit of an implementation does not transfer to
a fork.** Protocol equivalence transfers the *analysis*. It does not transfer any assurance
about our code.

## 1. What SP1 publicly claims

From SP1's security model page and its formal-verification posts (see Sources at the end).

| | SP1 Hypercube | Ziren, as the paper states it |
|---|---|---|
| Soundness claim | "a sound zero-knowledge proof"; **knowledge soundness is not claimed** | knowledge soundness, with an extractor, in the random-oracle model |
| Hash assumption | Poseidon2 over KoalaBear "as secure as if replaced with a random oracle" | same, Poseidon2 over KoalaBear, 248-bit digest |
| Proximity regime | no proximity-gap *conjectures*; unique-decoding proximity-gap theorems | unique decoding, no list-decoding conjecture |
| Stated level | 100 bits, from `SP1_TARGET_BITS_OF_SECURITY` | 64 bits, from the generated soundcalc report |
| Cross-shard digest | discrete log on a degree-7 extension curve, "at least 100 bits against known attacks" | discrete-log-type assumption on `y² = x³ + 3ζx − 3` over `F_p⁷`; **no bit figure stated by us** |
| Recursion composition | *assumed* lossless: "recursive proofs do not incur a loss in security as the number of recursive steps increases" | union bound over every proof in the tree (~200), stated as a theorem |
| Zero knowledge | STARK proofs are not ZK; the Groth16/PLONK wraps are | not claimed anywhere |
| Program safety | explicitly out of scope | same position |

Two asymmetries are worth keeping in view. SP1 states a higher number under a weaker
composition claim; we state a lower number under a stronger one, and the two are not
comparable as printed. And SP1 does not claim knowledge soundness at all, so our Theorem 1.1
is a *stronger* statement than anything SP1 publishes — which means it cannot be inherited and
has to be proved.

## 2. Their verification work, next to ours

| | SP1 | Ziren |
|---|---|---|
| Determinism / under-constraint | Picus via Veridise's LLZK, "ongoing", example circuits named (u32 add, XOR, range checks); no coverage numbers published | all 64 units extracted, 106 module theorems, counts published per family |
| Lean | Nethermind + Succinct: **functional correctness** of 62 core RV64 opcodes against the official RISC-V **Sail** specification | determinism only, plus an executable ISA model checked against 770 oracle vectors and 2275 decodings; the functional direction exists as one `Bridge` example, still open |
| What Lean does *not* cover, by their own statement | memory consistency, the execution hierarchy above single steps, lookup-bus semantics, the extraction mechanism | the same list, plus the recursion machine |
| How their worst public bug was found | a **completeness** bug in `JALR` (missing `& ~1` mask), found by the RISC-V architectural compliance tests, *not* by the Lean proof | our analogous flow (specification vectors, Cannon, the shared instruction suites) is what surfaced the missing `MADD`/`MSUB` rows |

The lesson SP1's own bug carries is the one our §8 should state plainly: a single-step
soundness theorem with an unproved hypothesis is a trust boundary, not a guarantee, and
conformance testing catches a class of defect that determinism proofs structurally cannot.

**Where we are behind:** they prove chips *correct against a standard specification*; we prove
chips *deterministic*. Determinism plus completeness gives functional correctness, but our
completeness side is testing, not proof.

**Where we are ahead:** published coverage numbers for the determinism flow, an explicit
composition theorem instead of an assumption, and a generated soundness report rather than a
query-count formula.

## 3. Protocol equivalence, layer by layer

### 3.1 Arithmetisation (AIR, chips, buses)

**Headline: the frame architecture is a genuine port, and the cross-shard digest is not.**

SP1 v6.3.1 has no CPU chip either. Its `adapter/state.rs` and `adapter/register/*` are Ziren's
`frame` module under other names, doing the same sequence: send the program tuple, bind the
selector to the opcode, do the register accesses at fixed sub-cycle positions, receive the
state tuple and send the next one. `InstructionCols` is field-for-field identical on the two
sides, in the same iteration order. The interaction-to-fraction encoding is the same formula,
the bus kinds correspond one to one for every shared subsystem, and both sides panic if a bus
value or a multiplicity has degree above one. Every production interaction on both sides is
local in scope; cross-shard traffic goes through the digest chip on both.

| Layer | Verdict | Note |
|---|---|---|
| Interaction/bus abstraction | PARAMETERISED | same API and same fraction formula, renamed; tuple widths differ because Ziren is 32-bit and SP1 v6 is 64-bit with a 48-bit address space |
| Instruction frame | ADAPTED | architecture ported; the state tuple is not. Ziren chains `(pc, next_pc)` pairs for the MIPS delay slot and uses a per-shard 25-bit clock with a variable syscall increment. SP1 chains a single pc with a global monotone 48-bit clock, a fixed increment, and a `StateBump` chip Ziren does not have |
| Memory argument | ADAPTED | construction identical down to the comments, including the two-branch timestamp gadget and the register shortcut. Two adaptations: Ziren's address is a single field element, so canonicality is a separate obligation, where SP1's limbed address is canonical by construction; and Ziren's `MemoryBump` triggers on a shard boundary where SP1's triggers on a clock-epoch crossing |
| **Cross-shard septic digest** | **DIVERGENT** | see below |
| Public values | ADAPTED | SP1 constrains digest and exit-code monotonicity and the commit-syscall flags inside the shard AIR through `prev_*` twins; Ziren has neither the fields nor the constraints and moves the rules to the recursion leaf |
| Preprocessed tables | PARAMETERISED | same three tables, same constructions; Ziren's byte table carries four extra operations and a fifth tuple slot for `ShrCarry` |
| Word and range discipline | PARAMETERISED | same discipline at a different limb width; Ziren additionally re-checks at the register write, which is strictly more conservative, and has one opt-out on memory-instruction accesses justified only by a comment |

### 3.2 The digest divergence, in detail

SP1 **hashes the interaction message to the curve**: it builds a width-16 state, applies the
Poseidon2 permutation, and takes the first seven output elements as the candidate
x-coordinate, with the whole permutation constrained in the AIR. Ziren applies **no hash at
all**. The interaction message *is* the x-coordinate, with a prover-chosen byte offset in the
top limb to make the cubic have a root. The chip drops from 213 columns to 30. The change was
deliberate and is recorded in the commit history.

The curve and the extension differ too. Ziren uses `y² = x³ + 3ζx − 3` over
`F_p[ζ]/(ζ⁷ + 2ζ − 8)`; SP1 uses `y² = x³ + 45x + 41ζ³` over `F_p[ζ]/(ζ⁷ − 3ζ − 5)`. All six
dummy and offset constants differ. Everything downstream of the point is the same: the
disjoint sign bands are literally SP1's numbers, and the accumulation bus is the same.

**Why this is the top soundness item and not a footnote.** With a hash to the curve, the
points are modelled as random-oracle outputs, so a vanishing signed combination among them is
a discrete-log-type problem and the argument is clean. Without the hash, the prover chooses
the points directly by choosing the messages. Security then rests entirely on the messages
being *sparse* in the group: the sender chips must range-constrain every limb, so that the
reachable x-coordinates are a thin, structured subset the prover cannot steer. Two things
follow, and both are ours to prove.

1. Nothing may let a prover realise a chosen point. If any sender chip lets a message limb
   range freely over the field, a prover can pick `k`, compute `kG`, read the x-coordinate off
   as a message, and assemble a vanishing combination with known coefficients. The audit found
   that `eval_single_digest` range-checks only the first value while forming the top limb from
   the seventh, so the per-chip bounds are load-bearing and have not been collected in one
   place.
2. Sparsity alone is not the end of the argument. The right analysis is a generalised
   birthday bound: with `k` lists of reachable points, a `k`-sum in a group of order about
   `2²¹⁷` costs roughly `2^(217/(1+log k))` work, so the bound has to be taken against the
   number of interactions a prover can actually put in a trace. That analysis does not exist
   on our side, and SP1's does not apply because its point set is pseudorandom.

**The paper is currently wrong about this.** Section 5.5 says Ziren "follows the
elliptic-curve digest construction of SP1". It does not: SP1 hashes first. That sentence has
to be corrected, and the digest lemma's security paragraph rewritten around the reachable
message set rather than around the lift offsets.

### 3.3 Recursion, aggregation and wrap

Verdict: **a fork of an SP1 v4/v5-era design that has since diverged.** The mechanisms are
recognisably the same — a register recursion VM, a Merkle allowlist of recursion verifying
keys, a public-values accumulator, a root digest, a gnark wrap. The predicate sets are not.
SP1 v6 rebuilt its recursion public values around previous/next twins on every mutable field,
timestamps, syscall-completion flags and a proof nonce; Ziren still carries the older shape.

Predicates present on both sides when a compose node merges its children: each child's
public-values digest is recomputed and bound, the child's key root matches the witnessed root,
the program key digest is identical across children, the program counter is continuous, the
memory initialise and finalise cursors tile, the deferred digest chains, the septic sums
accumulate, and the output digest is recomputed by kind.

Predicates SP1 v6 enforces that Ziren has no analogue of: timestamp continuity and the
included-shard count, the deferred-proof index, exit-code chaining, the two commit-syscall
flags, and the proof nonce. Ziren's committed-value and deferred digest chaining also uses the
older non-zero filter, asserting equality only when the accumulator is non-zero, where SP1 v6
chains unconditionally through previous/next twins.

Two divergences are not gaps in transferable analysis. They are live defects, and I verified
both directly in both trees rather than taking them on report.

**(1) Completeness is never asserted at the terminal stages.** In the compose program
`is_complete` is a free witnessed field, and `assert_complete` is multiplied by it, so every
completeness predicate is vacuous when it is zero: the program counter need not have reached
the halt value, the shard chain need not start at one, the deferred digest need not close,
and — the serious one — **the global cumulative sum need not be zero**, which is what closes
cross-shard memory consistency for the whole execution. The shrink and wrap circuits are
supposed to be where that flag is pinned. In Ziren, `crates/recursion/circuit/src/machine/wrap_basefold.rs`
contains **zero occurrences of `is_complete`**, its witness type has no such field, and the
host's `verify_shrink` (`crates/prover/src/verify.rs:337`) and `verify_wrap_bn254` do not check
it either. SP1 asserts it in both terminal circuits, at `root.rs:37` and `wrap.rs:50`. Nothing
between an adversarial compose proof and a valid Groth16 proof forces completeness. The host's
`verify_compressed` does check it, but a host check is not on the adversary's path.

**(2) The recursion key root is not pinned at the trust boundary.** Ziren's gnark circuit
exposes two public inputs, `VkeyHash` and `CommittedValuesDigest`
(`crates/recursion/gnark-ffi/go/zkm/zkm.go:33`), and the Solidity verifier reads
`uint256[2]` with no further checks. SP1 exposes five, adding `ExitCode`, `VkRoot` and
`ProofNonce`, and its Solidity template reverts on a wrong exit code or a wrong key root.
Ziren's `vk_root` is therefore a free in-circuit witness that no external verifier ever sees,
so a prover who builds their own allowlist tree — including a compose program with the merge
predicates removed — produces a proof an on-chain verifier cannot distinguish from an honest
one. This is the same defect a Code4rena competition found in SP1 and SP1 fixed by adding the
public input. Ziren is in the pre-fix state.

Supporting differences that matter for any inherited analysis: Ziren's recursion Poseidon2 uses
**13 internal rounds** against SP1's 20, so no SP1 conclusion about the recursion hash was
drawn at our parameters; Ziren's wrap runs at constraint degree 9 against SP1's 3; and Ziren's
key allowlist holds 169 keys **partly harvested from live runs** through an environment
variable, where SP1's holds 185,862 from a closed enumeration over all reachable shapes. The
allowlist difference turns "every reachable recursion shape is in the tree" from a fact by
construction into a claim by observation, and a miss is a hard panic, which is operational
pressure toward disabling the check.

### 3.4 The shard proof protocol and its Fiat-Shamir compilation

Verdict: **steps one through twenty of the transcript are the same protocol in the same
order.** The differences are two missing or extra steps, two mirrored endianness conventions,
and the acknowledged dense-commitment swap at the end.

| Layer | Verdict | Note |
|---|---|---|
| Sponge construction | IDENTICAL | both are a duplex challenger of width 16 and rate 8 in overwrite mode, same duplexing rule, same extension-element squeeze, same length-prefixed observes |
| **Permutation instance** | **DIVERGENT** | see below |
| Seeding and observe order | PARAMETERISED | both seed with the verifying key first, in the same field order, then public values, then the main commitment, then chip metadata, and only then sample |
| Round order, steps 1-20 | IDENTICAL | verified step by step |
| LogUp-GKR | ADAPTED | same fraction encoding, same circuit, same last-layer reduction and batching. The circuit layering is the *same* adjacent-row pairing on both sides, contrary to what we believed: the layout difference is in the evaluation-point ordering, not the tree |
| Zerocheck | IDENTICAL | random linear combination across units, powers of a challenge across constraints, same eq weighting, same padded-row mask, same degree, same challenge order |
| Jagged reduction | IDENTICAL | same branching program, same evaluation sumcheck, same assist and closing identity, same geometry bind |
| Stacking | ADAPTED | same stripe geometry, same height, same batch size, same two commitment rounds; mirrored point split and a different batching rule |
| Dense commitment | DIVERGENT | interface-preserving boundary, different argument system behind it |

**The permutation instance is the finding to act on.** Both sides run Poseidon2 over KoalaBear
at width 16 with 8 full rounds. Ziren uses **13 partial rounds**; SP1 uses **20**. KoalaBear's
S-box degree is 3, where BabyBear's is 7, and a lower S-box degree needs *more* rounds for the
same algebraic-attack margin. Thirteen partial rounds at width 16 is the *BabyBear* parameter,
and Ziren's constants are drawn from a BabyBear-shaped table. So our transcript hash, our
Merkle commitments and our in-circuit recursion hash all run at a round count chosen for a
different field and a different S-box. This needs either a justification we can point at or a
parameter change. It is not a transfer gap; it is a parameter that appears to have been
carried over from the wrong instance.

**Two protocol steps differ in presence.** SP1 samples a public-values challenge, folds the
record-level public-values AIR and requires the accumulator to be zero. Ziren samples nothing
there and checks only the arithmetic identity between the lookup sum and the public-values
digest. Separately, Ziren samples extra transcript coordinates to extend the reduced point up
to the stripe cube before the dense commitment, and multiplies the claim by a product over the
coordinates landing in the zero-padded region. SP1 has no such step.

**Two conventions are mirrored.** Ziren inserts the lookup circuit's line challenge at the
front of the row block where SP1 appends it at the back, and splits the stacking point at the
opposite end. Ziren compensates by anchoring the zerocheck on the reversed point. Each side is
internally consistent, but the claim that the reversal is a pure relabelling has never been
written down, and the reduction's binding depends on it.

**Two smaller items are worth recording.** Ziren's proof carries a fold-orientation tag that
selects which pairing the verifier applies in the lookup round identity, so a prover chooses a
protocol variant; SP1 has one fixed convention. And Ziren's lookup grinding helper returns
success unconditionally for any challenger that is not the inner one, which is inert today
because the grinding is set to zero bits, but is a trapdoor if grinding is ever restored.

### 3.5 What SP1's audits are worth to us

SP1 ships eight audit reports. Every one names a specific commit of a specific repository and
none examined a line of Ziren, so none of them provides assurance about our code. What can
transfer is the design conviction and the bug classes.

- The only PCS-level soundness review, Zellic's on Hypercube's verifier, is against BaseFold
  and jagged at SP1's commit and parameters. Our inner ring is WHIR at a different target.
  Neither the code nor the parameters were audited. Its jagged-layer questions are worth
  re-asking of our jagged layer; its BaseFold findings are not about us.
- The two reviews by rkm0959 of the compress verifier and the key-root check are the closest
  to transferable, because our compose verifier is a recognisable descendant. One of them
  documents an `is_complete` bypass as a carried-over bug. That is the defect above.
- The Code4rena competition report contains the missing key-root check in the BN254 verifiers.
  That is also the defect above. Its other finding, a missing limb recomposition in the
  KoalaBear range-check helper of the gnark bridge, is in code we ported and has not been
  checked here.
- The reviews of SP1's RISC-V chips and its 2024 FRI-era recursion circuits do not transfer at
  all; different instruction set, different chips, structurally rewritten recursion.

The net is worth stating plainly. Zero of SP1's audits gives assurance about Ziren, and two of
them describe defects Ziren currently exhibits.

## 4. Obligations that do not transfer

This is the contents of a soundness proof for Ziren, ordered by how much rests on each item.
Everything here is ours because it is either a place where we diverge from SP1 or a place
where SP1 claims nothing.

**Tier 0 — fix before writing any proof.** A proof of a system carrying these would be a proof
of a different system.

1. ~~Assert completeness at the terminal stages.~~ **Done.** The assertion lives in
   `verify_wrap_basefold_core`, the one function both shrink and wrap reach, with host mirrors
   in `verify_shrink` and `verify_wrap_bn254`.
2. Expose the recursion key root as a public input of the wrap circuit and check it in the
   Solidity and Rust verifiers. Consider adding the exit code at the same time, as SP1 does.
   **Still open.**
3. ~~Settle the Poseidon2 round count.~~ **Done.** Changed from 13 partial rounds to 20 in all
   four sites in this repo and in the GPU prover's Rust constant, kernel macro and baked
   constant arrays. This changes every verifying key, so the key map, the gnark circuit
   artifacts and the GPU build all have to be regenerated before it can be deployed.

**Tier 1 — the cross-shard digest**, the weakest link and the biggest departure from SP1.

4. Collect the per-unit limb bounds on every global interaction into one statement and prove
   the reachable message set is what the digest argument assumes. The digest unit itself
   range-checks only the first value while forming the top limb from the seventh, so the
   bounds live entirely in the senders and have never been gathered.
5. Do the k-list birthday analysis of the vanishing-combination assumption at our interaction
   count, and state the resulting bits. We state no figure today; SP1 states at least 100.

**Tier 2 — arithmetisation obligations SP1's analysis does not reach.**

6. Memory address canonicality, since our bus carries the address as one field element below a
   modulus smaller than the address space.
7. The shard-triggered memory bump, which is what licenses the narrower register access
   columns. SP1's bump is clock-epoch triggered and its argument does not apply.
8. The two-program-counter state chain and the per-shard clock fence, sound and complete.
9. The trusted memory access opt-out, justified today only by a comment.
10. Public-values integrity, which SP1 constrains inside the shard AIR and we move entirely to
    the recursion leaf. Two SP1 checks have no counterpart in our tree at all: the shard
    verifier's public-values length and padding rejection, and the memory cursors'
    non-emptiness in the completeness assertion.

**Tier 3 — the protocol layer.**

11. The dense commitment. Our WHIR schedule shares no soundness analysis with SP1's BaseFold.
    This is the single largest non-transferring item, and it is the one place where our
    existing tooling already does real work.
12. The missing public-values challenge and AIR fold. It must be proved that the boundary
    digest is fully determined by the public values with no residual constraints to enforce.
13. The mirrored row ordering, as a written relabelling argument. The reduction's binding
    depends on it and nobody has stated it.
14. The lookup grinding at zero bits, re-accounted without the twelve bits SP1's analysis
    assumes, plus a proof that the type-directed bypass is unreachable.
15. The transcript-extension step and its zero-padding identity, which SP1 has no analogue of.
16. Power batching of the stripe claims, whose error term differs from SP1's eq batching after
    a grind.
17. The fold-orientation tag, either proved harmless or pinned by the verifying key.
18. The beta-seed width, derived from unit arity alone where SP1 also accounts for the
    boundary message kinds.

**Tier 4 — the statement itself.**

19. Knowledge soundness. SP1 does not claim it; our Theorem 1.1 does, so it must be proved
    rather than cited. The route is standard — round-by-round knowledge soundness of the
    composed interactive protocol, then compilation to a non-interactive argument in the
    random-oracle model — but our bibliography currently cites none of the literature that
    route needs.
20. The composition theorem's proof sketch must become a proof, and it takes the key allowlist
    as a hypothesis, which item 2 currently invalidates.
21. The recursion machine's own soundness, which no Lean or Picus work on either side covers.

**What genuinely does transfer.** The fraction encoding of the buses, the offline
memory-checking construction, the frame architecture, the lookup circuit, the zerocheck, the
jagged reduction, the stacking geometry and the preprocessed table designs are the same
protocol as SP1's, so the literature behind them is ours to cite too. That is the real result
of this audit: the arithmetisation and reduction chapters of a soundness proof are mostly
assembly of known arguments, and the genuinely new work is concentrated in four places — the
digest, the dense commitment, the recursion boundary, and the compilation step.

## 5. What a soundness proof would then look like

With the line drawn, the proof has a shape. It is a chain of four reductions, and the audit
above says which links are ours to forge.

**Link 1: accepting proof to satisfying shard.** An accepting shard proof implies a shard that
satisfies every unit's constraints and balances every bus. This is the compiled interactive
protocol, and it decomposes into the components the accounting already names: the lookup
argument gives multiset equality from the fraction identity, the zerocheck gives the
constraints, the jagged reduction gives one dense claim from many column claims, and the dense
commitment gives the opening. Three of the four are the same protocol as SP1's and can be
argued from the cited literature. The fourth is ours. The compilation step, from a
round-by-round knowledge sound interactive protocol to a non-interactive argument in the
random-oracle model, is standard and cited nowhere in our bibliography yet.

**Link 2: satisfying shard to shard execution.** The two bus lemmas already in the paper: the
state bus forces the rows into one chain, and the memory bus forces every read to return the
last write. These are the standard arguments of the multiset construction and they are written.

**Link 3: shard executions to one whole execution.** The digest closes cross-shard memory, and
the recursion tree's merge predicates close the chain of shards. Both ends of this link are
weak right now, and for different reasons: the digest because we removed SP1's hash, the tree
because completeness is never pinned.

**Link 4: execution to the instruction set.** This link is not a soundness argument at all and
cannot be made into one by these means. Determinism gives *at most one* behaviour per input;
completeness of the constraint system against the specification gives *the right* one.
Together they give functional correctness, and that is the honest statement of what the
verification flow buys. Our completeness side is testing. SP1's is a Lean proof against the
Sail specification for 62 opcodes. Closing the `Bridge` files against our executable ISA model
is the same move, and it is the one piece of new mathematics the verification chapter needs.

The ordering advice that follows from this is not subtle. Fix the three Tier 0 items, because
they change what is true. Then do the digest analysis, because it is the assumption everything
cross-shard rests on and it is the one we have never written down. Then write Link 1
properly, which is mostly citation work plus the WHIR accounting we already generate. Link 4
is a research programme, not a paper revision.

## Sources

- SP1 security model: https://docs.succinct.xyz/docs/sp1/security/security-model
- Formal verification of SP1 Hypercube in Lean (Nethermind): https://blog.succinct.xyz/nethermind-lean/
- Formal verification of SP1 with Picus: https://blog.succinct.xyz/formal-verification-of-sp1-with-picus/
- On formal verification and a bug in SP1 Hypercube (Ethereum Foundation zkEVM): https://zkevm.ethereum.foundation/blog/sp1-fv
- Prior in-tree review of the IOPP/PCS parameter gap: `docs/soundness/sp1_iopp_pcs_gap_review.md` (branch `docs/sp1-iopp-pcs-gap`)

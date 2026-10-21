# Ethereum terminal verifier tooling

`src/` contains the arithmetic, transcript, compact decoder, WHIR and immutable
module-driver Solidity implementations. `compile-machine.py` emits a symbolic
KVE2 verifier from separately approved machine/key/wire data. `native/compile.py`
compiles that program into bounded Yul kernels and generates the Solidity entry
and WHIR/math modules. Generated artifacts must stay outside this repository.

The interpreted `KeccakTerminalVerifier` is a reference implementation and can
exceed Ethereum limits. The native generated verifier is the deployment target.
Foundry's reference configuration permits oversized diagnostic calls; successful
reference tests do not establish mainnet deployability. `native/measure.py`
checks deployed sizes and actual receipts on an explicitly local Anvil chain.
Use Osaka with `--enable-tx-gas-limit` to enforce the 16,777,216 transaction cap.

Example workflow (all paths point to independently approved external inputs):

```sh
python3 -m pip install -r native/requirements.in
python3 compile-machine.py "$APPROVED_MACHINE_EXPORT" "$EXTERNAL_COMPILED"
python3 native/compile.py --help
python3 native/transport.py --help
python3 native/measure.py --help
python3 native/test-compiler.py "$EXTERNAL_WIRE_FIXTURE"
python3 native/run-tests.py --build "$EXTERNAL_NATIVE_BUILD" \
  --fixtures "$EXTERNAL_WIRE_FIXTURE"
```

Choose compiler options and module splitting for the approved program. Useful
size options include `--base-power-window --shared-power-table` and
`--zero-run-fields`; the latter enables outer transport mode 3. They change
representation or exact arithmetic implementation, not proof security
parameters. Measure the combined bytecode, calldata and verification-gas result:
smaller bytecode can require more gas and can fail at nested call forwarding
limits even when an uncapped estimate looks below the transaction cap.

Every compiled module and its order are configuration. Approve source-program
and runtime hashes independently, then deploy kernels/helpers and the generated
entry. Verification performs static calls to those pinned modules in one
transaction. An application must independently approve the entry/profile and
check the returned public-values digest; it must never accept a submitter's
chosen verifier or generated program.

`parameters/*.json` are local parameter-model examples. They do not configure
the Rust ring implicitly. The ring's resolved configuration and trusted export
must match before compilation. See the [package release gate](../README.md).

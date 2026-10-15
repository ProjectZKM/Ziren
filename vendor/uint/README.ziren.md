# uint 0.9.5 compatibility patch

This directory contains `uint` 0.9.5 from parity-common commit
[`c41d51df8a314150c46cbbff31f8140a35dfb02c`](https://github.com/paritytech/parity-common/tree/c41d51df8a314150c46cbbff31f8140a35dfb02c/uint),
with its original MIT and Apache-2.0 licenses.

The only source change backports upstream commit
[`230b63ab8554b93fd3ee828e2a4c04721e0aa900`](https://github.com/paritytech/parity-common/commit/230b63ab8554b93fd3ee828e2a4c04721e0aa900):
remove two trailing semicolons from expression macro bodies. This fixes the
`semicolon_in_expressions_from_macros` future-compatibility warnings reported
through `ethereum-types` and `primitive-types` on the pinned Rust toolchain.

The upstream fix targets `uint` 0.10, while ethers 2.0 requires the 0.9 API.
The workspace applies this backport through `[patch.crates-io]` and excludes the
vendored crate from workspace membership. Remove the patch when the dependency
chain supports an upstream release containing the fix.

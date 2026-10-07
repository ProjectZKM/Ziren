# Installation

Ziren is available for Linux and macOS.

## Requirements

- [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)
- [Rust](https://www.rust-lang.org/tools/install) via `rustup`. The Ziren repository pins its nightly toolchain in `rust-toolchain.toml`, which `rustup` installs on first use.
- [Go](https://go.dev/dl/) 1.23 or later, only for generating Groth16 or PLONK proofs (the SNARK backend is built through a Go FFI).

## Get Started

### Option 1: Quick Install

The `zkmup` installer installs the Ziren guest toolchain, which compiles programs for the `mipsel-zkm-zkvm-elf` target. Run:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/ProjectZKM/toolchain/refs/heads/main/setup.sh | sh
```

The script downloads `zkmup` to `~/.zkm-toolchain/bin`, installs the latest toolchain release (`zkmup install`) and writes `~/.zkm-toolchain/env` (`zkmup setup`). Load the environment in each shell that builds guest programs:

```bash
. ~/.zkm-toolchain/env
```

List the available toolchain releases, and install or select a specific one:

```bash
~/.zkm-toolchain/bin/zkmup list-available
~/.zkm-toolchain/bin/zkmup install -v 20260917
~/.zkm-toolchain/bin/zkmup setup -v 20260917
```

Use release `20260917` or later. It fixes an LLVM MIPS backend bug, present in earlier releases, in which the delay-slot filler could move a store across a call and miscompile some guest programs.

Guest programs are built by running `cargo` from `PATH`, which after loading `~/.zkm-toolchain/env` is the Ziren toolchain's `cargo`; the environment file also sets `ZIREN_ZKM_CC` for C dependencies. If `cargo` is instead a `rustup` proxy, the build selects the `rustup` toolchain named by `ZKM_GUEST_TOOLCHAIN` (default `zkm`).

You can now run the Ziren examples or unit tests:

```bash
git clone https://github.com/ProjectZKM/Ziren
cd Ziren && cargo test -r
```

#### Troubleshooting

The following error may occur:

```bash
cargo build --release
cargo: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found (required by cargo)
cargo: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.33' not found (required by cargo)
cargo: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by cargo)
```

The prebuilt toolchain binaries are built for Ubuntu 22.04 and macOS. On systems with an older GLIBC, build the toolchain from source.

### Option 2: Building from Source

See the [toolchain](https://github.com/ProjectZKM/toolchain.git) repository.

## Choosing a Prover

The SDK's `ProverClient::new()` selects its prover from the `ZKM_PROVER` environment variable:

| `ZKM_PROVER` | Prover |
|--------------|--------|
| `local` or `cpu` (default) | CPU prover in the current process |
| `cuda` | GPU prover: a server started in Docker by default, or an already running one at `CUDA_ENDPOINT` with `CUDA_RUN_DOCKER=false` (see [GPU Acceleration](../dev/prover.md#gpu-acceleration)) |
| `network` | ZKM Prover Network (requires the SDK's `network` feature) |
| `mock` | Mock prover for testing, which produces no real proof |

Groth16 and PLONK circuit artifacts are downloaded on first use into `~/.zkm/circuits/{groth16,plonk}/<version>`, where `<version>` is the SDK's circuit version (`v2.0.0` for Ziren 2.0.0).

# Installation

ZKM2 is now available for Linux and macOS systems.

## Requirements

- [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)
- [Rust (Nightly)](https://www.rust-lang.org/tools/install)

## Option 1: Quick Install

To install the ZKM2 toolchain, use the `zkmup` installer. Simply open your terminal, run the command below, and follow the on-screen instructions:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/zkMIPS/toolchain/refs/heads/main/setup.sh | sh
```

It will install the latest ZKM2 Rust toolchain with support for compiling to the `mipsel-zkm-zkvm-elf` target.

List all available toolchain versions:

```bash
$ zkmup list-available
20250224 20250108 20241217
```

### Troubleshooting

The following error may occur:

```bash
cargo build --release
cargo: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found (required by cargo)
cargo: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.33' not found (required by cargo)
cargo: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by cargo)
```

Currently, our prebuilt binaries are built for Ubuntu 22.04 and macOS. Systems running older GLIBC versions may experience compatibility issues and will need to build the toolchain from source.

## Option 2: Building from Source

Build/Install rustc:

```bash
git clone https://github.com/zkMIPS/rust-workspace.git
cd rust-workspace
git checkout Triple_mips-zkm-zkvm-elf
cp config.example.toml config.toml
    Edit config.toml in 
    [install]
      prefix = "/home/USERNAME/rust-staged"
      sysconfdir = "etc"
    [build]
      docs = false
    [rust]
      lld = true
    [llvm]
      download-ci-llvm = false
./x build library
./x build --stage 2 compiler/rustc
BOOTSTRAP_SKIP_TARGET_SANITY=1 ./x build --target x86_64-unknown-linux-gnu,mips-zkm-zkvm-elf
BOOTSTRAP_SKIP_TARGET_SANITY=1 ./x install --target x86_64-unknown-linux-gnu,mips-zkm-zkvm-elf
```

Build/Install cargo:

```bash
git clone https://github.com/rust-lang/cargo.git
cd cargo
cargo build --release
cargo install --path . --root=/home/USERNAME/rust-staged/
```

You now have the ZKM2 Rust toolchain installed in `/home/USERNAME/rust-staged/`.

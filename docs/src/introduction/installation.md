# Installation

Ziren is now available for Linux and macOS systems.

## Requirements

- [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)
- [Rust (Nightly)](https://www.rust-lang.org/tools/install)

## Get Started 
### Option 1: Quick Install

To install the Ziren toolchain, use the `zkmup` installer. Simply open your terminal, run the command below, and follow the on-screen instructions:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/ProjectZKM/toolchain/refs/heads/main/setup.sh | sh
```

It will:
- Download the `zkmup` installer.
- Automatically utilize `zkmup` to install the latest Ziren Rust toolchain which has support for the `mipsel-zkm-zkvm-elf` compilation target.

List all available toolchain versions:

```bash
$ zkmup list-available
20250224 20250108 20241217
```

Now you can run Ziren examples or unit tests.

```
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

Currently, our prebuilt binaries are built for Ubuntu 22.04 and macOS. Systems running older GLIBC versions may experience compatibility issues and will need to build the toolchain from source.

### Option 2: Building from Source

For more details, please refer to document [toolchain](https://github.com/ProjectZKM/toolchain.git).

## Advanced Usage

### Use Musl-gcc for Static Compilation 

This feature is only enabled for Linux systems currently.

#### Download toolchain
The musl toolchain can be downloaded from https://toolchains.bootlin.com/releases_mips32.html

```sh
wget https://toolchains.bootlin.com/downloads/releases/toolchains/mips32/tarballs/mips32--musl--stable-2025.08-1.tar.xz

tar xvf mips32--musl--stable-2025.08-1.tar.xz -C ~/.zkm-toolchain/
```

#### Create mipsel-zkm-zkvm-elf-gcc
Create mipsel-zkm-zkvm-elf-gcc file in the same directory with rustc
the file contents is as follows：

```sh
#!/bin/sh
exec ~/.zkm-toolchain/mips32--musl--stable-2025.08-1/bin/mips-buildroot-linux-musl-gcc -EL -msoft-float -fno-stack-protector $@
```
Add execution permission for this file

```sh
chmod +x mipsel-zkm-zkvm-elf-gcc
```

Then build the host program with the following command: 

```sh
source ~/.zkm-toolchain/env
export ZIREN_ZKM_CC=mipsel-zkm-zkvm-elf-gcc  // Optional, used for rust project with c lib
cargo build -r
```
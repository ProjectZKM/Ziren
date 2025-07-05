# zkm-build
Lightweight crate used to build a Ziren programs.

Exposes `build_program`, which builds a Ziren program in the local environment or in a docker container with the specified parameters from `BuildArgs`.

## Usage

```rust
use zkm_build::build_program;

build_program(&BuildArgs::default(), Some(program_dir));
```
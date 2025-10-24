use std::process::Command;
use zkm_build::{build_program_with_args, BuildArgs};

fn main() {
    zkm_build::build_program("../guest");
}

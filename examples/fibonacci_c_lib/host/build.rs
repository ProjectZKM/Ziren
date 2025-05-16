use std::process::Command;
use zkm_build::{build_program_with_args, BuildArgs};

fn main() {
    let mut args: BuildArgs = Default::default();
    // mipsel-linux-gnu-g++ -mno-abicalls -msoft-float -mips2 -c add.cpp
    // mipsel-linux-gnu-ar rcs libadd.a add.o
    // mipsel-linux-gnu-gcc -mno-abicalls -msoft-float -mips2 -c modulus.c
    // mipsel-linux-gnu-ar rcs libmodulus.a modulus.o

    let status = Command::new("mipsel-linux-gnu-g++")
        .arg("-mno-abicalls")
        .arg("-msoft-float")
        .arg("-mips32r2")
        .arg("-c")
        .arg("../lib/add.cpp")
        .status()
        .expect("failed to compile add.cpp");
    if !status.success() {
        panic!("Failed to compile add.cpp");
    }

    let status = Command::new("mipsel-linux-gnu-ar")
        .arg("rcs")
        .arg("../lib/libadd.a")
        .arg("add.o")
        .status()
        .expect("failed to build libadd.a");
    if !status.success() {
        panic!("Failed to build libadd.a");
    }

    let status = Command::new("mipsel-linux-gnu-gcc")
        .arg("-mno-abicalls")
        .arg("-msoft-float")
        .arg("-mips32r2")
        .arg("-c")
        .arg("../lib/modulus.c")
        .status()
        .expect("failed to compile modulus.c");
    if !status.success() {
        panic!("Failed to compile modulus.c");
    }

    let status = Command::new("mipsel-linux-gnu-ar")
        .arg("rcs")
        .arg("../lib/libmodulus.a")
        .arg("modulus.o")
        .status()
        .expect("failed to build libmodulus.a");
    if !status.success() {
        panic!("Failed to build libmodulus.a");
    }

    args.libraries.push("../lib/libadd.a".to_string());
    args.libraries.push("../lib/libmodulus.a".to_string());
    build_program_with_args("../guest", args);
}

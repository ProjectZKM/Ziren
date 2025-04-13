use zkm_build::{build_program_with_args, BuildArgs};
fn main() {
    let mut args: BuildArgs = Default::default();
    args.libraries.push("../lib/libadd.a".to_string());
    args.libraries.push("../lib/libmodulus.a".to_string());
    build_program_with_args("../guest", args);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    vergen::EmitBuilder::builder().build_timestamp().git_sha(true).emit()?;

    tonic_build::configure()
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile(&["src/proto/stage.proto"], &["src/proto"])?;

    Ok(())
}

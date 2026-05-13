fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::compile_protos("proto/auth.proto")?;
    tonic_prost_build::compile_protos("proto/payments.proto")?;  // ← add
    Ok(())
}
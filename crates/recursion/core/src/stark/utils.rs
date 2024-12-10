/// Returns whether the `ZKM_DEV` environment variable is enabled or disabled.
///
/// This variable controls whether a smaller version of the circuit will be used for generating the
/// PLONK proofs. This is useful for development and testing purposes.
///
/// By default, the variable is disabled.
pub fn zkm2_dev_mode() -> bool {
    let value = std::env::var("ZKM_DEV").unwrap_or_else(|_| "false".to_string());
    let enabled = value == "1" || value.to_lowercase() == "true";
    if enabled {
        tracing::warn!("ZKM_DEV environment variable is enabled. do not enable this in production");
    }
    enabled
}

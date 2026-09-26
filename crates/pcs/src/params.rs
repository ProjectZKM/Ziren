//! Transcript parameters that a deployment may override.
//!
//! These fix the Fiat--Shamir transcript, so a prover and a verifier that
//! disagree on any of them do not share a protocol.  They are therefore read
//! once, through this module, and every one of them is carried in
//! [`crate::profile::transcript_profile`], whose digest a consumer checks: an
//! override moves the digest rather than silently changing the transcript.
//!
//! The defaults are solved so that the union bound over the transcript's
//! components clears 100 bits, which is the level the deployment claims.  A
//! lower setting is accepted, because experiments need one, and it is visible
//! in the profile digest.

/// Read a `usize` parameter, falling back to `default` if unset or unparsable.
pub fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Read an `f64` parameter, falling back to `default` if unset or unparsable.
pub fn env_f64(name: &str, default: f64) -> f64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

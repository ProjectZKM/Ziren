//! ## Task #397 (May 19 2026) — FRI root-verifier deletion
//!
//! `ZKMCompressRootVerifier` and `ZKMCompressRootVerifierWithVKey` were
//! thin wrappers around `ZKMCompressVerifier::verify` /
//! `ZKMCompressWithVKeyVerifier::verify` that asserted
//! `is_complete == ONE` and then re-entered the FRI compose body.
//! Both have been retired together with the rest of the FRI compose
//! chain — the basefold root behaviour is folded into the existing
//! [`super::compress_basefold::verify_compress_basefold`] entry point
//! by passing [`super::PublicValuesOutputDigest::Root`].
//!
//! The module is kept (rather than removed from `mod.rs`) so existing
//! `pub use root::*;` re-exports stay intact while the rest of the
//! cleanup lands; the module is empty by design.

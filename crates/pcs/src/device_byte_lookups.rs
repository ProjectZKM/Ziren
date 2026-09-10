//! Chips whose byte-table multiplicities a device prover counts itself.
//!
//! A chip's `generate_dependencies` exists to count the byte lookups its rows
//! send (the default implementation runs the whole host trace generator and
//! discards the matrix to get them).  A prover that generates the chip's trace
//! on the device can count the same sends there, straight off the finished
//! trace, and registers the chip here; the dependency pass then skips it.
//!
//! The registered chips must have dependencies that are byte lookups and
//! nothing else -- a chip that also appends global lookup events keeps its
//! host pass.  `ZIREN_BYTE_HIST_CHECK=1` keeps every host pass regardless, so
//! the prover can compare its counts against the host's.
use std::collections::HashSet;
use std::sync::{OnceLock, RwLock};

static CHIPS: OnceLock<RwLock<HashSet<String>>> = OnceLock::new();

fn chips() -> &'static RwLock<HashSet<String>> {
    CHIPS.get_or_init(|| RwLock::new(HashSet::new()))
}

/// Registers the chips whose byte lookups the device prover counts.
pub fn set_device_byte_lookup_chips<I, S>(names: I)
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut guard = chips().write().expect("device byte-lookup registry poisoned");
    guard.clear();
    guard.extend(names.into_iter().map(Into::into));
}

/// Whether the host dependency pass skips this chip: it is registered and the
/// check mode is off.
#[must_use]
pub fn chip_byte_lookups_on_device(name: &str) -> bool {
    if std::env::var_os("ZIREN_BYTE_HIST_CHECK").is_some() {
        return false;
    }
    chips().read().expect("device byte-lookup registry poisoned").contains(name)
}

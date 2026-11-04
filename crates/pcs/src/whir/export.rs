//! Export-only capture of the stacked WHIR verifier inputs.
//!
//! With `ZIREN_WHIR_EXPORT_DIR` set, each Keccak-transcript verification that
//! reaches the WHIR opening writes `whir-input.json` into that directory.
//! Verification does not depend on the capture: a failed write is logged.

use std::{any::Any, path::Path};

use crate::shrink::{CompactChallenger, Keccak256Suite};

const EXPORT_DIR_ENV: &str = "ZIREN_WHIR_EXPORT_DIR";
const CAPTURE_FILE: &str = "whir-input.json";

fn hex(bytes: &[u8]) -> String {
    let body: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("0x{body}")
}

/// Writes the capture for a verification run on `challenger`.
///
/// `inputs` runs only when the capture is enabled. Challengers other than the
/// Keccak transcript are skipped.
pub fn capture<Challenger: 'static>(
    challenger: &Challenger,
    inputs: impl FnOnce() -> serde_json::Value,
) {
    let Some(dir) = std::env::var_os(EXPORT_DIR_ENV) else {
        return;
    };
    let Some(keccak) = (challenger as &dyn Any).downcast_ref::<CompactChallenger<Keccak256Suite>>()
    else {
        return;
    };
    let state = keccak.export_state();
    let mut record = inputs();
    record["entry"] = serde_json::json!({
        "digest": hex(&state.digest),
        "buffered": hex(&state.buffered),
        "wordsLeft": state.words_left,
    });
    let dir = Path::new(&dir);
    let written =
        serde_json::to_vec_pretty(&record).map_err(std::io::Error::other).and_then(|bytes| {
            std::fs::create_dir_all(dir)?;
            std::fs::write(dir.join(CAPTURE_FILE), bytes)
        });
    if let Err(err) = written {
        tracing::warn!("WHIR export not written to {}: {err}", dir.display());
    }
}

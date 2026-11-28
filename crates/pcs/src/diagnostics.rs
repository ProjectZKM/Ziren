//! The log targets of the prover's timing and shape events, and the one parse
//! rule of its boolean settings.

use std::time::{Duration, Instant};

/// Target of the timing events, at debug level: `RUST_LOG=ziren::timing=debug`
/// shows them. A phase that runs inside a span of this target is timed by the
/// subscriber when the span closes.
pub const TIMING_TARGET: &str = "ziren::timing";

/// Target of the shape events, at debug level: `RUST_LOG=ziren::shape=debug`
/// shows them. Each event is a `program shape` event naming its `stage`
/// (`normalize`, `compose`, `prewarm` or `fix_shape`), with the program's
/// `shape_key` and pin `class` where the stage has them.
pub const SHAPE_TARGET: &str = "ziren::shape";

/// Whether the timing events are on.
#[must_use]
pub fn timing_enabled() -> bool {
    tracing::enabled!(target: TIMING_TARGET, tracing::Level::DEBUG)
}

/// Whether the shape events are on.
#[must_use]
pub fn shape_events_enabled() -> bool {
    tracing::enabled!(target: SHAPE_TARGET, tracing::Level::DEBUG)
}

/// The start of a timed section when the timing events are on.
#[must_use]
pub fn timing_start() -> Option<Instant> {
    timing_enabled().then(Instant::now)
}

/// The time since `start`, or zero when the timing events are off.
#[must_use]
pub fn elapsed_us(start: Option<Instant>) -> u64 {
    start.map_or(Duration::ZERO, |start| start.elapsed()).as_micros() as u64
}

/// The boolean setting `name`: `1`, `true`, `yes` and `on` set it, `0`,
/// `false`, `no` and `off` clear it, in any case. Unset, it is `default`; any
/// other value is also `default`, with a warning.
#[must_use]
pub fn env_flag(name: &str, default: bool) -> bool {
    let Ok(value) = std::env::var(name) else {
        return default;
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => {
            tracing::warn!("{name}={value} is not a boolean setting; it stays {default}");
            default
        }
    }
}

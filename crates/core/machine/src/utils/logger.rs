use std::sync::Once;

use tracing_forest::ForestLayer;
use tracing_subscriber::{
    fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry,
};

static INIT: Once = Once::new();

/// A simple logger.
///
/// Set the `RUST_LOG` environment variable to be set to `info` or `debug`.
pub fn setup_logger() {
    setup_logger_with_default("off", false);
}

/// The logger for command-line tools: `info` unless `RUST_LOG` says
/// otherwise, written to stderr, so a tool's report shows by default and
/// stdout stays free for its data.
pub fn setup_cli_logger() {
    setup_logger_with_default("info", true);
}

fn setup_logger_with_default(default: &'static str, to_stderr: bool) {
    INIT.call_once(|| {
        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(default))
            .add_directive("hyper=off".parse().unwrap())
            .add_directive("p3_keccak_air=off".parse().unwrap())
            .add_directive("p3_fri=off".parse().unwrap())
            .add_directive("p3_dft=off".parse().unwrap())
            .add_directive("p3_challenger=off".parse().unwrap())
            .add_directive("zkm_cuda=off".parse().unwrap());

        // if the RUST_LOGGER environment variable is set, use it to determine which logger to
        // configure (tracing_forest or tracing_subscriber)
        // otherwise, default to 'forest'
        let logger_type = std::env::var("RUST_LOGGER").unwrap_or_else(|_| "flat".to_string());
        match logger_type.as_str() {
            "forest" => {
                Registry::default().with(env_filter).with(ForestLayer::default()).init();
            }
            "flat" => {
                let builder = tracing_subscriber::fmt::Subscriber::builder()
                    .compact()
                    .with_file(false)
                    .with_target(false)
                    .with_thread_names(false)
                    .with_env_filter(env_filter)
                    .with_span_events(FmtSpan::CLOSE)
                    .with_ansi(false);
                if to_stderr {
                    builder.with_writer(std::io::stderr).finish().init();
                } else {
                    builder.finish().init();
                }
            }
            _ => {
                panic!("Invalid logger type: {logger_type}");
            }
        }
    });
}

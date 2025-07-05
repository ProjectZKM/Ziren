pub mod commands;

pub const ZKM_VERSION_MESSAGE: &str =
    concat!("ZKM", " (", env!("VERGEN_GIT_SHA"), " ", env!("VERGEN_BUILD_TIMESTAMP"), ")");

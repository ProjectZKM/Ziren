use enum_map::Enum;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use strum_macros::EnumIter;

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, EnumIter, Ord, PartialOrd, Serialize, Deserialize, Enum,
)]
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
pub enum SyscallCode {
    SYSGETPID = 4020,
    SYSGETGID = 4047,
    SYSMMAP2 = 4210,
    SYSMMAP = 4090,
    SYSBRK = 4045,
    SYSCLONE = 4120,
    SYSEXITGROUP = 4246,
    SYSREAD = 4003,
    SYSWRITE = 4004,
    SYSFCNTL = 4055,
    SYSSETTHREADAREA = 4283,
}

impl Display for SyscallCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

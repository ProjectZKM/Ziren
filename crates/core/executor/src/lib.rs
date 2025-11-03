mod air;
mod context;
mod cost;
mod dependencies;
pub mod events;
mod executor;
pub mod hook;
mod instruction;
mod io;
pub mod memory;
mod opcode;
mod program;
#[cfg(test)]
pub mod programs;
mod record;
pub mod reduce;
mod register;
pub mod report;
mod state;
pub mod subproof;
pub mod syscalls;
mod utils;

pub use air::*;
pub use context::*;
pub use cost::*;
pub use executor::*;
pub use hook::*;
pub use instruction::*;
pub use opcode::*;
pub use program::*;
pub use record::*;
pub use reduce::*;
pub use register::*;
pub use report::*;
pub use state::*;
pub use subproof::*;
pub use utils::*;

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum OptionValTag {
    Some = 0,
    None,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct OptionU32 {
    pub tag: OptionValTag,
    pub value: u32,
}

impl From<Option<u32>> for OptionU32 {
    fn from(val: Option<u32>) -> Self {
        match val {
            Some(value) => OptionU32 { tag: OptionValTag::Some, value },
            None => OptionU32 { tag: OptionValTag::None, value: 0 },
        }
    }
}

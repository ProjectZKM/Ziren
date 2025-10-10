use p3_koala_bear::KoalaBear;
use zkm_core_executor::events::{
    AluEvent, MemoryInitializeFinalizeEvent, MemoryLocalEvent, SyscallEvent,
};

use crate::{
    alu::AddSubCols,
    memory::{MemoryInitCols, SingleMemoryLocal},
    syscall::chip::SyscallCols,
};

#[link(name = "zkm-core-machine-sys", kind = "static")]
extern "C-unwind" {
    pub fn add_sub_event_to_row_koalabear(event: &AluEvent, cols: &mut AddSubCols<KoalaBear>);
    pub fn memory_local_event_to_row_koalabear(
        event: &MemoryLocalEvent,
        cols: &mut SingleMemoryLocal<KoalaBear>,
    );
    pub fn memory_global_event_to_row_koalabear(
        event: &MemoryInitializeFinalizeEvent,
        is_receive: bool,
        cols: &mut MemoryInitCols<KoalaBear>,
    );
    pub fn syscall_event_to_row_koalabear(
        event: &SyscallEvent,
        is_receive: bool,
        cols: &mut SyscallCols<KoalaBear>,
    );

    pub fn test_mul();
    pub fn test_inv();
    pub fn test_sqrt();
    pub fn test_curve_formula();
}

#[cfg(test)]
mod tests {
    use crate::sys::{test_curve_formula, test_inv, test_mul, test_sqrt};

    #[test]
    fn test_septic() {
        unsafe { test_mul() };
        unsafe { test_inv() };
        unsafe { test_sqrt() };
        unsafe { test_curve_formula() };
    }
}

#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Executes the Poseidon2 permutation on the given state.
///
/// ### Safety
///
/// The caller must ensure that `state` is valid pointer to data that is aligned along a four
/// byte boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_poseidon2_permute(state: *mut [u32; 16]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
        "syscall",
        in("$2") crate::syscalls::POSEIDON2_PERMUTE,
        in("$4") state,
        in("$5") 0,
        );
    }
}

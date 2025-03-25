#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Executes the Keccak256 sponge
///
/// ### Safety
///
/// The caller must ensure that `input` and `result` are valid pointers to data that are aligned along
/// a four byte boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_keccak_sponge(input: *const u32, result: *mut [u32; 16]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "syscall",
            in("$2") crate::syscalls::KECCAK_SPONGE,
            in("$4") input,
            in("$5") result,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

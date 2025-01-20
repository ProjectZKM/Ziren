#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Uint256 multiplication operation.
///
/// The result is written over the first input.
///
/// ### Safety
///
/// The caller must ensure that `x` and `y` are valid pointers to data that is aligned along a four
/// byte boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_uint256_mulmod(x: *mut [u32; 8], y: *const [u32; 8]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "syscall",
            in("$2") crate::syscalls::UINT256_MUL,
            in("$4") x,
            in("$5") y,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

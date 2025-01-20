#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Multiplication operation between a 256-bit and a 2048-bit unsigned integer.
///
/// The low 2048-bit result is written to the `lo` pointer, and the high 256-bit overflow is written to the `hi` pointer.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_u256x2048_mul(
    a: *const [u32; 8],
    b: *const [u32; 64],
    lo: *mut [u32; 64],
    hi: *mut [u32; 8],
) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "syscall",
            in("$2") crate::syscalls::U256XU2048_MUL,
            in("$4") a,
            in("$5") b,
            in("$6") lo,
            in("$7") hi,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

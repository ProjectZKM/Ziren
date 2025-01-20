#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Adds two Bn254 points.
///
/// The result is stored in the first point.
///
/// ### Safety
///
/// The caller must ensure that `p` and `q` are valid pointers to data that is aligned along a four
/// byte boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bn254_add(p: *mut [u32; 16], q: *const [u32; 16]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "syscall",
            in("$2") crate::syscalls::BN254_ADD,
            in("$4") p,
            in("$5") q,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Double a Bn254 point.
///
/// The result is stored in the first point.
///
/// ### Safety
///
/// The caller must ensure that `p` is valid pointer to data that is aligned along a four byte
/// boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bn254_double(p: *mut [u32; 16]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "syscall",
            in("$2") crate::syscalls::BN254_DOUBLE,
            in("$4") p,
            in("$5") 0,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

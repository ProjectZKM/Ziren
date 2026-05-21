#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Executes the AES-128 encryption on the given block with the given key.
///
/// ### Safety
///
/// The caller must ensure that `state` and `key` are valid pointers to data that are aligned along
/// a four byte boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_aes128_encrypt(state: *mut [u32; 4], key: *const [u32; 4]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
        "syscall",
        in("$2") crate::syscalls::AES128_ENCRYPT,
        in("$4") state,
        in("$5") key,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Executes the boolean circuit garble
///
/// ### Safety
///
/// The caller must ensure that `inputs` and `output` are valid pointers to data that are aligned along
/// a four byte boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_boolean_circuit_garble(input: *const u8, output: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
        "syscall",
        in("$2") crate::syscalls::BOOLEAN_CIRCUIT_GARBLE,
        in("$4") input,
        in("$5") output,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

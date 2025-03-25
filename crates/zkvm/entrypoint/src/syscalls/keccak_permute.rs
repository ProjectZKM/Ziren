// #[cfg(target_os = "zkvm")]
// use core::arch::asm;
//
// /// Executes the Keccak256 permutation on the given state.
// ///
// /// ### Safety
// ///
// /// The caller must ensure that `state` is valid pointer to data that is aligned along a four
// /// byte boundary.
// #[allow(unused_variables)]
// #[no_mangle]
// pub extern "C" fn syscall_keccak_permute(state: *mut [u64; 25]) {
//     #[cfg(target_os = "zkvm")]
//     unsafe {
//         asm!(
//             "syscall",
//             in("$2") crate::syscalls::KECCAK_PERMUTE,
//             in("$4") state,
//             in("$5") 0
//         );
//     }
//
//     #[cfg(not(target_os = "zkvm"))]
//     unreachable!()
// }

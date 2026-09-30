use super::syscall_uint256_mulmod;

/// The number of limbs in a "uint256".
const N: usize = 8;

/// Sets `result` to be `(x op y) % modulus`.
///
/// Currently only multiplication is supported and `op` is not used. If the modulus is zero, then
/// the modulus applied is 2^256.
///
/// ### Safety
///
/// The caller must ensure that `result`, `x`, `y`, and `modulus` are valid pointers to data that is
/// aligned along a four byte boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn sys_bigint(
    result: *mut [u32; N],
    op: u32,
    x: *const [u32; N],
    y: *const [u32; N],
    modulus: *const [u32; N],
) {
    let mut concat_y_modulus = core::mem::MaybeUninit::<[u32; N * 2]>::uninit();
    unsafe {
        let result_ptr = result as *mut u32;
        let x_ptr = x as *const u32;
        let y_ptr = y as *const u32;
        let concat_ptr = concat_y_modulus.as_mut_ptr() as *mut u32;

        core::ptr::copy(y_ptr, concat_ptr, N);

        core::ptr::copy(modulus as *const u32, concat_ptr.add(N), N);

        core::ptr::copy(x as *const u32, result_ptr, N);

        let result_ptr = result_ptr as *mut [u32; N];
        let concat_ptr = concat_ptr as *mut [u32; N];
        syscall_uint256_mulmod(result_ptr, concat_ptr);
    }
}

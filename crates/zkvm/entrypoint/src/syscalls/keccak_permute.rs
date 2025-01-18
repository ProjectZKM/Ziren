#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Executes the Keccak256 permutation on the given state.
///
/// ### Safety
///
/// The caller must ensure that `state` is valid pointer to data that is aligned along a four
/// byte boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_keccak_permute(data: &[u8]) -> [u8; 32] {
    let len = data.len();
    let mut u32_array = Vec::new();

    if len == 0 {
        return [
            0xC5, 0xD2, 0x46, 0x01, 0x86, 0xF7, 0x23, 0x3C, 0x92, 0x7E, 0x7D, 0xB2, 0xDC, 0xC7,
            0x03, 0xC0, 0xE5, 0, 0xB6, 0x53, 0xCA, 0x82, 0x27, 0x3B, 0x7B, 0xFA, 0xD8, 0x04, 0x5D,
            0x85, 0xA4, 0x70,
        ];
    }

    // covert to u32 to align the memory
    for i in (0..len).step_by(4) {
        if i + 4 <= len {
            let u32_value = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            u32_array.push(u32_value);
        } else {
            let mut padded_chunk = [0u8; 4];
            padded_chunk[..len - i].copy_from_slice(&data[i..]);
            padded_chunk[len - i] = 1;
            let end = len % 136;
            if end + 4 > 136 {
                padded_chunk[3] |= 0x80;
            }
            let u32_value = u32::from_be_bytes(padded_chunk);
            u32_array.push(u32_value);
        }
    }

    let mut result = [0u8; 32];
    // Read the vec into uninitialized memory. The syscall assumes the memory is uninitialized,
    // which should be true because the allocator does not dealloc, so a new alloc should be fresh.
    unsafe {
        #[cfg(target_os = "zkvm")]
        unsafe {
             asm!(
                "syscall",
                in("$2") crate::syscalls::KECCAK_PERMUTE,
                in("$4") u32_array.as_ptr(),
                in("$5") len,
                in("$6") result.as_mut_ptr(),
            );
        }

        #[cfg(not(target_os = "zkvm"))]
        unreachable!()
    }
    result
}

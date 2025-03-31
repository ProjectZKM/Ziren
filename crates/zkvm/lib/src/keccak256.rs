use crate::{syscall_keccak_permute, syscall_keccak_sponge};

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let len = data.len();
    let mut u32_array = Vec::new();

    if len == 0 {
        return [
            0xC5, 0xD2, 0x46, 0x01, 0x86, 0xF7, 0x23, 0x3C, 0x92, 0x7E, 0x7D, 0xB2, 0xDC, 0xC7,
            0x03, 0xC0, 0xE5, 0, 0xB6, 0x53, 0xCA, 0x82, 0x27, 0x3B, 0x7B, 0xFA, 0xD8, 0x04, 0x5D,
            0x85, 0xA4, 0x70,
        ];
    }

    // Padding input to reach the required size.
    let final_block_len = len % 136;
    let padded_len = len - final_block_len + 136;

    let mut padded_data = data.to_vec();
    padded_data.resize(padded_len, 0);

    if len % 136 == 135 {
        // Both 1s are placed in the same byte.
        padded_data[padded_len - 1 as usize] = 0b10000001;
    } else {
        padded_data[len] = 1;
        padded_data[padded_len - 1 as usize] = 0b10000000;
    }

    // covert to u32 to align the memory
    let mut count = 0;
    for i in (0..padded_len).step_by(4) {
        let u32_value = u32::from_be_bytes([padded_data[i + 3], padded_data[i + 2], padded_data[i + 1], padded_data[i]]);
        u32_array.push(u32_value);
        count += 1;
        // each block already has 34 u32 numbers, need to pad 2 u32 0s for each
        if count == 34 {
            for _ in 0..2 {
                u32_array.push(0);
            }
            count = 0;
        }
    }
    let mut general_result = [0u32; 17];
    let mut sha3_256_result = [0u8; 32];
    // Write the number which indicate the rate length (bytes) in the first cell of result.
    general_result[16] = u32_array.len() as u32;
    // Call precompile
    unsafe {
        syscall_keccak_sponge(u32_array.as_ptr(), &mut general_result);
    }

    let tmp: &mut [u8; 64] =
        unsafe { core::mem::transmute(&mut general_result)};
    sha3_256_result.copy_from_slice(&tmp[..32]);
    sha3_256_result
}
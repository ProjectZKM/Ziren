use crate::syscall_keccak_sponge;

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let len = data.len();
    let mut u32_array = Vec::new();

    if len == 0 {
        return [
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
            0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
        ];
    }

    // Padding input to reach the required size.
    let final_block_len = len % 136;
    let padded_len = len - final_block_len + 136;

    let mut padded_data = Vec::with_capacity(padded_len);
    padded_data.extend_from_slice(data);
    padded_data.resize(padded_len, 0);

    if len % 136 == 135 {
        padded_data[padded_len - 1 as usize] = 0b10000110;
    } else {
        padded_data[len] = 6;
        padded_data[padded_len - 1 as usize] = 0b10000000;
    }

    // covert to u32 to align the memory
    let mut count = 0;
    u32_array.reserve(padded_len / 4 + (padded_len / 136) * 2);
    for chunk in padded_data.chunks_exact(4) {
        let u32_value = u32::from_be_bytes([chunk[3], chunk[2], chunk[1], chunk[0]]);
        u32_array.push(u32_value);
        count += 1;
        if count == 34 {
            u32_array.extend_from_slice(&[0, 0]);
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

    let tmp: &mut [u8; 64] = unsafe { core::mem::transmute(&mut general_result)};
    sha3_256_result.copy_from_slice(&tmp[..32]);
    sha3_256_result
}
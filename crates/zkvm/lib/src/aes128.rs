use crate::syscall_aes128_encrypt;

pub fn aes128_encrypt(state: &mut [u8; 16], key: &[u8; 16]) {
    // convert to u32 to align the memory
    let mut state_u32 = [0u32; 4];
    let mut key_u32 = [0u32; 4];

    for i in 0..4 {
        state_u32[i] = u32::from_le_bytes([
            state[i * 4],
            state[i * 4 + 1],
            state[i * 4 + 2],
            state[i * 4 + 3],
        ]);
        key_u32[i] =
            u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }
    unsafe { syscall_aes128_encrypt(&mut state_u32, &key_u32) }
    for i in 0..4 {
        state[4 * i..4 * i + 4].copy_from_slice(&state_u32[i].to_le_bytes());
    }
}

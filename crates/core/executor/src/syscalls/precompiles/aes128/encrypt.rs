use crate::events::{AES128EncryptEvent, PrecompileEvent, AES_128_BLOCK_U32S};
use crate::syscalls::precompiles::aes128::utils::mul_md5;
use crate::syscalls::{Syscall, SyscallCode, SyscallContext};

pub(crate) struct AES128EncryptSyscall;

pub const AES128_RCON: [[u8; 4]; 10] = [
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1B, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00],
];

pub const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

impl Syscall for AES128EncryptSyscall {
    fn num_extra_cycles(&self) -> u32 {
        1
    }
    fn execute(
        &self,
        rt: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let start_clk = rt.clk;
        let block_ptr = arg1;
        let key_ptr = arg2;

        let mut input_read_records = Vec::new();
        let mut key_read_records = Vec::new();
        let mut output_write_records = Vec::new();

        let mut input = Vec::new();
        let mut key_u32s = Vec::new();
        let mut state = Vec::new();
        let mut key = Vec::new();
        let mut output = Vec::new();

        // read block input
        for i in 0..AES_128_BLOCK_U32S {
            let (record, value) = rt.mr(block_ptr + i as u32 * 4);
            input_read_records.push(record);
            input.push(value);
            state.extend(value.to_le_bytes());
        }

        // read key
        for i in 0..AES_128_BLOCK_U32S {
            let (record, value) = rt.mr(key_ptr + i as u32 * 4);
            key_read_records.push(record);
            key_u32s.push(value);
            key.extend(value.to_le_bytes());
        }

        // // Add Roundkey, Round 0
        for i in 0..state.len() {
            state[i] ^= key[i];
        }

        // perform AES
        let mut round_key = key;
        for i in 1..11 {
            // compute round key
            Self::compute_round_key(&mut round_key, i - 1);

            // Subs_bytes
            for j in 0..state.len() {
                let value = AES_SBOX[state[j] as usize];
                state[j] = value;
            }

            // Shift row
            let shift_row = [
                state[0], state[5], state[10], state[15], state[4], state[9], state[14], state[3],
                state[8], state[13], state[2], state[7], state[12], state[1], state[6], state[11],
            ]
            .to_vec();

            // Mix columns
            let mix_columns = if i != 10 {
                let mut mixed = shift_row.clone();
                for col in 0..4 {
                    let col_start = col * 4;
                    let s0 = shift_row[col_start];
                    let s1 = shift_row[col_start + 1];
                    let s2 = shift_row[col_start + 2];
                    let s3 = shift_row[col_start + 3];
                    mixed[col_start] =
                        mul_md5(s0, 2) ^ mul_md5(s1, 3) ^ mul_md5(s2, 1) ^ mul_md5(s3, 1);
                    mixed[col_start + 1] =
                        mul_md5(s0, 1) ^ mul_md5(s1, 2) ^ mul_md5(s2, 3) ^ mul_md5(s3, 1);
                    mixed[col_start + 2] =
                        mul_md5(s0, 1) ^ mul_md5(s1, 1) ^ mul_md5(s2, 2) ^ mul_md5(s3, 3);
                    mixed[col_start + 3] =
                        mul_md5(s0, 3) ^ mul_md5(s1, 1) ^ mul_md5(s2, 1) ^ mul_md5(s3, 2);
                }
                mixed
            } else {
                shift_row
            };

            // Add round key
            for j in 0..state.len() {
                state[j] = mix_columns[j] ^ round_key[j];
            }
        }

        // write output
        // Increment the clk by 1 before writing because we read from memory at start_clk.
        rt.clk += 1;
        assert_eq!(state.len(), 16);
        for chunk in state.chunks(4) {
            let value = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            output.push(value);
        }
        let write_records = rt.mw_slice(block_ptr, output.as_slice());
        output_write_records.extend_from_slice(&write_records);

        // Push the AES128 encrypt event.
        let shard = rt.current_shard();
        let aes128_event = PrecompileEvent::Aes128Encrypt(AES128EncryptEvent {
            shard,
            clk: start_clk,
            block_addr: block_ptr,
            key_addr: key_ptr,
            input: input.as_slice().try_into().unwrap(),
            key: key_u32s.as_slice().try_into().unwrap(),
            output: output.as_slice().try_into().unwrap(),
            input_read_records: input_read_records.as_slice().try_into().unwrap(),
            key_read_records: key_read_records.as_slice().try_into().unwrap(),
            output_write_records: output_write_records.as_slice().try_into().unwrap(),
            local_mem_access: rt.postprocess(),
        });
        let aes128_syscall_event =
            rt.rt.syscall_event(start_clk, None, rt.next_pc, syscall_code.syscall_id(), arg1, arg2);
        rt.add_precompile_event(syscall_code, aes128_syscall_event, aes128_event);
        None
    }
}

impl AES128EncryptSyscall {
    fn compute_round_key(previous_key: &mut [u8], round: usize) {
        if previous_key.len() != 16 {
            panic!("AES128: wrong previous key length");
        }
        // First 4 bytes
        let g_w3 = {
            let mut result =
                [previous_key[13], previous_key[14], previous_key[15], previous_key[12]];
            for (i, rcon) in AES128_RCON[round].iter().enumerate() {
                let value = AES_SBOX[result[i] as usize];
                result[i] = value ^ rcon;
            }
            result
        };

        let prev = previous_key.to_vec().clone();
        for i in 0..4 {
            let w = if i == 0 {
                prev[0..4].iter().zip(g_w3.iter()).map(|(&a, &b)| a ^ b).collect::<Vec<u8>>()
            } else {
                prev[i * 4..(i + 1) * 4]
                    .iter()
                    .zip(previous_key[(i - 1) * 4..i * 4].iter())
                    .map(|(&a, &b)| a ^ b)
                    .collect::<Vec<u8>>()
            };
            previous_key[i * 4..(i + 1) * 4].copy_from_slice(&w);
        }
    }
}

use log::info;
use crate::events::{AES128EncryptEvent, MemoryReadRecord, PrecompileEvent, AES_128_BLOCK_U32S};
use crate::Register::A2;
use crate::syscalls::{Syscall, SyscallCode, SyscallContext};
use crate::syscalls::precompiles::aes128::utils::mul_md5;

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
        let mut sbox_read_records = Vec::new();
        let mut output_write_records = Vec::new();

        let mut input = Vec::new();
        let mut key_u32s = Vec::new();
        let mut state = Vec::new();
        let mut key = Vec::new();
        let mut output = Vec::new();
        let mut sbox: Vec<u8> = Vec::new();

        // read sbox ptr
        let (sbox_ptr_memory, sbox_ptr) = rt.mr(A2 as u32);

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

        // Add Roundkey, Round 0
        for i in 0..state.len() {
            state[i] = state[i] ^ key[i];
        }

        // Read first 24 sbox elements, Round 0
        for i in 0..24 {
            let (record, value) = rt.mr(sbox_ptr + i as u32 * 4);
            sbox_read_records.push(record);
            assert!(value <= u8::MAX as u32);
            sbox.push(value as u8);
        }

        // perform AES
        let mut round_key = key;
        for i in 1..11 {
            // compute round key
            Self::compute_round_key(
                rt,
                &mut round_key,
                &mut sbox_read_records,
                &mut sbox,
                sbox_ptr,
                i - 1
            );

            // Subs_bytes
            for i in 0..state.len() {
                let (record, value) = rt.mr(sbox_ptr + state[i] as u32 * 4);
                sbox_read_records.push(record);
                assert!(value <= u8::MAX as u32);
                sbox.push(value as u8);
                state[i] = value as u8;
            }
            
            // Shift row
            let shift_row = [
              state[0], state[5], state[10], state[15],
              state[4], state[9], state[14], state[3],
              state[8], state[13], state[2], state[7],
              state[12], state[1], state[6], state[11],
            ].to_vec();

            // Mix columns
            let mix_columns = if i != 10 {
                let mut mixed = shift_row.clone();
                for col in 0..4 {
                    let col_start = col * 4;
                    let s0 = shift_row[col_start];
                    let s1 = shift_row[col_start + 1];
                    let s2 = shift_row[col_start + 2];
                    let s3 = shift_row[col_start + 3];
                    mixed[col_start]     = mul_md5(s0, 2) ^ mul_md5(s1, 3) ^ mul_md5(s2, 1) ^ mul_md5(s3, 1);
                    mixed[col_start + 1] = mul_md5(s0, 1) ^ mul_md5(s1, 2) ^ mul_md5(s2, 3) ^ mul_md5(s3, 1);
                    mixed[col_start + 2] = mul_md5(s0, 1) ^ mul_md5(s1, 1) ^ mul_md5(s2, 2) ^ mul_md5(s3, 3);
                    mixed[col_start + 3] = mul_md5(s0, 3) ^ mul_md5(s1, 1) ^ mul_md5(s2, 1) ^ mul_md5(s3, 2);
                }
                mixed
            } else {
                shift_row
            };

            // Add round key
            for i in 0..state.len() {
                state[i] = mix_columns[i] ^ round_key[i];
            }

            // Read 24 sbox elements
            if i != 10 {
                for j in i * 24..i * 24 + 24 {
                    let (record, value) = rt.mr(sbox_ptr as u32 + j as u32 * 4);
                    sbox_read_records.push(record);
                    assert!(value <= u8::MAX as u32);
                    sbox.push(value as u8);
                }
            } else {
                for j in i * 24..256 {
                    let (record, value) = rt.mr(sbox_ptr as u32 + j as u32 * 4);
                    sbox_read_records.push(record);
                    assert!(value <= u8::MAX as u32);
                    sbox.push(value as u8);
                }
            }
        }

        
        // write output
        // Increment the clk by 1 before writing because we read from memory at start_clk.
        rt.clk += 1;
        assert_eq!(state.len(), 16);
        log::info!("AES128 Encrypt output: {:?}", state);
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
            sbox_addr: sbox_ptr,
            sbox_addr_memory: sbox_ptr_memory,
            input: input.as_slice().try_into().unwrap(),
            key: key_u32s.as_slice().try_into().unwrap(),
            output: output.as_slice().try_into().unwrap(),
            sbox_reads: sbox,
            input_read_records: input_read_records.as_slice().try_into().unwrap(),
            key_read_records: key_read_records.as_slice().try_into().unwrap(),
            sbox_read_records,
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
    fn compute_round_key(
        rt: &mut SyscallContext,
        previous_key: &mut [u8],
        sbox_records: &mut Vec<MemoryReadRecord>,
        sbox: &mut Vec<u8>,
        sbox_ptr: u32,
        round: usize
    ) {
        if previous_key.len() != 16 {
            panic!("AES128: wrong previous key length");
        }
        // First 4 bytes
        let g_w3 = {
            let mut result = [previous_key[13], previous_key[14], previous_key[15], previous_key[12]];
            for (i, rcon) in AES128_RCON[round].iter().enumerate() {
                let (record, value) = rt.mr(sbox_ptr + result[i] as u32 * 4);
                sbox_records.push(record);
                assert!(value <= u8::MAX as u32);
                sbox.push(value as u8);
                result[i] = (value as u8) ^ rcon;
            }
            result
        };
        let w0 = [previous_key[0], previous_key[1], previous_key[2], previous_key[3]];
        let w1 = [previous_key[4], previous_key[5], previous_key[6], previous_key[7]];
        let w2 = [previous_key[8], previous_key[9], previous_key[10], previous_key[11]];
        let w3 = [previous_key[12], previous_key[13], previous_key[14], previous_key[15]];
        let w4: [u8; 4] = w0.iter().zip(g_w3.iter()).map(|(&a, &b)| a ^ b)
            .collect::<Vec<u8>>().try_into().unwrap();
        let w5: [u8; 4] = w4.iter().zip(w1.iter()).map(|(&a, &b)| a ^ b)
            .collect::<Vec<u8>>().try_into().unwrap();
        let w6: [u8; 4] = w5.iter().zip(w2.iter()).map(|(&a, &b)| a ^ b)
            .collect::<Vec<u8>>().try_into().unwrap();
        let w7: [u8; 4] = w6.iter().zip(w3.iter()).map(|(&a, &b)| a ^ b)
            .collect::<Vec<u8>>().try_into().unwrap();

        previous_key[0..4].copy_from_slice(&w4);
        previous_key[4..8].copy_from_slice(&w5);
        previous_key[8..12].copy_from_slice(&w6);
        previous_key[12..16].copy_from_slice(&w7);
    }
}

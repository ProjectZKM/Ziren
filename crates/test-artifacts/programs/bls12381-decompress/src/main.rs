#![no_std]
#![no_main]

zkm2_zkvm::entrypoint!(main);

use zkm2_lib::bls12381::decompress_pubkey;

pub fn main() {
    let compressed_key: [u8; 48] = zkm2_zkvm::io::read_vec().try_into().unwrap();

    for _ in 0..4 {
        // println!("before: {:?}", compressed_key);

        let decompressed_key = decompress_pubkey(&compressed_key).unwrap();

        // println!("after: {:?}", decompressed_key);
        zkm2_zkvm::io::commit_slice(&decompressed_key);
    }
}

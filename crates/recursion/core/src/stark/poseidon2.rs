use p3_bn254_fr::Bn254;
use zkhash::{
    ark_ff::{BigInteger, PrimeField},
    fields::bn256::FpBN256 as ark_FpBN256,
    poseidon2::poseidon2_instance_bn256::RC3,
};

fn bn254_from_ark_ff(input: ark_FpBN256) -> Bn254 {
    let bytes = input.into_bigint().to_bytes_le();
    // Convert little-endian bytes to little-endian u64 limbs
    let mut limbs = [0u64; 4];
    for (i, chunk) in bytes.chunks(8).enumerate() {
        if i >= 4 {
            break;
        }
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        limbs[i] = u64::from_le_bytes(buf);
    }
    Bn254::new(limbs)
}

pub fn bn254_poseidon2_rc3() -> Vec<[Bn254; 3]> {
    RC3.iter()
        .map(|vec| {
            vec.iter().cloned().map(bn254_from_ark_ff).collect::<Vec<_>>().try_into().unwrap()
        })
        .collect()
}

pub fn bn254_poseidon2_rc4() -> Vec<[Bn254; 4]> {
    RC3.iter()
        .map(|vec| {
            let result: [Bn254; 3] =
                vec.iter().cloned().map(bn254_from_ark_ff).collect::<Vec<_>>().try_into().unwrap();
            [result[0], result[1], result[2], result[2]]
        })
        .collect()
}

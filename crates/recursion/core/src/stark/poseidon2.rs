use ff::PrimeField as FFPrimeField;
#[cfg(feature = "bls12381")]
use p3_bls12381_fr::{Bls12381Fr as FR, FFBls12381Fr as FFFR};
#[cfg(feature = "bn254")]
use p3_bn254_fr::{Bn254Fr as FR, FFBn254Fr as FFFR};
use zkhash::ark_ff::{BigInteger, PrimeField};
#[cfg(feature = "bls12381")]
use zkhash::{fields::bls12::FpBLS12 as ark_Fp, poseidon2::poseidon2_instance_bls12::RC3};
#[cfg(feature = "bn254")]
use zkhash::{fields::bn256::FpBN256 as ark_Fp, poseidon2::poseidon2_instance_bn256::RC3};

fn bn254_from_ark_ff(input: ark_Fp) -> FR {
    let bytes = input.into_bigint().to_bytes_le();

    let mut res = <FFFR as ff::PrimeField>::Repr::default();

    for (i, digit) in res.as_mut().iter_mut().enumerate() {
        *digit = bytes[i];
    }

    let value = FFFR::from_repr(res);

    if value.is_some().into() {
        FR { value: value.unwrap() }
    } else {
        panic!("Invalid field element")
    }
}

pub fn bn254_poseidon2_rc3() -> Vec<[FR; 3]> {
    RC3.iter()
        .map(|vec| {
            vec.iter().cloned().map(bn254_from_ark_ff).collect::<Vec<_>>().try_into().unwrap()
        })
        .collect()
}

pub fn bn254_poseidon2_rc4() -> Vec<[FR; 4]> {
    RC3.iter()
        .map(|vec| {
            let result: [FR; 3] =
                vec.iter().cloned().map(bn254_from_ark_ff).collect::<Vec<_>>().try_into().unwrap();
            [result[0], result[1], result[2], result[2]]
        })
        .collect()
}